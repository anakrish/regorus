// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Foreign read-through value backend FFI.
//!
//! The caller supplies a C-ABI vtable for an immutable value graph. regorus keeps
//! only opaque caller contexts plus the read-only callbacks and materializes
//! values on demand as policy evaluation touches object fields or array elements.
//! The FFI is deliberately shape-agnostic: envelopes such as `{"Values": ...}`
//! are constructed by the caller, not by Rust.

use crate::common::{to_ref, to_regorus_result, RegorusResult, RegorusStatus};
use crate::engine::RegorusEngine;
use crate::panic_guard::with_unwind_guard;
use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use anyhow::{bail, Result};
use core::ffi::{c_char, c_void, CStr};
use core::ptr;
use regorus::{ArrayBackend, ForeignArcStr, ObjectBackend, Rc, Value, ValueArray as Array, ValueMap};

const TAG_UNDEFINED: u8 = 0;
const TAG_NULL: u8 = 1;
const TAG_BOOL: u8 = 2;
const TAG_I64: u8 = 3;
const TAG_U64: u8 = 4;
const TAG_F64: u8 = 5;
const TAG_STRING: u8 = 6;
const TAG_OBJECT: u8 = 7;
const TAG_ARRAY: u8 = 8;

const MAX_FOREIGN_KEYS: usize = 1024;

/// A single value produced by the caller per read-through access.
///
/// Scalars (tags 0..=6) terminate recursion. Tags 7=object and 8=array carry a
/// child context handle in `child_ctx`; the child is read through the same
/// immutable vtable held by the root [`RegorusForeignInput`]. Strings are
/// borrowed UTF-8 (`str_ptr`/`str_len`) and are copied synchronously by Rust.
#[repr(C)]
pub struct RegorusForeignField {
    /// 0=undefined, 1=null, 2=bool, 3=i64, 4=u64, 5=f64, 6=string,
    /// 7=object child, 8=array child.
    pub tag: u8,
    pub b: bool,
    pub i: i64,
    pub u: u64,
    pub f: f64,
    /// Borrowed UTF-8 bytes (valid only for the duration of the callback). Copied.
    pub str_ptr: *const u8,
    pub str_len: usize,
    /// Opaque caller context for nested object/array values (tags 7/8).
    pub child_ctx: *mut c_void,
}

impl RegorusForeignField {
    fn empty() -> Self {
        RegorusForeignField {
            tag: TAG_UNDEFINED,
            b: false,
            i: 0,
            u: 0,
            f: 0.0,
            str_ptr: ptr::null(),
            str_len: 0,
            child_ctx: ptr::null_mut(),
        }
    }

    unsafe fn to_value(&self, state: &Rc<ForeignViewState>) -> Value {
        match self.tag {
            TAG_NULL => Value::Null,
            TAG_BOOL => Value::Bool(self.b),
            TAG_I64 => Value::Int(self.i),
            TAG_U64 => Value::UInt(self.u),
            TAG_F64 => Value::Float(self.f),
            TAG_STRING => {
                if self.str_ptr.is_null() {
                    return Value::String(ForeignArcStr::from(""));
                }
                let bytes = core::slice::from_raw_parts(self.str_ptr, self.str_len);
                match core::str::from_utf8(bytes) {
                    Ok(s) => Value::String(ForeignArcStr::from(s)),
                    Err(_) => Value::Undefined,
                }
            }
            TAG_OBJECT | TAG_ARRAY if !self.child_ctx.is_null() => {
                ForeignNode::new_value(state.clone(), self.child_ctx, self.tag)
            }
            _ => Value::Undefined,
        }
    }
}

/// C-ABI vtable describing a recursive immutable foreign value graph.
///
/// Concurrency contract:
/// - After `regorus_foreign_input_new` returns, regorus may invoke `len`,
///   `get_field`, `get_element`, and `keys` concurrently from many threads with
///   the SAME `ctx` and child contexts. These callbacks must be pure,
///   read-only, exception-safe, and free of callback-internal shared mutable
///   state. Use per-thread/per-call scratch buffers and per-thread counters in
///   language bindings; never reuse one mutable scratch buffer or non-atomic
///   counter behind a shared `ctx`.
/// - The caller must fully construct and publish the immutable object graph
///   before sharing the returned `RegorusForeignInput` with worker threads. The
///   shared `Arc<CtxOwner>` used by regorus is the release/acquire share point
///   for all subsequent per-VM views.
/// - Each engine/VM attachment creates its own thin foreign root wrapper over
///   the shared owner, so materialization fallback caches (`OnceLock` cells in
///   foreign arrays/objects) are per-view and are never shared across VMs.
/// - `free(ctx)` is called exactly once, after the input handle and every
///   engine/VM view cloned from it have been dropped; no callback is in flight
///   when `free` runs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegorusForeignValue {
    pub ctx: *mut c_void,
    /// Root value kind: 7=object, 8=array.
    pub kind: u8,
    pub len: extern "C" fn(ctx: *mut c_void) -> usize,
    pub get_field:
        extern "C" fn(ctx: *mut c_void, key: *const c_char, out: *mut RegorusForeignField),
    pub keys: extern "C" fn(ctx: *mut c_void, out_ptrs: *mut *const c_char, out_len: *mut usize),
    pub get_element:
        extern "C" fn(ctx: *mut c_void, index: usize, out: *mut RegorusForeignField),
    /// Release the root caller handle exactly once on final owner drop.
    pub free: extern "C" fn(ctx: *mut c_void),
}

struct CtxOwner {
    vtable: RegorusForeignValue,
}

// SAFETY: `CtxOwner` owns only a copied, read-only vtable and an opaque handle
// to an immutable caller-owned object. The callbacks must be read-only, must not
// expose shared mutable scratch, and must keep all returned string bytes valid
// until the synchronous callback returns. Under those invariants, sharing the
// owner across read-only VM views is safe; `Drop` calls `free(root_ctx)` once.
unsafe impl Send for CtxOwner {}
unsafe impl Sync for CtxOwner {}

impl Drop for CtxOwner {
    fn drop(&mut self) {
        (self.vtable.free)(self.vtable.ctx);
    }
}

/// A per-engine/VM view over the shared immutable owner. The view has its own
/// reference-count word/cacheline (via the `Rc` that owns this state), so cloning
/// nested object/array backends within one VM does not touch the shared owner
/// refcount that other threads are also reading through.
struct ForeignViewState {
    owner: Arc<CtxOwner>,
    _per_view_refcount_word: Box<usize>,
}

// SAFETY: this state is a read-only view over an immutable `CtxOwner`. Any
// mutable scratch used by callbacks is per-view/per-worker on the caller side or
// Rust-owned within the node/view being accessed, never shared across threads.
unsafe impl Send for ForeignViewState {}
unsafe impl Sync for ForeignViewState {}

impl ForeignViewState {
    fn new(owner: Arc<CtxOwner>) -> Rc<Self> {
        Rc::new(Self {
            owner,
            _per_view_refcount_word: Box::new(0),
        })
    }
}

struct ForeignNode {
    state: Rc<ForeignViewState>,
    ctx: *mut c_void,
    kind: u8,
    keys: Vec<ForeignArcStr>,
    key_cstrings: Vec<CString>,
}

// SAFETY: `ForeignNode` contains an opaque immutable caller context and a
// per-view state. It performs no mutation except through caller callbacks that
// are required to be read-only and exception-safe.
unsafe impl Send for ForeignNode {}
unsafe impl Sync for ForeignNode {}

impl ForeignNode {
    fn new(state: Rc<ForeignViewState>, ctx: *mut c_void, kind: u8) -> Result<Self> {
        let (keys, key_cstrings) = if kind == TAG_OBJECT {
            unsafe { read_keys(&state.owner.vtable, ctx)? }
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Self {
            state,
            ctx,
            kind,
            keys,
            key_cstrings,
        })
    }

    fn new_value(state: Rc<ForeignViewState>, ctx: *mut c_void, kind: u8) -> Value {
        match Self::new(state, ctx, kind) {
            Ok(node) if kind == TAG_OBJECT => {
                let backend: Rc<dyn ObjectBackend> = Rc::new(ForeignObjectBackend { node });
                Value::Object(Rc::new(ValueMap::from_object_backend(backend)))
            }
            Ok(node) if kind == TAG_ARRAY => {
                let backend: Rc<dyn ArrayBackend> = Rc::new(ForeignArrayBackend { node });
                Value::Array(Rc::new(Array::from_backend(backend)))
            }
            _ => Value::Undefined,
        }
    }

    fn root_value(owner: Arc<CtxOwner>) -> Result<Value> {
        let state = ForeignViewState::new(owner.clone());
        let root = &owner.vtable;
        let node = Self::new(state, root.ctx, root.kind)?;
        match root.kind {
            TAG_OBJECT => {
                let backend: Rc<dyn ObjectBackend> = Rc::new(ForeignObjectBackend { node });
                Ok(Value::Object(Rc::new(ValueMap::from_object_backend(backend))))
            }
            TAG_ARRAY => {
                let backend: Rc<dyn ArrayBackend> = Rc::new(ForeignArrayBackend { node });
                Ok(Value::Array(Rc::new(Array::from_backend(backend))))
            }
            other => bail!("invalid foreign root kind {other}; expected 7=object or 8=array"),
        }
    }

    fn len(&self) -> usize {
        (self.state.owner.vtable.len)(self.ctx)
    }

    fn get_field(&self, key: &str) -> Option<Value> {
        if self.kind != TAG_OBJECT {
            return None;
        }
        let key_ptr = self
            .keys
            .iter()
            .position(|k| k.as_str() == key)
            .map(|i| self.key_cstrings[i].as_ptr())?;
        let mut out = RegorusForeignField::empty();
        (self.state.owner.vtable.get_field)(self.ctx, key_ptr, &mut out as *mut _);
        let value = unsafe { out.to_value(&self.state) };
        (!value.is_undefined()).then_some(value)
    }

    fn get_element(&self, index: usize) -> Option<Value> {
        if self.kind != TAG_ARRAY || index >= self.len() {
            return None;
        }
        let mut out = RegorusForeignField::empty();
        (self.state.owner.vtable.get_element)(self.ctx, index, &mut out as *mut _);
        let value = unsafe { out.to_value(&self.state) };
        (!value.is_undefined()).then_some(value)
    }
}

unsafe fn read_keys(
    vtable: &RegorusForeignValue,
    ctx: *mut c_void,
) -> Result<(Vec<ForeignArcStr>, Vec<CString>)> {
    let mut ptr_buf: Vec<*const c_char> = vec![ptr::null(); MAX_FOREIGN_KEYS];
    let mut out_len: usize = 0;
    (vtable.keys)(ctx, ptr_buf.as_mut_ptr(), &mut out_len as *mut usize);
    if out_len > MAX_FOREIGN_KEYS {
        bail!("foreign backend reported {out_len} keys (max {MAX_FOREIGN_KEYS})");
    }

    let mut keys = Vec::with_capacity(out_len);
    let mut key_cstrings = Vec::with_capacity(out_len);
    for &p in ptr_buf.iter().take(out_len) {
        if p.is_null() {
            bail!("foreign backend returned a null key pointer");
        }
        let s = CStr::from_ptr(p)
            .to_str()
            .map_err(|e| anyhow::anyhow!("invalid utf8 key: {e}"))?;
        keys.push(ForeignArcStr::from(s));
        key_cstrings.push(CString::new(s)?);
    }
    Ok((keys, key_cstrings))
}

struct ForeignObjectBackend {
    node: ForeignNode,
}

impl ObjectBackend for ForeignObjectBackend {
    fn get_value(&self, key: &str) -> Option<Value> {
        self.node.get_field(key)
    }

    fn keys(&self) -> &[ForeignArcStr] {
        &self.node.keys
    }

    fn len(&self) -> usize {
        self.node.keys.len()
    }
}

struct ForeignArrayBackend {
    node: ForeignNode,
}

impl ArrayBackend for ForeignArrayBackend {
    fn get_value(&self, index: usize) -> Option<Value> {
        self.node.get_element(index)
    }

    fn len(&self) -> usize {
        self.node.len()
    }
}

/// Opaque immutable foreign input handle.
///
/// The handle owns one shared `Arc<CtxOwner>` containing the copied vtable and
/// root caller handle. Calls to `regorus_engine_set_input_foreign_value` and
/// `regorus_rvm_set_input_foreign_value` do NOT share a root `Value`; each call
/// builds a fresh per-engine/VM wrapper with distinct materialization-cache cells
/// layered over the shared owner. Dropping this handle releases one owner
/// reference; the caller's `free(ctx)` fires exactly once when the last view also
/// drops. The caller must publish the immutable object graph before sharing this
/// handle with worker threads.
pub struct RegorusForeignInput {
    owner: Arc<CtxOwner>,
}

/// Construct a shared immutable foreign input owner from a recursive vtable.
///
/// The vtable is copied by value. The caller must keep the object graph
/// reachable through `root.ctx` immutable and safely published before this
/// returned handle is shared across threads. The callbacks may be called
/// concurrently with the same contexts by independent VM views.
#[no_mangle]
pub extern "C" fn regorus_foreign_input_new(root: *const RegorusForeignValue) -> RegorusResult {
    with_unwind_guard(|| {
        let output = || -> Result<*mut RegorusForeignInput> {
            if root.is_null() {
                bail!("null foreign value pointer");
            }
            let vtable = unsafe { *root };
            if vtable.ctx.is_null() {
                bail!("null foreign root ctx");
            }
            match vtable.kind {
                TAG_OBJECT | TAG_ARRAY => {}
                other => bail!("invalid foreign root kind {other}; expected 7=object or 8=array"),
            }
            Ok(Box::into_raw(Box::new(RegorusForeignInput {
                owner: Arc::new(CtxOwner { vtable }),
            })))
        }();

        match output {
            Ok(input) => RegorusResult::ok_pointer(input as *mut c_void),
            Err(err) => RegorusResult::err_with_message(RegorusStatus::InvalidArgument, err.to_string()),
        }
    })
}

/// Drop a foreign input handle.
///
/// This does not necessarily call the vtable's `free(ctx)` immediately: any
/// engine/VM that has attached the input owns a per-view wrapper holding the
/// shared owner alive. `free(ctx)` runs exactly once after this handle and all
/// per-view wrappers have been dropped.
#[no_mangle]
pub extern "C" fn regorus_foreign_input_drop(input: *mut RegorusForeignInput) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            if input.is_null() {
                return Ok(());
            }
            unsafe {
                let _ = Box::from_raw(input);
            }
            Ok(())
        }())
    })
}

fn input_to_value(input: *const RegorusForeignInput) -> Result<Value> {
    if input.is_null() {
        bail!("null foreign input pointer");
    }
    let input = unsafe { &*input };
    ForeignNode::root_value(input.owner.clone())
}

/// Set an engine input to a foreign value.
///
/// This attaches a new per-engine view over the shared immutable owner. The view
/// has its own materialization caches, so a force-materializing policy affects
/// only this engine's current input wrapper and not other threads/VMs.
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_foreign_value(
    engine: *mut RegorusEngine,
    input: *const RegorusForeignInput,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let value = input_to_value(input)?;
            let engine = to_ref(engine)?;
            let mut guard = engine.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}

/// Set an RVM input to a foreign value.
///
/// This attaches a new per-VM view over the shared immutable owner. The view has
/// its own materialization caches, so a force-materializing policy affects only
/// this VM's current input wrapper and not other threads/VMs.
#[cfg(feature = "rvm")]
#[no_mangle]
pub extern "C" fn regorus_rvm_set_input_foreign_value(
    vm: *mut crate::rvm::RegorusRvm,
    input: *const RegorusForeignInput,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let value = input_to_value(input)?;
            let vm = to_ref(vm)?;
            let mut guard = vm.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;

    struct TestRoot {
        rows: Vec<u64>,
        frees: AtomicUsize,
        element_fetches: AtomicUsize,
    }

    static ROOT_PTR: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const ROOT_CTX: usize = 1;
    const ARRAY_CTX: usize = 2;
    const ELEMENT_BASE: usize = 1024;

    fn root() -> &'static TestRoot {
        unsafe { &*(ROOT_PTR.load(Ordering::Acquire) as *const TestRoot) }
    }

    extern "C" fn len_cb(ctx: *mut c_void) -> usize {
        if ctx as usize == ARRAY_CTX {
            root().rows.len()
        } else {
            0
        }
    }

    extern "C" fn keys_cb(ctx: *mut c_void, out: *mut *const c_char, out_len: *mut usize) {
        static VALUES: &[u8] = b"Values\0";
        static V: &[u8] = b"v\0";
        unsafe {
            if ctx as usize == ROOT_CTX {
                *out = VALUES.as_ptr() as *const c_char;
            } else {
                *out = V.as_ptr() as *const c_char;
            }
            *out_len = 1;
        }
    }

    extern "C" fn get_field_cb(
        ctx: *mut c_void,
        key: *const c_char,
        out: *mut RegorusForeignField,
    ) {
        unsafe {
            *out = RegorusForeignField::empty();
            let key = CStr::from_ptr(key).to_bytes();
            match (ctx as usize, key) {
                (ROOT_CTX, b"Values") => {
                    (*out).tag = TAG_ARRAY;
                    (*out).child_ctx = ARRAY_CTX as *mut c_void;
                }
                (n, b"v") if n >= ELEMENT_BASE => {
                    (*out).tag = TAG_U64;
                    (*out).u = root().rows[n - ELEMENT_BASE];
                }
                _ => {}
            }
        }
    }

    extern "C" fn get_element_cb(
        ctx: *mut c_void,
        index: usize,
        out: *mut RegorusForeignField,
    ) {
        unsafe {
            *out = RegorusForeignField::empty();
            if ctx as usize == ARRAY_CTX && index < root().rows.len() {
                root().element_fetches.fetch_add(1, Ordering::SeqCst);
                (*out).tag = TAG_OBJECT;
                (*out).child_ctx = (ELEMENT_BASE + index) as *mut c_void;
            }
        }
    }

    extern "C" fn free_cb(_ctx: *mut c_void) {
        root().frees.fetch_add(1, Ordering::SeqCst);
    }

    fn count_enabled(value: Value) -> usize {
        let Value::Object(map) = value else {
            panic!("root object")
        };
        let values = map
            .get_owned(&Value::String(ForeignArcStr::from("Values")))
            .unwrap();
        let Value::Array(arr) = values else {
            panic!("values array")
        };
        (0..arr.len())
            .filter(|&i| match arr.element(i).unwrap() {
                Value::Object(obj) => matches!(
                    obj.get_owned(&Value::String(ForeignArcStr::from("v"))),
                    Some(Value::UInt(1))
                ),
                _ => false,
            })
            .count()
    }

    fn force_materialize_and_count(value: Value) -> usize {
        let Value::Object(map) = value else {
            panic!("root object")
        };
        let values = map
            .get_owned(&Value::String(ForeignArcStr::from("Values")))
            .unwrap();
        let Value::Array(arr) = values else {
            panic!("values array")
        };
        arr.as_slice()
            .iter()
            .filter(|v| match v {
                Value::Object(obj) => matches!(
                    obj.get_owned(&Value::String(ForeignArcStr::from("v"))),
                    Some(Value::UInt(1))
                ),
                _ => false,
            })
            .count()
    }

    #[test]
    fn shared_owner_supports_concurrent_read_views() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = Box::leak(Box::new(TestRoot {
            rows: (0..256).map(|i| (i % 4) as u64).collect(),
            frees: AtomicUsize::new(0),
            element_fetches: AtomicUsize::new(0),
        }));
        ROOT_PTR.store(root as *const TestRoot as usize, Ordering::Release);
        let owner = Arc::new(CtxOwner {
            vtable: RegorusForeignValue {
                ctx: ROOT_CTX as *mut c_void,
                kind: TAG_OBJECT,
                len: len_cb,
                get_field: get_field_cb,
                keys: keys_cb,
                get_element: get_element_cb,
                free: free_cb,
            },
        });
        let expected = count_enabled(ForeignNode::root_value(owner.clone()).unwrap());

        let mut threads = Vec::new();
        for _ in 0..16 {
            let owner = owner.clone();
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let got = count_enabled(ForeignNode::root_value(owner.clone()).unwrap());
                    assert_eq!(got, expected);
                }
            }));
        }
        for t in threads {
            t.join().unwrap();
        }
        drop(owner);
        assert_eq!(root.frees.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn force_materialization_is_per_view_under_concurrency() {
        let _guard = TEST_LOCK.lock().unwrap();
        let root = Box::leak(Box::new(TestRoot {
            rows: (0..128).map(|i| (i % 4) as u64).collect(),
            frees: AtomicUsize::new(0),
            element_fetches: AtomicUsize::new(0),
        }));
        ROOT_PTR.store(root as *const TestRoot as usize, Ordering::Release);
        let owner = Arc::new(CtxOwner {
            vtable: RegorusForeignValue {
                ctx: ROOT_CTX as *mut c_void,
                kind: TAG_OBJECT,
                len: len_cb,
                get_field: get_field_cb,
                keys: keys_cb,
                get_element: get_element_cb,
                free: free_cb,
            },
        });
        let expected = force_materialize_and_count(ForeignNode::root_value(owner.clone()).unwrap());

        let threads = 16;
        let iters = 25;
        let mut workers = Vec::new();
        for _ in 0..threads {
            let owner = owner.clone();
            workers.push(thread::spawn(move || {
                for _ in 0..iters {
                    let got =
                        force_materialize_and_count(ForeignNode::root_value(owner.clone()).unwrap());
                    assert_eq!(got, expected);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let expected_fetches = root.rows.len() * (1 + threads * iters);
        assert_eq!(
            root.element_fetches.load(Ordering::SeqCst),
            expected_fetches,
            "each per-VM wrapper must materialize independently; a shared OnceLock would undercount"
        );
        drop(owner);
        assert_eq!(root.frees.load(Ordering::SeqCst), 1);
    }
}