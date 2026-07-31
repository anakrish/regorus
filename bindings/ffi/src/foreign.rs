// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Foreign read-through value backend FFI.
//!
//! This is the cross-language half of the "foreign value backend" work: instead
//! of marshalling a whole input document (JSON/MessagePack) across the FFI
//! boundary and letting regorus parse an owned copy, the caller (e.g. C#) hands
//! regorus a small C-ABI vtable that reads individual fields on demand. regorus
//! holds no parsed copy of the array; it calls back through the vtable only as
//! the evaluated policy touches elements/fields.
//!
//! The array is exposed to regorus as a foreign-backed `Value::Array` whose
//! elements are foreign-backed `Value::Object`s (schema = the keys reported by
//! `keys`). To mirror the JSON/MessagePack document shape (`SegmentedResult`),
//! the array is wrapped as `{"Values": <foreign array>, "ContinuationToken":
//! null}` so `input.Values[_]` resolves identically across all three paths.

use crate::common::{to_ref, to_regorus_result, RegorusResult};
use crate::engine::RegorusEngine;
use crate::panic_guard::with_unwind_guard;
use alloc::ffi::CString;
use alloc::vec::Vec;
use anyhow::{bail, Result};
use core::ffi::{c_char, c_void, CStr};
use regorus::{
    ArrayBackend, ForeignArcStr, ObjectBackend, Rc, Value, ValueArray as Array, ValueMap,
};

/// A single field value produced by the C# side per field access.
///
/// The caller fills exactly one payload slot as indicated by `tag`. Strings are
/// borrowed UTF-8 (`str_ptr`/`str_len`); regorus copies them into an interned
/// `ArcStr` synchronously inside `get_value`, so the caller may reuse the buffer
/// after the call returns.
#[repr(C)]
pub struct RegorusForeignField {
    /// 0=undefined/absent, 1=null, 2=bool, 3=i64, 4=u64, 5=f64, 6=string.
    pub tag: u8,
    pub b: bool,
    pub i: i64,
    pub u: u64,
    pub f: f64,
    /// Borrowed UTF-8 bytes (valid only for the duration of the call). Copied.
    pub str_ptr: *const u8,
    pub str_len: usize,
}

impl RegorusForeignField {
    fn empty() -> Self {
        RegorusForeignField {
            tag: 0,
            b: false,
            i: 0,
            u: 0,
            f: 0.0,
            str_ptr: core::ptr::null(),
            str_len: 0,
        }
    }

    /// Translate the caller-filled field into a regorus `Value`. String bytes are
    /// copied into an `ArcStr` here (synchronous), so the caller's buffer need
    /// only outlive this call.
    unsafe fn to_value(&self) -> Value {
        match self.tag {
            1 => Value::Null,
            2 => Value::Bool(self.b),
            3 => Value::Int(self.i),
            4 => Value::UInt(self.u),
            5 => Value::Float(self.f),
            6 => {
                if self.str_ptr.is_null() {
                    return Value::String(ForeignArcStr::from(""));
                }
                let bytes = core::slice::from_raw_parts(self.str_ptr, self.str_len);
                match core::str::from_utf8(bytes) {
                    Ok(s) => Value::String(ForeignArcStr::from(s)),
                    Err(_) => Value::Undefined,
                }
            }
            // 0 (undefined/absent) and anything unexpected.
            _ => Value::Undefined,
        }
    }
}

/// C-ABI vtable describing a foreign array of objects. Passed by pointer; the
/// contents (ctx handle + function pointers) are copied by value into an owned
/// [`ForeignCtx`] so the caller's struct need only outlive the constructor call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RegorusForeignArray {
    /// Opaque handle to the caller object (e.g. a pinned C# GCHandle).
    pub ctx: *mut c_void,
    /// Number of elements in the array.
    pub len: extern "C" fn(ctx: *mut c_void) -> usize,
    /// Materialize element `index`'s field `key` into `out`.
    pub get_field: extern "C" fn(
        ctx: *mut c_void,
        index: usize,
        key: *const c_char,
        out: *mut RegorusForeignField,
    ),
    /// Report the schema keys: writes up to the buffer's capacity of NUL-
    /// terminated C-string pointers into `out_ptrs`, and the count into `out_len`.
    pub keys: extern "C" fn(ctx: *mut c_void, out_ptrs: *mut *const c_char, out_len: *mut usize),
    /// Release the caller handle. Called exactly once when regorus drops the
    /// input (on the next `set_input` or when the engine/vm is dropped).
    pub free: extern "C" fn(ctx: *mut c_void),
}

/// Owned copy of the vtable plus the materialized schema keys. Shared (via `Rc`)
/// by the array backend and every per-element object backend, so the C# handle
/// is freed exactly once (on last drop).
struct ForeignCtx {
    vtable: RegorusForeignArray,
    /// Schema keys as interned strings (returned by `ObjectBackend::keys`).
    keys: Vec<ForeignArcStr>,
    /// Parallel NUL-terminated copies handed back to `get_field` so the caller
    /// receives a stable pointer without a per-access allocation on our side.
    key_cstrings: Vec<CString>,
}

// SAFETY: the vtable holds raw pointers (an opaque handle + C function pointers).
// The foreign backend is only ever driven from the single thread that set the
// input; regorus wraps it in `Rc`/`Arc` whose `Send + Sync` bounds we satisfy
// here. The caller owns thread-safety of the underlying object.
unsafe impl Send for ForeignCtx {}
unsafe impl Sync for ForeignCtx {}

impl ForeignCtx {
    unsafe fn new(vtable: RegorusForeignArray) -> Result<Rc<Self>> {
        // Read the schema keys once. 64 slots is far above the 6-field schema.
        const MAX_KEYS: usize = 64;
        let mut ptr_buf: [*const c_char; MAX_KEYS] = [core::ptr::null(); MAX_KEYS];
        let mut out_len: usize = 0;
        (vtable.keys)(vtable.ctx, ptr_buf.as_mut_ptr(), &mut out_len as *mut usize);
        if out_len > MAX_KEYS {
            bail!("foreign backend reported {out_len} keys (max {MAX_KEYS})");
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
        Ok(Rc::new(ForeignCtx {
            vtable,
            keys,
            key_cstrings,
        }))
    }

    #[inline]
    fn len(&self) -> usize {
        (self.vtable.len)(self.vtable.ctx)
    }

    /// Read `key` of element `index` through the vtable and convert to a `Value`.
    fn get_field(&self, index: usize, key: &str) -> Option<Value> {
        // Resolve to the stable NUL-terminated key pointer (linear over 6 keys).
        let key_ptr = self
            .keys
            .iter()
            .position(|k| k.as_str() == key)
            .map(|i| self.key_cstrings[i].as_ptr())?;
        let mut out = RegorusForeignField::empty();
        (self.vtable.get_field)(self.vtable.ctx, index, key_ptr, &mut out as *mut _);
        let v = unsafe { out.to_value() };
        if v.is_undefined() {
            None
        } else {
            Some(v)
        }
    }
}

impl Drop for ForeignCtx {
    fn drop(&mut self) {
        (self.vtable.free)(self.vtable.ctx);
    }
}

/// Per-element object view: `input.Values[index]` as a read-through object.
struct ForeignObjectBackend {
    shared: Rc<ForeignCtx>,
    index: usize,
}

impl ObjectBackend for ForeignObjectBackend {
    fn get_value(&self, key: &str) -> Option<Value> {
        self.shared.get_field(self.index, key)
    }

    fn keys(&self) -> &[ForeignArcStr] {
        &self.shared.keys
    }

    fn len(&self) -> usize {
        self.shared.keys.len()
    }
}

/// The foreign array backend: hands out per-element object views on demand.
struct ForeignArrayBackend {
    shared: Rc<ForeignCtx>,
}

impl ArrayBackend for ForeignArrayBackend {
    fn get_value(&self, index: usize) -> Option<Value> {
        if index >= self.shared.len() {
            return None;
        }
        let backend: Rc<dyn ObjectBackend> = Rc::new(ForeignObjectBackend {
            shared: self.shared.clone(),
            index,
        });
        Some(Value::Object(Rc::new(ValueMap::from_object_backend(
            backend,
        ))))
    }

    fn len(&self) -> usize {
        self.shared.len()
    }
}

/// Build the foreign input `Value` document `{"Values": <foreign array>,
/// "ContinuationToken": null}` from a caller-provided vtable pointer.
unsafe fn build_foreign_input(arr: *const RegorusForeignArray) -> Result<Value> {
    if arr.is_null() {
        bail!("null foreign array pointer");
    }
    let vtable = *arr; // copy ctx + fn pointers; we own the handle from here.
    let shared = ForeignCtx::new(vtable)?;
    let backend: Rc<dyn ArrayBackend> = Rc::new(ForeignArrayBackend { shared });
    let values = Value::Array(Rc::new(Array::from_backend(backend)));

    let mut doc = ValueMap::new();
    doc.insert(Value::String(ForeignArcStr::from("Values")), values);
    doc.insert(
        Value::String(ForeignArcStr::from("ContinuationToken")),
        Value::Null,
    );
    Ok(Value::Object(Rc::new(doc)))
}

/// Set the engine input to a foreign read-through document.
///
/// `foreign` points to a [`RegorusForeignArray`] vtable. The vtable contents are
/// copied; the caller must keep the underlying object (referenced by `ctx`)
/// alive until the `free` callback fires (on the next `set_input` or on engine
/// drop). No bulk copy of the array is made — fields are read on demand during
/// evaluation.
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_foreign(
    engine: *mut RegorusEngine,
    foreign: *const RegorusForeignArray,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let engine = to_ref(engine)?;
            let value = unsafe { build_foreign_input(foreign)? };
            let mut guard = engine.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}

/// RVM variant of [`regorus_engine_set_input_foreign`].
#[cfg(feature = "rvm")]
#[no_mangle]
pub extern "C" fn regorus_rvm_set_input_foreign(
    vm: *mut crate::rvm::RegorusRvm,
    foreign: *const RegorusForeignArray,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let vm = to_ref(vm)?;
            let value = unsafe { build_foreign_input(foreign)? };
            let mut guard = vm.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}

// ─────────────────────────────────────────────────────────────────────────────
//  Rust-native foreign proxy (NO FFI crossing) — bench baseline
// ─────────────────────────────────────────────────────────────────────────────
//
// Same foreign ArrayBackend/ObjectBackend machinery as the C# path, but the
// data lives in a Rust `Vec<NativeBenchSub>` and `get_value` reads straight from
// it — no callback, no GCHandle, no managed↔native transition. This isolates the
// intrinsic foreign-backend dispatch cost (indirect trait calls + per-element
// Object materialization + per-field Value/ArcStr construction) from the pure
// FFI boundary cost. Field values/types mirror the C# DataGenerator exactly so
// the same scan.rego touches the same fields and yields the same counts.

/// One Rust-resident subscription record (mirrors the C# SubscriptionValue).
struct NativeBenchSub {
    id: [u8; 16],
    name: ForeignArcStr,
    state: u64,
    placement: ForeignArcStr,
    quota: ForeignArcStr,
    spending: u64,
}

/// Packed Rust-resident array + shared schema keys.
struct NativeBenchArray {
    subs: Vec<NativeBenchSub>,
    keys: Vec<ForeignArcStr>,
}

fn format_guid_bench(id: &[u8; 16]) -> ForeignArcStr {
    // Fast manual hex encode into a fixed 36-byte buffer (8-4-4-4-12 layout).
    // Avoids the fmt machinery so this baseline reflects foreign-dispatch cost,
    // not formatting overhead (mirrors C# Guid.TryFormat + memcpy on the FFI path).
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 36];
    let mut b = 0usize; // byte index into id
    let mut o = 0usize; // out index
    for &pos in &[8usize, 4, 4, 4, 12] {
        for _ in 0..(pos / 2) {
            let byte = id[b];
            buf[o] = HEX[(byte >> 4) as usize];
            buf[o + 1] = HEX[(byte & 0x0f) as usize];
            b += 1;
            o += 2;
        }
        if o < 36 {
            buf[o] = b'-';
            o += 1;
        }
    }
    // buf is guaranteed valid ASCII/UTF-8.
    let s = unsafe { core::str::from_utf8_unchecked(&buf) };
    ForeignArcStr::from(s)
}

impl NativeBenchArray {
    fn generate(n: usize) -> Rc<Self> {
        // Mirror FASTERBenchmarks.DataGenerator: State cycles Enabled(1)/Warned(2)/
        // PastDue(3)/Disabled(4); SpendingLimit cycles On(0)/Off(1)/CurrentPeriodOff(2).
        let states = [1u64, 2, 3, 4];
        let limits = [0u64, 1, 2];
        let keys: Vec<ForeignArcStr> = ["i", "n", "s", "p", "q", "l"]
            .iter()
            .map(|s| ForeignArcStr::from(*s))
            .collect();
        let mut subs = Vec::with_capacity(n);
        for i in 0..n {
            let mut id = [0u8; 16];
            id[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            id[8] = 0x11;
            id[9] = 0x22;
            id[10] = 0x33;
            id[11] = 0x44;
            id[12] = 0x55;
            id[13] = 0x66;
            id[14] = 0x77;
            id[15] = 0x88;
            subs.push(NativeBenchSub {
                id,
                name: ForeignArcStr::from(alloc::format!("Subscription-{i:07}")),
                state: states[i % 4],
                placement: ForeignArcStr::from(alloc::format!("West US {}", i % 5)),
                quota: ForeignArcStr::from(alloc::format!("PayAsYouGo_2014-09-01_{:02}", i % 12)),
                spending: limits[i % 3],
            });
        }
        Rc::new(NativeBenchArray { subs, keys })
    }
}

/// Per-element object view over a Rust-resident record (no FFI).
struct NativeBenchObject {
    arr: Rc<NativeBenchArray>,
    index: usize,
}

impl ObjectBackend for NativeBenchObject {
    fn get_value(&self, key: &str) -> Option<Value> {
        let sub = self.arr.subs.get(self.index)?;
        match key {
            "i" => Some(Value::String(format_guid_bench(&sub.id))),
            "n" => Some(Value::String(sub.name.clone())),
            "s" => Some(Value::UInt(sub.state)),
            "p" => Some(Value::String(sub.placement.clone())),
            "q" => Some(Value::String(sub.quota.clone())),
            "l" => Some(Value::UInt(sub.spending)),
            _ => None,
        }
    }

    fn keys(&self) -> &[ForeignArcStr] {
        &self.arr.keys
    }

    fn len(&self) -> usize {
        self.arr.keys.len()
    }
}

struct NativeBenchArrayBackend {
    arr: Rc<NativeBenchArray>,
}

impl ArrayBackend for NativeBenchArrayBackend {
    fn get_value(&self, index: usize) -> Option<Value> {
        if index >= self.arr.subs.len() {
            return None;
        }
        let backend: Rc<dyn ObjectBackend> = Rc::new(NativeBenchObject {
            arr: self.arr.clone(),
            index,
        });
        Some(Value::Object(Rc::new(ValueMap::from_object_backend(
            backend,
        ))))
    }

    fn len(&self) -> usize {
        self.arr.subs.len()
    }
}

fn build_native_input(n: usize) -> Value {
    let arr = NativeBenchArray::generate(n);
    let backend: Rc<dyn ArrayBackend> = Rc::new(NativeBenchArrayBackend { arr });
    let values = Value::Array(Rc::new(Array::from_backend(backend)));

    let mut doc = ValueMap::new();
    doc.insert(Value::String(ForeignArcStr::from("Values")), values);
    doc.insert(
        Value::String(ForeignArcStr::from("ContinuationToken")),
        Value::Null,
    );
    Value::Object(Rc::new(doc))
}

/// Bench-only: set the engine input to a Rust-resident foreign proxy of `n`
/// subscriptions. Identical foreign-backend machinery to the C# path but the
/// data lives in Rust and `get_value` reads it directly — NO managed↔native
/// crossing. Used to isolate foreign-dispatch overhead from FFI-boundary cost.
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_foreign_native(
    engine: *mut RegorusEngine,
    n: usize,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let engine = to_ref(engine)?;
            let value = build_native_input(n);
            let mut guard = engine.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}

/// RVM variant of [`regorus_engine_set_input_foreign_native`]. Bench-only:
/// set the RVM input to a Rust-resident foreign proxy of `n` subscriptions
/// (no FFI crossing).
#[cfg(feature = "rvm")]
#[no_mangle]
pub extern "C" fn regorus_rvm_set_input_foreign_native(
    vm: *mut crate::rvm::RegorusRvm,
    n: usize,
) -> RegorusResult {
    with_unwind_guard(|| {
        to_regorus_result(|| -> Result<()> {
            let vm = to_ref(vm)?;
            let value = build_native_input(n);
            let mut guard = vm.try_write()?;
            guard.set_input(value);
            Ok(())
        }())
    })
}
