// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{c_char, c_void, CString};
use std::sync::Arc;
use regorus::Value;
use regorus::lazy::{LazyObject, LazyContext, ContextValue, TypeId};
use anyhow::{anyhow, Result};

use crate::common::{from_c_str, RegorusResult, RegorusStatus, RegorusPointerType};
use crate::engine::RegorusEngine;

// Helper to convert Value pointer
fn to_value_ref<'a>(ptr: *mut c_void) -> Result<&'a Value> {
    if ptr.is_null() {
        return Err(anyhow!("Null value pointer"));
    }
    Ok(unsafe { &*(ptr as *mut Value) })
}

fn to_value_mut<'a>(ptr: *mut c_void) -> Result<&'a mut Value> {
    if ptr.is_null() {
        return Err(anyhow!("Null value pointer"));
    }
    Ok(unsafe { &mut *(ptr as *mut Value) })
}

// Creation functions
#[no_mangle]
pub extern "C" fn regorus_value_create_null() -> RegorusResult {
    let value = Box::new(Value::Null);
    RegorusResult::ok_pointer(Box::into_raw(value) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_undefined() -> RegorusResult {
    let value = Box::new(Value::Undefined);
    RegorusResult::ok_pointer(Box::into_raw(value) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_bool(value: bool) -> RegorusResult {
    let val = Box::new(Value::Bool(value));
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_int(value: i64) -> RegorusResult {
    let val = Box::new(Value::from(value));
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_float(value: f64) -> RegorusResult {
    let val = Box::new(Value::from(value));
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_string(s: *const c_char) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        let s = from_c_str(s)?;
        let val = Box::new(Value::from(s.as_str()));
        Ok(Box::into_raw(val) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_create_array() -> RegorusResult {
    let val = Box::new(Value::new_array());
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_object() -> RegorusResult {
    let val = Box::new(Value::new_object());
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

#[no_mangle]
pub extern "C" fn regorus_value_create_set() -> RegorusResult {
    let val = Box::new(Value::new_set());
    RegorusResult::ok_pointer(Box::into_raw(val) as *mut c_void, RegorusPointerType::PointerValue)
}

// JSON serialization
#[no_mangle]
pub extern "C" fn regorus_value_from_json(json: *const c_char) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        let json_str = from_c_str(json)?;
        let val = Box::new(Value::from_json_str(&json_str)?);
        Ok(Box::into_raw(val) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_to_json(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<String> {
        let val = to_value_ref(value)?;
        val.to_json_str()
    }();
    
    match result {
        Ok(s) => {
            let c_str = CString::new(s).unwrap();
            RegorusResult::ok_string_raw(c_str.into_raw())
        }
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Type checking
#[no_mangle]
pub extern "C" fn regorus_value_is_null(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<bool> {
        let val = to_value_ref(value)?;
        Ok(matches!(val, Value::Null))
    }();
    
    match result {
        Ok(b) => RegorusResult::ok_bool(b),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_is_object(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<bool> {
        let val = to_value_ref(value)?;
        Ok(matches!(val, Value::Object(_)))
    }();
    
    match result {
        Ok(b) => RegorusResult::ok_bool(b),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_is_lazy_object(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<bool> {
        let val = to_value_ref(value)?;
        Ok(matches!(val, Value::LazyObject(_)))
    }();
    
    match result {
        Ok(b) => RegorusResult::ok_bool(b),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_is_string(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<bool> {
        let val = to_value_ref(value)?;
        Ok(matches!(val, Value::String(_)))
    }();
    
    match result {
        Ok(b) => RegorusResult::ok_bool(b),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Typed value accessors
/// Get boolean value
#[no_mangle]
pub extern "C" fn regorus_value_as_bool(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<bool> {
        let val = to_value_ref(value)?;
        Ok(*val.as_bool()?)
    }();
    
    match result {
        Ok(b) => RegorusResult::ok_bool(b),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Get integer value
#[no_mangle]
pub extern "C" fn regorus_value_as_i64(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<i64> {
        let val = to_value_ref(value)?;
        val.as_i64()
    }();
    
    match result {
        Ok(i) => RegorusResult::ok_int(i),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Get string value (returns owned copy)
#[no_mangle]
pub extern "C" fn regorus_value_as_string(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<String> {
        let val = to_value_ref(value)?;
        Ok(val.as_string()?.to_string())
    }();
    
    match result {
        Ok(s) => RegorusResult::ok_string(s),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Object operations
#[no_mangle]
pub extern "C" fn regorus_value_object_insert(
    object: *mut c_void,
    key: *const c_char,
    value: *mut c_void,
) -> RegorusResult {
    let result = || -> Result<()> {
        let obj = to_value_mut(object)?;
        let key_str = from_c_str(key)?;
        let val = unsafe { Box::from_raw(value as *mut Value) };
        
        obj.as_object_mut()?
            .insert(Value::from(key_str.as_str()), *val);
        
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_value_object_get(
    object: *mut c_void,
    key: *const c_char,
) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        let obj = to_value_ref(object)?;
        let key_str = from_c_str(key)?;
        
        let map = obj.as_object()?;
        let key_val = Value::from(key_str.as_str());
        
        if let Some(val) = map.get(&key_val) {
            let cloned = Box::new(val.clone());
            Ok(Box::into_raw(cloned) as *mut c_void)
        } else {
            Err(anyhow!("Key not found: {}", key_str))
        }
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Array operations
/// Get the length of an array
#[no_mangle]
pub extern "C" fn regorus_value_array_len(array: *mut c_void) -> RegorusResult {
    let result = || -> Result<i64> {
        let arr = to_value_ref(array)?;
        let array_ref = arr.as_array()?;
        Ok(array_ref.len() as i64)
    }();
    
    match result {
        Ok(len) => RegorusResult::ok_int(len),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Get an element from an array by index
#[no_mangle]
pub extern "C" fn regorus_value_array_get(
    array: *mut c_void,
    index: i64,
) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        let arr = to_value_ref(array)?;
        let array_ref = arr.as_array()?;
        
        if index < 0 || index >= array_ref.len() as i64 {
            return Err(anyhow!("Index out of bounds: {}", index));
        }
        
        let val = &array_ref[index as usize];
        let cloned = Box::new(val.clone());
        Ok(Box::into_raw(cloned) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Memory management
#[no_mangle]
pub extern "C" fn regorus_value_drop(value: *mut c_void) {
    if !value.is_null() {
        unsafe {
            let _ = Box::from_raw(value as *mut Value);
        }
    }
}

/// Clone a Value
#[no_mangle]
pub extern "C" fn regorus_value_clone(value: *mut c_void) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        if value.is_null() {
            return Err(anyhow!("Null value pointer"));
        }
        
        let val_ref = unsafe { &*(value as *mut Value) };
        let cloned = Box::new(val_ref.clone());
        Ok(Box::into_raw(cloned) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Engine integration - Input/Data
#[no_mangle]
pub extern "C" fn regorus_engine_set_input_value(
    engine: *mut RegorusEngine,
    value: *mut c_void,
) -> RegorusResult {
    let result = || -> Result<()> {
        if engine.is_null() {
            return Err(anyhow!("Null engine pointer"));
        }
        
        let engine_ref = unsafe { &mut *engine };
        let val = unsafe { Box::from_raw(value as *mut Value) };
        
        engine_ref.engine.set_input(*val);
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_add_data_value(
    engine: *mut RegorusEngine,
    value: *mut c_void,
) -> RegorusResult {
    let result = || -> Result<()> {
        if engine.is_null() {
            return Err(anyhow!("Null engine pointer"));
        }
        
        let engine_ref = unsafe { &mut *engine };
        let val = unsafe { Box::from_raw(value as *mut Value) };
        
        engine_ref.engine.add_data(*val)?;
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// Engine integration - Eval (returns Value instead of JSON)
#[no_mangle]
pub extern "C" fn regorus_engine_eval_query_as_value(
    engine: *mut RegorusEngine,
    query: *const c_char,
) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        if engine.is_null() {
            return Err(anyhow!("Null engine pointer"));
        }
        
        let engine_ref = unsafe { &mut *engine };
        let query_str = from_c_str(query)?;
        
        // Convert QueryResults to Value by directly extracting values (no JSON conversion)
        let results = engine_ref.engine.eval_query(query_str, false)?;
        
        // Create a Value array to hold all result expressions
        let mut result_array = Vec::new();
        for result in results.result {
            let mut expr_array = Vec::new();
            for expr in result.expressions {
                expr_array.push(expr.value);
            }
            result_array.push(Value::from(expr_array));
        }
        
        let value = Box::new(Value::from(result_array));
        
        Ok(Box::into_raw(value) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

#[no_mangle]
pub extern "C" fn regorus_engine_eval_rule_as_value(
    engine: *mut RegorusEngine,
    rule: *const c_char,
) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        if engine.is_null() {
            return Err(anyhow!("Null engine pointer"));
        }
        
        let engine_ref = unsafe { &mut *engine };
        let rule_str = from_c_str(rule)?;
        
        let value = Box::new(engine_ref.engine.eval_rule(rule_str)?);
        Ok(Box::into_raw(value) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// ============================================================================
// TypeId FFI Functions
// ============================================================================

/// Creates a TypeId from a string name.
/// 
/// # Parameters
/// * `name` - C string representing the type identifier
/// 
/// # Returns
/// RegorusResult containing pointer to TypeId on success
#[no_mangle]
pub extern "C" fn regorus_typeid_create(name: *const c_char) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        let name_str = from_c_str(name)?;
        let type_id = TypeId::from(name_str);
        Ok(Box::into_raw(Box::new(type_id)) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerTypeId),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Frees a TypeId.
/// 
/// # Parameters
/// * `type_id` - Pointer to TypeId to free
#[no_mangle]
pub extern "C" fn regorus_typeid_drop(type_id: *mut c_void) {
    if !type_id.is_null() {
        unsafe {
            let _ = Box::from_raw(type_id as *mut TypeId);
        }
    }
}

// ============================================================================
// LazyContext FFI Functions
// ============================================================================

/// Creates an empty LazyContext.
/// 
/// # Returns
/// RegorusResult containing pointer to LazyContext on success
#[no_mangle]
pub extern "C" fn regorus_lazy_context_create() -> RegorusResult {
    let context = LazyContext::new();
    let ptr = Box::into_raw(Box::new(context)) as *mut c_void;
    RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerLazyContext)
}

/// Inserts a u64 value into a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// * `value` - u64 value to insert
#[no_mangle]
pub extern "C" fn regorus_lazy_context_insert_u64(
    context: *mut c_void,
    key: *const c_char,
    value: u64,
) -> RegorusResult {
    let result = || -> Result<()> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let context_ref = unsafe { &mut *(context as *mut LazyContext) };
        let key_str = from_c_str(key)?;
        context_ref.insert(Arc::from(key_str), ContextValue::U64(value));
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Inserts an i64 value into a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// * `value` - i64 value to insert
#[no_mangle]
pub extern "C" fn regorus_lazy_context_insert_i64(
    context: *mut c_void,
    key: *const c_char,
    value: i64,
) -> RegorusResult {
    let result = || -> Result<()> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let context_ref = unsafe { &mut *(context as *mut LazyContext) };
        let key_str = from_c_str(key)?;
        context_ref.insert(Arc::from(key_str), ContextValue::I64(value));
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Inserts a string value into a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// * `value` - C string value to insert
#[no_mangle]
pub extern "C" fn regorus_lazy_context_insert_string(
    context: *mut c_void,
    key: *const c_char,
    value: *const c_char,
) -> RegorusResult {
    let result = || -> Result<()> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let context_ref = unsafe { &mut *(context as *mut LazyContext) };
        let key_str = from_c_str(key)?;
        let value_str = from_c_str(value)?;
        context_ref.insert(Arc::from(key_str), ContextValue::String(Arc::from(value_str)));
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Inserts a boolean value into a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// * `value` - Boolean value to insert (0 = false, non-zero = true)
#[no_mangle]
pub extern "C" fn regorus_lazy_context_insert_bool(
    context: *mut c_void,
    key: *const c_char,
    value: u8,
) -> RegorusResult {
    let result = || -> Result<()> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let context_ref = unsafe { &mut *(context as *mut LazyContext) };
        let key_str = from_c_str(key)?;
        context_ref.insert(Arc::from(key_str), ContextValue::Bool(value != 0));
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Inserts a byte array into a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// * `bytes` - Pointer to byte array
/// * `len` - Length of byte array
#[no_mangle]
pub extern "C" fn regorus_lazy_context_insert_bytes(
    context: *mut c_void,
    key: *const c_char,
    bytes: *const u8,
    len: usize,
) -> RegorusResult {
    let result = || -> Result<()> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        if bytes.is_null() && len > 0 {
            return Err(anyhow!("Null bytes pointer with non-zero length"));
        }
        
        let context_ref = unsafe { &mut *(context as *mut LazyContext) };
        let key_str = from_c_str(key)?;
        let byte_vec = unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec();
        context_ref.insert(Arc::from(key_str), ContextValue::Bytes(Arc::new(byte_vec)));
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Gets a u64 value from a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
/// 
/// # Returns
/// RegorusResult containing u64 value on success
#[no_mangle]
pub extern "C" fn regorus_lazy_context_get_u64(
    context: *mut c_void,
    key: *const c_char,
) -> RegorusResult {
    let result = || -> Result<u64> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let context_ref = unsafe { &*(context as *const LazyContext) };
        let key_str = from_c_str(key)?;
        
        match context_ref.get(&key_str) {
            Some(ContextValue::U64(value)) => Ok(*value),
            Some(_) => Err(anyhow!("Context value for key '{}' is not a u64", key_str)),
            None => Err(anyhow!("Key '{}' not found in context", key_str)),
        }
    }();
    
    match result {
        Ok(value) => RegorusResult::ok_u64(value),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Gets a string value from a LazyContext.
///
/// # Parameters
/// * `context` - Pointer to LazyContext
/// * `key` - C string key
///
/// # Returns
/// RegorusResult containing string value on success
#[no_mangle]
pub extern "C" fn regorus_lazy_context_get_string(
    context: *mut c_void,
    key: *const c_char,
) -> RegorusResult {
    let result = || -> Result<String> {
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }

        let context_ref = unsafe { &*(context as *const LazyContext) };
        let key_str = from_c_str(key)?;

        match context_ref.get(&key_str) {
            Some(ContextValue::String(value)) => Ok(value.as_ref().to_string()),
            Some(_) => Err(anyhow!("Context value for key '{}' is not a string", key_str)),
            None => Err(anyhow!("Key '{}' not found in context", key_str)),
        }
    }();

    match result {
        Ok(value) => RegorusResult::ok_string(value),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Frees a LazyContext.
/// 
/// # Parameters
/// * `context` - Pointer to LazyContext to free
#[no_mangle]
pub extern "C" fn regorus_lazy_context_drop(context: *mut c_void) {
    if !context.is_null() {
        unsafe {
            let _ = Box::from_raw(context as *mut LazyContext);
        }
    }
}

// ============================================================================
// LazyObject FFI Functions
// ============================================================================

/// Creates a LazyObject from a TypeId and LazyContext.
/// 
/// # Parameters
/// * `type_id` - Pointer to TypeId (ownership transferred)
/// * `context` - Pointer to LazyContext (ownership transferred)
/// 
/// # Returns
/// RegorusResult containing pointer to LazyObject on success
#[no_mangle]
pub extern "C" fn regorus_lazy_object_create(
    type_id: *mut c_void,
    context: *mut c_void,
) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        if type_id.is_null() {
            return Err(anyhow!("Null type_id pointer"));
        }
        if context.is_null() {
            return Err(anyhow!("Null context pointer"));
        }
        
        let type_id = unsafe { *Box::from_raw(type_id as *mut TypeId) };
        let context = unsafe { *Box::from_raw(context as *mut LazyContext) };
        
        let lazy_obj = LazyObject::new(type_id, context);
        Ok(Box::into_raw(Box::new(lazy_obj)) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerLazyObject),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Creates a Value containing a LazyObject.
/// 
/// # Parameters
/// * `lazy_object` - Pointer to LazyObject (ownership transferred)
/// 
/// # Returns
/// RegorusResult containing pointer to Value on success
#[no_mangle]
pub extern "C" fn regorus_value_from_lazy_object(lazy_object: *mut c_void) -> RegorusResult {
    let result = || -> Result<*mut c_void> {
        if lazy_object.is_null() {
            return Err(anyhow!("Null lazy_object pointer"));
        }
        
        let lazy_obj = unsafe { *Box::from_raw(lazy_object as *mut LazyObject) };
        let value = Box::new(Value::LazyObject(Arc::new(lazy_obj)));
        Ok(Box::into_raw(value) as *mut c_void)
    }();
    
    match result {
        Ok(ptr) => RegorusResult::ok_pointer(ptr, RegorusPointerType::PointerValue),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

/// Frees a LazyObject.
/// 
/// # Parameters
/// * `lazy_object` - Pointer to LazyObject to free
#[no_mangle]
pub extern "C" fn regorus_lazy_object_drop(lazy_object: *mut c_void) {
    if !lazy_object.is_null() {
        unsafe {
            let _ = Box::from_raw(lazy_object as *mut LazyObject);
        }
    }
}

// ============================================================================
// Schema Registration - Demo Schema
// ============================================================================

use regorus::lazy::{FieldGetter, SchemaBuilder};

/// Simple field getter that extracts a string from context
struct ContextStringGetter {
    field_name: Arc<str>,
}

impl FieldGetter for ContextStringGetter {
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        if let Some(ContextValue::String(s)) = ctx.get(&self.field_name) {
            Ok(Value::from(s.as_ref()))
        } else {
            Ok(Value::Null)
        }
    }
}

/// Simple field getter that extracts an i64 from context
struct ContextI64Getter {
    field_name: Arc<str>,
}

impl FieldGetter for ContextI64Getter {
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        match ctx.get_i64(&self.field_name) {
            Ok(i) => Ok(Value::from(i)),
            Err(_) => Ok(Value::Null)
        }
    }
}

/// Simple field getter that extracts a u64 from context
struct ContextU64Getter {
    field_name: Arc<str>,
}

impl FieldGetter for ContextU64Getter {
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        match ctx.get_u64(&self.field_name) {
            Ok(u) => Ok(Value::from(u)),
            Err(_) => Ok(Value::Null)
        }
    }
}

/// Simple field getter that extracts a bool from context
struct ContextBoolGetter {
    field_name: Arc<str>,
}

impl FieldGetter for ContextBoolGetter {
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        if let Some(ContextValue::Bool(b)) = ctx.get(&self.field_name) {
            Ok(Value::Bool(*b))
        } else {
            Ok(Value::Null)
        }
    }
}

/// Registers a simple schema that extracts fields from LazyContext.
/// This is a helper for FFI usage - fields are fetched from the context.
/// 
/// # Parameters
/// * `type_name` - C string name of the type
/// * `string_fields` - Array of C strings for string field names
/// * `string_fields_len` - Length of string_fields array
/// * `i64_fields` - Array of C strings for i64 field names
/// * `i64_fields_len` - Length of i64_fields array
#[no_mangle]
pub extern "C" fn regorus_register_context_schema(
    type_name: *const c_char,
    string_fields: *const *const c_char,
    string_fields_len: usize,
    i64_fields: *const *const c_char,
    i64_fields_len: usize,
    u64_fields: *const *const c_char,
    u64_fields_len: usize,
    bool_fields: *const *const c_char,
    bool_fields_len: usize,
) -> RegorusResult {
    let result = || -> Result<()> {
        let type_str = from_c_str(type_name)?;
        let mut builder = SchemaBuilder::new(type_str);
        
        // Add string fields
        if !string_fields.is_null() && string_fields_len > 0 {
            let fields_slice = unsafe { std::slice::from_raw_parts(string_fields, string_fields_len) };
            for &field_ptr in fields_slice {
                let field_name = from_c_str(field_ptr)?;
                let field_arc = Arc::from(field_name.as_str());
                builder = builder.field_immediate(
                    field_name.as_str(),
                    ContextStringGetter {
                        field_name: field_arc,
                    }
                );
            }
        }
        
        // Add i64 fields
        if !i64_fields.is_null() && i64_fields_len > 0 {
            let fields_slice = unsafe { std::slice::from_raw_parts(i64_fields, i64_fields_len) };
            for &field_ptr in fields_slice {
                let field_name = from_c_str(field_ptr)?;
                let field_arc = Arc::from(field_name.as_str());
                builder = builder.field_immediate(
                    field_name.as_str(),
                    ContextI64Getter {
                        field_name: field_arc,
                    }
                );
            }
        }
        
        // Add u64 fields
        if !u64_fields.is_null() && u64_fields_len > 0 {
            let fields_slice = unsafe { std::slice::from_raw_parts(u64_fields, u64_fields_len) };
            for &field_ptr in fields_slice {
                let field_name = from_c_str(field_ptr)?;
                let field_arc = Arc::from(field_name.as_str());
                builder = builder.field_immediate(
                    field_name.as_str(),
                    ContextU64Getter {
                        field_name: field_arc,
                    }
                );
            }
        }
        
        // Add bool fields
        if !bool_fields.is_null() && bool_fields_len > 0 {
            let fields_slice = unsafe { std::slice::from_raw_parts(bool_fields, bool_fields_len) };
            for &field_ptr in fields_slice {
                let field_name = from_c_str(field_ptr)?;
                let field_arc = Arc::from(field_name.as_str());
                builder = builder.field_immediate(
                    field_name.as_str(),
                    ContextBoolGetter {
                        field_name: field_arc,
                    }
                );
            }
        }
        
        builder.register();
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}

// ============================================================================
// Callback-based Field Getter for Complex Types
// ============================================================================

/// Callback function type for custom field getters.
/// Takes LazyContext pointer and returns a Value pointer (or null on error).
/// The caller owns the returned Value and must free it.
pub type FieldGetterCallback = extern "C" fn(ctx: *const c_void, field_name: *const c_char, user_data: *mut c_void) -> *mut c_void;

/// Field getter that uses a C callback
struct CallbackFieldGetter {
    field_name: Arc<str>,
    callback: FieldGetterCallback,
    user_data: *mut c_void,
}

// Safety: We assume the user_data pointer is thread-safe
unsafe impl Send for CallbackFieldGetter {}
unsafe impl Sync for CallbackFieldGetter {}

impl FieldGetter for CallbackFieldGetter {
    fn get(&self, ctx: &LazyContext) -> Result<Value> {
        let ctx_ptr = ctx as *const LazyContext as *const c_void;
        let field_cstr = CString::new(self.field_name.as_ref())?;
        
        let value_ptr = (self.callback)(ctx_ptr, field_cstr.as_ptr(), self.user_data);
        
        if value_ptr.is_null() {
            return Ok(Value::Null);
        }
        
        // The callback returns a cloned Value pointer (from regorus_value_clone)
        // Take ownership using Box::from_raw and return it
        let value = unsafe { Box::from_raw(value_ptr as *mut Value) };
        
        Ok(*value)
    }
}

/// Registers a schema with callback-based field getters for complex types.
/// This allows C/C++ code to provide custom field getter functions.
///
/// # Parameters
/// * `type_name` - C string name of the type
/// * `field_names` - Array of C strings for field names
/// * `field_callbacks` - Array of callback functions (same length as field_names)
/// * `user_data_array` - Array of user data pointers (same length as field_names)
/// * `fields_len` - Length of all arrays
#[no_mangle]
pub extern "C" fn regorus_register_callback_schema(
    type_name: *const c_char,
    field_names: *const *const c_char,
    field_callbacks: *const FieldGetterCallback,
    user_data_array: *const *mut c_void,
    fields_len: usize,
) -> RegorusResult {
    let result = || -> Result<()> {
        let type_str = from_c_str(type_name)?;
        let mut builder = SchemaBuilder::new(type_str);
        
        if !field_names.is_null() && !field_callbacks.is_null() && fields_len > 0 {
            let names_slice = unsafe { std::slice::from_raw_parts(field_names, fields_len) };
            let callbacks_slice = unsafe { std::slice::from_raw_parts(field_callbacks, fields_len) };
            let user_data_slice = if user_data_array.is_null() {
                vec![std::ptr::null_mut(); fields_len]
            } else {
                unsafe { std::slice::from_raw_parts(user_data_array, fields_len) }.to_vec()
            };
            
            for i in 0..fields_len {
                let field_name = from_c_str(names_slice[i])?;
                let field_arc = Arc::from(field_name.as_str());
                
                builder = builder.field_immediate(
                    field_name.as_str(),
                    CallbackFieldGetter {
                        field_name: field_arc,
                        callback: callbacks_slice[i],
                        user_data: user_data_slice[i],
                    }
                );
            }
        }
        
        builder.register();
        Ok(())
    }();
    
    match result {
        Ok(_) => RegorusResult::ok_void(),
        Err(e) => RegorusResult::err_with_message(RegorusStatus::Error, format!("{}", e)),
    }
}
