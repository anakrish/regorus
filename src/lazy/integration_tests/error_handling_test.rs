// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error handling in lazy evaluation

use crate::lazy::*;
use crate::*;
use anyhow::{anyhow, Result};

#[test]
fn test_failing_field_getter() -> anyhow::Result<()> {
    struct FailingGetter;
    impl FieldGetter for FailingGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Err(anyhow!("Simulated database connection error"))
        }
    }
    
    struct SuccessGetter;
    impl FieldGetter for SuccessGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Ok(Value::from("success"))
        }
    }
    
    let mut builder = SchemaBuilder::new("ErrorTest");
    builder = builder.field_immediate("failing", FailingGetter);
    builder = builder.field_immediate("working", SuccessGetter);
    builder.register();
    
    let lazy_obj = LazyObject::new(TypeId::new("ErrorTest"), LazyContext::new());
    
    // Accessing failing field should return error
    let result = lazy_obj.get_field("failing");
    assert!(result.is_err());
    
    // Working field should still work
    let result = lazy_obj.get_field("working")?;
    assert!(result.is_some());
    assert_eq!(result.unwrap().as_string()?.as_ref(), "success");
    
    Ok(())
}

#[test]
fn test_deferred_materialization_error() -> anyhow::Result<()> {
    struct ErrorOnMaterializeGetter;
    impl FieldGetter for ErrorOnMaterializeGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Err(anyhow!("Cannot materialize this field"))
        }
    }
    
    let mut builder = SchemaBuilder::new("DeferredError");
    builder = builder.field_deferred("error_field", ErrorOnMaterializeGetter);
    builder.register();
    
    let lazy_obj = LazyObject::new(TypeId::new("DeferredError"), LazyContext::new());
    
    // Getting deferred field should succeed (returns Deferred value)
    let deferred = lazy_obj.get_field("error_field")?;
    assert!(deferred.is_some());
    
    let deferred_value = deferred.unwrap();
    assert!(deferred_value.is_deferred());
    
    // Materializing should fail
    let materialize_result = deferred_value.materialize();
    assert!(materialize_result.is_err());
    
    Ok(())
}

#[test]
fn test_missing_schema_error() -> anyhow::Result<()> {
    // Create lazy object with non-existent schema
    let lazy_obj = LazyObject::new(TypeId::new("NonExistentSchema"), LazyContext::new());
    
    // Accessing any field should fail (schema not found error)
    let result = lazy_obj.get_field("anyfield");
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_lazy_array_getter_error() -> anyhow::Result<()> {
    struct FailingLengthGetter;
    impl LengthGetter for FailingLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Err(anyhow!("Cannot get length"))
        }
    }
    
    struct FailingIndexGetter;
    impl IndexGetter for FailingIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, _index: usize) -> Result<Option<Value>> {
            Err(anyhow!("Cannot get element"))
        }
    }
    
    let lazy_arr = LazyArray::new(
        TypeId::new("FailingArray"),
        LazyContext::new(),
        FailingLengthGetter,
        FailingIndexGetter,
    );
    
    // Getting length should return error
    assert!(lazy_arr.len().is_err());
    
    // Getting element should return error
    assert!(lazy_arr.get(0).is_err());
    
    Ok(())
}

