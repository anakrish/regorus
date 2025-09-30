// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for cascading lazy fields
//!
//! Tests scenarios where lazy fields return other lazy objects,
//! creating chains of deferred evaluation.

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use anyhow::Result;

#[test]
fn test_cascading_lazy_objects() -> anyhow::Result<()> {
    // Create a nested lazy structure: root -> properties (lazy object)
    // The nested lazy object loads fields on-demand
    
    struct MetadataGetter;
    impl FieldGetter for MetadataGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("created"), Value::from("2024-01-01"));
            obj.as_object_mut()?.insert(Value::from("author"), Value::from("test-user"));
            Ok(obj)
        }
    }
    
    struct PropertiesGetter;
    impl FieldGetter for PropertiesGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            // Return another lazy object
            let mut builder = SchemaBuilder::new("Properties");
            builder = builder.field_immediate("metadata", MetadataGetter);
            builder.register();
            
            Ok(Value::LazyObject(Arc::new(LazyObject::new(
                TypeId::new("Properties"),
                LazyContext::new(),
            ))))
        }
    }
    
    // Create root lazy object
    let mut builder = SchemaBuilder::new("CascadingRoot");
    builder = builder.field_immediate("properties", PropertiesGetter);
    builder.register();
    
    let root = LazyObject::new(TypeId::new("CascadingRoot"), LazyContext::new());
    
    // Test: access nested lazy object root.properties
    let properties = root.get_field("properties")?.expect("properties field");
    assert!(properties.is_lazy_object());
    
    // The nested lazy object can fetch its own fields
    if let Value::LazyObject(ref lazy_props) = properties {
        let metadata = lazy_props.get_field("metadata")?.expect("metadata");
        let author = metadata[&Value::from("author")].clone();
        assert_eq!(author.as_string()?.as_ref(), "test-user");
    }
    
    Ok(())
}

#[test]
fn test_deferred_cascading() -> anyhow::Result<()> {
    // Test deferred values that can be materialized
    
    struct DataGetter;
    impl FieldGetter for DataGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Ok(Value::from("deferred-data"))
        }
    }
    
    let mut builder = SchemaBuilder::new("DeferredTest");
    builder = builder.field_deferred("data", DataGetter);
    builder.register();
    
    let root = LazyObject::new(TypeId::new("DeferredTest"), LazyContext::new());
    
    // Access deferred field - should get a deferred value
    let data = root.get_field("data")?.expect("data field");
    assert!(data.is_deferred());
    
    // Materialize and check
    let materialized = data.materialize()?;
    assert_eq!(materialized.as_string()?.as_ref(), "deferred-data");
    
    Ok(())
}

#[test]
fn test_mixed_lazy_deferred_cascade() -> anyhow::Result<()> {
    // Test: deferred field that returns a lazy object
    
    struct NestedGetter;
    impl FieldGetter for NestedGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("value"), Value::from(42));
            Ok(obj)
        }
    }
    
    struct LazyObjGetter;
    impl FieldGetter for LazyObjGetter {
        fn get(&self, ctx: &LazyContext) -> Result<Value> {
            let mut builder = SchemaBuilder::new("NestedObj");
            builder = builder.field_immediate("nested", NestedGetter);
            builder.register();
            
            Ok(Value::LazyObject(Arc::new(LazyObject::new(
                TypeId::new("NestedObj"),
                ctx.clone(),
            ))))
        }
    }
    
    let mut builder = SchemaBuilder::new("MixedRoot");
    builder = builder.field_deferred("lazy_obj", LazyObjGetter);
    builder.register();
    
    let root = LazyObject::new(TypeId::new("MixedRoot"), LazyContext::new());
    
    // lazy_obj is deferred
    let lazy_obj = root.get_field("lazy_obj")?.expect("lazy_obj");
    assert!(lazy_obj.is_deferred());
    
    // Materialize it to get the lazy object
    let materialized = lazy_obj.materialize()?;
    assert!(materialized.is_lazy_object());
    
    Ok(())
}
