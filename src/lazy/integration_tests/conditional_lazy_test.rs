// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for conditional lazy loading
//!
//! Verifies that in conditional branches, only accessed fields are fetched.

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use anyhow::Result;
use core::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_conditional_field_access() -> anyhow::Result<()> {
    let expensive_count = Arc::new(AtomicUsize::new(0));
    let cheap_count = Arc::new(AtomicUsize::new(0));

    struct ExpensiveGetter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for ExpensiveGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            // Simulate expensive operation
            Ok(Value::from("expensive-data"))
        }
    }

    struct CheapGetter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for CheapGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::from("cheap-data"))
        }
    }

    let mut builder = SchemaBuilder::new("ConditionalTest");
    builder = builder.field_immediate(
        "expensive",
        ExpensiveGetter {
            count: expensive_count.clone(),
        },
    );
    builder = builder.field_immediate(
        "cheap",
        CheapGetter {
            count: cheap_count.clone(),
        },
    );
    builder.register();

    // Policy: if input.type == "cheap" { input.cheap } else { input.expensive }
    let policy = r#"
        package test
        result := input.cheap if input.type == "cheap"
        result := input.expensive if input.type == "expensive"
    "#;

    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    // Test 1: type == "cheap" - should only access cheap field
    let mut input1 = Value::new_object();
    input1
        .as_object_mut()?
        .insert(Value::from("type"), Value::from("cheap"));
    let lazy_obj = LazyObject::new(TypeId::new("ConditionalTest"), LazyContext::new());

    // Merge lazy object fields into input
    if let Some(cheap_value) = lazy_obj.get_field("cheap")? {
        input1
            .as_object_mut()?
            .insert(Value::from("cheap"), cheap_value);
    }

    engine.set_input(input1);
    let results = engine.eval_query("data.test.result".to_string(), false)?;

    assert_eq!(results.result.len(), 1);
    assert_eq!(cheap_count.load(Ordering::SeqCst), 1);
    assert_eq!(expensive_count.load(Ordering::SeqCst), 0); // Not accessed!

    Ok(())
}

#[test]
fn test_short_circuit_evaluation() -> anyhow::Result<()> {
    let field1_count = Arc::new(AtomicUsize::new(0));
    let field2_count = Arc::new(AtomicUsize::new(0));

    struct Field1Getter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for Field1Getter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Bool(false))
        }
    }

    struct Field2Getter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for Field2Getter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::Bool(true))
        }
    }

    let mut builder = SchemaBuilder::new("ShortCircuit");
    builder = builder.field_immediate(
        "field1",
        Field1Getter {
            count: field1_count.clone(),
        },
    );
    builder = builder.field_immediate(
        "field2",
        Field2Getter {
            count: field2_count.clone(),
        },
    );
    builder.register();

    // Policy: input.field1 == false (should succeed without checking field2)
    let policy = r#"
        package test
        result if {
            input.field1 == false
        }
    "#;

    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    let mut input = Value::new_object();
    let lazy_obj = LazyObject::new(TypeId::new("ShortCircuit"), LazyContext::new());

    // Manually get field1 for the test
    if let Some(field1) = lazy_obj.get_field("field1")? {
        input.as_object_mut()?.insert(Value::from("field1"), field1);
    }

    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;

    assert_eq!(results.result.len(), 1);
    assert_eq!(field1_count.load(Ordering::SeqCst), 1);
    // field2 should not be accessed since the rule succeeded without it
    assert_eq!(field2_count.load(Ordering::SeqCst), 0);

    Ok(())
}
