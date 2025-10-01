// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for lazy iteration over LazyArray and LazySet
//!
//! Demonstrates that when iterating over lazy collections (e.g., in "some" expressions),
//! values are fetched on-demand and iteration can exit early without fetching all values.

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

// Test lazy array iteration with early exit
#[test]
fn test_lazy_array_early_exit() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));

    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(1000)
        }
    }

    struct TestIndexGetter {
        access_count: Arc<AtomicUsize>,
    }

    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.access_count.fetch_add(1, Ordering::SeqCst);

            // Return objects with id = index
            let mut obj = Value::new_object();
            obj.as_object_mut()?
                .insert(Value::from("id"), Value::from(index));
            obj.as_object_mut()?.insert(
                Value::from("name"),
                Value::String(format!("item_{}", index).into()),
            );

            Ok(Some(obj))
        }
    }

    let lazy_arr = LazyArray::new(
        TypeId::new("TestArray"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter {
            access_count: access_count.clone(),
        },
    );

    // Policy: some item in lazy_array; item.id == 5 { true }
    // Should exit after checking items 0 through 5
    let policy = r#"
        package test
        result if {
            some item in input.lazy_array
            item.id == 5
        }
    "#;

    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    let mut input = Value::new_object();
    input.as_object_mut()?.insert(
        Value::from("lazy_array"),
        Value::LazyArray(alloc::sync::Arc::new(lazy_arr)),
    );

    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;

    // Should return true (found item with id == 5)
    assert_eq!(results.result.len(), 1);
    assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));

    // Should have accessed only items 0-5 (6 accesses total)
    // Critical: NOT all 1000 items!
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!(
        "Lazy array early exit: accessed {} items out of 1000",
        accesses
    );
    assert!(
        accesses <= 10,
        "Expected <= 10 accesses (early exit), got {}. This is the key optimization!",
        accesses
    );

    Ok(())
}

// Test lazy array full iteration
#[test]
fn test_lazy_array_full_iteration() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));

    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(10)
        }
    }

    struct TestIndexGetter {
        access_count: Arc<AtomicUsize>,
    }

    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.access_count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Value::from(index * 2)))
        }
    }

    let lazy_arr = LazyArray::new(
        TypeId::new("TestArray"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter {
            access_count: access_count.clone(),
        },
    );

    // Array comprehension that needs all values
    let policy = r#"
        package test
        result := [v | some v in input.lazy_array; v > 5]
    "#;

    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    let mut input = Value::new_object();
    input.as_object_mut()?.insert(
        Value::from("lazy_array"),
        Value::LazyArray(alloc::sync::Arc::new(lazy_arr)),
    );

    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;

    // Should return [6, 8, 10, 12, 14, 16, 18] (values 0,2,4 filtered out, 6-18 pass)
    assert_eq!(results.result.len(), 1);
    if let Value::Array(arr) = &results.result[0].expressions[0].value {
        assert_eq!(arr.len(), 7);
    } else {
        panic!("Expected array result");
    }

    // Should have accessed all 10 items
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!("Lazy array full iteration: accessed {} items", accesses);
    assert_eq!(accesses, 10, "Expected 10 accesses (full iteration)");

    Ok(())
}

// Test lazy set iteration with early exit
#[test]
fn test_lazy_set_early_exit() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));

    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(500)
        }
    }

    struct TestIndexGetter {
        access_count: Arc<AtomicUsize>,
    }

    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.access_count.fetch_add(1, Ordering::SeqCst);

            // Return strings "value_0", "value_1", etc.
            Ok(Some(Value::String(format!("value_{}", index).into())))
        }
    }

    let lazy_set = LazySet::new(
        TypeId::new("TestSet"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter {
            access_count: access_count.clone(),
        },
    );

    // Policy: some item in lazy_set; item == "value_7" { true }
    // Should exit after checking items 0 through 7
    let policy = r#"
        package test
        result if {
            some item in input.lazy_set
            item == "value_7"
        }
    "#;

    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    let mut input = Value::new_object();
    input.as_object_mut()?.insert(
        Value::from("lazy_set"),
        Value::LazySet(alloc::sync::Arc::new(lazy_set)),
    );

    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;

    // Should return true (found "value_7")
    assert_eq!(results.result.len(), 1);
    assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));

    // Should have accessed only items 0-7 (8 accesses total)
    // Critical: NOT all 500 items!
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!(
        "Lazy set early exit: accessed {} items out of 500",
        accesses
    );
    assert!(
        accesses <= 15,
        "Expected <= 15 accesses (early exit), got {}. This proves lazy set iteration!",
        accesses
    );

    Ok(())
}
