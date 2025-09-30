// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for lazy array filtering with early exit optimization

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use anyhow::Result;

#[test]
fn test_lazy_array_filter_comprehension() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));
    
    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(1000)
        }
    }
    
    struct TestIndexGetter {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("id"), Value::from(index));
            obj.as_object_mut()?.insert(Value::from("score"), Value::from(index % 100));
            
            Ok(Some(obj))
        }
    }
    
    let lazy_arr = LazyArray::new(
        TypeId::new("FilterArray"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter { count: access_count.clone() },
    );
    
    // Policy: Filter items with score > 50
    let policy = r#"
        package test
        
        matches := [item | 
            some item in input.data
            item.score > 50
        ]
        
        result := count(matches) > 0
    "#;
    
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    
    let mut input = Value::new_object();
    input.as_object_mut()?.insert(Value::from("data"), Value::LazyArray(Arc::new(lazy_arr)));
    
    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;
    
    assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));
    
    // Should have fetched all items (array comprehension needs all)
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!("Filter comprehension: accessed {} items", accesses);
    assert_eq!(accesses, 1000);
    
    Ok(())
}

#[test]
fn test_lazy_array_exists_with_complex_condition() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));
    
    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(500)
        }
    }
    
    struct TestIndexGetter {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("type"), Value::from(if index % 2 == 0 { "even" } else { "odd" }));
            obj.as_object_mut()?.insert(Value::from("value"), Value::from(index));
            
            Ok(Some(obj))
        }
    }
    
    let lazy_arr = LazyArray::new(
        TypeId::new("ComplexFilter"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter { count: access_count.clone() },
    );
    
    // Find first even item with value > 10
    let policy = r#"
        package test
        result if {
            some item in input.items
            item.type == "even"
            item.value > 10
        }
    "#;
    
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    
    let mut input = Value::new_object();
    input.as_object_mut()?.insert(Value::from("items"), Value::LazyArray(Arc::new(lazy_arr)));
    
    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;
    
    assert_eq!(results.result.len(), 1);
    
    // Should exit early after finding first match (item 12)
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!("Complex filter early exit: accessed {} items out of 500", accesses);
    assert!(accesses < 20, "Should exit early, accessed {}", accesses);
    
    Ok(())
}

#[test]
fn test_lazy_set_membership() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));
    
    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(100)
        }
    }
    
    struct TestIndexGetter {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Value::from(index)))
        }
    }
    
    let lazy_set = LazySet::new(
        TypeId::new("MembershipSet"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter { count: access_count.clone() },
    );
    
    // Test: iterate to find a value in the set
    let policy = r#"
        package test
        result if {
            some x in input.numbers
            x == 42
        }
    "#;
    
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyOnly);
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    
    let mut input = Value::new_object();
    input.as_object_mut()?.insert(Value::from("numbers"), Value::LazySet(Arc::new(lazy_set)));
    
    engine.set_input(input);
    let results = engine.eval_query("data.test.result".to_string(), false)?;
    
    assert_eq!(results.result.len(), 1);
    
    // Should exit early after finding 42
    let accesses = access_count.load(Ordering::SeqCst);
    std::eprintln!("Set membership check: accessed {} items to find 42", accesses);
    assert!(accesses <= 50, "Should exit early, accessed {}", accesses);
    
    Ok(())
}
