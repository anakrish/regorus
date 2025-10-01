// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for lazy value caching behavior

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use anyhow::Result;
use core::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_field_caching() -> anyhow::Result<()> {
    let fetch_count = Arc::new(AtomicUsize::new(0));

    struct CountingGetter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for CountingGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::from("cached-value"))
        }
    }

    let mut builder = SchemaBuilder::new("CacheTest");
    builder = builder.field_immediate(
        "cacheable",
        CountingGetter {
            count: fetch_count.clone(),
        },
    );
    builder.register();

    let lazy_obj = LazyObject::new(TypeId::new("CacheTest"), LazyContext::new());

    // First access - should fetch
    let val1 = lazy_obj.get_field("cacheable")?.unwrap();
    assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

    // Second access - should use cache
    let val2 = lazy_obj.get_field("cacheable")?.unwrap();
    assert_eq!(fetch_count.load(Ordering::SeqCst), 1); // Still 1!

    // Values should be equal
    assert_eq!(val1, val2);

    Ok(())
}

#[test]
fn test_different_instances_dont_share_cache() -> anyhow::Result<()> {
    let fetch_count = Arc::new(AtomicUsize::new(0));

    struct CountingGetter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for CountingGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let val = self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::from(val as i64))
        }
    }

    let mut builder = SchemaBuilder::new("NoCacheShare");
    builder = builder.field_immediate(
        "field",
        CountingGetter {
            count: fetch_count.clone(),
        },
    );
    builder.register();

    // Create two separate instances
    let lazy_obj1 = LazyObject::new(TypeId::new("NoCacheShare"), LazyContext::new());
    let lazy_obj2 = LazyObject::new(TypeId::new("NoCacheShare"), LazyContext::new());

    // Each should fetch independently
    let val1 = lazy_obj1.get_field("field")?.unwrap();
    assert_eq!(val1.as_i64()?, 0);

    let val2 = lazy_obj2.get_field("field")?.unwrap();
    assert_eq!(val2.as_i64()?, 1);

    // Total fetches: 2
    assert_eq!(fetch_count.load(Ordering::SeqCst), 2);

    Ok(())
}

#[test]
fn test_deferred_values_not_cached_until_materialized() -> anyhow::Result<()> {
    let materialize_count = Arc::new(AtomicUsize::new(0));

    struct DeferredGetter {
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for DeferredGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Value::from("materialized"))
        }
    }

    let mut builder = SchemaBuilder::new("DeferredCache");
    builder = builder.field_deferred(
        "deferred_field",
        DeferredGetter {
            count: materialize_count.clone(),
        },
    );
    builder.register();

    let lazy_obj = LazyObject::new(TypeId::new("DeferredCache"), LazyContext::new());

    // Getting deferred field should NOT materialize it
    let deferred1 = lazy_obj.get_field("deferred_field")?.unwrap();
    assert!(deferred1.is_deferred());
    assert_eq!(materialize_count.load(Ordering::SeqCst), 0);

    // Getting it again should still not materialize
    let deferred2 = lazy_obj.get_field("deferred_field")?.unwrap();
    assert!(deferred2.is_deferred());
    assert_eq!(materialize_count.load(Ordering::SeqCst), 0);

    // Now materialize
    let _ = deferred1.materialize()?;
    assert_eq!(materialize_count.load(Ordering::SeqCst), 1);

    Ok(())
}

#[test]
fn test_lazy_array_element_caching() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));

    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(10)
        }
    }

    struct TestIndexGetter {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Value::from(index * 100)))
        }
    }

    let lazy_arr = LazyArray::new(
        TypeId::new("CacheArray"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter {
            count: access_count.clone(),
        },
    );

    // First access to element 3
    let val1 = lazy_arr.get(3)?.unwrap();
    assert_eq!(access_count.load(Ordering::SeqCst), 1);
    assert_eq!(val1.as_i64()?, 300);

    // Second access to element 3 - should use cache
    let val2 = lazy_arr.get(3)?.unwrap();
    assert_eq!(access_count.load(Ordering::SeqCst), 1); // Still 1!
    assert_eq!(val2.as_i64()?, 300);

    // Access different element - should fetch
    let val3 = lazy_arr.get(5)?.unwrap();
    assert_eq!(access_count.load(Ordering::SeqCst), 2);
    assert_eq!(val3.as_i64()?, 500);

    Ok(())
}
