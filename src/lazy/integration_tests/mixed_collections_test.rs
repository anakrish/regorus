// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for mixed lazy and eager collections

use crate::lazy::*;
use crate::*;
use alloc::sync::Arc;
use anyhow::Result;
use core::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn test_lazy_array_in_eager_object() -> anyhow::Result<()> {
    let access_count = Arc::new(AtomicUsize::new(0));

    struct TestLengthGetter;
    impl LengthGetter for TestLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(5)
        }
    }

    struct TestIndexGetter {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for TestIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(Some(Value::from(index * 10)))
        }
    }

    let lazy_arr = LazyArray::new(
        TypeId::new("MixedTestArray"),
        LazyContext::new(),
        TestLengthGetter,
        TestIndexGetter {
            count: access_count.clone(),
        },
    );

    // Create regular object containing lazy array
    let mut obj = Value::new_object();
    obj.as_object_mut()?.insert(
        Value::from("lazy_data"),
        Value::LazyArray(Arc::new(lazy_arr)),
    );
    obj.as_object_mut()?
        .insert(Value::from("eager_data"), Value::from("immediate"));

    // Access eager field - should not trigger lazy fetch
    assert_eq!(
        obj[&Value::from("eager_data")].as_string()?.as_ref(),
        "immediate"
    );
    assert_eq!(access_count.load(Ordering::SeqCst), 0);

    // Access lazy array
    let lazy_field = &obj[&Value::from("lazy_data")];
    assert!(matches!(lazy_field, Value::LazyArray(_)));

    Ok(())
}

#[test]
fn test_eager_array_of_lazy_objects() -> anyhow::Result<()> {
    // Create eager array containing lazy objects
    let mut array = Vec::new();
    for i in 0..3 {
        struct ItemGetter {
            value: i64,
        }
        impl FieldGetter for ItemGetter {
            fn get(&self, _ctx: &LazyContext) -> Result<Value> {
                Ok(Value::from(self.value))
            }
        }

        let type_name = alloc::format!("Item{}", i);
        let mut builder = SchemaBuilder::new(type_name.as_str());
        builder = builder.field_immediate("value", ItemGetter { value: i * 10 });
        builder.register();

        let lazy_item = LazyObject::new(
            TypeId::new(&alloc::format!("Item{}", i)),
            LazyContext::new(),
        );
        array.push(Value::LazyObject(Arc::new(lazy_item)));
    }

    let eager_array = Value::from(array);

    // Verify it's a regular array
    assert!(eager_array.as_array().is_ok());
    assert_eq!(eager_array.as_array()?.len(), 3);

    // Each element is a lazy object
    assert!(eager_array[0].is_lazy_object());

    Ok(())
}

#[test]
fn test_lazy_object_with_eager_and_lazy_fields() -> anyhow::Result<()> {
    struct EagerGetter;
    impl FieldGetter for EagerGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Ok(Value::from("eager-value"))
        }
    }

    struct LazyNestedGetter;
    impl FieldGetter for LazyNestedGetter {
        fn get(&self, ctx: &LazyContext) -> Result<Value> {
            let mut nested_builder = SchemaBuilder::new("Nested");
            nested_builder = nested_builder.field_immediate("data", EagerGetter);
            nested_builder.register();

            Ok(Value::LazyObject(Arc::new(LazyObject::new(
                TypeId::new("Nested"),
                ctx.clone(),
            ))))
        }
    }

    let mut builder = SchemaBuilder::new("MixedFields");
    builder = builder.field_immediate("immediate", EagerGetter);
    builder = builder.field_immediate("nested_lazy", LazyNestedGetter);
    builder.register();

    let lazy_obj = LazyObject::new(TypeId::new("MixedFields"), LazyContext::new());

    // Get immediate field
    let immediate = lazy_obj.get_field("immediate")?.unwrap();
    assert_eq!(immediate.as_string()?.as_ref(), "eager-value");

    // Get nested lazy object
    let nested = lazy_obj.get_field("nested_lazy")?.unwrap();
    assert!(nested.is_lazy_object());

    Ok(())
}
