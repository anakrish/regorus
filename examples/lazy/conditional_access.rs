// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simplified Conditional Field Access Example
//!
//! This example demonstrates how lazy evaluation only fetches fields when the policy
//! logic actually needs them.
//!
//! Run with: cargo run --example conditional_access

use anyhow::Result;
use regorus::*;
use regorus::lazy::{FieldGetter, LazyContext, LazyObject, SchemaBuilder, TypeId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("🚀 Conditional Field Access Example\n");
    
    let details_count = Arc::new(AtomicUsize::new(0));
    let metadata_count = Arc::new(AtomicUsize::new(0));

    // Define getters
    struct DetailsGetter { count: Arc<AtomicUsize> }
    impl FieldGetter for DetailsGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  🔍 [EXPENSIVE] Fetching details...");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("verified"), Value::Bool(true));
            Ok(obj)
        }
    }

    struct MetadataGetter { count: Arc<AtomicUsize> }
    impl FieldGetter for MetadataGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  �� [EXPENSIVE] Fetching metadata...");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let mut obj = Value::new_object();
            obj.as_object_mut()?.insert(Value::from("owner"), Value::from("alice"));
            Ok(obj)
        }
    }

    // Register schema
    SchemaBuilder::new("Resource")
        .field_immediate_fn("type", |_| Ok(Value::from("premium")))
        .field_immediate_fn("status", |_| Ok(Value::from("ok")))
        .field_immediate("details", DetailsGetter { count: details_count.clone() })
        .field_immediate("metadata", MetadataGetter { count: metadata_count.clone() })
        .register();

    let policy = r#"
        package test
        allow if {
            input.type == "premium"
            input.details.verified == true
        }
    "#;

    let mut engine = Engine::new();
    engine.add_policy("test.rego".to_string(), policy.to_string())?;

    println!("📋 Scenario: Premium Resource\n");
    
    let lazy_obj = LazyObject::new(
        TypeId::new("Resource"),
        LazyContext::new(),
    );
    
    engine.set_input(Value::LazyObject(Arc::new(lazy_obj)));
    let results = engine.eval_query("data.test.allow".to_string(), false)?;
    
    println!("\n✅ Result: {}", results.result.len() > 0 && results.result[0].expressions.len() > 0);
    println!("\n📊 Access Statistics:");
    println!("  - details: {} times", details_count.load(Ordering::SeqCst));
    println!("  - metadata: {} times (should be 0!)", metadata_count.load(Ordering::SeqCst));

    Ok(())
}
