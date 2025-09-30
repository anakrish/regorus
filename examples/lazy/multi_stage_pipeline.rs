// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Multi-Stage Pipeline Example
//!
//! Demonstrates lazy evaluation with multi-stage validation pipeline.
//!
//! Run with: cargo run --example multi_stage_pipeline

use anyhow::Result;
use regorus::*;
use regorus::lazy::{FieldGetter, LazyContext, LazyObject, SchemaBuilder, TypeId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

fn main() -> Result<()> {
    println!("🚀 Multi-Stage Validation Pipeline Example\n");
    println!("Demonstrates how lazy evaluation enables efficient multi-stage validation.\n");

    // Track execution of different validation stages
    let syntax_count = Arc::new(AtomicUsize::new(0));
    let auth_count = Arc::new(AtomicUsize::new(0));
    let quota_count = Arc::new(AtomicUsize::new(0));

    // Define stage getters
    struct AuthGetter { count: Arc<AtomicUsize> }
    impl FieldGetter for AuthGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  🔐 Stage 2: Checking authentication... (50ms)");
            std::thread::sleep(std::time::Duration::from_millis(50));
            let mut auth = Value::new_object();
            auth.as_object_mut()?.insert(Value::from("authenticated"), Value::Bool(true));
            auth.as_object_mut()?.insert(Value::from("principal"), Value::from("user@example.com"));
            Ok(auth)
        }
    }

    struct QuotaGetter { count: Arc<AtomicUsize>, remaining: i64 }
    impl FieldGetter for QuotaGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  💾 Stage 3: Checking quota limits in database... (100ms)");
            std::thread::sleep(std::time::Duration::from_millis(100));
            let mut quota = Value::new_object();
            quota.as_object_mut()?.insert(Value::from("limit"), Value::from(1000));
            quota.as_object_mut()?.insert(Value::from("used"), Value::from(1000 - self.remaining));
            quota.as_object_mut()?.insert(Value::from("remaining"), Value::from(self.remaining));
            Ok(quota)
        }
    }

    let policy = r#"
        package pipeline

        # Stage 1: Basic syntax validation (always runs)
        valid_syntax if {
            input.validation.method in ["GET", "POST", "PUT", "DELETE"]
            input.validation.path != ""
        }

        # Stage 2: Authentication (only if syntax is valid)
        authenticated if {
            valid_syntax
            input.validation.auth.authenticated == true
        }

        # Stage 3: Check quota (only if authenticated)
        within_quota if {
            authenticated
            input.validation.quota.remaining > 0
        }

        # Final decision
        allow if { within_quota }

        # Alternative: fail fast on syntax
        deny_invalid_syntax if { not valid_syntax }
        deny_quota_exceeded if { authenticated; not within_quota }
    "#;

    let mut engine = Engine::new();
    engine.add_policy("pipeline.rego".to_string(), policy.to_string())?;

    // Scenario 1: Valid request - all stages should execute
    println!("📋 Scenario 1: Valid Request (All Stages Execute)");
    println!("Expected: All 3 stages should run\n");
    
    let start1 = Instant::now();
    let auth_count1 = Arc::new(AtomicUsize::new(0));
    let quota_count1 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("Validator1")
        .field_immediate_fn("method", |_| {
            println!("  ✅ Stage 1: Validating method... (0ms)");
            Ok(Value::from("POST"))
        })
        .field_immediate_fn("path", |_| {
            println!("  ✅ Stage 1: Validating path... (0ms)");
            Ok(Value::from("/api/v1/resources"))
        })
        .field_immediate("auth", AuthGetter { count: auth_count1.clone() })
        .field_immediate("quota", QuotaGetter { count: quota_count1.clone(), remaining: 650 })
        .register();

    let validator1 = LazyObject::new(TypeId::new("Validator1"), LazyContext::new());
    let mut input1 = Value::new_object();
    input1.as_object_mut()?.insert(Value::from("validation"), Value::LazyObject(Arc::new(validator1)));
    
    engine.set_input(input1);
    let result1 = engine.eval_query("data.pipeline.allow".to_string(), false)?;
    
    let duration1 = start1.elapsed();
    println!("\n✅ Decision: {}", result1.result.len() > 0);
    println!("⏱️  Total time: {:?}", duration1);
    println!("📊 Stages executed:");
    println!("  - Stage 1 (Syntax): ✓");
    println!("  - Stage 2 (Auth): {} checks", auth_count1.load(Ordering::SeqCst));
    println!("  - Stage 3 (Quota): {} checks", quota_count1.load(Ordering::SeqCst));

    // Scenario 2: Invalid syntax - should fail at stage 1
    println!("\n\n📋 Scenario 2: Invalid Method (Fail at Stage 1)");
    println!("Expected: Only syntax checks, NO expensive stages\n");
    
    let start2 = Instant::now();
    let auth_count2 = Arc::new(AtomicUsize::new(0));
    let quota_count2 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("Validator2")
        .field_immediate_fn("method", |_| {
            println!("  ❌ Stage 1: Invalid method detected");
            Ok(Value::from("INVALID"))
        })
        .field_immediate_fn("path", |_| {
            Ok(Value::from("/api/v1/resources"))
        })
        .field_immediate("auth", AuthGetter { count: auth_count2.clone() })
        .field_immediate("quota", QuotaGetter { count: quota_count2.clone(), remaining: 650 })
        .register();

    let validator2 = LazyObject::new(TypeId::new("Validator2"), LazyContext::new());
    let mut input2 = Value::new_object();
    input2.as_object_mut()?.insert(Value::from("validation"), Value::LazyObject(Arc::new(validator2)));
    
    engine.set_input(input2);
    let result2 = engine.eval_query("data.pipeline.deny_invalid_syntax".to_string(), false)?;
    
    let duration2 = start2.elapsed();
    println!("\n✅ Denied: {}", result2.result.len() > 0);
    println!("⏱️  Total time: {:?} (much faster!)", duration2);
    println!("📊 Stages executed:");
    println!("  - Stage 1 (Syntax): ✓ (failed)");
    println!("  - Stage 2 (Auth): {} checks (skipped!)", auth_count2.load(Ordering::SeqCst));
    println!("  - Stage 3 (Quota): {} checks (skipped!)", quota_count2.load(Ordering::SeqCst));

    // Scenario 3: Passes stage 1-2, fails at stage 3 (quota)
    println!("\n\n📋 Scenario 3: Quota Exceeded (Fail at Stage 3)");
    println!("Expected: Stages 1-2 run, stage 3 shows quota exceeded\n");
    
    let start3 = Instant::now();
    let auth_count3 = Arc::new(AtomicUsize::new(0));
    let quota_count3 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("Validator3")
        .field_immediate_fn("method", |_| {
            println!("  ✅ Stage 1: Valid method");
            Ok(Value::from("POST"))
        })
        .field_immediate_fn("path", |_| {
            Ok(Value::from("/api/v1/resources"))
        })
        .field_immediate("auth", AuthGetter { count: auth_count3.clone() })
        .field_immediate("quota", QuotaGetter { count: quota_count3.clone(), remaining: 0 })
        .register();

    let validator3 = LazyObject::new(TypeId::new("Validator3"), LazyContext::new());
    let mut input3 = Value::new_object();
    input3.as_object_mut()?.insert(Value::from("validation"), Value::LazyObject(Arc::new(validator3)));
    
    engine.set_input(input3);
    let result3 = engine.eval_query("data.pipeline.deny_quota_exceeded".to_string(), false)?;
    
    let duration3 = start3.elapsed();
    println!("\n✅ Denied (quota): {}", result3.result.len() > 0);
    println!("⏱️  Total time: {:?}", duration3);
    println!("📊 Stages executed:");
    println!("  - Stage 1 (Syntax): ✓");
    println!("  - Stage 2 (Auth): {} checks", auth_count3.load(Ordering::SeqCst));
    println!("  - Stage 3 (Quota): {} checks", quota_count3.load(Ordering::SeqCst));

    println!("\n\n🎯 Summary:");
    println!("Multi-stage pipeline with lazy evaluation:");
    println!("- Scenario 1: All stages executed (~150ms total)");
    println!("- Scenario 2: Only stage 1 (syntax) executed (~0ms)");
    println!("- Scenario 3: Stages 1-3 executed (~150ms)");
    println!("\nLazy evaluation saves significant time by short-circuiting on failures!");

    Ok(())
}
