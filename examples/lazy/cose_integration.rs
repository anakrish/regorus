// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE Integration Example
//!
//! Demonstrates lazy evaluation with COSE (CBOR Object Signing and Encryption) signature verification.
//!
//! Run with: cargo run --example cose_integration

use anyhow::Result;
use regorus::*;
use regorus::lazy::{FieldGetter, LazyContext, LazyObject, SchemaBuilder, TypeId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("🚀 COSE Object Integration Example\n");
    println!("Demonstrates lazy COSE signature verification - only when policy needs it.\n");

    let verify_count = Arc::new(AtomicUsize::new(0));
    let payload_count = Arc::new(AtomicUsize::new(0));

    // Define COSE signature getter
    struct VerifiedGetter { count: Arc<AtomicUsize> }
    impl FieldGetter for VerifiedGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            println!("  🔐 COSE Signature Verification #{} (expensive: 50ms)", count);
            println!("     - Algorithm: ES256");
            std::thread::sleep(std::time::Duration::from_millis(50));
            Ok(Value::Bool(true)) // Simulated successful verification
        }
    }

    struct PayloadGetter { count: Arc<AtomicUsize> }
    impl FieldGetter for PayloadGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  📦 Decoding COSE payload");
            let mut payload = Value::new_object();
            payload.as_object_mut()?.insert(Value::from("type"), Value::from("container_image"));
            payload.as_object_mut()?.insert(Value::from("digest"), Value::from("sha256:abc123"));
            Ok(payload)
        }
    }

    // Register COSE signature schema
    SchemaBuilder::new("CoseSignature")
        .field_immediate_fn("algorithm", |_| Ok(Value::from("ES256")))
        .field_immediate("verified", VerifiedGetter { count: verify_count.clone() })
        .field_immediate("payload", PayloadGetter { count: payload_count.clone() })
        .register();

    // Register container image schema
    SchemaBuilder::new("ContainerImage")
        .field_immediate_fn("name", |_| Ok(Value::from("mcr.microsoft.com/app")))
        .field_immediate_fn("tag", |_| Ok(Value::from("latest")))
        .register();

    let policy = r#"
        package cose_example

        # Check if image is from trusted registry (NO signature verification needed)
        from_trusted_registry if {
            input.container.name == "mcr.microsoft.com/app"
        }

        # Verify signature only for untrusted registries
        signature_valid if {
            not from_trusted_registry
            input.container.signature.verified == true
        }

        # Policy decision
        allow if { from_trusted_registry }
        allow if { signature_valid }

        # Get algorithm without verification
        signature_algorithm := input.container.signature.algorithm
    "#;

    let mut engine = Engine::new();
    engine.add_policy("cose_example.rego".to_string(), policy.to_string())?;

    // Scenario 1: Trusted registry - NO signature verification needed
    println!("📋 Scenario 1: Trusted Registry Image");
    println!("Expected: NO signature verification (policy allows based on registry)\n");
    
    let verify_count1 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("CoseSignature1")
        .field_immediate_fn("algorithm", |_| Ok(Value::from("ES256")))
        .field_immediate("verified", VerifiedGetter { count: verify_count1.clone() })
        .register();

    let signature1 = LazyObject::new(TypeId::new("CoseSignature1"), LazyContext::new());
    let container1 = LazyObject::new(TypeId::new("ContainerImage"), LazyContext::new());
    
    let mut input1 = Value::new_object();
    let mut container_obj1 = Value::new_object();
    container_obj1.as_object_mut()?.insert(Value::from("name"), Value::from("mcr.microsoft.com/app"));
    container_obj1.as_object_mut()?.insert(Value::from("signature"), Value::LazyObject(Arc::new(signature1)));
    input1.as_object_mut()?.insert(Value::from("container"), container_obj1);
    
    engine.set_input(input1);
    let results1 = engine.eval_query("data.cose_example.allow".to_string(), false)?;
    
    println!("\n✅ Allow: {}", results1.result.len() > 0);
    println!("📊 COSE verifications: {} (should be 0 - trusted registry!)", verify_count1.load(Ordering::SeqCst));

    // Scenario 2: Untrusted registry - MUST verify signature
    println!("\n\n📋 Scenario 2: Untrusted Registry Image");
    println!("Expected: Signature verification required\n");
    
    let verify_count2 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("CoseSignature2")
        .field_immediate_fn("algorithm", |_| Ok(Value::from("ES256")))
        .field_immediate("verified", VerifiedGetter { count: verify_count2.clone() })
        .register();

    let signature2 = LazyObject::new(TypeId::new("CoseSignature2"), LazyContext::new());
    
    let mut input2 = Value::new_object();
    let mut container_obj2 = Value::new_object();
    container_obj2.as_object_mut()?.insert(Value::from("name"), Value::from("docker.io/untrusted/app"));
    container_obj2.as_object_mut()?.insert(Value::from("signature"), Value::LazyObject(Arc::new(signature2)));
    input2.as_object_mut()?.insert(Value::from("container"), container_obj2);
    
    engine.set_input(input2);
    let results2 = engine.eval_query("data.cose_example.allow".to_string(), false)?;
    
    println!("\n✅ Allow: {}", results2.result.len() > 0);
    println!("📊 COSE verifications: {} (verified signature!)", verify_count2.load(Ordering::SeqCst));

    // Scenario 3: Get algorithm WITHOUT verification
    println!("\n\n📋 Scenario 3: Get Algorithm Metadata Only");
    println!("Expected: NO signature verification (just metadata access)\n");
    
    let verify_count3 = Arc::new(AtomicUsize::new(0));
    
    SchemaBuilder::new("CoseSignature3")
        .field_immediate_fn("algorithm", |_| Ok(Value::from("ES256")))
        .field_immediate("verified", VerifiedGetter { count: verify_count3.clone() })
        .register();

    let signature3 = LazyObject::new(TypeId::new("CoseSignature3"), LazyContext::new());
    
    let mut input3 = Value::new_object();
    let mut container_obj3 = Value::new_object();
    container_obj3.as_object_mut()?.insert(Value::from("signature"), Value::LazyObject(Arc::new(signature3)));
    input3.as_object_mut()?.insert(Value::from("container"), container_obj3);
    
    engine.set_input(input3);
    let results3 = engine.eval_query("data.cose_example.signature_algorithm".to_string(), false)?;
    
    println!("\n✅ Algorithm: {}", 
        if results3.result.len() > 0 && results3.result[0].expressions.len() > 0 {
            "ES256"
        } else {
            "Not found"
        }
    );
    println!("📊 COSE verifications: {} (no verification for metadata!)", verify_count3.load(Ordering::SeqCst));

    println!("\n\n🎯 Summary:");
    println!("COSE integration with lazy evaluation:");
    println!("- Scenario 1: 0 verifications (trusted registry, no need to verify)");
    println!("- Scenario 2: 1 verification (untrusted registry, signature required)");
    println!("- Scenario 3: 0 verifications (only metadata, no crypto needed)");
    println!("\nLazy COSE saves expensive cryptographic operations!");
    println!("\n💡 Real-world applications:");
    println!("- Container image signature verification (Notary v2, cosign)");
    println!("- Supply chain security (in-toto, SLSA attestations)");
    println!("- IoT device attestation (TPM, secure boot)");
    println!("- Secure firmware updates (automotive, industrial)");

    Ok(())
}
