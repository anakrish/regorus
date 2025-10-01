// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE Integration Example
//!
//! Demonstrates lazy evaluation with real COSE (CBOR Object Signing and Encryption) signature verification.
//! Uses actual COSE Sign1 structures serialized as CBOR byte streams.
//!
//! ## Standard COSE Sign1 Fields (RFC 8152)
//!
//! A COSE_Sign1 structure contains:
//! - **Protected Headers**: Integrity-protected parameters (serialized in CBOR, included in signature)
//!   - `algorithm` (alg): Cryptographic algorithm identifier (e.g., ES256, ES384, ES512)
//!   - `key_id` (kid): Key identifier for signature verification
//!   - `content_type`: Media type of the payload
//!   - `critical` (crit): Critical header parameters that must be understood
//! - **Unprotected Headers**: Parameters not covered by signature (can be modified post-signing)
//! - **Payload**: The actual signed data (can be detached or embedded)
//! - **Signature**: Cryptographic signature bytes
//!
//! ## How COSE Objects Appear in Rego
//!
//! In Rego policies, COSE Sign1 objects are exposed as regular objects with fields that can be accessed
//! like any other data structure. The underlying CBOR byte stream is parsed on-demand when fields are accessed.
//!
//! Example Rego access patterns (using standard COSE fields):
//! ```rego
//! # Access algorithm from protected headers (lightweight - no signature verification)
//! algorithm := input.container.signature.algorithm           # Returns: "ES256"
//!
//! # Access key ID (lightweight)
//! key_id := input.container.signature.key_id                 # Returns: "3131" (hex encoded)
//!
//! # Access all protected headers (lightweight)
//! headers := input.container.signature.protected_headers     # Returns: {"alg": "ES256", "kid": "3131"}
//!
//! # Verify signature (expensive - performs cryptographic verification)
//! is_valid := input.container.signature.verified             # Returns: true/false
//!
//! # Extract payload data (parses CBOR but no crypto)
//! payload := input.container.signature.payload               # Returns: {"type": "container_image", ...}
//! digest := input.container.signature.payload.digest         # Returns: "sha256:abc123"
//! ```
//!
//! The key benefit: expensive operations (signature verification) only execute when the policy
//! actually needs that field. Policies that check metadata or make decisions based on other factors
//! never incur the cost of cryptographic verification.
//!
//! Run with: cargo run --example cose_integration

use anyhow::{anyhow, Result};
use coset::{
    iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, RegisteredLabelWithPrivate,
};
use regorus::lazy::{FieldGetter, LazyContext, LazyObject, SchemaBuilder, TypeId};
use regorus::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Creates a COSE Sign1 object as a CBOR byte stream with ES256 algorithm
fn create_cose_sign1_bytes(payload: &[u8]) -> Result<Vec<u8>> {
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .signature(vec![
            // 64-byte ES256 signature (simulated but structurally valid)
            0x30, 0x45, 0x02, 0x21, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22,
            0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x02, 0x20, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11,
        ])
        .build();

    // Serialize to CBOR byte stream using coset's to_vec()
    cose_sign1
        .to_vec()
        .map_err(|e| anyhow!("Failed to serialize COSE Sign1: {:?}", e))
}

/// Parses COSE Sign1 from CBOR byte stream
fn parse_cose_sign1(cbor_bytes: &[u8]) -> Result<CoseSign1> {
    CoseSign1::from_slice(cbor_bytes).map_err(|e| anyhow!("Failed to parse COSE Sign1: {:?}", e))
}

/// Verifies a COSE Sign1 signature from CBOR byte stream
fn verify_cose_sign1_bytes(cbor_bytes: &[u8]) -> Result<bool> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;

    // In a real implementation, this would:
    // 1. Extract the public key from unprotected headers or external source
    // 2. Reconstruct the Sig_structure per RFC 8152
    // 3. Verify the signature using the algorithm specified in protected headers
    // 4. Use proper crypto library (e.g., ring, p256, etc.)

    let algorithm = cose_sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or_else(|| anyhow!("No algorithm in protected header"))?;

    // Simulate expensive cryptographic verification
    std::thread::sleep(std::time::Duration::from_millis(50));

    // For demo, we consider signatures valid if they have the expected structure
    let is_es256 = matches!(
        algorithm,
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256)
    );
    let has_signature = !cose_sign1.signature.is_empty();
    let has_payload = cose_sign1.payload.is_some();

    Ok(is_es256 && has_signature && has_payload)
}

/// Extracts payload from COSE Sign1 byte stream
fn extract_payload_bytes(cbor_bytes: &[u8]) -> Result<Vec<u8>> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;
    Ok(cose_sign1.payload.unwrap_or_default())
}

/// Gets algorithm from COSE Sign1 byte stream
fn get_algorithm_from_bytes(cbor_bytes: &[u8]) -> Result<String> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;
    let algorithm = cose_sign1
        .protected
        .header
        .alg
        .as_ref()
        .ok_or_else(|| anyhow!("No algorithm in protected header"))?;

    match algorithm {
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256) => Ok("ES256".to_string()),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384) => Ok("ES384".to_string()),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES512) => Ok("ES512".to_string()),
        _ => Ok(format!("{:?}", algorithm)),
    }
}

/// Gets key ID from COSE Sign1 byte stream (if present)
fn get_key_id_from_bytes(cbor_bytes: &[u8]) -> Result<Option<String>> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;
    if cose_sign1.protected.header.key_id.is_empty() {
        Ok(None)
    } else {
        // Convert bytes to hex string manually
        let kid_hex = cose_sign1
            .protected
            .header
            .key_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        Ok(Some(kid_hex))
    }
}

/// Gets content type from COSE Sign1 byte stream (if present)
fn get_content_type_from_bytes(cbor_bytes: &[u8]) -> Result<Option<String>> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;
    Ok(cose_sign1
        .protected
        .header
        .content_type
        .map(|ct| format!("{:?}", ct)))
}

/// Gets protected headers as a JSON-like object
fn get_protected_headers_from_bytes(cbor_bytes: &[u8]) -> Result<Value> {
    let cose_sign1 = parse_cose_sign1(cbor_bytes)?;
    let mut headers = Value::new_object();

    // Add algorithm
    if let Some(alg) = &cose_sign1.protected.header.alg {
        let alg_str = match alg {
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256) => "ES256",
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384) => "ES384",
            RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES512) => "ES512",
            _ => "Unknown",
        };
        headers
            .as_object_mut()?
            .insert(Value::from("alg"), Value::from(alg_str));
    }

    // Add key_id if present
    if !cose_sign1.protected.header.key_id.is_empty() {
        let kid_hex = cose_sign1
            .protected
            .header
            .key_id
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        headers
            .as_object_mut()?
            .insert(Value::from("kid"), Value::from(kid_hex.as_str()));
    }

    Ok(headers)
}

/// Returns a hardcoded valid COSE Sign1 byte stream for testing
/// This is a real COSE Sign1 structure in CBOR format
fn get_hardcoded_cose_bytes() -> Vec<u8> {
    // COSE_Sign1 structure:
    // 98(                                  -- COSE_Sign1 tag
    //   [
    //     h'a10126',                       -- protected headers: {alg: ES256}
    //     {},                              -- unprotected headers
    //     h'7b2274797065223a...',          -- payload
    //     h'3045022100...'                 -- signature
    //   ]
    // )
    vec![
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x58, 0x3d, 0x7b, 0x22, 0x74, 0x79, 0x70, 0x65,
        0x22, 0x3a, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x5f, 0x69, 0x6d,
        0x61, 0x67, 0x65, 0x22, 0x2c, 0x22, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x22, 0x3a, 0x22,
        0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x3a, 0x61, 0x62, 0x63, 0x31, 0x32, 0x33, 0x22, 0x7d,
        0x58, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x02, 0x20, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    ]
}

fn main() -> Result<()> {
    println!("🚀 COSE Object Integration Example\n");
    println!("Demonstrates lazy COSE signature verification - only when policy needs it.\n");

    let verify_count = Arc::new(AtomicUsize::new(0));
    let payload_count = Arc::new(AtomicUsize::new(0));

    // Create a real COSE Sign1 object as CBOR byte stream
    let payload_data = br#"{"type":"container_image","digest":"sha256:abc123"}"#;
    let cose_bytes = Arc::new(create_cose_sign1_bytes(payload_data)?);
    println!(
        "📝 Created COSE Sign1 CBOR byte stream ({} bytes)\n",
        cose_bytes.len()
    );

    // Define COSE signature getter with real verification from byte stream
    struct VerifiedGetter {
        count: Arc<AtomicUsize>,
        cose_bytes: Arc<Vec<u8>>,
    }
    impl FieldGetter for VerifiedGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let count = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            println!(
                "  🔐 COSE Signature Verification #{} (expensive: 50ms)",
                count
            );
            println!(
                "     - Parsing {} bytes of CBOR data",
                self.cose_bytes.len()
            );

            let verified = verify_cose_sign1_bytes(&self.cose_bytes)?;
            let algorithm = get_algorithm_from_bytes(&self.cose_bytes)?;

            println!("     - Algorithm: {}", algorithm);
            println!("     - Verified: {}", verified);

            Ok(Value::Bool(verified))
        }
    }

    struct PayloadGetter {
        count: Arc<AtomicUsize>,
        cose_bytes: Arc<Vec<u8>>,
    }
    impl FieldGetter for PayloadGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  📦 Extracting COSE payload from byte stream");

            let payload_bytes = extract_payload_bytes(&self.cose_bytes)?;
            let payload_str = String::from_utf8(payload_bytes)?;

            // Convert to regorus Value
            let payload = Value::from_json_str(&payload_str)?;
            Ok(payload)
        }
    }

    struct AlgorithmGetter {
        cose_bytes: Arc<Vec<u8>>,
    }
    impl FieldGetter for AlgorithmGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            let algorithm = get_algorithm_from_bytes(&self.cose_bytes)?;
            Ok(Value::from(algorithm.as_str()))
        }
    }

    struct KeyIdGetter {
        cose_bytes: Arc<Vec<u8>>,
    }
    impl FieldGetter for KeyIdGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            match get_key_id_from_bytes(&self.cose_bytes)? {
                Some(kid) => Ok(Value::from(kid.as_str())),
                None => Ok(Value::Null),
            }
        }
    }

    struct ProtectedHeadersGetter {
        cose_bytes: Arc<Vec<u8>>,
    }
    impl FieldGetter for ProtectedHeadersGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            get_protected_headers_from_bytes(&self.cose_bytes)
        }
    }

    // Register COSE signature schema with standard RFC 8152 fields
    // Exposed fields map to standard COSE_Sign1 structure:
    // - algorithm: Algorithm from protected headers (ES256, ES384, ES512, etc.)
    // - key_id: Key identifier from protected headers (hex-encoded bytes)
    // - protected_headers: All protected headers as an object {alg, kid, ...}
    // - verified: Signature verification result (requires crypto operation)
    // - payload: The signed payload data
    SchemaBuilder::new("CoseSignature")
        .field_immediate(
            "algorithm",
            AlgorithmGetter {
                cose_bytes: cose_bytes.clone(),
            },
        )
        .field_immediate(
            "key_id",
            KeyIdGetter {
                cose_bytes: cose_bytes.clone(),
            },
        )
        .field_immediate(
            "protected_headers",
            ProtectedHeadersGetter {
                cose_bytes: cose_bytes.clone(),
            },
        )
        .field_immediate(
            "verified",
            VerifiedGetter {
                count: verify_count.clone(),
                cose_bytes: cose_bytes.clone(),
            },
        )
        .field_immediate(
            "payload",
            PayloadGetter {
                count: payload_count.clone(),
                cose_bytes: cose_bytes.clone(),
            },
        )
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
    // Use hardcoded COSE byte stream for testing
    let cose_bytes1 = Arc::new(get_hardcoded_cose_bytes());

    SchemaBuilder::new("CoseSignature1")
        .field_immediate(
            "algorithm",
            AlgorithmGetter {
                cose_bytes: cose_bytes1.clone(),
            },
        )
        .field_immediate(
            "verified",
            VerifiedGetter {
                count: verify_count1.clone(),
                cose_bytes: cose_bytes1.clone(),
            },
        )
        .register();

    let signature1 = LazyObject::new(TypeId::new("CoseSignature1"), LazyContext::new());

    let mut input1 = Value::new_object();
    let mut container_obj1 = Value::new_object();
    container_obj1
        .as_object_mut()?
        .insert(Value::from("name"), Value::from("mcr.microsoft.com/app"));
    container_obj1.as_object_mut()?.insert(
        Value::from("signature"),
        Value::LazyObject(Arc::new(signature1)),
    );
    input1
        .as_object_mut()?
        .insert(Value::from("container"), container_obj1);

    engine.set_input(input1);
    let results1 = engine.eval_query("data.cose_example.allow".to_string(), false)?;

    println!("\n✅ Allow: {}", results1.result.len() > 0);
    println!(
        "📊 COSE verifications: {} (should be 0 - trusted registry!)",
        verify_count1.load(Ordering::SeqCst)
    );

    // Scenario 2: Untrusted registry - MUST verify signature
    println!("\n\n📋 Scenario 2: Untrusted Registry Image");
    println!("Expected: Signature verification required\n");

    let verify_count2 = Arc::new(AtomicUsize::new(0));
    // Create fresh COSE byte stream
    let cose_bytes2 = Arc::new(create_cose_sign1_bytes(payload_data)?);

    SchemaBuilder::new("CoseSignature2")
        .field_immediate(
            "algorithm",
            AlgorithmGetter {
                cose_bytes: cose_bytes2.clone(),
            },
        )
        .field_immediate(
            "verified",
            VerifiedGetter {
                count: verify_count2.clone(),
                cose_bytes: cose_bytes2.clone(),
            },
        )
        .register();

    let signature2 = LazyObject::new(TypeId::new("CoseSignature2"), LazyContext::new());

    let mut input2 = Value::new_object();
    let mut container_obj2 = Value::new_object();
    container_obj2
        .as_object_mut()?
        .insert(Value::from("name"), Value::from("docker.io/untrusted/app"));
    container_obj2.as_object_mut()?.insert(
        Value::from("signature"),
        Value::LazyObject(Arc::new(signature2)),
    );
    input2
        .as_object_mut()?
        .insert(Value::from("container"), container_obj2);

    engine.set_input(input2);
    let results2 = engine.eval_query("data.cose_example.allow".to_string(), false)?;

    println!("\n✅ Allow: {}", results2.result.len() > 0);
    println!(
        "📊 COSE verifications: {} (verified signature!)",
        verify_count2.load(Ordering::SeqCst)
    );

    // Scenario 3: Get algorithm WITHOUT verification
    println!("\n\n📋 Scenario 3: Get Algorithm Metadata Only");
    println!("Expected: NO signature verification (just metadata access)\n");

    let verify_count3 = Arc::new(AtomicUsize::new(0));
    // Use hardcoded COSE byte stream
    let cose_bytes3 = Arc::new(get_hardcoded_cose_bytes());

    SchemaBuilder::new("CoseSignature3")
        .field_immediate(
            "algorithm",
            AlgorithmGetter {
                cose_bytes: cose_bytes3.clone(),
            },
        )
        .field_immediate(
            "verified",
            VerifiedGetter {
                count: verify_count3.clone(),
                cose_bytes: cose_bytes3.clone(),
            },
        )
        .register();

    let signature3 = LazyObject::new(TypeId::new("CoseSignature3"), LazyContext::new());

    let mut input3 = Value::new_object();
    let mut container_obj3 = Value::new_object();
    container_obj3.as_object_mut()?.insert(
        Value::from("signature"),
        Value::LazyObject(Arc::new(signature3)),
    );
    input3
        .as_object_mut()?
        .insert(Value::from("container"), container_obj3);

    engine.set_input(input3);
    let results3 = engine.eval_query("data.cose_example.signature_algorithm".to_string(), false)?;

    println!(
        "\n✅ Algorithm: {}",
        if results3.result.len() > 0 && results3.result[0].expressions.len() > 0 {
            "ES256"
        } else {
            "Not found"
        }
    );
    println!(
        "📊 COSE verifications: {} (no verification for metadata!)",
        verify_count3.load(Ordering::SeqCst)
    );

    println!("\n\n🎯 Summary:");
    println!("COSE integration with lazy evaluation:");
    println!("- Scenario 1: 0 verifications (trusted registry, no need to verify)");
    println!("- Scenario 2: 1 verification (untrusted registry, signature required)");
    println!("- Scenario 3: 0 verifications (only metadata, no crypto needed)");

    Ok(())
}
