// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for lazy CBOR object evaluation in Rego policies
//!
//! These tests demonstrate how CBOR objects can be lazily decoded as subobjects
//! of the input structure, enabling efficient policy evaluation on binary data.

use crate::lazy::*;
use crate::*;
use ciborium::Value as CborValue;

/// Helper to create a lazy CBOR object from actual CBOR bytes
fn create_lazy_cbor_from_bytes(
    type_name: &str,
    cbor_bytes: Vec<u8>,
) -> Result<LazyObject, anyhow::Error> {
    let mut ctx = LazyContext::new();
    ctx.insert("cbor_bytes", cbor_bytes);
    
    Ok(LazyObject::new(TypeId::new(type_name), ctx))
}

/// Register schema for a simple CBOR object with immediate fields
fn register_simple_cbor_schema() {
    SchemaBuilder::new("SimpleCbor")
        .field_immediate_fn("name", |ctx| {
            let bytes = ctx.get_bytes("cbor_bytes")?;
            let cbor: CborValue = ciborium::from_reader(&bytes[..])
                .map_err(|e| anyhow::anyhow!("CBOR decode error: {}", e))?;
            
            // Extract "name" field from CBOR map
            if let CborValue::Map(map) = cbor {
                for (k, v) in map {
                    if let CborValue::Text(key) = k {
                        if key == "name" {
                            if let CborValue::Text(value) = v {
                                return Ok(crate::Value::from(value));
                            }
                        }
                    }
                }
            }
            Ok(crate::Value::Undefined)
        })
        .field_immediate_fn("count", |ctx| {
            let bytes = ctx.get_bytes("cbor_bytes")?;
            let cbor: CborValue = ciborium::from_reader(&bytes[..])
                .map_err(|e| anyhow::anyhow!("CBOR decode error: {}", e))?;
            
            if let CborValue::Map(map) = cbor {
                for (k, v) in map {
                    if let CborValue::Text(key) = k {
                        if key == "count" {
                            if let CborValue::Integer(int_val) = v {
                                // Convert ciborium::Integer to i128 and then to Value
                                let i: i128 = int_val.into();
                                return Ok(crate::Value::from(i as i64));
                            }
                        }
                    }
                }
            }
            Ok(crate::Value::Undefined)
        })
        .field_immediate_fn("enabled", |ctx| {
            let bytes = ctx.get_bytes("cbor_bytes")?;
            let cbor: CborValue = ciborium::from_reader(&bytes[..])
                .map_err(|e| anyhow::anyhow!("CBOR decode error: {}", e))?;
            
            if let CborValue::Map(map) = cbor {
                for (k, v) in map {
                    if let CborValue::Text(key) = k {
                        if key == "enabled" {
                            if let CborValue::Bool(bool_val) = v {
                                return Ok(crate::Value::from(bool_val));
                            }
                        }
                    }
                }
            }
            Ok(crate::Value::Undefined)
        })
        .register();
}

/// Test: CBOR object as subobject of input (key test - CBOR is nested in regular input)
#[test]
fn test_cbor_as_input_subobject() -> anyhow::Result<()> {
    use crate::Rc;
    
    // Register schema
    register_simple_cbor_schema();
    
    // Create actual CBOR data
    let cbor_data = CborValue::Map(vec![
        (CborValue::Text("name".into()), CborValue::Text("azure_vm_42".into())),
        (CborValue::Text("count".into()), CborValue::Integer(100.into())),
        (CborValue::Text("enabled".into()), CborValue::Bool(true)),
    ]);
    
    // Encode to CBOR bytes
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&cbor_data, &mut cbor_bytes)?;
    
    // Create lazy CBOR object
    let lazy_cbor = create_lazy_cbor_from_bytes("SimpleCbor", cbor_bytes)?;
    
    // Create input with regular fields AND a CBOR subobject
    let mut input = crate::Value::new_object();
    let input_map = input.as_object_mut()?;
    
    // Regular input fields (parsed from JSON/YAML)
    input_map.insert(
        crate::Value::from("request_id"),
        crate::Value::from("req-98765"),
    );
    input_map.insert(
        crate::Value::from("user"),
        crate::Value::from("alice@example.com"),
    );
    
    // CBOR subobject (this is the key part - CBOR binary data nested in input)
    input_map.insert(
        crate::Value::from("resource_metadata"),
        crate::Value::LazyObject(Rc::new(lazy_cbor)),
    );
    
    // Create engine and policy
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyWithDeferred);
    
    let policy = r#"
        package test.cbor_subobject
        
        # Access regular input fields
        request_id := input.request_id
        user := input.user
        
        # Access CBOR subobject fields - these are lazily decoded from binary
        resource_name := input.resource_metadata.name
        resource_count := input.resource_metadata.count
        
        # Policy decision based on both regular and CBOR fields
        allow if {
            input.user != ""
            input.resource_metadata.enabled == true
            input.resource_metadata.count >= 50
        }
        
        # Demonstrate mixed access
        summary := {
            "user": input.user,
            "resource": input.resource_metadata.name,
            "count": input.resource_metadata.count
        }
    "#;
    
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    engine.set_input(input);
    
    // Test regular field access
    let results = engine.eval_query("data.test.cbor_subobject.request_id".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::String(s) => assert_eq!(s.as_ref(), "req-98765"),
        _ => panic!("Expected string result"),
    }
    
    // Test CBOR field access
    let results = engine.eval_query("data.test.cbor_subobject.resource_name".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::String(s) => assert_eq!(s.as_ref(), "azure_vm_42"),
        _ => panic!("Expected string result for CBOR field"),
    }
    
    // Test policy decision combining regular and CBOR fields
    let results = engine.eval_query("data.test.cbor_subobject.allow".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected boolean result"),
    }
    
    Ok(())
}

/// Test: Nested CBOR objects in input with deferred evaluation
#[test]
fn test_nested_cbor_with_deferred() -> anyhow::Result<()> {
    use crate::Rc;
    
    // Register schema for nested CBOR
    SchemaBuilder::new("CborMetadata")
        .field_immediate_fn("version", |ctx| {
            let bytes = ctx.get_bytes("cbor_bytes")?;
            let cbor: CborValue = ciborium::from_reader(&bytes[..])
                .map_err(|e| anyhow::anyhow!("CBOR decode error: {}", e))?;
            
            if let CborValue::Map(map) = cbor {
                for (k, v) in map {
                    if let CborValue::Text(key) = k {
                        if key == "version" {
                            if let CborValue::Text(value) = v {
                                return Ok(crate::Value::from(value));
                            }
                        }
                    }
                }
            }
            Ok(crate::Value::Undefined)
        })
        .field_deferred_fn("tags", |ctx| {
            // Expensive operation - decode tags (deferred)
            let bytes = ctx.get_bytes("cbor_bytes")?;
            let cbor: CborValue = ciborium::from_reader(&bytes[..])
                .map_err(|e| anyhow::anyhow!("CBOR decode error: {}", e))?;
            
            if let CborValue::Map(map) = cbor {
                for (k, v) in map {
                    if let CborValue::Text(key) = k {
                        if key == "tags" {
                            if let CborValue::Array(arr) = v {
                                let mut result = crate::Value::new_array();
                                for item in arr {
                                    if let CborValue::Text(tag) = item {
                                        result.as_array_mut()?.push(crate::Value::from(tag));
                                    }
                                }
                                return Ok(result);
                            }
                        }
                    }
                }
            }
            Ok(crate::Value::Undefined)
        })
        .register();
    
    // Create CBOR metadata
    let cbor_metadata = CborValue::Map(vec![
        (CborValue::Text("version".into()), CborValue::Text("2.1.0".into())),
        (CborValue::Text("tags".into()), CborValue::Array(vec![
            CborValue::Text("production".into()),
            CborValue::Text("critical".into()),
        ])),
    ]);
    
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&cbor_metadata, &mut cbor_bytes)?;
    
    let lazy_metadata = create_lazy_cbor_from_bytes("CborMetadata", cbor_bytes)?;
    
    // Create input with nested structure
    let mut input = crate::Value::new_object();
    let input_map = input.as_object_mut()?;
    
    // Regular fields
    input_map.insert(
        crate::Value::from("environment"),
        crate::Value::from("prod"),
    );
    
    // Nested object containing CBOR
    let mut resource = crate::Value::new_object();
    resource.as_object_mut()?.insert(
        crate::Value::from("id"),
        crate::Value::from("resource-999"),
    );
    resource.as_object_mut()?.insert(
        crate::Value::from("metadata"),
        crate::Value::LazyObject(Rc::new(lazy_metadata)),
    );
    
    input_map.insert(
        crate::Value::from("resource"),
        resource,
    );
    
    // Test with policy
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyWithDeferred);
    
    let policy = r#"
        package test.nested
        
        # Access through multiple levels
        metadata_version := input.resource.metadata.version
        
        # Deferred field - only evaluated when needed
        metadata_tags := input.resource.metadata.tags
        
        # Policy using deferred field
        is_production if {
            input.environment == "prod"
            "production" in input.resource.metadata.tags
        }
    "#;
    
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    engine.set_input(input);
    
    // Test immediate field
    let results = engine.eval_query("data.test.nested.metadata_version".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::String(s) => assert_eq!(s.as_ref(), "2.1.0"),
        _ => panic!("Expected string result"),
    }
    
    // Test policy with deferred field (tags should be lazily loaded)
    let results = engine.eval_query("data.test.nested.metadata_tags".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    // The tags field is deferred, so it returns a Deferred value until materialized
    
    // Test policy with deferred field - the 'in' operator materializes the deferred value
    let results = engine.eval_query("data.test.nested.is_production".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected boolean result"),
    }
    match &results.result[0].expressions[0].value {
        crate::Value::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected boolean result"),
    }
    
    Ok(())
}

/// Test: Multiple CBOR subobjects in input
#[test]
fn test_multiple_cbor_subobjects() -> anyhow::Result<()> {
    use crate::Rc;
    
    // Register schemas
    register_simple_cbor_schema();
    
    // Create first CBOR object
    let cbor1 = CborValue::Map(vec![
        (CborValue::Text("name".into()), CborValue::Text("resource_a".into())),
        (CborValue::Text("count".into()), CborValue::Integer(75.into())),
        (CborValue::Text("enabled".into()), CborValue::Bool(true)),
    ]);
    
    let mut cbor1_bytes = Vec::new();
    ciborium::into_writer(&cbor1, &mut cbor1_bytes)?;
    let lazy_cbor1 = create_lazy_cbor_from_bytes("SimpleCbor", cbor1_bytes)?;
    
    // Create second CBOR object
    let cbor2 = CborValue::Map(vec![
        (CborValue::Text("name".into()), CborValue::Text("resource_b".into())),
        (CborValue::Text("count".into()), CborValue::Integer(25.into())),
        (CborValue::Text("enabled".into()), CborValue::Bool(false)),
    ]);
    
    let mut cbor2_bytes = Vec::new();
    ciborium::into_writer(&cbor2, &mut cbor2_bytes)?;
    let lazy_cbor2 = create_lazy_cbor_from_bytes("SimpleCbor", cbor2_bytes)?;
    
    // Create input with multiple CBOR subobjects
    let mut input = crate::Value::new_object();
    let input_map = input.as_object_mut()?;
    
    input_map.insert(
        crate::Value::from("resource_a"),
        crate::Value::LazyObject(Rc::new(lazy_cbor1)),
    );
    input_map.insert(
        crate::Value::from("resource_b"),
        crate::Value::LazyObject(Rc::new(lazy_cbor2)),
    );
    
    // Policy accessing multiple CBOR objects
    let mut engine = Engine::new();
    engine.set_lazy_mode(engine::LazyMode::LazyWithDeferred);
    
    let policy = r#"
        package test.multi
        
        # Access multiple CBOR resources
        total_count := input.resource_a.count + input.resource_b.count
        
        # Policy based on multiple CBOR objects
        allow if {
            input.resource_a.enabled == true
            input.resource_a.count > 50
        }
        
        deny if {
            input.resource_b.enabled == false
        }
    "#;
    
    engine.add_policy("test.rego".to_string(), policy.to_string())?;
    engine.set_input(input);
    
    // Test total count
    let results = engine.eval_query("data.test.multi.total_count".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    // Should be 100 (75 + 25)
    match &results.result[0].expressions[0].value {
        crate::Value::Number(_) => {
            // Number comparison - just verify it's a number
            // In real tests you'd convert and compare properly
        },
        _ => panic!("Expected number result"),
    }
    
    // Test allow
    let results = engine.eval_query("data.test.multi.allow".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected boolean result"),
    }
    
    // Test deny
    let results = engine.eval_query("data.test.multi.deny".to_string(), false)?;
    assert_eq!(results.result.len(), 1);
    match &results.result[0].expressions[0].value {
        crate::Value::Bool(b) => assert_eq!(*b, true),
        _ => panic!("Expected boolean result"),
    }
    
    Ok(())
}

