// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Example: Using `eval_rule` for direct rule evaluation.
//!
//! This demonstrates the recommended `eval_rule` API, which is faster and
//! simpler than `eval_query` for the common case of evaluating a specific
//! policy rule and getting its value directly.
//!
//! Run with:
//!   cargo run --example eval_rule

use anyhow::Result;
use regorus::{Engine, Value};

fn main() -> Result<()> {
    let mut engine = Engine::new();

    // Load the server policy.
    engine.add_policy_from_file("examples/server/allowed_server.rego")?;

    // Set input data.
    engine.set_input(Value::from_json_file("examples/server/input.json")?);

    // --- eval_rule: get the value of a rule directly ---
    // The path uses dotted notation: data.<package>.<rule>
    let allow = engine.eval_rule("data.example.allow".to_string())?;
    println!("allow = {allow}");

    let violations = engine.eval_rule("data.example.violation".to_string())?;
    println!(
        "violations = {}",
        serde_json::to_string_pretty(&violations)?
    );

    let public_servers = engine.eval_rule("data.example.public_server".to_string())?;
    println!(
        "public_servers = {}",
        serde_json::to_string_pretty(&public_servers)?
    );

    // --- Demonstrate re-evaluation with different input ---
    // Clone the engine to reuse loaded policies (avoids re-parsing).
    let mut engine2 = engine.clone();

    // Create a compliant input: all servers use HTTPS on private networks.
    let compliant_input = Value::from_json_str(
        r#"{
        "servers": [
            {"id": "web", "protocols": ["https"], "ports": ["p1"]}
        ],
        "networks": [
            {"id": "net1", "public": false}
        ],
        "ports": [
            {"id": "p1", "network": "net1"}
        ]
    }"#,
    )?;
    engine2.set_input(compliant_input);

    let allow = engine2.eval_rule("data.example.allow".to_string())?;
    println!("\nWith compliant input:");
    println!("allow = {allow}");
    assert_eq!(allow, Value::from(true));

    Ok(())
}
