// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enterprise Policy Verification with Z3
//!
//! This example demonstrates Z3-based formal verification of real-world enterprise policies
//! from Azure Policy, Microsoft Graph, and other enterprise scenarios.

use regorus::z3_integration::Z3PolicyVerifier;
use regorus::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Enterprise Policy Verification with Z3 ===\n");

    // Test different enterprise policy scenarios
    test_azure_resource_policies()?;
   
    println!("🏁 Z3 Formal Verification Complete");
    println!("==================================");
    println!("✅ All enterprise policies have been verified using Z3 theorem prover");
    println!("📊 Policy consistency analysis integrated into each scenario above");

    Ok(())
}

/// Test Azure Policy Conflicts - Streamlined Version
fn test_azure_resource_policies() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Azure Policy Conflicts - Strategic Scenarios");
    println!("===============================================");

    let mut engine = Engine::new();

    // Azure Policy similar to JSON Policy definitions
    let azure_tagging_policy = r#"
        package azure.resources

        # Rule 0: VM SKU governance for cost control (STRATEGIC CONFLICT #1)
        deny contains msg if {
            input.type == "Microsoft.Compute/virtualMachines"
            input.properties.hardwareProfile.vmSize in ["Standard_GS51", "Standard_M128s1"]
            input.tags.Environment in ["dev", "test"]
            msg := "High-cost VM SKUs only allowed in production environments"
        }

        # Rule 1: AI/ML workload exception vs cost control (CONFLICT 1)
        # Modify effect to add special tags for AI workloads that would normally be denied by Rule 0
        # Note only M128s is allowed
        modify contains modification if {
            modification := {
                "resource": input,
                "operation": "addTags", 
                "tags": {
                    "ApprovedFor": "AI-ML-Development",
                    "Exception": "HighPerformanceCompute"
                }
            }
            input.type == "Microsoft.Compute/virtualMachines"
            input.properties.hardwareProfile.vmSize in ["Standard_M128s"]
            input.tags.Workload == "AI-ML"
            input.tags.Environment in ["dev", "test"]  # This creates conflict with Rule 0
            input.tags.ProjectCode == "ML-2025"
        }

        # Rule 2: Network security baseline (STRATEGIC CONFLICT #2)  
        deny contains msg if {
            input.type == "Microsoft.Network/networkSecurityGroups"
            rule := input.properties.securityRules[_]
            rule.properties.access == "Allow"
            rule.properties.direction == "Inbound"
            rule.properties.protocol == "TCP"
            rule.properties.destinationPortRange in ["22", "3389"]
            rule.properties.sourceAddressPrefix == "*"
            msg := sprintf("NSG rule blocks public access to sensitive port %s", [rule.properties.destinationPortRange])
        }

        # Rule 3: Emergency access vs security baseline (CONFLICT 2)
        # Audit emergency NSG changes that would normally be denied by Rule 2
        audit contains finding if {
            finding := {
                "resource": input,
                "severity": "High", 
                "description": "Emergency access rule activated"
            }
            input.type == "Microsoft.Network/networkSecurityGroups"
            input.tags.EmergencyAccess == "Approved"
            input.properties.emergency.incidentId
            input.properties.emergency.approver
            # This conflicts with Rule 2 by allowing what should be denied
            #rule := input.properties.securityRules[_]
            rule := input.properties.securityRules[0]
            rule.properties.access == "Allow"
            rule.properties.direction == "Inbound"
            rule.properties.protocol == "TCP"
            rule.properties.destinationPortRange in ["22", "3389"]
            rule.properties.sourceAddressPrefix == "*"
        }
    "#;

    engine.add_policy(
        "azure_tagging.rego".to_string(),
        azure_tagging_policy.to_string(),
    )?;

    // Z3 formal verification of the same policy
    use std::time::Instant;
    println!("🔍 Z3 Formal Verification:");
    let start = Instant::now();
    let mut verifier = Z3PolicyVerifier::new();

    // Focus verification on entry point rules only (Azure Policy effects)
    let entry_points = &[
        "data.azure.resources.deny",
        "data.azure.resources.audit", 
        "data.azure.resources.modify",
    ];
    let verification_result = verifier.verify_entry_points(azure_tagging_policy, entry_points)?;
    let verification_time = start.elapsed();

    println!(
        "   - Policy consistency: {}",
        if verification_result.is_consistent {
            "✅ CONSISTENT"
        } else {
            "❌ INCONSISTENT"
        }
    );
    println!(
        "   - Conflicts detected: {}",
        verification_result.conflicts.len()
    );
    println!("   - Verification time: {:?}", verification_time);

    if !verification_result.is_consistent {
        println!("   - Conflict Details:");
        for conflict in &verification_result.conflicts {
            println!("{}", conflict);
        }
    }

    // Scope analysis removed as field doesn't exist in current struct
    // let scope_analysis = &verification_result.scope_analysis;
    // println!(
    //     "\n🔍 Z3 Scope Analysis:\n   - Scope analysis time: {:?}\n   - Rules analyzed: {}\n   - Disjoint rule pairs: {}\n   - Overlapping rule pairs: {}",
    //     scope_analysis.analysis_time,
    //     scope_analysis.total_rules,
    //     scope_analysis.disjoint_pairs,
    //     scope_analysis.overlapping_pairs
    // );

    // Print detailed scope report
    // println!("\n📋 Detailed Scope Analysis:");
    // println!("{}", scope_analysis.scope_coverage_report);

    // Z3-driven test case generation for Azure policies
    println!("\n🧪 Z3-Generated Azure Test Cases:");
    let test_cases = verifier.generate_test_cases(azure_tagging_policy)?;
    for (i, test_case) in test_cases.iter().take(3).enumerate() {
        engine.clear_data();
        engine.set_input_json(&test_case.input)?;
        
        let deny_results = engine.eval_rule("data.azure.resources.deny".to_string())?;
        let audit_results = engine.eval_rule("data.azure.resources.audit".to_string())?;
        let modify_results = engine.eval_rule("data.azure.resources.modify".to_string())?;
        
        let deny_count = if let Value::Set(denies) = &deny_results { denies.len() } else { 0 };
        let audit_count = if let Value::Set(audits) = &audit_results { audits.len() } else { 0 };
        let modify_count = if let Value::Set(modifies) = &modify_results { modifies.len() } else { 0 };
        
        let icon = if deny_count > 0 { "🚫 DENY" } 
                  else if audit_count > 0 { "📋 AUDIT" }
                  else if modify_count > 0 { "🔧 MODIFY" }
                  else { "✅ ALLOW" };
        
        println!("   Test {}: {} (deny: {}, audit: {}, modify: {})", 
                i + 1, icon, deny_count, audit_count, modify_count);
        println!("      Input: {}", test_case.input);
        println!("      Description: {}", test_case.description);
    }

    // Show counterexamples that violate policies
    println!("\n🚨 Z3-Generated Counterexamples:");
    let counterexamples = verifier.find_counterexamples(azure_tagging_policy, "azure_policy_conflicts")?;
    for (i, example) in counterexamples.iter().enumerate() {
        engine.clear_data();
        engine.set_input_json(&example.violating_input)?;
        
        let deny_results = engine.eval_rule("data.azure.resources.deny".to_string())?;
        let audit_results = engine.eval_rule("data.azure.resources.audit".to_string())?;
        let modify_results = engine.eval_rule("data.azure.resources.modify".to_string())?;
        
        let deny_count = if let Value::Set(denies) = &deny_results { denies.len() } else { 0 };
        let audit_count = if let Value::Set(audits) = &audit_results { audits.len() } else { 0 };
        let modify_count = if let Value::Set(modifies) = &modify_results { modifies.len() } else { 0 };
        
        println!("   Counterexample {}: Input that violates property: {}", i + 1, example.property);
        println!("      Azure Policy Effects: deny={}, audit={}, modify={}", deny_count, audit_count, modify_count);
        println!("      Input: {}", example.violating_input);
    }

    println!();
    Ok(())
}
