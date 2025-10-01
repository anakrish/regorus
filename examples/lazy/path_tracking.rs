// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Path Tracking Example (Azure Policy-style Aliases)
//!
//! Demonstrates lazy evaluation with path tracking for resource aliases.
//!
//! Run with: cargo run --example path_tracking

use anyhow::Result;
use regorus::lazy::{
    FieldGetter, IndexGetter, LazyArray, LazyContext, LazyObject, LengthGetter, SchemaBuilder,
    TypeId,
};
use regorus::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("🚀 Path Tracking for Aliases Example\n");
    println!("Demonstrates Azure Policy-style alias resolution with lazy evaluation.\n");

    let access_count = Arc::new(AtomicUsize::new(0));

    // Define network interface getter
    struct NetworkInterfaceGetter {
        index: usize,
        count: Arc<AtomicUsize>,
    }
    impl FieldGetter for NetworkInterfaceGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  📍 Fetching network interface [{}] id", self.index);
            Ok(Value::from(format!(
                "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-{}",
                self.index
            )))
        }
    }

    // Register network interface schema for each index
    SchemaBuilder::new("NetworkInterface0")
        .field_immediate(
            "id",
            NetworkInterfaceGetter {
                index: 0,
                count: access_count.clone(),
            },
        )
        .register();
    SchemaBuilder::new("NetworkInterface1")
        .field_immediate(
            "id",
            NetworkInterfaceGetter {
                index: 1,
                count: access_count.clone(),
            },
        )
        .register();
    SchemaBuilder::new("NetworkInterface2")
        .field_immediate(
            "id",
            NetworkInterfaceGetter {
                index: 2,
                count: access_count.clone(),
            },
        )
        .register();

    // Define array getters for network interfaces
    struct NetworkInterfacesLength;
    impl LengthGetter for NetworkInterfacesLength {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(3) // 3 network interfaces
        }
    }

    struct NetworkInterfacesIndex {
        count: Arc<AtomicUsize>,
    }
    impl IndexGetter for NetworkInterfacesIndex {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  🔍 Loading network interface [{}]", index);

            let type_id = match index {
                0 => TypeId::new("NetworkInterface0"),
                1 => TypeId::new("NetworkInterface1"),
                2 => TypeId::new("NetworkInterface2"),
                _ => return Ok(None),
            };

            let interface = LazyObject::new(type_id, LazyContext::new());

            Ok(Some(Value::LazyObject(Arc::new(interface))))
        }
    }

    let policy = r#"
        package aliases

        # Extract all network interface IDs (Azure Policy style)
        network_interface_ids := [nic_id |
            some nic in input.properties.networkProfile.networkInterfaces
            nic_id := nic.id
        ]

        # Check if any interface matches a pattern
        has_nic_in_resourcegroup(rg) if {
            some nic in input.properties.networkProfile.networkInterfaces
            contains(nic.id, rg)
        }

        # Get first interface ID (only materializes first element)
        primary_nic_id := input.properties.networkProfile.networkInterfaces[0].id
    "#;

    let mut engine = Engine::new();
    engine.add_policy("aliases.rego".to_string(), policy.to_string())?;

    // Scenario 1: Extract all network interface IDs
    println!("📋 Scenario 1: Extract All Network Interface IDs");
    println!("Path: properties.networkProfile.networkInterfaces[*].id\n");

    let access_count1 = Arc::new(AtomicUsize::new(0));

    let interfaces_array1 = LazyArray::new(
        TypeId::new("NetworkInterfaces"),
        LazyContext::new(),
        NetworkInterfacesLength,
        NetworkInterfacesIndex {
            count: access_count1.clone(),
        },
    );

    let mut network_profile1 = Value::new_object();
    network_profile1.as_object_mut()?.insert(
        Value::from("networkInterfaces"),
        Value::LazyArray(Arc::new(interfaces_array1)),
    );

    let mut properties1 = Value::new_object();
    properties1
        .as_object_mut()?
        .insert(Value::from("networkProfile"), network_profile1);

    let mut input1 = Value::new_object();
    input1
        .as_object_mut()?
        .insert(Value::from("properties"), properties1);

    engine.set_input(input1);
    let result1 = engine.eval_query("data.aliases.network_interface_ids".to_string(), false)?;

    println!("\n✅ Network Interface IDs:");
    if result1.result.len() > 0 && result1.result[0].expressions.len() > 0 {
        if let Value::Array(ref arr) = result1.result[0].expressions[0].value {
            for (i, id) in arr.iter().enumerate() {
                println!("  [{}] {}", i, id);
            }
        }
    }
    println!(
        "📊 Total accesses: {} (fetched all 3 interfaces)",
        access_count1.load(Ordering::SeqCst)
    );

    // Scenario 2: Check for interface in specific resource group (early exit)
    println!("\n\n📋 Scenario 2: Check for Interface in Resource Group");
    println!("Should exit early after finding first match\n");

    let access_count2 = Arc::new(AtomicUsize::new(0));

    let interfaces_array2 = LazyArray::new(
        TypeId::new("NetworkInterfaces"),
        LazyContext::new(),
        NetworkInterfacesLength,
        NetworkInterfacesIndex {
            count: access_count2.clone(),
        },
    );

    let mut network_profile2 = Value::new_object();
    network_profile2.as_object_mut()?.insert(
        Value::from("networkInterfaces"),
        Value::LazyArray(Arc::new(interfaces_array2)),
    );

    let mut properties2 = Value::new_object();
    properties2
        .as_object_mut()?
        .insert(Value::from("networkProfile"), network_profile2);

    let mut input2 = Value::new_object();
    input2
        .as_object_mut()?
        .insert(Value::from("properties"), properties2);

    engine.set_input(input2);
    let result2 = engine.eval_query(
        "data.aliases.has_nic_in_resourcegroup(\"resourceGroups/rg\")".to_string(),
        false,
    )?;

    println!(
        "\n✅ Has NIC in resource group 'rg': {}",
        result2.result.len() > 0 && result2.result[0].expressions.len() > 0
    );
    println!(
        "📊 Total accesses: {} (early exit after finding match!)",
        access_count2.load(Ordering::SeqCst)
    );

    // Scenario 3: Get only primary (first) interface ID
    println!("\n\n📋 Scenario 3: Get Primary Network Interface ID");
    println!("Path: properties.networkProfile.networkInterfaces[0].id");
    println!("Should only fetch index 0, not all interfaces\n");

    let access_count3 = Arc::new(AtomicUsize::new(0));

    let interfaces_array3 = LazyArray::new(
        TypeId::new("NetworkInterfaces"),
        LazyContext::new(),
        NetworkInterfacesLength,
        NetworkInterfacesIndex {
            count: access_count3.clone(),
        },
    );

    let mut network_profile3 = Value::new_object();
    network_profile3.as_object_mut()?.insert(
        Value::from("networkInterfaces"),
        Value::LazyArray(Arc::new(interfaces_array3)),
    );

    let mut properties3 = Value::new_object();
    properties3
        .as_object_mut()?
        .insert(Value::from("networkProfile"), network_profile3);

    let mut input3 = Value::new_object();
    input3
        .as_object_mut()?
        .insert(Value::from("properties"), properties3);

    engine.set_input(input3);
    let result3 = engine.eval_query("data.aliases.primary_nic_id".to_string(), false)?;

    println!("\n✅ Primary NIC ID:");
    if result3.result.len() > 0 && result3.result[0].expressions.len() > 0 {
        println!("  {}", result3.result[0].expressions[0].value);
    }
    println!(
        "📊 Total accesses: {} (only fetched index 0!)",
        access_count3.load(Ordering::SeqCst)
    );

    println!("\n\n🎯 Summary:");
    println!("Path tracking with lazy evaluation allows Azure Policy-style aliases");
    println!("to efficiently navigate nested structures:");
    println!("- Scenario 1: Fetched all 3 interfaces (full iteration)");
    println!("- Scenario 2: Early exit on first match (1-2 fetches)");
    println!("- Scenario 3: Only index 0 fetched (minimal access)");

    Ok(())
}
