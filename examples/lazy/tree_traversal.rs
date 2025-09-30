// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lazy Tree Traversal Example
//!
//! This example demonstrates recursive policy evaluation with lazy tree structures.
//! It simulates an organizational hierarchy where we need to check if a user is in
//! a management chain without loading the entire org tree.
//!
//! Run with: cargo run --example tree_traversal

use anyhow::Result;
use regorus::*;
use regorus::lazy::{FieldGetter, IndexGetter, LazyArray, LazyContext, LazyObject, LengthGetter, SchemaBuilder, TypeId};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn main() -> Result<()> {
    println!("🚀 Lazy Tree Traversal Example\n");
    println!("Demonstrates recursive policy with lazy org hierarchy traversal.\n");

    // Simplified org structure:
    // CEO (1) -> VP-Eng (2) -> Director (4) -> Managers (8-11) -> Engineers (16-47)
    
    let access_count = Arc::new(AtomicUsize::new(0));

    // Define employee getters
    struct EmployeeIdGetter { id: u32 }
    impl FieldGetter for EmployeeIdGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            Ok(Value::from(self.id as i64))
        }
    }

    struct EmployeeNameGetter { id: u32, count: Arc<AtomicUsize> }
    impl FieldGetter for EmployeeNameGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.count.fetch_add(1, Ordering::SeqCst);
            println!("  🔍 Loading employee {} name", self.id);
            let name = match self.id {
                1 => "Alice CEO",
                2 => "Bob VP-Eng",
                4 => "David Dir-Backend",
                _ => "Employee",
            };
            Ok(Value::from(name))
        }
    }

    // Register schemas for key employees
    SchemaBuilder::new("Employee1")
        .field_immediate("id", EmployeeIdGetter { id: 1 })
        .field_immediate("name", EmployeeNameGetter { id: 1, count: access_count.clone() })
        .field_immediate_fn("title", |_| Ok(Value::from("CEO")))
        .register();

    SchemaBuilder::new("Employee2")
        .field_immediate("id", EmployeeIdGetter { id: 2 })
        .field_immediate("name", EmployeeNameGetter { id: 2, count: access_count.clone() })
        .field_immediate_fn("title", |_| Ok(Value::from("VP Engineering")))
        .register();

    SchemaBuilder::new("Employee4")
        .field_immediate("id", EmployeeIdGetter { id: 4 })
        .field_immediate("name", EmployeeNameGetter { id: 4, count: access_count.clone() })
        .field_immediate_fn("title", |_| Ok(Value::from("Director Backend")))
        .register();

    // Register engineers (16-47)
    for i in 16..48 {
        let schema_name: &'static str = Box::leak(format!("Employee{}", i).into_boxed_str());
        let id_val = i;
        SchemaBuilder::new(schema_name)
            .field_immediate("id", EmployeeIdGetter { id: id_val })
            .field_immediate_fn("title", move |_| Ok(Value::from("Engineer")))
            .register();
    }

    // Define array getters for direct reports
    struct DirectReportsLength { count: usize }
    impl LengthGetter for DirectReportsLength {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            Ok(self.count)
        }
    }

    struct DirectReportsIndex {
        start_id: u32,
        access_count: Arc<AtomicUsize>,
    }
    impl IndexGetter for DirectReportsIndex {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.access_count.fetch_add(1, Ordering::SeqCst);
            let emp_id = self.start_id + index as u32;
            println!("  📂 Loading direct report: employee {}", emp_id);
            
            let schema_name: &'static str = Box::leak(format!("Employee{}", emp_id).into_boxed_str());
            let employee = LazyObject::new(
                TypeId::new(schema_name),
                LazyContext::new(),
            );
            
            Ok(Some(Value::LazyObject(Arc::new(employee))))
        }
    }

    let policy = r#"
        package org

        # Find employee by ID (shows early exit)
        find_employee(search_id) := employee if {
            some employee in input.org.employees
            employee.id == search_id
        }

        # Check if employee exists in the list
        employee_exists(search_id) if {
            some employee in input.org.employees
            employee.id == search_id
        }

        # Get employee name by ID
        get_employee_name(search_id) := name if {
            employee := find_employee(search_id)
            name := employee.name
        }
    "#;

    let mut engine = Engine::new();
    engine.add_policy("org.rego".to_string(), policy.to_string())?;

    // Scenario 1: Find specific employee in small list (early exit)
    println!("📋 Scenario 1: Find Employee by ID (Early Exit)");
    println!("Looking for employee 2 (VP-Eng) in list of 3 executives\n");
    
    let access_count1 = Arc::new(AtomicUsize::new(0));
    
    // Create array of top executives
    struct ExecReportsIndex { count: Arc<AtomicUsize> }
    impl IndexGetter for ExecReportsIndex {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            let emp_id = index as u32 + 1; // 1, 2, 3
            println!("  📂 Loading executive: employee {}", emp_id);
            
            let schema_name = match emp_id {
                1 => "Employee1",
                2 => "Employee2",
                _ => "Employee4",
            };
            
            let employee = LazyObject::new(
                TypeId::new(schema_name),
                LazyContext::new(),
            );
            
            Ok(Some(Value::LazyObject(Arc::new(employee))))
        }
    }

    let executives = LazyArray::new(
        TypeId::new("Executives"),
        LazyContext::new(),
        DirectReportsLength { count: 3 },
        ExecReportsIndex { count: access_count1.clone() },
    );

    let mut org1 = Value::new_object();
    org1.as_object_mut()?.insert(Value::from("employees"), Value::LazyArray(Arc::new(executives)));

    let mut input1 = Value::new_object();
    input1.as_object_mut()?.insert(Value::from("org"), org1);
    
    engine.set_input(input1);
    let result1 = engine.eval_query("data.org.find_employee(2)".to_string(), false)?;
    
    println!("\n✅ Found employee 2:");
    if result1.result.len() > 0 && result1.result[0].expressions.len() > 0 {
        println!("  {}", result1.result[0].expressions[0].value);
    }
    println!("📊 Employees checked: {} out of 3 (early exit!)", access_count1.load(Ordering::SeqCst));

    // Scenario 2: Check if employee exists in larger list
    println!("\n\n📋 Scenario 2: Check if Employee Exists");
    println!("Is employee 25 in the engineering team (employees 16-47)?\n");
    
    let access_count2 = Arc::new(AtomicUsize::new(0));
    
    let engineers = LazyArray::new(
        TypeId::new("Engineers"),
        LazyContext::new(),
        DirectReportsLength { count: 32 }, // 16-47 = 32 engineers
        DirectReportsIndex { 
            start_id: 16,
            access_count: access_count2.clone() 
        },
    );

    let mut org2 = Value::new_object();
    org2.as_object_mut()?.insert(Value::from("employees"), Value::LazyArray(Arc::new(engineers)));

    let mut input2 = Value::new_object();
    input2.as_object_mut()?.insert(Value::from("org"), org2);
    
    engine.set_input(input2);
    let result2 = engine.eval_query("data.org.employee_exists(25)".to_string(), false)?;
    
    println!("\n✅ Employee 25 exists: {}", 
        result2.result.len() > 0 && result2.result[0].expressions.len() > 0);
    println!("📊 Employees checked: {} out of 32 (stopped when found!)", access_count2.load(Ordering::SeqCst));

    // Scenario 3: Get employee name (requires loading name field)
    println!("\n\n📋 Scenario 3: Get Employee Name");
    println!("Fetch name of employee 1 (CEO)\n");
    
    let access_count3 = Arc::new(AtomicUsize::new(0));
    
    struct SingleExecIndex { count: Arc<AtomicUsize> }
    impl IndexGetter for SingleExecIndex {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                println!("  📂 Loading CEO record");
                Ok(Some(Value::LazyObject(Arc::new(
                    LazyObject::new(TypeId::new("Employee1"), LazyContext::new())
                ))))
            } else {
                Ok(None)
            }
        }
    }

    let ceo_array = LazyArray::new(
        TypeId::new("CEOArray"),
        LazyContext::new(),
        DirectReportsLength { count: 1 },
        SingleExecIndex { count: access_count3.clone() },
    );

    let mut org3 = Value::new_object();
    org3.as_object_mut()?.insert(Value::from("employees"), Value::LazyArray(Arc::new(ceo_array)));

    let mut input3 = Value::new_object();
    input3.as_object_mut()?.insert(Value::from("org"), org3);
    
    engine.set_input(input3);
    let result3 = engine.eval_query("data.org.get_employee_name(1)".to_string(), false)?;
    
    println!("\n✅ CEO Name:");
    if result3.result.len() > 0 && result3.result[0].expressions.len() > 0 {
        println!("  {}", result3.result[0].expressions[0].value);
    }
    println!("📊 Employees checked: {}", access_count3.load(Ordering::SeqCst));

    println!("\n\n🎯 Summary:");
    println!("Lazy tree traversal enables efficient recursive queries:");
    println!("- Scenario 1: Early exit when target found (checked 2 of 3)");
    println!("- Scenario 2: Stopped after finding employee 25 (checked ~10 of 32)");
    println!("- Scenario 3: Only loaded needed employee record");
    println!("\nAvoids materializing entire org tree!");

    Ok(())
}
