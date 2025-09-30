// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Database Integration Example with SQLite
//!
//! Demonstrates lazy loading from a real SQLite database.
//! Shows how Regorus lazy evaluation translates to efficient SQL queries.
//!
//! Key Benefits:
//! - Only executes SQL queries for fields actually accessed by policy
//! - Early exit stops querying database when condition is met
//! - Can integrate with any database (PostgreSQL, MySQL, Redis, etc.)
//!
//! Run with: cargo run --example database_integration

use anyhow::Result;
use regorus::*;
use regorus::lazy::{FieldGetter, IndexGetter, LazyArray, LazyContext, LazyObject, LengthGetter, SchemaBuilder, TypeId};
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};

// Database wrapper that tracks SQL queries
#[derive(Clone)]
struct Database {
    conn: Arc<Mutex<Connection>>,
    query_count: Arc<AtomicUsize>,
}

impl Database {
    fn new() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        
        // Create users table
        conn.execute(
            "CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                quota INTEGER NOT NULL,
                department TEXT NOT NULL
            )",
            [],
        )?;
        
        // Populate with sample data
        for i in 1..=100 {
            conn.execute(
                "INSERT INTO users (id, name, email, role, quota, department) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    i,
                    format!("User {}", i),
                    format!("user{}@example.com", i),
                    if i <= 5 { "admin" } else { "user" },
                    if i <= 5 { 10000 } else { 1000 },
                    match i % 3 {
                        0 => "Engineering",
                        1 => "Sales",
                        _ => "Marketing",
                    }
                ],
            )?;
        }
        
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            query_count: Arc::new(AtomicUsize::new(0)),
        })
    }
    
    fn execute_query(&self, query: &str) {
        self.query_count.fetch_add(1, Ordering::SeqCst);
        println!("  🗄️  SQL: {}", query);
    }
    
    fn get_user_field(&self, user_id: i64, field: &str) -> Result<Value> {
        let query = format!("SELECT {} FROM users WHERE id = {}", field, user_id);
        self.execute_query(&query);
        
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        
        if let Some(row) = rows.next()? {
            match field {
                "id" => Ok(Value::from(row.get::<_, i64>(0)?)),
                "name" => Ok(Value::from(row.get::<_, String>(0)?)),
                "email" => Ok(Value::from(row.get::<_, String>(0)?)),
                "role" => Ok(Value::from(row.get::<_, String>(0)?)),
                "quota" => Ok(Value::from(row.get::<_, i64>(0)?)),
                "department" => Ok(Value::from(row.get::<_, String>(0)?)),
                _ => Ok(Value::Null),
            }
        } else {
            Ok(Value::Null)
        }
    }
    
    fn count_users(&self) -> Result<usize> {
        let query = "SELECT COUNT(*) FROM users";
        self.execute_query(query);
        
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(query, [], |row| row.get(0))?;
        Ok(count as usize)
    }
    
    fn get_user_at_index(&self, index: usize) -> Result<Option<i64>> {
        let query = format!("SELECT id FROM users ORDER BY id LIMIT 1 OFFSET {}", index);
        self.execute_query(&query);
        
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(&query)?;
        let mut rows = stmt.query([])?;
        
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }
    
    fn get_query_count(&self) -> usize {
        self.query_count.load(Ordering::SeqCst)
    }
    
    fn reset_query_count(&self) {
        self.query_count.store(0, Ordering::SeqCst);
    }
}

fn main() -> Result<()> {
    println!("🚀 Database Integration Example\n");
    println!("Demonstrates lazy loading from a real SQLite database.\n");
    
    let db = Database::new()?;
    
    // Create field getters for user schema
    struct UserIdGetter { user_id: i64, db: Database }
    impl FieldGetter for UserIdGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "id")
        }
    }
    
    struct UserNameGetter { user_id: i64, db: Database }
    impl FieldGetter for UserNameGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "name")
        }
    }
    
    struct UserEmailGetter { user_id: i64, db: Database }
    impl FieldGetter for UserEmailGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "email")
        }
    }
    
    struct UserRoleGetter { user_id: i64, db: Database }
    impl FieldGetter for UserRoleGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "role")
        }
    }
    
    struct UserQuotaGetter { user_id: i64, db: Database }
    impl FieldGetter for UserQuotaGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "quota")
        }
    }
    
    struct UserDepartmentGetter { user_id: i64, db: Database }
    impl FieldGetter for UserDepartmentGetter {
        fn get(&self, _ctx: &LazyContext) -> Result<Value> {
            self.db.get_user_field(self.user_id, "department")
        }
    }
    
    // Array getters
    struct UsersLengthGetter { db: Database }
    impl LengthGetter for UsersLengthGetter {
        fn len(&self, _ctx: &LazyContext) -> Result<usize> {
            self.db.count_users()
        }
    }
    
    struct UsersIndexGetter { db: Database }
    impl IndexGetter for UsersIndexGetter {
        fn get_at(&self, _ctx: &LazyContext, index: usize) -> Result<Option<Value>> {
            if let Some(user_id) = self.db.get_user_at_index(index)? {
                // Register schema for this user
                let schema_name: &'static str = Box::leak(format!("User{}", user_id).into_boxed_str());
                let db_clone = self.db.clone();
                
                SchemaBuilder::new(schema_name)
                    .field_deferred("id", UserIdGetter { user_id, db: db_clone.clone() })
                    .field_deferred("name", UserNameGetter { user_id, db: db_clone.clone() })
                    .field_deferred("email", UserEmailGetter { user_id, db: db_clone.clone() })
                    .field_deferred("role", UserRoleGetter { user_id, db: db_clone.clone() })
                    .field_deferred("quota", UserQuotaGetter { user_id, db: db_clone.clone() })
                    .field_deferred("department", UserDepartmentGetter { user_id, db: db_clone })
                    .register();
                
                let user = LazyObject::new(TypeId::new(schema_name), LazyContext::new());
                Ok(Some(Value::LazyObject(Arc::new(user))))
            } else {
                Ok(None)
            }
        }
    }
    
    let policy = r#"
        package authz

        # Check if user is admin (only needs role field)
        is_admin if {
            input.user.role == "admin"
        }

        # Find first admin in list (early exit)
        first_admin := user if {
            some user in input.users
            user.role == "admin"
        }

        # Check quota for specific user (only queries quota)
        has_high_quota if {
            input.user.quota >= 5000
        }

        # Complex policy that may not need all fields
        allow if {
            input.user.role == "admin"
        } else if {
            input.user.department == "Engineering"
            input.user.quota >= 1000
        }
    "#;

    let mut engine = Engine::new();
    engine.add_policy("authz.rego".to_string(), policy.to_string())?;

    // Scenario 1: Check if single user is admin (only role field needed)
    println!("📋 Scenario 1: Check if User is Admin");
    println!("Policy only checks role field - other fields shouldn't be queried\n");
    
    db.reset_query_count();
    
    SchemaBuilder::new("SingleUser")
        .field_deferred("id", UserIdGetter { user_id: 3, db: db.clone() })
        .field_deferred("name", UserNameGetter { user_id: 3, db: db.clone() })
        .field_deferred("email", UserEmailGetter { user_id: 3, db: db.clone() })
        .field_deferred("role", UserRoleGetter { user_id: 3, db: db.clone() })
        .field_deferred("quota", UserQuotaGetter { user_id: 3, db: db.clone() })
        .field_deferred("department", UserDepartmentGetter { user_id: 3, db: db.clone() })
        .register();
    
    let user1 = LazyObject::new(TypeId::new("SingleUser"), LazyContext::new());
    let mut input1 = Value::new_object();
    input1.as_object_mut()?.insert(Value::from("user"), Value::LazyObject(Arc::new(user1)));
    
    engine.set_input(input1);
    let result1 = engine.eval_query("data.authz.is_admin".to_string(), false)?;
    
    println!("\n✅ Is admin: {}", result1.result.len() > 0 && result1.result[0].expressions.len() > 0);
    println!("📊 SQL queries executed: {} (only queried 'role' field!)", db.get_query_count());

    // Scenario 2: Find first admin in list (early exit)
    println!("\n\n📋 Scenario 2: Find First Admin in User List");
    println!("Should stop after finding first admin (user 1)\n");
    
    db.reset_query_count();
    
    let users_array = LazyArray::new(
        TypeId::new("UsersArray"),
        LazyContext::new(),
        UsersLengthGetter { db: db.clone() },
        UsersIndexGetter { db: db.clone() },
    );
    
    let mut input2 = Value::new_object();
    input2.as_object_mut()?.insert(Value::from("users"), Value::LazyArray(Arc::new(users_array)));
    
    engine.set_input(input2);
    let result2 = engine.eval_query("data.authz.first_admin".to_string(), false)?;
    
    println!("\n✅ Found first admin:");
    if result2.result.len() > 0 && result2.result[0].expressions.len() > 0 {
        println!("  {}", result2.result[0].expressions[0].value);
    }
    println!("📊 SQL queries executed: {}", db.get_query_count());

    // Scenario 3: Check quota (only quota field needed)
    println!("\n\n📋 Scenario 3: Check High Quota");
    println!("Policy only checks quota - other fields shouldn't be queried\n");
    
    db.reset_query_count();
    
    SchemaBuilder::new("QuotaUser")
        .field_deferred("id", UserIdGetter { user_id: 2, db: db.clone() })
        .field_deferred("name", UserNameGetter { user_id: 2, db: db.clone() })
        .field_deferred("email", UserEmailGetter { user_id: 2, db: db.clone() })
        .field_deferred("role", UserRoleGetter { user_id: 2, db: db.clone() })
        .field_deferred("quota", UserQuotaGetter { user_id: 2, db: db.clone() })
        .field_deferred("department", UserDepartmentGetter { user_id: 2, db: db.clone() })
        .register();
    
    let user3 = LazyObject::new(TypeId::new("QuotaUser"), LazyContext::new());
    let mut input3 = Value::new_object();
    input3.as_object_mut()?.insert(Value::from("user"), Value::LazyObject(Arc::new(user3)));
    
    engine.set_input(input3);
    let result3 = engine.eval_query("data.authz.has_high_quota".to_string(), false)?;
    
    println!("\n✅ Has high quota: {}", result3.result.len() > 0 && result3.result[0].expressions.len() > 0);
    println!("📊 SQL queries executed: {} (only queried 'quota' field!)", db.get_query_count());

    // Scenario 4: Complex policy with early exit
    println!("\n\n📋 Scenario 4: Authorization Check (Early Exit on Admin)");
    println!("Admin user - should only check role, not department/quota\n");
    
    db.reset_query_count();
    
    SchemaBuilder::new("AdminUser")
        .field_deferred("id", UserIdGetter { user_id: 1, db: db.clone() })
        .field_deferred("name", UserNameGetter { user_id: 1, db: db.clone() })
        .field_deferred("email", UserEmailGetter { user_id: 1, db: db.clone() })
        .field_deferred("role", UserRoleGetter { user_id: 1, db: db.clone() })
        .field_deferred("quota", UserQuotaGetter { user_id: 1, db: db.clone() })
        .field_deferred("department", UserDepartmentGetter { user_id: 1, db: db.clone() })
        .register();
    
    let user4 = LazyObject::new(TypeId::new("AdminUser"), LazyContext::new());
    let mut input4 = Value::new_object();
    input4.as_object_mut()?.insert(Value::from("user"), Value::LazyObject(Arc::new(user4)));
    
    engine.set_input(input4);
    let result4 = engine.eval_query("data.authz.allow".to_string(), false)?;
    
    println!("\n✅ Allowed: {}", result4.result.len() > 0 && result4.result[0].expressions.len() > 0);
    println!("📊 SQL queries executed: {} (early exit on admin check!)", db.get_query_count());

    println!("\n\n🎯 Summary:");
    println!("Lazy database integration provides massive performance benefits:");
    println!("- Scenario 1: Only 1 SQL query (role) instead of 6 (all fields)");
    println!("- Scenario 2: Early exit with COUNT + minimal row fetches");
    println!("- Scenario 3: Only 1 SQL query (quota) instead of 6");
    println!("- Scenario 4: Only 1 SQL query (role) due to early exit");
    println!("\n💡 Real SQLite database demonstrates actual SQL query optimization!");

    Ok(())
}
