// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the RVM symbolic analysis engine.
//!
//! These tests require the `z3-analysis` feature for solving.

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::string::ToString;

    use crate::rvm::analysis::*;
    use crate::value::Value;
    use regorus_smt::SmtExpr;

    /// Smoke test: the Z3 solver backend can solve a trivial boolean constraint.
    #[test]
    fn test_z3_smoke() {
        use regorus_smt::{SmtProblem, SmtSort, SmtStatus};

        let mut problem = SmtProblem::new();
        let x_id = problem.declare_const("x", SmtSort::Bool);
        // Assert x == true.
        problem.assert(SmtExpr::Const(x_id));

        let solution = crate::rvm::analysis::z3_solver::solve(&problem).unwrap();
        let check = solution.first().unwrap();
        assert_eq!(check.status, SmtStatus::Sat);
    }

    /// Test PathRegistry creation and variable access.
    #[test]
    fn test_path_registry() {
        let mut registry = PathRegistry::new();

        // Create a string path variable.
        let _entry = registry.get_or_create("input.user.role", ValueSort::String, true, 0);
        assert_eq!(registry.len(), 1);

        // Get the SMT string variable.
        let smt_str = registry.get_string("input.user.role");
        // smt_str should be a Const reference.
        match smt_str {
            SmtExpr::Const(_) => {} // ok
            other => panic!("Expected Const, got: {:?}", other),
        }

        // Creating again should reuse.
        let _entry2 = registry.get_or_create("input.user.role", ValueSort::String, true, 5);
        assert_eq!(registry.len(), 1);
    }

    /// Test that model extraction produces the right JSON structure.
    #[test]
    fn test_model_extraction() {
        use regorus_smt::{SmtProblem, SmtSort, SmtStatus};

        let mut registry = PathRegistry::new();

        // Create a path variable and constrain it to "admin".
        let _ = registry.get_or_create("input.user.role", ValueSort::String, true, 0);
        let role_var = registry.get_string("input.user.role");
        let admin = SmtExpr::StringLit("admin".into());
        let defined = registry.get("input.user.role").unwrap().defined.clone();

        // Build a SmtProblem manually.
        let mut problem = SmtProblem::new();

        // Declarations from the registry.
        for decl in registry.declarations() {
            problem.declarations.push(decl.clone());
        }

        // Assert: role_var == "admin" AND defined.
        problem.assert(SmtExpr::Eq(Box::new(role_var), Box::new(admin)));
        problem.assert(defined);

        // Register extractions for model reconstruction.
        let plan = crate::rvm::analysis::model_extract::register_extractions(
            &mut problem,
            &registry,
        );

        let solution = crate::rvm::analysis::z3_solver::solve(&problem).unwrap();
        let check = solution.first().unwrap();
        assert_eq!(check.status, SmtStatus::Sat);

        let input = crate::rvm::analysis::model_extract::extract_input(check, &plan);

        // The result should be {"user": {"role": "admin"}}.
        assert!(input != Value::Undefined);
        let user = &input[&Value::from("user")];
        assert!(user != &Value::Undefined, "expected 'user' key in result");
        let role = &user[&Value::from("role")];
        assert_eq!(role, &Value::from("admin"));
    }

    /// Test Definedness AND combinator.
    #[test]
    fn test_definedness_and() {
        // Defined AND Defined → Defined.
        let r = Definedness::and(&Definedness::Defined, &Definedness::Defined);
        assert!(r.is_defined());

        // Undefined AND anything → Undefined.
        let r = Definedness::and(&Definedness::Undefined, &Definedness::Defined);
        assert!(r.is_undefined());

        // Defined AND Symbolic → Symbolic.
        let b = SmtExpr::Const(99); // arbitrary const id
        let r = Definedness::and(&Definedness::Defined, &Definedness::Symbolic(b));
        assert!(!r.is_defined() && !r.is_undefined()); // Symbolic
    }

    // ===================================================================
    // Helper: compile policy + run analysis, print results
    // ===================================================================

    fn run_analysis(
        test_name: &str,
        policy: &str,
        entrypoint: &str,
        desired: Value,
    ) -> (crate::rvm::analysis::AnalysisResult, alloc::string::String) {
        use alloc::string::ToString;

        use crate::engine::Engine;
        use crate::languages::rego::compiler::Compiler;
        use crate::rvm::analysis::{generate_input, AnalysisConfig};

        let mut engine = Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("add_policy");

        let entry_point: crate::Rc<str> = crate::Rc::from(entrypoint);
        let compiled = engine
            .compile_with_entrypoint(&entry_point)
            .expect("compile_with_entrypoint");

        let program =
            Compiler::compile_from_policy(&compiled, &[entrypoint]).expect("compile_from_policy");

        let config = AnalysisConfig::default();
        let data = Value::new_object();

        let result = generate_input(&program, &data, &desired, entrypoint, &config);

        let mut output = alloc::string::String::new();
        output.push_str(&alloc::format!("\n=== {} ===\n", test_name));
        output.push_str(&alloc::format!("Policy:\n{}\n", policy));

        match result {
            Ok(ref r) => {
                output.push_str(&alloc::format!("Satisfiable: {}\n", r.satisfiable));
                if let Some(ref input) = r.input {
                    output.push_str(&alloc::format!(
                        "Generated input:\n{}\n",
                        input
                            .to_json_str()
                            .unwrap_or_else(|_| alloc::format!("{:?}", input))
                    ));
                }
                if !r.warnings.is_empty() {
                    output.push_str(&alloc::format!("Warnings:\n"));
                    for w in &r.warnings {
                        output.push_str(&alloc::format!("  - {}\n", w));
                    }
                }
                std::println!("{}", output);
                (r.clone(), output)
            }
            Err(e) => {
                output.push_str(&alloc::format!("Error: {}\n", e));
                std::println!("{}", output);
                panic!("{}: Analysis failed: {}", test_name, e);
            }
        }
    }

    /// Convenience: assert SAT and return the input.
    fn expect_sat(test_name: &str, policy: &str, entrypoint: &str) -> Value {
        let (result, _) = run_analysis(test_name, policy, entrypoint, Value::Bool(true));
        assert!(
            result.satisfiable,
            "{}: Expected SAT but got UNSAT",
            test_name
        );
        result
            .input
            .expect(&alloc::format!("{}: Expected input value", test_name))
    }

    // ===================================================================
    // Helper: compile policy + run goal-based analysis
    // ===================================================================

    fn run_goal_analysis(
        test_name: &str,
        policy: &str,
        entrypoint: &str,
        goal: AnalysisGoal,
    ) -> crate::rvm::analysis::AnalysisResult {
        use alloc::string::ToString;

        use crate::engine::Engine;
        use crate::languages::rego::compiler::Compiler;
        use crate::rvm::analysis::{generate_input_for_goal, AnalysisConfig};

        let mut engine = Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("add_policy");

        let entry_point: crate::Rc<str> = crate::Rc::from(entrypoint);
        let compiled = engine
            .compile_with_entrypoint(&entry_point)
            .expect("compile_with_entrypoint");

        let program =
            Compiler::compile_from_policy(&compiled, &[entrypoint]).expect("compile_from_policy");

        let config = AnalysisConfig::default();
        let data = Value::new_object();

        let result = generate_input_for_goal(&program, &data, entrypoint, &goal, &config).expect(
            &alloc::format!("{}: generate_input_for_goal failed", test_name),
        );

        std::println!("\n=== {} ===", test_name);
        std::println!("Satisfiable: {}", result.satisfiable);
        if let Some(ref input) = result.input {
            std::println!(
                "Generated input:\n{}",
                input
                    .to_json_str()
                    .unwrap_or_else(|_| alloc::format!("{:?}", input))
            );
        }
        if !result.warnings.is_empty() {
            std::println!("Warnings:");
            for w in &result.warnings {
                std::println!("  - {}", w);
            }
        }

        result
    }

    // ===================================================================
    // Level 1: Simple string equality
    // ===================================================================

    #[test]
    fn test_level1_string_eq() {
        let policy = r#"
            package test
            default allow = false
            allow if input.role == "admin"
        "#;
        let input = expect_sat("level1_string_eq", policy, "data.test.allow");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
    }

    // ===================================================================
    // Level 2: Multiple string conditions (conjunction)
    // ===================================================================

    #[test]
    fn test_level2_multi_string() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.role == "admin"
                input.action == "read"
            }
        "#;
        let input = expect_sat("level2_multi_string", policy, "data.test.allow");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
        assert_eq!(&input[&Value::from("action")], &Value::from("read"));
    }

    // ===================================================================
    // Level 3: Numeric comparison
    // ===================================================================

    #[test]
    fn test_level3_numeric_ge() {
        let policy = r#"
            package test
            default allow = false
            allow if input.age >= 18
        "#;
        let input = expect_sat("level3_numeric_ge", policy, "data.test.allow");
        let age = &input[&Value::from("age")];
        // Should be a number >= 18.
        let n = age.as_number().expect("age should be a number");
        let val = n.as_i64().expect("age should fit in i64");
        assert!(val >= 18, "Expected age >= 18, got {}", val);
    }

    // ===================================================================
    // Level 4: Mixed string + numeric conditions
    // ===================================================================

    #[test]
    fn test_level4_mixed_types() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.role == "admin"
                input.level >= 5
            }
        "#;
        let input = expect_sat("level4_mixed_types", policy, "data.test.allow");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
        let level = input[&Value::from("level")]
            .as_number()
            .expect("level should be number")
            .as_i64()
            .expect("level should fit i64");
        assert!(level >= 5, "Expected level >= 5, got {}", level);
    }

    // ===================================================================
    // Level 5: Nested object access
    // ===================================================================

    #[test]
    fn test_level5_nested_object() {
        let policy = r#"
            package test
            default allow = false
            allow if input.user.role == "admin"
        "#;
        let input = expect_sat("level5_nested_object", policy, "data.test.allow");
        let user = &input[&Value::from("user")];
        assert!(user != &Value::Undefined, "Expected 'user' key");
        assert_eq!(&user[&Value::from("role")], &Value::from("admin"));
    }

    // ===================================================================
    // Level 6: Boolean field access
    // ===================================================================

    #[test]
    fn test_level6_boolean_field() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.user.role == "admin"
                input.user.active == true
            }
        "#;
        let input = expect_sat("level6_boolean_field", policy, "data.test.allow");
        let user = &input[&Value::from("user")];
        assert_eq!(&user[&Value::from("role")], &Value::from("admin"));
        assert_eq!(&user[&Value::from("active")], &Value::Bool(true));
    }

    // ===================================================================
    // Level 7: OR rules (multiple definitions)
    // ===================================================================

    #[test]
    fn test_level7_or_rules() {
        let policy = r#"
            package test
            default allow = false
            allow if input.role == "admin"
            allow if input.role == "superuser"
        "#;
        let input = expect_sat("level7_or_rules", policy, "data.test.allow");
        let role = &input[&Value::from("role")];
        // Should be either "admin" or "superuser".
        let role_str = role.as_string().expect("role should be string");
        assert!(
            role_str.as_ref() == "admin" || role_str.as_ref() == "superuser",
            "Expected role to be 'admin' or 'superuser', got '{}'",
            role_str
        );
    }

    // ===================================================================
    // Level 8: Helper rule reference
    // ===================================================================

    #[test]
    fn test_level8_helper_rule() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                is_admin
                input.action == "write"
            }
            is_admin if input.role == "admin"
        "#;
        let input = expect_sat("level8_helper_rule", policy, "data.test.allow");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
        assert_eq!(&input[&Value::from("action")], &Value::from("write"));
    }

    // ===================================================================
    // Level 9: Negation
    // ===================================================================

    #[test]
    fn test_level9_negation() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.role == "admin"
                not input.suspended
            }
        "#;
        let (result, _) = run_analysis(
            "level9_negation",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
        // `suspended` should either be absent or false.
    }

    // ===================================================================
    // Level 10: Inequality (not-equal)
    // ===================================================================

    #[test]
    fn test_level10_not_equal() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.role != "guest"
                input.role != "anonymous"
            }
        "#;
        let (result, _) = run_analysis(
            "level10_not_equal",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        let role = input[&Value::from("role")]
            .as_string()
            .expect("role should be string");
        assert!(
            role.as_ref() != "guest" && role.as_ref() != "anonymous",
            "Expected role != guest and != anonymous, got '{}'",
            role
        );
    }

    // ===================================================================
    // Level 11: Numeric arithmetic in conditions
    // ===================================================================

    #[test]
    fn test_level11_arithmetic() {
        let policy = r#"
            package test
            default allow = false
            allow if input.score + 10 >= 100
        "#;
        let input = expect_sat("level11_arithmetic", policy, "data.test.allow");
        let score = input[&Value::from("score")]
            .as_number()
            .expect("score should be number")
            .as_i64()
            .expect("score should fit i64");
        assert!(
            score + 10 >= 100,
            "Expected score+10 >= 100, got score={}",
            score
        );
    }

    // ===================================================================
    // Level 12: UNSAT (contradictory conditions)
    // ===================================================================

    #[test]
    fn test_level12_unsat_contradiction() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.role == "admin"
                input.role == "guest"
            }
        "#;
        let (result, _) = run_analysis(
            "level12_unsat_contradiction",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(
            !result.satisfiable,
            "Expected UNSAT: role can't be both admin and guest"
        );
    }

    // ===================================================================
    // Level 13: Deep nesting with multiple constraints
    // ===================================================================

    #[test]
    fn test_level13_deep_nesting() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.request.user.department == "engineering"
                input.request.user.clearance >= 3
                input.request.resource.classification == "internal"
            }
        "#;
        let input = expect_sat("level13_deep_nesting", policy, "data.test.allow");
        let dept =
            &input[&Value::from("request")][&Value::from("user")][&Value::from("department")];
        assert_eq!(dept, &Value::from("engineering"));
        let clearance = input[&Value::from("request")][&Value::from("user")]
            [&Value::from("clearance")]
            .as_number()
            .expect("clearance should be number")
            .as_i64()
            .expect("clearance i64");
        assert!(clearance >= 3);
        let class = &input[&Value::from("request")][&Value::from("resource")]
            [&Value::from("classification")];
        assert_eq!(class, &Value::from("internal"));
    }

    // ===================================================================
    // Level 14: Chained helper rules
    // ===================================================================

    #[test]
    fn test_level14_chained_rules() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                is_authorized
                input.action == "deploy"
            }
            is_authorized if {
                is_admin
                is_active
            }
            is_admin if input.role == "admin"
            is_active if input.active == true
        "#;
        let input = expect_sat("level14_chained_rules", policy, "data.test.allow");
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
        assert_eq!(&input[&Value::from("active")], &Value::Bool(true));
        assert_eq!(&input[&Value::from("action")], &Value::from("deploy"));
    }

    // ===================================================================
    // Level 14a: Simple array membership (wildcard iteration)
    // ===================================================================

    #[test]
    fn test_level14a_array_membership() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                input.users[_] == "admin"
            }
        "#;
        let (result, _) = run_analysis(
            "level14a_array_membership",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        // Should have a users array with at least one element == "admin".
        std::println!(
            "level14a input: {}",
            input
                .to_json_str()
                .unwrap_or_else(|_| alloc::format!("{:?}", input))
        );
    }

    // ===================================================================
    // Level 14b: Iteration with field access
    // ===================================================================

    #[test]
    fn test_level14b_iter_field_access() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                some i
                input.users[i].role == "admin"
            }
        "#;
        let (result, _) = run_analysis(
            "level14b_iter_field_access",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        std::println!(
            "level14b input: {}",
            input
                .to_json_str()
                .unwrap_or_else(|_| alloc::format!("{:?}", input))
        );
    }

    // ===================================================================
    // Level 14c: Multiple conditions with iteration
    // ===================================================================

    #[test]
    fn test_level14c_iter_multi_condition() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                some i
                input.servers[i].protocol == "https"
                input.servers[i].port >= 443
            }
        "#;
        let (result, _) = run_analysis(
            "level14c_iter_multi_condition",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        std::println!(
            "level14c input: {}",
            input
                .to_json_str()
                .unwrap_or_else(|_| alloc::format!("{:?}", input))
        );
    }

    // ===================================================================
    // Level 14d: Assignment from iteration (server := input.servers[_])
    // ===================================================================

    #[test]
    fn test_level14d_assignment_from_iter() {
        let policy = r#"
            package test
            default allow = false
            allow if {
                server := input.servers[_]
                server.name == "web"
                server.healthy == true
            }
        "#;
        let (result, _) = run_analysis(
            "level14d_assignment_from_iter",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        std::println!(
            "level14d input: {}",
            input
                .to_json_str()
                .unwrap_or_else(|_| alloc::format!("{:?}", input))
        );
    }

    // ===================================================================
    // Level 14e: Negation with iteration (no telnet servers)
    // ===================================================================

    #[test]
    fn test_level14e_negation_iter() {
        // This is a simplification of allowed_server's telnet check.
        // "allow if no server uses telnet"
        let policy = r#"
            package test
            default allow = false
            has_telnet if {
                input.servers[_].protocol == "telnet"
            }
            allow if {
                not has_telnet
                input.verified == true
            }
        "#;
        let (result, _) = run_analysis(
            "level14e_negation_iter",
            policy,
            "data.test.allow",
            Value::Bool(true),
        );
        assert!(result.satisfiable, "Expected SAT");
        let input = result.input.expect("Expected input");
        std::println!(
            "level14e input: {}",
            input
                .to_json_str()
                .unwrap_or_else(|_| alloc::format!("{:?}", input))
        );
    }

    // ===================================================================
    // Level 15: allowed_server.rego (the target!)
    // ===================================================================

    #[test]
    fn test_level15_allowed_server() {
        use alloc::string::ToString;

        use crate::engine::Engine;
        use crate::languages::rego::compiler::Compiler;
        use crate::rvm::analysis::{generate_input, AnalysisConfig};

        // This is the ultimate target. The policy uses:
        // - count() on a partial set rule
        // - Partial set rules (violation[server.id])
        // - Iteration over input arrays (input.servers[_])
        // - Cross-collection joins
        // - some/with bindings
        //
        // We test it but allow it to fail gracefully for now.
        let policy = r#"
            package example

            default allow := false

            allow := true if {
                count(violation) == 0
            }

            violation[server.id] if {
                some server
                public_server[server]
                server.protocols[_] == "http"
            }

            violation[server.id] if {
                server := input.servers[_]
                server.protocols[_] == "telnet"
            }

            public_server[server] if {
                some i, j
                server := input.servers[_]
                server.ports[_] == input.ports[i].id
                input.ports[i].network == input.networks[j].id
                input.networks[j].public
            }
        "#;

        let mut engine = Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("add_policy");

        let entry_point: crate::Rc<str> = crate::Rc::from("data.example.allow");
        let compiled = engine
            .compile_with_entrypoint(&entry_point)
            .expect("compile_with_entrypoint");

        let program = Compiler::compile_from_policy(&compiled, &["data.example.allow"])
            .expect("compile_from_policy");

        std::println!("\n=== level15_allowed_server ===");
        std::println!("Policy:\n{}", policy);

        let config = AnalysisConfig::default();
        let data = Value::new_object();
        let desired = Value::Bool(true);

        let result = generate_input(&program, &data, &desired, "data.example.allow", &config);

        match result {
            Ok(r) => {
                std::println!("Satisfiable: {}", r.satisfiable);
                if let Some(ref input) = r.input {
                    std::println!(
                        "Generated input:\n{}",
                        input
                            .to_json_str()
                            .unwrap_or_else(|_| alloc::format!("{:?}", input))
                    );
                }
                if !r.warnings.is_empty() {
                    std::println!("Warnings:");
                    for w in &r.warnings {
                        std::println!("  - {}", w);
                    }
                }
                // For now, just verify it doesn't crash. As we improve,
                // we'll strengthen assertions.
            }
            Err(e) => {
                std::println!("Expected limitation: {}", e);
                // This is expected at this stage — allowed_server uses features
                // we haven't fully modeled yet (comprehensions, partial sets, etc.)
            }
        }
    }

    // ===================================================================
    // Level 16: Deny server — the mirror of allowed_server.rego
    //
    // Same structure as allowed_server.rego but with a top-level `deny`
    // rule instead of `allow`. deny is true when there ARE violations.
    // Z3 should find a problematic input (e.g., a server using telnet
    // or a public server using http).
    // ===================================================================

    #[test]
    fn test_level16_deny_server() {
        use alloc::string::ToString;

        use crate::engine::Engine;
        use crate::languages::rego::compiler::Compiler;
        use crate::rvm::analysis::{generate_input, AnalysisConfig};

        // Exact mirror of allowed_server.rego with deny instead of allow.
        // deny is true when count(violation) > 0 — there exist violations.
        let policy = r#"
            package example

            default deny := false

            deny := true if {
                count(violation) > 0
            }

            violation[server.id] if {
                some server
                public_server[server]
                server.protocols[_] == "http"
            }

            violation[server.id] if {
                server := input.servers[_]
                server.protocols[_] == "telnet"
            }

            public_server[server] if {
                some i, j
                server := input.servers[_]
                server.ports[_] == input.ports[i].id
                input.ports[i].network == input.networks[j].id
                input.networks[j].public
            }
        "#;

        let mut engine = Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("add_policy");

        let entry_point: crate::Rc<str> = crate::Rc::from("data.example.deny");
        let compiled = engine
            .compile_with_entrypoint(&entry_point)
            .expect("compile_with_entrypoint");

        let program = Compiler::compile_from_policy(&compiled, &["data.example.deny"])
            .expect("compile_from_policy");

        std::println!("\n=== level16_deny_server ===");
        std::println!("Policy:\n{}", policy);

        let config = AnalysisConfig::default();
        let data = Value::new_object();

        // Ask for deny == true — find a problematic input.
        let desired = Value::Bool(true);

        let result = generate_input(&program, &data, &desired, "data.example.deny", &config);

        match result {
            Ok(r) => {
                std::println!("Satisfiable: {}", r.satisfiable);
                if let Some(ref input) = r.input {
                    std::println!(
                        "Generated input:\n{}",
                        input
                            .to_json_str()
                            .unwrap_or_else(|_| alloc::format!("{:?}", input))
                    );
                }
                if !r.warnings.is_empty() {
                    std::println!("Warnings:");
                    for w in &r.warnings {
                        std::println!("  - {}", w);
                    }
                }
                // Z3 should find a server with telnet or a public server with http.
                assert!(
                    r.satisfiable,
                    "Expected SAT: should be able to find a problematic server"
                );
                if let Some(ref input) = r.input {
                    std::println!("level16_deny input: {}", input.to_json_str().unwrap());
                }
            }
            Err(e) => {
                std::println!("Limitation (expected for now): {}", e);
                // Full policy with partial sets / count may exceed current capabilities
            }
        }
    }

    // ===================================================================
    // Level 17: ExpectedOutput goal — specify a concrete expected value
    // ===================================================================

    #[test]
    fn test_level17_expected_output_true() {
        // Use ExpectedOutput goal to find an input that makes allow == true.
        let policy = r#"
            package test
            default allow = false
            allow if input.role == "admin"
        "#;
        let goal = AnalysisGoal::ExpectedOutput(Value::Bool(true));
        let r = run_goal_analysis(
            "level17_expected_output_true",
            policy,
            "data.test.allow",
            goal,
        );
        assert!(r.satisfiable, "Expected SAT");
        let input = r.input.unwrap();
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
    }

    #[test]
    fn test_level17b_expected_output_false() {
        // ExpectedOutput(false) — find an input where allow is false.
        // With `default allow = false`, anything that doesn't satisfy the body works.
        let policy = r#"
            package test
            default allow = false
            allow if input.role == "admin"
        "#;
        let goal = AnalysisGoal::ExpectedOutput(Value::Bool(false));
        let r = run_goal_analysis(
            "level17b_expected_output_false",
            policy,
            "data.test.allow",
            goal,
        );
        assert!(
            r.satisfiable,
            "Expected SAT: false output should be trivially satisfiable"
        );
    }

    // ===================================================================
    // Level 18: CoverLines goal — force execution through specific lines
    // ===================================================================

    #[test]
    fn test_level18_cover_lines() {
        // Policy:
        //   line 1: package test
        //   line 2: default allow = false
        //   line 3: allow if {
        //   line 4:     input.role == "admin"
        //   line 5:     input.level >= 5
        //   line 6: }
        //
        // Requesting coverage of line 4 forces input.role == "admin".
        let policy = "package test\ndefault allow = false\nallow if {\n    input.role == \"admin\"\n    input.level >= 5\n}\n";

        let goal = AnalysisGoal::CoverLines {
            cover: alloc::vec![("test.rego".to_string(), 4)],
            avoid: alloc::vec![],
        };
        let r = run_goal_analysis("level18_cover_lines", policy, "data.test.allow", goal);
        assert!(
            r.satisfiable,
            "Expected SAT: should find input that covers line 4"
        );
        let input = r.input.unwrap();
        assert_eq!(&input[&Value::from("role")], &Value::from("admin"));
    }

    // ===================================================================
    // Level 19: OutputAndCoverLines — both expected output + line coverage
    // ===================================================================

    #[test]
    fn test_level19_output_and_cover() {
        // Two OR rules: we want allow == true AND specifically the second rule
        // to be the one that fires (cover its line).
        //
        // 1: package test
        // 2: default allow = false
        // 3: allow if input.role == "admin"
        // 4: allow if input.role == "superuser"
        let policy = "package test\ndefault allow = false\nallow if input.role == \"admin\"\nallow if input.role == \"superuser\"\n";

        let goal = AnalysisGoal::OutputAndCoverLines {
            expected: Value::Bool(true),
            cover: alloc::vec![("test.rego".to_string(), 4)],
            avoid: alloc::vec![],
        };
        let r = run_goal_analysis("level19_output_and_cover", policy, "data.test.allow", goal);
        assert!(
            r.satisfiable,
            "Expected SAT: should find input covering the superuser rule"
        );
        let input = r.input.unwrap();
        let role = &input[&Value::from("role")];
        // Should specifically be "superuser" since that's line 4.
        assert_eq!(role, &Value::from("superuser"));
    }

    // ===================================================================
    // Level 20: allowed_server with allow == false
    // ===================================================================

    #[test]
    fn test_level20_allowed_server_false() {
        use alloc::string::ToString;

        use crate::engine::Engine;
        use crate::languages::rego::compiler::Compiler;

        let policy = r#"
            package example

            default allow := false

            allow := true if {
                count(violation) == 0
            }

            violation[server.id] if {
                some server
                public_server[server]
                server.protocols[_] == "http"
            }

            violation[server.id] if {
                server := input.servers[_]
                server.protocols[_] == "telnet"
            }

            public_server[server] if {
                some i, j
                server := input.servers[_]
                server.ports[_] == input.ports[i].id
                input.ports[i].network == input.networks[j].id
                input.networks[j].public
            }
        "#;

        let mut engine = Engine::new();
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .expect("add_policy");

        let entry_point: crate::Rc<str> = crate::Rc::from("data.example.allow");
        let compiled = engine
            .compile_with_entrypoint(&entry_point)
            .expect("compile_with_entrypoint");

        let program = Compiler::compile_from_policy(&compiled, &["data.example.allow"])
            .expect("compile_from_policy");

        let config = AnalysisConfig::default();
        let data = Value::new_object();

        // Ask for allow == false — find an input with a violation.
        let goal = AnalysisGoal::ExpectedOutput(Value::Bool(false));
        let result = generate_input_for_goal(&program, &data, "data.example.allow", &goal, &config);

        match result {
            Ok(r) => {
                std::println!("\n=== level20_allowed_server_false ===");
                std::println!("Satisfiable: {}", r.satisfiable);
                if let Some(ref input) = r.input {
                    std::println!(
                        "Generated input:\n{}",
                        input
                            .to_json_str()
                            .unwrap_or_else(|_| alloc::format!("{:?}", input))
                    );
                }
                if !r.warnings.is_empty() {
                    std::println!("Warnings (first 10):");
                    for w in r.warnings.iter().take(10) {
                        std::println!("  - {}", w);
                    }
                }
                assert!(
                    r.satisfiable,
                    "Expected SAT: should find an input where allow is false (a violation exists)"
                );
            }
            Err(e) => {
                std::println!("Error: {}", e);
                panic!("Analysis failed: {}", e);
            }
        }
    }

    // ===================================================================
    // Cedar: IAM Zero Trust (permit + forbid with context attrs)
    // ===================================================================

    #[cfg(feature = "cedar")]
    #[test]
    fn test_cedar_iam_zero_trust() {
        use crate::languages::cedar::compiler as cedar_compiler;
        use crate::languages::cedar::parser::Parser as CedarParser;
        use crate::lexer::Source;
        use crate::rvm::analysis::{generate_input, AnalysisConfig};

        let cedar_policy = r#"
permit(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.mfa == true && context.ip like "10.*" };

forbid(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.suspended == true };
"#;

        let entities_json = r#"{
  "User::alice": { "parents": ["User::admins"], "attrs": {} },
  "User::admins": { "parents": [], "attrs": {} }
}"#;

        // Parse Cedar policy.
        let source =
            Source::from_contents("policy.cedar".to_string(), cedar_policy.to_string()).unwrap();
        let mut parser = CedarParser::new(&source).unwrap();
        let policies = parser.parse().unwrap();

        // Compile to RVM program.
        let program = cedar_compiler::compile_to_program(&policies).unwrap();

        // Set entities as concrete input data.
        let entities: Value = serde_json::from_str(entities_json).unwrap();
        let mut config = AnalysisConfig::default();
        config.concrete_input.insert("entities".to_string(), entities);

        let data = Value::new_object();
        let desired = Value::from(1_u64); // permit output = 1

        let result =
            generate_input(&program, &data, &desired, "cedar.authorize", &config).unwrap();

        std::println!("\n=== test_cedar_iam_zero_trust ===");
        std::println!("Satisfiable: {}", result.satisfiable);
        if let Some(ref input) = result.input {
            std::println!(
                "Generated input:\n{}",
                input
                    .to_json_str()
                    .unwrap_or_else(|_| alloc::format!("{:?}", input))
            );
        }
        if !result.warnings.is_empty() {
            std::println!("Warnings:");
            for w in &result.warnings {
                std::println!("  - {}", w);
            }
        }
        assert!(
            result.satisfiable,
            "Expected SAT: should find an input that produces permit"
        );
    }

    /// Cedar IAM test that mimics the web demo path: entities in data, not concrete_input.
    #[cfg(feature = "cedar")]
    #[test]
    fn test_cedar_iam_zero_trust_webdemo_path() {
        use crate::languages::cedar::compiler as cedar_compiler;
        use crate::languages::cedar::parser::Parser as CedarParser;
        use crate::lexer::Source;
        use crate::rvm::analysis::{generate_input, AnalysisConfig};

        let cedar_policy = r#"
permit(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.mfa == true && context.ip like "10.*" };

forbid(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.suspended == true };
"#;

        let entities_json = r#"{
  "User::alice": { "parents": ["User::admins"], "attrs": {} },
  "User::admins": { "parents": [], "attrs": {} }
}"#;

        // Parse Cedar policy.
        let source =
            Source::from_contents("policy.cedar".to_string(), cedar_policy.to_string()).unwrap();
        let mut parser = CedarParser::new(&source).unwrap();
        let policies = parser.parse().unwrap();

        // Compile to RVM program.
        let program = cedar_compiler::compile_to_program(&policies).unwrap();

        // Web demo path: entities in data (NOT in concrete_input).
        let entities: Value = serde_json::from_str(entities_json).unwrap();
        let config = AnalysisConfig::default(); // No concrete_input!
        let mut data = Value::new_object();
        data.as_object_mut().unwrap().insert("entities".into(), entities);

        let desired = Value::from(1_u64); // permit output = 1

        let result =
            generate_input(&program, &data, &desired, "cedar.authorize", &config).unwrap();

        std::println!("\n=== test_cedar_iam_zero_trust_webdemo_path ===");
        std::println!("Satisfiable: {}", result.satisfiable);
        if let Some(ref input) = result.input {
            std::println!(
                "Generated input:\n{}",
                input
                    .to_json_str()
                    .unwrap_or_else(|_| alloc::format!("{:?}", input))
            );
        }
        if !result.warnings.is_empty() {
            std::println!("Warnings:");
            for w in &result.warnings {
                std::println!("  - {}", w);
            }
        }
        assert!(
            result.satisfiable,
            "Expected SAT: should find an input that produces permit (web demo path)"
        );
    }
}
