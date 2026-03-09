// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{bail, Result};
use regorus::*;

#[test]
fn extension() -> Result<()> {
    fn repeat(mut params: Vec<Value>) -> Result<Value> {
        match params.remove(0) {
            Value::String(s) => {
                let s = s.as_ref().to_owned();
                Ok(Value::from(s.clone() + &s))
            }
            _ => bail!("param must be string"),
        }
    }
    let mut engine = Engine::new();
    engine.add_policy(
        "test.rego".to_string(),
        r#"package test
               x = repeat("hello")
             "#
        .to_string(),
    )?;

    // Raises error since repeat is not defined.
    assert!(engine.eval_query("data.test.x".to_string(), false).is_err());

    // Register extension.
    engine.add_extension("repeat".to_string(), 1, Box::new(repeat))?;

    // Adding extension twice is error.
    assert!(engine
        .add_extension(
            "repeat".to_string(),
            1,
            Box::new(|_| { Ok(Value::Undefined) })
        )
        .is_err());

    let r = engine.eval_query("data.test.x".to_string(), false)?;
    assert_eq!(
        r.result[0].expressions[0].value.as_string()?.as_ref(),
        "hellohello"
    );

    Ok(())
}

#[test]
fn extension_with_state() -> Result<()> {
    #[derive(Clone)]
    struct Gen {
        n: i64,
    }

    let mut engine = Engine::new();
    engine.add_policy(
        "test.rego".to_string(),
        r#"package test
               x = gen()
        "#
        .to_string(),
    )?;

    let mut g = Box::new(Gen { n: 5 });
    engine.add_extension(
        "gen".to_string(),
        0,
        Box::new(move |_: Vec<Value>| {
            let v = Value::from(g.n);
            g.n += 1;
            Ok(v)
        }),
    )?;

    // First eval.
    let r = engine.eval_query("data.test.x".to_string(), false)?;
    assert_eq!(r.result[0].expressions[0].value.as_i64()?, 5);

    // Second eval will produce a new value since for each query, the
    // internal evaluation state of the interpreter is cleared.
    // This might change in the future.
    let r = engine.eval_query("data.test.x".to_string(), false)?;
    assert_eq!(r.result[0].expressions[0].value.as_i64()?, 6);

    // Clone the engine.
    // This should also clone the stateful extension.
    let mut engine1 = engine.clone();

    // Both the engines should produce the same value.
    let r = engine.eval_query("data.test.x".to_string(), false)?;
    let r1 = engine1.eval_query("data.test.x".to_string(), false)?;
    assert_eq!(
        r.result[0].expressions[0].value,
        r1.result[0].expressions[0].value
    );

    assert_eq!(r.result[0].expressions[0].value.as_i64()?, 7);

    Ok(())
}

#[test]
#[cfg(feature = "azure_policy")]
#[cfg_attr(docsrs, doc(cfg(feature = "azure_policy")))]
fn get_policy_package_names() -> Result<()> {
    let mut engine = Engine::new();
    engine.add_policy(
        "testPolicy1".to_string(),
        r#"package test
               
                deny if {
                    1 == 2
                }
        "#
        .to_string(),
    )?;

    engine.add_policy(
        "testPolicy2".to_string(),
        r#"package test.nested.name
                deny if {
                    1 == 2
                }
        "#
        .to_string(),
    )?;

    let package_names = engine.get_policy_package_names()?;

    assert_eq!(2, package_names.len());
    assert_eq!("test", package_names[0].package_name);
    assert_eq!("testPolicy1", package_names[0].source_file);

    assert_eq!("test.nested.name", package_names[1].package_name);
    assert_eq!("testPolicy2", package_names[1].source_file);
    Ok(())
}

#[test]
#[cfg(feature = "azure_policy")]
#[cfg_attr(docsrs, doc(cfg(feature = "azure_policy")))]
fn get_policy_parameters() -> Result<()> {
    let mut engine = Engine::new();
    engine.add_policy(
        "testPolicy1".to_string(),
        r#"package test
                default parameters.a = 5
                default parameters.b = { asdf: 10}

                parameters.c = 10

                deny if {
                    parameter.a == parameter.b.asdf
                }
        "#
        .to_string(),
    )?;

    engine.add_policy(
        "testPolicy2".to_string(),
        r#"package test
                default parameters = {
                    a: 5,
                    b: { asdf: 10 }
                }

                parameters.c = 5

                deny if {
                    parameters.a == parameters.b.asdf
                }
        "#
        .to_string(),
    )?;

    let parameters = engine.get_policy_parameters()?;
    // let ast = engine.get_ast_as_json()?;
    // println!("ast: {}", ast);
    // let parameters = Value::from_json_str(&result)?;

    assert_eq!(2, parameters.len());

    let test_policy1_parameters = &parameters[0];
    assert_eq!(2, test_policy1_parameters.parameters.len());
    assert_eq!("a", test_policy1_parameters.parameters[0].name);
    assert_eq!("b", test_policy1_parameters.parameters[1].name);

    // We expect parameters to be defined separately, so the second policy does not have any parameters
    let test_policy2_parameters = &parameters[1];
    assert_eq!(0, test_policy2_parameters.parameters.len());

    assert_eq!(1, test_policy2_parameters.modifiers.len());
    assert_eq!("c", test_policy2_parameters.modifiers[0].name);

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_redacts_secret_bindings_by_default() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            user := input.user
            api_token := input.token
            user != ""
            msg := sprintf("deny: %v", [user])
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"user":"alice","token":"super-secret"}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("deny: alice"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let user_binding = records[0]
        .bindings
        .iter()
        .find(|binding| binding.name.as_ref() == "user")
        .ok_or_else(|| anyhow::anyhow!("missing user binding"))?;
    let token_binding = records[0]
        .bindings
        .iter()
        .find(|binding| binding.name.as_ref() == "api_token")
        .ok_or_else(|| anyhow::anyhow!("missing token binding"))?;

    assert_eq!(user_binding.value, Value::from("alice"));
    assert!(!user_binding.redacted);
    assert_eq!(token_binding.value, Value::from("<redacted>"));
    assert!(token_binding.redacted);

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_can_preserve_values_when_requested() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Full,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            api_token := input.token
            msg := sprintf("token len: %v", [count(api_token)])
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"token":"super-secret"}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("token len: 12"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let token_binding = records[0]
        .bindings
        .iter()
        .find(|binding| binding.name.as_ref() == "api_token")
        .ok_or_else(|| anyhow::anyhow!("missing token binding"))?;

    assert_eq!(token_binding.value, Value::from("super-secret"));
    assert!(!token_binding.redacted);

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_prefers_predicate_conditions() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.protocol == "http"
            msg := sprintf("service %v uses http", [svc.name])
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"services":[{"name":"frontend","protocol":"http"}]}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("service frontend uses http"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Success);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("svc.protocol == \"http"));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_reasons_captures_comparison_values() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.port < 1024
            msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"services":[{"name":"dns","port":53}]}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("service dns uses privileged port 53"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing structured evaluation"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Comparison);
    assert_eq!(evaluation.operator, Some(ConditionOperator::LessThan));
    assert_eq!(evaluation.actual_value, Some(Value::from(53u64)));
    assert_eq!(evaluation.expected_value, Some(Value::from(1024u64)));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_reasons_captures_builtin_values() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            startswith(input.name, "prod-")
            msg := "name starts with prod-"
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"name":"prod-api"}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("name starts with prod-"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing structured evaluation"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Builtin);
    assert_eq!(evaluation.operator, Some(ConditionOperator::StartsWith));
    assert_eq!(evaluation.actual_value, Some(Value::from("prod-api")));
    assert_eq!(evaluation.expected_value, Some(Value::from("prod-")));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_inlines_helper_rule_conditions() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        helper if {
            clock_timezone := data.config.DEVICE_METADATA.localhost
            clock_timezone.timezone != "UTC"
        }

        violations contains msg if {
            helper
            msg := "The clock timezone is not set to UTC"
        }
        "#
        .to_string(),
    )?;
    engine.add_data_json(r#"{"config":{"DEVICE_METADATA":{"localhost":{"timezone":"PST"}}}}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("The clock timezone is not set to UTC"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Success);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("clock_timezone.timezone != \"UTC"));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_inlines_negated_helper_failures() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        valid_clock_time_zone if {
            clock_timezone := data.config.DEVICE_METADATA.localhost
            clock_timezone.timezone == "UTC"
        }

        violations contains msg if {
            not valid_clock_time_zone
            msg := "The clock timezone is not set to UTC"
        }
        "#
        .to_string(),
    )?;
    engine.add_data_json(r#"{"config":{"DEVICE_METADATA":{"localhost":{"timezone":"PST"}}}}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    assert_eq!(explanations.len(), 1);
    let records = explanations
        .get(&Value::from("The clock timezone is not set to UTC"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Failure);
    assert_eq!(records[0].location.row, 7);
    assert_eq!(records[0].location.col, 13);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("clock_timezone.timezone == \"UTC"));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_redacts_secret_bindings() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        violations contains msg if {
            user := input.user
            api_token := input.token
            user != ""
            msg := sprintf("deny: %v", [user])
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(
        r#"{"user":"alice","token":"super-secret"}"#,
    )?);

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("deny: alice"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let token_binding = records[0]
        .bindings
        .iter()
        .find(|binding| binding.name.as_ref() == "api_token")
        .ok_or_else(|| anyhow::anyhow!("missing token binding"))?;

    assert_eq!(token_binding.value, Value::from("<redacted>"));
    assert!(token_binding.redacted);

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_prefers_predicate_conditions() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.protocol == "http"
            msg := sprintf("service %v uses http", [svc.name])
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(
        r#"{"services":[{"name":"frontend","protocol":"http"}]}"#,
    )?);

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("service frontend uses http"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Success);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("svc.protocol == \"http"));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_reasons_captures_comparison_values() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.port < 1024
            msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(
        r#"{"services":[{"name":"dns","port":53}]}"#,
    )?);

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("service dns uses privileged port 53"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing structured evaluation"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Comparison);
    assert_eq!(evaluation.operator, Some(ConditionOperator::LessThan));
    assert_eq!(evaluation.actual_value, Some(Value::from(53u64)));
    assert_eq!(evaluation.expected_value, Some(Value::from(1024u64)));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_reasons_captures_builtin_values() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        violations contains msg if {
            startswith(input.name, "prod-")
            msg := "name starts with prod-"
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(r#"{"name":"prod-api"}"#)?);

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("name starts with prod-"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing structured evaluation"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Builtin);
    assert_eq!(evaluation.operator, Some(ConditionOperator::StartsWith));
    assert_eq!(evaluation.actual_value, Some(Value::from("prod-api")));
    assert_eq!(evaluation.expected_value, Some(Value::from("prod-")));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_inlines_helper_rule_conditions() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        helper if {
            clock_timezone := data.config.DEVICE_METADATA.localhost
            clock_timezone.timezone != "UTC"
        }

        violations contains msg if {
            helper
            msg := "The clock timezone is not set to UTC"
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::from_json_str(r#"{"config":{"DEVICE_METADATA":{"localhost":{"timezone":"PST"}}}}"#)?,
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("The clock timezone is not set to UTC"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Success);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("clock_timezone.timezone != \"UTC"));
    assert!(records[0]
        .bindings
        .iter()
        .any(|binding| binding.name.as_ref() == "clock_timezone"));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_inlines_negated_helper_failures() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        valid_clock_time_zone if {
            clock_timezone := data.config.DEVICE_METADATA.localhost
            clock_timezone.timezone == "UTC"
        }

        violations contains msg if {
            not valid_clock_time_zone
            msg := "The clock timezone is not set to UTC"
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::from_json_str(r#"{"config":{"DEVICE_METADATA":{"localhost":{"timezone":"PST"}}}}"#)?,
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    assert_eq!(explanations.len(), 1);
    let records = explanations
        .get(&Value::from("The clock timezone is not set to UTC"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, ExplanationOutcome::Failure);
    assert_eq!(records[0].location.row, 7);
    assert_eq!(records[0].location.col, 13);
    assert!(records[0]
        .text
        .as_ref()
        .starts_with("clock_timezone.timezone == \"UTC"));
    assert!(records[0]
        .bindings
        .iter()
        .any(|binding| binding.name.as_ref() == "clock_timezone"));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_tracks_all_contributing_conditions() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::AllContributing,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.port < 1024
            startswith(svc.name, "dn")
            msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"services":[{"name":"dns","port":53}]}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("service dns uses privileged port 53"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 2);
    assert!(records[0].text.as_ref().starts_with("svc.port < 1024"));
    assert!(records[1]
        .text
        .as_ref()
        .starts_with("startswith(svc.name, \"dn\")"));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_normalizes_mixed_outcome_search_records() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        allow if {
            helper
        }

        helper if {
            some n in input.values
            n > 1
            n < 3
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"values":[0,2,4]}"#)?;

    let _value = engine.eval_rule("data.test.allow".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::Bool(true))
        .ok_or_else(|| anyhow::anyhow!("missing boolean explanation record"))?;

    assert!(!records.is_empty());
    assert!(records
        .iter()
        .all(|record| record.outcome == ExplanationOutcome::Success));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_tracks_all_contributing_conditions() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        violations contains msg if {
            svc := input.services[_]
            svc.port < 1024
            startswith(svc.name, "dn")
            msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.violations".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.violations"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::AllContributing,
    });
    vm.set_input(Value::from_json_str(
        r#"{"services":[{"name":"dns","port":53}]}"#,
    )?);

    let _value = vm.execute_entry_point_by_name("data.test.violations")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::from("service dns uses privileged port 53"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;

    assert_eq!(records.len(), 2);
    assert!(records[0].text.as_ref().starts_with("svc.port < 1024"));
    assert!(records[1]
        .text
        .as_ref()
        .starts_with("startswith(svc.name, \"dn\")"));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_normalizes_mixed_outcome_search_records() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        allow if {
            helper
        }

        helper if {
            some n in input.values
            n > 1
            n < 3
        }
        "#
        .into(),
    }];

    let compiled =
        compile_policy_with_entrypoint(Value::new_object(), &modules, "data.test.allow".into())?;
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &["data.test.allow"])?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(r#"{"values":[0,2,4]}"#)?);

    let _value = vm.execute_entry_point_by_name("data.test.allow")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::Bool(true))
        .ok_or_else(|| anyhow::anyhow!("missing boolean explanation record"))?;

    assert!(!records.is_empty());
    assert!(records
        .iter()
        .all(|record| record.outcome == ExplanationOutcome::Success));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_keeps_supporting_helper_chain_for_complete_rules() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package example
        import rego.v1

        default allow := false

        allow := true if {
            count(violation) == 0
        }

        violation contains server.id if {
            some server
            public_server[server]
            server.protocols[_] == "http"
        }

        public_server contains server if {
            some i, j
            server := input.servers[_]
            server.ports[_] == input.ports[i].id
            input.ports[i].network == input.networks[j].id
            input.networks[j].public
        }
        "#
        .into(),
    }];

    let compiled =
        compile_policy_with_entrypoint(Value::new_object(), &modules, "data.example.allow".into())?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.example.allow"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(
        r#"{
            "servers": [
                {"id": "app", "protocols": ["https", "ssh"], "ports": ["p1", "p2", "p3"]},
                {"id": "db", "protocols": ["mysql"], "ports": ["p3"]},
                {"id": "cache", "protocols": ["memcache"], "ports": ["p3"]},
                {"id": "ci", "protocols": ["http"], "ports": ["p1", "p2"]},
                {"id": "busybox", "protocols": ["telnet"], "ports": ["p1"]}
            ],
            "ports": [
                {"id": "p1", "network": "net1"},
                {"id": "p2", "network": "net3"},
                {"id": "p3", "network": "net2"}
            ],
            "networks": [
                {"id": "net1", "public": false},
                {"id": "net2", "public": false},
                {"id": "net3", "public": true},
                {"id": "net4", "public": true}
            ]
        }"#,
    )?);

    let _value = vm.execute_entry_point_by_name("data.example.allow")?;
    let explanations = vm.take_explanations();

    assert_eq!(explanations.len(), 1);

    let records = explanations
        .get(&Value::Bool(false))
        .ok_or_else(|| anyhow::anyhow!("missing false explanation record"))?;

    assert!(records
        .iter()
        .any(|record| record.text.as_ref().starts_with("count(violation) == 0")));

    let violation_record = records
        .iter()
        .find(|record| {
            record
                .text
                .as_ref()
                .starts_with("server.protocols[_] == \"http")
        })
        .ok_or_else(|| anyhow::anyhow!("missing violation helper explanation"))?;
    let violation_evaluation = violation_record
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing violation evaluation"))?;
    assert_eq!(
        violation_evaluation.kind,
        ConditionEvaluationKind::Comparison
    );

    let public_server_record = records
        .iter()
        .find(|record| record.text.as_ref() == "input.servers[_]")
        .ok_or_else(|| anyhow::anyhow!("missing public_server helper explanation"))?;
    let public_server_witness = public_server_record
        .evaluation
        .as_ref()
        .and_then(|evaluation| evaluation.witness.as_ref())
        .ok_or_else(|| anyhow::anyhow!("missing public_server witness"))?;
    assert!(public_server_witness.condition_texts.iter().any(|text| {
        text.as_ref()
            .starts_with("server.ports[_] == input.ports[i].id")
    }));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_captures_every_witness() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            every i, port in input.ports { port > 0 }
            msg := "all ports are positive"
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"ports":[80,443]}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("all ports are positive"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(evaluation.operator, Some(ConditionOperator::Every));
    assert_eq!(witness.iteration_count, Some(2));
    assert_eq!(witness.success_count, Some(2));
    assert_eq!(
        witness.condition_texts,
        vec![regorus::Rc::<str>::from("port > 0")]
    );
    assert_eq!(
        witness
            .passing_iteration
            .as_ref()
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(80u64))
    );

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_captures_every_failure_witness() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        default allow := false

        allow if {
            every i, port in input.ports {
                port > 0
                port < 1000
            }
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"ports":[80,0,443]}"#)?;

    let _value = engine.eval_rule("data.test.allow".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::Bool(false))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records
        .iter()
        .find_map(|record| record.evaluation.as_ref())
        .ok_or_else(|| anyhow::anyhow!("missing evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(witness.iteration_count, Some(2));
    assert_eq!(witness.success_count, Some(1));
    assert_eq!(
        witness.condition_texts,
        vec![
            regorus::Rc::<str>::from("port > 0"),
            regorus::Rc::<str>::from("port < 1000")
        ]
    );
    assert_eq!(
        witness
            .failing_iteration
            .as_ref()
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(0u64))
    );

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_captures_comprehension_witness() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            [v | v := input.values[_]; v > 1]
            msg := "found high values"
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"values":[1,2,3]}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("found high values"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Comprehension);
    assert_eq!(witness.yield_count, Some(2));
    assert_eq!(witness.sample_value, Some(Value::from(2u64)));

    Ok(())
}

#[cfg(feature = "explanations")]
#[test]
fn eval_rule_with_explanations_captures_typecheck_builtin() -> Result<()> {
    let mut engine = Engine::new();
    engine.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    engine.add_policy(
        "test.rego".to_string(),
        r#"
        package test
        import rego.v1

        violations contains msg if {
            is_string(input.name)
            msg := "name is a string"
        }
        "#
        .to_string(),
    )?;
    engine.set_input_json(r#"{"name":"frontend"}"#)?;

    let _value = engine.eval_rule("data.test.violations".to_string())?;
    let explanations = engine.take_explanations();
    let records = explanations
        .get(&Value::from("name is a string"))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing evaluation"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Builtin);
    assert_eq!(evaluation.operator, Some(ConditionOperator::IsString));
    assert_eq!(evaluation.actual_value, Some(Value::from("frontend")));

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_captures_every_and_comprehension_witnesses() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        all_positive contains msg if {
            every i, port in input.ports { port > 0 }
            msg := "all ports are positive"
        }

        found_high contains msg if {
            [v | v := input.values[_]; v > 1]
            msg := "found high values"
        }
        "#
        .into(),
    }];

    let compiled = compile_policy_with_entrypoint(
        Value::new_object(),
        &modules,
        "data.test.all_positive".into(),
    )?;
    let program = languages::rego::compiler::Compiler::compile_from_policy(
        &compiled,
        &["data.test.all_positive", "data.test.found_high"],
    )?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(
        r#"{"ports":[80,443],"values":[1,2,3]}"#,
    )?);

    let _ = vm.execute_entry_point_by_name("data.test.all_positive")?;
    let every_reasons = vm.take_explanations();
    let every_records = every_reasons
        .get(&Value::from("all ports are positive"))
        .ok_or_else(|| anyhow::anyhow!("missing every explanation"))?;
    let every_eval = every_records
        .iter()
        .filter_map(|record| record.evaluation.as_ref())
        .find(|evaluation| evaluation.operator == Some(ConditionOperator::Every))
        .ok_or_else(|| anyhow::anyhow!("missing every evaluation"))?;
    assert_eq!(every_eval.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(
        every_eval.witness.as_ref().and_then(|w| w.iteration_count),
        Some(2)
    );
    assert_eq!(
        every_eval
            .witness
            .as_ref()
            .map(|w| w.condition_texts.clone())
            .unwrap_or_default(),
        vec![regorus::Rc::<str>::from("port > 0")]
    );
    assert_eq!(
        every_eval
            .witness
            .as_ref()
            .and_then(|w| w.passing_iteration.as_ref())
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(80u64))
    );

    vm.set_input(Value::from_json_str(
        r#"{"ports":[80,443],"values":[1,2,3]}"#,
    )?);
    let _ = vm.execute_entry_point_by_name("data.test.found_high")?;
    let comp_reasons = vm.take_explanations();
    let comp_records = comp_reasons
        .get(&Value::from("found high values"))
        .ok_or_else(|| anyhow::anyhow!("missing comprehension explanation"))?;
    let comp_eval = comp_records[0]
        .evaluation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing comprehension evaluation"))?;
    assert_eq!(comp_eval.kind, ConditionEvaluationKind::Comprehension);
    assert_eq!(
        comp_eval.witness.as_ref().and_then(|w| w.yield_count),
        Some(2)
    );

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_summarizes_some_in_loop() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        allow if {
            some n in input.values
            n > 1
            n < 3
        }
        "#
        .into(),
    }];

    let compiled =
        compile_policy_with_entrypoint(Value::new_object(), &modules, "data.test.allow".into())?;
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &["data.test.allow"])?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(r#"{"values":[0,2,4]}"#)?);

    let _value = vm.execute_entry_point_by_name("data.test.allow")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::Bool(true))
        .ok_or_else(|| anyhow::anyhow!("missing boolean explanation record"))?;
    let evaluation = records
        .iter()
        .filter_map(|record| record.evaluation.as_ref())
        .find(|evaluation| evaluation.operator == Some(ConditionOperator::ForEach))
        .ok_or_else(|| anyhow::anyhow!("missing loop summary evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(witness.iteration_count, Some(3));
    assert_eq!(witness.success_count, Some(1));
    assert_eq!(
        witness.condition_texts,
        vec![
            regorus::Rc::<str>::from("n > 1"),
            regorus::Rc::<str>::from("n < 3")
        ]
    );
    assert_eq!(
        witness
            .passing_iteration
            .as_ref()
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(2u64))
    );

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_summarizes_hoisted_loop() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        allow if {
            n := input.values[_]
            n > 1
            n < 3
        }
        "#
        .into(),
    }];

    let compiled =
        compile_policy_with_entrypoint(Value::new_object(), &modules, "data.test.allow".into())?;
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &["data.test.allow"])?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(r#"{"values":[0,2,4]}"#)?);

    let _value = vm.execute_entry_point_by_name("data.test.allow")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::Bool(true))
        .ok_or_else(|| anyhow::anyhow!("missing boolean explanation record"))?;
    let evaluation = records
        .iter()
        .filter_map(|record| record.evaluation.as_ref())
        .find(|evaluation| evaluation.operator == Some(ConditionOperator::ForEach))
        .ok_or_else(|| anyhow::anyhow!("missing loop summary evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(witness.iteration_count, Some(3));
    assert_eq!(witness.success_count, Some(1));
    assert_eq!(
        witness.condition_texts,
        vec![
            regorus::Rc::<str>::from("n > 1"),
            regorus::Rc::<str>::from("n < 3")
        ]
    );
    assert_eq!(
        witness
            .passing_iteration
            .as_ref()
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(2u64))
    );

    Ok(())
}

#[cfg(all(feature = "explanations", feature = "rvm"))]
#[test]
fn rvm_execute_with_explanations_captures_every_failure_witness() -> Result<()> {
    let modules = vec![PolicyModule {
        id: "test.rego".into(),
        content: r#"
        package test
        import rego.v1

        default allow := false

        allow if {
            every i, port in input.ports {
                port > 0
                port < 1000
            }
        }
        "#
        .into(),
    }];

    let compiled =
        compile_policy_with_entrypoint(Value::new_object(), &modules, "data.test.allow".into())?;
    let program =
        languages::rego::compiler::Compiler::compile_from_policy(&compiled, &["data.test.allow"])?;

    let mut vm = rvm::RegoVM::new_with_policy(compiled);
    vm.load_program(program);
    vm.set_explanation_settings(ExplanationSettings {
        enabled: true,
        value_mode: ExplanationValueMode::Redacted,
        condition_mode: ExplanationConditionMode::PrimaryOnly,
    });
    vm.set_input(Value::from_json_str(r#"{"ports":[80,0,443]}"#)?);

    let _ = vm.execute_entry_point_by_name("data.test.allow")?;
    let explanations = vm.take_explanations();
    let records = explanations
        .get(&Value::Bool(false))
        .ok_or_else(|| anyhow::anyhow!("missing explanation record"))?;
    let evaluation = records
        .iter()
        .filter_map(|record| record.evaluation.as_ref())
        .find(|evaluation| evaluation.kind == ConditionEvaluationKind::Quantifier)
        .ok_or_else(|| anyhow::anyhow!("missing evaluation"))?;
    let witness = evaluation
        .witness
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing witness"))?;

    assert_eq!(evaluation.kind, ConditionEvaluationKind::Quantifier);
    assert_eq!(witness.iteration_count, Some(2));
    assert_eq!(witness.success_count, Some(1));
    assert_eq!(
        witness.condition_texts,
        vec![
            regorus::Rc::<str>::from("port > 0"),
            regorus::Rc::<str>::from("port < 1000")
        ]
    );
    assert_eq!(
        witness
            .failing_iteration
            .as_ref()
            .and_then(|iteration| iteration.sample_value.clone()),
        Some(Value::from(0u64))
    );

    Ok(())
}
