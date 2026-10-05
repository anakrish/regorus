#![cfg(feature = "rvm")]

use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::RegoVM;
use regorus::{Engine, Value};

#[test]
fn mixed_object_templates_match_interpreter_and_clear_dynamic_values() {
    for source in [
        r#"package test
result := {"op":"=", "path":"input.actor", "value":input.x}"#,
        r#"package test
result := {"a":input.x, "b":{"fixed":[1,true,null]}, "z":input.y}"#,
        r#"package test
result := [{"path":"input.actor","op":"=","value":input.x},
           {"path":"input.resource","op":"=","value":input.y}]"#,
        r#"package test
result := {input.key:input.x, "fixed":42}"#,
        r#"package test
result := {1:input.x, true:"constant", null:[1,2]}"#,
    ] {
        let mut engine = Engine::new();
        engine
            .add_policy("template.rego".into(), source.into())
            .unwrap();
        let policy = engine
            .compile_with_entrypoint(&"data.test.result".into())
            .unwrap();
        let program = Compiler::compile_from_policy(&policy, &["data.test.result"]).unwrap();
        let mut vm = RegoVM::new();
        vm.load_program(program);
        vm.set_compiled_policy(policy.clone());
        for text in [
            r#"{"x":"alice","y":"repo/file","key":"dynamic"}"#,
            r#"{"x":3,"y":false,"key":"second"}"#,
            "{}",
            r#"{"x":null,"y":[1,2],"key":"other"}"#,
        ] {
            let input = Value::from_json_str(text).unwrap();
            let expected = policy.eval_with_input(input.clone()).unwrap();
            vm.set_input(input);
            assert_eq!(
                vm.execute_entry_point_by_name("data.test.result").unwrap(),
                expected
            );
        }
    }
}
