#![cfg(feature = "rvm")]

use std::sync::Arc;

use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::{program::Program, RegoVM};
use regorus::{CompiledPolicy, Engine, Value};

fn compile(
    source: &str,
    arity: u8,
    callback: Box<dyn regorus::Extension>,
) -> (CompiledPolicy, Arc<Program>) {
    let mut engine = Engine::new();
    engine
        .add_extension("host.query".into(), arity, callback)
        .unwrap();
    engine
        .add_policy("extension.rego".into(), source.into())
        .unwrap();
    let policy = engine
        .compile_with_entrypoint(&"data.test.result".into())
        .unwrap();
    let program = Compiler::compile_from_policy(&policy, &["data.test.result"]).unwrap();
    (policy, program)
}

fn vm_for(policy: &CompiledPolicy, program: &Arc<Program>) -> RegoVM {
    let mut vm = RegoVM::new();
    vm.load_program(Arc::clone(program));
    vm.set_compiled_policy(policy.clone());
    vm
}

#[test]
fn repeated_call_sites_share_one_stateful_binding_and_rebind_resets_it() {
    let mut count = 0i64;
    let (policy, program) = compile(
        "package test\nresult := [host.query(1), host.query(2)]",
        1,
        Box::new(move |_: Vec<Value>| {
            count += 1;
            Ok(Value::from(count))
        }),
    );
    let mut vm = vm_for(&policy, &program);
    for start in [1i64, 3] {
        assert_eq!(
            vm.execute_entry_point_by_name("data.test.result").unwrap(),
            Value::from_json_str(&format!("[{start},{}]", start + 1)).unwrap()
        );
    }
    vm.set_compiled_policy(policy);
    assert_eq!(
        vm.execute_entry_point_by_name("data.test.result").unwrap(),
        Value::from_json_str("[1,2]").unwrap()
    );
}

#[test]
fn dynamic_arguments_match_interpreter() {
    let (policy, program) = compile(
        "package test\nresult := host.query(input.x, 2)",
        2,
        Box::new(|args: Vec<Value>| Ok(Value::from(args[0].as_i64()? + args[1].as_i64()?))),
    );
    let mut vm = vm_for(&policy, &program);
    for x in [-2, 0, 4] {
        let input = Value::from_json_str(&format!(r#"{{"x":{x}}}"#)).unwrap();
        let expected = policy.eval_with_input(input.clone()).unwrap();
        vm.set_input(input);
        assert_eq!(
            vm.execute_entry_point_by_name("data.test.result").unwrap(),
            expected
        );
    }
}

#[test]
fn borrowed_arguments_match_interpreter_and_rvm() {
    let mut engine = Engine::new();
    engine
        .add_extension_borrowed(
            "host.query".into(),
            1,
            Box::new(|args: &[Value]| Ok(args[0].clone())),
        )
        .unwrap();
    engine
        .add_policy(
            "extension.rego".into(),
            "package test\nresult := host.query(input.x)".into(),
        )
        .unwrap();
    let policy = engine
        .compile_with_entrypoint(&"data.test.result".into())
        .unwrap();
    let program = Compiler::compile_from_policy(&policy, &["data.test.result"]).unwrap();
    let mut vm = vm_for(&policy, &program);

    for x in [-2, 0, 4] {
        let input = Value::from_json_str(&format!(r#"{{"x":{x}}}"#)).unwrap();
        let expected = policy.eval_with_input(input.clone()).unwrap();
        vm.set_input(input);
        assert_eq!(
            vm.execute_entry_point_by_name("data.test.result").unwrap(),
            expected
        );
    }
}

#[test]
fn stateful_callbacks_are_private_to_each_vm_and_run_again_on_next_evaluation() {
    let mut count = 0i64;
    let (policy, program) = compile(
        "package test\nresult := host.query()",
        0,
        Box::new(move |_: Vec<Value>| {
            count += 1;
            Ok(Value::from(count))
        }),
    );
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let policy = policy.clone();
            let program = Arc::clone(&program);
            std::thread::spawn(move || {
                let mut vm = vm_for(&policy, &program);
                for expected in 1..=3i64 {
                    assert_eq!(
                        vm.execute_entry_point_by_name("data.test.result").unwrap(),
                        Value::from(expected)
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn errors_propagate_even_in_non_strict_mode_and_vm_can_recover() {
    let (policy, program) = compile(
        "package test\nresult := host.query(input.x)",
        1,
        Box::new(|args: Vec<Value>| {
            if args[0] == Value::from(0) {
                anyhow::bail!("kernel unavailable");
            }
            Ok(args[0].clone())
        }),
    );
    let mut vm = vm_for(&policy, &program);
    vm.set_strict_builtin_errors(false);
    vm.set_input(Value::from_json_str(r#"{"x":0}"#).unwrap());
    let error = vm
        .execute_entry_point_by_name("data.test.result")
        .unwrap_err();
    assert!(error.to_string().contains("kernel unavailable"));
    vm.set_input(Value::from_json_str(r#"{"x":5}"#).unwrap());
    assert_eq!(
        vm.execute_entry_point_by_name("data.test.result").unwrap(),
        Value::from(5)
    );
}

#[test]
fn undefined_argument_does_not_invoke_callback() {
    let (policy, program) = compile(
        "package test\nresult := host.query(input.missing)",
        1,
        Box::new(|_: Vec<Value>| -> anyhow::Result<Value> {
            panic!("undefined arguments must not call host")
        }),
    );
    let mut vm = vm_for(&policy, &program);
    vm.set_input(Value::new_object());
    assert_eq!(
        vm.execute_entry_point_by_name("data.test.result").unwrap(),
        Value::Undefined
    );
}

#[test]
fn serialized_program_requires_explicit_host_binding() {
    let (policy, program) = compile(
        "package test\nresult := host.query(3)",
        1,
        Box::new(|args: Vec<Value>| Ok(args[0].clone())),
    );
    let json = program.serialize_json().unwrap();
    let restored = Arc::new(Program::deserialize_json(&json).unwrap());
    let mut vm = RegoVM::new();
    vm.load_program(Arc::clone(&restored));
    let error = vm
        .execute_entry_point_by_name("data.test.result")
        .unwrap_err();
    assert!(error.to_string().contains("not resolved"));
    vm.set_compiled_policy(policy);
    assert_eq!(
        vm.execute_entry_point_by_name("data.test.result").unwrap(),
        Value::from(3)
    );
    vm.load_program(restored);
    assert!(
        vm.execute_entry_point_by_name("data.test.result").is_err(),
        "program reload must clear host bindings"
    );
}

#[test]
fn excessive_arity_is_rejected_without_truncation() {
    let mut engine = Engine::new();
    engine
        .add_extension(
            "host.query".into(),
            9,
            Box::new(|_: Vec<Value>| Ok(Value::Bool(true))),
        )
        .unwrap();
    engine
        .add_policy(
            "extension.rego".into(),
            "package test\nresult := host.query(1,2,3,4,5,6,7,8,9)".into(),
        )
        .unwrap();
    let policy = engine
        .compile_with_entrypoint(&"data.test.result".into())
        .unwrap();
    let error = Compiler::compile_from_policy(&policy, &["data.test.result"]).unwrap_err();
    assert!(error.to_string().contains("at most 8"));
}

#[test]
fn binary_roundtrip_preserves_extension_requirements() {
    use regorus::rvm::program::DeserializationResult;
    let (policy, program) = compile(
        "package test\nresult := host.query(3)",
        1,
        Box::new(|args: Vec<Value>| Ok(args[0].clone())),
    );
    let bytes = program.serialize_binary().unwrap();
    let restored = match Program::deserialize_binary(&bytes).unwrap() {
        DeserializationResult::Complete(program) => Arc::new(program),
        DeserializationResult::Partial(_) => panic!("new program must roundtrip completely"),
    };
    let mut vm = vm_for(&policy, &restored);
    assert_eq!(
        vm.execute_entry_point_by_name("data.test.result").unwrap(),
        Value::from(3)
    );
}

#[test]
fn older_binary_format_retains_source_for_recompilation() {
    use regorus::rvm::program::DeserializationResult;
    let (_, program) = compile(
        "package test\nresult := host.query(3)",
        1,
        Box::new(|args: Vec<Value>| Ok(args[0].clone())),
    );
    let mut bytes = program.serialize_binary().unwrap();
    bytes[4..8].copy_from_slice(&6u32.to_le_bytes());
    let restored = match Program::deserialize_binary(&bytes).unwrap() {
        DeserializationResult::Partial(program) => program,
        DeserializationResult::Complete(_) => panic!("older format must require recompilation"),
    };
    assert!(!restored.sources.is_empty());
    assert!(!restored.entry_points.is_empty());
}
