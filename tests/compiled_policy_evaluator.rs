use regorus::{CompiledPolicy, Engine, Value};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

fn compile(source: &str, callback: Box<dyn regorus::Extension>) -> CompiledPolicy {
    let mut engine = Engine::new();
    engine.set_strict_builtin_errors(true);
    engine
        .add_extension("host.query".into(), 1, callback)
        .unwrap();
    engine
        .add_policy("test.rego".into(), source.into())
        .unwrap();
    engine
        .compile_with_entrypoint(&"data.test.result".into())
        .unwrap()
}

#[test]
fn changing_inputs_and_undefined_results_match_fresh_evaluations() {
    let policy = compile(
        "package test\nresult := host.query(input.x)",
        Box::new(|args: Vec<Value>| Ok(args[0].clone())),
    );
    let mut evaluator = policy.create_evaluator();
    for text in [r#"{"x":1}"#, r#"{"x":2}"#, "{}", r#"{"x":3}"#] {
        let input = Value::from_json_str(text).unwrap();
        assert_eq!(
            evaluator.eval_with_input(input.clone()).unwrap(),
            policy.eval_with_input(input).unwrap()
        );
    }
}

#[test]
fn unchanged_input_does_not_cache_external_history() {
    let history = Arc::new(AtomicI64::new(1));
    let state = Arc::clone(&history);
    let policy = compile(
        "package test\nresult := host.query(input.x)",
        Box::new(move |_: Vec<Value>| Ok(Value::from(state.load(Ordering::SeqCst)))),
    );
    let mut evaluator = policy.create_evaluator();
    let input = Value::from_json_str(r#"{"x":0}"#).unwrap();
    for expected in [1, 5, 0] {
        history.store(expected, Ordering::SeqCst);
        assert_eq!(
            evaluator.eval_with_input(input.clone()).unwrap(),
            Value::from(expected)
        );
    }
}

#[test]
fn errors_do_not_contaminate_later_evaluations() {
    let policy = compile(
        "package test\nresult := host.query(input.x)",
        Box::new(|args: Vec<Value>| {
            if args[0] == Value::from(0) {
                anyhow::bail!("host failure");
            }
            Ok(args[0].clone())
        }),
    );
    let mut evaluator = policy.create_evaluator();
    for x in [2, 0, 3, 0, 4] {
        let input = Value::from_json_str(&format!(r#"{{"x":{x}}}"#)).unwrap();
        let actual = evaluator.eval_with_input(input.clone());
        let expected = policy.eval_with_input(input);
        match (actual, expected) {
            (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
            (Err(actual), Err(expected)) => assert_eq!(actual.to_string(), expected.to_string()),
            _ => panic!("reused and fresh interpreters disagreed"),
        }
    }
}

#[test]
fn callback_state_is_private_and_persistence_is_opt_in() {
    let mut count = 0i64;
    let policy = compile(
        "package test\nresult := host.query(0)",
        Box::new(move |_: Vec<Value>| {
            count += 1;
            Ok(Value::from(count))
        }),
    );
    let mut a = policy.create_evaluator();
    let mut b = policy.create_evaluator();
    for expected in 1..=3i64 {
        assert_eq!(
            a.eval_with_input(Value::new_object()).unwrap(),
            Value::from(expected)
        );
        assert_eq!(
            b.eval_with_input(Value::new_object()).unwrap(),
            Value::from(expected)
        );
        assert_eq!(
            policy.eval_with_input(Value::new_object()).unwrap(),
            Value::from(1)
        );
    }
}
