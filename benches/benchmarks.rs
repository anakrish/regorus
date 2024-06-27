// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use regorus::*;

fn criterion_benchmark(c: &mut Criterion) {
    let mut engine = Engine::new();
    engine
        .add_policy_from_file("examples/example.rego")
        .expect("failed to add policy");
    engine.set_input(Value::from_json_file("examples/input.json").expect("failed to load input"));

    c.bench_function("eval example policy", |b| {
        b.iter(|| engine.eval_rule("data.example.allow".to_owned()).expect(""))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
