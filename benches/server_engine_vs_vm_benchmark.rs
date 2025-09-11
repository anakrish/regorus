use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use regorus::rvm::{Compiler, RegoVM};
use regorus::{compile_policy_with_entrypoint, Engine, PolicyModule, Value};
use serde_json::json;
use std::hint::black_box;

const SERVER_POLICY: &str = r#"
package example

default allow := false                              # unless otherwise defined, allow is false

allow := r if {                                     # allow is true if...
    r := {
      "count": count(violation) == 0,               # there are zero violations.
      "violation": violation,
    }
}

violation contains server.id if {                   # a server is in the violation set if...
    some server
    public_server[server]                           # it exists in the 'public_server' set and...
    server.protocols[_] == "http"                   # it contains the insecure "http" protocol.
}

violation contains server.id if {                              # a server is in the violation set if...
    server := input.servers[_]                      # it exists in the input.servers collection and...
    server.protocols[_] == "telnet"                 # it contains the "telnet" protocol.
}

public_server contains server if  {                             # a server exists in the public_server set if...
    some i, j
    server := input.servers[_]                      # it exists in the input.servers collection and...
    server.ports[_] == input.ports[i].id            # it references a port in the input.ports collection and...
    input.ports[i].network == input.networks[j].id  # the port references a network in the input.networks collection and...
    input.networks[j].public                        # the network is public.
}
"#;

// Generate various test scenarios with different input configurations
fn generate_test_inputs() -> Vec<(&'static str, Value)> {
    vec![
        // Original safe configuration
        ("safe_config", json!({
            "servers": [
                {"id": "app", "protocols": ["https", "ssh"], "ports": ["p1", "p2", "p3"]},
                {"id": "db", "protocols": ["mysql"], "ports": ["p3"]},
                {"id": "cache", "protocols": ["memcache"], "ports": ["p3"]}
            ],
            "networks": [
                {"id": "net1", "public": false},
                {"id": "net2", "public": false},
                {"id": "net3", "public": true}
            ],
            "ports": [
                {"id": "p1", "network": "net1"},
                {"id": "p2", "network": "net3"},
                {"id": "p3", "network": "net2"}
            ]
        }).into()),
        
        // Configuration with HTTP violation (public server with http)
        ("http_violation", json!({
            "servers": [
                {"id": "web", "protocols": ["http", "https"], "ports": ["p1", "p2"]},
                {"id": "db", "protocols": ["mysql"], "ports": ["p3"]}
            ],
            "networks": [
                {"id": "net1", "public": true},
                {"id": "net2", "public": false}
            ],
            "ports": [
                {"id": "p1", "network": "net1"},
                {"id": "p2", "network": "net1"},
                {"id": "p3", "network": "net2"}
            ]
        }).into()),
        
        // Configuration with telnet violation
        ("telnet_violation", json!({
            "servers": [
                {"id": "legacy", "protocols": ["telnet"], "ports": ["p1"]},
                {"id": "app", "protocols": ["https"], "ports": ["p2"]}
            ],
            "networks": [
                {"id": "net1", "public": false},
                {"id": "net2", "public": true}
            ],
            "ports": [
                {"id": "p1", "network": "net1"},
                {"id": "p2", "network": "net2"}
            ]
        }).into()),
        
        // Large configuration with many servers
        ("large_config", json!({
            "servers": (0..50).map(|i| json!({
                "id": format!("server{}", i),
                "protocols": if i % 3 == 0 { vec!["https", "ssh"] } else if i % 7 == 0 { vec!["http"] } else { vec!["https"] },
                "ports": [format!("p{}", i % 10)]
            })).collect::<Vec<_>>(),
            "networks": (0..10).map(|i| json!({
                "id": format!("net{}", i),
                "public": i % 3 == 0
            })).collect::<Vec<_>>(),
            "ports": (0..10).map(|i| json!({
                "id": format!("p{}", i),
                "network": format!("net{}", i)
            })).collect::<Vec<_>>()
        }).into()),
        
        // Complex configuration with multiple violations
        ("complex_violations", json!({
            "servers": [
                {"id": "web1", "protocols": ["http"], "ports": ["p1"]},
                {"id": "web2", "protocols": ["https", "http"], "ports": ["p2"]},
                {"id": "legacy1", "protocols": ["telnet"], "ports": ["p3"]},
                {"id": "legacy2", "protocols": ["telnet", "ssh"], "ports": ["p4"]},
                {"id": "secure", "protocols": ["https", "ssh"], "ports": ["p5"]}
            ],
            "networks": [
                {"id": "public_net", "public": true},
                {"id": "private_net", "public": false}
            ],
            "ports": [
                {"id": "p1", "network": "public_net"},
                {"id": "p2", "network": "public_net"},
                {"id": "p3", "network": "private_net"},
                {"id": "p4", "network": "private_net"},
                {"id": "p5", "network": "private_net"}
            ]
        }).into()),
        
        // Edge case: empty configuration
        ("empty_config", json!({
            "servers": [],
            "networks": [],
            "ports": []
        }).into()),
    ]
}

fn print_evaluation_outputs() {
    println!("\n=== Server Policy Evaluation Results ===");
    let test_inputs = generate_test_inputs();

    for (input_name, input_value) in &test_inputs {
        println!("\n--- Input: {} ---", input_name);
        
        // Engine result
        let mut engine = Engine::new();
        engine
            .add_policy("server.rego".to_string(), SERVER_POLICY.to_string())
            .unwrap();
        engine.set_input(input_value.clone());
        let engine_result = engine.eval_rule("data.example.allow".to_string()).unwrap();
        
        // RVM result
        let module = PolicyModule {
            id: "server.rego".into(),
            content: SERVER_POLICY.into(),
        };
        let compiled_policy = compile_policy_with_entrypoint(
            Value::new_object(),
            &[module],
            "data.example.allow".into(),
        ).unwrap();
        
        let program = Compiler::compile_from_policy(&compiled_policy, "data.example.allow").unwrap();
        let mut vm = RegoVM::new_with_policy(compiled_policy.clone());
        vm.load_program(program);
        vm.set_input(input_value.clone());
        let rvm_result = vm.execute().unwrap();
        
        // Print results
        println!("  Engine allow result: {:?}", engine_result);
        println!("  RVM allow result:    {:?}", rvm_result);
       
        // Verify consistency
        if engine_result != rvm_result {
            println!("  ⚠️  WARNING: Engine and RVM results differ!");
        } else {
            println!("  ✅ Engine and RVM results match");
        }
    }
    println!("\n=== End Evaluation Results ===\n");
}

fn engine_vs_vm_comparison(c: &mut Criterion) {
    // Print outputs once before benchmarking
    print_evaluation_outputs();
    
    let test_inputs = generate_test_inputs();

    let mut group = c.benchmark_group("Server Policy: Engine vs RVM");

    for (input_name, input_value) in &test_inputs {
        // Benchmark Engine evaluation
        group.bench_with_input(
            BenchmarkId::new("engine", input_name),
            input_value,
            |b, input| {
                let mut engine = Engine::new();
                engine
                    .add_policy("server.rego".to_string(), SERVER_POLICY.to_string())
                    .unwrap();

                b.iter(|| {
                    engine.set_input(black_box(input.clone()));
                    let result = engine
                        .eval_rule(black_box("data.example.allow".to_string()))
                        .unwrap();
                    black_box(result);
                });
            },
        );

        // Benchmark RVM execution
        group.bench_with_input(
            BenchmarkId::new("rvm", input_name),
            input_value,
            |b, input| {
                // Compile policy to get the CompiledPolicy object
                let module = PolicyModule {
                    id: "server.rego".into(),
                    content: SERVER_POLICY.into(),
                };
                let compiled_policy = compile_policy_with_entrypoint(
                    Value::new_object(),
                    &[module],
                    "data.example.allow".into(),
                )
                .unwrap();

                // Compile to RVM program
                let program =
                    Compiler::compile_from_policy(&compiled_policy, "data.example.allow").unwrap();

                b.iter(|| {
                    let mut vm = RegoVM::new_with_policy(compiled_policy.clone());
                    vm.load_program(program.clone());
                    vm.set_input(black_box(input.clone()));
                    let result = vm.execute().unwrap();
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn server_policy_throughput(c: &mut Criterion) {
    let test_inputs = generate_test_inputs();

    let mut group = c.benchmark_group("Server Policy Throughput");
    group.throughput(Throughput::Elements(1));

    for (input_name, input_value) in &test_inputs {
        // Engine throughput
        group.bench_with_input(
            BenchmarkId::new("engine", format!("{}_throughput", input_name)),
            input_value,
            |b, input| {
                let mut engine = Engine::new();
                engine
                    .add_policy("server.rego".to_string(), SERVER_POLICY.to_string())
                    .unwrap();

                b.iter(|| {
                    engine.set_input(black_box(input.clone()));
                    let result = engine
                        .eval_rule(black_box("data.example.allow".to_string()))
                        .unwrap();
                    black_box(result);
                });
            },
        );

        // RVM throughput
        group.bench_with_input(
            BenchmarkId::new("rvm", format!("{}_throughput", input_name)),
            input_value,
            |b, input| {
                // Compile policy to get the CompiledPolicy object
                let module = PolicyModule {
                    id: "server.rego".into(),
                    content: SERVER_POLICY.into(),
                };
                let compiled_policy = compile_policy_with_entrypoint(
                    Value::new_object(),
                    &[module],
                    "data.example.allow".into(),
                )
                .unwrap();

                // Compile to RVM program
                let program =
                    Compiler::compile_from_policy(&compiled_policy, "data.example.allow").unwrap();

                b.iter(|| {
                    let mut vm = RegoVM::new_with_policy(compiled_policy.clone());
                    vm.load_program(program.clone());
                    vm.set_input(black_box(input.clone()));
                    let result = vm.execute().unwrap();
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

fn server_policy_batch_evaluation(c: &mut Criterion) {
    let test_inputs = generate_test_inputs();
    let batch_sizes = [1, 10, 100];

    let mut group = c.benchmark_group("Server Policy Batch Evaluation");

    for &batch_size in &batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64));

        // Engine batch evaluation
        group.bench_with_input(
            BenchmarkId::new("engine", format!("batch_{}", batch_size)),
            &batch_size,
            |b, &batch_size| {
                let mut engine = Engine::new();
                engine
                    .add_policy("server.rego".to_string(), SERVER_POLICY.to_string())
                    .unwrap();

                b.iter(|| {
                    for i in 0..batch_size {
                        let input = &test_inputs[i % test_inputs.len()].1;
                        engine.set_input(black_box(input.clone()));
                        let result = engine
                            .eval_rule(black_box("data.example.allow".to_string()))
                            .unwrap();
                        black_box(result);
                    }
                });
            },
        );

        // RVM batch evaluation
        group.bench_with_input(
            BenchmarkId::new("rvm", format!("batch_{}", batch_size)),
            &batch_size,
            |b, &batch_size| {
                // Compile policy to get the CompiledPolicy object
                let module = PolicyModule {
                    id: "server.rego".into(),
                    content: SERVER_POLICY.into(),
                };
                let compiled_policy = compile_policy_with_entrypoint(
                    Value::new_object(),
                    &[module],
                    "data.example.allow".into(),
                )
                .unwrap();

                // Compile to RVM program
                let program =
                    Compiler::compile_from_policy(&compiled_policy, "data.example.allow").unwrap();

                b.iter(|| {
                    for i in 0..batch_size {
                        let input = &test_inputs[i % test_inputs.len()].1;
                        let mut vm = RegoVM::new_with_policy(compiled_policy.clone());
                        vm.load_program(program.clone());
                        vm.set_input(black_box(input.clone()));
                        let result = vm.execute().unwrap();
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

fn server_policy_validation(c: &mut Criterion) {
    // Validate that engine, compiled policy, and RVM produce the same results
    let test_inputs = generate_test_inputs();

    c.bench_function("validation_check", |b| {
        b.iter(|| {
            for (input_name, input_value) in &test_inputs {
                // Engine result
                let mut engine = Engine::new();
                engine
                    .add_policy("server.rego".to_string(), SERVER_POLICY.to_string())
                    .unwrap();
                engine.set_input(input_value.clone());
                let engine_result = engine.eval_rule("data.example.allow".to_string()).unwrap();
                
                // Compiled Policy result
                let module = PolicyModule {
                    id: "server.rego".into(),
                    content: SERVER_POLICY.into(),
                };
                let compiled_policy = compile_policy_with_entrypoint(
                    Value::new_object(),
                    &[module],
                    "data.example.allow".into(),
                ).unwrap();
                let compiled_result = compiled_policy.eval_with_input(input_value.clone()).unwrap();
                
                // RVM result
                let program = Compiler::compile_from_policy(&compiled_policy, "data.example.allow").unwrap();
                let mut vm = RegoVM::new_with_policy(compiled_policy.clone());
                vm.load_program(program);
                vm.set_input(input_value.clone());
                let rvm_result = vm.execute().unwrap();
                
                // Verify all results match
                assert_eq!(
                    engine_result, compiled_result,
                    "Engine vs Compiled Policy results differ for input '{}': engine={:?}, compiled={:?}",
                    input_name, engine_result, compiled_result
                );
                assert_eq!(
                    engine_result, rvm_result,
                    "Engine vs RVM results differ for input '{}': engine={:?}, rvm={:?}",
                    input_name, engine_result, rvm_result
                );
                
                black_box((engine_result, compiled_result, rvm_result));
            }
        });
    });
}

criterion_group!(
    benches,
    engine_vs_vm_comparison,
    server_policy_throughput,
    server_policy_batch_evaluation,
    server_policy_validation
);
criterion_main!(benches);
