use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use regorus::{compile_policy_with_entrypoint, CompiledPolicy, PolicyModule, Value};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

mod policy_data;

fn multi_threaded_compiled_eval(
    num_threads: usize,
    evals_per_thread: usize,
    use_cloned_inputs: bool,
) -> (std::time::Duration, HashMap<String, usize>) {
    // Complex policies with multiple valid inputs for each
    let policies_with_inputs = policy_data::policies_with_inputs();

    // Policy names for tracking
    let policy_names = policy_data::policy_names().into_iter().map(|s| s.to_string()).collect::<Vec<_>>();

    // Pre-compile all policies and share them between threads
    let compiled_policies: Arc<Vec<CompiledPolicy>> = Arc::new(
        policies_with_inputs
            .iter()
            .map(|(policy, _)| {
                let module = PolicyModule {
                    id: "policy.rego".into(),
                    content: policy.as_str().into(),
                };
                compile_policy_with_entrypoint(
                    Value::new_object(),
                    &[module],
                    "data.bench.allow".into(),
                ).unwrap()
            })
            .collect()
    );

    // Initialize policy evaluation counters
    let policy_counters = Arc::new(Mutex::new(HashMap::new()));
    for policy_name in &policy_names {
        policy_counters
            .lock()
            .unwrap()
            .insert(policy_name.to_string(), 0);
    }

    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::with_capacity(num_threads);

    for thread_id in 0..num_threads {
        let barrier = barrier.clone();
        let policies_with_inputs = policies_with_inputs.clone();
        let compiled_policies = Arc::clone(&compiled_policies);
        let policy_names = policy_names.clone();
        let policy_counters = policy_counters.clone();

        handles.push(thread::spawn(move || {
            let mut elapsed = std::time::Duration::ZERO;

            // Pre-parse inputs if using cloned inputs
            let parsed_inputs = if use_cloned_inputs {
                Some(
                    policies_with_inputs
                        .iter()
                        .map(|(_, inputs)| {
                            inputs
                                .iter()
                                .map(|input_str| Value::from_json_str(input_str).unwrap())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };

            barrier.wait();
            for i in 0..evals_per_thread {
                // Use different policy for each iteration
                let policy_idx = (thread_id + i) % policies_with_inputs.len();
                let (_, inputs) = &policies_with_inputs[policy_idx];

                // Use different input for the same policy based on iteration
                let input_idx = i % inputs.len();
                let input = &inputs[input_idx];

                let start = std::time::Instant::now();

                let compiled_policy = &compiled_policies[policy_idx];

                let input_value = if use_cloned_inputs {
                    parsed_inputs.as_ref().unwrap()[policy_idx][input_idx].clone()
                } else {
                    Value::from_json_str(input).unwrap()
                };

                let result = compiled_policy.eval_with_input(input_value);
                elapsed += start.elapsed();

                // Track successful evaluations
                if result.is_ok() {
                    if let Some(policy_name) = policy_names.get(policy_idx) {
                        let mut counters = policy_counters.lock().unwrap();
                        *counters.entry(policy_name.to_string()).or_insert(0) += 1;
                    }
                }
            }
            elapsed
        }));
    }

    let mut total = std::time::Duration::ZERO;
    for handle in handles {
        total += handle.join().unwrap();
    }

    let final_counters = policy_counters.lock().unwrap().clone();
    (total, final_counters)
}

fn criterion_benchmark(c: &mut Criterion) {
    let max_threads = num_cpus::get() * 2;
    println!("Running compiled policy benchmark with max_threads: {}", max_threads);

    let evals_per_thread = 1000;

    // Benchmark with and without cloned inputs (policies are always shared/cloned)
    for use_cloned_inputs in [true, false] {
        let group_name = match use_cloned_inputs {
            true => "compiled_shared_policies, cloned_inputs ",
            false => "compiled_shared_policies, fresh_inputs  ",
        };

        let mut group = c.benchmark_group(group_name);
        group.measurement_time(Duration::from_secs(5));

        // Test specific thread counts: powers of 2 + some intermediate values
        let thread_counts: Vec<usize> = (1..=max_threads)
            .filter(|&n| {
                n == 1 || // Always test single-threaded
                n % 2 == 0 || // Always test even threads
                n == max_threads // Maximum threads
            })
            .collect();

        for threads in thread_counts {
            let total_evals = threads * evals_per_thread;
            group.throughput(Throughput::Elements(total_evals as u64));
            group.bench_with_input(
                BenchmarkId::new("compiled_eval", format!(" {threads} threads")),
                &threads,
                |b, &threads| {
                    b.iter_custom(|iters| {
                        let evals_per_thread = evals_per_thread * (iters as usize);
                        let (duration, policy_counters) = multi_threaded_compiled_eval(
                            black_box(threads),
                            black_box(evals_per_thread),
                            black_box(use_cloned_inputs),
                        );

                        // On one iteration, print policy evaluation statistics
                        if iters == 1 {
                            // println!("\nCompiled Policy Evaluation Statistics:");
                            for (policy_name, count) in &policy_counters {
                                // println!("  {}: {} evaluations", policy_name, count);
                                if *count == 0 {
                                    println!("\x1b[31mERROR: Policy '{}' was never evaluated successfully!\x1b[0m", policy_name);
                                }
                            }
                        }

                        duration
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
