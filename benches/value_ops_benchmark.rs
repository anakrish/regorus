// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fast-running benchmarks focused on Value type operations.
//!
//! Designed for quick A/B comparison of different Value implementations.
//! Total runtime: ~30-60 seconds (vs ~10+ minutes for rvm_benchmark).
//!
//! # Benchmark groups
//!
//! | Group                 | What it measures                                     |
//! |-----------------------|------------------------------------------------------|
//! | `deserialize`         | JSON → Value parsing (small, medium, large)          |
//! | `serialize`           | Value → JSON string                                  |
//! | `clone`               | Value::clone for various shapes                      |
//! | `eq`                  | Value equality comparison                            |
//! | `hash`                | Value hashing (implicit in set/map ops)              |
//! | `lookup`              | Object key lookup                                    |
//! | `insert`              | Object/set mutation                                  |
//! | `set_ops`             | Set contains / intersection patterns                 |
//! | `eval/hot`            | Engine hot-path (set_input + eval_rule) — 3 policies |
//!
//! # Running
//!
//! ```sh
//! cargo bench --bench value_ops_benchmark                    # everything
//! cargo bench --bench value_ops_benchmark -- deserialize     # one group
//! cargo bench --bench value_ops_benchmark -- eval            # engine eval
//!
//! # With optimized-value feature:
//! cargo bench --bench value_ops_benchmark --features optimized-value
//! ```

#[cfg(feature = "optimized-value")]
use std::collections::hash_map::DefaultHasher;
#[cfg(feature = "optimized-value")]
use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::path::Path;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use regorus::{Engine, Value};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
//  Test data
// ---------------------------------------------------------------------------

/// Small Kubernetes-like object (~12 keys, nested).
const SMALL_JSON: &str = r#"{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "test-pod",
        "namespace": "default",
        "labels": {"app": "web", "env": "production", "version": "2.1.0"}
    },
    "spec": {
        "containers": [{
            "name": "nginx",
            "image": "nginx:1.25",
            "ports": [{"containerPort": 80}],
            "resources": {
                "limits": {"cpu": "500m", "memory": "128Mi"},
                "requests": {"cpu": "250m", "memory": "64Mi"}
            }
        }]
    }
}"#;

/// Medium ACI-like input (~30 keys, one level of nesting).
const MEDIUM_JSON: &str = r#"{
    "containerGroups": {
        "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerInstance/containerGroups/cg-1",
        "name": "cg-1",
        "location": "eastus",
        "properties": {
            "osType": "Linux",
            "restartPolicy": "Always",
            "containers": [
                {
                    "name": "my-container",
                    "properties": {
                        "image": "myregistry.azurecr.io/myimage:latest",
                        "command": ["/bin/sh", "-c", "echo hello"],
                        "environmentVariables": [
                            {"name": "ENV1", "value": "val1"},
                            {"name": "ENV2", "value": "val2"},
                            {"name": "ENV3", "secureValue": "secret"}
                        ],
                        "ports": [{"protocol": "TCP", "port": 8080}],
                        "resources": {
                            "requests": {"cpu": 1.0, "memoryInGB": 1.5}
                        },
                        "volumeMounts": [
                            {"name": "vol1", "mountPath": "/mnt/data", "readOnly": false}
                        ]
                    }
                }
            ],
            "volumes": [
                {"name": "vol1", "emptyDir": {}}
            ],
            "ipAddress": {
                "type": "Public",
                "ports": [{"protocol": "TCP", "port": 8080}]
            }
        }
    },
    "metadata": {
        "policyDefinitionId": "policy-123",
        "effect": "deny",
        "evaluationTimestamp": "2025-01-15T10:30:00Z"
    }
}"#;

/// Generate a flat object with N string→string pairs.
fn flat_obj_json(n: usize) -> String {
    let entries: Vec<String> = (0..n)
        .map(|i| format!(r#""key_{i}": "value_{i}""#))
        .collect();
    format!("{{{}}}", entries.join(", "))
}

/// Generate an array of N identical objects (each with `keys` string keys).
/// Maximizes benefit of key interning / string dedup.
fn array_of_objects_json(count: usize, keys: usize) -> String {
    let obj = flat_obj_json(keys);
    let objs: Vec<&str> = (0..count).map(|_| obj.as_str()).collect();
    format!("[{}]", objs.join(","))
}

// ---------------------------------------------------------------------------
//  Deserialization: JSON string → Value
// ---------------------------------------------------------------------------

fn bench_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize");

    group.bench_function("small", |b| {
        b.iter(|| {
            let v: Value = serde_json::from_str(black_box(SMALL_JSON)).unwrap();
            black_box(v);
        });
    });

    group.bench_function("medium", |b| {
        b.iter(|| {
            let v: Value = serde_json::from_str(black_box(MEDIUM_JSON)).unwrap();
            black_box(v);
        });
    });

    let large = array_of_objects_json(50, 10);
    group.bench_function("large_array_50x10", |b| {
        b.iter(|| {
            let v: Value = serde_json::from_str(black_box(&large)).unwrap();
            black_box(v);
        });
    });

    for &size in &[10, 32] {
        let json = flat_obj_json(size);
        group.bench_with_input(BenchmarkId::new("flat", size), &json, |b, j| {
            b.iter(|| {
                let v: Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Serialization: Value → JSON string
// ---------------------------------------------------------------------------

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    let small: Value = serde_json::from_str(SMALL_JSON).unwrap();
    group.bench_function("small", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&small)).unwrap()));
    });

    let medium: Value = serde_json::from_str(MEDIUM_JSON).unwrap();
    group.bench_function("medium", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&medium)).unwrap()));
    });

    let large: Value = serde_json::from_str(&array_of_objects_json(50, 10)).unwrap();
    group.bench_function("large_array_50x10", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&large)).unwrap()));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Clone: Value::clone()
// ---------------------------------------------------------------------------

fn bench_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("clone");

    // Scalar clones (should be trivial / free)
    let undef = Value::Undefined;
    group.bench_function("undefined", |b| {
        b.iter(|| black_box(black_box(&undef).clone()));
    });

    let boolean = Value::Bool(true);
    group.bench_function("bool", |b| {
        b.iter(|| black_box(black_box(&boolean).clone()));
    });

    let string_val = Value::from("hello_world");
    group.bench_function("string", |b| {
        b.iter(|| black_box(black_box(&string_val).clone()));
    });

    let long_string = Value::from("a]".repeat(50).as_str());
    group.bench_function("string_long", |b| {
        b.iter(|| black_box(black_box(&long_string).clone()));
    });

    // Collection clones (Rc bump)
    let small_obj: Value = serde_json::from_str(SMALL_JSON).unwrap();
    group.bench_function("object_small", |b| {
        b.iter(|| black_box(black_box(&small_obj).clone()));
    });

    let medium_obj: Value = serde_json::from_str(MEDIUM_JSON).unwrap();
    group.bench_function("object_medium", |b| {
        b.iter(|| black_box(black_box(&medium_obj).clone()));
    });

    let large_arr: Value = serde_json::from_str(&array_of_objects_json(50, 10)).unwrap();
    group.bench_function("array_large", |b| {
        b.iter(|| black_box(black_box(&large_arr).clone()));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Equality: Value == Value
// ---------------------------------------------------------------------------

fn bench_eq(c: &mut Criterion) {
    let mut group = c.benchmark_group("eq");

    // Same-pointer equality (fast path)
    let obj: Value = serde_json::from_str(SMALL_JSON).unwrap();
    let obj_clone = obj.clone();
    group.bench_function("same_ptr_object", |b| {
        b.iter(|| black_box(black_box(&obj) == black_box(&obj_clone)));
    });

    // Deep equality (different instances, same content)
    let obj_a: Value = serde_json::from_str(SMALL_JSON).unwrap();
    let obj_b: Value = serde_json::from_str(SMALL_JSON).unwrap();
    group.bench_function("deep_equal_object", |b| {
        b.iter(|| black_box(black_box(&obj_a) == black_box(&obj_b)));
    });

    // String equality
    let s1 = Value::from("production_environment_label");
    let s2 = Value::from("production_environment_label");
    group.bench_function("string_equal", |b| {
        b.iter(|| black_box(black_box(&s1) == black_box(&s2)));
    });

    // String inequality (short-circuit on first byte)
    let sa = Value::from("production_environment_label");
    let sb = Value::from("staging_environment_label");
    group.bench_function("string_not_equal", |b| {
        b.iter(|| black_box(black_box(&sa) == black_box(&sb)));
    });

    // Undefined check (hottest comparison in RVM)
    let undef = Value::Undefined;
    let val = Value::from(42u64);
    group.bench_function("undefined_check", |b| {
        b.iter(|| black_box(black_box(&val) == black_box(&undef)));
    });

    // Number cross-type equality
    let int_val = Value::from(42u64);
    let float_val: Value = serde_json::from_str("42.0").unwrap();
    group.bench_function("number_cross_type", |b| {
        b.iter(|| black_box(black_box(&int_val) == black_box(&float_val)));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Hashing: exercises the Hash impl (implicit in set/map operations)
//  Only available with optimized-value (default Value uses BTreeMap, no Hash).
// ---------------------------------------------------------------------------

#[cfg(feature = "optimized-value")]
fn hash_value(v: &Value) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

#[cfg(feature = "optimized-value")]
fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");

    let s = Value::from("production_environment_label");
    group.bench_function("string", |b| {
        b.iter(|| black_box(hash_value(black_box(&s))));
    });

    let num = Value::from(42u64);
    group.bench_function("uint", |b| {
        b.iter(|| black_box(hash_value(black_box(&num))));
    });

    let obj: Value = serde_json::from_str(SMALL_JSON).unwrap();
    group.bench_function("object_small", |b| {
        b.iter(|| black_box(hash_value(black_box(&obj))));
    });

    let arr: Value = serde_json::from_str(r#"["a","b","c","d","e"]"#).unwrap();
    group.bench_function("array_5", |b| {
        b.iter(|| black_box(hash_value(black_box(&arr))));
    });

    group.finish();
}

#[cfg(not(feature = "optimized-value"))]
fn bench_hash(_c: &mut Criterion) {
    // Hash benchmark skipped: default Value doesn't implement Hash.
}

// ---------------------------------------------------------------------------
//  Key lookup: obj[key]
// ---------------------------------------------------------------------------

fn bench_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("lookup");

    // Small object — hit
    let obj: Value = serde_json::from_str(SMALL_JSON).unwrap();
    let key = Value::from("metadata");
    group.bench_function("small_hit", |b| {
        b.iter(|| black_box(&obj[black_box(&key)]));
    });

    // Small object — miss
    let miss_key = Value::from("nonexistent");
    group.bench_function("small_miss", |b| {
        b.iter(|| black_box(&obj[black_box(&miss_key)]));
    });

    // Medium object — nested chain (obj["containerGroups"]["properties"]["osType"])
    let obj_m: Value = serde_json::from_str(MEDIUM_JSON).unwrap();
    let k1 = Value::from("containerGroups");
    let k2 = Value::from("properties");
    let k3 = Value::from("osType");
    group.bench_function("chain_3_deep", |b| {
        b.iter(|| {
            let v1 = &obj_m[black_box(&k1)];
            let v2 = &v1[black_box(&k2)];
            black_box(&v2[black_box(&k3)]);
        });
    });

    // Flat 32-key object — lookup last key
    let flat: Value = serde_json::from_str(&flat_obj_json(32)).unwrap();
    let last_key = Value::from("key_31");
    group.bench_function("flat32_last_key", |b| {
        b.iter(|| black_box(&flat[black_box(&last_key)]));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Insert: build objects and sets
// ---------------------------------------------------------------------------

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    // Build a 20-key object from scratch
    group.bench_function("build_object_20", |b| {
        b.iter(|| {
            let mut obj = Value::new_object();
            for i in 0..20 {
                let k = Value::from(format!("key_{i}").as_str());
                let v = Value::from(format!("val_{i}").as_str());
                obj.as_object_mut().unwrap().insert(k, v);
            }
            black_box(obj);
        });
    });

    // Build a 20-element set from scratch
    group.bench_function("build_set_20", |b| {
        b.iter(|| {
            let mut set = Value::new_set();
            for i in 0..20 {
                let v = Value::from(format!("elem_{i}").as_str());
                set.as_set_mut().unwrap().insert(v);
            }
            black_box(set);
        });
    });

    // Insert into existing object (clone-on-write pattern via Rc::make_mut)
    // Two references → forces deep clone
    let base: Value = serde_json::from_str(SMALL_JSON).unwrap();
    group.bench_function("cow_insert_shared", |b| {
        b.iter(|| {
            let mut obj = base.clone();
            let _keep_alive = base.clone(); // hold second Rc ref
            obj.as_object_mut()
                .unwrap()
                .insert(Value::from("new_key"), Value::from("new_val"));
            black_box(obj);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Set operations: contains, membership patterns
// ---------------------------------------------------------------------------

fn bench_set_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_ops");

    // Build a set of 100 string values
    let mut set = Value::new_set();
    for i in 0..100 {
        set.as_set_mut()
            .unwrap()
            .insert(Value::from(format!("item_{i}").as_str()));
    }

    let hit = Value::from("item_50");
    group.bench_function("contains_hit_100", |b| {
        b.iter(|| {
            black_box(set.as_set().unwrap().contains(black_box(&hit)));
        });
    });

    let miss = Value::from("item_999");
    group.bench_function("contains_miss_100", |b| {
        b.iter(|| {
            black_box(set.as_set().unwrap().contains(black_box(&miss)));
        });
    });

    // Iterate set (common in comprehensions)
    group.bench_function("iterate_100", |b| {
        b.iter(|| {
            let s = set.as_set().unwrap();
            let mut count = 0u64;
            for v in s.iter() {
                black_box(v);
                count += 1;
            }
            black_box(count);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Engine eval — hot path benchmark (reuses Engine, only set_input + eval)
//
//  Uses 3 representative synthetic policies. Each iteration does:
//    engine.set_input(input.clone())
//    engine.eval_rule("data.bench.allow")
//
//  This exercises the full Value pipeline: deserialization (input clone),
//  hashing (object lookups), equality (rule conditions), set membership,
//  and result construction.
// ---------------------------------------------------------------------------

fn bench_eval_hot(c: &mut Criterion) {
    let base_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches")
        .join("evaluation")
        .join("test_data");

    // Representative subset: one simple, one medium, one complex policy
    let policies: &[(&str, &str, &str)] = &[
        ("rbac", "rbac_policy.rego", "rbac_input.json"),
        (
            "api_access",
            "api_access_policy.rego",
            "api_access_input.json",
        ),
        ("azure_nsg", "azure_nsg_policy.rego", "azure_nsg_input.json"),
    ];

    let mut group = c.benchmark_group("eval/hot");

    for &(name, policy_file, input_file) in policies {
        let policy_path = base_dir.join("policies").join(policy_file);
        let input_path = base_dir.join("inputs").join(input_file);

        let policy = std::fs::read_to_string(&policy_path)
            .unwrap_or_else(|e| panic!("read {policy_path:?}: {e}"));
        let input_json = std::fs::read_to_string(&input_path)
            .unwrap_or_else(|e| panic!("read {input_path:?}: {e}"));
        let input: Value = Value::from_json_str(&input_json).unwrap();

        let mut engine = Engine::new();
        engine
            .add_policy("policy.rego".to_string(), policy)
            .unwrap();
        // Warm up
        engine.set_input(input.clone());
        let _ = engine.eval_rule("data.bench.allow".to_string());

        group.bench_function(name, |b| {
            b.iter(|| {
                engine.set_input(black_box(input.clone()));
                black_box(engine.eval_rule("data.bench.allow".to_string()).unwrap());
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  ACI scenario types and loading
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
struct AciTestCase {
    note: String,
    data: Value,
    input: Value,
    modules: Vec<String>,
    query: String,
    want_result: Value,
}

#[derive(Serialize, Deserialize, Debug)]
struct AciYamlTest {
    cases: Vec<AciTestCase>,
}

fn load_aci_cases(dir: &Path) -> Vec<AciTestCase> {
    let mut cases = Vec::new();
    for entry in WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.to_string_lossy().ends_with(".yaml") {
            continue;
        }
        let yaml = std::fs::read(path).expect("failed to read yaml");
        let yaml = String::from_utf8_lossy(&yaml);
        let test: AciYamlTest = serde_yaml::from_str(&yaml).expect("failed to deserialize yaml");
        cases.extend(test.cases);
    }
    cases
}

fn build_aci_engine(dir: &Path, case: &AciTestCase) -> Engine {
    let mut engine = Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_data(case.data.clone())
        .expect("failed to add data");
    engine.set_input(case.input.clone());
    for (idx, rego) in case.modules.iter().enumerate() {
        if rego.ends_with(".rego") {
            engine
                .add_policy_from_file(dir.join(rego).to_str().expect("invalid path"))
                .expect("failed to add policy");
        } else {
            engine
                .add_policy(format!("rego{idx}.rego"), rego.clone())
                .expect("failed to add policy");
        }
    }
    engine
}

// ---------------------------------------------------------------------------
//  Engine eval — hot path for ACI scenarios
//
//  Loads all ACI test cases from tests/aci/*.yaml. Each case gets its own
//  pre-built Engine; iterations only do set_input + eval_rule.
// ---------------------------------------------------------------------------

fn bench_eval_aci(c: &mut Criterion) {
    let dir = Path::new("tests/aci");
    let cases = load_aci_cases(dir);

    let mut group = c.benchmark_group("eval/aci");

    for case in &cases {
        let mut engine = build_aci_engine(dir, case);
        let rule = case.query.replace("=x", "");

        // Warm up
        engine.set_input(case.input.clone());
        let _ = engine.eval_rule(rule.clone());

        let input = case.input.clone();
        group.bench_function(&case.note, |b| {
            b.iter(|| {
                engine.set_input(black_box(input.clone()));
                black_box(engine.eval_rule(rule.clone()).unwrap());
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Criterion configuration — short warmup + measurement for fast iteration
// ---------------------------------------------------------------------------

criterion_group! {
    name = value_micro;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2))
        .sample_size(50);
    targets =
        bench_deserialize,
        bench_serialize,
        bench_clone,
        bench_eq,
        bench_hash,
        bench_lookup,
        bench_insert,
        bench_set_ops,
}

criterion_group! {
    name = value_eval;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3))
        .sample_size(50);
    targets = bench_eval_hot, bench_eval_aci,
}

criterion_main!(value_micro, value_eval);
