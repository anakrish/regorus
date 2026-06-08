// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Criterion benchmarks comparing baseline (regorus::Value) vs v1::Value.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use value_compare::v1;
use value_compare::v2;
use value_compare::v3;
use value_compare::v4;
use value_compare::v5;
use value_compare::v6;
use value_compare::v7;
use value_compare::v8;
use value_compare::v9;
use bumpalo::Bump;

// ---------------------------------------------------------------------------
//  Test data
// ---------------------------------------------------------------------------

/// A small policy-like JSON with string keys (typical Rego object).
const SMALL_OBJ_JSON: &str = r#"{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "test-pod",
        "namespace": "default",
        "labels": {
            "app": "web",
            "env": "production",
            "version": "2.1.0"
        }
    },
    "spec": {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:1.25",
                "ports": [{"containerPort": 80}],
                "resources": {
                    "limits": {"cpu": "500m", "memory": "128Mi"},
                    "requests": {"cpu": "250m", "memory": "64Mi"}
                }
            }
        ]
    }
}"#;

/// Flat object with N string keys — simulates real-world config/policy data.
fn flat_obj_json(n: usize) -> String {
    let mut entries: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        entries.push(format!(r#""key_{i}": "value_{i}""#));
    }
    format!("{{{}}}", entries.join(", "))
}

/// An array of `count` objects, each with `keys` string keys.
/// All objects share the same key names — the ideal case for key interning.
fn array_of_objects_json(count: usize, keys: usize) -> String {
    let obj = flat_obj_json(keys);
    let objs: Vec<&str> = (0..count).map(|_| obj.as_str()).collect();
    format!("[{}]", objs.join(","))
}

/// A realistic policy-like object with nested structures and N top-level keys.
fn realistic_obj_json(n: usize) -> String {
    let mut entries: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        entries.push(format!(
            r#""rule_{i}": {{"action": "allow", "resource": "/api/v1/item/{i}", "priority": {i}, "enabled": true}}"#
        ));
    }
    format!("{{{}}}", entries.join(", "))
}

// ---------------------------------------------------------------------------
//  Deserialization benchmarks
// ---------------------------------------------------------------------------

fn bench_deserialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize");

    // Small object (Kubernetes pod-like, ~12 keys nested)
    group.bench_function("baseline/small", |b| {
        b.iter(|| {
            let v: regorus::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v1/small", |b| {
        b.iter(|| {
            let v: v1::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v2/small", |b| {
        b.iter(|| {
            let v: v2::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v2_interned/small", |b| {
        b.iter(|| {
            let v: v2::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v3/small", |b| {
        b.iter(|| {
            let v: v3::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v3_interned/small", |b| {
        b.iter(|| {
            let v: v3::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v4/small", |b| {
        b.iter(|| {
            let v: v4::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v4_interned/small", |b| {
        b.iter(|| {
            let v: v4::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v5/small", |b| {
        b.iter(|| {
            let v: v5::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v5_interned/small", |b| {
        b.iter(|| {
            let v: v5::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v6/small", |b| {
        b.iter(|| {
            let v: v6::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v6_interned/small", |b| {
        b.iter(|| {
            let v: v6::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v7/small", |b| {
        b.iter(|| {
            let v: v7::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v7_interned/small", |b| {
        b.iter(|| {
            let v: v7::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v8/small", |b| {
        b.iter(|| {
            let v: v8::Value = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v8_interned/small", |b| {
        b.iter(|| {
            let v: v8::Interned = serde_json::from_str(black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v.0);
        });
    });
    group.bench_function("v9/small", |b| {
        b.iter(|| {
            let arena = Bump::new();
            let v = v9::from_json(&arena, black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });
    group.bench_function("v9_interned/small", |b| {
        b.iter(|| {
            let arena = Bump::new();
            let mut interner = v9::StringInterner::new(&arena);
            let v = v9::from_json_interned(&arena, &mut interner, black_box(SMALL_OBJ_JSON)).unwrap();
            black_box(v);
        });
    });

    // Realistic flat objects at typical sizes
    for &size in &[10, 15, 20, 32] {
        let json = flat_obj_json(size);
        group.bench_with_input(BenchmarkId::new("baseline/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: regorus::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v1::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v2::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v2::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v3::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v3::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v4::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v4::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v5::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v5::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v6::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v6::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v7::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v7::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v8::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let v: v8::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/flat", size), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let v = v9::from_json(&arena, black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9_interned/flat", size), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let mut interner = v9::StringInterner::new(&arena);
                let v = v9::from_json_interned(&arena, &mut interner, black_box(j)).unwrap();
                black_box(v);
            });
        });
    }

    // Realistic nested policy objects
    for &size in &[10, 20, 32] {
        let json = realistic_obj_json(size);
        group.bench_with_input(BenchmarkId::new("baseline/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: regorus::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v1::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v2::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v2::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v3::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v3::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v4::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v4::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v5::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v5::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v6::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v6::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v7::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v7::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v8::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let v: v8::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/realistic", size), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let v = v9::from_json(&arena, black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9_interned/realistic", size), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let mut interner = v9::StringInterner::new(&arena);
                let v = v9::from_json_interned(&arena, &mut interner, black_box(j)).unwrap();
                black_box(v);
            });
        });
    }

    // Array of objects with shared keys — measures interning benefit from key reuse
    for &(count, keys) in &[(10, 10), (100, 10), (100, 32)] {
        let json = array_of_objects_json(count, keys);
        let label = format!("{}x{}", count, keys);
        group.bench_with_input(BenchmarkId::new("v2/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v2::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2_interned/array", &label), &json, |b, j| {
            v2::interner::clear();
            b.iter(|| {
                let v: v2::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v3::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3_interned/array", &label), &json, |b, j| {
            v3::interner::clear();
            b.iter(|| {
                let v: v3::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v4::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4_interned/array", &label), &json, |b, j| {
            v4::interner::clear();
            b.iter(|| {
                let v: v4::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v5::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5_interned/array", &label), &json, |b, j| {
            v5::interner::clear();
            b.iter(|| {
                let v: v5::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v6::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6_interned/array", &label), &json, |b, j| {
            v6::interner::clear();
            b.iter(|| {
                let v: v6::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v7::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7_interned/array", &label), &json, |b, j| {
            v7::interner::clear();
            v7::object_map::clear_schema_cache();
            b.iter(|| {
                let v: v7::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/array", &label), &json, |b, j| {
            b.iter(|| {
                let v: v8::Value = serde_json::from_str(black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8_interned/array", &label), &json, |b, j| {
            v8::object_map::clear_schema_cache();
            b.iter(|| {
                let v: v8::Interned = serde_json::from_str(black_box(j)).unwrap();
                black_box(v.0);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/array", &label), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let v = v9::from_json(&arena, black_box(j)).unwrap();
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9_interned/array", &label), &json, |b, j| {
            b.iter(|| {
                let arena = Bump::new();
                let mut interner = v9::StringInterner::new(&arena);
                let v = v9::from_json_interned(&arena, &mut interner, black_box(j)).unwrap();
                black_box(v);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Key lookup benchmarks
// ---------------------------------------------------------------------------

fn bench_key_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_lookup");

    // Small object
    let baseline: regorus::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v1_val: v1::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v2_val: v2::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v3_val: v3::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v4_val: v4::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v5_val: v5::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v6_val: v6::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v7_val: v7::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v8_val: v8::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v9_arena = Bump::new();
    let v9_val = v9::from_json(&v9_arena, SMALL_OBJ_JSON).unwrap();
    let baseline_meta_key = regorus::Value::from(regorus::Value::String("metadata".into()));
    let v1_meta_key = v1::Value::String(std::sync::Arc::from("metadata"));
    let v2_meta_key = v2::Value::String(std::sync::Arc::from("metadata"));
    let v3_meta_key = v3::Value::String(std::sync::Arc::from("metadata"));
    let v4_meta_key = v4::Value::String(arcstr::ArcStr::from("metadata"));
    let v5_meta_key = v5::Value::from_arcstr(arcstr::ArcStr::from("metadata"));
    let v6_meta_key = v6::Value::from_arcstr(arcstr::ArcStr::from("metadata"));
    let v7_meta_key = v7::Value::from_arcstr(arcstr::ArcStr::from("metadata"));
    let v8_meta_key = v8::Value::String(arcstr::ArcStr::from("metadata"));
    let v9_meta_key = v9::Value::from_str_ref(&v9_arena, v9_arena.alloc_str("metadata"));

    group.bench_function("baseline/small_index", |b| {
        b.iter(|| {
            let v = &baseline[black_box(&baseline_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v1/small_get_str", |b| {
        b.iter(|| {
            let v = v1_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v1/small_index", |b| {
        b.iter(|| {
            let v = &v1_val[black_box(&v1_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v2/small_get_str", |b| {
        b.iter(|| {
            let v = v2_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v2/small_index", |b| {
        b.iter(|| {
            let v = &v2_val[black_box(&v2_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v3/small_get_str", |b| {
        b.iter(|| {
            let v = v3_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v3/small_index", |b| {
        b.iter(|| {
            let v = &v3_val[black_box(&v3_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v4/small_get_str", |b| {
        b.iter(|| {
            let v = v4_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v4/small_index", |b| {
        b.iter(|| {
            let v = &v4_val[black_box(&v4_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v5/small_get_str", |b| {
        b.iter(|| {
            let v = v5_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v5/small_index", |b| {
        b.iter(|| {
            let v = &v5_val[black_box(&v5_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v6/small_get_str", |b| {
        b.iter(|| {
            let v = v6_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v6/small_index", |b| {
        b.iter(|| {
            let v = &v6_val[black_box(&v6_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v7/small_get_str", |b| {
        b.iter(|| {
            let v = v7_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v7/small_index", |b| {
        b.iter(|| {
            let v = &v7_val[black_box(&v7_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v8/small_get_str", |b| {
        b.iter(|| {
            let v = v8_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v8/small_index", |b| {
        b.iter(|| {
            let v = &v8_val[black_box(&v8_meta_key)];
            black_box(v);
        });
    });
    group.bench_function("v9/small_get_str", |b| {
        b.iter(|| {
            let v = v9_val.get_str(black_box("metadata"));
            black_box(v);
        });
    });
    group.bench_function("v9/small_index", |b| {
        b.iter(|| {
            let v = &v9_val[black_box(&v9_meta_key)];
            black_box(v);
        });
    });

    // Realistic sizes: 10, 20, 32 keys — lookup a middle key
    for &size in &[10, 20, 32] {
        let json = flat_obj_json(size);
        let baseline_obj: regorus::Value = serde_json::from_str(&json).unwrap();
        let v1_obj: v1::Value = serde_json::from_str(&json).unwrap();
        let v2_obj: v2::Value = serde_json::from_str(&json).unwrap();
        let v3_obj: v3::Value = serde_json::from_str(&json).unwrap();
        let v4_obj: v4::Value = serde_json::from_str(&json).unwrap();
        let v5_obj: v5::Value = serde_json::from_str(&json).unwrap();
        let v6_obj: v6::Value = serde_json::from_str(&json).unwrap();
        let v7_obj: v7::Value = serde_json::from_str(&json).unwrap();
        let v8_obj: v8::Value = serde_json::from_str(&json).unwrap();
        let v9_sized_arena = Bump::new();
        let v9_obj = v9::from_json(&v9_sized_arena, &json).unwrap();
        let mid = size / 2;
        let key_str = format!("key_{mid}");
        let baseline_key = regorus::Value::from(regorus::Value::String(key_str.clone().into()));
        let v1_key = v1::Value::String(std::sync::Arc::from(key_str.as_str()));
        let v2_key = v2::Value::String(std::sync::Arc::from(key_str.as_str()));
        let v3_key = v3::Value::String(std::sync::Arc::from(key_str.as_str()));
        let v4_key = v4::Value::String(arcstr::ArcStr::from(key_str.as_str()));
        let v5_key = v5::Value::from_arcstr(arcstr::ArcStr::from(key_str.as_str()));
        let v6_key = v6::Value::from_arcstr(arcstr::ArcStr::from(key_str.as_str()));
        let v7_key = v7::Value::from_arcstr(arcstr::ArcStr::from(key_str.as_str()));
        let v8_key = v8::Value::String(arcstr::ArcStr::from(key_str.as_str()));
        let v9_key = v9::Value::from_str_ref(&v9_sized_arena, v9_sized_arena.alloc_str(&key_str));

        group.bench_with_input(BenchmarkId::new("baseline/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &baseline_obj[black_box(&baseline_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v1_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v1_obj[black_box(&v1_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v2_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v2_obj[black_box(&v2_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v3_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v3_obj[black_box(&v3_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v4_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v4_obj[black_box(&v4_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v5_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v5_obj[black_box(&v5_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v6_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v6_obj[black_box(&v6_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v7_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v7_obj[black_box(&v7_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v8_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v8_obj[black_box(&v8_key)];
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/get_str", size), &size, |b, _| {
            b.iter(|| {
                let v = v9_obj.get_str(black_box(&key_str));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/index", size), &size, |b, _| {
            b.iter(|| {
                let v = &v9_obj[black_box(&v9_key)];
                black_box(v);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Comparison benchmarks (PartialEq, Ord)
// ---------------------------------------------------------------------------

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison");

    // Small object equality
    let baseline_a: regorus::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let baseline_b: regorus::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v1_a: v1::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v1_b: v1::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v2_a: v2::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v2_b: v2::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v3_a: v3::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v3_b: v3::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v4_a: v4::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v4_b: v4::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v5_a: v5::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v5_b: v5::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v6_a: v6::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v6_b: v6::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v7_a: v7::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v7_b: v7::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v8_a: v8::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v8_b: v8::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v9_arena_a = Bump::new();
    let v9_arena_b = Bump::new();
    let v9_a = v9::from_json(&v9_arena_a, SMALL_OBJ_JSON).unwrap();
    let v9_b = v9::from_json(&v9_arena_b, SMALL_OBJ_JSON).unwrap();

    group.bench_function("baseline/eq_small", |b| {
        b.iter(|| black_box(&baseline_a) == black_box(&baseline_b));
    });
    group.bench_function("v1/eq_small", |b| {
        b.iter(|| black_box(&v1_a) == black_box(&v1_b));
    });
    group.bench_function("v2/eq_small", |b| {
        b.iter(|| black_box(&v2_a) == black_box(&v2_b));
    });
    group.bench_function("v3/eq_small", |b| {
        b.iter(|| black_box(&v3_a) == black_box(&v3_b));
    });
    group.bench_function("v4/eq_small", |b| {
        b.iter(|| black_box(&v4_a) == black_box(&v4_b));
    });
    group.bench_function("v5/eq_small", |b| {
        b.iter(|| black_box(&v5_a) == black_box(&v5_b));
    });
    group.bench_function("v6/eq_small", |b| {
        b.iter(|| black_box(&v6_a) == black_box(&v6_b));
    });
    group.bench_function("v7/eq_small", |b| {
        b.iter(|| black_box(&v7_a) == black_box(&v7_b));
    });
    group.bench_function("v8/eq_small", |b| {
        b.iter(|| black_box(&v8_a) == black_box(&v8_b));
    });
    group.bench_function("v9/eq_small", |b| {
        b.iter(|| black_box(&v9_a) == black_box(&v9_b));
    });

    // Realistic-sized object equality (10, 20, 32 keys)
    for &size in &[10, 20, 32] {
        let json = flat_obj_json(size);
        let ba: regorus::Value = serde_json::from_str(&json).unwrap();
        let bb: regorus::Value = serde_json::from_str(&json).unwrap();
        let va: v1::Value = serde_json::from_str(&json).unwrap();
        let vb: v1::Value = serde_json::from_str(&json).unwrap();

        group.bench_with_input(BenchmarkId::new("baseline/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&ba) == black_box(&bb));
        });
        group.bench_with_input(BenchmarkId::new("v1/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&va) == black_box(&vb));
        });

        let v2a: v2::Value = serde_json::from_str(&json).unwrap();
        let v2b: v2::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v2/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v2a) == black_box(&v2b));
        });

        let v3a: v3::Value = serde_json::from_str(&json).unwrap();
        let v3b: v3::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v3/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v3a) == black_box(&v3b));
        });

        let v4a: v4::Value = serde_json::from_str(&json).unwrap();
        let v4b: v4::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v4/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v4a) == black_box(&v4b));
        });

        let v5a: v5::Value = serde_json::from_str(&json).unwrap();
        let v5b: v5::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v5/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v5a) == black_box(&v5b));
        });

        let v6a: v6::Value = serde_json::from_str(&json).unwrap();
        let v6b: v6::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v6/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v6a) == black_box(&v6b));
        });

        let v7a: v7::Value = serde_json::from_str(&json).unwrap();
        let v7b: v7::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v7/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v7a) == black_box(&v7b));
        });

        let v8a: v8::Value = serde_json::from_str(&json).unwrap();
        let v8b: v8::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v8/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v8a) == black_box(&v8b));
        });

        let v9_flat_arena_a = Bump::new();
        let v9_flat_arena_b = Bump::new();
        let v9a = v9::from_json(&v9_flat_arena_a, &json).unwrap();
        let v9b = v9::from_json(&v9_flat_arena_b, &json).unwrap();
        group.bench_with_input(BenchmarkId::new("v9/eq_flat", size), &size, |b, _| {
            b.iter(|| black_box(&v9a) == black_box(&v9b));
        });
    }

    // Number comparison (100 pairs)
    let base_nums: Vec<regorus::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    let v1_nums: Vec<v1::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();

    group.bench_function("baseline/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&base_nums[i]) == black_box(&base_nums[99 - i]));
            }
        });
    });
    group.bench_function("v1/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v1_nums[i]) == black_box(&v1_nums[99 - i]));
            }
        });
    });

    let v2_nums: Vec<v2::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v2/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v2_nums[i]) == black_box(&v2_nums[99 - i]));
            }
        });
    });

    let v3_nums: Vec<v3::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v3/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v3_nums[i]) == black_box(&v3_nums[99 - i]));
            }
        });
    });

    let v4_nums: Vec<v4::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v4/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v4_nums[i]) == black_box(&v4_nums[99 - i]));
            }
        });
    });

    let v5_nums: Vec<v5::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v5/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v5_nums[i]) == black_box(&v5_nums[99 - i]));
            }
        });
    });

    let v6_nums: Vec<v6::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v6/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v6_nums[i]) == black_box(&v6_nums[99 - i]));
            }
        });
    });

    let v7_nums: Vec<v7::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v7/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v7_nums[i]) == black_box(&v7_nums[99 - i]));
            }
        });
    });

    let v8_nums: Vec<v8::Value> = (0..100i64)
        .map(|i| serde_json::from_str(&i.to_string()).unwrap())
        .collect();
    group.bench_function("v8/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v8_nums[i]) == black_box(&v8_nums[99 - i]));
            }
        });
    });

    let v9_num_arena = Bump::new();
    let v9_nums: Vec<v9::Value> = (0..100i64)
        .map(|i| v9::from_json(&v9_num_arena, &i.to_string()).unwrap())
        .collect();
    group.bench_function("v9/number_eq_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                black_box(black_box(&v9_nums[i]) == black_box(&v9_nums[99 - i]));
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
//  Serialization benchmarks
// ---------------------------------------------------------------------------

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    // Compare: baseline (BTreeMap, naturally sorted) vs v1 unsorted vs v1 sorted
    let baseline: regorus::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v1_val: v1::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    let v2_val: v2::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();

    group.bench_function("baseline/small", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&baseline)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v1/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v1_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v1/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v1::SortedValue(black_box(&v1_val))).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v2/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v2_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v2/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v2::SortedValue(black_box(&v2_val))).unwrap();
            black_box(s);
        });
    });

    let v3_val: v3::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v3/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v3_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v3/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v3::SortedValue(black_box(&v3_val))).unwrap();
            black_box(s);
        });
    });

    let v4_val: v4::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v4/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v4_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v4/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v4::SortedValue(black_box(&v4_val))).unwrap();
            black_box(s);
        });
    });

    let v5_val: v5::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v5/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v5_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v5/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v5::SortedValue(black_box(&v5_val))).unwrap();
            black_box(s);
        });
    });

    let v6_val: v6::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v6/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v6_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v6/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v6::SortedValue(black_box(&v6_val))).unwrap();
            black_box(s);
        });
    });

    let v7_ser_val: v7::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v7/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v7_ser_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v7/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v7::SortedValue(black_box(&v7_ser_val))).unwrap();
            black_box(s);
        });
    });

    let v8_ser_val: v8::Value = serde_json::from_str(SMALL_OBJ_JSON).unwrap();
    group.bench_function("v8/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v8_ser_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v8/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v8::SortedValue(black_box(&v8_ser_val))).unwrap();
            black_box(s);
        });
    });

    let v9_ser_arena = Bump::new();
    let v9_ser_val = v9::from_json(&v9_ser_arena, SMALL_OBJ_JSON).unwrap();
    group.bench_function("v9/small_unsorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&v9_ser_val)).unwrap();
            black_box(s);
        });
    });
    group.bench_function("v9/small_sorted", |b| {
        b.iter(|| {
            let s = serde_json::to_string(&v9::SortedValue(black_box(&v9_ser_val))).unwrap();
            black_box(s);
        });
    });

    // Realistic sizes
    for &size in &[10, 20, 32] {
        let json = flat_obj_json(size);
        let bl: regorus::Value = serde_json::from_str(&json).unwrap();
        let v1_obj: v1::Value = serde_json::from_str(&json).unwrap();

        group.bench_with_input(BenchmarkId::new("baseline/flat", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&bl)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v1_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v1/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v1::SortedValue(black_box(&v1_obj))).unwrap();
                black_box(s);
            });
        });

        let v2_obj: v2::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v2/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v2_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v2/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v2::SortedValue(black_box(&v2_obj))).unwrap();
                black_box(s);
            });
        });

        let v3_obj: v3::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v3/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v3_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v3/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v3::SortedValue(black_box(&v3_obj))).unwrap();
                black_box(s);
            });
        });

        let v4_obj: v4::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v4/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v4_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v4/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v4::SortedValue(black_box(&v4_obj))).unwrap();
                black_box(s);
            });
        });

        let v5_obj: v5::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v5/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v5_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v5/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v5::SortedValue(black_box(&v5_obj))).unwrap();
                black_box(s);
            });
        });

        let v6_obj: v6::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v6/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v6_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v6/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v6::SortedValue(black_box(&v6_obj))).unwrap();
                black_box(s);
            });
        });

        let v7_obj: v7::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v7/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v7_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v7/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v7::SortedValue(black_box(&v7_obj))).unwrap();
                black_box(s);
            });
        });

        let v8_obj: v8::Value = serde_json::from_str(&json).unwrap();
        group.bench_with_input(BenchmarkId::new("v8/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v8_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v8/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v8::SortedValue(black_box(&v8_obj))).unwrap();
                black_box(s);
            });
        });

        let v9_ser_flat_arena = Bump::new();
        let v9_obj = v9::from_json(&v9_ser_flat_arena, &json).unwrap();
        group.bench_with_input(BenchmarkId::new("v9/flat_unsorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&v9_obj)).unwrap();
                black_box(s);
            });
        });
        group.bench_with_input(BenchmarkId::new("v9/flat_sorted", size), &size, |b, _| {
            b.iter(|| {
                let s = serde_json::to_string(&v9::SortedValue(black_box(&v9_obj))).unwrap();
                black_box(s);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Set benchmarks (creation and membership testing)
// ---------------------------------------------------------------------------

/// Build a vector of v2::Value objects with `keys` string keys each,
/// where each object has unique values (so they're distinct).
fn make_v2_objects(count: usize, keys: usize) -> Vec<v2::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v2::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    std::sync::Arc::from(format!("key_{k}").as_str()),
                    v2::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v2::Value::Object(std::sync::Arc::new(obj))
        })
        .collect()
}

/// Build a vector of baseline (regorus::Value) objects.
fn make_baseline_objects(count: usize, keys: usize) -> Vec<regorus::Value> {
    (0..count)
        .map(|i| {
            let mut m = std::collections::BTreeMap::new();
            for k in 0..keys {
                m.insert(
                    regorus::Value::String(format!("key_{k}").into()),
                    regorus::Value::String(format!("val_{}_{}", i, k).into()),
                );
            }
            regorus::Value::from(m)
        })
        .collect()
}

/// Build a vector of v3::Value objects (precomputed hash).
fn make_v3_objects(count: usize, keys: usize) -> Vec<v3::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v3::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    std::sync::Arc::from(format!("key_{k}").as_str()),
                    v3::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v3::Value::Object(std::sync::Arc::new(obj))
        })
        .collect()
}

/// Build a vector of v4::Value objects (ArcStr keys, precomputed hash).
fn make_v4_objects(count: usize, keys: usize) -> Vec<v4::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v4::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    arcstr::ArcStr::from(format!("key_{k}").as_str()),
                    v4::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v4::Value::Object(std::sync::Arc::new(obj))
        })
        .collect()
}

/// Build a vector of v5::Value objects (NaN-boxed, ArcStr keys, precomputed hash).
fn make_v5_objects(count: usize, keys: usize) -> Vec<v5::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v5::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    arcstr::ArcStr::from(format!("key_{k}").as_str()),
                    v5::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v5::Value::from_object(obj)
        })
        .collect()
}

/// Build a vector of v6::Value objects (tagged pointer, ArcStr keys, precomputed hash).
fn make_v6_objects(count: usize, keys: usize) -> Vec<v6::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v6::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    arcstr::ArcStr::from(format!("key_{k}").as_str()),
                    v6::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v6::Value::from_object(obj)
        })
        .collect()
}

/// Build a vector of v7::Value objects (tagged pointer, schema-shared compact objects).
fn make_v7_objects(count: usize, keys: usize) -> Vec<v7::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v7::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    arcstr::ArcStr::from(format!("key_{k}").as_str()),
                    v7::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v7::Value::from_object(obj)
        })
        .collect()
}

/// Build a vector of v8::Value objects (enum-based, schema-shared compact objects, ArcStr).
fn make_v8_objects(count: usize, keys: usize) -> Vec<v8::Value> {
    (0..count)
        .map(|i| {
            let mut obj = v8::ObjectMap::with_capacity(keys);
            for k in 0..keys {
                obj.insert_str(
                    arcstr::ArcStr::from(format!("key_{k}").as_str()),
                    v8::Value::from(format!("val_{}_{}", i, k)),
                );
            }
            v8::Value::Object(std::sync::Arc::new(obj))
        })
        .collect()
}

/// Build a vector of v9::Value objects (arena-allocated, sorted slices).
fn make_v9_objects<'a>(arena: &'a Bump, count: usize, keys: usize) -> Vec<v9::Value<'a>> {
    (0..count)
        .map(|i| {
            let mut builder = v9::ObjectMapBuilder::with_capacity(arena, keys);
            for k in 0..keys {
                let key = arena.alloc_str(&format!("key_{k}"));
                let val = v9::Value::from_str(arena, &format!("val_{}_{}", i, k));
                builder.insert_str(key, val);
            }
            v9::Value::Arena(v9::ArenaValue::Object(builder.build()))
        })
        .collect()
}

fn bench_set_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_ops");

    // --- Set creation: insert objects into a set ---
    for &(count, keys) in &[(10, 5), (50, 5), (100, 5), (50, 10), (100, 10)] {
        let label = format!("{}obj_x_{}keys", count, keys);

        // baseline: BTreeSet
        let baseline_objs = make_baseline_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("baseline/create", &label),
            &baseline_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::BTreeSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v2: BTreeSet (same underlying structure)
        let v2_objs = make_v2_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v2/create", &label),
            &v2_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::BTreeSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v3: HashSet with precomputed hashes
        let v3_objs = make_v3_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v3/create", &label),
            &v3_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v4: HashSet with ArcStr keys + precomputed hashes
        let v4_objs = make_v4_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v4/create", &label),
            &v4_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v5: NaN-boxed HashSet with precomputed hashes
        let v5_objs = make_v5_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v5/create", &label),
            &v5_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v6: tagged pointer HashSet with precomputed hashes
        let v6_objs = make_v6_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v6/create", &label),
            &v6_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v7: tagged pointer + schema-shared HashSet with precomputed hashes
        let v7_objs = make_v7_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v7/create", &label),
            &v7_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v8: enum-based + schema-shared HashSet with precomputed hashes
        let v8_objs = make_v8_objects(count, keys);
        group.bench_with_input(
            BenchmarkId::new("v8/create", &label),
            &v8_objs,
            |b, objs| {
                b.iter(|| {
                    let mut s = std::collections::HashSet::new();
                    for o in objs {
                        s.insert(o.clone());
                    }
                    black_box(s);
                });
            },
        );

        // v9: arena-allocated ArenaSet (sorted slice)
        let v9_set_arena = Bump::new();
        let v9_objs = make_v9_objects(&v9_set_arena, count, keys);
        group.bench_with_input(
            BenchmarkId::new("v9/create", &label),
            &v9_objs,
            |b, objs| {
                b.iter(|| {
                    let iter_arena = Bump::new();
                    let s = v9::ArenaSet::from_iter_in(&iter_arena, objs.iter().copied());
                    black_box(s);
                });
            },
        );
    }

    // --- Set membership: test `contains` for an existing object ---
    for &(count, keys) in &[(10, 5), (50, 5), (100, 5), (50, 10), (100, 10)] {
        let label = format!("{}obj_x_{}keys", count, keys);

        let baseline_objs = make_baseline_objects(count, keys);
        let baseline_set: std::collections::BTreeSet<regorus::Value> =
            baseline_objs.iter().cloned().collect();
        // Probe the middle element (exists) and a non-existing one.
        let probe_hit = baseline_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("baseline/contains_hit", &label),
            &(&baseline_set, &probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v2_objs = make_v2_objects(count, keys);
        let v2_set: std::collections::BTreeSet<v2::Value> = v2_objs.iter().cloned().collect();
        let v2_probe_hit = v2_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v2/contains_hit", &label),
            &(&v2_set, &v2_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v3_objs = make_v3_objects(count, keys);
        let v3_set: std::collections::HashSet<v3::Value> = v3_objs.iter().cloned().collect();
        let v3_probe_hit = v3_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v3/contains_hit", &label),
            &(&v3_set, &v3_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v4_objs = make_v4_objects(count, keys);
        let v4_set: std::collections::HashSet<v4::Value> = v4_objs.iter().cloned().collect();
        let v4_probe_hit = v4_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v4/contains_hit", &label),
            &(&v4_set, &v4_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v5_objs = make_v5_objects(count, keys);
        let v5_set: std::collections::HashSet<v5::Value> = v5_objs.iter().cloned().collect();
        let v5_probe_hit = v5_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v5/contains_hit", &label),
            &(&v5_set, &v5_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v6_objs = make_v6_objects(count, keys);
        let v6_set: std::collections::HashSet<v6::Value> = v6_objs.iter().cloned().collect();
        let v6_probe_hit = v6_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v6/contains_hit", &label),
            &(&v6_set, &v6_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v7_objs = make_v7_objects(count, keys);
        let v7_set: std::collections::HashSet<v7::Value> = v7_objs.iter().cloned().collect();
        let v7_probe_hit = v7_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v7/contains_hit", &label),
            &(&v7_set, &v7_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v8_objs = make_v8_objects(count, keys);
        let v8_set: std::collections::HashSet<v8::Value> = v8_objs.iter().cloned().collect();
        let v8_probe_hit = v8_objs[count / 2].clone();

        group.bench_with_input(
            BenchmarkId::new("v8/contains_hit", &label),
            &(&v8_set, &v8_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );

        let v9_cont_arena = Bump::new();
        let v9_cont_objs = make_v9_objects(&v9_cont_arena, count, keys);
        let v9_set = v9::ArenaSet::from_iter_in(&v9_cont_arena, v9_cont_objs.iter().copied());
        let v9_probe_hit = v9_cont_objs[count / 2];

        group.bench_with_input(
            BenchmarkId::new("v9/contains_hit", &label),
            &(v9_set, &v9_probe_hit),
            |b, (set, probe)| {
                b.iter(|| black_box(set.contains(black_box(probe))));
            },
        );
    }

    // --- Set creation with simple values (strings + numbers) for baseline ---
    for &count in &[100, 500, 1000] {
        let label = format!("{}_strings", count);
        let baseline_strs: Vec<regorus::Value> = (0..count)
            .map(|i| regorus::Value::String(format!("str_{i}").into()))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("baseline/create_strings", &label),
            &baseline_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::BTreeSet<regorus::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v2_strs: Vec<v2::Value> = (0..count)
            .map(|i| v2::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v2/create_strings", &label),
            &v2_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::BTreeSet<v2::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v3_strs: Vec<v3::Value> = (0..count)
            .map(|i| v3::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v3/create_strings", &label),
            &v3_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v3::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v4_strs: Vec<v4::Value> = (0..count)
            .map(|i| v4::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v4/create_strings", &label),
            &v4_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v4::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v5_strs: Vec<v5::Value> = (0..count)
            .map(|i| v5::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v5/create_strings", &label),
            &v5_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v5::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v6_strs: Vec<v6::Value> = (0..count)
            .map(|i| v6::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v6/create_strings", &label),
            &v6_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v6::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v7_strs: Vec<v7::Value> = (0..count)
            .map(|i| v7::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v7/create_strings", &label),
            &v7_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v7::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v8_strs: Vec<v8::Value> = (0..count)
            .map(|i| v8::Value::from(format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v8/create_strings", &label),
            &v8_strs,
            |b, vals| {
                b.iter(|| {
                    let s: std::collections::HashSet<v8::Value> = vals.iter().cloned().collect();
                    black_box(s);
                });
            },
        );
        let v9_str_arena = Bump::new();
        let v9_strs: Vec<v9::Value> = (0..count)
            .map(|i| v9::Value::from_str(&v9_str_arena, &format!("str_{i}")))
            .collect();
        group.bench_with_input(
            BenchmarkId::new("v9/create_strings", &label),
            &v9_strs,
            |b, vals| {
                b.iter(|| {
                    let iter_arena = Bump::new();
                    let s = v9::ArenaSet::from_iter_in(&iter_arena, vals.iter().copied());
                    black_box(s);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Arithmetic benchmarks — index increment simulation
// ---------------------------------------------------------------------------

fn bench_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("arithmetic");

    // Simulate `i = i + 1` for N iterations (typical loop index update).
    for &n in &[100, 1000] {
        // baseline: regorus::Value — extract u64, add, reconstruct
        group.bench_with_input(BenchmarkId::new("baseline/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = regorus::Value::from(0u64);
                let one = regorus::Value::from(1u64);
                for _ in 0..n {
                    let i = v.as_u64().unwrap();
                    let j = one.as_u64().unwrap();
                    v = regorus::Value::from(i + j);
                }
                black_box(v);
            });
        });

        // v1: extract Number, call add, wrap back
        group.bench_with_input(BenchmarkId::new("v1/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v1::Value::from(0u64);
                let one_num = v1::Number::from(1u64);
                for _ in 0..n {
                    let num = match &v {
                        v1::Value::Number(n) => n.add(&one_num),
                        _ => unreachable!(),
                    };
                    v = v1::Value::Number(num);
                }
                black_box(v);
            });
        });

        // v2: same pattern, shared Number type
        group.bench_with_input(BenchmarkId::new("v2/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v2::Value::from(0u64);
                let one_num = v2::Number::from(1u64);
                for _ in 0..n {
                    let num = match &v {
                        v2::Value::Number(n) => n.add(&one_num),
                        _ => unreachable!(),
                    };
                    v = v2::Value::Number(num);
                }
                black_box(v);
            });
        });

        // v3: uses v2::Number
        group.bench_with_input(BenchmarkId::new("v3/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v3::Value::from(0u64);
                let one_num = v3::Number::from(1u64);
                for _ in 0..n {
                    let num = match &v {
                        v3::Value::Number(n) => n.add(&one_num),
                        _ => unreachable!(),
                    };
                    v = v3::Value::Number(num);
                }
                black_box(v);
            });
        });

        // v4: uses v2::Number
        group.bench_with_input(BenchmarkId::new("v4/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v4::Value::from(0u64);
                let one_num = v4::Number::from(1u64);
                for _ in 0..n {
                    let num = match &v {
                        v4::Value::Number(n) => n.add(&one_num),
                        _ => unreachable!(),
                    };
                    v = v4::Value::Number(num);
                }
                black_box(v);
            });
        });

        // v5: NaN-boxed — uses add_number (extract f64 → integer math → re-encode)
        group.bench_with_input(BenchmarkId::new("v5/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v5::Value::from(0u64);
                let one = v5::Value::from(1u64);
                for _ in 0..n {
                    v = v.add_number(&one);
                }
                black_box(v);
            });
        });

        // v6: tagged pointer — inline uint fast path
        group.bench_with_input(BenchmarkId::new("v6/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v6::Value::from(0u64);
                let one = v6::Value::from(1u64);
                for _ in 0..n {
                    v = v.add_number(&one);
                }
                black_box(v);
            });
        });

        // v7: same encoding as v6
        group.bench_with_input(BenchmarkId::new("v7/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v7::Value::from(0u64);
                let one = v7::Value::from(1u64);
                for _ in 0..n {
                    v = v.add_number(&one);
                }
                black_box(v);
            });
        });

        // v8: enum-based, flattened numbers
        group.bench_with_input(BenchmarkId::new("v8/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let mut v = v8::Value::from(0u64);
                let one = v8::Value::from(1u64);
                for _ in 0..n {
                    let num = match (v.as_number(), one.as_number()) {
                        (Some(a), Some(b)) => a.add(&b),
                        _ => unreachable!(),
                    };
                    v = v8::Value::from_number(num);
                }
                black_box(v);
            });
        });

        // v9: arena-allocated numbers
        group.bench_with_input(BenchmarkId::new("v9/index_inc", n), &n, |b, &n| {
            b.iter(|| {
                let arena = Bump::new();
                let mut v = v9::Value::from(0u64);
                let one = v9::Value::from(1u64);
                for _ in 0..n {
                    v = v.add_number(&one, &arena);
                }
                black_box(v);
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
//  Group + main
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(30)
        .without_plots();
    targets = bench_deserialize,
        bench_key_lookup,
        bench_comparison,
        bench_serialize,
        bench_set_operations,
        bench_arithmetic
}
criterion_main!(benches);
