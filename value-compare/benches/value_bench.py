#!/usr/bin/env python3
"""
Equivalent benchmarks for Python dict/json, mirroring the Rust value_bench.rs.

Measures:
  - JSON deserialization (json.loads)
  - Key lookup by string key
  - Equality comparison
  - JSON serialization (json.dumps / sorted)

Usage:
    python3 value_bench.py
"""

import json
import timeit
import sys

# ---------------------------------------------------------------------------
#  Test data (mirrors Rust benchmarks)
# ---------------------------------------------------------------------------

SMALL_OBJ_JSON = r"""{
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
}"""


def flat_obj_json(n: int) -> str:
    entries = [f'"key_{i}": "value_{i}"' for i in range(n)]
    return "{" + ", ".join(entries) + "}"


def array_of_objects_json(count: int, keys: int) -> str:
    obj = flat_obj_json(keys)
    return "[" + ",".join([obj] * count) + "]"


def realistic_obj_json(n: int) -> str:
    entries = []
    for i in range(n):
        entries.append(
            f'"rule_{i}": {{"action": "allow", "resource": "/api/v1/item/{i}", "priority": {i}, "enabled": true}}'
        )
    return "{" + ", ".join(entries) + "}"


# ---------------------------------------------------------------------------
#  Benchmark harness
# ---------------------------------------------------------------------------

def bench(name: str, stmt, number: int = 0, min_time: float = 0.05):
    """Run a benchmark, auto-calibrating iterations if number=0."""
    if number == 0:
        # Calibrate: find number such that total time >= min_time
        number = 10
        while True:
            t = timeit.timeit(stmt, number=number)
            if t >= min_time:
                break
            number = max(number + 1, int(number * min_time / t) + 1)
            if number > 5_000_000:
                break

    # Run 3 iterations and take the median
    times = []
    for _ in range(3):
        t = timeit.timeit(stmt, number=number)
        times.append(t / number)
    times.sort()
    median = times[1]  # median of 3

    if median < 1e-6:
        unit, scale = "ns", 1e9
    elif median < 1e-3:
        unit, scale = "µs", 1e6
    else:
        unit, scale = "ms", 1e3

    print(f"  {name:45s} {median * scale:10.3f} {unit}  ({number} iters)")
    return median


# ---------------------------------------------------------------------------
#  Deserialization benchmarks
# ---------------------------------------------------------------------------

def bench_deserialize():
    print("\n=== Deserialization (json.loads) ===")

    # Small object
    bench("small", lambda: json.loads(SMALL_OBJ_JSON))

    # Flat objects
    for size in [10, 15, 20, 32]:
        j = flat_obj_json(size)
        bench(f"flat/{size}", lambda j=j: json.loads(j))

    # Realistic (nested) objects
    for size in [10, 20, 32]:
        j = realistic_obj_json(size)
        bench(f"realistic/{size}", lambda j=j: json.loads(j))

    # Array of objects
    for count, keys in [(10, 10), (100, 10), (100, 32)]:
        j = array_of_objects_json(count, keys)
        bench(f"array/{count}x{keys}", lambda j=j: json.loads(j))


# ---------------------------------------------------------------------------
#  Key lookup benchmarks
# ---------------------------------------------------------------------------

def bench_key_lookup():
    print("\n=== Key Lookup (dict[key]) ===")

    # Small object
    obj = json.loads(SMALL_OBJ_JSON)
    key = "metadata"
    bench("small", lambda: obj[key])

    # Flat objects — lookup middle key
    for size in [10, 20, 32]:
        j = flat_obj_json(size)
        obj = json.loads(j)
        mid = size // 2
        key = f"key_{mid}"
        bench(f"flat/{size}", lambda obj=obj, key=key: obj[key])


# ---------------------------------------------------------------------------
#  Equality benchmarks
# ---------------------------------------------------------------------------

def bench_equality():
    print("\n=== Equality (==) ===")

    # Small object
    a = json.loads(SMALL_OBJ_JSON)
    b = json.loads(SMALL_OBJ_JSON)
    bench("eq_small", lambda: a == b)

    # Flat objects
    for size in [10, 20, 32]:
        j = flat_obj_json(size)
        a = json.loads(j)
        b = json.loads(j)
        bench(f"eq_flat/{size}", lambda a=a, b=b: a == b)

    # Number comparison (100 pairs)
    nums = list(range(100))
    bench("number_eq_100", lambda: all(nums[i] == nums[99 - i] for i in range(100)))


# ---------------------------------------------------------------------------
#  Serialization benchmarks
# ---------------------------------------------------------------------------

def bench_serialize():
    print("\n=== Serialization (json.dumps) ===")

    obj = json.loads(SMALL_OBJ_JSON)
    bench("small_unsorted", lambda: json.dumps(obj))
    bench("small_sorted", lambda: json.dumps(obj, sort_keys=True))

    for size in [10, 20, 32]:
        j = flat_obj_json(size)
        obj = json.loads(j)
        bench(f"flat/{size}_unsorted", lambda obj=obj: json.dumps(obj))
        bench(f"flat/{size}_sorted", lambda obj=obj: json.dumps(obj, sort_keys=True))


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"Python {sys.version}")
    print(f"Benchmarking with timeit (median of 5 runs, auto-calibrated)\n")

    bench_deserialize()
    bench_key_lookup()
    bench_equality()
    bench_serialize()

    print("\nDone.")
