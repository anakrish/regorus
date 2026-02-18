# Z3 Symbolic Analysis for Rego

Regorus includes an **experimental** Z3-backed symbolic analysis engine that
can automatically answer questions about Rego policies:

* *"What input would cause this policy to deny?"*
* *"Is there any input that passes compliance?"*
* *"Can the DMZ rule fire without the PII rule also firing?"*

Instead of executing the policy on test inputs, the analyzer **translates the
compiled RVM bytecode into SMT constraints** and hands them to the
[Z3 theorem prover](https://github.com/Z3Prover/z3).  Z3 either produces a
concrete satisfying input or proves that none exists.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building](#building)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [JSON Schema Support](#json-schema-support)
- [Example Walkthroughs](#example-walkthroughs)
  - [Server Infrastructure](#example-1--server-infrastructure)
  - [Container Admission](#example-2--container-admission-controller)
  - [Network Segmentation](#example-3--network-segmentation-compliance)
- [Running the Demo Suite](#running-the-demo-suite)
- [Inspecting Z3 Internals](#inspecting-z3-internals)
- [Limitations](#limitations)

---

## Prerequisites

| Dependency | Version | Install |
|---|---|---|
| **Rust** | stable (1.70+) | [rustup.rs](https://rustup.rs) |
| **Z3** | 4.12+ | See below |
| **libclang** | (for bindgen) | Bundled with Xcode / LLVM |

### Installing Z3

**macOS (Homebrew):**

```bash
brew install z3
```

**Ubuntu / Debian:**

```bash
sudo apt-get install libz3-dev
```

**Windows (vcpkg):**

```bash
vcpkg install z3:x64-windows
```

**From source:**

```bash
git clone https://github.com/Z3Prover/z3.git
cd z3 && mkdir build && cd build
cmake -G Ninja .. -DCMAKE_INSTALL_PREFIX=/usr/local
ninja && sudo ninja install
```

---

## Building & Installing

The Z3 integration is behind the `z3-analysis` Cargo feature and is **not
included in default builds**.

The examples below use a bare `regorus` command.  To make that available,
**install** the example binary:

### macOS (Homebrew Z3)

```bash
BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
LIBRARY_PATH="/opt/homebrew/lib" \
cargo install --example regorus --features z3-analysis --path .
```

### Linux (system Z3)

```bash
cargo install --example regorus --features z3-analysis --path .
```

If Z3 is installed in a non-standard location, set:

```bash
BINDGEN_EXTRA_CLANG_ARGS="-I/path/to/z3/include" \
LIBRARY_PATH="/path/to/z3/lib" \
cargo install --example regorus --features z3-analysis --path .
```

> **Tip:** If you prefer not to install, you can substitute `regorus` with
> `cargo run --example regorus --features z3-analysis --` in any command below.

### Running tests

```bash
# macOS
BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
LIBRARY_PATH="/opt/homebrew/lib" \
cargo test --features z3-analysis

# Linux
cargo test --features z3-analysis
```

---

## Quick Start

Given a Rego policy, ask Z3 to find an input that causes a specific output:

```bash
# "What input makes allow = false?"
regorus analyze \
  -d policy.rego \
  -e data.example.allow \
  -o false

# "What input makes allow = true?"
regorus analyze \
  -d policy.rego \
  -e data.example.allow \
  -o true
```

Add a JSON Schema for better results:

```bash
regorus analyze \
  -d policy.rego \
  -e data.example.allow \
  -o false \
  -s input_schema.json
```

The output is JSON:

```json
{
  "satisfiable": true,
  "input": { ... },
  "warnings": [ ... ]
}
```

If `satisfiable` is `true`, the `input` field contains a concrete JSON object
that produces the requested output when evaluated by the policy.  If `false`,
no such input exists within the constraints.

---

## CLI Reference

```
regorus analyze [OPTIONS] --entrypoint <RULE>
```

### Required

| Flag | Description |
|---|---|
| `-e, --entrypoint <RULE>` | Entry point to analyze (e.g. `data.example.allow`) |

### Policy & Data

| Flag | Description |
|---|---|
| `-d, --data <FILE>` | Policy (`.rego`) or data (`.json` / `.yaml`) files. Repeatable. |
| `-b, --bundles <DIR>` | Directories containing `.rego` files. Repeatable. |

### Analysis Goal

| Flag | Description |
|---|---|
| `-o, --output <JSON>` | Expected output value as a JSON literal (e.g. `true`, `false`, `42`, `"admin"`). When omitted, the solver only requires the result to be defined. |
| `-l, --cover-line <FILE:LINE>` | Source lines to **cover** — the generated input must execute these lines. Repeatable. |
| `--avoid-line <FILE:LINE>` | Source lines to **avoid** — the generated input must NOT execute these lines. Repeatable. |

### Type Hints & Constraints

| Flag | Description |
|---|---|
| `-i, --input <FILE>` | Example input (JSON). Used to infer Z3 sorts (Bool / Int / String) for symbolic fields. |
| `-s, --schema <FILE>` | JSON Schema for the input. Generates Z3 constraints for types, required fields, array bounds, string lengths, enums, and uniqueness. |

### Solver Tuning

| Flag | Default | Description |
|---|---|---|
| `--timeout <MS>` | 30000 | Z3 solver timeout in milliseconds. |
| `--max-loops <N>` | 5 | Maximum loop unrolling depth. Lower values produce cleaner output; higher values explore more iterations. |

### Debugging

| Flag | Description |
|---|---|
| `--dump-smt <FILE>` | Write the full SMT-LIB2 encoding to a file. |
| `--dump-model <FILE>` | Write Z3's variable assignments (the model) to a file when SAT. |

---

## JSON Schema Support

When a JSON Schema is provided via `-s`, the analyzer generates additional Z3
constraints that restrict the symbolic input space.  Supported schema keywords:

| Keyword | Effect |
|---|---|
| `type` | Sets Z3 sort: `"boolean"` → Bool, `"integer"` → Int, `"string"` → String |
| `required` | Ensures the field's definedness variable is `true` |
| `properties` | Recurses into sub-schemas |
| `items` | Applies constraints to each array element |
| `minItems` / `maxItems` | Controls how many array elements are defined |
| `minLength` | Asserts `str_length(field) >= N` |
| `enum` | Asserts field equals one of the listed values |
| `x-unique` | Asserts pairwise distinctness for the named sub-fields across array elements |
| `uniqueItems` | Asserts pairwise distinctness across all elements of a plain-value array |

### Example schema

```json
{
  "type": "object",
  "required": ["servers"],
  "properties": {
    "servers": {
      "type": "array",
      "minItems": 1,
      "maxItems": 3,
      "x-unique": ["id"],
      "items": {
        "type": "object",
        "required": ["id", "protocols"],
        "properties": {
          "id": { "type": "string", "minLength": 1 },
          "protocols": {
            "type": "array",
            "minItems": 1,
            "maxItems": 3,
            "items": { "type": "string", "minLength": 1 }
          }
        }
      }
    }
  }
}
```

---

## Example Walkthroughs

### Example 1 — Server Infrastructure

**Policy:** [`examples/server/allowed_server.rego`](examples/server/allowed_server.rego)
**Schema:** [`examples/server/input_schema.json`](examples/server/input_schema.json)

This is the classic OPA example.  The policy denies servers that use `"http"`
on a public network or `"telnet"` anywhere.  It uses the Rego `in` operator
for protocol membership checks.

#### Find a violation (`allow = false`)

```bash
regorus analyze \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o false \
  -s examples/server/input_schema.json \
  --max-loops 3
```

The policy has two denial rules: (1) a server using `"http"` that is reachable
on a public network (a multi-way join across servers → ports → networks), and
(2) any server using `"telnet"` regardless of network.  Z3 finds the easiest
path — in this case, the `"telnet"` rule:

```json
{
  "input": {
    "networks": [
      { "id": "net3", "public": false },
      { "id": "net2", "public": false },
      { "id": "net1", "public": true }
    ],
    "ports": [
      { "id": "p3", "network": "net1" },
      { "id": "p2", "network": "net1" },
      { "id": "p1", "network": "net1" }
    ],
    "servers": [
      { "id": "cache", "ports": ["p3"], "protocols": ["memcache"] },
      { "id": "db",    "ports": ["p3"], "protocols": ["telnet"] },
      { "id": "web",   "ports": ["p3"], "protocols": ["memcache"] }
    ]
  },
  "satisfiable": true
}
```

Z3 assigned `"telnet"` to the `db` server, which triggers the second denial
rule (telnet is banned everywhere) and makes `allow = false`.

#### Find a compliant configuration (`allow = true`)

```bash
regorus analyze \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o true \
  -s examples/server/input_schema.json \
  --max-loops 3
```

```json
{
  "input": {
    "networks": [
      { "id": "net3", "public": false },
      { "id": "net1", "public": false },
      { "id": "net4", "public": false }
    ],
    "ports": [
      { "id": "p3", "network": "net1" },
      { "id": "p1", "network": "net2" },
      { "id": "p2", "network": "net2" }
    ],
    "servers": [
      { "id": "cache", "ports": ["p3"], "protocols": ["https"] },
      { "id": "db",    "ports": ["p2"], "protocols": ["https"] },
      { "id": "web",   "ports": ["p1"], "protocols": ["https"] }
    ]
  },
  "satisfiable": true
}
```

All servers use only `"https"` and no network is public — every denial path
is blocked.

### Example 2 — Container Admission Controller

**Policy:** [`examples/demos/container_admission.rego`](examples/demos/container_admission.rego)
**Schema:** [`examples/demos/container_admission_schema.json`](examples/demos/container_admission_schema.json)

Denies privileged containers, and containers that mount unencrypted volumes on
public hosts (a 3-way cross-collection join).

#### Find a violation (`allow = false`)

```bash
regorus analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3
```

```json
{
  "input": {
    "containers": [
      { "host_id": "host1", "name": "worker", "privileged": false, "volume_ids": ["vol3", "vol1"] },
      { "host_id": "host1", "name": "api",    "privileged": false, "volume_ids": ["vol2"] },
      { "host_id": "host1", "name": "web",    "privileged": false, "volume_ids": ["vol2"] }
    ],
    "hosts": [
      { "id": "host3", "public": false },
      { "id": "host2", "public": false },
      { "id": "host1", "public": true }
    ],
    "volumes": [
      { "encrypted": true,  "id": "vol2" },
      { "encrypted": true,  "id": "vol3" },
      { "encrypted": false, "id": "vol1" }
    ]
  },
  "satisfiable": true
}
```

Z3 placed all three containers on `host1` (public), gave `vol1` `encrypted: false`,
and put `vol1` in `worker`'s `volume_ids` — a 3-way join across containers, hosts,
and volumes that triggers the "sensitive container on public host" rule.

#### Targeted path exploration

Find a violation that triggers *only* the complex path (sensitive container on
public host, line 97) and *not* the simple privileged check (line 73):

```bash
regorus analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -l container_admission.rego:97 \
  --avoid-line container_admission.rego:73 \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3
```

```json
{
  "input": {
    "containers": [
      { "host_id": "host1", "name": "worker", "privileged": false, "volume_ids": ["vol2"] },
      { "host_id": "host1", "name": "api",    "privileged": false, "volume_ids": ["vol2"] },
      { "host_id": "host3", "name": "web",    "privileged": false, "volume_ids": ["vol2", "vol1"] }
    ],
    "hosts": [
      { "id": "host2", "public": false },
      { "id": "host1", "public": false },
      { "id": "host3", "public": true }
    ],
    "volumes": [
      { "encrypted": true,  "id": "vol3" },
      { "encrypted": true,  "id": "vol2" },
      { "encrypted": false, "id": "vol1" }
    ]
  },
  "satisfiable": true
}
```

All `privileged` fields are `false` (the privileged rule is avoided), yet Z3
still found a violation: `web` is on `host3` (public) and mounts `vol1`
(unencrypted) — precisely the 3-way join path.

### Example 3 — Network Segmentation Compliance

**Policy:** [`examples/demos/network_segmentation.rego`](examples/demos/network_segmentation.rego)
**Schema:** [`examples/demos/network_segmentation_schema.json`](examples/demos/network_segmentation_schema.json)

Enforces that DMZ services never connect to internal databases, and that
PII-handling services only use encrypted connections.

#### Find a non-compliant topology (`compliant = false`)

```bash
regorus analyze \
  -d examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -o false \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3
```

```json
{
  "input": {
    "connections": [
      { "encrypted": true,  "source": "frontend", "target": "frontend" },
      { "encrypted": true,  "source": "frontend", "target": "userdb" },
      { "encrypted": false, "source": "frontend", "target": "frontend" }
    ],
    "databases": [
      { "internal": false, "name": "orderdb" },
      { "internal": false, "name": "userdb" }
    ],
    "services": [
      { "handles_pii": false, "name": "inventory", "zone_id": "dmz" },
      { "handles_pii": false, "name": "payment",   "zone_id": "dmz" },
      { "handles_pii": true,  "name": "frontend",  "zone_id": "internal" }
    ],
    "zones": [
      { "dmz": false, "id": "restricted" },
      { "dmz": false, "id": "dmz" },
      { "dmz": false, "id": "internal" }
    ]
  },
  "satisfiable": true
}
```

Z3 found a PII violation: `frontend` handles PII and has an unencrypted
connection (`encrypted: false`).

#### Targeted: isolate the DMZ rule (line 93) without the PII rule (line 121)

```bash
regorus analyze \
  -d examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -o false \
  -l network_segmentation.rego:93 \
  --avoid-line network_segmentation.rego:121 \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3
```

```json
{
  "input": {
    "connections": [
      { "encrypted": true, "source": "frontend", "target": "frontend" },
      { "encrypted": true, "source": "frontend", "target": "frontend" },
      { "encrypted": true, "source": "inventory", "target": "frontend" }
    ],
    "databases": [
      { "internal": false, "name": "orderdb" },
      { "internal": false, "name": "userdb" },
      { "internal": true,  "name": "frontend" }
    ],
    "services": [
      { "handles_pii": false, "name": "payment",   "zone_id": "dmz" },
      { "handles_pii": false, "name": "frontend",  "zone_id": "dmz" },
      { "handles_pii": false, "name": "inventory", "zone_id": "restricted" }
    ],
    "zones": [
      { "dmz": false, "id": "internal" },
      { "dmz": false, "id": "dmz" },
      { "dmz": true,  "id": "restricted" }
    ]
  },
  "satisfiable": true
}
```

Z3 built a **4-way ID chain**: `inventory` is in zone `restricted` (which is
DMZ), has a connection targeting `frontend`, and `frontend` is an internal
database.  All connections are encrypted and no service handles PII, so the
PII rule (line 121) is never triggered.

---

## Running the Demo Suite

A script that runs all examples end-to-end is provided:

```bash
./examples/demos/run_demos.sh
```

This exercises violation finding, compliance synthesis, targeted path
exploration, and SMT/model file dumps across all three policies.

---

## Inspecting Z3 Internals

### Dumping the SMT encoding

```bash
regorus analyze \
  -d examples/demos/container_admission.rego \
  -e data.container_admission.allow \
  -o false \
  -s examples/demos/container_admission_schema.json \
  --max-loops 3 \
  --dump-smt constraints.smt2 \
  --dump-model model.txt
```

The SMT file (`constraints.smt2`) contains the full SMT-LIB2 encoding — every
`declare-fun` for symbolic input fields and every `assert` for policy logic and
schema constraints.  You can feed it directly to a standalone Z3 binary:

```bash
z3 constraints.smt2
```

The model file (`model.txt`) shows every variable assignment Z3 chose when the
result is SAT:

```
input.containers[0].host_id -> "host2"
defined_input.hosts[2] -> true
input.volumes[2].encrypted -> false
defined_input.volumes[2] -> true
input.containers[0].volume_ids[1] -> "vol2"
input.containers[1].host_id -> "host1"
input.containers[0].volume_ids[0] -> "vol3"
input.containers[1].name -> "api"
input.hosts[0].id -> "host3"
defined_input.containers[2] -> true
input.volumes[2].id -> "vol2"
input.containers[0].name -> "worker"
...
```

---

## Limitations

The symbolic engine is under active development.  Current limitations include:

| Area | Status |
|---|---|
| **Comprehensions** | Set/array/object comprehensions are symbolically unrolled; results support `in` and `count` |
| **String builtins** | `startswith`, `endswith`, `regex.match`, etc. are modeled as unconstrained Bools |
| **Numeric builtins** | `sum`, `max`, `min`, etc. are modeled as unconstrained Ints |
| **Aggregations** | `count` on symbolic collections uses cardinality tracking; other aggregations are approximate |
| **Recursion** | Bounded by `--max-rule-depth` (default 3) |
| **Loop depth** | Bounded by `--max-loops` (default 5); iterations beyond the bound are not explored |
| **Negation** | `not` in rule bodies is supported for concrete and simple symbolic expressions |
| **`with` keyword** | Not yet supported |
| **Functions** | User-defined functions are inlined up to the rule depth limit |

Despite these limitations, the engine handles the core Rego patterns — nested
loops, multi-way joins, set membership (`in`), partial rules, `count`, and
Boolean/string/numeric comparisons — which cover a large class of real-world
admission control and compliance policies.
