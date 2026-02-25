# Z3 Symbolic Analysis for Rego and Cedar

Regorus includes an **experimental** Z3-backed symbolic analysis engine that
can automatically answer questions about Rego and Cedar policies:

* *"What input would cause this policy to deny?"*
* *"Is there any input that passes compliance?"*
* *"Can the DMZ rule fire without the PII rule also firing?"*
* *"What Cedar request gets permitted despite the forbid rule?"*

Instead of executing the policy on test inputs, the analyzer **translates the
compiled RVM bytecode into SMT constraints** and hands them to the
[Z3 theorem prover](https://github.com/Z3Prover/z3).  Z3 either produces a
concrete satisfying input or proves that none exists.

For Cedar policies, the analyzer synthesises a complete **authorization
request** — principal, action, resource, and context fields — that satisfies
(or violates) the policy given a concrete entity graph.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building](#building)
- [Python Z3 Analyzer](#python-z3-analyzer)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Policy Diff](#policy-diff)
- [Policy Subsumption](#policy-subsumption)
- [Test Suite Generation](#test-suite-generation)
  - [Condition Coverage](#condition-coverage)
  - [Annotated Output](#annotated-output)
- [JSON Schema Support](#json-schema-support)
- [Example Walkthroughs](#example-walkthroughs)
  - [Server Infrastructure](#example-1--server-infrastructure)
  - [Container Admission](#example-2--container-admission-controller)
  - [Network Segmentation](#example-3--network-segmentation-compliance)
- [Cedar Policy Analysis](#cedar-policy-analysis)
  - [Cedar Quick Start](#cedar-quick-start)
  - [IAM Zero Trust](#cedar-example-1--iam-zero-trust)
  - [Healthcare (HIPAA-inspired)](#cedar-example-2--healthcare-hipaa-inspired)
  - [Financial Trading](#cedar-example-3--financial-trading-platform)
  - [Kubernetes RBAC](#cedar-example-4--kubernetes-rbac)
- [Running the Demo Suite](#running-the-demo-suite)
- [Inspecting Z3 Internals](#inspecting-z3-internals)
- [Pre-generated SMT2 Files](#pre-generated-smt2-files)
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
included in default builds**.  Cedar support additionally requires the `cedar`
feature.

The examples below use a bare `regorus` command.  To make that available,
**install** the example binary:

### macOS (Homebrew Z3)

```bash
BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
LIBRARY_PATH="/opt/homebrew/lib" \
cargo install --example regorus --features z3-analysis,cedar --path .
```

### Linux (system Z3)

```bash
cargo install --example regorus --features z3-analysis,cedar --path .
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
cargo test --features z3-analysis,cedar

# Linux
cargo test --features z3-analysis,cedar
```

---

## Python Z3 Analyzer

A **pure-Python** reimplementation of the Z3 symbolic analyzer is available
under [`tools/z3analyze/`](tools/z3analyze/).  It operates on the same RVM
bytecode as the Rust version but has no Rust/C build dependency — only Python 3
and the `z3-solver` pip package.

### Why two implementations?

| | Rust (`regorus analyze`) | Python (`tools/z3analyze`) |
|---|---|---|
| **Build** | Requires Z3 C library + bindgen | `pip install z3-solver` |
| **Workflow** | Single command | Two steps: compile → analyze |
| **Cedar** | ✅ | ✅ |
| **SMT dump** | `--dump-smt FILE` | `--dump-smt` (stdout) |

Use the Rust version for the tightest integration (single command).
Use the Python version for quick experimentation without a C toolchain.

### Prerequisites

```bash
pip install z3-solver   # or: pip3 install z3-solver
```

### Workflow

Pre-compiled RVM bytecode JSON files are checked in alongside the demo
policies (e.g. `container_admission_program.json`).  You can run the Python
analyzer directly on these files:

```bash
python3 -m tools.z3analyze examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --example-input examples/demos/container_admission_input.json \
  --schema examples/demos/container_admission_schema.json
```

To compile your own policy, use the two-step workflow:

```bash
# Step 1 — Compile the Rego policy to RVM bytecode JSON
regorus compile \
  -d policy.rego \
  -e data.example.allow \
  -o program.json

# Step 2 — Run the Python analyzer
python3 -m tools.z3analyze program.json \
  -e data.example.allow \
  -o false \
  --example-input input.json \
  --schema input_schema.json
```

#### Cedar policies

Cedar policies use a separate compile command and require the entity graph
to be passed as a concrete input:

```bash
# Step 1 — Compile the Cedar policy to RVM bytecode JSON
regorus cedar compile \
  -p policy.cedar \
  -o program.json

# Step 2 — Run the Python analyzer with concrete entities
python3 -m tools.z3analyze program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities entities.json
```

Cedar output uses `1` for permit and `0` for deny.

> **Note:** the `regorus compile` / `regorus cedar compile` commands do **not**
> need the `z3-analysis` feature.  A plain
> `cargo build --example regorus --features cedar` is sufficient for the
> compile step.

### Python CLI Reference

```
python3 -m tools.z3analyze <program.json> [OPTIONS]
```

| Flag | Description |
|---|---|
| `program` | Path to JSON bytecode from `regorus compile -o` |
| `-e, --entrypoint` | Entry point name (e.g. `data.policy.allow`) |
| `-o, --output` | Desired output value as JSON (default: `true`) |
| `-d, --data` | Path to data JSON file |
| `--example-input` | Example input JSON — seeds Z3 sort info |
| `--schema` | JSON Schema for input — generates Z3 constraints |
| `--concrete-input KEY FILE` | Inject a concrete input key (repeatable) |
| `--cover-line FILE LINE` | Force coverage of a source line (repeatable) |
| `--avoid-line FILE LINE` | Avoid a source line (repeatable) |
| `--max-loop-depth N` | Max loop unrolling (default: 5) |
| `--max-rule-depth N` | Max rule recursion (default: 3) |
| `--timeout MS` | Z3 timeout in ms (default: 30000) |
| `--dump-smt` | Print SMT-LIB2 assertions to stdout |
| `--dump-model` | Print Z3 model when SAT |
| `--sat-check` | Just check satisfiability (no target output) |

### Python Quick-Start Examples

```bash
# Find a violation (using checked-in bytecode)
python3 -m tools.z3analyze \
  examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --example-input examples/demos/container_admission_input.json \
  --schema examples/demos/container_admission_schema.json \
  --max-loop-depth 3

# Targeted: cover line 101 (sensitive-on-public-host), avoid line 75 (privileged)
python3 -m tools.z3analyze \
  examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --cover-line container_admission.rego 101 \
  --avoid-line container_admission.rego 75 \
  --example-input examples/demos/container_admission_input.json \
  --schema examples/demos/container_admission_schema.json \
  --max-loop-depth 3

# Cedar: find a PERMITTED request (IAM zero trust)
python3 -m tools.z3analyze \
  examples/demos/iam_zero_trust_program.json \
  -e cedar.authorize -o 1 \
  --concrete-input entities \
  examples/cedar/examples/iam_zero_trust/entities.json

# Cedar: find a DENIED request
python3 -m tools.z3analyze \
  examples/demos/iam_zero_trust_program.json \
  -e cedar.authorize -o 0 \
  --concrete-input entities \
  examples/cedar/examples/iam_zero_trust/entities.json
```

### Pre-compiled Bytecode Files

The following bytecode JSON files are checked in under `examples/demos/`:

| Bytecode file | Source policy | Entry point |
|---|---|---|
| `container_admission_program.json` | `container_admission.rego` | `data.container_admission.allow` |
| `network_segmentation_program.json` | `network_segmentation.rego` | `data.network_segmentation.compliant` |
| `allowed_server_program.json` | `allowed_server.rego` | `data.example.allow` |
| `iam_zero_trust_program.json` | `iam_zero_trust/policy.cedar` | `cedar.authorize` |
| `hipaa_healthcare_program.json` | `hipaa_healthcare/policy.cedar` | `cedar.authorize` |
| `financial_trading_program.json` | `financial_trading/policy.cedar` | `cedar.authorize` |
| `k8s_rbac_program.json` | `k8s_rbac/policy.cedar` | `cedar.authorize` |

To regenerate Rego: `regorus compile -d <policy.rego> -e <entrypoint> -o <output.json>`
To regenerate Cedar: `regorus cedar compile -p <policy.cedar> -o <output.json>`

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

## Policy Diff

Find inputs where two policy versions disagree:

```bash
regorus diff \
  --policy1 policy_v1.rego \
  --policy2 policy_v2.rego \
  -e data.example.allow \
  -s input_schema.json \
  -i input.json
```

The analyzer translates **both** policies into SMT constraints over the
**same** symbolic input space and asks Z3 for an input where
`policy1(input) XOR policy2(input)`.  If SAT, the model is a concrete
**distinguishing input**.  If UNSAT, the two policies are **equivalent**
for all inputs (within the analysis scope).

### Diff CLI Reference

```
regorus diff [OPTIONS] --policy1 <FILE> --policy2 <FILE> --entrypoint <RULE>
```

| Flag | Description |
|---|---|
| `--policy1 <FILE>` | Policy or data files for version 1. Repeatable. |
| `--policy2 <FILE>` | Policy or data files for version 2. Repeatable. |
| `-e, --entrypoint <RULE>` | Entry point to compare. |
| `-o, --output <JSON>` | Desired output value to compare against (default: `true`). |
| `-i, --input <FILE>` | Example input JSON for type inference. |
| `-s, --schema <FILE>` | JSON Schema for input constraints. |
| `--timeout <MS>` | Z3 timeout (default: 30000). |
| `--max-loops <N>` | Loop unrolling depth (default: 5). |
| `--dump-smt <FILE>` | Write SMT-LIB2 assertions. |
| `--dump-model <FILE>` | Write Z3 model. |

### Diff Output

```json
{
  "equivalent": false,
  "distinguishing_input": { "servers": [ ... ] },
  "policy1_output": "false",
  "policy2_output": "true",
  "warnings": []
}
```

When `equivalent` is `true`, no `distinguishing_input` is produced.

### Diff Example 1 — Server Infrastructure

Compare the original server policy (which bans telnet) with a v2 that
removes the telnet rule **and** completely restructures the HTTP-on-public
check:

| Aspect | v1 | v2 |
|---|---|---|
| Decision | `count(violation) == 0` | `not http_on_public_network` |
| HTTP check | `"http" in server.protocols` | `speaks_http()` function, `proto == "http"` |
| Public server | `public_server` partial-set + inline join | `public_port_ids` comprehension + `is_public_network()` function |
| Join style | `port.id in server.ports` | `server_is_public()` function, port-set membership |
| Telnet rule | Present | Removed |

```bash
regorus diff \
  --policy1 examples/server/allowed_server.rego \
  --policy2 examples/server/allowed_server_v2.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3
```

Z3 finds a server using `"telnet"` — policy 1 denies it, policy 2 allows it.
The completely different HTTP-on-public logic is proved equivalent; only the
removed telnet rule creates a behavioural difference.

### Diff Example 2 — Network Segmentation

Compare the network segmentation v1 (partial-set violations + `dmz_service`
helper) with a v2 that uses object-comprehension lookup maps, function rules,
and `every` — plus drops the PII rule:

| Aspect | v1 | v2 |
|---|---|---|
| Decision | `count(violation) == 0` | `every conn ... { not dmz_to_internal(conn) }` |
| DMZ detection | `dmz_service` partial-set (linear scan) | `zone_of[]` / `zone_is_dmz[]` comprehension maps + `in_dmz()` |
| DB check | Inline in 4-way join | `db_is_internal[]` map + `targets_internal_db()` function |
| Iteration | Service-centric | Connection-centric |
| PII rule | Present | Removed |

```bash
regorus diff \
  --policy1 examples/demos/network_segmentation.rego \
  --policy2 examples/demos/network_segmentation_v2.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3
```

Z3 finds a PII-related distinguishing input — a service handling PII with
an unencrypted connection.  v1 flags it as non-compliant; v2 allows it
because v2 dropped the PII rule.

---

## Policy Subsumption

Prove whether one policy is at least as permissive as another:

```bash
regorus subsumes \
  --old policy_old.rego \
  --new policy_new.rego \
  -e data.example.allow \
  -s input_schema.json
```

The analyzer checks: **∀ input: old(input) = desired → new(input) = desired**.
It negates this to ∃ input: old(input) = desired ∧ new(input) ≠ desired.
If SAT, the model is a **counterexample** where old permits but new does not.
If UNSAT, new **subsumes** old.

### Subsumption CLI Reference

```
regorus subsumes [OPTIONS] --old <FILE> --new <FILE> --entrypoint <RULE>
```

| Flag | Description |
|---|---|
| `--old <FILE>` | Policy files for the old (reference) policy. Repeatable. |
| `--new <FILE>` | Policy files for the new policy. Repeatable. |
| `-e, --entrypoint <RULE>` | Entry point to check. |
| `-o, --output <JSON>` | Desired output value (default: `true`). |
| `-i, --input <FILE>` | Example input JSON for type inference. |
| `-s, --schema <FILE>` | JSON Schema for input constraints. |
| `--timeout <MS>` | Z3 timeout (default: 30000). |
| `--max-loops <N>` | Loop unrolling depth (default: 5). |
| `--dump-smt <FILE>` | Write SMT-LIB2 assertions. |
| `--dump-model <FILE>` | Write Z3 model. |

### Subsumption Output

```json
{
  "subsumes": true,
  "counterexample": null,
  "warnings": []
}
```

When `subsumes` is `false`, `counterexample` contains a concrete input where
old permits but new does not.

### Subsumption Example 1 — Server Infrastructure

Check whether v2 (telnet rule removed, HTTP logic restructured) subsumes v1:

```bash
# Does v2 subsume v1? (Yes — v2 is more permissive)
regorus subsumes \
  --old examples/server/allowed_server.rego \
  --new examples/server/allowed_server_v2.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3
```

Result: `"subsumes": true` — every input allowed by v1 is also allowed by v2,
despite v2 using a completely different rule structure (comprehensions +
function rules instead of partial sets + inline joins).

```bash
# Does v1 subsume v2? (No — v1 is stricter)
regorus subsumes \
  --old examples/server/allowed_server_v2.rego \
  --new examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3
```

Result: `"subsumes": false` with a counterexample where v2 allows (telnet ok)
but v1 denies (telnet banned).

### Subsumption Example 2 — Network Segmentation

Check whether the restructured v2 (object-comprehension maps + `every`,
PII rule dropped) subsumes v1:

```bash
# Does v2 subsume v1? (Yes — v2 is more permissive)
regorus subsumes \
  --old examples/demos/network_segmentation.rego \
  --new examples/demos/network_segmentation_v2.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3
```

Result: `"subsumes": true` — every compliant topology under v1 is also
compliant under v2.

```bash
# Does v1 subsume v2? (No — v1 is stricter)
regorus subsumes \
  --old examples/demos/network_segmentation_v2.rego \
  --new examples/demos/network_segmentation.rego \
  -e data.network_segmentation.compliant \
  -i examples/demos/network_segmentation_input.json \
  -s examples/demos/network_segmentation_schema.json \
  --max-loops 3
```

Result: `"subsumes": false` — Z3 produces a counterexample with a PII service
using an unencrypted connection that v2 allows but v1 blocks.

---

## Test Suite Generation

Automatically generate a set of test inputs that cover all reachable source
lines in a policy:

```bash
regorus gen-tests \
  -d policy.rego \
  -e data.example.allow \
  -o false \
  -s input_schema.json \
  --max-tests 20
```

The algorithm:
1. Translates the program once, collecting per-PC path conditions.
2. Groups PCs by source line → a set of coverable lines.
3. For each uncovered line, asks Z3 for an input that covers it.
4. Records the test case and all lines it additionally covers.
5. Repeats until all lines are covered or proved unreachable.

### Test Gen CLI Reference

```
regorus gen-tests [OPTIONS] --entrypoint <RULE>
```

| Flag | Description |
|---|---|
| `-d, --data <FILE>` | Policy or data files. Repeatable. |
| `-b, --bundles <DIR>` | Bundle directories. Repeatable. |
| `-e, --entrypoint <RULE>` | Entry point to generate tests for. |
| `-o, --output <JSON>` | Desired output value for all tests (optional). |
| `-i, --input <FILE>` | Example input JSON for type inference. |
| `-s, --schema <FILE>` | JSON Schema for input constraints. |
| `--max-tests <N>` | Maximum test cases to generate (default: 100). |
| `--timeout <MS>` | Z3 timeout (default: 30000). |
| `--max-loops <N>` | Loop unrolling depth (default: 5). |
| `--condition-coverage` | Enable condition coverage: ensure every boolean condition evaluates to both `true` and `false` across the test suite. |
| `--format <FORMAT>` | Output format: `json` (default) or `annotated` (full source listing with `true`/`false` markers per condition line). |
| `--dump-smt <FILE>` | Write base SMT-LIB2 assertions. |

### Test Gen Output

```json
{
  "test_cases": [
    {
      "input": { ... },
      "covered_lines": ["policy.rego:14", "policy.rego:15", ...]
    }
  ],
  "coverage_summary": {
    "coverable_lines": 16,
    "covered_lines": 16,
    "coverage_pct": "100.0%"
  },
  "warnings": []
}
```

### Test Gen Example

Generate tests for the server infrastructure policy:

```bash
regorus gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -o false \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3 \
  --max-tests 10
```

Produces 2 test cases covering all 16 coverable lines (100%): one triggers
the `"telnet"` ban rule, the other triggers the `"http"` on public network
rule.

Without `--output`, the tool generates tests for **all** paths (both
`allow=true` and `allow=false`):

```bash
regorus gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3
```

### Condition Coverage

Line coverage ensures every reachable line is executed by at least one test.
**Condition coverage** goes further: it ensures every boolean condition in the
policy evaluates to both `true` and `false` across the test suite.

Enable it with `--condition-coverage`:

```bash
regorus gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3 \
  --condition-coverage
```

The algorithm adds a Phase 2 after line coverage:
1. Collects all boolean conditions from the symbolic translation.
2. For each condition, checks which tests already exercise `true` and `false`.
3. For each uncovered condition goal, asks Z3 for an input that forces it.
4. Repeats until all condition goals are covered or proved tautological.

The JSON output includes condition coverage information per test case:

```json
{
  "test_cases": [
    {
      "input": { ... },
      "covered_lines": [
        { "location": "policy.rego:14", "text": "    \"http\" in server.protocols" }
      ],
      "condition_coverage": [
        { "location": "policy.rego:14", "value": true, "text": "    \"http\" in server.protocols" },
        { "location": "policy.rego:16", "value": false, "text": "    port.id in server.ports" }
      ]
    }
  ],
  "coverage_summary": {
    "coverable_lines": 16,
    "covered_lines": 16,
    "coverage_pct": "100.0%",
    "condition_goals": 12,
    "condition_goals_covered": 12,
    "condition_coverage_pct": "100.0%"
  }
}
```

### Annotated Output

Use `--format annotated` to see a full source listing per test, with
`true`/`false` markers on each condition line:

```bash
regorus gen-tests \
  -d examples/server/allowed_server.rego \
  -e data.example.allow \
  -i examples/server/input.json \
  -s examples/server/input_schema.json \
  --max-loops 3 \
  --condition-coverage \
  --format annotated
```

Each test case is displayed as the full policy source with a 5-character
prefix before each line number:

```
== Test 5 ==
  Result: true
  Source: examples/server/allowed_server.rego
         1 | package example
  ...
  false   11 |     "http" in server.protocols
         12 |     port := input.ports[_]
  ...
  true    16 |     "telnet" in server.protocols
```

- `true ` — the condition evaluated to true in this test
- `false` — the condition evaluated to false in this test
- (blank) — the line is not a condition, or was not reached

This makes it easy to visually verify which conditions each test exercises.

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

> **SMT2 encoding:** [`examples/smt2/server_allow_false.smt2`](examples/smt2/server_allow_false.smt2)

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

> **SMT2 encoding:** [`examples/smt2/server_allow_true.smt2`](examples/smt2/server_allow_true.smt2)

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

> **SMT2 encoding:** [`examples/smt2/container_admission_allow_false.smt2`](examples/smt2/container_admission_allow_false.smt2)

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

> **SMT2 encoding:** [`examples/smt2/container_admission_targeted.smt2`](examples/smt2/container_admission_targeted.smt2)

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

> **SMT2 encoding:** [`examples/smt2/network_segmentation_compliant_false.smt2`](examples/smt2/network_segmentation_compliant_false.smt2)

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

> **SMT2 encoding:** [`examples/smt2/network_segmentation_targeted.smt2`](examples/smt2/network_segmentation_targeted.smt2)

---

## Cedar Policy Analysis

The analyzer also supports [Cedar](https://www.cedarpolicy.com/) policies.
Cedar uses a **permit/forbid** model with entity hierarchies, wildcard
patterns (`like`), and typed context attributes.  The analyzer translates
Cedar policies to SMT constraints and synthesises a complete authorization
**request** — principal, action, resource, and context — given a concrete
entity graph.

### Cedar Quick Start

```bash
# "What request gets permitted?"
regorus analyze \
  -d policy.cedar \
  -d entities.json \
  -e cedar.authorize \
  -o 1

# "What request gets denied?"
regorus analyze \
  -d policy.cedar \
  -d entities.json \
  -e cedar.authorize \
  -o 0
```

Cedar output uses `1` for permit and `0` for deny (matching Cedar's
`to_number(permit_exclusive)` encoding).

### Cedar Example 1 — IAM Zero Trust

**Policy:** [`examples/cedar/examples/iam_zero_trust/policy.cedar`](examples/cedar/examples/iam_zero_trust/policy.cedar)
**Entities:** [`examples/cedar/examples/iam_zero_trust/entities.json`](examples/cedar/examples/iam_zero_trust/entities.json)

Admin login requires MFA, an internal IP (`10.*`), and the account must not
be suspended.  The policy features two interacting rules: a `permit` with
context constraints and a `forbid` override for suspended accounts.

```bash
regorus analyze \
  -d examples/cedar/examples/iam_zero_trust/policy.cedar \
  -d examples/cedar/examples/iam_zero_trust/entities.json \
  -e cedar.authorize \
  -o 1
```

```json
{
  "input": {
    "action": "Action::login",
    "context": {
      "ip": "10.",
      "mfa": true,
      "suspended": false
    },
    "principal": "User::admins",
    "resource": "App::portal"
  },
  "satisfiable": true,
  "warnings": []
}
```

Z3 discovers that the principal must be in the `admins` hierarchy
(`User::admins` or `User::alice`), the IP must match `10.*` (Z3 string
regex theory), MFA must be `true`, and `suspended` must be `false` — all
derived purely from the policy and entity graph.

> **SMT2 encoding:** [`examples/smt2/cedar/iam_zero_trust_permit.smt2`](examples/smt2/cedar/iam_zero_trust_permit.smt2)

### Cedar Example 2 — Healthcare (HIPAA-inspired)

**Policy:** [`examples/cedar/examples/hipaa_healthcare/policy.cedar`](examples/cedar/examples/hipaa_healthcare/policy.cedar)
**Entities:** [`examples/cedar/examples/hipaa_healthcare/entities.json`](examples/cedar/examples/hipaa_healthcare/entities.json)

Doctors in the oncology department may view patient records during approved
hours (8–18) with a trusted device.  Nurses may view non-VIP records during
a wider window (6–20).  After-hours access is forbidden for non-emergencies.

```bash
regorus analyze \
  -d examples/cedar/examples/hipaa_healthcare/policy.cedar \
  -d examples/cedar/examples/hipaa_healthcare/entities.json \
  -e cedar.authorize \
  -o 1
```

```json
{
  "input": {
    "action": "Action::viewRecord",
    "context": {
      "device_trusted": false,
      "emergency": true,
      "hour": 6
    },
    "principal": "Role::nurses",
    "resource": "PatientRecord::chart-42"
  },
  "satisfiable": true,
  "warnings": []
}
```

Z3 navigates a 3-level entity hierarchy (`User → Role → Staff`), an ITE
chain for the `department` attribute, numeric hour range constraints (`>=`
and `<=`), and the VIP boolean flag — and finds the nurse path at hour 6.

> **SMT2 encoding:** [`examples/smt2/cedar/hipaa_healthcare_permit.smt2`](examples/smt2/cedar/hipaa_healthcare_permit.smt2)

### Cedar Example 3 — Financial Trading Platform

**Policy:** [`examples/cedar/examples/financial_trading/policy.cedar`](examples/cedar/examples/financial_trading/policy.cedar)
**Entities:** [`examples/cedar/examples/financial_trading/entities.json`](examples/cedar/examples/financial_trading/entities.json)

Tiered trade execution: regular traders up to $1M, senior traders up to $50M.
Compliance officers can review/audit any trade.  All access is
forbidden from sanctioned regions (`SANC-*`).

```bash
regorus analyze \
  -d examples/cedar/examples/financial_trading/policy.cedar \
  -d examples/cedar/examples/financial_trading/entities.json \
  -e cedar.authorize \
  -o 1
```

```json
{
  "input": {
    "action": "Action::reviewTrade",
    "context": {
      "market_open": false,
      "region": "",
      "trade_value": 0
    },
    "principal": "Role::compliance",
    "resource": "Market::NYSE"
  },
  "satisfiable": true,
  "warnings": []
}
```

Z3 finds the compliance officer path (no trade value or region constraints)
as the easiest permit.  The SMT2 encoding beautifully shows the three
permit disjuncts, the sanctions forbid, and the entity hierarchy — all in
~40 lines of readable SMT-LIB2.

> **SMT2 encoding:** [`examples/smt2/cedar/financial_trading_permit.smt2`](examples/smt2/cedar/financial_trading_permit.smt2)

### Cedar Example 4 — Kubernetes RBAC

**Policy:** [`examples/cedar/examples/k8s_rbac/policy.cedar`](examples/cedar/examples/k8s_rbac/policy.cedar)
**Entities:** [`examples/cedar/examples/k8s_rbac/entities.json`](examples/cedar/examples/k8s_rbac/entities.json)

Namespace-scoped access: developers can read, SREs can also delete (with an
incident ticket + on-call session), cluster-admins can do everything —
**except** nobody can delete `kube-system` resources (hard deny).

```bash
regorus analyze \
  -d examples/cedar/examples/k8s_rbac/policy.cedar \
  -d examples/cedar/examples/k8s_rbac/entities.json \
  -e cedar.authorize \
  -o 1
```

```json
{
  "input": {
    "action": "Action::get",
    "context": {
      "has_incident_ticket": false,
      "oncall_session": false
    },
    "principal": "Group::cluster-admins",
    "resource": "Namespace::kube-system"
  },
  "satisfiable": true,
  "warnings": []
}
```

Z3 discovers that cluster-admins can `get` from `kube-system` — the forbid
only blocks `Action::delete`.  The SMT2 encoding shows the four permit
disjuncts and the forbid negation clearly.

> **SMT2 encoding:** [`examples/smt2/cedar/k8s_rbac_permit.smt2`](examples/smt2/cedar/k8s_rbac_permit.smt2)

---

## Running the Demo Suite

A script that runs all examples end-to-end is provided:

```bash
./examples/demos/run_demos.sh
```

This exercises violation finding, compliance synthesis, targeted path
exploration, Cedar permit/deny synthesis, and SMT/model file dumps across
Rego and Cedar policies.

The demo script also includes **Python analyzer demos** (Demos 9–15) that
mirror the Rego and Cedar demos using the two-step `regorus compile` →
`python3 -m tools.z3analyze` workflow.  These require `pip install z3-solver`.

**Demos 16–20** exercise the **policy diff**, **subsumption**, and **test
suite generation** features:

| Demo | Feature | Policies |
|---|---|---|
| 16 | Diff | Server v1 vs v2 (telnet rule removed, HTTP logic restructured) |
| 17 | Subsumption | Server v1 ↔ v2 (both directions) |
| 18 | Test Gen | Server infrastructure (with/without output constraint) |
| 19 | Diff | Network segmentation v1 vs v2 (PII rule dropped, comprehension-based) |
| 20 | Subsumption | Network segmentation v1 ↔ v2 (both directions) |

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

## Pre-generated SMT2 Files

The [`examples/smt2/`](examples/smt2/) directory contains pre-generated SMT-LIB2
encodings for every demo walkthrough above.  You can feed them directly to a
standalone Z3 binary (`z3 file.smt2`) without building Regorus.

| File | Demo | Goal |
|---|---|---|
| [`server_allow_false.smt2`](examples/smt2/server_allow_false.smt2) | Server Infrastructure | Find a violation (`allow = false`) |
| [`server_allow_true.smt2`](examples/smt2/server_allow_true.smt2) | Server Infrastructure | Find a compliant config (`allow = true`) |
| [`container_admission_allow_false.smt2`](examples/smt2/container_admission_allow_false.smt2) | Container Admission | Find a violation (`allow = false`) |
| [`container_admission_targeted.smt2`](examples/smt2/container_admission_targeted.smt2) | Container Admission | Targeted: cover line 97, avoid line 73 |
| [`network_segmentation_compliant_false.smt2`](examples/smt2/network_segmentation_compliant_false.smt2) | Network Segmentation | Find non-compliant topology |
| [`network_segmentation_targeted.smt2`](examples/smt2/network_segmentation_targeted.smt2) | Network Segmentation | Targeted: DMZ rule only (line 93, avoid 121) |
| [`cedar/quickstart_permit.smt2`](examples/smt2/cedar/quickstart_permit.smt2) | Cedar Quickstart | Permit with IP regex + entity hierarchy |
| [`cedar/iam_zero_trust_permit.smt2`](examples/smt2/cedar/iam_zero_trust_permit.smt2) | Cedar IAM Zero Trust | Permit with MFA + IP + forbid override |
| [`cedar/hipaa_healthcare_permit.smt2`](examples/smt2/cedar/hipaa_healthcare_permit.smt2) | Cedar Healthcare | Permit with hour ranges + VIP + department |
| [`cedar/financial_trading_permit.smt2`](examples/smt2/cedar/financial_trading_permit.smt2) | Cedar Financial Trading | Permit with trade limits + sanctions forbid |
| [`cedar/k8s_rbac_permit.smt2`](examples/smt2/cedar/k8s_rbac_permit.smt2) | Cedar Kubernetes RBAC | Permit with tiered access + hard deny |
| [`cedar/deny_overrides_permit.smt2`](examples/smt2/cedar/deny_overrides_permit.smt2) | Cedar Deny Overrides | Permit when suspended=false |

To regenerate these files, run the corresponding `regorus analyze` command with
`--dump-smt <path>`.

---

## Limitations

The symbolic engine is under active development.  Current limitations include:

| Area | Status |
|---|---|
| **Comprehensions** | Set/array/object comprehensions are symbolically unrolled; results support `in` and `count` |
| **String builtins** | `startswith`, `endswith`, `contains`, `indexof`, `replace`, `substring`, `trim_prefix`, `trim_suffix` use Z3 string theory; `regex.match` etc. are unconstrained Bools |
| **Numeric builtins** | `abs` uses `ite(x>=0, x, -x)`; `bits.*` use Z3 bitvector theory; `sum`, `max`, `min` are unconstrained Ints |
| **Aggregations** | `count` on symbolic collections uses cardinality tracking; other aggregations are approximate |
| **Recursion** | Bounded by `--max-rule-depth` (default 3) |
| **Loop depth** | Bounded by `--max-loops` (default 5); iterations beyond the bound are not explored |
| **Negation** | `not` in rule bodies is supported for concrete and simple symbolic expressions |
| **`with` keyword** | Not yet supported |
| **Functions** | User-defined functions are inlined up to the rule depth limit |
| **Cedar** | Supports `permit`/`forbid`, `in` (entity hierarchy), `like` (regex), `has`, `attr`, `is`, `==`, numeric/boolean context; entity graph must be concrete |

Despite these limitations, the engine handles the core Rego patterns — nested
loops, multi-way joins, set membership (`in`), partial rules, `count`, and
Boolean/string/numeric comparisons — and the core Cedar patterns — entity
hierarchy traversal, permit/forbid interplay, wildcard matching, and typed
context constraints — which cover a large class of real-world admission
control, compliance, and authorization policies.
