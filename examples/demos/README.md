# Z3 Symbolic Analysis — Demo Gallery

These demos showcase **automatic input synthesis** for Rego policies using
Z3-backed symbolic execution.  Given a policy, a schema, and a goal, the
analyzer constructs a concrete JSON input that satisfies (or violates) the
policy — without executing the policy at all.

## Quick start

```bash
# One-time build (requires Z3: brew install z3)
BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
LIBRARY_PATH="/opt/homebrew/lib" \
cargo build --example regorus --features z3-analysis

# Run all demos
./examples/demos/run_demos.sh
```

---

## Demo 1 — Container Admission Controller

**Policy** ([container_admission.rego](container_admission.rego)):
A deployment is allowed only when *zero* violations exist.

| # | Violation rule | Trigger |
|---|---|---|
| 1 | Privileged container | `container.privileged == true` |
| 2 | Sensitive container on public host | container mounts an unencrypted volume **and** resides on a public host |

Rule 2 is a *3-way cross-collection join* — the analyzer must coordinate
string IDs across `containers`, `hosts`, and `volumes`.

### 1a) "What input causes a denial?"

```bash
regorus analyze \
  -d container_admission.rego \
  -e data.container_admission.allow -o false \
  -s container_admission_schema.json --max-loops 3
```

Z3 finds a container with `privileged: true` — the simplest violation.

### 1b) "What input is fully compliant?"

```bash
regorus analyze ... -o true ...
```

Z3 sets all containers to `privileged: false`, all volumes to
`encrypted: true`, and all hosts to `public: false`.

### 1c) "Find a violation specifically through the complex path"

```bash
regorus analyze ... -o false \
  -l container_admission.rego:31 \          # cover: public-host check
  --avoid-line container_admission.rego:23   # avoid: privileged check
```

Z3 synthesises coordinated IDs:

| Collection | Key fields |
|---|---|
| `containers[2]` | `host_id: "I"`, `volume_ids: ["K"]`, `privileged: false` |
| `hosts[2]` | `id: "I"`, `public: true` |
| `volumes[2]` | `id: "K"`, `encrypted: false` |

Three string equalities across three collections — all inferred automatically.

---

## Demo 2 — Network Segmentation Compliance

**Policy** ([network_segmentation.rego](network_segmentation.rego)):
A microservice topology is compliant only when zero violations exist.

| # | Violation rule | Trigger |
|---|---|---|
| 1 | DMZ → internal DB | A service in a DMZ zone connects to an internal database |
| 2 | PII over unencrypted | A PII-handling service has an unencrypted connection |

Rule 1 is a *4-way cross-collection join* across `services`, `zones`,
`connections`, and `databases`.

### 2a) "Find a non-compliant topology"

Z3 synthesises a 4-way ID chain:

```
service "E"  →  zone_id "M"  →  zone "M" (dmz=true)
                  ↓
connection source="E", target="F"  →  database "F" (internal=true)
```

### 2b) "Fail only via DMZ rule" (cover line 27, avoid line 36)

Z3 ensures all `handles_pii: false` and all connections encrypted (avoiding
the PII rule), while constructing the DMZ→internal-DB chain.

### 2c) "Fail only via PII rule" (cover line 36, avoid line 27)

Z3 ensures all zones have `dmz: false` (no DMZ services at all), while
finding a PII-handling service with an unencrypted connection.

---

## Demo 3 — Server Infrastructure (classic OPA example)

**Policy** ([../../examples/server/allowed_server.rego](../../examples/server/allowed_server.rego)):
No `"http"` on public servers; no `"telnet"` anywhere.  Uses the Rego `in`
operator for protocol membership checks.

---

## Demo 4 — SMT / Model File Dump

Use `--dump-smt <file>` and `--dump-model <file>` to inspect the Z3 encoding:

```bash
regorus analyze ... --dump-smt demo.smt2 --dump-model demo.model
```

The SMT file contains ~1,900 lines of SMT-LIB2 assertions, and the model
file shows every symbolic variable assignment Z3 chose.

---

## Key capabilities demonstrated

| Capability | How it's shown |
|---|---|
| **Input synthesis** | Given `-o true` or `-o false`, Z3 constructs the exact JSON |
| **Schema constraints** | `minItems`, `maxItems`, `x-unique`, `required`, `minLength` restrict the search space |
| **Cross-collection joins** | Z3 coordinates string IDs across 3–4 collections |
| **Path targeting** | `-l FILE:LINE` forces execution through a specific rule body |
| **Path avoidance** | `--avoid-line FILE:LINE` prevents a specific code path |
| **Soundness** | Every generated input is verified by the concrete Rego engine |
| **SMT debugging** | `--dump-smt` / `--dump-model` dump the full Z3 encoding |
