# Z3 Symbolic Analysis — Demo Gallery

These demos showcase **automatic input synthesis** for Rego and Cedar
policies using Z3-backed symbolic execution.  Given a policy, a schema (for
Rego) or entity data (for Cedar), and a goal, the analyzer constructs a
concrete JSON input that satisfies (or violates) the policy — without
executing the policy at all.

## Quick start

```bash
# One-time build (requires Z3: brew install z3)
BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/include" \
LIBRARY_PATH="/opt/homebrew/lib" \
cargo build --example regorus --features z3-analysis,cedar

# Run all demos (Rust + Python)
./examples/demos/run_demos.sh
```

**Python-only alternative** (no C toolchain needed):

```bash
pip install z3-solver
# Use pre-compiled bytecode JSON (checked in)
python3 -m tools.z3analyze examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --example-input examples/demos/container_admission_input.json \
  --schema examples/demos/container_admission_schema.json
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

## Demo 4 — Cedar: IAM Zero Trust

**Policy** ([../../examples/cedar/examples/iam_zero_trust/policy.cedar](../../examples/cedar/examples/iam_zero_trust/policy.cedar)):
Admins may log in if they have MFA enabled and connect from an internal IP
(matching `10.*`).  A `forbid` rule overrides everything if the account is
suspended.

```bash
regorus analyze \
  -d examples/cedar/examples/iam_zero_trust/policy.cedar \
  -d examples/cedar/examples/iam_zero_trust/entities.json \
  -e cedar.authorize -o 1
```

Z3 discovers that the principal must belong to the `admins` group, the IP
must start with `"10."` (encoded as a Z3 regex `re.++ (str.to_re "10.") re.all`),
`mfa` must be `true`, and `suspended` must be `false`.

---

## Demo 5 — Cedar: Healthcare (HIPAA-inspired)

**Policy** ([../../examples/cedar/examples/hipaa_healthcare/policy.cedar](../../examples/cedar/examples/hipaa_healthcare/policy.cedar)):
Doctors in oncology may view patient records during hours 8–18 with a
trusted device.  Nurses may view non-VIP records during hours 6–20.
A `forbid` rule blocks all access outside hours 6–22 unless
`emergency` is `true`.

```bash
regorus analyze \
  -d examples/cedar/examples/hipaa_healthcare/policy.cedar \
  -d examples/cedar/examples/hipaa_healthcare/entities.json \
  -e cedar.authorize -o 1
```

Z3 navigates a 3-level entity hierarchy (`User → Role → Staff`),
department attribute matching, and numeric hour constraints to find a
valid combination.

---

## Demo 6 — Cedar: Financial Trading Platform

**Policy** ([../../examples/cedar/examples/financial_trading/policy.cedar](../../examples/cedar/examples/financial_trading/policy.cedar)):
Regular traders may execute trades ≤ $1M from `US-*` regions during market
hours.  Senior traders get a $50M limit.  Compliance officers may
`reviewTrade` or `auditLog` with no monetary constraints.  A `forbid`
blocks all access from sanctioned regions matching `SANC-*`.

```bash
regorus analyze \
  -d examples/cedar/examples/financial_trading/policy.cedar \
  -d examples/cedar/examples/financial_trading/entities.json \
  -e cedar.authorize -o 1
```

Z3 discovers the compliance-officer path (no trade-value or region
constraints), or a trader path satisfying the `US-*` region regex and
`trade_value ≤ limit`.

---

## Demo 7 — Cedar: Kubernetes RBAC

**Policy** ([../../examples/cedar/examples/k8s_rbac/policy.cedar](../../examples/cedar/examples/k8s_rbac/policy.cedar)):
Developers may `get`/`list` resources in the `production` namespace.
SREs may also `delete`, but only with an incident ticket and while on-call.
Cluster-admins may perform all actions on `production` and read
`kube-system`.  A hard `forbid` prevents *anyone* from deleting
`kube-system` resources.

```bash
regorus analyze \
  -d examples/cedar/examples/k8s_rbac/policy.cedar \
  -d examples/cedar/examples/k8s_rbac/entities.json \
  -e cedar.authorize -o 1
```

Z3 explores the permit/forbid interplay — cluster-admins can read
`kube-system` but the forbid blocks delete there.

---

## Demo 8 — SMT / Model File Dump

Use `--dump-smt <file>` and `--dump-model <file>` to inspect the Z3 encoding:

```bash
# Rego: container admission targeted query
regorus analyze ... --dump-smt demo.smt2 --dump-model demo.model

# Cedar: financial trading
regorus analyze \
  -d examples/cedar/examples/financial_trading/policy.cedar \
  -d examples/cedar/examples/financial_trading/entities.json \
  -e cedar.authorize -o 1 \
  --dump-smt cedar.smt2 --dump-model cedar.model
```

The Rego SMT file contains ~1,900 lines of SMT-LIB2 assertions.  The Cedar
encoding is much more compact (~67 lines) — entity hierarchy disjuncts,
regex constraints for `like` patterns, numeric bounds, and the
permit-unless-forbid structure are all directly visible.

---

## Python Z3 Analyzer (Demos 9–11)

The same analysis can be performed with the **Python Z3 analyzer** — a
pure-Python reimplementation under [`../../tools/z3analyze/`](../../tools/z3analyze/).
It requires only `pip install z3-solver` (no C toolchain or bindgen).

Pre-compiled bytecode JSON files are checked in alongside the policies:

| Bytecode file | Source policy |
|---|---|
| `container_admission_program.json` | `container_admission.rego` |
| `network_segmentation_program.json` | `network_segmentation.rego` |
| `allowed_server_program.json` | `allowed_server.rego` |

### Demo 9 — Python: Container Admission

Mirrors Demos 1a–1c.  Violation finding, compliance synthesis, and targeted
path analysis all work identically.

```bash
# Violation
python3 -m tools.z3analyze examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --example-input container_admission_input.json \
  --schema container_admission_schema.json --max-loop-depth 3

# Targeted: cover line 101, avoid line 75
python3 -m tools.z3analyze examples/demos/container_admission_program.json \
  -e data.container_admission.allow -o false \
  --cover-line container_admission.rego 101 \
  --avoid-line container_admission.rego 75 \
  --example-input container_admission_input.json \
  --schema container_admission_schema.json --max-loop-depth 3
```

### Demo 10 — Python: Network Segmentation

Mirrors Demos 2a–2c.  Includes targeted DMZ-only and PII-only queries.

### Demo 11 — Python: Server Infrastructure

Mirrors Demos 3a–3b.

> **Note:** `--cover-line` and `--avoid-line` take **separate** `FILE` and
> `LINE` arguments (not `FILE:LINE` as in the Rust CLI).

---

## Key capabilities demonstrated

| Capability | How it's shown |
|---|---|
| **Input synthesis** | Given `-o true`/`false` (Rego) or `-o 1`/`0` (Cedar), Z3 constructs the exact JSON |
| **Schema constraints** | `minItems`, `maxItems`, `x-unique`, `required`, `minLength` restrict the Rego search space |
| **Cross-collection joins** | Z3 coordinates string IDs across 3–4 collections (Rego) |
| **Entity hierarchy** | Z3 enumerates transitive group membership in Cedar `in` checks |
| **Permit / forbid interplay** | Cedar's `forbid` overrides are encoded as `permit ∧ ¬forbid` |
| **Regex constraints** | Cedar `like` patterns become Z3 string regexes |
| **Path targeting** | `-l FILE:LINE` forces execution through a specific rule body (Rego) |
| **Path avoidance** | `--avoid-line FILE:LINE` prevents a specific code path (Rego) |
| **Soundness** | Every generated input is verified by the concrete engine |
| **SMT debugging** | `--dump-smt` / `--dump-model` dump the full Z3 encoding |
