# Z3 Symbolic Analyzer — Ideas & Roadmap

A collection of feature ideas for the Regorus Z3 symbolic analysis engine,
organized by theme.  Each idea includes a brief description, potential CLI
surface, and implementation sketch.

---

## Table of Contents

- [Policy Comparison & Verification](#policy-comparison--verification)
- [Coverage & Testing](#coverage--testing)
- [Explanation & Debugging](#explanation--debugging)
- [Optimization & Quantitative Analysis](#optimization--quantitative-analysis)
- [Cedar-Specific Extensions](#cedar-specific-extensions)
- [Developer Experience](#developer-experience)
- [Advanced Analysis Techniques](#advanced-analysis-techniques)
- [Integration & Tooling](#integration--tooling)
- [Security & Formal Properties](#security--formal-properties)
- [Policy Synthesis & Repair](#policy-synthesis--repair)
- [Operational / Runtime](#operational--runtime)
- [Schema & Data Evolution](#schema--data-evolution)
- [Multi-Policy / Ecosystem](#multi-policy--ecosystem)
- [Kubernetes / Cloud-Specific](#kubernetes--cloud-specific)
- [Quantitative Information Theory](#quantitative-information-theory)

---

## Policy Comparison & Verification

### 1. Policy Diff Analysis

Given two versions of a policy (or two policy files), find an input where
they produce different outputs.  Encodes `P1(input) XOR P2(input)` and asks
Z3 for a satisfying assignment.

```bash
regorus diff \
  -d policy_v1.rego -d policy_v2.rego \
  -e data.example.allow \
  -s input_schema.json
```

**Output:** A concrete input where the two versions disagree, or a proof
that they are equivalent within the schema.

**Use case:** Catch regressions before deploying policy updates.  Integrate
into CI as a gate.

### 2. Policy Subsumption Checking

Prove that policy A is strictly more permissive (or more restrictive) than
policy B — or find a counterexample.

```bash
regorus subsumes \
  -d policy_new.rego -d policy_old.rego \
  -e data.example.allow \
  -s input_schema.json
```

Encodes: ∀ input: `old(input) = true → new(input) = true` (new subsumes
old).  Negation gives the distinguishing input.

**Use case:** Policy migration validation — ensure a rewrite doesn't
accidentally restrict access.

### 3. Cross-Language Equivalence (Rego ↔ Cedar)

Given a Rego policy and a Cedar policy that are intended to be equivalent,
verify they produce the same authorization decision for all inputs, or find
a distinguishing input.

```bash
regorus equiv \
  --rego policy.rego -e data.policy.allow \
  --cedar policy.cedar --entities entities.json \
  -s input_schema.json
```

**Use case:** Safely migrate from Rego to Cedar (or vice versa).

### 4. Default-Deny Verification

Prove that a policy is default-deny: without matching any permit rule, the
output is always deny.  Catches accidental permissive defaults.

```bash
regorus verify-default-deny \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

Encodes: "Does there exist an input where no rule body fires AND the result
is `true`?"  If SAT, the policy has a default-allow gap.

### 5. Conflict Detection Between Policy Modules

When multiple `.rego` files contribute rules to the same entrypoint, detect
if they can produce conflicting intermediate results.

```bash
regorus check-conflicts \
  -d module_a.rego -d module_b.rego \
  -e data.authz.allow
```

**Use case:** Large policy bundles where different teams own different
modules.  Detects semantic conflicts that syntactic checks miss.

---

## Coverage & Testing

### 6. Unreachable Rule Detection (Dead Code)

For each rule body, check if there exists *any* input that makes it fire.
Rules that are always UNSAT are dead code.

```bash
regorus dead-code \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

**Output:** A list of rule bodies (file:line) that can never execute,
regardless of input.  Optionally explains *why* (conflicting constraints
from other rules or schema).

### 7. Minimal Test Suite Generation

Enumerate all reachable paths and generate one input per path, producing a
minimal set of test cases that achieves full path coverage.

```bash
regorus gen-tests \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json \
  --format opa          # or: json, rego-test
  -o tests/
```

For each path, Z3 produces a concrete input + expected output.  Output
formats:
- **OPA test:** `test_*.rego` files with `test_rule_path_N` functions
- **JSON:** array of `{input, expected_output, covered_lines}`
- **Table:** human-readable coverage matrix

### 8. Mutation Testing

Automatically mutate the policy (flip operators, change constants, remove
conditions) and check if any existing test case detects the mutation.

```bash
regorus mutate \
  -d policy.rego \
  -e data.example.allow \
  --tests tests/
```

For each surviving mutant (not caught by tests), Z3 generates a
distinguishing input — a suggested new test case.

### 9. Holes / Underspecification Detection

Find inputs where the policy produces no decision (undefined result).
These are gaps that may need explicit rules.

```bash
regorus find-gaps \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

Encodes: "Find an input where the entrypoint is undefined (not `true`,
not `false`, just undefined)."  Useful for policies that should be total
but accidentally aren't.

---

## Explanation & Debugging

### 10. UNSAT Core / "Why Not" Explanation

When the result is UNSAT, extract the minimal set of conflicting
constraints and map them back to source lines.

```bash
regorus analyze \
  -d policy.rego \
  -e data.example.allow -o true \
  -s input_schema.json \
  --explain
```

**Output:** "No input can produce `allow = true` because:
1. Rule at policy.rego:15 requires `input.role == "admin"`
2. Schema constraint restricts `input.role` to `["viewer", "editor"]`
3. These are contradictory."

Uses Z3's `unsat_core()` with named assertions mapped to source locations.

### 11. Natural Language Explanation of Results

Given a satisfying input, generate a human-readable explanation of *why*
this input produces the observed output.

```bash
regorus analyze ... --explain-result
```

**Output:** "The request is PERMITTED because:
1. Principal `User::alice` is in group `admins` (entity hierarchy: alice → admins)
2. `context.mfa` is `true` (satisfies permit rule at policy.cedar:2)
3. `context.ip` is `"10.0.1.5"` (matches wildcard `10.*` at policy.cedar:3)
4. `context.suspended` is `false` (forbid rule at policy.cedar:6 does not fire)"

Walks the solved constraint graph and annotates each assertion with its
source.

### 12. Sensitivity Analysis / Input Importance

For a given output, which input fields actually matter?  Fix the output
constraint and check which fields can be set to *any* value without
changing satisfiability.

```bash
regorus sensitivity \
  -d policy.rego \
  -e data.example.allow -o false \
  -s input_schema.json
```

**Output:**
```
CRITICAL:  input.containers[*].privileged  (any true → deny)
CRITICAL:  input.hosts[*].public           (must be true for path 2)
IRRELEVANT: input.hosts[*].id              (any string works)
IRRELEVANT: input.containers[*].name       (unchecked by policy)
```

**Use case:** Understand which fields drive decisions, simplify schemas,
prioritize review.

### 13. Decision Boundary Exploration

For numeric fields, find the boundary where the policy decision changes.
Uses Z3 optimization to find the tightest bound.

```bash
regorus boundary \
  -d policy.cedar -d entities.json \
  -e cedar.authorize \
  --field context.trade_value \
  --principal "Role::traders"
```

**Output:** "For `Role::traders`, `context.trade_value` must be ≤ 1000000
for permit.  At 1000001, the policy denies."

Uses `z3.Optimize()` with `maximize(context.trade_value)` subject to
`output == 1`.

---

## Optimization & Quantitative Analysis

### 14. Quantitative Bounds

Answer "what's the maximum/minimum value of a field that still satisfies
the policy?" using Z3's optimization engine.

```bash
regorus optimize \
  -d policy.cedar -d entities.json \
  -e cedar.authorize -o 1 \
  --maximize context.trade_value \
  --constraint "context.region == \"US-East\""
```

**Output:** `Maximum trade_value for permitted US-East trades: 50000000`

### 15. Counterexample Minimization

When Z3 finds a satisfying input, minimize it: fewest defined fields,
shortest strings, smallest numbers.  Produces the simplest possible
witness.

```bash
regorus analyze ... --minimize
```

Uses iterative Z3 optimization or incremental solving to progressively
simplify the model while maintaining satisfiability.

### 16. All-SAT Enumeration

Enumerate *all* distinct satisfying structures (up to a bound), not just
one.  Useful for understanding the full space of inputs that trigger a
particular decision.

```bash
regorus enumerate \
  -d policy.rego -e data.example.allow -o false \
  -s input_schema.json \
  --max-models 10
```

After each SAT result, adds a blocking clause to exclude that model's
structure and re-solves.  Groups results by which rule path they exercise.

---

## Cedar-Specific Extensions

### 17. Entity Graph Synthesis

Instead of requiring a concrete entity graph, make parts of it symbolic.
"What entity hierarchy would permit this request?"

```bash
regorus analyze \
  -d policy.cedar \
  -e cedar.authorize -o 1 \
  --symbolic-entities \
  --entity-types "User,Role,Group" \
  --max-entities 5
```

Z3 synthesizes both the request *and* the entity graph.  Useful for
designing entity models during policy development.

### 18. Access Matrix Enumeration (Cedar)

For a Cedar policy, enumerate all `(principal_type, action, resource_type)`
triples that can be permitted.  Gives a high-level view of the policy's
authorization surface.

```bash
regorus cedar access-matrix \
  -d policy.cedar -d entities.json
```

**Output:**
```
 Principal        | Action          | Resource            | Result
 User::alice      | Action::login   | App::portal         | PERMIT (via rule 1)
 User::admins     | Action::login   | App::portal         | PERMIT (via rule 1)
 *                | *               | *                   | DENY (default)
```

Iteratively queries Z3 for each entity-type combination.

### 19. Forbidden Path Reachability (Cedar)

For each `forbid` rule in a Cedar policy, check whether there exists a
request that would be permitted *if* the forbid didn't exist.  If not,
the forbid is redundant (no permit would apply anyway).

```bash
regorus cedar check-forbids \
  -d policy.cedar -d entities.json
```

**Output:** "forbid at policy.cedar:8 is REDUNDANT — no permit rule
covers the same (principal, action, resource) scope."

### 20. Permit/Forbid Interaction Report (Cedar)

For Cedar policies, analyze how each forbid interacts with each permit.
Identifies which permits are partially or fully shadowed by forbids.

```bash
regorus cedar shadow-report \
  -d policy.cedar -d entities.json
```

**Output:**
```
permit rule 1 (line 2): NOT shadowed
permit rule 2 (line 5): PARTIALLY shadowed by forbid rule 3 (line 8)
  → shadowed when: context.suspended == true
permit rule 3 (line 9): FULLY shadowed by forbid rule 4 (line 12)
  → this permit can never produce an authorization
```

---

## Developer Experience

### 21. Interactive "What-If" Mode (REPL)

A constraint-based REPL where the user provides partial input constraints
and the analyzer fills in the rest.

```bash
regorus interactive \
  -d policy.rego -e data.example.allow -s input_schema.json

> set input.role = "admin"
> set output = true
> solve
SAT: { "role": "admin", "department": "engineering", ... }

> add-constraint input.department != "engineering"
> solve
SAT: { "role": "admin", "department": "finance", ... }

> why input.mfa
"input.mfa must be true because rule at policy.rego:15 requires it"
```

### 22. Incremental / Watch Mode

Cache the SMT encoding and re-solve only the changed constraints when a
policy file changes.

```bash
regorus analyze --watch \
  -d policy.rego -e data.example.allow -o false -s input_schema.json
```

Re-translates only modified rules, preserving Z3's learned lemmas.
Provides sub-second feedback in editor integrations.

### 23. VS Code Extension

A VS Code extension that provides:
- Inline annotations showing which rule paths are reachable
- Hover-to-see-witness: hover over a rule body to see a satisfying input
- "Find input for this line" code lens
- Side-by-side diff analysis when editing policies
- Gutter indicators for dead code

### 24. Schema Inference

Given a policy (no schema provided), infer what the input schema must look
like based on how the policy uses input fields.

```bash
regorus infer-schema \
  -d policy.rego \
  -e data.example.allow \
  -o input_schema.json
```

Analyzes field accesses, comparisons, and builtins to infer:
- Field names and nesting structure
- Types (boolean, integer, string, array, object)
- Required vs optional
- Enum values (from `==` comparisons with literals)
- Bounds (from `<`, `>`, `<=`, `>=` comparisons)

---

## Advanced Analysis Techniques

### 25. CEGAR (Counterexample-Guided Abstraction Refinement)

Formalize the verify-and-retry loop: when the Z3 model produces a spurious
input (fails concrete verification), automatically extract a refinement
constraint from the concrete execution trace and add it to the SMT
encoding.

```
Loop:
  1. Z3 produces candidate input I
  2. Concrete engine evaluates policy(I)
  3. If matches expected output → done
  4. If mismatch → analyze divergence point
  5. Add refinement constraint blocking the spurious path
  6. Re-solve (goto 1)
```

The current code does a simple retry.  Full CEGAR would extract *why* the
model is spurious and add a targeted constraint, converging faster.

### 26. Partial Evaluation + Z3

Partially evaluate the policy with known data (the data document), then
symbolically analyze only the residual policy.  Produces a much smaller
SMT encoding.

```bash
regorus analyze \
  -d policy.rego -d data.json \
  -e data.example.allow -o false \
  --partial-eval
```

First pass: concrete-evaluate everything that depends only on `data.*`.
Second pass: translate the residual (input-dependent) constraints to Z3.
Result: smaller encoding, faster solving, especially for policies with
large data documents.

### 27. Abstract Interpretation Pre-Pass

Before encoding to SMT, use abstract interpretation (interval analysis,
type inference, constant propagation) to prune the symbolic input space.

Identifies constraints like "this field is always compared to integers
in [0, 100]" and adds them as Z3 bounds without needing schema input.
Makes Z3 faster on large policies by reducing the search space.

### 28. Bounded Model Checking for Stateful Policies

For policies that depend on mutable state (data documents that change
over time), unroll K steps and check if an invariant can be violated
across any sequence of state transitions.

```bash
regorus bmc \
  -d policy.rego \
  -e data.example.allow \
  --invariant "NOT (input.role == 'viewer' AND output == true)" \
  --steps 3 \
  --transitions state_transitions.json
```

**Use case:** Detect multi-step privilege escalation: "Can a viewer
become an admin and then access restricted resources through a sequence
of valid API calls?"

### 29. Temporal / Multi-Request Analysis

Model sequences of authorization requests to find multi-step privilege
escalation paths.

```bash
regorus escalation \
  -d policy.cedar -d entities.json \
  --start-principal "User::viewer" \
  --target-action "Action::delete" \
  --target-resource "Namespace::kube-system" \
  --max-steps 3
```

Unrolls the policy K times with intermediate state changes.  Finds chains
like: "Step 1: viewer creates a resource → Step 2: resource triggers a
role grant → Step 3: new role permits delete."

### 30. Symbolic Data Documents

Currently data is always concrete.  Allow some data fields to be symbolic.

```bash
regorus analyze \
  -d policy.rego \
  -e data.example.allow -o true \
  --symbolic-data data.roles \
  --constraint "input.user == \"alice\""
```

"What role assignment in `data.roles` would permit Alice?"  Useful for
understanding what data configurations enable specific behaviors.

---

## Integration & Tooling

### 31. Regression Guard / CI Integration

A `regorus guard` command that takes a policy + a set of invariants and
returns pass/fail.  Designed for CI pipelines.

```bash
regorus guard \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json \
  --invariant "NOT (input.privileged == true AND output == true)" \
  --invariant "output == true IMPLIES input.mfa == true"
```

Exit code 0 = all invariants hold.  Exit code 1 = violation found
(prints counterexample).

### 32. OPA / Cedar Test Generation

Generate test files from Z3's satisfying inputs, annotated with which
rule path each test exercises.

```bash
# OPA format
regorus gen-tests -d policy.rego -e data.example.allow \
  --format opa -o tests/generated_test.rego

# Cedar format (request JSON files)
regorus gen-tests -d policy.cedar -d entities.json \
  -e cedar.authorize --format cedar -o tests/
```

### 33. Fuzzing Seed Generation

Use Z3's satisfying inputs as seeds for traditional fuzzers.  Z3 finds
structurally interesting inputs (edge cases, boundary conditions), then
the fuzzer explores nearby inputs.

```bash
regorus fuzz-seeds \
  -d policy.rego -e data.example.allow \
  -s input_schema.json \
  --num-seeds 100 \
  -o seeds/
```

### 34. Performance Profiling of SMT Encoding

Identify which rules/constraints are most expensive for Z3 to solve.
Helps users simplify their policies for faster analysis.

```bash
regorus analyze ... --profile
```

**Output:**
```
Rule                          | Constraints | Solve time
policy.rego:45 (3-way join)   |         142 | 2.3s
policy.rego:12 (array loop)   |          38 | 0.1s
schema constraints            |          25 | 0.01s
```

### 35. Visualization / Diagram Generation

Generate visual diagrams of the policy's decision structure or the
satisfying model.

```bash
# Decision tree of rule paths
regorus visualize \
  -d policy.rego -e data.example.allow \
  --format mermaid -o decision_tree.md

# Entity hierarchy + request flow (Cedar)
regorus cedar visualize \
  -d policy.cedar -d entities.json \
  --format dot -o entity_graph.dot
```

### 36. Policy Complexity Metrics

Static analysis metrics computed from the SMT encoding.

```bash
regorus complexity \
  -d policy.rego -e data.example.allow -s input_schema.json
```

**Output:**
```
Symbolic variables:     47
Boolean constraints:   312
String constraints:     23
Array unrollings:        9
Max path depth:          7
Estimated Z3 difficulty: MEDIUM
Rule interaction graph: 3 strongly-connected components
```

---

## Security & Formal Properties

### 37. Non-Interference / Information Flow Analysis

Mark certain input fields as "sensitive" (e.g., `input.user.ssn`) and prove
they cannot influence the authorization decision.  Encodes:
∀ i1, i2 that differ only on sensitive fields → `policy(i1) == policy(i2)`.
If SAT on the negation, Z3 produces two inputs showing the leak.

```bash
regorus non-interference \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json \
  --sensitive input.user.ssn,input.user.dob
```

**Output:** Either a proof that the sensitive fields don't affect the
decision, or two concrete inputs differing only in the sensitive fields
that produce different outputs.

**Use case:** Privacy audits — ensure authorization decisions don't leak
personally identifiable information.

### 38. Separation of Duty Verification

Prove that no single principal can perform conflicting actions (e.g.,
both "submit" and "approve").  Encodes: ∃ input where
`role=R ∧ policy(action=submit)=permit ∧ policy(action=approve)=permit`.
If SAT → SoD violation with concrete witness.

```bash
regorus check-sod \
  -d policy.rego \
  -e data.authz.allow \
  -s input_schema.json \
  --conflicting-actions submit,approve
```

**Output:** "SoD VIOLATION: role=`manager` can both `submit` and `approve`
with input: {...}"  Or: "SoD HOLDS: no single role can perform both actions."

**Use case:** SOX compliance, financial controls, approval workflows.

### 39. Monotonicity / Lattice Properties

Prove a policy is monotonic w.r.t. privilege escalation: if
`role1 ⊆ role2`, then `permit(role1) → permit(role2)`.  Critical for
RBAC correctness — ensures adding permissions never *removes* access.

```bash
regorus check-monotonicity \
  -d policy.rego \
  -e data.authz.allow \
  -s input_schema.json \
  --privilege-order roles_lattice.json
```

Z3 encodes the subset ordering and checks the implication universally.
If violated, produces a concrete counterexample: "Adding permission X
to role Y causes deny for input {...}".

**Use case:** RBAC correctness audits, ensuring role hierarchies behave
as expected.

### 40. Idempotency & Commutativity

For admission controllers used in at-least-once delivery or distributed
enforcement: prove that applying the same request twice yields the same
state (idempotency), or that request ordering doesn't matter
(commutativity).

```bash
regorus check-idempotent \
  -d policy.rego \
  -e data.admission.allow \
  -s input_schema.json
```

Unrolls two orderings and checks equivalence.  Detects cases where the
policy is order-dependent or non-idempotent.

**Use case:** Distributed admission control, webhook retry safety,
eventual consistency.

---

## Policy Synthesis & Repair

### 41. Policy Repair / CEGIS

Given a policy and a set of failing test cases (input→expected output),
synthesize a *minimal patch* that fixes all failures while preserving
all passing behavior.

```bash
regorus repair \
  -d policy.rego \
  -e data.example.allow \
  --failing-tests tests/failing/ \
  --passing-tests tests/passing/
```

Uses counterexample-guided inductive synthesis: Z3 proposes a constraint
modification, concrete engine verifies, loop until convergent.

**Output:** A suggested patch (rule condition change) that fixes the
failing tests without breaking passing ones.

### 42. Policy Learning / Specification Mining

Given only a set of allow/deny examples (no policy), synthesize the
simplest policy (as a boolean combination of path constraints) consistent
with all examples.

```bash
regorus learn \
  --examples examples.json \
  -s input_schema.json \
  --max-complexity 5
```

Uses Z3's interpolation or quantifier elimination.  The inverse of test
generation.

**Output:** A synthesized Rego rule (or boolean formula over input
fields) that matches all examples.

**Use case:** Reverse-engineering implicit policies from observed
behavior, bootstrapping policy authoring from access logs.

### 43. Policy Simplification

Prove that a simpler rewrite of a rule is semantically equivalent to
the original.  Iterate: propose simplification (merge conditions, remove
redundant checks, collapse nested rules), verify equivalence via Z3,
accept if equivalent.

```bash
regorus simplify \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

**Output:** A semantically equivalent policy with fewer rules, simpler
conditions, or merged branches.  Each simplification step is verified
via Z3 equivalence checking.

**Use case:** Policy refactoring, technical debt reduction, readability
improvements.

---

## Operational / Runtime

### 44. Optimal Cache Key Derivation

Determine the minimal set of input fields that fully determine the
output.  If only 3 of 20 fields matter, you can cache decisions keyed
on those 3 fields.

```bash
regorus cache-key \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

Goes beyond sensitivity analysis (#12) — computes the *minimal
determining set* by iteratively checking if removing a field changes
any decision.

**Output:**
```
Minimal cache key: [input.user.role, input.resource.type, input.action]
Unnecessary fields: [input.user.name, input.request.id, ...]
Cache hit rate estimate: ~94% (based on schema cardinality)
```

**Use case:** High-throughput authorization engines, sidecar proxies,
reducing evaluation latency.

### 45. Policy Partitioning for Parallel Evaluation

Prove that subsets of rules touch disjoint input fields.  Independent
rule groups can be evaluated in parallel or sharded across nodes.

```bash
regorus partition \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

Z3 proves independence by showing the path variable sets are disjoint.

**Output:**
```
Partition 1: [rule_a, rule_b] — depends on input.user.*
Partition 2: [rule_c, rule_d] — depends on input.resource.*
Partition 3: [rule_e]         — depends on both (serial)
```

### 46. Worst-Case Input Discovery

Use Z3 optimization to find the input that maximizes the number of loop
iterations / rule invocations.  The symbolic execution already tracks
loop unrollings and rule call depth per path.

```bash
regorus worst-case \
  -d policy.rego \
  -e data.example.allow \
  -s input_schema.json
```

**Output:** A concrete input that triggers maximum evaluation cost,
plus metrics (loop iterations, rule calls, constraint count).

**Use case:** DoS protection — reject inputs that cause exponential
evaluation.  SLA planning for authorization latency.

### 47. Input Pre-Filter Generation

From the Z3 constraints, extract the *necessary* conditions for permit.
Generate a lightweight runtime filter (as JSON Schema or code) that
rejects any input that is *guaranteed* to be denied, before running the
full policy engine.

```bash
regorus gen-prefilter \
  -d policy.rego \
  -e data.example.allow -o true \
  -s input_schema.json \
  --format json-schema
```

**Output:** A JSON Schema (or Bloom filter spec, or code snippet) that
represents the necessary conditions for `allow=true`.  Inputs failing
the pre-filter are guaranteed to be denied.

**Use case:** Reduces evaluation cost by 80%+ in deny-heavy workloads.

---

## Schema & Data Evolution

### 48. Schema Evolution Safety

Given a schema change (add/remove/rename fields), prove the policy still
behaves correctly: (a) all previously valid inputs produce the same
decision, (b) new fields are handled gracefully (no undefined gaps).

```bash
regorus check-schema-evolution \
  -d policy.rego \
  -e data.example.allow \
  --old-schema schema_v1.json \
  --new-schema schema_v2.json
```

Encodes both schemas and checks behavioral equivalence on their
intersection.

**Output:** "Schema evolution is SAFE: policy behavior is identical for
all inputs valid under both schemas."  Or: "REGRESSION: input {...} is
valid under both schemas but produces different results."

**Use case:** API versioning, schema migration safety gates.

### 49. Abductive Schema Inference

Given a desired property (e.g., "allow=true is always reachable"), find
the *weakest schema constraints* under which the property holds.

```bash
regorus abduce-schema \
  -d policy.rego \
  -e data.example.allow -o true \
  --property reachable
```

Answers: "What's the loosest input contract that keeps this policy
useful?"  Uses Z3 quantifier elimination.

**Output:** A minimal JSON Schema — only the constraints strictly needed
for the property to hold.

**Use case:** Avoid over-constraining input schemas, identify the true
requirements.

### 50. RBAC Role Explosion Analysis

For policies with role-based access, compute the effective permission
set for each role.  Identify roles that are semantically identical
(candidates for merging) and roles that are pure supersets of others
(simplify the hierarchy).

```bash
regorus role-analysis \
  -d policy.rego \
  -e data.authz.allow \
  -s input_schema.json \
  --roles admin,editor,viewer,auditor
```

Each pair costs one Z3 equivalence/subsumption query.

**Output:**
```
role "editor" ≡ role "contributor"  → candidates for merge
role "admin" ⊇ role "editor"       → proper hierarchy
role "auditor" ⊥ role "editor"     → independent permissions
Effective permission sets:
  admin:   {read, write, delete, configure}
  editor:  {read, write}
  auditor: {read, audit-log}
```

---

## Multi-Policy / Ecosystem

### 51. Policy Composition Analysis

When multiple policies combine (`allow = p1 AND p2`, or OPA's decision
merging), analyze emergent properties of the composition that aren't
present in either individual policy.

```bash
regorus check-composition \
  -d policy_a.rego -d policy_b.rego \
  -e data.combined.allow \
  -s input_schema.json
```

Is the composition strictly more restrictive?  Are there interactions
that neither author intended?

**Output:** "Composition is strictly more restrictive than either policy
alone.  Example input permitted by both individually but denied by
composition: {...}"

### 52. Regression Blame

Beyond diff (#1), when a regression is found, trace it to the *specific
rule change* responsible.  Incrementally diff individual rule bodies to
pinpoint which modification introduced the behavior change.

```bash
regorus blame \
  --policy-old policy_v1.rego \
  --policy-new policy_v2.rego \
  -e data.example.allow \
  -s input_schema.json \
  --witness '{"role": "admin", ...}'
```

**Output:** "The regression is caused by the change at policy_v2.rego:47
(condition `input.mfa == true` was added to rule `allow_admin`).  This
rule previously permitted the witness input but now denies it."

### 53. Compliance Template Library

Define reusable compliance properties as parameterized Z3 templates
(RBAC invariants, SOX separation-of-duty, HIPAA access rules, K8s
pod-security-standards).

```bash
regorus comply \
  --template hipaa-access \
  -d policy.rego \
  -e data.authz.allow \
  -s input_schema.json \
  --params template_params.json
```

Each template is a pre-built Z3 formula instantiated against the
policy's symbolic encoding.

**Output:** "HIPAA access control: 4/5 properties PASS, 1 FAIL:
  FAIL: Minimum Necessary — role `receptionist` can access
  `resource.type=medical_record` (counterexample: {...})"

**Use case:** Compliance-as-code, audit automation, regulatory checks.

---

## Kubernetes / Cloud-Specific

### 54. Admission Controller Completeness

For K8s admission policies, prove every possible API request is
explicitly handled (allowed or denied).  No request should produce
"undefined".

```bash
regorus check-completeness \
  -d admission_policy.rego \
  -e data.admission.allow \
  -s k8s_admission_schema.json
```

Encodes the K8s API resource schema and checks totality.

**Output:** "Policy is INCOMPLETE: Pod spec with
`securityContext.runAsNonRoot=null` produces undefined.  Suggested fix:
add default rule."

### 55. Network Policy Reachability

For K8s NetworkPolicy or cloud security groups encoded as Rego, prove
reachability: "Can pod A reach pod B on port 443?" or "Is there *any*
path from the internet to the database?"

```bash
regorus net-reach \
  -d network_policy.rego \
  -e data.network.allowed \
  --source "namespace=frontend,app=web" \
  --dest "namespace=backend,app=database" \
  --port 5432
```

Each query is a satisfiability check on the symbolic network graph.

**Output:** "REACHABLE: frontend/web → backend/database:5432 via:
  1. NetworkPolicy `allow-backend` permits namespace=frontend
  2. No egress policy blocks port 5432"
Or: "UNREACHABLE: blocked by NetworkPolicy `deny-database-direct`
at line 23."

**Use case:** Network segmentation verification, zero-trust audits,
compliance checks.

### 56. Resource Quota Feasibility

For admission controllers enforcing resource limits, use Z3 optimization
to determine whether any valid workload configuration exists within the
combined constraints.

```bash
regorus check-feasibility \
  -d quota_policy.rego \
  -e data.admission.allow \
  -s pod_schema.json \
  --constraints "namespace=production"
```

"Is it possible to deploy a pod that satisfies all quotas, limits, and
policies simultaneously?"

**Output:** "FEASIBLE: minimal pod spec that satisfies all constraints:
{cpu: 100m, memory: 128Mi, replicas: 1}"
Or: "INFEASIBLE: resource quota (max 4Gi memory) conflicts with
min-memory policy (requires 8Gi for gpu workloads)."

---

## Quantitative Information Theory

### 57. Quantitative Information Leakage

For policies that shouldn't reveal too much about their inputs through
their outputs (e.g., "the deny reason shouldn't let you reconstruct
the ACL"), use Z3's model counting (or approximate counting via `#SAT`)
to estimate how many bits of input information are leaked by each
distinct output.

```bash
regorus info-leakage \
  -d policy.rego \
  -e data.example.deny_reason \
  -s input_schema.json \
  --sensitive input.user.role,input.user.groups
```

This goes far beyond non-interference (#37) — it *quantifies* the
leakage rather than just detecting it.

**Output:**
```
Output value "insufficient_role"  → leaks ~2.3 bits about input.user.role
Output value "group_not_permitted" → leaks ~4.1 bits about input.user.groups
Output value "denied"             → leaks ~0.1 bits (safe)
Total max leakage: 4.1 bits
```

**Use case:** Privacy-sensitive authorization, GDPR compliance for
error messages, zero-knowledge policy design.

---

## Priority Assessment

### Tier 1 — High impact, near-term (builds directly on existing infra)

| # | Idea | Why |
|---|---|---|
| 1 | Policy diff | Direct CI value, simple XOR encoding |
| 6 | Dead code detection | Low-hanging fruit, iterates over rule bodies |
| 10 | UNSAT core / "why not" | Z3 has `unsat_core()` built in |
| 7 | Test suite generation | Natural extension of path enumeration |
| 31 | CI guard | Thin wrapper around existing analyze |

### Tier 2 — Medium effort, high value

| # | Idea | Why |
|---|---|---|
| 4 | Default-deny verification | Important safety property |
| 12 | Sensitivity analysis | Deep policy understanding |
| 14 | Quantitative bounds | Z3 Optimize is ready to use |
| 15 | Counterexample minimization | Better UX for existing feature |
| 19 | Forbid reachability (Cedar) | Cedar-specific high value |
| 24 | Schema inference | Removes manual schema authoring |

### Tier 3 — Significant effort, research-oriented

| # | Idea | Why |
|---|---|---|
| 3 | Cross-language equivalence | Requires cross-compilation |
| 17 | Entity graph synthesis | Hard combinatorics |
| 25 | Full CEGAR | Research-level loop |
| 26 | Partial evaluation + Z3 | Architectural change |
| 28 | Bounded model checking | Multi-step state encoding |
| 29 | Temporal analysis | State machine modeling |

### Tier 4 — New ideas: High impact, moderate effort

| # | Idea | Why |
|---|---|---|
| 37 | Non-interference | Privacy audits, straightforward 2-copy encoding |
| 38 | Separation of duty | Compliance requirement, simple conjunction check |
| 44 | Cache key derivation | Direct runtime performance gain |
| 46 | Worst-case input | DoS protection, uses existing Z3 Optimize |
| 47 | Input pre-filter generation | Reduces evaluation cost, schema extraction |
| 48 | Schema evolution safety | API versioning gate, reuses diff infra |
| 50 | RBAC role analysis | Reuses subsumption/equivalence queries |
| 52 | Regression blame | Extends existing diff with rule-level granularity |
| 54 | Admission controller completeness | K8s-specific, totality check |

### Tier 5 — New ideas: Significant effort, research-oriented

| # | Idea | Why |
|---|---|---|
| 39 | Monotonicity / lattice | Requires privilege ordering model |
| 40 | Idempotency / commutativity | Multi-copy state encoding |
| 41 | Policy repair (CEGIS) | Synthesis loop, complex |
| 42 | Policy learning | Interpolation / quantifier elimination |
| 43 | Policy simplification | Iterative equivalence + rewriting |
| 45 | Policy partitioning | Dependency graph analysis |
| 49 | Abductive schema inference | Quantifier elimination |
| 51 | Composition analysis | Multi-policy symbolic merge |
| 53 | Compliance templates | Library design + parameterization |
| 55 | Network policy reachability | Graph encoding in SMT |
| 56 | Resource quota feasibility | Optimization + constraint interplay |
| 57 | Quantitative info leakage | Model counting (#SAT), hardest |
