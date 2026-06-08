# LLM × Policy Intelligence — Synergy Ideas

How LLM-based policy authoring and Z3 symbolic analysis can work together.

## 1. LLM Generates → Policy Intelligence Validates

User describes intent in natural language → LLM produces Rego/Cedar → Z3 checks it.

- **Counterexample surfacing**: "Here's an input the LLM's policy would allow — did you intend that?"
- **Vacuity detection**: Z3 proves no input can ever satisfy the policy → dead code.
- **Over-permissiveness detection**: Synthesize an input that gets `allow = true` but violates an unstated constraint.

## 2. Policy Intelligence Generates → LLM Explains

Z3 produces formal artifacts that are hard for humans to parse.

- **Counterexample narration**: Z3 synthesizes `{"user":{"role":"intern",...},"request":{"hour":3}}` → LLM explains: "An unsuspended intern can access the system at 3 AM because there's no business-hours check for interns."
- **Diff explanation**: Z3 finds where two policy versions diverge → LLM narrates the semantic difference in business terms.
- **Subsumption explanation**: Z3 proves policy A subsumes B → LLM explains why in terms of which rules are strictly more permissive.
- **Test case narration**: Z3 generates a test suite → LLM annotates each test with the business scenario it exercises.

## 3. Iterative Refinement Loop (Human-in-the-Loop)

A multi-turn cycle where both engines collaborate:

1. **User** states intent in natural language
2. **LLM** generates candidate policy
3. **Z3** synthesizes edge-case inputs (both allow and deny)
4. **LLM** narrates each edge case in plain English
5. **User** flags which edge cases are wrong → these become new constraints
6. **LLM** revises the policy incorporating the new constraints
7. **Z3** re-analyzes → loop until no surprises

Key insight: Z3 is an *exhaustive adversary* — it finds worst-case inputs that the LLM (and often the human) miss.

## 4. Policy Intelligence Steers LLM Generation

Use Z3 results *as part of the LLM prompt*:

- **Schema-guided generation**: Feed the input JSON Schema to the LLM so it knows what fields exist — same schema Z3 uses for bounded analysis.
- **Counterexample-driven prompting**: After Z3 finds a bad input, include it in the LLM prompt: "The current policy allows this input, but it shouldn't. Fix the policy."
- **Coverage-gap prompting**: Z3 identifies uncovered code paths → LLM is asked to add rules that exercise those paths.
- **Condition-aware repair**: Z3's MC/DC condition analysis reveals which boolean sub-expressions are untested → feed these to LLM for targeted rule additions.

## 5. LLM as Intent Specification → Z3 as Formal Contract

Separate intent from implementation:

- **Intent predicates**: LLM translates NL into a set of (input, expected_output) pairs or invariants — not the policy itself. Z3 checks whether a candidate policy satisfies all invariants.
- **Specification synthesis**: User describes "managers can always access" → LLM generates a specification (∀ input where role=manager: allow=true). Z3 checks the actual policy against this spec via subsumption.
- **Bidirectional verification**: LLM generates both the policy and a natural-language spec. Z3 checks them against each other. Discrepancies mean the LLM contradicted itself.

## 6. Policy Repair & Patching

When Z3 finds a flaw, LLM can fix it surgically:

- **Minimal patch generation**: Z3 identifies the specific path condition that leads to a violation. LLM generates a targeted fix rather than rewriting the whole policy.
- **Regression-safe repair**: After LLM patches the policy, Z3 runs a diff against the original to confirm the fix doesn't break existing correct behavior.

## 7. Multi-Policy Coherence

For organizations with many policies:

- **Cross-policy conflict detection**: Z3 finds inputs where Policy A allows but Policy B denies. LLM explains the business conflict.
- **Policy consolidation**: LLM merges overlapping policies; Z3 verifies the merged policy is equivalent to the union of originals.
- **Layered authoring**: User describes high-level rules; LLM generates per-service policies; Z3 proves each conforms to the organizational rules.

## 8. Natural Language Querying of Existing Policies

Not authoring — understanding:

- **"Can an intern access production on weekends?"** → LLM translates to a Z3 query. Z3 answers definitively yes/no with a concrete example.
- **"What's the difference between v1 and v2?"** → Z3 diff produces the divergence inputs → LLM summarizes in business English.
- **"Is this policy HIPAA-compliant?"** → LLM generates HIPAA-derived invariants as Z3 specs → Z3 checks each one.

## 9. Test Suite as Living Documentation

- **Z3 generates minimal test suites** → LLM annotates each test as a BDD-style scenario.
- **Regression narration**: When a policy change causes test failures, LLM explains which business scenarios broke.

## 10. Confidence Scoring & Provenance

- **LLM confidence + Z3 certainty**: LLM says "I'm 70% sure." Z3 then either proves correctness (100%) or finds a counterexample (0%).
- **Explainable provenance**: For each rule, LLM cites which NL requirement it addresses. Z3 confirms each rule is reachable.

---

**Recurring theme**: LLMs are good at *translation* (NL ↔ code) but unreliable for *correctness*. Z3 is perfect for *correctness* but terrible at *explanation*. Together they form a closed loop: **LLM translates, Z3 verifies, LLM explains, human decides, repeat.**
