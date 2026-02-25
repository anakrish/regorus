# Policy Intelligence — Presentation Diagrams

> Mermaid diagrams showcasing formal analysis capabilities for inclusion in PowerPoint.
> Each diagram has a `.mmd` source file and a `.png` rendered image.

---

## Slide Deck Order

### 1. Overview — From Policies to Proven Guarantees
**File:** `01-overview.mmd` / `01-overview.png`

The big picture: access control policies + schema go in, four types of guarantees come out — auto-generated tests, change impact analysis, root cause explanations, and compliance proofs.

![01-overview](01-overview.png)

---

### 2. The Problem — Manual Testing vs. Automated Generation
**File:** `02-auto-test-generation.mmd` / `02-auto-test-generation.png`

Side-by-side contrast: manual testing (misses edge cases, leaves security gaps) vs. the engine automatically finding all decision paths and generating a minimal test suite with full coverage.

![02-auto-test-generation](02-auto-test-generation.png)

---

### 3. Safe Policy Migration — Prove Equivalence Before Deploying
**File:** `03-safe-policy-migration.mmd` / `03-safe-policy-migration.png`

When refactoring policies, the diff analysis either proves mathematical equivalence (safe to deploy) or surfaces the exact input where behavior diverges. Fix-and-re-verify loop.

![03-safe-policy-migration](03-safe-policy-migration.png)

---

### 4. "Why Denied?" — Root Cause Analysis
**File:** `04-why-denied.mmd` / `04-why-denied.png`

When a request is denied, MAX-SAT analysis pinpoints the minimal set of failing conditions and provides actionable insight (which specific condition failed and what to do about it).

![04-why-denied](04-why-denied.png)

---

### 5. Compliance Proofs — Mathematical Guarantees
**File:** `05-compliance-proofs.mmd` / `05-compliance-proofs.png`

Three common compliance questions ("Can anything bypass this?", "Is the new policy tighter?", "Any dead rules?") answered with mathematical proofs — not just tested, but **proven**.

![05-compliance-proofs](05-compliance-proofs.png)

---

### 6. MC/DC Condition Coverage — Aviation-Grade Testing
**File:** `06-mcdc-condition-coverage.mmd` / `06-mcdc-condition-coverage.png`

Shows how MC/DC (Modified Condition/Decision Coverage) works: for each condition in a rule, the engine generates a pair of test inputs that flip **only that condition** while holding others constant. This is the same standard used in safety-critical software (DO-178C for avionics). Applied to the real `applicable` rule from the AGS policy.

![06-mcdc-condition-coverage](06-mcdc-condition-coverage.png)

---

### 7. Real Policy Example — Decision Tree
**File:** `07-policy-decision-tree.mmd` / `07-policy-decision-tree.png`

The actual Azure Graph Service group governance policy visualized as a decision tree with 5 distinct paths: allowed app bypass, enforced deny, reportOnly audit, expected HTTP errors (403/404), and fail-closed on unexpected errors.

![07-policy-decision-tree](07-policy-decision-tree.png)

---

### 8. Real Results — 23 Tests, 100% Coverage
**File:** `08-real-results.mmd` / `08-real-results.png`

Concrete results from running the engine on the AGS group governance policy: 34/34 lines covered (100%), 46/46 condition goals covered (100% MC/DC), 23 test cases auto-generated — with sample inputs color-coded by outcome (deny = red, allow = green).

![08-real-results](08-real-results.png)

---

## Color Coding (consistent across all diagrams)

| Color | Meaning |
|-------|---------|
| 🔵 Blue | Inputs / questions |
| 🟠 Orange | Analysis engine |
| 🟢 Green | Positive outcomes / passing |
| 🔴 Red | Problems / denials / failures |
| 🟡 Yellow | Warnings / differences found |
| 🟣 Purple | Fix / iterative actions |

## Usage Notes

- All diagrams use **left-to-right (LR)** layout for landscape/wide PowerPoint slides
- Font sizes are 14-16px for readability at presentation scale
- To re-render: open any `.mmd` file in a Mermaid-compatible viewer or use `mmdc` CLI
- For PowerPoint: use the `.png` files directly or paste the Mermaid source into a live renderer
