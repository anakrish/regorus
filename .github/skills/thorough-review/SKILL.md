---
name: thorough-review
description: >-
  Multi-agent thorough code review for regorus. Use this skill when asked to
  do a thorough review, deep review, or comprehensive review of code changes.
  Orchestrates parallel focused reviewers with adversarial defense filtering.
allowed-tools: shell
---

# Thorough Review Skill

You orchestrate a deep code review of regorus changes by launching parallel
focused reviewers, each with a different focus area. regorus is a
security-critical policy engine — behavioral bugs are security bugs.

**Do not** run cargo, clippy, tests, or build commands. This skill is
diff-review only.

## Step 1: Get the Diff

```bash
git diff $(git merge-base origin/main HEAD)..HEAD --stat
git diff $(git merge-base origin/main HEAD)..HEAD
```

If that fails, try `git diff main` then `git diff HEAD~1`.
If the diff is large (>500 lines), get the stat first and focus reviewers on
relevant files rather than the full diff.

## Step 2: Select Focus Areas

**Always run these 3:**

| # | Focus | Description |
|---|-------|-------------|
| 1 | Semantic Correctness | Wrong allow/deny, Undefined propagation, three-valued logic, `with` scoping, dual-path consistency. For non-Rego languages: language-specific evaluation semantics (effects, aliases, conditions). |
| 2 | Panic Safety | unwrap/indexing/overflow bypasses that deny lints can't catch statically, logic-dependent panic paths, fallible conversions without error handling. |
| 3 | Resource Exhaustion | Unbounded loops, recursion, allocation growth, complexity bombs on untrusted input, missing limit checks. |

**Add these when triggered by changed files:**

| # | Focus | Description | Triggers |
|---|-------|-------------|----------|
| 4 | API & FFI | Semver breaks, panic containment across 9 bindings, handle safety, null checks, UTF-8/ABI. | `src/engine.rs`, `bindings/**`, public type changes |
| 5 | Feature Composition | `#[cfg]` correctness, no_std leakage, missing feature gates, non-default build combos. | `Cargo.toml`, files with `#[cfg(feature` |
| 6 | Input & Encoding | Parser limits, injection, malformed UTF-8, path traversal, bundle decoding. | `src/lexer*`, `src/parser*`, `src/builtins/**` |
| 7 | Supply Chain & CI | Unpinned actions, expression injection, new deps without audit, lockfile drift. | `.github/**`, `Cargo.toml` deps, lockfiles |

Look at the diff's file list. Activate triggered areas whose patterns match.
In `thorough` mode (default), activate ALL areas regardless of triggers.

## Step 3: Launch Parallel Reviewers

For each selected focus area, launch a **task agent** (agent_type: "rubber-duck")
in background mode with this prompt (fill in the blanks):

> Review this regorus diff for **{focus area name}** issues:
> **{one-line description from table above}**
>
> Context: regorus is a security-critical policy evaluation engine (Rego + Azure
> Policy). `#![no_std]`, `#![forbid(unsafe_code)]`, 80+ deny lints, 9 FFI targets,
> dual execution paths (interpreter + RVM).
>
> Relevant knowledge: `docs/knowledge/{relevant file}` — read it if you need
> domain-specific invariants.
>
> Here are the changed files:
> {file list from --stat}
>
> Here is the diff (or relevant hunks if large):
> ```
> {diff content — for large diffs, include only hunks relevant to this focus}
> ```
>
> Find real bugs with code evidence. No vague concerns. If you find nothing
> noteworthy, say so.

For large diffs (>500 lines), split the diff by relevance — each reviewer gets
only the hunks/files relevant to their focus area rather than the full diff.

**Knowledge file mapping** (suggest the most relevant one per focus):
- Semantic Correctness → `rego-semantics.md`, `value-semantics.md`, `azure-policy-language.md`
- Panic Safety → `ffi-boundary.md`, `error-handling-migration.md`
- Resource Exhaustion → `policy-evaluation-security.md`
- API & FFI → `ffi-boundary.md`, `engine-api.md`
- Feature Composition → `feature-composition.md`
- Input & Encoding → `policy-evaluation-security.md`, `compilation-pipeline.md`
- Supply Chain & CI → `workflow-security.md`

Launch ALL reviewers in parallel using the task tool (rubber-duck agent type).

## Step 4: Defense

After all reviewers report back, challenge **Critical and High** findings:

For each Critical/High finding, ask yourself:
- Is the code path actually reachable with untrusted input?
- Does an existing guard (limit check, type constraint, deny lint) already prevent this?
- Is the "fix" obvious, or is this a design-level issue?

Downgrade or drop findings that fail this check. When downgrading or dropping,
name the exact guard or constraint that makes the issue unreachable or contained.
Keep findings that survive.

## Step 5: Report

Present findings sorted by severity (Critical → High → Medium → Low):

For each finding:
- **Severity**: Critical / High / Medium / Low
- **Focus area**: which reviewer found it
- **Location**: file:line
- **Issue**: one-sentence summary
- **Evidence**: the specific code and why it's wrong
- **Suggestion**: how to fix (if obvious)

End with a summary: X findings (N critical, N high, N medium, N low).

## Modes

- **`thorough`** (default): All 7 focus areas, full defense phase
- **`quick`**: Only the 3 always-run areas, skip defense for medium/low findings
