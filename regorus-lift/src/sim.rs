//! A faithful user-space simulator of the fixed kernel enforcer.
//!
//! Given an [`EnforcerConfig`] and a concrete input (as `serde_json::Value`,
//! the way a kernel hook would present extracted fields), this reproduces the
//! verdict the kernel enforcer would return — *without* a kernel. It exists so
//! the lift can be conformance-tested against full RVM evaluation, asserting the
//! soundness property `sim_allow ⟹ rvm_allow` (no over-permission).
//!
//! Fail-closed ABI: anything not provably `Allow` is `Deny`.

use crate::ir::{Clause, EnforcerConfig, LiftScalar, Verdict};

/// Simulate the enforcer for `input`.
pub fn simulate(config: &EnforcerConfig, input: &serde_json::Value) -> Verdict {
    if let Some(v) = config.static_verdict {
        return v;
    }
    for clause in &config.allow_clauses {
        if clause_matches(clause, input) {
            return Verdict::Allow;
        }
    }
    // Fail closed.
    Verdict::Deny
}

fn clause_matches(clause: &Clause, input: &serde_json::Value) -> bool {
    clause.atoms.iter().all(|atom| {
        match extract_scalar(input, &atom.input_path) {
            Some(actual) => actual == atom.scalar,
            // Missing field cannot satisfy an equality — fail closed.
            None => false,
        }
    })
}

/// Extract the scalar at a dotted `input_path` (e.g. `input.dest_ip`) from a
/// concrete input object. The leading `input` segment is stripped because the
/// concrete input *is* the input object.
pub fn extract_scalar(input: &serde_json::Value, input_path: &str) -> Option<LiftScalar> {
    let mut cur = input;
    for (i, seg) in input_path.split('.').enumerate() {
        if i == 0 && seg == "input" {
            continue;
        }
        cur = cur.get(seg)?;
    }
    LiftScalar::from_json(cur)
}
