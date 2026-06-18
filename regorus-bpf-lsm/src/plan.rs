// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lower a [`regorus_lift::EnforcerConfig`] into a [`FilePlan`] for the fixed
//! `lsm/file_open` access enforcer.
//!
//! Each lift allow-clause (a conjunction of atoms) becomes one or more
//! [`FileRule`] rows. A field with no constraining atom is a **wildcard**
//! (`Any`), so the full conjunction — including unconstrained fields — is
//! preserved exactly; nothing is dropped or cross-producted across disjuncts.
//!
//! Only two fields are observable on this hook:
//!
//! - `input.path` accepts `Eq` / `Membership` of exact path strings and a
//!   non-negated `Prefix(StartsWith)` (lowered to [`PathMatch::Prefix`]).
//! - `input.op` accepts `Eq` / `Membership` of the strings `read`/`write`/`exec`.
//!
//! Anything this hook cannot represent makes the **whole clause** non-lowerable,
//! and the clause is dropped from the plan:
//!
//! - a non-observable field, or a second atom on the same field,
//! - a negated prefix, or an `EndsWith` / `Contains` prefix (the fixed kernel
//!   program cannot do suffix/substring matching soundly — only a leading-byte
//!   prefix scan — so these are dropped, not approximated),
//! - an unknown `op` string, or any non-`Eq`/`Membership`/`StartsWith` atom.
//!
//! Dropping an allow clause can only remove allows, never add them —
//! fail-closed. A `Membership` expands to a bounded cross-product (bounded by
//! [`MAX_RULES`]); an overflow rejects the clause.

use regorus_lift::ir::{Atom, Clause, EnforcerConfig, LiftScalar, PrefixKind};

use crate::abi::{FieldId, FileOp, Verdict, MAX_RULES};

/// `input.path` match: wildcard, an exact path, or a leading-byte prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathMatch {
    Any,
    Exact(String),
    Prefix(String),
}

/// `input.op` match: wildcard or an exact operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpMatch {
    Any,
    Exact(FileOp),
}

/// One compiled allow rule: a full conjunction over the two hook fields. A
/// request matches iff every field matches (a wildcard matches anything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRule {
    pub path_match: PathMatch,
    pub op_match: OpMatch,
}

/// The concrete plan consumed by the enforcer. `static_verdict`, when set,
/// determines the verdict independent of any request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePlan {
    pub static_verdict: Option<Verdict>,
    pub rules: Vec<FileRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportError {
    /// The lowered rule table would exceed [`MAX_RULES`]; the plan is not
    /// exported (the caller must route to user-space RVM). Fail-closed.
    TooManyRules { needed: usize, max: usize },
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::TooManyRules { needed, max } => {
                write!(f, "lowered rule table needs {needed} rows but the fixed enforcer holds at most {max}")
            }
        }
    }
}

impl std::error::Error for ExportError {}

/// Lower an [`EnforcerConfig`] into a [`FilePlan`].
pub fn export(config: &EnforcerConfig) -> Result<FilePlan, ExportError> {
    if let Some(v) = config.static_verdict {
        return Ok(FilePlan {
            static_verdict: Some(map_verdict(v)),
            rules: Vec::new(),
        });
    }

    let mut rules = Vec::new();
    for clause in &config.allow_clauses {
        // A non-lowerable clause is dropped (fail-closed). Only fully
        // representable clauses contribute allow rules.
        if let Some(entries) = lower_clause(clause) {
            rules.extend(entries);
        }
    }

    if rules.len() > MAX_RULES {
        return Err(ExportError::TooManyRules {
            needed: rules.len(),
            max: MAX_RULES,
        });
    }

    Ok(FilePlan {
        static_verdict: None,
        rules,
    })
}

fn map_verdict(v: regorus_lift::Verdict) -> Verdict {
    match v {
        regorus_lift::Verdict::Allow => Verdict::Allow,
        regorus_lift::Verdict::Deny => Verdict::Deny,
        regorus_lift::Verdict::Undecided => Verdict::Undecided,
    }
}

/// Lower a single conjunction clause to one or more [`FileRule`] rows, or
/// `None` if any atom is not representable by this hook (reject the clause).
fn lower_clause(clause: &Clause) -> Option<Vec<FileRule>> {
    // Alternatives per field. `None` = no constraining atom yet (wildcard).
    let mut path_alts: Option<Vec<PathMatch>> = None;
    let mut op_alts: Option<Vec<OpMatch>> = None;

    for atom in &clause.atoms {
        let field = FieldId::from_input_path(atom.input_path())?; // non-observable -> reject
        match field {
            FieldId::Path => {
                if path_alts.is_some() {
                    return None; // two atoms on the same field -> reject (fail-closed)
                }
                path_alts = Some(lower_path_atom(atom)?);
            }
            FieldId::Op => {
                if op_alts.is_some() {
                    return None;
                }
                op_alts = Some(lower_op_atom(atom)?);
            }
        }
    }

    let path_alts = path_alts.unwrap_or_else(|| vec![PathMatch::Any]);
    let op_alts = op_alts.unwrap_or_else(|| vec![OpMatch::Any]);

    // Bounded cross-product across the per-field alternatives.
    let product = path_alts.len().checked_mul(op_alts.len())?;
    if product > MAX_RULES {
        return None; // explosion -> reject clause (fail-closed)
    }
    let mut entries = Vec::with_capacity(product);
    for path_match in &path_alts {
        for &op_match in &op_alts {
            entries.push(FileRule {
                path_match: path_match.clone(),
                op_match,
            });
        }
    }
    Some(entries)
}

fn lower_path_atom(atom: &Atom) -> Option<Vec<PathMatch>> {
    match atom {
        Atom::Eq(eq) => Some(vec![PathMatch::Exact(scalar_to_string(&eq.scalar)?)]),
        Atom::Membership(m) => {
            let mut out = Vec::with_capacity(m.values.len());
            for v in &m.values {
                out.push(PathMatch::Exact(scalar_to_string(v)?));
            }
            (!out.is_empty()).then_some(out)
        }
        Atom::Prefix(p) => {
            // Only a non-negated leading-byte prefix is representable by the
            // fixed kernel program. EndsWith/Contains require suffix/substring
            // matching the program cannot do soundly -> reject (fail-closed).
            if p.negated || p.kind != PrefixKind::StartsWith {
                return None;
            }
            if p.pattern.is_empty() {
                return None; // an empty prefix matches everything -> reject for safety
            }
            Some(vec![PathMatch::Prefix(p.pattern.clone())])
        }
        _ => None,
    }
}

fn lower_op_atom(atom: &Atom) -> Option<Vec<OpMatch>> {
    match atom {
        Atom::Eq(eq) => Some(vec![OpMatch::Exact(scalar_to_op(&eq.scalar)?)]),
        Atom::Membership(m) => {
            let mut out = Vec::with_capacity(m.values.len());
            for v in &m.values {
                out.push(OpMatch::Exact(scalar_to_op(v)?));
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

fn scalar_to_string(scalar: &LiftScalar) -> Option<String> {
    match scalar {
        LiftScalar::Str(s) => Some(s.clone()),
        _ => None,
    }
}

fn scalar_to_op(scalar: &LiftScalar) -> Option<FileOp> {
    match scalar {
        LiftScalar::Str(s) => FileOp::from_name(s),
        _ => None,
    }
}
