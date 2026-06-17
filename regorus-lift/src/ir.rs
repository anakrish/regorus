//! The enforcer-config intermediate representation produced by [`crate::lift`].
//!
//! This is a user-space, kernel-agnostic representation. A later backend lowers
//! it into concrete BPF maps + a fixed enforcer program; the [`crate::sim`]
//! module evaluates it directly for conformance testing.

use std::collections::BTreeMap;

use regorus::Value;

use crate::schema::FieldType;

/// Enforcement verdict. Fail-closed ABI: `Undecided` collapses to `Deny` at the
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Deny = 0,
    Allow = 1,
    Undecided = 2,
}

/// A lowerable scalar value, in a fixed-width-friendly representation suitable
/// for a kernel map key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiftScalar {
    Str(String),
    Bool(bool),
    Int(i64),
    Uint(u64),
}

impl LiftScalar {
    /// Build a scalar from a Regorus [`Value`], or `None` if the value is not a
    /// lowerable scalar (e.g. object/array/null/float/out-of-range number).
    pub fn from_value(value: &Value) -> Option<Self> {
        match serde_json::to_value(value).ok()? {
            serde_json::Value::String(s) => Some(LiftScalar::Str(s)),
            serde_json::Value::Bool(b) => Some(LiftScalar::Bool(b)),
            serde_json::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Some(LiftScalar::Uint(u))
                } else {
                    n.as_i64().map(LiftScalar::Int)
                }
            }
            _ => None,
        }
    }

    /// Build a scalar from a `serde_json` value (used by the simulator when
    /// extracting concrete input fields).
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        match value {
            serde_json::Value::String(s) => Some(LiftScalar::Str(s.clone())),
            serde_json::Value::Bool(b) => Some(LiftScalar::Bool(*b)),
            serde_json::Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Some(LiftScalar::Uint(u))
                } else {
                    n.as_i64().map(LiftScalar::Int)
                }
            }
            _ => None,
        }
    }

    pub fn field_type(&self) -> FieldType {
        match self {
            LiftScalar::Str(_) => FieldType::Str,
            LiftScalar::Bool(_) => FieldType::Bool,
            LiftScalar::Int(_) => FieldType::Int,
            LiftScalar::Uint(_) => FieldType::Uint,
        }
    }
}

/// A single equality atom: `input_path == scalar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqAtom {
    pub input_path: String,
    pub scalar: LiftScalar,
}

/// A conjunction (AND) of atoms. A request satisfying every atom matches the
/// clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub atoms: Vec<EqAtom>,
}

/// The lifted enforcement configuration.
///
/// Semantics: a request is `Allow` if it matches **any** [`Clause`] (the OR of
/// the lifted allow-disjuncts) or if `static_verdict` is `Allow`; otherwise the
/// enforcer falls back per the fail-closed ABI.
#[derive(Debug, Clone)]
pub struct EnforcerConfig {
    /// Observable fields referenced by the clauses (input_path -> type).
    pub fields: BTreeMap<String, FieldType>,
    /// Allow clauses (OR of ANDs).
    pub allow_clauses: Vec<Clause>,
    /// A fully-determined verdict independent of input, if any.
    pub static_verdict: Option<Verdict>,
}

impl EnforcerConfig {
    pub fn new(fields: BTreeMap<String, FieldType>, allow_clauses: Vec<Clause>) -> Self {
        Self {
            fields,
            allow_clauses,
            static_verdict: None,
        }
    }

    pub fn with_static(verdict: Verdict) -> Self {
        Self {
            fields: BTreeMap::new(),
            allow_clauses: Vec::new(),
            static_verdict: Some(verdict),
        }
    }
}
