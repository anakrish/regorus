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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A single equality atom: `input_path == scalar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqAtom {
    pub input_path: String,
    pub scalar: LiftScalar,
}

/// A comparison atom over a typed scalar field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmpAtom {
    pub input_path: String,
    pub op: CmpOp,
    pub scalar: LiftScalar,
    pub missing_matches: bool,
}

/// A membership atom. `input_path in values` when `values` is non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipAtom {
    pub input_path: String,
    pub values: Vec<LiftScalar>,
}

/// CIDR containment over an IP string field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrAtom {
    pub input_path: String,
    pub network: String,
    pub prefix_len: u8,
    pub family: IpFamily,
    pub negated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Prefix/suffix byte-string atom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixAtom {
    pub input_path: String,
    pub pattern: String,
    pub kind: PrefixKind,
    pub negated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixKind {
    StartsWith,
    EndsWith,
}

/// Field-presence atom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistsAtom {
    pub input_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Atom {
    Eq(EqAtom),
    Cmp(CmpAtom),
    Membership(MembershipAtom),
    Cidr(CidrAtom),
    Prefix(PrefixAtom),
    Exists(ExistsAtom),
}

impl Atom {
    pub fn input_path(&self) -> &str {
        match self {
            Atom::Eq(atom) => &atom.input_path,
            Atom::Cmp(atom) => &atom.input_path,
            Atom::Membership(atom) => &atom.input_path,
            Atom::Cidr(atom) => &atom.input_path,
            Atom::Prefix(atom) => &atom.input_path,
            Atom::Exists(atom) => &atom.input_path,
        }
    }
}

/// A conjunction (AND) of atoms. A request satisfying every atom matches the
/// clause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub atoms: Vec<Atom>,
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
