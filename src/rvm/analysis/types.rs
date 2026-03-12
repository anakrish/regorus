// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core symbolic types for RVM symbolic translation.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use regorus_smt::SmtExpr;

use crate::value::Value;

/// The sort (type) of a symbolic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSort {
    Bool,
    Int,
    Real,
    String,
    Unknown,
}

/// A symbolic value: either a concrete Rego `Value` or an SMT expression.
/// An element of a symbolically-modeled partial set.
///
/// Each element represents one potential member of the set, gated by a Z3
/// condition (the body succeeded for this iteration witness).  The
/// `element_path` is the access path of the iteration variable at the
/// point the element was added (e.g. `"input.servers[0]"`) — this is
/// what consumers use when iterating over the set.  The `key_path` is
/// the path of the actual set key (e.g. `"input.servers[0].id"` for
/// `violation contains server.id`) — this determines set membership and
/// deduplication for cardinality counting.
#[derive(Debug, Clone)]
pub struct SymSetElement {
    /// Under what condition this element is present in the set.
    pub condition: SmtExpr,
    /// Access path of the iteration variable (e.g. `"input.servers[0]"`).
    /// Used when the set is iterated by a consumer loop.
    pub element_path: std::string::String,
    /// Access path of the set KEY value (e.g. `"input.servers[0].id"`).
    /// Used for deduplication when computing cardinality — elements with
    /// the same key_path are grouped and counted as at most 1.
    pub key_path: std::string::String,
    /// Z3 sort of the element.
    pub element_sort: ValueSort,
}

/// An entry in a symbolically-modeled object (map from symbolic keys to
/// symbolic values).  Each entry represents one `key := value` assignment
/// from an object rule or comprehension iteration, gated by a Z3 condition.
#[derive(Debug, Clone)]
pub struct SymObjectEntry {
    /// Source path of the key (e.g., `"input.services[0].name"`).
    pub key_path: std::string::String,
    /// Source path of the value (e.g., `"input.services[0].zone_id"`).
    pub value_path: std::string::String,
    /// The sort of the value, if known.
    pub value_sort: ValueSort,
    /// Path condition under which this entry is active.
    pub condition: SmtExpr,
}

/// An element of a symbolically-modeled array.
///
/// Unlike `SymSetElement`, this preserves per-element symbolic values and
/// ordering—critical for positional access (`arr[i]`) and for builtins
/// like `sprintf` that consume array elements by index.
#[derive(Debug, Clone)]
pub struct SymArrayElement {
    /// The symbolic value of this element.
    pub value: SymValue,
    /// The definedness of this element.
    pub defined: Definedness,
    /// Optional source path (e.g., `"input.user.name"`).
    pub source_path: Option<std::string::String>,
}

#[derive(Debug, Clone)]
pub enum SymValue {
    /// A fully-known concrete value.
    Concrete(Value),
    /// A symbolic boolean (Z3 Bool sort).
    Bool(SmtExpr),
    /// A symbolic integer (Z3 Int sort).
    Int(SmtExpr),
    /// A symbolic real number (Z3 Real sort).
    Real(SmtExpr),
    /// A symbolic string (Z3 String sort).
    Str(SmtExpr),
    /// A symbolic set whose cardinality is represented by a Z3 Int.
    /// Produced by partial set rule calls — the Int encodes how many
    /// elements the set contains as a function of input path conditions.
    /// `count()` on this value extracts the Int directly.
    SetCardinality(SmtExpr),
    /// A symbolic set with both cardinality AND element witnesses.
    ///
    /// Produced by partial set rules whose elements are tracked.  When
    /// another rule iterates over this set, the translator uses the
    /// recorded elements instead of creating disconnected witnesses.
    /// `count()` extracts the cardinality Int.
    SymbolicSet {
        cardinality: SmtExpr,
        elements: Vec<SymSetElement>,
    },
    /// A symbolic array with ordered elements preserving per-element
    /// symbolic values and source paths.
    ///
    /// Produced by `ArrayCreate` and array comprehensions when at least
    /// one element is symbolic (a path placeholder or Z3 expression).
    /// The length is always known concretely (it is `elements.len()`).
    /// Supports: positional access, `count()`, `Contains`, iteration,
    /// and extraction by builtins like `sprintf`.
    SymbolicArray {
        elements: Vec<SymArrayElement>,
    },
    /// A symbolic object (map) whose keys and values are symbolic.
    ///
    /// Produced by object rules or comprehensions that iterate over symbolic
    /// arrays, yielding `key := value` pairs where both key and value come
    /// from input paths.  Lookups are resolved as Z3 ITE chains over the
    /// entries, matching the lookup key against each entry's key.
    SymbolicObject {
        entries: Vec<SymObjectEntry>,
    },
    /// A conditional choice among concrete values, produced when a rule
    /// has multiple else-chain bodies that return different concrete objects.
    ///
    /// Semantics: if branches[0].0 then branches[0].1
    ///            else if branches[1].0 then branches[1].1
    ///            ... else fallback
    ConditionalConcrete {
        branches: Vec<(SmtExpr, Value)>,
        fallback: Value,
    },
}

/// Tracks whether a symbolic register holds a defined (non-Undefined) value.
#[derive(Debug, Clone)]
pub enum Definedness {
    /// Statically known to be defined.
    Defined,
    /// Statically known to be undefined.
    Undefined,
    /// Unknown at translation time; governed by a Z3 boolean.
    Symbolic(SmtExpr),
}

/// A symbolic register in the symbolic VM state.
#[derive(Debug, Clone)]
pub struct SymRegister {
    pub value: SymValue,
    pub defined: Definedness,
    /// If this register traces back to an input/data access path.
    pub source_path: Option<std::string::String>,
}

/// One yielded element during comprehension translation.
#[derive(Debug, Clone)]
pub struct ComprehensionYieldEntry {
    /// The symbolic value being yielded.
    pub value: SymRegister,
    /// Optional key register (for object comprehensions).
    pub key: Option<SymRegister>,
    /// Path condition under which this yield is reached.
    pub condition: SmtExpr,
}

/// Accumulator for a comprehension being translated.
#[derive(Debug, Clone)]
pub struct ComprehensionAccumulator {
    /// Comprehension mode (Set, Array, Object).
    pub mode: crate::rvm::instructions::ComprehensionMode,
    /// Register that holds the comprehension result.
    #[allow(dead_code)]
    pub result_reg: u8,
    /// Accumulated yield entries from the comprehension body.
    pub yields: Vec<ComprehensionYieldEntry>,
}

// ---------------------------------------------------------------------------
// SymValue helpers
// ---------------------------------------------------------------------------

impl SymValue {
    /// Is this a concrete value?
    pub fn is_concrete(&self) -> bool {
        matches!(self, SymValue::Concrete(_))
    }

    /// Try to extract the concrete value.
    pub fn as_concrete(&self) -> Option<&Value> {
        match self {
            SymValue::Concrete(v) => Some(v),
            _ => None,
        }
    }

    /// Infer the [`ValueSort`] of this symbolic value.
    pub fn sort(&self) -> ValueSort {
        match self {
            SymValue::Concrete(v) => match v {
                Value::Bool(_) => ValueSort::Bool,
                Value::Number(n) => {
                    if n.as_f64().is_some() && n.as_i64().is_none() {
                        ValueSort::Real
                    } else {
                        ValueSort::Int
                    }
                }
                Value::String(_) => ValueSort::String,
                _ => ValueSort::Unknown,
            },
            SymValue::Bool(_) => ValueSort::Bool,
            SymValue::Int(_) => ValueSort::Int,
            SymValue::Real(_) => ValueSort::Real,
            SymValue::Str(_) => ValueSort::String,
            SymValue::SetCardinality(_) => ValueSort::Int,
            SymValue::SymbolicSet { .. } => ValueSort::Int,
            SymValue::SymbolicArray { .. } => ValueSort::Unknown,
            SymValue::SymbolicObject { .. } => ValueSort::Unknown,
            SymValue::ConditionalConcrete { .. } => ValueSort::Unknown,
        }
    }

    // -- Promotion helpers: convert SymValue to a specific Z3 sort ----------

    /// Promote to an SMT Bool, converting concrete booleans.
    pub fn to_z3_bool(&self) -> anyhow::Result<SmtExpr> {
        match self {
            SymValue::Bool(b) => Ok(b.clone()),
            SymValue::Concrete(Value::Bool(b)) => Ok(SmtExpr::bool_lit(*b)),
            SymValue::ConditionalConcrete { branches, fallback } => {
                // Build ITE chain: rightmost branch first, then fold left.
                let fb = match fallback {
                    Value::Bool(b) => *b,
                    _ => anyhow::bail!("ConditionalConcrete fallback is not Bool"),
                };
                let mut result = SmtExpr::bool_lit(fb);
                for (cond, val) in branches.iter().rev() {
                    let b = match val {
                        Value::Bool(b) => *b,
                        _ => anyhow::bail!("ConditionalConcrete branch is not Bool"),
                    };
                    result = SmtExpr::ite(cond.clone(), SmtExpr::bool_lit(b), result);
                }
                Ok(result)
            }
            other => {
                anyhow::bail!("Cannot promote {:?} to SMT Bool", other.sort())
            }
        }
    }

    /// Promote to an SMT Int, converting concrete numbers.
    pub fn to_z3_int(&self) -> anyhow::Result<SmtExpr> {
        match self {
            SymValue::Int(i) => Ok(i.clone()),
            SymValue::SetCardinality(i) => Ok(i.clone()),
            SymValue::SymbolicSet { cardinality, .. } => Ok(cardinality.clone()),
            SymValue::Concrete(Value::Number(n)) => {
                if let Some(i) = n.as_i64() {
                    Ok(SmtExpr::IntLit(i))
                } else if let Some(u) = n.as_u64() {
                    // u64 values that fit in i64 are handled above;
                    // for larger values, use string representation.
                    Ok(SmtExpr::IntLit(u as i64))
                } else {
                    anyhow::bail!("Cannot convert Number to SMT Int")
                }
            }
            other => anyhow::bail!("Cannot promote {:?} to SMT Int", other.sort()),
        }
    }

    /// Promote to an SMT Real, converting concrete numbers.
    pub fn to_z3_real(&self) -> anyhow::Result<SmtExpr> {
        match self {
            SymValue::Real(r) => Ok(r.clone()),
            SymValue::Int(i) => Ok(SmtExpr::Int2Real(Box::new(i.clone()))),
            SymValue::Concrete(Value::Number(n)) => {
                if let Some(f) = n.as_f64() {
                    // Approximate: SMT Real is exact rationals, f64 is IEEE754.
                    // For integer-valued floats, use exact conversion.
                    let int_val = f as i64;
                    if (int_val as f64) == f {
                        Ok(SmtExpr::RealLit(int_val, 1))
                    } else {
                        // Approximate with large numerator/denominator
                        let numer = (f * 1_000_000.0) as i64;
                        Ok(SmtExpr::RealLit(numer, 1_000_000))
                    }
                } else if let Some(i) = n.as_i64() {
                    Ok(SmtExpr::RealLit(i, 1))
                } else {
                    anyhow::bail!("Cannot convert Number to SMT Real")
                }
            }
            other => anyhow::bail!("Cannot promote {:?} to SMT Real", other.sort()),
        }
    }

    /// Promote to an SMT String, converting concrete strings.
    pub fn to_z3_string(&self) -> anyhow::Result<SmtExpr> {
        match self {
            SymValue::Str(s) => Ok(s.clone()),
            SymValue::Concrete(Value::String(s)) => Ok(SmtExpr::StringLit(s.to_string())),
            other => anyhow::bail!("Cannot promote {:?} to SMT String", other.sort()),
        }
    }

    /// Create a Z3 Bool that is true when `self` differs from its default /
    /// fallback value.
    ///
    /// For `ConditionalConcrete`, the fallback is the default; any active
    /// branch whose value differs from the fallback makes the result
    /// non-default.  For plain `Concrete`, we compare against a supplied
    /// default (if given).  Symbolic primitive types are always non-default.
    pub fn is_non_default(&self) -> SmtExpr {
        match self {
            SymValue::ConditionalConcrete { branches, fallback } => {
                let non_default_conds: Vec<SmtExpr> = branches
                    .iter()
                    .filter(|(_, val)| val != fallback)
                    .map(|(c, _)| c.clone())
                    .collect();
                if non_default_conds.is_empty() {
                    SmtExpr::False
                } else {
                    SmtExpr::Or(non_default_conds)
                }
            }
            SymValue::Concrete(Value::Undefined) => SmtExpr::False,
            // A fully-concrete non-Undefined value is always "itself".
            SymValue::Concrete(_) => SmtExpr::True,
            // Symbolic primitives are non-default by construction.
            _ => SmtExpr::True,
        }
    }

    /// Create an SMT Bool representing `self == desired_output`.
    pub fn equals_value(
        &self,
        desired: &Value,
    ) -> anyhow::Result<SmtExpr> {
        // Fast path: concrete values can be compared directly regardless of type.
        if let SymValue::Concrete(v) = self {
            return Ok(SmtExpr::bool_lit(v == desired));
        }

        // ConditionalConcrete: ITE chain comparing each branch to desired.
        if let SymValue::ConditionalConcrete { branches, fallback } = self {
            let mut result = SmtExpr::bool_lit(fallback == desired);
            for (cond, val) in branches.iter().rev() {
                let branch_eq = SmtExpr::bool_lit(val == desired);
                result = SmtExpr::ite(cond.clone(), branch_eq, result);
            }
            return Ok(result);
        }

        match desired {
            Value::Bool(b) => {
                let smt_self = self.to_z3_bool()?;
                let smt_desired = SmtExpr::bool_lit(*b);
                Ok(SmtExpr::eq(smt_self, smt_desired))
            }
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    let smt_self = self.to_z3_int()?;
                    let smt_desired = SmtExpr::IntLit(i);
                    Ok(SmtExpr::eq(smt_self, smt_desired))
                } else {
                    anyhow::bail!("Cannot compare with non-integer Number yet")
                }
            }
            Value::String(s) => {
                let smt_self = self.to_z3_string()?;
                let smt_desired = SmtExpr::StringLit(s.to_string());
                Ok(SmtExpr::eq(smt_self, smt_desired))
            }
            Value::Null => {
                // Null is a sentinel; for now, require concrete match
                match self {
                    SymValue::Concrete(v) => Ok(SmtExpr::bool_lit(v == desired)),
                    _ => anyhow::bail!("Cannot compare symbolic value with Null"),
                }
            }
            _ => anyhow::bail!("Unsupported desired output type: {:?}", desired),
        }
    }

    /// Create an SMT Bool representing "this value is defined (not Undefined)".
    pub fn is_defined(&self) -> SmtExpr {
        match self {
            SymValue::Concrete(Value::Undefined) => SmtExpr::False,
            SymValue::Concrete(_) => SmtExpr::True,
            SymValue::ConditionalConcrete { branches, fallback } => {
                // Defined if any branch is active OR the fallback is not Undefined.
                if *fallback != Value::Undefined {
                    return SmtExpr::True;
                }
                if branches.is_empty() {
                    return SmtExpr::False;
                }
                let conds: Vec<SmtExpr> = branches.iter().map(|(c, _)| c.clone()).collect();
                SmtExpr::Or(conds)
            }
            // Symbolic values (including SetCardinality) are defined by
            // construction; their definedness is tracked separately.
            _ => SmtExpr::True,
        }
    }

    /// If this is a `SetCardinality` or `SymbolicSet`, extract the Z3 Int directly.
    pub fn as_set_cardinality(&self) -> Option<&SmtExpr> {
        match self {
            SymValue::SetCardinality(i) => Some(i),
            SymValue::SymbolicSet { cardinality, .. } => Some(cardinality),
            _ => None,
        }
    }

    /// If this is a `SymbolicSet`, extract the element witnesses.
    pub fn as_symbolic_set_elements(&self) -> Option<&Vec<SymSetElement>> {
        match self {
            SymValue::SymbolicSet { elements, .. } => Some(elements),
            _ => None,
        }
    }

    /// If this is a `SymbolicArray`, extract the ordered elements.
    pub fn as_symbolic_array_elements(&self) -> Option<&Vec<SymArrayElement>> {
        match self {
            SymValue::SymbolicArray { elements } => Some(elements),
            _ => None,
        }
    }

    /// If this is a `SymbolicObject`, extract the entries.
    pub fn as_symbolic_object_entries(&self) -> Option<&Vec<SymObjectEntry>> {
        match self {
            SymValue::SymbolicObject { entries } => Some(entries),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Definedness helpers
// ---------------------------------------------------------------------------

impl Definedness {
    /// Combine two definedness values with AND (both must be defined).
    pub fn and(
        a: &Definedness,
        b: &Definedness,
    ) -> Definedness {
        match (a, b) {
            (Definedness::Defined, Definedness::Defined) => Definedness::Defined,
            (Definedness::Undefined, _) | (_, Definedness::Undefined) => Definedness::Undefined,
            (Definedness::Defined, Definedness::Symbolic(s))
            | (Definedness::Symbolic(s), Definedness::Defined) => Definedness::Symbolic(s.clone()),
            (Definedness::Symbolic(a), Definedness::Symbolic(b)) => {
                Definedness::Symbolic(SmtExpr::and2(a.clone(), b.clone()))
            }
        }
    }

    /// Convert to an SMT Bool (Defined → true, Undefined → false).
    pub fn to_z3_bool(&self) -> SmtExpr {
        match self {
            Definedness::Defined => SmtExpr::True,
            Definedness::Undefined => SmtExpr::False,
            Definedness::Symbolic(b) => b.clone(),
        }
    }

    /// Is this statically known to be defined?
    pub fn is_defined(&self) -> bool {
        matches!(self, Definedness::Defined)
    }

    /// Is this statically known to be undefined?
    pub fn is_undefined(&self) -> bool {
        matches!(self, Definedness::Undefined)
    }
}

// ---------------------------------------------------------------------------
// SymRegister helpers
// ---------------------------------------------------------------------------

impl SymRegister {
    /// Create a new register with a concrete value.
    pub fn concrete(value: Value) -> Self {
        let defined = if value == Value::Undefined {
            Definedness::Undefined
        } else {
            Definedness::Defined
        };
        Self {
            value: SymValue::Concrete(value),
            defined,
            source_path: None,
        }
    }

    /// Create a new register holding Undefined.
    pub fn undefined() -> Self {
        Self {
            value: SymValue::Concrete(Value::Undefined),
            defined: Definedness::Undefined,
            source_path: None,
        }
    }

    /// Create a new symbolic register.
    pub fn symbolic(value: SymValue, defined: Definedness) -> Self {
        Self {
            value,
            defined,
            source_path: None,
        }
    }

    /// Create a new symbolic register with a source path.
    pub fn symbolic_with_path(
        value: SymValue,
        defined: Definedness,
        path: std::string::String,
    ) -> Self {
        Self {
            value,
            defined,
            source_path: Some(path),
        }
    }
}
