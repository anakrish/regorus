// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core symbolic types for RVM-to-Z3 translation.

use alloc::vec::Vec;

use z3::ast::{Ast, Bool as Z3Bool, Int as Z3Int, Real as Z3Real, String as Z3String};

use crate::value::Value;

/// The Z3 sort (type) of a symbolic value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueSort {
    Bool,
    Int,
    Real,
    String,
    Unknown,
}

/// A symbolic value: either a concrete Rego `Value` or a Z3 expression.
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
pub struct SymSetElement<'ctx> {
    /// Under what condition this element is present in the set.
    pub condition: Z3Bool<'ctx>,
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

/// An element of a symbolically-modeled array.
///
/// Unlike `SymSetElement`, this preserves per-element symbolic values and
/// ordering—critical for positional access (`arr[i]`) and for builtins
/// like `sprintf` that consume array elements by index.
#[derive(Debug, Clone)]
pub struct SymArrayElement<'ctx> {
    /// The symbolic value of this element.
    pub value: SymValue<'ctx>,
    /// The definedness of this element.
    pub defined: Definedness<'ctx>,
    /// Optional source path (e.g., `"input.user.name"`).
    pub source_path: Option<std::string::String>,
}

#[derive(Debug, Clone)]
pub enum SymValue<'ctx> {
    /// A fully-known concrete value.
    Concrete(Value),
    /// A symbolic boolean (Z3 Bool sort).
    Bool(Z3Bool<'ctx>),
    /// A symbolic integer (Z3 Int sort).
    Int(Z3Int<'ctx>),
    /// A symbolic real number (Z3 Real sort).
    Real(Z3Real<'ctx>),
    /// A symbolic string (Z3 String sort).
    Str(Z3String<'ctx>),
    /// A symbolic set whose cardinality is represented by a Z3 Int.
    /// Produced by partial set rule calls — the Int encodes how many
    /// elements the set contains as a function of input path conditions.
    /// `count()` on this value extracts the Int directly.
    SetCardinality(Z3Int<'ctx>),
    /// A symbolic set with both cardinality AND element witnesses.
    ///
    /// Produced by partial set rules whose elements are tracked.  When
    /// another rule iterates over this set, the translator uses the
    /// recorded elements instead of creating disconnected witnesses.
    /// `count()` extracts the cardinality Int.
    SymbolicSet {
        cardinality: Z3Int<'ctx>,
        elements: Vec<SymSetElement<'ctx>>,
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
        elements: Vec<SymArrayElement<'ctx>>,
    },
    /// A conditional choice among concrete values, produced when a rule
    /// has multiple else-chain bodies that return different concrete objects.
    ///
    /// Semantics: if branches[0].0 then branches[0].1
    ///            else if branches[1].0 then branches[1].1
    ///            ... else fallback
    ConditionalConcrete {
        branches: Vec<(Z3Bool<'ctx>, Value)>,
        fallback: Value,
    },
}

/// Tracks whether a symbolic register holds a defined (non-Undefined) value.
#[derive(Debug, Clone)]
pub enum Definedness<'ctx> {
    /// Statically known to be defined.
    Defined,
    /// Statically known to be undefined.
    Undefined,
    /// Unknown at translation time; governed by a Z3 boolean.
    Symbolic(Z3Bool<'ctx>),
}

/// A symbolic register in the symbolic VM state.
#[derive(Debug, Clone)]
pub struct SymRegister<'ctx> {
    pub value: SymValue<'ctx>,
    pub defined: Definedness<'ctx>,
    /// If this register traces back to an input/data access path.
    pub source_path: Option<std::string::String>,
}

/// One yielded element during comprehension translation.
#[derive(Debug, Clone)]
pub struct ComprehensionYieldEntry<'ctx> {
    /// The symbolic value being yielded.
    pub value: SymRegister<'ctx>,
    /// Optional key register (for object comprehensions).
    pub key: Option<SymRegister<'ctx>>,
    /// Path condition under which this yield is reached.
    pub condition: Z3Bool<'ctx>,
}

/// Accumulator for a comprehension being translated.
#[derive(Debug, Clone)]
pub struct ComprehensionAccumulator<'ctx> {
    /// Comprehension mode (Set, Array, Object).
    pub mode: crate::rvm::instructions::ComprehensionMode,
    /// Register that holds the comprehension result.
    #[allow(dead_code)]
    pub result_reg: u8,
    /// Accumulated yield entries from the comprehension body.
    pub yields: Vec<ComprehensionYieldEntry<'ctx>>,
}

// ---------------------------------------------------------------------------
// SymValue helpers
// ---------------------------------------------------------------------------

impl<'ctx> SymValue<'ctx> {
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
            SymValue::ConditionalConcrete { .. } => ValueSort::Unknown,
        }
    }

    // -- Promotion helpers: convert SymValue to a specific Z3 sort ----------

    /// Promote to a Z3 Bool, converting concrete booleans.
    pub fn to_z3_bool(&self, ctx: &'ctx z3::Context) -> anyhow::Result<Z3Bool<'ctx>> {
        match self {
            SymValue::Bool(b) => Ok(b.clone()),
            SymValue::Concrete(Value::Bool(b)) => Ok(Z3Bool::from_bool(ctx, *b)),
            SymValue::ConditionalConcrete { branches, fallback } => {
                // Build ITE chain: rightmost branch first, then fold left.
                let fb = match fallback {
                    Value::Bool(b) => *b,
                    _ => anyhow::bail!("ConditionalConcrete fallback is not Bool"),
                };
                let mut result = Z3Bool::from_bool(ctx, fb);
                for (cond, val) in branches.iter().rev() {
                    let b = match val {
                        Value::Bool(b) => *b,
                        _ => anyhow::bail!("ConditionalConcrete branch is not Bool"),
                    };
                    result = cond.ite(&Z3Bool::from_bool(ctx, b), &result);
                }
                Ok(result)
            }
            other => {
                anyhow::bail!("Cannot promote {:?} to Z3 Bool", other.sort())
            }
        }
    }

    /// Promote to a Z3 Int, converting concrete numbers.
    pub fn to_z3_int(&self, ctx: &'ctx z3::Context) -> anyhow::Result<Z3Int<'ctx>> {
        match self {
            SymValue::Int(i) => Ok(i.clone()),
            SymValue::SetCardinality(i) => Ok(i.clone()),
            SymValue::SymbolicSet { cardinality, .. } => Ok(cardinality.clone()),
            SymValue::Concrete(Value::Number(n)) => {
                if let Some(i) = n.as_i64() {
                    Ok(Z3Int::from_i64(ctx, i))
                } else if let Some(u) = n.as_u64() {
                    // u64 values that fit in i64 are handled above;
                    // for larger values, use string representation.
                    Ok(Z3Int::from_i64(ctx, u as i64))
                } else {
                    anyhow::bail!("Cannot convert Number to Z3 Int")
                }
            }
            other => anyhow::bail!("Cannot promote {:?} to Z3 Int", other.sort()),
        }
    }

    /// Promote to a Z3 Real, converting concrete numbers.
    pub fn to_z3_real(&self, ctx: &'ctx z3::Context) -> anyhow::Result<Z3Real<'ctx>> {
        match self {
            SymValue::Real(r) => Ok(r.clone()),
            SymValue::Int(i) => Ok(Z3Real::from_int(i)),
            SymValue::Concrete(Value::Number(n)) => {
                if let Some(f) = n.as_f64() {
                    // Approximate: Z3 Real is exact rationals, f64 is IEEE754.
                    // For integer-valued floats, use exact conversion.
                    let int_val = f as i64;
                    if (int_val as f64) == f {
                        Ok(Z3Real::from_real(ctx, int_val as i32, 1))
                    } else {
                        // Approximate with large numerator/denominator
                        let numer = (f * 1_000_000.0) as i32;
                        Ok(Z3Real::from_real(ctx, numer, 1_000_000))
                    }
                } else if let Some(i) = n.as_i64() {
                    Ok(Z3Real::from_real(ctx, i as i32, 1))
                } else {
                    anyhow::bail!("Cannot convert Number to Z3 Real")
                }
            }
            other => anyhow::bail!("Cannot promote {:?} to Z3 Real", other.sort()),
        }
    }

    /// Promote to a Z3 String, converting concrete strings.
    pub fn to_z3_string(&self, ctx: &'ctx z3::Context) -> anyhow::Result<Z3String<'ctx>> {
        match self {
            SymValue::Str(s) => Ok(s.clone()),
            SymValue::Concrete(Value::String(s)) => Ok(Z3String::from_str(ctx, s).unwrap()),
            other => anyhow::bail!("Cannot promote {:?} to Z3 String", other.sort()),
        }
    }

    /// Create a Z3 Bool representing `self == desired_output`.
    pub fn equals_value(
        &self,
        ctx: &'ctx z3::Context,
        desired: &Value,
    ) -> anyhow::Result<Z3Bool<'ctx>> {
        // Fast path: concrete values can be compared directly regardless of type.
        if let SymValue::Concrete(v) = self {
            return Ok(Z3Bool::from_bool(ctx, v == desired));
        }

        // ConditionalConcrete: ITE chain comparing each branch to desired.
        if let SymValue::ConditionalConcrete { branches, fallback } = self {
            let mut result = Z3Bool::from_bool(ctx, fallback == desired);
            for (cond, val) in branches.iter().rev() {
                let branch_eq = Z3Bool::from_bool(ctx, val == desired);
                result = cond.ite(&branch_eq, &result);
            }
            return Ok(result);
        }

        match desired {
            Value::Bool(b) => {
                let z3_self = self.to_z3_bool(ctx)?;
                let z3_desired = Z3Bool::from_bool(ctx, *b);
                Ok(z3_self._eq(&z3_desired))
            }
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    let z3_self = self.to_z3_int(ctx)?;
                    let z3_desired = Z3Int::from_i64(ctx, i);
                    Ok(z3_self._eq(&z3_desired))
                } else {
                    anyhow::bail!("Cannot compare with non-integer Number yet")
                }
            }
            Value::String(s) => {
                let z3_self = self.to_z3_string(ctx)?;
                let z3_desired = Z3String::from_str(ctx, s).unwrap();
                Ok(z3_self._eq(&z3_desired))
            }
            Value::Null => {
                // Null is a sentinel; for now, require concrete match
                match self {
                    SymValue::Concrete(v) => Ok(Z3Bool::from_bool(ctx, v == desired)),
                    _ => anyhow::bail!("Cannot compare symbolic value with Null"),
                }
            }
            _ => anyhow::bail!("Unsupported desired output type: {:?}", desired),
        }
    }

    /// Create a Z3 Bool representing "this value is defined (not Undefined)".
    pub fn is_defined(&self, ctx: &'ctx z3::Context) -> Z3Bool<'ctx> {
        match self {
            SymValue::Concrete(Value::Undefined) => Z3Bool::from_bool(ctx, false),
            SymValue::Concrete(_) => Z3Bool::from_bool(ctx, true),
            SymValue::ConditionalConcrete { branches, fallback } => {
                // Defined if any branch is active OR the fallback is not Undefined.
                if *fallback != Value::Undefined {
                    return Z3Bool::from_bool(ctx, true);
                }
                if branches.is_empty() {
                    return Z3Bool::from_bool(ctx, false);
                }
                let conds: Vec<&Z3Bool<'ctx>> = branches.iter().map(|(c, _)| c).collect();
                Z3Bool::or(ctx, &conds)
            }
            // Symbolic values (including SetCardinality) are defined by
            // construction; their definedness is tracked separately.
            _ => Z3Bool::from_bool(ctx, true),
        }
    }

    /// If this is a `SetCardinality` or `SymbolicSet`, extract the Z3 Int directly.
    pub fn as_set_cardinality(&self) -> Option<&Z3Int<'ctx>> {
        match self {
            SymValue::SetCardinality(i) => Some(i),
            SymValue::SymbolicSet { cardinality, .. } => Some(cardinality),
            _ => None,
        }
    }

    /// If this is a `SymbolicSet`, extract the element witnesses.
    pub fn as_symbolic_set_elements(&self) -> Option<&Vec<SymSetElement<'ctx>>> {
        match self {
            SymValue::SymbolicSet { elements, .. } => Some(elements),
            _ => None,
        }
    }

    /// If this is a `SymbolicArray`, extract the ordered elements.
    pub fn as_symbolic_array_elements(&self) -> Option<&Vec<SymArrayElement<'ctx>>> {
        match self {
            SymValue::SymbolicArray { elements } => Some(elements),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Definedness helpers
// ---------------------------------------------------------------------------

impl<'ctx> Definedness<'ctx> {
    /// Combine two definedness values with AND (both must be defined).
    pub fn and(
        ctx: &'ctx z3::Context,
        a: &Definedness<'ctx>,
        b: &Definedness<'ctx>,
    ) -> Definedness<'ctx> {
        match (a, b) {
            (Definedness::Defined, Definedness::Defined) => Definedness::Defined,
            (Definedness::Undefined, _) | (_, Definedness::Undefined) => Definedness::Undefined,
            (Definedness::Defined, Definedness::Symbolic(s))
            | (Definedness::Symbolic(s), Definedness::Defined) => Definedness::Symbolic(s.clone()),
            (Definedness::Symbolic(a), Definedness::Symbolic(b)) => {
                Definedness::Symbolic(Z3Bool::and(ctx, &[a, b]))
            }
        }
    }

    /// Convert to a Z3 Bool (Defined → true, Undefined → false).
    pub fn to_z3_bool(&self, ctx: &'ctx z3::Context) -> Z3Bool<'ctx> {
        match self {
            Definedness::Defined => Z3Bool::from_bool(ctx, true),
            Definedness::Undefined => Z3Bool::from_bool(ctx, false),
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

impl<'ctx> SymRegister<'ctx> {
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
    pub fn symbolic(value: SymValue<'ctx>, defined: Definedness<'ctx>) -> Self {
        Self {
            value,
            defined,
            source_path: None,
        }
    }

    /// Create a new symbolic register with a source path.
    pub fn symbolic_with_path(
        value: SymValue<'ctx>,
        defined: Definedness<'ctx>,
        path: std::string::String,
    ) -> Self {
        Self {
            value,
            defined,
            source_path: Some(path),
        }
    }
}
