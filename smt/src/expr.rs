// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core SMT expression AST.
//!
//! Each [`SmtExpr`] variant maps to exactly one `Z3_mk_*` C API function.
//! The AST is serializable (via serde) so it can be shipped across a WASM
//! boundary as JSON and reconstructed into live Z3 objects on the JS side.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Sorts
// ---------------------------------------------------------------------------

/// SMT sort (type) identifiers — mirrors `Z3_mk_*_sort`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SmtSort {
    /// Boolean sort.  (`Z3_mk_bool_sort`)
    Bool,
    /// Arbitrary-precision integer sort.  (`Z3_mk_int_sort`)
    Int,
    /// Arbitrary-precision rational sort.  (`Z3_mk_real_sort`)
    Real,
    /// Unicode string sort.  (`Z3_mk_string_sort`)
    String,
    /// Fixed-width bitvector sort.  (`Z3_mk_bv_sort(sz)`)
    BitVec(u32),
    /// Regular expression sort over strings.
    Regex,
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

/// A constant or function declaration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SmtDecl {
    /// `(declare-const <name> <sort>)` — corresponds to `Z3_mk_const`.
    Const {
        /// Variable id (index into the declarations table).
        id: u32,
        /// Human-readable name (e.g. `"input.user.role"`).
        name: String,
        /// The sort of this constant.
        sort: SmtSort,
    },
    /// `(declare-fun <name> (<arg_sorts>) <ret_sort>)` — corresponds to
    /// `Z3_mk_func_decl`.
    Fun {
        /// Function id (index into the declarations table).
        id: u32,
        /// Human-readable name.
        name: String,
        /// Argument sorts.
        arg_sorts: Vec<SmtSort>,
        /// Return sort.
        ret_sort: SmtSort,
    },
}

impl SmtDecl {
    /// The id of this declaration.
    pub fn id(&self) -> u32 {
        match self {
            SmtDecl::Const { id, .. } | SmtDecl::Fun { id, .. } => *id,
        }
    }

    /// The name of this declaration.
    pub fn name(&self) -> &str {
        match self {
            SmtDecl::Const { name, .. } | SmtDecl::Fun { name, .. } => name,
        }
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

/// A serializable SMT expression node.
///
/// Every variant corresponds to one `Z3_mk_*` C API function.  This makes
/// reconstruction into any Z3 interface (Rust crate, JS npm, or SMT-LIB2
/// text) a trivial switch/match.
///
/// # Variable References
///
/// Variables are referred to by `u32` indices into the declarations table
/// (see [`SmtDecl`]).  This keeps the AST compact and avoids duplicating
/// name strings throughout the tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SmtExpr {
    // =================================================================
    // Literals
    // =================================================================
    /// `true` — `Z3_mk_true`
    True,
    /// `false` — `Z3_mk_false`
    False,
    /// Integer literal — `Z3_mk_int64`
    IntLit(i64),
    /// Rational literal (numerator, denominator) — `Z3_mk_real(num, den)`
    RealLit(i64, i64),
    /// String literal — `Z3_mk_string`
    StringLit(String),
    /// Bitvector literal (value, bit-width) — `Z3_mk_int64` with bv sort
    BvLit(i64, u32),

    // =================================================================
    // Variable / function references
    // =================================================================
    /// Reference to a declared constant — `Z3_mk_const` result
    ///
    /// The `u32` is an index into the [`SmtProblem::declarations`] table.
    Const(u32),

    /// Function application — `Z3_mk_app(func_decl, args)`
    ///
    /// The `u32` is the function declaration id.
    App(u32, Vec<SmtExpr>),

    // =================================================================
    // Propositional logic — `Z3_mk_and`, `Z3_mk_or`, etc.
    // =================================================================
    /// `(not a)` — `Z3_mk_not`
    Not(Box<SmtExpr>),
    /// `(and a1 a2 ...)` — `Z3_mk_and`
    And(Vec<SmtExpr>),
    /// `(or a1 a2 ...)` — `Z3_mk_or`
    Or(Vec<SmtExpr>),
    /// `(xor a b)` — `Z3_mk_xor`
    Xor(Box<SmtExpr>, Box<SmtExpr>),
    /// `(=> a b)` — `Z3_mk_implies`
    Implies(Box<SmtExpr>, Box<SmtExpr>),
    /// `(iff a b)` — `Z3_mk_iff`
    Iff(Box<SmtExpr>, Box<SmtExpr>),
    /// `(ite c t e)` — `Z3_mk_ite`
    Ite(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),

    // =================================================================
    // Equality — `Z3_mk_eq`, `Z3_mk_distinct`
    // =================================================================
    /// `(= a b)` — `Z3_mk_eq`
    Eq(Box<SmtExpr>, Box<SmtExpr>),
    /// `(distinct a1 a2 ...)` — `Z3_mk_distinct`
    Distinct(Vec<SmtExpr>),

    // =================================================================
    // Arithmetic — `Z3_mk_add`, `Z3_mk_sub`, etc.
    // =================================================================
    /// `(+ a1 a2 ...)` — `Z3_mk_add`
    Add(Vec<SmtExpr>),
    /// `(- a1 a2 ...)` — `Z3_mk_sub`
    Sub(Vec<SmtExpr>),
    /// `(* a1 a2 ...)` — `Z3_mk_mul`
    Mul(Vec<SmtExpr>),
    /// `(div a b)` — `Z3_mk_div`
    Div(Box<SmtExpr>, Box<SmtExpr>),
    /// `(mod a b)` — `Z3_mk_mod`
    Mod(Box<SmtExpr>, Box<SmtExpr>),
    /// `(rem a b)` — `Z3_mk_rem`
    Rem(Box<SmtExpr>, Box<SmtExpr>),
    /// `(- a)` — `Z3_mk_unary_minus`
    Neg(Box<SmtExpr>),
    /// `(abs a)` — `Z3_mk_abs`
    Abs(Box<SmtExpr>),
    /// `(^ a b)` — `Z3_mk_power`
    Power(Box<SmtExpr>, Box<SmtExpr>),

    // =================================================================
    // Comparison — `Z3_mk_lt`, `Z3_mk_le`, etc.
    // =================================================================
    /// `(< a b)` — `Z3_mk_lt`
    Lt(Box<SmtExpr>, Box<SmtExpr>),
    /// `(<= a b)` — `Z3_mk_le`
    Le(Box<SmtExpr>, Box<SmtExpr>),
    /// `(> a b)` — `Z3_mk_gt`
    Gt(Box<SmtExpr>, Box<SmtExpr>),
    /// `(>= a b)` — `Z3_mk_ge`
    Ge(Box<SmtExpr>, Box<SmtExpr>),

    // =================================================================
    // Coercion — `Z3_mk_int2real`, `Z3_mk_int2bv`, `Z3_mk_bv2int`
    // =================================================================
    /// `(to_real a)` — `Z3_mk_int2real`
    Int2Real(Box<SmtExpr>),
    /// `(to_int a)` — `Z3_mk_real2int`
    Real2Int(Box<SmtExpr>),
    /// `((_ int2bv n) a)` — `Z3_mk_int2bv`
    Int2Bv(Box<SmtExpr>, u32),
    /// `(bv2int a signed)` — `Z3_mk_bv2int`
    Bv2Int(Box<SmtExpr>, bool),

    // =================================================================
    // Bitvector — `Z3_mk_bvand`, `Z3_mk_bvor`, etc.
    // =================================================================
    /// `(bvand a b)` — `Z3_mk_bvand`
    BvAnd(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvor a b)` — `Z3_mk_bvor`
    BvOr(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvxor a b)` — `Z3_mk_bvxor`
    BvXor(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvnot a)` — `Z3_mk_bvnot`
    BvNot(Box<SmtExpr>),
    /// `(bvneg a)` — `Z3_mk_bvneg`
    BvNeg(Box<SmtExpr>),
    /// `(bvadd a b)` — `Z3_mk_bvadd`
    BvAdd(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvsub a b)` — `Z3_mk_bvsub`
    BvSub(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvmul a b)` — `Z3_mk_bvmul`
    BvMul(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvudiv a b)` — `Z3_mk_bvudiv`
    BvUDiv(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvshl a b)` — `Z3_mk_bvshl`
    BvShl(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvlshr a b)` — `Z3_mk_bvlshr`
    BvLShr(Box<SmtExpr>, Box<SmtExpr>),
    /// `(bvashr a b)` — `Z3_mk_bvashr`
    BvAShr(Box<SmtExpr>, Box<SmtExpr>),

    // =================================================================
    // Sequences / Strings — `Z3_mk_seq_*`
    // =================================================================
    /// `(str.len s)` — `Z3_mk_seq_length`
    SeqLength(Box<SmtExpr>),
    /// `(str.++ s1 s2 ...)` — `Z3_mk_seq_concat`
    SeqConcat(Vec<SmtExpr>),
    /// `(str.contains s t)` — `Z3_mk_seq_contains`
    SeqContains(Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.prefixof pre s)` — `Z3_mk_seq_prefix`
    SeqPrefix(Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.suffixof suf s)` — `Z3_mk_seq_suffix`
    SeqSuffix(Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.at s i)` — `Z3_mk_seq_at`
    SeqAt(Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.indexof s t offset)` — `Z3_mk_seq_index`
    SeqIndex(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.replace s src dst)` — `Z3_mk_seq_replace`
    SeqReplace(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.substr s offset length)` — `Z3_mk_seq_extract`
    SeqExtract(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.< a b)` — `Z3_mk_str_lt`
    StrLt(Box<SmtExpr>, Box<SmtExpr>),
    /// `(str.<= a b)` — `Z3_mk_str_le`
    StrLe(Box<SmtExpr>, Box<SmtExpr>),

    // =================================================================
    // String ↔ numeric conversions
    // =================================================================
    /// `(str.from_int i)` — `Z3_mk_int_to_str`
    IntToStr(Box<SmtExpr>),
    /// `(str.to_int s)` — `Z3_mk_str_to_int`
    StrToInt(Box<SmtExpr>),

    // =================================================================
    // Regular expressions — `Z3_mk_re_*`, `Z3_mk_seq_in_re`
    // =================================================================
    /// `(str.to_re s)` — `Z3_mk_seq_to_re`
    SeqToRe(Box<SmtExpr>),
    /// `(str.in_re s re)` — `Z3_mk_seq_in_re`
    SeqInRe(Box<SmtExpr>, Box<SmtExpr>),
    /// `(re.* re)` — `Z3_mk_re_star`
    ReStar(Box<SmtExpr>),
    /// `(re.+ re)` — `Z3_mk_re_plus`
    RePlus(Box<SmtExpr>),
    /// `(re.opt re)` — `Z3_mk_re_option`
    ReOption(Box<SmtExpr>),
    /// `(re.union re1 re2 ...)` — `Z3_mk_re_union`
    ReUnion(Vec<SmtExpr>),
    /// `(re.inter re1 re2 ...)` — `Z3_mk_re_intersect`
    ReIntersect(Vec<SmtExpr>),
    /// `(re.++ re1 re2 ...)` — `Z3_mk_re_concat`
    ReConcat(Vec<SmtExpr>),
    /// `(re.range lo hi)` — `Z3_mk_re_range`
    ReRange(Box<SmtExpr>, Box<SmtExpr>),
    /// `(re.comp re)` — `Z3_mk_re_complement`
    ReComplement(Box<SmtExpr>),
    /// `(re.diff re1 re2)` — `Z3_mk_re_diff`
    ReDiff(Box<SmtExpr>, Box<SmtExpr>),
    /// `(re.loop re lo hi)` — `Z3_mk_re_loop`
    ReLoop(Box<SmtExpr>, u32, u32),
    /// `(_ re.all <sort>)` — `Z3_mk_re_full`
    ReFull(SmtSort),
    /// `(re.none <sort>)` — `Z3_mk_re_empty`
    ReEmpty(SmtSort),
    /// `re.allchar` — `Z3_mk_re_allchar`
    ReAllChar(SmtSort),

    // =================================================================
    // Quantifiers (future use) — `Z3_mk_forall`, `Z3_mk_exists`
    // =================================================================
    /// `(forall ((x Sort) ...) body)` — `Z3_mk_forall`
    ForAll {
        /// Bound variable sorts and names.
        vars: Vec<(String, SmtSort)>,
        /// Quantifier body (may reference bound vars by de-Bruijn index).
        body: Box<SmtExpr>,
    },
    /// `(exists ((x Sort) ...) body)` — `Z3_mk_exists`
    Exists {
        vars: Vec<(String, SmtSort)>,
        body: Box<SmtExpr>,
    },
    /// de-Bruijn bound variable — `Z3_mk_bound(index, sort)`
    Bound(u32, SmtSort),
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

impl SmtExpr {
    /// Create a boolean literal.
    pub fn bool_lit(b: bool) -> Self {
        if b {
            SmtExpr::True
        } else {
            SmtExpr::False
        }
    }

    /// Create a variable reference.
    pub fn var(id: u32) -> Self {
        SmtExpr::Const(id)
    }

    /// `(and a b)` — binary shorthand.
    pub fn and2(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::And(alloc::vec![a, b])
    }

    /// `(or a b)` — binary shorthand.
    pub fn or2(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Or(alloc::vec![a, b])
    }

    /// `(not a)` shorthand.
    pub fn not(a: SmtExpr) -> Self {
        SmtExpr::Not(Box::new(a))
    }

    /// `(=> a b)` shorthand.
    pub fn implies(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Implies(Box::new(a), Box::new(b))
    }

    /// `(ite c t e)` shorthand.
    pub fn ite(c: SmtExpr, t: SmtExpr, e: SmtExpr) -> Self {
        SmtExpr::Ite(Box::new(c), Box::new(t), Box::new(e))
    }

    /// `(= a b)` shorthand.
    pub fn eq(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Eq(Box::new(a), Box::new(b))
    }

    /// `(< a b)` shorthand.
    pub fn lt(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Lt(Box::new(a), Box::new(b))
    }

    /// `(<= a b)` shorthand.
    pub fn le(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Le(Box::new(a), Box::new(b))
    }

    /// `(> a b)` shorthand.
    pub fn gt(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Gt(Box::new(a), Box::new(b))
    }

    /// `(>= a b)` shorthand.
    pub fn ge(a: SmtExpr, b: SmtExpr) -> Self {
        SmtExpr::Ge(Box::new(a), Box::new(b))
    }
}
