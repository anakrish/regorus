// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unknown_lints)]
#![allow(clippy::doc_lazy_continuation)]
// Fail-fast lints: correctness, safety, and API surface
#![deny(
    // Panic sources - catch all ways code can panic
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::manual_assert,
    // TODO: restore once indexing in tests avoids panics
    // clippy::indexing_slicing,
    // TODO: restore once arithmetic operations use checked variants
    //clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,

    // Rust warnings/upstream
    dead_code,
    deprecated,
    deprecated_in_future,
    exported_private_dependencies,
    future_incompatible,
    invalid_doc_attributes,
    keyword_idents,
    macro_use_extern_crate,
    missing_debug_implementations,
    // TODO: restore once test modules are documented
    // missing_docs,
    non_ascii_idents,
    nonstandard_style,
    noop_method_call,
    trivial_bounds,
    trivial_casts,
    unreachable_code,
    unreachable_patterns,
    //unreachable_pub,
    unused_extern_crates,
    unused_import_braces,
    absolute_paths_not_starting_with_crate,

    // Unsafe code / low-level hazards
    clippy::undocumented_unsafe_blocks,
    // TODO: restore once numeric literal suffixes are underscored
    // clippy::unseparated_literal_suffix,
    // TODO: restore once tests stop using stderr for logging
    // clippy::print_stderr,
    // TODO: restore once Debug formatting is removed from tests
    // clippy::use_debug,

    // Documentation & diagnostics
    // TODO: restore once intra-doc links use backticks
    // clippy::doc_link_with_quotes,
    // TODO: restore once doc backtick warnings are fixed
    // clippy::doc_markdown,
    // TODO: restore once private items are documented
    // clippy::missing_docs_in_private_items
    // TODO: restore once error docs are added
    // clippy::missing_errors_doc,
    // TODO: restore once panic docs are added
    // clippy::missing_panics_doc,

    // API correctness / style
    // TODO: restore once const candidates are annotated
    // clippy::missing_const_for_fn,
    // TODO: restore once option map_or rewrites are done
    // clippy::option_if_let_else,
    // TODO: restore once if/else option patterns are simplified
    // clippy::if_then_some_else_none,
    // TODO: restore once trailing semicolons are added in tests
    // clippy::semicolon_if_nothing_returned,
    // TODO: restore once unused self args are cleaned up
    // clippy::unused_self,
    // TODO: restore once underscore bindings are cleaned up
    // clippy::used_underscore_binding,
    // TODO: restore once let-if chains are simplified
    // clippy::useless_let_if_seq,
    clippy::similar_names,
    // TODO: restore once shadowing in tests is cleaned up
    // clippy::shadow_unrelated,
    clippy::redundant_pub_crate,
    clippy::wildcard_dependencies,
    // TODO: restore once wildcard imports in tests are removed
    // clippy::wildcard_imports,

    // Numeric correctness
    // TODO: restore once float comparisons use tolerances
    // clippy::float_cmp,
    // clippy::float_cmp_const,
    // clippy::float_equality_without_abs,
    clippy::suspicious_operation_groupings,

    // no_std hygiene
    clippy::std_instead_of_core,

    // Misc polish
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::empty_line_after_outer_attr,
    clippy::empty_structs_with_brackets,
)]
// Advisory lints: useful, but not fatal
#![warn(
    // TODO: restore once Result assertions are rewritten
    // clippy::assertions_on_result_states,
    // TODO: restore once match-like macros are adjusted
    // clippy::match_like_matches_macro,
    // TODO: restore once continues are simplified
    // clippy::needless_continue,
    // TODO: restore once trait imports are adjusted
    // clippy::unused_trait_names,
    clippy::verbose_file_reads,
    // TODO: restore once arithmetic side effects are reviewed
    // clippy::arithmetic_side_effects,
    // TODO: restore once unsafe `as` conversions are fixed
    // clippy::as_conversions,
    // TODO: restore once pattern type mismatches in tests are fixed
    // clippy::pattern_type_mismatch
)]
// Use README.md as crate documentation.
#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]
// We'll default to building for no_std - use core, alloc instead of std.
#![no_std]

extern crate alloc;
use serde::Serialize;

// Import std crate if building with std support.
// We don't import types or macros from std.
// As a result, types and macros from std must be qualified via `std::`
// making dependencies on std easier to spot.
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(feature = "mimalloc")]
mimalloc::assign_global!();

mod ast;
mod builtins;
mod compile;
pub(crate) mod compiled_policy;
pub(crate) mod compiler;
pub(crate) mod engine;
pub(crate) mod indexchecker;
pub(crate) mod interpreter;

pub mod languages {
    #[cfg(feature = "azure-rbac")]
    pub mod azure_rbac;

    #[cfg(feature = "rvm")]
    pub mod rego;
}

mod lexer;
pub(crate) mod lookup;
pub(crate) mod number;
mod parser;
mod policy_info;
pub(crate) mod query;
#[cfg(feature = "azure_policy")]
pub mod registry;
#[cfg(feature = "rvm")]
pub mod rvm;
pub(crate) mod scheduler;
#[cfg(feature = "azure_policy")]
mod schema;
#[cfg(feature = "azure_policy")]
pub mod target;
#[cfg(any(test, all(feature = "yaml", feature = "std")))]
pub mod test_utils;
pub(crate) mod utils;
mod value;

#[cfg(feature = "azure_policy")]
pub use {
    compile::compile_policy_for_target,
    schema::{error::ValidationError, validate::SchemaValidator, Schema},
    target::Target,
};

pub use compile::{compile_policy_with_entrypoint, PolicyModule};
pub use compiled_policy::CompiledPolicy;
pub use engine::Engine;
pub use lexer::Source;
pub use policy_info::PolicyInfo;
pub use value::Value;

#[cfg(feature = "arc")]
pub use alloc::sync::Arc as Rc;

#[cfg(not(feature = "arc"))]
pub use alloc::rc::Rc;

#[cfg(feature = "std")]
use std::collections::{hash_map::Entry as MapEntry, HashMap as Map, HashSet as Set};

#[cfg(not(feature = "std"))]
use alloc::collections::{btree_map::Entry as MapEntry, BTreeMap as Map, BTreeSet as Set};

use alloc::{
    borrow::ToOwned,
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use core::fmt;

/// Location of an [`Expression`] in a Rego query.
///
/// ```
/// # use regorus::Engine;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "  \n  1 + 2".
/// let results = Engine::new().eval_query("  \n  1 + 2".to_string(), false)?;
///
/// // Fetch the location for the expression.
/// let loc = &results.result[0].expressions[0].location;
///
/// assert_eq!(loc.row, 2);
/// assert_eq!(loc.col, 3);
/// # Ok(())
/// # }
/// ````
/// See also [`QueryResult`].
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct Location {
    /// Line number. Starts at 1.
    pub row: u32,
    /// Column number. Starts at 1.
    pub col: u32,
}

/// An expression in a Rego query.
///
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 + 2".
/// let results = Engine::new().eval_query("1 + 2".to_string(), false)?;
///
/// // Fetch the expression from results.
/// let expr = &results.result[0].expressions[0];
///
/// assert_eq!(expr.value, Value::from(3u64));
/// assert_eq!(expr.text.as_ref(), "1 + 2");
/// # Ok(())
/// # }
/// ```
/// See also [`QueryResult`].
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct Expression {
    /// Computed value of the expression.
    pub value: Value,

    /// The Rego expression.
    pub text: Rc<str>,

    /// Location of the expression in the query string.
    pub location: Location,
}

/// Result of evaluating a Rego query.
///
/// A query containing single expression.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 + 2".
/// let results = Engine::new().eval_query("1 + 2".to_string(), false)?;
///
/// // Fetch the first (sole) result.
/// let result = &results.result[0];
///
/// assert_eq!(result.expressions[0].value, Value::from(3u64));
/// assert_eq!(result.expressions[0].text.as_ref(), "1 + 2");
/// # Ok(())
/// # }
/// ```
///
/// A query containing multiple expressions.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 + 2; 3.5 * 4".
/// let results = Engine::new().eval_query("1 + 2; 3.55 * 4".to_string(), false)?;
///
/// // Fetch the first (sole) result.
/// let result = &results.result[0];
///
/// // First expression.
/// assert_eq!(result.expressions[0].value, Value::from(3u64));
/// assert_eq!(result.expressions[0].text.as_ref(), "1 + 2");
///
/// // Second expression.
/// assert_eq!(result.expressions[1].value, Value::from(14.2));
/// assert_eq!(result.expressions[1].text.as_ref(), "3.55 * 4");
/// # Ok(())
/// # }
/// ```
///
/// Expressions that create bindings (i.e. associate names to values) evaluate to
/// either true or false. The value of bindings are available in the `bindings` field.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "x = 1; y = x > 0".
/// let results = Engine::new().eval_query("x = 1; y = x > 0".to_string(), false)?;
///
/// // Fetch the first (sole) result.
/// let result = &results.result[0];
///
/// // First expression is true.
/// assert_eq!(result.expressions[0].value, Value::from(true));
/// assert_eq!(result.expressions[0].text.as_ref(), "x = 1");
///
/// // Second expression is true.
/// assert_eq!(result.expressions[1].value, Value::from(true));
/// assert_eq!(result.expressions[1].text.as_ref(), "y = x > 0");
///
/// // bindings contains the value for each named expession.
/// assert_eq!(result.bindings[&Value::from("x")], Value::from(1u64));
/// assert_eq!(result.bindings[&Value::from("y")], Value::from(true));
/// # Ok(())
/// # }
/// ```
///
/// If any expression evaluates to false, then no results are produced.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "true; true; false".
/// let results = Engine::new().eval_query("true; true; false".to_string(), false)?;
///
/// assert!(results.result.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct QueryResult {
    /// Expressions in the query.
    ///
    /// Each statement in the query is treated as a separte expression.
    ///
    pub expressions: Vec<Expression>,

    /// Bindings created in the query.
    #[serde(skip_serializing_if = "Value::is_empty_object")]
    pub bindings: Value,
}

impl Default for QueryResult {
    fn default() -> Self {
        Self {
            bindings: Value::new_object(),
            expressions: vec![],
        }
    }
}

/// Results of evaluating a Rego query.
///
/// Generates the same `json` representation as `opa eval`.
///
/// Queries typically produce a single result.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 + 1".
/// let results = Engine::new().eval_query("1 + 1".to_string(), false)?;
///
/// assert_eq!(results.result.len(), 1);
/// assert_eq!(results.result[0].expressions[0].value, Value::from(2u64));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "1 + 1");
/// # Ok(())
/// # }
/// ```
///
/// If a query contains only one expression, and even if the expression evaluates
/// to false, the value will be returned.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 > 2" which is false.
/// let results = Engine::new().eval_query("1 > 2".to_string(), false)?;
///
/// assert_eq!(results.result.len(), 1);
/// assert_eq!(results.result[0].expressions[0].value, Value::from(false));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "1 > 2");
/// # Ok(())
/// # }
/// ```
///
/// In a query containing multiple expressions, if  any expression evaluates to false,
/// then no results are produced.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "true; true; false".
/// let results = Engine::new().eval_query("true; true; false".to_string(), false)?;
///
/// assert!(results.result.is_empty());
/// # Ok(())
/// # }
/// ```
///
/// Note that `=` is different from `==`. The former evaluates to undefined if the LHS and RHS
/// are not equal. The latter evaluates to either true or false.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// // Create engine and evaluate "1 = 2" which is undefined and produces no resutl.
/// let results = Engine::new().eval_query("1 = 2".to_string(), false)?;
///
/// assert_eq!(results.result.len(), 0);
///
/// // Create engine and evaluate "1 == 2" which evaluates to false.
/// let results = Engine::new().eval_query("1 == 2".to_string(), false)?;
///
/// assert_eq!(results.result.len(), 1);
/// assert_eq!(results.result[0].expressions[0].value, Value::from(false));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "1 == 2");
/// # Ok(())
/// # }
/// ```
///
/// Queries containing loops produce multiple results.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// let results = Engine::new().eval_query("x = [1, 2, 3][_]".to_string(), false)?;
///
/// // Three results are produced, one of each value of x.
/// assert_eq!(results.result.len(), 3);
///
/// // Assert expressions and bindings of results.
/// assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "x = [1, 2, 3][_]");
/// assert_eq!(results.result[0].bindings[&Value::from("x")], Value::from(1u64));
///
/// assert_eq!(results.result[1].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[1].expressions[0].text.as_ref(), "x = [1, 2, 3][_]");
/// assert_eq!(results.result[1].bindings[&Value::from("x")], Value::from(2u64));
///
/// assert_eq!(results.result[2].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[2].expressions[0].text.as_ref(), "x = [1, 2, 3][_]");
/// assert_eq!(results.result[2].bindings[&Value::from("x")], Value::from(3u64));
/// # Ok(())
/// # }
/// ```
///
/// Loop iterations that evaluate to false or undefined don't produce results.
/// ```
/// # use regorus::*;
/// # fn main() -> anyhow::Result<()> {
/// let results = Engine::new().eval_query("x = [1, 2, 3][_]; x >= 2".to_string(), false)?;
///
/// // Two results are produced, one for x = 2 and another for x = 3.
/// assert_eq!(results.result.len(), 2);
///
/// // Assert expressions and bindings of results.
/// assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "x = [1, 2, 3][_]");
/// assert_eq!(results.result[0].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[0].expressions[1].text.as_ref(), "x >= 2");
/// assert_eq!(results.result[0].bindings[&Value::from("x")], Value::from(2u64));
///
/// assert_eq!(results.result[1].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[1].expressions[0].text.as_ref(), "x = [1, 2, 3][_]");
/// assert_eq!(results.result[1].expressions[0].value, Value::Bool(true));
/// assert_eq!(results.result[1].expressions[1].text.as_ref(), "x >= 2");
/// assert_eq!(results.result[1].bindings[&Value::from("x")], Value::from(3u64));
/// # Ok(())
/// # }
/// ```
///
/// See [QueryResult] for examples of different kinds of results.
#[derive(Debug, Clone, Default, Serialize, Eq, PartialEq)]
pub struct QueryResults {
    /// Collection of results of evaluting a query.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub result: Vec<QueryResult>,
}

/// A user defined builtin function implementation.
///
/// It is not necessary to implement this trait directly.
pub trait Extension: FnMut(Vec<Value>) -> anyhow::Result<Value> + Send + Sync {
    /// Fn, FnMut etc are not sized and cannot be cloned in their boxed form.
    /// clone_box exists to overcome that.
    fn clone_box<'a>(&self) -> Box<dyn 'a + Extension>
    where
        Self: 'a;
}

/// Automatically make matching closures a valid [`Extension`].
impl<F> Extension for F
where
    F: FnMut(Vec<Value>) -> anyhow::Result<Value> + Clone + Send + Sync,
{
    fn clone_box<'a>(&self) -> Box<dyn 'a + Extension>
    where
        Self: 'a,
    {
        Box::new(self.clone())
    }
}

/// Implement clone for a boxed extension using [`Extension::clone_box`].
impl Clone for Box<dyn '_ + Extension> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

impl fmt::Debug for dyn Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        f.write_fmt(format_args!("<extension>"))
    }
}

#[cfg(feature = "coverage")]
#[cfg_attr(docsrs, doc(cfg(feature = "coverage")))]
pub mod coverage {
    use crate::*;

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    /// Coverage information about a rego policy file.
    pub struct File {
        /// Path of the policy file.
        pub path: String,

        /// The rego policy.
        pub code: String,

        /// Lines that were evaluated.
        pub covered: alloc::collections::BTreeSet<u32>,

        /// Lines that were not evaluated.
        pub not_covered: alloc::collections::BTreeSet<u32>,
    }

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    /// Policy coverage report.
    pub struct Report {
        /// Coverage information for files.
        pub files: Vec<File>,
    }

    impl Report {
        /// Produce an ANSI color encoded version of the report.
        ///
        /// Covered lines are green.
        /// Lines that are not covered are red.
        ///
        /// <img src="https://github.com/microsoft/regorus/blob/main/docs/coverage.png?raw=true">
        pub fn to_string_pretty(&self) -> anyhow::Result<String> {
            let mut s = String::default();
            s.push_str("COVERAGE REPORT:\n");
            for file in self.files.iter() {
                if file.not_covered.is_empty() {
                    s.push_str(&format!("{} has full coverage\n", file.path));
                    continue;
                }

                s.push_str(&format!("{}:\n", file.path));
                for (line, code) in file.code.split('\n').enumerate() {
                    let line = (line as u32).saturating_add(1);
                    if file.not_covered.contains(&line) {
                        s.push_str(&format!("\x1b[31m {line:4}  {code}\x1b[0m\n"));
                    } else if file.covered.contains(&line) {
                        s.push_str(&format!("\x1b[32m {line:4}  {code}\x1b[0m\n"));
                    } else {
                        s.push_str(&format!(" {line:4}  {code}\n"));
                    }
                }
            }

            s.push('\n');
            Ok(s)
        }
    }
}

/// Items in `unstable` are likely to change.
#[doc(hidden)]
pub mod unstable {
    pub use crate::ast::*;
    pub use crate::lexer::*;
    pub use crate::parser::*;
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests;
