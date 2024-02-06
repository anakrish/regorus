// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Use README.md as crate documentation.
#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use serde::Serialize;

mod ast;
mod builtins;
mod engine;
mod interpreter;
mod lexer;
mod number;
mod parser;
mod scheduler;
mod utils;
mod value;

pub use engine::Engine;
pub use value::Value;

#[cfg(feature = "bindings")]
pub mod bindings;

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
#[derive(Debug, Clone, Serialize)]
pub struct Location {
    /// Line number. Starts at 1.
    pub row: u16,
    /// Column number. Starts at 1.
    pub col: u16,
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
#[derive(Debug, Clone, Serialize)]
pub struct Expression {
    /// Computed value of the expression.
    pub value: Value,

    /// The Rego expression.
    pub text: std::rc::Rc<str>,

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
#[derive(Debug, Clone, Serialize)]
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
/// // Create engine and evaluate "true; true; false".
/// let results = Engine::new().eval_query("1 + 1".to_string(), false)?;
///
/// assert!(results.result.len() == 1);
/// assert_eq!(results.result[0].expressions[0].value, Value::from(2u64));
/// assert_eq!(results.result[0].expressions[0].text.as_ref(), "1 + 1");
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
#[derive(Debug, Clone, Default, Serialize)]
pub struct QueryResults {
    /// Collection of results of evaluting a query.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub result: Vec<QueryResult>,
}

/// Items in `unstable` are likely to change.
#[doc(hidden)]
pub mod unstable {
    pub use crate::ast::*;
    pub use crate::lexer::*;
    pub use crate::parser::*;
}

#[cfg(test)]
mod tests;