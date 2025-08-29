//! Z3 Integration Module
//!
//! This module provides Z3 theorem prover integration for Regorus,
//! enabling formal verification, policy analysis, and constraint solving.

pub mod converter;
pub mod verifier;

// Re-export main public types
pub use converter::RegoToZ3Converter;
pub use verifier::{ConsistencyResult, CounterExample, TestCase, Z3PolicyVerifier};

// Feature-gated Z3 context utilities
pub mod context {
    use z3::{Config, Context};

    /// Create a standard Z3 context with common settings
    pub fn create_context() -> Context {
        let cfg = Config::new();
        Context::new(&cfg)
    }

    /// Create a Z3 context optimized for SMT solving
    pub fn create_smt_context() -> Context {
        let mut cfg = Config::new();
        cfg.set_timeout_msec(30000); // 30 second timeout
        cfg.set_bool_param_value("model", true);
        Context::new(&cfg)
    }

    /// Create a Z3 context optimized for SAT solving
    pub fn create_sat_context() -> Context {
        let mut cfg = Config::new();
        cfg.set_timeout_msec(10000); // 10 second timeout
        cfg.set_bool_param_value("auto_config", false);
        cfg.set_param_value("sat.phase", "caching");
        Context::new(&cfg)
    }
}

/// Common Z3 integration utilities
pub mod utils {
    use crate::ast::*;
    use crate::value::Value;
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    /// Convert a Regorus Value to a string representation for Z3
    pub fn value_to_z3_string(value: &Value) -> String {
        match value {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => format!("{:?}", n),
            Value::String(s) => format!("\"{}\"", s),
            Value::Array(arr) => {
                let elements: Vec<String> = arr.iter().map(value_to_z3_string).collect();
                format!("[{}]", elements.join(", "))
            }
            Value::Object(obj) => {
                let pairs: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, value_to_z3_string(v)))
                    .collect();
                format!("{{{}}}", pairs.join(", "))
            }
            Value::Set(set) => {
                let elements: Vec<String> = set.iter().map(value_to_z3_string).collect();
                format!("{{{}}}", elements.join(", "))
            }
            Value::Undefined => "undefined".to_string(),
        }
    }

    /// Extract variable names from an expression
    pub fn extract_variables(expr: &Ref<Expr>) -> Vec<String> {
        let mut vars = Vec::new();
        extract_variables_recursive(expr, &mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    fn extract_variables_recursive(expr: &Ref<Expr>, vars: &mut Vec<String>) {
        match expr.as_ref() {
            Expr::Var { value, .. } => {
                if let Value::String(name) = value {
                    vars.push(name.to_string());
                }
            }
            Expr::BoolExpr { lhs, rhs, .. } => {
                extract_variables_recursive(lhs, vars);
                extract_variables_recursive(rhs, vars);
            }
            Expr::ArithExpr { lhs, rhs, .. } => {
                extract_variables_recursive(lhs, vars);
                extract_variables_recursive(rhs, vars);
            }
            Expr::UnaryExpr { expr, .. } => {
                extract_variables_recursive(expr, vars);
            }
            Expr::Membership {
                value, collection, ..
            } => {
                extract_variables_recursive(value, vars);
                extract_variables_recursive(collection, vars);
            }
            Expr::RefDot { refr, .. } => {
                extract_variables_recursive(refr, vars);
            }
            Expr::RefBrack { refr, index, .. } => {
                extract_variables_recursive(refr, vars);
                extract_variables_recursive(index, vars);
            }
            Expr::Call { params, .. } => {
                for param in params {
                    extract_variables_recursive(param, vars);
                }
            }
            Expr::Array { items, .. } => {
                for item in items {
                    extract_variables_recursive(item, vars);
                }
            }
            Expr::Set { items, .. } => {
                for item in items {
                    extract_variables_recursive(item, vars);
                }
            }
            Expr::Object { fields, .. } => {
                for (_, key, value) in fields {
                    extract_variables_recursive(key, vars);
                    extract_variables_recursive(value, vars);
                }
            }
            // Add more cases as needed
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;
    use crate::alloc::string::ToString;

    #[test]
    fn test_value_to_z3_string() {
        assert_eq!(utils::value_to_z3_string(&Value::Bool(true)), "true");
        assert_eq!(
            utils::value_to_z3_string(&Value::String("test".to_string().into())),
            "\"test\""
        );
    }

    #[test]
    fn test_module_imports() {
        // Test that all modules can be imported
        let _verifier = verifier::Z3PolicyVerifier::new();
    }
}
