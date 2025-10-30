// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Functions responsible for building destructuring plans.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::ast::{Expr, ExprRef};
use crate::compiler::destructuring_planner::context::OverlayBindingContext;
use crate::compiler::destructuring_planner::utils::extract_literal_key;
use crate::compiler::destructuring_planner::{
    DestructuringPlan, ScopingMode, VariableBindingContext,
};

/// Create a destructuring plan for an expression using a variable binding context.
pub fn create_destructuring_plan<T: VariableBindingContext>(
    expr: &ExprRef,
    context: &T,
    scoping: ScopingMode,
) -> Option<DestructuringPlan> {
    let mut newly_bound = BTreeSet::new();
    create_destructuring_plan_with_tracking(expr, context, scoping, &mut newly_bound)
}

/// Create a destructuring plan while tracking newly bound variables.
pub(crate) fn create_destructuring_plan_with_tracking<T: VariableBindingContext>(
    expr: &ExprRef,
    context: &T,
    scoping: ScopingMode,
    newly_bound: &mut BTreeSet<String>,
) -> Option<DestructuringPlan> {
    let overlay = OverlayBindingContext {
        base: context,
        newly_bound,
    };

    match expr.as_ref() {
        // Variable binding
        Expr::Var { span: name, .. } => {
            if name.text() == "_" {
                return Some(DestructuringPlan::Ignore);
            }
            if overlay.is_var_unbound(name.text(), scoping) {
                newly_bound.insert(name.text().to_string());
                Some(DestructuringPlan::Var(name.clone()))
            } else {
                // Already bound - treat as equality check
                Some(DestructuringPlan::EqualityExpr(expr.clone()))
            }
        }

        Expr::String { value, .. }
        | Expr::RawString { value, .. }
        | Expr::Number { value, .. }
        | Expr::Bool { value, .. }
        | Expr::Null { value, .. } => Some(DestructuringPlan::EqualityValue(value.clone())),

        // Array destructuring
        Expr::Array { items, .. } => {
            let mut element_plans = Vec::new();
            for item in items {
                if let Some(plan) =
                    create_destructuring_plan_with_tracking(item, context, scoping, newly_bound)
                {
                    element_plans.push(plan);
                } else {
                    // If any element can't be destructured, fail the whole array
                    return None;
                }
            }
            Some(DestructuringPlan::Array { element_plans })
        }

        // Object destructuring
        Expr::Object { fields, .. } => {
            let mut field_plans = BTreeMap::new();
            let mut dynamic_fields = Vec::new();
            for (_, key_expr, value_expr) in fields {
                if let Some(value_plan) = create_destructuring_plan_with_tracking(
                    value_expr,
                    context,
                    scoping,
                    newly_bound,
                ) {
                    if let Some(key_value) = extract_literal_key(key_expr) {
                        field_plans.insert(key_value, value_plan);
                    } else {
                        dynamic_fields.push((key_expr.clone(), value_plan));
                    }
                } else {
                    return None;
                }
            }

            Some(DestructuringPlan::Object {
                field_plans,
                dynamic_fields,
            })
        }

        // Set destructuring is not supported - but only fail if the set contains unbound variables
        // Otherwise treat it as an equality check (e.g., for literal sets or empty sets)
        Expr::Set { items, .. } => {
            // Check if any item in the set contains unbound variables
            let has_unbound_vars = items.iter().any(|item| {
                if let Expr::Var { span: name, .. } = item.as_ref() {
                    overlay.is_var_unbound(name.text(), scoping)
                } else {
                    false
                }
            });

            if has_unbound_vars {
                // Set contains unbound variables - can't destructure
                None
            } else {
                // Set is a literal or contains only bound vars - treat as equality check
                Some(DestructuringPlan::EqualityExpr(expr.clone()))
            }
        }

        // For all others, treat as equality checks
        _ => Some(DestructuringPlan::EqualityExpr(expr.clone())),
    }
}
