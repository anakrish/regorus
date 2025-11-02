// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Expression-level result structures captured by the analyser.

use alloc::string::String;

use super::virtual_data::VirtualDataLookup;
use crate::type_analysis::constants::{ConstantFact, ConstantStore};
use crate::type_analysis::context::{DynamicReferencePattern, LookupContext};
use crate::type_analysis::model::TypeFact;
use crate::value::Value;

/// Combined set of per-expression facts and constant information.
#[derive(Clone, Debug, Default)]
pub struct ExpressionFacts {
    pub facts: LookupContext,
    pub constants: ConstantStore,
}

impl ExpressionFacts {
    /// Retrieve the inferred `TypeFact` for the expression, if any.
    pub fn fact(&self, module_idx: u32, expr_idx: u32) -> Option<&TypeFact> {
        self.facts.get_expr(module_idx, expr_idx)
    }

    /// Retrieve the constant fact backing an expression, if any.
    pub fn constant_fact(&self, module_idx: u32, expr_idx: u32) -> Option<&ConstantFact> {
        self.constants.get(module_idx, expr_idx)
    }

    /// Retrieve the inferred constant value for an expression, if known.
    pub fn constant_value(&self, module_idx: u32, expr_idx: u32) -> Option<&Value> {
        self.constant_fact(module_idx, expr_idx)
            .and_then(|fact| fact.value.as_ref())
    }

    /// Iterate the set of rules that the analyzer marked as reachable.
    pub fn reachable_rules(&self) -> impl Iterator<Item = &String> {
        self.facts.reachable_rules()
    }

    /// Access the catalog of dynamic reference patterns discovered during analysis.
    pub fn dynamic_references(&self) -> &[DynamicReferencePattern] {
        self.facts.dynamic_references()
    }

    /// Retrieve virtual data lookup metadata recorded for this expression, if any.
    pub fn virtual_data_lookup(
        &self,
        module_idx: u32,
        expr_idx: u32,
    ) -> Option<&VirtualDataLookup> {
        self.facts.get_virtual_data_lookup(module_idx, expr_idx)
    }

    /// Retrieve the list of rule references recorded for an expression.
    pub fn rule_references(&self, module_idx: u32, expr_idx: u32) -> Option<&[String]> {
        self.facts.get_rule_references(module_idx, expr_idx)
    }
}
