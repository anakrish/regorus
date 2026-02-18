// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::error::{CompilerError, Result};
use crate::languages::cedar::ast::*;
use alloc::vec::Vec;

use super::helpers::path_to_string;
use super::Compiler;

impl Compiler {
    pub(super) fn compile_scope(&mut self, scope: &Scope) -> Result<u8> {
        let principal_match = self.compile_principal(&scope.principal)?;
        let action_match = self.compile_action(&scope.action)?;
        let resource_match = self.compile_resource(&scope.resource)?;

        let tmp = self.emit_and(principal_match, action_match)?;
        self.emit_and(tmp, resource_match)
    }

    fn compile_principal(&mut self, principal: &Principal) -> Result<u8> {
        let principal_reg = self.get_principal_register()?;
        self.compile_qualifier(principal_reg, principal.qualifier.as_ref(), true)
    }

    fn compile_action(&mut self, action: &Action) -> Result<u8> {
        let action_reg = self.get_action_register()?;
        match *action {
            Action::All => self.emit_load_bool(true),
            Action::Equals { ref entity, .. } => {
                let entity_reg = self.compile_entity(entity)?;
                self.emit_eq(action_reg, entity_reg)
            }
            Action::In { ref entities, .. } => {
                let list_reg = self.compile_entity_list(entities)?;
                self.emit_cedar_in_set(action_reg, list_reg)
            }
        }
    }

    fn compile_resource(&mut self, resource: &Resource) -> Result<u8> {
        let resource_reg = self.get_resource_register()?;
        self.compile_qualifier(resource_reg, resource.qualifier.as_ref(), false)
    }

    fn compile_qualifier(
        &mut self,
        subject_reg: u8,
        qualifier: Option<&Qualifier>,
        is_principal: bool,
    ) -> Result<u8> {
        let Some(qualifier) = qualifier else {
            return self.emit_load_bool(true);
        };

        match *qualifier {
            Qualifier::Equals { ref category, .. } => {
                let entity_reg = self.compile_entity_or_template(category, is_principal)?;
                self.emit_eq(subject_reg, entity_reg)
            }
            Qualifier::In { ref category, .. } => {
                let entity_reg = self.compile_entity_or_template(category, is_principal)?;
                self.emit_cedar_in(subject_reg, entity_reg)
            }
            Qualifier::IsIn {
                ref path,
                ref category,
                ..
            } => {
                let type_reg = self.emit_load_literal(path_to_string(path)?)?;
                let is_reg = self.emit_cedar_is(subject_reg, type_reg)?;
                if let Some(category) = category.as_ref() {
                    let entity_reg = self.compile_entity_or_template(category, is_principal)?;
                    let in_check = self.emit_cedar_in(subject_reg, entity_reg)?;
                    self.emit_and(is_reg, in_check)
                } else {
                    Ok(is_reg)
                }
            }
        }
    }

    pub(super) fn compile_conditions(&mut self, conditions: &[Condition]) -> Result<u8> {
        let mut regs = Vec::new();

        for condition in conditions {
            let mut expr_regs = Vec::new();
            for expr in &condition.exprs {
                expr_regs.push(self.compile_expr(expr)?);
            }

            let combined = self.fold_and(expr_regs)?;
            let reg = match condition.ctype {
                ConditionType::When => combined,
                ConditionType::Unless => self.emit_not(combined)?,
            };
            regs.push(reg);
        }

        self.fold_and(regs)
    }

    fn compile_entity_or_template(
        &mut self,
        entity: &EntityOrTemplate,
        _is_principal: bool,
    ) -> Result<u8> {
        match *entity {
            EntityOrTemplate::Entity { ref entity } => self.compile_entity(entity),
            EntityOrTemplate::Template { .. } => Err(CompilerError::TemplateUnsupported.into()),
        }
    }
}
