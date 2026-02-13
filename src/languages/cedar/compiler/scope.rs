// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::error::{CompilerError, Result};
use crate::languages::cedar::ast::*;
use alloc::vec::Vec;

use super::helpers::path_to_string;
use super::Compiler;

impl Compiler {
    pub(super) fn compile_scope(&mut self, scope: &Scope) -> Result<u8> {
        self.with_span(&scope.span, |this| {
            let principal_match = this.compile_principal(&scope.principal)?;
            let action_match = this.compile_action(&scope.action)?;
            let resource_match = this.compile_resource(&scope.resource)?;

            let tmp = this.emit_and(principal_match, action_match)?;
            this.emit_and(tmp, resource_match)
        })
    }

    fn compile_principal(&mut self, principal: &Principal) -> Result<u8> {
        self.with_span(&principal.span, |this| {
            let principal_reg = this.get_principal_register()?;
            this.compile_qualifier(principal_reg, principal.qualifier.as_ref(), true)
        })
    }

    fn compile_action(&mut self, action: &Action) -> Result<u8> {
        let action_reg = self.get_action_register()?;
        match *action {
            Action::All => self.emit_load_bool(true),
            Action::Equals {
                ref span,
                ref entity,
            } => self.with_span(span, |this| {
                let entity_reg = this.compile_entity(entity)?;
                this.emit_eq(action_reg, entity_reg)
            }),
            Action::In {
                ref span,
                ref entities,
            } => self.with_span(span, |this| {
                let list_reg = this.compile_entity_list(entities)?;
                this.emit_cedar_in_set(action_reg, list_reg)
            }),
        }
    }

    fn compile_resource(&mut self, resource: &Resource) -> Result<u8> {
        self.with_span(&resource.span, |this| {
            let resource_reg = this.get_resource_register()?;
            this.compile_qualifier(resource_reg, resource.qualifier.as_ref(), false)
        })
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

        self.with_span(qualifier.span(), |this| match *qualifier {
            Qualifier::Equals { ref category, .. } => {
                let entity_reg = this.compile_entity_or_template(category, is_principal)?;
                this.emit_eq(subject_reg, entity_reg)
            }
            Qualifier::In { ref category, .. } => {
                let entity_reg = this.compile_entity_or_template(category, is_principal)?;
                this.emit_cedar_in(subject_reg, entity_reg)
            }
            Qualifier::IsIn {
                ref path,
                ref category,
                ..
            } => {
                let type_reg = this.emit_load_literal(path_to_string(path)?)?;
                let is_reg = this.emit_cedar_is(subject_reg, type_reg)?;
                if let Some(category) = category.as_ref() {
                    let entity_reg = this.compile_entity_or_template(category, is_principal)?;
                    let in_check = this.emit_cedar_in(subject_reg, entity_reg)?;
                    this.emit_and(is_reg, in_check)
                } else {
                    Ok(is_reg)
                }
            }
        })
    }

    pub(super) fn compile_conditions(&mut self, conditions: &[Condition]) -> Result<u8> {
        let mut regs = Vec::new();

        for condition in conditions {
            let reg = self.with_span(&condition.span, |this| {
                let mut expr_regs = Vec::new();
                for expr in &condition.exprs {
                    expr_regs.push(this.compile_expr(expr)?);
                }

                let combined = this.fold_and(expr_regs)?;
                let reg = match condition.ctype {
                    ConditionType::When => combined,
                    ConditionType::Unless => this.emit_not(combined)?,
                };
                Ok(reg)
            })?;
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
