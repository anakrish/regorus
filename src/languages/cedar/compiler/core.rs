// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::as_conversions)]

use super::error::{CompilerError, Result};
use crate::languages::cedar::ast::{Effect, Policy};
use crate::lexer::{Source, Span};
use crate::rvm::program::Program;
use crate::rvm::Instruction;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

#[derive(Debug)]
pub struct Compiler {
    pub(super) program: Program,
    pub(super) next_reg: u8,
    pub(super) builtin_index_map: BTreeMap<String, u16>,
    pub(super) source_to_index: BTreeMap<String, usize>,
    pub(super) current_span: Option<Span>,
    pub(super) input_reg: Option<u8>,
    pub(super) principal_reg: Option<u8>,
    pub(super) action_reg: Option<u8>,
    pub(super) resource_reg: Option<u8>,
    pub(super) context_reg: Option<u8>,
    pub(super) entities_reg: Option<u8>,
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            program: Program::new(),
            next_reg: 0,
            builtin_index_map: BTreeMap::new(),
            source_to_index: BTreeMap::new(),
            current_span: None,
            input_reg: None,
            principal_reg: None,
            action_reg: None,
            resource_reg: None,
            context_reg: None,
            entities_reg: None,
        }
    }

    pub fn compile(mut self, policies: &[Policy]) -> Result<Program> {
        let mut permit_regs = Vec::new();
        let mut deny_regs = Vec::new();

        for policy in policies {
            let match_reg = self.with_span(&policy.span, |this| {
                let scope_reg = this.compile_scope(&policy.scope)?;
                let conditions_reg = this.compile_conditions(&policy.conditions)?;
                this.emit_and(scope_reg, conditions_reg)
            })?;

            match policy.effect {
                Effect::Permit => permit_regs.push(match_reg),
                Effect::Forbid => deny_regs.push(match_reg),
            }
        }

        self.current_span = None;
        let permit_any = self.fold_or(permit_regs)?;
        let deny_any = self.fold_or(deny_regs)?;
        let deny_not = self.emit_not(deny_any)?;
        let permit_exclusive = self.emit_and(permit_any, deny_not)?;

        let decision_reg = self.emit_to_number(permit_exclusive)?;

        self.emit_instruction(Instruction::Return {
            value: decision_reg,
        });

        self.program.main_entry_point = 0;
        self.program.dispatch_window_size = self.next_reg;
        self.program.max_rule_window_size = self.next_reg;
        self.program
            .entry_points
            .insert(String::from("cedar.authorize"), 0);

        if !self.program.builtin_info_table.is_empty() {
            self.program.initialize_resolved_builtins().map_err(|err| {
                super::error::SpannedCompilerError::from(super::error::CompilerError::General {
                    message: format!("{err}"),
                })
            })?;
        }

        self.program.validate_limits().map_err(|message| {
            super::error::SpannedCompilerError::from(CompilerError::General { message })
        })?;

        Ok(self.program)
    }

    pub(super) fn fold_and(&mut self, regs: Vec<u8>) -> Result<u8> {
        let mut iter = regs.into_iter();
        let mut current = match iter.next() {
            Some(reg) => reg,
            None => return self.emit_load_bool(true),
        };

        for reg in iter {
            current = self.emit_and(current, reg)?;
        }
        Ok(current)
    }

    pub(super) fn fold_or(&mut self, regs: Vec<u8>) -> Result<u8> {
        let mut iter = regs.into_iter();
        let mut current = match iter.next() {
            Some(reg) => reg,
            None => return self.emit_load_bool(false),
        };

        for reg in iter {
            current = self.emit_or(current, reg)?;
        }
        Ok(current)
    }

    pub(super) fn alloc_register(&mut self) -> Result<u8> {
        if self.next_reg == u8::MAX {
            return Err(CompilerError::RegisterOverflow.into());
        }
        let reg = self.next_reg;
        self.next_reg = self.next_reg.saturating_add(1);
        Ok(reg)
    }

    pub(super) fn with_span<T, F>(&mut self, span: &Span, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let previous = self.current_span.clone();
        self.current_span = Some(span.clone());
        let result = f(self);
        self.current_span = previous;
        result
    }

    pub(super) fn get_or_create_source_index(&mut self, source: &Source) -> usize {
        let source_path = source.get_path().to_string();
        if let Some(&index) = self.source_to_index.get(&source_path) {
            return index;
        }

        let index = self
            .program
            .add_source(source_path.clone(), source.get_contents().to_string());
        self.source_to_index.insert(source_path, index);
        index
    }
}
