// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::value::Value;
use alloc::string::String;
use alloc::vec::Vec;

use super::dispatch::InstructionOutcome;
use super::errors::{Result, VmError};
use super::machine::RegoVM;

impl RegoVM {
    pub fn execute(&mut self) -> Result<Value> {
        self.reset_execution_state();

        self.jump_to(0)
    }

    pub fn execute_entry_point_by_index(&mut self, index: usize) -> Result<Value> {
        let entry_points: Vec<(String, usize)> = self
            .program
            .entry_points
            .iter()
            .map(|(name, pc)| (name.clone(), *pc))
            .collect();

        if index >= entry_points.len() {
            return Err(VmError::InvalidEntryPointIndex {
                index,
                max_index: entry_points.len().saturating_sub(1),
            });
        }

        let (_entry_point_name, entry_point_pc) = &entry_points[index];

        if *entry_point_pc >= self.program.instructions.len() {
            return Err(VmError::Internal(alloc::format!(
                "Entry point PC {} >= instruction count {} for index {} | {}",
                entry_point_pc,
                self.program.instructions.len(),
                index,
                self.get_debug_state()
            )));
        }

        self.reset_execution_state();

        if let Err(e) = self.validate_vm_state() {
            return Err(VmError::Internal(alloc::format!(
                "VM state validation failed before entry point execution: {} | {}",
                e,
                self.get_debug_state()
            )));
        }

        self.jump_to(*entry_point_pc)
    }

    pub fn execute_entry_point_by_name(&mut self, name: &str) -> Result<Value> {
        let entry_point_pc =
            self.program
                .get_entry_point(name)
                .ok_or_else(|| VmError::EntryPointNotFound {
                    name: String::from(name),
                    available: self.program.entry_points.keys().cloned().collect(),
                })?;

        if entry_point_pc >= self.program.instructions.len() {
            return Err(VmError::Internal(alloc::format!(
                "Entry point PC {} >= instruction count {} for '{}' | {}",
                entry_point_pc,
                self.program.instructions.len(),
                name,
                self.get_debug_state()
            )));
        }

        self.reset_execution_state();

        if let Err(e) = self.validate_vm_state() {
            return Err(VmError::Internal(alloc::format!(
                "VM state validation failed before entry point execution: {} | {}",
                e,
                self.get_debug_state()
            )));
        }

        self.jump_to(entry_point_pc)
    }

    pub(super) fn jump_to(&mut self, target: usize) -> Result<Value> {
        let program = self.program.clone();
        self.pc = target;
        while self.pc < program.instructions.len() {
            if self.executed_instructions >= self.max_instructions {
                return Err(VmError::InstructionLimitExceeded {
                    limit: self.max_instructions,
                });
            }

            self.executed_instructions += 1;
            let instruction = program.instructions[self.pc].clone();

            match self.execute_instruction(&program, instruction)? {
                InstructionOutcome::Continue => {
                    self.pc += 1;
                }
                InstructionOutcome::Return(value) => {
                    return Ok(value);
                }
                InstructionOutcome::Break => {
                    return Ok(self.registers[0].clone());
                }
            }
        }

        Ok(self.registers[0].clone())
    }
}
