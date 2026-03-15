// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::builtins;
use crate::value::Value;

use super::errors::{Result, VmError};
use super::execution_model::ExecutionMode;
use super::machine::RegoVM;

impl RegoVM {
    pub(super) fn execute_function_call(&mut self, params_index: u16) -> Result<()> {
        let params = self
            .program
            .instruction_data
            .get_function_call_params(params_index)
            .cloned()
            .ok_or(VmError::InvalidFunctionCallParamsIndex {
                index: params_index,
                pc: self.pc,
                available: self.program.instruction_data.function_call_params.len(),
            })?;
        let call_result = match self.execution_mode {
            ExecutionMode::RunToCompletion => {
                self.execute_call_rule_common(params.dest, params.func_rule_index, Some(&params))
            }
            ExecutionMode::Suspendable => self.execute_call_rule_suspendable(
                params.dest,
                params.func_rule_index,
                Some(&params),
            ),
        };

        call_result?;

        self.memory_check()?;
        Ok(())
    }

    pub(super) fn execute_builtin_call(&mut self, params_index: u16) -> Result<()> {
        let params = self
            .program
            .instruction_data
            .get_builtin_call_params(params_index)
            .ok_or(VmError::InvalidBuiltinCallParamsIndex {
                index: params_index,
                pc: self.pc,
                available: self.program.instruction_data.builtin_call_params.len(),
            })?;
        let dest = params.dest;
        let builtin_index = params.builtin_index;
        let builtin_info = self.program.get_builtin_info(builtin_index).ok_or(
            VmError::InvalidBuiltinInfoIndex {
                index: builtin_index,
                pc: self.pc,
                available: self.program.builtin_info_table.len(),
            },
        )?;

        let mut args = core::mem::take(&mut self.cached_builtin_args);
        args.clear();
        for &arg_reg in params.arg_registers().iter() {
            let arg_value = self.get_register(arg_reg)?.clone();
            args.push(arg_value);
        }

        let expected_args = builtin_info.num_args;
        let actual_args = args.len();
        if u16::try_from(actual_args).unwrap_or(u16::MAX) != expected_args {
            self.cached_builtin_args = args;
            return Err(VmError::BuiltinArgumentMismatch {
                expected: expected_args,
                actual: actual_args,
                pc: self.pc,
            });
        }

        let builtin_name = builtin_info.name.clone();

        if args.iter().any(|a| a == &Value::Undefined) {
            self.cached_builtin_args = args;
            self.set_register(dest, Value::Undefined)?;
            #[cfg(feature = "explanations")]
            self.provenance.clear_reg(dest);
            self.memory_check()?;
            return Ok(());
        }

        let builtin_fcn = match self.program.get_resolved_builtin(builtin_index) {
            Some(fcn) => fcn.0,
            None => {
                self.cached_builtin_args = args;
                return Err(VmError::BuiltinNotResolved {
                    name: builtin_name,
                    pc: self.pc,
                });
            }
        };
        let cache_name = builtins::must_cache(builtin_name.as_str());

        self.ensure_dummy_exprs(args.len())?;
        let dummy_span = self.get_dummy_span()?.clone();
        let dummy_exprs = core::mem::take(&mut self.dummy_exprs);

        if let Some(name) = cache_name {
            if let Some(entries) = self.builtins_cache.get(name) {
                for entry in entries {
                    if entry.0.as_slice() == args.as_slice() {
                        let cached = entry.1.clone();
                        self.dummy_exprs = dummy_exprs;
                        self.cached_builtin_args = args;
                        self.set_register(dest, cached)?;
                        #[cfg(feature = "explanations")]
                        self.provenance.clear_reg(dest);
                        self.memory_check()?;
                        return Ok(());
                    }
                }
            }
        }

        let result = match builtin_fcn(
            &dummy_span,
            dummy_exprs.get(..args.len()).unwrap_or(&[]),
            &args,
            self.strict_builtin_errors,
        ) {
            Ok(value) => value,
            Err(_) if !self.strict_builtin_errors => Value::Undefined,
            Err(err) => {
                self.dummy_exprs = dummy_exprs;
                self.cached_builtin_args = args;
                return Err(err.into());
            }
        };

        self.dummy_exprs = dummy_exprs;

        #[cfg(feature = "explanations")]
        self.provenance.clear_reg(dest);

        if let Some(name) = cache_name {
            let cache_args = core::mem::take(&mut args);
            self.cached_builtin_args = args;
            self.builtins_cache
                .entry(name)
                .or_default()
                .push((cache_args, result.clone()));
            self.set_register(dest, result)?;
        } else {
            self.cached_builtin_args = args;
            self.set_register(dest, result)?;
        }

        self.memory_check()?;

        Ok(())
    }
}
