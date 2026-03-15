// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::builtins;
use crate::value::Value;
use alloc::string::String;
use alloc::vec::Vec;

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

        let mut args = Vec::new();
        for &arg_reg in params.arg_registers().iter() {
            let arg_value = self.get_register(arg_reg)?.clone();
            args.push(arg_value);
        }

        let expected_args = builtin_info.num_args;
        let actual_args = args.len();
        if u16::try_from(actual_args).unwrap_or(u16::MAX) != expected_args {
            return Err(VmError::BuiltinArgumentMismatch {
                expected: expected_args,
                actual: actual_args,
                pc: self.pc,
            });
        }

        let builtin_name = builtin_info.name.clone();

        if args.iter().any(|a| a == &Value::Undefined) {
            self.set_register(dest, Value::Undefined)?;
            #[cfg(feature = "explanations")]
            self.provenance.clear_reg(dest);
            self.memory_check()?;
            return Ok(());
        }

        if let Some(builtin_fcn) = self.program.get_resolved_builtin(builtin_index) {
            let dummy_source = crate::lexer::Source::from_contents("arg".into(), String::new())?;
            let dummy_span = crate::lexer::Span {
                source: dummy_source,
                line: 1,
                col: 1,
                start: 0,
                end: 3,
            };

            let mut dummy_exprs: Vec<crate::ast::Ref<crate::ast::Expr>> = Vec::new();
            for _ in 0..args.len() {
                let dummy_expr = crate::ast::Expr::Null {
                    span: dummy_span.clone(),
                    value: Value::Null,
                    eidx: 0,
                };
                dummy_exprs.push(crate::ast::Ref::new(dummy_expr));
            }

            let cache_name = builtins::must_cache(builtin_name.as_str());
            if let Some(name) = cache_name {
                if let Some(value) = self.builtins_cache.get(&(name, args.clone())) {
                    self.set_register(dest, value.clone())?;
                    #[cfg(feature = "explanations")]
                    self.provenance.clear_reg(dest);
                    self.memory_check()?;
                    return Ok(());
                }
            }

            let result =
                match (builtin_fcn.0)(&dummy_span, &dummy_exprs, &args, self.strict_builtin_errors)
                {
                    Ok(value) => value,
                    Err(_) if !self.strict_builtin_errors => Value::Undefined,
                    Err(err) => return Err(err.into()),
                };

            if result == Value::Undefined {
                self.set_register(dest, Value::Undefined)?;
            } else {
                self.set_register(dest, result.clone())?;
            }

            #[cfg(feature = "explanations")]
            self.provenance.clear_reg(dest);

            if let Some(name) = cache_name {
                self.builtins_cache.insert((name, args), result);
            }

            self.memory_check()?;
        } else {
            return Err(VmError::BuiltinNotResolved {
                name: builtin_name,
                pc: self.pc,
            });
        }

        Ok(())
    }
}
