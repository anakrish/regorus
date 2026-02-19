// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Policy AST -> RVM compiler (core subset).
//!
//! This compiler currently targets the parser AST in `super::ast` and supports:
//! - Logical combinators: `allOf`, `anyOf`, `not`
//! - Core operators over field/value/count expressions
//! - Template expressions used in the current core tests
//! - `count` and `count.where`
//!
//! Alias normalization/mapping is intentionally deferred. Alias-like paths are
//! currently treated as direct paths under `input.resource`.
//!
//! The compiler is split across several files:
//! - [`conditions`]: constraint / condition / LHS compilation
//! - [`count`]: `count` / `count.where` loops and binding resolution
//! - [`expressions`]: template-expression and call-expression compilation
//! - [`fields`]: field-kind and resource-path compilation
//! - [`utils`]: pure helper functions (path splitting, JSON conversion)

mod conditions;
mod count;
mod expressions;
mod fields;
mod utils;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{EffectKind, PolicyDefinition, PolicyRule};
use crate::rvm::instructions::{BuiltinCallParams, ChainedIndexParams, LiteralOrRegister};
use crate::rvm::program::{Program, SpanInfo};
use crate::rvm::Instruction;
use crate::{Rc, Value};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CountBinding {
    name: Option<String>,
    field_wildcard_prefix: Option<String>,
    current_reg: u8,
}

#[derive(Debug, Default)]
struct Compiler {
    program: Program,
    register_counter: u8,
    source_to_index: BTreeMap<String, usize>,
    builtin_index: BTreeMap<String, u16>,
    count_bindings: Vec<CountBinding>,
    /// Map from lowercase fully-qualified alias name → short name.
    ///
    /// Populated from [`AliasRegistry::alias_map()`] so the compiler can
    /// resolve aliases like `"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"`
    /// to short names like `"supportsHttpsTrafficOnly"` without knowing the
    /// resource type.
    alias_map: BTreeMap<String, String>,
    /// Default values for policy parameters, built from `PolicyDefinition.parameters`.
    ///
    /// Stored as a `Value::Object` mapping parameter names to their default values.
    /// When set, the compiler emits a builtin call for `parameters()` that falls
    /// back to these defaults when the caller does not supply a value.
    parameter_defaults: Option<Value>,
}

// ---------------------------------------------------------------------------
// Core infrastructure + top-level compile / effect
// ---------------------------------------------------------------------------

impl Compiler {
    fn new() -> Self {
        Self {
            register_counter: 0,
            ..Self::default()
        }
    }

    fn compile(mut self, rule: &PolicyRule) -> Result<Rc<Program>> {
        let cond_reg = self.compile_constraint(&rule.condition)?;
        self.emit(
            Instruction::ReturnUndefinedIfNotTrue {
                condition: cond_reg,
            },
            &rule.span,
        );

        let effect_reg = self.compile_effect(rule)?;
        self.emit(
            Instruction::Return { value: effect_reg },
            &rule.then_block.span,
        );

        self.program.main_entry_point = 0;
        self.program.entry_points.insert("main".to_string(), 0);
        self.program.dispatch_window_size = self.register_counter.max(2);
        self.program.max_rule_window_size = 0;

        if !self.program.builtin_info_table.is_empty() {
            self.program.initialize_resolved_builtins()?;
        }

        self.program
            .validate_limits()
            .map_err(|message| anyhow!(message))?;

        Ok(Rc::new(self.program))
    }

    // -- register / span / emit helpers ------------------------------------

    fn alloc_register(&mut self) -> Result<u8> {
        if self.register_counter == u8::MAX {
            bail!("azure-policy compiler exhausted RVM registers");
        }
        let reg = self.register_counter;
        self.register_counter = self.register_counter.saturating_add(1);
        Ok(reg)
    }

    fn span_info(&mut self, span: &crate::lexer::Span) -> SpanInfo {
        let path = span.source.get_path().to_string();
        let source_index = if let Some(index) = self.source_to_index.get(path.as_str()) {
            *index
        } else {
            let index = self
                .program
                .add_source(path.clone(), span.source.get_contents().to_string());
            self.source_to_index.insert(path, index);
            index
        };

        SpanInfo::from_lexer_span(span, source_index)
    }

    fn emit(&mut self, instruction: Instruction, span: &crate::lexer::Span) {
        let span_info = self.span_info(span);
        self.program.add_instruction(instruction, Some(span_info));
    }

    // -- literal / builtin / chained-index helpers -------------------------

    fn add_literal_u16(&mut self, value: Value) -> Result<u16> {
        let idx = self.program.add_literal(value);
        u16::try_from(idx).map_err(|_| anyhow!("literal table exceeds u16 index space"))
    }

    fn load_literal(&mut self, value: Value, span: &crate::lexer::Span) -> Result<u8> {
        let literal_idx = self.add_literal_u16(value)?;
        let dest = self.alloc_register()?;
        self.emit(Instruction::Load { dest, literal_idx }, span);
        Ok(dest)
    }

    fn get_or_add_builtin_index(&mut self, name: &str, num_args: u16) -> u16 {
        // Key by name+arity so variadic builtins (logic_all, logic_any)
        // can be called with different argument counts.
        let key = format!("{}/{}", name, num_args);
        if let Some(index) = self.builtin_index.get(&key) {
            return *index;
        }

        let index = self
            .program
            .add_builtin_info(crate::rvm::program::BuiltinInfo {
                name: name.to_string(),
                num_args,
                kind: crate::rvm::program::BuiltinKind::Standard,
            });
        self.builtin_index.insert(key, index);
        index
    }

    fn emit_builtin_call(
        &mut self,
        name: &str,
        args: &[u8],
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        if args.len() > 8 {
            bail!("builtin call {} exceeds max 8 args", name);
        }

        let dest = self.alloc_register()?;
        let builtin_index = self.get_or_add_builtin_index(
            name,
            u16::try_from(args.len()).map_err(|_| anyhow!("arg count overflow"))?,
        );

        let mut arg_slots = [0_u8; 8];
        for (index, arg) in args.iter().enumerate() {
            arg_slots[index] = *arg;
        }

        let params_index = self.program.add_builtin_call_params(BuiltinCallParams {
            dest,
            builtin_index,
            num_args: u8::try_from(args.len()).map_err(|_| anyhow!("arg count overflow"))?,
            args: arg_slots,
        });

        self.emit(Instruction::BuiltinCall { params_index }, span);
        Ok(dest)
    }

    fn emit_chained_index_literal_path(
        &mut self,
        root: u8,
        path: &[&str],
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        let dest = self.alloc_register()?;

        let path_components = path
            .iter()
            .map(|segment| {
                self.add_literal_u16(Value::from((*segment).to_string()))
                    .map(LiteralOrRegister::Literal)
            })
            .collect::<Result<Vec<_>>>()?;

        let params_index =
            self.program
                .instruction_data
                .add_chained_index_params(ChainedIndexParams {
                    dest,
                    root,
                    path_components,
                });
        self.emit(Instruction::ChainedIndex { params_index }, span);

        Ok(dest)
    }

    fn load_input(&mut self, span: &crate::lexer::Span) -> Result<u8> {
        let dest = self.alloc_register()?;
        self.emit(Instruction::LoadInput { dest }, span);
        Ok(dest)
    }

    /// Emit a `CoalesceUndefinedToNull` instruction for the given register.
    ///
    /// In Azure Policy, a missing field is semantically `null`, not undefined.
    /// This prevents the RVM's undefined-propagation from short-circuiting
    /// subsequent builtin calls.
    fn emit_coalesce_undefined_to_null(&mut self, register: u8, span: &crate::lexer::Span) {
        self.emit(Instruction::CoalesceUndefinedToNull { register }, span);
    }

    // -- effect compilation ------------------------------------------------

    fn compile_effect(&mut self, rule: &PolicyRule) -> Result<u8> {
        let effect = &rule.then_block.effect;
        let span = &effect.span;

        match &effect.kind {
            // Known effects: emit the original text to preserve casing.
            EffectKind::Deny
            | EffectKind::Audit
            | EffectKind::Append
            | EffectKind::AuditIfNotExists
            | EffectKind::DeployIfNotExists
            | EffectKind::Disabled
            | EffectKind::Modify
            | EffectKind::DenyAction
            | EffectKind::Manual => self.load_literal(Value::from(effect.raw.clone()), span),
            EffectKind::Other(raw) => {
                if raw.starts_with('[') && raw.ends_with(']') && !raw.starts_with("[[") {
                    let inner = &raw[1..raw.len().saturating_sub(1)];
                    let expr =
                        crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
                            inner, span,
                        )
                        .map_err(|error| anyhow!("invalid effect expression: {}", error))?;
                    self.compile_expr(&expr)
                } else {
                    self.load_literal(Value::from(raw.clone()), span)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Compile a parsed Azure Policy rule into an RVM program.
pub fn compile_policy_rule(rule: &PolicyRule) -> Result<Rc<Program>> {
    Compiler::new().compile(rule)
}

/// Compile a parsed Azure Policy rule with alias resolution.
///
/// The `alias_map` maps lowercase fully-qualified alias names to their short
/// names.  Obtain it from [`AliasRegistry::alias_map()`].  During compilation,
/// any `FieldKind::Alias` containing a fully-qualified name (e.g.,
/// `"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"`) is resolved
/// to its short name (`"supportsHttpsTrafficOnly"`) and compiled as
/// `input.resource.supportsHttpsTrafficOnly`.
pub fn compile_policy_rule_with_aliases(
    rule: &PolicyRule,
    alias_map: BTreeMap<String, String>,
) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.alias_map = alias_map;
    compiler.compile(rule)
}

/// Compile a parsed Azure Policy definition into an RVM program.
///
/// This extracts the `policyRule` from the definition and compiles it.
/// Parameter `defaultValue`s are stored in the literal table so the
/// `azure.policy.get_parameter` builtin can fall back to them at runtime.
pub fn compile_policy_definition(defn: &PolicyDefinition) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.parameter_defaults = Some(build_parameter_defaults(&defn.parameters)?);
    compiler.compile(&defn.policy_rule)
}

/// Compile a parsed Azure Policy definition with alias resolution.
///
/// Combines alias map injection with parameter-default extraction.
pub fn compile_policy_definition_with_aliases(
    defn: &PolicyDefinition,
    alias_map: BTreeMap<String, String>,
) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.alias_map = alias_map;
    compiler.parameter_defaults = Some(build_parameter_defaults(&defn.parameters)?);
    compiler.compile(&defn.policy_rule)
}

/// Build a `Value::Object` of `{ param_name: defaultValue }` from
/// the parsed parameter definitions.
fn build_parameter_defaults(
    params: &[crate::languages::azure_policy::ast::ParameterDefinition],
) -> Result<Value> {
    use crate::languages::azure_policy::compiler::utils::json_value_to_runtime;
    let mut obj = Value::new_object();
    let map = obj.as_object_mut()?;
    for param in params {
        if let Some(ref default_val) = param.default_value {
            let runtime_val = json_value_to_runtime(default_val)?;
            map.insert(Value::from(param.name.clone()), runtime_val);
        }
    }
    Ok(obj)
}
