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
mod template_dispatch;
mod utils;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use anyhow::{anyhow, bail, Result};

use crate::languages::azure_policy::ast::{
    Condition, EffectKind, EffectNode, Expr, ExprLiteral, FieldKind, JsonValue, Lhs, OperatorKind,
    PolicyDefinition, PolicyRule, ValueOrExpr,
};
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
    /// High-water mark of `register_counter` — tracks the maximum number of
    /// registers ever live at once.  Used for `dispatch_window_size`.
    register_high_water: u8,
    source_to_index: BTreeMap<String, usize>,
    builtin_index: BTreeMap<String, u16>,
    count_bindings: Vec<CountBinding>,
    /// Cached register for `LoadInput` — allocated once on first use.
    cached_input_reg: Option<u8>,
    /// Cached register for `LoadContext` — allocated once on first use.
    cached_context_reg: Option<u8>,
    /// Map from lowercase fully-qualified alias name → short name.
    ///
    /// Populated from [`AliasRegistry::alias_map()`] so the compiler can
    /// resolve aliases like `"Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly"`
    /// to short names like `"supportsHttpsTrafficOnly"` without knowing the
    /// resource type.
    alias_map: BTreeMap<String, String>,
    /// Map from lowercase fully-qualified alias name → modifiable flag.
    ///
    /// Populated from [`AliasRegistry::alias_modifiable_map()`].  Used to
    /// validate that Modify effect targets reference only aliases with
    /// `defaultMetadata.attributes = "Modifiable"`.
    alias_modifiable: BTreeMap<String, bool>,
    /// Default values for policy parameters, built from `PolicyDefinition.parameters`.
    ///
    /// Stored as a `Value::Object` mapping parameter names to their default values.
    /// When set, the compiler emits a builtin call for `parameters()` that falls
    /// back to these defaults when the caller does not supply a value.
    parameter_defaults: Option<Value>,

    /// When set, the `"field":` **condition key** resolves against this
    /// register instead of `input.resource`.  Used while compiling
    /// `existenceCondition` to evaluate condition keys against the related
    /// resource returned by `HostAwait`.
    ///
    /// **Important distinction**: the `field()` *template function* (inside
    /// `[...]` value expressions) always resolves against the *primary*
    /// resource (`input.resource`), even inside `existenceCondition`.
    /// The `compile_call_expr("field", …)` path temporarily clears this
    /// override so that `compile_resource_path_value` reads from
    /// `input.resource`.
    ///
    /// See: <https://learn.microsoft.com/azure/governance/policy/concepts/effect-audit-if-not-exists>
    resource_override_reg: Option<u8>,

    // -- Metadata accumulators (populated during compilation) ---------------
    /// Built-in field kinds referenced (e.g. "type", "location", "tags").
    observed_field_kinds: BTreeSet<String>,
    /// Fully-qualified alias paths referenced.
    observed_aliases: BTreeSet<String>,
    /// Tag names referenced via `tags.name` or `tags['name']`.
    observed_tag_names: BTreeSet<String>,
    /// Operator kinds used in conditions.
    observed_operators: BTreeSet<String>,
    /// Resource types discovered from `field("type") equals/in` conditions.
    observed_resource_types: BTreeSet<String>,
    /// Whether a count expression was compiled.
    observed_uses_count: bool,
    /// Whether a `FieldKind::Expr` (dynamic field reference) was compiled.
    observed_has_dynamic_fields: bool,
    /// Whether any alias contains `[*]` (wildcard array traversal).
    observed_has_wildcard_aliases: bool,
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
        self.program.dispatch_window_size = self.register_high_water.max(2);
        self.program.max_rule_window_size = 0;

        if !self.program.builtin_info_table.is_empty() {
            self.program.initialize_resolved_builtins()?;
        }

        self.program
            .validate_limits()
            .map_err(|message| anyhow!(message))?;

        // Populate annotations accumulated during compilation.
        self.populate_compiled_annotations();

        Ok(Rc::new(self.program))
    }

    // -- register / span / emit helpers ------------------------------------

    /// Restore `register_counter` to `saved` while protecting any globally-
    /// cached registers (`cached_input_reg`, `cached_context_reg`) from being
    /// overwritten by future allocations.
    fn restore_register_counter(&mut self, saved: u8) {
        let mut floor = saved;
        if let Some(r) = self.cached_input_reg {
            floor = floor.max(r.saturating_add(1));
        }
        if let Some(r) = self.cached_context_reg {
            floor = floor.max(r.saturating_add(1));
        }
        self.register_counter = floor;
    }

    fn alloc_register(&mut self) -> Result<u8> {
        if self.register_counter == u8::MAX {
            bail!("azure-policy compiler exhausted RVM registers");
        }
        let reg = self.register_counter;
        self.register_counter = self.register_counter.saturating_add(1);
        if self.register_counter > self.register_high_water {
            self.register_high_water = self.register_counter;
        }
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
        // Key by name+arity so the same builtin can be called with
        // different argument counts.
        let key = format!("{}/{}", name, num_args);
        if let Some(index) = self.builtin_index.get(&key) {
            return *index;
        }

        let index = self
            .program
            .add_builtin_info(crate::rvm::program::BuiltinInfo {
                name: name.to_string(),
                num_args,
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
                // Numeric segments → Number literals (for array indexing).
                let value = if let Ok(n) = segment.parse::<u64>() {
                    Value::from(n)
                } else {
                    Value::from((*segment).to_string())
                };
                self.add_literal_u16(value).map(LiteralOrRegister::Literal)
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
        if let Some(reg) = self.cached_input_reg {
            return Ok(reg);
        }
        let dest = self.alloc_register()?;
        self.emit(Instruction::LoadInput { dest }, span);
        self.cached_input_reg = Some(dest);
        Ok(dest)
    }

    fn load_context(&mut self, span: &crate::lexer::Span) -> Result<u8> {
        if let Some(reg) = self.cached_context_reg {
            return Ok(reg);
        }
        let dest = self.alloc_register()?;
        self.emit(Instruction::LoadContext { dest }, span);
        self.cached_context_reg = Some(dest);
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

    /// Return the PC (instruction index) that the *next* emitted instruction
    /// will occupy.
    fn current_pc(&self) -> Result<u16> {
        u16::try_from(self.program.instructions.len())
            .map_err(|_| anyhow!("instruction index overflow"))
    }

    /// Patch a set of tracked instruction indices, setting their `end_pc`
    /// field to the given value.
    ///
    /// Works for `AllOfStart`, `AllOfNext`, `AnyOfStart`, and `AnyOfNext`
    /// instructions — any instruction whose `end_pc` needs back-patching.
    fn patch_end_pc(&mut self, pcs: &[u16], end_pc: u16) {
        for &pc in pcs {
            match &mut self.program.instructions[pc as usize] {
                Instruction::AllOfStart {
                    end_pc: ref mut ep, ..
                }
                | Instruction::AllOfNext {
                    end_pc: ref mut ep, ..
                }
                | Instruction::AnyOfStart {
                    end_pc: ref mut ep, ..
                }
                | Instruction::AnyOfNext {
                    end_pc: ref mut ep, ..
                } => {
                    *ep = end_pc;
                }
                _ => {}
            }
        }
    }

    fn resolve_alias_path(&self, path: &str) -> Result<String> {
        let lc = path.to_lowercase();
        if let Some(short) = self.alias_map.get(&lc) {
            let resolved = short.clone();
            return Ok(self.strip_fq_prefix(&resolved).to_lowercase());
        }

        // Fallback: if the alias isn't found, try deriving the array path
        // from a corresponding `[*]` alias.  Policies often reference
        // `field('Type/prop.array')` (without `[*]`) inside `length()` to
        // get the array length, even when only `prop.array[*]` is registered.
        if !lc.contains("[*]") {
            let wildcard_key = alloc::format!("{}[*]", lc);
            if let Some(short) = self.alias_map.get(&wildcard_key) {
                let resolved = self.strip_fq_prefix(short).to_lowercase();
                if let Some(base) = resolved.strip_suffix("[*]") {
                    return Ok(base.to_string());
                }
            }
        }

        // When aliases are loaded, every field must be a known alias.
        if !self.alias_map.is_empty() {
            bail!(
                "unknown alias '{}': field references must use fully-qualified alias names when an alias catalog is loaded",
                path
            );
        }

        // No alias catalog — pass through as-is (legacy / no-alias mode).
        Ok(path.to_string())
    }

    /// Strip any resource-type prefix segments from a resolved alias short
    /// name, keeping only the trailing property path.
    ///
    /// Short names from `alias_to_short` may still contain child resource
    /// type prefixes (e.g. `securityRules/destinationPortRanges[*]`).
    /// Azure alias property paths use `.` as a separator, never `/`, so the
    /// part after the last `/` is always the property name.
    fn strip_fq_prefix(&self, resolved: &str) -> String {
        if let Some(idx) = resolved.rfind('/') {
            resolved[idx + 1..].to_string()
        } else {
            resolved.to_string()
        }
    }

    // -- effect compilation ------------------------------------------------

    fn compile_effect(&mut self, rule: &PolicyRule) -> Result<u8> {
        let effect = &rule.then_block.effect;
        let span = &effect.span;
        if matches!(effect.kind, EffectKind::Other(_)) {
            let resolved_effect_kind = self.resolve_effect_kind(effect);
            if resolved_effect_kind == EffectKind::AuditIfNotExists {
                let effect_text = self
                    .resolve_effect_name_from_parameter_default(effect)
                    .unwrap_or_else(|| "AuditIfNotExists".to_string());
                return self.compile_cross_resource_effect(rule, &effect_text);
            }
            if resolved_effect_kind == EffectKind::DeployIfNotExists {
                let effect_text = self
                    .resolve_effect_name_from_parameter_default(effect)
                    .unwrap_or_else(|| "DeployIfNotExists".to_string());
                return self.compile_cross_resource_effect(rule, &effect_text);
            }

            // Parameterized effect with resolved kind that has details
            let resolved_for_details = match &resolved_effect_kind {
                EffectKind::Modify => Some(EffectKind::Modify),
                EffectKind::Append => Some(EffectKind::Append),
                _ => None,
            };
            if let Some(kind) = resolved_for_details {
                // Compile the effect name expression, then build structured result
                let effect_name_reg = if effect.raw.starts_with('[')
                    && effect.raw.ends_with(']')
                    && !effect.raw.starts_with("[[")
                {
                    let inner = &effect.raw[1..effect.raw.len().saturating_sub(1)];
                    let expr =
                        crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
                            inner, span,
                        )
                        .map_err(|error| anyhow!("invalid effect expression: {}", error))?;
                    self.compile_expr(&expr)?
                } else {
                    self.load_literal(Value::from(effect.raw.clone()), span)?
                };
                return self.compile_effect_with_details(
                    &kind,
                    effect_name_reg,
                    rule.then_block.details.as_ref(),
                    span,
                );
            }

            if effect.raw.starts_with('[')
                && effect.raw.ends_with(']')
                && !effect.raw.starts_with("[[")
            {
                let inner = &effect.raw[1..effect.raw.len().saturating_sub(1)];
                let expr = crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
                    inner, span,
                )
                .map_err(|error| anyhow!("invalid effect expression: {}", error))?;
                let name_reg = self.compile_expr(&expr)?;
                return self.wrap_effect_result(name_reg, None, span);
            }

            let name_reg = self.load_literal(Value::from(effect.raw.clone()), span)?;
            return self.wrap_effect_result(name_reg, None, span);
        }

        match &effect.kind {
            EffectKind::AuditIfNotExists | EffectKind::DeployIfNotExists => {
                self.compile_cross_resource_effect(rule, &effect.raw)
            }
            EffectKind::Modify | EffectKind::Append => {
                let effect_name_reg = self.load_literal(Value::from(effect.raw.clone()), span)?;
                self.compile_effect_with_details(
                    &effect.kind,
                    effect_name_reg,
                    rule.then_block.details.as_ref(),
                    span,
                )
            }
            EffectKind::Deny
            | EffectKind::Audit
            | EffectKind::Disabled
            | EffectKind::DenyAction
            | EffectKind::Manual => {
                let name_reg = self.load_literal(Value::from(effect.raw.clone()), span)?;
                self.wrap_effect_result(name_reg, None, span)
            }
            // SAFETY: Other variants are filtered out above.
            EffectKind::Other(_) => {
                bail!(span.error(&alloc::format!("unsupported effect kind: {}", effect.raw)))
            }
        }
    }

    /// Wrap an effect name register into `{ "effect": <name> }` or
    /// `{ "effect": <name>, "details": <details> }`.
    fn wrap_effect_result(
        &mut self,
        effect_name_reg: u8,
        details_reg: Option<u8>,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::rvm::instructions::ObjectCreateParams;

        let mut keys = Vec::new();
        let effect_key_idx = self.add_literal_u16(Value::from("effect"))?;
        keys.push((effect_key_idx, effect_name_reg));

        if let Some(det_reg) = details_reg {
            let details_key_idx = self.add_literal_u16(Value::from("details"))?;
            keys.push((details_key_idx, det_reg));
        }

        // Build template: object with all keys set to Undefined.
        let mut template = alloc::collections::BTreeMap::new();
        for &(key_idx, _) in &keys {
            let key_val = self.program.literals[key_idx as usize].clone();
            template.insert(key_val, Value::Undefined);
        }
        let template_idx = self.add_literal_u16(Value::Object(crate::Rc::new(template)))?;

        // Sort keys by literal value (BTreeMap order).
        keys.sort_by(|a, b| {
            self.program.literals[a.0 as usize].cmp(&self.program.literals[b.0 as usize])
        });

        let dest = self.alloc_register()?;
        let params = ObjectCreateParams {
            dest,
            template_literal_idx: template_idx,
            literal_key_fields: keys,
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(params);
        self.emit(Instruction::ObjectCreate { params_index }, span);
        Ok(dest)
    }

    /// Compile a Modify or Append effect with its details into a structured
    /// result object.
    fn compile_effect_with_details(
        &mut self,
        kind: &EffectKind,
        effect_name_reg: u8,
        details: Option<&JsonValue>,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        match kind {
            EffectKind::Modify => self.compile_modify_details(effect_name_reg, details, span),
            EffectKind::Append => self.compile_append_details(effect_name_reg, details, span),
            _ => self.wrap_effect_result(effect_name_reg, None, span),
        }
    }

    /// Compile Modify effect details:
    /// `{ "effect": "modify", "details": { "roleDefinitionIds": [...], "operations": [...] } }`
    fn compile_modify_details(
        &mut self,
        effect_name_reg: u8,
        details: Option<&JsonValue>,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::languages::azure_policy::ast::ObjectEntry;
        use crate::languages::azure_policy::compiler::utils::json_value_to_runtime;
        use crate::rvm::instructions::{ArrayCreateParams, ObjectCreateParams};

        let Some(JsonValue::Object(_, entries)) = details else {
            // No details or not an object — return bare effect
            return self.wrap_effect_result(effect_name_reg, None, span);
        };

        // Extract roleDefinitionIds and operations from details entries.
        let mut role_ids_value: Option<&JsonValue> = None;
        let mut operations: Option<&Vec<JsonValue>> = None;

        for ObjectEntry { key, value, .. } in entries {
            match key.to_lowercase().as_str() {
                "roledefinitionids" => role_ids_value = Some(value),
                "operations" => {
                    if let JsonValue::Array(_, ops) = value {
                        operations = Some(ops);
                    }
                }
                _ => {} // existenceCondition, conflictEffect, etc. — skip
            }
        }

        // Build details object fields
        let mut detail_keys: Vec<(u16, u8)> = Vec::new();

        // roleDefinitionIds — emit as a literal array
        if let Some(role_json) = role_ids_value {
            let role_val = json_value_to_runtime(role_json)?;
            let role_reg = self.load_literal(role_val, span)?;
            let key_idx = self.add_literal_u16(Value::from("roleDefinitionIds"))?;
            detail_keys.push((key_idx, role_reg));
        }

        // operations — compile each operation into an object
        if let Some(ops) = operations {
            let mut op_regs = Vec::new();
            for op_json in ops {
                let op_reg = self.compile_modify_operation(op_json, span)?;
                op_regs.push(op_reg);
            }
            // Create the operations array
            let ops_dest = self.alloc_register()?;
            let ops_params = ArrayCreateParams {
                dest: ops_dest,
                elements: op_regs,
            };
            let ops_params_index = self
                .program
                .instruction_data
                .add_array_create_params(ops_params);
            self.emit(
                Instruction::ArrayCreate {
                    params_index: ops_params_index,
                },
                span,
            );

            let key_idx = self.add_literal_u16(Value::from("operations"))?;
            detail_keys.push((key_idx, ops_dest));
        }

        if detail_keys.is_empty() {
            return self.wrap_effect_result(effect_name_reg, None, span);
        }

        // Build template for details object
        let mut template = alloc::collections::BTreeMap::new();
        for &(key_idx, _) in &detail_keys {
            let key_val = self.program.literals[key_idx as usize].clone();
            template.insert(key_val, Value::Undefined);
        }
        let template_idx = self.add_literal_u16(Value::Object(crate::Rc::new(template)))?;

        detail_keys.sort_by(|a, b| {
            self.program.literals[a.0 as usize].cmp(&self.program.literals[b.0 as usize])
        });

        let details_dest = self.alloc_register()?;
        let details_params = ObjectCreateParams {
            dest: details_dest,
            template_literal_idx: template_idx,
            literal_key_fields: detail_keys,
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(details_params);
        self.emit(Instruction::ObjectCreate { params_index }, span);

        self.wrap_effect_result(effect_name_reg, Some(details_dest), span)
    }

    /// Compile a single Modify operation `{ "operation": "...", "field": "...", "value": ... }`
    /// into an object register.
    fn compile_modify_operation(
        &mut self,
        op_json: &JsonValue,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::languages::azure_policy::ast::ObjectEntry;
        use crate::languages::azure_policy::compiler::utils::json_value_to_runtime;
        use crate::rvm::instructions::ObjectCreateParams;

        let JsonValue::Object(_, entries) = op_json else {
            bail!("modify operation must be an object");
        };

        let mut op_keys: Vec<(u16, u8)> = Vec::new();

        for ObjectEntry { key, value, .. } in entries {
            match key.to_lowercase().as_str() {
                "operation" => {
                    let val = json_value_to_runtime(value)?;
                    let reg = self.load_literal(val, span)?;
                    let key_idx = self.add_literal_u16(Value::from("operation"))?;
                    op_keys.push((key_idx, reg));
                }
                "field" => {
                    if let JsonValue::Str(_, field_path) = value {
                        // Check modifiability when alias catalog is loaded
                        self.check_modify_field_alias(field_path, span)?;

                        let val = Value::from(field_path.clone());
                        let reg = self.load_literal(val, span)?;
                        let key_idx = self.add_literal_u16(Value::from("field"))?;
                        op_keys.push((key_idx, reg));
                    }
                }
                "value" => {
                    // Value may contain template expressions
                    let reg = self.compile_value_or_expr_from_json(value, span)?;
                    let key_idx = self.add_literal_u16(Value::from("value"))?;
                    op_keys.push((key_idx, reg));
                }
                "condition" => {
                    // Condition for conditional operations — pass through
                    let val = json_value_to_runtime(value)?;
                    let reg = self.load_literal(val, span)?;
                    let key_idx = self.add_literal_u16(Value::from("condition"))?;
                    op_keys.push((key_idx, reg));
                }
                _ => {} // Unknown fields — skip
            }
        }

        // Build template
        let mut template = alloc::collections::BTreeMap::new();
        for &(key_idx, _) in &op_keys {
            let key_val = self.program.literals[key_idx as usize].clone();
            template.insert(key_val, Value::Undefined);
        }
        let template_idx = self.add_literal_u16(Value::Object(crate::Rc::new(template)))?;

        op_keys.sort_by(|a, b| {
            self.program.literals[a.0 as usize].cmp(&self.program.literals[b.0 as usize])
        });

        let dest = self.alloc_register()?;
        let params = ObjectCreateParams {
            dest,
            template_literal_idx: template_idx,
            literal_key_fields: op_keys,
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(params);
        self.emit(Instruction::ObjectCreate { params_index }, span);
        Ok(dest)
    }

    /// Check whether a field path used in a Modify operation targets a modifiable alias.
    ///
    /// When the alias catalog is loaded, non-modifiable aliases produce a
    /// compile-time error.  Without an alias catalog, no check is performed.
    fn check_modify_field_alias(&self, field_path: &str, span: &crate::lexer::Span) -> Result<()> {
        if self.alias_modifiable.is_empty() {
            return Ok(());
        }

        let lc = field_path.to_lowercase();

        // Check the FQ alias directly
        if let Some(&modifiable) = self.alias_modifiable.get(&lc) {
            if !modifiable {
                bail!(span.error(&alloc::format!(
                    "alias '{}' is not modifiable (defaultMetadata.attributes != 'Modifiable')",
                    field_path
                )));
            }
            return Ok(());
        }

        // Tags and built-in fields are always modifiable for Modify operations
        // (tags.*, type, location, etc.)
        Ok(())
    }

    /// Compile an Append effect's details array:
    /// `{ "effect": "append", "details": [ { "field": "...", "value": ... }, ... ] }`
    fn compile_append_details(
        &mut self,
        effect_name_reg: u8,
        details: Option<&JsonValue>,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::rvm::instructions::ArrayCreateParams;

        let Some(JsonValue::Array(_, items)) = details else {
            return self.wrap_effect_result(effect_name_reg, None, span);
        };

        let mut item_regs = Vec::new();
        for item in items {
            let reg = self.compile_append_item(item, span)?;
            item_regs.push(reg);
        }

        if item_regs.is_empty() {
            return self.wrap_effect_result(effect_name_reg, None, span);
        }

        // Create details array
        let details_dest = self.alloc_register()?;
        let params = ArrayCreateParams {
            dest: details_dest,
            elements: item_regs,
        };
        let params_index = self
            .program
            .instruction_data
            .add_array_create_params(params);
        self.emit(Instruction::ArrayCreate { params_index }, span);

        self.wrap_effect_result(effect_name_reg, Some(details_dest), span)
    }

    /// Compile a single Append item `{ "field": "...", "value": ... }` into an object register.
    fn compile_append_item(
        &mut self,
        item_json: &JsonValue,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::languages::azure_policy::ast::ObjectEntry;
        use crate::rvm::instructions::ObjectCreateParams;

        let JsonValue::Object(_, entries) = item_json else {
            bail!("append details item must be an object");
        };

        let mut item_keys: Vec<(u16, u8)> = Vec::new();

        for ObjectEntry { key, value, .. } in entries {
            match key.to_lowercase().as_str() {
                "field" => {
                    if let JsonValue::Str(_, field_path) = value {
                        let val = Value::from(field_path.clone());
                        let reg = self.load_literal(val, span)?;
                        let key_idx = self.add_literal_u16(Value::from("field"))?;
                        item_keys.push((key_idx, reg));
                    }
                }
                "value" => {
                    let reg = self.compile_value_or_expr_from_json(value, span)?;
                    let key_idx = self.add_literal_u16(Value::from("value"))?;
                    item_keys.push((key_idx, reg));
                }
                _ => {}
            }
        }

        let mut template = alloc::collections::BTreeMap::new();
        for &(key_idx, _) in &item_keys {
            let key_val = self.program.literals[key_idx as usize].clone();
            template.insert(key_val, Value::Undefined);
        }
        let template_idx = self.add_literal_u16(Value::Object(crate::Rc::new(template)))?;

        item_keys.sort_by(|a, b| {
            self.program.literals[a.0 as usize].cmp(&self.program.literals[b.0 as usize])
        });

        let dest = self.alloc_register()?;
        let params = ObjectCreateParams {
            dest,
            template_literal_idx: template_idx,
            literal_key_fields: item_keys,
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(params);
        self.emit(Instruction::ObjectCreate { params_index }, span);
        Ok(dest)
    }

    /// Compile a JSON value that may contain template expressions into a register.
    ///
    /// If the value is a string with `[...]` brackets, it's parsed as a
    /// template expression and compiled. Otherwise it's loaded as a literal.
    fn compile_value_or_expr_from_json(
        &mut self,
        value: &JsonValue,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::languages::azure_policy::compiler::utils::json_value_to_runtime;

        if let JsonValue::Str(_, s) = value {
            if s.starts_with('[') && s.ends_with(']') && !s.starts_with("[[") {
                let inner = &s[1..s.len().saturating_sub(1)];
                let expr = crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
                    inner, span,
                )
                .map_err(|error| anyhow!("invalid template expression in value: {}", error))?;
                return self.compile_expr(&expr);
            }
        }
        let val = json_value_to_runtime(value)?;
        self.load_literal(val, span)
    }

    /// Compile cross-resource effects (auditIfNotExists / deployIfNotExists).
    ///
    /// These effects use a two-phase evaluation:
    /// 1. `HostAwait` requests the related resource from the host
    /// 2. The `existenceCondition` (if any) is evaluated against the returned
    ///    resource inline. If no `existenceCondition`, existence is checked
    ///    via `PolicyExists`.
    ///
    /// Host protocol:
    ///   id  = `"azure.policy.existence_check"`
    ///   arg = `{ operation: "lookup_related_resources", type, name, ... }`
    ///   response = related resource object, or `null` if not found
    fn compile_cross_resource_effect(
        &mut self,
        rule: &PolicyRule,
        effect_text: &str,
    ) -> Result<u8> {
        let span = &rule.then_block.effect.span;

        let Some(details) = rule.then_block.details.as_ref() else {
            return self.load_literal(Value::from(effect_text.to_string()), span);
        };

        // Phase 1: Request related resource from host via HostAwait.
        // Host contract:
        //   id  = "azure.policy.existence_check"
        //   arg = lookup request object (type/name/scope metadata)
        //   response: the related resource (object), or null if not found
        let request_value = self.build_host_await_request(details)?;
        let request_reg = self.load_literal(request_value, span)?;
        let id_reg = self.load_literal(Value::from("azure.policy.existence_check"), span)?;

        let related_resource_reg = self.alloc_register()?;
        self.emit(
            Instruction::HostAwait {
                dest: related_resource_reg,
                arg: request_reg,
                id: id_reg,
            },
            span,
        );

        // Phase 2: Evaluate existence.
        let exists_reg = if let Some(ref existence_condition) = rule.then_block.existence_condition
        {
            // First check whether the related resource was found at all.
            // When HostAwait returns null (resource not found), we must
            // short-circuit to false — the existenceCondition only applies
            // when the resource actually exists.  Without this guard,
            // field lookups on a null response yield Undefined and operators
            // like PolicyNotEquals(Undefined, _) return true, incorrectly
            // marking a missing resource as compliant.
            let true_reg = self.load_literal(Value::Bool(true), span)?;
            let resource_found_reg = self.alloc_register()?;
            self.emit(
                Instruction::PolicyExists {
                    dest: resource_found_reg,
                    left: related_resource_reg,
                    right: true_reg,
                },
                span,
            );

            // Compile existenceCondition with field references resolving
            // against the related resource instead of input.resource.
            self.resource_override_reg = Some(related_resource_reg);
            let cond_reg = self.compile_constraint(existence_condition)?;
            self.resource_override_reg = None;

            // Combine: resource must exist AND condition must pass.
            // When resource is null: resource_found_reg=false,
            // And(false, _) = false → non-compliant → effect fires.
            let and_reg = self.alloc_register()?;
            self.emit(
                Instruction::And {
                    dest: and_reg,
                    left: resource_found_reg,
                    right: cond_reg,
                },
                span,
            );
            and_reg
        } else {
            // No existenceCondition — just check if the resource was found
            // (non-null/non-undefined). Uses PolicyExists which returns true
            // when the value is defined and non-null (matching expected=true).
            let true_reg = self.load_literal(Value::Bool(true), span)?;
            let dest = self.alloc_register()?;
            self.emit(
                Instruction::PolicyExists {
                    dest,
                    left: related_resource_reg,
                    right: true_reg,
                },
                span,
            );
            dest
        };

        // Phase 3: Produce result.
        // If exists_reg is truthy → resource is compliant → return Undefined.
        // If exists_reg is falsy → non-compliant → return the effect object.
        let not_exists_reg = self.alloc_register()?;
        self.emit(
            Instruction::PolicyNot {
                dest: not_exists_reg,
                operand: exists_reg,
            },
            span,
        );

        let effect_name_reg = self.load_literal(Value::from(effect_text.to_string()), span)?;
        self.emit(
            Instruction::ReturnUndefinedIfNotTrue {
                condition: not_exists_reg,
            },
            span,
        );

        // Build structured result with roleDefinitionIds if present.
        self.compile_cross_resource_details(effect_name_reg, details, span)
    }

    /// Build cross-resource effect details (roleDefinitionIds, deployment, etc.).
    fn compile_cross_resource_details(
        &mut self,
        effect_name_reg: u8,
        details: &JsonValue,
        span: &crate::lexer::Span,
    ) -> Result<u8> {
        use crate::languages::azure_policy::ast::ObjectEntry;
        use crate::languages::azure_policy::compiler::utils::json_value_to_runtime;
        use crate::rvm::instructions::ObjectCreateParams;

        let JsonValue::Object(_, entries) = details else {
            return self.wrap_effect_result(effect_name_reg, None, span);
        };

        let mut detail_keys: Vec<(u16, u8)> = Vec::new();

        for ObjectEntry { key, value, .. } in entries {
            match key.to_lowercase().as_str() {
                "roledefinitionids" => {
                    let val = json_value_to_runtime(value)?;
                    let reg = self.load_literal(val, span)?;
                    let key_idx = self.add_literal_u16(Value::from("roleDefinitionIds"))?;
                    detail_keys.push((key_idx, reg));
                }
                "type" => {
                    let val = json_value_to_runtime(value)?;
                    let reg = self.load_literal(val, span)?;
                    let key_idx = self.add_literal_u16(Value::from("type"))?;
                    detail_keys.push((key_idx, reg));
                }
                // existenceCondition, deployment, name, resourceGroupName, etc.
                // are not included in the structured result — they're used
                // during compilation only.
                _ => {}
            }
        }

        if detail_keys.is_empty() {
            return self.wrap_effect_result(effect_name_reg, None, span);
        }

        let mut template = alloc::collections::BTreeMap::new();
        for &(key_idx, _) in &detail_keys {
            let key_val = self.program.literals[key_idx as usize].clone();
            template.insert(key_val, Value::Undefined);
        }
        let template_idx = self.add_literal_u16(Value::Object(crate::Rc::new(template)))?;

        detail_keys.sort_by(|a, b| {
            self.program.literals[a.0 as usize].cmp(&self.program.literals[b.0 as usize])
        });

        let details_dest = self.alloc_register()?;
        let params = ObjectCreateParams {
            dest: details_dest,
            template_literal_idx: template_idx,
            literal_key_fields: detail_keys,
            fields: Vec::new(),
        };
        let params_index = self
            .program
            .instruction_data
            .add_object_create_params(params);
        self.emit(Instruction::ObjectCreate { params_index }, span);

        self.wrap_effect_result(effect_name_reg, Some(details_dest), span)
    }

    fn resolve_effect_kind(&self, effect: &EffectNode) -> EffectKind {
        match effect.kind {
            EffectKind::Other(_) => self
                .resolve_effect_kind_from_parameter_default(effect)
                .unwrap_or_else(|| effect.kind.clone()),
            _ => effect.kind.clone(),
        }
    }

    fn resolve_effect_kind_from_parameter_default(
        &self,
        effect: &EffectNode,
    ) -> Option<EffectKind> {
        let raw = effect.raw.as_str();
        if !(raw.starts_with('[') && raw.ends_with(']') && !raw.starts_with("[[")) {
            return None;
        }

        let inner = &raw[1..raw.len().saturating_sub(1)];
        let expr = crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
            inner,
            &effect.span,
        )
        .ok()?;

        let parameter_name = match expr {
            Expr::Call { func, args, .. } if args.len() == 1 => match (*func, &args[0]) {
                (
                    Expr::Ident { name, .. },
                    Expr::Literal {
                        value: ExprLiteral::String(param_name),
                        ..
                    },
                ) if name.eq_ignore_ascii_case("parameters") => param_name.clone(),
                _ => return None,
            },
            _ => return None,
        };

        let defaults = self.parameter_defaults.as_ref()?;
        let defaults_obj = defaults.as_object().ok()?;
        let default_effect = defaults_obj.get(&Value::from(parameter_name))?;
        let effect_name = default_effect.as_string().ok()?;

        Self::effect_kind_from_string(effect_name)
    }

    fn resolve_effect_name_from_parameter_default(&self, effect: &EffectNode) -> Option<String> {
        let raw = effect.raw.as_str();
        if !(raw.starts_with('[') && raw.ends_with(']') && !raw.starts_with("[[")) {
            return None;
        }

        let inner = &raw[1..raw.len().saturating_sub(1)];
        let expr = crate::languages::azure_policy::expr::ExprParser::parse_from_brackets(
            inner,
            &effect.span,
        )
        .ok()?;

        let parameter_name = match expr {
            Expr::Call { func, args, .. } if args.len() == 1 => match (*func, &args[0]) {
                (
                    Expr::Ident { name, .. },
                    Expr::Literal {
                        value: ExprLiteral::String(param_name),
                        ..
                    },
                ) if name.eq_ignore_ascii_case("parameters") => param_name.clone(),
                _ => return None,
            },
            _ => return None,
        };

        let defaults = self.parameter_defaults.as_ref()?;
        let defaults_obj = defaults.as_object().ok()?;
        let default_effect = defaults_obj.get(&Value::from(parameter_name))?;
        let effect_name = default_effect.as_string().ok()?;
        Some(effect_name.to_string())
    }

    // -- metadata population -----------------------------------------------

    /// Record a built-in field kind reference.
    fn record_field_kind(&mut self, name: &str) {
        self.observed_field_kinds.insert(name.to_string());
    }

    /// Record an alias reference.
    fn record_alias(&mut self, path: &str) {
        self.observed_aliases.insert(path.to_string());
        if path.contains("[*]") {
            self.observed_has_wildcard_aliases = true;
        }
    }

    /// Record a tag name reference.
    fn record_tag_name(&mut self, tag: &str) {
        self.observed_tag_names.insert(tag.to_string());
    }

    /// Record an operator usage.
    fn record_operator(&mut self, kind: &OperatorKind) {
        let name = match kind {
            OperatorKind::Equals => "equals",
            OperatorKind::NotEquals => "notEquals",
            OperatorKind::Greater => "greater",
            OperatorKind::GreaterOrEquals => "greaterOrEquals",
            OperatorKind::Less => "less",
            OperatorKind::LessOrEquals => "lessOrEquals",
            OperatorKind::In => "in",
            OperatorKind::NotIn => "notIn",
            OperatorKind::Contains => "contains",
            OperatorKind::NotContains => "notContains",
            OperatorKind::ContainsKey => "containsKey",
            OperatorKind::NotContainsKey => "notContainsKey",
            OperatorKind::Like => "like",
            OperatorKind::NotLike => "notLike",
            OperatorKind::Match => "match",
            OperatorKind::NotMatch => "notMatch",
            OperatorKind::MatchInsensitively => "matchInsensitively",
            OperatorKind::NotMatchInsensitively => "notMatchInsensitively",
            OperatorKind::Exists => "exists",
        };
        self.observed_operators.insert(name.to_string());
    }

    /// Record a resource type discovered from a `{ "field": "type", "equals"/"in": ... }` condition.
    fn record_resource_type_from_condition(&mut self, condition: &Condition) {
        // Only extract when LHS is FieldKind::Type
        let is_type_field =
            matches!(&condition.lhs, Lhs::Field(f) if matches!(f.kind, FieldKind::Type));
        if !is_type_field {
            return;
        }

        match &condition.operator.kind {
            OperatorKind::Equals => {
                // RHS should be a string literal
                if let ValueOrExpr::Value(JsonValue::Str(_, s)) = &condition.rhs {
                    self.observed_resource_types.insert(s.clone());
                }
            }
            OperatorKind::In | OperatorKind::Like => {
                // RHS should be an array of string literals
                if let ValueOrExpr::Value(JsonValue::Array(_, items)) = &condition.rhs {
                    for item in items {
                        if let JsonValue::Str(_, s) = item {
                            self.observed_resource_types.insert(s.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Build the effect annotation string, resolving parameterized effects to their defaults.
    fn resolve_effect_annotation(&self, rule: &PolicyRule) -> String {
        let effect = &rule.then_block.effect;
        match &effect.kind {
            EffectKind::Other(_) => {
                // Try to resolve from parameter defaults
                self.resolve_effect_name_from_parameter_default(effect)
                    .unwrap_or_else(|| effect.raw.clone())
            }
            _ => effect.raw.clone(),
        }
    }

    /// Populate `program.metadata.annotations` from accumulated observations.
    fn populate_compiled_annotations(&mut self) {
        // Read has_host_await before borrowing annotations mutably.
        let has_host_await = self.program.has_host_await();

        let annot = &mut self.program.metadata.annotations;

        // Effect
        // (set externally in entry points that have the PolicyRule)

        // Field kinds used
        if !self.observed_field_kinds.is_empty() {
            let set: BTreeSet<Value> = self
                .observed_field_kinds
                .iter()
                .map(|s| Value::String(s.as_str().into()))
                .collect();
            annot.insert("field_kinds".to_string(), Value::Set(Rc::new(set)));
        }

        // Aliases used
        if !self.observed_aliases.is_empty() {
            let set: BTreeSet<Value> = self
                .observed_aliases
                .iter()
                .map(|s| Value::String(s.as_str().into()))
                .collect();
            annot.insert("aliases".to_string(), Value::Set(Rc::new(set)));
        }

        // Tag names
        if !self.observed_tag_names.is_empty() {
            let set: BTreeSet<Value> = self
                .observed_tag_names
                .iter()
                .map(|s| Value::String(s.as_str().into()))
                .collect();
            annot.insert("tag_names".to_string(), Value::Set(Rc::new(set)));
        }

        // Operators used
        if !self.observed_operators.is_empty() {
            let set: BTreeSet<Value> = self
                .observed_operators
                .iter()
                .map(|s| Value::String(s.as_str().into()))
                .collect();
            annot.insert("operators".to_string(), Value::Set(Rc::new(set)));
        }

        // Resource types
        if !self.observed_resource_types.is_empty() {
            let set: BTreeSet<Value> = self
                .observed_resource_types
                .iter()
                .map(|s| Value::String(s.as_str().into()))
                .collect();
            annot.insert("resource_types".to_string(), Value::Set(Rc::new(set)));
        }

        // Boolean flags
        if self.observed_uses_count {
            annot.insert("uses_count".to_string(), Value::Bool(true));
        }
        if self.observed_has_dynamic_fields {
            annot.insert("has_dynamic_fields".to_string(), Value::Bool(true));
        }
        if self.observed_has_wildcard_aliases {
            annot.insert("has_wildcard_aliases".to_string(), Value::Bool(true));
        }
        if has_host_await {
            annot.insert("has_host_await".to_string(), Value::Bool(true));
        }
    }

    /// Set definition-level metadata from a PolicyDefinition.
    fn populate_definition_metadata(&mut self, defn: &PolicyDefinition) {
        let annot = &mut self.program.metadata.annotations;

        if let Some(ref name) = defn.display_name {
            annot.insert(
                "display_name".to_string(),
                Value::String(name.as_str().into()),
            );
        }
        if let Some(ref desc) = defn.description {
            annot.insert(
                "description".to_string(),
                Value::String(desc.as_str().into()),
            );
        }
        if let Some(ref mode) = defn.mode {
            annot.insert("mode".to_string(), Value::String(mode.as_str().into()));
        }

        // Extract category and version from metadata JSON
        if let Some(JsonValue::Object(_, entries)) = defn.metadata.as_ref() {
            for entry in entries {
                let key_lower = entry.key.to_lowercase();
                match key_lower.as_str() {
                    "category" => {
                        if let JsonValue::Str(_, ref s) = entry.value {
                            annot.insert("category".to_string(), Value::String(s.as_str().into()));
                        }
                    }
                    "version" => {
                        if let JsonValue::Str(_, ref s) = entry.value {
                            annot.insert("version".to_string(), Value::String(s.as_str().into()));
                        }
                    }
                    "preview" => {
                        if let JsonValue::Bool(_, b) = entry.value {
                            annot.insert("preview".to_string(), Value::Bool(b));
                        }
                    }
                    _ => {}
                }
            }
        }

        // Parameter names
        if !defn.parameters.is_empty() {
            let set: BTreeSet<Value> = defn
                .parameters
                .iter()
                .map(|p| Value::String(p.name.as_str().into()))
                .collect();
            annot.insert("parameter_names".to_string(), Value::Set(Rc::new(set)));
        }

        // Extra fields: policyType, id, name
        for entry in &defn.extra {
            let key_lower = entry.key.to_lowercase();
            match key_lower.as_str() {
                "policytype" => {
                    if let JsonValue::Str(_, ref s) = entry.value {
                        annot.insert("policy_type".to_string(), Value::String(s.as_str().into()));
                    }
                }
                "id" => {
                    if let JsonValue::Str(_, ref s) = entry.value {
                        annot.insert("policy_id".to_string(), Value::String(s.as_str().into()));
                    }
                }
                "name" => {
                    if let JsonValue::Str(_, ref s) = entry.value {
                        annot.insert("policy_name".to_string(), Value::String(s.as_str().into()));
                    }
                }
                _ => {}
            }
        }
    }

    fn effect_kind_from_string(effect_name: &str) -> Option<EffectKind> {
        let normalized = effect_name.to_lowercase();
        Some(match normalized.as_str() {
            "deny" => EffectKind::Deny,
            "audit" => EffectKind::Audit,
            "append" => EffectKind::Append,
            "auditifnotexists" => EffectKind::AuditIfNotExists,
            "deployifnotexists" => EffectKind::DeployIfNotExists,
            "disabled" => EffectKind::Disabled,
            "modify" => EffectKind::Modify,
            "denyaction" => EffectKind::DenyAction,
            "manual" => EffectKind::Manual,
            _ => return None,
        })
    }

    fn build_host_await_request(&self, details: &JsonValue) -> Result<Value> {
        let mut request = Value::new_object();
        let request_obj = request.as_object_mut()?;
        request_obj.insert(
            Value::from("operation"),
            Value::from("lookup_related_resources"),
        );

        let JsonValue::Object(_, entries) = details else {
            return Ok(request);
        };

        for key in ["type", "name", "resourceGroupName", "existenceScope"] {
            if let Some(entry) = entries
                .iter()
                .find(|entry| entry.key.eq_ignore_ascii_case(key))
            {
                let value = crate::languages::azure_policy::compiler::utils::json_value_to_runtime(
                    &entry.value,
                )?;
                request_obj.insert(Value::from(key), value);
            }
        }

        Ok(request)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Compile a parsed Azure Policy rule into an RVM program.
pub fn compile_policy_rule(rule: &PolicyRule) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.program.metadata.language = "azure_policy".to_string();
    let effect = compiler.resolve_effect_annotation(rule);
    compiler
        .program
        .metadata
        .annotations
        .insert("effect".to_string(), Value::String(effect.as_str().into()));
    compiler.compile(rule)
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
    alias_modifiable: BTreeMap<String, bool>,
) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.program.metadata.language = "azure_policy".to_string();
    compiler.alias_map = alias_map;
    compiler.alias_modifiable = alias_modifiable;
    let effect = compiler.resolve_effect_annotation(rule);
    compiler
        .program
        .metadata
        .annotations
        .insert("effect".to_string(), Value::String(effect.as_str().into()));
    compiler.compile(rule)
}

/// Compile a parsed Azure Policy definition into an RVM program.
///
/// This extracts the `policyRule` from the definition and compiles it.
/// Parameter `defaultValue`s are stored in the literal table so the
/// `azure.policy.get_parameter` builtin can fall back to them at runtime.
pub fn compile_policy_definition(defn: &PolicyDefinition) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.program.metadata.language = "azure_policy".to_string();
    compiler.parameter_defaults = Some(build_parameter_defaults(&defn.parameters)?);
    compiler.populate_definition_metadata(defn);
    let effect = compiler.resolve_effect_annotation(&defn.policy_rule);
    compiler
        .program
        .metadata
        .annotations
        .insert("effect".to_string(), Value::String(effect.as_str().into()));
    compiler.compile(&defn.policy_rule)
}

/// Compile a parsed Azure Policy definition with alias resolution.
///
/// Combines alias map injection with parameter-default extraction.
pub fn compile_policy_definition_with_aliases(
    defn: &PolicyDefinition,
    alias_map: BTreeMap<String, String>,
    alias_modifiable: BTreeMap<String, bool>,
) -> Result<Rc<Program>> {
    let mut compiler = Compiler::new();
    compiler.program.metadata.language = "azure_policy".to_string();
    compiler.alias_map = alias_map;
    compiler.alias_modifiable = alias_modifiable;
    compiler.parameter_defaults = Some(build_parameter_defaults(&defn.parameters)?);
    compiler.populate_definition_metadata(defn);
    let effect = compiler.resolve_effect_annotation(&defn.policy_rule);
    compiler
        .program
        .metadata
        .annotations
        .insert("effect".to_string(), Value::String(effect.as_str().into()));
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
