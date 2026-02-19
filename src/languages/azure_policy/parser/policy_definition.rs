// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parsing for the full Azure Policy definition envelope.
//!
//! Handles the outer `{ "properties": { ... } }` wrapper, extracting typed
//! fields (`displayName`, `description`, `mode`, `parameters`, `policyRule`)
//! and collecting everything else into `extra`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::lexer::Span;

use crate::languages::azure_policy::ast::{
    Condition, Constraint, EffectKind, EffectNode, JsonValue, Lhs, ObjectEntry, OperatorNode,
    ParameterDefinition, PolicyDefinition, PolicyRule, ThenBlock,
};

use super::core::{CountInner, Parser};
use super::error::ParseError;
use super::parse_operator_kind;

impl<'source> Parser<'source> {
    /// Parse a full Azure Policy definition JSON.
    ///
    /// Accepts two forms:
    /// 1. **Wrapped**: `{ "properties": { ... }, ... }` — the standard ARM resource format.
    /// 2. **Unwrapped**: `{ "displayName": ..., "policyRule": ..., ... }` — just the
    ///    `properties` contents directly.
    ///
    /// In the wrapped form, fields outside `properties` (like `id`, `name`, `type`)
    /// are collected into `extra`.
    pub fn parse_policy_definition(&mut self) -> Result<PolicyDefinition, ParseError> {
        let open = self.expect_symbol("{")?;

        // Peek at keys to decide if this is wrapped or unwrapped.
        // We'll parse all keys anyway — if we find a "properties" key that is an
        // object containing a "policyRule", it's wrapped. Otherwise treat as unwrapped.
        let mut top_entries = Vec::new();
        if self.token_text() != "}" {
            loop {
                let (key_span, key) = self.expect_string()?;
                self.expect_symbol(":")?;
                let value = self.parse_json_value()?;
                top_entries.push(ObjectEntry {
                    key_span,
                    key,
                    value,
                });
                if self.token_text() == "," {
                    self.advance()?;
                } else {
                    break;
                }
            }
        }
        let close = self.expect_symbol("}")?;
        let span = Span {
            source: open.source.clone(),
            line: open.line,
            col: open.col,
            start: open.start,
            end: close.end,
        };

        // Check if wrapped (has a "properties" key that is an object).
        let is_wrapped = top_entries.iter().any(|e| {
            e.key.to_ascii_lowercase() == "properties" && matches!(e.value, JsonValue::Object(..))
        });

        if is_wrapped {
            self.build_definition_from_wrapped(span, top_entries)
        } else {
            self.build_definition_from_properties(span, top_entries, Vec::new())
        }
    }

    /// Build a `PolicyDefinition` from the wrapped form.
    ///
    /// Extracts the `properties` object and collects the rest into `extra`.
    fn build_definition_from_wrapped(
        &mut self,
        span: Span,
        entries: Vec<ObjectEntry>,
    ) -> Result<PolicyDefinition, ParseError> {
        let mut properties_entries = None;
        let mut extra = Vec::new();

        for entry in entries {
            if entry.key.to_ascii_lowercase() == "properties" {
                if let JsonValue::Object(_, entries) = entry.value {
                    properties_entries = Some(entries);
                }
            } else {
                extra.push(entry);
            }
        }

        let properties_entries = properties_entries.ok_or_else(|| ParseError::MissingKey {
            span: span.clone(),
            key: "properties",
        })?;

        self.build_definition_from_properties(span, properties_entries, extra)
    }

    /// Build a `PolicyDefinition` from properties-level entries.
    fn build_definition_from_properties(
        &mut self,
        span: Span,
        entries: Vec<ObjectEntry>,
        mut extra: Vec<ObjectEntry>,
    ) -> Result<PolicyDefinition, ParseError> {
        let mut display_name: Option<String> = None;
        let mut description: Option<String> = None;
        let mut mode: Option<String> = None;
        let mut metadata: Option<JsonValue> = None;
        let mut parameters_value: Option<JsonValue> = None;
        let mut policy_rule_value: Option<JsonValue> = None;

        for entry in entries {
            match entry.key.to_ascii_lowercase().as_str() {
                "displayname" => {
                    display_name = extract_string_value(&entry.value);
                    if display_name.is_none() {
                        extra.push(entry);
                    }
                }
                "description" => {
                    description = extract_string_value(&entry.value);
                    if description.is_none() {
                        extra.push(entry);
                    }
                }
                "mode" => {
                    mode = extract_string_value(&entry.value);
                    if mode.is_none() {
                        extra.push(entry);
                    }
                }
                "metadata" => {
                    metadata = Some(entry.value);
                }
                "parameters" => {
                    parameters_value = Some(entry.value);
                }
                "policyrule" => {
                    policy_rule_value = Some(entry.value);
                }
                _ => {
                    extra.push(entry);
                }
            }
        }

        // Parse parameters
        let parameters = if let Some(params_jv) = parameters_value {
            parse_parameter_definitions(params_jv)?
        } else {
            Vec::new()
        };

        // Parse policyRule — re-parse the JSON value through the policy rule parser
        let policy_rule = match policy_rule_value {
            Some(jv) => reparse_policy_rule(jv, &span)?,
            None => {
                return Err(ParseError::MissingKey {
                    span,
                    key: "policyRule",
                });
            }
        };

        Ok(PolicyDefinition {
            span,
            display_name,
            description,
            mode,
            metadata,
            parameters,
            policy_rule,
            extra,
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Extract a plain string from a `JsonValue::Str`.
fn extract_string_value(jv: &JsonValue) -> Option<String> {
    match jv {
        JsonValue::Str(_, s) => Some(s.clone()),
        _ => None,
    }
}

/// Parse the `"parameters"` object value into a list of [`ParameterDefinition`].
fn parse_parameter_definitions(jv: JsonValue) -> Result<Vec<ParameterDefinition>, ParseError> {
    let JsonValue::Object(_, entries) = jv else {
        return Ok(Vec::new());
    };

    let mut defs = Vec::with_capacity(entries.len());
    for entry in entries {
        defs.push(parse_single_parameter(entry)?);
    }
    Ok(defs)
}

/// Parse a single parameter definition from an object entry.
fn parse_single_parameter(entry: ObjectEntry) -> Result<ParameterDefinition, ParseError> {
    let name = entry.key;
    let name_span = entry.key_span;

    let JsonValue::Object(span, inner_entries) = entry.value else {
        // If the parameter value is not an object, treat the whole thing as extra.
        return Ok(ParameterDefinition {
            span: name_span.clone(),
            name,
            name_span,
            param_type: None,
            default_value: None,
            allowed_values: None,
            metadata: None,
            extra: Vec::new(),
        });
    };

    let mut param_type: Option<String> = None;
    let mut default_value: Option<JsonValue> = None;
    let mut allowed_values: Option<Vec<JsonValue>> = None;
    let mut metadata: Option<JsonValue> = None;
    let mut extra = Vec::new();

    for e in inner_entries {
        match e.key.to_ascii_lowercase().as_str() {
            "type" => {
                param_type = extract_string_value(&e.value);
                if param_type.is_none() {
                    extra.push(e);
                }
            }
            "defaultvalue" => {
                default_value = Some(e.value);
            }
            "allowedvalues" => {
                if let JsonValue::Array(_, items) = e.value {
                    allowed_values = Some(items);
                } else {
                    extra.push(e);
                }
            }
            "metadata" => {
                metadata = Some(e.value);
            }
            _ => {
                extra.push(e);
            }
        }
    }

    Ok(ParameterDefinition {
        span,
        name,
        name_span,
        param_type,
        default_value,
        allowed_values,
        metadata,
        extra,
    })
}

/// Re-parse a `JsonValue` that represents a `policyRule` into a [`PolicyRule`].
///
/// This preserves spans by converting from the already-parsed `JsonValue` tree.
fn reparse_policy_rule(jv: JsonValue, fallback_span: &Span) -> Result<PolicyRule, ParseError> {
    policy_rule_from_json_value(jv, fallback_span)
}

fn policy_rule_from_json_value(
    jv: JsonValue,
    fallback_span: &Span,
) -> Result<PolicyRule, ParseError> {
    let (span, entries) = match jv {
        JsonValue::Object(span, entries) => (span, entries),
        other => {
            return Err(ParseError::UnexpectedToken {
                span: other.span().clone(),
                expected: "object for policyRule",
            })
        }
    };

    let mut condition: Option<Constraint> = None;
    let mut then_block: Option<ThenBlock> = None;
    let mut condition_span: Option<Span> = None;
    let mut then_span: Option<Span> = None;

    for entry in entries {
        match entry.key.to_ascii_lowercase().as_str() {
            "if" => {
                condition_span = Some(entry.key_span.clone());
                condition = Some(constraint_from_json_value(entry.value)?);
            }
            "then" => {
                then_span = Some(entry.key_span.clone());
                then_block = Some(then_block_from_json_value(entry.value)?);
            }
            _ => {}
        }
    }

    let condition = condition.ok_or_else(|| ParseError::MissingKey {
        span: condition_span.unwrap_or_else(|| fallback_span.clone()),
        key: "if",
    })?;
    let then_block = then_block.ok_or_else(|| ParseError::MissingKey {
        span: then_span.unwrap_or_else(|| fallback_span.clone()),
        key: "then",
    })?;

    Ok(PolicyRule {
        span,
        condition,
        then_block,
    })
}

fn then_block_from_json_value(jv: JsonValue) -> Result<ThenBlock, ParseError> {
    let (span, entries) = match jv {
        JsonValue::Object(span, entries) => (span, entries),
        other => {
            return Err(ParseError::UnexpectedToken {
                span: other.span().clone(),
                expected: "object for then block",
            })
        }
    };

    let mut effect: Option<EffectNode> = None;
    let mut details: Option<JsonValue> = None;

    for entry in entries {
        match entry.key.to_ascii_lowercase().as_str() {
            "effect" => match entry.value {
                JsonValue::Str(val_span, val_text) => {
                    let kind = match val_text.to_ascii_lowercase().as_str() {
                        "deny" => EffectKind::Deny,
                        "audit" => EffectKind::Audit,
                        "append" => EffectKind::Append,
                        "auditifnotexists" => EffectKind::AuditIfNotExists,
                        "deployifnotexists" => EffectKind::DeployIfNotExists,
                        "disabled" => EffectKind::Disabled,
                        "modify" => EffectKind::Modify,
                        "denyaction" => EffectKind::DenyAction,
                        "manual" => EffectKind::Manual,
                        _ => EffectKind::Other(val_text.clone()),
                    };
                    effect = Some(EffectNode {
                        span: val_span,
                        kind,
                        raw: val_text,
                    });
                }
                other => {
                    return Err(ParseError::UnexpectedToken {
                        span: other.span().clone(),
                        expected: "string for 'effect' value",
                    })
                }
            },
            "details" => {
                details = Some(entry.value);
            }
            _ => {}
        }
    }

    let effect = effect.ok_or_else(|| ParseError::MissingKey {
        span: span.clone(),
        key: "effect",
    })?;

    Ok(ThenBlock {
        span,
        effect,
        details,
    })
}

fn constraint_from_json_value(jv: JsonValue) -> Result<Constraint, ParseError> {
    let (span, entries) = match jv {
        JsonValue::Object(span, entries) => (span, entries),
        other => {
            return Err(ParseError::UnexpectedToken {
                span: other.span().clone(),
                expected: "object for constraint",
            })
        }
    };

    for entry in entries.iter() {
        let key_lower = entry.key.to_ascii_lowercase();
        if matches!(key_lower.as_str(), "allof" | "anyof" | "not") && entries.len() > 1 {
            return Err(ParseError::ExtraKeysInLogical {
                span: entry.key_span.clone(),
                operator: key_lower,
            });
        }
    }

    if entries.len() == 1 {
        let entry = entries.into_iter().next().expect("entry missing");
        let key_lower = entry.key.to_ascii_lowercase();
        match key_lower.as_str() {
            "allof" => {
                let JsonValue::Array(_, items) = entry.value else {
                    return Err(ParseError::LogicalOperatorNotArray {
                        span: entry.key_span,
                        operator: key_lower,
                    });
                };
                let mut constraints = Vec::with_capacity(items.len());
                for item in items {
                    constraints.push(constraint_from_json_value(item)?);
                }
                return Ok(Constraint::AllOf { span, constraints });
            }
            "anyof" => {
                let JsonValue::Array(_, items) = entry.value else {
                    return Err(ParseError::LogicalOperatorNotArray {
                        span: entry.key_span,
                        operator: key_lower,
                    });
                };
                let mut constraints = Vec::with_capacity(items.len());
                for item in items {
                    constraints.push(constraint_from_json_value(item)?);
                }
                return Ok(Constraint::AnyOf { span, constraints });
            }
            "not" => {
                let inner = constraint_from_json_value(entry.value)?;
                return Ok(Constraint::Not {
                    span,
                    constraint: Box::new(inner),
                });
            }
            _ => {
                return condition_from_entries(span, vec![entry]);
            }
        }
    }

    condition_from_entries(span, entries)
}

fn condition_from_entries(span: Span, entries: Vec<ObjectEntry>) -> Result<Constraint, ParseError> {
    let mut field: Option<(Span, JsonValue)> = None;
    let mut value: Option<(Span, JsonValue)> = None;
    let mut count: Option<(Span, CountInner)> = None;
    let mut operator: Option<OperatorNode> = None;
    let mut rhs: Option<JsonValue> = None;

    for entry in entries {
        let key_lower = entry.key.to_ascii_lowercase();
        match key_lower.as_str() {
            "field" => {
                field = Some((entry.key_span, entry.value));
            }
            "value" => {
                value = Some((entry.key_span, entry.value));
            }
            "count" => {
                let count_inner = count_inner_from_json_value(entry.value)?;
                count = Some((entry.key_span, count_inner));
            }
            _ => {
                if let Some(op_kind) = parse_operator_kind(&key_lower) {
                    operator = Some(OperatorNode {
                        span: entry.key_span,
                        kind: op_kind,
                    });
                    rhs = Some(entry.value);
                } else {
                    return Err(ParseError::UnrecognizedKey {
                        span: entry.key_span,
                        key: key_lower,
                    });
                }
            }
        }
    }

    let operator = operator.ok_or_else(|| ParseError::MissingOperator { span: span.clone() })?;
    let rhs_json = rhs.ok_or_else(|| ParseError::MissingOperator { span: span.clone() })?;
    let rhs_value = Parser::json_to_value_or_expr(rhs_json)?;

    let lhs = match (field, value, count) {
        (Some((_, fv)), None, None) => Lhs::Field(Parser::json_to_field(fv)?),
        (None, Some((key_span, vv)), None) => Lhs::Value {
            key_span,
            value: Parser::json_to_value_or_expr(vv)?,
        },
        (None, None, Some((_, ci))) => Lhs::Count(Parser::finalize_count(ci)?),
        (None, None, None) => {
            return Err(ParseError::MissingLhsOperand { span: span.clone() })
        }
        _ => {
            return Err(ParseError::MultipleLhsOperands { span: span.clone() })
        }
    };

    Ok(Constraint::Condition(Box::new(Condition {
        span,
        lhs,
        operator,
        rhs: rhs_value,
    })))
}

fn count_inner_from_json_value(jv: JsonValue) -> Result<CountInner, ParseError> {
    let (span, entries) = match jv {
        JsonValue::Object(span, entries) => (span, entries),
        other => {
            return Err(ParseError::UnexpectedToken {
                span: other.span().clone(),
                expected: "object for 'count'",
            })
        }
    };

    let mut field: Option<(Span, JsonValue)> = None;
    let mut value: Option<(Span, JsonValue)> = None;
    let mut name: Option<(Span, JsonValue)> = None;
    let mut where_: Option<Constraint> = None;

    for entry in entries {
        let key_lower = entry.key.to_ascii_lowercase();
        match key_lower.as_str() {
            "field" => {
                field = Some((entry.key_span, entry.value));
            }
            "value" => {
                value = Some((entry.key_span, entry.value));
            }
            "name" => {
                name = Some((entry.key_span, entry.value));
            }
            "where" => {
                where_ = Some(constraint_from_json_value(entry.value)?);
            }
            _ => {
                return Err(ParseError::UnrecognizedKey {
                    span: entry.key_span,
                    key: key_lower,
                })
            }
        }
    }

    Ok(CountInner {
        span,
        field,
        value,
        name,
        where_,
    })
}
