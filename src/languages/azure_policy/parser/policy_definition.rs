// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parsing for the full Azure Policy definition envelope.
//!
//! Handles the outer `{ "properties": { ... } }` wrapper, extracting typed
//! fields (`displayName`, `description`, `mode`, `parameters`, `policyRule`)
//! and collecting everything else into `extra`.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use crate::lexer::Span;

use crate::languages::azure_policy::ast::{
    JsonValue, ObjectEntry, ParameterDefinition, PolicyDefinition, PolicyRule,
};

use super::core::Parser;
use super::error::ParseError;

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
            e.key.to_lowercase() == "properties" && matches!(e.value, JsonValue::Object(..))
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
            if entry.key.to_lowercase() == "properties" {
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
            match entry.key.to_lowercase().as_str() {
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
        match e.key.to_lowercase().as_str() {
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
/// We need to serialize the JSON value back to a string and re-parse it through
/// the policy rule parser, since the policy rule parser expects to drive the lexer
/// itself.
fn reparse_policy_rule(jv: JsonValue, fallback_span: &Span) -> Result<PolicyRule, ParseError> {
    // Serialize the JsonValue to a JSON string.
    let json_str = json_value_to_string(&jv);
    let source = crate::lexer::Source::from_contents("policyRule".into(), json_str)
        .map_err(|e| ParseError::Lexer(e.to_string()))?;
    let mut parser = Parser::new(&source)?;
    let rule = parser.parse_policy_rule()?;

    if parser.tok.0 != crate::lexer::TokenKind::Eof {
        return Err(ParseError::UnexpectedToken {
            span: fallback_span.clone(),
            expected: "end of policyRule",
        });
    }

    Ok(rule)
}

/// Serialize a `JsonValue` back to a JSON string.
///
/// Emits newlines after commas and braces to keep lines short enough for the
/// lexer's `MAX_COL` limit when re-parsing large policy rules.
fn json_value_to_string(jv: &JsonValue) -> String {
    let mut out = String::new();
    write_json_value(&mut out, jv);
    out
}

fn write_json_value(out: &mut String, jv: &JsonValue) {
    match jv {
        JsonValue::Null(_) => out.push_str("null"),
        JsonValue::Bool(_, b) => {
            if *b {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        JsonValue::Number(_, s) => out.push_str(s),
        JsonValue::Str(_, s) => {
            out.push('"');
            // Escape special characters.
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        JsonValue::Array(_, items) => {
            out.push('[');
            out.push('\n');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    out.push('\n');
                }
                write_json_value(out, item);
            }
            out.push('\n');
            out.push(']');
        }
        JsonValue::Object(_, entries) => {
            out.push('{');
            out.push('\n');
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    out.push('\n');
                }
                out.push('"');
                for ch in entry.key.chars() {
                    match ch {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        c => out.push(c),
                    }
                }
                out.push('"');
                out.push(':');
                write_json_value(out, &entry.value);
            }
            out.push('\n');
            out.push('}');
        }
    }
}
