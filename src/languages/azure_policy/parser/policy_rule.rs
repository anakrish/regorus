// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Top-level policy rule parsing: `parse_policy_rule`, `parse_then_block`, and count parsing.

use alloc::boxed::Box;
use alloc::string::ToString as _;

use crate::lexer::Span;

use crate::languages::azure_policy::ast::{
    Constraint, CountNode, EffectKind, EffectNode, FieldNode, JsonValue, NameNode, PolicyRule,
    ThenBlock,
};

use super::classify_field;
use super::core::{CountInner, Parser};
use super::error::ParseError;

impl<'source> Parser<'source> {
    /// Parse the top-level `policyRule` object.
    pub fn parse_policy_rule(&mut self) -> Result<PolicyRule, ParseError> {
        let open = self.expect_symbol("{")?;

        let mut condition: Option<Constraint> = None;
        let mut then_block: Option<ThenBlock> = None;
        let mut condition_span: Option<Span> = None;
        let mut then_span: Option<Span> = None;

        if self.token_text() != "}" {
            loop {
                let (key_span, key) = self.expect_string()?;
                self.expect_symbol(":")?;

                match key.to_lowercase().as_str() {
                    "if" => {
                        condition_span = Some(key_span);
                        condition = Some(self.parse_constraint()?);
                    }
                    "then" => {
                        then_span = Some(key_span);
                        then_block = Some(self.parse_then_block()?);
                    }
                    _ => {
                        let _ = self.parse_json_value()?;
                    }
                }

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

        let condition = condition.ok_or_else(|| ParseError::MissingKey {
            span: condition_span.unwrap_or_else(|| span.clone()),
            key: "if",
        })?;
        let then_block = then_block.ok_or_else(|| ParseError::MissingKey {
            span: then_span.unwrap_or_else(|| span.clone()),
            key: "then",
        })?;

        Ok(PolicyRule {
            span,
            condition,
            then_block,
        })
    }

    /// Parse the `"then"` block.
    fn parse_then_block(&mut self) -> Result<ThenBlock, ParseError> {
        let open = self.expect_symbol("{")?;

        let mut effect: Option<EffectNode> = None;
        let mut details: Option<JsonValue> = None;

        if self.token_text() != "}" {
            loop {
                let (_key_span, key) = self.expect_string()?;
                self.expect_symbol(":")?;

                match key.to_lowercase().as_str() {
                    "effect" => {
                        let (val_span, val_text) = self.expect_string()?;
                        let kind = match val_text.to_lowercase().as_str() {
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
                    "details" => {
                        details = Some(self.parse_json_value()?);
                    }
                    _ => {
                        let _ = self.parse_json_value()?;
                    }
                }

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

        let effect = effect.ok_or_else(|| ParseError::MissingKey {
            span: span.clone(),
            key: "effect",
        })?;

        // Extract and parse `existenceCondition` from the `details` block.
        let existence_condition = Self::extract_existence_condition(&details)?;

        Ok(ThenBlock {
            span,
            effect,
            details,
            existence_condition,
        })
    }

    /// Extract `existenceCondition` from a `details` `JsonValue` and parse it
    /// as a `Constraint`.
    ///
    /// The `existenceCondition` uses the same grammar as `policyRule.if`, so
    /// we extract the source text via the span and re-parse it.
    fn extract_existence_condition(
        details: &Option<JsonValue>,
    ) -> Result<Option<Constraint>, ParseError> {
        let details = match details {
            Some(d) => d,
            None => return Ok(None),
        };

        let entries = match details {
            JsonValue::Object(_, entries) => entries,
            _ => return Ok(None),
        };

        let existence_entry = entries
            .iter()
            .find(|e| e.key.eq_ignore_ascii_case("existenceCondition"));

        let existence_value = match existence_entry {
            Some(e) => &e.value,
            None => return Ok(None),
        };

        // Get the source text of the existenceCondition value via its span.
        let ec_span = existence_value.span();
        let source_text = ec_span.source.get_contents();
        let start = ec_span.start as usize;
        let end = ec_span.end as usize;
        let ec_text = &source_text[start..end];

        let ec_source = crate::lexer::Source::from_contents(
            "existenceCondition".to_string(),
            ec_text.to_string(),
        )
        .map_err(|e| ParseError::Custom {
            span: ec_span.clone(),
            message: alloc::format!("failed to create source for existenceCondition: {}", e),
        })?;

        let constraint = super::parse_constraint(&ec_source).map_err(|e| ParseError::Custom {
            span: ec_span.clone(),
            message: alloc::format!("failed to parse existenceCondition: {}", e),
        })?;

        Ok(Some(constraint))
    }

    /// Parse the inner object of a `"count": { ... }` block.
    pub fn parse_count_inner(&mut self) -> Result<CountInner, ParseError> {
        let open = self.expect_symbol("{")?;

        let mut field: Option<(Span, JsonValue)> = None;
        let mut value: Option<(Span, JsonValue)> = None;
        let mut name: Option<(Span, JsonValue)> = None;
        let mut where_: Option<Constraint> = None;

        if self.token_text() != "}" {
            loop {
                let (key_span, key) = self.expect_string()?;
                self.expect_symbol(":")?;
                let key_lower = key.to_lowercase();

                match key_lower.as_str() {
                    "field" => {
                        let jv = self.parse_json_value()?;
                        field = Some((key_span, jv));
                    }
                    "value" => {
                        let jv = self.parse_json_value()?;
                        value = Some((key_span, jv));
                    }
                    "name" => {
                        let jv = self.parse_json_value()?;
                        name = Some((key_span, jv));
                    }
                    "where" => {
                        where_ = Some(self.parse_constraint()?);
                    }
                    _ => {
                        return Err(ParseError::UnrecognizedKey {
                            span: key_span,
                            key: key_lower,
                        });
                    }
                }

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

        Ok(CountInner {
            span,
            field,
            value,
            name,
            where_,
        })
    }

    /// Convert a JSON value (expected to be a string) into a [`FieldNode`].
    pub fn json_to_field(jv: JsonValue) -> Result<FieldNode, ParseError> {
        let (span, text) = match jv {
            JsonValue::Str(span, text) => (span, text),
            other => {
                return Err(ParseError::UnexpectedToken {
                    span: other.span().clone(),
                    expected: "string for 'field' value",
                });
            }
        };
        let kind = classify_field(&text, &span)?;
        Ok(FieldNode { span, kind })
    }

    /// Finalize a [`CountInner`] into a [`CountNode`].
    pub fn finalize_count(ci: CountInner) -> Result<CountNode, ParseError> {
        let CountInner {
            span,
            field,
            value,
            name,
            where_,
        } = ci;
        let where_box = where_.map(Box::new);

        let name_node = match name {
            Some((key_span, jv)) => {
                if value.is_none() {
                    return Err(ParseError::MisplacedCountName { span: key_span });
                }
                match jv {
                    JsonValue::Str(name_span, text) => Some(NameNode {
                        span: name_span,
                        name: text,
                    }),
                    _ => {
                        return Err(ParseError::InvalidCountName {
                            span: jv.span().clone(),
                        });
                    }
                }
            }
            None => None,
        };

        match (field, value) {
            (None, None) => Err(ParseError::MissingCountCollection { span }),
            (Some((_, fv)), None) => {
                let field_node = Self::json_to_field(fv)?;
                Ok(CountNode::Field {
                    span,
                    field: field_node,
                    where_: where_box,
                })
            }
            (None, Some((_, vv))) => {
                let val = Self::json_to_value_or_expr(vv)?;
                Ok(CountNode::Value {
                    span,
                    value: val,
                    name: name_node,
                    where_: where_box,
                })
            }
            (Some(_), Some(_)) => Err(ParseError::MultipleCountCollections { span }),
        }
    }
}
