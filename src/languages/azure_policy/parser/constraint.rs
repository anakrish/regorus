// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constraint parsing: logical combinators and leaf conditions.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::lexer::Span;

use crate::languages::azure_policy::ast::{Condition, Constraint, JsonValue, Lhs, OperatorNode};

use super::core::{CountInner, EntryValue, Parser};
use super::error::ParseError;
use super::parse_operator_kind;

impl<'source> Parser<'source> {
    /// Parse a constraint (a JSON object: logical combinator or leaf condition).
    pub fn parse_constraint(&mut self) -> Result<Constraint, ParseError> {
        let open = self.expect_symbol("{")?;
        let mut entries: Vec<(Span, String, EntryValue)> = Vec::new();

        if self.token_text() != "}" {
            loop {
                let (key_span, key) = self.expect_string()?;
                self.expect_symbol(":")?;
                let key_lower = key.to_ascii_lowercase();

                let value = match key_lower.as_str() {
                    "allof" | "anyof" => {
                        EntryValue::ConstraintArray(self.parse_constraint_array()?)
                    }
                    "not" | "where" => EntryValue::SingleConstraint(self.parse_constraint()?),
                    "count" => EntryValue::CountInner(Box::new(self.parse_count_inner()?)),
                    _ => EntryValue::Json(self.parse_json_value()?),
                };

                entries.push((key_span, key_lower, value));

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

        Self::build_constraint(span, entries)
    }

    /// Parse a `[constraint, constraint, ...]` array for `allOf`/`anyOf`.
    fn parse_constraint_array(&mut self) -> Result<Vec<Constraint>, ParseError> {
        self.expect_symbol("[")?;
        let mut constraints = Vec::new();
        if self.token_text() != "]" {
            constraints.push(self.parse_constraint()?);
            while self.token_text() == "," {
                self.advance()?;
                constraints.push(self.parse_constraint()?);
            }
        }
        self.expect_symbol("]")?;
        Ok(constraints)
    }

    /// Dispatch on collected entries to build the appropriate constraint.
    fn build_constraint(
        span: Span,
        entries: Vec<(Span, String, EntryValue)>,
    ) -> Result<Constraint, ParseError> {
        // Check for logical operators with extra keys.
        for entry in entries.iter() {
            if matches!(entry.1.as_str(), "allof" | "anyof" | "not") && entries.len() > 1 {
                return Err(ParseError::ExtraKeysInLogical {
                    span: entry.0.clone(),
                    operator: entry.1.clone(),
                });
            }
        }

        // Single-entry logical operators.
        if entries.len() == 1 {
            // Safe: we just checked len() == 1.
            let mut entries = entries;
            let (key_span, key, value) = entries
                .pop()
                .ok_or_else(|| ParseError::MissingLhsOperand { span: span.clone() })?;
            match key.as_str() {
                "allof" => {
                    let EntryValue::ConstraintArray(constraints) = value else {
                        return Err(ParseError::LogicalOperatorNotArray {
                            span: key_span,
                            operator: key,
                        });
                    };
                    return Ok(Constraint::AllOf { span, constraints });
                }
                "anyof" => {
                    let EntryValue::ConstraintArray(constraints) = value else {
                        return Err(ParseError::LogicalOperatorNotArray {
                            span: key_span,
                            operator: key,
                        });
                    };
                    return Ok(Constraint::AnyOf { span, constraints });
                }
                "not" => {
                    let EntryValue::SingleConstraint(constraint) = value else {
                        // `not` is always parsed as SingleConstraint in parse_constraint,
                        // so this branch is structurally unreachable.
                        return Err(ParseError::UnexpectedToken {
                            span: key_span,
                            expected: "constraint for 'not'",
                        });
                    };
                    return Ok(Constraint::Not {
                        span,
                        constraint: Box::new(constraint),
                    });
                }
                _ => {
                    return Self::build_condition(span, alloc::vec![(key_span, key, value)]);
                }
            }
        }

        Self::build_condition(span, entries)
    }

    /// Build a leaf condition from collected object entries.
    fn build_condition(
        span: Span,
        entries: Vec<(Span, String, EntryValue)>,
    ) -> Result<Constraint, ParseError> {
        let mut field: Option<(Span, JsonValue)> = None;
        let mut value: Option<(Span, JsonValue)> = None;
        let mut count: Option<(Span, Box<CountInner>)> = None;
        let mut operator: Option<OperatorNode> = None;
        let mut rhs: Option<JsonValue> = None;

        for (key_span, key, entry_value) in entries {
            match key.as_str() {
                "field" => {
                    let EntryValue::Json(jv) = entry_value else {
                        return Err(ParseError::UnexpectedToken {
                            span: key_span,
                            expected: "JSON value for 'field'",
                        });
                    };
                    field = Some((key_span, jv));
                }
                "value" => {
                    let EntryValue::Json(jv) = entry_value else {
                        return Err(ParseError::UnexpectedToken {
                            span: key_span,
                            expected: "JSON value for 'value'",
                        });
                    };
                    value = Some((key_span, jv));
                }
                "count" => {
                    let EntryValue::CountInner(ci) = entry_value else {
                        return Err(ParseError::UnexpectedToken {
                            span: key_span,
                            expected: "object for 'count'",
                        });
                    };
                    count = Some((key_span, ci));
                }
                _ => {
                    if let Some(op_kind) = parse_operator_kind(&key) {
                        let EntryValue::Json(jv) = entry_value else {
                            return Err(ParseError::UnexpectedToken {
                                span: key_span,
                                expected: "JSON value for operator",
                            });
                        };
                        operator = Some(OperatorNode {
                            span: key_span,
                            kind: op_kind,
                        });
                        rhs = Some(jv);
                    } else {
                        return Err(ParseError::UnrecognizedKey {
                            span: key_span,
                            key,
                        });
                    }
                }
            }
        }

        let operator =
            operator.ok_or_else(|| ParseError::MissingOperator { span: span.clone() })?;
        let rhs_json = rhs.ok_or_else(|| ParseError::MissingOperator { span: span.clone() })?;
        let rhs_value = Self::json_to_value_or_expr(rhs_json)?;

        let lhs = match (field, value, count) {
            (Some((_, fv)), None, None) => Lhs::Field(Self::json_to_field(fv)?),
            (None, Some((key_span, vv)), None) => Lhs::Value {
                key_span,
                value: Self::json_to_value_or_expr(vv)?,
            },
            (None, None, Some((_, ci))) => Lhs::Count(Self::finalize_count(*ci)?),

            (None, None, None) => {
                return Err(ParseError::MissingLhsOperand { span: span.clone() });
            }
            _ => {
                return Err(ParseError::MultipleLhsOperands { span: span.clone() });
            }
        };

        Ok(Constraint::Condition(Box::new(Condition {
            span,
            lhs,
            operator,
            rhs: rhs_value,
        })))
    }
}
