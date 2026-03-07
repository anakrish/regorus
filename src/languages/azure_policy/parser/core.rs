// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core parser struct and low-level JSON parsing methods.

use alloc::boxed::Box;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use crate::lexer::{Lexer, Source, Span, Token, TokenKind};

use crate::languages::azure_policy::ast::{Constraint, JsonValue, ObjectEntry, ValueOrExpr};
use crate::languages::azure_policy::expr::ExprParser;

use super::error::ParseError;
use super::is_template_expr;

/// Unescape a JSON string body (the content between the outer `"` delimiters).
///
/// The lexer returns the raw source text for strings which preserves backslash
/// escape sequences (e.g., `\"`, `\\`, `\n`, `\uXXXX`).  This function
/// converts them to the actual characters they represent so that runtime
/// `Value::String` comparisons work correctly.
fn json_unescape(raw: &str) -> String {
    // Fast path: if there is no backslash, the text is already unescaped.
    if !raw.contains('\\') {
        return raw.into();
    }

    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\u{0008}'),
                Some('f') => result.push('\u{000C}'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code_point) = u32::from_str_radix(&hex, 16) {
                        if let Some(c) = char::from_u32(code_point) {
                            result.push(c);
                        }
                    }
                }
                Some(c) => {
                    // Unknown escape — preserve as-is.
                    result.push('\\');
                    result.push(c);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(ch);
        }
    }

    result
}

// ============================================================================
// Intermediate types for constraint building
// ============================================================================

/// Intermediate value type used during constraint object parsing.
///
/// Different keys produce different value types; we track them separately
/// to avoid re-parsing.
pub(super) enum EntryValue {
    Json(JsonValue),
    ConstraintArray(Vec<Constraint>),
    SingleConstraint(Constraint),
    CountInner(Box<CountInner>),
}

/// Intermediate representation of a parsed count sub-object.
pub(super) struct CountInner {
    pub span: Span,
    pub field: Option<(Span, JsonValue)>,
    pub value: Option<(Span, JsonValue)>,
    pub name: Option<(Span, JsonValue)>,
    pub where_: Option<Constraint>,
}

// ============================================================================
// Parser struct
// ============================================================================

/// Recursive-descent parser for Azure Policy JSON.
///
/// Wraps a [`Lexer`] configured for JSON tokenization (`set_unknown_char_is_symbol(true)`)
/// and maintains the current look-ahead token.
pub(super) struct Parser<'source> {
    lexer: Lexer<'source>,
    /// Current look-ahead token.
    pub tok: Token,
}

impl<'source> Parser<'source> {
    /// Create a new parser for the given source.
    pub fn new(source: &'source Source) -> Result<Self, ParseError> {
        let mut lexer = Lexer::new(source);
        lexer.set_unknown_char_is_symbol(true);

        let tok = lexer
            .next_token()
            .map_err(|e| ParseError::Lexer(e.to_string()))?;

        Ok(Self { lexer, tok })
    }

    /// Advance to the next token.
    pub fn advance(&mut self) -> Result<(), ParseError> {
        self.tok = self
            .lexer
            .next_token()
            .map_err(|e| ParseError::Lexer(e.to_string()))?;
        Ok(())
    }

    /// Get the text of the current token (for Symbol, Number, Ident).
    pub fn token_text(&self) -> &str {
        match self.tok.0 {
            TokenKind::Symbol | TokenKind::Number | TokenKind::Ident | TokenKind::Eof => {
                self.tok.1.text()
            }
            TokenKind::String | TokenKind::RawString => "",
            #[cfg(feature = "azure-rbac")]
            _ => "",
        }
    }

    /// Expect and consume a specific symbol character (e.g., `{`, `}`, `:`, `,`).
    pub fn expect_symbol(&mut self, ch: &str) -> Result<Span, ParseError> {
        if self.tok.0 != TokenKind::Symbol || self.token_text() != ch {
            return Err(ParseError::UnexpectedToken {
                span: self.tok.1.clone(),
                expected: match ch {
                    "{" => "'{'",
                    "}" => "'}'",
                    "[" => "'['",
                    "]" => "']'",
                    ":" => "':'",
                    "," => "','",
                    _ => "symbol",
                },
            });
        }
        let span = self.tok.1.clone();
        self.advance()?;
        Ok(span)
    }

    /// Consume a string token and return its (span, text).
    ///
    /// The returned text has JSON escape sequences resolved (e.g., `\"` → `"`).
    pub fn expect_string(&mut self) -> Result<(Span, String), ParseError> {
        if self.tok.0 != TokenKind::String {
            return Err(ParseError::UnexpectedToken {
                span: self.tok.1.clone(),
                expected: "string",
            });
        }
        let span = self.tok.1.clone();
        let text = json_unescape(span.text());
        self.advance()?;
        Ok((span, text))
    }

    // ========================================================================
    // Generic JSON value parsing
    // ========================================================================

    /// Parse any JSON value.
    pub fn parse_json_value(&mut self) -> Result<JsonValue, ParseError> {
        match self.tok.0 {
            TokenKind::String => {
                let span = self.tok.1.clone();
                let text = json_unescape(span.text());
                self.advance()?;
                Ok(JsonValue::Str(span, text))
            }
            TokenKind::Number => {
                let span = self.tok.1.clone();
                let text: String = span.text().into();
                self.advance()?;
                Ok(JsonValue::Number(span, text))
            }
            TokenKind::Ident => {
                let span = self.tok.1.clone();
                let text = span.text();
                let value = match text {
                    "true" => JsonValue::Bool(span.clone(), true),
                    "false" => JsonValue::Bool(span.clone(), false),
                    "null" => JsonValue::Null(span.clone()),
                    _ => {
                        return Err(ParseError::UnexpectedToken {
                            span,
                            expected: "JSON value",
                        });
                    }
                };
                self.advance()?;
                Ok(value)
            }
            TokenKind::Symbol if self.token_text() == "[" => self.parse_json_array(),
            TokenKind::Symbol if self.token_text() == "{" => self.parse_json_object(),
            TokenKind::Symbol if self.token_text() == "-" => {
                let start_span = self.tok.1.clone();
                self.advance()?;
                if self.tok.0 != TokenKind::Number {
                    return Err(ParseError::UnexpectedToken {
                        span: self.tok.1.clone(),
                        expected: "number after '-'",
                    });
                }
                let num_span = self.tok.1.clone();
                let mut text = String::from("-");
                text.push_str(num_span.text());
                self.advance()?;
                let span = Span {
                    source: start_span.source.clone(),
                    line: start_span.line,
                    col: start_span.col,
                    start: start_span.start,
                    end: num_span.end,
                };
                Ok(JsonValue::Number(span, text))
            }
            _ => Err(ParseError::UnexpectedToken {
                span: self.tok.1.clone(),
                expected: "JSON value",
            }),
        }
    }

    /// Parse a JSON array `[...]`.
    fn parse_json_array(&mut self) -> Result<JsonValue, ParseError> {
        let open = self.expect_symbol("[")?;
        let mut items = Vec::new();
        if self.token_text() != "]" {
            items.push(self.parse_json_value()?);
            while self.token_text() == "," {
                self.advance()?;
                items.push(self.parse_json_value()?);
            }
        }
        let close = self.expect_symbol("]")?;
        let span = Span {
            source: open.source.clone(),
            line: open.line,
            col: open.col,
            start: open.start,
            end: close.end,
        };
        Ok(JsonValue::Array(span, items))
    }

    /// Parse a JSON object `{...}` as a generic `JsonValue::Object`.
    fn parse_json_object(&mut self) -> Result<JsonValue, ParseError> {
        let open = self.expect_symbol("{")?;
        let mut entries = Vec::new();
        if self.token_text() != "}" {
            entries.push(self.parse_object_entry()?);
            while self.token_text() == "," {
                self.advance()?;
                entries.push(self.parse_object_entry()?);
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
        Ok(JsonValue::Object(span, entries))
    }

    /// Parse a single `"key": value` entry in a JSON object.
    fn parse_object_entry(&mut self) -> Result<ObjectEntry, ParseError> {
        let (key_span, key) = self.expect_string()?;
        self.expect_symbol(":")?;
        let value = self.parse_json_value()?;
        Ok(ObjectEntry {
            key_span,
            key,
            value,
        })
    }

    // ========================================================================
    // Conversion helpers
    // ========================================================================

    /// Convert a JSON value into a [`ValueOrExpr`].
    pub fn json_to_value_or_expr(jv: JsonValue) -> Result<ValueOrExpr, ParseError> {
        match jv {
            JsonValue::Str(ref span, ref s) if is_template_expr(s) => {
                let end = s.len().saturating_sub(1);
                let inner = &s[1..end];
                let expr = ExprParser::parse_from_brackets(inner, span).map_err(|e| {
                    ParseError::ExprParse {
                        span: span.clone(),
                        message: e.to_string(),
                    }
                })?;
                Ok(ValueOrExpr::Expr {
                    span: span.clone(),
                    raw: s.clone(),
                    expr,
                })
            }
            // Handle `[[...` escaped literals: strip the leading `[`.
            JsonValue::Str(span, ref s) if s.starts_with("[[") => {
                let unescaped = alloc::string::String::from(&s[1..]);
                Ok(ValueOrExpr::Value(JsonValue::Str(span, unescaped)))
            }
            _ => Ok(ValueOrExpr::Value(jv)),
        }
    }
}
