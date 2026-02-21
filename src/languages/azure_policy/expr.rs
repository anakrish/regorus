// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template expression sub-parser.
//!
//! Parses expressions found inside `"[...]"` strings in Azure Policy JSON.
//! Uses the regorus [`Lexer`] with `set_unknown_char_is_symbol(true)` so that
//! characters like `(`, `)`, `[`, `]`, `.`, `,` are emitted as [`TokenKind::Symbol`] tokens.
//!
//! Grammar (from `azurepolicy.ebnf`):
//! ```text
//! string-expr    ::= NUMBER | STRING | complex-expr
//! complex-expr   ::= IDENT
//!                   | complex-expr '.' IDENT
//!                   | complex-expr '(' ( string-expr ( ',' string-expr )* )? ')'
//!                   | complex-expr '[' string-expr ']'
//! ```

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

use crate::lexer::{Lexer, Source, Span, Token, TokenKind};

use super::ast::{Expr, ExprLiteral};

/// Errors that can occur during ARM template expression parsing.
#[derive(Debug)]
pub enum ExprParseError {
    /// Error from the lexer.
    Lexer(String),
    /// Unexpected token encountered.
    UnexpectedToken { span: Span, expected: &'static str },
    /// Invalid numeric literal.
    InvalidNumber(Span, String),
}

impl core::fmt::Display for ExprParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            ExprParseError::Lexer(ref msg) => write!(f, "{}", msg),
            ExprParseError::UnexpectedToken { ref span, expected } => {
                write!(f, "{}", span.error(&format!("expected {}", expected)))
            }
            ExprParseError::InvalidNumber(ref span, ref msg) => {
                write!(f, "{}", span.error(&format!("invalid number: {}", msg)))
            }
        }
    }
}

/// Parser for ARM template expressions.
///
/// Wraps a [`Lexer`] configured for expression tokenization (symbol chars enabled)
/// and provides recursive descent parsing methods.
#[derive(Debug)]
pub struct ExprParser<'source> {
    lexer: Lexer<'source>,
    tok: Token,
}

impl<'source> ExprParser<'source> {
    /// Create a new expression parser from a source.
    ///
    /// The source should contain just the expression text (without the surrounding
    /// `[` and `]` delimiters).
    fn new(source: &'source Source) -> Self {
        let mut lexer = Lexer::new(source);
        lexer.set_unknown_char_is_symbol(true);
        lexer.set_comment_starts_with_double_slash(true);
        let tok = Token(
            TokenKind::Eof,
            Span {
                source: source.clone(),
                line: 0,
                col: 0,
                start: 0,
                end: 0,
            },
        );
        Self { lexer, tok }
    }

    /// Advance to the next token.
    fn advance(&mut self) -> Result<(), ExprParseError> {
        self.tok = self
            .lexer
            .next_token()
            .map_err(|e| ExprParseError::Lexer(e.to_string()))?;
        Ok(())
    }

    /// Get the text of the current token (for Symbol, Number, Ident).
    fn token_text(&self) -> &str {
        match self.tok.0 {
            TokenKind::Symbol | TokenKind::Number | TokenKind::Ident | TokenKind::Eof => {
                self.tok.1.text()
            }
            // String tokens return empty here; access via self.tok.1.text() directly.
            TokenKind::String | TokenKind::RawString => "",
            #[cfg(feature = "azure-rbac")]
            _ => "",
        }
    }

    /// Parse a complete expression from a `"[...]"` string.
    ///
    /// `expr_content` is the text between `[` and `]` (with single quotes replaced
    /// by double quotes for the lexer).
    /// `outer_span` is the span of the original string token (for error context).
    pub fn parse_from_brackets(
        expr_content: &str,
        outer_span: &Span,
    ) -> Result<Expr, ExprParseError> {
        // Replace single quotes with double quotes (Azure Policy convention).
        let normalized = expr_content.replace('\'', "\"");

        let source = Source::from_contents("<expr>".into(), normalized)
            .map_err(|e| ExprParseError::Lexer(e.to_string()))?;

        // Create the parser locally to keep the borrow of `source` scoped
        // to this function.
        parse_expr_from_source(&source, outer_span)
    }

    /// Parse a single expression (handles left-recursive postfix operators).
    fn parse_expr(&mut self) -> Result<Expr, ExprParseError> {
        let mut expr = self.parse_primary()?;

        // Handle postfix operations: `.field`, `(args)`, `[index]`
        loop {
            let text = self.token_text();
            match text {
                "." => {
                    let dot_start = self.tok.1.start;
                    self.advance()?;
                    let (field_span, field_name) = self.expect_ident()?;
                    let span = Span {
                        source: expr.span().source.clone(),
                        line: expr.span().line,
                        col: expr.span().col,
                        start: expr.span().start,
                        end: field_span.end,
                    };
                    let _ = dot_start;
                    expr = Expr::Dot {
                        span,
                        object: Box::new(expr),
                        field_span,
                        field: field_name,
                    };
                }
                "(" => {
                    self.advance()?;
                    let mut args = Vec::new();
                    if self.token_text() != ")" {
                        args.push(self.parse_expr()?);
                        while self.token_text() == "," {
                            self.advance()?;
                            args.push(self.parse_expr()?);
                        }
                    }
                    let close_span = self.tok.1.clone();
                    if self.token_text() != ")" {
                        return Err(ExprParseError::UnexpectedToken {
                            span: self.tok.1.clone(),
                            expected: "')'",
                        });
                    }
                    self.advance()?;
                    let span = Span {
                        source: expr.span().source.clone(),
                        line: expr.span().line,
                        col: expr.span().col,
                        start: expr.span().start,
                        end: close_span.end,
                    };
                    expr = Expr::Call {
                        span,
                        func: Box::new(expr),
                        args,
                    };
                }
                "[" => {
                    self.advance()?;
                    let index = self.parse_expr()?;
                    let close_span = self.tok.1.clone();
                    if self.token_text() != "]" {
                        return Err(ExprParseError::UnexpectedToken {
                            span: self.tok.1.clone(),
                            expected: "']'",
                        });
                    }
                    self.advance()?;
                    let span = Span {
                        source: expr.span().source.clone(),
                        line: expr.span().line,
                        col: expr.span().col,
                        start: expr.span().start,
                        end: close_span.end,
                    };
                    expr = Expr::Index {
                        span,
                        object: Box::new(expr),
                        index: Box::new(index),
                    };
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    /// Parse a primary expression (literal, identifier, or unary minus).
    fn parse_primary(&mut self) -> Result<Expr, ExprParseError> {
        match self.tok.0 {
            TokenKind::Ident => {
                let (span, name) = self.expect_ident()?;
                Ok(Expr::Ident { span, name })
            }
            TokenKind::Number => {
                let span = self.tok.1.clone();
                let text = span.text().into();
                self.advance()?;
                Ok(Expr::Literal {
                    span,
                    value: ExprLiteral::Number(text),
                })
            }
            TokenKind::String => {
                let span = self.tok.1.clone();
                let text: String = span.text().into();
                self.advance()?;
                // In ARM template expressions, string "true"/"false" → boolean.
                match text.to_lowercase().as_str() {
                    "true" => Ok(Expr::Literal {
                        span,
                        value: ExprLiteral::Bool(true),
                    }),
                    "false" => Ok(Expr::Literal {
                        span,
                        value: ExprLiteral::Bool(false),
                    }),
                    _ => Ok(Expr::Literal {
                        span,
                        value: ExprLiteral::String(text),
                    }),
                }
            }
            // Unary minus: `-5`, `-3.14`, or `-expr`
            TokenKind::Symbol if self.token_text() == "-" => {
                let minus_span = self.tok.1.clone();
                self.advance()?;
                // Fuse with a following numeric literal into a negative number.
                if self.tok.0 == TokenKind::Number {
                    let num_span = self.tok.1.clone();
                    let raw: String = num_span.text().into();
                    self.advance()?;
                    let negated = format!("-{}", raw);
                    let span = Span {
                        source: minus_span.source.clone(),
                        line: minus_span.line,
                        col: minus_span.col,
                        start: minus_span.start,
                        end: num_span.end,
                    };
                    Ok(Expr::Literal {
                        span,
                        value: ExprLiteral::Number(negated),
                    })
                } else {
                    // General unary minus: compile as `sub(0, expr)`.
                    let operand = self.parse_primary()?;
                    let span = Span {
                        source: minus_span.source.clone(),
                        line: minus_span.line,
                        col: minus_span.col,
                        start: minus_span.start,
                        end: operand.span().end,
                    };
                    let zero = Expr::Literal {
                        span: minus_span,
                        value: ExprLiteral::Number("0".into()),
                    };
                    Ok(Expr::Call {
                        span: span.clone(),
                        func: Box::new(Expr::Ident {
                            span,
                            name: "sub".into(),
                        }),
                        args: alloc::vec![zero, operand],
                    })
                }
            }
            _ => Err(ExprParseError::UnexpectedToken {
                span: self.tok.1.clone(),
                expected: "identifier or literal",
            }),
        }
    }

    /// Expect the current token to be an identifier, consume it, return (span, name).
    fn expect_ident(&mut self) -> Result<(Span, String), ExprParseError> {
        if self.tok.0 != TokenKind::Ident {
            return Err(ExprParseError::UnexpectedToken {
                span: self.tok.1.clone(),
                expected: "identifier",
            });
        }
        let span = self.tok.1.clone();
        let name: String = span.text().into();
        self.advance()?;
        Ok((span, name))
    }
}

/// Internal helper: parse a complete expression from an already-constructed
/// [`Source`].  Exists as a free function so that the borrow of `source`
/// can have its own (shorter) lifetime independent of any `ExprParser`
/// type-level lifetime parameter.
fn parse_expr_from_source(source: &Source, outer_span: &Span) -> Result<Expr, ExprParseError> {
    let mut parser = ExprParser::new(source);
    parser.advance()?;
    let expr = parser.parse_expr()?;

    if parser.tok.0 != TokenKind::Eof {
        return Err(ExprParseError::UnexpectedToken {
            span: if parser.tok.1.text().is_empty() {
                outer_span.clone()
            } else {
                parser.tok.1.clone()
            },
            expected: "end of expression",
        });
    }

    Ok(expr)
}
