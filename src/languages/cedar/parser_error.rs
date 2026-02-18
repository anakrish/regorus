// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use alloc::string::{String, ToString as _};
use core::fmt;

use crate::lexer::Span;

#[derive(thiserror::Error, Debug)]
pub enum ParserError {
    #[error("{message}")]
    Message { message: String },
}

#[derive(Debug)]
pub struct SpannedParserError {
    pub error: ParserError,
    pub span: Option<Span>,
}

impl SpannedParserError {
    pub const fn new(error: ParserError) -> Self {
        Self { error, span: None }
    }

    pub fn with_span(mut self, span: &Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span.clone());
        }
        self
    }
}

impl fmt::Display for SpannedParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(span) = self.span.as_ref() {
            let msg = self.error.to_string();
            write!(f, "{}", span.message("error", &msg))
        } else {
            write!(f, "{}", self.error)
        }
    }
}

impl core::error::Error for SpannedParserError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<ParserError> for SpannedParserError {
    fn from(error: ParserError) -> Self {
        Self::new(error)
    }
}

impl ParserError {
    pub fn at(self, span: &Span) -> SpannedParserError {
        SpannedParserError::from(self).with_span(span)
    }
}

pub type Result<T> = ::core::result::Result<T, SpannedParserError>;
