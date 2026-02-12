// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::lexer::Span;
use alloc::string::{String, ToString as _};
use core::fmt;

#[derive(thiserror::Error, Debug)]
pub enum CompilerError {
    #[error("unknown builtin `{name}`")]
    UnknownBuiltin { name: String },

    #[error("unknown contexted builtin `{name}`")]
    UnknownContextedBuiltin { name: String },

    #[error("contexted builtin `{name}` requires cedar feature")]
    ContextedBuiltinRequiresCedar { name: String },

    #[error("unsupported variable `{name}`")]
    UnsupportedVariable { name: String },

    #[error("invalid variable")]
    InvalidVariable,

    #[error("member call not supported")]
    MemberCallUnsupported,

    #[error("if expressions are not supported")]
    IfUnsupported,

    #[error("template entities are not supported")]
    TemplateUnsupported,

    #[error("invalid path")]
    InvalidPath,

    #[error("register overflow")]
    RegisterOverflow,

    #[error("compiler error: {message}")]
    General { message: String },
}

#[derive(Debug)]
pub struct SpannedCompilerError {
    pub error: CompilerError,
    pub span: Option<Span>,
}

impl SpannedCompilerError {
    pub const fn new(error: CompilerError) -> Self {
        Self { error, span: None }
    }

    pub fn with_span(mut self, span: &Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span.clone());
        }
        self
    }
}

impl fmt::Display for SpannedCompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(span) = self.span.as_ref() {
            let msg = self.error.to_string();
            write!(f, "{}", span.message("error", &msg))
        } else {
            write!(f, "{}", self.error)
        }
    }
}

impl core::error::Error for SpannedCompilerError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<CompilerError> for SpannedCompilerError {
    fn from(error: CompilerError) -> Self {
        Self::new(error)
    }
}

impl CompilerError {
    pub fn at(self, span: &Span) -> SpannedCompilerError {
        SpannedCompilerError::from(self).with_span(span)
    }
}

pub type Result<T> = ::core::result::Result<T, SpannedCompilerError>;
