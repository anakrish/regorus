// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(dead_code, clippy::unused_self, clippy::missing_const_for_fn)]

//! ARM template function dispatch.
//!
//! Stub — real implementation added in a later commit.

use anyhow::Result;

use crate::languages::azure_policy::ast::Expr;

use super::core::Compiler;

impl Compiler {
    pub(super) fn compile_arm_template_function(
        &mut self,
        _function_name: &str,
        _span: &crate::lexer::Span,
        _args: &[Expr],
    ) -> Result<Option<u8>> {
        Ok(None)
    }
}
