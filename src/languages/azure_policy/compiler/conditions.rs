// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![allow(clippy::pattern_type_mismatch, clippy::unused_self)]

//! Constraint / condition / LHS compilation.
//!
//! Stub — real implementation added in a later commit.

use anyhow::{bail, Result};

use crate::languages::azure_policy::ast::Constraint;

use super::core::Compiler;

impl Compiler {
    pub(super) fn compile_constraint(&mut self, _constraint: &Constraint) -> Result<u8> {
        bail!("condition compilation not yet implemented")
    }
}
