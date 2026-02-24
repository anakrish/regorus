// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Policy language support: AST types and custom JSON parser.
//!
//! This module provides:
//! - [`ast`]: Span-annotated AST types for Azure Policy rule conditions
//! - [`parser`]: Custom recursive-descent JSON parser using the regorus [`Lexer`](crate::lexer::Lexer)
//! - [`expr`]: ARM template expression sub-parser

#![allow(
    clippy::as_conversions,
    clippy::arithmetic_side_effects,
    clippy::for_kv_map,
    clippy::if_then_some_else_none,
    clippy::indexing_slicing,
    clippy::manual_ignore_case_cmp,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::pattern_type_mismatch,
    clippy::redundant_pub_crate,
    clippy::shadow_unrelated,
    clippy::unused_self,
    clippy::unused_trait_names,
    clippy::useless_conversion
)]

pub mod aliases;
pub mod ast;
pub mod compiler;
pub mod expr;
pub mod parser;
pub mod strings;
