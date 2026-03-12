// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `regorus-smt` — A Z3-compatible SMT abstraction layer.
//!
//! This crate provides:
//!
//! - [`SmtExpr`] — A serializable expression AST whose variants map 1:1 to
//!   `Z3_mk_*` C API functions. Can be rendered to SMT-LIB2 text or
//!   reconstructed into live Z3 objects (via the Rust `z3` crate or the
//!   `z3-solver` npm WASM module from JavaScript).
//!
//! - [`SmtProblem`] / [`SmtSolution`] — Serializable request/response types
//!   for shipping analysis problems to an external solver and getting typed
//!   results back.
//!
//! - [`SmtContext`] / [`SmtSolver`] — Traits abstracting over expression
//!   construction and solving, enabling both a native Z3 backend and a
//!   portable AST backend.
//!
//! # Design Principle
//!
//! Every [`SmtExpr`] variant corresponds to exactly one `Z3_mk_*` function.
//! This makes translation to any Z3 interface mechanical:
//!
//! | `SmtExpr` variant   | Rust `z3` crate          | JS `z3-solver` npm       | SMT-LIB2 text         |
//! |---------------------|--------------------------|--------------------------|-----------------------|
//! | `And(args)`         | `Z3_mk_and(ctx, n, args)`| `Z3.mk_and(ctx, args)`   | `(and ...)`           |
//! | `SeqLength(s)`      | `Z3_mk_seq_length(ctx,s)`| `Z3.mk_seq_length(ctx,s)`| `(str.len s)`         |

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod expr;
mod problem;
mod render;
mod context;
mod backend;

pub use expr::*;
pub use problem::*;
pub use render::*;
pub use context::*;
pub use backend::*;
