// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::shadow_unrelated,
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::option_if_let_else,
    clippy::semicolon_if_nothing_returned,
    clippy::useless_let_if_seq
)] // builtins perform validated indexing and intentional arithmetic/string ops

mod aggregates;
mod arrays;
#[cfg(feature = "azure_policy")]
pub mod azure_policy;
mod bitwise;
#[cfg(feature = "cedar")]
mod cedar;
pub mod comparison;
mod conversions;

mod encoding;
#[cfg(feature = "glob")]
mod glob;
#[cfg(feature = "graph")]
mod graph;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "net")]
mod net;

pub mod numbers;
mod objects;
#[cfg(feature = "opa-runtime")]
mod opa;
#[cfg(feature = "regex")]
mod regex;
#[cfg(feature = "semver")]
mod semver;
pub mod sets;
mod strings;
#[cfg(feature = "time")]
mod time;
mod tracing;
pub mod types;
mod units;
mod utils;
#[cfg(feature = "uuid")]
mod uuid;

#[cfg(feature = "opa-testutil")]
mod test;

use crate::ast::{Expr, Ref};
use crate::lexer::Span;
use crate::value::Value;

use crate::Map as BuiltinsMap;

use anyhow::Result;
use lazy_static::lazy_static;

pub type BuiltinFcn = (fn(&Span, &[Ref<Expr>], &[Value], bool) -> Result<Value>, u8);

#[cfg(feature = "cedar")]
#[derive(Debug, Default, Clone)]
pub struct BuiltinContext {
    pub cedar_cache: Option<crate::Rc<crate::languages::cedar::cache::CedarCache>>,
}

#[cfg(feature = "cedar")]
pub type BuiltinCtxFcn = (
    fn(&BuiltinContext, &Span, &[Ref<Expr>], &[Value], bool) -> Result<Value>,
    u8,
);

#[rustfmt::skip]
lazy_static! {
	pub static ref BUILTINS: BuiltinsMap<&'static str, BuiltinFcn> = {
	let mut m : BuiltinsMap<&'static str, BuiltinFcn>  = BuiltinsMap::new();

	// comparison functions are directly called.
	numbers::register(&mut m);
	aggregates::register(&mut m);
	arrays::register(&mut m);
	sets::register(&mut m);
	objects::register(&mut m);
	strings::register(&mut m);

	#[cfg(feature = "regex")]
	regex::register(&mut m);

	#[cfg(feature = "glob")]
	glob::register(&mut m);

	#[cfg(feature = "graph")]
	graph::register(&mut m);

	bitwise::register(&mut m);
	conversions::register(&mut m);
	//units::register(&mut m);
	types::register(&mut m);
	encoding::register(&mut m);
	#[cfg(feature = "time")]
	time::register(&mut m);

	//graphql::register(&mut m);
	#[cfg(feature = "http")]
	http::register(&mut m);
	#[cfg(feature = "net")]
	net::register(&mut m);
	//net::register(&mut m);
	#[cfg(feature = "uuid")]
	uuid::register(&mut m);
	#[cfg(feature = "semver")]
	semver::register(&mut m);
	//rego::register(&mut m);
	#[cfg(feature = "azure_policy")]
	azure_policy::register(&mut m);
	#[cfg(feature = "opa-runtime")]
	opa::register(&mut m);
	tracing::register(&mut m);
	units::register(&mut m);

	#[cfg(feature = "opa-testutil")]
	test::register(&mut m);

	// fetch — external I/O builtin. At runtime, the host provides
	// the response; for Z3 analysis it is modeled as input.
	m.insert("fetch", (fetch_stub, 1));

	m
    };
}

#[cfg(feature = "cedar")]
#[rustfmt::skip]
lazy_static! {
    pub static ref BUILTINS_CTX: BuiltinsMap<&'static str, BuiltinCtxFcn> = {
	let mut m : BuiltinsMap<&'static str, BuiltinCtxFcn>  = BuiltinsMap::new();

	cedar::register(&mut m);

	m
    };
}

/// Stub implementation for `fetch` builtin.
/// At runtime the host provides the response via HostAwait or a
/// custom runtime function.  This stub exists solely so the
/// compiler recognizes `fetch` as a known builtin.  For Z3
/// analysis the result is modeled as an input path.
fn fetch_stub(_span: &Span, _params: &[Ref<Expr>], _args: &[Value], _strict: bool) -> Result<Value> {
    Ok(Value::Undefined)
}

pub fn must_cache(path: &str) -> Option<&'static str> {
    match path {
        "opa.runtime" => Some("opa.runtime"),
        "rand.intn" => Some("rand.intn"),
        "time.now_ns" => Some("time.now_ns"),
        "uuid.rfc4122" => Some("uuid.rfc4122"),
        _ => None,
    }
}
