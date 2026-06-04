// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::ensure_n_args;

use crate::lexer::Span;
use crate::value::Value;

use anyhow::Result;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("http.send", (send, 1));
}

fn send(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "http.send";
    let (_args, _params) = ensure_n_args::<1>(span, name, params, args)?;
    Ok(Value::Undefined)
}
