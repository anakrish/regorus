// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::time;
use crate::builtins::utils::{ensure_n_args, ensure_string};
use crate::lexer::Span;
use crate::value::Value;
use crate::*;

use std::thread;

use anyhow::{Ok, Result};

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("test.sleep", (sleep, 1));
}

fn sleep(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "test.sleep";
    let (args, params) = ensure_n_args::<1>(span, name, params, args)?;

    let val = ensure_string(name, &params[0], &args[0])?;
    let dur = time::compat::parse_duration(val.as_ref())
        .map_err(|e| params[0].span().error(&format!("{e}")))?;

    let std_dur = dur
        .to_std()
        .map_err(|err| anyhow::anyhow!("Failed to convert to std::time::Duration: {err}"))?;

    thread::sleep(std_dur);

    Ok(Value::Null)
}
