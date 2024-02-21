// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ast::{Expr, LiteralStmt, Ref};
use crate::interpreter::Interpreter;
use crate::lexer::Span;
use crate::Value;

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

#[derive(Default, Debug)]
pub struct Debugger {
    rl: Option<DefaultEditor>,
}

impl Clone for Debugger {
    fn clone(&self) -> Self {
        Self { rl: None }
    }
}

impl Debugger {
    pub fn pre_eval_expr(&mut self, expr: &Ref<Expr>, interpreter: &Interpreter) {
        eprintln!("{}", expr.span().text());
        self.prompt(&expr.span(), interpreter);
    }

    pub fn post_eval_expr(&mut self, expr: &Ref<Expr>, value: &Value, interpreter: &Interpreter) {
        eprintln!("{} => {}", expr.span().text(), Self::value_to_string(value))
    }

    pub fn pre_eval_stmt(&mut self, stmt: &LiteralStmt, interpreter: &Interpreter) {
        eprintln!("{}", stmt.span.text())
    }

    pub fn post_eval_stmt(&mut self, stmt: &LiteralStmt, value: &Value, interpreter: &Interpreter) {
        eprintln!("{} => {}", stmt.span.text(), Self::value_to_string(value))
    }

    fn value_to_string(v: &Value) -> String {
        match serde_json::to_string_pretty(v) {
            Ok(s) => s,
            _ => "<could not print value>".to_string(),
        }
    }
}

impl Debugger {
    fn prompt(&mut self, span: &Span, interpreter: &Interpreter) {
        let mut rl = std::mem::take(&mut self.rl)
            .unwrap_or_else(|| DefaultEditor::new().expect("could not create debugger prompt"));
        let _r = rl.readline("rdb) ");
        self.rl = Some(rl);
    }
}
