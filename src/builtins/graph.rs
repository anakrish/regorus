// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::pattern_type_mismatch)]

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{enforce_limit, ensure_args_count, ensure_object};
use crate::lexer::Span;
use crate::value::Value;
use crate::*;

use alloc::collections::BTreeSet;

use anyhow::{bail, Result};

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("graph.reachable", (reachable, 2));
    m.insert("graph.reachable_paths", (reachable_paths, 2));
    m.insert("walk", (walk, 1));
}

fn reachable(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "graph.reachable";
    ensure_args_count(span, name, params, args, 2)?;

    let graph = ensure_object(name, &params[0], args[0].clone())?;
    let mut worklist = vec![];

    match &args[1] {
        Value::Array(arr) => {
            for node in arr.iter() {
                worklist.push(node.clone());
                // Guard worklist growth when seeding traversal from an array.
                enforce_limit()?;
            }
        }
        Value::Set(set) => {
            for node in set.iter() {
                worklist.push(node.clone());
                // Guard worklist growth when seeding traversal from a set.
                enforce_limit()?;
            }
        }
        _ if strict => bail!(params[1].span().error("initial vertices must be array/set")),
        _ => return Ok(Value::Undefined),
    }

    let mut reachable = BTreeSet::new();
    while let Some(v) = worklist.pop() {
        if reachable.contains(&v) {
            continue;
        }

        match graph.get(&v) {
            Some(Value::Array(arr)) => {
                for neighbor in arr.iter() {
                    worklist.push(neighbor.clone());
                    // Guard worklist growth when enqueuing array neighbors.
                    enforce_limit()?;
                }
            }
            Some(Value::Set(set)) => {
                for neighbor in set.iter() {
                    worklist.push(neighbor.clone());
                    // Guard worklist growth when enqueuing set neighbors.
                    enforce_limit()?;
                }
            }
            Some(_) => (),
            _ => continue,
        }

        reachable.insert(v);
        // Guard reachable set size as discovered vertices accumulate.
        enforce_limit()?;
    }

    Ok(Value::from_set(reachable))
}

enum ReachablePathsFrame {
    Enter(Value),
    Exit(Value),
}

fn record_path(path: &[Value], paths: &mut BTreeSet<Value>) -> Result<()> {
    if !path.is_empty() {
        paths.insert(Value::from_array(path.to_vec()));
        enforce_limit()?;
    }
    Ok(())
}

fn reachable_paths(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "graph.reachable_paths";
    ensure_args_count(span, name, params, args, 2)?;

    let graph = ensure_object(name, &params[0], args[0].clone())?;
    let mut visited = BTreeSet::new();
    let mut current_path = vec![];
    let mut paths = BTreeSet::new();
    let mut stack = vec![];

    match &args[1] {
        Value::Array(arr) => {
            for node in arr.iter().rev() {
                stack.push(ReachablePathsFrame::Enter(node.clone()));
                enforce_limit()?;
            }
        }
        Value::Set(set) => {
            for node in set.iter().rev() {
                stack.push(ReachablePathsFrame::Enter(node.clone()));
                enforce_limit()?;
            }
        }
        _ if strict => bail!(params[1].span().error("initial vertices must be array/set")),
        _ => return Ok(Value::Undefined),
    }

    while let Some(frame) = stack.pop() {
        match frame {
            ReachablePathsFrame::Enter(node) => {
                if matches!(&node, Value::String(s) if s.as_ref().is_empty()) {
                    record_path(&current_path, &mut paths)?;
                    continue;
                }

                let Some(neighbors) = graph.get(&node) else {
                    record_path(&current_path, &mut paths)?;
                    continue;
                };

                if visited.contains(&node) {
                    record_path(&current_path, &mut paths)?;
                    continue;
                }

                current_path.push(node.clone());
                enforce_limit()?;
                visited.insert(node.clone());
                enforce_limit()?;
                stack.push(ReachablePathsFrame::Exit(node));
                enforce_limit()?;

                match neighbors {
                    Value::Array(arr) if arr.is_empty() => record_path(&current_path, &mut paths)?,
                    Value::Array(arr) => {
                        for neighbor in arr.iter().rev() {
                            stack.push(ReachablePathsFrame::Enter(neighbor.clone()));
                            enforce_limit()?;
                        }
                    }
                    Value::Set(set) if set.is_empty() => record_path(&current_path, &mut paths)?,
                    Value::Set(set) => {
                        for neighbor in set.iter().rev() {
                            stack.push(ReachablePathsFrame::Enter(neighbor.clone()));
                            enforce_limit()?;
                        }
                    }
                    Value::Null => record_path(&current_path, &mut paths)?,
                    _ => bail!(format!(
                        "neighbors for node `{}` must be array/set.",
                        current_path.last().unwrap_or(&Value::Undefined)
                    )),
                }
            }
            ReachablePathsFrame::Exit(node) => {
                visited.remove(&node);
                current_path.pop();
            }
        }
    }

    Ok(Value::from_set(paths))
}

enum WalkFrame {
    Visit(Value),
    Push(Value),
    Pop,
}

fn walk(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "walk";
    ensure_args_count(span, name, params, args, 1)?;
    let mut outputs = vec![];
    let mut path = vec![];
    let mut stack = vec![WalkFrame::Visit(args[0].clone())];

    while let Some(frame) = stack.pop() {
        match frame {
            WalkFrame::Visit(value) => {
                let current_path = Value::from_array(path.clone());
                outputs.push(Value::from_array([current_path, value.clone()].into()));
                enforce_limit()?;

                match value {
                    Value::Array(arr) => {
                        for (idx, elem) in arr.iter().enumerate().rev() {
                            stack.push(WalkFrame::Pop);
                            stack.push(WalkFrame::Visit(elem.clone()));
                            stack.push(WalkFrame::Push(Value::from(idx)));
                            enforce_limit()?;
                        }
                    }
                    Value::Set(set) => {
                        for elem in set.iter().rev() {
                            stack.push(WalkFrame::Pop);
                            stack.push(WalkFrame::Visit(elem.clone()));
                            stack.push(WalkFrame::Push(elem.clone()));
                            enforce_limit()?;
                        }
                    }
                    Value::Object(obj) => {
                        let entries: Vec<(Value, Value)> = obj
                            .iter_sorted()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect();
                        for (key, value) in entries.into_iter().rev() {
                            stack.push(WalkFrame::Pop);
                            stack.push(WalkFrame::Visit(value));
                            stack.push(WalkFrame::Push(key));
                            enforce_limit()?;
                        }
                    }
                    _ => {}
                }
            }
            WalkFrame::Push(segment) => {
                path.push(segment);
                enforce_limit()?;
            }
            WalkFrame::Pop => {
                path.pop();
            }
        }
    }
    Ok(Value::from_array(outputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_span() -> Span {
        Span {
            source: crate::lexer::Source::from_contents("test.rego".into(), "x".into())
                .expect("source"),
            line: 1,
            col: 1,
            start: 0,
            end: 1,
        }
    }

    fn param() -> Ref<Expr> {
        Ref::new(Expr::Null {
            span: test_span(),
            value: Value::Null,
            eidx: 0,
        })
    }

    fn deep_chain(depth: usize) -> Value {
        let mut graph = crate::value::Object::new();
        for idx in 0..depth {
            graph.insert(
                Value::from(idx),
                Value::from_array(alloc::vec![Value::from(idx + 1)]),
            );
        }
        graph.insert(Value::from(depth), Value::Null);
        Value::Object(crate::Rc::new(graph))
    }

    fn deep_nested_value(depth: usize) -> Value {
        let mut value = Value::from(0_usize);
        for _ in 0..depth {
            value = Value::from_array(alloc::vec![value]);
        }
        value
    }

    #[test]
    fn reachable_paths_handles_deep_graph_without_recursion() {
        let paths = reachable_paths(
            &test_span(),
            &[param(), param()],
            &[
                deep_chain(4096),
                Value::from_array(alloc::vec![Value::from(0_usize)]),
            ],
            true,
        )
        .expect("reachable_paths must succeed");
        assert!(matches!(paths, Value::Set(_)));
    }

    #[test]
    fn walk_handles_deep_values_without_recursion() {
        let walked =
            walk(&test_span(), &[], &[deep_nested_value(4096)], true).expect("walk must succeed");
        assert!(matches!(walked, Value::Array(_)));
    }
}
