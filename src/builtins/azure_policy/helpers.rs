// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers: type coercion, comparison, pattern matching, and path resolution.

#![deny(
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
)]

use crate::languages::azure_policy::strings;
use crate::value::Value;

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

// ── Type helpers ──────────────────────────────────────────────────────

pub const fn is_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

pub const fn is_undefined(value: &Value) -> bool {
    matches!(value, Value::Undefined)
}

pub fn as_string(value: &Value) -> Option<String> {
    match *value {
        Value::String(ref s) => Some(s.to_string()),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn as_string_ci(value: &Value) -> Option<String> {
    as_string(value).map(|s| strings::case_fold::fold(&s).into_owned())
}

/// Coerce a value to its string representation for policy comparison operators.
///
/// Azure Policy coerces numbers and booleans to strings when used with string
/// operators (`like`, `match`, `contains`, `matchInsensitively`).  This is
/// needed when, for example, a count result (always a number) is compared
/// using a string operator: `count(...) like 2`.
pub fn coerce_to_string(value: &Value) -> Option<String> {
    match *value {
        Value::String(ref s) => Some(s.to_string()),
        Value::Number(ref n) => Some(n.format_decimal()),
        Value::Bool(b) => Some(if b { "true" } else { "false" }.to_string()),
        _ => None,
    }
}

pub fn coerce_to_string_ci(value: &Value) -> Option<String> {
    coerce_to_string(value).map(|s| strings::case_fold::fold(&s).into_owned())
}

pub fn as_boolish(value: &Value) -> Option<bool> {
    match *value {
        Value::Bool(b) => Some(b),
        Value::String(ref s) => match s.to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

// ── Comparison and coercion ───────────────────────────────────────────

pub fn compare_values(args: &[Value]) -> Option<i8> {
    #[allow(clippy::pattern_type_mismatch)]
    let [left, right] = args
    else {
        return None;
    };
    if is_undefined(left) || is_undefined(right) {
        return None;
    }

    #[allow(clippy::pattern_type_mismatch)]
    match (left, right) {
        (Value::String(a), Value::String(b)) => Some(match strings::case_fold::cmp(a, b) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }),
        (Value::Number(a), Value::Number(b)) => Some(if a < b {
            -1
        } else if a > b {
            1
        } else {
            0
        }),
        (Value::Bool(a), Value::Bool(b)) => Some(if a == b {
            0
        } else if !a && *b {
            -1
        } else {
            1
        }),
        // String ↔ Number coercion
        (Value::String(s), Value::Number(n)) => try_coerce_to_number(s).map(|sn| {
            if &sn < n {
                -1
            } else if &sn > n {
                1
            } else {
                0
            }
        }),
        (Value::Number(n), Value::String(s)) => try_coerce_to_number(s).map(|sn| {
            if n < &sn {
                -1
            } else if n > &sn {
                1
            } else {
                0
            }
        }),
        _ => None,
    }
}

pub fn case_insensitive_equals(left: &Value, right: &Value) -> bool {
    if is_undefined(left) || is_undefined(right) {
        return false;
    }

    // Azure Policy treats an explicit null field value as "" (empty string)
    // for comparison purposes.  Missing fields are Undefined and caught above.
    let empty = Value::String("".into());
    let left = if matches!(left, Value::Null) {
        &empty
    } else {
        left
    };
    let right = if matches!(right, Value::Null) {
        &empty
    } else {
        right
    };

    #[allow(clippy::pattern_type_mismatch)]
    match (left, right) {
        (Value::String(a), Value::String(b)) => strings::case_fold::eq(a, b),
        // String ↔ Number coercion
        (Value::String(s), Value::Number(_)) | (Value::Number(_), Value::String(s)) => {
            try_coerce_to_number(s).is_some_and(|n| {
                let num_val = Value::Number(n);
                let other = if matches!(left, Value::String(_)) {
                    right
                } else {
                    left
                };
                &num_val == other
            })
        }
        // String ↔ Bool coercion ("true"/"false" ↔ true/false)
        (Value::String(_), Value::Bool(b)) | (Value::Bool(b), Value::String(_)) => {
            as_boolish(if matches!(left, Value::String(_)) {
                left
            } else {
                right
            }) == Some(*b)
        }
        _ => left == right,
    }
}

/// Try to parse a string as a number for Azure Policy type coercion.
pub fn try_coerce_to_number(s: &str) -> Option<crate::number::Number> {
    use core::str::FromStr as _;
    // Try integer first, then float.
    i64::from_str(s.trim())
        .map(crate::number::Number::from)
        .ok()
        .or_else(|| {
            f64::from_str(s.trim())
                .map(crate::number::Number::from)
                .ok()
        })
}

// ── Pattern matching ──────────────────────────────────────────────────

pub fn match_pattern(args: &[Value], insensitive: bool) -> bool {
    #[allow(clippy::pattern_type_mismatch)]
    let [input_val, pattern_val] = args
    else {
        return false;
    };

    let Some(mut input) = coerce_to_string(input_val) else {
        return false;
    };
    let Some(mut pattern) = coerce_to_string(pattern_val) else {
        return false;
    };

    if insensitive {
        input = strings::case_fold::fold(&input).into_owned();
        pattern = strings::case_fold::fold(&pattern).into_owned();
    }

    match_question_hash_pattern(&input, &pattern)
}

pub fn match_like_pattern_ci(input: &str, pattern: &str) -> bool {
    wildcard_match(input.as_bytes(), pattern.as_bytes())
}

fn wildcard_match(input: &[u8], pattern: &[u8]) -> bool {
    let (mut input_index, mut pattern_index) = (0_usize, 0_usize);
    let mut star_index: Option<usize> = None;
    let mut match_index = 0_usize;

    while input_index < input.len() {
        let pat_byte = pattern.get(pattern_index).copied();
        let inp_byte = input.get(input_index).copied();

        if matches!(pat_byte, Some(b'?')) || (pat_byte.is_some() && pat_byte == inp_byte) {
            input_index = input_index.saturating_add(1);
            pattern_index = pattern_index.saturating_add(1);
        } else if pat_byte == Some(b'*') {
            star_index = Some(pattern_index);
            match_index = input_index;
            pattern_index = pattern_index.saturating_add(1);
        } else if let Some(star) = star_index {
            pattern_index = star.saturating_add(1);
            match_index = match_index.saturating_add(1);
            input_index = match_index;
        } else {
            return false;
        }
    }

    while pattern.get(pattern_index).copied() == Some(b'*') {
        pattern_index = pattern_index.saturating_add(1);
    }

    pattern_index == pattern.len()
}

pub fn match_question_hash_pattern(input: &str, pattern: &str) -> bool {
    let input_chars = input.chars().collect::<Vec<_>>();
    let pattern_chars = pattern.chars().collect::<Vec<_>>();

    if input_chars.len() != pattern_chars.len() {
        return false;
    }

    for (input_char, pattern_char) in input_chars.iter().zip(pattern_chars.iter()) {
        if *pattern_char == '.' {
            // '.' matches any single character (letter, digit, or special).
        } else if *pattern_char == '#' {
            if !input_char.is_ascii_digit() {
                return false;
            }
        } else if *pattern_char == '?' {
            if !input_char.is_ascii_alphabetic() {
                return false;
            }
        } else if input_char != pattern_char {
            return false;
        }
    }

    true
}

// ── Path resolution ───────────────────────────────────────────────────

pub fn resolve_path(root: &Value, path: &str) -> Value {
    let segments = tokenize_path(path);
    let mut current = root.clone();

    for segment in segments {
        #[allow(clippy::pattern_type_mismatch)]
        match &current {
            Value::Object(map) => {
                let mut next = None;
                for (key, value) in map.iter() {
                    if let Value::String(ref key_str) = *key {
                        if strings::keys::eq(key_str, &segment) {
                            next = Some(value.clone());
                            break;
                        }
                    }
                }

                if let Some(value) = next {
                    current = value;
                } else {
                    return Value::Undefined;
                }
            }
            Value::Array(items) => {
                let Ok(index) = segment.parse::<usize>() else {
                    return Value::Undefined;
                };

                let Some(value) = items.get(index) else {
                    return Value::Undefined;
                };
                current = value.clone();
            }
            _ => return Value::Undefined,
        }
    }

    current
}

fn tokenize_path(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut token = String::new();
    let mut bracket = String::new();
    let mut in_bracket = false;

    for ch in path.chars() {
        match ch {
            '.' if !in_bracket => {
                if !token.is_empty() {
                    segments.push(token.clone());
                    token.clear();
                }
            }
            '[' => {
                in_bracket = true;
                if !token.is_empty() {
                    segments.push(token.clone());
                    token.clear();
                }
            }
            ']' => {
                in_bracket = false;
                let cleaned = bracket.trim_matches('"').trim_matches('\'').to_string();
                if !cleaned.is_empty() {
                    segments.push(cleaned);
                }
                bracket.clear();
            }
            _ => {
                if in_bracket {
                    bracket.push(ch);
                } else {
                    token.push(ch);
                }
            }
        }
    }

    if !token.is_empty() {
        segments.push(token);
    }

    segments
}
