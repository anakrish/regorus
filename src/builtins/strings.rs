// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(
    clippy::unseparated_literal_suffix,
    clippy::as_conversions,
    clippy::pattern_type_mismatch
)]

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::builtins::utils::{
    enforce_limit, ensure_args_count, ensure_array, ensure_numeric, ensure_object, ensure_string,
    ensure_string_collection,
};
use crate::lexer::Span;
use crate::number::Number;
use crate::value::Value;
use crate::*;

use anyhow::{bail, Result};

pub fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("concat", (concat, 2));
    m.insert("contains", (contains, 2));
    m.insert("endswith", (endswith, 2));
    m.insert("format_int", (format_int, 2));
    m.insert("indexof", (indexof, 2));
    m.insert("indexof_n", (indexof_n, 2));
    m.insert("lower", (lower, 1));
    m.insert("replace", (replace, 3));
    m.insert("split", (split, 2));
    m.insert("sprintf", (sprintf, 2));
    m.insert("startswith", (startswith, 2));
    m.insert("strings.any_prefix_match", (any_prefix_match, 2));
    m.insert("strings.any_suffix_match", (any_suffix_match, 2));
    m.insert("strings.count", (strings_count, 2));
    m.insert("strings.replace_n", (replace_n, 2));
    m.insert("strings.reverse", (reverse, 1));
    m.insert("substring", (substring, 3));
    m.insert("trim", (trim, 2));
    m.insert("trim_left", (trim_left, 2));
    m.insert("trim_prefix", (trim_prefix, 2));
    m.insert("trim_right", (trim_right, 2));
    m.insert("trim_space", (trim_space, 1));
    m.insert("trim_suffix", (trim_suffix, 2));
    m.insert("upper", (upper, 1));
}

fn concat(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "concat";
    ensure_args_count(span, name, params, args, 2)?;
    let delimiter = ensure_string(name, &params[0], &args[0])?;
    let collection = ensure_string_collection(name, &params[1], &args[1])?;
    Ok(Value::String(collection.join(&delimiter).into()))
}

fn contains(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "contains";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::Bool(s1.contains(s2.as_ref())))
}

fn endswith(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "endswith";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::Bool(s1.ends_with(s2.as_ref())))
}

fn format_int(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "format_int";
    ensure_args_count(span, name, params, args, 2)?;
    let mut n = ensure_numeric(name, &params[0], &args[0])?;
    let mut sign = "";
    if n < Number::from(0u64) {
        n = n.abs();
        sign = "-";
    }
    let n = n.floor();

    let base = ensure_numeric(name, &params[1], &args[1])?;

    let num = match base.as_u64() {
        Some(2) => n.format_bin(),
        Some(8) => n.format_octal(),
        Some(10) => n.format_decimal(),
        Some(16) => n.format_hex(),
        _ => {
            if strict {
                let span = params[1].span();
                bail!(span.error(&format!("`{name}` expects base to be one of 2, 8, 10, 16")));
            }

            return Ok(Value::Undefined);
        }
    };

    Ok(Value::String((sign.to_owned() + &num).into()))
}

fn indexof(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "indexof";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    for (pos, (idx, _)) in s1.char_indices().enumerate() {
        if s1[idx..].starts_with(s2.as_ref()) {
            return Ok(Value::from(Number::from(pos)));
        }
    }
    Ok(Value::from(Number::from(-1i64)))
}

fn indexof_n(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "indexof_n";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;

    let mut positions = vec![];
    for (pos, (idx, _)) in s1.char_indices().enumerate() {
        if s1[idx..].starts_with(s2.as_ref()) {
            positions.push(Value::from(Number::from(pos)));
            // Guard position vector growth while tracking matches.
            enforce_limit()?;
        }
    }
    Ok(Value::from_array(positions))
}

fn lower(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "lower";
    ensure_args_count(span, name, params, args, 1)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    Ok(Value::String(s.to_lowercase().into()))
}

fn replace(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "replace";
    ensure_args_count(span, name, params, args, 3)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    let old = ensure_string(name, &params[1], &args[1])?;
    let new = ensure_string(name, &params[2], &args[2])?;
    let replaced = s.replace(old.as_ref(), new.as_ref());
    enforce_limit()?;
    Ok(Value::String(replaced.into()))
}

fn split(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "replace";
    ensure_args_count(span, name, params, args, 2)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    let delimiter = ensure_string(name, &params[1], &args[1])?;

    // Handle https://github.com/microsoft/regorus/issues/291
    let parts: Vec<Value> = if delimiter.as_ref() == "" {
        // If delimiter is "", str::split returns a leading and trailing "" whereas Golang's split doesn't.
        // Therefore avoid str::split and instead return each char as a Value::String.
        s.chars()
            .map(|c| {
                let value = Value::from(c.to_string());
                // Guard part accumulation when splitting into characters.
                enforce_limit()?;
                Ok(value)
            })
            .collect::<Result<Vec<Value>>>()?
    } else {
        s.split(delimiter.as_ref())
            .map(|s| {
                let value = Value::String(s.into());
                // Guard part accumulation when splitting by delimiter.
                enforce_limit()?;
                Ok(value)
            })
            .collect::<Result<Vec<Value>>>()?
    };

    Ok(Value::from(parts))
}

fn to_string(v: &Value, unescape: bool) -> String {
    match v {
        Value::Null => "null".to_owned(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) if unescape => {
            serde_json::to_string(s.as_ref()).unwrap_or(s.as_ref().to_string())
        }
        Value::String(s) => s.as_ref().to_string(),
        Value::Number(n) => n.format_decimal(),
        Value::Array(a) => {
            "[".to_owned()
                + &a.iter()
                    .map(|e| to_string(e, true))
                    .collect::<Vec<String>>()
                    .join(", ")
                + "]"
        }
        Value::Set(s) => {
            "{".to_owned()
                + &s.iter()
                    .map(|e| to_string(e, true))
                    .collect::<Vec<String>>()
                    .join(", ")
                + "}"
        }
        Value::Object(o) => {
            "{".to_owned()
                + &o.iter_sorted()
                    .map(|(k, v)| to_string(k, true) + ": " + &to_string(v, true))
                    .collect::<Vec<String>>()
                    .join(", ")
                + "}"
        }
        Value::Undefined => "#undefined".to_string(),
    }
}

const MAX_SPRINTF_WIDTH: usize = 262_144;

enum Width {
    None,
    LeadingZeros(usize),
    Cell(usize),
    Decimals(usize),
}

fn apply_width(w: Width, s: String) -> String {
    match w {
        Width::LeadingZeros(n) if n > s.len() => "0".repeat(n - s.len()) + &s,
        Width::Cell(n) if n > s.len() => " ".repeat(n - s.len()) + &s,
        _ => s,
    }
}

fn parse_width(width: u32, first_char: char, param: &Ref<Expr>) -> Result<Width> {
    let width =
        usize::try_from(width).map_err(|_| param.span().error("format width is too large"))?;
    if width > MAX_SPRINTF_WIDTH {
        bail!(param
            .span()
            .error("format width exceeds the maximum supported size"));
    }
    Ok(match first_char {
        '0' => Width::LeadingZeros(width),
        '.' => Width::Decimals(width),
        _ => Width::Cell(width),
    })
}

fn sprintf(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "sprintf";
    ensure_args_count(span, name, params, args, 2)?;
    let fmt = ensure_string(name, &params[0], &args[0])?;
    let args = ensure_array(name, &params[1], args[1].clone())?;

    let mut s = String::default();
    let mut args_idx = 0usize;
    let mut chars = fmt.chars().peekable();
    let args_span = params[1].span();
    loop {
        let (verb, width) = match chars.next() {
            Some('%') => match chars.next() {
                Some('%') => {
                    s.push('%');
                    continue;
                }
                Some(c) if c == '.' || c.is_numeric() => {
                    let first_char = c;
                    let mut w = 0u32;
                    if c != '.' {
                        let digit = c
                            .to_digit(10)
                            .ok_or_else(|| params[0].span().error("invalid width digit"))?;
                        w = digit;
                    }

                    while chars.peek().map(|c| c.is_numeric()) == Some(true) {
                        let digit = chars
                            .next()
                            .and_then(|ch| ch.to_digit(10))
                            .ok_or_else(|| params[0].span().error("invalid width digit"))?;
                        w = w
                            .checked_mul(10)
                            .and_then(|value| value.checked_add(digit))
                            .ok_or_else(|| params[0].span().error("format width overflow"))?;
                    }
                    let width = parse_width(w, first_char, &params[0])?;
                    match chars.next() {
                        Some(c) => (c, width),
                        _ => {
                            let span = params[0].span();
                            bail!(span.error(
                                "missing format verb after `%width` at end of format string"
                            ));
                        }
                    }
                }
                Some(c) => (c, Width::None),
                None => {
                    let span = params[0].span();
                    bail!(span.error("missing format verb after `%` at end of format string"));
                }
            },
            Some(c) => {
                s.push(c);
                continue;
            }
            None => break,
        };

        if args_idx >= args.len() {
            bail!(args_span
                .error(format!("no argument specified for format verb {args_idx}").as_str()));
        }
        let arg = &args[args_idx];
        args_idx += 1;

        // Handle Golang flags.
        let emit_sign = false;
        let leave_space_for_elided_sign = false;
        // Note: Golang flags come BEFORE the format verb, not after.
        // This code was incorrectly consuming characters after the verb.
        // Removing the incorrect flag handling to fix sprintf spacing.

        let get_sign_value = |f: &Number| match (emit_sign, f) {
            (_, v) if v < &Number::from(0.0) => ("-", v.clone()),
            (true, v) => ("+", v.clone()),
            (false, v) if leave_space_for_elided_sign => (" ", v.clone()),
            (false, v) => ("", v.clone()),
        };

        // Handle Golang printing verbs.
        // https://pkg.go.dev/fmt
        match (verb, arg) {
            ('s', Value::String(sv)) => s += sv.as_ref(),
            ('s', v) => s += &to_string(v, false),

            ('v', _) => s += &to_string(arg, false),
            ('b', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += v.format_bin().as_str()
            }
            ('c', Value::Number(f)) if f.is_integer() => {
                // TODO: range error
                let ch_opt = f.as_u64().map(|ival| char::from_u32(ival as u32));
                match ch_opt {
                    Some(Some(c)) => s.push(c),
                    _ => {
                        bail!(args_span.error(
                            format!("invalid value {} for format verb c.", f.format_decimal())
                                .as_str()
                        ))
                    }
                }
            }
            ('d', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += apply_width(width, v.format_decimal()).as_str()
            }
            ('o', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += apply_width(width, "0O".to_owned() + &v.format_octal()).as_str()
            }
            ('O', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += apply_width(width, "0o".to_owned() + &v.format_octal()).as_str()
            }
            ('x', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += apply_width(width, v.format_hex()).as_str()
            }
            ('X', Value::Number(f)) if f.is_integer() => {
                let (sign, v) = get_sign_value(f);
                s += sign;
                s += apply_width(width, v.format_big_hex()).as_str()
            }
            ('e', Value::Number(f)) => s += &f.format_scientific(),
            ('E', Value::Number(f)) => s += &f.format_scientific().replace('e', "E"),
            ('f' | 'F', Value::Number(f)) => {
                s += &match width {
                    Width::Decimals(d) => f.format_decimal_with_width(d as u32),
                    _ => apply_width(width, f.format_decimal()),
                }
            }
            ('g', Value::Number(f)) => {
                let (sign, v) = get_sign_value(f);
                let v = match v.as_f64() {
                    Some(v) => v,
                    _ => bail!(span.error("cannot print large float using g format specified")),
                };
                s += sign;
                let bits = v.to_bits();
                let exponent = (bits >> 52) & 0x7ff;
                // TODO: what is large exponent?
                if exponent > 32 {
                    s += format!("{v:e}").as_str()
                } else {
                    s += format!("{v}").as_str()
                }
            }
            ('G', Value::Number(f)) => {
                let (sign, v) = get_sign_value(f);
                let v = match v.as_f64() {
                    Some(v) => v,
                    _ => bail!("cannot print large float using g format specified"),
                };
                s += sign;
                let bits = v.to_bits();
                let exponent = (bits >> 52) & 0x7ff;
                // TODO: what is large exponent?
                if exponent > 32 {
                    s += format!("{v:E}").as_str()
                } else {
                    s += format!("{v}").as_str()
                }
            }
            (_, Value::Number(_)) => {
                bail!(args_span.error(&format!("number specified for format verb {verb}.")));
            }

            ('+', _) if chars.next() == Some('v') => {
                bail!(args_span.error("Go-syntax fields names format verm %#v is not supported."));
            }
            ('T', _) | ('#', _) | ('q', _) | ('p', _) => {
                bail!(
                    args_span.error("Go-syntax format verbs %#v. %q, %p and %T are not supported.")
                );
            }
            _ => {}
        }
        enforce_limit()?;
    }

    if args_idx < args.len() {
        bail!(args_span.error(
            format!(
                "extra arguments ({}) specified for {args_idx} format verbs.",
                args.len()
            )
            .as_str()
        ));
    }

    enforce_limit()?;
    Ok(Value::String(s.into()))
}

fn any_prefix_match(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "strings.any_prefix_match";
    ensure_args_count(span, name, params, args, 2)?;

    let search = match &args[0] {
        Value::String(s) => vec![s.as_ref()],
        Value::Array(_) | Value::Set(_) => {
            match ensure_string_collection(name, &params[0], &args[0]) {
                Ok(c) => c,
                Err(e) if strict => return Err(e),
                _ => return Ok(Value::Undefined),
            }
        }
        _ if strict => {
            let span = params[0].span();
            bail!(span.error(
                format!("`{name}` expects string/array[string]/set[string] argument.").as_str()
            ));
        }
        _ => return Ok(Value::Undefined),
    };

    let base = match &args[1] {
        Value::String(s) => vec![s.as_ref()],
        Value::Array(_) | Value::Set(_) => {
            match ensure_string_collection(name, &params[1], &args[1]) {
                Ok(c) => c,
                Err(e) if strict => return Err(e),
                _ => return Ok(Value::Undefined),
            }
        }
        _ if strict => {
            let span = params[0].span();
            bail!(span.error(
                format!("`{name}` expects string/array[string]/set[string] argument.").as_str()
            ));
        }
        _ => return Ok(Value::Undefined),
    };

    Ok(Value::Bool(
        search.iter().any(|s| base.iter().any(|b| s.starts_with(b))),
    ))
}

fn any_suffix_match(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    strict: bool,
) -> Result<Value> {
    let name = "strings.any_suffix_match";
    ensure_args_count(span, name, params, args, 2)?;

    let search = match &args[0] {
        Value::String(s) => vec![s.as_ref()],
        Value::Array(_) | Value::Set(_) => {
            match ensure_string_collection(name, &params[0], &args[0]) {
                Ok(c) => c,
                Err(e) if strict => return Err(e),
                _ => return Ok(Value::Undefined),
            }
        }
        _ if strict => {
            let span = params[0].span();
            bail!(span.error(
                format!("`{name}` expects string/array[string]/set[string] argument.").as_str()
            ));
        }
        _ => return Ok(Value::Undefined),
    };

    let base = match &args[1] {
        Value::String(s) => vec![s.as_ref()],
        Value::Array(_) | Value::Set(_) => {
            match ensure_string_collection(name, &params[1], &args[1]) {
                Ok(c) => c,
                Err(e) if strict => return Err(e),
                _ => return Ok(Value::Undefined),
            }
        }
        _ if strict => {
            let span = params[0].span();
            bail!(span.error(
                format!("`{name}` expects string/array[string]/set[string] argument.").as_str()
            ));
        }
        _ => return Ok(Value::Undefined),
    };

    Ok(Value::Bool(
        search.iter().any(|s| base.iter().any(|b| s.ends_with(b))),
    ))
}

fn strings_count(
    span: &Span,
    params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let name = "strings.count";
    ensure_args_count(span, name, params, args, 2)?;

    let search = ensure_string(name, &params[0], &args[0])?;
    let substring = ensure_string(name, &params[0], &args[1])?;

    if substring.is_empty() {
        return Ok(Value::from(search.chars().count() + 1));
    }

    Ok(Value::from(
        search
            .as_bytes()
            .windows(substring.len())
            .filter(|&w| w == substring.as_bytes())
            .count(),
    ))
}

fn startswith(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "startswith";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::Bool(s1.starts_with(s2.as_ref())))
}

fn replace_n(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim";
    ensure_args_count(span, name, params, args, 2)?;
    let obj = ensure_object(name, &params[0], args[0].clone())?;
    let mut s = ensure_string(name, &params[1], &args[1])?;

    let span = params[0].span();
    for item in obj.as_ref().iter_sorted() {
        match item {
            (Value::String(k), Value::String(v)) => {
                s = s.replace(k.as_ref(), v.as_ref()).into();
                enforce_limit()?;
            }
            _ => {
                bail!(span.error(
                    format!("`{name}` expects string keys and values in pattern object.").as_str()
                ))
            }
        }
    }

    Ok(Value::String(s.clone()))
}

fn reverse(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "reverse";
    ensure_args_count(span, name, params, args, 1)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    Ok(Value::String(s.chars().rev().collect::<String>().into()))
}

fn substring(span: &Span, params: &[Ref<Expr>], args: &[Value], strict: bool) -> Result<Value> {
    let name = "substring";
    ensure_args_count(span, name, params, args, 3)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    let offset = ensure_numeric(name, &params[1], &args[1])?;
    let length = ensure_numeric(name, &params[2], &args[2])?;

    match (offset.as_i64(), length.as_i64()) {
        (Some(offset), _) if offset < 0 && strict => {
            bail!(params[1].span().error("negative offset"))
        }
        (Some(offset), _) if offset < 0 => Ok(Value::Undefined),
        (Some(offset), Some(length)) => {
            let start = s.chars().skip(offset as usize);
            let length = if length < 0 { s.len() } else { length as usize };
            Ok(Value::String(start.take(length).collect::<String>().into()))
        }
        _ => Ok(Value::String("".into())),
    }
}

fn trim(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::String(s1.trim_matches(|c| s2.contains(c)).into()))
}

fn trim_left(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim_left";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::String(
        s1.trim_start_matches(|c| s2.contains(c)).into(),
    ))
}

fn trim_prefix(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim_prefix";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::String(match s1.strip_prefix(s2.as_ref()) {
        Some(s) => s.into(),
        _ => s1,
    }))
}

fn trim_right(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim_right";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::String(
        s1.trim_end_matches(|c| s2.contains(c)).into(),
    ))
}

fn trim_space(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim_space";
    ensure_args_count(span, name, params, args, 1)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    Ok(Value::String(s.trim().into()))
}

fn trim_suffix(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "trim_suffix";
    ensure_args_count(span, name, params, args, 2)?;
    let s1 = ensure_string(name, &params[0], &args[0])?;
    let s2 = ensure_string(name, &params[1], &args[1])?;
    Ok(Value::String(match s1.strip_suffix(s2.as_ref()) {
        Some(s) => s.into(),
        _ => s1,
    }))
}

fn upper(span: &Span, params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let name = "upper";
    ensure_args_count(span, name, params, args, 1)?;
    let s = ensure_string(name, &params[0], &args[0])?;
    Ok(Value::String(s.to_uppercase().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Engine;
    use alloc::format;
    use alloc::string::ToString as _;

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
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

    fn eval(query: &str) -> Value {
        Engine::new()
            .eval_query(query.to_string(), false)
            .expect("query must succeed")
            .result[0]
            .expressions[0]
            .value
            .clone()
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    struct LimitGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    impl LimitGuard {
        fn set_below_current_usage() -> Self {
            use crate::set_global_memory_limit;
            use std::sync::{Mutex, OnceLock};

            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let guard = LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            set_global_memory_limit(None);
            set_global_memory_limit(Some(1));
            Self { _guard: guard }
        }
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    impl Drop for LimitGuard {
        fn drop(&mut self) {
            crate::set_global_memory_limit(None);
        }
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    fn param() -> crate::ast::Ref<crate::ast::Expr> {
        crate::ast::Ref::new(crate::ast::Expr::Null {
            span: test_span(),
            value: Value::Null,
            eidx: 0,
        })
    }

    #[test]
    fn strings_count_empty_substring_matches_opa_semantics() {
        assert_eq!(eval(r#"strings.count("abc", "")"#), Value::from(4usize));
    }

    #[test]
    fn sprintf_rejects_excessive_widths() {
        let err = Engine::new()
            .eval_query(
                format!(r#"sprintf("%{}d", [1])"#, MAX_SPRINTF_WIDTH + 1),
                false,
            )
            .expect_err("excessive width must error");
        assert!(err
            .to_string()
            .contains("format width exceeds the maximum supported size"));
    }

    #[test]
    fn replace_n_applies_replacements() {
        assert_eq!(
            eval(r#"strings.replace_n({"f": "x", "foo": "xxx"}, "foo")"#),
            Value::from("xoo")
        );
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    #[test]
    fn replace_n_checks_memory_limit_after_each_step() {
        use crate::LimitError;
        use std::collections::BTreeMap;

        let span = test_span();
        let params = [param(), param()];
        let mut patterns = BTreeMap::new();
        patterns.insert(Value::from("a"), Value::from("a".repeat(40_000)));
        patterns.insert(Value::from("aa"), Value::from("bbbbbbbb"));
        let args = [Value::from_map(patterns), Value::from("a")];
        let _guard = LimitGuard::set_below_current_usage();
        let err = replace_n(&span, &params, &args, true).expect_err("memory limit must propagate");
        assert!(matches!(
            err.downcast_ref::<LimitError>(),
            Some(LimitError::MemoryLimitExceeded { .. })
        ));
    }

    #[cfg(all(
        feature = "allocator-memory-limits",
        not(miri),
        feature = "mimalloc",
        feature = "std"
    ))]
    #[test]
    fn replace_checks_memory_limit_after_growth() {
        use crate::LimitError;

        let span = test_span();
        let params = [param(), param(), param()];
        let args = [
            Value::from("a"),
            Value::from("a"),
            Value::from("a".repeat(40_000)),
        ];
        let _guard = LimitGuard::set_below_current_usage();
        let err = replace(&span, &params, &args, true).expect_err("memory limit must propagate");
        assert!(matches!(
            err.downcast_ref::<LimitError>(),
            Some(LimitError::MemoryLimitExceeded { .. })
        ));
    }
}
