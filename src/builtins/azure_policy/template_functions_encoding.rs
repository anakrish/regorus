// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template encoding builtins: base64, base64ToString, base64ToJson,
//! uri, uriComponent, uriComponentToString, dataUri, dataUriToString.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;

use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Result;

use super::helpers::as_string;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.base64", (fn_base64, 1));
    m.insert("azure.policy.fn.base64_to_string", (fn_base64_to_string, 1));
    m.insert("azure.policy.fn.base64_to_json", (fn_base64_to_json, 1));
    m.insert("azure.policy.fn.uri", (fn_uri, 2));
    m.insert("azure.policy.fn.uri_component", (fn_uri_component, 1));
    m.insert(
        "azure.policy.fn.uri_component_to_string",
        (fn_uri_component_to_string, 1),
    );
    m.insert("azure.policy.fn.data_uri", (fn_data_uri, 1));
    m.insert(
        "azure.policy.fn.data_uri_to_string",
        (fn_data_uri_to_string, 1),
    );
}

// ── Base64 helpers (pure implementation, no external deps) ────────────

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut result = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(BASE64_CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode_byte(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    if input.is_empty() {
        return Some(Vec::new());
    }
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r')
        .collect();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut result = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = base64_decode_byte(chunk[0])?;
        let b = base64_decode_byte(chunk[1])?;
        let triple = (a as u32) << 18
            | (b as u32) << 12
            | if chunk[2] != b'=' {
                (base64_decode_byte(chunk[2])? as u32) << 6
            } else {
                0
            }
            | if chunk[3] != b'=' {
                base64_decode_byte(chunk[3])? as u32
            } else {
                0
            };
        result.push(((triple >> 16) & 0xFF) as u8);
        if chunk[2] != b'=' {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if chunk[3] != b'=' {
            result.push((triple & 0xFF) as u8);
        }
    }
    Some(result)
}

/// `base64(inputString)` → base64-encoded string.
fn fn_base64(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    Ok(Value::from(base64_encode(s.as_bytes())))
}

/// `base64ToString(base64Value)` → decoded UTF-8 string.
fn fn_base64_to_string(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let Some(decoded) = base64_decode(&s) else {
        return Ok(Value::Undefined);
    };
    match String::from_utf8(decoded) {
        Ok(text) => Ok(Value::from(text)),
        Err(_) => Ok(Value::Undefined),
    }
}

/// `base64ToJson(base64Value)` → parsed JSON value from base64-encoded string.
fn fn_base64_to_json(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let Some(decoded) = base64_decode(&s) else {
        return Ok(Value::Undefined);
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return Ok(Value::Undefined);
    };
    match Value::from_json_str(&text) {
        Ok(v) => Ok(v),
        Err(_) => Ok(Value::Undefined),
    }
}

// ── URI helpers (pure implementation) ─────────────────────────────────

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~'
}

fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b) {
            result.push(b as char);
        } else {
            result.push('%');
            result.push(core::char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            result.push(core::char::from_digit((b & 0x0F) as u32, 16).unwrap_or('0'));
        }
    }
    // ARM template uses uppercase hex
    result.to_ascii_uppercase()
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            result.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).ok()
}

/// `uri(baseUri, relativeUri)` → combined URI.
fn fn_uri(_span: &Span, _params: &[Ref<Expr>], args: &[Value], _strict: bool) -> Result<Value> {
    if args.len() != 2 {
        return Ok(Value::Undefined);
    }
    let (Some(base), Some(relative)) = (as_string(&args[0]), as_string(&args[1])) else {
        return Ok(Value::Undefined);
    };

    // Simple URI combination: if base ends with '/', just append; otherwise
    // strip last path component and append.
    let combined = if relative.starts_with("http://") || relative.starts_with("https://") {
        relative
    } else if base.ends_with('/') {
        alloc::format!("{}{}", base, relative.trim_start_matches('/'))
    } else {
        // Find last '/' in base and replace everything after it.
        if let Some(pos) = base.rfind('/') {
            alloc::format!("{}/{}", &base[..pos], relative.trim_start_matches('/'))
        } else {
            alloc::format!("{}/{}", base, relative)
        }
    };

    Ok(Value::from(combined))
}

/// `uriComponent(stringToEncode)` → percent-encoded string.
fn fn_uri_component(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    Ok(Value::from(percent_encode(&s)))
}

/// `uriComponentToString(uriEncodedString)` → decoded string.
fn fn_uri_component_to_string(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    match percent_decode(&s) {
        Some(decoded) => Ok(Value::from(decoded)),
        None => Ok(Value::Undefined),
    }
}

/// `dataUri(stringToConvert)` → data URI (text/plain;charset=utf8).
fn fn_data_uri(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let encoded = base64_encode(s.as_bytes());
    Ok(Value::from(alloc::format!(
        "data:text/plain;charset=utf8;base64,{}",
        encoded
    )))
}

/// `dataUriToString(dataUriToConvert)` → decoded string from data URI.
fn fn_data_uri_to_string(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };

    // Expected format: data:<mediatype>;base64,<data>
    let Some(rest) = s.strip_prefix("data:") else {
        return Ok(Value::Undefined);
    };

    // Find the base64 data after the last comma.
    let Some(comma_pos) = rest.rfind(',') else {
        return Ok(Value::Undefined);
    };
    let b64_data = &rest[comma_pos + 1..];

    let Some(decoded) = base64_decode(b64_data) else {
        return Ok(Value::Undefined);
    };
    match String::from_utf8(decoded) {
        Ok(text) => Ok(Value::from(text)),
        Err(_) => Ok(Value::Undefined),
    }
}
