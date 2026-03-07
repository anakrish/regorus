// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ARM template date/time builtins: dateTimeAdd, dateTimeFromEpoch,
//! dateTimeToEpoch, addDays.
//!
//! `utcNow()` is handled in the compiler (loaded from context), not here.

use crate::ast::{Expr, Ref};
use crate::builtins;
use crate::lexer::Span;
use crate::value::Value;

use alloc::string::String;
use anyhow::Result;

use chrono::{DateTime, Duration, FixedOffset, Utc};

use super::helpers::as_string;

pub(super) fn register(m: &mut builtins::BuiltinsMap<&'static str, builtins::BuiltinFcn>) {
    m.insert("azure.policy.fn.date_time_add", (fn_date_time_add, 0));
    m.insert(
        "azure.policy.fn.date_time_from_epoch",
        (fn_date_time_from_epoch, 1),
    );
    m.insert(
        "azure.policy.fn.date_time_to_epoch",
        (fn_date_time_to_epoch, 1),
    );
    m.insert("azure.policy.fn.add_days", (fn_add_days, 0));
}

// ── ISO 8601 datetime parsing ─────────────────────────────────────────

/// Parse an ISO 8601 / RFC 3339 datetime string.
/// Accepts formats like:
///   `2024-01-15T12:00:00Z`
///   `2024-01-15T12:00:00.000Z`
///   `2024-01-15T12:00:00+00:00`
///   `2024-01-15T12:00:00`  (assumes UTC)
fn parse_datetime(s: &str) -> Option<DateTime<FixedOffset>> {
    // Try RFC 3339 first (most common for ARM templates).
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt);
    }
    // Try without timezone (assume UTC).
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        return Some(utc.fixed_offset());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        let utc = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        return Some(utc.fixed_offset());
    }
    None
}

/// Format a datetime as ISO 8601 / RFC 3339 string.
fn format_datetime(dt: &DateTime<FixedOffset>) -> String {
    dt.to_rfc3339()
}

// ── ISO 8601 duration parsing ─────────────────────────────────────────

/// Parse an ISO 8601 duration string into a `chrono::Duration`.
///
/// Supports: `P[nY][nM][nD][T[nH][nM][nS]]`
/// Examples: `P1D`, `PT1H`, `P1Y2M3DT4H5M6S`, `PT30M`, `-P1D`
///
/// Note: months/years are approximated (1 month = 30 days, 1 year = 365 days)
/// since chrono::Duration is absolute. ARM template behavior matches this.
fn parse_iso8601_duration(s: &str) -> Option<Duration> {
    let (s, negative) = s.strip_prefix('-').map_or((s, false), |rest| (rest, true));

    let s = s.strip_prefix('P')?;
    let mut total_seconds: i64 = 0;
    let mut in_time = false;
    let mut num_buf = String::new();

    for ch in s.chars() {
        match ch {
            'T' => {
                in_time = true;
            }
            '0'..='9' | '.' => {
                num_buf.push(ch);
            }
            'Y' if !in_time => {
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 365.0 * 86400.0))?;
                num_buf.clear();
            }
            'M' if !in_time => {
                // Months in date part
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 30.0 * 86400.0))?;
                num_buf.clear();
            }
            'W' if !in_time => {
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 7.0 * 86400.0))?;
                num_buf.clear();
            }
            'D' if !in_time => {
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 86400.0))?;
                num_buf.clear();
            }
            'H' if in_time => {
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 3600.0))?;
                num_buf.clear();
            }
            'M' if in_time => {
                // Minutes in time part
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n * 60.0))?;
                num_buf.clear();
            }
            'S' if in_time => {
                let n: f64 = num_buf.parse().ok()?;
                total_seconds = total_seconds.checked_add(f64_as_i64(n))?;
                num_buf.clear();
            }
            _ => return None,
        }
    }

    let dur = Duration::seconds(if negative {
        total_seconds.checked_neg()?
    } else {
        total_seconds
    });
    Some(dur)
}

// ── Builtin functions ─────────────────────────────────────────────────

/// `dateTimeAdd(base, duration, format?)` → add ISO 8601 duration to datetime.
///
/// ARM template: `dateTimeAdd('2020-04-07 14:55:59', 'P3Y2M', 'yyyy-MM-dd')`
/// format parameter is ignored — we always return ISO 8601.
fn fn_date_time_add(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(base_str) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let Some(duration_str) = args.get(1).and_then(as_string) else {
        return Ok(Value::Undefined);
    };

    let Some(base_dt) = parse_datetime(&base_str) else {
        return Ok(Value::Undefined);
    };
    let Some(duration) = parse_iso8601_duration(&duration_str) else {
        return Ok(Value::Undefined);
    };

    let result = base_dt
        .checked_add_signed(duration)
        .ok_or_else(|| anyhow::anyhow!("dateTimeAdd: datetime overflow"))?;
    Ok(Value::from(format_datetime(&result)))
}

/// `dateTimeFromEpoch(epoch)` → ISO 8601 UTC datetime string from Unix epoch.
fn fn_date_time_from_epoch(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(epoch) = args.first().and_then(extract_i64) else {
        return Ok(Value::Undefined);
    };
    let Some(dt) = DateTime::from_timestamp(epoch, 0) else {
        return Ok(Value::Undefined);
    };
    Ok(Value::from(dt.fixed_offset().to_rfc3339()))
}

/// `dateTimeToEpoch(dateTime)` → Unix epoch seconds from ISO 8601 string.
fn fn_date_time_to_epoch(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(s) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let Some(dt) = parse_datetime(&s) else {
        return Ok(Value::Undefined);
    };
    Ok(Value::from(dt.timestamp()))
}

/// `addDays(dateTime, numberOfDays)` → ISO 8601 datetime with days added.
///
/// Very common in real Azure Policy definitions (e.g., key expiry checks).
fn fn_add_days(
    _span: &Span,
    _params: &[Ref<Expr>],
    args: &[Value],
    _strict: bool,
) -> Result<Value> {
    let Some(base_str) = args.first().and_then(as_string) else {
        return Ok(Value::Undefined);
    };
    let Some(days) = args.get(1).and_then(extract_i64) else {
        return Ok(Value::Undefined);
    };

    let Some(base_dt) = parse_datetime(&base_str) else {
        return Ok(Value::Undefined);
    };
    let duration = Duration::days(days);
    let result = base_dt
        .checked_add_signed(duration)
        .ok_or_else(|| anyhow::anyhow!("addDays: datetime overflow"))?;
    Ok(Value::from(format_datetime(&result)))
}

// ── Helpers ───────────────────────────────────────────────────────────

fn extract_i64(v: &Value) -> Option<i64> {
    match *v {
        Value::Number(ref n) => n.as_i64(),
        _ => None,
    }
}

/// Deliberate truncating conversion from `f64` → `i64`.
#[expect(clippy::as_conversions)]
const fn f64_as_i64(x: f64) -> i64 {
    x as i64
}
