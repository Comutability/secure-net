//! Canonical JSON (CVP-002, section 1).
//!
//! The same value always gives the same bytes on every platform: object members sorted by their
//! keys as UTF-16 code units, no whitespace, and only values that encode one way. A number must be
//! a whole number in the range every language handles exactly (|n| <= 2^53 - 1); anything else is
//! refused, not tidied.
use std::fmt::Write;

use serde_json::{Number, Value};

use crate::error::{Error, Result};

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn refuse(path: &str, why: &str) -> Error {
    Error::new("NOT_CANONICAL", format!("{path} {why}"))
}

fn number(n: &Number, path: &str) -> Result<i64> {
    if let Some(i) = n.as_i64() {
        if i.abs() <= MAX_SAFE_INTEGER {
            return Ok(i);
        }
    } else if let Some(u) = n.as_u64() {
        if u <= MAX_SAFE_INTEGER as u64 {
            return Ok(u as i64);
        }
    } else if let Some(f) = n.as_f64() {
        // A value the JavaScript would read as a whole number (1.0, 1e2, -0.0) is that number.
        if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64 {
            return Ok(f as i64);
        }
    }
    Err(refuse(path, "isn't a whole number in the safe range"))
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn utf16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn encode(value: &Value, path: &str, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let _ = write!(out, "{}", number(n, path)?);
        }
        Value::String(s) => string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                encode(v, &format!("{path}[{i}]"), out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_cached_key(|k| utf16_key(k));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                string(k, out);
                out.push(':');
                encode(&map[k.as_str()], &format!("{path}.{k}"), out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical text of a value.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut out = String::new();
    encode(value, "$", &mut out)?;
    Ok(out)
}

/// The canonical bytes of a value.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    canonical_json(value).map(String::into_bytes)
}

/// Parse JSON text and return its canonical text. Text with a lone surrogate is refused, as the
/// JavaScript refuses the string it would parse to.
pub fn canonicalize_text(text: &str) -> Result<String> {
    let value: Value = serde_json::from_str(text).map_err(|e| refuse("$", &format!("isn't JSON that encodes one way ({e})")))?;
    canonical_json(&value)
}
