//! JavaScript semantics the protocol's rules depend on, in one place: truthiness, string length
//! in UTF-16 code units, safe integers and `Date.parse` for ISO 8601 times.
use serde_json::Value;

use crate::canonical::MAX_SAFE_INTEGER;

/// JavaScript truthiness for a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// `typeof v === "object" && v !== null`: objects and arrays.
pub fn is_object_like(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

/// `Object.entries(v)`: an object's own properties, an array's items by index, a string's UTF-16
/// code units by index; nothing for other values.
pub fn entries(v: &Value) -> Vec<(String, Value)> {
    match v {
        Value::Object(o) => o.iter().map(|(k, x)| (k.clone(), x.clone())).collect(),
        Value::Array(a) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Value::String(s) => s.encode_utf16().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[u])))).collect(),
        _ => Vec::new(),
    }
}

/// `${v}` in a template: "undefined" for a missing field, otherwise JavaScript's `String(v)`.
pub fn show(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(x) => crate::cv::canonical::js_string(x),
    }
}

/// `s.trim()`, with JavaScript's idea of white space.
pub fn trim(s: &str) -> &str {
    s.trim_matches(crate::social::vocabulary::js_space_pub)
}

/// `s.length`: UTF-16 code units.
pub fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `Number.isSafeInteger(v)`.
pub fn safe_int(v: &Value) -> Option<i64> {
    let max = MAX_SAFE_INTEGER;
    if let Some(i) = v.as_i64() {
        return (i.unsigned_abs() <= max as u64).then_some(i);
    }
    v.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= max as f64).map(|f| f as i64)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// `Date.parse` as V8 (Node.js, Chrome) answers for the ISO 8601 forms: `YYYY`, `YYYY-MM`,
/// `YYYY-MM-DD` (UTC), optionally followed by `THH:MM`, `:SS`, `.fraction` and a zone (`Z`,
/// `±HH:MM` or `±HHMM`), with `±YYYYYY` years and `t`/`z` in either case. Like V8, a day from 1
/// to 31 is accepted in any month and rolls over (`2026-02-30` is 2 March), and `24:00` is the
/// end of the day.
///
/// A date and time with no zone is local time in JavaScript, so it depends on the machine's time
/// zone; that is refused here (None), as are the other, implementation-defined formats
/// `Date.parse` may accept. Protocol records should always carry `toISOString()` times.
pub fn date_parse(s: &str) -> Option<i64> {
    if let Some(t) = http_date(s) {
        return Some(t);
    }
    let b = s.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = s.get(from..from + n)?;
        part.bytes().all(|c| c.is_ascii_digit()).then(|| part.parse().ok())?
    };
    let (y, mut at) = match b.first() {
        Some(sign @ (b'+' | b'-')) => {
            let y = digits(1, 6)?;
            if *sign == b'-' && y == 0 {
                return None;
            }
            (if *sign == b'-' { -y } else { y }, 7)
        }
        _ => (digits(0, 4)?, 4),
    };
    let date_start = at;
    let (mut mo, mut d) = (1, 1);
    if b.get(at) == Some(&b'-') {
        mo = digits(at + 1, 2)?;
        at += 3;
        if b.get(at) == Some(&b'-') {
            d = digits(at + 1, 2)?;
            at += 3;
        }
    }
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut ms = days_from_civil(y, mo, d) * 86_400_000;
    if at == b.len() {
        return Some(ms);
    }
    if !matches!(b.get(at), Some(b'T' | b't')) || at != date_start + 6 {
        return None;
    }
    let h = digits(at + 1, 2)?;
    if b.get(at + 3) != Some(&b':') {
        return None;
    }
    let mi = digits(at + 4, 2)?;
    at += 6;
    let mut sec = 0;
    let mut frac = 0;
    if b.get(at) == Some(&b':') {
        sec = digits(at + 1, 2)?;
        at += 3;
        if b.get(at) == Some(&b'.') {
            let start = at + 1;
            let mut end = start;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
            if end == start {
                return None;
            }
            let f = &s[start..end];
            frac = format!("{:0<3}", &f[..f.len().min(3)]).parse().ok()?;
            at = end;
        }
    }
    if h > 24 || mi > 59 || sec > 59 || (h == 24 && (mi > 0 || sec > 0 || frac > 0)) {
        return None;
    }
    ms += h * 3_600_000 + mi * 60_000 + sec * 1000 + frac;
    match b.get(at) {
        Some(b'Z' | b'z') if at + 1 == b.len() => Some(ms),
        Some(sign @ (b'+' | b'-')) => {
            let (oh, om) = if at + 6 == b.len() && b[at + 3] == b':' {
                (digits(at + 1, 2)?, digits(at + 4, 2)?)
            } else if at + 5 == b.len() {
                (digits(at + 1, 2)?, digits(at + 3, 2)?)
            } else {
                return None;
            };
            if oh > 23 || om > 59 {
                return None;
            }
            let off = (oh * 60 + om) * 60_000;
            Some(if *sign == b'+' { ms - off } else { ms + off })
        }
        _ => None,
    }
}

/// The HTTP date form `toUTCString()` writes, `Sun, 15 Nov 2026 10:00:00 GMT` (the weekday is
/// optional and, as in V8, not checked; `UTC` may stand for `GMT`).
fn http_date(s: &str) -> Option<i64> {
    let rest = match s.split_once(", ") {
        Some((wd, r)) if wd.len() == 3 && wd.bytes().all(|c| c.is_ascii_alphabetic()) => r,
        _ => s,
    };
    let parts: Vec<&str> = rest.split(' ').collect();
    if parts.len() != 5 || !(parts[4] == "GMT" || parts[4] == "UTC") {
        return None;
    }
    let d: i64 = parts[0].parse().ok().filter(|_| (1..=2).contains(&parts[0].len()) && parts[0].bytes().all(|c| c.is_ascii_digit()))?;
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mo = MONTHS.iter().position(|m| *m == parts[1])? as i64 + 1;
    if parts[2].len() != 4 || !parts[2].bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let y: i64 = parts[2].parse().ok()?;
    let hms: Vec<&str> = parts[3].split(':').collect();
    if hms.len() != 3 || hms.iter().any(|x| x.len() != 2 || !x.bytes().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let (h, mi, sec): (i64, i64, i64) = (hms[0].parse().ok()?, hms[1].parse().ok()?, hms[2].parse().ok()?);
    if !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * 86_400_000 + h * 3_600_000 + mi * 60_000 + sec * 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_like_javascript() {
        assert_eq!(date_parse("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(date_parse("1970-01-01"), Some(0));
        assert_eq!(date_parse("1970-01"), Some(0));
        assert_eq!(date_parse("1970"), Some(0));
        assert_eq!(date_parse("1970-01-01T01:00+01:00"), Some(0));
        assert_eq!(date_parse("1970-01-01T00:00:00.5Z"), Some(500));
        assert_eq!(date_parse("1970-01-01T00:00:00.123456Z"), Some(123));
        assert_eq!(date_parse("1970-01-02T24:00:00Z"), date_parse("1970-01-03T00:00:00Z"));
        assert_eq!(date_parse("1970-01-01T00:00:00"), None, "local time is refused");
        assert_eq!(date_parse("2026-02-30"), date_parse("2026-03-02"));
        assert_eq!(date_parse("2026-02-32"), None);
        assert_eq!(date_parse("nonsense"), None);
        assert!(truthy(&json!("x")) && !truthy(&json!("")) && !truthy(&json!(0)) && truthy(&json!([])));
        assert_eq!(len16("😀a"), 3);
    }
}
