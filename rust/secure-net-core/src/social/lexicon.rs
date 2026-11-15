//! Lexicons (CVP-021), matching `src/social/lexicon.js`: new object types named by reverse
//! domain names, with schemas signed by lexicons@<that domain>.
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::js::{entries, len16, safe_int, truthy};
use crate::signed::{check_signature, sign, SigningKey};
use crate::social::actor::handle_of;
use crate::social::vocabulary::{is_actor_id, is_object_id};

pub const LEXICON: &str = "lexicon.schema";
pub const PUBLISHER: &str = "lexicons";
pub const FIELD_TYPES: [&str; 6] = ["string", "integer", "boolean", "id", "actor", "array"];
pub const COMMON: [&str; 15] = ["type", "id", "attributedTo", "published", "updated", "content", "mediaType", "name", "summary", "sensitive", "language", "inReplyTo", "context", "attachment", "tag"];

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}$`, at most 200 characters.
pub fn is_nsid(v: &Value) -> bool {
    v.as_str().is_some_and(|s| len16(s) <= 200 && {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() >= 3 && parts.iter().all(|p| p.as_bytes().first().is_some_and(|c| c.is_ascii_lowercase()) && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
    })
}

pub fn authority_of(nsid: &Value) -> Option<String> {
    if !is_nsid(nsid) {
        return None;
    }
    let parts: Vec<&str> = nsid.as_str().unwrap().split('.').collect();
    let mut a: Vec<&str> = parts[..parts.len() - 1].to_vec();
    a.reverse();
    Some(a.join("."))
}

/// `^[a-z][A-Za-z0-9]{0,39}$`
fn field_name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 40 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_alphanumeric())
}

fn field_problems(name: &str, f: &Value, out: &mut Vec<String>, nested: bool) {
    let t = f["type"].as_str();
    if !truthy(f) || !t.is_some_and(|t| FIELD_TYPES.contains(&t)) || (nested && t == Some("array")) {
        out.push(format!("{name}: type must be one of {}", FIELD_TYPES.join(", ")));
        return;
    }
    if f.get("max").is_some() && !safe_int(&f["max"]).is_some_and(|m| m >= 0) {
        out.push(format!("{name}: max must be a whole number"));
    }
    if f.get("min").is_some() && safe_int(&f["min"]).is_none() {
        out.push(format!("{name}: min must be an integer"));
    }
    if f.get("required").is_some() && !f["required"].is_boolean() {
        out.push(format!("{name}: required must be true or false"));
    }
    if t == Some("array") {
        field_problems(&format!("{name}[]"), &f["items"], out, true);
    }
}

pub fn lexicon_problems(l: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if !truthy(l) || l["v"] != 1 || !is_nsid(&l["id"]) {
        return vec!["A lexicon needs v: 1 and an id like org.example.recipe".into()];
    }
    if !safe_int(&l["revision"]).is_some_and(|r| r >= 1) {
        out.push("revision must be a positive integer".into());
    }
    if l.get("description").is_some() && !l["description"].as_str().is_some_and(|d| len16(d) <= 1000) {
        out.push("description is too long".into());
    }
    let fields = &l["fields"];
    let names: Vec<(String, Value)> = if truthy(fields) { entries(fields) } else { vec![] };
    if !truthy(fields) || !(fields.is_object() || fields.is_array()) || names.len() > 50 {
        out.push("fields must be an object of at most 50 fields".into());
        return out;
    }
    for (n, f) in names {
        if !field_name_ok(&n) || COMMON.contains(&n.as_str()) {
            out.push(format!("\"{n}\" can't be a field name"));
        } else {
            field_problems(&n, &f, &mut out, false);
        }
    }
    out
}

pub fn create_lexicon(account: &SigningKey, body: &Value) -> Result<Value> {
    let mut full = json!({ "v": 1 });
    for (k, v) in entries(body) {
        full[k.as_str()] = v;
    }
    let p = lexicon_problems(&full);
    if !p.is_empty() {
        return Err(err("BAD_INPUT", p.join("; ")));
    }
    sign(LEXICON, &full, account)
}

pub fn verify_lexicon(record: &Value, actor: &Value, min_revision: i64) -> Result<Value> {
    let l = &record["body"];
    if record["kind"] != LEXICON {
        return Err(err("BAD_MESSAGE", "Not a lexicon"));
    }
    let p = lexicon_problems(l);
    if !p.is_empty() {
        return Err(err("BAD_MESSAGE", p.join("; ")));
    }
    let signed = record["sig"]["kid"] == actor["id"] && actor["account"].as_str().is_some_and(|a| check_signature(record, &record["sig"], a));
    if !signed {
        return Err(err("UNTRUSTED", "Lexicon isn't signed by that actor"));
    }
    let auth = authority_of(&l["id"]);
    let h = handle_of(&actor["handle"]).and_then(|h| crate::social::actor::parse_handle(&h));
    if h.as_ref().map(|h| h.1.clone()) != auth || h.as_ref().map(|h| h.0.as_str()) != Some(PUBLISHER) {
        return Err(err("UNTRUSTED", format!("Only {PUBLISHER}@{} may define {}", auth.unwrap_or_else(|| "null".into()), crate::js::show(l.get("id")))));
    }
    if safe_int(&l["revision"]).unwrap_or(0) < min_revision {
        return Err(err("ROLLBACK", "Lexicon is older than one already seen"));
    }
    Ok(l.clone())
}

fn value_ok(v: &Value, f: &Value) -> bool {
    let max = |d: i64| match f.get("max").filter(|m| !m.is_null()) {
        Some(m) => m.as_f64().unwrap_or(f64::NAN),
        None => d as f64,
    };
    match f["type"].as_str() {
        Some("string") => v.as_str().is_some_and(|s| (len16(s) as f64) <= max(10_000)),
        Some("integer") => safe_int(v).is_some_and(|n| {
            let n = n as f64;
            (f.get("min").is_none() || f["min"].as_f64().is_some_and(|m| n >= m)) && (f.get("max").is_none() || f["max"].as_f64().is_some_and(|m| n <= m))
        }),
        Some("boolean") => v.is_boolean(),
        Some("id") => is_object_id(Some(v)),
        Some("actor") => is_actor_id(Some(v)),
        Some("array") => v.as_array().is_some_and(|a| (a.len() as f64) <= max(100) && a.iter().all(|x| value_ok(x, &f["items"]))),
        _ => false,
    }
}

pub fn extension_problems(object: &Value, lexicon: &Value) -> Vec<String> {
    let id = crate::js::show(lexicon.get("id"));
    if object["type"] != lexicon["id"] {
        return vec![format!("Object isn't a {id}")];
    }
    let mut out = Vec::new();
    for (n, f) in entries(&lexicon["fields"]) {
        match object.get(&n) {
            None => {
                if truthy(&f["required"]) {
                    out.push(format!("{n} is required"));
                }
            }
            Some(v) if !value_ok(v, &f) => out.push(format!("{n} isn't a valid {}", crate::js::show(f.get("type")))),
            _ => {}
        }
    }
    for (n, _) in entries(object) {
        if !COMMON.contains(&n.as_str()) && !truthy(&lexicon["fields"][n.as_str()]) {
            out.push(format!("{n} isn't in {id} revision {}", crate::js::show(lexicon.get("revision"))));
        }
    }
    out
}
