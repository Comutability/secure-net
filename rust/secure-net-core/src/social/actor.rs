//! Actors and discovery (CVP-017), matching `src/social/actor.js`: self-certifying actor
//! documents signed by a quantum-resistant account key, and handles that only point to them.
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::js::{len16, safe_int, trim};
use crate::session::keys::verify_device_list;
use crate::signed::{key_id, sign, verify, SigningKey};
use crate::social::vocabulary::ACTOR_TYPES;
use crate::wire::federation::norm_host;

pub const ACTOR: &str = "actor.document";
const MAX_FORMER: usize = 200;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// `^[a-z0-9_]([a-z0-9_.-]{0,62}[a-z0-9_])?$`
fn name_ok(n: &str) -> bool {
    let b = n.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
    !b.is_empty() && b.len() <= 64 && edge(b[0]) && edge(b[b.len() - 1]) && b.iter().all(|c| edge(*c) || *c == b'.' || *c == b'-')
}

/// `{ name, host, handle }` for "@name@host" or "name@host", or None.
pub fn parse_handle(handle: &str) -> Option<(String, String, String)> {
    let t = trim(handle);
    let t = t.strip_prefix('@').unwrap_or(t);
    let (name, host) = t.split_once('@')?;
    let bad = |s: &str| s.is_empty() || s.contains('@') || s.chars().any(crate::social::vocabulary::js_space_pub);
    if bad(name) || bad(host) {
        return None;
    }
    let name = name.to_lowercase();
    let host = norm_host(host)?;
    name_ok(&name).then(|| (name.clone(), host.clone(), format!("{name}@{host}")))
}

pub fn handle_of(v: &Value) -> Option<String> {
    let s = match v {
        Value::Null => String::new(),
        v if !crate::js::truthy(v) => String::new(),
        v => crate::cv::canonical::js_string(v),
    };
    parse_handle(&s).map(|h| h.2)
}

pub fn actor_id_of(account_public_key: &str) -> Result<String> {
    key_id(account_public_key)
}

/// Make an actor document. `p`: `{ handle, type, name, summary, icon, devices, former, seq, now, discoverable }`.
pub fn create_actor_document(account: &SigningKey, p: &Value) -> Result<Value> {
    let handle = handle_of(&p["handle"]).ok_or_else(|| err("BAD_INPUT", "A handle looks like name@host"))?;
    if !account.public_key.contains('.') {
        return Err(err("BAD_INPUT", "An actor's account key must be quantum-resistant (Ed25519 + ML-DSA-65)"));
    }
    let or = |k: &str, d: Value| p.get(k).cloned().unwrap_or(d);
    let mut body = json!({
        "v": 1, "type": or("type", json!("Person")), "id": actor_id_of(&account.public_key)?, "handle": handle,
        "account": account.public_key, "seq": p["seq"], "devices": p["devices"], "former": or("former", json!([])),
        "discoverable": or("discoverable", json!(true)), "updated": p["now"],
    });
    for k in ["name", "summary", "icon"] {
        if let Some(v) = p.get(k) {
            body[k] = v.clone();
        }
    }
    let record = sign(ACTOR, &body, account)?;
    verify_actor_document(&record, None, None, 0)?;
    Ok(record)
}

/// Check an actor document; returns its body.
pub fn verify_actor_document(record: &Value, id: Option<&str>, handle: Option<&Value>, min_seq: i64) -> Result<Value> {
    let b = &record["body"];
    if record["kind"] != ACTOR || !(b.is_object() || b.is_array()) {
        return Err(err("BAD_MESSAGE", "Not an actor document"));
    }
    if b["v"] != 1 {
        return Err(err("BAD_MESSAGE", "Unsupported actor document version"));
    }
    let Some(account) = b["account"].as_str().filter(|a| a.contains('.')) else { return Err(err("UNTRUSTED", "Actor's account key isn't quantum-resistant")) };
    let own_id = actor_id_of(account)?;
    if b["id"] != own_id.as_str() {
        return Err(err("UNTRUSTED", "Actor id isn't its account key's id"));
    }
    verify(record, |kid| (kid == own_id).then(|| account.to_string()), Some(&[ACTOR])).map_err(|e| {
        if ["MALFORMED", "WRONG_KIND", "UNKNOWN_SIGNER", "BAD_SIGNATURE", "BAD_KIND"].contains(&e.code) {
            err("UNTRUSTED", format!("Actor document: {}", e.message))
        } else {
            e
        }
    })?;
    if id.is_some_and(|i| b["id"] != i) {
        return Err(err("UNTRUSTED", "That's a different actor"));
    }
    match handle_of(&b["handle"]) {
        Some(h) if b["handle"] == h.as_str() => {}
        _ => return Err(err("BAD_MESSAGE", "Bad handle")),
    }
    if let Some(h) = handle {
        if handle_of(h).as_deref() != b["handle"].as_str() {
            return Err(err("UNTRUSTED", "The document is for a different handle"));
        }
    }
    if !b["type"].as_str().is_some_and(|t| ACTOR_TYPES.contains(&t)) {
        return Err(err("BAD_MESSAGE", format!("Unknown actor type {}", crate::js::show(b.get("type")))));
    }
    let Some(seq) = safe_int(&b["seq"]).filter(|s| *s >= 1) else { return Err(err("BAD_MESSAGE", "Bad seq")) };
    if seq < min_seq {
        return Err(err("ROLLBACK", "Actor document is older than one already seen"));
    }
    if safe_int(&b["updated"]).is_none() {
        return Err(err("BAD_MESSAGE", "Bad updated time"));
    }
    for (f, max) in [("name", 200), ("summary", 2000)] {
        if b.get(f).is_some() && !b[f].as_str().is_some_and(|s| len16(s) <= max) {
            return Err(err("BAD_MESSAGE", format!("Bad {f}")));
        }
    }
    verify_device_list(&b["devices"], account, 0)?;
    let Some(former) = b["former"].as_array().filter(|f| f.len() <= MAX_FORMER) else { return Err(err("BAD_MESSAGE", "Bad former devices")) };
    for f in former {
        let shape = f["kid"].is_string() && f["sign"].is_string() && safe_int(&f["until"]).is_some();
        if !shape {
            return Err(err("BAD_MESSAGE", "Bad former device"));
        }
        let kid = key_id(f["sign"].as_str().unwrap()).map_err(|_| err("TypeError", "not base64url"))?;
        if f["kid"] != kid.as_str() {
            return Err(err("BAD_MESSAGE", "Bad former device"));
        }
    }
    Ok(b.clone())
}

/// The signing key a device had for this actor at a time (ms), or None.
pub fn device_key_at(actor: &Value, device_kid: &Value, at: &Value) -> Option<String> {
    if let Some(cur) = actor["devices"]["body"]["devices"].as_array().into_iter().flatten().find(|d| d["kid"] == *device_kid) {
        return cur["sign"].as_str().map(str::to_string);
    }
    let old = actor["former"].as_array().into_iter().flatten().find(|d| d["kid"] == *device_kid)?;
    let (at, until) = (safe_int(at)?, old["until"].as_f64()?);
    ((at as f64) < until).then(|| old["sign"].as_str().map(str::to_string)).flatten()
}

/// Where a handle's actor document is.
pub fn discovery_url(handle: &str, endpoint: &str) -> Result<String> {
    let (name, host, _) = parse_handle(handle).ok_or_else(|| err("BAD_INPUT", "A handle looks like name@host"))?;
    Ok(format!("https://{host}{endpoint}?handle={}", encode_uri_component(&name)))
}

/// JavaScript's `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
