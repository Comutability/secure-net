//! Consent capsules (CVP-014), matching `src/consent/capsule.js`: signed, specific, time-limited
//! permissions, and signed revocations that stop future access (and say they can't undo the past).
use serde_json::{json, Value};

use crate::bytes::{random_b64u, sha256_b64u};
use crate::cv::encoding::iso_from_ms;
use crate::error::{Error, Result};
use crate::js::date_parse;
use crate::signed::{check_signature, sign, signing_bytes, SigningKey};

pub const CAPSULE: &str = "consent.capsule";
pub const REVOCATION: &str = "consent.revocation";
pub const ACTIONS: [&str; 6] = ["read", "store", "replicate", "forward", "process", "publish"];
pub const REVOCATION_LIMITS: &str = "Revoking stops new access from now on. It can't remove copies, screenshots or downloads someone already made, or what they remember.";

fn fail<T>(code: &'static str, msg: &str) -> Result<T> {
    Err(Error::new(code, msg))
}

pub fn capsule_id(capsule: &Value) -> Result<String> {
    Ok(sha256_b64u(&signing_bytes(capsule["kind"].as_str().unwrap_or(""), &capsule["body"])?))
}

/// Grant consent. `g`: `{ audience, actions, resource, notBefore, expires, purpose, keys }`.
pub fn grant(g: &Value, grantor: &SigningKey, now: i64) -> Result<Value> {
    if !g["audience"].as_array().is_some_and(|a| !a.is_empty() && a.len() <= 256) {
        return fail("BAD_AUDIENCE", "Say who this is for");
    }
    if !g["actions"].as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|x| x.as_str().is_some_and(|s| ACTIONS.contains(&s)))) {
        return fail("BAD_ACTIONS", "Actions must be from read, store, replicate, forward, process, publish");
    }
    if !g["resource"].as_str().is_some_and(|r| !r.is_empty()) {
        return fail("BAD_RESOURCE", "Say what this is about");
    }
    let not_before = match g.get("notBefore") {
        None => json!(iso_from_ms(now)?),
        Some(v) => v.clone(),
    };
    let (nb, ex) = (date_parse(not_before.as_str().unwrap_or("")), date_parse(g["expires"].as_str().unwrap_or("")));
    if !matches!((nb, ex), (Some(nb), Some(ex)) if ex > nb) {
        return fail("BAD_TIME", "Consent must end after it starts");
    }
    let body = json!({
        "id": random_b64u(12), "grantor": grantor.kid, "audience": g["audience"], "actions": g["actions"], "resource": g["resource"],
        "not_before": not_before, "expires": g["expires"], "purpose": g.get("purpose").cloned().unwrap_or(json!("")), "keys": g.get("keys").cloned().unwrap_or(Value::Null),
    });
    sign(CAPSULE, &body, grantor)
}

pub fn revoke(capsule: &Value, grantor: &SigningKey, reason: &str, now: i64) -> Result<Value> {
    sign(REVOCATION, &json!({ "capsule": capsule_id(capsule)?, "at": iso_from_ms(now)?, "reason": reason }), grantor)
}

fn verdict(allowed: bool, why: &str) -> Value {
    json!({ "allowed": allowed, "why": why })
}

/// Whether a capsule allows this action, now: `{ allowed, why }`.
pub fn check(capsule: &Value, grantor_pub: &str, actor: &Value, action: &Value, resource: &Value, now: i64, revocations: &[Value]) -> Result<Value> {
    let b = &capsule["body"];
    if capsule["kind"] != CAPSULE || !crate::js::truthy(b) {
        return Ok(verdict(false, "not a consent capsule"));
    }
    if capsule["sig"]["kid"] != b["grantor"] || !check_signature(capsule, &capsule["sig"], grantor_pub) {
        return Ok(verdict(false, "not signed by its grantor"));
    }
    let id = capsule_id(capsule)?;
    let revoked = revocations.iter().any(|r| {
        r["kind"] == REVOCATION
            && r["body"]["capsule"] == id.as_str()
            && r["sig"]["kid"] == b["grantor"]
            && check_signature(r, &r["sig"], grantor_pub)
            && date_parse(r["body"]["at"].as_str().unwrap_or("")).is_some_and(|t| t <= now)
    });
    if revoked {
        return Ok(verdict(false, "revoked"));
    }
    // now < NaN and now > NaN are both false in JavaScript, so an unreadable time doesn't refuse.
    if date_parse(b["not_before"].as_str().unwrap_or("")).is_some_and(|t| now < t) {
        return Ok(verdict(false, "not yet"));
    }
    if date_parse(b["expires"].as_str().unwrap_or("")).is_some_and(|t| now > t) {
        return Ok(verdict(false, "expired"));
    }
    if !b["audience"].as_array().is_some_and(|a| a.contains(actor)) {
        return Ok(verdict(false, "not for this person or site"));
    }
    if !b["actions"].as_array().is_some_and(|a| a.contains(action)) {
        return Ok(verdict(false, &format!("doesn't allow {}", crate::cv::canonical::js_string(action))));
    }
    if b["resource"] != "*" && b["resource"] != *resource {
        return Ok(verdict(false, "about something else"));
    }
    Ok(verdict(true, ""))
}
