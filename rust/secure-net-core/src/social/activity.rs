//! Signed activities (CVP-018), matching `src/social/activity.js`: made and signed on a device,
//! checked against the actor document for the time they say they were published.
use serde_json::{json, Value};

use crate::canonical::canonical_bytes;
use crate::error::{Error, Result};
use crate::js::{safe_int, truthy};
use crate::session::keys::Device;
use crate::signed::{check_signature, record_id, sign};
use crate::social::actor::device_key_at;
use crate::social::vocabulary::{activity_problems, is_actor_id, limits, new_id, recipients};

pub const ACTIVITY: &str = "social.activity";
pub const FUTURE_SKEW_MS: i64 = 5 * 60_000;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn problems_or_ok(body: &Value, encrypted: bool) -> Result<()> {
    let p = activity_problems(body, encrypted)?;
    if !p.is_empty() {
        return Err(err("BAD_ACTIVITY", p.join("; ")));
    }
    Ok(())
}

fn build_body(device: &Device, actor_id: &str, activity: &Value, encrypted: bool, now: i64) -> Result<Value> {
    let mut body = activity.as_object().cloned().unwrap_or_default();
    body.insert("actor".into(), json!(actor_id));
    body.insert("device".into(), json!(device.kid));
    if !body.contains_key("id") {
        body.insert("id".into(), json!(new_id(actor_id)?));
    }
    if !body.contains_key("published") {
        body.insert("published".into(), json!(now));
    }
    let is_create = body.get("type") == Some(&json!("Create"));
    if let Some(obj) = body.get("object").filter(|o| truthy(o) && (o.is_object() || o.is_array())).cloned() {
        if is_create {
            let mut o = serde_json::Map::new();
            o.insert("attributedTo".into(), json!(actor_id));
            o.insert("published".into(), body["published"].clone());
            for (k, v) in crate::js::entries(&obj) {
                o.insert(k, v);
            }
            if !o.contains_key("id") {
                o.insert("id".into(), json!(new_id(actor_id)?));
            }
            body.insert("object".into(), Value::Object(o));
        }
    }
    let body = Value::Object(body);
    problems_or_ok(&body, encrypted)?;
    if canonical_bytes(&body)?.len() > limits::BYTES {
        return Err(err("TOO_LARGE", "Activity is too large"));
    }
    Ok(body)
}

pub fn sign_activity(device: &Device, actor_id: &str, activity: &Value, encrypted: bool, now: i64) -> Result<Value> {
    sign(ACTIVITY, &build_body(device, actor_id, activity, encrypted, now)?, &device.sign)
}

/// An unsigned activity, for direct envelopes over version 2 sessions only (deniable).
pub fn session_activity(device: &Device, actor_id: &str, activity: &Value, now: i64) -> Result<Value> {
    Ok(json!({ "kind": ACTIVITY, "body": build_body(device, actor_id, activity, true, now)? }))
}

fn common_checks(b: &Value, now: i64, encrypted: bool) -> Result<()> {
    if safe_int(&b["published"]).is_some_and(|p| p > now + FUTURE_SKEW_MS) {
        return Err(err("BAD_TIME", "Activity is dated in the future"));
    }
    if canonical_bytes(b)?.len() > limits::BYTES {
        return Err(err("TOO_LARGE", "Activity is too large"));
    }
    problems_or_ok(b, encrypted)
}

/// Check an unsigned activity that arrived over a session with `from_device` of `actor`.
pub fn verify_session_activity(record: &Value, actor: &Value, from_device: &str, now: i64) -> Result<Value> {
    let b = &record["body"];
    if record["kind"] != ACTIVITY || !truthy(b) || !(b.is_object() || b.is_array()) || record.get("sig").is_some() {
        return Err(err("BAD_MESSAGE", "Not an unsigned activity"));
    }
    if b["actor"] != actor["id"] || b["device"] != from_device {
        return Err(err("UNTRUSTED", "The activity wasn't made by the device that sent it"));
    }
    if recipients(b, &["to", "cc", "bto", "bcc"])?.iter().any(|t| !is_actor_id(Some(t))) {
        return Err(err("UNTRUSTED", "Only activities addressed to actors may go unsigned"));
    }
    common_checks(b, now, true)?;
    Ok(b.clone())
}

/// Check a signed activity against its actor's document body.
pub fn verify_activity(record: &Value, actor: &Value, encrypted: bool, now: i64) -> Result<Value> {
    let b = &record["body"];
    if record["kind"] != ACTIVITY || !truthy(b) || !(b.is_object() || b.is_array()) {
        return Err(err("BAD_MESSAGE", "Not an activity"));
    }
    if b["actor"] != actor["id"] || (b.get("actor").is_none() != actor.get("id").is_none()) {
        return Err(err("UNTRUSTED", "Activity is from a different actor"));
    }
    if !b["device"].is_string() || record["sig"]["kid"] != b["device"] {
        return Err(err("UNTRUSTED", "Activity isn't signed by the device it names"));
    }
    let Some(key) = device_key_at(actor, &b["device"], &b["published"]) else { return Err(err("UNTRUSTED", "That device didn't speak for this actor then")) };
    if !key.contains('.') {
        return Err(err("UNTRUSTED", "Device key isn't quantum-resistant"));
    }
    if !check_signature(record, &record["sig"], &key) {
        return Err(err("UNTRUSTED", "Activity signature doesn't match"));
    }
    common_checks(b, now, encrypted)?;
    Ok(b.clone())
}

pub fn activity_digest(record: &Value) -> Result<String> {
    record_id(record)
}
