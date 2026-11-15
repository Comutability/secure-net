//! End-to-end delivery (CVP-019), matching `src/social/delivery.js`: public, direct, audience and
//! group envelopes, the payloads inside them, sealed sending with delivery tokens, and the bodies
//! sites exchange.
use serde_json::{json, Map, Value};

use crate::bytes::{b64u, from_b64u, random, sha256};
use crate::canonical::{canonical_bytes, canonical_json};
use crate::error::{Error, Result};
use crate::js::{show, truthy};
use crate::session::{group, v1, v2};
use crate::social::activity::ACTIVITY;
use crate::social::actor::{actor_id_of, ACTOR};
use crate::social::vocabulary::{b64u_chars, is_actor_id, is_group_id, is_object_id, kid_str, new_id, owner_of, PUBLIC};

pub const MODES: [&str; 4] = ["public", "direct", "audience", "group"];
pub const MAX_ITEMS: usize = 100;
pub const ENVELOPE_BYTES: usize = 512 * 1024;
pub const REQUEST_BYTES: usize = 4 * 1024 * 1024;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// `KID.test(v || "")`.
fn kid_test(v: Option<&Value>) -> bool {
    match v {
        Some(x) if truthy(x) => kid_str(&crate::cv::canonical::js_string(x)),
        _ => false,
    }
}

/// `TOKEN.test(v || "")`: 43 base64url characters.
fn token_test(v: Option<&Value>) -> bool {
    match v {
        Some(x) if truthy(x) => {
            let s = crate::cv::canonical::js_string(x);
            s.len() == 43 && b64u_chars(&s)
        }
        _ => false,
    }
}

fn b64u_val(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty() && b64u_chars(s))
}

fn keys_of(v: &Value) -> Vec<String> {
    crate::js::entries(v).into_iter().map(|(k, _)| k).collect()
}

/// Problems with an envelope's outer form.
pub fn envelope_problems(env: &Value) -> Result<Vec<String>> {
    if !truthy(env) || !(env.is_object() || env.is_array()) || !(env["v"] == 1 || env["v"] == 2) {
        return Ok(vec!["Not a version 1 or 2 envelope".into()]);
    }
    let Some(mode) = env["mode"].as_str().filter(|m| MODES.contains(m)) else { return Ok(vec![format!("Unknown mode \"{}\"", show(env.get("mode")))]) };
    if env["v"] == 2 {
        return envelope2_problems(env, mode);
    }
    if mode == "group" {
        return Ok(vec!["Group envelopes are version 2".into()]);
    }
    let mut out = Vec::new();
    match mode {
        "public" => {
            let a = &env["activity"];
            if a["kind"] != ACTIVITY || !truthy(&a["sig"]) {
                out.push("A public envelope carries one signed activity".into());
            } else if !crate::social::vocabulary::recipients(&a["body"], &["to", "cc"])?.iter().any(|r| r == PUBLIC) {
                out.push("Only activities addressed to public may travel in the clear".into());
            }
        }
        "direct" => {
            if !kid_test(env.get("device")) {
                out.push("A direct envelope names the recipient device".into());
            }
            if !kid_test(env.get("session")) {
                out.push("A direct envelope carries its session tag".into());
            }
            if env["message"]["v"] != 1 || !env["message"]["c"].is_string() {
                out.push("A direct envelope carries one CVP-016 message".into());
            }
        }
        _ => {
            if !is_object_id(env.get("audience")) {
                out.push("An audience envelope names its audience".into());
            }
            let m = &env["message"];
            let same_group = match (m.get("group"), env.get("audience")) {
                (None, None) => true,
                (Some(a), Some(b)) => a == b,
                _ => false,
            };
            if m["v"] != 1 || !same_group || !m["sig"].is_string() {
                out.push("An audience envelope carries one sender-key message for that audience".into());
            }
        }
    }
    for k in keys_of(env) {
        if !["v", "mode", "activity", "device", "session", "message", "audience"].contains(&k.as_str()) {
            out.push(format!("Unexpected field {k}: envelopes carry nothing else, so they leak nothing else"));
        }
    }
    if out.is_empty() && canonical_bytes(env)?.len() > ENVELOPE_BYTES {
        out.push("Envelope is too large".into());
    }
    Ok(out)
}

fn envelope2_problems(env: &Value, mode: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let allowed: &[&str] = match mode {
        "direct" => {
            if !kid_test(env.get("device")) {
                out.push("A direct envelope names the recipient device".into());
            }
            let m = &env["message"];
            if m["v"] != 2 || !b64u_val(&m["h"]) || !b64u_val(&m["c"]) {
                out.push("A version 2 direct envelope carries one version 2 CVP-016 message".into());
            } else {
                for k in keys_of(m) {
                    if !["v", "h", "c", "x"].contains(&k.as_str()) {
                        out.push(format!("Unexpected message field {k}"));
                    }
                }
            }
            &["v", "mode", "device", "message"]
        }
        "group" => {
            if !is_group_id(env.get("group")) {
                out.push("A group envelope names its group".into());
            }
            if !b64u_val(&env["message"]) {
                out.push("A group envelope carries one MLS message".into());
            }
            &["v", "mode", "group", "message"]
        }
        m => return Ok(vec![format!("Version 2 has no {m} envelope")]),
    };
    for k in keys_of(env) {
        if !allowed.contains(&k.as_str()) {
            out.push(format!("Unexpected field {k}: envelopes carry nothing else, so they leak nothing else"));
        }
    }
    if out.is_empty() && canonical_bytes(env)?.len() > ENVELOPE_BYTES {
        out.push("Envelope is too large".into());
    }
    Ok(out)
}

fn problems_to_err(code: &'static str, env: &Value) -> Result<()> {
    let p = envelope_problems(env)?;
    if !p.is_empty() {
        return Err(err(code, p.join("; ")));
    }
    Ok(())
}

/// The tag a version 1 direct envelope carries.
pub fn session_tag(state_ad: &str) -> Result<String> {
    let ad = from_b64u(state_ad)?;
    Ok(b64u(&sha256(&[b"secure-net/social/v1/session\n".as_slice(), &ad].concat()))[..22].to_string())
}

fn decode(bytes: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(bytes);
    let p: Value = serde_json::from_str(&text).map_err(|_| err("BAD_MESSAGE", "Payload isn't JSON"))?;
    let has = |k: &str| p.get(k).is_some();
    if !truthy(&p) || p["v"] != 1 || !(has("activity") || has("senderKeys") || has("actor") || has("delivery") || has("groups")) {
        return Err(err("BAD_MESSAGE", "Not a version 1 payload"));
    }
    if has("delivery") && !(p["delivery"].is_string() && token_test(p.get("delivery"))) {
        return Err(err("BAD_MESSAGE", "Bad delivery token"));
    }
    if has("groups") {
        let ok = p["groups"].as_array().is_some_and(|gs| {
            gs.len() <= 20
                && gs.iter().all(|g| {
                    truthy(g)
                        && is_group_id(g.get("group"))
                        && b64u_val(&g["welcome"])
                        && (g.get("actors").is_none() || g["actors"].as_array().is_some_and(|a| a.len() <= 1000 && a.iter().all(|x| x["kind"] == ACTOR)))
                })
        });
        if !ok {
            return Err(err("BAD_MESSAGE", "Bad group welcomes"));
        }
    }
    if has("actor") && p["actor"]["kind"] != ACTOR {
        return Err(err("BAD_MESSAGE", "Payload actor isn't an actor document"));
    }
    if has("activity") && p["activity"]["kind"] != ACTIVITY {
        return Err(err("BAD_MESSAGE", "Payload activity isn't a signed activity"));
    }
    if has("senderKeys") && !p["senderKeys"].is_array() {
        return Err(err("BAD_MESSAGE", "Bad sender keys"));
    }
    Ok(p)
}

pub fn public_envelope(record: &Value) -> Result<Value> {
    let env = json!({ "v": 1, "mode": "public", "activity": record });
    problems_to_err("BAD_INPUT", &env)?;
    Ok(env)
}

/// Seal a payload for several devices: `{ sessions, items: [{ to, envelope }] }`.
pub fn seal_direct(sessions: &Map<String, Value>, payload_in: &Value) -> Result<Value> {
    let mut payload = json!({ "v": 1 });
    let nonempty_list = |k: &str| payload_in[k].as_array().is_some_and(|a| !a.is_empty());
    if truthy(&payload_in["activity"]) {
        payload["activity"] = payload_in["activity"].clone();
    }
    if nonempty_list("senderKeys") {
        payload["senderKeys"] = payload_in["senderKeys"].clone();
    }
    if truthy(&payload_in["actor"]) {
        payload["actor"] = payload_in["actor"].clone();
    }
    if truthy(&payload_in["delivery"]) {
        payload["delivery"] = payload_in["delivery"].clone();
    }
    if nonempty_list("groups") {
        payload["groups"] = payload_in["groups"].clone();
    }
    let unsigned = truthy(&payload_in["activity"]) && payload_in["activity"].get("sig").is_none();
    let text = canonical_json(&payload)?;
    let mut out = sessions.clone();
    let mut items = Vec::new();
    for (device, state) in sessions {
        let to = actor_id_of(state["peer"]["account"].as_str().unwrap_or(""))?;
        if state["v"] == 2 {
            let st: v2::State = serde_json::from_value(state.clone()).map_err(|e| err("BAD_INPUT", format!("session: {e}")))?;
            let (st, message) = v2::encrypt(&st, text.as_bytes())?;
            out.insert(device.clone(), serde_json::to_value(st).expect("JSON"));
            items.push(json!({ "to": to, "envelope": { "v": 2, "mode": "direct", "device": device, "message": message } }));
        } else {
            if unsigned || truthy(&payload_in["delivery"]) || nonempty_list("groups") {
                return Err(err("BAD_INPUT", "Unsigned activities, delivery tokens and group welcomes need a version 2 session"));
            }
            let st: v1::State = serde_json::from_value(state.clone()).map_err(|e| err("BAD_INPUT", format!("session: {e}")))?;
            let (st, message) = v1::encrypt(&st, text.as_bytes())?;
            let tag = session_tag(&st.ad)?;
            out.insert(device.clone(), serde_json::to_value(st).expect("JSON"));
            items.push(json!({ "to": to, "envelope": { "v": 1, "mode": "direct", "device": device, "session": tag, "message": message } }));
        }
    }
    Ok(json!({ "sessions": out, "items": items }))
}

/// Read a direct payload the session layer decrypted, checking it came from that device.
pub fn open_direct_payload(plaintext: &[u8], from_device: &str, from_actor: &str, version: i64) -> Result<Value> {
    let p = decode(plaintext)?;
    let a = &p["activity"];
    if truthy(a) && (a["body"]["device"] != from_device || a["body"]["actor"] != from_actor) {
        return Err(err("UNTRUSTED", "The activity wasn't made by the device that sent it"));
    }
    let unsigned = truthy(a) && a.get("sig").is_none();
    if version != 2 && (unsigned || p.get("delivery").is_some() || p.get("groups").is_some()) {
        return Err(err("UNTRUSTED", "Unsigned activities, delivery tokens and group welcomes need a version 2 session"));
    }
    let mut keys = Vec::new();
    for d in p["senderKeys"].as_array().into_iter().flatten() {
        if owner_of(d.get("group")).as_deref() != Some(from_actor) {
            return Err(err("UNTRUSTED", "A sender key for someone else's audience"));
        }
        keys.push(serde_json::to_value(group::accept_distribution(d, json!(from_device))?).expect("JSON"));
    }
    if truthy(&p["actor"]) && p["actor"]["body"]["id"] != from_actor {
        return Err(err("UNTRUSTED", "An actor document for someone else"));
    }
    let mut out = json!({ "senderKeys": keys, "groups": if truthy(&p["groups"]) { p["groups"].clone() } else { json!([]) } });
    if truthy(a) {
        out[if unsigned { "unsigned" } else { "activity" }] = a.clone();
    }
    for k in ["actor", "delivery"] {
        if let Some(v) = p.get(k) {
            out[k] = v.clone();
        }
    }
    Ok(out)
}

pub fn new_delivery_token() -> String {
    b64u(&random::<32>())
}

pub fn delivery_verifier(token: &str) -> Result<String> {
    if !(token.len() == 43 && b64u_chars(token)) {
        return Err(err("BAD_INPUT", "Not a delivery token"));
    }
    Ok(b64u(&sha256(&[b"secure-net/social/v2/delivery-token\n".as_slice(), &from_b64u(token)?].concat())))
}

pub fn sealed_body(items: &[Value]) -> Result<Value> {
    if items.is_empty() || items.len() > MAX_ITEMS {
        return Err(err("BAD_INPUT", format!("1 to {MAX_ITEMS} items per request")));
    }
    let checked = read_sealed_body(&json!({ "v": 1, "items": items }), "BAD_INPUT")?;
    Ok(json!({ "v": 1, "items": checked }))
}

pub fn read_sealed_body(body: &Value, code: &'static str) -> Result<Vec<Value>> {
    let Some(items) = body["items"].as_array().filter(|i| body["v"] == 1 && !i.is_empty() && i.len() <= MAX_ITEMS) else { return Err(err(code, "Not a version 1 sealed delivery")) };
    for it in items {
        if !is_actor_id(it.get("to")) || !token_test(it.get("token")) {
            return Err(err(code, "Each item names the recipient actor and carries its delivery token"));
        }
        if it["envelope"]["v"] != 2 {
            return Err(err(code, "Only version 2 direct and group envelopes may be sent sealed"));
        }
        problems_to_err(code, &it["envelope"])?;
        for k in keys_of(it) {
            if !["to", "envelope", "token"].contains(&k.as_str()) {
                return Err(err(code, format!("Unexpected field {k}")));
            }
        }
    }
    Ok(items.clone())
}

// ---- Audiences ----

pub fn create_audience(actor_id: &str, kind: &str) -> Result<Value> {
    let id = new_id(actor_id)?;
    Ok(json!({ "id": id, "kind": kind, "key": group::create_sender_key(&id), "members": [] }))
}

fn member_key(m: &Value) -> String {
    format!("{}/{}", show(m.get("actor")), show(m.get("device")))
}

/// Add member devices: `{ audience, send: { to, senderKey } }`.
pub fn add_members(audience: &Value, members: &[Value]) -> Result<Value> {
    let have: Vec<String> = audience["members"].as_array().into_iter().flatten().map(member_key).collect();
    let fresh: Vec<Value> = members.iter().filter(|m| is_actor_id(m.get("actor")) && kid_test(m.get("device")) && !have.contains(&member_key(m))).cloned().collect();
    let mut a = audience.clone();
    let mut all = audience["members"].as_array().cloned().unwrap_or_default();
    all.extend(fresh.clone());
    a["members"] = Value::Array(all);
    let key: group::SenderKey = serde_json::from_value(audience["key"].clone()).map_err(|e| err("BAD_INPUT", format!("key: {e}")))?;
    Ok(json!({ "audience": a, "send": { "to": fresh, "senderKey": group::distribution(&key) } }))
}

/// Remove members for which `remove` is true; the audience gets a new sender key.
pub fn remove_members(audience: &Value, remove: &dyn Fn(&Value) -> bool) -> Result<Value> {
    let members: Vec<Value> = audience["members"].as_array().into_iter().flatten().filter(|m| !remove(m)).cloned().collect();
    let key = group::create_sender_key(audience["id"].as_str().unwrap_or(""));
    let mut a = audience.clone();
    a["members"] = json!(members);
    a["key"] = serde_json::to_value(&key).expect("JSON");
    Ok(json!({ "audience": a, "send": { "to": members, "senderKey": group::distribution(&key) } }))
}

pub fn seal_to_audience(audience: &Value, record: &Value) -> Result<Value> {
    let key: group::SenderKey = serde_json::from_value(audience["key"].clone()).map_err(|e| err("BAD_INPUT", format!("key: {e}")))?;
    let (key, message) = group::group_encrypt(&key, canonical_json(&json!({ "v": 1, "activity": record }))?.as_bytes())?;
    let mut a = audience.clone();
    a["key"] = serde_json::to_value(key).expect("JSON");
    Ok(json!({ "audience": a, "envelope": { "v": 1, "mode": "audience", "audience": audience["id"], "message": message } }))
}

pub fn open_audience(view: &Value, envelope: &Value) -> Result<Value> {
    if envelope["mode"] != "audience" || envelope["audience"] != view["group"] || envelope["message"]["group"] != view["group"] {
        return Err(err("BAD_MESSAGE", "Not for this audience"));
    }
    let state: group::Received = serde_json::from_value(view.clone()).map_err(|e| err("BAD_INPUT", format!("view: {e}")))?;
    let (state, plaintext) = group::group_decrypt(&state, &envelope["message"])?;
    let p = decode(&plaintext)?;
    let a = &p["activity"];
    if !truthy(a) || a["body"]["device"] != view["from"] || a["body"]["actor"].as_str() != owner_of(view.get("group")).as_deref() {
        return Err(err("UNTRUSTED", "The activity wasn't made by the device whose key sealed it"));
    }
    Ok(json!({ "view": state, "activity": a }))
}

pub fn view_key(audience_id: &str, sender_key_id: &str) -> String {
    format!("{audience_id}#{sender_key_id}")
}

// ---- Site to site ----

pub fn delivery_body(items: &[Value]) -> Result<Value> {
    if items.is_empty() || items.len() > MAX_ITEMS {
        return Err(err("BAD_INPUT", format!("1 to {MAX_ITEMS} items per request")));
    }
    for it in items {
        if !is_actor_id(it.get("to")) {
            return Err(err("BAD_INPUT", "Each item names the recipient actor"));
        }
        problems_to_err("BAD_INPUT", &it["envelope"])?;
    }
    Ok(json!({ "v": 1, "items": items }))
}

pub fn read_delivery_body(body: &Value) -> Result<Vec<Value>> {
    let Some(items) = body["items"].as_array().filter(|i| body["v"] == 1 && !i.is_empty() && i.len() <= MAX_ITEMS) else { return Err(err("BAD_MESSAGE", "Not a version 1 delivery")) };
    for it in items {
        if !is_actor_id(it.get("to")) {
            return Err(err("BAD_MESSAGE", "Item without a recipient"));
        }
        problems_to_err("BAD_MESSAGE", &it["envelope"])?;
    }
    Ok(items.clone())
}
