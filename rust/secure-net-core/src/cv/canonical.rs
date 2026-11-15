//! Canonical text for every signed Commonveil statement (`src/crypto/canonical.js`).
//!
//! `commonveil/<context>\n<number of fields>\n<fields joined by \n>`. Fields are strings with no
//! line breaks; numbers are written as JavaScript's `String()` writes them.
use serde_json::Value;

use crate::error::{Error, Result};

pub mod contexts {
    pub const ACCOUNT_KEY: &str = "account-key/v1";
    pub const ACCOUNT_KEY_PQ: &str = "account-key/v2";
    pub const DEVICE_CERT: &str = "device-cert/v1";
    pub const DEVICE_CERT_PQ: &str = "device-cert/v2";
    pub const DEVICE_KEM: &str = "device-kem/v1";
    pub const DEVICE_PROOF: &str = "device-proof/v1";
    pub const ITEM: &str = "item/v1";
    pub const RECOVERY_ANCHOR: &str = "recovery-anchor/v1";
    pub const RECOVERY_ANCHOR_PQ: &str = "recovery-anchor/v2";
    pub const CHAIN_GENERATION: &str = "chain-gen/v1";
    pub const KEY_GRANT: &str = "key-grant/v1";
    pub const SERVER_ITEM: &str = "server-item/v1";
    pub const VOICE_HELLO: &str = "voice-hello/v1";
}
use contexts::*;

fn context_ok(c: &str) -> bool {
    let Some((name, v)) = c.split_once("/v") else { return false };
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !v.is_empty()
        && v.bytes().all(|b| b.is_ascii_digit())
}

pub fn canonical(context: &str, fields: &[String]) -> Result<String> {
    if !context_ok(context) {
        return Err(Error::new("BAD_FORMAT", "Invalid signing context"));
    }
    for f in fields {
        if f.contains('\r') || f.contains('\n') {
            return Err(Error::new("BAD_FORMAT", "Signed fields cannot contain line breaks"));
        }
    }
    Ok(format!("commonveil/{context}\n{}\n{}", fields.len(), fields.join("\n")))
}

/// JavaScript's `String(value)` for the values statements hold.
pub fn js_string(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(u) = n.as_u64() {
                u.to_string()
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                if f.fract() == 0.0 && f.abs() < 1e21 {
                    format!("{f:.0}")
                } else {
                    f.to_string()
                }
            }
        }
        Value::Array(a) => a.iter().map(|x| if x.is_null() { String::new() } else { js_string(x) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

/// A field used as it is: it has to be a string.
fn s(v: &Value, k: &str) -> Result<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::new("BAD_FORMAT", "Signed fields must be strings"))
}

/// A field written with `String(...)`, so a missing one is "undefined", as in JavaScript.
fn n(v: &Value, k: &str) -> String {
    v.get(k).map(js_string).unwrap_or_else(|| "undefined".into())
}

/// `x || ""` for an optional string field.
fn opt(v: &Value, k: &str) -> Result<String> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(x)) => Ok(x.clone()),
        Some(Value::Bool(false)) => Ok(String::new()),
        Some(Value::Number(x)) if x.as_f64() == Some(0.0) => Ok(String::new()),
        _ => Err(Error::new("BAD_FORMAT", "Signed fields must be strings")),
    }
}

pub fn has_kem(v: &Value) -> bool {
    v.get("kem_pub").and_then(Value::as_str).is_some_and(|k| !k.is_empty())
}

pub fn account_key_fields(st: &Value) -> Result<Vec<String>> {
    Ok(vec![s(st, "user_id")?, n(st, "version"), s(st, "ecdh_pub")?, s(st, "sign_pub")?, s(st, "recovery_pub")?, n(st, "signed_by_version"), s(st, "issued_at")?])
}

pub fn account_key_fields_pq(st: &Value) -> Result<Vec<String>> {
    Ok(vec![
        s(st, "user_id")?,
        n(st, "version"),
        s(st, "ecdh_pub")?,
        s(st, "sign_pub")?,
        s(st, "kem_pub")?,
        s(st, "recovery_pub")?,
        opt(st, "recovery_kem_pub")?,
        n(st, "signed_by_version"),
        s(st, "issued_at")?,
    ])
}

/// The text an account key statement is signed over. Adding or removing a post-quantum key
/// changes the form, so the signature stops verifying.
pub fn statement_text(st: &Value) -> Result<String> {
    if has_kem(st) {
        canonical(ACCOUNT_KEY_PQ, &account_key_fields_pq(st)?)
    } else {
        canonical(ACCOUNT_KEY, &account_key_fields(st)?)
    }
}

pub fn anchor_text(st: &Value) -> Result<String> {
    if has_kem(st) {
        canonical(RECOVERY_ANCHOR_PQ, &account_key_fields_pq(st)?)
    } else {
        canonical(RECOVERY_ANCHOR, &account_key_fields(st)?)
    }
}

pub fn cert_text(c: &Value) -> Result<String> {
    if has_kem(c) {
        canonical(DEVICE_CERT_PQ, &[s(c, "user_id")?, s(c, "device_id")?, s(c, "sign_pub")?, s(c, "box_pub")?, s(c, "kem_pub")?, n(c, "key_version"), s(c, "issued_at")?])
    } else {
        canonical(DEVICE_CERT, &[s(c, "user_id")?, s(c, "device_id")?, s(c, "sign_pub")?, s(c, "box_pub")?, n(c, "key_version"), s(c, "issued_at")?])
    }
}

pub fn device_kem_text(user_id: &str, device_id: &str, kem_pub: &str) -> Result<String> {
    canonical(DEVICE_KEM, &[user_id.into(), device_id.into(), kem_pub.into()])
}

pub fn device_proof_text(p: &Value) -> Result<String> {
    canonical(DEVICE_PROOF, &[s(p, "user_id")?, s(p, "device_id")?, s(p, "action")?, s(p, "payload_hash")?, s(p, "issued_at")?, s(p, "nonce")?])
}

pub fn item_text(m: &Value) -> Result<String> {
    canonical(ITEM, &[s(m, "kind")?, s(m, "conversation_id")?, s(m, "item_id")?, s(m, "sender_id")?, s(m, "device_id")?, s(m, "envelope_hash")?, s(m, "sent_at")?])
}

pub fn chain_generation_text(g: &Value) -> Result<String> {
    canonical(CHAIN_GENERATION, &[s(g, "server_id")?, s(g, "chain_id")?, n(g, "generation"), s(g, "started_at")?, s(g, "commit")?, s(g, "creator_id")?, s(g, "device_id")?])
}

pub fn key_grant_text(g: &Value) -> Result<String> {
    canonical(
        KEY_GRANT,
        &[
            s(g, "server_id")?,
            s(g, "chain_id")?,
            n(g, "generation"),
            n(g, "step"),
            s(g, "recipient_id")?,
            n(g, "recipient_key_version"),
            s(g, "sealed_hash")?,
            s(g, "grantor_id")?,
            s(g, "grantor_device_id")?,
            s(g, "granted_at")?,
        ],
    )
}

pub fn server_item_text(m: &Value) -> Result<String> {
    canonical(
        SERVER_ITEM,
        &[s(m, "kind")?, s(m, "server_id")?, s(m, "channel_id")?, s(m, "item_id")?, s(m, "sender_id")?, s(m, "device_id")?, s(m, "envelope_hash")?, s(m, "sent_at")?],
    )
}

pub fn voice_hello_text(v: &Value) -> Result<String> {
    canonical(VOICE_HELLO, &[s(v, "room")?, s(v, "user_id")?, s(v, "device_id")?, s(v, "peer_id")?, s(v, "fingerprint")?, s(v, "issued_at")?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn forms() {
        assert_eq!(canonical("item/v1", &["a".into(), "b".into()]).unwrap(), "commonveil/item/v1\n2\na\nb");
        assert!(canonical("Item/v1", &[]).is_err());
        assert!(canonical("item/v", &[]).is_err());
        assert!(canonical("item/v1", &["a\nb".into()]).is_err());
        assert_eq!(js_string(&json!(3)), "3");
        assert_eq!(js_string(&json!(1.5)), "1.5");
        let st = json!({"user_id":"u","version":2,"ecdh_pub":"e","sign_pub":"s","recovery_pub":"r","signed_by_version":1,"issued_at":"t"});
        assert_eq!(statement_text(&st).unwrap(), "commonveil/account-key/v1\n7\nu\n2\ne\ns\nr\n1\nt");
        let mut pq = st.clone();
        pq["kem_pub"] = json!("k");
        assert_eq!(statement_text(&pq).unwrap(), "commonveil/account-key/v2\n9\nu\n2\ne\ns\nk\nr\n\n1\nt");
    }
}
