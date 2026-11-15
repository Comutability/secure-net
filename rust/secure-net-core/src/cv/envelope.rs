//! Message envelopes (`src/crypto/envelope.js`): a fresh content key per message, AES-256-GCM
//! once, the key sealed to each recipient account (post-quantum where they have a key, v3) and a
//! commitment to the key that every recipient checks, so nobody can be shown a different text.
use serde_json::{json, Value};
use std::collections::HashSet;
use zeroize::Zeroizing;

use super::encoding::{from_b64, to_b64};
use super::kem::{kem_open, kem_seal, KEM_CIPHERTEXT_BYTES};
use super::keyring::{as_int, key_for_version};
use super::primitives::{aes_decrypt, aes_encrypt, open_sealed, seal_to, secret_from_pkcs8};
use crate::bytes::{equal_bytes, random, sha256};
use crate::error::{Error, Result};

pub const ENVELOPE_VERSION: i64 = 3;
pub const MAX_RECIPIENTS: usize = 32;

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

pub fn id_ok(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

fn check_scope(scope: &Value) -> Result<()> {
    if !matches!(str_of(scope, "kind"), "message" | "title" | "report") {
        return Err(err("BAD_SCOPE", "Unknown item kind"));
    }
    for name in ["conversation_id", "item_id", "sender_id", "device_id"] {
        if !scope[name].as_str().is_some_and(id_ok) {
            return Err(Error::new("BAD_SCOPE", format!("Invalid {name}")));
        }
    }
    Ok(())
}

fn content_context(s: &Value) -> String {
    format!(
        "commonveil/content/v1|{}|{}|{}|{}|{}",
        str_of(s, "kind"),
        str_of(s, "conversation_id"),
        str_of(s, "item_id"),
        str_of(s, "sender_id"),
        str_of(s, "device_id")
    )
}

fn wrap_context(s: &Value, user: &str, kv: i64) -> String {
    format!("commonveil/wrap/v1|{}|{}|{}|{user}|{kv}", str_of(s, "kind"), str_of(s, "conversation_id"), str_of(s, "item_id"))
}

fn key_commitment(scope: &Value, key: &[u8]) -> [u8; 32] {
    sha256(&[format!("commonveil/key-commitment/v1|{}|", content_context(scope)).as_bytes(), key].concat())
}

fn b64_len(v: &Value, exact: Option<usize>, min: Option<usize>) -> Result<Vec<u8>> {
    let b = from_b64(v.as_str().ok_or_else(|| err("BAD_FORMAT", "missing"))?)?;
    if exact.is_some_and(|e| b.len() != e) || min.is_some_and(|m| b.len() < m) {
        return Err(err("BAD_FORMAT", "Wrong length"));
    }
    Ok(b)
}

pub fn validate_envelope(env: &Value) -> Result<&Value> {
    let check = || -> Result<()> {
        let v = env.get("v").and_then(as_int).ok_or_else(|| err("BAD_FORMAT", "version"))?;
        if v != 2 && v != 3 {
            return Err(err("BAD_FORMAT", "version"));
        }
        b64_len(&env["iv"], Some(12), None)?;
        b64_len(&env["ct"], None, Some(17))?;
        b64_len(&env["kc"], Some(32), None)?;
        let wraps = env["wraps"].as_array().filter(|w| !w.is_empty() && w.len() <= MAX_RECIPIENTS).ok_or_else(|| err("BAD_FORMAT", "wraps"))?;
        let mut seen = HashSet::new();
        for w in wraps {
            let u = w["u"].as_str().filter(|u| id_ok(u)).ok_or_else(|| err("BAD_FORMAT", "wrap user"))?;
            if !seen.insert(u) {
                return Err(err("BAD_FORMAT", "wrap user"));
            }
            if !w.get("kv").and_then(as_int).is_some_and(|k| k >= 1) {
                return Err(err("BAD_FORMAT", "wrap version"));
            }
            if w.get("kct").is_some() {
                if v < 3 || w.get("epk").is_some() {
                    return Err(err("BAD_FORMAT", "wrap kind"));
                }
                b64_len(&w["kct"], Some(KEM_CIPHERTEXT_BYTES), None)?;
            } else {
                b64_len(&w["epk"], Some(65), None)?;
            }
            b64_len(&w["iv"], Some(12), None)?;
            b64_len(&w["wk"], Some(48), None)?;
        }
        Ok(())
    };
    check().map_err(|_| err("BAD_ENVELOPE", "The encrypted message is malformed."))?;
    Ok(env)
}

pub fn parse_envelope(text: &str) -> Result<Value> {
    let v: Value = serde_json::from_str(text).map_err(|_| err("BAD_ENVELOPE", "The encrypted message is malformed."))?;
    validate_envelope(&v)?;
    Ok(v)
}

/// recipients: `[{ user_id, key_version, ecdh_pub, kem_pub? }]`, the sender's own account
/// included. Returns the envelope object.
pub fn encrypt_envelope(scope: &Value, recipients: &[Value], payload: &Value) -> Result<Value> {
    check_scope(scope)?;
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(err("BAD_RECIPIENTS", "A message needs between 1 and 32 recipients."));
    }
    let content_key = Zeroizing::new(random::<32>());
    let text = serde_json::to_string(payload).map_err(|_| err("BAD_INPUT", "payload"))?;
    let (iv, ct) = aes_encrypt(&content_key[..], text.as_bytes(), content_context(scope).as_bytes())?;
    let mut seen = HashSet::new();
    let mut wraps = Vec::new();
    for r in recipients {
        let user = r["user_id"].as_str().filter(|u| id_ok(u));
        let kv = r.get("key_version").and_then(as_int).filter(|k| *k >= 1);
        let (Some(user), Some(kv)) = (user, kv) else { return Err(err("BAD_RECIPIENTS", "Invalid recipient")) };
        if !seen.insert(user) {
            return Err(err("BAD_RECIPIENTS", "Duplicate recipient"));
        }
        let context = wrap_context(scope, user, kv);
        match r["kem_pub"].as_str().filter(|k| !k.is_empty()) {
            Some(kem) => {
                let s = kem_seal(kem, &content_key[..], &context)?;
                wraps.push(json!({ "u": user, "kv": kv, "kct": s["kct"], "iv": s["iv"], "wk": s["ct"] }));
            }
            None => {
                let s = seal_to(str_of(r, "ecdh_pub"), &content_key[..], &context)?;
                wraps.push(json!({ "u": user, "kv": kv, "epk": s["epk"], "iv": s["iv"], "wk": s["ct"] }));
            }
        }
    }
    let v = if wraps.iter().any(|w| w.get("kct").is_some()) { ENVELOPE_VERSION } else { 2 };
    Ok(json!({ "v": v, "iv": to_b64(&iv), "ct": to_b64(&ct), "kc": to_b64(&key_commitment(scope, &content_key[..])), "wraps": wraps }))
}

/// Open an envelope for `user_id` with its keyring. Errors carry the JavaScript codes.
pub fn decrypt_envelope(scope: &Value, envelope: &Value, user_id: &str, keyring: &Value) -> Result<Value> {
    check_scope(scope)?;
    let parsed;
    let env = match envelope.as_str() {
        Some(text) => {
            parsed = parse_envelope(text)?;
            &parsed
        }
        None => validate_envelope(envelope)?,
    };
    let wrap = env["wraps"].as_array().unwrap().iter().find(|w| w["u"] == user_id).ok_or_else(|| err("NOT_ADDRESSED", "This item wasn't encrypted for your account."))?;
    let kv = as_int(&wrap["kv"]).unwrap();
    let key = key_for_version(keyring, kv).ok_or_else(|| err("KEY_VERSION_MISSING", "This item was encrypted to an account key this device doesn't hold."))?;
    let context = wrap_context(scope, user_id, kv);
    let unwrap = || -> Result<Zeroizing<Vec<u8>>> {
        if wrap.get("kct").is_some() {
            let kem = key["kem_priv"].as_str().ok_or_else(|| err("BAD_FORMAT", "no post-quantum key"))?;
            kem_open(kem, &json!({ "kct": wrap["kct"], "iv": wrap["iv"], "ct": wrap["wk"] }), &context)
        } else {
            let sk = secret_from_pkcs8(str_of(key, "ecdh_priv"))?;
            open_sealed(&sk, str_of(key, "ecdh_pub"), &json!({ "epk": wrap["epk"], "iv": wrap["iv"], "ct": wrap["wk"] }), &context)
        }
    };
    let content_key = unwrap().map_err(|_| err("UNWRAP_FAILED", "This item's key failed its integrity check."))?;
    if content_key.len() != 32 {
        return Err(err("UNWRAP_FAILED", "This item's key is malformed."));
    }
    if !equal_bytes(&key_commitment(scope, &content_key), &from_b64(str_of(env, "kc"))?) {
        return Err(err("KEY_COMMITMENT_FAILED", "This item's key doesn't match the one its sender committed to."));
    }
    let plain = aes_decrypt(&content_key, &from_b64(str_of(env, "iv"))?, &from_b64(str_of(env, "ct"))?, content_context(scope).as_bytes())
        .map_err(|_| err("DECRYPT_FAILED", "This item failed its integrity check."))?;
    let text = std::str::from_utf8(&plain).map_err(|_| err("DECRYPT_FAILED", "This item's contents are malformed."))?;
    serde_json::from_str(text).map_err(|_| err("DECRYPT_FAILED", "This item's contents are malformed."))
}
