//! Account identity (`src/crypto/identity.js`): signed key statements and the hash chain over an
//! account's key history, pins, device certificates, device proofs, item signatures, safety
//! numbers and device-link codes.
use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::canonical::{cert_text, device_kem_text, device_proof_text, has_kem, item_text, statement_text};
use super::encoding::{iso_from_ms, random_id, sha256_b64, to_b64};
use super::kem::is_kem_public;
use super::keyring::{as_int, latest_version, versions};
use super::primitives::{sign_with_pkcs8, verify_with_raw};
use crate::bytes::sha256;
use crate::error::{Error, Result};

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

/// A statement for one account key version. `signer` is the same version (first key, reset) or
/// the previous one (rotation). Versions with a post-quantum key publish it, and the recovery
/// phrase's post-quantum key if the account has one.
pub fn make_account_statement(user_id: &str, key_version: &Value, recovery_pub: &str, recovery_kem_pub: &str, signer: &Value, now: i64) -> Result<Value> {
    let mut st = json!({
        "user_id": user_id,
        "version": key_version["version"],
        "ecdh_pub": key_version["ecdh_pub"],
        "sign_pub": key_version["sign_pub"],
        "recovery_pub": recovery_pub,
        "signed_by_version": signer["version"],
        "issued_at": iso_from_ms(now)?,
    });
    if has_kem(key_version) {
        st["kem_pub"] = key_version["kem_pub"].clone();
        st["recovery_kem_pub"] = json!(recovery_kem_pub);
    }
    st["signature"] = json!(sign_with_pkcs8(str_of(signer, "sign_priv"), statement_text(&st)?.as_bytes())?);
    Ok(st)
}

fn next_digest(previous: &str, st: &Value) -> Result<String> {
    let sig = st.get("signature").map(super::canonical::js_string).unwrap_or_else(|| "undefined".into());
    Ok(to_b64(&sha256(format!("commonveil/chain-digest/v1\n{previous}\n{}\n{sig}", statement_text(st)?).as_bytes())))
}

/// A verified key history.
#[derive(Debug, Clone)]
pub struct Chain {
    pub user_id: String,
    /// Sorted by version; version n is at index n - 1.
    pub statements: Vec<Value>,
    pub root_version: i64,
    pub digests: BTreeMap<i64, String>,
}

impl Chain {
    pub fn latest(&self) -> &Value {
        self.statements.last().expect("a chain has at least one statement")
    }
    pub fn latest_version(&self) -> i64 {
        self.statements.len() as i64
    }
    pub fn by_version(&self, v: i64) -> Option<&Value> {
        usize::try_from(v - 1).ok().and_then(|i| self.statements.get(i))
    }
    pub fn head_digest(&self) -> &str {
        &self.digests[&self.latest_version()]
    }
    pub fn to_json(&self) -> Value {
        json!({
            "userId": self.user_id,
            "latest": self.latest(),
            "rootVersion": self.root_version,
            "digests": self.digests.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),
            "statements": self.statements,
        })
    }
}

/// Verify an account's whole published key history.
pub fn verify_account_chain(user_id: &str, statements: &[Value]) -> Result<Chain> {
    if statements.is_empty() {
        return Err(err("NO_KEYS", "This member hasn't set up encryption yet."));
    }
    let mut sorted = statements.to_vec();
    sorted.sort_by(|a, b| a["version"].as_f64().unwrap_or(f64::NAN).total_cmp(&b["version"].as_f64().unwrap_or(f64::NAN)));
    let mut digests = BTreeMap::new();
    let mut digest = String::new();
    for (i, st) in sorted.iter().enumerate() {
        if st["user_id"] != user_id {
            return Err(err("WRONG_USER", "A key statement belongs to someone else."));
        }
        let version = as_int(&st["version"]).filter(|v| *v == i as i64 + 1).ok_or_else(|| err("VERSION_GAP", "This member's key history has a gap."))?;
        let by = as_int(&st["signed_by_version"]);
        let self_signed = by == Some(version);
        if !self_signed && by != Some(version - 1) {
            return Err(err("BAD_CHAIN", "This member's key history is out of order."));
        }
        if has_kem(st) {
            let rk = st["recovery_kem_pub"].as_str().unwrap_or("");
            if !is_kem_public(str_of(st, "kem_pub")) || (!rk.is_empty() && !is_kem_public(rk)) {
                return Err(err("BAD_KEY", "A published post-quantum key is malformed."));
            }
        }
        let signer = if self_signed { st } else { &sorted[i - 1] };
        let sig = st["signature"].as_str().unwrap_or("");
        if !verify_with_raw(str_of(signer, "sign_pub"), sig, &statement_text(st)?) {
            return Err(err("BAD_SIGNATURE", "A published key statement failed its signature check."));
        }
        digest = next_digest(&digest, st)?;
        digests.insert(version, digest.clone());
    }
    let mut root = sorted.len() as i64;
    while as_int(&sorted[(root - 1) as usize]["signed_by_version"]) != Some(root) {
        root -= 1;
    }
    Ok(Chain { user_id: user_id.into(), statements: sorted, root_version: root, digests })
}

/// "new", "same", "rotated" or "changed": a verified chain against what this device pinned.
pub fn compare_with_pin(chain: &Chain, pin: &Value) -> &'static str {
    if pin.is_null() {
        return "new";
    }
    let Some(pv) = as_int(&pin["version"]) else { return "changed" };
    let Some(pinned) = chain.by_version(pv) else { return "changed" };
    if pv < chain.root_version {
        return "changed";
    }
    match pin["digest"].as_str().filter(|d| !d.is_empty()) {
        Some(d) => {
            if chain.digests.get(&pv).map(String::as_str) != Some(d) {
                "changed"
            } else if pv == chain.latest_version() {
                "same"
            } else {
                "rotated"
            }
        }
        None if pinned["sign_pub"] == pin["sign_pub"] => "rotated",
        None => "changed",
    }
}

pub fn pin_from_chain(chain: &Chain, verified: bool, now: i64) -> Result<Value> {
    Ok(json!({
        "version": chain.latest_version(),
        "digest": chain.head_digest(),
        "sign_pub": chain.latest()["sign_pub"],
        "statements": chain.statements,
        "verified": verified,
        "pinned_at": iso_from_ms(now)?,
    }))
}

/// A published statement and a keyring version carry the same public keys.
pub fn same_keys(st: &Value, v: &Value) -> bool {
    let kem = |x: &Value| x["kem_pub"].as_str().unwrap_or("").to_string();
    st.is_object() && v.is_object() && st["ecdh_pub"] == v["ecdh_pub"] && st["sign_pub"] == v["sign_pub"] && kem(st) == kem(v)
}

/// Check a chain against what only this account's own devices can vouch for: a keyring this
/// device holds, or the history it showed in its link code. Returns the anchor version.
pub fn anchor_chain(chain: &Chain, keyring: Option<&Value>, pin: Option<&Value>) -> Result<i64> {
    let anchor = if let Some(k) = keyring {
        for v in versions(k) {
            let st = as_int(&v["version"]).and_then(|n| chain.by_version(n)).ok_or_else(|| {
                err("KEYS_ROLLED_BACK", "Your account's published keys are older than the keys on this device. Don't send anything until this is sorted out.")
            })?;
            if !same_keys(st, v) {
                return Err(err("KEYRING_MISMATCH", "Your account's published keys don't match the keys on this device. Don't send anything until this is sorted out."));
            }
        }
        latest_version(k)?
    } else if let Some((pv, d)) = pin.and_then(|p| Some((as_int(&p["version"])?, p["digest"].as_str().filter(|d| !d.is_empty())?))) {
        if chain.digests.get(&pv).map(String::as_str) != Some(d) {
            return Err(err("ANCHOR_MISMATCH", "Your account's keys aren't the ones this device showed in its link code, so they weren't accepted."));
        }
        pv
    } else {
        return Err(err("NO_ANCHOR", "This device can't confirm where these keys came from. Set it up again."));
    };
    if chain.root_version > anchor {
        return Err(err("ACCOUNT_RESET", "Your account's encryption was reset from another device, so the keys in this browser no longer apply."));
    }
    Ok(anchor)
}

pub fn assert_keyring_matches_chain(keyring: &Value, chain: &Chain) -> Result<()> {
    for v in versions(keyring) {
        let st = as_int(&v["version"]).and_then(|n| chain.by_version(n));
        if !st.is_some_and(|st| same_keys(st, v)) {
            return Err(err("KEYRING_MISMATCH", "These keys don't match the keys published for this account."));
        }
    }
    if latest_version(keyring)? != chain.latest_version() {
        return Err(err("KEYRING_STALE", "This copy of the account keys is out of date."));
    }
    Ok(())
}

/// A certificate for a device's keys under one account key version. `kem_pub` only when the
/// caller has verified it belongs to the device.
pub fn make_device_cert(user_id: &str, device: &Value, key_version: &Value, kem_pub: &str, now: i64) -> Result<Value> {
    let mut cert = json!({
        "user_id": user_id,
        "device_id": device["device_id"],
        "sign_pub": device["sign_pub"],
        "box_pub": device["box_pub"],
        "key_version": key_version["version"],
        "issued_at": iso_from_ms(now)?,
    });
    if !kem_pub.is_empty() {
        cert["kem_pub"] = json!(kem_pub);
    }
    cert["signature"] = json!(sign_with_pkcs8(str_of(key_version, "sign_priv"), cert_text(&cert)?.as_bytes())?);
    Ok(cert)
}

pub fn verify_device_cert(cert: &Value, chain: &Chain) -> bool {
    let Some(signer) = as_int(&cert["key_version"]).and_then(|v| chain.by_version(v)) else { return false };
    if cert["user_id"] != chain.user_id.as_str() {
        return false;
    }
    match cert_text(cert) {
        Ok(text) => verify_with_raw(str_of(signer, "sign_pub"), str_of(cert, "signature"), &text),
        Err(_) => false,
    }
}

/// A device's own signature over its post-quantum key.
pub fn sign_device_kem(user_id: &str, device: &Value) -> Result<String> {
    let text = device_kem_text(user_id, str_of(device, "device_id"), str_of(device, "kem_pub"))?;
    sign_with_pkcs8(str_of(device, "sign_priv"), text.as_bytes())
}

pub fn verify_device_kem(user_id: &str, device_id: &str, sign_pub: &str, kem_pub: &str, signature: &str) -> bool {
    is_kem_public(kem_pub) && device_kem_text(user_id, device_id, kem_pub).is_ok_and(|t| verify_with_raw(sign_pub, signature, &t))
}

/// Proof that a request comes from this device. `payload_json` is hashed as sent.
pub fn make_device_proof(user_id: &str, device: &Value, action: &str, payload_json: &str, now: i64) -> Result<Value> {
    let issued_at = iso_from_ms(now)?;
    let nonce = random_id(12);
    let text = device_proof_text(&json!({
        "user_id": user_id, "device_id": device["device_id"], "action": action,
        "payload_hash": sha256_b64(payload_json), "issued_at": issued_at, "nonce": nonce,
    }))?;
    Ok(json!({ "device_id": device["device_id"], "issued_at": issued_at, "nonce": nonce, "signature": sign_with_pkcs8(str_of(device, "sign_priv"), text.as_bytes())? }))
}

/// Check a device proof (what the server does).
pub fn verify_device_proof(user_id: &str, sign_pub: &str, action: &str, payload_json: &str, proof: &Value) -> bool {
    let fields = json!({
        "user_id": user_id, "device_id": proof["device_id"], "action": action,
        "payload_hash": sha256_b64(payload_json), "issued_at": proof["issued_at"], "nonce": proof["nonce"],
    });
    device_proof_text(&fields).is_ok_and(|t| verify_with_raw(sign_pub, str_of(proof, "signature"), &t))
}

/// item: `{ kind, conversationId, itemId, senderId, deviceId, envelopeJson, sentAt }`.
fn item_text_of(item: &Value) -> Result<String> {
    item_text(&json!({
        "kind": item["kind"], "conversation_id": item["conversationId"], "item_id": item["itemId"],
        "sender_id": item["senderId"], "device_id": item["deviceId"],
        "envelope_hash": sha256_b64(str_of(item, "envelopeJson")), "sent_at": item["sentAt"],
    }))
}

pub fn sign_item(sign_priv: &str, item: &Value) -> Result<String> {
    sign_with_pkcs8(sign_priv, item_text_of(item)?.as_bytes())
}

pub fn verify_item(sign_pub: &str, signature: &str, item: &Value) -> bool {
    item_text_of(item).is_ok_and(|t| verify_with_raw(sign_pub, signature, &t))
}

fn digit_groups(bytes: &[u8], groups: usize, per: usize, modulo: u64, width: usize) -> String {
    (0..groups)
        .map(|i| {
            let n = bytes[i * per..(i + 1) * per].iter().fold(0u64, |n, b| n * 256 + u64::from(*b));
            format!("{:0width$}", n % modulo)
        })
        .collect()
}

/// 30 digits for one account, covering its whole key history.
pub fn safety_fingerprint(user_id: &str, digest: &str) -> Result<String> {
    if digest.is_empty() {
        return Err(err("NO_KEYS", "No key history to fingerprint."));
    }
    let mut h = sha256(format!("commonveil/safety/v2|{user_id}|{digest}").as_bytes());
    for _ in 0..4096 {
        h = sha256(&[&h[..], digest.as_bytes()].concat());
    }
    Ok(digit_groups(&h, 6, 5, 100_000, 5))
}

/// JavaScript's `<` on strings: UTF-16 code units.
pub fn js_less(a: &str, b: &str) -> bool {
    a.encode_utf16().lt(b.encode_utf16())
}

/// 60 digits for a pair of accounts, the same on both sides.
pub fn safety_number(a: (&str, &str), b: (&str, &str)) -> Result<String> {
    let (first, second) = if js_less(b.0, a.0) { (b, a) } else { (a, b) };
    Ok(safety_fingerprint(first.0, first.1)? + &safety_fingerprint(second.0, second.1)?)
}

pub struct LinkCode<'a> {
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub sign_pub: &'a str,
    pub box_pub: &'a str,
    pub kem_pub: &'a str,
    pub account_digest: &'a str,
}

/// 20 digits shown on both devices while linking.
pub fn link_code(c: LinkCode) -> Result<String> {
    if c.account_digest.is_empty() {
        return Err(err("NO_ANCHOR", "No account history for the link code."));
    }
    let text = if c.kem_pub.is_empty() {
        format!("commonveil/link-code/v2|{}|{}|{}|{}|{}", c.user_id, c.device_id, c.sign_pub, c.box_pub, c.account_digest)
    } else {
        format!("commonveil/link-code/v3|{}|{}|{}|{}|{}|{}", c.user_id, c.device_id, c.sign_pub, c.box_pub, c.kem_pub, c.account_digest)
    };
    Ok(digit_groups(&sha256(text.as_bytes()), 5, 2, 10_000, 4))
}

pub fn group_digits(digits: &str, size: usize) -> String {
    let chars: Vec<char> = digits.chars().collect();
    chars.chunks(size.max(1)).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}
