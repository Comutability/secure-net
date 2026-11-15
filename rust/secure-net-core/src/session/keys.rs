//! Accounts, devices and prekeys (CVP-016, "Devices" and "Bundles").
//!
//! An account is one quantum-resistant signing key. It signs the account's device list. Each
//! device has its own signing key and X25519 identity key, and publishes prekeys signed by its
//! signing key. Nothing a site serves is trusted unless it chains back to the account key.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bytes::{random_b64u, sha256, sha256_b64u};
use crate::canonical::canonical_bytes;
use crate::error::{Error, Result};
use crate::session::primitives::{dh_key_pair, kem_key_pair, KeyPair};
use crate::signed::{sign, verify, SigningKey};

pub const DEVICE_LIST: &str = "session.device-list";
pub const PREKEY: &str = "session.prekey";
const DAY: i64 = 86_400_000;
pub const SIGNED_PREKEY_LIFETIME: i64 = 30 * DAY;

/// A device with its secrets, as the JavaScript holds it: `{ kid, sign, dh }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub kid: String,
    pub sign: SigningKey,
    pub dh: KeyPair,
}

/// A new account key (quantum-resistant).
pub fn create_account() -> SigningKey {
    SigningKey::generate(true)
}

/// A new device: a signing key and an X25519 identity key.
pub fn create_device() -> Device {
    let sign = SigningKey::generate(true);
    Device { kid: sign.kid.clone(), sign, dh: dh_key_pair() }
}

/// What others may know about a device: `{ kid, sign, dh }` with public keys only.
pub fn device_public(device: &Device) -> Value {
    json!({ "kid": device.kid, "sign": device.sign.public_key, "dh": device.dh.pk })
}

fn bad(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

/// The account's device list, signed by the account key. `devices` are public device objects.
pub fn sign_device_list(account: &SigningKey, devices: Vec<Value>, seq: i64, now: i64) -> Result<Value> {
    if seq < 1 {
        return Err(bad("BAD_INPUT", "seq must be a positive integer"));
    }
    sign(DEVICE_LIST, &json!({ "account": account.public_key, "devices": devices, "seq": seq, "issued": now }), account)
}

/// Check a device list against the account key you trust for that person. Returns its body.
pub fn verify_device_list(record: &Value, account_key: &str, min_seq: i64) -> Result<Value> {
    let kid = record["sig"]["kid"].as_str().unwrap_or("").to_string();
    let body = verify(record, |k| (k == kid).then(|| account_key.to_string()), Some(&[DEVICE_LIST]))
        .map_err(|e| if ["MALFORMED", "WRONG_KIND", "UNKNOWN_SIGNER", "BAD_SIGNATURE", "BAD_KIND", "NOT_CANONICAL"].contains(&e.code) { Error::new("UNTRUSTED", format!("Device list: {}", e.message)) } else { e })?;
    if body["account"].as_str() != Some(account_key) {
        return Err(bad("UNTRUSTED", "Device list is for a different account"));
    }
    if !body["seq"].as_i64().is_some_and(|s| s >= min_seq) {
        return Err(bad("ROLLBACK", "Device list is older than one already seen"));
    }
    if !body["devices"].as_array().is_some_and(|d| !d.is_empty()) {
        return Err(bad("BAD_INPUT", "Device list is empty"));
    }
    Ok(body.clone())
}

fn digits(bytes: &[u8], groups: usize) -> String {
    (0..groups)
        .map(|i| format!("{:05}", u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()) % 100_000))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The code both devices show while linking a new one.
pub fn link_code(sign_public: &str, dh_public: &str) -> String {
    digits(&sha256(format!("secure-net/session/v1/link\n{sign_public}\n{dh_public}").as_bytes()), 6)
}

/// The safety number two people compare to know they have each other's real account keys.
pub fn safety_number(account_key_a: &str, account_key_b: &str) -> String {
    let (a, b) = if account_key_a <= account_key_b { (account_key_a, account_key_b) } else { (account_key_b, account_key_a) };
    digits(&sha256(format!("secure-net/session/v1/safety\n{a}\n{b}").as_bytes()), 8)
}

/// Prekeys and their secrets. `secrets` maps prekey id to `{ type, sk, pk, ... }`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Prekeys {
    pub secrets: Map<String, Value>,
    pub published: Published,
}

/// What a device publishes to its site.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Published {
    pub signed: Value,
    #[serde(rename = "lastResort")]
    pub last_resort: Value,
    #[serde(rename = "oneTime")]
    pub one_time: Vec<Value>,
    #[serde(rename = "pqOneTime")]
    pub pq_one_time: Vec<Value>,
}

fn make(device: &Device, secrets: &mut Map<String, Value>, kind: &str, extra: Value) -> Result<Value> {
    let pair = if kind == "x25519" { dh_key_pair() } else { kem_key_pair() };
    let id = random_b64u(9);
    let mut secret = json!({ "type": kind, "sk": pair.sk, "pk": pair.pk });
    let mut body = json!({ "device": device.kid, "type": kind, "id": id, "pub": pair.pk });
    for (k, v) in extra.as_object().into_iter().flatten() {
        secret[k] = v.clone();
        body[k] = v.clone();
    }
    secrets.insert(id, secret);
    sign(PREKEY, &body, &device.sign)
}

/// Prekeys for a device: a signed X25519 prekey, a last-resort ML-KEM-768 prekey, and one-time
/// X25519 and ML-KEM-768 prekeys. `sessions` is the highest session version the device speaks.
pub fn create_prekeys(device: &Device, one_time: usize, pq_one_time: usize, now: i64, sessions: i64) -> Result<Prekeys> {
    let mut secrets = Map::new();
    let expires = now + SIGNED_PREKEY_LIFETIME;
    let signed_extra = if sessions > 1 { json!({ "expires": expires, "sessions": sessions }) } else { json!({ "expires": expires }) };
    let signed = make(device, &mut secrets, "x25519", signed_extra)?;
    let last_resort = make(device, &mut secrets, "ml-kem-768", json!({ "expires": expires, "lastResort": true }))?;
    let one = (0..one_time).map(|_| make(device, &mut secrets, "x25519", json!({ "oneTime": true }))).collect::<Result<Vec<_>>>()?;
    let pq = (0..pq_one_time).map(|_| make(device, &mut secrets, "ml-kem-768", json!({ "oneTime": true }))).collect::<Result<Vec<_>>>()?;
    Ok(Prekeys { secrets, published: Published { signed, last_resort, one_time: one, pq_one_time: pq } })
}

/// What a site hands out for one device, taking one-time prekeys from `published` as a site would.
pub fn take_bundle(device_list: &Value, published: &mut Published, kid: &str) -> Value {
    let pq = if published.pq_one_time.is_empty() { published.last_resort.clone() } else { published.pq_one_time.remove(0) };
    let one = if published.one_time.is_empty() { Value::Null } else { published.one_time.remove(0) };
    json!({ "deviceList": device_list, "device": kid, "signed": published.signed, "pq": pq, "oneTime": one })
}

/// A bundle after checking: the device list body, the device, and the prekey bodies.
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    pub list: Value,
    pub device: Value,
    pub signed: Value,
    pub pq: Value,
    pub one_time: Option<Value>,
}

/// Check a bundle: everything must chain back to the account key you trust.
pub fn verify_bundle(bundle: &Value, account_key: &str, min_seq: i64, now: i64) -> Result<VerifiedBundle> {
    let list = verify_device_list(&bundle["deviceList"], account_key, min_seq)?;
    let want = bundle["device"].as_str().unwrap_or("");
    let dev = list["devices"].as_array().into_iter().flatten().find(|d| d["kid"].as_str() == Some(want)).cloned().ok_or_else(|| bad("UNTRUSTED", "That device isn't on the account's device list"))?;
    let dev_kid = dev["kid"].as_str().unwrap_or("").to_string();
    let dev_sign = dev["sign"].as_str().unwrap_or("").to_string();
    let check = |rec: &Value, kind: &str, optional: bool| -> Result<Option<Value>> {
        if rec.is_null() {
            return if optional { Ok(None) } else { Err(Error::new("BAD_INPUT", format!("Bundle is missing a {kind} prekey"))) };
        }
        let body = verify(rec, |k| (k == dev_kid).then(|| dev_sign.clone()), Some(&[PREKEY])).map_err(|e| Error::new("UNTRUSTED", format!("Prekey: {}", e.message)))?;
        if body["device"].as_str() != Some(dev_kid.as_str()) || body["type"].as_str() != Some(kind) {
            return Err(bad("UNTRUSTED", "Prekey is for a different device or of the wrong type"));
        }
        if body["expires"].as_i64().is_some_and(|e| e < now) {
            return Err(bad("EXPIRED", "Prekey has expired"));
        }
        Ok(Some(body.clone()))
    };
    let truthy = |v: &Value| !matches!(v, Value::Null | Value::Bool(false));
    let signed = check(&bundle["signed"], "x25519", false)?.unwrap();
    if truthy(&signed["oneTime"]) {
        return Err(bad("BAD_INPUT", "Signed prekey must not be one-time"));
    }
    let pq = check(&bundle["pq"], "ml-kem-768", false)?.unwrap();
    if !truthy(&pq["oneTime"]) && !truthy(&pq["lastResort"]) {
        return Err(bad("BAD_INPUT", "ML-KEM prekey must be one-time or last-resort"));
    }
    let one_time = check(&bundle["oneTime"], "x25519", true)?;
    if one_time.as_ref().is_some_and(|o| !truthy(&o["oneTime"])) {
        return Err(bad("BAD_INPUT", "One-time prekey isn't marked one-time"));
    }
    Ok(VerifiedBundle { list, device: dev, signed, pq, one_time })
}

/// A stable fingerprint of a device list (for logs and UIs, never for trust).
pub fn device_list_id(record: &Value) -> Result<String> {
    Ok(sha256_b64u(&canonical_bytes(&record["body"])?)[..22].to_string())
}
