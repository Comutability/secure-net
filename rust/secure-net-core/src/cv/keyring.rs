//! The account keyring (`src/crypto/keyring.js`): every version of an account's P-256 encryption
//! and signing key pairs, and from November 2026 a post-quantum key pair per new version.
//! Keyrings travel as JSON, so they're handled as `serde_json::Value` with the same checks.
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::encoding::{from_b64, iso_from_ms};
use super::kem::{is_kem_sealed, kem_keygen, kem_open, kem_public_from_secret, kem_seal, KEM_PUBLIC_BYTES, KEM_SEED_BYTES};
use super::primitives::{generate_pair, open_sealed, public_from_b64, raw_public, seal_to, secret_from_pkcs8};
use crate::error::{Error, Result};

pub const KEYRING_FORMAT: &str = "commonveil.keyring.v1";
const MAX_VERSIONS: usize = 256;

fn format(msg: impl Into<String>) -> Error {
    Error::new("BAD_FORMAT", msg)
}

/// A new key version (classical pairs and a post-quantum pair). `now` is milliseconds.
pub fn create_key_version(version: i64, now: i64) -> Result<Value> {
    if version < 1 {
        return Err(format("Invalid key version"));
    }
    let (ecdh_priv, ecdh_pub) = generate_pair()?;
    let (sign_priv, sign_pub) = generate_pair()?;
    let kem = kem_keygen(None)?;
    Ok(json!({
        "version": version,
        "ecdh_priv": ecdh_priv, "ecdh_pub": ecdh_pub,
        "sign_priv": sign_priv, "sign_pub": sign_pub,
        "kem_priv": kem["kem_priv"], "kem_pub": kem["kem_pub"],
        "created_at": iso_from_ms(now)?,
    }))
}

pub fn new_keyring(user_id: &str, first: Value) -> Result<Value> {
    let k = json!({ "format": KEYRING_FORMAT, "user_id": user_id, "versions": [first] });
    validate_keyring(&k, Some(user_id))?;
    Ok(k)
}

pub fn versions(keyring: &Value) -> &[Value] {
    keyring["versions"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

pub fn latest_key(keyring: &Value) -> Result<&Value> {
    versions(keyring).last().ok_or_else(|| format("Keyring has no keys"))
}

pub fn latest_version(keyring: &Value) -> Result<i64> {
    latest_key(keyring)?["version"].as_i64().ok_or_else(|| format("Keyring has no keys"))
}

pub fn key_for_version(keyring: &Value, version: i64) -> Option<&Value> {
    versions(keyring).iter().find(|v| v["version"].as_i64() == Some(version))
}

/// A new keyring with one more version. Versions go up by exactly one.
pub fn with_version(keyring: &Value, key_version: Value) -> Result<Value> {
    if key_version["version"].as_i64() != Some(latest_version(keyring)? + 1) {
        return Err(format("Key versions must increase by exactly one"));
    }
    let mut next = keyring.clone();
    next["versions"].as_array_mut().expect("validated").push(key_version);
    validate_keyring(&next, keyring["user_id"].as_str())?;
    Ok(next)
}

fn is_b64(v: &Value, len: Option<usize>) -> bool {
    match v.as_str() {
        Some(s) if !s.is_empty() => from_b64(s).is_ok_and(|b| len.is_none_or(|l| b.len() == l)),
        _ => false,
    }
}

/// Whole-number check that also accepts JSON numbers written as `2.0`, as JavaScript does.
pub fn as_int(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).map(|f| f as i64))
}

pub fn validate_keyring<'a>(keyring: &'a Value, expected_user: Option<&str>) -> Result<&'a Value> {
    if !keyring.is_object() || keyring["format"] != KEYRING_FORMAT {
        return Err(format("Unknown keyring format"));
    }
    let owner = keyring["user_id"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| format("Keyring has no owner"))?;
    if let Some(u) = expected_user.filter(|u| !u.is_empty()) {
        if owner != u {
            return Err(format("Keyring belongs to a different account"));
        }
    }
    let vs = keyring["versions"].as_array().filter(|v| !v.is_empty() && v.len() <= MAX_VERSIONS).ok_or_else(|| format("Keyring has no keys"))?;
    let first = as_int(&vs[0]["version"]).ok_or_else(|| format("Keyring versions are not contiguous"))?;
    for (i, v) in vs.iter().enumerate() {
        let n = as_int(&v["version"]);
        if n != Some(first + i as i64) {
            return Err(format("Keyring versions are not contiguous"));
        }
        let n = n.unwrap();
        for f in ["ecdh_priv", "ecdh_pub", "sign_priv", "sign_pub"] {
            if !is_b64(&v[f], None) {
                return Err(format(format!("Keyring version {n} is missing {f}")));
            }
        }
        let has_any = v.get("kem_priv").is_some() || v.get("kem_pub").is_some();
        if has_any && (!is_b64(&v["kem_priv"], Some(KEM_SEED_BYTES)) || !is_b64(&v["kem_pub"], Some(KEM_PUBLIC_BYTES))) {
            return Err(format(format!("Keyring version {n} has a malformed post-quantum key")));
        }
    }
    Ok(keyring)
}

pub fn has_kem_key(v: &Value) -> bool {
    v["kem_pub"].as_str().is_some_and(|s| !s.is_empty())
}

pub fn serialize_keyring(keyring: &Value) -> Result<String> {
    validate_keyring(keyring, None)?;
    serde_json::to_string(keyring).map_err(|_| format("Keyring is not valid JSON"))
}

pub fn parse_keyring(text: &str, expected_user: Option<&str>) -> Result<Value> {
    let v: Value = serde_json::from_str(text).map_err(|_| format("Keyring is not valid JSON"))?;
    validate_keyring(&v, expected_user)?;
    Ok(v)
}

/// Every private key matches the public key listed with it.
pub fn assert_keyring_consistent(keyring: &Value) -> Result<()> {
    for v in versions(keyring) {
        let n = v["version"].as_i64().unwrap_or(0);
        for (p, q) in [("ecdh_priv", "ecdh_pub"), ("sign_priv", "sign_pub")] {
            let sk = secret_from_pkcs8(v[p].as_str().unwrap_or(""))?;
            let pk = public_from_b64(v[q].as_str().unwrap_or(""))?;
            if raw_public(&sk.public_key()) != raw_public(&pk) {
                return Err(format(format!("Keyring version {n} has mismatched keys")));
            }
        }
        if has_kem_key(v) && kem_public_from_secret(v["kem_priv"].as_str().unwrap_or(""))? != v["kem_pub"].as_str().unwrap_or("") {
            return Err(format(format!("Keyring version {n} has a mismatched post-quantum key")));
        }
    }
    Ok(())
}

/// Seal to a recipient: post-quantum when they have a post-quantum key, classical otherwise.
pub fn seal_to_recipient(ecdh_pub: &str, kem_pub: Option<&str>, plaintext: &[u8], context: &str) -> Result<Value> {
    match kem_pub.filter(|k| !k.is_empty()) {
        Some(k) => kem_seal(k, plaintext, context),
        None => seal_to(ecdh_pub, plaintext, context),
    }
}

/// Open something sealed with `seal_to_recipient`, given the PKCS#8 ECDH key and the KEM seed.
pub fn open_from_sender(ecdh_priv: Option<&str>, ecdh_pub: &str, kem_priv: Option<&str>, sealed: &Value, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    if is_kem_sealed(sealed) {
        let k = kem_priv.filter(|k| !k.is_empty()).ok_or_else(|| format("Sealed to a post-quantum key this device doesn't have"))?;
        return kem_open(k, sealed, context);
    }
    let sk = secret_from_pkcs8(ecdh_priv.ok_or_else(|| format("No private key"))?)?;
    open_sealed(&sk, ecdh_pub, sealed, context)
}

pub fn device_transfer_context(user_id: &str, device_id: &str, version: i64) -> String {
    format!("commonveil/keyring-to-device/v1|{user_id}|{device_id}|{version}")
}

pub fn recovery_context(user_id: &str, version: i64) -> String {
    format!("commonveil/keyring-recovery/v1|{user_id}|{version}")
}

/// Seal the keyring to another device (to its post-quantum key when one is given and verified).
pub fn seal_keyring_to_device(keyring: &Value, device_id: &str, box_pub: &str, kem_pub: Option<&str>) -> Result<Value> {
    let version = latest_version(keyring)?;
    let user = keyring["user_id"].as_str().unwrap_or("");
    let sealed = seal_to_recipient(box_pub, kem_pub, serialize_keyring(keyring)?.as_bytes(), &device_transfer_context(user, device_id, version))?;
    Ok(json!({ "keyring_version": version, "sealed": sealed }))
}

pub struct OpenFromDevice<'a> {
    pub box_priv: &'a str,
    pub box_pub: &'a str,
    pub kem_priv: Option<&'a str>,
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub keyring_version: i64,
    pub sealed: &'a Value,
}

pub fn open_keyring_from_device(a: OpenFromDevice) -> Result<Value> {
    let bytes = open_from_sender(Some(a.box_priv), a.box_pub, a.kem_priv, a.sealed, &device_transfer_context(a.user_id, a.device_id, a.keyring_version))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| format("Keyring is not valid JSON"))?;
    let keyring = parse_keyring(text, Some(a.user_id))?;
    if latest_version(&keyring)? != a.keyring_version {
        return Err(format("Keyring version mismatch"));
    }
    assert_keyring_consistent(&keyring)?;
    Ok(keyring)
}

/// Seal the keyring to the recovery key: the phrase's post-quantum key when the account has one.
pub fn seal_keyring_for_recovery(keyring: &Value, recovery_pub: &str, recovery_kem_pub: Option<&str>) -> Result<Value> {
    let version = latest_version(keyring)?;
    let user = keyring["user_id"].as_str().unwrap_or("");
    let sealed = seal_to_recipient(recovery_pub, recovery_kem_pub, serialize_keyring(keyring)?.as_bytes(), &recovery_context(user, version))?;
    Ok(json!({ "keyring_version": version, "sealed": sealed }))
}
