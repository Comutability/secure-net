//! The passcode lock (`src/crypto/lock.js`): PBKDF2-SHA-256 (600,000 rounds) turns a passcode
//! into an AES-256-GCM key that encrypts this device's copy of the account keys at rest.
//!
//! In a browser the JavaScript keeps that key as a non-extractable WebCrypto key. This API is
//! stateless, so `unlock` hands the key back as bytes for the caller to hold in memory: web
//! clients should keep using WebCrypto for the lock itself and use this for native clients and
//! for checking the two agree.
use pbkdf2::pbkdf2_hmac;
use serde_json::{json, Value};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::encoding::{from_b64, to_b64};
use super::keyring::as_int;
use super::primitives::{aes_decrypt, aes_encrypt};
use crate::bytes::random;
use crate::error::{Error, Result};

pub const LOCK_ITERATIONS: u32 = 600_000;
pub const MIN_PASSCODE_CHARS: usize = 8;
pub const IDLE_CHOICES: [i64; 3] = [5, 15, 60];
const CHECK: &str = "commonveil passcode check v1";

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn aad(purpose: &str) -> String {
    format!("commonveil-lock:{purpose}")
}

/// NFKC, then a length check counted the way JavaScript counts (UTF-16 code units).
pub fn check_passcode(passcode: &str) -> Result<String> {
    let p: String = passcode.nfkc().collect();
    let len = p.encode_utf16().count();
    if len < MIN_PASSCODE_CHARS {
        return Err(Error::new("TOO_SHORT", format!("Use at least {MIN_PASSCODE_CHARS} characters.")));
    }
    if len > 256 {
        return Err(err("TOO_LONG", "That passcode is too long."));
    }
    Ok(p)
}

fn check_record(record: &Value) -> Result<u32> {
    let it = record.get("iterations").and_then(as_int).filter(|i| (100_000..=10_000_000).contains(i));
    let ok = record["v"] == 1 && record["kdf"] == "PBKDF2-SHA256" && record["salt"].is_string() && record.get("check").is_some_and(|c| !c.is_null());
    match (ok, it) {
        (true, Some(i)) => Ok(i as u32),
        _ => Err(err("BAD_LOCK", "This browser's lock settings are damaged.")),
    }
}

pub fn derive_lock_key(passcode: &str, salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let p: Zeroizing<String> = Zeroizing::new(passcode.nfkc().collect());
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(p.as_bytes(), salt, iterations, &mut key[..]);
    key
}

pub fn seal_with_lock(key: &[u8], text: &str, purpose: &str) -> Result<Value> {
    let (iv, ct) = aes_encrypt(key, text.as_bytes(), aad(purpose).as_bytes())?;
    Ok(json!({ "iv": to_b64(&iv), "ct": to_b64(&ct) }))
}

pub fn open_with_lock(key: &[u8], sealed: &Value, purpose: &str) -> Result<Zeroizing<String>> {
    let wrong = || err("WRONG_PASSCODE", "That passcode isn't right.");
    let iv = from_b64(sealed["iv"].as_str().unwrap_or("-")).map_err(|_| wrong())?;
    let ct = from_b64(sealed["ct"].as_str().unwrap_or("-")).map_err(|_| wrong())?;
    let plain = aes_decrypt(key, &iv, &ct, aad(purpose).as_bytes()).map_err(|_| wrong())?;
    String::from_utf8(plain.to_vec()).map(Zeroizing::new).map_err(|_| wrong())
}

/// A new lock: the record to store and the key to keep while unlocked.
pub fn create_lock(passcode: &str, idle_minutes: i64, iterations: u32) -> Result<(Value, Zeroizing<[u8; 32]>)> {
    let p = Zeroizing::new(check_passcode(passcode)?);
    if !IDLE_CHOICES.contains(&idle_minutes) {
        return Err(err("BAD_IDLE", "Choose when to lock."));
    }
    let salt = random::<16>();
    let key = derive_lock_key(&p, &salt, iterations);
    let record = json!({
        "v": 1, "kdf": "PBKDF2-SHA256", "iterations": iterations, "salt": to_b64(&salt),
        "idle_minutes": idle_minutes, "check": seal_with_lock(&key[..], CHECK, "check")?,
    });
    Ok((record, key))
}

/// The key for a stored lock, if the passcode is right.
pub fn unlock(passcode: &str, record: &Value) -> Result<Zeroizing<[u8; 32]>> {
    let iterations = check_record(record)?;
    let salt = from_b64(record["salt"].as_str().unwrap_or("-")).map_err(|_| err("BAD_LOCK", "This browser's lock settings are damaged."))?;
    let key = derive_lock_key(passcode, &salt, iterations);
    if open_with_lock(&key[..], &record["check"], "check")?.as_str() != CHECK {
        return Err(err("WRONG_PASSCODE", "That passcode isn't right."));
    }
    Ok(key)
}

fn keyring_purpose(user_id: &str) -> String {
    format!("keyring:{user_id}")
}

pub fn seal_keyring_text(key: &[u8], user_id: &str, text: &str) -> Result<Value> {
    let mut sealed = seal_with_lock(key, text, &keyring_purpose(user_id))?;
    let mut out = json!({ "v": 1, "locked": true });
    out.as_object_mut().unwrap().append(sealed.as_object_mut().unwrap());
    Ok(out)
}

pub fn is_sealed_keyring(stored: &Value) -> bool {
    stored["locked"] == true
}

pub fn open_keyring_text(key: &[u8], user_id: &str, stored: &Value) -> Result<Zeroizing<String>> {
    open_with_lock(key, stored, &keyring_purpose(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_round_trip() {
        assert_eq!(check_passcode("short").unwrap_err().code, "TOO_SHORT");
        // Eight UTF-16 units: four characters outside the BMP count as two each.
        assert!(check_passcode("😀😀😀😀").is_ok());
        let (record, key) = create_lock("correct horse", 15, 100_000).unwrap();
        let again = unlock("correct horse", &record).unwrap();
        assert_eq!(&key[..], &again[..]);
        assert_eq!(unlock("wrong horse!", &record).unwrap_err().code, "WRONG_PASSCODE");
        let stored = seal_keyring_text(&key[..], "u1", "{}").unwrap();
        assert!(is_sealed_keyring(&stored));
        assert_eq!(open_keyring_text(&key[..], "u1", &stored).unwrap().as_str(), "{}");
        assert!(open_keyring_text(&key[..], "u2", &stored).is_err());
        let mut weak = record.clone();
        weak["iterations"] = json!(1000);
        assert_eq!(unlock("correct horse", &weak).unwrap_err().code, "BAD_LOCK");
    }
}
