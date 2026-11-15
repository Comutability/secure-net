//! The sealed relay (CVP-015), matching `src/wire/sealed.js`: site-to-site requests encrypted
//! with an ephemeral P-256 ECDH and ML-KEM-768 together (HKDF-SHA-256, AES-256-GCM), signed with
//! ML-DSA-65 alongside the site's Ed25519 signature, and replies sealed under a one-time key that
//! travels inside the request.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::bytes::{b64u, from_b64u, random, sha256};
use crate::cv::primitives::{ecdh, generate_pair, public_from_raw, random_secret, raw_public, secret_from_pkcs8};
use crate::error::{Error, Result};
use crate::session::primitives::{decapsulate, encapsulate, kem_key_pair};
use crate::signed::{mldsa_public, mldsa_sign, verify_mldsa};

pub const SUITE: &str = "p256-mlkem768+mldsa65";
const INFO: &[u8] = b"secure-net/relay/v1";

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn cannot_open() -> Error {
    err("CANNOT_OPEN", "That couldn't be opened: it wasn't sealed for this site and this request.")
}

/// Strict base64url as the JavaScript's `fromB64u` here: the URL-safe alphabet only.
fn b(s: &str) -> Result<Vec<u8>> {
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(err("MALFORMED", "Not base64url"));
    }
    from_b64u(s).map_err(|_| err("MALFORMED", "Not base64url"))
}

pub fn relay_context(from: &str, to: &str, path: &str) -> String {
    format!("{from}\n{to}\n{path}")
}

fn aes_key(ecdh_shared: &[u8], kem_shared: &[u8], context: &str, transcript: &[u8]) -> Zeroizing<[u8; 32]> {
    let salt = sha256(context.as_bytes());
    let info = [INFO, &sha256(transcript)[..]].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), &[ecdh_shared, kem_shared].concat()).expand(&info, &mut key[..]).expect("length");
    key
}

fn gcm_seal(key: &[u8], iv: &[u8; 12], data: &[u8], aad: &str) -> Vec<u8> {
    Aes256Gcm::new_from_slice(key).expect("32-byte key").encrypt(&Nonce::from(*iv), Payload { msg: data, aad: aad.as_bytes() }).expect("encrypts")
}

fn gcm_open(key: &[u8], iv: &[u8], data: &[u8], aad: &str) -> Result<Vec<u8>> {
    let iv: [u8; 12] = iv.try_into().map_err(|_| cannot_open())?;
    Aes256Gcm::new_from_slice(key).map_err(|_| cannot_open())?.decrypt(&Nonce::from(iv), Payload { msg: data, aad: aad.as_bytes() }).map_err(|_| cannot_open())
}

/// A site's relay keys: `{ kem: { public, secret }, sig: { public, secret } }`.
pub fn generate_keys() -> Result<Value> {
    let (ec_priv, ec_pub) = generate_pair()?;
    let ec_priv = crate::cv::encoding::from_b64(&ec_priv)?;
    let ec_pub = crate::cv::encoding::from_b64(&ec_pub)?;
    let kem = kem_key_pair();
    let seed = Zeroizing::new(random::<32>());
    Ok(json!({
        "kem": { "public": format!("{}.{}", b64u(&ec_pub), kem.pk), "secret": format!("{}.{}", b64u(&ec_priv), kem.sk) },
        "sig": { "public": b64u(&mldsa_public(&seed[..])?), "secret": b64u(&seed[..]) },
    }))
}

/// Seal text for a site. Returns `(sealed JSON text, reply key)`.
pub fn seal(recipient_kem_public: &str, text: &str, context: &str) -> Result<(String, [u8; 32])> {
    let (ec_b, kem_b) = recipient_kem_public.split_once('.').unwrap_or((recipient_kem_public, ""));
    let bad_key = || err("BAD_KEY", "That site's relay key isn't usable.");
    let theirs = public_from_raw(&b(ec_b).map_err(|_| bad_key())?).map_err(|_| bad_key())?;
    let (kem_ct, kem_ss) = encapsulate(kem_b, None).map_err(|_| bad_key())?;
    let kem_ct = from_b64u(&kem_ct)?;
    let eph = random_secret();
    let eph_pub = raw_public(&eph.public_key());
    let shared = ecdh(&eph, &theirs);
    let key = aes_key(&shared[..], &kem_ss, context, &[eph_pub.as_slice(), &kem_ct].concat());
    let reply_key = random::<32>();
    let iv = random::<12>();
    let inner = json!({ "r": b64u(&reply_key), "t": text }).to_string();
    let ct = gcm_seal(&key[..], &iv, inner.as_bytes(), context);
    let sealed = json!({ "v": 1, "s": SUITE, "e": b64u(&eph_pub), "k": b64u(&kem_ct), "n": b64u(&iv), "c": b64u(&ct) });
    Ok((sealed.to_string(), reply_key))
}

/// Open something sealed for this site: `(text, reply key)`.
pub fn open(kem_secret: &str, sealed: &str, context: &str) -> Result<(String, Vec<u8>)> {
    let bx: Value = serde_json::from_str(sealed).unwrap_or(Value::Null);
    if bx["v"] != 1 || bx["s"] != SUITE {
        return Err(err("MALFORMED", "Not a sealed request this site understands."));
    }
    let s = |k: &str| bx[k].as_str().unwrap_or("").to_string();
    let (ec_b, kem_b) = kem_secret.split_once('.').unwrap_or((kem_secret, ""));
    let eph_pub = b(&s("e"))?;
    let kem_ct = b(&s("k"))?;
    let shared = (|| -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
        let mine = secret_from_pkcs8(&crate::cv::encoding::to_b64(&b(ec_b)?))?;
        let theirs = public_from_raw(&eph_pub)?;
        Ok((ecdh(&mine, &theirs), decapsulate(&b64u(&kem_ct), kem_b)?))
    })()
    .map_err(|_| cannot_open())?;
    let key = aes_key(&shared.0[..], &shared.1, context, &[eph_pub.as_slice(), &kem_ct].concat());
    let plain = gcm_open(&key[..], &b(&s("n"))?, &b(&s("c"))?, context)?;
    let inner: Value = serde_json::from_slice(&plain).map_err(|_| err("MALFORMED", "Not a sealed request this site understands."))?;
    let text = crate::cv::canonical::js_string(&inner["t"]);
    Ok((text, b(inner["r"].as_str().unwrap_or("-"))?))
}

pub fn seal_reply(reply_key: &[u8], text: &str, context: &str) -> Result<String> {
    if reply_key.len() != 32 {
        return Err(err("BAD_KEY", "A reply key is 32 bytes"));
    }
    let iv = random::<12>();
    let ct = gcm_seal(reply_key, &iv, text.as_bytes(), &format!("reply\n{context}"));
    Ok(json!({ "v": 1, "n": b64u(&iv), "c": b64u(&ct) }).to_string())
}

pub fn open_reply(reply_key: &[u8], sealed: &str, context: &str) -> Result<String> {
    let bx: Value = serde_json::from_str(sealed).unwrap_or(Value::Null);
    if bx["v"] != 1 {
        return Err(err("MALFORMED", "Not a sealed reply."));
    }
    let plain = gcm_open(reply_key, &b(bx["n"].as_str().unwrap_or("-"))?, &b(bx["c"].as_str().unwrap_or("-"))?, &format!("reply\n{context}"))?;
    String::from_utf8(plain).map_err(|_| cannot_open())
}

/// The ML-DSA-65 signature over a request's signature base.
pub fn sign(sig_secret: &str, text: &str) -> Result<String> {
    Ok(b64u(&mldsa_sign(&b(sig_secret)?, text.as_bytes())?))
}

pub fn verify(sig_public: &str, text: &str, signature: &str) -> bool {
    verify_mldsa(signature, text.as_bytes(), sig_public)
}

fn b64u_len_ok(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// A site's published relay keys, checked: `{ suite, kem, sig }` or None.
pub fn relay_keys_of(doc: &Value) -> Option<Value> {
    let pq = &doc["pq"];
    let (kem, sig) = (pq["kem"].as_str()?, pq["sig"].as_str()?);
    if pq["suite"] != SUITE {
        return None;
    }
    let (a, k) = kem.split_once('.')?;
    if k.contains('.') || !b64u_len_ok(a, 80, 100) || !b64u_len_ok(k, 1500, 1700) || !b64u_len_ok(sig, 2500, 2700) {
        return None;
    }
    Some(json!({ "suite": SUITE, "kem": kem, "sig": sig }))
}

/// Published keys are acceptable given what was pinned: the same, or new where there were none.
pub fn relay_keys_acceptable(pinned: &Value, now: &Value) -> bool {
    if !crate::js::truthy(pinned) {
        return true;
    }
    crate::js::truthy(now) && pinned["kem"] == now["kem"] && pinned["sig"] == now["sig"]
}
