//! The primitives of the session protocol (CVP-016, "Key schedule").
//!
//!   X25519 (RFC 7748) and ML-KEM-768 (FIPS 203) for key agreement, always together;
//!   HKDF-SHA-256 (RFC 5869) and HMAC-SHA-256 for derivation; AES-256-GCM for encryption.
//!
//! Keys are held as base64url strings, as in the JavaScript, so state is plain JSON. An ML-KEM
//! secret key is the 2,400-byte FIPS 203 decapsulation key.
#![allow(deprecated)] // ml-kem's expanded-key encoding, needed to share state with the JavaScript.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ml_kem::array::Array;
use ml_kem::{B32, Decapsulate, DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, KeyExport, MlKem768, TryKeyInit};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::bytes::{b64u, from_b64u, random, sha256};
use crate::canonical::canonical_bytes;
use crate::error::{Error, Result};
use crate::Value;

/// The session errors use the same codes as the JavaScript (`BAD_KEY`, `DECRYPT_FAILED`, ...).
pub type SessionError = Error;

pub const LABEL: &str = "secure-net/session/v1";
/// Every purpose derived through `info`. Anything else is refused.
pub const PURPOSES: [&str; 6] = ["handshake", "transcript", "root", "message", "group", "history"];
pub const MLKEM_PUBLIC_LEN: usize = 1184;
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

fn info(what: &str) -> Vec<u8> {
    assert!(PURPOSES.contains(&what), "\"{LABEL}/{what}\" isn't a registered label");
    format!("{LABEL}/{what}").into_bytes()
}

/// An X25519 or ML-KEM-768 key pair, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub sk: String,
    pub pk: String,
}

pub fn dh_key_pair_from(secret: [u8; 32]) -> KeyPair {
    let s = StaticSecret::from(secret);
    KeyPair { sk: b64u(&secret), pk: b64u(PublicKey::from(&s).as_bytes()) }
}

pub fn dh_key_pair() -> KeyPair {
    dh_key_pair_from(random::<32>())
}

fn key32(s: &str, code: &'static str, what: &str) -> Result<[u8; 32]> {
    from_b64u(s).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()).ok_or_else(|| Error::new(code, format!("Not {what}")))
}

/// X25519. An all-zero result (the peer sent a low-order point) is refused (RFC 7748, 6.1).
pub fn dh(sk: &str, pk: &str) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(key32(sk, "BAD_KEY", "a usable X25519 key")?);
    let out = secret.diffie_hellman(&PublicKey::from(key32(pk, "BAD_KEY", "a usable X25519 key")?)).to_bytes();
    if out.iter().all(|b| *b == 0) {
        return Err(Error::new("BAD_KEY", "Key agreement produced a weak result"));
    }
    Ok(out)
}

/// An ML-KEM-768 key pair from a 64-byte seed (d || z, FIPS 203 ML-KEM.KeyGen_internal).
pub fn kem_key_pair_from(seed: [u8; 64]) -> KeyPair {
    let dk = DecapsulationKey::<MlKem768>::from_seed(Array::from(seed));
    KeyPair { sk: b64u(dk.to_expanded_bytes().as_slice()), pk: b64u(dk.encapsulation_key().to_bytes().as_slice()) }
}

pub fn kem_key_pair() -> KeyPair {
    kem_key_pair_from(random::<64>())
}

/// Encapsulate to an ML-KEM-768 public key. `coins` fixes the randomness (for test vectors only).
pub fn encapsulate(pk: &str, coins: Option<[u8; 32]>) -> Result<(String, [u8; 32])> {
    let bad = || Error::new("BAD_KEY", "Not an ML-KEM-768 public key");
    let key = from_b64u(pk).map_err(|_| bad())?;
    if key.len() != MLKEM_PUBLIC_LEN {
        return Err(bad());
    }
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(&key).map_err(|_| bad())?;
    let m = B32::from(coins.unwrap_or_else(random::<32>));
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    Ok((b64u(ct.as_slice()), ss.into()))
}

pub fn decapsulate(ct: &str, sk: &str) -> Result<[u8; 32]> {
    let bad = || Error::new("BAD_MESSAGE", "Not an ML-KEM-768 ciphertext");
    let c = from_b64u(ct).map_err(|_| bad())?;
    if c.len() != MLKEM_CIPHERTEXT_LEN {
        return Err(bad());
    }
    let sk = from_b64u(sk).map_err(|_| Error::new("BAD_KEY", "Not an ML-KEM-768 secret key"))?;
    let expanded = Array::try_from(sk.as_slice()).map_err(|_| Error::new("BAD_KEY", "Not an ML-KEM-768 secret key"))?;
    let dk = DecapsulationKey::<MlKem768>::from_expanded(&expanded).map_err(|_| Error::new("BAD_KEY", "Not an ML-KEM-768 secret key"))?;
    let ct = Array::try_from(c.as_slice()).map_err(|_| bad())?;
    Ok(dk.decapsulate(&ct).into())
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("HKDF output length is in range");
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// The handshake secret: HKDF over 32 bytes of 0xFF, every X25519 output and the ML-KEM secret,
/// with the transcript hash in the info.
pub fn handshake_secret(dhs: &[[u8; 32]], ss: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    let mut ikm = vec![0xffu8; 32];
    for d in dhs {
        ikm.extend_from_slice(d);
    }
    ikm.extend_from_slice(ss);
    let mut i = info("handshake");
    i.extend_from_slice(transcript_hash);
    hkdf_sha256(&ikm, &[0u8; 32], &i, 32).try_into().unwrap()
}

/// One step of the root chain. Returns (new root key, chain key).
pub fn kdf_root(rk: &[u8], dh_out: &[u8], ss: &[u8]) -> ([u8; 32], [u8; 32]) {
    let ikm = [dh_out, ss].concat();
    let out = hkdf_sha256(&ikm, rk, &info("root"), 64);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

/// One step of a sending or receiving chain. Returns (message key, next chain key).
pub fn kdf_chain(ck: &[u8]) -> ([u8; 32], [u8; 32]) {
    (hmac_sha256(ck, &[1]), hmac_sha256(ck, &[2]))
}

/// A message key's AES-256-GCM key and nonce.
pub fn message_keys(mk: &[u8], label: &str) -> ([u8; 32], [u8; 12]) {
    let out = hkdf_sha256(mk, &[0u8; 32], &info(label), 44);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

pub fn transcript_hash(obj: &Value) -> Result<[u8; 32]> {
    let mut b = info("transcript");
    b.extend(canonical_bytes(obj)?);
    Ok(sha256(&b))
}

pub fn seal(mk: &[u8], plaintext: &[u8], ad: &[u8], label: &str) -> Vec<u8> {
    let (key, iv) = message_keys(mk, label);
    Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad: ad })
        .expect("AES-GCM encryption doesn't fail")
}

pub fn open(mk: &[u8], ciphertext: &[u8], ad: &[u8], label: &str) -> Result<Vec<u8>> {
    let (key, iv) = message_keys(mk, label);
    Aes256Gcm::new_from_slice(&key)
        .expect("32-byte key")
        .decrypt(&Nonce::from(iv), Payload { msg: ciphertext, aad: ad })
        .map_err(|_| Error::new("DECRYPT_FAILED", "The message couldn't be decrypted"))
}
