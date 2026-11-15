//! P-256 ECDH and ECDSA, HKDF-SHA-256, AES-256-GCM and ECIES sealing
//! (`src/crypto/primitives.js`, which uses WebCrypto).
//!
//! Formats match WebCrypto exactly: public keys are 65-byte uncompressed points, private keys are
//! PKCS#8 (with the public key included, as browsers write them), signatures are the 64-byte
//! `r || s` form, and ECDH gives the 32-byte x coordinate.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::encoding::{from_b64, to_b64};
use crate::bytes::random;
use crate::error::{Error, Result};

fn format(msg: &str) -> Error {
    Error::new("BAD_FORMAT", msg)
}

pub fn decrypt_error() -> Error {
    Error::new("DECRYPT_FAILED", "Decryption failed")
}

/// A fresh P-256 secret key, by rejection sampling (the odds of a retry are about 2^-32).
pub fn random_secret() -> SecretKey {
    loop {
        let bytes = Zeroizing::new(random::<32>());
        if let Ok(sk) = SecretKey::from_slice(&bytes[..]) {
            return sk;
        }
    }
}

/// The raw (uncompressed, 65-byte) public key.
pub fn raw_public(pk: &PublicKey) -> Vec<u8> {
    pk.to_sec1_point(false).as_bytes().to_vec()
}

/// A key pair in WebCrypto's export forms: `{ priv: PKCS#8 base64, pub: raw base64 }`.
pub fn generate_pair() -> Result<(String, String)> {
    let sk = random_secret();
    Ok((pkcs8_of(&sk)?, to_b64(&raw_public(&sk.public_key()))))
}

pub fn pkcs8_of(sk: &SecretKey) -> Result<String> {
    let der = sk.to_pkcs8_der().map_err(|_| format("Couldn't encode a private key"))?;
    Ok(to_b64(der.as_bytes()))
}

/// Check and decode a 65-byte uncompressed public key (WebCrypto's "raw" import also checks the
/// point is on the curve).
pub fn public_from_raw(raw: &[u8]) -> Result<PublicKey> {
    if raw.len() != 65 || raw[0] != 4 {
        return Err(format("Invalid P-256 public key"));
    }
    PublicKey::from_sec1_bytes(raw).map_err(|_| format("Invalid P-256 public key"))
}

pub fn public_from_b64(b64: &str) -> Result<PublicKey> {
    public_from_raw(&from_b64(b64)?)
}

pub fn secret_from_pkcs8(b64: &str) -> Result<SecretKey> {
    let der = Zeroizing::new(from_b64(b64)?);
    SecretKey::from_pkcs8_der(&der).map_err(|_| format("Invalid P-256 private key"))
}

/// ECDH: the shared point's x coordinate.
pub fn ecdh(sk: &SecretKey, pk: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes());
    out
}

pub fn hkdf_bytes(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("HKDF output length is in range");
    out
}

pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out[..]).expect("HKDF output length is in range");
    out
}

/// AES-256-GCM with a fresh 12-byte nonce. Returns `(iv, ciphertext || tag)`.
pub fn aes_encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    if key.len() != 32 {
        return Err(format("AES key must be 32 bytes"));
    }
    let iv = random::<12>();
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| format("AES key must be 32 bytes"))?;
    let ct = cipher.encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad }).map_err(|_| format("Encryption failed"))?;
    Ok((iv, ct))
}

pub fn aes_decrypt(key: &[u8], iv: &[u8], ct: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != 32 || iv.len() != 12 || ct.len() < 16 {
        return Err(Error::new("DECRYPT_FAILED", "Malformed ciphertext"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| decrypt_error())?;
    let iv = Nonce::try_from(iv).map_err(|_| decrypt_error())?;
    cipher.decrypt(&iv, Payload { msg: ct, aad }).map(Zeroizing::new).map_err(|_| decrypt_error())
}

/// ECDSA P-256 with SHA-256, as a base64 `r || s`. Nonces are RFC 6979 (deterministic), which
/// any WebCrypto verifier accepts.
pub fn sign_bytes(sk: &SecretKey, bytes: &[u8]) -> String {
    let key = SigningKey::from(sk);
    let sig: Signature = key.sign(bytes);
    to_b64(&sig.to_bytes())
}

pub fn sign_with_pkcs8(pkcs8: &str, bytes: &[u8]) -> Result<String> {
    Ok(sign_bytes(&secret_from_pkcs8(pkcs8)?, bytes))
}

/// The same answers as WebCrypto's verify: false for anything malformed, never an error. Like
/// WebCrypto, both low and high `s` are accepted.
pub fn verify_bytes(pk: &PublicKey, sig_b64: &str, bytes: &[u8]) -> bool {
    let Ok(sig) = from_b64(sig_b64) else { return false };
    if sig.len() != 64 {
        return false;
    }
    let Ok(sig) = Signature::from_slice(&sig) else { return false };
    VerifyingKey::from(pk).verify(bytes, &sig).is_ok()
}

pub fn verify_with_raw(pub_b64: &str, sig_b64: &str, text: &str) -> bool {
    match public_from_b64(pub_b64) {
        Ok(pk) => verify_bytes(&pk, sig_b64, text.as_bytes()),
        Err(_) => false,
    }
}

// ---------- ECIES ----------

/// Seal to a P-256 public key: ephemeral ECDH, HKDF-SHA-256 (salt `epk || recipient`, info the
/// context), AES-256-GCM with the context as associated data. Returns `{ epk, iv, ct }`.
pub fn seal_to(recipient_b64: &str, plaintext: &[u8], context: &str) -> Result<Value> {
    let recipient_raw = from_b64(recipient_b64)?;
    let recipient = public_from_raw(&recipient_raw)?;
    let eph = random_secret();
    let epk = raw_public(&eph.public_key());
    let shared = ecdh(&eph, &recipient);
    let key = hkdf32(&shared[..], &[epk.as_slice(), &recipient_raw].concat(), context.as_bytes());
    let (iv, ct) = aes_encrypt(&key[..], plaintext, context.as_bytes())?;
    Ok(json!({ "epk": to_b64(&epk), "iv": to_b64(&iv), "ct": to_b64(&ct) }))
}

pub struct Sealed {
    pub epk: Vec<u8>,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
}

pub fn parse_sealed(sealed: &Value) -> Result<Sealed> {
    if !sealed.is_object() {
        return Err(format("Missing sealed value"));
    }
    let get = |k: &str| from_b64(sealed[k].as_str().ok_or_else(|| format("Malformed sealed value"))?);
    let epk = get("epk")?;
    public_from_raw(&epk)?;
    let (iv, ct) = (get("iv")?, get("ct")?);
    if iv.len() != 12 || ct.len() < 17 {
        return Err(format("Malformed sealed value"));
    }
    Ok(Sealed { epk, iv, ct })
}

/// Open a value made by `seal_to`.
pub fn open_sealed(sk: &SecretKey, recipient_b64: &str, sealed: &Value, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let s = parse_sealed(sealed)?;
    let shared = ecdh(sk, &public_from_raw(&s.epk)?);
    open_with_secret(&shared[..], &s, &from_b64(recipient_b64)?, context)
}

/// The rest of opening once the ECDH secret is known (the recovery key computes it itself).
pub fn open_with_secret(shared: &[u8], s: &Sealed, recipient_raw: &[u8], context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let key = hkdf32(shared, &[s.epk.as_slice(), recipient_raw].concat(), context.as_bytes());
    aes_decrypt(&key[..], &s.iv, &s.ct, context.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_sign() {
        let (priv_b64, pub_b64) = generate_pair().unwrap();
        let sk = secret_from_pkcs8(&priv_b64).unwrap();
        let sealed = seal_to(&pub_b64, b"hello", "ctx").unwrap();
        assert_eq!(&open_sealed(&sk, &pub_b64, &sealed, "ctx").unwrap()[..], b"hello");
        assert!(open_sealed(&sk, &pub_b64, &sealed, "other").is_err());
        let sig = sign_bytes(&sk, b"text");
        assert!(verify_with_raw(&pub_b64, &sig, "text"));
        assert!(!verify_with_raw(&pub_b64, &sig, "texT"));
        assert!(!verify_with_raw(&pub_b64, "AAAA", "text"));
        // High s verifies too, as in WebCrypto.
        let s = Signature::from_slice(&from_b64(&sig).unwrap()).unwrap();
        let (r, s_scalar) = s.split_scalars();
        let flipped = Signature::from_scalars(r.to_bytes(), (-*s_scalar).to_bytes()).unwrap();
        assert!(verify_with_raw(&pub_b64, &to_b64(&flipped.to_bytes()), "text"));
    }

    #[test]
    fn refuses_bad_points() {
        let mut raw = vec![4u8; 65];
        raw[1..].fill(1);
        assert!(public_from_raw(&raw).is_err());
        assert!(public_from_raw(&[2u8; 33]).is_err());
    }
}
