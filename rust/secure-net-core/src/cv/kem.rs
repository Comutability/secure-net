//! Post-quantum hybrid sealing (`src/crypto/kem.js`).
//!
//! MLKEM768-P256 is the "concrete hybrid KEM" from `@noble/post-quantum`, rebuilt here byte for
//! byte so values sealed by one implementation open in the other:
//!
//! * key generation: a 32-byte seed is stretched with SHAKE256 to 192 bytes, the first 64 seed
//!   ML-KEM-768 (`d || z`), the other 128 pick a P-256 scalar (the first 32-byte window that is a
//!   valid non-zero scalar). The public key is the ML-KEM key (1184 bytes) then the P-256 point
//!   (65 bytes).
//! * encapsulation: 32 bytes of ML-KEM coins and 128 bytes to pick the ephemeral P-256 scalar the
//!   same way. The ciphertext is the ML-KEM ciphertext (1088 bytes) then the ephemeral point.
//! * the shared secret is SHA3-256(ss_mlkem || x || ct_p256 || pk_p256 || "MLKEM768-P256"), where
//!   x is the ECDH x coordinate. (The library's comments say `x || y`, but its code calls
//!   `getSharedSecret` with compression on and drops the prefix byte, so it is x alone; the
//!   vectors in tests/vectors/cv-kem.json pin this down.)
//!
//! A sealed value is `{ kct, iv, ct }`: AES-256-GCM under HKDF(shared secret, salt
//! "commonveil/kem-seal/v1", info context), with the context as associated data.
use ml_kem::array::Array;
use ml_kem::{B32, Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768, TryKeyInit};
use p256::{PublicKey, SecretKey};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

use super::encoding::{from_b64, from_b64_len, to_b64};
use super::primitives::{aes_decrypt, aes_encrypt, ecdh, hkdf32, public_from_raw, raw_public};
use crate::bytes::random;
use crate::error::{Error, Result};

pub const KEM_NAME: &str = "MLKEM768-P256";
pub const KEM_PUBLIC_BYTES: usize = 1249;
pub const KEM_SEED_BYTES: usize = 32;
pub const KEM_CIPHERTEXT_BYTES: usize = 1153;
const MLKEM_PUBLIC: usize = 1184;
const MLKEM_CT: usize = 1088;
const CURVE_SEED: usize = 128;
const SALT: &[u8] = b"commonveil/kem-seal/v1";

fn kem_error() -> Error {
    Error::new("KEM_FAILED", "Couldn't open this sealed value")
}

/// The first 32-byte window of `seed` that is a valid non-zero P-256 scalar.
fn curve_secret(seed: &[u8]) -> Result<SecretKey> {
    seed.chunks_exact(32)
        .find_map(|w| SecretKey::from_slice(w).ok())
        .ok_or_else(|| Error::new("KEM_FAILED", "rejection sampling failed"))
}

/// The ECDH x coordinate, as the library's combiner uses it.
fn curve_shared(sk: &SecretKey, pk: &PublicKey) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(ecdh(sk, pk).to_vec())
}

struct Expanded {
    dk: DecapsulationKey<MlKem768>,
    curve: SecretKey,
}

fn expand(seed: &[u8]) -> Result<Expanded> {
    if seed.len() != KEM_SEED_BYTES {
        return Err(Error::new("BAD_FORMAT", "Invalid post-quantum secret"));
    }
    let mut xof = Shake256::default();
    xof.update(seed);
    let mut out = Zeroizing::new([0u8; 64 + CURVE_SEED]);
    xof.finalize_xof().read(&mut out[..]);
    let mut d = Zeroizing::new([0u8; 64]);
    d.copy_from_slice(&out[..64]);
    let dk = DecapsulationKey::<MlKem768>::from_seed(Array::from(*d));
    Ok(Expanded { dk, curve: curve_secret(&out[64..])? })
}

fn public_of(e: &Expanded) -> Vec<u8> {
    let mut pk = e.dk.encapsulation_key().to_bytes().as_slice().to_vec();
    pk.extend_from_slice(&raw_public(&e.curve.public_key()));
    pk
}

fn combine(ss0: &[u8], ss1: &[u8], ct1: &[u8], pk1: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    for part in [ss0, ss1, ct1, pk1, KEM_NAME.as_bytes()] {
        Digest::update(&mut h, part);
    }
    Zeroizing::new(h.finalize().into())
}

/// A key pair from a 32-byte seed: `(seed, public key)`, both raw bytes.
pub fn keygen_from(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(public_of(&expand(seed)?))
}

/// `{ kem_pub, kem_priv }` in base64, from a given seed (the recovery phrase's) or a random one.
pub fn kem_keygen(seed: Option<&[u8]>) -> Result<Value> {
    let seed = Zeroizing::new(match seed {
        Some(s) => s.to_vec(),
        None => random::<32>().to_vec(),
    });
    let pk = keygen_from(&seed)?;
    Ok(json!({ "kem_pub": to_b64(&pk), "kem_priv": to_b64(&seed) }))
}

pub fn kem_public_from_secret(priv_b64: &str) -> Result<String> {
    let seed = Zeroizing::new(from_b64_len(priv_b64, KEM_SEED_BYTES, "post-quantum secret")?);
    Ok(to_b64(&keygen_from(&seed)?))
}

pub fn is_kem_public(b64: &str) -> bool {
    from_b64_len(b64, KEM_PUBLIC_BYTES, "post-quantum key").is_ok()
}

/// Encapsulate with given randomness (160 bytes: 32 ML-KEM coins, 128 for the P-256 scalar).
/// Only tests should fix the randomness; `encapsulate` draws it fresh.
pub fn encapsulate_with(pk: &[u8], rand: &[u8; 160]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let bad = || Error::new("BAD_FORMAT", "Invalid post-quantum key");
    if pk.len() != KEM_PUBLIC_BYTES {
        return Err(bad());
    }
    let (pk0, pk1) = pk.split_at(MLKEM_PUBLIC);
    let ek = EncapsulationKey::<MlKem768>::new_from_slice(pk0).map_err(|_| bad())?;
    let recipient = public_from_raw(pk1).map_err(|_| bad())?;
    let mut coins = Zeroizing::new([0u8; 32]);
    coins.copy_from_slice(&rand[..32]);
    let (ct0, ss0) = ek.encapsulate_deterministic(&B32::from(*coins));
    let ss0 = Zeroizing::new(<[u8; 32]>::from(ss0));
    let eph = curve_secret(&rand[32..])?;
    let ct1 = raw_public(&eph.public_key());
    let ss1 = curve_shared(&eph, &recipient);
    let ss = combine(&ss0[..], &ss1, &ct1, pk1);
    let mut ct = ct0.as_slice().to_vec();
    ct.extend_from_slice(&ct1);
    Ok((ct, ss))
}

pub fn encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let rand = Zeroizing::new(random::<160>());
    encapsulate_with(pk, &rand)
}

/// Decapsulate with the 32-byte seed. ML-KEM rejects implicitly (a wrong ciphertext gives a
/// wrong secret, so the AEAD fails); a P-256 part that isn't a curve point is an error.
pub fn decapsulate(ct: &[u8], seed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(kem_error());
    }
    let e = expand(seed)?;
    let (ct0, ct1) = ct.split_at(MLKEM_CT);
    let ct0 = Array::try_from(ct0).map_err(|_| kem_error())?;
    let ss0 = Zeroizing::new(<[u8; 32]>::from(e.dk.decapsulate(&ct0)));
    let eph = public_from_raw(ct1).map_err(|_| kem_error())?;
    let ss1 = curve_shared(&e.curve, &eph);
    let pk1 = raw_public(&e.curve.public_key());
    Ok(combine(&ss0[..], &ss1, ct1, &pk1))
}

/// Seal bytes to a hybrid public key: `{ kct, iv, ct }`.
pub fn kem_seal(pub_b64: &str, plaintext: &[u8], context: &str) -> Result<Value> {
    let pk = from_b64_len(pub_b64, KEM_PUBLIC_BYTES, "post-quantum key")?;
    let (kct, ss) = encapsulate(&pk)?;
    let key = hkdf32(&ss[..], SALT, context.as_bytes());
    let (iv, ct) = aes_encrypt(&key[..], plaintext, context.as_bytes())?;
    Ok(json!({ "kct": to_b64(&kct), "iv": to_b64(&iv), "ct": to_b64(&ct) }))
}

pub fn is_kem_sealed(sealed: &Value) -> bool {
    sealed.is_object() && sealed["kct"].is_string()
}

/// Open a value made by `kem_seal`. Every failure is the same `KEM_FAILED`.
pub fn kem_open(priv_b64: &str, sealed: &Value, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !is_kem_sealed(sealed) {
        return Err(Error::new("KEM_FAILED", "Not a post-quantum sealed value"));
    }
    let open = || -> Result<Zeroizing<Vec<u8>>> {
        let kct = from_b64_len(sealed["kct"].as_str().unwrap_or(""), KEM_CIPHERTEXT_BYTES, "post-quantum ciphertext")?;
        let iv = from_b64(sealed["iv"].as_str().unwrap_or("-"))?;
        let ct = from_b64(sealed["ct"].as_str().unwrap_or("-"))?;
        let seed = Zeroizing::new(from_b64_len(priv_b64, KEM_SEED_BYTES, "post-quantum secret")?);
        let ss = decapsulate(&kct, &seed)?;
        let key = hkdf32(&ss[..], SALT, context.as_bytes());
        aes_decrypt(&key[..], &iv, &ct, context.as_bytes())
    };
    open().map_err(|_| kem_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip() {
        let keys = kem_keygen(None).unwrap();
        let (pk, sk) = (keys["kem_pub"].as_str().unwrap(), keys["kem_priv"].as_str().unwrap());
        assert_eq!(from_b64(pk).unwrap().len(), KEM_PUBLIC_BYTES);
        assert_eq!(kem_public_from_secret(sk).unwrap(), pk);
        let sealed = kem_seal(pk, b"secret", "ctx").unwrap();
        assert_eq!(from_b64(sealed["kct"].as_str().unwrap()).unwrap().len(), KEM_CIPHERTEXT_BYTES);
        assert_eq!(&kem_open(sk, &sealed, "ctx").unwrap()[..], b"secret");
        assert_eq!(kem_open(sk, &sealed, "other").unwrap_err().code, "KEM_FAILED");
        let other = kem_keygen(None).unwrap();
        assert!(kem_open(other["kem_priv"].as_str().unwrap(), &sealed, "ctx").is_err());
    }
}
