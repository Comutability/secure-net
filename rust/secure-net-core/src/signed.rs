//! Signed records (CVP-002, sections 2 to 4): `{ kind, body, sig: { kid, alg, value, pq? } }`.
//!
//! The signature covers `secure-net/<kind>/v1`, a newline, then the canonical JSON of the body,
//! so a signature made for one kind of record can never pass as another. A quantum-resistant key
//! signs twice, Ed25519 and ML-DSA-65 (FIPS 204, empty context), and both must verify.
use ed25519_dalek::Signer;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, B32};
use serde_json::{json, Map, Value};

use crate::bytes::{b64u, from_b64u, random, sha256_b64u};
use crate::canonical::{canonical_bytes, canonical_json};
use crate::error::{Error, Result};

pub const ALG: &str = "Ed25519";
pub const HYBRID_ALG: &str = "Ed25519+ML-DSA-65";

fn is_hybrid(key: &str) -> bool {
    key.contains('.')
}

/// A key's id: the first 22 base64url characters of the SHA-256 of its public key (of the 32 key
/// bytes for an Ed25519 key, of the UTF-8 public key string for a quantum-resistant key).
pub fn key_id(public_key: &str) -> Result<String> {
    let hash = if is_hybrid(public_key) { sha256_b64u(public_key.as_bytes()) } else { sha256_b64u(&from_b64u(public_key)?) };
    Ok(hash[..22].to_string())
}

/// A signing key as the JavaScript library holds it: base64url strings, the quantum-resistant
/// halves joined by a full stop.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SigningKey {
    pub kid: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "secretKey")]
    pub secret_key: String,
}

fn ed_secret(seed: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::new("BAD_KEY", "An Ed25519 secret key is 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn mldsa_from_seed(seed: &[u8]) -> Result<ml_dsa::SigningKey<MlDsa65>> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| Error::new("BAD_KEY", "An ML-DSA-65 seed is 32 bytes"))?;
    Ok(ml_dsa::SigningKey::<MlDsa65>::from_seed(&B32::from(seed)))
}

impl SigningKey {
    /// A key from its secret parts: a 32-byte Ed25519 secret and, for a quantum-resistant key, a
    /// 32-byte ML-DSA-65 seed.
    pub fn from_secrets(ed25519_secret: &[u8], mldsa65_seed: Option<&[u8]>) -> Result<Self> {
        let mut public_key = b64u(ed_secret(ed25519_secret)?.verifying_key().as_bytes());
        let mut secret_key = b64u(ed25519_secret);
        if let Some(seed) = mldsa65_seed {
            let pq = mldsa_from_seed(seed)?;
            public_key = format!("{public_key}.{}", b64u(pq.verifying_key().encode().as_slice()));
            secret_key = format!("{secret_key}.{}", b64u(seed));
        }
        Ok(Self { kid: key_id(&public_key)?, public_key, secret_key })
    }

    /// A new random key; `pq` makes it quantum-resistant.
    pub fn generate(pq: bool) -> Self {
        let ed = random::<32>();
        let seed = random::<32>();
        Self::from_secrets(&ed, pq.then_some(&seed[..])).expect("fresh key material is the right size")
    }

    fn sign_bytes(&self, bytes: &[u8]) -> Result<Value> {
        let mut parts = self.secret_key.split('.');
        let ed = ed_secret(&from_b64u(parts.next().unwrap_or(""))?)?;
        let value = b64u(&ed.sign(bytes).to_bytes());
        match parts.next() {
            None => Ok(json!({ "kid": self.kid, "alg": ALG, "value": value })),
            Some(seed) => {
                // Hedged ML-DSA.Sign with an empty context: M' = 0 || 0 || M, fresh randomness.
                let pq = mldsa_from_seed(&from_b64u(seed)?)?;
                let sig = pq.expanded_key().sign_internal(&[&[0u8, 0u8], bytes], &B32::from(random::<32>()));
                Ok(json!({ "kid": self.kid, "alg": HYBRID_ALG, "value": value, "pq": b64u(sig.encode().as_slice()) }))
            }
        }
    }

    /// Deterministic ML-DSA signing, for reproducing test vectors only.
    #[doc(hidden)]
    pub fn sign_deterministic_for_vectors(&self, kind: &str, body: &Value) -> Result<Value> {
        let bytes = signing_bytes(kind, body)?;
        let mut sig = self.sign_bytes(&bytes)?;
        if let Some(seed) = self.secret_key.split('.').nth(1) {
            let pq = mldsa_from_seed(&from_b64u(seed)?)?;
            let s = pq.expanded_key().sign_deterministic(&bytes, b"").map_err(|_| Error::new("BAD_KEY", "ML-DSA signing failed"))?;
            sig["pq"] = Value::String(b64u(s.encode().as_slice()));
        }
        Ok(json!({ "kind": kind, "body": body, "sig": sig }))
    }
}

/// The ML-DSA-65 public key for a 32-byte seed.
pub fn mldsa_public(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(mldsa_from_seed(seed)?.verifying_key().encode().as_slice().to_vec())
}

/// A hedged ML-DSA-65 signature (empty context) with the key from a 32-byte seed.
pub fn mldsa_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let pq = mldsa_from_seed(seed)?;
    Ok(pq.expanded_key().sign_internal(&[&[0u8, 0u8], msg], &B32::from(random::<32>())).encode().as_slice().to_vec())
}

fn is_kind(kind: &str) -> bool {
    // ^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$
    let mut parts = kind.split('.');
    let ok = |p: &str| p.as_bytes().first().is_some_and(u8::is_ascii_lowercase) && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    let first = parts.next().is_some_and(ok);
    let rest: Vec<&str> = parts.collect();
    first && !rest.is_empty() && rest.into_iter().all(ok)
}

/// The exact bytes signed for a record of this kind.
pub fn signing_bytes(kind: &str, body: &Value) -> Result<Vec<u8>> {
    if !is_kind(kind) {
        return Err(Error::new("BAD_KIND", format!("\"{kind}\" isn't a record kind")));
    }
    let mut out = format!("secure-net/{kind}/v1\n").into_bytes();
    out.extend(canonical_bytes(body)?);
    Ok(out)
}

/// Sign a record.
pub fn sign(kind: &str, body: &Value, key: &SigningKey) -> Result<Value> {
    let sig = key.sign_bytes(&signing_bytes(kind, body)?)?;
    Ok(json!({ "kind": kind, "body": body, "sig": sig }))
}

/// A further signature over the same record, by another key.
pub fn cosign(record: &Value, key: &SigningKey) -> Result<Value> {
    let kind = record["kind"].as_str().ok_or_else(|| Error::new("MALFORMED", "Not a signed record"))?;
    key.sign_bytes(&signing_bytes(kind, &record["body"])?)
}

fn verify_ed(sig: &str, bytes: &[u8], public: &str) -> bool {
    crate::ed25519::verify_b64u(public, sig, bytes)
}

/// An ML-DSA-65 signature check (empty context), base64url signature and key.
pub fn verify_mldsa(sig: &str, bytes: &[u8], public: &str) -> bool {
    let (Ok(sig), Ok(public)) = (from_b64u(sig), from_b64u(public)) else { return false };
    let (Ok(sig), Ok(public)) = (EncodedSignature::<MlDsa65>::try_from(sig.as_slice()), EncodedVerifyingKey::<MlDsa65>::try_from(public.as_slice())) else { return false };
    let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&sig) else { return false };
    ml_dsa::VerifyingKey::<MlDsa65>::decode(&public).verify_with_context(bytes, b"", &sig)
}

/// Whether one signature over a record is good, given the signer's public key. The key decides
/// what is required, never the signature: a quantum-resistant key's records need both halves.
pub fn check_signature(record: &Value, sig: &Value, public_key: &str) -> bool {
    let (Some(value), Some(kid), Some(alg)) = (sig["value"].as_str(), sig["kid"].as_str(), sig["alg"].as_str()) else { return false };
    if key_id(public_key).ok().as_deref() != Some(kid) {
        return false;
    }
    let mut halves = public_key.split('.');
    let ed_pub = halves.next().unwrap_or("");
    let pq_pub = halves.next();
    if alg != if pq_pub.is_some() { HYBRID_ALG } else { ALG } {
        return false;
    }
    let Some(kind) = record["kind"].as_str() else { return false };
    let Ok(bytes) = signing_bytes(kind, &record["body"]) else { return false };
    if !verify_ed(value, &bytes, ed_pub) {
        return false;
    }
    match pq_pub {
        None => true,
        Some(pq_pub) => sig["pq"].as_str().is_some_and(|pq| verify_mldsa(pq, &bytes, pq_pub)),
    }
}

/// Verify a record. `key_for(kid)` returns the public key for an id, or `None` if it isn't
/// trusted here; `kinds`, when given, are the kinds the caller will accept. Returns the body.
pub fn verify<'a>(record: &'a Value, key_for: impl Fn(&str) -> Option<String>, kinds: Option<&[&str]>) -> Result<&'a Value> {
    let sig = record.get("sig").filter(|s| s.is_object()).ok_or_else(|| Error::new("MALFORMED", "Not a signed record"))?;
    let kind = record["kind"].as_str().unwrap_or("");
    if let Some(kinds) = kinds {
        if !kinds.contains(&kind) {
            return Err(Error::new("WRONG_KIND", format!("Expected {}, got {kind}", kinds.join(" or "))));
        }
    }
    let public = sig["kid"].as_str().and_then(&key_for).ok_or_else(|| Error::new("UNKNOWN_SIGNER", "Signed by a key that isn't trusted here"))?;
    if !check_signature(record, sig, &public) {
        return Err(Error::new("BAD_SIGNATURE", "The signature doesn't match"));
    }
    Ok(&record["body"])
}

/// A record's id: the hash of its canonical form, signature (and any cosignatures) included.
pub fn record_id(record: &Value) -> Result<String> {
    let mut m = Map::new();
    for k in ["kind", "body", "sig", "cosigs"] {
        if let Some(v) = record.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Ok(sha256_b64u(canonical_json(&Value::Object(m))?.as_bytes()))
}
