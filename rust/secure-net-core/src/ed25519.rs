//! Ed25519 verification under ZIP-215 rules, the rules the JavaScript library (noble, with its
//! default `zip215: true`) applies: point encodings needn't be canonical, small-order points are
//! allowed, `S` must be below the group order, and the cofactored equation is checked.
//!
//! Using the same rules everywhere matters wherever several parties must agree on whether a
//! signature is valid (the commons ledger, vote results): with different rules, one crafted
//! signature could be accepted by some sites and refused by others. Every Ed25519 check in this
//! crate goes through here. Signing is plain RFC 8032 and gives identical signatures either way.
use ed25519_zebra::{Signature, VerificationKey};

use crate::bytes::from_b64u;

/// Whether `sig` (64 bytes) is a valid signature of `msg` by `public` (32 bytes).
pub fn verify(public: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else { return false };
    let Ok(key) = VerificationKey::try_from(public) else { return false };
    key.verify(&Signature::from_bytes(&sig), msg).is_ok()
}

/// The same, with base64url key and signature.
pub fn verify_b64u(public: &str, sig: &str, msg: &[u8]) -> bool {
    match (from_b64u(public), from_b64u(sig)) {
        (Ok(p), Ok(s)) => verify(&p, &s, msg),
        _ => false,
    }
}
