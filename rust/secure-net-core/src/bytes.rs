//! Byte helpers: base64url without padding (the wire form), SHA-256, randomness, key ids.
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// The same decoder as the JavaScript `fromB64u`: the URL-safe alphabet, no padding, and (like
/// `atob`) leftover bits in the last character are ignored.
const B64U: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

pub fn b64u(bytes: &[u8]) -> String {
    B64U.encode(bytes)
}

pub fn from_b64u(s: &str) -> Result<Vec<u8>> {
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(Error::new("BAD_INPUT", "not base64url"));
    }
    B64U.decode(s).map_err(|_| Error::new("BAD_INPUT", "not base64url"))
}

/// Whether a string is non-empty base64url (the `^[A-Za-z0-9_-]+$` test the JavaScript uses).
pub fn is_b64u(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_b64u(bytes: &[u8]) -> String {
    b64u(&sha256(bytes))
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("the system has no source of randomness");
    out
}

pub fn random_b64u(n: usize) -> String {
    let mut out = vec![0u8; n];
    getrandom::fill(&mut out).expect("the system has no source of randomness");
    b64u(&out)
}

/// Constant-time comparison of two byte strings.
pub fn equal_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}
