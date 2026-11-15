//! The owner key (`src/crypto/owner.js`): the recovery phrase's 256 bits as one string
//! (`cvkey1…` with a 4-byte checksum), and the Ed25519 key both derive, which proves an account
//! is yours by signing a site's challenge.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use super::primitives::hkdf32;
use super::recovery::{entropy_to_mnemonic, phrase_entropy};
use crate::bytes::{b64u, from_b64u, sha256};
use crate::error::{Error, Result};

const PREFIX: &str = "cvkey1";

fn err(msg: &str) -> Error {
    Error::new("OWNER_KEY", msg)
}

pub fn looks_like_private_key(input: &str) -> bool {
    input.trim().starts_with(PREFIX)
}

/// The 32 bytes behind a phrase or a private key.
fn entropy_of(input: &str) -> Result<Zeroizing<[u8; 32]>> {
    let text = input.trim();
    if looks_like_private_key(text) {
        let raw = Zeroizing::new(from_b64u(&text[PREFIX.len()..]).unwrap_or_default());
        if raw.len() != 36 || sha256(&raw[..32])[..4] != raw[32..] {
            return Err(err("That private key isn't valid. Check it was copied whole."));
        }
        let mut e = Zeroizing::new([0u8; 32]);
        e.copy_from_slice(&raw[..32]);
        return Ok(e);
    }
    phrase_entropy(text).ok_or_else(|| err("That recovery phrase isn't valid. Check each word and the order."))
}

pub fn private_key_from_phrase(phrase: &str) -> Result<Zeroizing<String>> {
    let e = entropy_of(phrase)?;
    let mut raw = Zeroizing::new(e.to_vec());
    raw.extend_from_slice(&sha256(&e[..])[..4]);
    Ok(Zeroizing::new(format!("{PREFIX}{}", b64u(&raw))))
}

pub fn phrase_from_private_key(key: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(entropy_to_mnemonic(&*entropy_of(key)?)))
}

/// The owner signing key for a phrase or private key.
pub fn owner_key(input: &str) -> Result<SigningKey> {
    let e = entropy_of(input)?;
    let seed = hkdf32(&e[..], b"commonveil/owner/v1", b"ed25519");
    Ok(SigningKey::from_bytes(&seed))
}

pub fn owner_public(key: &SigningKey) -> String {
    b64u(key.verifying_key().as_bytes())
}

pub fn owner_text(host: &str, purpose: &str, challenge: &str) -> String {
    format!("commonveil-owner/v1\n{host}\n{purpose}\n{challenge}")
}

pub fn sign_owner(key: &SigningKey, host: &str, purpose: &str, challenge: &str) -> String {
    b64u(&key.sign(owner_text(host, purpose, challenge).as_bytes()).to_bytes())
}

/// What the server checks. Honest signatures verify here and in the JavaScript; see the README
/// for how Ed25519 edge cases differ between ed25519-dalek and noble.
pub fn verify_owner(public_b64u: &str, signature_b64u: &str, host: &str, purpose: &str, challenge: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (from_b64u(public_b64u), from_b64u(signature_b64u)) else { return false };
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk.as_slice()), <[u8; 64]>::try_from(sig.as_slice())) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    vk.verify(owner_text(host, purpose, challenge).as_bytes(), &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cv::recovery::generate_recovery_phrase;

    #[test]
    fn owner_round_trip() {
        let phrase = generate_recovery_phrase();
        let key = private_key_from_phrase(&phrase).unwrap();
        assert!(key.starts_with("cvkey1"));
        assert_eq!(phrase_from_private_key(&key).unwrap().as_str(), phrase);
        let a = owner_key(&phrase).unwrap();
        let b = owner_key(&key).unwrap();
        assert_eq!(owner_public(&a), owner_public(&b));
        let sig = sign_owner(&a, "example.org", "recover", "abc");
        assert!(verify_owner(&owner_public(&a), &sig, "example.org", "recover", "abc"));
        assert!(!verify_owner(&owner_public(&a), &sig, "example.org", "set-owner", "abc"));
        let mut broken = key.to_string();
        broken.pop();
        broken.push(if key.ends_with('A') { 'B' } else { 'A' });
        assert!(owner_key(&broken).is_err());
    }
}
