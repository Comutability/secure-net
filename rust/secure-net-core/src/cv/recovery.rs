//! The 24-word recovery phrase (`src/crypto/recovery.js`): standard BIP-39 English, 256 bits.
//!
//! The phrase derives a P-256 recovery key pair (devices seal the keyring to its public half), a
//! secret anchor key (statements made while the phrase is to hand carry an HMAC under it, so a
//! recovering device knows the published keys are really the account's) and a post-quantum key
//! pair the backup is sealed to for newer accounts. The phrase is never stored or sent.
use hmac::{Hmac, KeyInit, Mac};
use p256::SecretKey;
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::canonical::anchor_text;
use super::encoding::{from_b64, to_b64};
use super::kem::{is_kem_sealed, kem_keygen, kem_open};
use super::keyring::{assert_keyring_consistent, latest_version, parse_keyring, recovery_context};
use super::primitives::{aes_decrypt, ecdh, hkdf32, parse_sealed, public_from_raw, raw_public};
use crate::bytes::{equal_bytes, random, sha256};
use crate::error::{Error, Result};

pub const RECOVERY_WORD_COUNT: usize = 24;
const WORDS_TEXT: &str = include_str!("bip39-english.txt");

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

pub fn wordlist() -> Vec<&'static str> {
    WORDS_TEXT.lines().collect()
}

fn index_of(word: &str) -> Option<usize> {
    // The list is sorted, so a binary search finds a word or proves it absent.
    let list = wordlist();
    list.binary_search(&word).ok()
}

/// 32 bytes of entropy as 24 words (the last word carries an 8-bit SHA-256 checksum).
pub fn entropy_to_mnemonic(entropy: &[u8; 32]) -> String {
    let list = wordlist();
    let check = sha256(entropy)[0];
    let mut bits = Zeroizing::new(Vec::with_capacity(264));
    for byte in entropy.iter().chain(std::iter::once(&check)) {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    bits.chunks(11).map(|c| list[c.iter().fold(0usize, |n, b| n * 2 + usize::from(*b))]).collect::<Vec<_>>().join(" ")
}

/// The 32 bytes behind 24 valid words, or None (wrong count, unknown word or bad checksum).
pub fn mnemonic_to_entropy(words: &[&str]) -> Option<Zeroizing<[u8; 32]>> {
    if words.len() != RECOVERY_WORD_COUNT {
        return None;
    }
    let mut bits = Zeroizing::new(Vec::with_capacity(264));
    for w in words {
        let i = index_of(w)?;
        for b in (0..11).rev() {
            bits.push(((i >> b) & 1) as u8);
        }
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    for (i, chunk) in bits[..256].chunks(8).enumerate() {
        entropy[i] = chunk.iter().fold(0u8, |n, b| n * 2 + b);
    }
    let check = bits[256..].iter().fold(0u8, |n, b| n * 2 + b);
    (sha256(&entropy[..])[0] == check).then_some(entropy)
}

pub fn generate_recovery_phrase() -> String {
    let e = Zeroizing::new(random::<32>());
    entropy_to_mnemonic(&e)
}

pub fn normalize_phrase(input: &str) -> String {
    let lower = input.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut gap = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() {
            if gap && !out.is_empty() {
                out.push(' ');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    out
}

pub fn phrase_words(input: &str) -> Vec<String> {
    let n = normalize_phrase(input);
    if n.is_empty() {
        vec![]
    } else {
        n.split(' ').map(str::to_string).collect()
    }
}

pub fn is_known_word(word: &str) -> bool {
    index_of(&word.to_lowercase()).is_some()
}

pub fn phrase_entropy(input: &str) -> Option<Zeroizing<[u8; 32]>> {
    let words = phrase_words(input);
    mnemonic_to_entropy(&words.iter().map(String::as_str).collect::<Vec<_>>())
}

pub fn is_valid_phrase(input: &str) -> bool {
    phrase_entropy(input).is_some()
}

/// Everything a phrase derives. Secrets are wiped when this is dropped.
pub struct RecoveryKeys {
    pub secret: SecretKey,
    pub public_key: String,
    pub anchor_key: Zeroizing<[u8; 32]>,
    pub kem_secret: Zeroizing<String>,
    pub kem_public_key: String,
}

pub fn derive_recovery_key(phrase: &str) -> Result<RecoveryKeys> {
    let entropy = phrase_entropy(phrase).ok_or_else(|| err("INVALID_PHRASE", "That recovery phrase isn't valid. Check each word and the order."))?;
    let salt = b"commonveil/recovery/v1";
    let anchor_key = hkdf32(&entropy[..], salt, b"anchor-hmac");
    let kem_seed = hkdf32(&entropy[..], salt, b"mlkem768-p256-seed");
    let kem = kem_keygen(Some(&kem_seed[..]))?;
    for counter in 0..8 {
        let s = hkdf32(&entropy[..], salt, format!("p256-secret|{counter}").as_bytes());
        if let Ok(secret) = SecretKey::from_slice(&s[..]) {
            let public_key = to_b64(&raw_public(&secret.public_key()));
            return Ok(RecoveryKeys {
                secret,
                public_key,
                anchor_key,
                kem_secret: Zeroizing::new(kem["kem_priv"].as_str().unwrap_or("").to_string()),
                kem_public_key: kem["kem_pub"].as_str().unwrap_or("").to_string(),
            });
        }
    }
    Err(err("DERIVATION_FAILED", "Could not derive a recovery key."))
}

fn anchor_hmac(anchor_key: &[u8], statement: &Value) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(anchor_key).expect("HMAC takes any key length");
    mac.update(anchor_text(statement)?.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

pub fn recovery_anchor_mac(anchor_key: &[u8], statement: &Value) -> Result<String> {
    Ok(to_b64(&anchor_hmac(anchor_key, statement)?))
}

pub fn verify_recovery_anchor(anchor_key: &[u8], statement: &Value) -> bool {
    let Some(given) = statement["recovery_mac"].as_str().filter(|s| !s.is_empty()) else { return false };
    let Ok(given) = from_b64(given) else { return false };
    anchor_hmac(anchor_key, statement).is_ok_and(|m| equal_bytes(&m, &given))
}

/// Open a value sealed (classically) to the recovery public key.
pub fn open_with_recovery_secret(secret: &SecretKey, recovery_pub: &str, sealed: &Value, context: &str) -> Result<Zeroizing<Vec<u8>>> {
    let s = parse_sealed(sealed)?;
    let shared = ecdh(secret, &public_from_raw(&s.epk)?);
    let key = hkdf32(&shared[..], &[s.epk.as_slice(), &from_b64(recovery_pub)?].concat(), context.as_bytes());
    aes_decrypt(&key[..], &s.iv, &s.ct, context.as_bytes())
}

/// Open the recovery backup. On its own this proves nothing about where the backup came from:
/// check the published keys with the anchor and the keyring against them as well.
pub fn open_keyring_with_recovery_key(keys: &RecoveryKeys, user_id: &str, keyring_version: i64, recovery_pub: &str, recovery_kem_pub: &str, sealed: &Value) -> Result<Value> {
    if keys.public_key != recovery_pub || (!recovery_kem_pub.is_empty() && keys.kem_public_key != recovery_kem_pub) {
        return Err(err("WRONG_PHRASE", "That phrase is valid, but it isn't the recovery phrase for this account."));
    }
    let context = recovery_context(user_id, keyring_version);
    let bytes = if is_kem_sealed(sealed) { kem_open(&keys.kem_secret, sealed, &context) } else { open_with_recovery_secret(&keys.secret, recovery_pub, sealed, &context) }
        .map_err(|_| err("BACKUP_UNREADABLE", "The encrypted backup could not be opened with this phrase."))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| err("BAD_FORMAT", "Keyring is not valid JSON"))?;
    let keyring = parse_keyring(text, Some(user_id))?;
    if latest_version(&keyring)? != keyring_version {
        return Err(err("BAD_FORMAT", "Keyring version mismatch"));
    }
    assert_keyring_consistent(&keyring)?;
    Ok(keyring)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cv::encoding::from_b64_len;

    #[test]
    fn bip39_vectors() {
        // BIP-39 reference vectors (Trezor), 256-bit entropy.
        let zero = [0u8; 32];
        assert_eq!(entropy_to_mnemonic(&zero), "abandon ".repeat(23) + "art");
        let ff = [0xffu8; 32];
        assert_eq!(entropy_to_mnemonic(&ff), "zoo ".repeat(23) + "vote");
        let mut e = [0u8; 32];
        e.copy_from_slice(&hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c").unwrap());
        let words = entropy_to_mnemonic(&e);
        assert_eq!(words, "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
        assert_eq!(&phrase_entropy(&words.to_uppercase().replace(' ', ",  ")).unwrap()[..], &e);
        assert!(!is_valid_phrase(&("abandon ".repeat(23) + "abandon")));
        assert!(is_known_word("Zoo") && !is_known_word("zooo"));
        let p = generate_recovery_phrase();
        assert!(is_valid_phrase(&p));
        let k = derive_recovery_key(&p).unwrap();
        assert!(from_b64_len(&k.kem_secret, 32, "seed").is_ok());
    }
}
