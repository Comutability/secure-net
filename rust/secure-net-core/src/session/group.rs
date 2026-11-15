//! Group messages with sender keys (CVP-016, "Groups"), matching `src/session/group.js`.
//!
//! Each member device has a sending chain per group, sent to the other members over their
//! one-to-one sessions; each message is encrypted once, the chain moves forward with every
//! message, and the sender signs each message with Ed25519 so members can't impersonate each other.
use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bytes::{b64u, from_b64u, random, random_b64u};
use crate::canonical::{canonical_bytes, MAX_SAFE_INTEGER};
use crate::error::{Error, Result};
use crate::session::primitives::{kdf_chain, open, seal, LABEL};
use crate::session::v1::{MAX_SKIP, MAX_STORED};

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

/// This device's own sending chain in a group. Secret.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SenderKey {
    pub group: String,
    pub id: String,
    pub ck: String,
    pub n: u64,
    #[serde(rename = "signSk")]
    pub sign_sk: String,
    #[serde(rename = "signPk")]
    pub sign_pk: String,
}

/// A member's chain, as accepted from them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Received {
    pub group: String,
    pub id: String,
    pub from: Value,
    pub ck: String,
    pub n: u64,
    pub sign: String,
    pub skipped: BTreeMap<u64, String>,
}

fn header(m: &Value) -> Value {
    json!({ "v": 1, "group": m["group"], "id": m["id"], "n": m["n"] })
}

fn ad(m: &Value) -> Result<Vec<u8>> {
    Ok([format!("{LABEL}/group\n").into_bytes(), canonical_bytes(&header(m))?].concat())
}

fn signed(m: &Value) -> Result<Vec<u8>> {
    let mut h = header(m);
    h["c"] = m["c"].clone();
    Ok([format!("{LABEL}/group-sig\n").into_bytes(), canonical_bytes(&h)?].concat())
}

pub fn create_sender_key(group: &str) -> SenderKey {
    let sk = SigningKey::from_bytes(&random::<32>());
    SenderKey { group: group.into(), id: random_b64u(9), ck: b64u(&random::<32>()), n: 0, sign_sk: b64u(sk.as_bytes()), sign_pk: b64u(sk.verifying_key().as_bytes()) }
}

pub fn distribution(key: &SenderKey) -> Value {
    json!({ "type": "sender-key", "group": key.group, "id": key.id, "ck": key.ck, "n": key.n, "sign": key.sign_pk })
}

fn len_of(v: &Value) -> Option<usize> {
    from_b64u(v.as_str()?).ok().map(|b| b.len())
}

/// Accept a member's sender key. `from` must come from the session it arrived on.
pub fn accept_distribution(dist: &Value, from: Value) -> Result<Received> {
    if dist["type"] != "sender-key" || !dist["group"].is_string() || !dist["id"].is_string() {
        return Err(err("BAD_MESSAGE", "Not a sender key"));
    }
    let n = dist["n"].as_u64().filter(|n| *n <= MAX_SAFE_INTEGER as u64);
    if len_of(&dist["ck"]) != Some(32) || len_of(&dist["sign"]) != Some(32) || n.is_none() {
        return Err(err("BAD_MESSAGE", "Bad sender key"));
    }
    Ok(Received {
        group: dist["group"].as_str().unwrap().into(),
        id: dist["id"].as_str().unwrap().into(),
        from,
        ck: dist["ck"].as_str().unwrap().into(),
        n: n.unwrap(),
        sign: dist["sign"].as_str().unwrap().into(),
        skipped: BTreeMap::new(),
    })
}

pub fn group_encrypt(key: &SenderKey, plaintext: &[u8]) -> Result<(SenderKey, Value)> {
    let mut k = key.clone();
    let ck = from_b64u(&k.ck)?;
    let (mk, next) = kdf_chain(&ck);
    let mut m = json!({ "v": 1, "group": k.group, "id": k.id, "n": k.n });
    k.ck = b64u(&next);
    k.n += 1;
    m["c"] = json!(b64u(&seal(&mk, plaintext, &ad(&m)?, "group")));
    let seed: [u8; 32] = from_b64u(&k.sign_sk)?.try_into().map_err(|_| err("BAD_INPUT", "Corrupt sender key"))?;
    m["sig"] = json!(b64u(&SigningKey::from_bytes(&seed).sign(&signed(&m)?).to_bytes()));
    Ok((k, m))
}

fn verify(sig: &str, msg: &[u8], pk: &str) -> bool {
    crate::ed25519::verify_b64u(pk, sig, msg)
}

pub fn group_decrypt(state: &Received, m: &Value) -> Result<(Received, Vec<u8>)> {
    let n = m["n"].as_u64().filter(|n| *n <= MAX_SAFE_INTEGER as u64);
    if m["v"] != 1 || m["group"] != state.group.as_str() || m["id"] != state.id.as_str() || n.is_none() || !m["c"].is_string() || !m["sig"].is_string() {
        return Err(err("BAD_MESSAGE", "Not a message for this sender key"));
    }
    let n = n.unwrap();
    if !verify(m["sig"].as_str().unwrap(), &signed(m)?, &state.sign) {
        return Err(err("UNTRUSTED", "Group message signature doesn't match its sender"));
    }
    let mut s = state.clone();
    let mk = if let Some(mk) = s.skipped.remove(&n) {
        from_b64u(&mk)?
    } else {
        if n < s.n {
            return Err(err("REPLAY", "Message already received"));
        }
        if n - s.n > MAX_SKIP {
            return Err(err("TOO_FAR_AHEAD", "Too many messages missing"));
        }
        let mut ck = from_b64u(&s.ck)?;
        while s.n < n {
            let (mk, next) = kdf_chain(&ck);
            s.skipped.insert(s.n, b64u(&mk));
            ck = next.to_vec();
            s.n += 1;
        }
        let (mk, next) = kdf_chain(&ck);
        s.ck = b64u(&next);
        s.n += 1;
        while s.skipped.len() > MAX_STORED {
            let first = *s.skipped.keys().next().unwrap();
            s.skipped.remove(&first);
        }
        mk.to_vec()
    };
    let c = from_b64u(m["c"].as_str().unwrap()).map_err(|_| err("BAD_MESSAGE", "Bad ciphertext"))?;
    Ok((s, open(&mk, &c, &ad(m)?, "group")?))
}
