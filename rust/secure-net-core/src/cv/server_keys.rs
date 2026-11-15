//! Server (community) encryption (`src/crypto/serverKeys.js`): key chains with generations, an
//! hourly forward ratchet on live chains, key grants sealed to members, per-item keys bound to
//! everything about the item, and invite previews only the link can open.
use std::collections::HashMap;

use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::canonical::{chain_generation_text, key_grant_text, server_item_text};
use super::encoding::{from_b64, iso_from_ms, ms_from_iso, sha256_b64, to_b64};
use super::envelope::id_ok;
use super::kem::is_kem_sealed;
use super::keyring::{as_int, key_for_version, open_from_sender, seal_to_recipient};
use super::primitives::{aes_decrypt, aes_encrypt, sign_with_pkcs8, verify_with_raw};
use crate::bytes::{b64u, equal_bytes, random, sha256};
use crate::error::{Error, Result};

pub const STEP_MS: i64 = 3_600_000;
pub const MAX_STEPS: i64 = 100_000;
pub const SERVER_ENVELOPE_VERSION: i64 = 1;
const KINDS: [&str; 16] = ["message", "server", "channel", "role", "nick", "rules", "ban", "automod", "emoji", "stickers", "onboarding", "icon", "banner", "event", "rsvp", "case"];

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or("")
}

// ---------- chains ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainId {
    pub server_id: String,
    /// "h", "l" or "c"
    pub kind: &'static str,
    pub channel_id: String,
}

pub fn parse_chain_id(chain_id: &str) -> Option<ChainId> {
    let (server, rest) = chain_id.split_once('.')?;
    if !id_ok(server) {
        return None;
    }
    let (kind, channel) = match rest {
        "h" => ("h", ""),
        "l" => ("l", ""),
        _ => ("c", rest.strip_prefix("c.").filter(|c| id_ok(c))?),
    };
    Some(ChainId { server_id: server.into(), kind, channel_id: channel.into() })
}

pub fn is_live_chain(chain_id: &str) -> bool {
    parse_chain_id(chain_id).is_some_and(|c| c.kind == "l")
}

/// The hour of a live chain generation a moment falls in (history and channel chains: 0).
pub fn step_at(chain_id: &str, started_at: &str, at_ms: i64) -> Result<i64> {
    if !is_live_chain(chain_id) {
        return Ok(0);
    }
    let start = ms_from_iso(started_at)?;
    let step = ((at_ms - start).div_euclid(STEP_MS)).max(0);
    if step > MAX_STEPS {
        return Err(err("CHAIN_TOO_OLD", "This key generation has run out of hours."));
    }
    Ok(step)
}

fn hkdf_into(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    // noble's hkdf with an empty salt uses a block of zeros, as RFC 5869 says; so does this.
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out[..]).expect("length in range");
    out
}

/// The key for a later hour of a live chain generation. Never backwards.
pub fn ratchet_to(key: &[u8], chain_id: &str, generation: i64, from: i64, to: i64) -> Result<Zeroizing<[u8; 32]>> {
    if key.len() != 32 {
        return Err(err("BAD_FORMAT", "Chain keys are 32 bytes"));
    }
    if to < from {
        return Err(err("BEFORE_KEY", "That's from before this key."));
    }
    if to - from > MAX_STEPS {
        return Err(err("CHAIN_TOO_OLD", "This key generation has run out of hours."));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(key);
    for n in from + 1..=to {
        k = hkdf_into(&k[..], &[], format!("commonveil/ratchet/v1|{chain_id}|{generation}|{n}").as_bytes());
    }
    Ok(k)
}

pub fn generation_commit(chain_id: &str, generation: i64, key: &[u8]) -> String {
    to_b64(&sha256(&[format!("commonveil/chain-commit/v1|{chain_id}|{generation}|").as_bytes(), key].concat()))
}

struct Held {
    step: i64,
    key: Zeroizing<[u8; 32]>,
    latest_step: i64,
    latest_key: Zeroizing<[u8; 32]>,
}

/// Chain keys this device holds, by chain and generation (the earliest step given, and the
/// latest worked out, so moving on an hour is one step).
#[derive(Default)]
pub struct ChainKeys {
    map: HashMap<(String, i64), Held>,
}

impl ChainKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// A key for an earlier step of the same generation wins.
    pub fn add(&mut self, chain_id: &str, generation: i64, step: i64, key: &[u8; 32]) {
        let k = (chain_id.to_string(), generation);
        if self.map.get(&k).is_some_and(|h| h.step <= step) {
            return;
        }
        self.map.insert(k, Held { step, key: Zeroizing::new(*key), latest_step: step, latest_key: Zeroizing::new(*key) });
    }

    pub fn has(&self, chain_id: &str, generation: i64) -> bool {
        self.map.contains_key(&(chain_id.to_string(), generation))
    }

    pub fn first_step(&self, chain_id: &str, generation: i64) -> Option<i64> {
        self.map.get(&(chain_id.to_string(), generation)).map(|h| h.step)
    }

    pub fn get(&mut self, chain_id: &str, generation: i64, step: i64) -> Result<Zeroizing<[u8; 32]>> {
        let h = self.map.get_mut(&(chain_id.to_string(), generation)).ok_or_else(|| err("NO_KEY", "This device hasn't been given that key yet."))?;
        if step < h.step {
            return Err(err("BEFORE_KEY", "That's from before you could read here."));
        }
        if step == h.step {
            return Ok(h.key.clone());
        }
        if step >= h.latest_step {
            let k = ratchet_to(&h.latest_key[..], chain_id, generation, h.latest_step, step)?;
            h.latest_key = k.clone();
            h.latest_step = step;
            return Ok(k);
        }
        ratchet_to(&h.key[..], chain_id, generation, h.step, step)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Load keys given as `[{ chain, gen, step, key }]` (key base64).
    pub fn from_json(list: &Value) -> Result<Self> {
        let mut keys = Self::new();
        for e in list.as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let key = from_b64(str_of(e, "key"))?;
            let key: [u8; 32] = key.as_slice().try_into().map_err(|_| err("BAD_FORMAT", "Chain keys are 32 bytes"))?;
            let (Some(gen), Some(step)) = (as_int(&e["gen"]), as_int(&e["step"])) else { return Err(err("BAD_FORMAT", "Invalid chain key")) };
            keys.add(str_of(e, "chain"), gen, step, &key);
        }
        Ok(keys)
    }
}

// ---------- generations ----------

/// A new generation made on this device: `(signed statement, key)`.
pub fn make_generation(server_id: &str, chain_id: &str, generation: i64, user_id: &str, device: &Value, started_at: &str) -> Result<(Value, Zeroizing<[u8; 32]>)> {
    if parse_chain_id(chain_id).map(|c| c.server_id) != Some(server_id.into()) {
        return Err(err("BAD_CHAIN", "That key chain isn't this server's."));
    }
    if generation < 0 {
        return Err(err("BAD_GENERATION", "Invalid key generation."));
    }
    let key = Zeroizing::new(random::<32>());
    let mut st = json!({
        "server_id": server_id, "chain_id": chain_id, "generation": generation, "started_at": started_at,
        "commit": generation_commit(chain_id, generation, &key[..]), "creator_id": user_id, "device_id": device["device_id"],
    });
    st["signature"] = json!(sign_with_pkcs8(str_of(device, "sign_priv"), chain_generation_text(&st)?.as_bytes())?);
    Ok((st, key))
}

pub fn verify_generation(st: &Value, sign_pub: &str) -> bool {
    chain_generation_text(st).is_ok_and(|t| verify_with_raw(sign_pub, str_of(st, "signature"), &t))
}

// ---------- grants ----------

pub fn grant_context(g: &Value) -> String {
    use super::canonical::js_string as s;
    format!(
        "commonveil/key-grant/v1|{}|{}|{}|{}|{}|{}",
        s(&g["server_id"]),
        s(&g["chain_id"]),
        s(&g["generation"]),
        s(&g["step"]),
        s(&g["recipient_id"]),
        s(&g["recipient_key_version"])
    )
}

fn grant_text(g: &Value) -> Result<String> {
    let mut f = g.clone();
    f["sealed_hash"] = json!(sha256_b64(str_of(g, "sealed")));
    key_grant_text(&f)
}

pub struct GrantArgs<'a> {
    pub server_id: &'a str,
    pub chain_id: &'a str,
    pub generation: i64,
    pub step: i64,
    pub key: &'a [u8],
    /// `{ user_id, key_version, ecdh_pub, kem_pub }` from their verified key history
    pub recipient: &'a Value,
    pub user_id: &'a str,
    pub device: &'a Value,
    pub now: i64,
}

/// Seal a chain key to one member; the sealing device signs the grant.
pub fn make_grant(a: GrantArgs) -> Result<Value> {
    let mut g = json!({
        "server_id": a.server_id, "chain_id": a.chain_id, "generation": a.generation, "step": a.step,
        "recipient_id": a.recipient["user_id"], "recipient_key_version": a.recipient["key_version"],
    });
    let sealed = seal_to_recipient(str_of(a.recipient, "ecdh_pub"), a.recipient["kem_pub"].as_str(), a.key, &grant_context(&g))?;
    g["sealed"] = json!(serde_json::to_string(&sealed).expect("JSON"));
    g["grantor_id"] = json!(a.user_id);
    g["grantor_device_id"] = a.device["device_id"].clone();
    g["granted_at"] = json!(iso_from_ms(a.now)?);
    g["signature"] = json!(sign_with_pkcs8(str_of(a.device, "sign_priv"), grant_text(&g)?.as_bytes())?);
    Ok(g)
}

pub fn verify_grant_signature(g: &Value, sign_pub: &str) -> bool {
    grant_text(g).is_ok_and(|t| verify_with_raw(sign_pub, str_of(g, "signature"), &t))
}

/// Open a grant made to this account: the 32-byte key.
pub fn open_grant(g: &Value, user_id: &str, keyring: &Value) -> Result<Zeroizing<Vec<u8>>> {
    if g["recipient_id"] != user_id {
        return Err(err("NOT_YOURS", "That key was given to someone else."));
    }
    let kv = as_int(&g["recipient_key_version"])
        .and_then(|v| key_for_version(keyring, v))
        .ok_or_else(|| err("KEY_VERSION_MISSING", "That key was sealed to an account key this device doesn't hold."))?;
    let sealed: Value = serde_json::from_str(str_of(g, "sealed")).map_err(|_| err("BAD_GRANT", "That key is malformed."))?;
    let ecdh_priv = if is_kem_sealed(&sealed) { None } else { kv["ecdh_priv"].as_str() };
    let bytes = open_from_sender(ecdh_priv, str_of(kv, "ecdh_pub"), kv["kem_priv"].as_str(), &sealed, &grant_context(g))
        .map_err(|_| err("GRANT_UNREADABLE", "That key couldn't be opened."))?;
    if bytes.len() != 32 {
        return Err(err("BAD_GRANT", "That key is malformed."));
    }
    Ok(bytes)
}

// ---------- items ----------

fn check_scope(s: &Value) -> Result<()> {
    if !KINDS.contains(&str_of(s, "kind")) {
        return Err(err("BAD_SCOPE", "Unknown item kind"));
    }
    for name in ["server_id", "item_id", "sender_id", "device_id"] {
        if !s[name].as_str().is_some_and(id_ok) {
            return Err(Error::new("BAD_SCOPE", format!("Invalid {name}")));
        }
    }
    match s["channel_id"].as_str() {
        Some(c) if c.is_empty() || id_ok(c) => {}
        _ => return Err(err("BAD_SCOPE", "Invalid channel_id")),
    }
    if parse_chain_id(str_of(s, "chain_id")).map(|c| c.server_id).as_deref() != s["server_id"].as_str() {
        return Err(err("BAD_SCOPE", "Invalid chain"));
    }
    if !as_int(&s["generation"]).is_some_and(|g| g >= 0) || !as_int(&s["step"]).is_some_and(|g| g >= 0) {
        return Err(err("BAD_SCOPE", "Invalid generation"));
    }
    Ok(())
}

pub fn item_context(s: &Value) -> String {
    use super::canonical::js_string as j;
    format!(
        "commonveil/server-content/v1|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        j(&s["kind"]),
        j(&s["server_id"]),
        j(&s["channel_id"]),
        j(&s["item_id"]),
        j(&s["sender_id"]),
        j(&s["device_id"]),
        j(&s["chain_id"]),
        j(&s["generation"]),
        j(&s["step"])
    )
}

fn item_key(chain_key: &[u8], context: &str) -> Zeroizing<[u8; 32]> {
    hkdf_into(chain_key, b"commonveil/server-item-key/v1", context.as_bytes())
}

fn key_commitment(context: &str, key: &[u8]) -> [u8; 32] {
    sha256(&[format!("commonveil/key-commitment/v1|{context}|").as_bytes(), key].concat())
}

/// Encrypt one item under a chain key at a step. Returns `{ v, chain, gen, step, iv, ct, kc }`.
pub fn encrypt_server_item(scope: &Value, chain_key: &[u8], payload: &Value) -> Result<Value> {
    check_scope(scope)?;
    let context = item_context(scope);
    let key = item_key(chain_key, &context);
    let (iv, ct) = aes_encrypt(&key[..], serde_json::to_string(payload).expect("JSON").as_bytes(), context.as_bytes())?;
    Ok(json!({
        "v": SERVER_ENVELOPE_VERSION, "chain": scope["chain_id"], "gen": scope["generation"], "step": scope["step"],
        "iv": to_b64(&iv), "ct": to_b64(&ct), "kc": to_b64(&key_commitment(&context, &key[..])),
    }))
}

pub fn parse_server_envelope(env: &Value) -> Result<Value> {
    let bad = || err("BAD_ENVELOPE", "This item is malformed.");
    let env: Value = match env.as_str() {
        Some(t) => serde_json::from_str(t).map_err(|_| bad())?,
        None => env.clone(),
    };
    let ok = env["v"] == SERVER_ENVELOPE_VERSION
        && parse_chain_id(str_of(&env, "chain")).is_some()
        && as_int(&env["gen"]).is_some_and(|g| g >= 0)
        && as_int(&env["step"]).is_some_and(|g| g >= 0)
        && from_b64(str_of(&env, "iv")).is_ok_and(|b| b.len() == 12)
        && from_b64(str_of(&env, "ct")).is_ok_and(|b| b.len() >= 17)
        && from_b64(str_of(&env, "kc")).is_ok_and(|b| b.len() == 32);
    if ok {
        Ok(env)
    } else {
        Err(bad())
    }
}

/// Decrypt with the chain keys held. `base` is the scope without the chain fields, which come
/// from the (signed) envelope. Returns `{ payload, chain, generation, step }`.
pub fn decrypt_server_item(base: &Value, envelope: &Value, keys: &mut ChainKeys) -> Result<Value> {
    let env = parse_server_envelope(envelope)?;
    let mut scope = base.clone();
    if !scope.is_object() {
        return Err(err("BAD_SCOPE", "Unknown item kind"));
    }
    scope["chain_id"] = env["chain"].clone();
    scope["generation"] = env["gen"].clone();
    scope["step"] = env["step"].clone();
    check_scope(&scope)?;
    let (gen, step) = (as_int(&env["gen"]).unwrap(), as_int(&env["step"]).unwrap());
    let chain_key = keys.get(str_of(&env, "chain"), gen, step)?;
    let context = item_context(&scope);
    let key = item_key(&chain_key[..], &context);
    if !equal_bytes(&key_commitment(&context, &key[..]), &from_b64(str_of(&env, "kc"))?) {
        return Err(err("DECRYPT_FAILED", "This item's key doesn't match its commitment."));
    }
    let failed = || err("DECRYPT_FAILED", "This item failed its integrity check.");
    let plain = aes_decrypt(&key[..], &from_b64(str_of(&env, "iv"))?, &from_b64(str_of(&env, "ct"))?, context.as_bytes()).map_err(|_| failed())?;
    let payload: Value = std::str::from_utf8(&plain).ok().and_then(|t| serde_json::from_str(t).ok()).ok_or_else(failed)?;
    Ok(json!({ "payload": payload, "chain": env["chain"], "generation": env["gen"], "step": env["step"] }))
}

/// item: `{ kind, serverId, channelId, itemId, senderId, deviceId, envelopeJson, sentAt }`.
fn server_item_text_of(item: &Value) -> Result<String> {
    server_item_text(&json!({
        "kind": item["kind"], "server_id": item["serverId"], "channel_id": item["channelId"], "item_id": item["itemId"],
        "sender_id": item["senderId"], "device_id": item["deviceId"],
        "envelope_hash": sha256_b64(str_of(item, "envelopeJson")), "sent_at": item["sentAt"],
    }))
}

pub fn sign_server_item(sign_priv: &str, item: &Value) -> Result<String> {
    sign_with_pkcs8(sign_priv, server_item_text_of(item)?.as_bytes())
}

pub fn verify_server_item(sign_pub: &str, signature: &str, item: &Value) -> bool {
    server_item_text_of(item).is_ok_and(|t| verify_with_raw(sign_pub, signature, &t))
}

// ---------- invite previews ----------

pub fn new_invite_secret() -> String {
    b64u(&random::<18>())
}

fn invite_key(secret: &str, code: &str) -> Zeroizing<[u8; 32]> {
    hkdf_into(secret.as_bytes(), b"commonveil/invite-preview/v1", code.as_bytes())
}

pub fn seal_invite_preview(code: &str, secret: &str, preview: &Value) -> Result<String> {
    let key = invite_key(secret, code);
    let (iv, ct) = aes_encrypt(&key[..], serde_json::to_string(preview).expect("JSON").as_bytes(), format!("commonveil/invite-preview/v1|{code}").as_bytes())?;
    Ok(json!({ "v": 1, "iv": to_b64(&iv), "ct": to_b64(&ct) }).to_string())
}

/// The preview, or None if the link's secret doesn't open it.
pub fn open_invite_preview(code: &str, secret: &str, sealed: &str) -> Option<Value> {
    let key = invite_key(secret, code);
    let env: Value = serde_json::from_str(sealed).ok()?;
    let plain = aes_decrypt(&key[..], &from_b64(env["iv"].as_str()?).ok()?, &from_b64(env["ct"].as_str()?).ok()?, format!("commonveil/invite-preview/v1|{code}").as_bytes()).ok()?;
    serde_json::from_str(std::str::from_utf8(&plain).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains_and_ratchet() {
        assert_eq!(parse_chain_id("s1.h").unwrap().kind, "h");
        assert_eq!(parse_chain_id("s1.c.ch_2").unwrap().channel_id, "ch_2");
        assert!(parse_chain_id("s1.c.").is_none() && parse_chain_id("s1.x").is_none() && parse_chain_id("s.1.h").is_none());
        assert_eq!(step_at("s1.l", "2026-11-15T00:00:00.000Z", ms_from_iso("2026-11-15T02:59:59.999Z").unwrap()).unwrap(), 2);
        assert_eq!(step_at("s1.h", "2026-11-15T00:00:00.000Z", 0).unwrap(), 0);
        let k0 = [7u8; 32];
        let k3 = ratchet_to(&k0, "s1.l", 0, 0, 3).unwrap();
        let k1 = ratchet_to(&k0, "s1.l", 0, 0, 1).unwrap();
        assert_eq!(&ratchet_to(&k1[..], "s1.l", 0, 1, 3).unwrap()[..], &k3[..]);
        assert_eq!(ratchet_to(&k3[..], "s1.l", 0, 3, 1).unwrap_err().code, "BEFORE_KEY");
        let mut keys = ChainKeys::new();
        keys.add("s1.l", 0, 1, &k1);
        assert_eq!(&keys.get("s1.l", 0, 3).unwrap()[..], &k3[..]);
        assert_eq!(keys.get("s1.l", 0, 0).unwrap_err().code, "BEFORE_KEY");
        assert_eq!(keys.get("s1.l", 1, 0).unwrap_err().code, "NO_KEY");
    }

    #[test]
    fn items_and_invites() {
        let scope = json!({"kind":"message","server_id":"s1","channel_id":"c1","item_id":"i1","sender_id":"u1","device_id":"d1","chain_id":"s1.l","generation":0,"step":2});
        let k0 = [9u8; 32];
        let k2 = ratchet_to(&k0, "s1.l", 0, 0, 2).unwrap();
        let env = encrypt_server_item(&scope, &k2[..], &json!({"text":"hi"})).unwrap();
        let mut keys = ChainKeys::new();
        keys.add("s1.l", 0, 0, &k0);
        let base = json!({"kind":"message","server_id":"s1","channel_id":"c1","item_id":"i1","sender_id":"u1","device_id":"d1"});
        assert_eq!(decrypt_server_item(&base, &env, &mut keys).unwrap()["payload"]["text"], "hi");
        let mut moved = base.clone();
        moved["item_id"] = json!("i2");
        assert_eq!(decrypt_server_item(&moved, &env, &mut keys).unwrap_err().code, "DECRYPT_FAILED");
        let secret = new_invite_secret();
        let sealed = seal_invite_preview("CODE1", &secret, &json!({"name":"A"})).unwrap();
        assert_eq!(open_invite_preview("CODE1", &secret, &sealed).unwrap()["name"], "A");
        assert!(open_invite_preview("CODE2", &secret, &sealed).is_none());
    }
}
