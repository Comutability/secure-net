//! One-to-one sessions, version 1 (CVP-016): a hybrid post-quantum handshake, then a double
//! ratchet that mixes a fresh ML-KEM-768 secret into every Diffie-Hellman ratchet step.
//!
//! As in the JavaScript, every call takes a state and returns a new one, so a message that fails
//! leaves the session exactly as it was. Store the returned state before showing the message, and
//! never use an older copy again. The state serialises to the same JSON as the JavaScript's.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::bytes::{b64u, from_b64u, is_b64u, sha256_b64u};
use crate::canonical::canonical_bytes;
use crate::error::{Error, Result};
use crate::session::keys::{verify_bundle, verify_device_list, Device};
use crate::session::primitives::{decapsulate, dh, dh_key_pair, encapsulate, handshake_secret, kdf_chain, kdf_root, kem_key_pair, open, seal, transcript_hash, KeyPair};

pub const VERSION: i64 = 1;
/// How far ahead of the last message a message may be, in one chain.
pub const MAX_SKIP: u64 = 1000;
/// How many keys for not-yet-arrived messages a session keeps, across chains.
pub const MAX_STORED: usize = 2000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub account: String,
    pub device: String,
}

/// A session's state. Field names are the JavaScript's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub v: i64,
    pub ad: String,
    pub rk: String,
    pub peer: Peer,
    #[serde(rename = "self")]
    pub self_device: String,
    pub dhs: Option<KeyPair>,
    pub dhr: Option<String>,
    pub kems: Option<KeyPair>,
    pub kemr: Option<String>,
    #[serde(rename = "sendCt")]
    pub send_ct: Option<String>,
    pub cks: Option<String>,
    pub ckr: Option<String>,
    pub ns: u64,
    pub nr: u64,
    pub pn: u64,
    /// `"<dh>:<n>"` to message key, in the order they were stored.
    pub skipped: Map<String, Value>,
    pub pending: Option<Value>,
}

/// Your device and your account's signed device list (and, to respond, your prekey secrets).
pub struct Me<'a> {
    pub device: &'a Device,
    pub device_list: &'a Value,
    pub prekeys: Option<&'a Map<String, Value>>,
}

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn is_key32(v: &Value) -> bool {
    v.as_str().and_then(|s| from_b64u(s).ok()).is_some_and(|b| b.len() == 32) && v.as_str().is_some_and(is_b64u)
}

fn transcript(initiator: Value, responder: Value, x: &Value) -> Result<Value> {
    let ct = from_b64u(x["ct"].as_str().unwrap_or("")).map_err(|_| err("BAD_MESSAGE", "Bad KEM ciphertext"))?;
    Ok(json!({
        "v": VERSION,
        "initiator": initiator,
        "responder": responder,
        "ek": x["ek"],
        "ct": sha256_b64u(&ct),
        "signed": x["signed"],
        "pq": x["pq"],
        "oneTime": if x["oneTime"].is_null() { Value::Null } else { x["oneTime"].clone() },
    }))
}

fn party(account: &str, dev: &Value) -> Value {
    json!({ "account": account, "device": dev["kid"], "sign": dev["sign"], "dh": dev["dh"] })
}

fn new_state(rk: [u8; 32], ad: [u8; 32], peer: Peer, self_device: String) -> State {
    State { v: VERSION, ad: b64u(&ad), rk: b64u(&rk), peer, self_device, dhs: None, dhr: None, kems: None, kemr: None, send_ct: None, cks: None, ckr: None, ns: 0, nr: 0, pn: 0, skipped: Map::new(), pending: None }
}

fn b(s: &str) -> Result<Vec<u8>> {
    from_b64u(s).map_err(|_| err("BAD_INPUT", "Corrupt session state"))
}

fn my_device<'a>(me: &Me<'a>) -> Result<Value> {
    me.device_list["body"]["devices"].as_array().into_iter().flatten().find(|d| d["kid"].as_str() == Some(me.device.kid.as_str())).cloned().ok_or_else(|| err("BAD_INPUT", "Your device isn't on your own device list"))
}

/// Start a session with one of someone's devices, from a bundle their site handed out.
pub fn initiate(me: &Me, bundle: &Value, account_key: &str, min_seq: i64, now: i64) -> Result<State> {
    let v = verify_bundle(bundle, account_key, min_seq, now)?;
    let my_account = me.device_list["body"]["account"].as_str().unwrap_or("").to_string();
    let my_dev = my_device(me)?;
    if my_dev["dh"].as_str() != Some(me.device.dh.pk.as_str()) {
        return Err(err("BAD_INPUT", "Your device isn't on your own device list"));
    }
    let ek = dh_key_pair();
    let (ct, ss) = encapsulate(v.pq["pub"].as_str().unwrap_or(""), None)?;
    let signed_pub = v.signed["pub"].as_str().unwrap_or("");
    let mut dhs = vec![dh(&me.device.dh.sk, signed_pub)?, dh(&ek.sk, v.device["dh"].as_str().unwrap_or(""))?, dh(&ek.sk, signed_pub)?];
    if let Some(one) = &v.one_time {
        dhs.push(dh(&ek.sk, one["pub"].as_str().unwrap_or(""))?);
    }
    let x = json!({
        "list": me.device_list, "device": me.device.kid, "ek": ek.pk, "ct": ct,
        "signed": v.signed["id"], "pq": v.pq["id"], "oneTime": v.one_time.as_ref().map(|o| o["id"].clone()).unwrap_or(Value::Null),
    });
    let th = transcript_hash(&transcript(party(&my_account, &my_dev), party(account_key, &v.device), &x)?)?;
    let peer = Peer { account: account_key.to_string(), device: v.device["kid"].as_str().unwrap_or("").to_string() };
    let mut s = new_state(handshake_secret(&dhs, &ss, &th), th, peer, me.device.kid.clone());
    let dhs_pair = dh_key_pair();
    let (rk, ck) = kdf_root(&b(&s.rk)?, &dh(&dhs_pair.sk, signed_pub)?, &[]);
    s.dhs = Some(dhs_pair);
    s.dhr = Some(signed_pub.to_string());
    s.kems = Some(kem_key_pair());
    s.rk = b64u(&rk);
    s.cks = Some(b64u(&ck));
    s.pending = Some(x);
    Ok(s)
}

/// An id for a first message's handshake. Remember these while a signed prekey is live and refuse repeats.
pub fn handshake_id(message: &Value) -> Option<String> {
    let ek = message["x"]["ek"].as_str()?;
    Some(sha256_b64u(&from_b64u(ek).ok()?)[..22].to_string())
}

/// Who a first message claims to be from: (account, device, handshake id).
pub fn initial_sender(message: &Value) -> Option<(String, String, Option<String>)> {
    let x = &message["x"];
    let account = x["list"]["body"]["account"].as_str()?;
    Some((account.to_string(), x["device"].as_str().unwrap_or("").to_string(), handshake_id(message)))
}

/// Whether a message starts a new session.
pub fn is_initial(message: &Value) -> bool {
    !matches!(message.get("x"), None | Some(Value::Null) | Some(Value::Bool(false)))
}

/// What `respond` returns: the session, the plaintext, and the prekey secrets without the
/// one-time prekeys this used. Store both before showing the message.
pub struct Responded {
    pub state: State,
    pub plaintext: Vec<u8>,
    pub prekeys: Map<String, Value>,
}

/// Accept a first message on the device it was sent to.
pub fn respond(me: &Me, message: &Value, account_key: &str, min_seq: i64) -> Result<Responded> {
    let x = &message["x"];
    if !x.is_object() {
        return Err(err("BAD_MESSAGE", "Not a first message"));
    }
    if !is_key32(&x["ek"]) {
        return Err(err("BAD_MESSAGE", "Bad ephemeral key"));
    }
    let list = verify_device_list(&x["list"], account_key, min_seq)?;
    let their_dev = list["devices"].as_array().into_iter().flatten().find(|d| d["kid"] == x["device"]).cloned().ok_or_else(|| err("UNTRUSTED", "The sending device isn't on its account's device list"))?;
    let my_dev = my_device(me)?;
    let prekeys = me.prekeys.ok_or_else(|| err("BAD_INPUT", "Responding needs the device's prekey secrets"))?;
    let truthy = |v: &Value| !matches!(v, Value::Null | Value::Bool(false));
    let secret = |id: &Value, kind: &str, want: &str| -> Result<Value> {
        let k = id.as_str().and_then(|i| prekeys.get(i)).filter(|k| k["type"].as_str() == Some(kind));
        match k {
            Some(k) if !(want == "oneTime" && !truthy(&k["oneTime"])) && !(want == "signed" && (truthy(&k["oneTime"]) || truthy(&k["lastResort"]))) => Ok(k.clone()),
            _ => Err(err("UNKNOWN_PREKEY", "That prekey is unknown or already used")),
        }
    };
    let spk = secret(&x["signed"], "x25519", "signed")?;
    let pq = secret(&x["pq"], "ml-kem-768", "pq")?;
    if !truthy(&pq["oneTime"]) && !truthy(&pq["lastResort"]) {
        return Err(err("UNKNOWN_PREKEY", "That prekey is unknown or already used"));
    }
    let opk = if x["oneTime"].is_null() { None } else { Some(secret(&x["oneTime"], "x25519", "oneTime")?) };
    let s = |v: &Value, k: &str| v[k].as_str().unwrap_or("").to_string();
    let ek = s(x, "ek");
    let mut dhs = vec![dh(&s(&spk, "sk"), &s(&their_dev, "dh"))?, dh(&me.device.dh.sk, &ek)?, dh(&s(&spk, "sk"), &ek)?];
    if let Some(o) = &opk {
        dhs.push(dh(&s(o, "sk"), &ek)?);
    }
    let ss = decapsulate(&s(x, "ct"), &s(&pq, "sk"))?;
    let my_account = s(&me.device_list["body"], "account");
    let th = transcript_hash(&transcript(party(&s(&list, "account"), &their_dev), party(&my_account, &my_dev), x)?)?;
    let peer = Peer { account: s(&list, "account"), device: s(&their_dev, "kid") };
    let mut state = new_state(handshake_secret(&dhs, &ss, &th), th, peer, me.device.kid.clone());
    state.dhs = Some(KeyPair { sk: s(&spk, "sk"), pk: s(&spk, "pk") });
    let (state, plaintext) = decrypt(&state, message)?;
    let mut left = prekeys.clone();
    if opk.is_some() {
        left.remove(&s(x, "oneTime"));
    }
    if truthy(&pq["oneTime"]) {
        left.remove(&s(x, "pq"));
    }
    Ok(Responded { state, plaintext, prekeys: left })
}

fn ad_of(s: &State, h: &Value, x: Option<&Value>) -> Result<Vec<u8>> {
    let mut out = b(&s.ad)?;
    out.extend(canonical_bytes(&match x {
        Some(x) => json!({ "h": h, "x": x }),
        None => json!({ "h": h }),
    })?);
    Ok(out)
}

/// Encrypt for the peer. Returns the new state and the message (JSON for the relay).
pub fn encrypt(state: &State, plaintext: &[u8]) -> Result<(State, Value)> {
    let Some(cks) = &state.cks else { return Err(err("NOT_READY", "This session can't send until it has received a message")) };
    let mut s = state.clone();
    let (mk, ck) = kdf_chain(&b(cks)?);
    s.cks = Some(b64u(&ck));
    let (Some(dhs), Some(kems)) = (&s.dhs, &s.kems) else { return Err(err("BAD_INPUT", "Corrupt session state")) };
    let mut h = json!({ "dh": dhs.pk, "kem": kems.pk, "pn": s.pn, "n": s.ns });
    if let Some(ct) = &s.send_ct {
        h["ct"] = Value::String(ct.clone());
    }
    s.ns += 1;
    let ad = ad_of(&s, &h, s.pending.as_ref())?;
    let mut message = json!({ "v": VERSION, "h": h });
    if let Some(x) = &s.pending {
        message["x"] = x.clone();
    }
    message["c"] = Value::String(b64u(&seal(&mk, plaintext, &ad, "message")));
    Ok((s, message))
}

fn check_header(message: &Value) -> Result<()> {
    if message["v"].as_i64() != Some(VERSION) {
        return Err(err("BAD_MESSAGE", "Unsupported message version"));
    }
    let h = &message["h"];
    if !h.is_object() || !is_key32(&h["dh"]) || !h["kem"].as_str().is_some_and(is_b64u) {
        return Err(err("BAD_MESSAGE", "Bad message header"));
    }
    let counter = |v: &Value| v.as_u64().is_some_and(|n| n <= crate::canonical::MAX_SAFE_INTEGER as u64);
    if !counter(&h["n"]) || !counter(&h["pn"]) {
        return Err(err("BAD_MESSAGE", "Bad message counters"));
    }
    if !h["ct"].is_null() && !h["ct"].as_str().is_some_and(is_b64u) {
        return Err(err("BAD_MESSAGE", "Bad KEM ciphertext"));
    }
    if !message["c"].as_str().is_some_and(is_b64u) {
        return Err(err("BAD_MESSAGE", "Bad ciphertext"));
    }
    Ok(())
}

fn skip_to(s: &mut State, until: u64) -> Result<()> {
    let Some(ckr) = &s.ckr else { return Ok(()) };
    if until.saturating_sub(s.nr) > MAX_SKIP {
        return Err(err("TOO_FAR_AHEAD", "Too many messages missing"));
    }
    let mut ck = b(ckr)?;
    let dhr = s.dhr.clone().unwrap_or_default();
    while s.nr < until {
        let (mk, next) = kdf_chain(&ck);
        s.skipped.insert(format!("{dhr}:{}", s.nr), Value::String(b64u(&mk)));
        ck = next.to_vec();
        s.nr += 1;
    }
    s.ckr = Some(b64u(&ck));
    while s.skipped.len() > MAX_STORED {
        let oldest = s.skipped.keys().next().cloned().unwrap_or_default();
        s.skipped.shift_remove(&oldest);
    }
    Ok(())
}

fn ratchet(s: &mut State, h: &Value) -> Result<()> {
    let ct = h["ct"].as_str();
    // Once we've sent an ML-KEM key, every new chain from the peer must answer it.
    if s.kems.is_some() && ct.is_none() {
        return Err(err("DOWNGRADE", "Message is missing its ML-KEM ciphertext"));
    }
    if s.kems.is_none() && ct.is_some() {
        return Err(err("BAD_MESSAGE", "Unexpected ML-KEM ciphertext"));
    }
    let ss = match (ct, &s.kems) {
        (Some(ct), Some(kems)) => decapsulate(ct, &kems.sk)?.to_vec(),
        _ => Vec::new(),
    };
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    let dhr = h["dh"].as_str().unwrap_or("").to_string();
    s.dhr = Some(dhr.clone());
    s.kemr = h["kem"].as_str().map(str::to_string);
    let dhs = s.dhs.clone().ok_or_else(|| err("BAD_INPUT", "Corrupt session state"))?;
    let (rk, ckr) = kdf_root(&b(&s.rk)?, &dh(&dhs.sk, &dhr)?, &ss);
    s.ckr = Some(b64u(&ckr));
    let new_dhs = dh_key_pair();
    s.kems = Some(kem_key_pair());
    let (send_ct, ss_out) = encapsulate(s.kemr.as_deref().unwrap_or(""), None)?;
    s.send_ct = Some(send_ct);
    let (rk, cks) = kdf_root(&rk, &dh(&new_dhs.sk, &dhr)?, &ss_out);
    s.dhs = Some(new_dhs);
    s.rk = b64u(&rk);
    s.cks = Some(b64u(&cks));
    Ok(())
}

/// Decrypt a message from the peer. Returns the new state and the plaintext.
pub fn decrypt(state: &State, message: &Value) -> Result<(State, Vec<u8>)> {
    check_header(message)?;
    let mut s = state.clone();
    let h = &message["h"];
    let x = message.get("x").filter(|x| !x.is_null());
    let ad = ad_of(&s, h, x)?;
    let c = from_b64u(message["c"].as_str().unwrap_or("")).map_err(|_| err("BAD_MESSAGE", "Bad ciphertext"))?;
    let hdh = h["dh"].as_str().unwrap_or("");
    let n = h["n"].as_u64().unwrap_or(0);
    let id = format!("{hdh}:{n}");
    let mk = if let Some(Value::String(mk)) = s.skipped.shift_remove(&id) {
        b(&mk)?
    } else {
        if s.dhr.as_deref() != Some(hdh) {
            skip_to(&mut s, h["pn"].as_u64().unwrap_or(0))?;
            ratchet(&mut s, h)?;
        }
        skip_to(&mut s, n)?;
        if n < s.nr {
            return Err(err("REPLAY", "Message already received"));
        }
        let (mk, ck) = kdf_chain(&b(s.ckr.as_deref().unwrap_or(""))?);
        s.ckr = Some(b64u(&ck));
        s.nr += 1;
        mk.to_vec()
    };
    let plaintext = open(&mk, &c, &ad, "message")?;
    // Hearing back means the peer has the session, so stop sending the handshake.
    if s.pending.is_some() && x.is_none() {
        s.pending = None;
    }
    Ok((s, plaintext))
}
