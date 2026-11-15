//! One-to-one sessions, version 2 (CVP-016 version 2), matching `src/session/v2.js`.
//!
//! Compared with version 1: the transcript binds the prekeys' public keys; the initiator's
//! identity travels encrypted in the first message; message headers are encrypted; the ML-KEM-768
//! keys and ciphertexts that keep the ratchet quantum-resistant travel in 256-byte pieces inside
//! the headers (one new ML-KEM secret per completed exchange); and keys for messages that haven't
//! arrived are deleted after seven days.
//!
//! Every call takes a state and returns a new one, so a failed message leaves the session as it
//! was. The state is the same JSON as the JavaScript's.
use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::bytes::{b64u, from_b64u, is_b64u, random, sha256, sha256_b64u};
use crate::canonical::{canonical_bytes, MAX_SAFE_INTEGER};
use crate::error::{Error, Result};
use crate::session::keys::{verify_bundle, verify_device_list, Device};
use crate::session::primitives::{decapsulate, dh, dh_key_pair, encapsulate, kdf_chain, kem_key_pair, KeyPair};
use crate::session::v1::Peer;

pub const VERSION: i64 = 2;
pub const MAX_SKIP: u64 = 1000;
pub const MAX_STORED: usize = 2000;
pub const SKIPPED_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const CHUNK: usize = 256;
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;

const L_TRANSCRIPT: &[u8] = b"secure-net/session/v2/transcript";
const L_HANDSHAKE: &[u8] = b"secure-net/session/v2/handshake";
const L_IDENTITY: &[u8] = b"secure-net/session/v2/identity";
const L_ROOT: &[u8] = b"secure-net/session/v2/root";
const L_MESSAGE: &[u8] = b"secure-net/session/v2/message";

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn bad(msg: &str) -> Error {
    err("BAD_MESSAGE", msg)
}

fn corrupt() -> Error {
    err("BAD_INPUT", "Corrupt session state")
}

fn b(s: &str) -> Result<Vec<u8>> {
    from_b64u(s).map_err(|_| corrupt())
}

fn is_key32(v: &Value) -> bool {
    v.as_str().is_some_and(|s| is_b64u(s) && from_b64u(s).is_ok_and(|b| b.len() == 32))
}

fn is_b64u_val(v: &Value) -> bool {
    v.as_str().is_some_and(is_b64u)
}

/// `Number.isSafeInteger(n) && n >= 0`.
fn uint(v: &Value) -> Option<u64> {
    let max = MAX_SAFE_INTEGER as u64;
    v.as_u64().filter(|n| *n <= max).or_else(|| v.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= max as f64).map(|f| f as u64))
}

fn hkdf_out(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out).expect("HKDF length in range");
    out
}

fn aead(key: &[u8], iv: &[u8], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let iv: [u8; 12] = iv.try_into().expect("12-byte IV");
    Aes256Gcm::new_from_slice(key).expect("32-byte key").encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad: ad }).expect("AES-GCM encryption doesn't fail")
}

fn aead_open(key: &[u8], iv: &[u8], ct: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    let iv: [u8; 12] = iv.try_into().ok()?;
    Aes256Gcm::new_from_slice(key).ok()?.decrypt(&Nonce::from(iv), Payload { msg: ct, aad: ad }).ok()
}

// ---- Derivations ----

/// What the transcript covers.
pub fn transcript_of(initiator: Value, responder: Value, x: &Value, signed: &str, pq: &str, one_time: Option<&str>) -> Result<Value> {
    let ct = from_b64u(x["ct"].as_str().unwrap_or("")).map_err(|_| bad("Bad KEM ciphertext"))?;
    let pq = from_b64u(pq).map_err(|_| bad("Bad prekey"))?;
    Ok(json!({
        "v": VERSION,
        "initiator": initiator,
        "responder": responder,
        "ek": x["ek"],
        "ct": sha256_b64u(&ct),
        "signed": { "id": x["signed"], "pub": signed },
        "pq": { "id": x["pq"], "pub": sha256_b64u(&pq) },
        "oneTime": if x["oneTime"].is_null() { Value::Null } else { json!({ "id": x["oneTime"], "pub": one_time }) },
    }))
}

pub fn transcript_hash(t: &Value) -> Result<[u8; 32]> {
    Ok(sha256(&[L_TRANSCRIPT, &canonical_bytes(t)?].concat()))
}

fn ikm(dhs: &[[u8; 32]], ss: &[u8]) -> Vec<u8> {
    let mut v = vec![0xffu8; 32];
    for d in dhs {
        v.extend_from_slice(d);
    }
    v.extend_from_slice(ss);
    v
}

/// The handshake output: (root key, initiator's header key, responder's next header key).
pub fn handshake_keys(dhs: &[[u8; 32]], ss: &[u8], th: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let out = hkdf_out(&ikm(dhs, ss), &[0u8; 32], &[L_HANDSHAKE, th].concat(), 96);
    (out[..32].try_into().unwrap(), out[32..64].try_into().unwrap(), out[64..].try_into().unwrap())
}

/// One step of the root chain: (new root key, chain key, next header key).
pub fn kdf_root2(rk: &[u8], dh_out: &[u8], ss: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let out = hkdf_out(&[dh_out, ss].concat(), rk, L_ROOT, 96);
    (out[..32].try_into().unwrap(), out[32..64].try_into().unwrap(), out[64..].try_into().unwrap())
}

/// A message key's AES-256-GCM key and IV.
pub fn message_key(mk: &[u8]) -> ([u8; 32], [u8; 12]) {
    let out = hkdf_out(mk, &[0u8; 32], L_MESSAGE, 44);
    (out[..32].try_into().unwrap(), out[32..].try_into().unwrap())
}

/// The key that hides the initiator's identity.
pub fn identity_key(dhs: &[[u8; 32]], ss: &[u8], x: &Value) -> Result<([u8; 32], [u8; 12])> {
    let ct = from_b64u(x["ct"].as_str().unwrap_or("")).map_err(|_| bad("Bad KEM ciphertext"))?;
    let one = if x["oneTime"].is_null() { Value::Null } else { x["oneTime"].clone() };
    let public = canonical_bytes(&json!({ "ek": x["ek"], "ct": sha256_b64u(&ct), "signed": x["signed"], "pq": x["pq"], "oneTime": one }))?;
    let out = hkdf_out(&ikm(dhs, ss), &[0u8; 32], &[L_IDENTITY, &sha256(&public)[..]].concat(), 44);
    Ok((out[..32].try_into().unwrap(), out[32..].try_into().unwrap()))
}

// ---- State ----

/// The sparse ML-KEM exchange for one epoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Epoch {
    pub e: u64,
    /// "ek" (we send the key) or "ct" (we answer with the ciphertext)
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sk: Option<String>,
    pub out: Option<Vec<String>>,
    pub i: u64,
    pub got: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked: Option<bool>,
    pub ss: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Skipped {
    pub hk: String,
    pub n: u64,
    pub mk: String,
    pub t: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub v: i64,
    pub ad: String,
    pub rk: String,
    pub peer: Peer,
    #[serde(rename = "self")]
    pub self_device: String,
    pub initiator: bool,
    pub dhs: Option<KeyPair>,
    pub dhr: Option<String>,
    pub hks: Option<String>,
    pub hkr: Option<String>,
    pub nhks: Option<String>,
    pub nhkr: Option<String>,
    pub cks: Option<String>,
    pub ckr: Option<String>,
    pub ns: u64,
    pub nr: u64,
    pub pn: u64,
    pub pe: Option<u64>,
    pub mixed: u64,
    pub pq: Epoch,
    pub skipped: Vec<Skipped>,
    pub pending: Option<Value>,
}

fn split(bytes: &[u8]) -> Vec<String> {
    bytes.chunks(CHUNK).map(b64u).collect()
}

fn pieces(len: usize) -> usize {
    len.div_ceil(CHUNK)
}

fn new_epoch(e: u64, we_send_key: bool) -> Epoch {
    if we_send_key {
        let kp = kem_key_pair();
        let out = split(&from_b64u(&kp.pk).expect("own key"));
        Epoch { e, role: "ek".into(), sk: Some(kp.sk), out: Some(out), i: 0, got: BTreeMap::new(), seen: Some(false), acked: None, ss: None }
    } else {
        Epoch { e, role: "ct".into(), sk: None, out: None, i: 0, got: BTreeMap::new(), seen: None, acked: Some(false), ss: None }
    }
}

/// Where the post-quantum exchange stands.
pub fn pq_status(s: &State) -> Value {
    json!({ "epoch": s.pq.e, "mixed": s.mixed, "role": s.pq.role })
}

fn piece_to_send(pq: &mut Epoch) -> Option<Value> {
    if pq.role == "ek" {
        if pq.ss.is_some() {
            return Some(json!({ "e": pq.e, "t": "ack" }));
        }
        if pq.seen == Some(true) {
            return None;
        }
    } else if pq.out.is_none() || pq.acked == Some(true) {
        return None;
    }
    let out = pq.out.as_ref()?;
    if out.is_empty() {
        return None;
    }
    let i = (pq.i % out.len() as u64) as usize;
    let d = out[i].clone();
    pq.i += 1;
    Some(json!({ "e": pq.e, "t": pq.role, "i": i, "d": d }))
}

fn keep(pq: &mut Epoch, k: &Value, total: usize) -> Result<Option<String>> {
    let n = pieces(total);
    let i = uint(&k["i"]).filter(|i| (*i as usize) < n).ok_or_else(|| bad("Bad key piece"))? as usize;
    let d = k["d"].as_str().filter(|d| is_b64u(d)).ok_or_else(|| bad("Bad key piece"))?;
    let want = if i == n - 1 { total - CHUNK * (n - 1) } else { CHUNK };
    if from_b64u(d).map_err(|_| bad("Bad key piece"))?.len() != want {
        return Err(bad("Bad key piece"));
    }
    pq.got.insert(i.to_string(), d.to_string());
    if pq.got.len() < n {
        return Ok(None);
    }
    let mut whole = Vec::with_capacity(total);
    for j in 0..n {
        whole.extend(b(&pq.got[&j.to_string()])?);
    }
    pq.got.clear();
    Ok(Some(b64u(&whole)))
}

fn piece_received(pq: &mut Epoch, k: Option<&Value>) -> Result<()> {
    let Some(k) = k.filter(|k| !k.is_null()) else { return Ok(()) };
    if uint(&k["e"]) != Some(pq.e) {
        return Ok(());
    }
    let t = k["t"].as_str();
    if pq.role == "ct" {
        if t == Some("ack") {
            pq.acked = Some(true);
        } else if t == Some("ek") && pq.ss.is_none() {
            let Some(ek) = keep(pq, k, EK_LEN)? else { return Ok(()) };
            // Not a usable key: collect it again rather than lose the message it came with.
            if let Ok((ct, ss)) = encapsulate(&ek, None) {
                pq.out = Some(split(&b(&ct)?));
                pq.i = 0;
                pq.ss = Some(b64u(&ss));
            }
        }
    } else if t == Some("ct") && pq.ss.is_none() {
        pq.seen = Some(true);
        let Some(ct) = keep(pq, k, CT_LEN)? else { return Ok(()) };
        let sk = pq.sk.clone().ok_or_else(corrupt)?;
        pq.ss = Some(b64u(&decapsulate(&ct, &sk)?));
        pq.sk = None;
        pq.out = None;
    }
    Ok(())
}

// ---- Headers ----

fn seal_header(hk: &str, header: &Value, th: &[u8]) -> Result<String> {
    let iv = random::<12>();
    let mut out = iv.to_vec();
    out.extend(aead(&b(hk)?, &iv, &canonical_bytes(header)?, th));
    Ok(b64u(&out))
}

/// Ok(None) if this key doesn't open it; an error if it opens but isn't a valid header.
fn open_header(hk: Option<&str>, h: &str, th: &[u8]) -> Result<Option<Value>> {
    let Some(hk) = hk else { return Ok(None) };
    let Ok(raw) = from_b64u(h) else { return Ok(None) };
    if raw.len() < 28 {
        return Ok(None);
    }
    let Some(pt) = aead_open(&b(hk)?, &raw[..12], &raw[12..], th) else { return Ok(None) };
    let header: Value = std::str::from_utf8(&pt).ok().and_then(|t| serde_json::from_str(t).ok()).ok_or_else(|| bad("Bad message header"))?;
    let ok = header.is_object()
        && is_key32(&header["dh"])
        && uint(&header["n"]).is_some()
        && uint(&header["pn"]).is_some()
        && (header["pe"].is_null() || uint(&header["pe"]).is_some_and(|p| p >= 1))
        && (header["k"].is_null() || ((header["k"].is_object() || header["k"].is_array()) && uint(&header["k"]["e"]).is_some()));
    if !ok {
        return Err(bad("Bad message header"));
    }
    Ok(Some(header))
}

// ---- Handshake ----

fn party(account: &str, dev: &Value) -> Value {
    json!({ "account": account, "device": dev["kid"], "sign": dev["sign"], "dh": dev["dh"] })
}

pub struct Me<'a> {
    pub device: &'a Device,
    pub device_list: &'a Value,
    pub prekeys: Option<&'a Map<String, Value>>,
}

fn my_device(me: &Me) -> Result<Value> {
    me.device_list["body"]["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["kid"].as_str() == Some(me.device.kid.as_str()))
        .cloned()
        .ok_or_else(|| err("BAD_INPUT", "Your device isn't on your own device list"))
}

fn new_state(rk: [u8; 32], th: [u8; 32], peer: Peer, self_device: String, initiator: bool) -> State {
    State {
        v: VERSION,
        ad: b64u(&th),
        rk: b64u(&rk),
        peer,
        self_device,
        initiator,
        dhs: None,
        dhr: None,
        hks: None,
        hkr: None,
        nhks: None,
        nhkr: None,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        pe: None,
        mixed: 0,
        pq: new_epoch(1, initiator),
        skipped: vec![],
        pending: None,
    }
}

fn s_of(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}

/// Start a session with one of someone's devices, from a bundle their site handed out.
pub fn initiate(me: &Me, bundle: &Value, account_key: &str, min_seq: i64, now: i64) -> Result<State> {
    let identity = json!({ "list": me.device_list, "device": me.device.kid });
    initiate_as(me, bundle, account_key, min_seq, now, &identity)
}

/// `initiate` with the hidden identity given explicitly (tests use it to send lies).
fn initiate_as(me: &Me, bundle: &Value, account_key: &str, min_seq: i64, now: i64, identity: &Value) -> Result<State> {
    let v = verify_bundle(bundle, account_key, min_seq, now)?;
    let my_account = s_of(&me.device_list["body"], "account");
    let my_dev = my_device(me)?;
    if my_dev["dh"].as_str() != Some(me.device.dh.pk.as_str()) {
        return Err(err("BAD_INPUT", "Your device isn't on your own device list"));
    }
    let ek = dh_key_pair();
    let (ct, ss) = encapsulate(v.pq["pub"].as_str().unwrap_or(""), None)?;
    let signed_pub = s_of(&v.signed, "pub");
    let one_pub = v.one_time.as_ref().map(|o| s_of(o, "pub"));
    let mut x = json!({
        "ek": ek.pk, "ct": ct, "signed": v.signed["id"], "pq": v.pq["id"],
        "oneTime": v.one_time.as_ref().map(|o| o["id"].clone()).unwrap_or(Value::Null),
    });
    let mut hidden = vec![dh(&ek.sk, &signed_pub)?];
    if let Some(p) = &one_pub {
        hidden.push(dh(&ek.sk, p)?);
    }
    let (ik, iv) = identity_key(&hidden, &ss, &x)?;
    x["id"] = json!(b64u(&aead(&ik, &iv, &canonical_bytes(identity)?, &[])));

    let mut dhs = vec![dh(&me.device.dh.sk, &signed_pub)?, dh(&ek.sk, v.device["dh"].as_str().unwrap_or(""))?];
    dhs.extend(hidden);
    let t = transcript_of(party(&my_account, &my_dev), party(account_key, &v.device), &x, &signed_pub, v.pq["pub"].as_str().unwrap_or(""), one_pub.as_deref())?;
    let th = transcript_hash(&t)?;
    let (rk, hka, nhkb) = handshake_keys(&dhs, &ss, &th);

    let peer = Peer { account: account_key.into(), device: s_of(&v.device, "kid") };
    let mut s = new_state(rk, th, peer, me.device.kid.clone(), true);
    let pair = dh_key_pair();
    let (rk2, ck, nhk) = kdf_root2(&rk, &dh(&pair.sk, &signed_pub)?, &[]);
    s.dhs = Some(pair);
    s.dhr = Some(signed_pub);
    s.rk = b64u(&rk2);
    s.cks = Some(b64u(&ck));
    s.nhks = Some(b64u(&nhk));
    s.hks = Some(b64u(&hka));
    s.nhkr = Some(b64u(&nhkb));
    s.pending = Some(x);
    Ok(s)
}

pub fn is_initial(message: &Value) -> bool {
    !matches!(message.get("x"), None | Some(Value::Null) | Some(Value::Bool(false)))
}

pub fn handshake_id(message: &Value) -> Option<String> {
    let ek = &message["x"]["ek"];
    if !is_key32(ek) {
        return None;
    }
    Some(sha256_b64u(&from_b64u(ek.as_str()?).ok()?)[..22].to_string())
}

struct Opened {
    spk: Value,
    pq: Value,
    opk: Option<Value>,
    hidden: Vec<[u8; 32]>,
    ss: [u8; 32],
    id: Value,
}

fn truthy(v: &Value) -> bool {
    !matches!(v, Value::Null | Value::Bool(false))
}

fn open_identity(me: &Me, x: &Value) -> Result<Opened> {
    if !x.is_object() || !is_key32(&x["ek"]) || !is_b64u_val(&x["ct"]) || !is_b64u_val(&x["id"]) {
        return Err(bad("Not a first message"));
    }
    let prekeys = me.prekeys.ok_or_else(|| err("BAD_INPUT", "Responding needs the device's prekey secrets"))?;
    let secret = |id: &Value, kind: &str, want: &str| -> Result<Value> {
        let k = if id.is_null() { None } else { id.as_str().and_then(|i| prekeys.get(i)) };
        let ok = k.is_some_and(|k| {
            k["type"].as_str() == Some(kind)
                && !(want == "oneTime" && !truthy(&k["oneTime"]))
                && !(want == "signed" && (truthy(&k["oneTime"]) || truthy(&k["lastResort"])))
                && !(want == "pq" && !truthy(&k["oneTime"]) && !truthy(&k["lastResort"]))
        });
        if ok {
            Ok(k.unwrap().clone())
        } else {
            Err(err("UNKNOWN_PREKEY", "That prekey is unknown or already used"))
        }
    };
    let spk = secret(&x["signed"], "x25519", "signed")?;
    let pq = secret(&x["pq"], "ml-kem-768", "pq")?;
    let opk = if x["oneTime"].is_null() { None } else { Some(secret(&x["oneTime"], "x25519", "oneTime")?) };
    let ek = s_of(x, "ek");
    let mut hidden = vec![dh(&s_of(&spk, "sk"), &ek)?];
    if let Some(o) = &opk {
        hidden.push(dh(&s_of(o, "sk"), &ek)?);
    }
    let ss = decapsulate(&s_of(x, "ct"), &s_of(&pq, "sk"))?;
    let (ik, iv) = identity_key(&hidden, &ss, x)?;
    let pt = aead_open(&ik, &iv, &from_b64u(&s_of(x, "id")).map_err(|_| bad("Not a first message"))?, &[]).ok_or_else(|| err("DECRYPT_FAILED", "The first message couldn't be opened"))?;
    let id: Value = std::str::from_utf8(&pt).ok().and_then(|t| serde_json::from_str(t).ok()).ok_or_else(|| bad("Not a first message"))?;
    if !truthy(&id["list"]["body"]) || !id["device"].is_string() {
        return Err(bad("Not a first message"));
    }
    Ok(Opened { spk, pq, opk, hidden, ss, id })
}

/// Who a first message says it is from: `{ account, device, handshake }`. Nothing is verified.
pub fn initial_sender(me: &Me, message: &Value) -> Result<Value> {
    let o = open_identity(me, &message["x"])?;
    Ok(json!({ "account": o.id["list"]["body"]["account"], "device": o.id["device"], "handshake": handshake_id(message) }))
}

pub struct Responded {
    pub state: State,
    pub plaintext: Vec<u8>,
    pub prekeys: Map<String, Value>,
}

/// Accept a first message on the device it was sent to.
pub fn respond(me: &Me, message: &Value, account_key: &str, min_seq: i64, now: i64) -> Result<Responded> {
    let x = &message["x"];
    let Opened { spk, pq, opk, hidden, ss, id } = open_identity(me, x)?;
    let list = verify_device_list(&id["list"], account_key, min_seq)?;
    let their = list["devices"].as_array().into_iter().flatten().find(|d| d["kid"] == id["device"]).cloned().ok_or_else(|| err("UNTRUSTED", "The sending device isn't on its account's device list"))?;
    let my_dev = my_device(me)?;
    let ek = s_of(x, "ek");
    let mut dhs = vec![dh(&s_of(&spk, "sk"), &s_of(&their, "dh"))?, dh(&me.device.dh.sk, &ek)?];
    dhs.extend(hidden);
    let t = transcript_of(
        party(&s_of(&list, "account"), &their),
        party(&s_of(&me.device_list["body"], "account"), &my_dev),
        x,
        &s_of(&spk, "pk"),
        &s_of(&pq, "pk"),
        opk.as_ref().map(|o| o["pk"].as_str().unwrap_or("")),
    )?;
    let th = transcript_hash(&t)?;
    let (rk, hka, nhkb) = handshake_keys(&dhs, &ss, &th);
    let peer = Peer { account: s_of(&list, "account"), device: s_of(&their, "kid") };
    let mut s = new_state(rk, th, peer, me.device.kid.clone(), false);
    s.dhs = Some(KeyPair { sk: s_of(&spk, "sk"), pk: s_of(&spk, "pk") });
    s.nhks = Some(b64u(&nhkb));
    s.nhkr = Some(b64u(&hka));
    let (state, plaintext) = decrypt(&s, message, now)?;
    let mut left = me.prekeys.cloned().unwrap_or_default();
    if opk.is_some() {
        left.remove(&s_of(x, "oneTime"));
    }
    if truthy(&pq["oneTime"]) {
        left.remove(&s_of(x, "pq"));
    }
    Ok(Responded { state, plaintext, prekeys: left })
}

// ---- Ratchet ----

fn ad_of(s: &State, message: &Value) -> Result<Vec<u8>> {
    let mut out = b(&s.ad)?;
    let x = &message["x"];
    out.extend(canonical_bytes(&if truthy(x) { json!({ "h": message["h"], "x": x }) } else { json!({ "h": message["h"] }) })?);
    Ok(out)
}

/// Encrypt for the peer. Returns the new state and the message.
pub fn encrypt(state: &State, plaintext: &[u8]) -> Result<(State, Value)> {
    if state.v != VERSION {
        return Err(err("BAD_INPUT", "Not a version 2 session"));
    }
    let Some(cks) = &state.cks else { return Err(err("NOT_READY", "This session can't send until it has received a message")) };
    let mut s = state.clone();
    let (mk, ck) = kdf_chain(&b(cks)?);
    s.cks = Some(b64u(&ck));
    let dhs = s.dhs.clone().ok_or_else(corrupt)?;
    let mut h = json!({ "dh": dhs.pk, "pn": s.pn, "n": s.ns });
    if let Some(pe) = s.pe {
        h["pe"] = json!(pe);
    }
    if let Some(k) = piece_to_send(&mut s.pq) {
        h["k"] = k;
    }
    s.ns += 1;
    let mut message = json!({ "v": VERSION, "h": seal_header(s.hks.as_deref().ok_or_else(corrupt)?, &h, &b(&s.ad)?)? });
    if let Some(x) = &s.pending {
        message["x"] = x.clone();
    }
    let (key, iv) = message_key(&mk);
    let c = aead(&key, &iv, plaintext, &ad_of(&s, &message)?);
    message["c"] = json!(b64u(&c));
    Ok((s, message))
}

fn skip_to(s: &mut State, until: u64, now: i64) -> Result<()> {
    let Some(ckr) = s.ckr.clone() else { return Ok(()) };
    if until.saturating_sub(s.nr) > MAX_SKIP {
        return Err(err("TOO_FAR_AHEAD", "Too many messages missing"));
    }
    let hk = s.hkr.clone().ok_or_else(corrupt)?;
    let mut ck = b(&ckr)?;
    while s.nr < until {
        let (mk, next) = kdf_chain(&ck);
        s.skipped.push(Skipped { hk: hk.clone(), n: s.nr, mk: b64u(&mk), t: now });
        ck = next.to_vec();
        s.nr += 1;
    }
    s.ckr = Some(b64u(&ck));
    if s.skipped.len() > MAX_STORED {
        let extra = s.skipped.len() - MAX_STORED;
        s.skipped.drain(..extra);
    }
    Ok(())
}

fn ratchet(s: &mut State, h: &Value) -> Result<()> {
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.hks = s.nhks.clone();
    s.hkr = s.nhkr.clone();
    let dhr = s_of(h, "dh");
    s.dhr = Some(dhr.clone());
    let pe = uint(&h["pe"]).filter(|_| !h["pe"].is_null());
    let mut ss_in = Vec::new();
    if let Some(pe) = pe {
        if s.pq.role != "ct" || pe != s.pq.e || s.pq.ss.is_none() {
            return Err(bad("The post-quantum exchange is out of step"));
        }
        ss_in = b(s.pq.ss.as_deref().unwrap())?;
    }
    let dhs = s.dhs.clone().ok_or_else(corrupt)?;
    let (rk, ckr, nhkr) = kdf_root2(&b(&s.rk)?, &dh(&dhs.sk, &dhr)?, &ss_in);
    s.ckr = Some(b64u(&ckr));
    s.nhkr = Some(b64u(&nhkr));
    if let Some(pe) = pe {
        s.pq = new_epoch(pe + 1, true);
        s.mixed += 1;
    }
    let pair = dh_key_pair();
    let mut ss_out = Vec::new();
    s.pe = None;
    if s.pq.role == "ek" && s.pq.ss.is_some() {
        ss_out = b(s.pq.ss.as_deref().unwrap())?;
        s.pe = Some(s.pq.e);
        s.pq = new_epoch(s.pq.e + 1, false);
        s.mixed += 1;
    }
    let (rk, cks, nhks) = kdf_root2(&rk, &dh(&pair.sk, &dhr)?, &ss_out);
    s.dhs = Some(pair);
    s.rk = b64u(&rk);
    s.cks = Some(b64u(&cks));
    s.nhks = Some(b64u(&nhks));
    Ok(())
}

fn check_outer(message: &Value) -> Result<()> {
    if message["v"].as_i64() != Some(VERSION) {
        return Err(bad("Unsupported message version"));
    }
    if !is_b64u_val(&message["h"]) || !is_b64u_val(&message["c"]) {
        return Err(bad("Bad message"));
    }
    Ok(())
}

fn unique_hks(s: &State) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in &s.skipped {
        if !out.contains(&k.hk) {
            out.push(k.hk.clone());
        }
    }
    out
}

/// Whether this session can open the message's header, without changing anything.
pub fn can_open(state: &State, message: &Value) -> bool {
    if state.v != VERSION || message["v"].as_i64() != Some(VERSION) || !is_b64u_val(&message["h"]) {
        return false;
    }
    let Ok(th) = b(&state.ad) else { return false };
    let h = message["h"].as_str().unwrap_or("");
    let mut keys: Vec<Option<String>> = vec![state.hkr.clone(), state.nhkr.clone()];
    for hk in unique_hks(state) {
        keys.push(Some(hk));
    }
    let mut seen = Vec::new();
    for hk in keys {
        if seen.contains(&hk) {
            continue;
        }
        seen.push(hk.clone());
        match open_header(hk.as_deref(), h, &th) {
            Ok(Some(_)) | Err(_) => return true,
            Ok(None) => {}
        }
    }
    false
}

/// Decrypt a message from the peer. Returns the new state and the plaintext.
pub fn decrypt(state: &State, message: &Value, now: i64) -> Result<(State, Vec<u8>)> {
    if state.v != VERSION {
        return Err(err("BAD_INPUT", "Not a version 2 session"));
    }
    check_outer(message)?;
    let mut s = state.clone();
    s.skipped.retain(|k| now - k.t <= SKIPPED_TTL_MS);
    let th = b(&s.ad)?;
    let mh = message["h"].as_str().unwrap_or("");
    let mut h: Option<Value> = None;
    let mut mk: Option<Vec<u8>> = None;
    let mut seen_old = false;

    for hk in unique_hks(&s) {
        let Some(header) = open_header(Some(&hk), mh, &th)? else { continue };
        let n = uint(&header["n"]);
        if let Some(at) = s.skipped.iter().position(|k| k.hk == hk && Some(k.n) == n) {
            mk = Some(b(&s.skipped[at].mk)?);
            s.skipped.remove(at);
            h = Some(header);
        } else if Some(&hk) != s.hkr.as_ref() {
            seen_old = true;
        }
        break;
    }
    if mk.is_none() && seen_old {
        return Err(err("REPLAY", "Message already received"));
    }

    if mk.is_none() {
        let header = match open_header(s.hkr.as_deref(), mh, &th)? {
            Some(header) => {
                if header["dh"].as_str() != s.dhr.as_deref() {
                    return Err(bad("Bad message header"));
                }
                if uint(&header["n"]).unwrap() < s.nr {
                    return Err(err("REPLAY", "Message already received"));
                }
                header
            }
            None => {
                let header = open_header(s.nhkr.as_deref(), mh, &th)?.ok_or_else(|| err("DECRYPT_FAILED", "The message couldn't be decrypted"))?;
                if header["dh"].as_str() == s.dhr.as_deref() {
                    return Err(bad("Bad message header"));
                }
                skip_to(&mut s, uint(&header["pn"]).unwrap(), now)?;
                ratchet(&mut s, &header)?;
                header
            }
        };
        skip_to(&mut s, uint(&header["n"]).unwrap(), now)?;
        let (m, ck) = kdf_chain(&b(s.ckr.as_deref().ok_or_else(corrupt)?)?);
        mk = Some(m.to_vec());
        s.ckr = Some(b64u(&ck));
        s.nr += 1;
        h = Some(header);
    }

    let h = h.expect("set above");
    let (key, iv) = message_key(&mk.expect("set above"));
    let c = from_b64u(message["c"].as_str().unwrap_or("")).map_err(|_| bad("Bad message"))?;
    let plaintext = aead_open(&key, &iv, &c, &ad_of(&s, message)?).ok_or_else(|| err("DECRYPT_FAILED", "The message couldn't be decrypted"))?;
    piece_received(&mut s.pq, h.get("k"))?;
    if s.pending.is_some() && !truthy(&message["x"]) {
        s.pending = None;
    }
    Ok((s, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(role_ek: bool) -> State {
        let peer = Peer { account: "a".into(), device: "d".into() };
        let mut s = new_state(random::<32>(), random::<32>(), peer, "me".into(), role_ek);
        s.dhs = Some(dh_key_pair());
        s
    }

    #[test]
    fn a_mixed_in_secret_is_only_accepted_from_the_side_that_should_mix_it() {
        let h = |pe: u64| json!({ "dh": dh_key_pair().pk, "n": 0, "pn": 0, "pe": pe });
        // We sent the ML-KEM key (role "ek") and hold the secret: the peer can't be the one mixing it.
        let mut s = bare(true);
        s.pq.ss = Some(b64u(&[7u8; 32]));
        assert_eq!(ratchet(&mut s.clone(), &h(1)).unwrap_err().code, "BAD_MESSAGE");
        // We answered with the ciphertext for epoch 1: a claim for epoch 2 is out of step.
        let mut t = bare(false);
        t.pq.ss = Some(b64u(&[7u8; 32]));
        assert_eq!(ratchet(&mut t.clone(), &h(2)).unwrap_err().code, "BAD_MESSAGE");
        assert!(ratchet(&mut t, &h(1)).is_ok());
        assert_eq!(t.mixed, 1);
        assert_eq!((t.pq.e, t.pq.role.as_str()), (2, "ek"));
    }

    #[test]
    fn a_first_message_must_name_a_device_on_its_list() {
        use crate::session::keys::*;
        let account_a = create_account();
        let (d1, d2) = (create_device(), create_device());
        let list = sign_device_list(&account_a, vec![device_public(&d1)], 1, 0).unwrap();
        let both = sign_device_list(&account_a, vec![device_public(&d1), device_public(&d2)], 1, 0).unwrap();
        let account_b = create_account();
        let db = create_device();
        let list_b = sign_device_list(&account_b, vec![device_public(&db)], 1, 0).unwrap();
        let mut pk = create_prekeys(&db, 1, 1, 0, 2).unwrap();
        let bundle = take_bundle(&list_b, &mut pk.published, &db.kid.clone());
        // Device 2 sends, but names itself in a list that only has device 1.
        let me = Me { device: &d2, device_list: &both, prekeys: None };
        let lie = json!({ "list": list, "device": d2.kid });
        let a = initiate_as(&me, &bundle, &account_b.public_key, 0, 0, &lie).unwrap();
        let (_, first) = encrypt(&a, b"hi").unwrap();
        let bob = Me { device: &db, device_list: &list_b, prekeys: Some(&pk.secrets) };
        assert_eq!(respond(&bob, &first, &account_a.public_key, 0, 0).err().unwrap().code, "UNTRUSTED");
    }
}
