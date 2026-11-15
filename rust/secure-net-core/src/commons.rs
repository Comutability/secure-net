//! The commons ledger (CVP-011), matching `src/commons/ledger.js`: a community's signed,
//! hash-chained history that any approved site can keep a full copy of, checked block by block
//! from the first, with forks settled the same way on every site.
//!
//! Every site must reach the same verdict on every block, so this follows the JavaScript's rules
//! exactly, including how it treats unusual JSON (missing fields, values of the wrong type).
//! Signatures are checked under ZIP-215 rules on both sides (see `crate::ed25519`).
use std::collections::{BTreeSet, HashSet};

use serde_json::{json, Map, Value};

use crate::bytes::sha256_b64u;
use crate::canonical::canonical_json;
use crate::cv::canonical::js_string;
use crate::error::{Error, Result};
use crate::js::{date_parse, len16, safe_int, truthy};
use crate::signed::{check_signature, cosign, key_id, sign, signing_bytes, SigningKey};

pub const BLOCK_KIND: &str = "commons.block";
pub const HOST_KIND: &str = "commons.host";
const MAX_EVENTS: usize = 256;
const MAX_BLOCK_BYTES: usize = 512 * 1024;
pub const CAPS: [&str; 7] = ["authority", "govern", "members", "roles", "moderate", "channels", "content"];
const AUTHORITY_EVENTS: [&str; 4] = ["keys.set", "replicas.set", "policy.set", "host.move"];

fn event_cap(t: &str) -> Option<&'static str> {
    Some(match t {
        "commons.genesis" | "keys.set" | "replicas.set" | "policy.set" | "host.move" => "authority",
        "governance.result" => "govern",
        "member.add" | "member.remove" => "members",
        "role.set" => "roles",
        "ban.set" => "moderate",
        "channel.set" | "channel.remove" => "channels",
        "content.ref" | "note" => "content",
        _ => return None,
    })
}

fn default_policy() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("auto_failover".into(), json!(true));
    m.insert("failover_after_s".into(), json!(300));
    m.insert("authority_change".into(), json!("threshold"));
    m.insert("open_join".into(), json!(false));
    m
}

/// A ledger refusal, with the height of the block (when it has one).
fn fail<T>(code: &'static str, msg: impl Into<String>, height: &Value) -> Result<T> {
    let at = if height.is_null() { String::new() } else { format!(" (block {})", js_string(height)) };
    Err(Error::new(code, format!("{}{at}", msg.into())))
}

pub fn block_id(block: &Value) -> Result<String> {
    Ok(sha256_b64u(&signing_bytes(BLOCK_KIND, &block["body"])?))
}

/// The hash an authority event is voted on as, without its mandate.
pub fn action_hash(event: &Value) -> Result<String> {
    let mut rest = event.clone();
    if let Some(o) = rest.as_object_mut() {
        o.shift_remove("mandate");
    }
    Ok(sha256_b64u(canonical_json(&rest)?.as_bytes()))
}

/// `{ ...a, ...b }` for JSON values, as JavaScript spreads them (strings spread to their UTF-16
/// code units by index, arrays to their items by index, other values to nothing).
fn spread_into(out: &mut Map<String, Value>, v: &Value) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                out.insert(k.clone(), x.clone());
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                out.insert(i.to_string(), x.clone());
            }
        }
        Value::String(s) => {
            let units: Vec<u16> = s.encode_utf16().collect();
            for (i, u) in units.iter().enumerate() {
                out.insert(i.to_string(), json!(String::from_utf16_lossy(&[*u])));
            }
        }
        _ => {}
    }
}

/// `keyId(pub) === kid`, where an unusable key never matches.
fn kid_matches(public: &Value, kid: &Value) -> bool {
    public.as_str().and_then(|p| key_id(p).ok()).is_some_and(|k| kid.as_str() == Some(k.as_str()))
}

fn caps_of(k: &Value) -> Vec<String> {
    k["caps"].as_array().map(|a| a.iter().map(js_string).collect()).unwrap_or_default()
}

fn has_authority(k: &Value) -> bool {
    k["caps"].as_array().is_some_and(|a| a.iter().any(|c| c == "authority"))
}

fn check_keys(keys: &Value, h: &Value) -> Result<()> {
    let Some(list) = keys.as_array().filter(|l| !l.is_empty() && l.len() <= 64) else { return fail("BAD_KEYS", "A community needs between 1 and 64 keys", h) };
    let mut seen = HashSet::new();
    for k in list {
        if !truthy(k) || !k["pub"].is_string() || !kid_matches(&k["pub"], &k["kid"]) {
            return fail("BAD_KEYS", "A key's id doesn't match its public key", h);
        }
        if !seen.insert(js_string(&k["kid"])) {
            return fail("BAD_KEYS", "A key is listed twice", h);
        }
        let ok = k["caps"].as_array().is_some_and(|c| !c.is_empty() && c.iter().all(|x| x.as_str().is_some_and(|s| CAPS.contains(&s))));
        if !ok {
            return fail("BAD_KEYS", "A key has an unknown capability", h);
        }
    }
    Ok(())
}

fn check_replicas(replicas: &Value, succession: &Value, h: &Value) -> Result<()> {
    let Some(list) = replicas.as_array().filter(|l| l.len() <= 32) else { return fail("BAD_REPLICAS", "Up to 32 replicas", h) };
    for r in list {
        let site_ok = r["site"].as_str().is_some_and(|s| !s.is_empty());
        if !truthy(r) || !site_ok || !r["pub"].is_string() || !kid_matches(&r["pub"], &r["kid"]) {
            return fail("BAD_REPLICAS", "A replica needs a site and its key", h);
        }
        if truthy(&r["caps"]) {
            let bad = match r["caps"].as_array() {
                Some(c) => c.iter().any(|x| !x.as_str().is_some_and(|s| CAPS.contains(&s)) || x == "authority" || x == "govern"),
                None => true,
            };
            if bad {
                return fail("BAD_REPLICAS", "A replica can't hold authority", h);
            }
        }
    }
    let ok = succession.as_array().is_some_and(|s| s.iter().all(|x| list.iter().any(|r| r["site"] == *x)));
    if !ok {
        return fail("BAD_REPLICAS", "Succession may only name replicas", h);
    }
    Ok(())
}

fn check_home(home: &Value, h: &Value) -> Result<()> {
    let site_ok = home["site"].as_str().is_some_and(|s| !s.is_empty());
    if !truthy(home) || !site_ok || !home["pub"].is_string() || !kid_matches(&home["pub"], &home["kid"]) {
        return fail("BAD_HOME", "The home site needs an address and a key", h);
    }
    Ok(())
}

/// The property name JavaScript uses for `obj[v[k]]`: "undefined" when the field is missing.
fn key_of(v: &Value, k: &str) -> String {
    match v.get(k) {
        None => "undefined".into(),
        Some(x) => js_string(x),
    }
}

fn or_empty(v: &Value) -> Value {
    if truthy(v) {
        v.clone()
    } else {
        json!([])
    }
}

/// The state before a community exists.
pub fn empty_state() -> Value {
    json!({
        "community": "", "name": "", "height": -1, "head": "", "epoch": 0,
        "keys": [], "threshold": 1, "home": null, "replicas": [], "succession": [],
        "policy": Value::Object(default_policy()),
        "members": {}, "bans": {}, "channels": {}, "results": {}, "content": 0,
    })
}

#[derive(Clone, Debug)]
pub struct Signer {
    pub kid: String,
    pub public: String,
    pub caps: BTreeSet<String>,
    pub authority: bool,
}

/// Everyone who may sign blocks, with what they may do, in the JavaScript's order.
pub fn signers_of(state: &Value) -> Vec<Signer> {
    let mut out: Vec<Signer> = Vec::new();
    let has = |out: &Vec<Signer>, kid: &str| out.iter().any(|s| s.kid == kid);
    for k in state["keys"].as_array().into_iter().flatten() {
        let caps: BTreeSet<String> = if has_authority(k) { CAPS.iter().map(|c| c.to_string()).collect() } else { caps_of(k).into_iter().collect() };
        let kid = js_string(&k["kid"]);
        // A later entry for the same id replaces the earlier one in a JavaScript Map.
        out.retain(|s| s.kid != kid);
        out.push(Signer { kid, public: js_string(&k["pub"]), caps, authority: has_authority(k) });
    }
    for r in state["replicas"].as_array().into_iter().flatten() {
        let kid = js_string(&r["kid"]);
        if !has(&out, &kid) {
            let caps = if truthy(&r["caps"]) { caps_of(r) } else { vec!["members".into(), "content".into()] };
            out.push(Signer { kid, public: js_string(&r["pub"]), caps: caps.into_iter().collect(), authority: false });
        }
    }
    let home = &state["home"];
    if truthy(home) && !has(&out, &js_string(&home["kid"])) {
        out.push(Signer { kid: js_string(&home["kid"]), public: js_string(&home["pub"]), caps: ["members", "content"].iter().map(|c| c.to_string()).collect(), authority: false });
    }
    for (kid, m) in state["members"].as_object().into_iter().flatten() {
        if !has(&out, kid) && !truthy(&state["bans"][kid.as_str()]) {
            out.push(Signer { kid: kid.clone(), public: js_string(&m["pub"]), caps: ["content".to_string()].into_iter().collect(), authority: false });
        }
    }
    out
}

fn signer(state: &Value, kid: &Value) -> Option<Signer> {
    let kid = kid.as_str()?;
    signers_of(state).into_iter().find(|s| s.kid == kid)
}

fn sigs_of(block: &Value) -> Vec<&Value> {
    let mut v = vec![&block["sig"]];
    v.extend(block["cosigs"].as_array().into_iter().flatten());
    v
}

/// Distinct authority keys that signed this block (author and co-signers).
fn authority_signers(block: &Value, state: &Value) -> usize {
    let keys: Vec<(&str, &str)> = state["keys"].as_array().into_iter().flatten().filter(|k| has_authority(k)).filter_map(|k| Some((k["kid"].as_str()?, k["pub"].as_str()?))).collect();
    let mut got = HashSet::new();
    for s in sigs_of(block) {
        let Some(kid) = s["kid"].as_str() else { continue };
        // A JavaScript Map keeps the last value set for a key.
        let Some((_, public)) = keys.iter().rev().find(|(k, _)| *k == kid) else { continue };
        if !got.contains(kid) && check_signature(block, s, public) {
            got.insert(kid.to_string());
        }
    }
    got.len()
}

fn threshold_ok(e: &Value, h: &Value) -> Result<()> {
    let authority = e["keys"].as_array().map(|k| k.iter().filter(|k| has_authority(k)).count()).unwrap_or(0) as i64;
    match safe_int(&e["threshold"]) {
        Some(t) if t >= 1 && t <= authority => Ok(()),
        _ => fail("BAD_EVENT", "The threshold must be between 1 and the number of authority keys", h),
    }
}

struct Ctx {
    caps: BTreeSet<String>,
    new_epoch: bool,
}

fn obj<'a>(state: &'a mut Value, k: &str) -> &'a mut Map<String, Value> {
    if !state[k].is_object() {
        state[k] = json!({});
    }
    state[k].as_object_mut().unwrap()
}

fn add_content(state: &mut Value) {
    let n = state["content"].as_f64().unwrap_or(0.0) + 1.0;
    state["content"] = if n.fract() == 0.0 { json!(n as i64) } else { json!(n) };
}

fn apply_event(state: &mut Value, e: &Value, block: &Value, ctx: &mut Ctx) -> Result<()> {
    let h = &block["body"]["height"];
    let member = key_of(e, "member");
    match e["type"].as_str().unwrap_or("") {
        "commons.genesis" => {
            if safe_int(h) != Some(0) || !h.is_number() {
                return fail("BAD_EVENT", "Only the first block can start a community", h);
            }
            if !e["name"].as_str().is_some_and(|n| !n.is_empty() && len16(n) <= 100) {
                return fail("BAD_EVENT", "A community needs a name", h);
            }
            check_keys(&e["keys"], h)?;
            check_home(&e["home"], h)?;
            check_replicas(&or_empty(&e["replicas"]), &or_empty(&e["succession"]), h)?;
            threshold_ok(e, h)?;
            let mut policy = default_policy();
            if truthy(&e["policy"]) {
                spread_into(&mut policy, &e["policy"]);
            }
            state["name"] = e["name"].clone();
            state["keys"] = e["keys"].clone();
            state["threshold"] = e["threshold"].clone();
            state["home"] = e["home"].clone();
            state["replicas"] = or_empty(&e["replicas"]);
            state["succession"] = or_empty(&e["succession"]);
            state["policy"] = Value::Object(policy);
        }
        "keys.set" => {
            check_keys(&e["keys"], h)?;
            threshold_ok(e, h)?;
            state["keys"] = e["keys"].clone();
            state["threshold"] = e["threshold"].clone();
            ctx.new_epoch = true;
        }
        "replicas.set" => {
            check_replicas(&e["replicas"], &or_empty(&e["succession"]), h)?;
            state["replicas"] = e["replicas"].clone();
            state["succession"] = or_empty(&e["succession"]);
        }
        "policy.set" => {
            let ac = &e["policy"]["authority_change"];
            if truthy(ac) && !(ac == "threshold" || ac == "vote") {
                return fail("BAD_EVENT", "Unknown authority rule", h);
            }
            let mut policy = state["policy"].as_object().cloned().unwrap_or_default();
            spread_into(&mut policy, &e["policy"]);
            state["policy"] = Value::Object(policy);
        }
        "host.move" => {
            check_home(&e["home"], h)?;
            state["home"] = e["home"].clone();
            ctx.new_epoch = true;
        }
        "governance.result" => {
            let r = &e["result"];
            if !truthy(&r["body"]["motion"]) || !truthy(&r["sig"]) {
                return fail("BAD_EVENT", "Not a vote result", h);
            }
            let tallier = state["keys"].as_array().into_iter().flatten().find(|k| k["kid"] == r["sig"]["kid"] && k["caps"].as_array().is_some_and(|c| c.iter().any(|x| x == "authority" || x == "govern")));
            let ok = tallier.is_some_and(|t| t["pub"].as_str().is_some_and(|p| check_signature(r, &r["sig"], p)));
            if !ok {
                return fail("BAD_EVENT", "A vote result must be signed by one of the community's keys", h);
            }
            let id = sha256_b64u(&signing_bytes(r["kind"].as_str().unwrap_or(""), &r["body"])?);
            let action = if truthy(&r["body"]["action"]) { r["body"]["action"].clone() } else { json!("") };
            obj(state, "results").insert(id, json!({ "motion": r["body"]["motion"], "passed": truthy(&r["body"]["passed"]), "action": action }));
        }
        "member.add" => {
            if !e["pub"].is_string() || !kid_matches(&e["pub"], &e["member"]) {
                return fail("BAD_EVENT", "A member's id must match their key", h);
            }
            if truthy(&state["bans"][member.as_str()]) {
                return fail("BANNED", "That member is banned", h);
            }
            let roles = state["members"][member.as_str()]["roles"].clone();
            let roles = if truthy(&roles) { roles } else { json!([]) };
            obj(state, "members").insert(member, json!({ "pub": e["pub"], "roles": roles, "since": h }));
        }
        "member.remove" => {
            if e["member"] != block["sig"]["kid"] && !ctx.caps.contains("members") {
                return fail("NOT_ALLOWED", "Only the member or a moderator can remove a member", h);
            }
            obj(state, "members").shift_remove(&member);
        }
        "role.set" => {
            if !truthy(&state["members"][member.as_str()]) {
                return fail("BAD_EVENT", "Not a member", h);
            }
            if !e["roles"].as_array().is_some_and(|r| r.iter().all(Value::is_string)) {
                return fail("BAD_EVENT", "Roles are a list of names", h);
            }
            obj(state, "members").get_mut(&member).unwrap()["roles"] = e["roles"].clone();
        }
        "ban.set" => {
            if truthy(&e["banned"]) {
                obj(state, "bans").insert(member.clone(), json!({ "since": h }));
                obj(state, "members").shift_remove(&member);
            } else {
                obj(state, "bans").shift_remove(&member);
            }
        }
        "channel.set" => {
            let Some(ch) = e["channel"].as_str().filter(|c| !c.is_empty()) else { return fail("BAD_EVENT", "A channel needs an id", h) };
            let since = match &state["channels"][ch]["since"] {
                Value::Null => h.clone(),
                s => s.clone(),
            };
            let name = if truthy(&e["name"]) { js_string(&e["name"]) } else { String::new() };
            let sealed = if truthy(&e["sealed"]) { e["sealed"].clone() } else { Value::Null };
            obj(state, "channels").insert(ch.to_string(), json!({ "name": name, "sealed": sealed, "since": since }));
        }
        "channel.remove" => {
            obj(state, "channels").shift_remove(&key_of(e, "channel"));
        }
        "content.ref" => {
            if truthy(&e["channel"]) && !truthy(&state["channels"][key_of(e, "channel").as_str()]) {
                return fail("BAD_EVENT", "No such channel", h);
            }
            add_content(state);
        }
        "note" => add_content(state),
        t => return fail("UNKNOWN_EVENT", format!("Unknown event type {t}"), h),
    }
    Ok(())
}

/// Apply one block to a state, checking everything. Returns the new state.
pub fn apply_block(prior: &Value, block: &Value) -> Result<Value> {
    let b = &block["body"];
    let h = &b["height"];
    if !truthy(block) || block["kind"] != BLOCK_KIND || !truthy(b) || !truthy(&block["sig"]) {
        return fail("MALFORMED", "Not a ledger block", h);
    }
    if len16(&canonical_json(block)?) > MAX_BLOCK_BYTES {
        return fail("TOO_LARGE", "Block too large", h);
    }
    let Some(events) = b["events"].as_array().filter(|e| !e.is_empty() && e.len() <= MAX_EVENTS) else { return fail("MALFORMED", "A block holds 1 to 256 events", h) };
    let expected = prior["height"].as_f64().unwrap_or(f64::NAN) + 1.0;
    if h.as_f64() != Some(expected) {
        return fail("WRONG_HEIGHT", format!("Expected block {expected}"), h);
    }
    if b["prev"] != prior["head"] {
        return fail("WRONG_PREV", "This block doesn't follow the one before it", h);
    }
    let height = expected as i64;
    if height > 0 && b["community"] != prior["community"] {
        return fail("WRONG_COMMUNITY", "This block belongs to another community", h);
    }
    if b["epoch"].as_f64().is_none() || b["epoch"].as_f64() != prior["epoch"].as_f64() {
        return fail("WRONG_EPOCH", "This block was made under a different authority", h);
    }
    let mut state = prior.clone();
    if height == 0 {
        let g = &events[0];
        if events.len() != 1 || g["type"] != "commons.genesis" {
            return fail("MALFORMED", "The first block holds only the genesis event", h);
        }
        let mut ctx = Ctx { caps: CAPS.iter().map(|c| c.to_string()).collect(), new_epoch: false };
        apply_event(&mut state, g, block, &mut ctx)?;
        let s = signer(&state, &block["sig"]["kid"]);
        if !s.as_ref().is_some_and(|s| s.authority && check_signature(block, &block["sig"], &s.public)) {
            return fail("BAD_SIGNATURE", "The first block must be signed by one of its own authority keys", h);
        }
        if (authority_signers(block, &state) as f64) < state["threshold"].as_f64().unwrap_or(f64::NAN) {
            return fail("THRESHOLD", "Not enough authority signatures", h);
        }
        state["community"] = json!(block_id(block)?);
    } else {
        let Some(s) = signer(prior, &block["sig"]["kid"]) else { return fail("UNKNOWN_SIGNER", "Signed by a key this community doesn't know", h) };
        if !check_signature(block, &block["sig"], &s.public) {
            return fail("BAD_SIGNATURE", "The block's signature doesn't match", h);
        }
        let mut ctx = Ctx { caps: s.caps.clone(), new_epoch: false };
        let needs_authority = events.iter().any(|e| e["type"].as_str().is_some_and(|t| AUTHORITY_EVENTS.contains(&t)));
        if needs_authority {
            let count = authority_signers(block, prior);
            let threshold = prior["threshold"].as_f64().unwrap_or(f64::NAN);
            if (count as f64) < threshold {
                return fail("THRESHOLD", format!("Needs {} authority signatures, has {count}", js_string(&prior["threshold"])), h);
            }
        }
        for e in events {
            let Some(t) = e["type"].as_str().filter(|_| truthy(e)) else { return fail("MALFORMED", "An event needs a type", h) };
            let Some(cap) = event_cap(t) else { return fail("UNKNOWN_EVENT", format!("Unknown event type {t}"), h) };
            if t == "commons.genesis" {
                return fail("BAD_EVENT", "A community only starts once", h);
            }
            let allowed = if cap == "authority" { needs_authority } else { s.caps.contains(cap) || (t == "member.remove" && e["member"] == block["sig"]["kid"]) };
            if !allowed {
                return fail("NOT_ALLOWED", format!("This signer can't make {t}"), h);
            }
            if AUTHORITY_EVENTS.contains(&t) && prior["policy"]["authority_change"] == "vote" {
                let result = &state["results"][key_of(e, "mandate").as_str()];
                if !truthy(&result["passed"]) || result["action"].as_str() != Some(action_hash(e)?.as_str()) {
                    return fail("NO_MANDATE", "This change needs a passed vote for exactly this change", h);
                }
            }
            apply_event(&mut state, e, block, &mut ctx)?;
        }
        if ctx.new_epoch {
            state["epoch"] = json!(state["epoch"].as_i64().unwrap_or(0) + 1);
        }
    }
    state["height"] = json!(height);
    state["head"] = json!(block_id(block)?);
    Ok(state)
}

/// Check a whole chain from its first block. Returns the final state.
pub fn replay(blocks: &[Value]) -> Result<Value> {
    let mut state = empty_state();
    for b in blocks {
        state = apply_block(&state, b)?;
    }
    Ok(state)
}

/// Make a block that follows a state. `at` is the block's (informational) time.
pub fn make_block(state: &Value, events: Value, key: &SigningKey, cosigners: &[SigningKey], at: &str) -> Result<Value> {
    let fresh = state["height"].as_i64().unwrap_or(-1) < 0;
    let body = json!({
        "community": if fresh { json!("") } else { state["community"].clone() },
        "height": state["height"].as_i64().unwrap_or(-1) + 1,
        "prev": state["head"],
        "epoch": state["epoch"],
        "at": at,
        "events": events,
    });
    let mut block = sign(BLOCK_KIND, &body, key)?;
    let cosigs: Vec<Value> = cosigners.iter().filter(|k| k.kid != key.kid).map(|k| cosign(&block, k)).collect::<Result<_>>()?;
    if !cosigs.is_empty() {
        block["cosigs"] = Value::Array(cosigs);
    }
    Ok(block)
}

/// Add a co-signature to a block waiting for enough of them.
pub fn add_cosignature(block: &Value, key: &SigningKey) -> Result<Value> {
    let mut out = block.clone();
    let mut cosigs: Vec<Value> = block["cosigs"].as_array().into_iter().flatten().filter(|s| s["kid"] != key.kid.as_str()).cloned().collect();
    cosigs.push(cosign(block, key)?);
    out["cosigs"] = Value::Array(cosigs);
    Ok(out)
}

/// The first block of a community. `spec`: `{ name, keys, threshold, home, replicas, succession, policy }`.
pub fn genesis(spec: &Value, key: &SigningKey, cosigners: &[SigningKey], at: &str) -> Result<Value> {
    let mut policy = default_policy();
    spread_into(&mut policy, &spec["policy"]);
    let or = |k: &str, d: Value| if spec[k].is_null() { d } else { spec[k].clone() };
    let event = json!({
        "type": "commons.genesis", "name": spec["name"], "keys": spec["keys"], "threshold": or("threshold", json!(1)),
        "home": spec["home"], "replicas": or("replicas", json!([])), "succession": or("succession", json!([])), "policy": Value::Object(policy),
    });
    make_block(&empty_state(), json!([event]), key, cosigners, at)
}

struct Side {
    blocks: Vec<Value>,
    state: Value,
}

/// Bring a copy up to date from another, choosing between branches the same way on every site:
/// more authority signatures on the first differing block, then the longer valid branch, then
/// the first block id in sort order. Never by timestamp. Keys that signed both sides of a split
/// are reported, with both blocks as proof.
pub fn reconcile(local: &[Value], remote: &[Value]) -> Result<Value> {
    let mut states = vec![empty_state()];
    let mut i = 0;
    while i < local.len() && i < remote.len() && block_id(&local[i])? == block_id(&remote[i])? {
        let next = apply_block(&states[i], &local[i])?;
        states.push(next);
        i += 1;
    }
    let base = states[i].clone();
    let extend = |blocks: &[Value]| -> Side {
        let mut out = Vec::new();
        let mut s = base.clone();
        for b in blocks.iter().skip(i) {
            match apply_block(&s, b) {
                Ok(n) => s = n,
                Err(_) => break,
            }
            out.push(b.clone());
        }
        Side { blocks: out, state: s }
    };
    let mine = extend(local);
    let theirs = extend(remote);
    let mut evidence = Vec::new();
    if !mine.blocks.is_empty() && !theirs.blocks.is_empty() {
        let (a, b) = (&mine.blocks[0], &theirs.blocks[0]);
        let signers_a: HashSet<String> = sigs_of(a).iter().map(|s| js_string(&s["kid"])).collect();
        for s in sigs_of(b) {
            let kid = js_string(&s["kid"]);
            if signers_a.contains(&kid) {
                evidence.push(json!({ "kid": s["kid"], "height": a["body"]["height"], "blocks": [a, b] }));
            }
        }
    }
    let score = |side: &Side| -> Result<(i64, usize, String)> {
        Ok(match side.blocks.first() {
            Some(first) => (authority_signers(first, &base) as i64, side.blocks.len(), block_id(first)?),
            None => (-1, 0, String::new()),
        })
    };
    let (sa, sb) = (score(&mine)?, score(&theirs)?);
    let take_theirs = if sb.0 != sa.0 {
        sb.0 > sa.0
    } else if sb.1 != sa.1 {
        sb.1 > sa.1
    } else {
        !theirs.blocks.is_empty() && crate::cv::identity::js_less(&sb.2, &sa.2)
    };
    let forked = !mine.blocks.is_empty() && !theirs.blocks.is_empty();
    let changed = take_theirs && !theirs.blocks.is_empty();
    let pick = if take_theirs { theirs } else { mine };
    let mut blocks: Vec<Value> = local[..i].to_vec();
    blocks.extend(pick.blocks);
    Ok(json!({ "blocks": blocks, "state": pick.state, "changed": changed, "forked": forked, "evidence": evidence }))
}

/// A site saying it serves a community, signed with the site's key.
pub fn announce_host(state: &Value, site: &str, role: &str, valid_for_s: i64, at_ms: i64, site_key: &SigningKey) -> Result<Value> {
    use crate::cv::encoding::iso_from_ms;
    let body = json!({
        "community": state["community"], "site": site, "role": role, "height": state["height"], "head": state["head"],
        "at": iso_from_ms(at_ms)?, "until": iso_from_ms(at_ms + valid_for_s * 1000)?,
    });
    sign(HOST_KIND, &body, site_key)
}

/// Which site to use now: home while it answers; otherwise, if the policy allows, the first
/// replica in succession order with a current copy. `{ site, role }` or null.
pub fn choose_host(state: &Value, announcements: &[Value], now: i64, unreachable: &HashSet<String>) -> Value {
    let mut valid: Vec<(String, Value)> = Vec::new();
    for a in announcements {
        let b = &a["body"];
        if a["kind"] != HOST_KIND || b["community"] != state["community"] {
            continue;
        }
        // Date.parse gives NaN for something unreadable, and NaN < now is false: it isn't skipped.
        if date_parse(b["until"].as_str().unwrap_or("")).is_some_and(|u| u < now) {
            continue;
        }
        let site = &b["site"];
        let who = if truthy(&state["home"]) && *site == state["home"]["site"] {
            Some(state["home"].clone())
        } else {
            state["replicas"].as_array().into_iter().flatten().find(|r| r["site"] == *site).cloned()
        };
        let Some(who) = who else { continue };
        if !who["pub"].as_str().is_some_and(|p| check_signature(a, &a["sig"], p)) {
            continue;
        }
        let key = js_string(site);
        let have = valid.iter().find(|(k, _)| *k == key).map(|(_, v)| v["body"]["height"].as_f64().unwrap_or(-1.0)).unwrap_or(-1.0);
        if b["height"].as_f64().is_some_and(|h| have < h) {
            valid.retain(|(k, _)| *k != key);
            valid.push((key, a.clone()));
        }
    }
    if truthy(&state["home"]) && !unreachable.contains(&js_string(&state["home"]["site"])) {
        return json!({ "site": state["home"]["site"], "role": "home" });
    }
    if !truthy(&state["policy"]["auto_failover"]) {
        return Value::Null;
    }
    let best = valid.iter().map(|(_, a)| a["body"]["height"].as_f64().unwrap_or(f64::NAN)).fold(-1.0_f64, |m, h| if h.is_nan() || m.is_nan() { f64::NAN } else { m.max(h) });
    for site in state["succession"].as_array().into_iter().flatten() {
        let key = js_string(site);
        if unreachable.contains(&key) {
            continue;
        }
        if let Some((_, a)) = valid.iter().find(|(k, _)| *k == key) {
            if a["body"]["height"].as_f64().is_some_and(|h| h >= best) {
                return json!({ "site": site, "role": "acting" });
            }
        }
    }
    Value::Null
}

/// A plain summary of a state.
pub fn describe(state: &Value) -> Value {
    let list = |k: &str, f: &dyn Fn(&Value) -> Value| -> Vec<Value> { state[k].as_array().into_iter().flatten().map(f).collect() };
    json!({
        "community": state["community"],
        "name": state["name"],
        "height": state["height"],
        "epoch": state["epoch"],
        "authority": state["keys"].as_array().into_iter().flatten().filter(|k| has_authority(k)).map(|k| k["kid"].clone()).collect::<Vec<_>>(),
        "threshold": state["threshold"],
        "home": if truthy(&state["home"]["site"]) { state["home"]["site"].clone() } else { json!("") },
        "replicas": list("replicas", &|r| r["site"].clone()),
        "succession": state["succession"],
        "members": state["members"].as_object().map(|m| m.len()).unwrap_or(0),
        "channels": state["channels"].as_object().map(|m| m.len()).unwrap_or(0),
    })
}
