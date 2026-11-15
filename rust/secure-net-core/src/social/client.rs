//! A reference client for CVP-017 to 019, matching `src/social/client.js`: what an app does on a
//! person's device, one device per client. Policy choices an app would make differently: it
//! accepts every follow, pins actors on first contact, and keeps everything in memory.
use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::session::keys::{create_account, create_device, create_prekeys, device_public, sign_device_list, Device};
use crate::session::{v1, v2};
use crate::signed::SigningKey;
use crate::social::activity::{session_activity, sign_activity, verify_activity, verify_session_activity};
use crate::social::actor::{actor_id_of, create_actor_document, handle_of, parse_handle, verify_actor_document};
use crate::social::delivery::{
    add_members, create_audience, delivery_verifier, new_delivery_token, open_audience, open_direct_payload, public_envelope, remove_members, seal_direct, seal_to_audience, sealed_body, session_tag, view_key,
};
use crate::social::repo::{append_to_repo, create_repo, export_repo};
use crate::social::site::MemoryNetwork;
use crate::social::vocabulary::{is_actor_id, FOLLOWERS, PUBLIC};

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

/// The highest session version a bundle's device says it speaks (from its signed prekey).
pub fn session_version_of(bundle: &Value) -> i64 {
    bundle["signed"]["body"]["sessions"].as_i64().filter(|s| *s >= 1).unwrap_or(1)
}

pub struct SocialClient {
    pub handle: String,
    pub host: String,
    pub typ: String,
    pub name: Option<String>,
    pub account: SigningKey,
    pub device: Device,
    pub id: String,
    pub device_list: Value,
    pub seq: i64,
    pub sessions: Map<String, Value>,
    pub by_tag: HashMap<String, String>,
    pub handshakes: HashSet<String>,
    pub known: HashMap<String, Value>,
    pub records: HashMap<String, Value>,
    pub followers: Value,
    pub views: HashMap<String, Value>,
    pub following: HashSet<String>,
    pub pending: Vec<(String, String)>,
    pub timeline: Vec<Value>,
    pub likes: HashMap<String, HashSet<String>>,
    pub repo: Value,
    pub actor_sent: HashMap<String, i64>,
    pub max_sessions: i64,
    pub deniable: bool,
    pub token: Option<String>,
    pub token_sent: HashSet<String>,
    pub tokens: HashMap<String, String>,
    pub peer_version: HashMap<String, i64>,
    pub prekeys: Map<String, Value>,
    pub actor_record: Value,
    pub now: i64,
}

impl SocialClient {
    /// `sessions`: the highest session version this client starts; `deniable`: whether direct
    /// activities go unsigned over version 2 sessions.
    pub fn new(handle: &str, typ: &str, name: Option<&str>, sessions: i64, deniable: bool, now: i64) -> Result<Self> {
        let (_, host, handle) = parse_handle(handle).ok_or_else(|| err("BAD_INPUT", "A handle looks like name@host"))?;
        let account = create_account();
        let device = create_device();
        let id = actor_id_of(&account.public_key)?;
        let device_list = sign_device_list(&account, vec![device_public(&device)], 1, now)?;
        Ok(Self {
            handle,
            host,
            typ: typ.into(),
            name: name.map(str::to_string),
            followers: create_audience(&id, "followers")?,
            repo: create_repo(&id),
            account,
            device,
            id,
            device_list,
            seq: 0,
            sessions: Map::new(),
            by_tag: HashMap::new(),
            handshakes: HashSet::new(),
            known: HashMap::new(),
            records: HashMap::new(),
            views: HashMap::new(),
            following: HashSet::new(),
            pending: vec![],
            timeline: vec![],
            likes: HashMap::new(),
            actor_sent: HashMap::new(),
            max_sessions: sessions,
            deniable,
            token: (sessions >= 2).then(new_delivery_token),
            token_sent: HashSet::new(),
            tokens: HashMap::new(),
            peer_version: HashMap::new(),
            prekeys: Map::new(),
            actor_record: Value::Null,
            now,
        })
    }

    fn actor_doc(&self) -> Result<Value> {
        let mut p = json!({ "handle": self.handle, "type": self.typ, "devices": self.device_list, "seq": self.seq, "now": self.now });
        if let Some(n) = &self.name {
            p["name"] = json!(n);
        }
        create_actor_document(&self.account, &p)
    }

    /// Publish the actor document and prekeys to our site.
    pub fn register(&mut self, net: &mut MemoryNetwork) -> Result<()> {
        self.seq += 1;
        self.actor_record = self.actor_doc()?;
        let pk = create_prekeys(&self.device, 10, 10, self.now, self.max_sessions)?;
        self.prekeys = pk.secrets;
        let site = net.site(&self.host)?;
        site.publish_actor(&self.actor_record)?;
        site.publish_prekeys(&self.id, &self.device.kid, pk.published)?;
        if let Some(t) = &self.token {
            site.set_delivery_verifiers(&self.id, &[delivery_verifier(t)?])?;
        }
        let r = self.actor_record.clone();
        self.remember(&r)?;
        Ok(())
    }

    pub fn remember(&mut self, record: &Value) -> Result<Value> {
        let id = record["body"]["id"].as_str().unwrap_or("").to_string();
        let min = self.known.get(&id).and_then(|p| p["seq"].as_i64()).unwrap_or(0);
        let body = verify_actor_document(record, Some(&id), None, min)?;
        self.known.insert(id.clone(), body.clone());
        self.records.insert(id, record.clone());
        Ok(body)
    }

    pub fn host_of(&self, actor_id: &str) -> Result<String> {
        let a = self.known.get(actor_id).ok_or_else(|| err("UNKNOWN_ACTOR", "Look this actor up first"))?;
        handle_of(&a["handle"]).and_then(|h| parse_handle(&h)).map(|h| h.1).ok_or_else(|| err("BAD_MESSAGE", "Bad handle"))
    }

    /// Look someone up by handle.
    pub fn lookup(&mut self, net: &mut MemoryNetwork, handle: &str) -> Result<Value> {
        let (name, host, full) = parse_handle(handle).ok_or_else(|| err("BAD_INPUT", "A handle looks like name@host"))?;
        let record = net.actor(&host, Some(&name), None)?;
        if let Some(moved) = record.get("moved") {
            let body = verify_actor_document(moved, None, None, 0)?;
            let new_host = handle_of(&body["handle"]).and_then(|h| parse_handle(&h)).map(|h| h.1).unwrap_or_default();
            let id = body["id"].as_str().unwrap_or("").to_string();
            let there = net.actor(&new_host, None, Some(&id))?;
            verify_actor_document(&there, Some(&id), Some(&body["handle"]), 0)?;
            return self.remember(&there);
        }
        verify_actor_document(&record, None, Some(&json!(full)), 0)?;
        self.remember(&record)
    }

    /// Sessions with every device of an actor, starting any that are missing.
    pub fn sessions_for(&mut self, net: &mut MemoryNetwork, actor_id: &str) -> Result<Map<String, Value>> {
        let actor = self.known.get(actor_id).cloned().ok_or_else(|| err("UNKNOWN_ACTOR", "Look this actor up first"))?;
        let mut out = Map::new();
        for d in actor["devices"]["body"]["devices"].as_array().cloned().unwrap_or_default() {
            let kid = d["kid"].as_str().unwrap_or("").to_string();
            if kid == self.device.kid {
                continue;
            }
            if !self.sessions.contains_key(&kid) {
                let bundle = net.bundle(&self.host_of(actor_id)?, actor_id, &kid)?;
                let account_key = actor["account"].as_str().unwrap_or("");
                let min_seq = actor["devices"]["body"]["seq"].as_i64().unwrap_or(0);
                let theirs = self.max_sessions.min(session_version_of(&bundle));
                if theirs < *self.peer_version.get(&kid).unwrap_or(&1) {
                    return Err(err("DOWNGRADE", "That device spoke a newer session version before"));
                }
                let state = if theirs >= 2 {
                    let me = v2::Me { device: &self.device, device_list: &self.device_list, prekeys: None };
                    serde_json::to_value(v2::initiate(&me, &bundle, account_key, min_seq, self.now)?).expect("JSON")
                } else {
                    let me = v1::Me { device: &self.device, device_list: &self.device_list, prekeys: None };
                    let st = v1::initiate(&me, &bundle, account_key, min_seq, self.now)?;
                    self.by_tag.insert(session_tag(&st.ad)?, kid.clone());
                    serde_json::to_value(st).expect("JSON")
                };
                self.sessions.insert(kid.clone(), state);
                self.peer_version.insert(kid.clone(), theirs);
            }
            out.insert(kid.clone(), self.sessions[&kid].clone());
        }
        Ok(out)
    }

    /// An activity for direct envelopes to these actors: unsigned if deniable and every session is version 2.
    pub fn direct(&mut self, net: &mut MemoryNetwork, recipients: &[String], activity: &Value) -> Result<Value> {
        let mut all2 = self.deniable;
        for a in recipients {
            let s = self.sessions_for(net, a)?;
            all2 = s.values().all(|st| st["v"] == 2) && all2;
        }
        if all2 {
            session_activity(&self.device, &self.id, activity, self.now)
        } else {
            sign_activity(&self.device, &self.id, activity, true, self.now)
        }
    }

    /// Send a payload to every device of an actor.
    pub fn send_direct(&mut self, net: &mut MemoryNetwork, actor_id: &str, payload: &Value) -> Result<&'static str> {
        let sessions = self.sessions_for(net, actor_id)?;
        let all2 = sessions.values().all(|st| st["v"] == 2);
        let mut out = payload.clone();
        let seq = self.actor_record["body"]["seq"].as_i64().unwrap_or(0);
        if self.actor_sent.get(actor_id) != Some(&seq) {
            out["actor"] = self.actor_record.clone();
        }
        let send_token = all2 && self.token.is_some() && !self.token_sent.contains(actor_id);
        if send_token {
            out["delivery"] = json!(self.token);
        }
        let sealed_ok = all2 && sessions.values().all(|st| st["pending"].is_null());
        let r = seal_direct(&sessions, &out)?;
        self.actor_sent.insert(actor_id.into(), seq);
        if send_token {
            self.token_sent.insert(actor_id.into());
        }
        for (k, v) in r["sessions"].as_object().unwrap() {
            self.sessions.insert(k.clone(), v.clone());
        }
        let envelopes: Vec<Value> = r["items"].as_array().unwrap().iter().map(|i| i["envelope"].clone()).collect();
        self.deliver(net, actor_id, &envelopes, sealed_ok)
    }

    /// Send envelopes that need no sender: sealed, straight to their site, if we hold their token.
    pub fn deliver(&mut self, net: &mut MemoryNetwork, actor_id: &str, envelopes: &[Value], sealed: bool) -> Result<&'static str> {
        let host = self.host_of(actor_id)?;
        if let Some(token) = self.tokens.get(actor_id).cloned().filter(|_| sealed) {
            let items: Vec<Value> = envelopes.iter().map(|e| json!({ "to": actor_id, "envelope": e, "token": token })).collect();
            match net.receive_sealed(&host, &sealed_body(&items)?) {
                Ok(()) => return Ok("sealed"),
                Err(e) if e.code == "UNTRUSTED" => {
                    self.tokens.remove(actor_id);
                }
                Err(e) => return Err(e),
            }
        }
        let items: Vec<Value> = envelopes.iter().map(|e| json!({ "host": host, "to": actor_id, "envelope": e })).collect();
        net.send(&self.host, &self.id, &items, self.now)?;
        Ok("site")
    }

    /// Replace our delivery token; the old one still works until people have the new one.
    pub fn rotate_delivery_token(&mut self, net: &mut MemoryNetwork) -> Result<()> {
        let old = self.token.clone().unwrap_or_default();
        let new = new_delivery_token();
        self.token = Some(new.clone());
        self.token_sent.clear();
        net.site(&self.host)?.set_delivery_verifiers(&self.id, &[delivery_verifier(&new)?, delivery_verifier(&old)?])
    }

    pub fn follower_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for m in self.followers["members"].as_array().into_iter().flatten() {
            let a = m["actor"].as_str().unwrap_or("").to_string();
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    /// Post a Note to "public", "followers" or a list of actor ids.
    pub fn post(&mut self, net: &mut MemoryNetwork, content: &str, to: &Value) -> Result<Value> {
        let object = json!({ "type": "Note", "content": content, "mediaType": "text/plain" });
        if *to == PUBLIC {
            let record = sign_activity(&self.device, &self.id, &json!({ "type": "Create", "to": [PUBLIC], "cc": [FOLLOWERS], "object": object }), false, self.now)?;
            self.repo = append_to_repo(&self.repo, &self.device, &record, self.now)?;
            let exported = export_repo(&self.repo, &self.actor_record);
            net.site(&self.host)?.publish_repo(&exported, self.now)?;
            let env = public_envelope(&record)?;
            let mut targets = vec![self.id.clone()];
            targets.extend(self.follower_ids());
            let items: Vec<Value> = targets.iter().map(|a| Ok(json!({ "host": self.host_of(a)?, "to": a, "envelope": env }))).collect::<Result<_>>()?;
            net.send(&self.host, &self.id, &items, self.now)?;
            return Ok(record);
        }
        if *to == FOLLOWERS {
            let record = sign_activity(&self.device, &self.id, &json!({ "type": "Create", "to": [FOLLOWERS], "object": object }), true, self.now)?;
            let r = seal_to_audience(&self.followers, &record)?;
            self.followers = r["audience"].clone();
            let items: Vec<Value> = self.follower_ids().iter().map(|a| Ok(json!({ "host": self.host_of(a)?, "to": a, "envelope": r["envelope"] }))).collect::<Result<_>>()?;
            if !items.is_empty() {
                net.send(&self.host, &self.id, &items, self.now)?;
            }
            return Ok(record);
        }
        let Some(list) = to.as_array().filter(|l| l.iter().all(|x| is_actor_id(Some(x)))) else { return Err(err("BAD_INPUT", "to must be public, followers or a list of actor ids")) };
        let ids: Vec<String> = list.iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let record = self.direct(net, &ids, &json!({ "type": "Create", "to": ids, "object": object }))?;
        for a in &ids {
            self.send_direct(net, a, &json!({ "activity": record }))?;
        }
        Ok(record)
    }

    pub fn follow(&mut self, net: &mut MemoryNetwork, handle: &str) -> Result<()> {
        let target = self.lookup(net, handle)?;
        let tid = target["id"].as_str().unwrap_or("").to_string();
        let record = self.direct(net, std::slice::from_ref(&tid), &json!({ "type": "Follow", "to": [tid], "object": tid }))?;
        self.pending.push((record["body"]["id"].as_str().unwrap_or("").to_string(), tid.clone()));
        self.send_direct(net, &tid, &json!({ "activity": record }))?;
        Ok(())
    }

    pub fn unfollow(&mut self, net: &mut MemoryNetwork, actor_id: &str) -> Result<()> {
        let follow = self.pending.iter().find(|(_, a)| a == actor_id).map(|(f, _)| f.clone());
        self.following.remove(actor_id);
        let Some(follow) = follow else { return Ok(()) };
        let rec = self.direct(net, &[actor_id.to_string()], &json!({ "type": "Undo", "to": [actor_id], "object": follow }))?;
        self.send_direct(net, actor_id, &json!({ "activity": rec }))?;
        Ok(())
    }

    pub fn like(&mut self, net: &mut MemoryNetwork, object_id: &str, author_id: &str) -> Result<()> {
        let rec = self.direct(net, &[author_id.to_string()], &json!({ "type": "Like", "to": [author_id], "object": object_id }))?;
        self.send_direct(net, author_id, &json!({ "activity": rec }))?;
        Ok(())
    }

    /// Remove a follower and give everyone else a new key.
    pub fn remove_follower(&mut self, net: &mut MemoryNetwork, actor_id: &str) -> Result<()> {
        let r = remove_members(&self.followers, &|m: &Value| m["actor"] == actor_id)?;
        self.followers = r["audience"].clone();
        let mut sent: Vec<String> = Vec::new();
        for m in r["send"]["to"].as_array().cloned().unwrap_or_default() {
            let a = m["actor"].as_str().unwrap_or("").to_string();
            if !sent.contains(&a) {
                self.send_direct(net, &a, &json!({ "senderKeys": [r["send"]["senderKey"]] }))?;
                sent.push(a);
            }
        }
        Ok(())
    }

    /// Move to another site, keeping the same actor id, keys, followers and sessions.
    pub fn migrate(&mut self, net: &mut MemoryNetwork, new_handle: &str) -> Result<()> {
        let (_, host, handle) = parse_handle(new_handle).ok_or_else(|| err("BAD_INPUT", "A handle looks like name@host"))?;
        let from = self.host.clone();
        self.seq += 1;
        self.handle = handle;
        self.actor_record = self.actor_doc()?;
        let pk = create_prekeys(&self.device, 10, 10, self.now, 2)?;
        for (k, v) in pk.secrets {
            self.prekeys.insert(k, v);
        }
        {
            let to = net.site(&host)?;
            to.publish_actor(&self.actor_record)?;
            to.publish_prekeys(&self.id, &self.device.kid, pk.published)?;
        }
        if !self.repo["head"].is_null() {
            let exported = export_repo(&self.repo, &self.actor_record);
            net.site(&host)?.publish_repo(&exported, self.now)?;
        }
        net.site(&from)?.release(&self.actor_record)?;
        self.host = host;
        let r = self.actor_record.clone();
        self.remember(&r)?;
        let mut everyone = self.follower_ids();
        for f in self.following.clone() {
            if !everyone.contains(&f) {
                everyone.push(f);
            }
        }
        for a in everyone {
            let rec = self.direct(net, std::slice::from_ref(&a), &json!({ "type": "Update", "to": [a], "object": { "type": self.typ, "id": self.id } }))?;
            self.send_direct(net, &a, &json!({ "activity": rec }))?;
        }
        Ok(())
    }

    /// Collect and process our mailbox: what was shown, as `{ kind, ... }`.
    pub fn sync(&mut self, net: &mut MemoryNetwork) -> Result<Vec<Value>> {
        let mut shown = Vec::new();
        let items = net.site(&self.host)?.collect(&self.id);
        for d in items {
            match self.open(net, &d.envelope, d.from.as_deref()) {
                Ok(Some(r)) if !r.is_null() => shown.push(r),
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => shown.push(json!({ "kind": "refused", "reason": e.code })),
            }
        }
        Ok(shown)
    }

    fn open(&mut self, net: &mut MemoryNetwork, env: &Value, from_host: Option<&str>) -> Result<Option<Value>> {
        match env["mode"].as_str() {
            Some("public") => {
                let author = env["activity"]["body"]["actor"].as_str().unwrap_or("").to_string();
                if !self.known.contains_key(&author) {
                    let rec = net.actor(from_host.unwrap_or(""), None, Some(&author))?;
                    self.remember(&rec)?;
                }
                let b = verify_activity(&env["activity"], &self.known[&author], false, self.now)?;
                return self.handle(net, &b, "public", false).map(Some);
            }
            Some("audience") => {
                let key = view_key(env["audience"].as_str().unwrap_or(""), env["message"]["id"].as_str().unwrap_or(""));
                let Some(view) = self.views.get(&key).cloned() else {
                    return Ok(Some(json!({ "kind": "unreadable", "reason": "no key for this audience (not a member when it was sealed)" })));
                };
                let r = open_audience(&view, env)?;
                self.views.insert(key, r["view"].clone());
                let author = r["activity"]["body"]["actor"].as_str().unwrap_or("").to_string();
                let doc = self.known.get(&author).cloned().unwrap_or(Value::Null);
                let b = verify_activity(&r["activity"], &doc, true, self.now)?;
                return self.handle(net, &b, "followers", false).map(Some);
            }
            Some("group") => return Ok(Some(json!({ "kind": "unreadable", "reason": "this client doesn't do groups" }))),
            _ => {}
        }
        if env["device"] != self.device.kid.as_str() {
            return Ok(None);
        }
        let (peer, plaintext, version) = if env["v"] == 2 { self.open_direct2(env)? } else { self.open_direct1(env)? };
        let from_actor = actor_id_of(self.sessions[&peer]["peer"]["account"].as_str().unwrap_or(""))?;
        let p = open_direct_payload(&plaintext, &peer, &from_actor, version)?;
        if p.get("actor").is_some_and(crate::js::truthy) {
            self.remember(&p["actor"])?;
        }
        if let Some(t) = p["delivery"].as_str() {
            self.tokens.insert(from_actor.clone(), t.to_string());
        }
        for v in p["senderKeys"].as_array().cloned().unwrap_or_default() {
            self.views.insert(view_key(v["group"].as_str().unwrap_or(""), v["id"].as_str().unwrap_or("")), v);
        }
        let doc = self.known.get(&from_actor).cloned().unwrap_or(Value::Null);
        if let Some(u) = p.get("unsigned") {
            let b = verify_session_activity(u, &doc, &peer, self.now)?;
            return self.handle(net, &b, "direct", true).map(Some);
        }
        let Some(a) = p.get("activity") else { return Ok(Some(json!({ "kind": "keys", "from": from_actor }))) };
        let b = verify_activity(a, &doc, true, self.now)?;
        self.handle(net, &b, "direct", false).map(Some)
    }

    fn open_direct1(&mut self, env: &Value) -> Result<(String, Vec<u8>, i64)> {
        let peer = env["session"].as_str().and_then(|t| self.by_tag.get(t)).cloned();
        if peer.is_none() && v1::is_initial(&env["message"]) {
            let (account, device, handshake) = v1::initial_sender(&env["message"]).ok_or_else(|| err("BAD_MESSAGE", "Not a first message"))?;
            if *self.peer_version.get(&device).unwrap_or(&1) > 1 {
                return Err(err("DOWNGRADE", "That device spoke a newer session version before"));
            }
            if handshake.as_ref().is_some_and(|h| self.handshakes.contains(h)) {
                return Err(err("REPLAY", "First message already received"));
            }
            let me = v1::Me { device: &self.device, device_list: &self.device_list, prekeys: Some(&self.prekeys) };
            let r = v1::respond(&me, &env["message"], &account, 0)?;
            if let Some(h) = v1::handshake_id(&env["message"]) {
                self.handshakes.insert(h);
            }
            self.prekeys = r.prekeys;
            let peer = r.state.peer.device.clone();
            self.by_tag.insert(session_tag(&r.state.ad)?, peer.clone());
            self.sessions.insert(peer.clone(), serde_json::to_value(&r.state).expect("JSON"));
            return Ok((peer, r.plaintext, 1));
        }
        let peer = peer.ok_or_else(|| err("UNKNOWN_SESSION", "No session for that tag"))?;
        let st: v1::State = serde_json::from_value(self.sessions[&peer].clone()).map_err(|_| err("BAD_INPUT", "Corrupt session state"))?;
        let (st, plaintext) = v1::decrypt(&st, &env["message"])?;
        self.sessions.insert(peer.clone(), serde_json::to_value(st).expect("JSON"));
        Ok((peer, plaintext, 1))
    }

    fn open_direct2(&mut self, env: &Value) -> Result<(String, Vec<u8>, i64)> {
        if self.max_sessions < 2 {
            return Err(err("BAD_MESSAGE", "Unsupported message version"));
        }
        for (peer, state) in self.sessions.clone() {
            if state["v"] != 2 {
                continue;
            }
            let st: v2::State = serde_json::from_value(state).map_err(|_| err("BAD_INPUT", "Corrupt session state"))?;
            if !v2::can_open(&st, &env["message"]) {
                continue;
            }
            let (st, plaintext) = v2::decrypt(&st, &env["message"], self.now)?;
            self.sessions.insert(peer.clone(), serde_json::to_value(st).expect("JSON"));
            return Ok((peer, plaintext, 2));
        }
        if !v2::is_initial(&env["message"]) {
            return Err(err("UNKNOWN_SESSION", "No session opens that message"));
        }
        let me = v2::Me { device: &self.device, device_list: &self.device_list, prekeys: Some(&self.prekeys) };
        let who = v2::initial_sender(&me, &env["message"])?;
        let handshake = who["handshake"].as_str().unwrap_or("").to_string();
        if self.handshakes.contains(&handshake) {
            return Err(err("REPLAY", "First message already received"));
        }
        let r = v2::respond(&me, &env["message"], who["account"].as_str().unwrap_or(""), 0, self.now)?;
        self.handshakes.insert(handshake);
        self.prekeys = r.prekeys;
        let peer = r.state.peer.device.clone();
        self.sessions.insert(peer.clone(), serde_json::to_value(&r.state).expect("JSON"));
        self.peer_version.insert(peer.clone(), 2);
        Ok((peer, r.plaintext, 2))
    }

    fn handle(&mut self, net: &mut MemoryNetwork, a: &Value, how: &str, deniable: bool) -> Result<Value> {
        let actor = a["actor"].as_str().unwrap_or("").to_string();
        let author = self.known.get(&actor).cloned().unwrap_or(Value::Null);
        let who = format!("@{}", crate::js::show(author.get("handle")));
        Ok(match a["type"].as_str().unwrap_or("") {
            "Create" => {
                let o = &a["object"];
                self.timeline.push(json!({ "id": o["id"], "from": who, "how": how, "content": o["content"], "type": o["type"], "object": o, "deniable": deniable }));
                let content = if o.get("content").is_some_and(|c| !c.is_null()) { o["content"].clone() } else { o["name"].clone() };
                json!({ "kind": "post", "from": who, "how": how, "content": content, "id": o["id"], "type": o["type"], "deniable": deniable })
            }
            "Update" => {
                if a["object"]["id"] == a["actor"] {
                    json!({ "kind": "profile-updated", "from": who })
                } else {
                    json!({ "kind": "other", "type": a["type"], "from": who })
                }
            }
            "Follow" => {
                if a["object"] != self.id.as_str() {
                    return Ok(Value::Null);
                }
                let devices: Vec<Value> = author["devices"]["body"]["devices"].as_array().into_iter().flatten().map(|d| json!({ "actor": actor, "device": d["kid"] })).collect();
                let r = add_members(&self.followers, &devices)?;
                self.followers = r["audience"].clone();
                let accept = self.direct(net, std::slice::from_ref(&actor), &json!({ "type": "Accept", "to": [actor], "object": a["id"] }))?;
                self.send_direct(net, &actor, &json!({ "activity": accept, "senderKeys": [r["send"]["senderKey"]] }))?;
                json!({ "kind": "followed-by", "from": who })
            }
            "Accept" => {
                if self.pending.iter().any(|(f, x)| a["object"] == f.as_str() && *x == actor) {
                    self.following.insert(actor.clone());
                }
                json!({ "kind": "accepted", "from": who })
            }
            "Undo" => {
                if !self.followers["members"].as_array().into_iter().flatten().any(|m| m["actor"] == actor.as_str()) {
                    return Ok(Value::Null);
                }
                self.remove_follower(net, &actor)?;
                json!({ "kind": "unfollowed-by", "from": who })
            }
            "Like" => {
                let o = a["object"].as_str().unwrap_or("").to_string();
                self.likes.entry(o.clone()).or_default().insert(actor);
                json!({ "kind": "like", "from": who, "object": o })
            }
            _ => json!({ "kind": "other", "type": a["type"], "from": who }),
        })
    }
}
