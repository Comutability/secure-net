//! A reference site for CVP-017 and CVP-019, in memory, matching `src/social/site.js`: what a
//! server must do, without a web framework or database, so the protocol can be tested end to end.
//! Sites live in a [`MemoryNetwork`], which records everything that crosses it.
//!
//! A site never needs, and never gets, a key that opens a direct or audience envelope.
use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::bytes::{b64u, random, random_b64u};
use crate::canonical::canonical_json;
use crate::cv::encoding::iso_from_ms;
use crate::error::{Error, Result};
use crate::session::keys::{take_bundle, Published};
use crate::social::activity::verify_activity;
use crate::social::actor::{handle_of, parse_handle, verify_actor_document};
use crate::social::delivery::{delivery_body, delivery_verifier, envelope_problems, read_delivery_body, read_sealed_body};
use crate::social::lexicon::verify_lexicon;
use crate::social::repo::verify_repo;
use crate::wire::features::describe_site;
use crate::wire::federation::{digest_of, norm_host, sign_request, verify_request, RequestFields, DEFAULT_ENDPOINTS, SKEW_MS, SOCIAL_ENDPOINTS};

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn deliver_path() -> &'static str {
    SOCIAL_ENDPOINTS.iter().find(|(k, _)| *k == "deliver").unwrap().1
}

/// One stored item in a mailbox.
#[derive(Clone, Debug)]
pub struct Delivered {
    pub envelope: Value,
    pub from: Option<String>,
}

pub struct ReferenceSite {
    pub host: String,
    pub secret_key: String,
    pub public_key: String,
    pub actors: HashMap<String, Value>,
    pub handles: HashMap<String, String>,
    pub prekeys: HashMap<String, Published>,
    pub mailboxes: HashMap<String, Vec<Delivered>>,
    pub public: HashMap<String, Vec<Value>>,
    pub seen_nonces: HashSet<String>,
    pub repos: HashMap<String, Value>,
    pub change_log: Vec<Value>,
    pub moved: HashMap<String, Value>,
    pub lexicons: HashMap<String, Value>,
    pub key_packages: HashMap<String, Vec<String>>,
    pub verifiers: HashMap<String, Vec<String>>,
    pub sealed_log: Vec<Value>,
}

impl ReferenceSite {
    pub fn new(host: &str) -> Result<Self> {
        let host = norm_host(host).ok_or_else(|| err("BAD_INPUT", "Bad host"))?;
        let seed = random::<32>();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Ok(Self {
            host,
            secret_key: b64u(&seed),
            public_key: b64u(sk.verifying_key().as_bytes()),
            actors: HashMap::new(),
            handles: HashMap::new(),
            prekeys: HashMap::new(),
            mailboxes: HashMap::new(),
            public: HashMap::new(),
            seen_nonces: HashSet::new(),
            repos: HashMap::new(),
            change_log: vec![],
            moved: HashMap::new(),
            lexicons: HashMap::new(),
            key_packages: HashMap::new(),
            verifiers: HashMap::new(),
            sealed_log: vec![],
        })
    }

    /// The site document.
    pub fn document(&self) -> Value {
        let mut doc = describe_site(None);
        doc["host"] = json!(self.host);
        doc["public_key"] = json!(self.public_key);
        let mut ep = serde_json::Map::new();
        for (k, v) in DEFAULT_ENDPOINTS.iter().chain(SOCIAL_ENDPOINTS.iter()) {
            ep.insert(k.to_string(), json!(v));
        }
        doc["endpoints"] = Value::Object(ep);
        doc
    }

    /// An actor document by handle name or id, or `{ moved }` if they have moved on.
    pub fn actor(&self, handle: Option<&str>, id: Option<&str>) -> Result<Value> {
        let key = match id {
            Some(i) => i.to_string(),
            None => handle.unwrap_or("").to_lowercase(),
        };
        if let Some(m) = self.moved.get(&key) {
            return Ok(json!({ "moved": m }));
        }
        let actor_id = match id {
            Some(i) => Some(i.to_string()),
            None => self.handles.get(&key).cloned(),
        };
        actor_id.and_then(|a| self.actors.get(&a).cloned()).ok_or_else(|| err("NOT_FOUND", "No such actor here"))
    }

    /// One bundle for a device, using up a one-time prekey.
    pub fn bundle(&mut self, actor_id: &str, device: &str) -> Result<Value> {
        let doc = self.actors.get(actor_id).cloned();
        let k = format!("{actor_id}/{device}");
        match (doc, self.prekeys.get_mut(&k)) {
            (Some(doc), Some(pubk)) => Ok(take_bundle(&doc["body"]["devices"], pubk, device)),
            _ => Err(err("NOT_FOUND", "No prekeys for that device")),
        }
    }

    pub fn public_activities(&self, actor_id: &str) -> Vec<Value> {
        self.public.get(actor_id).cloned().unwrap_or_default()
    }

    pub fn repo(&self, actor_id: &str) -> Result<Value> {
        self.repos.get(actor_id).cloned().ok_or_else(|| err("NOT_FOUND", "No repository for that actor here"))
    }

    pub fn changes(&self, cursor: usize) -> Value {
        json!({ "cursor": self.change_log.len(), "commits": self.change_log.iter().skip(cursor).collect::<Vec<_>>() })
    }

    pub fn lexicon(&self, id: &str) -> Result<Value> {
        self.lexicons.get(id).cloned().ok_or_else(|| err("NOT_FOUND", "No such lexicon here"))
    }

    pub fn publish_repo(&mut self, exported: &Value, now: i64) -> Result<Value> {
        let id = exported["actor"]["body"]["id"].as_str().unwrap_or("").to_string();
        let min = self.repos.get(&id).map(|p| p["head"]["body"]["seq"].as_i64().unwrap_or(0) + 1).unwrap_or(0);
        let v = verify_repo(exported, None, min, now)?;
        let actor_id = v["actor"]["id"].as_str().unwrap_or("").to_string();
        if !self.actors.contains_key(&actor_id) {
            return Err(err("UNTRUSTED", "Not a local actor"));
        }
        self.repos.insert(actor_id.clone(), exported.clone());
        self.change_log.push(json!({ "actor": actor_id, "head": exported["head"] }));
        Ok(v["commit"].clone())
    }

    pub fn publish_lexicon(&mut self, record: &Value) -> Result<()> {
        let author = record["sig"]["kid"].as_str().and_then(|k| self.actors.get(k)).cloned().ok_or_else(|| err("UNTRUSTED", "Not a local actor"))?;
        let id = record["body"]["id"].as_str().unwrap_or("").to_string();
        let min = self.lexicons.get(&id).map(|l| l["body"]["revision"].as_i64().unwrap_or(0)).unwrap_or(0) + 1;
        let l = verify_lexicon(record, &author["body"], min)?;
        self.lexicons.insert(l["id"].as_str().unwrap_or("").to_string(), record.clone());
        Ok(())
    }

    /// An actor has moved to another site: stop hosting them and point lookups at the new document.
    pub fn release(&mut self, record: &Value) -> Result<()> {
        let id = record["body"]["id"].as_str().unwrap_or("").to_string();
        let prev = self.actors.get(&id).cloned().ok_or_else(|| err("NOT_FOUND", "Not a local actor"))?;
        let body = verify_actor_document(record, Some(&id), None, prev["body"]["seq"].as_i64().unwrap_or(0) + 1)?;
        let new_host = handle_of(&body["handle"]).and_then(|h| parse_handle(&h)).map(|h| h.1);
        if new_host.as_deref() == Some(self.host.as_str()) {
            return Err(err("BAD_INPUT", "That document is still for this site"));
        }
        let name = handle_of(&prev["body"]["handle"]).and_then(|h| parse_handle(&h)).map(|h| h.0).unwrap_or_default();
        self.moved.insert(name.clone(), record.clone());
        self.moved.insert(id.clone(), record.clone());
        self.actors.remove(&id);
        self.handles.remove(&name);
        self.mailboxes.remove(&id);
        self.repos.remove(&id);
        Ok(())
    }

    pub fn publish_actor(&mut self, record: &Value) -> Result<()> {
        let id = record["body"]["id"].as_str().unwrap_or("").to_string();
        let prev = self.actors.get(&id).cloned();
        let min = prev.as_ref().map(|p| p["body"]["seq"].as_i64().unwrap_or(0) + 1).unwrap_or(0);
        let body = verify_actor_document(record, None, None, min)?;
        let (name, host, _) = handle_of(&body["handle"]).and_then(|h| parse_handle(&h)).ok_or_else(|| err("BAD_MESSAGE", "Bad handle"))?;
        if host != self.host {
            return Err(err("BAD_INPUT", "That handle belongs to another site"));
        }
        let holder = self.handles.get(&name);
        let taken_by_move = self.moved.get(&name).is_some_and(|m| m["body"]["id"] != body["id"]);
        if holder.is_some_and(|h| *h != id) || taken_by_move {
            return Err(err("TAKEN", "That handle is taken"));
        }
        self.moved.remove(&name);
        self.moved.remove(&id);
        if let Some(p) = &prev {
            if p["body"]["handle"] != body["handle"] {
                if let Some((old, _, _)) = handle_of(&p["body"]["handle"]).and_then(|h| parse_handle(&h)) {
                    self.handles.remove(&old);
                }
            }
        }
        self.actors.insert(id.clone(), record.clone());
        self.handles.insert(name, id.clone());
        self.mailboxes.entry(id).or_default();
        Ok(())
    }

    fn device_listed(&self, actor_id: &str, device: &str) -> bool {
        self.actors.get(actor_id).is_some_and(|d| d["body"]["devices"]["body"]["devices"].as_array().into_iter().flatten().any(|x| x["kid"] == device))
    }

    pub fn publish_prekeys(&mut self, actor_id: &str, device: &str, published: Published) -> Result<()> {
        if !self.device_listed(actor_id, device) {
            return Err(err("BAD_INPUT", "That device isn't on the actor's device list"));
        }
        self.prekeys.insert(format!("{actor_id}/{device}"), published);
        Ok(())
    }

    pub fn publish_key_packages(&mut self, actor_id: &str, device: &str, list: &[String]) -> Result<()> {
        if !self.device_listed(actor_id, device) {
            return Err(err("BAD_INPUT", "That device isn't on the actor's device list"));
        }
        if list.is_empty() || list.len() > 100 {
            return Err(err("BAD_INPUT", "1 to 100 key packages"));
        }
        self.key_packages.insert(format!("{actor_id}/{device}"), list.to_vec());
        Ok(())
    }

    pub fn key_package(&mut self, actor_id: &str, device: &str) -> Result<String> {
        let list = self.key_packages.get_mut(&format!("{actor_id}/{device}")).filter(|l| !l.is_empty()).ok_or_else(|| err("NOT_FOUND", "No key packages for that device"))?;
        Ok(if list.len() > 1 { list.remove(0) } else { list[0].clone() })
    }

    pub fn set_delivery_verifiers(&mut self, actor_id: &str, verifiers: &[String]) -> Result<()> {
        if !self.actors.contains_key(actor_id) {
            return Err(err("UNTRUSTED", "Not a local actor"));
        }
        if verifiers.len() > 2 || verifiers.iter().any(|v| !(v.len() == 43 && crate::social::vocabulary::b64u_chars(v))) {
            return Err(err("BAD_INPUT", "Up to two verifiers"));
        }
        self.verifiers.insert(actor_id.into(), verifiers.to_vec());
        Ok(())
    }

    /// Sealed deliveries: accepted whole, only if every item carries a token its recipient accepts.
    pub fn receive_sealed(&mut self, body: &Value) -> Result<()> {
        let items = read_sealed_body(body, "BAD_MESSAGE")?;
        for it in &items {
            let accepted = self.verifiers.get(it["to"].as_str().unwrap_or("")).cloned().unwrap_or_default();
            if !accepted.contains(&delivery_verifier(it["token"].as_str().unwrap_or(""))?) {
                return Err(err("UNTRUSTED", "That delivery token isn't accepted"));
            }
        }
        for it in &items {
            self.sealed_log.push(json!({ "to": it["to"], "mode": it["envelope"]["mode"], "bytes": it["envelope"].to_string().len() }));
            self.store(&it["to"], &it["envelope"], None)?;
        }
        Ok(())
    }

    pub fn collect(&mut self, actor_id: &str) -> Vec<Delivered> {
        std::mem::take(self.mailboxes.entry(actor_id.into()).or_default())
    }

    fn keep_public(&mut self, activity: &Value) {
        let actor = activity["body"]["actor"].as_str().unwrap_or("").to_string();
        self.public.entry(actor).or_default().push(activity.clone());
    }

    fn store(&mut self, to: &Value, envelope: &Value, from: Option<&str>) -> Result<()> {
        if !envelope_problems(envelope)?.is_empty() {
            return Err(err("BAD_MESSAGE", "Bad envelope"));
        }
        if let Some(b) = to.as_str().and_then(|t| self.mailboxes.get_mut(t)) {
            b.push(Delivered { envelope: envelope.clone(), from: from.map(str::to_string) });
        }
        Ok(())
    }
}

/// A network of sites that records everything sent across it.
#[derive(Default)]
pub struct MemoryNetwork {
    pub sites: HashMap<String, ReferenceSite>,
    pub log: Vec<String>,
}

impl MemoryNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, site: ReferenceSite) {
        self.sites.insert(site.host.clone(), site);
    }

    pub fn site(&mut self, host: &str) -> Result<&mut ReferenceSite> {
        self.sites.get_mut(host).ok_or_else(|| err("UNREACHABLE", format!("No site at {host}")))
    }

    pub fn record(&mut self, what: &Value) {
        self.log.push(what.to_string());
    }

    /// Look an actor up on a site, as another party would (recorded).
    pub fn actor(&mut self, host: &str, handle: Option<&str>, id: Option<&str>) -> Result<Value> {
        let r = self.site(host)?.actor(handle, id)?;
        self.record(&r);
        Ok(r)
    }

    pub fn bundle(&mut self, host: &str, actor_id: &str, device: &str) -> Result<Value> {
        let b = self.site(host)?.bundle(actor_id, device)?;
        self.record(&b);
        Ok(b)
    }

    pub fn receive_sealed(&mut self, host: &str, body: &Value) -> Result<()> {
        self.record(&json!({ "sealed": true, "to": host, "body": body }));
        self.site(host)?.receive_sealed(body)
    }

    /// The outbox of `host`: items `[{ host, to, envelope }]` from a local actor. Local recipients
    /// get them straight away; the rest go to their sites, one signed request per 100 items.
    pub fn send(&mut self, host: &str, from_actor: &str, items: &[Value], now: i64) -> Result<()> {
        if !self.site(host)?.actors.contains_key(from_actor) {
            return Err(err("UNTRUSTED", "Not a local actor"));
        }
        let mut by_host: Vec<(String, Vec<Value>)> = Vec::new();
        for it in items {
            let h = it["host"].as_str().and_then(norm_host).ok_or_else(|| err("BAD_INPUT", "Bad host"))?;
            let entry = json!({ "to": it["to"], "envelope": it["envelope"] });
            match by_host.iter_mut().find(|(k, _)| *k == h) {
                Some((_, l)) => l.push(entry),
                None => by_host.push((h, vec![entry])),
            }
        }
        for (to_host, list) in by_host {
            for it in &list {
                if it["envelope"]["mode"] == "public" {
                    self.site(host)?.keep_public(&it["envelope"]["activity"]);
                }
            }
            if to_host == host {
                for it in read_delivery_body(&delivery_body(&list)?)? {
                    self.site(host)?.store(&it["to"], &it["envelope"], Some(host))?;
                }
                continue;
            }
            for chunk in list.chunks(100) {
                self.deliver(host, &to_host, chunk, now)?;
            }
        }
        Ok(())
    }

    fn deliver(&mut self, from: &str, to: &str, items: &[Value], now: i64) -> Result<()> {
        let text = canonical_json(&delivery_body(items)?)?;
        let date = iso_from_ms(now)?;
        let nonce = random_b64u(16);
        let digest = digest_of(text.as_bytes());
        let fields = RequestFields { method: "POST", to, path: deliver_path(), from, date: &date, nonce: &nonce, digest: &digest, user: "" };
        let signature = sign_request(&fields, &self.site(from)?.secret_key.clone())?;
        let request = json!({ "method": "POST", "to": to, "path": deliver_path(), "from": from, "date": date, "nonce": nonce, "digest": digest, "signature": signature, "body": text });
        self.record(&request);
        self.receive(to, &request, now)
    }

    /// A signed delivery from another site arriving at `host`. Accepted whole or not at all.
    pub fn receive(&mut self, host: &str, request: &Value, now: i64) -> Result<()> {
        let s = |k: &str| request[k].as_str().unwrap_or("").to_string();
        let (to, path, method, from, date, nonce, digest, body) = (s("to"), s("path"), s("method"), s("from"), s("date"), s("nonce"), s("digest"), s("body"));
        if to != host || path != deliver_path() || method != "POST" {
            return Err(err("BAD_REQUEST", "Not a delivery for this site"));
        }
        if !crate::js::date_parse(&date).is_some_and(|t| (now - t).abs() <= SKEW_MS) {
            return Err(err("BAD_TIME", "Request is too old or from the future"));
        }
        let nonce_key = format!("{from}/{nonce}");
        if self.site(host)?.seen_nonces.contains(&nonce_key) {
            return Err(err("REPLAY", "Request already received"));
        }
        if digest_of(body.as_bytes()) != digest {
            return Err(err("BAD_REQUEST", "Body doesn't match its digest"));
        }
        let sender_key = self.site(&from)?.public_key.clone();
        let user = s("user");
        let fields = RequestFields { method: &method, to: &to, path: &path, from: &from, date: &date, nonce: &nonce, digest: &digest, user: &user };
        if !verify_request(&fields, &s("signature"), &sender_key) {
            return Err(err("UNTRUSTED", "Request signature doesn't match the sending site"));
        }
        self.site(host)?.seen_nonces.insert(nonce_key);
        let parsed: Value = serde_json::from_str(&body).map_err(|_| err("BAD_MESSAGE", "Not a version 1 delivery"))?;
        let items = read_delivery_body(&parsed)?;
        for it in &items {
            if it["envelope"]["mode"] == "public" {
                self.check_public(&it["envelope"]["activity"], &from, now)?;
            }
        }
        for it in &items {
            self.site(host)?.store(&it["to"], &it["envelope"], Some(&from))?;
        }
        Ok(())
    }

    fn check_public(&mut self, activity: &Value, from_host: &str, now: i64) -> Result<()> {
        let author = activity["body"]["actor"].as_str().unwrap_or("").to_string();
        let record = self.actor(from_host, None, Some(&author))?;
        let doc = verify_actor_document(&record, Some(&author), None, 0)?;
        let host = handle_of(&doc["handle"]).and_then(|h| parse_handle(&h)).map(|h| h.1);
        if host.as_deref() != Some(from_host) {
            return Err(err("UNTRUSTED", "A public activity must come from its author's own site"));
        }
        verify_activity(activity, &doc, false, now)?;
        Ok(())
    }
}
