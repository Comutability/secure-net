//! Groups for the reference client (CVP-022 with CVP-019 group envelopes), matching
//! `src/groups/client.js`.
//!
//! ```text
//! alice.enable_groups(net, 5)?;
//! let group = alice.create_group()?;
//! alice.invite(net, &group, &bob.id)?;
//! alice.post_to_group(net, &group, "hello")?;
//! ```
use serde_json::{json, Map, Value};

use crate::canonical::canonical_json;
use crate::error::{Error, Result};
use crate::groups::mls as g;
use crate::social::activity::{sign_activity, verify_activity, ACTIVITY};
use crate::social::client::SocialClient;
use crate::social::site::MemoryNetwork;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn envelope(group: &str, message: &Value) -> Value {
    json!({ "v": 2, "mode": "group", "group": group, "message": message })
}

impl SocialClient {
    fn actor_map(&self) -> Value {
        Value::Object(self.known.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<Map<_, _>>())
    }

    fn group_state(&self, group: &str) -> Result<Value> {
        self.groups.get(group).cloned().ok_or_else(|| err("BAD_INPUT", "Not a group of ours"))
    }

    fn group_others(&self, state: &Value) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for m in g::describe(state)?["members"].as_array().into_iter().flatten() {
            let a = m["actor"].as_str().unwrap_or("").to_string();
            if a != self.id && !out.contains(&a) {
                out.push(a);
            }
        }
        Ok(out)
    }

    fn fan_out(&mut self, net: &mut MemoryNetwork, group: &str, message: &Value, to: &[String]) -> Result<()> {
        for a in to {
            self.deliver(net, a, &[envelope(group, message)], true)?;
        }
        Ok(())
    }

    /// Make key packages and publish them, so others can add this device to groups.
    pub fn enable_groups(&mut self, net: &mut MemoryNetwork, count: usize) -> Result<()> {
        let mut published = Vec::new();
        for _ in 0..count {
            let k = g::create_key_package(&self.device, &self.id)?;
            published.push(k["published"].as_str().unwrap_or("").to_string());
            self.key_packages.push(k["secret"].clone());
        }
        let (host, id, kid) = (self.host.clone(), self.id.clone(), self.device.kid.clone());
        net.site(&host)?.publish_key_packages(&id, &kid, &published)?;
        self.groups_enabled = true;
        Ok(())
    }

    /// Create a group. This device becomes its committer.
    pub fn create_group(&mut self) -> Result<String> {
        let own = g::create_key_package(&self.device, &self.id)?;
        let state = g::create_group(None, &own["secret"])?;
        let id = state["group"].as_str().unwrap_or("").to_string();
        self.groups.insert(id.clone(), state);
        self.groups_enabled = true;
        Ok(id)
    }

    fn change(&mut self, net: &mut MemoryNetwork, group: &str, make: &dyn Fn(&Value, &Value) -> Result<Value>, welcome_to: &[String]) -> Result<()> {
        let mut before = self.group_state(group)?;
        let existing = self.group_others(&before)?;
        if !welcome_to.is_empty() && !existing.is_empty() {
            // Members check every leaf against its actor's document, so they need the newcomers'
            // documents before the commit that adds them. Actor documents certify themselves.
            let docs: Vec<Value> = welcome_to.iter().map(|a| self.records.get(a).cloned().unwrap_or(Value::Null)).collect();
            let intro = g::seal(&before, canonical_json(&json!({ "v": 1, "actors": docs }))?.as_bytes())?;
            before = intro["state"].clone();
            self.groups.insert(group.to_string(), before.clone());
            self.fan_out(net, group, &intro["message"], &existing)?;
        }
        let r = make(&before, &self.actor_map())?;
        self.groups.insert(group.to_string(), r["state"].clone());
        self.fan_out(net, group, &r["commit"], &existing)?;
        // Newcomers likewise get everyone's documents with their welcome.
        let everyone: Vec<Value> = std::iter::once(&self.id).chain(existing.iter()).map(|a| self.records.get(a).cloned().unwrap_or(Value::Null)).collect();
        for a in welcome_to {
            self.send_direct(net, a, &json!({ "groups": [{ "group": group, "welcome": r["welcome"], "actors": everyone }] }))?;
        }
        Ok(())
    }

    /// Add every device of an actor (look them up first). Only the committer can.
    pub fn invite(&mut self, net: &mut MemoryNetwork, group: &str, actor_id: &str) -> Result<()> {
        let actor = self.known.get(actor_id).cloned().ok_or_else(|| err("UNKNOWN_ACTOR", "Look this actor up first"))?;
        let host = self.host_of(actor_id)?;
        let mut packages = Vec::new();
        for d in actor["devices"]["body"]["devices"].as_array().into_iter().flatten() {
            packages.push(json!(net.site(&host)?.key_package(actor_id, d["kid"].as_str().unwrap_or(""))?));
        }
        self.change(net, group, &|s, actors| g::add_members(s, &packages, actors), &[actor_id.to_string()])
    }

    /// Remove every device of an actor. They can't read anything sent afterwards.
    pub fn remove_from_group(&mut self, net: &mut MemoryNetwork, group: &str, actor_id: &str) -> Result<()> {
        let who = json!(actor_id);
        self.change(net, group, &|s, _| g::remove_members(s, &|m| m["actor"] == who), &[])
    }

    /// New group secrets from the committer, for example on a schedule.
    pub fn refresh_group(&mut self, net: &mut MemoryNetwork, group: &str) -> Result<()> {
        self.change(net, group, &|s, _| g::refresh(s), &[])
    }

    /// Post to a group. The activity is signed on this device, then sealed once for the group.
    pub fn post_to_group(&mut self, net: &mut MemoryNetwork, group: &str, content: &str) -> Result<Value> {
        let state = self.group_state(group)?;
        let record = sign_activity(&self.device, &self.id, &json!({ "type": "Create", "to": [group], "object": { "type": "Note", "content": content, "context": group } }), true, self.now)?;
        self.seal_into_group(net, group, &state, &json!({ "v": 1, "activity": record }))?;
        Ok(record)
    }

    /// Seal any payload into a group and send it to the other members (tests use this to play a
    /// member who goes around `post_to_group`).
    pub fn seal_into_group(&mut self, net: &mut MemoryNetwork, group: &str, state: &Value, payload: &Value) -> Result<()> {
        let r = g::seal(state, canonical_json(payload)?.as_bytes())?;
        self.groups.insert(group.to_string(), r["state"].clone());
        let others = self.group_others(state)?;
        self.fan_out(net, group, &r["message"], &others)
    }

    /// A welcome arrived over a direct session: join with whichever unused key package it was
    /// made for.
    pub(crate) fn on_welcome(&mut self, w: &Value, from_actor: &str) -> Result<()> {
        for record in w["actors"].as_array().cloned().unwrap_or_default() {
            self.remember(&record)?;
        }
        let group = w["group"].as_str().unwrap_or("");
        for i in 0..self.key_packages.len() {
            let Ok(state) = g::join(w["welcome"].as_str().unwrap_or(""), &self.key_packages[i], &self.actor_map()) else { continue };
            let d = g::describe(&state)?;
            // The welcome must be for the group it says, and must come from that group's committer.
            let committer = d["members"].as_array().into_iter().flatten().find(|m| m["leaf"] == g::COMMITTER_LEAF).cloned();
            if d["group"] != group || committer.is_none_or(|c| c["actor"] != from_actor) {
                return Err(err("UNTRUSTED", "A welcome that isn't from its group's committer"));
            }
            self.key_packages.remove(i);
            self.groups.insert(group.to_string(), state);
            return Ok(());
        }
        Err(err("UNKNOWN_PREKEY", "No key package of ours opens that welcome"))
    }

    pub(crate) fn on_group_envelope(&mut self, net: &mut MemoryNetwork, env: &Value) -> Result<Value> {
        let group = env["group"].as_str().unwrap_or("").to_string();
        let Some(state) = self.groups.get(&group).cloned() else { return Ok(json!({ "kind": "unreadable", "reason": "not a member of this group" })) };
        let r = g::open(&state, env["message"].as_str().unwrap_or(""), &self.actor_map())?;
        self.groups.insert(group.clone(), r["state"].clone());
        if r["kind"] == "commit" {
            let d = g::describe(&r["state"])?;
            let members = d["members"].as_array().cloned().unwrap_or_default();
            if r["removed"] == true || !members.iter().any(|m| m["actor"] == self.id.as_str() && m["device"] == self.device.kid.as_str()) {
                self.groups.remove(&group);
            }
            return Ok(json!({ "kind": "group-changed", "group": group, "members": members.len() }));
        }
        let bytes = crate::bytes::from_b64u(r["plaintext"].as_str().unwrap_or(""))?;
        let p: Value = serde_json::from_slice(&bytes).map_err(|_| err("BAD_MESSAGE", "Payload isn't JSON"))?;
        if p["v"] == 1 && p["actors"].is_array() && p.get("activity").is_none() {
            for record in p["actors"].as_array().cloned().unwrap_or_default() {
                self.remember(&record)?;
            }
            return Ok(json!({ "kind": "keys", "group": group }));
        }
        let a = &p["activity"];
        if p["v"] != 1 || a["kind"] != ACTIVITY {
            return Err(err("BAD_MESSAGE", "Not a version 1 payload"));
        }
        // MLS says a member sealed it. The signature inside says which device wrote it; that
        // device must be a member, and it must have written it for this group.
        let d = g::describe(&state)?;
        let author = d["members"].as_array().into_iter().flatten().find(|m| m["actor"] == a["body"]["actor"] && m["device"] == a["body"]["device"]).cloned();
        let Some(author) = author else { return Err(err("UNTRUSTED", "The activity wasn't made by a member of the group")) };
        let doc = self.known.get(author["actor"].as_str().unwrap_or("")).cloned().unwrap_or(Value::Null);
        let body = verify_activity(a, &doc, true, self.now)?;
        if !body["to"].as_array().is_some_and(|t| t.iter().any(|x| x == group.as_str())) {
            return Err(err("UNTRUSTED", "The activity wasn't written for this group"));
        }
        self.handle(net, &body, "group", false)
    }
}
