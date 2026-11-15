//! Structured debates (CVP-012), matching `src/governance/debate.js`: a motion's discussion as
//! signed, typed records arranged into a tree and an accessible threaded list.
use std::cmp::Ordering;

use serde_json::{json, Map, Value};

use crate::bytes::sha256_b64u;
use crate::cv::identity::js_less;
use crate::error::Result;
use crate::js::{date_parse, len16};
use crate::signed::{check_signature, sign, signing_bytes, SigningKey};

pub const KINDS: [&str; 6] = ["debate.position", "debate.argument", "debate.rebuttal", "debate.evidence", "debate.round", "debate.moderation"];
const PHASES: [&str; 5] = ["opening", "argument", "rebuttal", "closing", "open"];
const MAX_TEXT: usize = 10_000;

pub fn item_id(record: &Value) -> Result<String> {
    Ok(sha256_b64u(&signing_bytes(record["kind"].as_str().unwrap_or(""), &record["body"])?))
}

fn text(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty() && len16(s) <= max)
}

fn absent_or_text(b: &Value, k: &str, max: usize) -> bool {
    b.get(k).is_none() || text(&b[k], max)
}

/// Make a debate record. `at` is used when the body has no time of its own.
pub fn post(kind: &str, body: &Value, key: &SigningKey, at: &str) -> Result<Value> {
    if !KINDS.contains(&kind) {
        return Err(crate::error::Error::new("BAD_INPUT", format!("Unknown debate record {kind}")));
    }
    let mut b = body.clone();
    if !crate::js::truthy(&b["at"]) {
        b["at"] = json!(at);
    }
    sign(kind, &b, key)
}

fn shape_ok(r: &Value, sides: &[String]) -> bool {
    let b = &r["body"];
    let side_ok = || b["side"].as_str().is_some_and(|s| sides.iter().any(|x| x == s));
    match r["kind"].as_str() {
        Some("debate.position") => side_ok() && text(&b["statement"], MAX_TEXT),
        Some("debate.argument") => side_ok() && text(&b["claim"], 500) && absent_or_text(b, "detail", MAX_TEXT),
        Some("debate.rebuttal") => b["target"].is_string() && text(&b["claim"], 500) && absent_or_text(b, "detail", MAX_TEXT),
        Some("debate.evidence") => b["target"].is_string() && text(&b["source"], 2000) && absent_or_text(b, "citation", 2000),
        Some("debate.round") => {
            let who = if crate::js::truthy(&b["who"]) { b["who"].clone() } else { json!("all") };
            let times = matches!((date_parse(b["opens"].as_str().unwrap_or("")), date_parse(b["closes"].as_str().unwrap_or(""))), (Some(o), Some(c)) if o < c);
            text(&b["name"], 100) && b["phase"].as_str().is_some_and(|p| PHASES.contains(&p)) && times && (who == "all" || who == "debaters")
        }
        Some("debate.moderation") => b["target"].is_string() && (b["action"] == "hide" || b["action"] == "restore") && absent_or_text(b, "reason", 500),
        _ => false,
    }
}

fn phase_for(kind: &str) -> &'static [&'static str] {
    match kind {
        "debate.position" => &["opening", "open"],
        "debate.argument" => &["opening", "argument", "open"],
        "debate.rebuttal" => &["rebuttal", "argument", "open"],
        "debate.evidence" => &["opening", "argument", "rebuttal", "closing", "open"],
        _ => &[],
    }
}

/// Who may do what in a debate. `can_post`: None means anyone `key_for` knows.
pub struct Roles<'a> {
    pub key_for: &'a dyn Fn(&str) -> Option<String>,
    pub can_post: Option<&'a dyn Fn(&str) -> bool>,
    pub is_moderator: &'a dyn Fn(&str) -> bool,
    pub debaters: &'a [String],
}

struct Node {
    value: Map<String, Value>,
    alive: bool,
    replies: Vec<usize>,
}

fn is_mod_kind(k: &Value) -> bool {
    k == "debate.round" || k == "debate.moderation"
}

/// Check and arrange a debate's records: `{ items, rejected, rounds, tree, threaded }`.
pub fn arrange(motion: &Value, records: &[Value], roles: Roles) -> Result<Value> {
    let motion_key = sha256_b64u(&signing_bytes(motion["kind"].as_str().unwrap_or(""), &motion["body"])?);
    let mut sides: Vec<String> = motion["body"]["options"].as_array().into_iter().flatten().filter_map(|o| o["id"].as_str().map(str::to_string)).collect();
    sides.push("neutral".into());
    let mut rejected: Vec<Value> = Vec::new();
    let reject = |rejected: &mut Vec<Value>, r: &Value, why: &str| -> Result<()> {
        let id = if crate::js::truthy(&r["kind"]) && crate::js::truthy(&r["body"]) { json!(item_id(r)?) } else { Value::Null };
        rejected.push(json!({ "id": id, "why": why }));
        Ok(())
    };
    let mut ordered: Vec<&Value> = records.iter().collect();
    ordered.sort_by_key(|r| if is_mod_kind(&r["kind"]) { 0 } else { 1 });
    let mut rounds: Vec<Value> = Vec::new();
    let mut hidden: Vec<(String, Value)> = Vec::new();
    let mut accepted: Vec<(String, Value)> = Vec::new();
    for r in ordered {
        let kind_ok = r["kind"].as_str().is_some_and(|k| KINDS.contains(&k));
        if !crate::js::truthy(r) || !kind_ok || r["body"]["motion"] != motion_key.as_str() {
            reject(&mut rejected, r, "not part of this debate")?;
            continue;
        }
        let kid = r["sig"]["kid"].as_str().unwrap_or("").to_string();
        let ok = r["sig"]["kid"].as_str().and_then(|k| (roles.key_for)(k)).is_some_and(|p| check_signature(r, &r["sig"], &p));
        if !ok {
            reject(&mut rejected, r, "signature doesn't match")?;
            continue;
        }
        if !shape_ok(r, &sides) {
            reject(&mut rejected, r, "malformed")?;
            continue;
        }
        let id = item_id(r)?;
        if accepted.iter().any(|(k, _)| *k == id) {
            continue;
        }
        if is_mod_kind(&r["kind"]) {
            if !(roles.is_moderator)(&kid) {
                reject(&mut rejected, r, "only moderators can do that")?;
                continue;
            }
            if r["kind"] == "debate.round" {
                rounds.push(r["body"].clone());
            } else {
                let target = r["body"]["target"].as_str().unwrap_or("").to_string();
                let replace = match hidden.iter().find(|(t, _)| *t == target) {
                    None => true,
                    Some((_, prev)) => matches!((date_parse(r["body"]["at"].as_str().unwrap_or("")), date_parse(prev["at"].as_str().unwrap_or(""))), (Some(a), Some(b)) if a >= b),
                };
                if replace {
                    hidden.retain(|(t, _)| *t != target);
                    hidden.push((target, r["body"].clone()));
                }
            }
            accepted.push((id, r.clone()));
            continue;
        }
        let may_post = match roles.can_post {
            Some(f) => f(&kid),
            None => (roles.key_for)(&kid).is_some(),
        };
        if !may_post {
            reject(&mut rejected, r, "not allowed to take part")?;
            continue;
        }
        if !rounds.is_empty() {
            let t = date_parse(r["body"]["at"].as_str().unwrap_or(""));
            let kind = r["kind"].as_str().unwrap_or("");
            let open = rounds.iter().any(|rd| {
                let (o, c) = (date_parse(rd["opens"].as_str().unwrap_or("")), date_parse(rd["closes"].as_str().unwrap_or("")));
                let in_time = matches!((t, o, c), (Some(t), Some(o), Some(c)) if t >= o && t <= c);
                in_time && rd["phase"].as_str().is_some_and(|p| phase_for(kind).contains(&p)) && (rd["who"] != "debaters" || roles.debaters.contains(&kid))
            });
            if !open {
                reject(&mut rejected, r, "outside any round that allows it")?;
                continue;
            }
        }
        accepted.push((id, r.clone()));
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    for (id, r) in &accepted {
        if is_mod_kind(&r["kind"]) {
            continue;
        }
        let mut v = Map::new();
        v.insert("id".into(), json!(id));
        v.insert("kind".into(), r["kind"].clone());
        v.insert("author".into(), r["sig"]["kid"].clone());
        for (k, x) in r["body"].as_object().into_iter().flatten() {
            v.insert(k.clone(), x.clone());
        }
        let is_hidden = hidden.iter().find(|(t, _)| t == id).is_some_and(|(_, m)| m["action"] == "hide");
        v.insert("hidden".into(), json!(is_hidden));
        v.insert("replies".into(), json!([]));
        nodes.push(Node { value: v, alive: true, replies: vec![] });
        ids.push(id.clone());
    }
    let mut roots: Vec<usize> = Vec::new();
    for i in 0..nodes.len() {
        let n = &nodes[i].value;
        let kind = n["kind"].clone();
        let parent_ref = if kind == "debate.argument" { n.get("parent").cloned().unwrap_or(Value::Null) } else { n.get("target").cloned().unwrap_or(Value::Null) };
        if kind == "debate.position" || (kind == "debate.argument" && !crate::js::truthy(&parent_ref)) {
            roots.push(i);
            continue;
        }
        let parent = parent_ref.as_str().and_then(|p| (0..nodes.len()).find(|&j| nodes[j].alive && ids[j] == p));
        match parent {
            Some(j) if nodes[j].value["kind"] != "debate.position" => nodes[j].replies.push(i),
            _ => {
                rejected.push(json!({ "id": ids[i], "why": "replies to something that isn't in this debate" }));
                nodes[i].alive = false;
            }
        }
    }
    let by_time = |nodes: &[Node], a: usize, b: usize| -> Ordering {
        let t = |i: usize| date_parse(nodes[i].value["at"].as_str().unwrap_or(""));
        let diff = match (t(a), t(b)) {
            (Some(x), Some(y)) => x - y,
            _ => 0,
        };
        if diff != 0 {
            return diff.cmp(&0);
        }
        if js_less(nodes[a].value["id"].as_str().unwrap_or(""), nodes[b].value["id"].as_str().unwrap_or("")) {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    };
    fn sort_all(nodes: &mut [Node], list: &mut [usize], by: &dyn Fn(&[Node], usize, usize) -> Ordering, threaded: &mut Vec<Value>, depth: usize) {
        list.sort_by(|a, b| by(nodes, *a, *b));
        for &i in list.iter() {
            let mut item = nodes[i].value.clone();
            item.shift_remove("replies");
            item.insert("depth".into(), json!(depth));
            threaded.push(Value::Object(item));
            let mut kids = std::mem::take(&mut nodes[i].replies);
            sort_all(nodes, &mut kids, by, threaded, depth + 1);
            nodes[i].replies = kids;
        }
    }
    let mut threaded = Vec::new();
    sort_all(&mut nodes, &mut roots, &by_time, &mut threaded, 0);
    fn build(nodes: &[Node], i: usize) -> Value {
        let mut v = nodes[i].value.clone();
        v.insert("replies".into(), Value::Array(nodes[i].replies.iter().map(|&j| build(nodes, j)).collect()));
        Value::Object(v)
    }
    let tree: Vec<Value> = roots.iter().map(|&i| build(&nodes, i)).collect();
    let items = nodes.iter().filter(|n| n.alive).count();
    Ok(json!({ "items": items, "rejected": rejected, "rounds": rounds, "tree": tree, "threaded": threaded }))
}
