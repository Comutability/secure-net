//! Repositories (CVP-020), matching `src/social/repo.js`: an actor's public activities as a signed
//! Merkle-rooted set that anyone can check, from any source.
use serde_json::{json, Value};

use crate::bytes::{b64u, equal_bytes, from_b64u, sha256};
use crate::error::{Error, Result};
use crate::js::safe_int;
use crate::session::keys::Device;
use crate::signed::{check_signature, record_id, sign};
use crate::social::activity::verify_activity;
use crate::social::actor::{device_key_at, verify_actor_document};
use crate::social::vocabulary::{recipients, PUBLIC};

pub const COMMIT: &str = "repo.commit";
pub const MAX_RECORDS: usize = 100_000;

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn leaf(id: &str) -> [u8; 32] {
    sha256(&[b"secure-net/repo/v1/leaf\n".as_slice(), id.as_bytes()].concat())
}

fn node(l: &[u8], r: &[u8]) -> [u8; 32] {
    sha256(&[b"secure-net/repo/v1/node\n".as_slice(), l, r].concat())
}

fn empty() -> [u8; 32] {
    sha256(b"secure-net/repo/v1/empty\n")
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn root_of(h: &[[u8; 32]]) -> [u8; 32] {
    match h.len() {
        0 => empty(),
        1 => h[0],
        n => {
            let k = split(n);
            node(&root_of(&h[..k]), &root_of(&h[k..]))
        }
    }
}

fn path_of(h: &[[u8; 32]], i: usize) -> Vec<[u8; 32]> {
    if h.len() == 1 {
        return vec![];
    }
    let k = split(h.len());
    if i < k {
        let mut p = path_of(&h[..k], i);
        p.push(root_of(&h[k..]));
        p
    } else {
        let mut p = path_of(&h[k..], i - k);
        p.push(root_of(&h[..k]));
        p
    }
}

pub fn merkle_root(ids: &[String]) -> String {
    b64u(&root_of(&ids.iter().map(|i| leaf(i)).collect::<Vec<_>>()))
}

pub fn inclusion_proof(ids: &[String], index: i64) -> Result<Vec<String>> {
    if index < 0 || index as usize >= ids.len() {
        return Err(err("BAD_INPUT", "No such record"));
    }
    Ok(path_of(&ids.iter().map(|i| leaf(i)).collect::<Vec<_>>(), index as usize).iter().map(|h| b64u(h)).collect())
}

pub fn verify_inclusion(id: &str, index: i64, count: i64, proof: &[String], root: &str) -> bool {
    fn up(id: &str, i: i64, n: i64, p: &[String]) -> Option<[u8; 32]> {
        if n == 1 {
            return p.is_empty().then(|| leaf(id));
        }
        let (last, rest) = p.split_last()?;
        let k = split(n as usize) as i64;
        let sib = from_b64u(last).ok()?;
        Some(if i < k { node(&up(id, i, k, rest)?, &sib) } else { node(&sib, &up(id, i - k, n - k, rest)?) })
    }
    index >= 0 && index < count && up(id, index, count, proof).zip(from_b64u(root).ok()).is_some_and(|(a, b)| equal_bytes(&a, &b))
}

pub fn create_repo(actor_id: &str) -> Value {
    json!({ "actor": actor_id, "records": [], "head": null })
}

fn ids_of(records: &[Value]) -> Result<Vec<String>> {
    records.iter().map(record_id).collect()
}

fn commit(repo: &Value, device: &Device, records: Vec<Value>, now: i64) -> Result<Value> {
    let head = &repo["head"];
    let seq = if head.is_null() { 1 } else { safe_int(&head["body"]["seq"]).unwrap_or(0) + 1 };
    let prev = if head.is_null() { Value::Null } else { json!(record_id(head)?) };
    let body = json!({ "v": 1, "actor": repo["actor"], "device": device.kid, "seq": seq, "prev": prev, "root": merkle_root(&ids_of(&records)?), "count": records.len(), "at": now });
    Ok(json!({ "actor": repo["actor"], "records": records, "head": sign(COMMIT, &body, &device.sign)? }))
}

fn records(repo: &Value) -> Vec<Value> {
    repo["records"].as_array().cloned().unwrap_or_default()
}

pub fn append_to_repo(repo: &Value, device: &Device, record: &Value, now: i64) -> Result<Value> {
    if record["body"]["actor"] != repo["actor"] {
        return Err(err("BAD_INPUT", "That activity is another actor's"));
    }
    if !recipients(&record["body"], &["to", "cc"])?.iter().any(|r| r == PUBLIC) {
        return Err(err("BAD_INPUT", "Only public activities go in a repository"));
    }
    let mut list = records(repo);
    if list.len() >= MAX_RECORDS {
        return Err(err("TOO_LARGE", "Repository is full"));
    }
    list.push(record.clone());
    commit(repo, device, list, now)
}

pub fn remove_from_repo(repo: &Value, device: &Device, id: &Value, now: i64) -> Result<Value> {
    let kept = records(repo).into_iter().filter(|r| r["body"]["id"] != *id && r["body"]["object"]["id"] != *id).collect();
    commit(repo, device, kept, now)
}

pub fn export_repo(repo: &Value, actor_record: &Value) -> Value {
    json!({ "v": 1, "actor": actor_record, "head": repo["head"], "records": repo["records"] })
}

pub fn verify_commit(head: &Value, actor: &Value, min_seq: i64) -> Result<Value> {
    let c = &head["body"];
    if head["kind"] != COMMIT || !c.is_object() || c["v"] != 1 {
        return Err(err("BAD_MESSAGE", "Not a repository commit"));
    }
    if c["actor"] != actor["id"] || head["sig"]["kid"] != c["device"] {
        return Err(err("UNTRUSTED", "Commit is for another actor or device"));
    }
    let key = device_key_at(actor, &c["device"], &c["at"]);
    if !key.is_some_and(|k| k.contains('.') && check_signature(head, &head["sig"], &k)) {
        return Err(err("UNTRUSTED", "Commit isn't signed by a device of the actor"));
    }
    let (seq, count) = (safe_int(&c["seq"]), safe_int(&c["count"]));
    if !seq.is_some_and(|s| s >= 1) || !count.is_some_and(|n| n >= 0) {
        return Err(err("BAD_MESSAGE", "Bad commit"));
    }
    if seq.unwrap() < min_seq {
        return Err(err("ROLLBACK", "Repository is older than one already seen"));
    }
    Ok(c.clone())
}

/// Check a whole exported repository: `{ actor, commit, records }`.
pub fn verify_repo(exported: &Value, id: Option<&str>, min_seq: i64, now: i64) -> Result<Value> {
    let Some(recs) = exported["records"].as_array().filter(|_| exported["v"] == 1) else { return Err(err("BAD_MESSAGE", "Not a repository")) };
    let actor = verify_actor_document(&exported["actor"], id, None, 0)?;
    let c = verify_commit(&exported["head"], &actor, min_seq)?;
    if Some(recs.len() as i64) != safe_int(&c["count"]) {
        return Err(err("TAMPERED", "Records are missing or added"));
    }
    for r in recs {
        let b = verify_activity(r, &actor, false, now)?;
        if !recipients(&b, &["to", "cc"])?.iter().any(|x| x == PUBLIC) {
            return Err(err("TAMPERED", "A record that isn't public"));
        }
    }
    if c["root"].as_str() != Some(merkle_root(&ids_of(recs)?).as_str()) {
        return Err(err("TAMPERED", "Records don't match the signed root"));
    }
    Ok(json!({ "actor": actor, "commit": c, "records": recs }))
}
