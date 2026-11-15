//! Community votes (CVP-012), matching `src/governance/vote.js`: signed motions, public and
//! secret ballots, and results that anyone holding the ballots can recount.
use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

use crate::bytes::{random_b64u, sha256_b64u};
use crate::canonical::canonical_json;
use crate::cv::canonical::js_string;
use crate::cv::identity::js_less;
use crate::error::{Error, Result};
use crate::js::{date_parse, len16, safe_int, truthy};
use crate::signed::{check_signature, sign, signing_bytes, SigningKey};
use crate::tokens::spend_token;

pub const MOTION: &str = "governance.motion";
pub const BALLOT: &str = "vote.ballot";
pub const SECRET_BALLOT: &str = "vote.secret-ballot";
pub const RESULT: &str = "vote.result";
pub const METHODS: [&str; 4] = ["majority", "supermajority", "approval", "ranked"];

fn fail<T>(code: &'static str, msg: &str) -> Result<T> {
    Err(Error::new(code, msg))
}

pub fn motion_id(motion: &Value) -> Result<String> {
    Ok(sha256_b64u(&signing_bytes(motion["kind"].as_str().unwrap_or(""), &motion["body"])?))
}

/// Propose a motion. `p` holds the JavaScript's parameters (`community`, `title`, `question`,
/// `options`, `method`, `passOption`, `threshold`, `quorum`, `opens`, `closes`, `ballot`,
/// `eligible`, `eligibleAt`, `issuer`, `action`), with the same defaults.
pub fn propose(p: &Value, key: &SigningKey) -> Result<Value> {
    let or = |k: &str, d: Value| match p.get(k) {
        None => d,
        Some(v) => v.clone(),
    };
    let body = json!({
        "id": random_b64u(12),
        "community": p["community"],
        "title": p["title"],
        "question": or("question", json!("")),
        "options": p["options"],
        "method": or("method", json!("majority")),
        "pass_option": or("passOption", p["options"][0]["id"].clone()),
        "threshold": or("threshold", json!({ "num": 2, "den": 3 })),
        "quorum": or("quorum", json!(0)),
        "opens": p["opens"],
        "closes": p["closes"],
        "ballot": or("ballot", json!("public")),
        "eligible": p["eligible"],
        "eligible_at": or("eligibleAt", json!(-1)),
        "issuer": or("issuer", Value::Null),
        "action": or("action", json!("")),
    });
    check_motion_body(&body)?;
    sign(MOTION, &body, key)
}

fn option_ids(m: &Value) -> Vec<Value> {
    m["options"].as_array().into_iter().flatten().map(|o| o.get("id").cloned().unwrap_or(Value::Null)).collect()
}

pub fn check_motion_body(m: &Value) -> Result<()> {
    if !m["title"].as_str().is_some_and(|t| !t.is_empty() && len16(t) <= 200) {
        return fail("BAD_MOTION", "A motion needs a title");
    }
    let Some(options) = m["options"].as_array().filter(|o| (2..=50).contains(&o.len())) else { return fail("BAD_MOTION", "A motion needs 2 to 50 options") };
    let ids = option_ids(m);
    let mut unique: Vec<&Value> = Vec::new();
    for id in &ids {
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    if unique.len() != options.len() || unique.iter().any(|id| !id.as_str().is_some_and(|s| !s.is_empty())) {
        return fail("BAD_MOTION", "Each option needs its own id");
    }
    if !m["method"].as_str().is_some_and(|x| METHODS.contains(&x)) {
        return fail("BAD_MOTION", "Method must be one of majority, supermajority, approval, ranked");
    }
    if !ids.contains(&m["pass_option"]) {
        return fail("BAD_MOTION", "The passing option must be one of the options");
    }
    if m["method"] == "supermajority" {
        let (num, den) = (safe_int(&m["threshold"]["num"]), safe_int(&m["threshold"]["den"]));
        if !matches!((num, den), (Some(n), Some(d)) if n > 0 && n <= d) {
            return fail("BAD_MOTION", "A supermajority needs a fraction, such as 2/3");
        }
    }
    if !safe_int(&m["quorum"]).is_some_and(|q| q >= 0) {
        return fail("BAD_MOTION", "Quorum is a number of ballots");
    }
    let (o, c) = (date_parse(m["opens"].as_str().unwrap_or("")), date_parse(m["closes"].as_str().unwrap_or("")));
    if !matches!((o, c), (Some(o), Some(c)) if o < c) {
        return fail("BAD_MOTION", "A vote must open before it closes");
    }
    if !(m["ballot"] == "public" || m["ballot"] == "secret") {
        return fail("BAD_MOTION", "Ballots are public or secret");
    }
    if !m["eligible"].as_array().is_some_and(|e| !e.is_empty()) {
        return fail("BAD_MOTION", "Someone must be able to vote");
    }
    if m["ballot"] == "secret" && !m["issuer"]["publicKey"].is_string() {
        return fail("BAD_MOTION", "A secret ballot needs a token issuer");
    }
    Ok(())
}

/// Check a motion's signature and contents. Returns its body.
pub fn check_motion<'a>(motion: &'a Value, key_for: &dyn Fn(&str) -> Option<String>) -> Result<&'a Value> {
    if motion["kind"] != MOTION {
        return fail("BAD_MOTION", "Not a motion");
    }
    let ok = motion["sig"]["kid"].as_str().and_then(key_for).is_some_and(|p| check_signature(motion, &motion["sig"], &p));
    if !ok {
        return fail("BAD_SIGNATURE", "The motion's signature doesn't match its proposer");
    }
    check_motion_body(&motion["body"])?;
    Ok(&motion["body"])
}

pub fn cast_ballot(motion: &Value, choice: &Value, key: &SigningKey, seq: i64) -> Result<Value> {
    sign(BALLOT, &json!({ "motion": motion_id(motion)?, "choice": choice, "seq": seq }), key)
}

pub fn cast_secret_ballot(motion: &Value, choice: &Value, token: &Value) -> Result<Value> {
    Ok(json!({ "kind": SECRET_BALLOT, "body": { "motion": motion_id(motion)?, "choice": choice, "token": token } }))
}

pub fn ballot_id(ballot: &Value) -> Result<String> {
    let sig = if truthy(&ballot["sig"]) { ballot["sig"].clone() } else { Value::Null };
    Ok(sha256_b64u(canonical_json(&json!({ "kind": ballot["kind"], "body": ballot["body"], "sig": sig }))?.as_bytes()))
}

fn valid_choice(m: &Value, choice: &Value) -> bool {
    let ids = option_ids(m);
    if m["method"] == "majority" || m["method"] == "supermajority" {
        return choice.is_string() && ids.contains(choice);
    }
    let Some(list) = choice.as_array() else { return false };
    let distinct_ids = {
        let mut u: Vec<&Value> = Vec::new();
        for i in &ids {
            if !u.contains(&i) {
                u.push(i);
            }
        }
        u.len()
    };
    if list.is_empty() || list.len() > distinct_ids {
        return false;
    }
    let mut seen: Vec<&Value> = Vec::new();
    for c in list {
        if seen.contains(&c) {
            return false;
        }
        seen.push(c);
    }
    list.iter().all(|c| ids.contains(c))
}

/// Instant-runoff: drop the option with fewest first preferences until one has a majority.
fn instant_runoff(options: &[String], choices: &[Vec<String>]) -> (Value, Vec<Value>) {
    let mut remaining: Vec<String> = options.to_vec();
    let mut rounds = Vec::new();
    loop {
        let mut counts: HashMap<String, i64> = remaining.iter().map(|id| (id.clone(), 0)).collect();
        let mut active = 0;
        for ranking in choices {
            if let Some(top) = ranking.iter().find(|c| remaining.contains(c)) {
                *counts.get_mut(top).unwrap() += 1;
                active += 1;
            }
        }
        rounds.push(Value::Object(remaining.iter().map(|id| (id.clone(), json!(counts[id]))).collect::<Map<_, _>>()));
        let mut sorted = remaining.clone();
        sorted.sort_by(|a, b| counts[b].cmp(&counts[a]).then_with(|| if js_less(a, b) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater }));
        if counts[&sorted[0]] * 2 > active || remaining.len() <= 2 || active == 0 {
            let winner = if active > 0 { json!(sorted[0]) } else { Value::Null };
            return (winner, rounds);
        }
        let least = remaining.iter().map(|id| counts[id]).min().unwrap();
        let out = remaining.iter().rev().find(|id| counts[*id] == least).unwrap().clone();
        remaining.retain(|id| *id != out);
    }
}

/// How a tally checks ballots: the voters' public keys, and for secret ballots the issuer's key
/// and the spent tokens.
pub struct TallyKeys<'a> {
    pub key_for: &'a dyn Fn(&str) -> Option<String>,
    pub issuer_key: Option<&'a Value>,
    pub spent: &'a mut HashSet<String>,
}

/// Count a vote. received: `[{ ballot, at }]`. Returns the result body (unsigned).
pub fn tally(motion: &Value, received: &[Value], keys: TallyKeys) -> Result<Value> {
    let m = &motion["body"];
    let id = motion_id(motion)?;
    let opens = date_parse(m["opens"].as_str().unwrap_or(""));
    let closes = date_parse(m["closes"].as_str().unwrap_or(""));
    let eligible: Vec<&Value> = m["eligible"].as_array().into_iter().flatten().collect();
    let in_time: Vec<&Value> = received
        .iter()
        .filter(|r| {
            let at = date_parse(r["at"].as_str().unwrap_or(""));
            r["ballot"]["body"]["motion"] == id.as_str() && matches!((at, opens, closes), (Some(a), Some(o), Some(c)) if a >= o && a <= c)
        })
        .map(|r| &r["ballot"])
        .collect();
    let mut spoiled = 0;
    let mut counted: Vec<Value> = Vec::new();
    if m["ballot"] == "public" {
        let mut latest: Vec<(String, Value)> = Vec::new();
        let mut clash = HashSet::new();
        for ballot in in_time {
            let kid = &ballot["sig"]["kid"];
            if ballot["kind"] != BALLOT || !eligible.contains(&kid) || safe_int(&ballot["body"]["seq"]).is_none() {
                spoiled += 1;
                continue;
            }
            let kid = kid.as_str().unwrap_or("").to_string();
            if !(keys.key_for)(&kid).is_some_and(|p| check_signature(ballot, &ballot["sig"], &p)) {
                spoiled += 1;
                continue;
            }
            let seq = safe_int(&ballot["body"]["seq"]).unwrap();
            match latest.iter_mut().find(|(k, _)| *k == kid) {
                None => latest.push((kid, ballot.clone())),
                Some((_, prev)) => {
                    let prev_seq = safe_int(&prev["body"]["seq"]).unwrap();
                    if seq > prev_seq {
                        *prev = ballot.clone();
                    } else if seq == prev_seq && canonical_json(&ballot["body"])? != canonical_json(&prev["body"])? {
                        clash.insert(format!("{kid}:{seq}"));
                    }
                }
            }
        }
        for (kid, ballot) in latest {
            let seq = safe_int(&ballot["body"]["seq"]).unwrap();
            if clash.contains(&format!("{kid}:{seq}")) || !valid_choice(m, &ballot["body"]["choice"]) {
                spoiled += 1;
            } else {
                counted.push(ballot);
            }
        }
    } else {
        let Some(issuer) = keys.issuer_key else { return fail("NO_ISSUER", "Counting secret ballots needs the issuer's key") };
        for ballot in in_time {
            if ballot["kind"] != SECRET_BALLOT || !valid_choice(m, &ballot["body"]["choice"]) {
                spoiled += 1;
                continue;
            }
            match spend_token(issuer, &ballot["body"]["token"], keys.spent) {
                Ok(_) => counted.push(ballot.clone()),
                Err(_) => spoiled += 1,
            }
        }
    }

    let options: Vec<String> = option_ids(m).iter().map(js_string).collect();
    let mut counts: Vec<(String, i64)> = options.iter().map(|o| (o.clone(), 0)).collect();
    let bump = |counts: &mut Vec<(String, i64)>, c: &str| {
        if let Some((_, n)) = counts.iter_mut().find(|(k, _)| k == c) {
            *n += 1;
        }
    };
    let total = counted.len() as i64;
    let mut rounds = Value::Null;
    let winner;
    if m["method"] == "ranked" {
        let choices: Vec<Vec<String>> = counted.iter().map(|b| b["body"]["choice"].as_array().unwrap().iter().map(js_string).collect()).collect();
        let (w, r) = instant_runoff(&options, &choices);
        winner = w;
        rounds = Value::Array(r);
        for c in &choices {
            bump(&mut counts, &c[0]);
        }
    } else {
        for b in &counted {
            match &b["body"]["choice"] {
                Value::Array(list) => list.iter().for_each(|c| bump(&mut counts, &js_string(c))),
                c => bump(&mut counts, &js_string(c)),
            }
        }
        let best = counts.iter().map(|(_, n)| *n).max().unwrap_or(0);
        let top: Vec<&String> = counts.iter().filter(|(_, n)| *n == best).map(|(k, _)| k).collect();
        winner = if total > 0 && top.len() == 1 { json!(top[0]) } else { Value::Null };
    }
    let quorum_met = total >= safe_int(&m["quorum"]).unwrap_or(0);
    let pass = js_string(&m["pass_option"]);
    let yes = counts.iter().find(|(k, _)| *k == pass).map(|(_, n)| *n).unwrap_or(0);
    let passes = match m["method"].as_str() {
        Some("majority") => yes * 2 > total,
        Some("supermajority") => {
            let (num, den) = (safe_int(&m["threshold"]["num"]).unwrap_or(0), safe_int(&m["threshold"]["den"]).unwrap_or(1));
            yes * den >= num * total && total > 0
        }
        _ => winner == json!(pass),
    };
    let mut ballots: Vec<String> = counted.iter().map(ballot_id).collect::<Result<_>>()?;
    ballots.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    let action = if truthy(&m["action"]) { m["action"].clone() } else { json!("") };
    Ok(json!({
        "motion": id,
        "community": m["community"],
        "method": m["method"],
        "counts": Value::Object(counts.into_iter().map(|(k, n)| (k, json!(n))).collect()),
        "rounds": rounds,
        "winner": winner,
        "total": total,
        "spoiled": spoiled,
        "quorum_met": quorum_met,
        "passed": quorum_met && passes,
        "ballots": ballots.clone(),
        "ballots_hash": sha256_b64u(ballots.join("\n").as_bytes()),
        "action": action,
    }))
}

pub fn sign_result(body: &Value, key: &SigningKey) -> Result<Value> {
    sign(RESULT, body, key)
}

/// Recount a public vote and compare with a published result.
pub fn verify_result(motion: &Value, result: &Value, received: &[Value], key_for: &dyn Fn(&str) -> Option<String>, tallier_key: &str) -> Result<Value> {
    if result["kind"] != RESULT || !check_signature(result, &result["sig"], tallier_key) {
        return fail("BAD_SIGNATURE", "The result isn't signed by the tallier");
    }
    if motion["body"]["ballot"] != "public" {
        return fail("NOT_PUBLIC", "Only public ballots can be recounted by anyone");
    }
    let mut spent = HashSet::new();
    let again = tally(motion, received, TallyKeys { key_for, issuer_key: None, spent: &mut spent })?;
    if canonical_json(&again)? != canonical_json(&result["body"])? {
        return fail("MISCOUNT", "Counting the ballots again gives a different result");
    }
    Ok(again)
}
