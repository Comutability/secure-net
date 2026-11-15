//! Portable identity (CVP-001), matching `src/identity/portable.js`: personas with a private,
//! two-way signed link proof, and signed, sequenced migration notices.
use serde_json::{json, Value};

use crate::error::{Error, Result};
use crate::js::{len16, safe_int, truthy};
use crate::signed::{check_signature, key_id, sign, SigningKey};

pub const PERSONA_LINK: &str = "identity.persona-link";
pub const MIGRATION: &str = "identity.migration";

fn fail<T>(code: &'static str, msg: &str) -> Result<T> {
    Err(Error::new(code, msg))
}

/// A new persona for one community: `{ key, shown, link }`.
pub fn create_persona(account: &SigningKey, community: &Value, name: &str, at: &str) -> Result<Value> {
    if name.trim().is_empty() || len16(name) > 64 {
        return fail("BAD_NAME", "A persona needs a name");
    }
    let key = SigningKey::generate(false);
    let shown = json!({ "kid": key.kid, "pub": key.public_key, "name": name.trim(), "community": community });
    let body = json!({ "account": account.kid, "account_pub": account.public_key, "persona": key.kid, "persona_pub": key.public_key, "community": community, "at": at });
    let mut link = sign(PERSONA_LINK, &body, account)?;
    let persona_sig = sign(PERSONA_LINK, &body, &key)?["sig"].clone();
    link["cosigs"] = json!([persona_sig]);
    Ok(json!({ "key": key, "shown": shown, "link": link }))
}

fn kid_of(v: &Value) -> Option<String> {
    v.as_str().and_then(|p| key_id(p).ok())
}

/// Check a revealed link: both keys signed it. `{ account, persona, community }`.
pub fn check_persona_link(link: &Value) -> Result<Value> {
    let b = &link["body"];
    if link["kind"] != PERSONA_LINK || !truthy(b) {
        return fail("MALFORMED", "Not a persona link");
    }
    if kid_of(&b["account_pub"]).as_deref() != b["account"].as_str() || kid_of(&b["persona_pub"]).as_deref() != b["persona"].as_str() || !b["account"].is_string() || !b["persona"].is_string() {
        return fail("BAD_KEYS", "Key ids don't match the keys");
    }
    let (ap, pp) = (b["account_pub"].as_str().unwrap(), b["persona_pub"].as_str().unwrap());
    if link["sig"]["kid"] != b["account"] || !check_signature(link, &link["sig"], ap) {
        return fail("BAD_SIGNATURE", "The account didn't sign this");
    }
    let ps = link["cosigs"].as_array().into_iter().flatten().find(|s| s["kid"] == b["persona"]);
    if !ps.is_some_and(|s| check_signature(link, s, pp)) {
        return fail("BAD_SIGNATURE", "The persona didn't sign this");
    }
    Ok(json!({ "account": b["account"], "persona": b["persona"], "community": b["community"] }))
}

/// A move between sites, signed by the owner.
pub fn migration_notice(subject: &Value, from: &str, to: &str, seq: &Value, keep_old_until: &Value, at: &str, owner: &SigningKey) -> Result<Value> {
    if !safe_int(seq).is_some_and(|s| s >= 1) {
        return fail("BAD_SEQ", "A notice needs a sequence number from 1");
    }
    if from.is_empty() || to.is_empty() || from == to {
        return fail("BAD_SITES", "A move needs two different sites");
    }
    sign(MIGRATION, &json!({ "subject": subject, "from": from, "to": to, "seq": seq, "at": at, "keep_old_until": keep_old_until }), owner)
}

/// Check a notice against the owner's key and the last accepted one.
pub fn accept_migration(notice: &Value, owner_pub: &str, last: &Value) -> Result<Value> {
    if notice["kind"] != MIGRATION {
        return fail("MALFORMED", "Not a migration notice");
    }
    if !check_signature(notice, &notice["sig"], owner_pub) {
        return fail("BAD_SIGNATURE", "Not signed by the owner");
    }
    let b = &notice["body"];
    if truthy(last) {
        if b["subject"] != last["subject"] {
            return fail("WRONG_SUBJECT", "This notice is about something else");
        }
        // b.seq <= last.seq, with JavaScript's number comparison (NaN compares false).
        if let (Some(x), Some(y)) = (b["seq"].as_f64(), last["seq"].as_f64()) {
            if x <= y {
                return fail("REPLAYED", "An older notice than one already accepted");
            }
        }
        if b["from"] != last["to"] {
            return fail("DISCONTINUOUS", "This move doesn't start where the last one ended");
        }
    }
    Ok(b.clone())
}

/// Where something lives now, after a list of notices.
pub fn current_site(notices: &[Value], owner_pub: &str, start: &Value) -> Value {
    let mut sorted: Vec<&Value> = notices.iter().collect();
    sorted.sort_by(|a, b| {
        let (x, y) = (a["body"]["seq"].as_f64().unwrap_or(f64::NAN), b["body"]["seq"].as_f64().unwrap_or(f64::NAN));
        x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut last = Value::Null;
    let mut site = start.clone();
    for n in sorted {
        let prior = if last.is_null() { json!({ "subject": n["body"]["subject"], "seq": 0, "to": start }) } else { last.clone() };
        if let Ok(b) = accept_migration(n, owner_pub, &prior) {
            site = b["to"].clone();
            last = b;
        }
    }
    site
}
