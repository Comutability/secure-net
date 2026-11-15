//! The social vocabulary (CVP-018), matching `src/social/vocabulary.js`: ActivityStreams 2.0
//! names as plain canonical JSON, and the rules every activity and object must meet. The problem
//! lists are the JavaScript's, word for word, so a site can show the same reasons either way.
use serde_json::Value;

use crate::cv::canonical::js_string;
use crate::error::{Error, Result};
use crate::js::{len16, safe_int, show, truthy};

pub const ACTOR_TYPES: [&str; 5] = ["Person", "Group", "Organization", "Service", "Application"];
pub const ACTIVITY_TYPES: [&str; 17] = ["Create", "Update", "Delete", "Follow", "Accept", "Reject", "Undo", "Like", "Announce", "Add", "Remove", "Block", "Flag", "Join", "Leave", "Invite", "Move"];
pub const OBJECT_TYPES: [&str; 11] = ["Note", "Article", "Image", "Video", "Audio", "Document", "Page", "Event", "Place", "Question", "Tombstone"];
pub const PUBLIC: &str = "public";
pub const FOLLOWERS: &str = "followers";
pub const MEDIA_TYPES: [&str; 2] = ["text/plain", "text/markdown"];

pub mod limits {
    pub const CONTENT: usize = 50_000;
    pub const SUMMARY: usize = 500;
    pub const NAME: usize = 200;
    pub const ATTACHMENTS: usize = 20;
    pub const TAGS: usize = 100;
    pub const RECIPIENTS: usize = 1000;
    pub const OPTIONS: usize = 50;
    pub const BYTES: usize = 256 * 1024;
}

pub(crate) fn b64u_chars(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// `^[A-Za-z0-9_-]{22}$` (on a string).
pub fn kid_str(s: &str) -> bool {
    s.len() == 22 && b64u_chars(s)
}

/// The actor part of `^([A-Za-z0-9_-]{22}):[A-Za-z0-9_-]{16,64}$`.
fn id_owner(s: &str) -> Option<&str> {
    let (a, r) = s.split_once(':')?;
    (kid_str(a) && (16..=64).contains(&r.len()) && b64u_chars(r)).then_some(a)
}

/// `^group:[A-Za-z0-9_-]{16,64}$`
pub fn group_str(s: &str) -> bool {
    s.strip_prefix("group:").is_some_and(|r| (16..=64).contains(&r.len()) && b64u_chars(r))
}

/// `(?=.{1,200}$)[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2,}`
pub fn extension_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    (1..=200).contains(&len16(s))
        && parts.len() >= 3
        && parts.iter().all(|p| p.as_bytes().first().is_some_and(|c| c.is_ascii_lowercase()) && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
}

/// `^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$`
fn lang_ok(s: &str) -> bool {
    let mut parts = s.split('-');
    let first = parts.next().unwrap_or("");
    (2..=3).contains(&first.len()) && first.bytes().all(|c| c.is_ascii_lowercase()) && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_alphanumeric()))
}

/// JavaScript's `\s`.
pub(crate) fn js_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

pub fn js_space_pub(c: char) -> bool {
    js_space(c)
}

/// What a regular expression's `test(v)` sees: `String(v)`.
fn as_text(v: Option<&Value>) -> String {
    show(v)
}

/// `test(v || "")`.
fn as_text_or_empty(v: Option<&Value>) -> String {
    match v {
        Some(x) if truthy(x) => js_string(x),
        _ => String::new(),
    }
}

pub fn is_actor_id(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(kid_str)
}

pub fn is_object_id(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| id_owner(s).is_some())
}

pub fn is_group_id(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(group_str)
}

/// The actor an id belongs to, or None (JavaScript's null).
pub fn owner_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).and_then(id_owner).map(str::to_string)
}

pub fn is_address(v: &Value) -> bool {
    v == PUBLIC || v == FOLLOWERS || is_actor_id(Some(v)) || v.as_str().is_some_and(group_str)
}

/// A new id for something this actor makes.
pub fn new_id(actor: &str) -> Result<String> {
    if !kid_str(actor) {
        return Err(Error::new("BAD_INPUT", "Not an actor id"));
    }
    Ok(format!("{actor}:{}", crate::bytes::random_b64u(16)))
}

fn is_int(v: Option<&Value>) -> bool {
    v.and_then(safe_int).is_some_and(|n| n >= 0)
}

fn s_max(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| len16(s) <= max)
}

/// `owner === actor`, with JavaScript's strict equality (None owner is null, None actor undefined).
fn owner_is(owner: Option<String>, actor: Option<&Value>) -> bool {
    match owner {
        None => actor == Some(&Value::Null),
        Some(o) => actor.and_then(Value::as_str) == Some(o.as_str()),
    }
}

fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|o| o.get(k))
}

fn attachment_problems(a: &Value, encrypted: bool, at: &str, out: &mut Vec<String>) {
    if !truthy(a) || !(a.is_object() || a.is_array()) {
        out.push(format!("{at} isn't an object"));
        return;
    }
    let g = |k| get(a, k);
    if !g("type").and_then(Value::as_str).is_some_and(|t| ["Image", "Video", "Audio", "Document"].contains(&t)) {
        out.push(format!("{at}.type must be Image, Video, Audio or Document"));
    }
    if !s_max(g("url"), 2048) || !g("url").and_then(Value::as_str).is_some_and(|u| u.starts_with("https://")) {
        out.push(format!("{at}.url must be an https URL"));
    }
    let media_ok = g("mediaType").and_then(Value::as_str).is_some_and(|m| {
        m.split_once('/').is_some_and(|(x, y)| !x.is_empty() && x.bytes().all(|c| c.is_ascii_lowercase()) && !y.is_empty() && y.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".+-".contains(&c)))
    });
    if !s_max(g("mediaType"), 100) || !media_ok {
        out.push(format!("{at}.mediaType must be a media type"));
    }
    if !is_int(g("size")) {
        out.push(format!("{at}.size must be a whole number of bytes"));
    }
    if !g("sha256").and_then(Value::as_str).is_some_and(|h| h.len() == 43 && b64u_chars(h)) {
        out.push(format!("{at}.sha256 must be the base64url SHA-256 of the stored bytes"));
    }
    match g("key") {
        Some(k) => {
            if !encrypted {
                out.push(format!("{at}.key may only appear in end-to-end encrypted activities"));
            }
            if !k.as_str().is_some_and(|k| !k.is_empty() && b64u_chars(k) && k.len() == 43) {
                out.push(format!("{at}.key must be a base64url 32-byte AES-256-GCM key"));
            }
        }
        None if encrypted => out.push(format!("{at} in an encrypted activity must carry its key (the file is stored encrypted)")),
        None => {}
    }
    if g("name").is_some() && !s_max(g("name"), 1500) {
        out.push(format!("{at}.name (the description) is too long"));
    }
    if g("width").is_some() && !is_int(g("width")) {
        out.push(format!("{at}.width must be a whole number"));
    }
    if g("height").is_some() && !is_int(g("height")) {
        out.push(format!("{at}.height must be a whole number"));
    }
}

/// Problems with an object. `actor` is who the activity says made it (None: undefined).
pub fn object_problems(o: Option<&Value>, actor: Option<&Value>, encrypted: bool, at: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(o) = o.filter(|o| truthy(o) && o.is_object()) else { return vec![format!("{at} must be an object")] };
    let g = |k| get(o, k);
    let t = g("type");
    let registered = t.and_then(Value::as_str).is_some_and(|t| OBJECT_TYPES.contains(&t));
    if !registered && !extension_type(&as_text_or_empty(t)) {
        return vec![format!("{at}.type \"{}\" isn't a registered object type or an extension type like org.example.recipe", show(t))];
    }
    if !is_object_id(g("id")) {
        out.push(format!("{at}.id must be \"<actor id>:<random>\""));
    }
    let attributed_ok = match (g("attributedTo"), actor) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    };
    if !attributed_ok {
        out.push(format!("{at}.attributedTo must be the actor ({})", show(actor)));
    }
    if g("id").is_some_and(truthy) && !owner_is(owner_of(g("id")), actor) {
        out.push(format!("{at}.id must start with the actor's id"));
    }
    if t == Some(&Value::String("Tombstone".into())) {
        return out;
    }
    if !is_int(g("published")) {
        out.push(format!("{at}.published must be milliseconds since 1970 (an integer)"));
    }
    if g("updated").is_some() && !is_int(g("updated")) {
        out.push(format!("{at}.updated must be an integer"));
    }
    if g("content").is_some() && !s_max(g("content"), limits::CONTENT) {
        out.push(format!("{at}.content must be text of at most {} characters", limits::CONTENT));
    }
    if g("mediaType").is_some() && !g("mediaType").and_then(Value::as_str).is_some_and(|m| MEDIA_TYPES.contains(&m)) {
        out.push(format!("{at}.mediaType must be {}", MEDIA_TYPES.join(" or ")));
    }
    if g("name").is_some() && !s_max(g("name"), limits::NAME) {
        out.push(format!("{at}.name is too long"));
    }
    if g("summary").is_some() && !s_max(g("summary"), limits::SUMMARY) {
        out.push(format!("{at}.summary (content warning) is too long"));
    }
    if g("sensitive").is_some() && !g("sensitive").is_some_and(Value::is_boolean) {
        out.push(format!("{at}.sensitive must be true or false"));
    }
    if g("language").is_some() && !g("language").and_then(Value::as_str).is_some_and(lang_ok) {
        out.push(format!("{at}.language must be a BCP 47 tag"));
    }
    if g("inReplyTo").is_some() && !is_object_id(g("inReplyTo")) {
        out.push(format!("{at}.inReplyTo must be an object id"));
    }
    if g("context").is_some() && !(is_object_id(g("context")) || group_str(&as_text(g("context")))) {
        out.push(format!("{at}.context must be an object or group id"));
    }
    if let Some(att) = g("attachment") {
        match att.as_array().filter(|a| a.len() <= limits::ATTACHMENTS) {
            None => out.push(format!("{at}.attachment must be a list of at most {}", limits::ATTACHMENTS)),
            Some(list) => list.iter().enumerate().for_each(|(i, a)| attachment_problems(a, encrypted, &format!("{at}.attachment[{i}]"), &mut out)),
        }
    }
    if let Some(tags) = g("tag") {
        match tags.as_array().filter(|a| a.len() <= limits::TAGS) {
            None => out.push(format!("{at}.tag must be a list of at most {}", limits::TAGS)),
            Some(list) => {
                for (i, t) in list.iter().enumerate() {
                    let tt = get(t, "type");
                    let bad = if tt == Some(&Value::String("Mention".into())) {
                        !is_actor_id(get(t, "href"))
                    } else if tt == Some(&Value::String("Hashtag".into())) {
                        let name = get(t, "name");
                        !s_max(name, 100) || !name.and_then(Value::as_str).is_some_and(|n| n.len() > 1 && n.starts_with('#') && !n[1..].chars().any(js_space))
                    } else {
                        true
                    };
                    if bad {
                        out.push(format!("{at}.tag[{i}] must be a Mention (href: actor id) or a Hashtag (name: #word)"));
                    }
                }
            }
        }
    }
    if t == Some(&Value::String("Question".into())) {
        let one = g("oneOf").filter(|v| !v.is_null());
        let opts = one.or(g("anyOf").filter(|v| !v.is_null()));
        let both = g("oneOf").is_some_and(truthy) && g("anyOf").is_some_and(truthy);
        match opts.and_then(Value::as_array).filter(|o| (2..=limits::OPTIONS).contains(&o.len()) && !both) {
            None => out.push(format!("{at} must have 2 to {} options in oneOf or anyOf", limits::OPTIONS)),
            Some(list) => {
                if !list.iter().all(|x| get(x, "type") == Some(&Value::String("Note".into())) && s_max(get(x, "name"), limits::NAME)) {
                    out.push(format!("{at} options must be {{ type: \"Note\", name }}"));
                }
            }
        }
        if g("endTime").is_some() && !is_int(g("endTime")) {
            out.push(format!("{at}.endTime must be an integer"));
        }
    }
    if t == Some(&Value::String("Event".into())) {
        if !is_int(g("startTime")) {
            out.push(format!("{at}.startTime must be an integer"));
        }
        if g("endTime").is_some() && !is_int(g("endTime")) {
            out.push(format!("{at}.endTime must be an integer"));
        }
    }
    out
}

fn object_rule(t: &str) -> &'static str {
    match t {
        "Create" => "object",
        "Update" => "object-or-actor",
        "Follow" | "Block" | "Invite" | "Move" => "actor",
        "Flag" => "id-or-actor",
        "Join" | "Leave" => "group",
        _ => "id",
    }
}

/// `[...(v || [])]`: the items of an array, the characters of a string, or a TypeError.
fn spread(v: Option<&Value>, name: &str) -> Result<Vec<Value>> {
    match v {
        None => Ok(vec![]),
        Some(x) if !truthy(x) => Ok(vec![]),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::String(s)) => Ok(s.chars().map(|c| Value::String(c.to_string())).collect()),
        Some(_) => Err(Error::new("TypeError", format!("{name} is not iterable"))),
    }
}

pub fn recipients(a: &Value, fields: &[&str]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for f in fields {
        out.extend(spread(get(a, f), &format!("a.{f}"))?);
    }
    Ok(out)
}

/// Problems with an activity body (empty if fine). An error means the JavaScript would throw.
pub fn activity_problems(a: &Value, encrypted: bool) -> Result<Vec<String>> {
    let mut out = Vec::new();
    if !a.is_object() {
        return Ok(vec!["An activity must be an object".into()]);
    }
    let g = |k| get(a, k);
    let Some(t) = g("type").and_then(Value::as_str).filter(|t| ACTIVITY_TYPES.contains(t)) else {
        return Ok(vec![format!("Activity type \"{}\" isn't registered", show(g("type")))]);
    };
    if !is_actor_id(g("actor")) {
        out.push("actor must be an actor id".into());
    }
    if !is_object_id(g("id")) || !owner_is(owner_of(g("id")), g("actor")) {
        out.push("id must be \"<actor id>:<random>\" for this actor".into());
    }
    if !is_int(g("published")) {
        out.push("published must be milliseconds since 1970 (an integer)".into());
    }
    for f in ["to", "cc"] {
        if let Some(v) = g(f) {
            if !v.as_array().is_some_and(|l| l.iter().all(is_address)) {
                out.push(format!("{f} must be a list of addresses (\"public\", \"followers\", actor ids or group ids)"));
            }
        }
    }
    let rec = recipients(a, &["to", "cc"])?;
    if rec.is_empty() {
        out.push("An activity must be addressed (to or cc)".into());
    }
    if rec.len() > limits::RECIPIENTS {
        out.push(format!("At most {} recipients", limits::RECIPIENTS));
    }
    if rec.iter().any(|r| r == PUBLIC) && encrypted {
        out.push("A public activity isn't encrypted (CVP-019): send it as a public envelope".into());
    }
    let o = g("object");
    match object_rule(t) {
        "object" => out.extend(object_problems(o, g("actor"), encrypted, "object")),
        "object-or-actor" => {
            let actor_type = o.filter(|o| o.is_object() || o.is_array()).and_then(|o| get(o, "type")).filter(|x| truthy(x)).and_then(Value::as_str).is_some_and(|x| ACTOR_TYPES.contains(&x));
            if actor_type {
                let same = match (o.and_then(|o| get(o, "id")), g("actor")) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x == y,
                    _ => false,
                };
                if !same {
                    out.push("Update of an actor must be of the actor itself".into());
                }
            } else {
                out.extend(object_problems(o, g("actor"), encrypted, "object"));
            }
        }
        "id" if !is_object_id(o) => out.push(format!("{t}'s object must be an object or activity id")),
        "actor" if !is_actor_id(o) => out.push(format!("{t}'s object must be an actor id")),
        "id-or-actor" if !is_object_id(o) && !is_actor_id(o) => out.push(format!("{t}'s object must be an object id or an actor id")),
        "group" if !o.and_then(Value::as_str).is_some_and(group_str) => out.push(format!("{t}'s object must be a group id")),
        _ => {}
    }
    if ["Delete", "Update", "Undo"].contains(&t) {
        let target = match o {
            Some(Value::String(_)) => o,
            Some(x) if x.is_object() || x.is_array() => get(x, "id"),
            _ => None,
        };
        if target.is_some_and(truthy) {
            if let Some(owner) = owner_of(target) {
                if !owner_is(Some(owner), g("actor")) {
                    out.push(format!("{t} may only act on the actor's own objects and activities"));
                }
            }
        }
    }
    if t == "Move" && !is_actor_id(g("target")) {
        out.push("Move needs target: the actor id moved to".into());
    }
    if (t == "Add" || t == "Remove") && !g("target").and_then(Value::as_str).is_some_and(|s| group_str(s) || id_owner(s).is_some()) {
        out.push(format!("{t} needs target: a group or collection id"));
    }
    if t == "Flag" && g("content").is_some() && !s_max(g("content"), limits::SUMMARY * 4) {
        out.push("Flag content (the reason) is too long".into());
    }
    if g("result").is_some() {
        out.push("result is not part of version 1 activities".into());
    }
    Ok(out)
}
