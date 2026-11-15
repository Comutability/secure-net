//! Site-to-site requests (CVP-005), matching `src/wire/federation.js`: endpoint rules, the
//! request signature base, host normalisation and the private-address check.
use serde_json::{Map, Value};

use crate::bytes::{b64u, sha256};
use crate::error::Result;

pub const PROTOCOL: &str = "commonveil/1";
pub const SITE_DOCUMENT: &str = "/.well-known/commonveil";
pub const SKEW_MS: i64 = 5 * 60_000;

pub const DEFAULT_ENDPOINTS: [(&str, &str); 7] = [
    ("act", "/cvp/v1/act"),
    ("directory", "/cvp/v1/directory"),
    ("inbox", "/cvp/v1/inbox"),
    ("discover", "/cvp/v1/discover"),
    ("actors", "/cvp/v1/actors/{name}/{room}"),
    ("identity", "/.well-known/commonveil/identity"),
    ("files", "/api/files"),
];

pub const SOCIAL_ENDPOINTS: [(&str, &str); 12] = [
    ("actor", "/.well-known/commonveil/actor"),
    ("prekeys", "/cvp/v2/prekeys/{actor}/{device}"),
    ("deliver", "/cvp/v2/deliver"),
    ("outbox", "/cvp/v2/outbox"),
    ("mailbox", "/cvp/v2/mailbox"),
    ("public", "/cvp/v2/public/{actor}"),
    ("repo", "/cvp/v2/repo/{actor}"),
    ("changes", "/cvp/v2/changes"),
    ("lexicon", "/cvp/v2/lexicon/{id}"),
    ("sealed", "/cvp/v2/sealed"),
    ("key_packages", "/cvp/v2/key-packages/{actor}/{device}"),
    ("delivery_token", "/cvp/v2/delivery-token"),
];

/// `^\/[A-Za-z0-9._~{}\/-]{0,199}$`, no `//`, no `..` segment.
fn safe_path(v: &str) -> bool {
    v.starts_with('/')
        && v.len() <= 200
        && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"._~{}/-".contains(&c))
        && !v.contains("//")
        && !v.split('/').any(|seg| seg == "..")
}

/// A site's endpoints from its site document: only plain paths on that site; anything else falls
/// back to the default.
pub fn endpoints_of(doc: &Value) -> Value {
    let given = doc.get("endpoints").filter(|e| e.is_object());
    let mut out = Map::new();
    for (name, default) in DEFAULT_ENDPOINTS {
        let v = given.and_then(|g| g[name].as_str()).filter(|v| safe_path(v)).unwrap_or(default);
        out.insert(name.into(), Value::String(v.into()));
    }
    Value::Object(out)
}

fn label_ok(l: &str) -> bool {
    let b = l.as_bytes();
    !b.is_empty() && b.len() <= 63 && b[0].is_ascii_alphanumeric() && b[b.len() - 1].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// HOST_RE: a lower-case DNS name of up to 253 characters, with an optional port of 1 to 5 digits.
pub fn host_ok(v: &str) -> bool {
    let (name, port) = match v.rsplit_once(':') {
        Some((n, p)) => (n, Some(p)),
        None => (v, None),
    };
    if port.is_some_and(|p| p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit())) {
        return false;
    }
    !name.is_empty() && name.len() <= 253 && name.split('.').all(label_ok)
}

/// A site address in its one accepted form, or None.
pub fn norm_host(h: &str) -> Option<String> {
    let mut v = crate::js::trim(h).to_lowercase();
    for scheme in ["http://", "https://"] {
        if let Some(rest) = v.strip_prefix(scheme) {
            v = rest.to_string();
            break;
        }
    }
    if let Some(i) = v.find('/') {
        v.truncate(i);
    }
    host_ok(&v).then_some(v)
}

pub fn digest_of(body: &[u8]) -> String {
    format!("sha-256={}", b64u(&sha256(body)))
}

pub struct RequestFields<'a> {
    pub method: &'a str,
    pub to: &'a str,
    pub path: &'a str,
    pub from: &'a str,
    pub date: &'a str,
    pub nonce: &'a str,
    pub digest: &'a str,
    pub user: &'a str,
}

pub fn signature_base(f: &RequestFields) -> String {
    let user = if f.user.is_empty() { "-" } else { f.user };
    ["commonveil-request/v1", &f.method.to_uppercase(), f.to, f.path, f.from, f.date, f.nonce, f.digest, user].join("\n")
}

/// Sign a request with a site's Ed25519 secret key (base64url).
pub fn sign_request(f: &RequestFields, secret_key: &str) -> Result<String> {
    use ed25519_dalek::Signer;
    let seed: [u8; 32] = crate::bytes::from_b64u(secret_key)?.try_into().map_err(|_| crate::error::Error::new("BAD_KEY", "An Ed25519 secret key is 32 bytes"))?;
    Ok(b64u(&ed25519_dalek::SigningKey::from_bytes(&seed).sign(signature_base(f).as_bytes()).to_bytes()))
}

pub fn verify_request(f: &RequestFields, signature: &str, public_key: &str) -> bool {
    crate::ed25519::verify_b64u(public_key, signature, signature_base(f).as_bytes())
}

/// Whether a request's date (ISO 8601) is within the allowed skew of `now`.
pub fn fresh_enough(date: &str, now: i64) -> bool {
    crate::js::date_parse(date).is_some_and(|t| (now - t).abs() <= SKEW_MS)
}

/// IPv4 in the JavaScript's form: four parts each matching `25[0-5]|2[0-4]\d|1?\d?\d`.
fn ipv4(v: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        // One or two digits: anything. Three: 1dd, or 200 to 255.
        if p.len() == 3 && !(p.starts_with('1') || (p.starts_with('2') && n <= 255)) {
            return None;
        }
        out[i] = n as u8;
    }
    Some(out)
}

/// Whether an address is private, loopback, link-local, CGNAT, multicast or reserved.
pub fn is_private(ip: &str) -> bool {
    let lower = ip.to_lowercase();
    let v = lower.trim_start_matches('[').trim_end_matches(']');
    if let Some([a, b, _, _]) = ipv4(v) {
        return a == 10 || a == 127 || a == 0 || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 100 && (64..=127).contains(&b)) || a >= 224;
    }
    if let Some(rest) = v.strip_prefix("::ffff:") {
        return is_private(rest);
    }
    v == "::1" || v == "::" || v.starts_with("fc") || v.starts_with("fd") || v.starts_with("fe80") || v.starts_with("ff")
}
