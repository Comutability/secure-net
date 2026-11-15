//! Extensions and themes (CVP-008), matching `src/extensions/manifest.js`: signed manifests that
//! pin code by hash and declare exactly what they may touch, and data-only themes whose colours
//! must keep WCAG AA contrast.
use serde_json::Value;

use crate::bytes::sha256_b64u;
use crate::cv::canonical::js_string;
use crate::js::{entries, is_object_like, len16, safe_int, truthy};
use crate::signed::{check_signature, sign, signing_bytes, SigningKey};
use crate::error::{Error, Result};

pub const MANIFEST: &str = "extension.manifest";
pub const THEME: &str = "theme.package";

/// Execution models and the permissions each may ask for (registered in spec/registry.json).
pub const EXECUTION: [(&str, &[&str]); 4] = [
    ("client-local", &["read.selected", "read.channel", "write.message", "ui.panel", "ui.command", "storage.local"]),
    ("server-side", &["read.metadata", "read.ciphertext", "write.ciphertext", "queue", "ratelimit"]),
    ("external", &["send.selected", "ui.panel"]),
    ("public", &["read.public", "publish.public"]),
];

pub fn execution(model: &str) -> Option<&'static [&'static str]> {
    EXECUTION.iter().find(|(m, _)| *m == model).map(|(_, p)| *p)
}

/// `^[a-z0-9]+(\.[a-z0-9-]+){2,}$`
fn id_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 3
        && !parts[0].is_empty()
        && parts[0].bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && parts[1..].iter().all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'))
}

/// `^\d{1,4}\.\d{1,4}\.\d{1,6}$`
fn semver_ok(s: &str) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() == 3 && [4, 4, 6].iter().zip(&p).all(|(max, x)| !x.is_empty() && x.len() <= *max && x.bytes().all(|c| c.is_ascii_digit()))
}

/// `^[A-Za-z0-9_-]{43}$`
fn hash_ok(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() == 43 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'))
}

/// `m.x || ""` as a string, for the regular-expression tests.
fn str_or_empty(v: &Value) -> String {
    if truthy(v) {
        js_string(v)
    } else {
        String::new()
    }
}

pub fn manifest_problems(m: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if !is_object_like(m) {
        out.push("Not a manifest".into());
        return out;
    }
    if !id_ok(&str_or_empty(&m["id"])) {
        out.push("The id must be a reverse domain name, like org.example.debates".into());
    }
    if !m["name"].as_str().is_some_and(|n| !n.is_empty() && len16(n) <= 60) {
        out.push("A name of up to 60 characters".into());
    }
    if !semver_ok(&str_or_empty(&m["version"])) {
        out.push("A version like 1.2.3".into());
    }
    let allowed = m["execution"].as_str().and_then(execution);
    if allowed.is_none() {
        out.push("Execution must be one of client-local, server-side, external, public".into());
    }
    match m["permissions"].as_array() {
        None => out.push("List the permissions it needs (an empty list is fine)".into()),
        Some(ps) => {
            for p in ps {
                let ok = allowed.is_some_and(|a| p.as_str().is_some_and(|s| a.contains(&s)));
                if !ok {
                    let shown = if m.get("execution").is_none() { "undefined".to_string() } else { js_string(&m["execution"]) };
                    out.push(format!("\"{}\" isn't available to {shown} extensions", js_string(p)));
                }
            }
        }
    }
    if !hash_ok(&Value::String(str_or_empty(&m["code_hash"]))) {
        out.push("The code must be pinned by its SHA-256 (base64url)".into());
    }
    if m["execution"] == "external" {
        let ok = m["service"].as_str().is_some_and(|s| s.strip_prefix("https://").is_some_and(|r| !r.is_empty() && !r.starts_with('/')));
        if !ok {
            out.push("An external extension must name its service (https)".into());
        }
    }
    if truthy(&m["licence"]) && !m["licence"].is_string() {
        out.push("The licence is an SPDX identifier".into());
    }
    out
}

pub fn publish(body: &Value, publisher: &SigningKey) -> Result<Value> {
    let problems = manifest_problems(body);
    if !problems.is_empty() {
        return Err(Error::new("BAD_MANIFEST", problems.join(" ")));
    }
    let mut b = body.clone();
    b["publisher"] = Value::String(publisher.kid.clone());
    sign(MANIFEST, &b, publisher)
}

/// Check a signed manifest and (if given) the code it pins: `{ ok, problems }`.
pub fn check_manifest(record: &Value, publisher_pub: &str, code: Option<&[u8]>) -> Value {
    let mut problems = manifest_problems(&record["body"]);
    if record["kind"] != MANIFEST || !check_signature(record, &record["sig"], publisher_pub) || record["body"]["publisher"] != record["sig"]["kid"] {
        problems.push("Not signed by its publisher".into());
    }
    if let Some(code) = code {
        if record["body"]["code_hash"].as_str() != Some(sha256_b64u(code).as_str()) {
            problems.push("The code doesn't match the hash in the manifest".into());
        }
    }
    serde_json::json!({ "ok": problems.is_empty(), "problems": problems })
}

pub fn explain_permissions(m: &Value) -> Vec<String> {
    let say = |p: &str| -> Option<&'static str> {
        Some(match p {
            "read.selected" => "read the message you choose to share with it",
            "read.channel" => "read every message in the channels you enable it in",
            "write.message" => "send messages as you, when you ask it to",
            "ui.panel" => "show a panel",
            "ui.command" => "add commands",
            "storage.local" => "keep data on this device",
            "read.metadata" => "see who's in a community and when messages are sent (not what they say)",
            "read.ciphertext" => "store encrypted messages it can't read",
            "write.ciphertext" => "deliver encrypted messages",
            "queue" => "hold messages until they can be delivered",
            "ratelimit" => "slow down floods of messages",
            "send.selected" => "send what you choose to share to an outside service",
            "read.public" => "read what's been published publicly",
            "publish.public" => "publish things publicly",
            _ => return None,
        })
    };
    let mut lines: Vec<String> = m["permissions"].as_array().into_iter().flatten().map(|p| say(p.as_str().unwrap_or("")).map(str::to_string).unwrap_or_else(|| js_string(p))).collect();
    if m["execution"] == "external" {
        lines.push(format!("Anything you share goes to {}, outside Commonveil's encryption", js_string(&m["service"])));
    }
    lines
}

// ---- Themes ----

pub const APPROVED_FONTS: [&str; 11] = ["system-ui", "serif", "sans-serif", "monospace", "Atkinson Hyperlegible", "Inter", "Source Serif 4", "IBM Plex Sans", "IBM Plex Mono", "Lexend", "OpenDyslexic"];
const COLOR_TOKENS: [&str; 9] = ["background", "surface", "text", "muted", "accent", "accent-text", "danger", "danger-text", "border"];
const CONTRAST_PAIRS: [(&str, &str); 5] = [("text", "background"), ("text", "surface"), ("muted", "background"), ("accent-text", "accent"), ("danger-text", "danger")];

/// `^#[0-9a-fA-F]{6}$`
fn color_ok(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|c| c.is_ascii_hexdigit()))
}

fn luminance(hex: &str) -> f64 {
    let ch = |i: usize| {
        let c = u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0) as f64 / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * ch(1) + 0.7152 * ch(3) + 0.0722 * ch(5)
}

/// WCAG contrast ratio times 100, rounded (450 means 4.5:1), as JavaScript's `Math.round`.
pub fn contrast(a: &str, b: &str) -> i64 {
    let (x, y) = (luminance(a), luminance(b));
    let (hi, lo) = if x >= y { (x, y) } else { (y, x) };
    ((hi + 0.05) / (lo + 0.05) * 100.0 + 0.5).floor() as i64
}

pub fn theme_problems(t: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !is_object_like(t) {
        return vec!["Not a theme".into()];
    }
    if !id_ok(&str_or_empty(&t["id"])) {
        out.push("The id must be a reverse domain name".into());
    }
    if !semver_ok(&str_or_empty(&t["version"])) {
        out.push("A version like 1.2.3".into());
    }
    let allowed = ["id", "name", "version", "colors", "dark", "fonts", "radius", "spacing", "images", "attribution", "licence", "publisher"];
    for (k, _) in entries(t) {
        if !allowed.contains(&k.as_str()) {
            out.push(format!("\"{k}\" isn't something a theme can set"));
        }
    }
    for scheme in ["colors", "dark"] {
        if scheme == "dark" && t.get("dark").is_none() {
            continue;
        }
        let c = &t[scheme];
        if !is_object_like(c) {
            out.push(format!("{scheme} needs colours"));
            continue;
        }
        for (k, v) in entries(c) {
            if !COLOR_TOKENS.contains(&k.as_str()) {
                out.push(format!("\"{k}\" isn't a colour a theme can set"));
            } else if !color_ok(&v) {
                out.push(format!("{scheme}.{k} must be a colour like #1a2b3c"));
            }
        }
        for tk in COLOR_TOKENS {
            if !color_ok(&Value::String(str_or_empty(&c[tk]))) {
                out.push(format!("{scheme}.{tk} is missing"));
            }
        }
        for (fg, bg) in CONTRAST_PAIRS {
            let (f, b) = (str_or_empty(&c[fg]), str_or_empty(&c[bg]));
            if color_ok(&Value::String(f.clone())) && color_ok(&Value::String(b.clone())) && contrast(&f, &b) < 450 {
                out.push(format!("{scheme}: {fg} on {bg} is too faint to read (needs 4.5:1)"));
            }
        }
    }
    if truthy(&t["fonts"]) {
        for (k, v) in entries(&t["fonts"]) {
            if !["body", "heading", "code"].contains(&k.as_str()) {
                out.push(format!("\"{k}\" isn't a font a theme can set"));
            } else if !v.as_str().is_some_and(|f| APPROVED_FONTS.contains(&f)) {
                out.push(format!("{} isn't one of the approved fonts", js_string(&v)));
            }
        }
    }
    if t.get("radius").is_some() && !safe_int(&t["radius"]).is_some_and(|r| (0..=24).contains(&r)) {
        out.push("Radius is 0 to 24 pixels".into());
    }
    if t.get("spacing").is_some() && !["compact", "normal", "relaxed"].iter().any(|s| t["spacing"] == *s) {
        out.push("Spacing is compact, normal or relaxed".into());
    }
    let images: Vec<Value> = match &t["images"] {
        Value::Array(a) => a.clone(),
        // for...of over a string visits its characters.
        Value::String(s) => s.chars().map(|c| Value::String(c.to_string())).collect(),
        v if truthy(v) => vec![Value::Null],
        _ => vec![],
    };
    {
        for img in &images {
            let role_ok = ["background", "banner", "icon"].iter().any(|r| img["role"] == *r);
            let type_ok = ["image/png", "image/webp"].iter().any(|r| img["type"] == *r);
            if !role_ok || !hash_ok(&Value::String(str_or_empty(&img["hash"]))) || !type_ok {
                out.push("Images are PNG or WebP, pinned by hash, with a role of background, banner or icon".into());
            }
        }
    }
    out
}

pub fn publish_theme(body: &Value, publisher: &SigningKey) -> Result<Value> {
    let problems = theme_problems(body);
    if !problems.is_empty() {
        return Err(Error::new("BAD_THEME", problems.join(" ")));
    }
    let mut b = body.clone();
    b["publisher"] = Value::String(publisher.kid.clone());
    sign(THEME, &b, publisher)
}

pub fn check_theme(record: &Value, publisher_pub: &str) -> Value {
    let mut problems = theme_problems(&record["body"]);
    if record["kind"] != THEME || !check_signature(record, &record["sig"], publisher_pub) || record["body"]["publisher"] != record["sig"]["kid"] {
        problems.push("Not signed by its publisher".into());
    }
    serde_json::json!({ "ok": problems.is_empty(), "problems": problems })
}

pub fn theme_id(record: &Value) -> Result<String> {
    Ok(sha256_b64u(&signing_bytes(record["kind"].as_str().unwrap_or(""), &record["body"])?))
}
