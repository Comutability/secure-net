//! Moving history to a new device (CVP-016, "New devices"), matching `src/session/history.js`.
//! The history is sealed in chunks under a fresh key; the key and manifest go to the new device
//! over the one-to-one session, the chunks anywhere convenient.
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::bytes::{b64u, equal_bytes, from_b64u, random, sha256};
use crate::canonical::{canonical_bytes, MAX_SAFE_INTEGER};
use crate::error::{Error, Result};
use crate::session::primitives::{open, seal, LABEL};

pub const CHUNK_SIZE: usize = 256 * 1024;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn chunk_key(key: &[u8], i: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), key).expand(format!("{LABEL}/history/{i}").as_bytes(), &mut out).expect("length");
    out
}

fn chunk_ad(manifest: &Value, i: usize) -> Result<Vec<u8>> {
    Ok([format!("{LABEL}/history\n").into_bytes(), canonical_bytes(&json!({ "id": manifest["id"], "chunks": manifest["chunks"], "i": i }))?].concat())
}

/// Seal history items (a JSON array). Returns `(offer, chunks)`.
pub fn seal_history(items: &Value, chunk_size: usize, note: Option<&str>) -> Result<(Value, Vec<String>)> {
    let count = items.as_array().ok_or_else(|| err("BAD_INPUT", "History items must be an array"))?.len();
    let chunk_size = chunk_size.max(1);
    let key = random::<32>();
    let bytes = canonical_bytes(items)?;
    let parts: Vec<&[u8]> = if bytes.is_empty() { vec![&bytes[..]] } else { bytes.chunks(chunk_size).collect() };
    let mut manifest = json!({ "id": b64u(&random::<16>()), "chunks": parts.len(), "count": count, "size": bytes.len() });
    let mut chunks = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        chunks.push(b64u(&seal(&chunk_key(&key, i), p, &chunk_ad(&manifest, i)?, "history")));
    }
    manifest["digest"] = json!(b64u(&sha256(chunks.join(".").as_bytes())));
    let mut offer = json!({ "type": "history", "key": b64u(&key), "manifest": manifest });
    if let Some(n) = note.filter(|n| !n.is_empty()) {
        let mut units = 0;
        offer["note"] = json!(n.chars().take_while(|c| { units += c.len_utf16(); units <= 200 }).collect::<String>());
    }
    Ok((offer, chunks))
}

/// Open a transfer on the new device.
pub fn open_history(offer: &Value, chunks: &[String]) -> Result<Value> {
    let m = &offer["manifest"];
    let n = m["chunks"].as_u64().filter(|n| *n >= 1 && *n <= MAX_SAFE_INTEGER as u64);
    if offer["type"] != "history" || !m.is_object() || n.is_none() {
        return Err(err("BAD_MESSAGE", "Not a history offer"));
    }
    let n = n.unwrap() as usize;
    if chunks.len() != n {
        return Err(err("INCOMPLETE", format!("Expected {n} chunks, got {}", chunks.len())));
    }
    let digest = from_b64u(m["digest"].as_str().unwrap_or("")).unwrap_or_default();
    if !equal_bytes(&sha256(chunks.join(".").as_bytes()), &digest) {
        return Err(err("TAMPERED", "History chunks don't match the manifest"));
    }
    let key = from_b64u(offer["key"].as_str().unwrap_or("")).map_err(|_| err("BAD_MESSAGE", "Not a history offer"))?;
    let mut all = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        let ct = from_b64u(c).map_err(|_| err("TAMPERED", "History chunks don't match the manifest"))?;
        all.extend(open(&chunk_key(&key, i), &ct, &chunk_ad(m, i)?, "history")?);
    }
    if Some(all.len() as u64) != m["size"].as_u64() {
        return Err(err("TAMPERED", "History is the wrong size"));
    }
    let items: Value = serde_json::from_slice(&all).map_err(|_| err("TAMPERED", "History is malformed"))?;
    if items.as_array().map(Vec::len).map(|l| l as u64) != m["count"].as_u64() {
        return Err(err("TAMPERED", "History has the wrong number of items"));
    }
    Ok(items)
}
