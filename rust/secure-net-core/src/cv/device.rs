//! Per-device keys (`src/crypto/device.js`).
//!
//! In a browser the JavaScript makes the signing and box private keys non-extractable WebCrypto
//! keys, which page script can use but never read. WebAssembly memory can't offer that, so web
//! clients keep making device keys with WebCrypto. This version, with PKCS#8 private keys, is
//! for native clients and tests.
use serde_json::{json, Value};

use super::encoding::{iso_from_ms, random_id};
use super::kem::kem_keygen;
use super::primitives::generate_pair;
use crate::error::Result;

pub fn create_device_keys(label: &str, now: i64) -> Result<Value> {
    let (sign_priv, sign_pub) = generate_pair()?;
    let (box_priv, box_pub) = generate_pair()?;
    let kem = kem_keygen(None)?;
    let label = if label.is_empty() { "This device" } else { label };
    // JavaScript's slice(0, 60) counts UTF-16 units; this keeps whole characters within that.
    let mut units = 0;
    let label: String = label.chars().take_while(|c| { units += c.len_utf16(); units <= 60 }).collect();
    Ok(json!({
        "device_id": random_id(16), "label": label,
        "sign_priv": sign_priv, "sign_pub": sign_pub, "box_priv": box_priv, "box_pub": box_pub,
        "kem_priv": kem["kem_priv"], "kem_pub": kem["kem_pub"], "created_at": iso_from_ms(now)?,
    }))
}

/// The public half of a device, as published.
pub fn public_device(device: &Value) -> Value {
    let mut out = json!({ "device_id": device["device_id"], "sign_pub": device["sign_pub"], "box_pub": device["box_pub"], "label": device["label"] });
    if device["kem_pub"].as_str().is_some_and(|k| !k.is_empty()) {
        out["kem_pub"] = device["kem_pub"].clone();
    }
    out
}
