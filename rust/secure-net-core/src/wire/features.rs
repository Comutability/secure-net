//! Feature negotiation (CVP-008), matching `src/wire/features.js`.
use serde_json::{json, Map, Value};

use crate::canonical::MAX_SAFE_INTEGER;

pub const SECURE_NET_VERSION: &str = "0.6.0";

/// Everything this version implements, with the version of each, in the JavaScript's order.
pub const FEATURES: [(&str, i64); 18] = [
    ("cvp.federation", 2),
    ("cvp.sealed-relay", 1),
    ("cvp.pq-signatures", 1),
    ("cvp.identity", 2),
    ("cvp.sessions", 2),
    ("cvp.actors", 1),
    ("cvp.activities", 1),
    ("cvp.delivery", 2),
    ("cvp.groups", 1),
    ("cvp.repos", 1),
    ("cvp.lexicons", 1),
    ("cvp.envelope", 1),
    ("cvp.commons-ledger", 1),
    ("cvp.governance", 1),
    ("cvp.tokens", 1),
    ("cvp.personas", 1),
    ("cvp.consent", 1),
    ("cvp.extensions", 1),
];

pub fn features() -> Value {
    Value::Object(FEATURES.iter().map(|(k, v)| (k.to_string(), json!(v))).collect())
}

pub fn describe_site(features: Option<&Value>) -> Value {
    json!({ "protocol": "secure-net", "version": SECURE_NET_VERSION, "features": features.cloned().unwrap_or_else(self::features) })
}

fn safe_int(v: &Value) -> Option<i64> {
    v.as_i64().filter(|n| n.unsigned_abs() <= MAX_SAFE_INTEGER as u64).or_else(|| {
        v.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64).map(|f| f as i64)
    })
}

/// The features two sites share, at the lower of the two versions. Unknown ones are ignored.
pub fn negotiate(ours: &Value, theirs: &Value) -> Value {
    let mut out = Map::new();
    for (name, v) in ours.as_object().into_iter().flatten() {
        if let (Some(v), Some(t)) = (safe_int(v), safe_int(&theirs[name.as_str()])) {
            if t > 0 {
                out.insert(name.clone(), json!(v.min(t)));
            }
        }
    }
    Value::Object(out)
}
