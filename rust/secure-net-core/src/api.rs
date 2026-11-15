//! One JSON-in, JSON-out entry point for everything in this crate, shared by the command-line
//! front end (`examples/cli.rs`) and the WebAssembly build (`secure-net-wasm`), so both expose
//! exactly the same operations with the same JSON as the JavaScript library.
//!
//! A request is `{ "op": ..., ...arguments }`. Byte strings (plaintexts) are base64url. Times are
//! milliseconds since 1970 and must be given (`now`), so results are reproducible.
use serde_json::{json, Map, Value};

use crate::bytes::{b64u, from_b64u};
use crate::canonical::canonical_json;
use crate::error::Error;
use crate::session::keys::{create_account, create_device, create_prekeys, link_code, safety_number, sign_device_list, verify_bundle, verify_device_list, Device};
use crate::session::v1;
use crate::signed::{check_signature, record_id, sign, SigningKey};

fn field<T: serde::de::DeserializeOwned>(req: &Value, name: &str) -> Result<T, Error> {
    serde_json::from_value(req[name].clone()).map_err(|e| Error::new("BAD_INPUT", format!("{name}: {e}")))
}

/// Run one request.
pub fn call(req: &Value) -> Result<Value, Error> {
    if let Some(reply) = crate::cv::api::call(req["op"].as_str().unwrap_or(""), req) {
        return reply;
    }
    let now = || req["now"].as_i64().ok_or_else(|| Error::new("BAD_INPUT", "now: milliseconds since 1970 are required"));
    Ok(match req["op"].as_str().unwrap_or("") {
        "canonical" => json!(canonical_json(&req["value"])?),
        "createAccount" => json!(create_account()),
        "createDevice" => json!(create_device()),
        "signDeviceList" => {
            let account: SigningKey = field(req, "account")?;
            let devices: Vec<Value> = field(req, "devices")?;
            sign_device_list(&account, devices, req["seq"].as_i64().unwrap_or(1), now()?)?
        }
        "createPrekeys" => {
            let device: Device = field(req, "device")?;
            let n = |k: &str, d: u64| req[k].as_u64().unwrap_or(d) as usize;
            json!(create_prekeys(&device, n("oneTime", 3), n("pqOneTime", 3), now()?, req["sessions"].as_i64().unwrap_or(1))?)
        }
        "sign" => {
            let key: SigningKey = field(req, "key")?;
            sign(req["kind"].as_str().unwrap_or(""), &req["body"], &key)?
        }
        "check" => json!(check_signature(&req["record"], &req["record"]["sig"], req["publicKey"].as_str().unwrap_or(""))),
        "initiate" => {
            let device: Device = field(&req["me"], "device")?;
            let me = v1::Me { device: &device, device_list: &req["me"]["deviceList"], prekeys: None };
            json!(v1::initiate(&me, &req["bundle"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0), now()?)?)
        }
        "respond" => {
            let device: Device = field(&req["me"], "device")?;
            let prekeys: Map<String, Value> = field(&req["me"], "prekeys")?;
            let me = v1::Me { device: &device, device_list: &req["me"]["deviceList"], prekeys: Some(&prekeys) };
            let r = v1::respond(&me, &req["message"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0))?;
            json!({ "state": r.state, "plaintext": b64u(&r.plaintext), "prekeys": r.prekeys })
        }
        "encrypt" => {
            let state: v1::State = field(req, "state")?;
            let plaintext = from_b64u(req["plaintext"].as_str().unwrap_or(""))?;
            let (state, message) = v1::encrypt(&state, &plaintext)?;
            json!({ "state": state, "message": message })
        }
        "decrypt" => {
            let state: v1::State = field(req, "state")?;
            let (state, plaintext) = v1::decrypt(&state, &req["message"])?;
            json!({ "state": state, "plaintext": b64u(&plaintext) })
        }
        "recordId" => json!(record_id(&req["record"])?),
        "verifyDeviceList" => verify_device_list(&req["record"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0))?,
        "verifyBundle" => {
            let b = verify_bundle(&req["bundle"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0), now()?)?;
            json!({ "list": b.list, "device": b.device, "signed": b.signed, "pq": b.pq, "oneTime": b.one_time })
        }
        "safetyNumber" => json!(safety_number(req["a"].as_str().unwrap_or(""), req["b"].as_str().unwrap_or(""))),
        "linkCode" => json!(link_code(req["sign"].as_str().unwrap_or(""), req["dh"].as_str().unwrap_or(""))),
        "handshakeId" => json!(v1::handshake_id(&req["message"])),
        "isInitial" => json!(v1::is_initial(&req["message"])),
        op => return Err(Error::new("BAD_INPUT", format!("unknown op \"{op}\""))),
    })
}


/// Run one request given as JSON text, and answer with `{ "ok": ... }` or
/// `{ "error": { "code", "message" } }` as JSON text.
pub fn call_text(request: &str) -> String {
    let reply = match serde_json::from_str::<Value>(request) {
        Err(e) => json!({ "error": { "code": "BAD_INPUT", "message": e.to_string() } }),
        Ok(req) => match call(&req) {
            Ok(v) => json!({ "ok": v }),
            Err(e) => json!({ "error": { "code": e.code, "message": e.message } }),
        },
    };
    reply.to_string()
}
