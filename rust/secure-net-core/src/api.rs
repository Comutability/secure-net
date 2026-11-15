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
use crate::session::{group, history, v1, v2};
use crate::signed::{check_signature, record_id, sign, SigningKey};

fn field<T: serde::de::DeserializeOwned>(req: &Value, name: &str) -> Result<T, Error> {
    serde_json::from_value(req[name].clone()).map_err(|e| Error::new("BAD_INPUT", format!("{name}: {e}")))
}

/// Run one request.
pub fn call(req: &Value) -> Result<Value, Error> {
    if let Some(reply) = crate::cv::api::call(req["op"].as_str().unwrap_or(""), req) {
        return reply;
    }
    if let Some(reply) = crate::api_more::call(req["op"].as_str().unwrap_or(""), req) {
        return reply;
    }
    if let Some(reply) = crate::api_more::call_social(req["op"].as_str().unwrap_or(""), req) {
        return reply;
    }
    if let Some(reply) = crate::api_more::call_groups(req["op"].as_str().unwrap_or(""), req) {
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
        "takeBundle" => {
            // What a site hands out for one device; returns the bundle and what is left to publish.
            let mut published: crate::session::keys::Published = field(req, "published")?;
            let bundle = crate::session::keys::take_bundle(&req["deviceList"], &mut published, req["device"].as_str().unwrap_or(""));
            json!({ "bundle": bundle, "published": published })
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
        // sessions, version 2
        "v2.initiate" => {
            let device: Device = field(&req["me"], "device")?;
            let me = v2::Me { device: &device, device_list: &req["me"]["deviceList"], prekeys: None };
            json!(v2::initiate(&me, &req["bundle"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0), now()?)?)
        }
        "v2.initialSender" | "v2.respond" => {
            let device: Device = field(&req["me"], "device")?;
            let prekeys: Map<String, Value> = field(&req["me"], "prekeys")?;
            let me = v2::Me { device: &device, device_list: &req["me"]["deviceList"], prekeys: Some(&prekeys) };
            if req["op"] == "v2.initialSender" {
                v2::initial_sender(&me, &req["message"])?
            } else {
                let r = v2::respond(&me, &req["message"], req["accountKey"].as_str().unwrap_or(""), req["minSeq"].as_i64().unwrap_or(0), now()?)?;
                json!({ "state": r.state, "plaintext": b64u(&r.plaintext), "prekeys": r.prekeys })
            }
        }
        "v2.encrypt" => {
            let state: v2::State = field(req, "state")?;
            let (state, message) = v2::encrypt(&state, &from_b64u(req["plaintext"].as_str().unwrap_or(""))?)?;
            json!({ "state": state, "message": message })
        }
        "v2.decrypt" => {
            let state: v2::State = field(req, "state")?;
            let (state, plaintext) = v2::decrypt(&state, &req["message"], now()?)?;
            json!({ "state": state, "plaintext": b64u(&plaintext) })
        }
        "v2.canOpen" => json!(v2::can_open(&field::<v2::State>(req, "state")?, &req["message"])),
        "v2.pqStatus" => v2::pq_status(&field::<v2::State>(req, "state")?),
        "v2.handshakeId" => json!(v2::handshake_id(&req["message"])),
        "v2.isInitial" => json!(v2::is_initial(&req["message"])),
        // sender keys
        "group.createSenderKey" => json!(group::create_sender_key(req["group"].as_str().unwrap_or(""))),
        "group.distribution" => group::distribution(&field(req, "key")?),
        "group.accept" => json!(group::accept_distribution(&req["distribution"], req["from"].clone())?),
        "group.encrypt" => {
            let (key, message) = group::group_encrypt(&field(req, "key")?, &from_b64u(req["plaintext"].as_str().unwrap_or(""))?)?;
            json!({ "key": key, "message": message })
        }
        "group.decrypt" => {
            let (state, plaintext) = group::group_decrypt(&field(req, "state")?, &req["message"])?;
            json!({ "state": state, "plaintext": b64u(&plaintext) })
        }
        // history transfer
        "history.seal" => {
            let size = req["chunkSize"].as_u64().map(|n| n as usize).unwrap_or(history::CHUNK_SIZE);
            let (offer, chunks) = history::seal_history(&req["items"], size, req["note"].as_str())?;
            json!({ "offer": offer, "chunks": chunks })
        }
        "history.open" => history::open_history(&req["offer"], &field::<Vec<String>>(req, "chunks")?)?,
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
