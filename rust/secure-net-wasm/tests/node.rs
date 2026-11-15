//! The WebAssembly build, run under Node.js through the same `call` function JavaScript uses:
//!   cargo test --target wasm32-unknown-unknown -p secure-net-wasm
//! (with `wasm-bindgen-test-runner` as the wasm32 runner; CI sets it up). Natively, `cargo test`
//! runs the same tests against the same function.
use secure_net_wasm::{call, version};
use serde_json::{json, Value};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

const NOW: i64 = 1_800_000_000_000;

fn ok(req: Value) -> Value {
    let mut req = req;
    req["now"] = json!(NOW);
    let out: Value = serde_json::from_str(&call(&req.to_string())).unwrap();
    assert!(out.get("error").is_none(), "{}: {}", req["op"], out["error"]);
    out["ok"].clone()
}
fn code(req: Value) -> String {
    let out: Value = serde_json::from_str(&call(&req.to_string())).unwrap();
    out["error"]["code"].as_str().unwrap_or("").to_string()
}
fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}
fn unb64(s: &Value) -> String {
    use base64::Engine;
    String::from_utf8(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.as_str().unwrap()).unwrap()).unwrap()
}

struct Person {
    account: Value,
    device: Value,
    list: Value,
}
fn person() -> Person {
    let account = ok(json!({ "op": "createAccount" }));
    let device = ok(json!({ "op": "createDevice" }));
    let public = json!({ "kid": device["kid"], "sign": device["sign"]["publicKey"], "dh": device["dh"]["pk"] });
    let list = ok(json!({ "op": "signDeviceList", "account": account, "devices": [public], "seq": 1 }));
    Person { account, device, list }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn the_build_reports_the_release() {
    assert_eq!(version(), secure_net_core::wire::features::SECURE_NET_VERSION);
    assert_eq!(ok(json!({ "op": "canonical", "value": { "b": 1, "a": [true, null] } })), json!("{\"a\":[true,null],\"b\":1}"));
    assert_eq!(code(json!({ "op": "no.such.thing" })), "BAD_INPUT");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_version_2_session_runs_both_ways_and_refuses_a_replay() {
    let (alice, bob) = (person(), person());
    let prekeys = ok(json!({ "op": "createPrekeys", "device": bob.device, "oneTime": 2, "pqOneTime": 2, "sessions": 2 }));
    let taken = ok(json!({ "op": "takeBundle", "deviceList": bob.list, "published": prekeys["published"], "device": bob.device["kid"] }));
    let a = ok(json!({ "op": "initiate", "me": { "device": alice.device, "deviceList": alice.list }, "bundle": taken["bundle"], "accountKey": bob.account["publicKey"] }));
    let first = ok(json!({ "op": "encrypt", "state": a, "plaintext": b64("hello Bob") }));
    let me = json!({ "device": bob.device, "deviceList": bob.list, "prekeys": prekeys["secrets"] });
    let r = ok(json!({ "op": "respond", "me": me, "message": first["message"], "accountKey": alice.account["publicKey"] }));
    assert_eq!(unb64(&r["plaintext"]), "hello Bob");
    let reply = ok(json!({ "op": "encrypt", "state": r["state"], "plaintext": b64("hello Alice") }));
    let got = ok(json!({ "op": "decrypt", "state": first["state"], "message": reply["message"] }));
    assert_eq!(unb64(&got["plaintext"]), "hello Alice");
    assert_ne!(code(json!({ "op": "decrypt", "state": got["state"], "message": reply["message"], "now": NOW })), "");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn an_mls_group_forms_talks_and_locks_out_a_removed_member() {
    let people: Vec<Person> = (0..3).map(|_| person()).collect();
    let mut actors = serde_json::Map::new();
    let mut ids = Vec::new();
    for (i, p) in people.iter().enumerate() {
        let record = ok(json!({ "op": "social.createActor", "account": p.account, "params": { "handle": format!("p{i}@a.example"), "devices": p.list, "seq": 1, "now": NOW } }));
        let body = ok(json!({ "op": "social.verifyActor", "record": record }));
        ids.push(body["id"].as_str().unwrap().to_string());
        actors.insert(ids[i].clone(), body);
    }
    let actors = Value::Object(actors);
    let kps: Vec<Value> = people.iter().zip(&ids).map(|(p, id)| ok(json!({ "op": "groups.createKeyPackage", "device": p.device, "actor": id }))).collect();
    let a = ok(json!({ "op": "groups.createGroup", "keyPackage": kps[0]["secret"] }));
    let added = ok(json!({ "op": "groups.addMembers", "state": a, "keyPackages": [kps[1]["published"], kps[2]["published"]], "actors": actors }));
    let b = ok(json!({ "op": "groups.join", "welcome": added["welcome"], "keyPackage": kps[1]["secret"], "actors": actors }));
    let c = ok(json!({ "op": "groups.join", "welcome": added["welcome"], "keyPackage": kps[2]["secret"], "actors": actors }));
    let m = ok(json!({ "op": "groups.seal", "state": added["state"], "plaintext": "picnic on Saturday" }));
    for s in [&b, &c] {
        let r = ok(json!({ "op": "groups.open", "state": s, "message": m["message"], "actors": actors }));
        assert_eq!(unb64(&r["plaintext"]), "picnic on Saturday");
    }
    let out = ok(json!({ "op": "groups.removeMembers", "state": m["state"], "actorsOut": [ids[2]] }));
    let b2 = ok(json!({ "op": "groups.open", "state": b, "message": out["commit"], "actors": actors }));
    let later = ok(json!({ "op": "groups.seal", "state": b2["state"], "plaintext": "moved to Sunday" }));
    let r = ok(json!({ "op": "groups.open", "state": out["state"], "message": later["message"], "actors": actors }));
    assert_eq!(unb64(&r["plaintext"]), "moved to Sunday");
    assert_ne!(code(json!({ "op": "groups.open", "state": c, "message": later["message"], "actors": actors })), "");
}
