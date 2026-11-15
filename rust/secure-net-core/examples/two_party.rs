//! A runnable walk through CVP-016: Alice (one device) and Bob (two devices) talk through a relay
//! that keeps a copy of everything it carries. Then Bob shares a group key with Alice, and moves
//! his history to a new device. At the end the relay's copy is searched for every plaintext.
//!
//!   cargo run --example two_party
use std::collections::HashMap;

use secure_net_core::session::group::{accept_distribution, create_sender_key, distribution, group_decrypt, group_encrypt};
use secure_net_core::session::history::{open_history, seal_history};
use secure_net_core::session::keys::{create_account, create_device, create_prekeys, device_public, safety_number, sign_device_list, take_bundle, verify_device_list, Device, Published};
use secure_net_core::session::v2;
use secure_net_core::signed::SigningKey;
use serde_json::{json, Map, Value};

const NOW: i64 = 1_800_000_000_000;

/// The relay: hands out prekey bundles and passes messages on. It is trusted with nothing.
#[derive(Default)]
struct Relay {
    seen: Vec<String>,
    bundles: HashMap<String, (Value, Published)>,
    inbox: HashMap<String, Vec<Value>>,
}
impl Relay {
    fn bundle(&mut self, kid: &str) -> Value {
        let (list, published) = self.bundles.get_mut(kid).expect("published");
        take_bundle(list, published, kid)
    }
    fn send(&mut self, to: &str, payload: Value) {
        self.seen.push(payload.to_string());
        self.inbox.entry(to.into()).or_default().push(payload);
    }
    fn receive(&mut self, kid: &str) -> Vec<Value> {
        self.inbox.remove(kid).unwrap_or_default()
    }
}

struct Person {
    name: &'static str,
    account: SigningKey,
    devices: Vec<Device>,
    list: Value,
    secrets: HashMap<String, Map<String, Value>>,
    sessions: HashMap<(String, String), v2::State>,
}

fn person(relay: &mut Relay, name: &'static str, devices: usize) -> Person {
    let account = create_account();
    let devices: Vec<Device> = (0..devices).map(|_| create_device()).collect();
    let list = sign_device_list(&account, devices.iter().map(device_public).collect(), 1, NOW).unwrap();
    let mut secrets = HashMap::new();
    for d in &devices {
        let p = create_prekeys(d, 5, 5, NOW, 2).unwrap();
        secrets.insert(d.kid.clone(), p.secrets);
        relay.bundles.insert(d.kid.clone(), (list.clone(), p.published));
    }
    Person { name, account, devices, list, secrets, sessions: HashMap::new() }
}

/// Send from one of `from`'s devices to every device of `to`, starting sessions where needed.
fn send(relay: &mut Relay, from: &mut Person, dev: usize, to: &Person, text: &str) {
    let d = from.devices[dev].clone();
    let list = verify_device_list(&to.list, &to.account.public_key, 0).unwrap();
    for target in list["devices"].as_array().unwrap() {
        let kid = target["kid"].as_str().unwrap().to_string();
        let key = (d.kid.clone(), kid.clone());
        let state = match from.sessions.remove(&key) {
            Some(s) => s,
            None => {
                let bundle = relay.bundle(&kid);
                let me = v2::Me { device: &d, device_list: &from.list, prekeys: None };
                v2::initiate(&me, &bundle, &to.account.public_key, 0, NOW).unwrap()
            }
        };
        let (state, message) = v2::encrypt(&state, text.as_bytes()).unwrap();
        from.sessions.insert(key, state);
        relay.send(&kid, json!({ "from": d.kid, "account": from.account.public_key, "message": message }));
    }
}

/// Read everything waiting for one device.
fn read(relay: &mut Relay, p: &mut Person, dev: usize, trusted: &str) -> Vec<String> {
    let d = p.devices[dev].clone();
    let mut out = Vec::new();
    for m in relay.receive(&d.kid) {
        assert_eq!(m["account"], trusted, "a message from an account we haven't pinned");
        let key = (d.kid.clone(), m["from"].as_str().unwrap().to_string());
        let plaintext = match p.sessions.remove(&key) {
            Some(s) => {
                let (s, pt) = v2::decrypt(&s, &m["message"], NOW).unwrap();
                p.sessions.insert(key, s);
                pt
            }
            None => {
                let me = v2::Me { device: &d, device_list: &p.list, prekeys: p.secrets.get(&d.kid) };
                let r = v2::respond(&me, &m["message"], trusted, 0, NOW).unwrap();
                p.secrets.insert(d.kid.clone(), r.prekeys);
                p.sessions.insert(key, r.state);
                r.plaintext
            }
        };
        out.push(String::from_utf8(plaintext).unwrap());
    }
    out
}

fn main() {
    let mut relay = Relay::default();
    let mut alice = person(&mut relay, "Alice", 1);
    let mut bob = person(&mut relay, "Bob", 2);
    println!("Safety number Alice and Bob compare: {}", safety_number(&alice.account.public_key, &bob.account.public_key));
    let (ak, bk) = (alice.account.public_key.clone(), bob.account.public_key.clone());

    send(&mut relay, &mut alice, 0, &bob, "Hello Bob, this reaches both your devices.");
    for dev in 0..2 {
        for t in read(&mut relay, &mut bob, dev, &ak) {
            println!("{}'s device {dev} reads: {t}", bob.name);
        }
    }
    send(&mut relay, &mut bob, 1, &alice, "Hi Alice, from my laptop.");
    for t in read(&mut relay, &mut alice, 0, &bk) {
        println!("{} reads: {t}", alice.name);
    }

    // A group: Bob's phone makes a sender key and gives it to Alice inside their session.
    let key = create_sender_key("bob:family");
    send(&mut relay, &mut bob, 0, &alice, &distribution(&key).to_string());
    let dist: Value = serde_json::from_str(&read(&mut relay, &mut alice, 0, &bk)[0]).unwrap();
    let received = accept_distribution(&dist, json!(bob.devices[0].kid)).unwrap();
    let (_, m) = group_encrypt(&key, b"Dinner on Sunday?").unwrap();
    relay.send("group", m.clone());
    let (_, pt) = group_decrypt(&received, &m).unwrap();
    println!("Alice reads Bob's group message: {}", String::from_utf8(pt).unwrap());

    // A new phone: history sealed in chunks, the key sent over a session, chunks through the relay.
    let (offer, chunks) = seal_history(&json!([{ "from": "Alice", "text": "Hello Bob, this reaches both your devices." }]), 1024, Some("Bob's old phone")).unwrap();
    for c in &chunks {
        relay.send("new-phone", json!(c));
    }
    let restored = open_history(&offer, &chunks).unwrap();
    println!("Bob's new phone restored {} message(s) of history", restored.as_array().map_or(0, Vec::len));

    let everything = relay.seen.join("\n");
    for secret in ["Hello Bob", "Hi Alice", "Dinner on Sunday"] {
        assert!(!everything.contains(secret), "the relay saw {secret}");
    }
    println!("The relay kept {} payloads; none contains any of the plaintexts.", relay.seen.len());
}
