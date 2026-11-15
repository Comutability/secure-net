//! Version 1 sessions between two Rust devices.
use secure_net_core::bytes::b64u;
use secure_net_core::session::keys::*;
use secure_net_core::session::v1::{self, Me, State};
use serde_json::Value;

const NOW: i64 = 1_800_000_000_000;

struct Person {
    account: secure_net_core::signed::SigningKey,
    device: Device,
    list: Value,
    prekeys: Prekeys,
}

fn person() -> Person {
    let account = create_account();
    let device = create_device();
    let list = sign_device_list(&account, vec![device_public(&device)], 1, NOW).unwrap();
    let prekeys = create_prekeys(&device, 2, 2, NOW, 1).unwrap();
    Person { account, device, list, prekeys }
}

fn pair() -> (Person, Person, State, State) {
    let alice = person();
    let mut bob = person();
    let bundle = take_bundle(&bob.list, &mut bob.prekeys.published, &bob.device.kid.clone());
    let me = Me { device: &alice.device, device_list: &alice.list, prekeys: None };
    let a = v1::initiate(&me, &bundle, &bob.account.public_key, 0, NOW).unwrap();
    let (a, first) = v1::encrypt(&a, b"hello Bob").unwrap();
    let me = Me { device: &bob.device, device_list: &bob.list, prekeys: Some(&bob.prekeys.secrets) };
    let r = v1::respond(&me, &first, &alice.account.public_key, 0).unwrap();
    assert_eq!(r.plaintext, b"hello Bob");
    (alice, bob, a, r.state)
}

fn send(from: &mut State, to: &mut State, body: &str) -> Value {
    let (s, m) = v1::encrypt(from, body.as_bytes()).unwrap();
    *from = s;
    let (s, p) = v1::decrypt(to, &m).unwrap();
    *to = s;
    assert_eq!(p, body.as_bytes());
    m
}

#[test]
fn a_conversation_both_ways() {
    let (_, _, mut a, mut b) = pair();
    for i in 0..10 {
        let m = send(&mut b, &mut a, &format!("b{i}"));
        assert!(m.get("x").is_none());
        let m = send(&mut a, &mut b, &format!("a{i}"));
        assert!(m.get("x").is_none(), "the handshake stops once Bob has answered");
        assert!(m["h"]["ct"].is_string(), "every new chain answers the peer's ML-KEM key");
    }
}

#[test]
fn state_survives_json() {
    let (_, _, a, mut b) = pair();
    let mut a: State = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
    send(&mut b, &mut a, "after a save and load");
    send(&mut a, &mut b, "and back");
}

#[test]
fn late_messages_open_once() {
    let (_, _, mut a, mut b) = pair();
    let mut sent = vec![];
    for i in 0..4 {
        let (s, m) = v1::encrypt(&a, format!("a{i}").as_bytes()).unwrap();
        a = s;
        sent.push(m);
    }
    let (s, p) = v1::decrypt(&b, &sent[3]).unwrap();
    b = s;
    assert_eq!(p, b"a3");
    send(&mut b, &mut a, "reply");
    send(&mut a, &mut b, "new chain");
    for i in [1, 0, 2] {
        let (s, p) = v1::decrypt(&b, &sent[i]).unwrap();
        b = s;
        assert_eq!(p, format!("a{i}").as_bytes());
        assert!(v1::decrypt(&b, &sent[i]).is_err(), "only once");
    }
}

#[test]
fn refusals() {
    let (alice, bob, a, b) = pair();
    let (_, m) = v1::encrypt(&b, b"intact").unwrap();
    let mut bent = m.clone();
    let c = bent["c"].as_str().unwrap().to_string();
    let i = c.len() / 2;
    let flipped = format!("{}{}{}", &c[..i], if &c[i..i + 1] == "A" { "B" } else { "A" }, &c[i + 1..]);
    bent["c"] = Value::String(flipped);
    assert_eq!(v1::decrypt(&a, &bent).unwrap_err().code, "DECRYPT_FAILED");
    let mut stripped = m.clone();
    stripped["h"].as_object_mut().unwrap().remove("ct");
    assert_eq!(v1::decrypt(&a, &stripped).unwrap_err().code, "DOWNGRADE");
    let mut v2 = m.clone();
    v2["v"] = 2.into();
    assert_eq!(v1::decrypt(&a, &v2).unwrap_err().code, "BAD_MESSAGE");
    let (_, ok) = v1::decrypt(&a, &m).unwrap();
    assert_eq!(ok, b"intact", "a failure leaves the state as it was");

    // Too far ahead.
    let mut far = b.clone();
    let mut last = Value::Null;
    for _ in 0..=v1::MAX_SKIP + 1 {
        let (s, m) = v1::encrypt(&far, b"x").unwrap();
        far = s;
        last = m;
    }
    assert_eq!(v1::decrypt(&a, &last).unwrap_err().code, "TOO_FAR_AHEAD");

    // A first message answered with the wrong account key, or with a used one-time prekey.
    let carol = person();
    let mut bob2 = person();
    let bundle = take_bundle(&bob2.list, &mut bob2.prekeys.published, &bob2.device.kid.clone());
    let me = Me { device: &carol.device, device_list: &carol.list, prekeys: None };
    let (_, first) = v1::encrypt(&v1::initiate(&me, &bundle, &bob2.account.public_key, 0, NOW).unwrap(), b"hi").unwrap();
    let me = Me { device: &bob2.device, device_list: &bob2.list, prekeys: Some(&bob2.prekeys.secrets) };
    assert_eq!(v1::respond(&me, &first, &alice.account.public_key, 0).err().unwrap().code, "UNTRUSTED");
    let r = v1::respond(&me, &first, &carol.account.public_key, 0).unwrap();
    let me = Me { device: &bob2.device, device_list: &bob2.list, prekeys: Some(&r.prekeys) };
    assert_eq!(v1::respond(&me, &first, &carol.account.public_key, 0).err().unwrap().code, "UNKNOWN_PREKEY");
    let _ = (bob, b64u(&[]));
}

#[test]
fn bundles_must_chain_to_the_account() {
    let mut bob = person();
    let other = person();
    let bundle = take_bundle(&bob.list, &mut bob.prekeys.published, &bob.device.kid.clone());
    assert_eq!(verify_bundle(&bundle, &other.account.public_key, 0, NOW).unwrap_err().code, "UNTRUSTED");
    assert_eq!(verify_bundle(&bundle, &bob.account.public_key, 2, NOW).unwrap_err().code, "ROLLBACK");
    assert_eq!(verify_bundle(&bundle, &bob.account.public_key, 0, NOW + SIGNED_PREKEY_LIFETIME + 1).unwrap_err().code, "EXPIRED");
    let mut forged = bundle.clone();
    forged["signed"]["body"]["pub"] = forged["oneTime"]["body"]["pub"].clone();
    assert_eq!(verify_bundle(&forged, &bob.account.public_key, 0, NOW).unwrap_err().code, "UNTRUSTED");
    assert!(verify_bundle(&bundle, &bob.account.public_key, 0, NOW).is_ok());
}

#[test]
fn a_replayed_message_is_named_a_replay() {
    let (_, _, mut a, mut b) = pair();
    let m = send(&mut a, &mut b, "once");
    assert_eq!(v1::decrypt(&b, &m).unwrap_err().code, "REPLAY");
}

#[test]
fn one_time_prekeys_are_used_up() {
    let alice = person();
    let mut bob = person();
    // No ML-KEM one-time prekeys left: the bundle has the last-resort one and an X25519 one-time prekey.
    bob.prekeys.published.pq_one_time.clear();
    let bundle = take_bundle(&bob.list, &mut bob.prekeys.published, &bob.device.kid.clone());
    let one_time = bundle["oneTime"]["body"]["id"].as_str().unwrap().to_string();
    let last_resort = bundle["pq"]["body"]["id"].as_str().unwrap().to_string();
    let me = Me { device: &alice.device, device_list: &alice.list, prekeys: None };
    let (_, first) = v1::encrypt(&v1::initiate(&me, &bundle, &bob.account.public_key, 0, NOW).unwrap(), b"hi").unwrap();
    let me = Me { device: &bob.device, device_list: &bob.list, prekeys: Some(&bob.prekeys.secrets) };
    let r = v1::respond(&me, &first, &alice.account.public_key, 0).unwrap();
    assert!(!r.prekeys.contains_key(&one_time), "the one-time prekey is gone");
    assert!(r.prekeys.contains_key(&last_resort), "the last-resort prekey stays");
    let me = Me { device: &bob.device, device_list: &bob.list, prekeys: Some(&r.prekeys) };
    assert_eq!(v1::respond(&me, &first, &alice.account.public_key, 0).err().unwrap().code, "UNKNOWN_PREKEY");
}

#[test]
fn a_device_list_must_name_the_account_that_signed_it() {
    let bob = person();
    let carol = person();
    let list = secure_net_core::signed::sign(DEVICE_LIST, &serde_json::json!({ "account": carol.account.public_key, "devices": [device_public(&bob.device)], "seq": 1, "issued": NOW }), &bob.account).unwrap();
    assert_eq!(verify_device_list(&list, &bob.account.public_key, 0).unwrap_err().code, "UNTRUSTED");
    assert_eq!(verify_device_list(&list, &carol.account.public_key, 0).unwrap_err().code, "UNTRUSTED");
}
