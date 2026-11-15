//! Version 2 sessions and sender keys between Rust devices: each refusal exercised directly.
use secure_net_core::bytes::b64u;
use secure_net_core::session::group::{accept_distribution, create_sender_key, distribution, group_decrypt, group_encrypt};
use secure_net_core::session::keys::*;
use secure_net_core::session::primitives::dh_key_pair;
use secure_net_core::session::v2::{self, Me, State};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn pair() -> (State, State) {
    let account_a = create_account();
    let device_a = create_device();
    let list_a = sign_device_list(&account_a, vec![device_public(&device_a)], 1, NOW).unwrap();
    let account_b = create_account();
    let device_b = create_device();
    let list_b = sign_device_list(&account_b, vec![device_public(&device_b)], 1, NOW).unwrap();
    let mut prekeys = create_prekeys(&device_b, 2, 2, NOW, 2).unwrap();
    let bundle = take_bundle(&list_b, &mut prekeys.published, &device_b.kid.clone());
    let a = v2::initiate(&Me { device: &device_a, device_list: &list_a, prekeys: None }, &bundle, &account_b.public_key, 0, NOW).unwrap();
    let (a, first) = v2::encrypt(&a, b"hello").unwrap();
    let r = v2::respond(&Me { device: &device_b, device_list: &list_b, prekeys: Some(&prekeys.secrets) }, &first, &account_a.public_key, 0, NOW).unwrap();
    (a, r.state)
}

fn send(from: &mut State, to: &mut State, body: &str) -> Value {
    let (s, m) = v2::encrypt(from, body.as_bytes()).unwrap();
    *from = s;
    let (s, p) = v2::decrypt(to, &m, NOW).unwrap();
    *to = s;
    assert_eq!(p, body.as_bytes());
    m
}

#[test]
fn the_handshake_stops_once_answered() {
    let (mut a, mut b) = pair();
    assert!(a.pending.is_some());
    send(&mut b, &mut a, "reply");
    assert!(a.pending.is_none());
    let m = send(&mut a, &mut b, "after");
    assert!(m.get("x").is_none());
}

#[test]
fn a_message_from_an_old_chain_is_a_replay() {
    let (mut a, mut b) = pair();
    let (a1, m0) = v2::encrypt(&a, b"0").unwrap();
    let (a2, _m1) = v2::encrypt(&a1, b"1").unwrap();
    let (a3, m2) = v2::encrypt(&a2, b"2").unwrap();
    a = a3;
    let (b1, _) = v2::decrypt(&b, &m0, NOW).unwrap();
    let (b2, _) = v2::decrypt(&b1, &m2, NOW).unwrap(); // leaves a key waiting for message 1
    b = b2;
    send(&mut b, &mut a, "turn");
    send(&mut a, &mut b, "new chain");
    assert_eq!(v2::decrypt(&b, &m0, NOW).unwrap_err().code, "REPLAY");
}

#[test]
fn a_header_must_carry_the_chain_key() {
    let (mut a, mut b) = pair();
    send(&mut a, &mut b, "first");
    let mut forged = a.clone();
    forged.dhs.as_mut().unwrap().pk = dh_key_pair().pk;
    let (_, m) = v2::encrypt(&forged, b"same chain, other key").unwrap();
    assert_eq!(v2::decrypt(&b, &m, NOW).unwrap_err().code, "BAD_MESSAGE");
}

#[test]
fn too_far_ahead_is_refused() {
    let (mut a, mut b) = pair();
    send(&mut a, &mut b, "first");
    let mut m = Value::Null;
    for _ in 0..1002 {
        let (s, next) = v2::encrypt(&a, b"x").unwrap();
        a = s;
        m = next;
    }
    assert_eq!(v2::decrypt(&b, &m, NOW).unwrap_err().code, "TOO_FAR_AHEAD");
}

#[test]
fn key_pieces_must_be_the_right_size() {
    let (mut a, b) = pair();
    assert_eq!(a.pq.role, "ek");
    a.pq.out.as_mut().unwrap()[0] = b64u(&[1, 2, 3]);
    a.pq.i = 0;
    let (_, m) = v2::encrypt(&a, b"bad piece").unwrap();
    assert_eq!(v2::decrypt(&b, &m, NOW).unwrap_err().code, "BAD_MESSAGE");
}

#[test]
fn the_ml_kem_exchange_must_be_in_step() {
    let (mut a, mut b) = pair();
    // Bob claims to have mixed in a secret for an epoch where Alice, not Bob, sent the ciphertext.
    send(&mut a, &mut b, "1");
    send(&mut b, &mut a, "2");
    send(&mut a, &mut b, "3");
    send(&mut b, &mut a, "4");
    let (a2, m) = v2::encrypt(&a, b"5").unwrap();
    let (mut b2, _) = v2::decrypt(&b, &m, NOW).unwrap();
    b2.pe = Some(if a2.pq.role == "ct" { a2.pq.e + 1 } else { a2.pq.e });
    let (_, lie) = v2::encrypt(&b2, b"lie").unwrap();
    assert_eq!(v2::decrypt(&a2, &lie, NOW).unwrap_err().code, "BAD_MESSAGE");
}

#[test]
fn sender_keys_refuse_gaps_too_large() {
    let mut key = create_sender_key("g");
    let state = accept_distribution(&distribution(&key), json!("dev")).unwrap();
    key.n = 1001;
    let (_, m) = group_encrypt(&key, b"far").unwrap();
    assert_eq!(group_decrypt(&state, &m).unwrap_err().code, "TOO_FAR_AHEAD");
    let (_, m) = group_encrypt(&create_sender_key("g"), b"other").unwrap();
    assert_eq!(group_decrypt(&state, &m).unwrap_err().code, "BAD_MESSAGE");
}
