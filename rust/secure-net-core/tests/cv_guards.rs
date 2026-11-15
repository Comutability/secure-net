//! Each refusal in the Commonveil port, exercised directly. Removing any guard must make one of
//! these fail (checked by mutation: see rust/README.md).
use secure_net_core::cv::encoding::to_b64;
use secure_net_core::cv::envelope::{decrypt_envelope, encrypt_envelope, validate_envelope};
use secure_net_core::cv::identity::{anchor_chain, make_account_statement, make_device_cert, verify_account_chain, verify_device_cert};
use secure_net_core::cv::kem::{decapsulate, kem_keygen, KEM_CIPHERTEXT_BYTES};
use secure_net_core::cv::keyring::{create_key_version, device_transfer_context, new_keyring, open_keyring_from_device, seal_to_recipient, with_version, OpenFromDevice};
use secure_net_core::cv::primitives::{generate_pair, public_from_raw};
use secure_net_core::cv::server_keys::{encrypt_server_item, decrypt_server_item, make_grant, open_grant, ChainKeys, GrantArgs};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn ring(user: &str) -> Value {
    new_keyring(user, create_key_version(1, NOW).unwrap()).unwrap()
}

fn scope() -> Value {
    json!({ "kind": "message", "conversation_id": "c1", "item_id": "i1", "sender_id": "u1", "device_id": "d1" })
}

#[test]
fn envelope_shapes_are_refused() {
    let r = ring("u1");
    let v = &r["versions"][0];
    let classical = json!({ "user_id": "u1", "key_version": 1, "ecdh_pub": v["ecdh_pub"] });
    let pq = json!({ "user_id": "u2", "key_version": 1, "ecdh_pub": v["ecdh_pub"], "kem_pub": v["kem_pub"] });
    let env = encrypt_envelope(&scope(), &[classical.clone(), pq], &json!({"t": 1})).unwrap();
    assert!(validate_envelope(&env).is_ok());

    // A post-quantum wrap in a version 2 envelope.
    let mut v2 = env.clone();
    v2["v"] = json!(2);
    assert_eq!(validate_envelope(&v2).unwrap_err().code, "BAD_ENVELOPE");
    // A wrap claiming to be both kinds.
    let mut both = env.clone();
    both["wraps"][1]["epk"] = env["wraps"][0]["epk"].clone();
    assert_eq!(validate_envelope(&both).unwrap_err().code, "BAD_ENVELOPE");
    // The same account twice.
    let mut dup = env.clone();
    dup["wraps"][1]["u"] = json!("u1");
    assert_eq!(validate_envelope(&dup).unwrap_err().code, "BAD_ENVELOPE");
    assert_eq!(decrypt_envelope(&scope(), &env, "u1", &r).unwrap(), json!({"t": 1}));
}

#[test]
fn reset_accounts_and_foreign_certificates_are_refused() {
    let v1 = create_key_version(1, NOW).unwrap();
    let v2 = create_key_version(2, NOW).unwrap();
    let s1 = make_account_statement("u1", &v1, &v1["ecdh_pub"].as_str().unwrap().to_string(), "", &v1, NOW).unwrap();
    // Version 2 signs itself: an account reset from another device.
    let s2 = make_account_statement("u1", &v2, v1["ecdh_pub"].as_str().unwrap(), "", &v2, NOW).unwrap();
    let chain = verify_account_chain("u1", &[s1.clone(), s2]).unwrap();
    assert_eq!(chain.root_version, 2);
    let old_ring = new_keyring("u1", v1.clone()).unwrap();
    assert_eq!(anchor_chain(&chain, Some(&old_ring), None).unwrap_err().code, "ACCOUNT_RESET");

    let chain1 = verify_account_chain("u1", &[s1]).unwrap();
    let (_, box_pub) = generate_pair().unwrap();
    let (_, sign_pub) = generate_pair().unwrap();
    let device = json!({ "device_id": "d1", "sign_pub": sign_pub, "box_pub": box_pub });
    let mine = make_device_cert("u1", &device, &v1, "", NOW).unwrap();
    assert!(verify_device_cert(&mine, &chain1));
    let theirs = make_device_cert("u2", &device, &v1, "", NOW).unwrap();
    assert!(!verify_device_cert(&theirs, &chain1));
}

#[test]
fn a_keyring_must_be_the_version_it_was_sent_as() {
    let r = ring("u1");
    let (box_priv, box_pub) = generate_pair().unwrap();
    // Sealed in the context for version 2, but the keyring inside only reaches version 1.
    let text = serde_json::to_string(&r).unwrap();
    let sealed = seal_to_recipient(&box_pub, None, text.as_bytes(), &device_transfer_context("u1", "d1", 2)).unwrap();
    let e = open_keyring_from_device(OpenFromDevice { box_priv: &box_priv, box_pub: &box_pub, kem_priv: None, user_id: "u1", device_id: "d1", keyring_version: 2, sealed: &sealed }).unwrap_err();
    assert_eq!(e.message, "Keyring version mismatch");
    let r2 = with_version(&r, create_key_version(2, NOW).unwrap()).unwrap();
    let ok = seal_to_recipient(&box_pub, None, serde_json::to_string(&r2).unwrap().as_bytes(), &device_transfer_context("u1", "d1", 2)).unwrap();
    assert_eq!(open_keyring_from_device(OpenFromDevice { box_priv: &box_priv, box_pub: &box_pub, kem_priv: None, user_id: "u1", device_id: "d1", keyring_version: 2, sealed: &ok }).unwrap(), r2);
}

#[test]
fn server_items_and_grants_are_bound() {
    let key = [4u8; 32];
    let scope = json!({"kind":"message","server_id":"s1","channel_id":"","item_id":"i1","sender_id":"u1","device_id":"d1","chain_id":"s1.h","generation":0,"step":0});
    let base = json!({"kind":"message","server_id":"s1","channel_id":"","item_id":"i1","sender_id":"u1","device_id":"d1"});
    let env = encrypt_server_item(&scope, &key, &json!({"x": 1})).unwrap();
    let mut keys = ChainKeys::new();
    keys.add("s1.h", 0, 0, &key);
    assert_eq!(decrypt_server_item(&base, &env, &mut keys).unwrap()["payload"], json!({"x": 1}));
    // A commitment to some other key: refused even though the ciphertext itself is fine.
    let mut wrong = env.clone();
    wrong["kc"] = json!(to_b64(&[0u8; 32]));
    let e = decrypt_server_item(&base, &wrong, &mut keys).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("DECRYPT_FAILED", "This item's key doesn't match its commitment."));

    let mut later = ChainKeys::new();
    later.add("s1.l", 0, 2, &key);
    let e = later.get("s1.l", 0, 1).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("BEFORE_KEY", "That's from before you could read here."));

    let r = ring("u2");
    let v = &r["versions"][0];
    let (sign_priv, _) = generate_pair().unwrap();
    let device = json!({ "device_id": "d1", "sign_priv": sign_priv });
    let recipient = json!({ "user_id": "u2", "key_version": 1, "ecdh_pub": v["ecdh_pub"], "kem_pub": v["kem_pub"] });
    let g = make_grant(GrantArgs { server_id: "s1", chain_id: "s1.h", generation: 0, step: 0, key: &key, recipient: &recipient, user_id: "u1", device: &device, now: NOW }).unwrap();
    assert_eq!(&open_grant(&g, "u2", &r).unwrap()[..], &key);
    assert_eq!(open_grant(&g, "u3", &r).unwrap_err().code, "NOT_YOURS");
}

#[test]
fn malformed_points_are_refused() {
    let keys = kem_keygen(None).unwrap();
    let seed = secure_net_core::cv::encoding::from_b64(keys["kem_priv"].as_str().unwrap()).unwrap();
    let mut ct = vec![0u8; KEM_CIPHERTEXT_BYTES];
    ct[1088] = 4;
    ct[1089..].fill(1);
    assert!(decapsulate(&ct, &seed).is_err());

    let (_, pub_b64) = generate_pair().unwrap();
    let mut raw = secure_net_core::cv::encoding::from_b64(&pub_b64).unwrap();
    assert!(public_from_raw(&raw).is_ok());
    // The SEC 1 "hybrid" forms (0x06, 0x07) carry the same point but WebCrypto refuses them.
    for prefix in [6u8, 7u8] {
        raw[0] = prefix;
        assert!(public_from_raw(&raw).is_err());
    }
}
