//! Group guards the scenario tests don't reach on their own: each test builds the one forgery a
//! single check exists to stop.
use secure_net_core::bytes::{b64u, from_b64u, sha256_b64u};
use secure_net_core::groups::mls as g;
use secure_net_core::session::keys::{create_account, create_device, device_public, sign_device_list, Device};
use secure_net_core::signed::sign;
use secure_net_core::social::actor::{actor_id_of, create_actor_document, verify_actor_document};
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use serde_json::{json, Map, Value};

const NOW: i64 = 1_800_000_000_000;

struct Person {
    device: Device,
    id: String,
    doc: Value,
}

fn person(name: &str) -> Person {
    let account = create_account();
    let device = create_device();
    let id = actor_id_of(&account.public_key).unwrap();
    let devices = sign_device_list(&account, vec![device_public(&device)], 1, NOW).unwrap();
    let record = create_actor_document(&account, &json!({ "handle": format!("{name}@a.example"), "type": "Person", "devices": devices, "seq": 1, "now": NOW })).unwrap();
    Person { doc: verify_actor_document(&record, Some(&id), None, 0).unwrap(), device, id }
}

fn directory(people: &[&Person]) -> Value {
    Value::Object(people.iter().map(|p| (p.id.clone(), p.doc.clone())).collect::<Map<_, _>>())
}

/// A credential, as its identity bytes (base64url), for an MLS key `key`.
fn credential(signer: &Device, actor: &str, device: &str, key: &[u8]) -> Value {
    sign(g::CREDENTIAL, &json!({ "actor": actor, "device": device, "key": sha256_b64u(key) }), &signer.sign).unwrap()
}

fn check(record: &Value, key: &[u8], actors: &Value) -> bool {
    g::validate_credential_json(&b64u(record.to_string().as_bytes()), &b64u(key), actors).unwrap()
}

#[test]
fn a_credential_is_checked_against_the_document_of_the_actor_it_names() {
    let (alice, mallory) = (person("alice"), person("mallory"));
    let key = [7u8; 64];
    // Mallory's own credential checks out against her own document...
    let hers = credential(&mallory.device, &mallory.id, &mallory.device.kid, &key);
    assert!(check(&hers, &key, &directory(&[&mallory])));
    // ...but one naming Alice, checked against a directory that (wrongly) files Mallory's
    // document under Alice's id, must not.
    let posing = credential(&mallory.device, &alice.id, &mallory.device.kid, &key);
    let muddled = json!({ alice.id.clone(): mallory.doc.clone() });
    assert!(!check(&posing, &key, &muddled));
}

#[test]
fn a_credential_must_be_signed_under_the_device_it_names() {
    let alice = person("alice");
    let key = [9u8; 64];
    let mut record = credential(&alice.device, &alice.id, &alice.device.kid, &key);
    assert!(check(&record, &key, &directory(&[&alice])));
    record["sig"]["kid"] = json!("someone-else");
    assert!(!check(&record, &key, &directory(&[&alice])));
}

struct Trio {
    alice: Person,
    bob: Person,
    carol: Person,
    a: Value,
    b: Value,
    c: Value,
}

fn trio() -> Trio {
    let (alice, bob, carol) = (person("alice"), person("bob"), person("carol"));
    let actors = directory(&[&alice, &bob, &carol]);
    let ka = g::create_key_package(&alice.device, &alice.id).unwrap();
    let kb = g::create_key_package(&bob.device, &bob.id).unwrap();
    let kc = g::create_key_package(&carol.device, &carol.id).unwrap();
    let a = g::create_group(None, &ka["secret"]).unwrap();
    let r = g::add_members(&a, &[kb["published"].clone(), kc["published"].clone()], &actors).unwrap();
    let w = r["welcome"].as_str().unwrap();
    let (b, c) = (g::join(w, &kb["secret"], &actors).unwrap(), g::join(w, &kc["secret"], &actors).unwrap());
    Trio { a: r["state"].clone(), b, c, alice, bob, carol }
}

#[test]
fn a_member_refuses_a_commit_adding_someone_it_cant_verify() {
    let t = trio();
    let dave = person("dave");
    let with_dave = directory(&[&t.alice, &t.bob, &t.carol, &dave]);
    let kp = g::create_key_package(&dave.device, &dave.id).unwrap();
    let r = g::add_members(&t.a, &[kp["published"].clone()], &with_dave).unwrap();
    let commit = r["commit"].as_str().unwrap();
    let without = directory(&[&t.alice, &t.bob, &t.carol]);
    let e = g::open(&t.b, commit, &without).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("DECRYPT_FAILED", "The group message couldn't be opened: a credential didn't verify"));
    assert_eq!(g::open(&t.b, commit, &with_dave).unwrap()["kind"], "commit");
}

#[test]
fn a_member_refuses_a_commit_whose_committer_leaf_it_cant_verify() {
    let t = trio();
    let r = g::refresh(&t.a).unwrap();
    let commit = r["commit"].as_str().unwrap();
    let no_alice = directory(&[&t.bob, &t.carol]);
    let e = g::open(&t.c, commit, &no_alice).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("DECRYPT_FAILED", "The group message couldn't be opened: a credential didn't verify"));
    assert_eq!(g::open(&t.c, commit, &directory(&[&t.alice, &t.bob, &t.carol])).unwrap()["kind"], "commit");
}

#[test]
fn wire_messages_with_bytes_after_them_are_refused() {
    let t = trio();
    let m = g::seal(&t.a, b"exact").unwrap();
    let mut bytes = from_b64u(m["message"].as_str().unwrap()).unwrap();
    bytes.push(0);
    let actors = directory(&[&t.alice, &t.bob, &t.carol]);
    assert_eq!(g::open(&t.b, &b64u(&bytes), &actors).unwrap_err().code, "BAD_MESSAGE");
    assert!(g::open(&t.b, m["message"].as_str().unwrap(), &actors).is_ok());
}

#[test]
fn the_committer_cant_be_replaced_and_non_committers_are_told_so_first() {
    let t = trio();
    let actors = directory(&[&t.alice, &t.bob, &t.carol]);
    let fresh = g::create_key_package(&t.alice.device, &t.alice.id).unwrap();
    let e = g::replace_member(&t.a, fresh["published"].as_str().unwrap(), &actors).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("BAD_INPUT", "The committer refreshes itself with refresh()"));
    // A non-committer is refused as such, before anything about the key packages is checked.
    let stranger = person("stranger");
    let unknown = g::create_key_package(&stranger.device, &stranger.id).unwrap();
    assert_eq!(g::add_members(&t.b, &[unknown["published"].clone()], &actors).unwrap_err().code, "NOT_ALLOWED");
    let _ = &t.c;
}

#[test]
fn a_welcome_passed_on_by_someone_other_than_its_committer_is_refused() {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("a.example").unwrap());
    let mut make = |h: &str| {
        let mut c = SocialClient::new(h, "Person", None, 2, true, NOW).unwrap();
        c.register(&mut net).unwrap();
        c.enable_groups(&mut net, 2).unwrap();
        c
    };
    let (mut alice, mut bob, mut carol) = (make("alice@a.example"), make("bob@a.example"), make("carol@a.example"));
    alice.lookup(&mut net, "carol@a.example").unwrap();
    bob.lookup(&mut net, "carol@a.example").unwrap();
    // Alice makes a group and a welcome for Carol, but it reaches Carol from Bob.
    let group = alice.create_group().unwrap();
    let actors = Value::Object(alice.known.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let kp = net.site("a.example").unwrap().key_package(&carol.id, &carol.device.kid).unwrap();
    let r = g::add_members(&alice.groups[&group], &[json!(kp)], &actors).unwrap();
    let docs = vec![alice.records[&alice.id].clone()];
    let cid = carol.id.clone();
    bob.send_direct(&mut net, &cid, &json!({ "groups": [{ "group": group, "welcome": r["welcome"], "actors": docs }] })).unwrap();
    let shown = carol.sync(&mut net).unwrap();
    assert_eq!(shown.iter().map(|s| s["reason"].clone()).collect::<Vec<_>>(), vec![json!("UNTRUSTED")], "{shown:?}");
    assert!(!carol.groups.contains_key(&group));
}

#[test]
fn a_credential_from_a_classical_only_device_is_refused() {
    // An actor whose device list holds an Ed25519-only device (no ML-DSA): its credentials don't
    // count, even correctly signed.
    let account = create_account();
    let mut device = create_device();
    device.sign = secure_net_core::signed::SigningKey::generate(false);
    device.kid = device.sign.kid.clone();
    let id = actor_id_of(&account.public_key).unwrap();
    let devices = sign_device_list(&account, vec![device_public(&device)], 1, NOW).unwrap();
    let record = create_actor_document(&account, &json!({ "handle": "old@a.example", "type": "Person", "devices": devices, "seq": 1, "now": NOW })).unwrap();
    let doc = verify_actor_document(&record, Some(&id), None, 0).unwrap();
    let key = [3u8; 64];
    let cred = credential(&device, &id, &device.kid, &key);
    assert!(!check(&cred, &key, &json!({ id.clone(): doc })));
}
