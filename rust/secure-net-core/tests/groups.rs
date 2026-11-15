//! MLS groups (CVP-022) in Rust, mirroring the JavaScript's test/groups.test.mjs.
use secure_net_core::bytes::{b64u, from_b64u};
use secure_net_core::groups::mls as g;
use secure_net_core::session::keys::{create_account, create_device, device_public, sign_device_list, Device};
use secure_net_core::social::actor::{actor_id_of, create_actor_document, verify_actor_document};
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
    let record = create_actor_document(&account, &json!({ "handle": format!("{name}@a.example"), "type": "Person", "name": name, "devices": devices, "seq": 1, "now": NOW })).unwrap();
    let doc = verify_actor_document(&record, Some(&id), None, 0).unwrap();
    Person { device, id, doc }
}

fn directory(people: &[&Person]) -> Value {
    Value::Object(people.iter().map(|p| (p.id.clone(), p.doc.clone())).collect::<Map<_, _>>())
}

fn code<T>(r: secure_net_core::error::Result<T>) -> Option<&'static str> {
    r.err().map(|e| e.code)
}

struct Trio {
    alice: Person,
    bob: Person,
    carol: Person,
    actors: Value,
    s: std::collections::BTreeMap<&'static str, Value>,
}

fn trio() -> Trio {
    let (alice, bob, carol) = (person("alice"), person("bob"), person("carol"));
    let actors = directory(&[&alice, &bob, &carol]);
    let ka = g::create_key_package(&alice.device, &alice.id).unwrap();
    let kb = g::create_key_package(&bob.device, &bob.id).unwrap();
    let kc = g::create_key_package(&carol.device, &carol.id).unwrap();
    let a = g::create_group(None, &ka["secret"]).unwrap();
    let added = g::add_members(&a, &[kb["published"].clone(), kc["published"].clone()], &actors).unwrap();
    let w = added["welcome"].as_str().unwrap();
    let b = g::join(w, &kb["secret"], &actors).unwrap();
    let c = g::join(w, &kc["secret"], &actors).unwrap();
    let s = [("a", added["state"].clone()), ("b", b), ("c", c)].into_iter().collect();
    Trio { alice, bob, carol, actors, s }
}

fn say(t: &mut Trio, from: &'static str, body: &str) -> String {
    let m = g::seal(&t.s[from], body.as_bytes()).unwrap();
    t.s.insert(from, m["state"].clone());
    let keys: Vec<&'static str> = t.s.keys().copied().filter(|k| *k != from).collect();
    for k in keys {
        let r = g::open(&t.s[k], m["message"].as_str().unwrap(), &t.actors).unwrap();
        assert_eq!(from_b64u(r["plaintext"].as_str().unwrap()).unwrap(), body.as_bytes(), "{k} reads {from}");
        t.s.insert(k, r["state"].clone());
    }
    m["message"].as_str().unwrap().to_string()
}

fn apply(t: &mut Trio, change: &Value, who: &[&'static str]) {
    for k in who {
        let r = g::open(&t.s[k], change["commit"].as_str().unwrap(), &t.actors).unwrap();
        assert_eq!(r["kind"], "commit");
        t.s.insert(k, r["state"].clone());
    }
}

#[test]
fn three_devices_agree_a_group_and_everyone_can_write_to_everyone() {
    let mut t = trio();
    let d = g::describe(&t.s["b"]).unwrap();
    assert!(d["group"].as_str().unwrap().starts_with("group:"));
    let mut got: Vec<String> = d["members"].as_array().unwrap().iter().map(|m| m["actor"].as_str().unwrap().to_string()).collect();
    let mut want = vec![t.alice.id.clone(), t.bob.id.clone(), t.carol.id.clone()];
    got.sort();
    want.sort();
    assert_eq!(got, want);
    assert_eq!(g::describe(&t.s["a"]).unwrap()["epoch"], g::describe(&t.s["c"]).unwrap()["epoch"]);
    assert_eq!(g::describe(&t.s["a"]).unwrap()["leaf"], 0);
    let wire = say(&mut t, "a", "hello from the committer");
    say(&mut t, "b", "hello from Bob");
    say(&mut t, "c", "hello from Carol");
    let raw = from_b64u(&wire).unwrap();
    assert!(!raw.windows(8).any(|w| w == b"hello fr"), "a site carrying it sees only ciphertext");
}

#[test]
fn a_removed_member_is_locked_out_by_one_commit_for_everyone() {
    let mut t = trio();
    say(&mut t, "c", "before");
    let kept = t.s["c"].clone();
    let carol = t.carol.id.clone();
    let change = g::remove_members(&t.s["a"], &|m| m["actor"] == carol.as_str()).unwrap();
    t.s.insert("a", change["state"].clone());
    apply(&mut t, &change, &["b"]);
    let r = g::open(&kept, change["commit"].as_str().unwrap(), &t.actors).unwrap();
    assert_eq!(r["removed"], true, "she learns she was removed");
    let hers = r["state"].clone();
    t.s.remove("c");
    let after = say(&mut t, "b", "Carol can't read this");
    assert!(code(g::open(&kept, &after, &t.actors)).is_some(), "her old state doesn't open it");
    assert!(code(g::open(&hers, &after, &t.actors)).is_some(), "nor after the commit that removed her");
    assert_eq!(g::describe(&t.s["a"]).unwrap()["members"].as_array().unwrap().len(), 2);
}

#[test]
fn someone_who_copied_a_members_state_is_locked_out_when_that_member_gets_fresh_keys() {
    let mut t = trio();
    say(&mut t, "b", "before the theft");
    let stolen = t.s["b"].clone();
    let fresh = g::create_key_package(&t.bob.device, &t.bob.id).unwrap();
    let change = g::replace_member(&t.s["a"], fresh["published"].as_str().unwrap(), &t.actors).unwrap();
    t.s.insert("a", change["state"].clone());
    apply(&mut t, &change, &["c"]);
    t.s.insert("b", g::join(change["welcome"].as_str().unwrap(), &fresh["secret"], &t.actors).unwrap());
    let m = say(&mut t, "c", "after the repair");
    let thief = g::open(&stolen, change["commit"].as_str().unwrap(), &t.actors).map(|r| r["state"].clone()).unwrap_or(stolen);
    assert!(code(g::open(&thief, &m, &t.actors)).is_some());
}

#[test]
fn someone_who_copied_the_committers_state_is_locked_out_by_a_refresh() {
    let mut t = trio();
    let stolen = t.s["a"].clone();
    let change = g::refresh(&t.s["a"]).unwrap();
    t.s.insert("a", change["state"].clone());
    apply(&mut t, &change, &["b", "c"]);
    let m = say(&mut t, "b", "after the refresh");
    assert!(code(g::open(&stolen, change["commit"].as_str().unwrap(), &t.actors)).is_some(), "the copy can't open the commit made from its own leaf");
    assert!(code(g::open(&stolen, &m, &t.actors)).is_some());
}

#[test]
fn a_newcomer_cant_read_what_was_said_before_they_joined() {
    let mut t = trio();
    let earlier = say(&mut t, "b", "before Dave");
    let dave = person("dave");
    let actors = directory(&[&t.alice, &t.bob, &t.carol, &dave]);
    t.actors = actors;
    let kp = g::create_key_package(&dave.device, &dave.id).unwrap();
    let change = g::add_members(&t.s["a"], &[kp["published"].clone()], &t.actors).unwrap();
    t.s.insert("a", change["state"].clone());
    apply(&mut t, &change, &["b", "c"]);
    t.s.insert("d", g::join(change["welcome"].as_str().unwrap(), &kp["secret"], &t.actors).unwrap());
    assert!(code(g::open(&t.s["d"], &earlier, &t.actors)).is_some());
    say(&mut t, "d", "hello, I'm new");
}

#[test]
fn only_the_committer_changes_the_group() {
    let t = trio();
    assert!(g::is_committer(&t.s["a"]).unwrap());
    assert!(!g::is_committer(&t.s["b"]).unwrap());
    let carol = t.carol.id.clone();
    assert_eq!(code(g::remove_members(&t.s["b"], &|m| m["actor"] == carol.as_str())), Some("NOT_ALLOWED"));
    assert_eq!(code(g::refresh(&t.s["c"])), Some("NOT_ALLOWED"));
    let kp = g::create_key_package(&t.carol.device, &t.carol.id).unwrap();
    assert_eq!(code(g::add_members(&t.s["b"], &[kp["published"].clone()], &t.actors)), Some("NOT_ALLOWED"));
    assert_eq!(code(g::remove_members(&t.s["a"], &|m| m["leaf"] == 0)), Some("BAD_INPUT"), "the committer can't remove itself");
}

#[test]
fn a_key_package_is_accepted_only_if_a_listed_device_of_that_actor_signed_its_credential() {
    let t = trio();
    let stranger = person("stranger");
    let unknown = g::create_key_package(&stranger.device, &stranger.id).unwrap();
    assert!(code(g::add_members(&t.s["a"], &[unknown["published"].clone()], &t.actors)).is_some(), "an actor we hold no document for");
    let erin = person("erin");
    let actors = directory(&[&t.alice, &t.bob, &t.carol, &erin]);
    let forged = g::create_key_package(&create_device(), &erin.id).unwrap();
    assert!(code(g::add_members(&t.s["a"], &[forged["published"].clone()], &actors)).is_some(), "a device that isn't on Erin's list");
    let real = g::create_key_package(&erin.device, &erin.id).unwrap();
    assert_eq!(g::key_package_owner(real["published"].as_str().unwrap()).unwrap(), json!({ "actor": erin.id, "device": erin.device.kid }));
    let ok = g::add_members(&t.s["a"], &[real["published"].clone()], &actors).unwrap();
    assert_eq!(g::describe(&ok["state"]).unwrap()["members"].as_array().unwrap().len(), 4);
    // A joiner refuses a group with a member it can't verify.
    let missing_erin = t.actors.clone();
    assert_eq!(code(g::join(ok["welcome"].as_str().unwrap(), &real["secret"], &missing_erin)), Some("UNTRUSTED"));
    assert!(g::join(ok["welcome"].as_str().unwrap(), &real["secret"], &actors).is_ok());
}

#[test]
fn the_credential_must_name_the_mls_key_it_travels_with() {
    let erin = person("erin2");
    let actors = directory(&[&erin]);
    let real = g::create_key_package(&erin.device, &erin.id).unwrap();
    // Take the identity and key out of the key package the JavaScript way: via the owner helper's
    // inputs. The credential is the canonical JSON of the record.
    let other = g::create_key_package(&erin.device, &erin.id).unwrap();
    let (cred, key) = leaf_of(real["published"].as_str().unwrap());
    let (_, other_key) = leaf_of(other["published"].as_str().unwrap());
    assert!(g::validate_credential_json(&cred, &key, &actors).unwrap());
    assert!(!g::validate_credential_json(&cred, &other_key, &actors).unwrap());
    assert!(!g::validate_credential_json(&b64u(b"erin"), &key, &actors).unwrap());
    let mut record: Value = serde_json::from_slice(&from_b64u(&cred).unwrap()).unwrap();
    record["body"]["key"] = json!(secure_net_core::bytes::sha256_b64u(&from_b64u(&other_key).unwrap()));
    assert!(!g::validate_credential_json(&b64u(record.to_string().as_bytes()), &other_key, &actors).unwrap());
}

/// The credential identity and signature key of a published key package (TLS, by hand).
fn leaf_of(published: &str) -> (String, String) {
    let bytes = from_b64u(published).unwrap();
    // MLSMessage: version(2) wire_format(2); KeyPackage: version(2) suite(2) init_key<V>
    // leaf_node: encryption_key<V> signature_key<V> credential: type(2) identity<V>
    let mut i = 8;
    let varint = |b: &[u8], i: &mut usize| -> usize {
        let first = b[*i];
        let (len, n) = match first >> 6 {
            0 => ((first & 0x3f) as usize, 1),
            1 => ((((first & 0x3f) as usize) << 8) | b[*i + 1] as usize, 2),
            _ => ((((first & 0x3f) as usize) << 24) | ((b[*i + 1] as usize) << 16) | ((b[*i + 2] as usize) << 8) | b[*i + 3] as usize, 4),
        };
        *i += n;
        len
    };
    let n = varint(&bytes, &mut i);
    i += n; // init key
    let n = varint(&bytes, &mut i);
    i += n; // encryption key
    let n = varint(&bytes, &mut i);
    let key = b64u(&bytes[i..i + n]);
    i += n;
    i += 2; // credential type
    let n = varint(&bytes, &mut i);
    (b64u(&bytes[i..i + n]), key)
}

#[test]
fn a_message_opens_once_and_a_failure_changes_nothing() {
    let t = trio();
    let m = g::seal(&t.s["a"], b"once").unwrap();
    let msg = m["message"].as_str().unwrap();
    let r = g::open(&t.s["b"], msg, &t.actors).unwrap();
    assert_eq!(from_b64u(r["plaintext"].as_str().unwrap()).unwrap(), b"once");
    assert!(code(g::open(&r["state"], msg, &t.actors)).is_some(), "a second copy is refused");
    let i = msg.len() / 2;
    let bent = format!("{}{}{}", &msg[..i], if &msg[i..=i] == "A" { "B" } else { "A" }, &msg[i + 1..]);
    assert!(code(g::open(&t.s["c"], &bent, &t.actors)).is_some());
    let again = g::open(&t.s["c"], msg, &t.actors).unwrap();
    assert_eq!(from_b64u(again["plaintext"].as_str().unwrap()).unwrap(), b"once");
    assert_eq!(code(g::open(&t.s["c"], "AAAA", &t.actors)), Some("BAD_MESSAGE"));
    assert_eq!(code(g::describe(&json!({ "v": 1, "group": "group:aaaaaaaaaaaaaaaa", "sign": "AA", "storage": [] }))), Some("BAD_INPUT"));
}
