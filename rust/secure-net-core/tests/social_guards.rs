//! Social protocol guards that the end-to-end scenarios can't reach on their own: each test
//! builds the one forgery a single check exists to stop.
use secure_net_core::signed::sign;
use secure_net_core::social::activity::{sign_activity, verify_activity};
use secure_net_core::social::actor::{verify_actor_document, ACTOR};
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::delivery::open_direct_payload;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use secure_net_core::social::repo::{append_to_repo, export_repo, inclusion_proof, merkle_root, remove_from_repo, verify_inclusion, verify_repo};
use serde_json::json;

const NOW: i64 = 1_800_000_000_000;

fn person(handle: &str) -> SocialClient {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new(handle.split('@').nth(1).unwrap()).unwrap());
    let mut c = SocialClient::new(handle, "Person", None, 2, true, NOW).unwrap();
    c.register(&mut net).unwrap();
    c
}

fn note() -> serde_json::Value {
    json!({ "type": "Create", "to": ["public"], "object": { "type": "Note", "content": "hi", "mediaType": "text/plain" } })
}

#[test]
fn an_actor_document_must_carry_its_own_accounts_id() {
    let alice = person("alice@a.example");
    let mut body = alice.actor_record["body"].clone();
    body["id"] = json!(person("bob@b.example").id);
    let forged = sign(ACTOR, &body, &alice.account).unwrap();
    let e = verify_actor_document(&forged, None, None, 0).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("UNTRUSTED", "Actor id isn't its account key's id"));
}

#[test]
fn an_activity_must_name_the_actor_it_is_checked_against() {
    let bob = person("bob@b.example");
    let doc = verify_actor_document(&bob.actor_record, None, None, 0).unwrap();
    // Signed by Bob's own device, but claiming to be someone else's activity.
    let forged = sign_activity(&bob.device, &person("carol@c.example").id, &note(), false, NOW).unwrap();
    assert_eq!(verify_activity(&forged, &doc, false, NOW).unwrap_err().code, "UNTRUSTED");
    let good = sign_activity(&bob.device, &bob.id, &note(), false, NOW).unwrap();
    assert!(verify_activity(&good, &doc, false, NOW).is_ok());
}

#[test]
fn an_activity_must_be_signed_under_the_device_it_names() {
    let bob = person("bob@b.example");
    let doc = verify_actor_document(&bob.actor_record, None, None, 0).unwrap();
    let mut rec = sign_activity(&bob.device, &bob.id, &note(), false, NOW).unwrap();
    rec["sig"]["kid"] = json!("someone-else");
    let e = verify_activity(&rec, &doc, false, NOW).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("UNTRUSTED", "Activity isn't signed by the device it names"));
}

#[test]
fn inclusion_proofs_refuse_positions_past_the_end() {
    let ids: Vec<String> = ["aaaa", "bbbb", "cccc"].iter().map(|s| s.to_string()).collect();
    let root = merkle_root(&ids);
    for i in 0..3 {
        let proof = inclusion_proof(&ids, i).unwrap();
        assert!(verify_inclusion(&ids[i as usize], i, 3, &proof, &root));
        for bad in [i + 3, i + 6, -1] {
            assert!(!verify_inclusion(&ids[i as usize], bad, 3, &proof, &root), "index {bad}");
        }
    }
}

#[test]
fn repositories_refuse_unsigned_commits_short_records_and_private_records() {
    let alice = person("alice@a.example");
    let r1 = sign_activity(&alice.device, &alice.id, &note(), false, NOW).unwrap();
    let r2 = sign_activity(&alice.device, &alice.id, &note(), false, NOW + 1).unwrap();
    let repo = append_to_repo(&append_to_repo(&alice.repo, &alice.device, &r1, NOW).unwrap(), &alice.device, &r2, NOW).unwrap();
    let good = export_repo(&repo, &alice.actor_record);
    assert!(verify_repo(&good, Some(&alice.id), 0, NOW).is_ok());

    let mut unsigned = good.clone();
    unsigned["head"]["body"]["at"] = json!(NOW + 5);
    let e = verify_repo(&unsigned, Some(&alice.id), 0, NOW).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("UNTRUSTED", "Commit isn't signed by a device of the actor"));

    let mut short = good.clone();
    short["records"].as_array_mut().unwrap().pop();
    let e = verify_repo(&short, Some(&alice.id), 0, NOW).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("TAMPERED", "Records are missing or added"));

    // A followers-only activity slipped into the list and committed properly is still refused.
    let private = sign_activity(&alice.device, &alice.id, &json!({ "type": "Create", "to": [alice.id], "object": { "type": "Note", "content": "just us", "mediaType": "text/plain" } }), false, NOW).unwrap();
    let mut sneaky = repo.clone();
    sneaky["records"].as_array_mut().unwrap().push(private);
    let sneaky = remove_from_repo(&sneaky, &alice.device, &json!("nothing-by-this-id"), NOW).unwrap();
    let e = verify_repo(&export_repo(&sneaky, &alice.actor_record), Some(&alice.id), 0, NOW).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("TAMPERED", "A record that isn't public"));
}

#[test]
fn a_direct_payload_activity_must_come_from_the_device_that_sent_it() {
    let alice = person("alice@a.example");
    let act = sign_activity(&alice.device, &alice.id, &note(), false, NOW).unwrap();
    let payload = serde_json::to_vec(&json!({ "v": 1, "activity": act })).unwrap();
    assert!(open_direct_payload(&payload, &alice.device.kid, &alice.id, 2).is_ok());
    let e = open_direct_payload(&payload, "another-device", &alice.id, 2).unwrap_err();
    assert_eq!((e.code, e.message.as_str()), ("UNTRUSTED", "The activity wasn't made by the device that sent it"));
    let e = open_direct_payload(&payload, &alice.device.kid, &person("bob@b.example").id, 2).unwrap_err();
    assert_eq!(e.code, "UNTRUSTED");
}
