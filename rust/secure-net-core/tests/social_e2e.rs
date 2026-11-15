//! The social protocol end to end, entirely in Rust: reference sites and clients, mirroring the
//! JavaScript's test/social.test.mjs and test/social2.test.mjs scenarios.
use secure_net_core::canonical::canonical_json;
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::delivery::{new_delivery_token, public_envelope, sealed_body};
use secure_net_core::social::repo::verify_repo;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use secure_net_core::wire::federation::{digest_of, sign_request, RequestFields};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn net(hosts: &[&str]) -> MemoryNetwork {
    let mut n = MemoryNetwork::new();
    for h in hosts {
        n.add(ReferenceSite::new(h).unwrap());
    }
    n
}

fn client(n: &mut MemoryNetwork, handle: &str, sessions: i64) -> SocialClient {
    let mut c = SocialClient::new(handle, "Person", None, sessions, true, NOW).unwrap();
    c.register(n).unwrap();
    c
}

fn kinds(v: &[Value]) -> Vec<String> {
    v.iter().map(|x| x["kind"].as_str().unwrap_or("").to_string()).collect()
}

fn settle(n: &mut MemoryNetwork, a: &mut SocialClient, b: &mut SocialClient) -> (Vec<Value>, Vec<Value>) {
    let (mut sa, mut sb) = (vec![], vec![]);
    for _ in 0..4 {
        sa.extend(a.sync(n).unwrap());
        sb.extend(b.sync(n).unwrap());
    }
    (sa, sb)
}

#[test]
fn follows_followers_only_posts_direct_messages_and_unfollowing() {
    let mut n = net(&["a.example", "b.example"]);
    let mut alice = client(&mut n, "alice@a.example", 2);
    let mut bob = client(&mut n, "bob@b.example", 2);
    let mut carol = client(&mut n, "carol@b.example", 2);
    bob.follow(&mut n, "alice@a.example").unwrap();
    assert_eq!(kinds(&alice.sync(&mut n).unwrap()), ["followed-by"]);
    assert_eq!(kinds(&bob.sync(&mut n).unwrap()), ["accepted"]);
    assert!(bob.following.contains(&alice.id));
    alice.post(&mut n, "for followers", &json!("followers")).unwrap();
    alice.post(&mut n, "for Bob", &json!([bob.id])).unwrap();
    let got = bob.sync(&mut n).unwrap();
    let pairs: Vec<(String, String)> = got.iter().map(|x| (x["how"].as_str().unwrap().into(), x["content"].as_str().unwrap().into())).collect();
    assert_eq!(pairs, [("followers".to_string(), "for followers".to_string()), ("direct".to_string(), "for Bob".to_string())]);
    assert!(carol.sync(&mut n).unwrap().is_empty());
    bob.like(&mut n, got[0]["id"].as_str().unwrap(), &alice.id.clone()).unwrap();
    alice.sync(&mut n).unwrap();
    assert_eq!(alice.likes[got[0]["id"].as_str().unwrap()].len(), 1);
    let aid = alice.id.clone();
    bob.unfollow(&mut n, &aid).unwrap();
    alice.sync(&mut n).unwrap();
    assert_eq!(alice.followers["members"].as_array().unwrap().len(), 0);
    alice.post(&mut n, "after", &json!("followers")).unwrap();
    assert!(bob.sync(&mut n).unwrap().is_empty());
    let everything = n.log.join("\n");
    for secret in ["for followers", "for Bob", "\"type\":\"Follow\"", "\\\"type\\\":\\\"Like\\\"", "\"type\":\"Undo\"", "\\\"type\\\":\\\"Create\\\""] {
        assert!(!everything.contains(secret), "{secret} crossed the network in the clear");
    }
    carol.follow(&mut n, "alice@a.example").unwrap();
    alice.sync(&mut n).unwrap();
    alice.post(&mut n, "out loud", &json!("public")).unwrap();
    assert!(n.log.join("\n").contains("\\\"type\\\":\\\"Create\\\""), "the same search finds a public post");
    assert_eq!(carol.sync(&mut n).unwrap().iter().filter(|x| x["content"] == "out loud").count(), 1);
}

#[test]
fn sites_refuse_replayed_altered_and_misattributed_deliveries() {
    let mut n = net(&["a.example", "b.example"]);
    let mut alice = client(&mut n, "alice@a.example", 2);
    let mut bob = client(&mut n, "bob@b.example", 2);
    bob.follow(&mut n, "@alice@a.example").unwrap();
    alice.sync(&mut n).unwrap();
    bob.sync(&mut n).unwrap();
    alice.post(&mut n, "public hello", &json!("public")).unwrap();
    let req: Value = n.log.iter().rev().map(|l| serde_json::from_str::<Value>(l).unwrap()).find(|r| r.get("signature").is_some()).unwrap();
    assert_eq!(n.receive("b.example", &req, NOW).unwrap_err().code, "REPLAY");
    let mut fresh = req.clone();
    fresh["nonce"] = json!("fresh-nonce-1234");
    assert_eq!(n.receive("b.example", &fresh, NOW).unwrap_err().code, "UNTRUSTED");
    let mut altered = req.clone();
    altered["nonce"] = json!("n2");
    altered["body"] = json!(req["body"].as_str().unwrap().replace("hello", "HELLO"));
    assert_eq!(n.receive("b.example", &altered, NOW).unwrap_err().code, "BAD_REQUEST");
    let mut late = req.clone();
    late["nonce"] = json!("n3");
    assert_eq!(n.receive("b.example", &late, NOW + 3_600_000).unwrap_err().code, "BAD_TIME");
    // Handles are first come.
    let mut mallory = SocialClient::new("alice@a.example", "Person", None, 2, true, NOW).unwrap();
    assert_eq!(mallory.register(&mut n).unwrap_err().code, "TAKEN");
    // Another site can't host Alice, so it can't deliver her public posts as if from her site.
    n.add(ReferenceSite::new("evil.example").unwrap());
    assert_eq!(n.site("evil.example").unwrap().publish_actor(&alice.actor_record).unwrap_err().code, "BAD_INPUT");
    let pubrec = n.site("a.example").unwrap().public_activities(&alice.id).last().cloned().unwrap();
    let body = canonical_json(&json!({ "v": 1, "items": [{ "to": bob.id, "envelope": public_envelope(&pubrec).unwrap() }] })).unwrap();
    let digest = digest_of(body.as_bytes());
    let date = secure_net_core::cv::encoding::iso_from_ms(NOW).unwrap();
    let fields = RequestFields { method: "POST", to: "b.example", path: "/cvp/v2/deliver", from: "evil.example", date: &date, nonce: "evil-nonce-00001", digest: &digest, user: "" };
    let evil_key = n.site("evil.example").unwrap().secret_key.clone();
    let forged = json!({ "method": "POST", "to": "b.example", "path": "/cvp/v2/deliver", "from": "evil.example", "date": date, "nonce": "evil-nonce-00001", "digest": digest, "signature": sign_request(&fields, &evil_key).unwrap(), "body": body });
    let before = n.site("b.example").unwrap().mailboxes[&bob.id].len();
    assert_eq!(n.receive("b.example", &forged, NOW).unwrap_err().code, "NOT_FOUND");
    assert_eq!(n.site("b.example").unwrap().mailboxes[&bob.id].len(), before, "nothing was stored");
}

#[test]
fn direct_messages_are_unsigned_unlinkable_and_then_sealed() {
    let mut n = net(&["a.example", "b.example"]);
    let mut alice = client(&mut n, "alice@a.example", 2);
    let mut bob = client(&mut n, "bob@b.example", 2);
    bob.lookup(&mut n, "alice@a.example").unwrap();
    alice.lookup(&mut n, "bob@b.example").unwrap();
    alice.post(&mut n, "first, through our sites", &json!([bob.id])).unwrap();
    let (_, sb) = settle(&mut n, &mut alice, &mut bob);
    let got = sb.iter().find(|s| s["kind"] == "post").unwrap();
    assert_eq!(got["content"], "first, through our sites");
    assert_eq!(got["deniable"], true);
    assert!(n.sites["b.example"].sealed_log.is_empty());
    bob.post(&mut n, "reply", &json!([alice.id])).unwrap();
    settle(&mut n, &mut alice, &mut bob);
    let before = n.log.len();
    alice.post(&mut n, "second, sealed", &json!([bob.id])).unwrap();
    let (_, sb) = settle(&mut n, &mut alice, &mut bob);
    assert!(sb.iter().any(|s| s["content"] == "second, sealed"));
    assert!(!n.sites["b.example"].sealed_log.is_empty());
    let carried = n.log[before..].join("\n");
    assert!(carried.contains(&format!("\"{}\"", bob.id)));
    for secret in [alice.id.as_str(), alice.device.kid.as_str(), "alice@a.example", "a.example", "second, sealed"] {
        assert!(!carried.contains(secret), "nothing about the sender ({secret}) is on the wire");
    }
    // A sealed delivery needs Bob's current token.
    let env = json!({ "v": 2, "mode": "direct", "device": bob.device.kid, "message": { "v": 2, "h": "AAAA", "c": "AAAA" } });
    let bad = sealed_body(&[json!({ "to": bob.id, "envelope": env, "token": new_delivery_token() })]).unwrap();
    assert_eq!(n.receive_sealed("b.example", &bad).unwrap_err().code, "UNTRUSTED");
    let old = alice.tokens[&bob.id].clone();
    bob.rotate_delivery_token(&mut n).unwrap();
    bob.post(&mut n, "new token inside", &json!([alice.id])).unwrap();
    settle(&mut n, &mut alice, &mut bob);
    assert_ne!(alice.tokens[&bob.id], old);
    bob.rotate_delivery_token(&mut n).unwrap();
    let stale = sealed_body(&[json!({ "to": bob.id, "envelope": env, "token": old })]).unwrap();
    assert_eq!(n.receive_sealed("b.example", &stale).unwrap_err().code, "UNTRUSTED");
    alice.post(&mut n, "still arrives", &json!([bob.id])).unwrap();
    let (_, sb) = settle(&mut n, &mut alice, &mut bob);
    assert!(sb.iter().any(|s| s["content"] == "still arrives"));
}

#[test]
fn older_and_newer_clients_still_talk_over_version_1() {
    for old in ["alice", "bob"] {
        let mut n = net(&["a.example", "b.example"]);
        let mut alice = client(&mut n, "alice@a.example", if old == "alice" { 1 } else { 2 });
        let mut bob = client(&mut n, "bob@b.example", if old == "bob" { 1 } else { 2 });
        bob.lookup(&mut n, "alice@a.example").unwrap();
        alice.lookup(&mut n, "bob@b.example").unwrap();
        alice.post(&mut n, "from Alice", &json!([bob.id])).unwrap();
        let (_, sb) = settle(&mut n, &mut alice, &mut bob);
        let got = sb.iter().find(|s| s["kind"] == "post").unwrap();
        assert_eq!(got["content"], "from Alice");
        assert_eq!(got["deniable"], false);
        bob.post(&mut n, "from Bob", &json!([alice.id])).unwrap();
        let (sa, _) = settle(&mut n, &mut alice, &mut bob);
        assert!(sa.iter().any(|s| s["content"] == "from Bob"));
        assert!(n.sites["b.example"].sealed_log.is_empty());
        assert_eq!(alice.sessions.values().next().unwrap()["v"], 1);
    }
}

#[test]
fn a_site_cant_talk_a_sender_down_to_version_1() {
    let mut n = net(&["a.example", "b.example"]);
    let mut alice = client(&mut n, "alice@a.example", 2);
    let mut bob = client(&mut n, "bob@b.example", 2);
    alice.lookup(&mut n, "bob@b.example").unwrap();
    alice.post(&mut n, "hello", &json!([bob.id])).unwrap();
    settle(&mut n, &mut alice, &mut bob);
    alice.sessions.remove(&bob.device.kid);
    // Bob's site strips the version from his signed prekey: the signature then fails, and even a
    // bundle that claims version 1 is refused for a device that has spoken version 2.
    alice.peer_version.insert(bob.device.kid.clone(), 2);
    alice.max_sessions = 1;
    assert_eq!(alice.post(&mut n, "again", &json!([bob.id])).unwrap_err().code, "DOWNGRADE");
}

#[test]
fn moving_keeps_id_followers_sessions_and_history() {
    let mut n = net(&["a.example", "b.example", "c.example"]);
    let mut alice = client(&mut n, "alice@a.example", 2);
    let mut bob = client(&mut n, "bob@b.example", 2);
    bob.follow(&mut n, "alice@a.example").unwrap();
    alice.sync(&mut n).unwrap();
    bob.sync(&mut n).unwrap();
    alice.post(&mut n, "public before the move", &json!("public")).unwrap();
    bob.sync(&mut n).unwrap();
    let id_before = alice.id.clone();
    alice.migrate(&mut n, "alice@c.example").unwrap();
    assert_eq!(alice.id, id_before);
    assert_eq!(kinds(&bob.sync(&mut n).unwrap()), ["profile-updated"]);
    assert_eq!(bob.known[&alice.id]["handle"], "alice@c.example");
    alice.post(&mut n, "after the move", &json!("followers")).unwrap();
    let got = bob.sync(&mut n).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0]["how"].as_str(), got[0]["content"].as_str()), (Some("followers"), Some("after the move")));
    let repo = verify_repo(&n.sites["c.example"].repo(&alice.id).unwrap(), Some(&alice.id), 0, NOW).unwrap();
    assert_eq!(repo["records"][0]["body"]["object"]["content"], "public before the move");
    assert_eq!(n.sites["a.example"].repo(&alice.id).unwrap_err().code, "NOT_FOUND");
    let mut carol = client(&mut n, "carol@b.example", 2);
    assert_eq!(carol.lookup(&mut n, "alice@a.example").unwrap()["id"], alice.id.as_str());
    assert_eq!(carol.known[&alice.id]["handle"], "alice@c.example");
    let mut taker = SocialClient::new("alice@a.example", "Person", None, 2, true, NOW).unwrap();
    assert_eq!(taker.register(&mut n).unwrap_err().code, "TAKEN");
    let code = n.site("c.example").unwrap().release(&alice.actor_record).unwrap_err().code;
    assert!(code == "ROLLBACK" || code == "BAD_INPUT");
    assert_eq!(n.sites["a.example"].changes(0)["commits"].as_array().unwrap().len(), 1);
    assert_eq!(n.sites["c.example"].changes(0)["commits"][0]["actor"], alice.id.as_str());
}
