//! Groups end to end through reference sites, in Rust: mirrors the end-to-end part of the
//! JavaScript's test/groups.test.mjs.
use secure_net_core::social::activity::sign_activity;
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

struct Town {
    net: MemoryNetwork,
    alice: SocialClient,
    bob: SocialClient,
    carol: SocialClient,
}

fn town() -> Town {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("a.example").unwrap());
    net.add(ReferenceSite::new("b.example").unwrap());
    let mut make = |h: &str| {
        let mut c = SocialClient::new(h, "Person", None, 2, true, NOW).unwrap();
        c.register(&mut net).unwrap();
        c.enable_groups(&mut net, 5).unwrap();
        c
    };
    let (mut alice, bob, carol) = (make("alice@a.example"), make("bob@b.example"), make("carol@a.example"));
    alice.lookup(&mut net, "bob@b.example").unwrap();
    alice.lookup(&mut net, "carol@a.example").unwrap();
    Town { net, alice, bob, carol }
}

/// Everyone syncs a few rounds; what each was shown.
fn settle(t: &mut Town) -> [Vec<Value>; 3] {
    let mut shown: [Vec<Value>; 3] = Default::default();
    for _ in 0..6 {
        shown[0].extend(t.alice.sync(&mut t.net).unwrap());
        shown[1].extend(t.bob.sync(&mut t.net).unwrap());
        shown[2].extend(t.carol.sync(&mut t.net).unwrap());
    }
    shown
}

fn has(timeline: &[Value], content: &str) -> bool {
    timeline.iter().any(|t| t["content"] == content)
}

fn group_of_three(t: &mut Town) -> String {
    let group = t.alice.create_group().unwrap();
    let (b, c) = (t.bob.id.clone(), t.carol.id.clone());
    t.alice.invite(&mut t.net, &group, &b).unwrap();
    t.alice.invite(&mut t.net, &group, &c).unwrap();
    let shown = settle(t);
    for s in &shown {
        assert!(!s.iter().any(|x| x["kind"] == "refused"), "{s:?}");
    }
    group
}

#[test]
fn invite_post_remove_across_two_sites() {
    let mut t = town();
    let group = group_of_three(&mut t);
    assert!(t.bob.groups.contains_key(&group) && t.carol.groups.contains_key(&group));

    t.alice.post_to_group(&mut t.net, &group, "welcome, both").unwrap();
    settle(&mut t);
    t.bob.post_to_group(&mut t.net, &group, "thanks, from Bob").unwrap();
    let shown = settle(&mut t);
    assert!(shown[2].iter().any(|s| s["kind"] == "post" && s["how"] == "group" && s["content"] == "thanks, from Bob"));
    assert!(has(&t.alice.timeline, "thanks, from Bob"));
    assert!(has(&t.carol.timeline, "welcome, both"));

    let c = t.carol.id.clone();
    t.alice.remove_from_group(&mut t.net, &group, &c).unwrap();
    settle(&mut t);
    assert!(!t.carol.groups.contains_key(&group));
    t.bob.post_to_group(&mut t.net, &group, "Carol is gone").unwrap();
    settle(&mut t);
    assert!(has(&t.alice.timeline, "Carol is gone"));
    assert!(!has(&t.carol.timeline, "Carol is gone"));

    t.alice.refresh_group(&mut t.net, &group).unwrap();
    settle(&mut t);
    t.bob.post_to_group(&mut t.net, &group, "after a refresh").unwrap();
    settle(&mut t);
    assert!(has(&t.alice.timeline, "after a refresh"));

    let carried = t.net.log.join("\n");
    assert!(carried.contains(&format!("\"{group}\"")), "control: sites do see the group id");
    for secret in ["welcome, both", "thanks, from Bob", "Carol is gone", "after a refresh"] {
        assert!(!carried.contains(secret), "no site saw a group post");
    }
    // Only the committer changes the group.
    assert_eq!(t.bob.refresh_group(&mut t.net, &group).unwrap_err().code, "NOT_ALLOWED");
    let a = t.alice.id.clone();
    assert_eq!(t.bob.remove_from_group(&mut t.net, &group, &a).unwrap_err().code, "BAD_INPUT", "nobody can remove the committer (as in the JavaScript)");
}

#[test]
fn a_member_cant_post_someone_elses_signed_activity_as_a_group_post() {
    let mut t = town();
    let group = group_of_three(&mut t);
    // Bob takes an activity Alice signed for her followers and seals it into the group himself.
    let elsewhere = sign_activity(&t.alice.device, &t.alice.id, &json!({ "type": "Create", "to": ["followers"], "object": { "type": "Note", "content": "not for the group" } }), true, NOW).unwrap();
    let state = t.bob.groups[&group].clone();
    t.bob.seal_into_group(&mut t.net, &group, &state, &json!({ "v": 1, "activity": elsewhere })).unwrap();
    let shown = t.carol.sync(&mut t.net).unwrap();
    assert_eq!(shown.iter().map(|s| s["reason"].clone()).collect::<Vec<_>>(), vec![json!("UNTRUSTED")]);
    assert!(!has(&t.carol.timeline, "not for the group"));
}

#[test]
fn a_post_signed_by_someone_who_isnt_a_member_is_refused_even_if_a_member_seals_it() {
    let mut t = town();
    let group = group_of_three(&mut t);
    let c = t.carol.id.clone();
    t.alice.remove_from_group(&mut t.net, &group, &c).unwrap();
    settle(&mut t);
    // Carol, removed, signs a post for the group; Bob, still a member, seals it in for her.
    let hers = sign_activity(&t.carol.device, &t.carol.id, &json!({ "type": "Create", "to": [group], "object": { "type": "Note", "content": "I'm still here", "context": group } }), true, NOW).unwrap();
    let state = t.bob.groups[&group].clone();
    t.bob.seal_into_group(&mut t.net, &group, &state, &json!({ "v": 1, "activity": hers })).unwrap();
    let shown = t.alice.sync(&mut t.net).unwrap();
    assert_eq!(shown.iter().map(|s| s["reason"].clone()).collect::<Vec<_>>(), vec![json!("UNTRUSTED")]);
    assert!(!has(&t.alice.timeline, "I'm still here"));
}

#[test]
fn only_the_committer_invites() {
    let mut t = town();
    let group = group_of_three(&mut t);
    t.bob.lookup(&mut t.net, "carol@a.example").unwrap();
    let c = t.carol.id.clone();
    assert_eq!(t.bob.invite(&mut t.net, &group, &c).unwrap_err().code, "NOT_ALLOWED");
}
