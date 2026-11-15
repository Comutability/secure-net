//! The social protocol (CVP-017 to 021) end to end: three sites and three people. Public posts,
//! follows, followers-only posts, a direct message, a like, an unfollow, a verifiable repository,
//! a lexicon, and a move to another site, all over a network that keeps a copy of everything it
//! carries. At the end the network's copy is searched: public posts should be there, and nothing
//! private should be.
//!
//!   cargo run --example social
use secure_net_core::session::keys::safety_number;
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::lexicon::{create_lexicon, extension_problems, verify_lexicon};
use secure_net_core::social::repo::verify_repo;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn person(net: &mut MemoryNetwork, handle: &str, name: &str) -> SocialClient {
    let mut c = SocialClient::new(handle, "Person", Some(name), 2, true, NOW).unwrap();
    c.register(net).unwrap();
    c
}

fn show(who: &str, items: Vec<Value>) {
    for i in items {
        match i["kind"].as_str().unwrap_or("") {
            "post" => println!("  {who} sees {} post from {}: \"{}\"", i["how"].as_str().unwrap_or(""), i["from"].as_str().unwrap_or(""), i["content"].as_str().unwrap_or("")),
            "unreadable" | "refused" => println!("  {who} can't read one envelope ({})", i["reason"].as_str().unwrap_or("")),
            "keys" => {}
            k => println!("  {who}: {k} {}", i["from"].as_str().unwrap_or("")),
        }
    }
}

struct World {
    net: MemoryNetwork,
    alice: SocialClient,
    bob: SocialClient,
    carol: SocialClient,
}
impl World {
    fn sync(&mut self) {
        for _ in 0..2 {
            show("Alice", self.alice.sync(&mut self.net).unwrap());
            show("Bob", self.bob.sync(&mut self.net).unwrap());
            show("Carol", self.carol.sync(&mut self.net).unwrap());
        }
    }
}

fn main() {
    let mut net = MemoryNetwork::new();
    for h in ["a.example", "b.example", "c.example"] {
        net.add(ReferenceSite::new(h).unwrap());
    }
    let alice = person(&mut net, "alice@a.example", "Alice");
    let bob = person(&mut net, "bob@b.example", "Bob");
    let carol = person(&mut net, "carol@b.example", "Carol");
    let mut w = World { net, alice, bob, carol };
    let n = &mut w.net;

    println!("\n1. Alice posts publicly, and Bob follows her (the follow itself is end-to-end encrypted)");
    w.alice.post(n, "Hello from a.example. This one is public.", &json!("public")).unwrap();
    w.bob.follow(n, "@alice@a.example").unwrap();
    w.sync();
    println!("  Safety number Alice and Bob can compare: {}", safety_number(&w.alice.account.public_key, &w.bob.account.public_key));

    println!("\n2. Alice posts to her followers only");
    w.alice.post(&mut w.net, "Followers only: the meetup is on Thursday.", &json!("followers")).unwrap();
    w.sync();

    println!("\n3. Alice messages Bob directly; Bob likes her followers-only post");
    let bob_id = w.bob.id.clone();
    w.alice.post(&mut w.net, "Bob, are you coming on Thursday?", &json!([bob_id])).unwrap();
    w.sync();
    let meetup = w.bob.timeline.iter().find(|p| p["content"].as_str().is_some_and(|c| c.starts_with("Followers only"))).unwrap()["id"].as_str().unwrap().to_string();
    let alice_id = w.alice.id.clone();
    w.bob.like(&mut w.net, &meetup, &alice_id).unwrap();
    w.sync();
    println!("  Likes on Alice's followers-only post: {}", w.alice.likes.get(&meetup).map_or(0, |l| l.len()));

    println!("\n4. Carol follows, then Bob unfollows: Alice's next followers-only post reaches Carol only");
    w.carol.follow(&mut w.net, "@alice@a.example").unwrap();
    w.sync();
    w.bob.unfollow(&mut w.net, &alice_id).unwrap();
    w.sync();
    w.alice.post(&mut w.net, "Followers only: Bob has left, so he can't read this.", &json!("followers")).unwrap();
    w.sync();

    println!("\n5. Alice posts publicly again");
    w.alice.post(&mut w.net, "Public again: everyone welcome on Thursday.", &json!("public")).unwrap();
    w.sync();

    println!("\n6. Anyone can check Alice's public repository, from any copy");
    let mut copy = w.net.sites["a.example"].repo(&alice_id).unwrap();
    let repo = verify_repo(&copy, Some(&alice_id), 0, NOW).unwrap();
    println!("  A mirror's copy verifies: {} public records, signed by Alice's device", repo["records"].as_array().unwrap().len());
    copy["records"].as_array_mut().unwrap().pop();
    println!("  The same copy with one record dropped: refused ({})", verify_repo(&copy, Some(&alice_id), 0, NOW).unwrap_err().code);

    println!("\n7. A new kind of object, defined by a lexicon on its own domain");
    let mut chef = person(&mut w.net, "lexicons@c.example", "c.example types");
    let lexicon = create_lexicon(&chef.account, &json!({ "v": 1, "id": "example.c.recipe", "revision": 1, "fields": { "serves": { "type": "integer", "min": 1, "required": true }, "ingredients": { "type": "array", "items": { "type": "string" }, "required": true } } })).unwrap();
    w.net.site("c.example").unwrap().publish_lexicon(&lexicon).unwrap();
    let publisher = chef.lookup(&mut w.net, "lexicons@c.example").unwrap();
    let known = verify_lexicon(&w.net.sites["c.example"].lexicon("example.c.recipe").unwrap(), &publisher, 0).unwrap();
    let recipe = json!({ "type": "example.c.recipe", "id": format!("{alice_id}:RRRRRRRRRRRRRRRRRRRRRR"), "attributedTo": alice_id, "published": NOW, "name": "Dal for Thursday", "content": "Simmer the lentils.", "serves": 6, "ingredients": ["lentils", "onion"] });
    println!("  An app that knows recipes checks one: {}", if extension_problems(&recipe, &known).is_empty() { "valid recipe" } else { "invalid" });

    println!("\n8. Alice moves to c.example and keeps her identity, followers, keys and history");
    w.alice.migrate(&mut w.net, "alice@c.example").unwrap();
    w.sync();
    w.alice.post(&mut w.net, "Followers only: same me, new home.", &json!("followers")).unwrap();
    w.sync();
    let moved = verify_repo(&w.net.sites["c.example"].repo(&alice_id).unwrap(), Some(&alice_id), 0, NOW).unwrap();
    println!("  Same actor id: {}. Public history at the new site: {} records, still verifying", w.alice.id == alice_id, moved["records"].as_array().unwrap().len());
    println!("  Bob looks up the old handle and is sent to: @{}", w.bob.lookup(&mut w.net, "alice@a.example").unwrap()["handle"].as_str().unwrap_or(""));

    let everything = w.net.log.join("\n");
    let private = ["meetup is on Thursday", "are you coming", "Bob has left", "same me, new home", "type\\\":\\\"Follow", "type\\\":\\\"Like", "type\\\":\\\"Undo"];
    let leaked: Vec<&str> = private.iter().copied().filter(|t| everything.contains(t)).collect();
    println!("\nThe network carried {} items. Private text or activity types found in them: {}.", w.net.log.len(), if leaked.is_empty() { "none".to_string() } else { leaked.join(", ") });
    assert!(leaked.is_empty());
    assert!(everything.contains("everyone welcome"), "the public post crossed the network readable");
}
