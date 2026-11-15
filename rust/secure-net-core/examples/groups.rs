//! A group of three across two sites, with a removal, through a network that keeps everything.
//!
//!   cargo run --example groups
use secure_net_core::social::client::SocialClient;
use secure_net_core::social::site::{MemoryNetwork, ReferenceSite};

const NOW: i64 = 1_800_000_000_000;

fn say(ok: bool, what: &str) {
    println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    assert!(ok, "{what}");
}

fn main() {
    let mut net = MemoryNetwork::new();
    net.add(ReferenceSite::new("north.example").unwrap());
    net.add(ReferenceSite::new("south.example").unwrap());
    let mut join = |handle: &str| {
        let mut c = SocialClient::new(handle, "Person", None, 2, true, NOW).unwrap();
        c.register(&mut net).unwrap();
        c.enable_groups(&mut net, 5).unwrap();
        c
    };
    let mut people = [join("alice@north.example"), join("bob@south.example"), join("carol@north.example")];
    let settle = |people: &mut [SocialClient; 3], net: &mut MemoryNetwork| {
        for _ in 0..6 {
            for p in people.iter_mut() {
                p.sync(net).unwrap();
            }
        }
    };
    let has = |p: &SocialClient, text: &str| p.timeline.iter().any(|t| t["content"].as_str().is_some_and(|c| c.starts_with(text)));

    let (bob, carol) = (people[1].id.clone(), people[2].id.clone());
    people[0].lookup(&mut net, "bob@south.example").unwrap();
    people[0].lookup(&mut net, "carol@north.example").unwrap();
    let group = people[0].create_group().unwrap();
    people[0].invite(&mut net, &group, &bob).unwrap();
    people[0].invite(&mut net, &group, &carol).unwrap();
    settle(&mut people, &mut net);
    say(people[1].groups.contains_key(&group) && people[2].groups.contains_key(&group), "Alice made a group and added Bob and Carol");

    people[0].post_to_group(&mut net, &group, "the picnic is on Saturday").unwrap();
    settle(&mut people, &mut net);
    people[2].post_to_group(&mut net, &group, "I'll bring the kettle").unwrap();
    settle(&mut people, &mut net);
    say(has(&people[1], "I'll bring the kettle") && has(&people[2], "the picnic is on Saturday"), "everyone reads everyone");

    people[0].remove_from_group(&mut net, &group, &carol).unwrap();
    settle(&mut people, &mut net);
    people[1].post_to_group(&mut net, &group, "moved to Sunday, don't tell Carol").unwrap();
    settle(&mut people, &mut net);
    say(has(&people[0], "moved to Sunday"), "after Carol is removed, Alice and Bob carry on");
    say(!has(&people[2], "moved to Sunday"), "Carol can't read what was said after she was removed");

    let kept = net.log.join("\n");
    say(kept.contains(&format!("\"{group}\"")), "the sites did carry the group's envelopes (control)");
    say(!["picnic", "kettle", "Sunday"].iter().any(|w| kept.contains(w)), "nothing the sites carried contains a word of it");
    let sealed: usize = net.sites.values().map(|s| s.sealed_log.len()).sum();
    say(sealed > 0, &format!("{sealed} envelopes were sent sealed: the sites weren't told who sent them"));
}
