// A group of three across two sites, with a removal, through a network that keeps everything.
//   node examples/groups.mjs
// Needs the optional MLS library: npm install ts-mls @hpke/hybridkem-x-wing
import { MemoryNetwork, ReferenceSite } from "../src/social/site.js";
import { SocialClient } from "../src/social/client.js";
import { withGroups } from "../src/groups/client.js";

const network = new MemoryNetwork();
network.add(new ReferenceSite("north.example"));
network.add(new ReferenceSite("south.example"));
const join = (handle) => withGroups(new SocialClient({ handle, network }).register()).enableGroups();
const [alice, bob, carol] = [await join("alice@north.example"), await join("bob@south.example"), await join("carol@north.example")];
const everyone = [alice, bob, carol];
const settle = async () => {
  for (let i = 0; i < 6; i += 1) for (const p of everyone) await p.sync();
};
const say = (ok, what) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) process.exitCode = 1;
};

alice.lookup(bob.handle);
alice.lookup(carol.handle);
const group = await alice.createGroup();
await alice.invite(group, bob.id);
await alice.invite(group, carol.id);
await settle();
say(bob.groups.has(group) && carol.groups.has(group), "Alice made a group and added Bob and Carol");

await alice.postToGroup(group, "the picnic is on Saturday");
await settle();
await carol.postToGroup(group, "I'll bring the kettle");
await settle();
say(bob.timeline.some((t) => t.content === "I'll bring the kettle") && carol.timeline.some((t) => t.content === "the picnic is on Saturday"), "everyone reads everyone");

await alice.removeFromGroup(group, carol.id);
await settle();
await bob.postToGroup(group, "moved to Sunday, don't tell Carol");
await settle();
say(alice.timeline.some((t) => t.content.startsWith("moved to Sunday")), "after Carol is removed, Alice and Bob carry on");
say(!carol.timeline.some((t) => t.content.startsWith("moved to Sunday")), "Carol can't read what was said after she was removed");

const kept = network.log.join("\n");
say(kept.includes(`"${group}"`), "the sites did carry the group's envelopes (control)");
say(!["picnic", "kettle", "Sunday"].some((w) => kept.includes(w)), "nothing the sites carried contains a word of it");
const sealed = [...network.sites.values()].reduce((n, s) => n + s.sealedLog.length, 0);
say(sealed > 0, `${sealed} envelopes were sent sealed: the sites weren't told who sent them`);
