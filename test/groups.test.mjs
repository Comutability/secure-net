import test from "node:test";
import assert from "node:assert/strict";
import * as M from "ts-mls";
import { createAccount, createDevice, signDeviceList } from "../src/session/index.js";
import { createActorDocument, verifyActorDocument, actorIdOf } from "../src/social/actor.js";
import { b64u, fromB64u } from "../src/core/bytes.js";
import * as G from "../src/groups/mls.js";

const text = (b) => new TextDecoder().decode(b);
const code = (p) => p.then(() => null, (e) => e.code);

const directory = new Map();
const actors = (id) => directory.get(id);

function person(name, { listed = true } = {}) {
  const account = createAccount();
  const device = createDevice();
  const id = actorIdOf(account.publicKey);
  const record = createActorDocument(account, { handle: `${name}@a.example`, type: "Person", name, devices: signDeviceList(account, [device], { seq: 1 }), seq: 1 });
  if (listed) directory.set(id, verifyActorDocument(record, { id }));
  return { name, account, device, id };
}

/** Alice creates a group and adds Bob and Carol. */
async function trio() {
  const [alice, bob, carol] = ["alice", "bob", "carol"].map((n) => person(n));
  const kp = {};
  for (const p of [alice, bob, carol]) kp[p.name] = await G.createKeyPackage(p.device, p.id);
  let a = await G.createGroup({ keyPackage: kp.alice.secret, actors });
  const added = await G.addMembers(a, [kp.bob.published, kp.carol.published]);
  a = added.state;
  const b = await G.join({ welcome: added.welcome, keyPackage: kp.bob.secret, actors });
  const c = await G.join({ welcome: added.welcome, keyPackage: kp.carol.secret, actors });
  return { alice, bob, carol, kp, s: { a, b, c } };
}

async function say(s, from, body) {
  const m = await G.seal(s[from], body);
  s[from] = m.state;
  for (const k of Object.keys(s)) {
    if (k === from) continue;
    const r = await G.open(s[k], m.message);
    s[k] = r.state;
    assert.equal(text(r.plaintext), body);
  }
  return m.message;
}

async function apply(s, change, who) {
  for (const k of who) s[k] = (await G.open(s[k], change.commit)).state;
}

test("groups: three devices agree a group and everyone can write to everyone", async () => {
  const { s, alice, bob, carol } = await trio();
  const d = G.describe(s.b);
  assert.match(d.group, /^group:/);
  assert.deepEqual(d.members.map((m) => m.actor).sort(), [alice.id, bob.id, carol.id].sort());
  assert.equal(G.describe(s.a).epoch, G.describe(s.c).epoch);
  const wire = await say(s, "a", "hello from the committer");
  await say(s, "b", "hello from Bob");
  await say(s, "c", "hello from Carol");
  const raw = Buffer.from(fromB64u(wire)).toString("latin1");
  assert.ok(Buffer.from(fromB64u(b64u(new TextEncoder().encode("needle")))).toString("latin1") === "needle", "control");
  assert.ok(!raw.includes("hello from the committer"), "a site carrying it sees only ciphertext");
});

test("groups: a removed member is locked out by one commit, for everyone", async () => {
  const { s, carol } = await trio();
  await say(s, "c", "before");
  const kept = s.c;
  const change = await G.removeMembers(s.a, (m) => m.actor === carol.id);
  s.a = change.state;
  await apply(s, change, ["b"]);
  delete s.c;
  const after = await say(s, "b", "Carol can't read this");
  assert.notEqual(await code(G.open(kept, after)), null, "her old state doesn't open it");
  const hers = await G.open(kept, change.commit).then((r) => r.state, () => kept);
  assert.notEqual(await code(G.open(hers, after)), null, "nor does it after she sees the commit that removed her");
  assert.equal(G.describe(s.a).members.length, 2);
});

test("groups: someone who copied a member's state is locked out when that member gets fresh keys", async () => {
  const { s, bob } = await trio();
  await say(s, "b", "before the theft");
  const stolen = s.b;
  const fresh = await G.createKeyPackage(bob.device, bob.id);
  const change = await G.replaceMember(s.a, fresh.published);
  s.a = change.state;
  await apply(s, change, ["c"]);
  s.b = await G.join({ welcome: change.welcome, keyPackage: fresh.secret, actors });
  const m = await say(s, "c", "after the repair");
  const thief = await G.open(stolen, change.commit).then((r) => r.state, () => stolen);
  assert.notEqual(await code(G.open(thief, m)), null, "the copy can't follow the group any more");
});

test("groups: someone who copied the committer's state is locked out by a refresh", async () => {
  const { s } = await trio();
  const stolen = s.a;
  const change = await G.refresh(s.a);
  s.a = change.state;
  await apply(s, change, ["b", "c"]);
  const m = await say(s, "b", "after the refresh");
  assert.notEqual(await code(G.open(stolen, change.commit)), null, "the copy can't open the commit made from its own leaf");
  assert.notEqual(await code(G.open(stolen, m)), null);
});

test("groups: a newcomer can't read what was said before they joined", async () => {
  const { s } = await trio();
  const earlier = await say(s, "b", "before Dave");
  const dave = person("dave");
  const kp = await G.createKeyPackage(dave.device, dave.id);
  const change = await G.addMembers(s.a, [kp.published]);
  s.a = change.state;
  await apply(s, change, ["b", "c"]);
  s.d = await G.join({ welcome: change.welcome, keyPackage: kp.secret, actors });
  assert.notEqual(await code(G.open(s.d, earlier)), null);
  await say(s, "d", "hello, I'm new");
});

test("groups: only the committer changes the group", async () => {
  const { s, carol } = await trio();
  assert.equal(G.isCommitter(s.a), true);
  assert.equal(await code(G.removeMembers(s.b, (m) => m.actor === carol.id)), "NOT_ALLOWED");
  assert.equal(await code(G.refresh(s.c)), "NOT_ALLOWED");
  // Bob skips this module and makes a perfectly valid MLS commit himself. The others refuse it.
  const cs = await M.getCiphersuiteImpl(M.getCiphersuiteFromName(G.SUITE));
  const rogue = await M.createCommit({ state: s.b, cipherSuite: cs }, { extraProposals: [{ proposalType: "remove", remove: { removed: G.describe(s.b).members.find((m) => m.actor === carol.id).leaf } }] });
  const wire = b64u(M.encodeMlsMessage(rogue.commit));
  const before = G.describe(s.a);
  assert.equal(await code(G.open(s.a, wire)), "NOT_ALLOWED");
  assert.equal(await code(G.open(s.c, wire)), "NOT_ALLOWED");
  assert.deepEqual(G.describe(s.a), before);
  await say(s, "c", "still here");
});

test("groups: a key package is accepted only if a listed device of that actor signed its credential", async () => {
  const { s } = await trio();
  const stranger = person("stranger", { listed: false });
  const unknown = await G.createKeyPackage(stranger.device, stranger.id);
  assert.notEqual(await code(G.addMembers(s.a, [unknown.published])), null, "an actor we hold no document for");

  const erin = person("erin");
  const otherDevice = createDevice();
  const forged = await G.createKeyPackage(otherDevice, erin.id);
  assert.notEqual(await code(G.addMembers(s.a, [forged.published])), null, "a device that isn't on Erin's list");

  const real = await G.createKeyPackage(erin.device, erin.id);
  assert.deepEqual(G.keyPackageOwner(real.published), { actor: erin.id, device: erin.device.kid });
  const ok = await G.addMembers(s.a, [real.published]);
  assert.equal(G.describe(ok.state).members.length, 4);
});

test("groups: the credential must name the MLS key it travels with", async () => {
  const erin = person("erin2");
  const service = G.authService(actors);
  const real = await G.createKeyPackage(erin.device, erin.id);
  const leaf = M.decodeMlsMessage(fromB64u(real.published), 0)[0].keyPackage.leafNode;
  assert.equal(await service.validateCredential(leaf.credential, leaf.signaturePublicKey), true);
  const cs = await M.getCiphersuiteImpl(M.getCiphersuiteFromName(G.SUITE));
  const other = await cs.signature.keygen();
  assert.equal(await service.validateCredential(leaf.credential, other.publicKey), false);
  assert.equal(await service.validateCredential({ credentialType: "basic", identity: new TextEncoder().encode("erin") }, leaf.signaturePublicKey), false);
  // Someone takes Erin's credential and points it at their own MLS key: her signature no longer fits.
  const { sha256B64u } = await import("../src/core/bytes.js");
  const record = JSON.parse(text(leaf.credential.identity));
  record.body.key = sha256B64u(other.publicKey);
  const forged = { credentialType: "basic", identity: new TextEncoder().encode(JSON.stringify(record)) };
  assert.equal(await service.validateCredential(forged, other.publicKey), false);
});

test("groups: a message opens once, and a failure changes nothing", async () => {
  const { s } = await trio();
  const m = await G.seal(s.a, "once");
  const r = await G.open(s.b, m.message);
  assert.equal(text(r.plaintext), "once");
  assert.notEqual(await code(G.open(r.state, m.message)), null, "a second copy is refused");
  const i = Math.floor(m.message.length / 2);
  const bent = m.message.slice(0, i) + (m.message[i] === "A" ? "B" : "A") + m.message.slice(i + 1);
  assert.notEqual(await code(G.open(s.c, bent)), null);
  assert.equal(text((await G.open(s.c, m.message)).plaintext), "once");
  assert.equal(await code(G.open(s.c, "AAAA")), "BAD_MESSAGE");
});

test("groups: state can be saved and loaded", async () => {
  const { s } = await trio();
  s.b = G.loadState(G.saveState(s.b), { actors });
  await say(s, "b", "after a restart");
  await say(s, "a", "and back");
});

// ---- End to end, through sites ----

const { MemoryNetwork, ReferenceSite } = await import("../src/social/site.js");
const { SocialClient } = await import("../src/social/client.js");
const { withGroups } = await import("../src/groups/client.js");

async function town() {
  const network = new MemoryNetwork();
  network.add(new ReferenceSite("a.example"));
  network.add(new ReferenceSite("b.example"));
  const make = async (handle) => withGroups(new SocialClient({ handle, network }).register()).enableGroups();
  const [alice, bob, carol] = [await make("alice@a.example"), await make("bob@b.example"), await make("carol@a.example")];
  for (const p of [bob, carol]) alice.lookup(p.handle);
  const all = [alice, bob, carol];
  const settle = async () => {
    const shown = new Map(all.map((p) => [p, []]));
    for (let round = 0; round < 6; round += 1) for (const p of all) shown.get(p).push(...(await p.sync()));
    return shown;
  };
  return { network, alice, bob, carol, settle };
}

test("groups end to end: invite, post, remove, across two sites", async () => {
  const { network, alice, bob, carol, settle } = await town();
  const group = await alice.createGroup();
  await alice.invite(group, bob.id);
  await alice.invite(group, carol.id);
  let shown = await settle();
  assert.equal(shown.get(bob).filter((s) => s.kind === "refused").length, 0, JSON.stringify(shown.get(bob)));
  assert.ok(bob.groups.has(group) && carol.groups.has(group));

  await alice.postToGroup(group, "welcome, both");
  await settle();
  await bob.postToGroup(group, "thanks, from Bob");
  shown = await settle();
  assert.ok(shown.get(carol).some((s) => s.kind === "post" && s.how === "group" && s.content === "thanks, from Bob"));
  assert.ok(alice.timeline.some((t) => t.content === "thanks, from Bob"));
  assert.ok(carol.timeline.some((t) => t.content === "welcome, both"));

  await alice.removeFromGroup(group, carol.id);
  await settle();
  assert.ok(!carol.groups.has(group));
  await bob.postToGroup(group, "Carol is gone");
  await settle();
  assert.ok(alice.timeline.some((t) => t.content === "Carol is gone"));
  assert.ok(!carol.timeline.some((t) => t.content === "Carol is gone"));

  const carried = network.log.join("\n");
  assert.ok(carried.includes(`"${group}"`), "control: sites do see the group id");
  for (const secret of ["welcome, both", "thanks, from Bob", "Carol is gone"]) assert.ok(!carried.includes(secret), "no site saw a group post");
});

test("groups end to end: a member can't post someone else's signed activity as a group post", async () => {
  const { alice, bob, carol, settle } = await town();
  const group = await alice.createGroup();
  await alice.invite(group, bob.id);
  await alice.invite(group, carol.id);
  await settle();
  // Bob takes an activity Alice signed for her followers and seals it into the group himself.
  const elsewhere = alice.sign({ type: "Create", to: ["followers"], object: { type: "Note", content: "not for the group" } }, { encrypted: true });
  const G2 = await import("../src/groups/mls.js");
  const { canonicalJson } = await import("../src/core/canonical.js");
  const r = await G2.seal(bob.groups.get(group), canonicalJson({ v: 1, activity: elsewhere }));
  bob.groups.set(group, r.state);
  await bob.deliver(carol.id, [{ v: 2, mode: "group", group, message: r.message }]);
  const shown = await carol.sync();
  assert.deepEqual(shown.map((s) => s.reason), ["UNTRUSTED"]);
  assert.ok(!carol.timeline.some((t) => t.content === "not for the group"));
});

test("groups end to end: a post signed by someone who isn't a member is refused, even if a member seals it", async () => {
  const { alice, bob, carol, settle } = await town();
  const group = await alice.createGroup();
  await alice.invite(group, bob.id);
  await alice.invite(group, carol.id);
  await settle();
  await alice.removeFromGroup(group, carol.id);
  await settle();
  // Carol, removed, signs a post for the group; Bob, still a member, seals it in for her.
  const hers = carol.sign({ type: "Create", to: [group], object: { type: "Note", content: "I'm still here", context: group } }, { encrypted: true });
  const G2 = await import("../src/groups/mls.js");
  const { canonicalJson } = await import("../src/core/canonical.js");
  const r = await G2.seal(bob.groups.get(group), canonicalJson({ v: 1, activity: hers }));
  bob.groups.set(group, r.state);
  await bob.deliver(alice.id, [{ v: 2, mode: "group", group, message: r.message }]);
  const shown = await alice.sync();
  assert.deepEqual(shown.map((s) => s.reason), ["UNTRUSTED"]);
  assert.ok(!alice.timeline.some((t) => t.content === "I'm still here"));
});
