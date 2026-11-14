import test from "node:test";
import assert from "node:assert/strict";
import { MemoryNetwork, ReferenceSite } from "../src/social/site.js";
import { SocialClient } from "../src/social/client.js";
import { envelopeProblems, openDirectPayload, sealedBody, readSealedBody, newDeliveryToken, deliveryVerifier } from "../src/social/delivery.js";
import { sessionActivity, verifySessionActivity, signActivity } from "../src/social/activity.js";
import { canonicalJson } from "../src/core/canonical.js";

const code = (p) => Promise.resolve().then(p).then(() => null, (e) => e.code);

function town(opts = {}) {
  const network = new MemoryNetwork();
  network.add(new ReferenceSite("a.example"));
  network.add(new ReferenceSite("b.example"));
  const alice = new SocialClient({ handle: "alice@a.example", network, ...(opts.alice || {}) }).register();
  const bob = new SocialClient({ handle: "bob@b.example", network, ...(opts.bob || {}) }).register();
  alice.lookup(bob.handle);
  const settle = async () => {
    const shown = { alice: [], bob: [] };
    for (let i = 0; i < 4; i += 1) {
      shown.alice.push(...(await alice.sync()));
      shown.bob.push(...(await bob.sync()));
    }
    return shown;
  };
  return { network, alice, bob, settle, siteA: network.site("a.example"), siteB: network.site("b.example") };
}

test("delivery v2: direct messages are unsigned, unlinkable and, once two people have spoken, sealed", async () => {
  const { network, alice, bob, settle, siteA, siteB } = town();
  await alice.post("first, through our sites", { to: [bob.id] });
  let shown = await settle();
  const got = shown.bob.find((s) => s.kind === "post");
  assert.equal(got.content, "first, through our sites");
  assert.equal(got.deniable, true, "no signature travels with a direct message");
  assert.equal(siteB.sealedLog.length, 0, "a first message is vouched for by the sender's site");

  await bob.post("reply", { to: [alice.id] });
  await settle();
  const before = network.log.length;
  await alice.post("second, sealed", { to: [bob.id] });
  shown = await settle();
  assert.ok(shown.bob.some((s) => s.content === "second, sealed"));
  assert.ok(siteB.sealedLog.length >= 1, "it went straight to Bob's site with his token");
  const carried = network.log.slice(before).join("\n");
  assert.ok(carried.includes(`"${bob.id}"`), "control: the recipient is visible");
  for (const secret of [alice.id, alice.device.kid, "alice@a.example", "a.example", "second, sealed"]) {
    assert.ok(!carried.includes(secret), `nothing about the sender (${secret}) is on the wire`);
  }
  for (const entry of siteB.sealedLog) assert.deepEqual(Object.keys(entry).sort(), ["bytes", "mode", "to"]);
  // Two sealed envelopes of one conversation share nothing a site can match up.
  await alice.post("third", { to: [bob.id] });
  const [e1, e2] = network.log.slice(before).map((l) => JSON.parse(l)).filter((l) => l.sealed).map((l) => l.body.items[0].envelope);
  assert.deepEqual(Object.keys(e1).sort(), ["device", "message", "mode", "v"]);
  assert.equal(e1.session, undefined);
  assert.notEqual(e1.message.h.slice(0, 32), e2.message.h.slice(0, 32));
  void siteA;
});

test("delivery v2: a sealed delivery needs the recipient's current token", async () => {
  const { alice, bob, settle, siteB } = town();
  await alice.post("hello", { to: [bob.id] });
  await settle();
  await bob.post("hi", { to: [alice.id] });
  await settle();
  const env = { v: 2, mode: "direct", device: bob.device.kid, message: { v: 2, h: "AAAA", c: "AAAA" } };
  const bad = sealedBody([{ to: bob.id, envelope: env, token: newDeliveryToken() }]);
  assert.equal(await code(() => siteB.receiveSealed(bad)), "UNTRUSTED");
  assert.equal(await code(() => siteB.receiveSealed(sealedBody([{ to: bob.id, envelope: env, token: alice.tokens.get(bob.id) }]))), null);
  // Bob replaces his token. The old one works until he replaces it again; Alice learns the new one from his next message.
  const old = alice.tokens.get(bob.id);
  bob.rotateDeliveryToken();
  await bob.post("new token inside", { to: [alice.id] });
  await settle();
  assert.notEqual(alice.tokens.get(bob.id), old);
  bob.rotateDeliveryToken();
  assert.equal(await code(() => siteB.receiveSealed(sealedBody([{ to: bob.id, envelope: env, token: old }]))), "UNTRUSTED");
  // Alice still holds the token before last; her next message falls back to her site and arrives.
  await alice.post("still arrives", { to: [bob.id] });
  const shown = await settle();
  assert.ok(shown.bob.some((s) => s.content === "still arrives"));
});

test("delivery v2: only version 2 direct and group envelopes may be sealed, and nothing extra rides along", () => {
  const token = newDeliveryToken();
  const to = "A".repeat(22);
  const v1 = { v: 1, mode: "direct", device: "B".repeat(22), session: "C".repeat(22), message: { v: 1, c: "AAAA" } };
  assert.throws(() => sealedBody([{ to, envelope: v1, token }]), { code: "BAD_INPUT" });
  const ok = { v: 2, mode: "direct", device: "B".repeat(22), message: { v: 2, h: "AAAA", c: "AAAA" } };
  assert.equal(readSealedBody(sealedBody([{ to, envelope: ok, token }])).length, 1);
  assert.throws(() => sealedBody([{ to, envelope: ok, token, from: "me" }]), { code: "BAD_INPUT" });
  assert.throws(() => sealedBody([{ to, envelope: ok, token: "short" }]), { code: "BAD_INPUT" });
  assert.ok(envelopeProblems({ ...ok, session: "C".repeat(22) }).length > 0, "a version 2 direct envelope has no session tag");
  assert.ok(envelopeProblems({ ...ok, message: { ...ok.message, from: "x" } }).length > 0);
  assert.ok(envelopeProblems({ v: 2, mode: "audience", audience: `${to}:${"x".repeat(16)}`, message: {} }).length > 0);
  assert.equal(envelopeProblems({ v: 2, mode: "group", group: `group:${"x".repeat(16)}`, message: "AAAA" }).length, 0);
  assert.equal(deliveryVerifier(token).length, 43);
  assert.notEqual(deliveryVerifier(token), token);
});

test("delivery v2: an older client and a newer one still talk, signed, over version 1", async () => {
  for (const old of ["alice", "bob"]) {
    const { alice, bob, settle, siteB } = town({ [old]: { sessions: 1 } });
    await alice.post("from Alice", { to: [bob.id] });
    let shown = await settle();
    const got = shown.bob.find((s) => s.kind === "post");
    assert.equal(got.content, "from Alice");
    assert.equal(got.deniable, false, "version 1 sessions carry signed activities");
    await bob.post("from Bob", { to: [alice.id] });
    shown = await settle();
    assert.ok(shown.alice.some((s) => s.content === "from Bob"));
    assert.equal(siteB.sealedLog.length, 0);
    assert.equal(Object.values(alice.sessions)[0].v, 1);
  }
});

test("delivery v2: a site can't talk a sender down to version 1 once a device has spoken version 2", async () => {
  const { alice, bob, settle, siteB } = town();
  await alice.post("hello", { to: [bob.id] });
  await settle();
  // Alice loses her session and asks Bob's site for a bundle again. The site strips the version.
  delete alice.sessions[bob.device.kid];
  const real = siteB.bundle.bind(siteB);
  siteB.bundle = (...args) => {
    const b = real(...args);
    return { ...b, signed: { ...b.signed, body: { ...b.signed.body, sessions: undefined } } };
  };
  assert.equal(await code(() => alice.post("again", { to: [bob.id] })), "DOWNGRADE");
});

test("delivery v2: unsigned activities are only for direct envelopes over version 2 sessions", () => {
  const device = { kid: "D".repeat(22), sign: null };
  const actor = { id: "A".repeat(22) };
  const other = "B".repeat(22);
  const a = sessionActivity(device, actor.id, { type: "Create", to: [other], object: { type: "Note", content: "hi" } });
  assert.equal(a.sig, undefined);
  assert.equal(verifySessionActivity(a, actor, { fromDevice: device.kid }).object.content, "hi");
  assert.throws(() => verifySessionActivity(a, actor, { fromDevice: "E".repeat(22) }), { code: "UNTRUSTED" });
  assert.throws(() => verifySessionActivity(a, { id: other }, { fromDevice: device.kid }), { code: "UNTRUSTED" });
  assert.throws(() => verifySessionActivity({ ...a, sig: {} }, actor, { fromDevice: device.kid }), { code: "BAD_MESSAGE" });
  const toFollowers = sessionActivity(device, actor.id, { type: "Create", to: ["followers"], object: { type: "Note", content: "hi" } });
  assert.throws(() => verifySessionActivity(toFollowers, actor, { fromDevice: device.kid }), { code: "UNTRUSTED" });
  const payload = new TextEncoder().encode(canonicalJson({ v: 1, activity: a }));
  assert.throws(() => openDirectPayload(payload, { fromDevice: device.kid, fromActor: actor.id, version: 1 }), { code: "UNTRUSTED" });
  assert.equal(openDirectPayload(payload, { fromDevice: device.kid, fromActor: actor.id, version: 2 }).unsigned.body.id, a.body.id);
  void signActivity;
});
