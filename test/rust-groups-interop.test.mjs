// MLS groups (CVP-022): the Rust port (OpenMLS with the patched suite) against this implementation
// (ts-mls). Saved states differ between the two, but everything on the wire is shared: groups mix
// Rust and JavaScript devices, either side can be the committer, and both refuse the same things.
// Runs against the Rust CLI or WebAssembly build like test/rust-interop.test.mjs; skipped otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as M from "ts-mls";
import { b64u, fromB64u, sha256B64u } from "../src/core/bytes.js";
import { createAccount, createDevice, signDeviceList } from "../src/session/index.js";
import { createActorDocument, verifyActorDocument, actorIdOf } from "../src/social/actor.js";
import * as G from "../src/groups/mls.js";

const CLI = process.env.SECURE_NET_RUST_CLI || fileURLToPath(new URL("../rust/target/debug/examples/cli", import.meta.url));
const WASM = process.env.SECURE_NET_RUST_WASM;
const loaded = WASM ? await import(WASM) : null;
const wasm = loaded && (loaded.call ? loaded : loaded.default);
const skip = wasm || existsSync(CLI) ? false : "the Rust front end isn't built (cd rust && cargo build --example cli)";

function rust(req) {
  const input = JSON.stringify(req);
  const out = JSON.parse(wasm ? wasm.call(input) : execFileSync(CLI, { input, maxBuffer: 256 << 20 }).toString());
  if (out.error) {
    const e = new Error(out.error.message);
    e.code = out.error.code;
    throw e;
  }
  return out.ok;
}
const rustCode = (req) => {
  try {
    rust(req);
    return null;
  } catch (e) {
    return e.code;
  }
};
const jsCode = (p) => p.then(() => null, (e) => e.code);
const text = (b) => new TextDecoder().decode(b);

const directory = new Map();
const actors = (id) => directory.get(id);
const actorsObj = () => Object.fromEntries(directory);

function person(name, { listed = true } = {}) {
  const account = createAccount();
  const device = createDevice();
  const id = actorIdOf(account.publicKey);
  const record = createActorDocument(account, { handle: `${name}@a.example`, type: "Person", name, devices: signDeviceList(account, [device], { seq: 1 }), seq: 1 });
  if (listed) directory.set(id, verifyActorDocument(record, { id }));
  return { name, device, id };
}

// A member is { lang: "js" | "rust", state }. These run the same operation on either side.
const kpFor = async (lang, p) => (lang === "js" ? G.createKeyPackage(p.device, p.id) : rust({ op: "groups.createKeyPackage", device: p.device, actor: p.id }));
const describe = (m) => (m.lang === "js" ? G.describe(m.state) : rust({ op: "groups.describe", state: m.state }));
const create = async (lang, kp) => ({ lang, state: lang === "js" ? await G.createGroup({ keyPackage: kp.secret, actors }) : rust({ op: "groups.createGroup", keyPackage: kp.secret }) });
const join = async (lang, welcome, kp) => ({ lang, state: lang === "js" ? await G.join({ welcome, keyPackage: kp.secret, actors }) : rust({ op: "groups.join", welcome, keyPackage: kp.secret, actors: actorsObj() }) });
async function seal(m, body) {
  const r = m.lang === "js" ? await G.seal(m.state, body) : rust({ op: "groups.seal", state: m.state, plaintext: body });
  m.state = r.state;
  return r.message;
}
async function open(m, message) {
  if (m.lang === "js") {
    const r = await G.open(m.state, message);
    return { state: r.state, kind: r.kind, plaintext: r.plaintext && text(r.plaintext) };
  }
  const r = rust({ op: "groups.open", state: m.state, message, actors: actorsObj() });
  return { state: r.state, kind: r.kind, plaintext: r.plaintext && text(fromB64u(r.plaintext)) };
}
const openCode = (m, message) => (m.lang === "js" ? jsCode(G.open(m.state, message)) : rustCode({ op: "groups.open", state: m.state, message, actors: actorsObj() }));
async function change(m, op, args) {
  if (m.lang === "js") {
    const f = { addMembers: () => G.addMembers(m.state, args.keyPackages), removeMembers: () => G.removeMembers(m.state, (x) => args.actorsOut.includes(x.actor)), replaceMember: () => G.replaceMember(m.state, args.keyPackage), refresh: () => G.refresh(m.state) }[op];
    return f();
  }
  return rust({ op: `groups.${op}`, state: m.state, actors: actorsObj(), ...args });
}

async function say(group, from, body) {
  const message = await seal(group[from], body);
  for (const [k, m] of Object.entries(group)) {
    if (k === from) continue;
    const r = await open(m, message);
    m.state = r.state;
    assert.equal(r.plaintext, body, `${k} (${m.lang}) reads ${from} (${group[from].lang})`);
  }
  return message;
}

async function apply(group, commit, who) {
  for (const k of who) {
    const r = await open(group[k], commit);
    assert.equal(r.kind, "commit");
    group[k].state = r.state;
  }
}

/** A group of three with the given languages; the first creates it and adds the other two. */
async function trio(langs) {
  const people = ["alice", "bob", "carol"].map((n) => person(n));
  const kps = await Promise.all(people.map((p, i) => kpFor(langs[i], p)));
  const a = await create(langs[0], kps[0]);
  const added = await change(a, "addMembers", { keyPackages: [kps[1].published, kps[2].published] });
  a.state = added.state;
  const group = { a, b: await join(langs[1], added.welcome, kps[1]), c: await join(langs[2], added.welcome, kps[2]) };
  return { group, people };
}

const shape = (d) => ({ group: d.group, epoch: d.epoch, members: [...d.members].sort((x, y) => x.leaf - y.leaf) });

for (const langs of [["js", "rust", "js"], ["rust", "js", "rust"], ["rust", "js", "js"], ["js", "rust", "rust"]]) {
  test(`groups interop (${langs.join(", ")}): one group, everyone writes, everyone agrees who is in it`, { skip }, async () => {
    const { group } = await trio(langs);
    const views = Object.values(group).map((m) => shape(describe(m)));
    for (const v of views) assert.deepEqual(v, views[0]);
    assert.deepEqual(views[0].members.map((m) => m.leaf), [0, 1, 2]);
    await say(group, "a", "from the committer");
    await say(group, "b", "from Bob");
    await say(group, "c", "from Carol");
  });

  test(`groups interop (${langs.join(", ")}): remove, refresh, replace and add lock out the right people`, { skip }, async () => {
    const { group, people } = await trio(langs);
    const [, bob, carol] = people;
    await say(group, "c", "before");

    // Carol is removed: her state can't follow.
    const keptCarol = group.c;
    const out = await change(group.a, "removeMembers", { actorsOut: [carol.id] });
    group.a.state = out.state;
    await apply(group, out.commit, ["b"]);
    delete group.c;
    const after = await say(group, "b", "Carol can't read this");
    assert.notEqual(await openCode(keptCarol, after), null);

    // The committer refreshes: a copy of its old state can't follow.
    const stolen = { ...group.a };
    const r = await change(group.a, "refresh", {});
    group.a.state = r.state;
    await apply(group, r.commit, ["b"]);
    assert.notEqual(await openCode(stolen, await say(group, "b", "after the refresh")), null);

    // Bob gets fresh keys: a copy of his old state can't follow.
    const thief = { ...group.b };
    const fresh = await kpFor(group.b.lang, bob);
    const rep = await change(group.a, "replaceMember", { keyPackage: fresh.published });
    group.a.state = rep.state;
    group.b = await join(group.b.lang, rep.welcome, fresh);
    assert.notEqual(await openCode(thief, await say(group, "a", "after the repair")), null);

    // Dave, on the other side from the committer, joins and can't read what came before.
    const dave = person("dave");
    const earlier = await say(group, "b", "before Dave");
    const lang = group.a.lang === "js" ? "rust" : "js";
    const kp = await kpFor(lang, dave);
    const add = await change(group.a, "addMembers", { keyPackages: [kp.published] });
    group.a.state = add.state;
    await apply(group, add.commit, ["b"]);
    group.d = await join(lang, add.welcome, kp);
    assert.notEqual(await openCode(group.d, earlier), null);
    await say(group, "d", "hello, I'm new");
    const views = Object.values(group).map((m) => shape(describe(m)));
    for (const v of views) assert.deepEqual(v, views[0]);
  });
}

test("groups interop: a commit or proposal from anyone but the committer is refused by both", { skip }, async () => {
  // Alice (Rust) commits; Bob (JavaScript) goes around the profile with ts-mls itself.
  const { group, people } = await trio(["rust", "js", "rust"]);
  const cs = await M.getCiphersuiteImpl(M.getCiphersuiteFromName(G.SUITE));
  const carolLeaf = describe(group.b).members.find((m) => m.actor === people[2].id).leaf;
  const rogue = await M.createCommit({ state: group.b.state, cipherSuite: cs }, { extraProposals: [{ proposalType: "remove", remove: { removed: carolLeaf } }] });
  const wire = b64u(M.encodeMlsMessage(rogue.commit));
  const before = describe(group.a);
  assert.equal(await openCode(group.a, wire), "NOT_ALLOWED");
  assert.equal(await openCode(group.c, wire), "NOT_ALLOWED");
  assert.deepEqual(describe(group.a), before);
  const proposal = await M.createProposal(group.b.state, false, { proposalType: "remove", remove: { removed: carolLeaf } }, cs);
  assert.equal(await openCode(group.a, b64u(M.encodeMlsMessage(proposal.message))), "NOT_ALLOWED");
  await say(group, "c", "still here");
  // And the Rust profile won't make such a commit at all.
  assert.equal(rustCode({ op: "groups.refresh", state: group.c.state }), "NOT_ALLOWED");
  assert.equal(rustCode({ op: "groups.removeMembers", state: group.c.state, actorsOut: [people[1].id] }), "NOT_ALLOWED");
});

test("groups interop: key packages are checked the same way on both sides", { skip }, async () => {
  for (const [committer, maker] of [["rust", "js"], ["js", "rust"]]) {
    const { group } = await trio([committer, maker, maker]);
    const stranger = person("stranger", { listed: false });
    const unknown = await kpFor(maker, stranger);
    assert.notEqual(committer === "js" ? await jsCode(change(group.a, "addMembers", { keyPackages: [unknown.published] })) : rustCode({ op: "groups.addMembers", state: group.a.state, keyPackages: [unknown.published], actors: actorsObj() }), null, "an actor we hold no document for");
    const erin = person(`erin-${committer}`);
    const forged = await kpFor(maker, { device: createDevice(), id: erin.id });
    assert.notEqual(committer === "js" ? await jsCode(change(group.a, "addMembers", { keyPackages: [forged.published] })) : rustCode({ op: "groups.addMembers", state: group.a.state, keyPackages: [forged.published], actors: actorsObj() }), null, "a device that isn't on Erin's list");
    const real = await kpFor(maker, erin);
    assert.deepEqual(rust({ op: "groups.keyPackageOwner", published: real.published }), G.keyPackageOwner(real.published));
    const ok = await change(group.a, "addMembers", { keyPackages: [real.published] });
    assert.equal((committer === "js" ? G.describe(ok.state) : rust({ op: "groups.describe", state: ok.state })).members.length, 4);
  }
});

test("groups interop: the credential check gives the same answer on both sides", { skip }, async () => {
  const erin = person("erin-cred");
  const service = G.authService(actors);
  const real = await G.createKeyPackage(erin.device, erin.id);
  const other = await G.createKeyPackage(erin.device, erin.id);
  const leafOf = (kp) => M.decodeMlsMessage(fromB64u(kp.published), 0)[0].keyPackage.leafNode;
  const leaf = leafOf(real);
  const otherKey = leafOf(other).signaturePublicKey;
  const record = JSON.parse(text(leaf.credential.identity));
  record.body.key = sha256B64u(otherKey);
  const cases = [
    [leaf.credential.identity, leaf.signaturePublicKey],
    [leaf.credential.identity, otherKey],
    [new TextEncoder().encode("erin"), leaf.signaturePublicKey],
    [new TextEncoder().encode(JSON.stringify(record)), otherKey],
  ];
  for (const [identity, key] of cases) {
    const js = await service.validateCredential({ credentialType: "basic", identity }, key);
    assert.equal(rust({ op: "groups.validateCredential", identity: b64u(identity), key: b64u(key), actors: actorsObj() }), js);
  }
});

test("groups interop: a message opens once, a bent one never, and junk is refused alike", { skip }, async () => {
  const { group } = await trio(["js", "rust", "rust"]);
  const m = await seal(group.a, "once");
  const r = await open(group.b, m);
  assert.equal(r.plaintext, "once");
  assert.notEqual(await openCode({ ...group.b, state: r.state }, m), null, "a second copy is refused");
  const i = Math.floor(m.length / 2);
  const bent = m.slice(0, i) + (m[i] === "A" ? "B" : "A") + m.slice(i + 1);
  assert.notEqual(await openCode(group.c, bent), null);
  assert.equal((await open(group.c, m)).plaintext, "once");
  assert.equal(await openCode(group.c, "AAAA"), await jsCode(G.open(group.a.state, "AAAA")));
  assert.equal(await openCode(group.c, "AAAA"), "BAD_MESSAGE");
});

test("groups interop: a Rust device won't join an MLS group that isn't a Secure Net group", { skip }, async () => {
  // A ts-mls group made around the profile, with an id that isn't `group:...`.
  const alice = person("alice-odd");
  const bob = person("bob-odd");
  const cs = await M.getCiphersuiteImpl(M.getCiphersuiteFromName(G.SUITE));
  const own = await G.createKeyPackage(alice.device, alice.id);
  const keys = {
    initPrivateKey: fromB64u(own.secret.keys.init),
    hpkePrivateKey: fromB64u(own.secret.keys.hpke),
    signaturePrivateKey: fromB64u(own.secret.keys.sign),
  };
  const kp = M.decodeMlsMessage(fromB64u(own.published), 0)[0].keyPackage;
  for (const id of ["not-a-group", "group:short"]) {
    const state = await M.createGroup(new TextEncoder().encode(id), kp, keys, [], cs);
    const theirs = await kpFor("rust", bob);
    const r = await M.createCommit({ state, cipherSuite: cs }, { extraProposals: [{ proposalType: "add", add: { keyPackage: M.decodeMlsMessage(fromB64u(theirs.published), 0)[0].keyPackage } }], ratchetTreeExtension: true });
    const welcome = b64u(M.encodeMlsMessage({ welcome: r.welcome, wireformat: "mls_welcome", version: "mls10" }));
    assert.equal(rustCode({ op: "groups.join", welcome, keyPackage: theirs.secret, actors: actorsObj() }), "BAD_MESSAGE", id);
  }
});
