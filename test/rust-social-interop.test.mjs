// The social protocol (CVP-017 to CVP-021): the Rust port against this implementation. Actor
// documents, activities, lexicons, repositories and envelopes made by either side must check out
// on the other, and every problem list and refusal must be the same.
// Runs against the Rust CLI or WebAssembly build like test/rust-interop.test.mjs; skipped otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { b64u, fromB64u } from "../src/core/bytes.js";
import { generateSigningKey } from "../src/core/signed.js";
import { createAccount, createDevice, signDeviceList, createPrekeys, takeBundle } from "../src/session/keys.js";
import * as v1 from "../src/session/session.js";
import * as v2 from "../src/session/v2.js";
import * as S from "../src/social/index.js";

const CLI = process.env.SECURE_NET_RUST_CLI || fileURLToPath(new URL("../rust/target/debug/examples/cli", import.meta.url));
const WASM = process.env.SECURE_NET_RUST_WASM;
const loaded = WASM ? await import(WASM) : null;
const wasm = loaded && (loaded.call ? loaded : loaded.default);
const skip = wasm || existsSync(CLI) ? false : "the Rust front end isn't built (cd rust && cargo build --example cli)";
const NOW = 1_800_000_000_000;

function rust(req) {
  const input = JSON.stringify({ now: NOW, ...req });
  const out = JSON.parse(wasm ? wasm.call(input) : execFileSync(CLI, { input, maxBuffer: 64 << 20 }).toString());
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
const jsCode = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e.code ?? e.name;
  }
};
const both = (jsFn, req, what) => {
  let js;
  let jsErr = null;
  try {
    js = jsFn();
  } catch (e) {
    jsErr = e.code ?? e.name;
  }
  if (jsErr) assert.equal(rustCode(req), jsErr, what);
  else assert.deepEqual(rust(req), JSON.parse(JSON.stringify(js)), what);
};

function person(handle, kind = "js") {
  if (kind === "js") {
    const account = createAccount();
    const device = createDevice();
    const list = signDeviceList(account, [device], { seq: 1, now: NOW });
    const record = S.createActorDocument(account, { handle, name: "Someone", devices: list, seq: 1, now: NOW });
    return { account, device, list, record, body: S.verifyActorDocument(record), id: S.actorIdOf(account.publicKey) };
  }
  const account = rust({ op: "createAccount" });
  const device = rust({ op: "createDevice" });
  const list = rust({ op: "signDeviceList", account, devices: [{ kid: device.kid, sign: device.sign.publicKey, dh: device.dh.pk }], seq: 1 });
  const record = rust({ op: "social.createActor", account, params: { handle, name: "Someone", devices: list, seq: 1, now: NOW } });
  return { account, device, list, record, body: S.verifyActorDocument(record), id: S.actorIdOf(account.publicKey) };
}

test("vocabulary: the same problems for every activity and object, word for word", { skip }, () => {
  const a = "A".repeat(22);
  const id = `${a}:${"x".repeat(16)}`;
  const note = { type: "Note", id, attributedTo: a, published: NOW, content: "Hi", mediaType: "text/plain" };
  const att = { type: "Image", url: "https://files.example/x", mediaType: "image/png", size: 10, sha256: "h".repeat(43) };
  const activities = [
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["public"], object: note },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["public"], object: { ...note, attachment: [att, { ...att, key: "k".repeat(43) }, null, [], { type: "Gif" }] } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: { ...note, attachment: [att] } },
    { type: "Create", actor: a, id: "bad", published: -1, to: "abc", object: note },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [], cc: [], object: { ...note, type: "org.example.recipe" } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { ...note, type: "Question", oneOf: [{ type: "Note", name: "a" }] } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { ...note, type: "Question", oneOf: [{ type: "Note", name: "a" }, { type: "Note", name: "b" }], anyOf: [] } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { ...note, type: "Event", startTime: "soon", tag: [{ type: "Mention", href: a }, { type: "Hashtag", name: "#ok" }, { type: "Hashtag", name: "# no" }, { type: "Emoji" }], language: "en-GB", sensitive: "yes" } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { ...note, type: ["x.y.z"] } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { ...note, type: "Tombstone", published: "x" } },
    { type: "Create", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: [note] },
    { type: "Update", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: { type: "Person", id: "B".repeat(22) } },
    { type: "Delete", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: ["followers"], object: `${"B".repeat(22)}:${"z".repeat(16)}` },
    { type: "Follow", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: "nope" },
    { type: "Join", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: "group:" + "g".repeat(16) },
    { type: "Move", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: a },
    { type: "Add", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: id, target: 5 },
    { type: "Flag", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: [a], object: a, content: "x".repeat(2001), result: 1 },
    { type: "Dance", actor: a },
    { type: "Like", actor: a, id: `${a}:${"y".repeat(16)}`, published: NOW, to: { x: 1 }, object: id },
    null,
    [],
    "x",
  ];
  for (const act of activities) {
    for (const encrypted of [false, true]) {
      both(() => S.activityProblems(act, { encrypted }), { op: "social.activityProblems", activity: act, encrypted }, JSON.stringify(act)?.slice(0, 120));
    }
  }
});

test("actors: documents made by either side check out on the other, with the same refusals", { skip }, () => {
  for (const h of ["@Alice@A.Example", "alice", "a@b@c", "alice@-bad-.example", "Al ice@a.example", " bob@b.example ", "x@https://c.example/path", "_a.b-c_@d.example:8080", "a.@b.example"]) {
    assert.deepEqual(rust({ op: "social.parseHandle", handle: h }), S.parseHandle(h), h);
  }
  assert.equal(rust({ op: "social.discoveryUrl", handle: "@Al.ice@a.example" }), S.discoveryUrl("@Al.ice@a.example"));
  const js = person("alice@a.example");
  const rs = person("bob@b.example", "rust");
  assert.deepEqual(rust({ op: "social.verifyActor", record: js.record }), js.body);
  const cases = [
    [js.record, { minSeq: 2 }],
    [js.record, { id: rs.id }],
    [js.record, { handle: "bob@b.example" }],
    [{ ...js.record, body: { ...js.record.body, name: "Mallory" } }, {}],
    [{ ...js.record, body: { ...js.record.body, account: rs.account.publicKey } }, {}],
    [{ ...js.record, body: { ...js.record.body, v: 2 } }, {}],
    [{ ...js.record, kind: "other" }, {}],
  ];
  for (const [record, opts] of cases) {
    assert.equal(rustCode({ op: "social.verifyActor", record, ...opts }), jsCode(() => S.verifyActorDocument(record, opts)), JSON.stringify(opts));
  }
  const kid = rs.device.kid;
  assert.equal(rust({ op: "social.deviceKeyAt", actor: rs.body, device: kid, at: NOW }), S.deviceKeyAt(rs.body, kid, NOW));
  assert.equal(rust({ op: "social.deviceKeyAt", actor: rs.body, device: "nope", at: NOW }), S.deviceKeyAt(rs.body, "nope", NOW));
});

test("activities: signed and unsigned activities cross both ways, with the same refusals", { skip }, () => {
  const js = person("alice@a.example");
  const rs = person("bob@b.example", "rust");
  const note = { type: "Create", to: ["public"], object: { type: "Note", content: "Hello", mediaType: "text/plain" } };
  const fromRust = rust({ op: "social.signActivity", device: rs.device, actor: rs.id, activity: note });
  assert.deepEqual(S.verifyActivity(fromRust, rs.body, { now: NOW }), fromRust.body);
  const fromJs = S.signActivity(js.device, js.id, note, { now: NOW });
  assert.deepEqual(rust({ op: "social.verifyActivity", record: fromJs, actorDoc: js.body }), fromJs.body);
  assert.equal(rust({ op: "social.activityDigest", record: fromJs }), S.activityDigest(fromJs));
  const refusals = [
    [fromJs, rs.body, {}],
    [{ ...fromJs, body: { ...fromJs.body, published: NOW + 3600_000 } }, js.body, {}],
    [{ ...fromJs, body: { ...fromJs.body, object: { ...fromJs.body.object, content: "changed" } } }, js.body, {}],
    [fromJs, js.body, { encrypted: true }],
  ];
  for (const [record, doc, opts] of refusals) {
    assert.equal(rustCode({ op: "social.verifyActivity", record, actorDoc: doc, ...opts }), jsCode(() => S.verifyActivity(record, doc, { now: NOW, ...opts })));
  }
  const dm = { type: "Create", to: [js.id], object: { type: "Note", content: "Psst" } };
  const unsigned = rust({ op: "social.sessionActivity", device: rs.device, actor: rs.id, activity: dm });
  assert.equal(unsigned.sig, undefined);
  assert.deepEqual(S.verifySessionActivity(unsigned, rs.body, { fromDevice: rs.device.kid, now: NOW }), unsigned.body);
  for (const [record, from] of [[unsigned, "other"], [{ ...unsigned, body: { ...unsigned.body, to: ["public"] } }, rs.device.kid], [{ ...unsigned, sig: fromJs.sig }, rs.device.kid]]) {
    assert.equal(rustCode({ op: "social.verifySessionActivity", record, actorDoc: rs.body, fromDevice: from }), jsCode(() => S.verifySessionActivity(record, rs.body, { fromDevice: from, now: NOW })));
  }
  assert.equal(rustCode({ op: "social.signActivity", device: rs.device, actor: rs.id, activity: { type: "Create", to: [], object: {} } }), jsCode(() => S.signActivity(js.device, js.id, { type: "Create", to: [], object: {} })));
});

test("lexicons: the same problems, and schemas made by either side verify on the other", { skip }, () => {
  const lexAccount = person("lexicons@example.org");
  const body = { id: "org.example.recipe", revision: 1, fields: { servings: { type: "integer", min: 1, max: 50, required: true }, steps: { type: "array", items: { type: "string", max: 500 } }, by: { type: "actor" } } };
  const bad = [{}, { v: 1, id: "Recipe" }, { v: 1, id: "org.example.recipe", revision: 0, fields: { type: { type: "string" }, Bad: { type: "string" }, list: { type: "array", items: { type: "array" } }, n: { type: "integer", max: -1, min: 0.5, required: "yes" } } }, { v: 1, id: "org.example.recipe", revision: 1, fields: "ab" }, { v: 1, id: "org.example.recipe", revision: 1 }];
  for (const l of [{ v: 1, ...body }, ...bad]) assert.deepEqual(rust({ op: "social.lexiconProblems", lexicon: l }), S.lexiconProblems(l), JSON.stringify(l));
  const rec = rust({ op: "social.createLexicon", account: lexAccount.account, body });
  assert.deepEqual(S.verifyLexicon(rec, lexAccount.body), rec.body);
  const jsRec = S.createLexicon(lexAccount.account, body);
  assert.deepEqual(rust({ op: "social.verifyLexicon", record: jsRec, actorDoc: lexAccount.body }), jsRec.body);
  const other = person("alice@example.org");
  const byOther = S.createLexicon(other.account, body);
  assert.equal(rustCode({ op: "social.verifyLexicon", record: byOther, actorDoc: other.body }), jsCode(() => S.verifyLexicon(byOther, other.body)));
  assert.equal(rustCode({ op: "social.verifyLexicon", record: jsRec, actorDoc: lexAccount.body, minRevision: 2 }), jsCode(() => S.verifyLexicon(jsRec, lexAccount.body, { minRevision: 2 })));
  const a = "A".repeat(22);
  for (const obj of [{ type: "org.example.recipe", servings: 4, steps: ["mix"], by: a }, { type: "org.example.recipe", servings: 99, steps: "mix", extra: 1 }, { type: "org.example.recipe" }, { type: "Note" }]) {
    assert.deepEqual(rust({ op: "social.extensionProblems", object: obj, lexicon: rec.body }), S.extensionProblems(obj, rec.body), JSON.stringify(obj));
  }
});

test("repositories: the same Merkle roots and proofs, and repositories verify on both sides", { skip }, () => {
  const ids = Array.from({ length: 11 }, (_, i) => `id-${i}`);
  assert.equal(rust({ op: "social.merkleRoot", ids }), S.merkleRoot(ids));
  assert.equal(rust({ op: "social.merkleRoot", ids: [] }), S.merkleRoot([]));
  for (const i of [0, 5, 10]) {
    const proof = S.inclusionProof(ids, i);
    assert.deepEqual(rust({ op: "social.inclusionProof", ids, index: i }), proof);
    assert.equal(rust({ op: "social.verifyInclusion", id: ids[i], index: i, count: ids.length, proof, root: S.merkleRoot(ids) }), true);
    assert.equal(rust({ op: "social.verifyInclusion", id: "other", index: i, count: ids.length, proof, root: S.merkleRoot(ids) }), false);
  }
  const rs = person("bob@b.example", "rust");
  let repo = rust({ op: "social.createRepo", actor: rs.id });
  const posts = [];
  for (const text of ["one", "two", "three"]) {
    const rec = rust({ op: "social.signActivity", device: rs.device, actor: rs.id, activity: { type: "Create", to: ["public"], object: { type: "Note", content: text } } });
    posts.push(rec);
    repo = rust({ op: "social.appendToRepo", repo, device: rs.device, record: rec });
  }
  repo = rust({ op: "social.removeFromRepo", repo, device: rs.device, id: posts[1].body.object.id });
  const exported = rust({ op: "social.exportRepo", repo, actorRecord: rs.record });
  const jsView = S.verifyRepo(exported, { now: NOW });
  assert.equal(jsView.records.length, 2);
  assert.deepEqual(rust({ op: "social.verifyRepo", exported }), JSON.parse(JSON.stringify(jsView)));
  for (const bad of [{ ...exported, records: exported.records.slice(1) }, { ...exported, records: [exported.records[1], exported.records[0]] }, { ...exported, records: [...exported.records.slice(0, 1), posts[1]] }]) {
    assert.equal(rustCode({ op: "social.verifyRepo", exported: bad }), jsCode(() => S.verifyRepo(bad, { now: NOW })));
  }
  assert.equal(rustCode({ op: "social.verifyRepo", exported, minSeq: 9 }), jsCode(() => S.verifyRepo(exported, { minSeq: 9, now: NOW })));
});

test("delivery: envelopes, payloads, audiences and sealed sending cross both ways", { skip }, async () => {
  const alice = person("alice@a.example");
  const bob = person("bob@b.example", "rust");
  // Version 1 and 2 sessions from Bob (Rust) to Alice (JavaScript).
  const sessionsFor = async (version) => {
    const prekeys = createPrekeys(alice.device, { oneTime: 2, pqOneTime: 2, now: NOW, sessions: version });
    const bundle = takeBundle(alice.list, structuredClone(prekeys.published), alice.device.kid);
    const me = { device: bob.device, deviceList: bob.list };
    const state = rust({ op: version === 2 ? "v2.initiate" : "initiate", me, bundle, accountKey: alice.account.publicKey });
    return { prekeys, state };
  };
  for (const version of [1, 2]) {
    const { prekeys, state } = await sessionsFor(version);
    const activity = rust({ op: "social.signActivity", device: bob.device, actor: bob.id, activity: { type: "Create", to: [alice.id], object: { type: "Note", content: `v${version}` } }, encrypted: true });
    const sealed = rust({ op: "social.sealDirect", sessions: { [alice.device.kid]: state }, payload: { activity, actor: bob.record } });
    const env = sealed.items[0].envelope;
    assert.deepEqual(S.envelopeProblems(env), []);
    assert.equal(sealed.items[0].to, alice.id);
    const meA = { device: alice.device, deviceList: alice.list, prekeys: prekeys.secrets };
    const r = version === 2 ? await v2.respond({ me: meA, message: env.message, accountKey: bob.account.publicKey, now: NOW }) : await v1.respond({ me: meA, message: env.message, accountKey: bob.account.publicKey });
    const opened = S.openDirectPayload(r.plaintext, { fromDevice: bob.device.kid, fromActor: bob.id, version });
    assert.equal(opened.activity.body.object.content, `v${version}`);
    assert.deepEqual(rust({ op: "social.openDirectPayload", plaintext: b64u(r.plaintext), fromDevice: bob.device.kid, fromActor: bob.id, version }), JSON.parse(JSON.stringify(opened)));
    if (version === 1) {
      assert.equal(env.session, S.sessionTag(r.state));
      assert.equal(rustCode({ op: "social.sealDirect", sessions: { [alice.device.kid]: state }, payload: { delivery: S.newDeliveryToken() } }), "BAD_INPUT");
    }
  }
  // Payloads that must be refused, the same way.
  const enc = (o) => b64u(new TextEncoder().encode(JSON.stringify(o)));
  for (const [payload, version] of [[{ v: 2, activity: {} }, 2], [{ v: 1 }, 2], [{ v: 1, delivery: "short" }, 2], [{ v: 1, delivery: "d".repeat(43) }, 1], [{ v: 1, actor: alice.record }, 2], [{ v: 1, senderKeys: [{ group: `${alice.id}:${"a".repeat(16)}` }] }, 2], [{ v: 1, groups: [{ group: "x", welcome: "w" }] }, 2]]) {
    assert.equal(rustCode({ op: "social.openDirectPayload", plaintext: enc(payload), fromDevice: bob.device.kid, fromActor: bob.id, version }), jsCode(() => S.openDirectPayload(fromB64u(enc(payload)), { fromDevice: bob.device.kid, fromActor: bob.id, version })), JSON.stringify(payload));
  }
  // Audiences: Rust seals to followers, JavaScript opens, and the reverse.
  let audience = rust({ op: "social.createAudience", actor: bob.id });
  const added = rust({ op: "social.addMembers", audience, members: [{ actor: alice.id, device: alice.device.kid }, { actor: "bad", device: "x" }] });
  assert.equal(added.send.to.length, 1);
  audience = added.audience;
  const { acceptDistribution } = await import("../src/session/group.js");
  const aliceView = acceptDistribution(added.send.senderKey, { from: bob.device.kid });
  const post = rust({ op: "social.signActivity", device: bob.device, actor: bob.id, activity: { type: "Create", to: ["followers"], object: { type: "Note", content: "for followers" } }, encrypted: true });
  const sealedA = rust({ op: "social.sealToAudience", audience, record: post });
  const openedA = await S.openAudience(aliceView, sealedA.envelope);
  assert.equal(openedA.activity.body.object.content, "for followers");
  const jsAudience = S.createAudience(alice.id);
  const jsAdded = S.addMembers(jsAudience, [{ actor: bob.id, device: bob.device.kid }]);
  const bobView = rust({ op: "group.accept", distribution: jsAdded.send.senderKey, from: alice.device.kid });
  const jsPost = S.signActivity(alice.device, alice.id, { type: "Create", to: ["followers"], object: { type: "Note", content: "from js" } }, { encrypted: true, now: NOW });
  const jsSealed = await S.sealToAudience(jsAdded.audience, jsPost);
  assert.equal(rust({ op: "social.openAudience", view: bobView, envelope: jsSealed.envelope }).activity.body.object.content, "from js");
  const removed = rust({ op: "social.removeMembers", audience: sealedA.audience, actors: [alice.id] });
  assert.equal(removed.audience.members.length, 0);
  assert.notEqual(removed.audience.key.id, audience.key.id);
  // Sealed sending and site-to-site bodies.
  const token = S.newDeliveryToken();
  assert.equal(rust({ op: "social.deliveryVerifier", token }), S.deliveryVerifier(token));
  const { state } = await sessionsFor(2);
  const env2 = rust({ op: "social.sealDirect", sessions: { [alice.device.kid]: state }, payload: { delivery: token } }).items[0].envelope;
  const items = [{ to: alice.id, envelope: env2, token }];
  assert.deepEqual(rust({ op: "social.sealedBody", items }), S.sealedBody(items));
  const pub = S.publicEnvelope(S.signActivity(alice.device, alice.id, { type: "Create", to: ["public"], object: { type: "Note", content: "hi" } }, { now: NOW }));
  const bodies = [
    { v: 1, items },
    { v: 1, items: [{ ...items[0], extra: 1 }] },
    { v: 1, items: [{ ...items[0], token: "short" }] },
    { v: 1, items: [{ to: alice.id, envelope: pub, token }] },
    { v: 2, items },
    { v: 1, items: [] },
  ];
  for (const body of bodies) both(() => S.readSealedBody(body), { op: "social.readSealedBody", body }, JSON.stringify(body).slice(0, 80));
  for (const body of [{ v: 1, items: [{ to: alice.id, envelope: pub }] }, { v: 1, items: [{ to: "x", envelope: pub }] }, { v: 1, items: [{ to: alice.id, envelope: { ...pub, extra: 1 } }] }]) {
    both(() => S.readDeliveryBody(body), { op: "social.readDeliveryBody", body }, JSON.stringify(body).slice(0, 80));
  }
  const envs = [pub, env2, { v: 1, mode: "direct", device: "x", session: 5, message: {} }, { v: 2, mode: "group", group: "group:" + "g".repeat(16), message: "abc" }, { v: 2, mode: "audience" }, { v: 1, mode: "group" }, { v: 3 }, { v: 1, mode: "audience", audience: `${alice.id}:${"a".repeat(16)}`, message: { v: 1, group: `${alice.id}:${"a".repeat(16)}`, sig: "s" }, note: "x" }, { v: 2, mode: "direct", device: alice.device.kid, message: { v: 2, h: "a", c: "b", y: 1 } }];
  for (const env of envs) both(() => S.envelopeProblems(env), { op: "social.envelopeProblems", envelope: env }, JSON.stringify(env).slice(0, 80));
});
