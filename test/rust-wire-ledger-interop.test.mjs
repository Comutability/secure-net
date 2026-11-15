// The wire, tokens, commons ledger, governance, portable identity, consent and extensions: the
// Rust port against this implementation. Every site must reach the same verdict on the same
// records, so these compare results, states and refusal codes, not just that each side works.
// Runs against the Rust CLI or WebAssembly build like test/rust-interop.test.mjs; skipped otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { b64u, fromB64u, sha256B64u } from "../src/core/bytes.js";
import { generateSigningKey } from "../src/core/signed.js";
import * as fed from "../src/wire/federation.js";
import * as feat from "../src/wire/features.js";
import { relaySuite, relayKeysOf } from "../src/wire/sealed.js";
import * as tok from "../src/tokens/voprf.js";
import * as L from "../src/commons/ledger.js";
import * as V from "../src/governance/vote.js";
import * as D from "../src/governance/debate.js";
import * as P from "../src/identity/portable.js";
import * as C from "../src/consent/capsule.js";
import * as X from "../src/extensions/manifest.js";

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
const keysOf = (...ks) => Object.fromEntries(ks.map((k) => [k.kid, k.publicKey]));
const key = () => generateSigningKey();

test("Ed25519: both sides accept exactly the same signatures (ZIP-215, all 196 small-order cases)", { skip }, () => {
  // The eight small-order points, and the six other (non-canonical) encodings of them: the 14
  // encodings ZIP-215 was written to settle, tried as every key and R pair with S = 0.
  const ff = "ff".repeat(30);
  const hex = [
    "01" + "00".repeat(31),
    "ec" + ff + "7f",
    "00".repeat(32),
    "00".repeat(31) + "80",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "01" + "00".repeat(30) + "80",
    "ec" + ff + "ff",
    "ed" + ff + "7f",
    "ed" + ff + "ff",
    "ee" + ff + "7f",
    "ee" + ff + "ff",
  ];
  const list = hex.map((h) => b64u(Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)))));
  assert.equal(new Set(list).size, 14);
  const msg = new TextEncoder().encode("Zcash");
  let agree = 0;
  let accepted = 0;
  for (const A of list) {
    for (const R of list) {
      const sig = new Uint8Array(64);
      sig.set(fromB64u(R), 0);
      let js;
      try {
        js = ed25519.verify(sig, msg, fromB64u(A));
      } catch {
        js = false;
      }
      const rs = rust({ op: "ed25519.verify", publicKey: A, signature: b64u(sig), message: b64u(msg) });
      assert.equal(rs, js, `A=${A} R=${R}`);
      agree += 1;
      accepted += js ? 1 : 0;
    }
  }
  assert.equal(agree, 196);
  assert.ok(accepted > 0, "some small-order cases are accepted by both under ZIP-215");
  // S at or above the group order is refused by both.
  const k = key();
  const good = fromB64u(L.makeBlock(L.emptyState(), [{ type: "note" }], k).sig.value);
  const big = good.slice();
  big.set(new Uint8Array(32).fill(255), 32);
  assert.equal(rust({ op: "ed25519.verify", publicKey: k.publicKey, signature: b64u(big), message: b64u(msg) }), false);
});

test("times: Date.parse and the Rust parser agree on every form the protocol uses", { skip }, () => {
  const forms = ["2026-11-15T10:00:00.000Z", "2026-11-15T10:00:00Z", "2026-11-15T10:00Z", "2026-11-15", "2026-11", "2026", "2026-11-15T10:00:00.5Z", "2026-11-15T10:00:00.123456Z", "2026-11-15T11:00:00+01:00", "2026-11-15T09:00:00-01:00", "2024-02-29T00:00:00Z", "2026-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "nonsense", "", "2026-11-15T25:00:00Z", "2026-02-31T00:00:00Z", "2026-04-31", "2026-02-32", "2026-02-00", "2026-00-10", "2026-11-15T24:00:00Z", "2026-11-15T24:00:01Z", "2026-11-15T23:60:00Z", "+002026-11-15T00:00:00Z", "-000001-01-01T00:00:00Z", "2026-11-15T10:00:00.Z", "2026-11-15T10:00:00+0100", "2026-11-15T10:00:00+01", "2026-11-15t10:00:00z", "2026-11-15T1:00:00Z", "Sun, 15 Nov 2026 10:00:00 GMT", "Mon, 15 Nov 2026 10:00:00 UTC", "15 Nov 2026 10:00:00 GMT", "Sun, 5 Nov 2026 10:00:00 GMT", new Date(NOW).toUTCString()];
  for (const f of forms) {
    const js = Date.parse(f);
    assert.equal(rust({ op: "js.dateParse", text: f }), Number.isFinite(js) ? js : null, f);
  }
});

test("wire: endpoints, addresses, signed requests and features agree", { skip }, () => {
  for (const doc of [{}, null, { endpoints: { act: "/x/act", inbox: "https://evil.example/inbox", directory: "/a//b", discover: "/a/../b", actors: "/a b" } }, { endpoints: "nope" }]) {
    assert.deepEqual(rust({ op: "wire.endpointsOf", doc }), fed.endpointsOf(doc));
  }
  for (const h of ["Example.ORG", "https://site.example/path", "http://a.b:8080/x", "a..b", "-bad.example", "x".repeat(254), "site.example:123456", "  spaced.example  ", "bad_host.example", "ok.example:"]) {
    assert.equal(rust({ op: "wire.normHost", host: h }), fed.normHost(h), h);
  }
  for (const ip of ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1", "172.32.0.1", "100.64.0.1", "8.8.8.8", "224.0.0.1", "::1", "[fe80::1]", "::ffff:10.0.0.1", "2001:db8::1", "172.20.0.1", "172.31.255.255", "01.2.3.4", "001.2.3.4", "256.1.1.1", "fd00::1"]) {
    assert.equal(rust({ op: "wire.isPrivate", ip }), fed.isPrivate(ip), ip);
  }
  const site = key();
  const fields = { method: "post", to: "b.example", path: "/cvp/v1/act", from: "a.example", date: "2026-11-15T10:00:00.000Z", nonce: "n1", digest: fed.digestOf("{}"), user: "" };
  assert.equal(rust({ op: "wire.digestOf", body: "{}" }), fed.digestOf("{}"));
  assert.equal(rust({ op: "wire.signatureBase", fields }), fed.signatureBase(fields));
  const jsSig = fed.signRequest(fields, site.secretKey);
  assert.equal(rust({ op: "wire.signRequest", fields, secretKey: site.secretKey }), jsSig, "Ed25519 signatures are deterministic");
  assert.equal(rust({ op: "wire.verifyRequest", fields, signature: jsSig, publicKey: site.publicKey }), true);
  assert.equal(rust({ op: "wire.verifyRequest", fields: { ...fields, path: "/other" }, signature: jsSig, publicKey: site.publicKey }), false);
  const t = Date.parse(fields.date);
  for (const now of [t, t + fed.SKEW_MS, t + fed.SKEW_MS + 1, t - fed.SKEW_MS - 1]) assert.equal(rust({ op: "wire.freshEnough", date: fields.date, now }), fed.freshEnough(fields.date, now));
  assert.deepEqual(rust({ op: "wire.features" }), feat.FEATURES);
  assert.deepEqual(rust({ op: "wire.describeSite" }), feat.describeSite());
  const theirs = { "cvp.sessions": 1, "cvp.unknown": 5, "cvp.tokens": 0, "cvp.governance": "1" };
  assert.deepEqual(rust({ op: "wire.negotiate", ours: feat.FEATURES, theirs }), feat.negotiate(feat.FEATURES, theirs));
});

test("sealed relay: each side opens what the other sealed, replies included, and checks its signatures", { skip }, async () => {
  const js = relaySuite({ ml_kem768, ml_dsa65 });
  const jsKeys = await js.generateKeys();
  const rsKeys = rust({ op: "relay.generateKeys" });
  const ctx = rust({ op: "relay.context", from: "a.example", to: "b.example", path: "/cvp/v2/sealed" });
  assert.ok(relayKeysOf({ pq: { suite: "p256-mlkem768+mldsa65", kem: rsKeys.kem.public, sig: rsKeys.sig.public } }), "Rust's keys pass the JavaScript's shape check");
  assert.deepEqual(rust({ op: "relay.keysOf", doc: { pq: { suite: "p256-mlkem768+mldsa65", kem: jsKeys.kem.public, sig: jsKeys.sig.public } } }), relayKeysOf({ pq: { suite: "p256-mlkem768+mldsa65", kem: jsKeys.kem.public, sig: jsKeys.sig.public } }));

  const toRust = await js.seal(rsKeys.kem.public, "hello from js", ctx);
  const opened = rust({ op: "relay.open", secret: rsKeys.kem.secret, sealed: toRust.sealed, context: ctx });
  assert.equal(opened.text, "hello from js");
  const reply = rust({ op: "relay.sealReply", replyKey: opened.replyKey, text: "reply from rust", context: ctx });
  assert.equal(await js.openReply(toRust.replyKey, reply, ctx), "reply from rust");
  assert.equal(rustCode({ op: "relay.open", secret: rsKeys.kem.secret, sealed: toRust.sealed, context: ctx + "x" }), "CANNOT_OPEN");

  const toJs = rust({ op: "relay.seal", public: jsKeys.kem.public, text: "hello from rust", context: ctx });
  const back = await js.open(jsKeys.kem.secret, toJs.sealed, ctx);
  assert.equal(back.text, "hello from rust");
  const jsReply = await js.sealReply(back.replyKey, "reply from js", ctx);
  assert.equal(rust({ op: "relay.openReply", replyKey: toJs.replyKey, sealed: jsReply, context: ctx }), "reply from js");

  const base = "commonveil-request/v1\nPOST\nb\n/p\na\nd\nn\nsha-256=x\n-";
  assert.equal(rust({ op: "relay.verify", public: jsKeys.sig.public, text: base, signature: js.sign(jsKeys.sig.secret, base) }), true);
  assert.ok(js.verify(rsKeys.sig.public, base, rust({ op: "relay.sign", secret: rsKeys.sig.secret, text: base })));
  assert.equal(rust({ op: "relay.verify", public: jsKeys.sig.public, text: base + "x", signature: js.sign(jsKeys.sig.secret, base) }), false);
});

test("tokens: the same issuer keys from a seed, and tokens cross both ways with the same refusals", { skip }, () => {
  const seed = new Uint8Array(32).fill(9);
  const jsKey = tok.issuerKey(seed, "vote-1");
  const rsKey = rust({ op: "tokens.issuerKey", seed: b64u(seed), scope: "vote-1" });
  assert.deepEqual(rsKey, jsKey, "RFC 9497 DeriveKeyPair gives the same key");
  assert.equal(rust({ op: "tokens.fingerprint", publicKey: jsKey.publicKey }), tok.keyFingerprint(jsKey.publicKey));

  // JavaScript client, Rust issuer.
  const req = tok.requestTokens(3);
  const resp = rust({ op: "tokens.issue", key: rsKey, request: req.request });
  const tokens = tok.finishTokens(req.pending, resp, jsKey.publicKey);
  for (const t of tokens) assert.ok(tok.checkToken(jsKey, t) && rust({ op: "tokens.check", key: rsKey, token: t }));
  // Rust client, JavaScript issuer.
  const rreq = rust({ op: "tokens.request", n: 2 });
  const jresp = tok.issueTokens(jsKey, rreq.request);
  const rtokens = rust({ op: "tokens.finish", pending: rreq.pending, response: jresp, publicKey: jsKey.publicKey });
  for (const t of rtokens) {
    assert.ok(tok.checkToken(jsKey, t));
    assert.equal(rust({ op: "tokens.nullifier", token: t }), tok.nullifier(t));
  }
  // A proof against another key is refused; a forged or spent token is refused.
  const other = tok.issuerKey(new Uint8Array(32).fill(1), "vote-1");
  assert.equal(rustCode({ op: "tokens.finish", pending: rreq.pending, response: jresp, publicKey: other.publicKey }), jsCode(() => tok.finishTokens(rreq.pending, jresp, other.publicKey)));
  const spent = rust({ op: "tokens.spend", key: rsKey, token: rtokens[0] }).spent;
  assert.equal(rustCode({ op: "tokens.spend", key: rsKey, token: rtokens[0], spent }), "SPENT");
  assert.equal(rustCode({ op: "tokens.spend", key: rsKey, token: { ...rtokens[1], output: rtokens[0].output } }), "INVALID");
  assert.equal(rustCode({ op: "tokens.request", n: 65 }), jsCode(() => tok.requestTokens(65)));
});

// ---- The commons ledger ----

const entry = (k, caps = ["authority"]) => ({ kid: k.kid, pub: k.publicKey, caps });
const site = (name, k) => ({ site: name, kid: k.kid, pub: k.publicKey });
const AT = "2026-11-15T10:00:00.000Z";

function community({ threshold = 1, policy = {} } = {}) {
  const [alice, bob, carol, homeKey, r1Key, r2Key] = [key(), key(), key(), key(), key(), key()];
  const spec = { name: "Allotment Society", keys: [entry(alice), entry(bob), entry(carol)], threshold, home: site("home.example", homeKey), replicas: [site("one.example", r1Key), site("two.example", r2Key)], succession: ["one.example", "two.example"], policy };
  const g = L.genesis(spec, alice, { cosigners: threshold > 1 ? [bob, carol].slice(0, threshold - 1) : [], at: AT });
  return { alice, bob, carol, homeKey, r1Key, r2Key, spec, chain: [g], state: L.replay([g]) };
}

/** Add a block made by JavaScript or Rust, alternately, and check both sides agree on the state. */
function push(c, events, signer, opts = {}, maker = "js") {
  const b = maker === "js" ? L.makeBlock(c.state, events, signer, { at: AT, ...opts }) : rust({ op: "ledger.makeBlock", state: c.state, events, key: signer, cosigners: opts.cosigners || [], at: AT });
  c.chain.push(b);
  c.state = L.replay(c.chain);
  assert.deepEqual(rust({ op: "ledger.replay", blocks: c.chain }), c.state, "both sides replay to the same state");
  return b;
}

function sameVerdict(c, block, what) {
  const j = jsCode(() => L.applyBlock(c.state, block));
  const r = rustCode({ op: "ledger.apply", state: c.state, block });
  assert.equal(r, j, what);
  return j;
}

test("ledger: a community's history replays to the same state on both sides, blocks made by either", { skip }, () => {
  const c = community({ threshold: 2 });
  assert.deepEqual(rust({ op: "ledger.replay", blocks: c.chain }), c.state);
  const gRust = rust({ op: "ledger.genesis", spec: c.spec, key: c.alice, cosigners: [c.bob], at: AT });
  assert.equal(L.replay([gRust]).threshold, 2, "a Rust genesis replays in JavaScript");
  const [dan, erin] = [key(), key()];
  push(c, [{ type: "channel.set", channel: "general", name: "General" }], c.alice);
  push(c, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.homeKey, {}, "rust");
  push(c, [{ type: "member.add", member: erin.kid, pub: erin.publicKey }, { type: "role.set", member: erin.kid, roles: ["gardener"] }], c.bob);
  push(c, [{ type: "content.ref", channel: "general", ref: "blob:1", sealed: "ct" }], dan, {}, "rust");
  push(c, [{ type: "note", text: "hello" }], erin);
  push(c, [{ type: "ban.set", member: dan.kid, banned: true }], c.carol, {}, "rust");
  push(c, [{ type: "member.remove", member: erin.kid }], erin);
  const newKey = key();
  push(c, [{ type: "keys.set", keys: [entry(c.alice), entry(c.bob), entry(newKey)], threshold: 2 }], c.alice, { cosigners: [c.bob] }, "rust");
  push(c, [{ type: "host.move", home: site("new-home.example", c.homeKey) }], c.alice, { cosigners: [newKey] });
  assert.equal(c.state.epoch, 2);
  assert.deepEqual(rust({ op: "ledger.describe", state: c.state }), L.describe(c.state));
});

test("ledger: every refusal is the same on both sides", { skip }, () => {
  const c = community({ threshold: 2 });
  const dan = key();
  push(c, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.homeKey);
  const mk = (events, signer, opts = {}) => L.makeBlock(c.state, events, signer, { at: AT, ...opts });
  const good = mk([{ type: "note" }], c.alice);
  const cases = [
    ["wrong prev", { ...good, body: { ...good.body, prev: "x" } }],
    ["wrong height", { ...good, body: { ...good.body, height: 7 } }],
    ["height as text", { ...good, body: { ...good.body, height: String(good.body.height) } }],
    ["wrong epoch", { ...good, body: { ...good.body, epoch: 1 } }],
    ["unknown signer", mk([{ type: "note" }], key())],
    ["bad signature", { ...good, sig: { ...good.sig, value: mk([{ type: "note", x: 1 }], c.alice).sig.value } }],
    ["one authority signature is too few", mk([{ type: "replicas.set", replicas: [], succession: [] }], c.alice)],
    ["a member can't set channels", mk([{ type: "channel.set", channel: "x" }], dan)],
    ["a member can't remove others", mk([{ type: "member.remove", member: c.alice.kid }], dan)],
    ["unknown event", mk([{ type: "magic" }], c.alice)],
    ["no events", mk([], c.alice)],
    ["second genesis", mk([{ type: "commons.genesis", name: "x" }], c.alice)],
    ["bad keys", mk([{ type: "keys.set", keys: [{ kid: "nope", pub: c.alice.publicKey, caps: ["authority"] }], threshold: 1 }], c.alice, { cosigners: [c.bob] })],
    ["threshold too high", mk([{ type: "keys.set", keys: [entry(c.alice)], threshold: 2 }], c.alice, { cosigners: [c.bob] })],
    ["unknown capability", mk([{ type: "keys.set", keys: [entry(c.alice, ["wizard"])], threshold: 1 }], c.alice, { cosigners: [c.bob] })],
    ["replica with authority", mk([{ type: "replicas.set", replicas: [{ ...site("r.example", dan), caps: ["authority"] }], succession: [] }], c.alice, { cosigners: [c.bob] })],
    ["succession outside replicas", mk([{ type: "replicas.set", replicas: [], succession: ["x.example"] }], c.alice, { cosigners: [c.bob] })],
    ["member id doesn't match key", mk([{ type: "member.add", member: "nope", pub: dan.publicKey }], c.alice)],
    ["no such channel", mk([{ type: "content.ref", channel: "missing" }], c.alice)],
    ["unknown authority rule", mk([{ type: "policy.set", policy: { authority_change: "dice" } }], c.alice, { cosigners: [c.bob] })],
    ["vote result not from the community", mk([{ type: "governance.result", result: V.signResult({ motion: "m", passed: true }, dan) }], c.alice)],
    ["wrong kind", { ...good, kind: "commons.other" }],
    ["not an object", null],
  ];
  for (const [what, block] of cases) assert.ok(sameVerdict(c, block, what), `${what} is refused`);
  push(c, [{ type: "ban.set", member: dan.kid, banned: true }], c.alice);
  assert.ok(sameVerdict(c, L.makeBlock(c.state, [{ type: "member.add", member: dan.kid, pub: dan.publicKey }], c.alice, { at: AT }), "banned"));
});

test("ledger: authority changes by vote need a matching mandate on both sides", { skip }, () => {
  const c = community({ policy: { authority_change: "vote" } });
  const change = { type: "replicas.set", replicas: [], succession: [] };
  const motion = V.propose({ community: c.state.community, title: "Drop replicas", options: [{ id: "yes" }, { id: "no" }], opens: "2026-11-01T00:00:00Z", closes: "2026-11-02T00:00:00Z", eligible: [c.alice.kid], action: L.actionHash(change) }, c.alice);
  assert.equal(rust({ op: "ledger.actionHash", event: change }), L.actionHash(change));
  const ballot = V.castBallot(motion, "yes", c.alice);
  const body = V.tally(motion, [{ ballot, at: "2026-11-01T12:00:00Z" }], { keyFor: (k) => keysOf(c.alice)[k] });
  const result = V.signResult(body, c.alice);
  push(c, [{ type: "governance.result", result }], c.alice, {}, "rust");
  const mandate = Object.keys(c.state.results)[0];
  const without = L.makeBlock(c.state, [change], c.alice, { at: AT });
  assert.equal(sameVerdict(c, without, "no mandate"), "NO_MANDATE");
  const other = L.makeBlock(c.state, [{ ...change, note: "not what was voted on", mandate }], c.alice, { at: AT });
  assert.equal(sameVerdict(c, other, "mandate for a different change"), "NO_MANDATE");
  push(c, [{ ...change, mandate }], c.alice, {}, "rust");
  assert.deepEqual(c.state.replicas, []);
});

test("ledger: forks reconcile the same way, with the same evidence", { skip }, () => {
  const c = community({ threshold: 1 });
  push(c, [{ type: "note" }], c.alice);
  const base = c.chain.slice();
  const a = [...base, L.makeBlock(c.state, [{ type: "note", text: "a" }], c.alice, { at: AT })];
  const b = [...base, L.makeBlock(c.state, [{ type: "note", text: "b" }], c.alice, { at: AT, cosigners: [c.bob] })];
  const longer = [...a, L.makeBlock(L.replay(a), [{ type: "note" }], c.bob, { at: AT })];
  for (const [local, remote] of [[a, b], [b, a], [a, longer], [longer, b], [base, a], [a, a], [a, [...a.slice(0, -1), { ...a.at(-1), sig: b.at(-1).sig }]]]) {
    assert.deepEqual(rust({ op: "ledger.reconcile", local, remote }), L.reconcile(local, remote));
  }
});

test("ledger: hosts and failover are chosen the same way", { skip }, () => {
  const c = community();
  const t = Date.parse(AT);
  const ann = [
    L.announceHost(c.state, { site: "one.example", role: "acting", at: AT }, c.r1Key),
    rust({ op: "ledger.announceHost", state: c.state, site: "two.example", role: "acting", validForS: 600, at: t, siteKey: c.r2Key }),
    L.announceHost(c.state, { site: "one.example", role: "acting", at: "2026-11-15T09:00:00.000Z" }, c.r1Key),
    L.announceHost(c.state, { site: "evil.example", role: "acting", at: AT }, key()),
  ];
  assert.deepEqual(ann[1], L.announceHost(c.state, { site: "two.example", role: "acting", at: AT }, c.r2Key), "announcements are deterministic");
  for (const [now, unreachable] of [[t, []], [t, ["home.example"]], [t, ["home.example", "one.example"]], [t + 3600_000, ["home.example"]], [t, ["home.example", "one.example", "two.example"]]]) {
    assert.deepEqual(rust({ op: "ledger.chooseHost", state: c.state, announcements: ann, now, unreachable }), L.chooseHost(c.state, ann, { now, unreachable: new Set(unreachable) }), JSON.stringify(unreachable));
  }
});

// ---- Governance ----

test("votes: every counting method gives the same result on both sides, and results recount", { skip }, () => {
  const voters = Array.from({ length: 7 }, key);
  const keys = keysOf(...voters);
  const options = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "d" }];
  const choices = {
    majority: ["a", "a", "b", "a", "c", "b", "a"],
    supermajority: ["a", "a", "b", "a", "b", "b", "a"], // 3 of 5 counted: a majority, not two thirds
    approval: [["a", "b"], ["b"], ["c", "a"], ["a"], ["b", "c", "d"], ["d"], ["a", "d"]],
    ranked: [["a", "b"], ["b", "a"], ["c", "b", "a"], ["d", "c"], ["b"], ["c", "a"], ["a", "c", "b"]],
  };
  for (const method of V.METHODS) {
    const motion = V.propose({ community: "c1", title: `A ${method} vote`, options, method, threshold: { num: 2, den: 3 }, quorum: 3, opens: "2026-11-01T00:00:00Z", closes: "2026-11-08T00:00:00Z", eligible: voters.slice(0, 6).map((v) => v.kid) }, voters[0]);
    const received = voters.map((v, i) => ({ ballot: V.castBallot(motion, choices[method][i], v), at: "2026-11-02T00:00:00Z" }));
    received.push({ ballot: V.castBallot(motion, choices[method][1], voters[1], 2), at: "2026-11-03T00:00:00Z" }); // a changed vote
    received.push({ ballot: V.castBallot(motion, choices[method][0], voters[2], 1), at: "2026-11-03T00:00:00Z" }); // a clash at the same seq
    received.push({ ballot: V.castBallot(motion, choices[method][0], voters[3]), at: "2026-11-09T00:00:00Z" }); // too late
    const honest = V.castBallot(motion, choices[method][4], voters[4], 9);
    received.push({ ballot: { ...honest, body: { ...honest.body, choice: choices[method][0] } }, at: "2026-11-03T00:00:00Z" }); // altered after signing
    const js = V.tally(motion, received, { keyFor: (k) => keys[k] });
    assert.deepEqual(rust({ op: "vote.tally", motion, received, keys }), js, method);
    const result = V.signResult(js, voters[0]);
    assert.deepEqual(rust({ op: "vote.verifyResult", motion, result, received, keys, tallierKey: voters[0].publicKey }), js);
    const forged = V.signResult({ ...js, passed: !js.passed }, voters[0]);
    assert.equal(rustCode({ op: "vote.verifyResult", motion, result: forged, received, keys, tallierKey: voters[0].publicKey }), "MISCOUNT");
  }
  const rsMotion = rust({ op: "vote.propose", params: { community: "c1", title: "From Rust", options, opens: "2026-11-01T00:00:00Z", closes: "2026-11-02T00:00:00Z", eligible: [voters[0].kid] }, key: voters[0] });
  assert.deepEqual(V.checkMotion(rsMotion, (k) => keys[k]), rsMotion.body);
  for (const bad of [{ title: "" }, { options: [{ id: "a" }] }, { method: "dice" }, { opens: "2026-11-03T00:00:00Z" }, { ballot: "secret" }, { eligible: [] }, { options: [{ id: "a" }, { id: "a" }] }]) {
    const params = { community: "c1", title: "t", options, opens: "2026-11-01T00:00:00Z", closes: "2026-11-02T00:00:00Z", eligible: [voters[0].kid], ...bad };
    assert.equal(rustCode({ op: "vote.propose", params, key: voters[0] }), jsCode(() => V.propose(params, voters[0])), JSON.stringify(bad));
  }
});

test("votes: secret ballots with tokens count the same on both sides", { skip }, () => {
  const seed = new Uint8Array(32).fill(4);
  const issuer = tok.issuerKey(seed, "vote-2");
  const proposer = key();
  const motion = V.propose({ community: "c1", title: "Secret", options: [{ id: "yes" }, { id: "no" }], ballot: "secret", issuer: { publicKey: issuer.publicKey }, opens: "2026-11-01T00:00:00Z", closes: "2026-11-02T00:00:00Z", eligible: ["x"] }, proposer);
  const req = tok.requestTokens(4);
  const tokens = tok.finishTokens(req.pending, tok.issueTokens(issuer, req.request), issuer.publicKey);
  const received = [
    ...tokens.map((t, i) => ({ ballot: V.castSecretBallot(motion, i === 3 ? "no" : "yes", t), at: "2026-11-01T10:00:00Z" })),
    { ballot: V.castSecretBallot(motion, "yes", tokens[0]), at: "2026-11-01T11:00:00Z" },
    { ballot: V.castSecretBallot(motion, "yes", { ...tokens[1], output: tokens[2].output }), at: "2026-11-01T11:00:00Z" },
  ];
  const js = V.tally(motion, received, { issuerKey: issuer, spent: new Set() });
  assert.deepEqual(rust({ op: "vote.tally", motion, received, issuerKey: issuer }), js);
  assert.equal(js.total, 4);
  assert.equal(js.spoiled, 2);
});

test("debates: the same tree, thread and refusals on both sides", { skip }, () => {
  const [mod, ann, ben, out] = [key(), key(), key(), key()];
  const keys = keysOf(mod, ann, ben, out);
  const motion = V.propose({ community: "c1", title: "Plant an orchard?", options: [{ id: "yes" }, { id: "no" }], opens: "2026-11-01T00:00:00Z", closes: "2026-11-09T00:00:00Z", eligible: [ann.kid, ben.kid] }, mod);
  const mid = V.motionId(motion);
  const at = (h) => `2026-11-0${h}T10:00:00.000Z`;
  const round = D.post("debate.round", { motion: mid, name: "Opening", phase: "open", opens: at(1), closes: at(8), who: "all" }, mod);
  const pos = D.post("debate.position", { motion: mid, side: "yes", statement: "We should.", at: at(2) }, ann);
  const arg = rust({ op: "debate.post", kind: "debate.argument", body: { motion: mid, side: "yes", claim: "Fruit for everyone", detail: "Apples and pears." }, key: ann, at: at(3) });
  const reb = D.post("debate.rebuttal", { motion: mid, target: D.itemId(arg), claim: "Too much work", at: at(4) }, ben);
  const ev = D.post("debate.evidence", { motion: mid, target: D.itemId(reb), source: "https://example.org/orchards", at: at(5) }, ann);
  const sub = D.post("debate.argument", { motion: mid, side: "no", claim: "Shade", parent: D.itemId(arg), at: at(3) }, ben);
  const hide = D.post("debate.moderation", { motion: mid, target: D.itemId(ev), action: "hide", reason: "Off topic", at: at(6) }, mod);
  const orphan = D.post("debate.rebuttal", { motion: mid, target: "missing", claim: "Nothing to answer", at: at(4) }, ben);
  const toPosition = D.post("debate.rebuttal", { motion: mid, target: D.itemId(pos), claim: "Positions take no replies", at: at(4) }, ben);
  const outsider = D.post("debate.position", { motion: mid, side: "no", statement: "Let me in", at: at(2) }, out);
  const fakeMod = D.post("debate.moderation", { motion: mid, target: D.itemId(pos), action: "hide", at: at(6) }, ann);
  const malformed = D.post("debate.argument", { motion: mid, side: "maybe", claim: "x", at: at(3) }, ann);
  const late = D.post("debate.position", { motion: mid, side: "no", statement: "Too late", at: "2026-11-09T10:00:00.000Z" }, ben);
  const records = [pos, arg, reb, ev, sub, hide, round, orphan, toPosition, outsider, fakeMod, malformed, late, pos];
  const roles = { keyFor: (k) => keys[k], canPost: (k) => k !== out.kid, isModerator: (k) => k === mod.kid };
  const js = D.arrange(motion, records, roles);
  const rs = rust({ op: "debate.arrange", motion, records, keys, canPost: [mod.kid, ann.kid, ben.kid], moderators: [mod.kid] });
  assert.deepEqual(rs, JSON.parse(JSON.stringify(js)));
  assert.ok(js.rejected.length >= 6);
});

test("personas and migrations: links and notices made by either side check out in the other", { skip }, () => {
  const account = key();
  const rs = rust({ op: "persona.create", account, community: "c1", name: "  Gardener  ", at: AT });
  assert.deepEqual(P.checkPersonaLink(rs.link), { account: account.kid, persona: rs.key.kid, community: "c1" });
  const js = P.createPersona(account, { community: "c2", name: "Reader" });
  assert.deepEqual(rust({ op: "persona.check", link: js.link }), P.checkPersonaLink(js.link));
  const tampered = { ...js.link, cosigs: [] };
  assert.equal(rustCode({ op: "persona.check", link: tampered }), jsCode(() => P.checkPersonaLink(tampered)));
  assert.equal(rustCode({ op: "persona.create", account, community: "c1", name: "   ", at: AT }), jsCode(() => P.createPersona(account, { community: "c1", name: "   " })));

  const owner = key();
  const n1 = P.migrationNotice({ subject: "acct", from: "a.example", to: "b.example", seq: 1 }, owner);
  const n2 = rust({ op: "migration.notice", subject: "acct", from: "b.example", to: "c.example", seq: 2, keepOldUntil: null, at: AT, owner });
  const stale = P.migrationNotice({ subject: "acct", from: "a.example", to: "z.example", seq: 1 }, owner);
  const forged = P.migrationNotice({ subject: "acct", from: "c.example", to: "evil.example", seq: 3 }, key());
  const notices = [n2, n1, stale, forged];
  const jump = P.migrationNotice({ subject: "acct", from: "x.example", to: "y.example", seq: 3 }, owner);
  assert.equal(rust({ op: "migration.currentSite", notices, ownerPub: owner.publicKey, start: "a.example" }), P.currentSite(notices, owner.publicKey, "a.example"));
  assert.equal(P.currentSite(notices, owner.publicKey, "a.example"), "c.example");
  for (const [n, last] of [[n2, n1.body], [stale, n2.body], [n1, n2.body], [forged, n2.body], [n2, { ...n1.body, subject: "other" }], [jump, n2.body]]) {
    assert.equal(rustCode({ op: "migration.accept", notice: n, ownerPub: owner.publicKey, last }), jsCode(() => P.acceptMigration(n, owner.publicKey, last)));
  }
});

test("consent: the same answer for every check, and revocations work both ways", { skip }, () => {
  const grantor = key();
  const reader = key();
  const t = Date.parse(AT);
  const g = { audience: [reader.kid, "site.example"], actions: ["read", "store"], resource: "file-1", notBefore: AT, expires: "2026-11-20T00:00:00.000Z", purpose: "Sharing" };
  const jsCap = C.grant(g, grantor);
  const rsCap = rust({ op: "consent.grant", grant: g, key: grantor });
  const rsRev = rust({ op: "consent.revoke", capsule: rsCap, key: grantor, reason: "done", now: t + 3600_000 });
  const asks = [
    [reader.kid, "read", "file-1", t + 1000],
    ["site.example", "store", "file-1", t + 1000],
    [reader.kid, "publish", "file-1", t + 1000],
    [reader.kid, "read", "file-2", t + 1000],
    ["stranger", "read", "file-1", t + 1000],
    [reader.kid, "read", "file-1", t - 1000],
    [reader.kid, "read", "file-1", Date.parse("2026-11-21T00:00:00Z")],
    [reader.kid, "read", "file-1", t + 7200_000],
  ];
  for (const capsule of [jsCap, rsCap, { ...jsCap, body: { ...jsCap.body, resource: "*" } }]) {
    for (const [actor, action, resource, now] of asks) {
      const js = C.check(capsule, { grantorPub: grantor.publicKey, actor, action, resource, now, revocations: [rsRev] });
      const rs = rust({ op: "consent.check", capsule, grantorPub: grantor.publicKey, actor, action, resource, now, revocations: [rsRev] });
      assert.deepEqual(rs, js, `${actor} ${action} ${resource} ${now}`);
    }
  }
  for (const bad of [{ audience: [] }, { actions: ["sell"] }, { resource: "" }, { expires: AT }]) {
    assert.equal(rustCode({ op: "consent.grant", grant: { ...g, ...bad }, key: grantor }), jsCode(() => C.grant({ ...g, ...bad }, grantor)));
  }
});

test("extensions and themes: the same problems, signatures and contrast on both sides", { skip }, () => {
  const pub = key();
  const good = { id: "org.example.debates", name: "Debates", version: "1.2.3", execution: "client-local", permissions: ["read.selected", "ui.panel"], code_hash: sha256B64u("code"), licence: "MIT" };
  const manifests = [good, {}, null, [], "x", { ...good, id: "Debates" }, { ...good, version: "1.2" }, { ...good, execution: "server-side" }, { ...good, execution: "external", permissions: ["send.selected"], service: "http://x" }, { ...good, permissions: "all" }, { ...good, code_hash: "short" }, { ...good, licence: 5 }, { ...good, execution: undefined }];
  for (const m of manifests) assert.deepEqual(rust({ op: "ext.manifestProblems", manifest: m ?? null }), X.manifestProblems(m === undefined ? null : JSON.parse(JSON.stringify(m ?? null))), JSON.stringify(m));
  const rec = rust({ op: "ext.publish", body: good, key: pub });
  assert.deepEqual(X.checkManifest(rec, { publisherPub: pub.publicKey, code: "code" }), { ok: true, problems: [] });
  const jsRec = X.publish(good, pub);
  assert.deepEqual(rust({ op: "ext.checkManifest", record: jsRec, publisherPub: pub.publicKey, code: b64u(new TextEncoder().encode("other")) }), X.checkManifest(jsRec, { publisherPub: pub.publicKey, code: new TextEncoder().encode("other") }));
  assert.deepEqual(rust({ op: "ext.explain", manifest: { ...good, execution: "external", service: "https://x.example", permissions: ["send.selected", "custom"] } }), X.explainPermissions({ ...good, execution: "external", service: "https://x.example", permissions: ["send.selected", "custom"] }));

  const colors = { background: "#ffffff", surface: "#f5f5f5", text: "#111111", muted: "#555555", accent: "#0b5394", "accent-text": "#ffffff", danger: "#a61c00", "danger-text": "#ffffff", border: "#cccccc" };
  const theme = { id: "org.example.calm", name: "Calm", version: "1.0.0", colors, fonts: { body: "Inter" }, radius: 8, spacing: "normal", images: [{ role: "icon", hash: sha256B64u("img"), type: "image/png" }] };
  const themes = [theme, {}, [], { ...theme, colors: { ...colors, text: "#eeeeee" } }, { ...theme, colors: { ...colors, muted: "#777777" } }, { ...theme, dark: { ...colors, muted: "#fafafa" } }, { ...theme, script: "alert(1)" }, { ...theme, fonts: { body: "Comic Sans" } }, { ...theme, fonts: "ab" }, { ...theme, radius: 30 }, { ...theme, spacing: "huge" }, { ...theme, images: "ab" }, { ...theme, colors: [1, 2] }, { ...theme, dark: null }];
  for (const t of themes) assert.deepEqual(rust({ op: "theme.problems", theme: t }), X.themeProblems(t), JSON.stringify(t).slice(0, 80));
  for (const [a, b] of [["#000000", "#ffffff"], ["#777777", "#ffffff"], ["#0b5394", "#ffffff"], ["#123456", "#654321"]]) assert.equal(rust({ op: "theme.contrast", a, b }), X.contrast(a, b));
  const tRec = rust({ op: "theme.publish", body: theme, key: pub });
  assert.deepEqual(X.checkTheme(tRec, pub.publicKey), { ok: true, problems: [] });
  assert.equal(rust({ op: "theme.id", record: tRec }), X.themeId(tRec));
});
