// Sessions version 2, sender keys and history transfer: the Rust port against this
// implementation, message by message, with each side free to switch implementation at any point.
// Runs against the Rust CLI or WebAssembly build like test/rust-interop.test.mjs; skipped otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { b64u, fromB64u } from "../src/core/bytes.js";
import { createAccount, createDevice, signDeviceList, createPrekeys, takeBundle, v2, createSenderKey, distribution, acceptDistribution, groupEncrypt, groupDecrypt, sealHistory, openHistory } from "../src/session/index.js";

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
const enc = (s) => b64u(new TextEncoder().encode(s));
const text = (b) => new TextDecoder().decode(b);
const rustCode = (req) => {
  try {
    rust(req);
    return null;
  } catch (e) {
    return e.code;
  }
};
const jsCode = (p) => p.then(() => null, (e) => e.code);

const impl = {
  js: {
    encrypt: (state, body) => v2.encrypt(state, body),
    decrypt: async (state, message, now = NOW) => {
      const r = await v2.decrypt(state, message, { now });
      return { state: r.state, plaintext: text(r.plaintext) };
    },
    canOpen: (state, message) => v2.canOpen(state, message),
  },
  rust: {
    encrypt: async (state, body) => rust({ op: "v2.encrypt", state, plaintext: enc(body) }),
    decrypt: async (state, message, now = NOW) => {
      const r = rust({ op: "v2.decrypt", state, message, now });
      return { state: r.state, plaintext: text(fromB64u(r.plaintext)) };
    },
    canOpen: async (state, message) => rust({ op: "v2.canOpen", state, message }),
  },
};

function person(kind) {
  if (kind === "js") {
    const account = createAccount();
    const device = createDevice();
    const list = signDeviceList(account, [device], { seq: 1, now: NOW });
    const prekeys = createPrekeys(device, { oneTime: 3, pqOneTime: 3, now: NOW, sessions: 2 });
    return { account, device, list, prekeys };
  }
  const account = rust({ op: "createAccount" });
  const device = rust({ op: "createDevice" });
  const list = rust({ op: "signDeviceList", account, devices: [{ kid: device.kid, sign: device.sign.publicKey, dh: device.dh.pk }], seq: 1 });
  const prekeys = rust({ op: "createPrekeys", device, oneTime: 3, pqOneTime: 3, sessions: 2 });
  return { account, device, list, prekeys };
}

async function start(alice, bob, aSide, bSide) {
  const bundle = takeBundle(bob.list, structuredClone(bob.prekeys.published), bob.device.kid);
  const meA = { device: alice.device, deviceList: alice.list };
  let a = aSide === "js" ? await v2.initiate({ me: meA, bundle, accountKey: bob.account.publicKey, now: NOW }) : rust({ op: "v2.initiate", me: meA, bundle, accountKey: bob.account.publicKey });
  const first = await impl[aSide].encrypt(a, "hello Bob");
  a = first.state;
  const meB = { device: bob.device, deviceList: bob.list, prekeys: bob.prekeys.secrets };
  let b;
  if (bSide === "js") {
    const who = await v2.initialSender({ me: meB, message: first.message });
    assert.equal(who.account, alice.account.publicKey);
    const r = await v2.respond({ me: meB, message: first.message, accountKey: alice.account.publicKey, now: NOW });
    assert.equal(text(r.plaintext), "hello Bob");
    b = r.state;
  } else {
    const who = rust({ op: "v2.initialSender", me: meB, message: first.message });
    assert.equal(who.account, alice.account.publicKey);
    const r = rust({ op: "v2.respond", me: meB, message: first.message, accountKey: alice.account.publicKey });
    assert.equal(text(fromB64u(r.plaintext)), "hello Bob");
    assert.ok(Object.keys(r.prekeys).length < Object.keys(bob.prekeys.secrets).length, "one-time prekeys are used up");
    b = r.state;
  }
  return { a, b, first };
}

/** A long conversation, in runs, so both ratchets turn and several ML-KEM exchanges complete. */
async function talk(s, sides, count = 90) {
  const late = [];
  for (let i = 0; i < count; i += 1) {
    const fromA = i % 7 < 3;
    const side = sides(i);
    const from = fromA ? "a" : "b";
    const to = fromA ? "b" : "a";
    const body = `message ${i} from ${fromA ? "Alice" : "Bob"} £✓`;
    const m = await impl[fromA ? side.a : side.b].encrypt(s[from], body);
    s[from] = m.state;
    if (i % 23 === 5) {
      late.push({ to, message: m.message, body, side });
      continue;
    }
    assert.ok(await impl[fromA ? side.b : side.a].canOpen(s[to], m.message), `can open message ${i}`);
    const d = await impl[fromA ? side.b : side.a].decrypt(s[to], m.message);
    assert.equal(d.plaintext, body);
    s[to] = d.state;
  }
  for (const l of late) {
    const d = await impl[l.to === "b" ? l.side.b : l.side.a].decrypt(s[l.to], l.message);
    assert.equal(d.plaintext, l.body, "late messages still open");
    s[l.to] = d.state;
  }
  return s;
}

test("v2: JavaScript and Rust hold one conversation, switching sides freely, ML-KEM exchanges included", { skip }, async () => {
  for (const [ka, kb] of [["js", "rust"], ["rust", "js"], ["rust", "rust"]]) {
    const alice = person(ka);
    const bob = person(kb);
    const { a, b } = await start(alice, bob, ka, kb);
    const flip = (i) => ((i >> 2) % 2 === 0 ? "js" : "rust");
    const s = await talk({ a, b }, (i) => ({ a: flip(i), b: flip(i + 2) }));
    const pa = v2.pqStatus(s.a);
    const pb = rust({ op: "v2.pqStatus", state: s.b });
    assert.ok(pa.mixed >= 2 && pb.mixed >= 2, `ML-KEM secrets were mixed in (${pa.mixed}, ${pb.mixed})`);
    assert.equal(Math.abs(pa.mixed - pb.mixed) <= 1, true);
  }
});

test("v2: the same refusals on both sides", { skip }, async () => {
  const alice = person("js");
  const bob = person("rust");
  const { a, b, first } = await start(alice, bob, "js", "rust");
  const s = await talk({ a, b }, () => ({ a: "js", b: "rust" }), 12);
  const m = await v2.encrypt(s.a, "once");
  const d = await v2.decrypt(s.b, m.message, { now: NOW });
  const cases = [
    ["replay", d.state, m.message],
    ["tampered header", s.b, { ...m.message, h: m.message.h.slice(0, -4) + (m.message.h.endsWith("AAAA") ? "BBBB" : "AAAA") }],
    ["tampered body", s.b, { ...m.message, c: m.message.c.slice(0, -4) + (m.message.c.endsWith("AAAA") ? "BBBB" : "AAAA") }],
    ["wrong version", s.b, { ...m.message, v: 1 }],
    ["first message again", s.b, first.message],
  ];
  for (const [what, state, message] of cases) {
    const j = await jsCode(v2.decrypt(state, message, { now: NOW }));
    assert.ok(j, what);
    assert.equal(rustCode({ op: "v2.decrypt", state, message }), j, what);
  }
  // A different session can't open it, and both sides agree.
  const carol = person("js");
  const other = await start(carol, person("js"), "js", "js");
  assert.equal(rust({ op: "v2.canOpen", state: other.b, message: m.message }), await v2.canOpen(other.b, m.message));
  assert.equal(rust({ op: "v2.canOpen", state: other.b, message: m.message }), false);
  // A replayed first message is refused on a fresh responder by the prekeys it used.
  const meB = { device: bob.device, deviceList: bob.list, prekeys: {} };
  assert.equal(rustCode({ op: "v2.respond", me: meB, message: first.message, accountKey: alice.account.publicKey }), await jsCode(v2.respond({ me: meB, message: first.message, accountKey: alice.account.publicKey, now: NOW })));
  // An untrusted account key is refused.
  const meB2 = { device: bob.device, deviceList: bob.list, prekeys: bob.prekeys.secrets };
  const j = await jsCode(v2.respond({ me: meB2, message: first.message, accountKey: carol.account.publicKey, now: NOW }));
  assert.equal(rustCode({ op: "v2.respond", me: meB2, message: first.message, accountKey: carol.account.publicKey }), j);
  assert.equal(rust({ op: "v2.handshakeId", message: first.message }), v2.handshakeId(first.message));
});

test("v2: keys for missing messages expire after seven days on both sides", { skip }, async () => {
  const { a, b } = await start(person("js"), person("rust"), "js", "rust");
  const s = await talk({ a, b }, () => ({ a: "js", b: "rust" }), 4);
  const skipped = await v2.encrypt(s.a, "skipped");
  const next = await v2.encrypt(skipped.state, "next");
  const got = rust({ op: "v2.decrypt", state: s.b, message: next.message });
  const later = NOW + 7 * 24 * 3600 * 1000 + 1;
  assert.equal(rustCode({ op: "v2.decrypt", state: got.state, message: skipped.message, now: later }), await jsCode(v2.decrypt(got.state, skipped.message, { now: later })));
  assert.equal(text(fromB64u(rust({ op: "v2.decrypt", state: got.state, message: skipped.message, now: NOW + 1000 }).plaintext)), "skipped");
});

test("sender keys: group messages cross between implementations", { skip }, async () => {
  const rsKey = rust({ op: "group.createSenderKey", group: "g1" });
  const jsState = acceptDistribution(rust({ op: "group.distribution", key: rsKey }), { from: "dev-r" });
  let key = rsKey;
  const msgs = [];
  for (let i = 0; i < 5; i += 1) {
    const r = rust({ op: "group.encrypt", key, plaintext: enc(`g${i}`) });
    key = r.key;
    msgs.push(r.message);
  }
  let st = jsState;
  for (const i of [0, 3, 1, 4, 2]) {
    const r = await groupDecrypt(st, msgs[i]);
    assert.equal(text(r.plaintext), `g${i}`);
    st = r.state;
  }
  assert.equal(rustCode({ op: "group.decrypt", state: rust({ op: "group.accept", distribution: distribution(createSenderKey("g1")), from: "x" }), message: msgs[0] }), "BAD_MESSAGE");

  const jsKey = createSenderKey("g2");
  let rsState = rust({ op: "group.accept", distribution: distribution(jsKey), from: "dev-j" });
  const one = await groupEncrypt(jsKey, "hello group");
  const two = await groupEncrypt(one.key, "second");
  let r = rust({ op: "group.decrypt", state: rsState, message: two.message });
  assert.equal(text(fromB64u(r.plaintext)), "second");
  rsState = r.state;
  r = rust({ op: "group.decrypt", state: rsState, message: one.message });
  assert.equal(text(fromB64u(r.plaintext)), "hello group");
  for (const [what, state, message] of [
    ["replay", r.state, one.message],
    ["forged", rsState, { ...two.message, c: one.message.c }],
    ["too far ahead", rsState, { ...two.message, n: 5000 }],
  ]) {
    const j = await jsCode(groupDecrypt(state, message));
    assert.equal(rustCode({ op: "group.decrypt", state, message }), j, what);
  }
});

test("history transfer: sealed by one side, opened by the other", { skip }, async () => {
  const items = Array.from({ length: 40 }, (_, i) => ({ id: `m${i}`, text: `message ${i} ✓`, at: NOW + i }));
  const fromJs = await sealHistory(items, { chunkSize: 300, note: "From my laptop" });
  assert.deepEqual(rust({ op: "history.open", offer: fromJs.offer, chunks: fromJs.chunks }), items);
  const fromRust = rust({ op: "history.seal", items, chunkSize: 300, note: "From Rust" });
  assert.deepEqual(await openHistory(fromRust.offer, fromRust.chunks), items);
  const empty = rust({ op: "history.seal", items: [] });
  assert.deepEqual(await openHistory(empty.offer, empty.chunks), []);
  for (const [what, chunks] of [["missing", fromJs.chunks.slice(1)], ["reordered", [fromJs.chunks[1], fromJs.chunks[0], ...fromJs.chunks.slice(2)]]]) {
    const j = await jsCode(openHistory(fromJs.offer, chunks));
    assert.equal(rustCode({ op: "history.open", offer: fromJs.offer, chunks }), j, what);
  }
});
