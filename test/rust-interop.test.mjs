// The Rust implementation (rust/) against this one, message by message.
//
// Runs against the Rust command-line front end when it has been built:
//   (cd rust && cargo build --example cli)
// or when SECURE_NET_RUST_CLI points at one; or against the WebAssembly build when
// SECURE_NET_RUST_WASM points at the module wasm-bindgen made for Node.js (CI does both).
// Otherwise every test here is skipped.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { b64u, fromB64u } from "../src/core/bytes.js";
import { canonicalJson } from "../src/core/canonical.js";
import { sign, checkSignature, generateSigningKey } from "../src/core/signed.js";
import { createAccount, createDevice, signDeviceList, createPrekeys, takeBundle } from "../src/session/keys.js";
import * as js from "../src/session/session.js";

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

const text = (b) => new TextDecoder().decode(b);
const code = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e.code;
  }
};

// Each side can be run by either implementation. These wrap both behind one interface.
const impl = {
  js: {
    encrypt: async (state, msg) => js.encrypt(state, msg),
    decrypt: async (state, message) => {
      const r = await js.decrypt(state, message);
      return { state: r.state, plaintext: text(r.plaintext) };
    },
  },
  rust: {
    encrypt: async (state, msg) => rust({ op: "encrypt", state, plaintext: b64u(new TextEncoder().encode(msg)) }),
    decrypt: async (state, message) => {
      const r = rust({ op: "decrypt", state, message });
      return { state: r.state, plaintext: text(fromB64u(r.plaintext)) };
    },
  },
};

function jsPerson() {
  const account = createAccount();
  const device = createDevice();
  const list = signDeviceList(account, [device], { seq: 1, now: NOW });
  const prekeys = createPrekeys(device, { oneTime: 2, pqOneTime: 2, now: NOW, sessions: 1 });
  return { account, device, list, prekeys };
}

function rustPerson() {
  const account = rust({ op: "createAccount" });
  const device = rust({ op: "createDevice" });
  const list = rust({ op: "signDeviceList", account, devices: [{ kid: device.kid, sign: device.sign.publicKey, dh: device.dh.pk }], seq: 1 });
  const prekeys = rust({ op: "createPrekeys", device, oneTime: 2, pqOneTime: 2, sessions: 1 });
  return { account, device, list, prekeys };
}

test("rust: canonical JSON is byte for byte the same", { skip }, () => {
  const samples = [
    { b: 1, a: [3, 2, 1], B: { y: null, x: true } },
    { "é": "  \u0000\u001f\"\\/", "😀": "😀", "Z": -0, "z": 9007199254740991, "aa": -9007199254740991 },
    { "é": 1, "é": 2, "￿": 3, "𐀀": 4 },
    [[], {}, "", "line\nbreak\ttab\r\b\f"],
  ];
  for (const v of samples) assert.equal(rust({ op: "canonical", value: v }), canonicalJson(v));
  assert.equal(code(() => rust({ op: "canonical", value: 1.5 })), "NOT_CANONICAL");
  assert.equal(code(() => rust({ op: "canonical", value: 9007199254740992 })), "NOT_CANONICAL");
});

test("rust: signatures made by either side verify on the other", { skip }, () => {
  for (const pq of [false, true]) {
    const jsKey = generateSigningKey({ pq });
    const body = { text: "Built together. Open to everyone.", n: 7, nested: { "é": [1, 2] } };
    const fromJs = sign("example.note", body, jsKey);
    assert.equal(rust({ op: "check", record: fromJs, publicKey: jsKey.publicKey }), true);
    assert.equal(rust({ op: "check", record: { ...fromJs, body: { ...body, n: 8 } }, publicKey: jsKey.publicKey }), false);
    const fromRust = rust({ op: "sign", kind: "example.note", body, key: jsKey });
    assert.ok(checkSignature(fromRust, fromRust.sig, jsKey.publicKey), `JS verifies Rust (${pq ? "hybrid" : "Ed25519"})`);
    const rustKey = rust({ op: "createAccount" });
    const r2 = rust({ op: "sign", kind: "example.note", body, key: rustKey });
    assert.ok(checkSignature(r2, r2.sig, rustKey.publicKey), "a key made in Rust works in JS");
  }
});

async function conversation(alice, bob, sides) {
  // sides(i) says which implementation each person uses for message i: { a: "js" | "rust", b: ... }
  const bundle = takeBundle(bob.list, structuredClone(bob.prekeys.published), bob.device.kid);
  let a = sides(0).a === "js"
    ? js.initiate({ me: { device: alice.device, deviceList: alice.list }, bundle, accountKey: bob.account.publicKey, now: NOW })
    : rust({ op: "initiate", me: { device: alice.device, deviceList: alice.list }, bundle, accountKey: bob.account.publicKey });
  const first = await impl[sides(0).a].encrypt(a, "hello Bob");
  a = first.state;
  let b;
  if (sides(0).b === "js") {
    const r = await js.respond({ me: { device: bob.device, deviceList: bob.list, prekeys: bob.prekeys.secrets }, message: first.message, accountKey: alice.account.publicKey });
    assert.equal(text(r.plaintext), "hello Bob");
    b = r.state;
  } else {
    const r = rust({ op: "respond", me: { device: bob.device, deviceList: bob.list, prekeys: bob.prekeys.secrets }, message: first.message, accountKey: alice.account.publicKey });
    assert.equal(text(fromB64u(r.plaintext)), "hello Bob");
    assert.ok(Object.keys(r.prekeys).length < Object.keys(bob.prekeys.secrets).length, "one-time prekeys are used up");
    b = r.state;
  }
  // Mostly alternating, with runs, so both ratchets turn many times.
  const pattern = "BABBAABAAABBBABAB";
  const late = [];
  for (let i = 0; i < pattern.length; i += 1) {
    const s = sides(i + 1);
    const fromA = pattern[i] === "A";
    const body = `message ${i} from ${fromA ? "Alice" : "Bob"}`;
    const m = await impl[fromA ? s.a : s.b].encrypt(fromA ? a : b, body);
    if (fromA) a = m.state;
    else b = m.state;
    if (i === 6 || i === 10) {
      late.push({ fromA, message: m.message, body });
      continue;
    }
    const d = await impl[fromA ? s.b : s.a].decrypt(fromA ? b : a, m.message);
    assert.equal(d.plaintext, body);
    if (fromA) b = d.state;
    else a = d.state;
  }
  // Messages that arrived late still open, once, on whichever implementation holds the state now.
  for (const { fromA, message, body } of late) {
    const s = sides(99);
    const d = await impl[fromA ? s.b : s.a].decrypt(fromA ? b : a, message);
    assert.equal(d.plaintext, body);
    if (fromA) b = d.state;
    else a = d.state;
    await assert.rejects(impl[fromA ? s.b : s.a].decrypt(fromA ? b : a, message), (e) => ["REPLAY", "DECRYPT_FAILED"].includes(e.code));
  }
  return { a, b };
}

test("rust: a JS sender and a Rust recipient, then the other way round", { skip }, async () => {
  await conversation(jsPerson(), rustPerson(), () => ({ a: "js", b: "rust" }));
  await conversation(rustPerson(), jsPerson(), () => ({ a: "rust", b: "js" }));
});

test("rust: a session's state moves between implementations mid-conversation", { skip }, async () => {
  // Each person switches implementation every few messages, carrying the same JSON state.
  const flip = (i) => ({ a: Math.floor(i / 3) % 2 ? "rust" : "js", b: Math.floor(i / 2) % 2 ? "js" : "rust" });
  await conversation(jsPerson(), rustPerson(), flip);
  await conversation(rustPerson(), rustPerson(), flip);
});

test("rust: refuses what the JavaScript refuses", { skip }, async () => {
  const alice = jsPerson();
  const bob = rustPerson();
  const bundle = takeBundle(bob.list, structuredClone(bob.prekeys.published), bob.device.kid);
  let a = js.initiate({ me: { device: alice.device, deviceList: alice.list }, bundle, accountKey: bob.account.publicKey, now: NOW });
  const first = await js.encrypt(a, "hello");
  a = first.state;
  const me = { device: bob.device, deviceList: bob.list, prekeys: bob.prekeys.secrets };
  const mallory = jsPerson();
  assert.equal(code(() => rust({ op: "respond", me, message: first.message, accountKey: mallory.account.publicKey })), "UNTRUSTED");
  const i = Math.floor(first.message.c.length / 2);
  const bent = { ...first.message, c: first.message.c.slice(0, i) + (first.message.c[i] === "A" ? "B" : "A") + first.message.c.slice(i + 1) };
  assert.equal(code(() => rust({ op: "respond", me, message: bent, accountKey: alice.account.publicKey })), "DECRYPT_FAILED");
  const r = rust({ op: "respond", me, message: first.message, accountKey: alice.account.publicKey });
  assert.equal(code(() => rust({ op: "respond", me: { ...me, prekeys: r.prekeys }, message: first.message, accountKey: alice.account.publicKey })), "UNKNOWN_PREKEY");
  // A reply with its ML-KEM ciphertext stripped is a downgrade, and both refuse it.
  const reply = rust({ op: "encrypt", state: r.state, plaintext: b64u(new TextEncoder().encode("hi")) });
  const stripped = { ...reply.message, h: { ...reply.message.h } };
  delete stripped.h.ct;
  await assert.rejects(js.decrypt(a, stripped), (e) => ["DOWNGRADE", "DECRYPT_FAILED"].includes(e.code));
  assert.ok(["DOWNGRADE", "DECRYPT_FAILED"].includes(code(() => rust({ op: "decrypt", state: a, message: stripped }))));
  assert.equal(text((await js.decrypt(a, reply.message)).plaintext), "hi");
});
