import test from "node:test";
import assert from "node:assert/strict";
import { createAccount, createDevice, signDeviceList, createPrekeys, takeBundle, v2 } from "../src/session/index.js";

const text = (b) => new TextDecoder().decode(b);
const code = (p) => p.then(() => null, (e) => e.code);

function person() {
  const account = createAccount();
  const device = createDevice();
  const list = signDeviceList(account, [device], { seq: 1 });
  const prekeys = createPrekeys(device, { oneTime: 3, pqOneTime: 3 });
  return { account, device, list, prekeys, me: () => ({ device, deviceList: list, prekeys: prekeys.secrets }) };
}

async function pair() {
  const alice = person();
  const bob = person();
  const bundle = takeBundle(bob.list, bob.prekeys.published, bob.device.kid);
  let a = await v2.initiate({ me: alice.me(), bundle, accountKey: bob.account.publicKey });
  const first = await v2.encrypt(a, "hello Bob");
  a = first.state;
  const who = await v2.initialSender({ me: bob.me(), message: first.message });
  const r = await v2.respond({ me: bob.me(), message: first.message, accountKey: alice.account.publicKey });
  return { alice, bob, a, b: r.state, first, who, firstPlain: text(r.plaintext), bundle };
}

/** Send one message from `from` to `to` in a { a, b } pair of states. */
async function send(s, from, to, body, opts) {
  const m = await v2.encrypt(s[from], body);
  s[from] = m.state;
  const d = await v2.decrypt(s[to], m.message, opts);
  s[to] = d.state;
  assert.equal(text(d.plaintext), body);
  return m.message;
}

test("v2: a session is agreed and messages flow both ways", async () => {
  const p = await pair();
  assert.equal(p.firstPlain, "hello Bob");
  assert.ok(v2.isInitial(p.first.message));
  const s = { a: p.a, b: p.b };
  for (let i = 0; i < 5; i += 1) {
    const m = await send(s, "b", "a", `b${i}`);
    assert.ok(!m.x);
    const back = await send(s, "a", "b", `a${i}`);
    assert.ok(!back.x, "the handshake stops once Bob has answered");
  }
});

test("v2: the first message doesn't say who sent it, and only the right device can tell", async () => {
  const p = await pair();
  const wire = JSON.stringify(p.first.message);
  assert.ok(wire.includes(`"${p.first.message.x.ek}"`), "control: the search finds what is there");
  for (const secret of [p.alice.account.publicKey, p.alice.device.kid, p.alice.device.dh.pk, p.alice.device.sign.publicKey]) {
    assert.ok(!wire.includes(`"${secret}"`), "nothing that identifies the sender is readable");
  }
  assert.equal(p.who.account, p.alice.account.publicKey);
  assert.equal(p.who.device, p.alice.device.kid);
  const carol = person();
  assert.equal(await code(v2.initialSender({ me: carol.me(), message: p.first.message })), "UNKNOWN_PREKEY");
});

test("v2: headers are encrypted, so nothing links or orders messages", async () => {
  const p = await pair();
  const s = { a: p.a, b: p.b };
  const m1 = await send(s, "b", "a", "one");
  const m2 = await send(s, "b", "a", "two");
  assert.equal(typeof m1.h, "string");
  assert.deepEqual(Object.keys(m1).sort(), ["c", "h", "v"]);
  assert.notEqual(m1.h.slice(0, 40), m2.h.slice(0, 40), "two messages of one chain share nothing visible");
});

test("v2: an ordinary message is small", async () => {
  const p = await pair();
  const s = { a: p.a, b: p.b };
  let largest = 0;
  for (let i = 0; i < 40; i += 1) {
    const m = await send(s, i % 2 ? "a" : "b", i % 2 ? "b" : "a", "x");
    largest = Math.max(largest, JSON.stringify(m).length);
  }
  assert.ok(largest < 1000, `largest ordinary message was ${largest} bytes`);
});

test("v2: ML-KEM secrets keep entering the root key, in both directions", async () => {
  const p = await pair();
  const s = { a: p.a, b: p.b };
  assert.equal(v2.pqStatus(s.a).mixed, 0);
  for (let i = 0; i < 80; i += 1) await send(s, i % 2 ? "a" : "b", i % 2 ? "b" : "a", `m${i}`);
  const a = v2.pqStatus(s.a);
  const b = v2.pqStatus(s.b);
  assert.ok(a.mixed >= 3, `only ${a.mixed} exchanges finished in 80 messages`);
  assert.equal(a.mixed, b.mixed);
  assert.equal(a.epoch, b.epoch);
  assert.notEqual(a.role, b.role);
});

test("v2: the exchange survives lost and reordered messages", async () => {
  const p = await pair();
  let { a, b } = p;
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  let delivered = 0;
  for (let i = 0; i < 300; i += 1) {
    const fromA = rnd() < 0.5;
    const m = await v2.encrypt(fromA ? a : b, `m${i}`);
    if (fromA) a = m.state; else b = m.state;
    if (rnd() < 0.3) continue;
    const d = await v2.decrypt(fromA ? b : a, m.message);
    if (fromA) b = d.state; else a = d.state;
    assert.equal(text(d.plaintext), `m${i}`);
    delivered += 1;
  }
  assert.ok(delivered > 150);
  assert.ok(v2.pqStatus(a).mixed >= 3, `only ${v2.pqStatus(a).mixed} exchanges finished`);
});

test("v2: messages can arrive out of order and late, but only once", async () => {
  const p = await pair();
  let { a, b } = p;
  const sent = [];
  for (let i = 0; i < 5; i += 1) {
    const m = await v2.encrypt(a, `a${i}`);
    a = m.state;
    sent.push(m.message);
  }
  for (const i of [3, 0, 4]) {
    const d = await v2.decrypt(b, sent[i]);
    b = d.state;
    assert.equal(text(d.plaintext), `a${i}`);
  }
  // Bob answers, so Alice's next message starts a new chain; the late ones still open.
  const s = { a, b };
  await send(s, "b", "a", "reply");
  await send(s, "a", "b", "new chain");
  for (const i of [1, 2]) {
    const d = await v2.decrypt(s.b, sent[i]);
    s.b = d.state;
    assert.equal(text(d.plaintext), `a${i}`);
  }
  for (const i of [0, 1, 4]) assert.ok(["REPLAY", "DECRYPT_FAILED"].includes(await code(v2.decrypt(s.b, sent[i]))), "a second copy is refused");
});

test("v2: keys for missing messages are deleted after a week", async () => {
  const p = await pair();
  let { a, b } = p;
  const t0 = 1_800_000_000_000;
  const late = await v2.encrypt(a, "late");
  const next = await v2.encrypt(late.state, "next");
  b = (await v2.decrypt(b, next.message, { now: t0 })).state;
  assert.equal(b.skipped.length, 1);
  const stillOk = await v2.decrypt(b, late.message, { now: t0 + v2.SKIPPED_TTL_MS - 1 });
  assert.equal(text(stillOk.plaintext), "late");
  assert.notEqual(await code(v2.decrypt(b, late.message, { now: t0 + v2.SKIPPED_TTL_MS + 1 })), null);
});

test("v2: tampering is refused and leaves the session untouched", async () => {
  const p = await pair();
  const s = { a: p.a, b: p.b };
  const m = await v2.encrypt(s.b, "intact");
  const flip = (str) => {
    const i = Math.floor(str.length / 2);
    return str.slice(0, i) + (str[i] === "A" ? "B" : "A") + str.slice(i + 1);
  };
  const before = JSON.stringify(s.a);
  assert.equal(await code(v2.decrypt(s.a, { ...m.message, c: flip(m.message.c) })), "DECRYPT_FAILED");
  assert.equal(await code(v2.decrypt(s.a, { ...m.message, h: flip(m.message.h) })), "DECRYPT_FAILED");
  assert.equal(await code(v2.decrypt(s.a, { ...m.message, v: 1 })), "BAD_MESSAGE");
  assert.equal(JSON.stringify(s.a), before);
  assert.equal(text((await v2.decrypt(s.a, m.message)).plaintext), "intact");
});

test("v2: a header moved onto another message's body is refused", async () => {
  const p = await pair();
  const m1 = await v2.encrypt(p.b, "one");
  const m2 = await v2.encrypt(m1.state, "two");
  assert.equal(await code(v2.decrypt(p.a, { ...m1.message, c: m2.message.c })), "DECRYPT_FAILED");
});

test("v2: the transcript covers the prekeys' public keys", () => {
  const who = { account: "a", device: "d", sign: "s", dh: "h" };
  const x = { ek: "AAAA", ct: "AAAA", signed: "i1", pq: "i2", oneTime: "i3" };
  const base = JSON.stringify(v2.transcriptOf(who, who, x, { signed: "AAAA", pq: "AAAA", oneTime: "AAAA" }));
  for (const k of ["signed", "pq", "oneTime"]) {
    const other = JSON.stringify(v2.transcriptOf(who, who, x, { signed: "AAAA", pq: "AAAA", oneTime: "AAAA", [k]: "BBBB" }));
    assert.notEqual(other, base, `${k} prekey's public key is bound`);
  }
});

test("v2: a first message can't be answered with the wrong account key, or twice with a one-time prekey", async () => {
  const p = await pair();
  const mallory = person();
  const again = { device: p.bob.device, deviceList: p.bob.list, prekeys: p.bob.prekeys.secrets };
  assert.equal(await code(v2.respond({ me: again, message: p.first.message, accountKey: mallory.account.publicKey })), "UNTRUSTED");
  const r = await v2.respond({ me: again, message: p.first.message, accountKey: p.alice.account.publicKey });
  assert.equal(await code(v2.respond({ me: { ...again, prekeys: r.prekeys }, message: p.first.message, accountKey: p.alice.account.publicKey })), "UNKNOWN_PREKEY");
});

test("v2: a claim that a secret was mixed in is refused unless this side made that secret", async () => {
  const p = await pair();
  const s = { a: p.a, b: p.b };
  await send(s, "b", "a", "hi");
  // Alice's next chain claims epoch 1 was mixed, but Bob hasn't even seen the whole key yet.
  const lying = { ...s.a, pe: 1 };
  const m = await v2.encrypt(lying, "claim");
  const before = JSON.stringify(s.b);
  assert.equal(await code(v2.decrypt(s.b, m.message)), "BAD_MESSAGE");
  assert.equal(JSON.stringify(s.b), before);
});

test("v2: canOpen finds the session a message belongs to", async () => {
  const p1 = await pair();
  const p2 = await pair();
  const m = await v2.encrypt(p1.b, "for the first");
  assert.equal(await v2.canOpen(p1.a, m.message), true);
  assert.equal(await v2.canOpen(p2.a, m.message), false);
  assert.equal(await code(v2.decrypt(p2.a, m.message)), "DECRYPT_FAILED");
});

test("v2: a version 1 session state is refused", async () => {
  const p = await pair();
  assert.equal(await code(v2.encrypt({ ...p.a, v: 1 }, "x")), "BAD_INPUT");
});

test("v2: a message too far ahead is refused", async () => {
  const p = await pair();
  let a = p.a;
  let last;
  for (let i = 0; i <= v2.MAX_SKIP + 1; i += 1) {
    last = await v2.encrypt(a, "x");
    a = last.state;
  }
  assert.equal(await code(v2.decrypt(p.b, last.message)), "TOO_FAR_AHEAD");
});
