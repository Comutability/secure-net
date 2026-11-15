// Commonveil's cryptography (src/crypto) against its Rust port (rust/secure-net-core/src/cv):
// keys, seals, envelopes, statements, grants and items made by either side must open or verify
// in the other, and refusals must carry the same codes.
//
// Runs against the Rust command-line front end when built (cd rust && cargo build --example cli)
// or SECURE_NET_RUST_CLI, or the WebAssembly build via SECURE_NET_RUST_WASM. Skipped otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ml_kem768_p256 } from "@noble/post-quantum/hybrid.js";
import { fromB64, toB64, utf8, fromUtf8 } from "../src/crypto/encoding.js";
import * as pr from "../src/crypto/primitives.js";
import * as kem from "../src/crypto/kem.js";
import * as kr from "../src/crypto/keyring.js";
import * as env from "../src/crypto/envelope.js";
import * as id from "../src/crypto/identity.js";
import * as rc from "../src/crypto/recovery.js";
import * as lock from "../src/crypto/lock.js";
import * as owner from "../src/crypto/owner.js";
import * as sk from "../src/crypto/serverKeys.js";
import { createDeviceKeys } from "../src/crypto/device.js";

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

async function jsCode(fn) {
  try {
    await fn();
    return null;
  } catch (e) {
    return e.code || e.name;
  }
}

/** A Rust-made device, with WebCrypto keys the JavaScript can sign with. */
async function rustDevice() {
  const d = rust({ op: "cv.createDeviceKeys", label: "Rust device" });
  return { ...d, sign_key: await pr.importSignPrivate(d.sign_priv) };
}

test("hybrid KEM: same keys from a seed, and seals open both ways", { skip }, async () => {
  const seed = new Uint8Array(32).map((_, i) => i * 7);
  const js = kem.kemKeygen(seed);
  const rs = rust({ op: "cv.kemKeygen", seed: toB64(seed) });
  assert.equal(rs.kem_pub, js.kem_pub);
  assert.equal(rust({ op: "cv.kemPublic", priv: js.kem_priv }), js.kem_pub);

  const fromJs = await kem.kemSeal(js.kem_pub, utf8("to rust"), "ctx/1");
  assert.equal(fromUtf8(fromB64(rust({ op: "cv.kemOpen", priv: js.kem_priv, sealed: fromJs, context: "ctx/1" }))), "to rust");
  assert.equal(rustCode({ op: "cv.kemOpen", priv: js.kem_priv, sealed: fromJs, context: "ctx/2" }), "KEM_FAILED");

  const fromRust = rust({ op: "cv.kemSeal", pub: js.kem_pub, plaintext: toB64(utf8("to js")), context: "ctx/1" });
  assert.equal(fromUtf8(await kem.kemOpen(js.kem_priv, fromRust, "ctx/1")), "to js");

  // A ciphertext whose P-256 half is not a point is refused by both.
  const bad = fromB64(fromJs.kct);
  bad.fill(1, 1089);
  const tampered = { ...fromJs, kct: toB64(bad) };
  assert.equal(await jsCode(() => kem.kemOpen(js.kem_priv, tampered, "ctx/1")), "KemError");
  assert.equal(rustCode({ op: "cv.kemOpen", priv: js.kem_priv, sealed: tampered, context: "ctx/1" }), "KEM_FAILED");
});

test("hybrid KEM: deterministic encapsulation matches @noble/post-quantum", { skip }, () => {
  // The Rust test suite checks fixed randomness against these values (tests/cv_vectors.rs);
  // here we only confirm the library still produces them.
  const seed = new Uint8Array(32).fill(3);
  const rand = new Uint8Array(160).map((_, i) => (i * 13 + 5) & 255);
  const { publicKey } = ml_kem768_p256.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem768_p256.encapsulate(publicKey, rand);
  assert.equal(toB64(sharedSecret), "xRdu5V0EyZFhkoSze1ne1JGbPUm1S9jBc4f3MClQw/8=");
  assert.equal(cipherText.length, 1153);
});

test("P-256: PKCS#8 keys, signatures and ECIES seals work both ways", { skip }, async () => {
  const jsPair = await pr.generateEcdsa(true);
  const jsPriv = await pr.exportPkcs8(jsPair.privateKey);
  const jsPub = await pr.exportRaw(jsPair.publicKey);
  const rsSig = rust({ op: "cv.signText", priv: jsPriv, text: "hello" });
  assert.ok(await pr.verifyWithRaw(jsPub, rsSig, "hello"));
  const jsSig = await pr.signBytes(jsPair.privateKey, utf8("hello"));
  assert.equal(rust({ op: "cv.verifyText", pub: jsPub, signature: jsSig, text: "hello" }), true);
  assert.equal(rust({ op: "cv.verifyText", pub: jsPub, signature: jsSig, text: "hellO" }), false);

  const rsPair = rust({ op: "cv.generatePair" });
  const imported = await pr.importSignPrivate(rsPair.priv);
  const sig2 = await pr.signBytes(imported, utf8("x"));
  assert.equal(rust({ op: "cv.verifyText", pub: rsPair.pub, signature: sig2, text: "x" }), true);

  const ecdhKey = await pr.importEcdhPrivate(rsPair.priv);
  const sealed = await pr.sealTo(rsPair.pub, utf8("sealed in js"), "c");
  assert.equal(fromUtf8(fromB64(rust({ op: "cv.openSealed", priv: rsPair.priv, pub: rsPair.pub, sealed, context: "c" }))), "sealed in js");
  const sealed2 = rust({ op: "cv.sealTo", pub: rsPair.pub, plaintext: toB64(utf8("sealed in rust")), context: "c" });
  assert.equal(fromUtf8(await pr.openSealed(ecdhKey, rsPair.pub, sealed2, "c")), "sealed in rust");
  assert.equal(rustCode({ op: "cv.openSealed", priv: rsPair.priv, pub: rsPair.pub, sealed, context: "d" }), "DECRYPT_FAILED");
});

test("keyrings: each side's keys check out in the other, and travel between devices", { skip }, async () => {
  const jsRing = kr.newKeyring("u1", await kr.createKeyVersion(1));
  assert.equal(rust({ op: "cv.assertKeyringConsistent", keyring: jsRing }), true);
  const rsRing = rust({ op: "cv.newKeyring", userId: "u2", first: rust({ op: "cv.createKeyVersion", version: 1 }) });
  await kr.assertKeyringConsistent(rsRing);
  const grown = rust({ op: "cv.withVersion", keyring: rsRing, keyVersion: rust({ op: "cv.createKeyVersion", version: 2 }) });
  await kr.assertKeyringConsistent(kr.validateKeyring(grown, "u2"));
  assert.equal(rustCode({ op: "cv.withVersion", keyring: rsRing, keyVersion: rust({ op: "cv.createKeyVersion", version: 3 }) }), "BAD_FORMAT");

  // A mismatched key is caught by both.
  const swapped = structuredClone(grown);
  swapped.versions[1].sign_pub = grown.versions[0].sign_pub;
  assert.equal(await jsCode(() => kr.assertKeyringConsistent(swapped)), "CryptoFormatError");
  assert.equal(rustCode({ op: "cv.assertKeyringConsistent", keyring: swapped }), "BAD_FORMAT");

  // JavaScript seals to a Rust device (post-quantum); Rust opens. And back (classical).
  const dev = await rustDevice();
  const toRust = await kr.sealKeyringToDevice(jsRing, dev, dev.kem_pub);
  assert.ok(toRust.sealed.kct);
  const opened = rust({ op: "cv.openKeyringFromDevice", boxPriv: dev.box_priv, boxPub: dev.box_pub, kemPriv: dev.kem_priv, userId: "u1", deviceId: dev.device_id, keyringVersion: 1, sealed: toRust.sealed });
  assert.deepEqual(opened, jsRing);
  const jsDev = { device_id: "dJS", ...rust({ op: "cv.generatePair" }) };
  const toJs = rust({ op: "cv.sealKeyringToDevice", keyring: grown, device: { device_id: jsDev.device_id, box_pub: jsDev.pub } });
  assert.ok(toJs.sealed.epk);
  const back = await kr.openKeyringFromDevice({ boxPriv: await pr.importEcdhPrivate(jsDev.priv), boxPub: jsDev.pub, userId: "u2", deviceId: "dJS", keyringVersion: 2, sealed: toJs.sealed });
  assert.deepEqual(back, grown);
  assert.equal(rustCode({ op: "cv.openKeyringFromDevice", boxPriv: dev.box_priv, boxPub: dev.box_pub, kemPriv: dev.kem_priv, userId: "u1", deviceId: "other", keyringVersion: 1, sealed: toRust.sealed }), "KEM_FAILED");
});

test("envelopes: mixed classical and post-quantum recipients, both directions, same refusals", { skip }, async () => {
  const pq = kr.newKeyring("alice", await kr.createKeyVersion(1));
  const old = kr.newKeyring("bob", { ...(await kr.createKeyVersion(1)) });
  delete old.versions[0].kem_pub;
  delete old.versions[0].kem_priv;
  const recipients = [
    { user_id: "alice", key_version: 1, ecdh_pub: pq.versions[0].ecdh_pub, kem_pub: pq.versions[0].kem_pub },
    { user_id: "bob", key_version: 1, ecdh_pub: old.versions[0].ecdh_pub },
  ];
  const scope = { kind: "message", conversation_id: "c1", item_id: "i1", sender_id: "alice", device_id: "d1" };
  const payload = { text: "Hello £ ✓", n: 3 };

  const fromJs = await env.encryptEnvelope({ scope, recipients, payload });
  assert.equal(fromJs.v, 3);
  for (const [userId, keyring] of [["alice", pq], ["bob", old]]) {
    assert.deepEqual(rust({ op: "cv.decryptEnvelope", scope, envelope: fromJs, userId, keyring }), payload);
  }
  const fromRust = rust({ op: "cv.encryptEnvelope", scope, recipients, payload });
  assert.equal(fromRust.v, 3);
  for (const [userId, keyring] of [["alice", pq], ["bob", old]]) {
    assert.deepEqual(await env.decryptEnvelope({ scope, envelope: JSON.stringify(fromRust), userId, keyring }), payload);
  }

  const cases = [
    ["moved to another item", { ...scope, item_id: "i2" }, fromJs, "alice"],
    ["not addressed", scope, fromJs, "carol"],
    ["bad commitment", scope, { ...fromJs, kc: toB64(new Uint8Array(32)) }, "alice"],
    ["malformed", scope, { ...fromJs, wraps: [] }, "alice"],
    ["unknown kind", { ...scope, kind: "nope" }, fromJs, "alice"],
  ];
  for (const [what, sc, e, userId] of cases) {
    const keyring = userId === "alice" ? pq : old;
    const j = await jsCode(() => env.decryptEnvelope({ scope: sc, envelope: e, userId, keyring }));
    assert.equal(rustCode({ op: "cv.decryptEnvelope", scope: sc, envelope: e, userId, keyring }), j, what);
    assert.ok(j, what);
  }
});

test("identity: key histories, digests, pins, safety numbers and link codes agree", { skip }, async () => {
  const recovery = rust({ op: "cv.recoveryPublic", phrase: rc.generateRecoveryPhrase() });
  const v1 = await kr.createKeyVersion(1);
  const v2 = rust({ op: "cv.createKeyVersion", version: 2 });
  const s1 = await id.makeAccountStatement({ userId: "u1", keyVersion: v1, recoveryPub: recovery.publicKey, recoveryKemPub: recovery.kemPublicKey, signer: v1 });
  const s2 = rust({ op: "cv.makeAccountStatement", userId: "u1", keyVersion: v2, recoveryPub: recovery.publicKey, recoveryKemPub: recovery.kemPublicKey, signer: v1 });
  const statements = [s2, s1];
  const jsChain = await id.verifyAccountChain("u1", statements);
  const rsChain = rust({ op: "cv.verifyAccountChain", userId: "u1", statements });
  assert.equal(rsChain.rootVersion, jsChain.rootVersion);
  assert.deepEqual(rsChain.digests, Object.fromEntries([...jsChain.digests].map(([k, v]) => [String(k), v])));

  const pin = { version: 1, digest: jsChain.digests.get(1) };
  assert.equal(rust({ op: "cv.compareWithPin", userId: "u1", statements, pin }), id.compareWithPin(jsChain, pin));
  const keyring = kr.withVersion(kr.newKeyring("u1", v1), v2);
  assert.equal(rust({ op: "cv.anchorChain", userId: "u1", statements, keyring }), id.anchorChain(jsChain, { keyring }));

  const forged = { ...s2, sign_pub: v1.sign_pub };
  for (const bad of [[s1, forged], [s2], [s1, { ...s2, user_id: "u2" }]]) {
    const j = await jsCode(() => id.verifyAccountChain("u1", bad));
    assert.equal(rustCode({ op: "cv.verifyAccountChain", userId: "u1", statements: bad }), j);
  }

  const head = id.headDigest(jsChain);
  const a = { user_id: "u1", digest: head };
  const b = { user_id: "u0", digest: "other-history" };
  assert.equal(rust({ op: "cv.safetyNumber", a, b }), id.safetyNumber(a, b));
  const lc = { userId: "u1", deviceId: "d1", signPub: v1.sign_pub, boxPub: v1.ecdh_pub, kemPub: v1.kem_pub, accountDigest: head };
  assert.equal(rust({ op: "cv.linkCode", ...lc }), id.linkCode(lc));
  assert.equal(rust({ op: "cv.linkCode", ...lc, kemPub: "" }), id.linkCode({ ...lc, kemPub: "" }));
});

test("identity: device certificates, device keys, proofs and item signatures verify both ways", { skip }, async () => {
  const v1 = await kr.createKeyVersion(1);
  const st = await id.makeAccountStatement({ userId: "u1", keyVersion: v1, recoveryPub: v1.ecdh_pub, signer: v1 });
  const chain = await id.verifyAccountChain("u1", [st]);
  const dev = await rustDevice();

  const rsCert = rust({ op: "cv.makeDeviceCert", userId: "u1", device: dev, keyVersion: v1, kemPub: dev.kem_pub });
  assert.ok(await id.verifyDeviceCert(rsCert, chain));
  const jsCert = await id.makeDeviceCert({ userId: "u1", device: dev, keyVersion: v1 });
  assert.equal(rust({ op: "cv.verifyDeviceCert", cert: jsCert, userId: "u1", statements: [st] }), true);
  assert.equal(rust({ op: "cv.verifyDeviceCert", cert: { ...jsCert, box_pub: dev.sign_pub }, userId: "u1", statements: [st] }), false);

  const jsKemSig = await id.signDeviceKem({ userId: "u1", device: { ...dev, sign_priv: dev.sign_key } });
  assert.equal(rust({ op: "cv.verifyDeviceKem", userId: "u1", deviceId: dev.device_id, signPub: dev.sign_pub, kemPub: dev.kem_pub, signature: jsKemSig }), true);
  const rsKemSig = rust({ op: "cv.signDeviceKem", userId: "u1", device: dev });
  assert.ok(await id.verifyDeviceKem({ userId: "u1", deviceId: dev.device_id, signPub: dev.sign_pub, kemPub: dev.kem_pub, signature: rsKemSig }));

  const payloadJson = JSON.stringify({ a: 1 });
  const proof = await id.makeDeviceProof({ userId: "u1", device: { ...dev, sign_priv: dev.sign_key }, action: "send", payloadJson });
  assert.equal(rust({ op: "cv.verifyDeviceProof", userId: "u1", signPub: dev.sign_pub, action: "send", payloadJson, proof }), true);
  assert.equal(rust({ op: "cv.verifyDeviceProof", userId: "u1", signPub: dev.sign_pub, action: "delete", payloadJson, proof }), false);

  const item = { kind: "message", conversationId: "c1", itemId: "i1", senderId: "u1", deviceId: dev.device_id, envelopeJson: '{"v":3}', sentAt: "2026-11-15T10:00:00.000Z" };
  const rsSig = rust({ op: "cv.signItem", device: dev, item });
  assert.ok(await id.verifyItem({ signPub: dev.sign_pub, signature: rsSig, ...item }));
  const jsSig = await id.signItem({ device: { sign_priv: dev.sign_key }, ...item });
  assert.equal(rust({ op: "cv.verifyItem", signPub: dev.sign_pub, signature: jsSig, item }), true);
  assert.equal(rust({ op: "cv.verifyItem", signPub: dev.sign_pub, signature: jsSig, item: { ...item, envelopeJson: '{"v":2}' } }), false);
});

test("recovery: the same keys from a phrase, anchors agree, backups open in Rust", { skip }, async () => {
  const phrase = rust({ op: "cv.generatePhrase" });
  assert.ok(rc.isValidPhrase(phrase));
  const jsKeys = await rc.deriveRecoveryKey(phrase);
  const rsKeys = rust({ op: "cv.recoveryPublic", phrase: phrase.toUpperCase().replace(/ /g, "  ") });
  assert.equal(rsKeys.publicKey, jsKeys.publicKey);
  assert.equal(rsKeys.kemPublicKey, jsKeys.kemPublicKey);
  assert.equal(rust({ op: "cv.isValidPhrase", phrase: phrase.replace(/\w+$/, "zoo") }), rc.isValidPhrase(phrase.replace(/\w+$/, "zoo")));

  const v1 = await kr.createKeyVersion(1);
  const st = await id.makeAccountStatement({ userId: "u1", keyVersion: v1, recoveryPub: jsKeys.publicKey, recoveryKemPub: jsKeys.kemPublicKey, signer: v1 });
  const mac = await rc.recoveryAnchorMac(jsKeys.anchorKey, st);
  assert.equal(rust({ op: "cv.recoveryAnchorMac", phrase, statement: st }), mac);
  assert.equal(rust({ op: "cv.verifyRecoveryAnchor", phrase, statement: { ...st, recovery_mac: mac } }), true);
  assert.equal(rust({ op: "cv.verifyRecoveryAnchor", phrase, statement: { ...st, issued_at: "x", recovery_mac: mac } }), false);

  const keyring = kr.newKeyring("u1", v1);
  for (const kemPub of [jsKeys.kemPublicKey, ""]) {
    const backup = await kr.sealKeyringForRecovery(keyring, jsKeys.publicKey, kemPub);
    const opened = rust({ op: "cv.openKeyringWithPhrase", phrase, userId: "u1", keyringVersion: 1, recoveryPub: jsKeys.publicKey, recoveryKemPub: kemPub, sealed: backup.sealed });
    assert.deepEqual(opened, keyring);
  }
  const rsBackup = rust({ op: "cv.sealKeyringForRecovery", keyring, recoveryPub: jsKeys.publicKey, recoveryKemPub: jsKeys.kemPublicKey });
  assert.deepEqual(await rc.openKeyringWithRecoveryKey({ keys: jsKeys, userId: "u1", keyringVersion: 1, recoveryPub: jsKeys.publicKey, recoveryKemPub: jsKeys.kemPublicKey, sealed: rsBackup.sealed }), keyring);
  const other = rc.generateRecoveryPhrase();
  assert.equal(rustCode({ op: "cv.openKeyringWithPhrase", phrase: other, userId: "u1", keyringVersion: 1, recoveryPub: jsKeys.publicKey, sealed: rsBackup.sealed }), "WRONG_PHRASE");
  rc.wipeRecoveryKey(jsKeys);
});

test("passcode lock and owner key agree", { skip }, async () => {
  const fast = 100_000;
  const rs = rust({ op: "cv.createLock", passcode: "correct horse ﬁ", idleMinutes: 15, iterations: fast });
  // NFKC: the "ﬁ" ligature and "fi" are the same passcode on both sides.
  const jsKey = await lock.unlock("correct horse fi", rs.record);
  const stored = await lock.sealKeyringText(jsKey, "u1", "{\"k\":1}");
  assert.equal(rust({ op: "cv.openKeyringText", key: rs.key, userId: "u1", stored }), "{\"k\":1}");
  const js = await lock.createLock("another passcode", 5, { iterations: fast });
  const key = rust({ op: "cv.unlock", passcode: "another passcode", record: js.record });
  const rsStored = rust({ op: "cv.sealKeyringText", key, userId: "u1", text: "secret" });
  assert.equal(await lock.openKeyringText(js.key, "u1", rsStored), "secret");
  assert.equal(rustCode({ op: "cv.unlock", passcode: "wrong passcode", record: js.record }), await jsCode(() => lock.unlock("wrong passcode", js.record)));

  const phrase = rc.generateRecoveryPhrase();
  const priv = owner.privateKeyFromPhrase(phrase);
  assert.equal(rust({ op: "cv.privateKeyFromPhrase", phrase }), priv);
  assert.equal(rust({ op: "cv.phraseFromPrivateKey", key: priv }), phrase);
  const ok = await owner.ownerKey(phrase);
  assert.equal(rust({ op: "cv.ownerPublic", input: priv }), ok.publicKey);
  const sig = owner.signOwner(ok, { host: "commonveil.online", purpose: "recover", challenge: "c1" });
  assert.equal(rust({ op: "cv.signOwner", input: phrase, host: "commonveil.online", purpose: "recover", challenge: "c1" }), sig);
  assert.equal(rust({ op: "cv.verifyOwner", publicKey: ok.publicKey, signature: sig, host: "commonveil.online", purpose: "recover", challenge: "c1" }), true);
  assert.equal(rust({ op: "cv.verifyOwner", publicKey: ok.publicKey, signature: sig, host: "evil.example", purpose: "recover", challenge: "c1" }), false);
});

test("servers: ratchets, generations, grants, items and invite previews agree", { skip }, async () => {
  const key = new Uint8Array(32).fill(5);
  assert.equal(rust({ op: "cv.ratchetTo", key: toB64(key), chainId: "s1.l", generation: 2, fromStep: 0, toStep: 5 }), toB64(sk.ratchetTo(key, "s1.l", 2, 0, 5)));
  assert.equal(rust({ op: "cv.generationCommit", chainId: "s1.h", generation: 0, key: toB64(key) }), sk.generationCommit("s1.h", 0, key));
  const started = "2026-11-15T00:00:00.000Z";
  const at = Date.parse("2026-11-15T07:30:00.000Z");
  assert.equal(rust({ op: "cv.stepAt", chainId: "s1.l", startedAt: started, atMs: at }), sk.stepAt("s1.l", started, at));

  const dev = await rustDevice();
  const jsDevice = { device_id: dev.device_id, sign_priv: dev.sign_key };
  const gen = rust({ op: "cv.makeGeneration", serverId: "s1", chainId: "s1.l", generation: 1, userId: "u1", device: dev, startedAt: started });
  assert.ok(await sk.verifyGeneration(gen.generation, dev.sign_pub));
  const jsGen = await sk.makeGeneration({ serverId: "s1", chainId: "s1.h", generation: 0, userId: "u1", device: jsDevice });
  assert.equal(rust({ op: "cv.verifyGeneration", generation: jsGen.generation, signPub: dev.sign_pub }), true);
  assert.equal(rust({ op: "cv.verifyGeneration", generation: { ...jsGen.generation, generation: 1 }, signPub: dev.sign_pub }), false);

  const ring = kr.newKeyring("u2", await kr.createKeyVersion(1));
  const v = ring.versions[0];
  for (const kemPub of [v.kem_pub, undefined]) {
    const recipient = { user_id: "u2", key_version: 1, ecdh_pub: v.ecdh_pub, kem_pub: kemPub };
    const jsGrant = await sk.makeGrant({ serverId: "s1", chainId: "s1.l", generation: 1, step: 3, keyBytes: key, recipient, userId: "u1", device: jsDevice });
    assert.equal(rust({ op: "cv.verifyGrant", grant: jsGrant, signPub: dev.sign_pub }), true);
    assert.equal(rust({ op: "cv.openGrant", grant: jsGrant, userId: "u2", keyring: ring }), toB64(key));
    const rsGrant = rust({ op: "cv.makeGrant", serverId: "s1", chainId: "s1.l", generation: 1, step: 3, key: toB64(key), recipient, userId: "u1", device: dev });
    assert.ok(await sk.verifyGrantSignature(rsGrant, dev.sign_pub));
    assert.deepEqual(await sk.openGrant({ grant: rsGrant, userId: "u2", keyring: ring }), key);
    assert.equal(rustCode({ op: "cv.openGrant", grant: { ...rsGrant, step: 4 }, userId: "u2", keyring: ring }), "GRANT_UNREADABLE");
  }

  const base = { kind: "message", server_id: "s1", channel_id: "c1", item_id: "i1", sender_id: "u1", device_id: dev.device_id };
  const k3 = sk.ratchetTo(key, "s1.l", 1, 0, 3);
  const scope = { ...base, chain_id: "s1.l", generation: 1, step: 3 };
  const payload = { text: "hi there" };
  const keys = new sk.ChainKeys();
  keys.add("s1.l", 1, 0, key);
  const rsKeys = [{ chain: "s1.l", gen: 1, step: 0, key: toB64(key) }];
  const jsEnv = await sk.encryptServerItem({ scope, chainKey: k3, payload });
  assert.deepEqual(rust({ op: "cv.decryptServerItem", base, envelope: JSON.stringify(jsEnv), keys: rsKeys }).payload, payload);
  const rsEnv = rust({ op: "cv.encryptServerItem", scope, chainKey: toB64(k3), payload });
  assert.deepEqual((await sk.decryptServerItem({ base, envelope: rsEnv, keys })).payload, payload);
  for (const [b, e, k] of [[{ ...base, item_id: "i9" }, jsEnv, rsKeys], [base, jsEnv, [{ ...rsKeys[0], step: 4 }]], [base, { ...jsEnv, gen: 2 }, rsKeys]]) {
    const jk = new sk.ChainKeys();
    jk.add(k[0].chain, k[0].gen, k[0].step, fromB64(k[0].key));
    assert.equal(rustCode({ op: "cv.decryptServerItem", base: b, envelope: e, keys: k }), await jsCode(() => sk.decryptServerItem({ base: b, envelope: e, keys: jk })));
  }

  const item = { kind: "message", serverId: "s1", channelId: "", itemId: "i1", senderId: "u1", deviceId: dev.device_id, envelopeJson: JSON.stringify(rsEnv), sentAt: started };
  const rsSig = rust({ op: "cv.signServerItem", device: dev, item });
  assert.ok(await sk.verifyServerItem({ signPub: dev.sign_pub, signature: rsSig, ...item }));
  const jsSig = await sk.signServerItem({ device: jsDevice, ...item });
  assert.equal(rust({ op: "cv.verifyServerItem", signPub: dev.sign_pub, signature: jsSig, item }), true);

  const secret = sk.newInviteSecret();
  const sealed = await sk.sealInvitePreview({ code: "INV1", secret, preview: { name: "The Agora" } });
  assert.deepEqual(rust({ op: "cv.openInvitePreview", code: "INV1", secret, sealed }), { name: "The Agora" });
  assert.equal(rust({ op: "cv.openInvitePreview", code: "INV2", secret, sealed }), null);
  const rsSealed = rust({ op: "cv.sealInvitePreview", code: "INV1", secret, preview: { name: "A" } });
  assert.deepEqual(await sk.openInvitePreview({ code: "INV1", secret, sealed: rsSealed }), { name: "A" });
});

test("devices made in Rust have the JavaScript's public shape", { skip }, async () => {
  const jsDev = await createDeviceKeys("Phone");
  const rsDev = rust({ op: "cv.createDeviceKeys", label: "Phone" });
  const shape = (d) => Object.keys(d).sort();
  assert.deepEqual(shape(rust({ op: "cv.publicDevice", device: rsDev })), shape({ device_id: 1, sign_pub: 1, box_pub: 1, label: 1, kem_pub: 1 }));
  assert.deepEqual(Object.keys(rsDev).sort(), shape(jsDev));
});
