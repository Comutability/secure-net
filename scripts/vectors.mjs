// Test vectors (CVP-000, section 8): fixed inputs and what each must produce. Another
// implementation that matches these agrees with this one byte for byte.
//
//   cvp-002-v1.json  canonical JSON and signed records (Ed25519 and Ed25519 + ML-DSA-65)
//   cvp-016-v1.json  every derivation in the session protocol
//
//   node scripts/vectors.mjs           write them
//   node scripts/vectors.mjs --check   fail if the files and the code disagree
import fs from "node:fs";
import path from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { handshakeSecret, kdfRoot, kdfChain, messageKeys, transcriptHash, seal } from "../src/session/primitives.js";
import { linkCode, safetyNumber } from "../src/session/keys.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { canonicalJson } from "../src/core/canonical.js";
import { signingBytes, keyId, checkSignature, recordId, ALG, HYBRID_ALG } from "../src/core/signed.js";
import { b64u } from "../src/core/bytes.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const files = { "cvp-002-v1.json": () => signedRecordVectors(), "cvp-016-v1.json": () => vectors() };
const hex = (b) => Buffer.from(b).toString("hex");
const seq = (start, n = 32) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const utf8 = (s) => new TextEncoder().encode(s);

export async function vectors() {
  const aSk = seq(0x01);
  const bSk = seq(0x41);
  const kemSeed = seq(0x81, 64);
  const coins = seq(0xc1);
  const { publicKey: kemPk } = ml_kem768.keygen(kemSeed);
  const enc = ml_kem768.encapsulate(kemPk, coins);
  const transcript = { v: 1, initiator: { account: "A", device: "a1", sign: "As", dh: "Ad" }, responder: { account: "B", device: "b1", sign: "Bs", dh: "Bd" }, ek: "E", ct: "C", signed: "s", pq: "p", oneTime: null };
  const th = transcriptHash(transcript);
  const dhs = [seq(0x10), seq(0x30), seq(0x50), seq(0x70)];
  const ss = seq(0x90);
  const root1 = kdfRoot(seq(0x00), seq(0x20), seq(0x40));
  const root0 = kdfRoot(seq(0x00), seq(0x20));
  const chain = kdfChain(seq(0x60));
  const mkeys = messageKeys(chain.mk);
  return {
    description: "CVP-016 session protocol, version 1. All byte strings are hex. seq(s, n) means the n bytes s, s+1, s+2, ... (mod 256).",
    x25519: { aSecret: hex(aSk), bSecret: hex(bSk), aPublic: hex(x25519.getPublicKey(aSk)), bPublic: hex(x25519.getPublicKey(bSk)), shared: hex(x25519.getSharedSecret(aSk, x25519.getPublicKey(bSk))) },
    mlkem768: { seed: hex(kemSeed), coins: hex(coins), publicKeySha256: hex(sha256(kemPk)), cipherTextSha256: hex(sha256(enc.cipherText)), sharedSecret: hex(enc.sharedSecret) },
    transcript: { input: transcript, hash: hex(th) },
    handshake: { dh: dhs.map(hex), mlkem: hex(ss), transcriptHash: hex(th), secret: hex(handshakeSecret(dhs, ss, th)), threeDh: hex(handshakeSecret(dhs.slice(0, 3), ss, th)) },
    root: { rk: hex(seq(0x00)), dh: hex(seq(0x20)), mlkem: hex(seq(0x40)), out: { rk: hex(root1.rk), ck: hex(root1.ck) }, withoutMlkem: { rk: hex(root0.rk), ck: hex(root0.ck) } },
    chain: { ck: hex(seq(0x60)), mk: hex(chain.mk), next: hex(chain.ck) },
    message: { mk: hex(chain.mk), key: hex(mkeys.key), iv: hex(mkeys.iv), plaintext: "secure-net", ad: hex(utf8("ad")), ciphertext: hex(await seal(chain.mk, utf8("secure-net"), utf8("ad"))) },
    codes: { linkCode: linkCode({ sign: "S", dh: "D" }), safetyNumber: safetyNumber("A", "B") },
  };
}


/** CVP-002: canonical JSON, and signed records with a classical and a quantum-resistant key. */
export async function signedRecordVectors() {
  const canonical = [
    { name: "keys sorted by UTF-16 code unit, no whitespace", json: '{"z":1,"a":[3,2,1],"B":{"y":null,"x":true}}' },
    { name: "non-ASCII keys sort after ASCII; astral characters by their surrogates", json: '{"\\uffff":1,"\\ud83d\\ude00":2,"\\u00e9":3,"a":4,"B":5}' },
    { name: "strings: only quote, backslash and control characters are escaped; other text is raw UTF-8", json: '{"s":"line\\nbreak\\ttab \\u0007 \\"q\\" \\\\ / \\u00e9 \\u2028 \\ud83d\\ude00"}' },
    { name: "integers in the safe range; negative zero becomes 0", json: '[0,-0,9007199254740991,-9007199254740991,true,false,null,""]' },
    { name: "empty containers", json: '{"a":{},"b":[]}' },
  ].map((c) => {
    const text = canonicalJson(JSON.parse(c.json));
    return { ...c, canonical: text, canonicalUtf8: hex(utf8(text)) };
  });
  const refused = [
    { name: "a fraction", json: "1.5" },
    { name: "a number past 2^53 - 1", json: "9007199254740992" },
    { name: "an exponent that isn't a safe integer", json: "1e300" },
    { name: "a lone surrogate", json: '"\\ud800"' },
  ].map((c) => {
    try {
      canonicalJson(JSON.parse(c.json));
      throw new Error(`${c.name} was accepted`);
    } catch (e) {
      if (e.code !== "NOT_CANONICAL") throw e;
      return { ...c, result: "refused" };
    }
  });

  const kind = "example.note";
  const body = { text: "Built together. Open to everyone.", n: 7, tags: ["a", "b"] };
  const bytes = signingBytes(kind, body);

  const edSecret = seq(0x21);
  const edPub = b64u(ed25519.getPublicKey(edSecret));
  const classical = { kind, body, sig: { kid: keyId(edPub), alg: ALG, value: b64u(ed25519.sign(bytes, edSecret)) } };

  const pqSeed = seq(0x61);
  const pq = ml_dsa65.keygen(pqSeed);
  const hybridPub = `${edPub}.${b64u(pq.publicKey)}`;
  const hybrid = { kind, body, sig: { kid: keyId(hybridPub), alg: HYBRID_ALG, value: classical.sig.value, pq: b64u(ml_dsa65.sign(bytes, pq.secretKey, { extraEntropy: false })) } };
  for (const [r, k] of [[classical, edPub], [hybrid, hybridPub]]) if (!checkSignature(r, r.sig, k)) throw new Error("vector doesn't verify");

  const { pq: _drop, ...stripped } = hybrid.sig;
  const mustRefuse = [
    { name: "body changed after signing", record: { ...classical, body: { ...body, n: 8 } }, publicKey: edPub },
    { name: "same signature presented as another kind", record: { ...classical, kind: "example.other" }, publicKey: edPub },
    { name: "quantum-resistant key, ML-DSA-65 signature removed", record: { ...hybrid, sig: { ...stripped, alg: ALG } }, publicKey: hybridPub },
    { name: "quantum-resistant key, ML-DSA-65 signature from a different body", record: { ...hybrid, sig: { ...hybrid.sig, pq: b64u(ml_dsa65.sign(signingBytes(kind, { ...body, n: 8 }), pq.secretKey, { extraEntropy: false })) } }, publicKey: hybridPub },
    { name: "key id that isn't the hash of the key", record: { ...classical, sig: { ...classical.sig, kid: keyId(hybridPub) } }, publicKey: edPub },
  ];
  for (const m of mustRefuse) if (checkSignature(m.record, m.record.sig, m.publicKey)) throw new Error(`${m.name} was accepted`);

  return {
    description: "CVP-002 canonical JSON and signed records, version 1. Byte strings are hex unless a field says base64url. json fields are JSON texts to parse first. seq(s, n) means the n bytes s, s+1, ... (mod 256). ML-DSA-65 is FIPS 204 ML-DSA.Sign with an empty context; these signatures were made deterministically so they can be reproduced, but implementations may sign with randomness (hedged), so check by verifying, not by comparing.",
    canonical,
    refused,
    signingBytes: { kind, body, layout: "the label secure-net/<kind>/v1 in UTF-8, the byte 0x0a, then the canonical JSON of the body", label: `secure-net/${kind}/v1`, hex: hex(bytes) },
    classical: { secretKey: hex(edSecret), publicKey: edPub, record: classical, recordId: recordId(classical) },
    hybrid: { ed25519Secret: hex(edSecret), mldsa65Seed: hex(pqSeed), publicKey: hybridPub, record: hybrid, recordId: recordId(hybrid) },
    mustRefuse,
  };
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  let failed = false;
  for (const [name, make] of Object.entries(files)) {
    const file = path.join(root, "spec/vectors", name);
    const json = `${JSON.stringify(await make(), null, 2)}\n`;
    if (process.argv.includes("--check")) {
      const same = fs.existsSync(file) && fs.readFileSync(file, "utf8") === json;
      console.log(same ? `${name} matches` : `${name} doesn't match the code`);
      failed ||= !same;
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, json);
      console.log(`wrote spec/vectors/${name}`);
    }
  }
  process.exit(failed ? 1 : 0);
}
