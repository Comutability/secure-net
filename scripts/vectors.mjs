// Test vectors for CVP-016: fixed inputs to every derivation in the session protocol, and what
// each must produce. Another implementation that matches these agrees with this one byte for byte.
//
//   node scripts/vectors.mjs           write spec/vectors/cvp-016-v1.json
//   node scripts/vectors.mjs --check   fail if the file and the code disagree
import fs from "node:fs";
import path from "node:path";
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { handshakeSecret, kdfRoot, kdfChain, messageKeys, transcriptHash, seal } from "../src/session/primitives.js";
import { linkCode, safetyNumber } from "../src/session/keys.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const file = path.join(root, "spec/vectors/cvp-016-v1.json");
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

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const json = `${JSON.stringify(await vectors(), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    if (fs.readFileSync(file, "utf8") !== json) {
      console.error("spec/vectors/cvp-016-v1.json doesn't match the code");
      process.exit(1);
    }
    console.log("CVP-016 vectors match");
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, json);
    console.log(`wrote ${path.relative(root, file)}`);
  }
}
