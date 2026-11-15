# Secure Net in Rust

A port of the JavaScript reference library to Rust, compiled to WebAssembly so the same code can
run in browsers, Node.js, Deno and on servers. It is the first step of moving Secure Net, and then
Commonveil's cryptography, onto Rust.

**Status: in progress, and not reviewed.** Nothing here has been examined by a human
cryptographer or audited. The RustCrypto `ml-dsa` and `ml-kem` crates it uses say the same of
themselves.

## What is ported

| Part | Rust | Checked against |
| --- | --- | --- |
| Canonical JSON (CVP-002) | `canonical` | `spec/vectors/cvp-002-v1.json`; byte-for-byte with the JavaScript on sample values |
| Signed records, Ed25519 and Ed25519 + ML-DSA-65 (CVP-002) | `signed` | The vectors, including reproducing the JavaScript's exact deterministic ML-DSA-65 signature; signatures made by each side verify on the other |
| Session primitives (CVP-016) | `session::primitives` | Every derivation in `cvp-016-v1.json` (X25519, ML-KEM-768, handshake, root and chain steps, AES-256-GCM, safety number, link code) |
| Accounts, devices, prekeys, bundles (CVP-016) | `session::keys` | Rust tests |
| One-to-one sessions, version 1 (CVP-016) | `session::v1` | Conversations that alternate between the two implementations, including the same session state moving from one to the other mid-conversation (`test/rust-interop.test.mjs`) |
| Commonveil's cryptography (`src/crypto/*`) | `cv` (`cv.*` operations) | `test/rust-crypto-interop.test.mjs`: keys, seals, envelopes, key histories, certificates, proofs, item signatures, recovery backups, the passcode lock, owner keys, server key chains, grants, items and invite previews made by each side open or verify on the other, with the same refusal codes. The MLKEM768-P256 hybrid KEM matches `@noble/post-quantum` byte for byte with fixed randomness (`tests/vectors/cv-kem.json`); BIP-39 matches the reference vectors |

Not yet ported: sessions version 2, sender keys and history transfer, the social protocol,
groups, the commons ledger, governance, private tokens, consent, extensions, and the site-to-site
wire. They come next, in that rough order, each checked the same way.

## How it is used

Every operation is one JSON request and one JSON reply (`secure_net_core::api`), with the same
JSON the JavaScript uses, so state saved by one can be loaded by the other:

```js
import init, { call } from "./pkg/secure_net_wasm.js";
await init();
const reply = JSON.parse(call(JSON.stringify({ op: "encrypt", state, plaintext, now: Date.now() })));
```

From Rust, use the modules directly.

## Working on it

```bash
cd rust
cargo test                       # the Rust tests, against spec/vectors
cargo build --example cli        # then, from the repository root:
node --test test/rust-interop.test.mjs test/rust-crypto-interop.test.mjs
cargo build --release --target wasm32-unknown-unknown -p secure-net-wasm
```

CI runs all of these, and runs the interop test a second time against the WebAssembly build.

## Checks

- `cargo clippy --all-targets -- -D warnings` is clean, and `secure-net-core` forbids `unsafe`
  code.
- Mutation check of the Commonveil port: each of 19 security guards (key commitments, wrap
  shapes, duplicate recipients, key-history signatures, gaps and owners, account resets,
  certificate owners, keyring consistency and version, server item commitments, the forward
  ratchet, grant recipients, the recovery phrase match, the BIP-39 checksum, the lock's
  iteration floor, the owner key checksum and the KEM's point check) was removed in turn. 18
  made a test fail. The 19th, the explicit `0x04` prefix check on P-256 public keys, is already
  enforced by the SEC 1 decoder underneath (a test confirms the `0x06`/`0x07` forms are refused
  either way), so it stays as defence in depth.

## Known differences from the JavaScript

- **Ed25519 verification rules.** The JavaScript (noble) accepts signatures under ZIP-215 rules;
  `ed25519-dalek` uses its own rules. Honest signatures verify on both, but a deliberately
  malformed signature could be accepted by one and refused by the other. That matters wherever
  several parties must agree, such as the commons ledger, and must be settled (and specified)
  before the ledger is ported.
- **Secrets in memory.** The protocol port keeps secret keys in JSON strings, as the
  JavaScript does, so they are not wiped after use. The Commonveil port wipes the secrets it
  derives (content keys, shared secrets, KEM seeds, lock keys, recovery keys) with `zeroize`,
  but keyrings themselves travel as JSON, as they do in the JavaScript.
- **Keys a browser can't export.** In the browser, Commonveil makes each device's signing and box
  keys, and the passcode lock key, as non-extractable WebCrypto keys. WebAssembly memory can't
  give that guarantee, so web clients should keep making and holding those keys with WebCrypto
  and use the Rust code for everything else. `cv.createDeviceKeys` and `cv.unlock` (which returns
  the lock key) are for native clients and tests.
- **ECDSA nonces.** Rust signs P-256 with RFC 6979 deterministic nonces; WebCrypto uses random
  ones. Both verify everywhere; signatures from the two simply aren't byte-identical.
- **Recovery secrets never leave Rust.** The recovery operations take the phrase and return only
  public keys, MACs and opened backups, never the derived secrets.
- **ISO times.** Statements carry `toISOString()` times. Rust writes them from the `now` it is
  given, and reads only that exact form (`YYYY-MM-DDTHH:MM:SS.sssZ`, fraction optional), where
  JavaScript's `Date.parse` accepts more.
- **Signing randomness.** ML-DSA-65 signatures are hedged (fresh randomness), as the
  specification allows, so they differ from run to run; they are checked by verifying, not by
  comparing.

Licence: AGPL-3.0-only, like the rest of Secure Net.
