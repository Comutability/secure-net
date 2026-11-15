# Secure Net

Secure Net is the Commonveil Protocol as a library: private, end-to-end encrypted, federated
communication that any app or website can use. Commonveil is built on it, and so can anything
else that wants to talk to Commonveil sites, or to build its own network the same way.

It's written in Rust (`rust/secure-net-core`). The same code runs in browsers, Node.js and Deno
as WebAssembly: that's the npm package, `@comutability/secure-net`. It needs no particular
backend, database or host.

**Status: draft.** Nothing here has had a human cryptographic review yet. Don't rely on it for
anything that matters until it has.

## What's in it

| Module (`secure_net_core::`) | What it does | Spec |
| --- | --- | --- |
| `session` | **End-to-end messaging, post-quantum.** A handshake and double ratchet built on X25519 and ML-KEM-768 together, Ed25519 + ML-DSA-65 keys, several devices per person, sender keys for audiences, and moving history to a new device. Version 2 hides who starts a session, encrypts headers and sends ML-KEM in pieces. | CVP-016 |
| `social` | **A federated social protocol, end to end encrypted.** ActivityPub's vocabulary (actors, Create, Follow, Like) and the AT Protocol's portability (key-based identity, moving between sites, signed repositories, lexicons), with followers-only posts and direct messages sealed on devices and quantum-resistant throughout. Direct messages are unsigned (deniable) and, once two people have spoken, sent sealed so neither site learns who wrote them. | CVP-017 to CVP-021 |
| `groups` | **Groups on MLS (RFC 9420), hybrid post-quantum,** using OpenMLS with one added ciphersuite (X-Wing, AES-256-GCM, SHA-512, ML-DSA-87; see [rust/README.md](rust/README.md)). One commit locks out a removed or compromised member for everyone. | CVP-022 |
| `canonical`, `signed` | One byte-exact encoding for everything signed, and the signed-record envelope every other module uses. | CVP-002 |
| `cv` | Account key chains, device certificates, end-to-end envelopes, post-quantum hybrid sealing, recovery phrases, community keys: Commonveil's cryptography. | CVP-001, CVP-003 |
| `wire` | How sites sign requests to each other, which addresses they may connect to, how two sites agree on features, and the post-quantum sealed relay. | CVP-005, CVP-008, CVP-015 |
| `commons` | A community's signed, hash-chained history that approved sites mirror, so a community keeps running when its home site goes down. | CVP-011 |
| `governance` | Motions, structured debates, public and secret ballots, recountable results that can authorise changes in the ledger. No blockchain. | CVP-012 |
| `tokens` | Private one-use tokens (RFC 9497 VOPRF, P-256): secret ballots, anonymous rate limits and reports. | CVP-013 |
| `portable` | Personas (a different face per community) and signed moves between sites. | CVP-001 |
| `consent` | Specific, time-limited, revocable permissions, honest about what revoking can't undo. | CVP-014 |
| `extensions` | Extension manifests (what runs where, with which permissions, pinned code) and theme packages (data only, contrast-checked). | CVP-008 |

The specs are in [`spec/`](spec/). [CVP-000](spec/CVP-000-framework.md) says how the standard is
written, versioned and changed; [`spec/registry.json`](spec/registry.json) lists every name two
implementations must agree on; [CVP-010](spec/CVP-010-conformance.md) says how another
implementation shows it conforms; and `cargo run -p secure-net-tools -- standards` checks that
the code, registries and documents agree. [`spec/INTEROPERABILITY.md`](spec/INTEROPERABILITY.md)
explains how sites run by different people stay private, end-to-end encrypted and able to talk.

## Using it

From Rust, depend on `secure-net-core` (from this repository) and use the modules directly. The
examples are complete, runnable walk-throughs:

```bash
cd rust
cargo run --example two_party   # two people, three devices, a group key and a new phone, through a relay
cargo run --example social      # three sites: follows, private posts, a repository, a lexicon, a move
cargo run --example groups      # an MLS group across two sites, with a removal
```

From JavaScript, every operation is one JSON request and one JSON reply, the same as
`secure_net_core::api` describes:

```js
// Browsers and Deno
import init, { call } from "@comutability/secure-net/web";
await init();
// Node.js: import { call } from "@comutability/secure-net";

const ask = (req) => {
  const out = JSON.parse(call(JSON.stringify({ now: Date.now(), ...req })));
  if (out.error) throw Object.assign(new Error(out.error.message), { code: out.error.code });
  return out.ok;
};
const account = ask({ op: "createAccount" });
const device = ask({ op: "createDevice" });
```

Show people `ask({ op: "safetyNumber", a: yourAccountKey, b: theirAccountKey })` to compare, and
warn when an account key changes.

## Working on it

```bash
cd rust
cargo test                                   # Rust tests, and every vector in spec/vectors
cargo clippy --all-targets -- -D warnings
cargo run -p secure-net-tools -- standards   # the standard and the code agree
cargo run -p secure-net-tools -- manifest    # after any change: updates secure-net.manifest.json
cargo run -p secure-net-tools -- package     # the npm package (needs the wasm32 target and wasm-bindgen)
```

Commonveil keeps a copy and checks it against `secure-net.manifest.json`, so the two can't drift
apart unnoticed.

Until 0.6.0 Secure Net was JavaScript. The Rust implementation was checked against it message by
message (the interoperability tests are in the history, up to commit `c55f96d`) before the
JavaScript was removed in 0.7.0.

## How it changes

Protocol changes go through public, numbered proposals decided by human maintainers: see
[GOVERNANCE.md](GOVERNANCE.md) and [`snips/`](snips/). (Draft, not yet ratified.)

## Licence

AGPL-3.0-only, the same as Commonveil.
