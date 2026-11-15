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
| One-to-one sessions, version 2 (CVP-016 v2) | `session::v2` (`v2.*` operations) | Every derivation in `cvp-016-v2.json`; 90-message conversations between the two implementations with sides switching mid-conversation, late and skipped messages, and several ML-KEM exchanges completing; the same refusal codes (replays, tampering, wrong version, reused prekeys, untrusted keys, expired skipped keys) (`test/rust-session2-interop.test.mjs`) |
| Sender keys and history transfer (CVP-016) | `session::group`, `session::history` | Group messages and history transfers made by each side open on the other, with the same refusals |
| Site-to-site wire (CVP-005, CVP-008, CVP-015) | `wire::federation`, `wire::features`, `wire::sealed` | Endpoint rules, host and private-address rules, signed requests (byte-identical signatures), feature negotiation, and the P-256 + ML-KEM-768 / ML-DSA-65 sealed relay, with requests and replies sealed by each side opening on the other (`test/rust-wire-ledger-interop.test.mjs`) |
| Private tokens (CVP-013) | `tokens` (the `voprf` crate, RFC 9497 P256-SHA256) | The same issuer keys from a seed; tokens requested from one side and issued by the other; the same refusals for bad proofs, forged and spent tokens |
| Commons ledger (CVP-011) | `commons` | Histories with blocks made by both sides replay to identical states; 24 kinds of bad block get the same refusal codes; mandates, forks (and their evidence) and host failover are decided identically |
| Governance (CVP-012) | `governance::vote`, `governance::debate` | Every counting method (majority, supermajority, approval, ranked) and secret ballots give identical results, including changed, clashing, late and tampered ballots; results recount; debates arrange into the same tree, thread and rejections |
| Personas, migrations, consent, extensions and themes (CVP-001, CVP-014, CVP-008) | `portable`, `consent`, `extensions` | Links, notices, capsules, manifests and themes made by each side check out on the other, and every check gives the same answer and problems |
| Social protocol (CVP-017 to CVP-020): actors, activities, lexicons, repositories, delivery | `social` (`social.*` operations) | `test/rust-social-interop.test.mjs`: every vocabulary check gives the same problems; actor documents, activities, lexicons and repositories made by each side verify on the other with the same refusals (rollback, wrong actor or device, tampered records, non-public records); sealed and plain delivery bodies, delivery tokens, audiences and direct payloads open on either side. The reference site and client run end to end in Rust (`tests/social_e2e.rs`): follows, followers-only, direct and public posts, likes, unfollowing, sealed sending and token rotation, version 1 clients, downgrade refusal, replayed, altered, late and misattributed deliveries, and moving site with id, followers and history kept |
| MLS groups (CVP-022) | `groups::mls`, `groups::client` (`groups.*` operations) | OpenMLS, with one ciphersuite added (below). `test/rust-groups-interop.test.mjs`: groups that mix Rust (OpenMLS) and JavaScript (ts-mls) devices, with either side as committer; adds, removals, refreshes, replacements and newcomers lock out exactly the right people on both; both refuse commits and proposals from anyone but the committer, unverifiable key packages and replayed or bent messages, and the credential check gives the same answer. `tests/groups.rs` and `tests/groups_e2e.rs` mirror `test/groups.test.mjs`, including posting to groups through two sites with the reference client |
| Commonveil's cryptography (`src/crypto/*`) | `cv` (`cv.*` operations) | `test/rust-crypto-interop.test.mjs`: keys, seals, envelopes, key histories, certificates, proofs, item signatures, recovery backups, the passcode lock, owner keys, server key chains, grants, items and invite previews made by each side open or verify on the other, with the same refusal codes. The MLKEM768-P256 hybrid KEM matches `@noble/post-quantum` byte for byte with fixed randomness (`tests/vectors/cv-kem.json`); BIP-39 matches the reference vectors |

Everything in the protocol is now ported.

### The OpenMLS patch

Secure Net's groups use `MLS_256_XWING_AES256GCM_SHA512_MLDSA87`: X-Wing for the key tree,
AES-256-GCM, SHA-512 and ML-DSA-87 signatures, with the code point ts-mls gives it (0x0057). The
IETF hasn't assigned that combination a number yet, and OpenMLS doesn't list it, though it has
every piece. `rust/vendor/openmls_traits` and `rust/vendor/openmls_rust_crypto` are copies of the
crates.io releases with that one suite added (search for its name to see every changed line);
`[patch.crates-io]` in `rust/Cargo.toml` uses them. No cryptography was written for it. Drop the
copies once the suite has an IANA code point and OpenMLS supports it.

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
node --test test/rust-*.test.mjs
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
- Mutation check of sessions v2, sender keys and history transfer: 14 guards (the ML-KEM
  exchange staying in step, replays in the current and older chains, the skipped-key expiry,
  header keys bound to their chain, the skip limit, key piece sizes, untrusted sending devices,
  dropping the handshake once answered, group signatures, replays and skip limits, history
  digests and chunk counts) were removed in turn; all 14 made a test fail.
- Mutation check of the wire, tokens, ledger, governance, identity, consent and extensions: 30
  guards removed in turn, 29 caught. The survivor is the ledger's second check that only a
  member or a moderator removes a member: the capability check before it already refuses every
  other case, in the JavaScript as here, so it can't be reached.
- Mutation check of the social protocol: 27 guards (actor ids, handles and rollback; activity
  actors, signing devices and signatures; inclusion-proof bounds; commit signatures, record
  counts, public-only records, signed roots and rollback; lexicon authority and rollback; direct
  payloads from the sending device, version 2-only features, sender keys and actor documents;
  delivery tokens, request times, replays, digests and signatures; first-come handles; and
  downgrade refusal) removed in turn, 26 caught. The survivor is the reference site's check
  that a public activity comes from its author's own site: a site only hosts actor documents
  for its own handles, so the actor lookup before it already fails for any other site.
- Mutation check of MLS groups: 21 guards (the credential's key, actor, device, signature and
  quantum-resistant key; only the committer commits, refreshes, replaces or adds, and is told so
  first; key package credentials; every member's credential on joining; Secure Net group ids;
  commits only from the committer; added leaves and the committer's new leaf verified; proposals
  refused; never removing or replacing the committer; no bytes after a message; welcomes only
  from the group's committer; group posts only from members, written for that group; leaving a
  group on being removed) removed in turn, 20 caught. The survivor is the explicit suite check
  on key packages: OpenMLS refuses a key package from another suite itself.

## Known differences from the JavaScript

- **Ed25519 verification rules: now the same.** Every Ed25519 check in Rust uses ZIP-215 rules
  (`ed25519-zebra`), the rules noble applies by default, so a crafted signature can't be
  accepted by one implementation and refused by the other. All 196 small-order cases ZIP-215
  was written for give the same answer on both sides.
- **Times.** Rules that compare times use `Date.parse`. Rust matches V8 (Node.js, Chrome) for
  every ISO 8601 form, including its quirks (any day from 1 to 31 rolls over, `24:00`, lower-case
  `t` and `z`, `+0100`), and refuses times with no zone, which JavaScript reads as the machine's
  local time. Records should carry `toISOString()` times, which both read identically.
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
- **Group state doesn't move between the two.** Everything a group sends (key packages,
  welcomes, commits, messages) is shared, but a saved group state is each library's own: OpenMLS's
  key-value store in Rust, ts-mls's encoding in JavaScript. A device keeps using the
  implementation it joined with; one-to-one session states, by contrast, can move either way.
- **Signing randomness.** ML-DSA-65 signatures are hedged (fresh randomness), as the
  specification allows, so they differ from run to run; they are checked by verifying, not by
  comparing.

Licence: AGPL-3.0-only, like the rest of Secure Net.
