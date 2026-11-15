# CVP-016: End-to-end sessions

| | |
| --- | --- |
| Status | Draft (merged into the reference implementation; awaiting human cryptographic review) |
| Version | 2 |
| Feature | `cvp.sessions` (version 2; version 1 deprecated, still accepted) |
| Depends on | CVP-002 |
| Code | `rust/secure-net-core/src/session/` |
| Proposed in | [SNIP-0003](../snips/SNIP-0003.md); version 2 in [SNIP-0006](../snips/SNIP-0006.md) |

How two devices agree keys, exchange messages and keep them private, including from an attacker
who records everything today and has a large quantum computer later. It covers one-to-one
messages, a person's several devices, groups, and moving history to a new device.

Implemented in Secure Net 0.4.0. Not yet reviewed by a qualified human cryptographer; nothing
here should be relied on until it has been.

The design follows Signal's: an X3DH-style handshake made post-quantum as in PQXDH, then a double
ratchet. Unlike Signal's original ratchet, every DH ratchet step here also mixes in a fresh
ML-KEM-768 secret, so recovery after a compromise does not rest on X25519 alone.

## What it protects, and from whom

| Property | How | Holds against |
| --- | --- | --- |
| Confidentiality of content | AES-256-GCM under keys from X25519 **and** ML-KEM-768 | Sites, relays, networks, and a future quantum computer, unless both X25519 and ML-KEM-768 are broken |
| Forward secrecy | Message keys are deleted after use; chain keys move one way; ratchet keys are replaced every round trip | Someone who steals a device later can't read earlier messages |
| Recovery after compromise | Each round trip mixes in new X25519 and ML-KEM-768 secrets | Someone who copied a device's state once loses access after the next round trip, if they're not actively in the middle |
| Who is talking | Account keys sign device lists, devices sign prekeys, all with Ed25519 + ML-DSA-65; the handshake binds both parties' keys | A site serving fake keys (caught once people compare safety numbers) |
| Integrity and order | AEAD with the header as associated data; counters; one-time message keys | Tampering, replay, reordering beyond the stated window |

### What isn't protected

- **Metadata.** Sites still see which device sends to which, when, and how much. The sealed
  relay (CVP-015) hides it from the network between sites, not from the two sites.
- **First contact.** Until two people compare safety numbers, a site that controls the first
  key fetch can sit in the middle. Apps MUST show the safety number and MUST warn when a pinned
  account key changes.
- **Group authenticity against a quantum attacker.** Group messages are signed with Ed25519
  only (an ML-DSA-65 signature on every group message would add 3.3 KB). Forging one needs a
  quantum computer at the time of the attack **and** membership of the group; it doesn't help
  anyone read recordings. Group confidentiality is post-quantum.
- **A device someone controls now.** Encryption can't protect what's on an unlocked, compromised
  device.
- **Replay of a first message made with the last-resort prekey and no one-time X25519 prekey.**
  Receivers MUST remember the handshake ids (`handshakeId`) of first messages for as long as the
  signed prekey is live and refuse repeats.

## Keys

| Key | Algorithm | Held by | Purpose |
| --- | --- | --- | --- |
| Account key | Ed25519 + ML-DSA-65 | trusted devices or a recovery phrase | Signs the device list. Its fingerprint is what people compare. |
| Device signing key | Ed25519 + ML-DSA-65 | one device | Signs that device's prekeys |
| Device identity key (IK) | X25519 | one device | Long-term key agreement |
| Signed prekey (SPK) | X25519, expires (30 days by default) | one device | Handshake; rotated with `rotateSignedPrekeys` |
| Last-resort ML-KEM prekey (PQSPK) | ML-KEM-768, expires | one device | Handshake when one-time ML-KEM prekeys run out |
| One-time prekeys (OPK, PQOPK) | X25519 and ML-KEM-768 | one device | Handshake, used once then deleted |

Every public prekey is a signed record (CVP-002) of kind `session.prekey`:

```
{ device, type: "x25519" | "ml-kem-768", id, pub, expires?, lastResort?, oneTime? }
```

The device list is a signed record of kind `session.device-list`, signed by the account key:

```
{ account: <account public key>, devices: [{ kid, sign, dh }], seq, issued }
```

`seq` MUST increase with every change. A receiver MUST remember the highest `seq` it has seen
for each account and MUST refuse a lower one, so a site can't bring back a removed device.

## Bundles

A site hands out, for one device: the device list, the signed prekey, one ML-KEM-768 prekey (a
one-time one if any remain, otherwise the last-resort one) and one one-time X25519 prekey if any
remain. A site MUST NOT hand out a one-time prekey more than once.

The initiator MUST check (`verifyBundle`): the device list verifies under the account key it
trusts for that person and isn't older than one already seen; the device is on it; each prekey
is signed by that device's signing key, is of the right type and hasn't expired; the ML-KEM
prekey is marked one-time or last-resort; the X25519 one-time prekey, if present, is marked
one-time.

## Handshake

Initiator A, responder device B. A makes an ephemeral X25519 key EK, then:

```
DH1 = X25519(IK_A, SPK_B)
DH2 = X25519(EK_A, IK_B)
DH3 = X25519(EK_A, SPK_B)
DH4 = X25519(EK_A, OPK_B)          only if a one-time prekey was given
(CT, SS) = ML-KEM-768.Encaps(PQPK_B)
```

Any X25519 output of all zeros MUST be refused. The transcript is the canonical JSON (CVP-002) of

```
{ v: 1,
  initiator: { account, device, sign, dh },
  responder: { account, device, sign, dh },
  ek, ct: base64url(SHA-256(CT)), signed: <SPK id>, pq: <PQ prekey id>, oneTime: <OPK id or null> }
```

and `TH = SHA-256("secure-net/session/v1/transcript" || transcript)`. Then

```
SK = HKDF-SHA-256(salt = 32 zero bytes,
                  ikm  = 32 bytes of 0xFF || DH1 || DH2 || DH3 [|| DH4] || SS,
                  info = "secure-net/session/v1/handshake" || TH, length 32)
```

`TH` is also the session's associated data, so every message is bound to both parties' account
and device keys. The handshake fields `x` travel with A's messages until A hears back:

```
x = { list: <A's device list>, device: <A's kid>, ek, ct, signed, pq, oneTime }
```

B checks A's device list against the account key B trusts for A (apps look it up with
`initialSender` first), finds the prekey secrets by id, computes the same SK, and deletes the
one-time prekeys used once the first message has decrypted. A first message naming an unknown
or used prekey MUST be refused.

## Ratchet

State per session: root key RK; our ratchet X25519 key DHs and ML-KEM-768 key KEMs; the peer's
DHr and KEMr; sending and receiving chain keys; counters Ns, Nr, PN; skipped message keys.

```
KDF_RK(rk, dh, ss)  = HKDF-SHA-256(salt = rk, ikm = dh || ss, info = "secure-net/session/v1/root", 64)
                      -> (rk' = first 32 bytes, ck = last 32 bytes)
KDF_CK(ck)          = (mk = HMAC-SHA-256(ck, 0x01), ck' = HMAC-SHA-256(ck, 0x02))
message key         = HKDF-SHA-256(salt = 32 zero bytes, ikm = mk, info = "secure-net/session/v1/message", 44)
                      -> AES-256-GCM key (32) and nonce (12)
```

**Start.** A: `RK = SK`, DHr = SPK_B, new DHs and KEMs, `(RK, CKs) = KDF_RK(RK, X25519(DHs, DHr), "")`.
B: `RK = SK`, DHs = SPK_B, no KEMs yet.

**Sending.** `(mk, CKs) = KDF_CK(CKs)`. The header is `{ dh: DHs.pub, kem: KEMs.pub, ct?, pn: PN, n: Ns }`,
where `ct` is the ML-KEM ciphertext made when this sending chain started (absent only on A's
first chain). The message is

```
{ v: 1, h: header, x?: handshake, c: AES-256-GCM(mk, plaintext, ad = TH || canonical({ h, x? })) }
```

**Receiving a new ratchet key** (header `dh` differs from DHr):

1. If we have sent a KEMs and the header has no `ct`, refuse (`DOWNGRADE`).
2. Keep the remaining keys of the current receiving chain up to `pn` (skipped keys).
3. `SS = ML-KEM-768.Decaps(ct, KEMs)` (empty if no KEMs yet); `(RK, CKr) = KDF_RK(RK, X25519(DHs, dh), SS)`.
4. New DHs and KEMs; `(CT', SS') = Encaps(header.kem)`; `(RK, CKs) = KDF_RK(RK, X25519(DHs, dh), SS')`;
   CT' goes in every header of the new sending chain.

Every round trip so replaces both an X25519 and an ML-KEM-768 key on each side.

**Skipped keys.** At most 1,000 missing messages in one chain and 2,000 stored keys per session
(oldest dropped first). A used or skipped key is deleted once it decrypts a message, so a replay
fails.

**Failure.** A message that fails any check MUST leave the state unchanged. The reference code
returns new state from every call and never changes what it was given.

## Devices

A person's devices are the ones on their current device list. To send, a device encrypts the
message separately for every device on the recipient's list and every other device on its own
(`planFanOut`, `encryptToDevices`). When a list drops a device, sessions with it are deleted.
If both sides start a session at once, apps SHOULD keep, for each device, the session they most
recently received a message on (the reference code leaves this choice to the app).

## Groups

From Secure Net 0.6.0, conversations among a group of members SHOULD use CVP-022 (MLS), which
locks out a removed or compromised member with one commit. Sender keys, described here, remain
the way one author seals for many readers (CVP-019 audiences).

Each member device has a sender key per group: a random 32-byte chain key, a counter and an
Ed25519 key pair. It sends `{ type: "sender-key", group, id, ck, n, sign }` to every other member
device over their one-to-one sessions; the receiver records which session it came on, never
trusting a name inside it. A group message is

```
{ v: 1, group, id, n, c, sig }
c   = AES-256-GCM(message key from KDF_CK, info "secure-net/session/v1/group", ad = canonical({ v, group, id, n }))
sig = Ed25519 over "secure-net/session/v1/group-sig\n" || canonical({ v, group, id, n, c })
```

When anyone leaves, every remaining member MUST make a new sender key and send it only to the
remaining members. When someone joins, members SHOULD make new sender keys, so the newcomer can't
read earlier messages.

## New devices

1. **Link.** The new device shows a link code (`linkCode`: 30 digits from SHA-256 of its signing
   and identity keys), as text or a QR code. An existing device computes the code from what it
   received, the person checks they match, and the existing device signs a new device list with
   the new device added (`approveLink`).
2. **History.** The existing device seals the history (`sealHistory`): a fresh 32-byte key,
   chunks encrypted with AES-256-GCM under per-chunk keys, each bound to the transfer id, its
   index and the chunk count, plus a digest over all chunks. The chunks can go through any
   untrusted store. The key and manifest go to the new device over their one-to-one session.
   The new device refuses missing, reordered or altered chunks (`openHistory`).
3. With no existing device available, a new device starts with no history.

## Sizes and cost

Measured with the reference code (JSON on the wire, base64url):

| Item | Size |
| --- | --- |
| Bundle for one device | about 26 KB (mostly ML-DSA-65 signatures and ML-KEM-768 keys) |
| First message (carries the handshake and the sender's device list) | about 13 KB |
| Ordinary message | about 3.1 KB plus the content (the ML-KEM key and ciphertext of the current chain) |
| Session state | about 11 KB |
| A full ratchet round trip | about 10 ms in the cloud test environment (not yet measured on phones) |

Sending the ML-KEM fields only until the peer acknowledges them, or splitting them across
messages as Signal's SPQR does, would cut the per-message cost; that is future work and would be
a new version.

## Version 2

Version 2 changes the handshake and the ratchet of one-to-one sessions. Keys, bundles, devices,
sender keys and new devices are unchanged. It is implemented in `rust/secure-net-core/src/session/v2.rs` (Secure Net
0.6.0) and, like version 1, has **not been reviewed by a qualified human cryptographer**.

A device says it speaks version 2 with `"sessions": 2` in the body of its signed prekey. The
member is signed, so a site can't remove it. An initiator MUST use the highest version both
devices speak, and MUST NOT start a lower version with a device it has already seen speak a
higher one. Version 1 is deprecated: implementations MUST still accept it and SHOULD NOT start
it where the peer speaks version 2. Labels are `secure-net/session/v2/<purpose>`.

What changes, and why:

| Change | Why |
| --- | --- |
| The transcript binds each prekey's public key, not only its id | A site that swapped a prekey for another with the same id would otherwise go unnoticed by the transcript. No attack on version 1 is known; this removes the question |
| The initiator's identity is encrypted in the first message | A site carrying a first message can no longer tell who is writing |
| Headers are encrypted | Messages of one session can't be linked, counted or ordered by anyone but the two devices; there is no session tag (CVP-019) |
| ML-KEM keys and ciphertexts travel in pieces inside headers | An ordinary message carries 256 bytes of ML-KEM material at most, instead of 2,272 |
| Keys for messages that haven't arrived expire | A stolen state holds fewer old keys |

### Handshake

As in version 1, with these differences.

```
hidden = X25519(EK_A, SPK_B) [|| X25519(EK_A, OPK_B)]
IDK    = HKDF-SHA-256(ikm = 0xFF*32 || hidden || SS, salt = 0x00*32,
                      info = "secure-net/session/v2/identity" ||
                             SHA-256(canonical({ ek, ct: SHA-256(CT), signed, pq, oneTime })), 44 bytes)
id     = AES-256-GCM(key = IDK[0..32], iv = IDK[32..44], canonical({ list, device }))
x      = { ek, ct, signed, pq, oneTime, id }

TH = SHA-256("secure-net/session/v2/transcript" || canonical({
       v: 2, initiator, responder, ek, ct: SHA-256(CT),
       signed:  { id, pub: SPK_B },
       pq:      { id, pub: SHA-256(PQPK_B) },
       oneTime: null | { id, pub: OPK_B } }))

RK || HK_A || NHK_B = HKDF-SHA-256(ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4] || SS,
                                   salt = 0x00*32, info = "secure-net/session/v2/handshake" || TH, 96 bytes)
```

`IDK` uses only the ephemeral key and the prekeys, so the responder can open `id` before it
knows who the initiator is, and nobody without the prekey secrets can. The responder opens `id`,
checks the device list as in version 1, then derives the rest. `HK_A` is the initiator's first
sending header key; `NHK_B` is the responder's.

Hiding the identity this way protects it from sites and from anyone who records the message. It
does not protect it from someone who later takes the recipient's prekey secrets (until the
signed and last-resort prekeys are replaced and deleted).

### Ratchet

A double ratchet with encrypted headers, following section 4 of Signal's Double Ratchet
specification, with a sparse ML-KEM exchange carried in the headers.

```
KDF_RK(RK, dh, ss) = HKDF-SHA-256(ikm = dh || ss, salt = RK, info = "secure-net/session/v2/root", 96 bytes)
                   -> RK' || CK || NHK
KDF_CK             as in version 1
KEY || IV          = HKDF-SHA-256(MK, salt = 0x00*32, info = "secure-net/session/v2/message", 44 bytes)
```

A message is `{ v: 2, h, x?, c }`:

- `h` is base64url of a random 12-byte IV followed by AES-256-GCM, under the sender's current
  header key and with `TH` as associated data, of the canonical JSON header
  `{ dh, pn, n, pe?, k? }`.
- `c` is AES-256-GCM under `KEY`/`IV`, with associated data `TH || canonical({ h })`, or
  `TH || canonical({ h, x })` while the handshake is still being sent.

A receiver tries, in order: the header keys it holds for messages it is waiting for; its current
receiving header key; its next receiving header key (which means the peer has started a new
chain, so the ratchet steps exactly as in the Double Ratchet specification, with header keys
moving along with it). If none opens `h`, the message isn't for this session. A device with
several sessions finds the right one the same way: nothing outside the ciphertext says which it
is.

Limits: at most 1,000 messages skipped in one chain; at most 2,000 keys kept; a key for a
message that hasn't arrived MUST be deleted 7 days after it was made.

### Sparse ML-KEM

Epochs are numbered from 1. In each epoch one side (the initiator in odd epochs) sends a fresh
ML-KEM-768 encapsulation key and the other answers with a ciphertext, both in pieces of 256
bytes (5 pieces each) carried in `k`:

| `k` | Sent by | Until |
| --- | --- | --- |
| `{ e, t: "ek", i, d }` | the side sending the key, one piece per message, in turn | it receives any ciphertext piece for `e` |
| `{ e, t: "ct", i, d }` | the other side, once it has every key piece and has encapsulated | it receives an acknowledgement for `e` |
| `{ e, t: "ack" }` | the side that sent the key, once it has every ciphertext piece and has decapsulated | it mixes the secret |

A piece is only acted on after its message has decrypted, so pieces are authenticated by the
session. Pieces for any epoch but the current one are ignored.

The side that sent the key mixes the shared secret into the root chain at its next new sending
chain, as the `ss` of that `KDF_RK` step, and puts `pe: e` in every header of that chain. A
receiver starting a new receiving chain whose header carries `pe` MUST have made the secret for
exactly that epoch itself and MUST refuse the message otherwise; it mixes the same secret into
that step. Both sides then move to epoch `e + 1` with the roles swapped. Steps without `pe` use
an empty `ss`.

What this gives, and what it costs compared with version 1: each completed exchange puts a new
ML-KEM secret under every later key, so the session recovers from a compromise against a
quantum attacker as well as a classical one. Version 1 did that at every reply; version 2 does
it about once per 22 messages of back-and-forth, and X25519 still ratchets at every reply. An
attacker who can drop messages can't pick out the ones carrying a particular piece, because
headers are encrypted, but dropping everything stalls the exchange as it stalls the
conversation. `pqStatus` reports the epoch and how many secrets have been mixed in, so an app can
show or act on a session that hasn't refreshed for a long time.

### Deniability

Nothing in a version 2 session is signed by a long-term key over the conversation: device lists
and prekeys are signed, but they are public, and each side could have produced the whole
exchange alone. With unsigned direct activities (CVP-019) a recipient can read and trust a
message without being able to prove to anyone else who wrote it. This is the same offline
deniability X3DH and PQXDH aim for; it has not been analysed for this protocol.

### Sizes

| Thing | Version 1 | Version 2 |
| --- | --- | --- |
| Ordinary message, before content | about 3.1 KB | about 0.2 KB, or 0.7 KB while a piece is being carried (0.4 KB on average in a back-and-forth) |
| First message (carries the handshake and the sender's device list) | about 16 KB | about 16 KB |

## Conformance

`rust/secure-net-core/tests/session.rs` and the vectors in [vectors/cvp-016-v1.json](vectors/cvp-016-v1.json)
(written by the former JavaScript reference implementation's vector script; checked by `cargo test`). The X25519, HKDF, HMAC and AES-GCM vectors have been checked
against Node's built-in crypto, an independent implementation; the ML-KEM-768 vector comes from
@noble/post-quantum and has not been checked against a second implementation yet.
Version 2: `rust/secure-net-core/tests/session2.rs` and [vectors/cvp-016-v2.json](vectors/cvp-016-v2.json), whose
HKDF derivations have been checked against an independent implementation (Python's `hmac`).
`cargo run --example two_party` runs the whole protocol through a relay that keeps a copy of everything
and checks no plaintext is in it.

## Relation to older parts

`crypto/envelope` (CVP-003) seals content to an account's shared key, so it has no forward
secrecy and keeps a classical fallback. New messages SHOULD use sessions. Commonveil's switch is
a separate change with its own migration plan.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-13 | SNIP-0003 | First version, in Secure Net 0.4.0 |
| 1 | 2026-11-13 | SNIP-0004 | Editorial: standard header; labels registered |
| 2 | 2026-11-14 | SNIP-0006 | Version 2 of one-to-one sessions: bound prekeys, hidden initiator, encrypted headers, sparse ML-KEM, expiring skipped keys. Version 1 deprecated. Groups move to CVP-022; sender keys stay for audiences |
