# CVP-019: Delivery, end to end

| | |
| --- | --- |
| Status | Draft |
| Version | 2 |
| Feature | `cvp.delivery` (version 2) |
| Depends on | CVP-005, CVP-015, CVP-016, CVP-017, CVP-018 |
| Code | `src/social/delivery.js`, `src/social/site.js` (reference site), `src/social/client.js` (reference client) |
| Proposed in | [SNIP-0005](../snips/SNIP-0005.md); version 2 in [SNIP-0006](../snips/SNIP-0006.md) |

## Summary

How activities get from one actor's devices to another's, across sites, so that **nothing but
public posts can be read by any site on the way**, now or by an attacker with a quantum computer
later. ActivityPub servers deliver to inboxes and read everything they deliver. Here, sites still
run inboxes and outboxes and talk to each other, but what they carry is sealed on the sender's
device and opened only on the recipients' devices, using CVP-016's post-quantum sessions and
sender keys.

## Definitions

- **Envelope**: what a site stores and forwards: one of three modes (section 1).
- **Mailbox**: the queue a site keeps for each of its actors, from which the actor's devices
  collect.
- **Audience**: a set of devices that can read the same encrypted posts: an actor's followers, or
  a group's members. Each posting device keeps a sender key (CVP-016, "Groups") per audience.
- **Payload**: what is inside a direct or audience envelope once decrypted.

## Specification

### 1. Envelopes

Every envelope has `v: 1`, a `mode`, and only the members listed for that mode. A site MUST
refuse an envelope with anything else, so an envelope can't carry more metadata than this part
allows.

| Mode | Members | Used for | A site can read |
| --- | --- | --- | --- |
| `public` | `activity`: a signed activity | Activities addressed to `public` | Everything |
| `direct` | `device`: the recipient device's id; `session`: the session tag (1.2); `message`: a CVP-016 message | Direct messages, follows and their answers, likes, sender keys | The recipient device and the session tag. On the first messages of a session, also what CVP-016's handshake carries in the clear, including the sender's device list |
| `audience` | `audience`: the audience id; `message`: a CVP-016 sender-key message for that audience | Followers-only posts and group posts | The audience id, which starts with its owner's actor id |

A `public` envelope MUST only carry an activity addressed to `public`. An activity addressed to
`public` MUST NOT be sent in any other mode. An envelope MUST NOT exceed 512 KiB.

#### 1.1 Payloads

The plaintext of a direct or audience message is the canonical JSON of

```
{ v: 1, activity?: <signed activity>, senderKeys?: [<sender key distribution>...], actor?: <actor document> }
```

with at least one of the three. Audience payloads carry only `activity`. A receiver MUST refuse a
payload whose:

- `activity` wasn't signed by the device the message came from (for a direct message, the
  session's peer device; for an audience message, the device whose sender key opened it);
- `senderKeys` entry is for an audience that doesn't belong to the sending actor (its id doesn't
  start with the sender's actor id);
- `actor` isn't the sender's own actor document.

Senders SHOULD include their actor document in the first payload to an actor, and again whenever
its `seq` changes, and not otherwise.

#### 1.2 Session tags

So that a device knows which session opens a direct envelope without trying each one, the
envelope carries a tag both ends derive from the session's handshake hash `TH` (CVP-016):

```
session = first 22 characters of base64url( SHA-256( "secure-net/social/v1/session" || 0x0a || TH ) )
```

### 2. Posting

| To | The client... |
| --- | --- |
| `public` | signs the activity, adds it to its repository and publishes the new head (CVP-020), and sends one `public` envelope to its own site's outbox, addressed to its own mailbox and to each follower's |
| `followers` | signs it, seals it once with its followers audience sender key, and sends the `audience` envelope to each follower's mailbox |
| actors | signs it and seals it over a CVP-016 session to **every device** of every recipient, and to the sender's own other devices |
| a group | seals it with its sender key for the group's audience and sends it to each member's mailbox |

### 3. Following and audiences

1. The follower's client sends `Follow` (CVP-018) in a direct envelope to every device of the
   followed actor.
2. The followed actor's client decides (automatically or by asking the person). To accept, it adds
   every device on the follower's current device list to its followers audience, and sends
   `Accept` with the audience's current sender key (`senderKeys`) directly to each of those
   devices. Each of the actor's posting devices does this for its own sender key.
3. Joining doesn't reveal earlier posts: a sender key only moves forward (CVP-016).
4. When a follower leaves (`Undo` of the `Follow`), is removed, or is blocked, or when one of
   their devices leaves their device list, every posting device of the followed actor MUST make a
   new sender key for that audience before its next post. It sends the key to the remaining
   member devices only. Whoever left can't read anything sealed after that.
5. When a follower's device list gains a device, the follower's client sends `Update` of its actor
   to the actors it follows. Their clients add the new device and send it their current keys.

Groups work the same way, with `Join`, `Leave`, `Add` and `Remove` deciding membership.

Very large audiences make every rekey expensive, because each new key goes to every member device
over its own session. Actors who need to reach many thousands of devices SHOULD post publicly.

### 4. Client to site

A site authenticates its own actors' clients by any means it chooses; this part doesn't fix one.
It offers them:

- **Outbox**, `POST <outbox>` (default `/cvp/v2/outbox`): a list of `{ host, to, envelope }`. The
  site checks each envelope's form, keeps public ones in the actor's public collection, puts local
  ones straight into mailboxes, and delivers the rest (section 5).
- **Mailbox**, `GET <mailbox>` (default `/cvp/v2/mailbox`): the envelopes waiting for the actor,
  each with the host it came from. A device acknowledges what it has collected, and the site
  deletes an envelope once every device it was for has collected it, or after 30 days.
- **Actor and prekeys**: publishing the actor document and each device's prekeys (CVP-017).

A site lists the endpoints in this part and in CVP-017, CVP-020 and CVP-021 in its site document
only once it serves them, together with the matching features. A site that announces neither is
simply not reachable by this protocol yet.

### 5. Site to site

A site delivers to another site with `POST <deliver>` (default `/cvp/v2/deliver`). The body is

```
{ v: 1, items: [{ to: <recipient actor id>, envelope }, ...] }      (1 to 100 items, at most 4 MiB)
```

The request MUST be signed as a CVP-005 site request, and MUST be sealed and doubly signed by the
CVP-015 sealed relay when the receiving site publishes relay keys. The receiving site:

1. checks the request signature against the sending site's key, the time (CVP-005 clock skew),
   the nonce (refusing repeats) and the body digest;
2. checks every item's envelope form, and for `public` envelopes checks the activity against its
   author's actor document, fetched from the sending site. The sending site MUST be the author's
   own site, the host in the author's handle;
3. stores every item, or none: a delivery is accepted or refused whole;
4. drops items for actors it doesn't host.

### 6. Public collections

`GET <public>` (default `/cvp/v2/public/{actor}`) returns an actor's public activities, newest
first, for anyone: profile pages, search, people who don't follow the actor. Encrypted activities
never appear there.

### 7. Sizes (informative)

Measured with the reference code, as JSON. Quantum-resistant signatures and keys are large:

| Item | Size |
| --- | --- |
| Actor document (one device) | about 17 KB |
| Signed activity (a short post) | about 5 KB, of which 4.4 KB is the ML-DSA-65 signature |
| Public envelope | about 5 KB |
| Audience envelope (one for all followers) | about 7 KB |
| First direct envelope to a device (handshake, device list and actor document) | about 43 KB |
| Later direct envelopes | about 10 KB |

## Version 2

Version 2 adds to version 1; every version 1 envelope stays valid. A site announces
`cvp.delivery: 2`.

### Version 2 direct envelopes

```
{ "v": 2, "mode": "direct", "device": <recipient device id>, "message": { "v": 2, "h", "c", "x"? } }
```

The message is a version 2 CVP-016 message. There is no session tag and MUST be no other member.
The recipient device finds the session by trying its header keys. A site carrying it learns the
recipient actor and device and the size; on a first message it also sees prekey ids, but not the
sender.

### Unsigned direct activities

In a version 2 direct envelope, and nowhere else, the payload's `activity` MAY have no `sig`. A
receiver MUST then check that its `actor` and `device` are the actor and device the session is
with, that it is addressed only to actors, and the same vocabulary rules as a signed activity.
It MUST refuse an unsigned activity that arrives any other way, and MUST NOT store or forward
one as if it were signed.

Senders SHOULD leave direct activities unsigned: the session already proves to the recipient
who sent them, and a signature would let the recipient prove it to everyone else. The cost is
that a recipient can't prove what they were sent, for example to a moderator; an app that needs
that asks the sender to sign.

### Sealed sending

So far the sender's site learns who its actor writes to, and the recipient's site learns which
site a message came from. Sealed sending removes both for people who have already spoken.

- An actor has a **delivery token**: 32 random bytes. It gives the token to the people it talks
  to as `delivery` in a direct payload (version 2 sessions only), and gives its own site the
  **verifier** `base64url(SHA-256("secure-net/social/v2/delivery-token\n" || token))` through
  the `delivery_token` endpoint (signed in, as itself). A site keeps at most two verifiers per
  actor, so a token can be replaced without losing messages on the way.
- A device holding a recipient's token MAY send version 2 direct and group envelopes to the
  recipient's site's `sealed` endpoint: `{ "v": 1, "items": [{ "to", "envelope", "token" }] }`,
  with no login and no site signature. The site MUST check each token against the recipient's
  verifiers and MUST accept the request whole or not at all. It MUST NOT accept other envelopes
  this way, and SHOULD limit rates per token and per network address.
- A sender MUST NOT send sealed to a session the recipient hasn't answered yet: a first message
  goes through the sender's site, which vouches for it. If a token is refused the sender falls
  back to its site.

What a site still learns from a sealed delivery: the recipient, the size, the time, and the
network address it came from. Hiding the address needs a proxy or relay and is outside this
part. Someone holding a token can send unwanted messages without their site being able to stop
them; the recipient replaces the token and gives the new one only to the people it wants.

### Group envelopes

```
{ "v": 2, "mode": "group", "group": "group:<id>", "message": <base64url MLS message> }
```

One MLS private message (CVP-022). A site learns the group id, the recipient and the size.

## Security and privacy

What each party learns:

| Party | Learns |
| --- | --- |
| The network between sites | That two sites talk, when, and how much (CVP-015 seals the rest) |
| The sender's site | Which actors its actor sends to (recipients' mailboxes), when, and sizes; public posts in full |
| The recipient's site | Which site each envelope came from, which of its actors receives it, when, sizes; for direct envelopes, the session tag (so which envelopes belong to the same conversation) and, on a session's first messages, the sender's device list; for audience envelopes, whose audience it is |
| Recipients | Everything addressed to them, signed, so they can prove who wrote it |

So: **content, activity types (who follows, likes or replies to whom), followers lists, group
membership and attachments are end to end encrypted** with X25519 and ML-KEM-768 together, and
authenticated with Ed25519 and ML-DSA-65. **Not hidden** from sites: who delivers to whom, when
and how much, and on a session's first messages the sender's identity. Hiding the sender of
direct messages from the recipient's site (as Signal's "sealed sender" does) would need the
CVP-016 handshake fields themselves encrypted; that is future work.

Other limits:

- A follower can copy what they read; encryption can't stop that.
- Spam: a recipient's site can limit by sending site, but can't read what it is limiting. Clients
  SHOULD let people refuse first messages from actors they don't follow, and sites MAY require
  private tokens (CVP-013) for first contact.
- Sender keys sign group messages with Ed25519 only (CVP-016). Inside, every activity also carries
  its device's Ed25519 + ML-DSA-65 signature, which receivers check.

## Conformance

[`vectors/cvp-019-v1.json`](vectors/cvp-019-v1.json): reproduce `sessionTag`; judge every envelope
valid or invalid as stated; accept `deliveryBody`. The cryptography inside envelopes is CVP-016's,
with its own vectors.

`examples/social.mjs` runs the whole protocol (two sites, three people: public posts, follows,
followers-only posts, a direct message, a like, an unfollow) through a network that keeps
everything. It then checks that no private text or activity type appears in what the network
kept, and that the public posts do. Tests: `test/social.test.mjs`.

Version 2: [`vectors/cvp-019-v2.json`](vectors/cvp-019-v2.json): reproduce the delivery-token
verifier; judge every envelope and sealed body as stated. Tests: `test/social2.test.mjs`.

The reference site keeps everything in memory and doesn't seal between sites; real sites MUST.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0005 | First version |
| 2 | 2026-11-14 | SNIP-0006 | Version 2 direct envelopes (no session tag), unsigned direct activities, sealed sending, group envelopes |
