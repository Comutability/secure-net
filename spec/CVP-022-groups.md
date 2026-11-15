# CVP-022: Groups

| | |
| --- | --- |
| Status | Draft |
| Version | 1 |
| Feature | `cvp.groups` (version 1) |
| Depends on | CVP-002, CVP-016, CVP-017, CVP-018, CVP-019 |
| Code | `rust/secure-net-core/src/groups/` |
| Proposed in | [SNIP-0006](../snips/SNIP-0006.md) |

## Summary

Group conversations use the IETF's Messaging Layer Security (MLS, RFC 9420) with a hybrid
post-quantum ciphersuite. This part does not define a group protocol: it says which MLS options
Secure Net uses, how MLS credentials are tied to Secure Net devices, who may change a group, and
how MLS messages travel.

Not reviewed by a qualified human cryptographer. The reference code relies on the `ts-mls`
library, which states that it has not had a formal security audit.

## Why MLS

Sender keys (CVP-016) give each member a key that every other member holds. Someone who copies
one member's state reads the group until every member has made a new key, and removing a member
means every remaining member doing so. MLS agrees one group secret through a tree of keys:

- one commit replaces the group secret for everyone, so a removed member, or someone holding a
  copy of a member's old state, is locked out at once;
- the work grows with the logarithm of the group's size;
- it is a published standard with public security analysis, which a design of our own would not
  have.

## Definitions

**Committer**: the one member allowed to change the group. **Key package**: what a device
publishes so that it can be added to groups. **Welcome**: what a new member needs to join.

## Specification

### Ciphersuite

`MLS_256_XWING_AES256GCM_SHA512_MLDSA87`: X-Wing (X25519 and ML-KEM-768 combined) for the key
tree, AES-256-GCM, SHA-512, and ML-DSA-87 signatures. A member MUST refuse a group using any
other suite.

MLS signs with ML-DSA-87 alone, where the rest of Secure Net signs with Ed25519 and ML-DSA
together. Two things keep the usual rule (safe unless both families are broken) for what
matters most: a member's credential is signed by its Secure Net device key, which is hybrid, and
every post inside a group carries its author's hybrid signature (below).

### Group ids

`group:` followed by 16 to 64 base64url characters, chosen at random by the creator. It is the
MLS group id (as UTF-8) and the `group` of a group envelope.

### Credentials

A leaf's credential is a basic credential whose identity is the canonical JSON of a signed
record of kind `group.credential`:

```
{ "actor": <actor id>, "device": <device id>, "key": base64url(SHA-256(MLS signature public key)) }
```

signed by that device (Ed25519 + ML-DSA-65). Every member MUST check every leaf, when it is
added and when joining: the record's signature verifies under the key of a device currently on
that actor's device list (CVP-017), that key is quantum-resistant, and `key` matches the leaf's
MLS signature key. A member that holds no verified actor document for the actor MUST refuse the
leaf.

So that members can make this check, the committer sends new members' actor documents to the
group before the commit that adds them, as a group message `{ "v": 1, "actors": [...] }`, and
sends every member's actor document with a welcome. Actor documents certify themselves
(CVP-017), so who relays them doesn't matter.

### Key packages

A device publishes MLS key packages to its site (`key_packages` endpoint); the site hands each
out once and keeps the last for when they run out. A device deletes a key package's secret once
a welcome has used it.

### Who may change a group

MLS needs every member to apply commits in one order, and Secure Net has no central server to
choose it. So:

- only the member at leaf 0, the device that created the group, may commit. A member MUST refuse
  a commit from any other leaf;
- members MUST refuse proposals; a member that wants something changed asks the committer over a
  direct session;
- a member that fears its state was copied sends the committer a new key package; the committer
  removes the old leaf and adds the new one in one commit;
- the committer SHOULD commit regularly even when nothing changes, which replaces the group
  secret from its own fresh keys.

Limits of this rule, stated plainly: while the committer is offline nobody joins or leaves and
no member can get fresh keys; if the committer's device is lost the group has to be made again.
Handing the role over is future work.

### Messages

All MLS messages are private messages. They travel in group envelopes (CVP-019), one per member
actor, sealed where the sender holds the member's delivery token. Welcomes travel in direct
payloads: `groups: [{ "group", "welcome", "actors" }]`, version 2 sessions only. A device MUST
accept a welcome only from the actor at leaf 0 of the group it opens, and only for the group id
it names.

A post is a group message `{ "v": 1, "activity": <signed activity> }`. A receiver MUST check
that the activity's signature verifies (CVP-018), that its `actor` and `device` are a member's
leaf, and that its `to` includes the group id. Without the last check, a member could seal
something another member wrote for a different audience into the group.

## Security and privacy

| Who | Learns |
| --- | --- |
| A site carrying group envelopes | The group id, which of its actors receive them, sizes and times. With sealed sending, not who sent them |
| A member | Everything said while they are a member; the other members' actors and devices |
| A removed member, or someone with a copy of a member's old state | Nothing sent after the commit that removed or replaced that leaf |
| A new member | Nothing sent before they joined |

- Group posts are signed by their authors, so they are not deniable. Direct messages are
  (CVP-019).
- A member can always copy what it reads. Nothing here stops a member leaking.
- The suite's identifier is the name given above as `ts-mls` 1.6.4 implements it. Whether it is
  a registered IANA MLS ciphersuite has not been checked.
- Sizes: a key package is about 14 KB, a leaf adds about 8 KB to a welcome, and every group
  message carries an ML-DSA-87 signature of about 4.6 KB.

## Conformance

`rust/secure-net-core/tests/groups.rs`, `groups_e2e.rs` and `groups_guards.rs`: forming a group; removal; recovery from a copied member state and from a
copied committer state; a newcomer can't read the past; only the committer commits (including a
valid MLS commit made by another member with the library directly); credential checks; two sites
end to end. There are no vectors of this part's own: MLS conformance is RFC 9420's, and the
credential is a CVP-002 signed record.

## Changes

| Version | Date | SNIP | Change |
| --- | --- | --- | --- |
| 1 | 2026-11-14 | SNIP-0006 | First version |
