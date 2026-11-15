// Groups (CVP-022): the IETF's Messaging Layer Security (RFC 9420), profiled for Secure Net.
//
// Why MLS and not sender keys (CVP-016, "Groups"): with sender keys, someone who copies a member's
// state keeps reading until every member happens to make a new key. MLS agrees one group secret
// through a key tree, so a single commit locks out a removed or compromised member for everyone
// at once, at a cost that grows with the logarithm of the group's size.
//
// What this module is: a thin, strict profile over the `ts-mls` library. It doesn't implement
// MLS. It fixes the ciphersuite, ties MLS credentials to Secure Net devices, and decides who may
// change a group. It needs `ts-mls` and `@hpke/hybridkem-x-wing` installed; the rest of Secure
// Net doesn't.
//
//   Ciphersuite    MLS_256_XWING_AES256GCM_SHA512_MLDSA87: X-Wing (X25519 + ML-KEM-768 together)
//                  for the key tree, AES-256-GCM, SHA-512, ML-DSA-87 signatures.
//   Credential     a record signed by the Secure Net device (Ed25519 + ML-DSA-65) naming the
//                  actor, the device and the MLS signature key. Every member checks every leaf.
//   Committer      only the member at leaf 0 (the device that created the group) may commit, so
//                  there is one order of changes without a central server deciding it.
//   Framing        everything is an MLS PrivateMessage: sites see the group id and sizes only.
import * as M from "ts-mls";
import { sign, checkSignature } from "../core/signed.js";
import { b64u, fromB64u, utf8, sha256B64u } from "../core/bytes.js";
import { canonicalJson } from "../core/canonical.js";
import { SessionError } from "../session/primitives.js";
import { deviceKeyAt } from "../social/actor.js";

export const SUITE = "MLS_256_XWING_AES256GCM_SHA512_MLDSA87";
export const CREDENTIAL = "group.credential";
/** The leaf that may commit. */
export const COMMITTER_LEAF = 0;
const GROUP = /^group:[A-Za-z0-9_-]{16,64}$/;
const text = (b) => new TextDecoder().decode(b);

let suite;
const impl = () => (suite ||= M.getCiphersuiteImpl(M.getCiphersuiteFromName(SUITE)));

const wrap = async (code, what, fn) => {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof SessionError) throw e;
    throw new SessionError(code, `${what}: ${e?.message || e}`);
  }
};

/** A new group id. */
export const newGroupId = () => `group:${b64u(globalThis.crypto.getRandomValues(new Uint8Array(18)))}`;

// ---- Credentials ----

function readCredential(credential) {
  if (credential?.credentialType !== "basic") return null;
  try {
    const record = JSON.parse(text(credential.identity));
    const b = record?.body;
    if (record?.kind !== CREDENTIAL || typeof b?.actor !== "string" || typeof b.device !== "string" || typeof b.key !== "string") return null;
    return record;
  } catch {
    return null;
  }
}

/**
 * The check every member makes on every leaf (RFC 9420's authentication service).
 * `actors(actorId)` returns the verified actor document body you hold for that actor, or nothing.
 * A leaf is accepted only if its credential is signed by a device currently on that actor's
 * device list, with a quantum-resistant key, and names this very MLS signature key.
 */
export function authService(actors) {
  return {
    async validateCredential(credential, signaturePublicKey) {
      const record = readCredential(credential);
      if (!record) return false;
      const b = record.body;
      if (b.key !== sha256B64u(signaturePublicKey)) return false;
      const actor = await actors(b.actor);
      if (!actor || actor.id !== b.actor) return false;
      const key = deviceKeyAt(actor, b.device, null);
      if (!key || !key.includes(".") || record.sig?.kid !== b.device) return false;
      try {
        return checkSignature(record, record.sig, key) === true;
      } catch {
        return false;
      }
    },
  };
}

const config = (actors) => ({
  keyRetentionConfig: M.defaultKeyRetentionConfig,
  lifetimeConfig: M.defaultLifetimeConfig,
  keyPackageEqualityConfig: M.defaultKeyPackageEqualityConfig,
  paddingConfig: M.defaultPaddingConfig,
  authService: authService(actors),
});

// ---- Key packages ----

const packKeys = (p) => ({ init: b64u(p.initPrivateKey), hpke: b64u(p.hpkePrivateKey), sign: b64u(p.signaturePrivateKey) });
const unpackKeys = (s) => ({ initPrivateKey: fromB64u(s.init), hpkePrivateKey: fromB64u(s.hpke), signaturePrivateKey: fromB64u(s.sign) });
const encodeKp = (kp) => b64u(M.encodeMlsMessage({ keyPackage: kp, wireformat: "mls_key_package", version: "mls10" }));

function decodeAs(b64, wireformat) {
  let m;
  try {
    m = M.decodeMlsMessage(fromB64u(b64), 0)?.[0];
  } catch {
    m = null;
  }
  if (!m || m.wireformat !== wireformat) throw new SessionError("BAD_MESSAGE", `Not an MLS ${wireformat.replace("mls_", "").replace("_", " ")}`);
  return m;
}

/**
 * A key package for a device: what others need to add it to a group. Publish `published` (a
 * site hands each one out once, like a one-time prekey); keep `secret` on the device until a
 * welcome uses it, then delete it.
 */
export async function createKeyPackage(device, actorId) {
  const cs = await impl();
  const keys = await cs.signature.keygen();
  const record = sign(CREDENTIAL, { actor: actorId, device: device.kid, key: sha256B64u(keys.publicKey) }, device.sign);
  const credential = { credentialType: "basic", identity: utf8(canonicalJson(record)) };
  const kp = await M.generateKeyPackageWithKey(credential, M.defaultCapabilities(), M.defaultLifetime, [], keys, cs);
  const published = encodeKp(kp.publicPackage);
  return { published, secret: { package: published, keys: packKeys(kp.privatePackage) } };
}

/** Who a key package says it is for. Not verified: adding it to a group verifies it. */
export function keyPackageOwner(published) {
  const record = readCredential(decodeAs(published, "mls_key_package").keyPackage.leafNode.credential);
  if (!record) throw new SessionError("BAD_MESSAGE", "Key package has no Secure Net credential");
  return { actor: record.body.actor, device: record.body.device };
}

// ---- Group state ----

const idBytes = (groupId) => {
  if (!GROUP.test(groupId || "")) throw new SessionError("BAD_INPUT", "Not a group id");
  return utf8(groupId);
};

/** The group's id, epoch and members ([{ actor, device, leaf }]). */
export function describe(state) {
  const members = [];
  state.ratchetTree.forEach((node, i) => {
    if (i % 2 !== 0 || node?.nodeType !== "leaf") return;
    const record = readCredential(node.leaf.credential);
    if (record) members.push({ actor: record.body.actor, device: record.body.device, leaf: i / 2 });
  });
  return { group: text(state.groupContext.groupId), epoch: Number(state.groupContext.epoch), members, leaf: state.privatePath.leafIndex };
}

/** Whether this state belongs to the group's committer. */
export const isCommitter = (state) => state.privatePath.leafIndex === COMMITTER_LEAF;

/** Create a group with one member: this device, which becomes its committer. */
export async function createGroup({ groupId = newGroupId(), keyPackage, actors }) {
  const cs = await impl();
  const kp = decodeAs(keyPackage.package, "mls_key_package").keyPackage;
  const state = await wrap("BAD_INPUT", "Couldn't create the group", () => M.createGroup(idBytes(groupId), kp, unpackKeys(keyPackage.keys), [], cs, config(actors)));
  return state;
}

async function commit(state, proposals) {
  if (!isCommitter(state)) throw new SessionError("NOT_ALLOWED", "Only the group's committer changes the group");
  const cs = await impl();
  const r = await wrap("BAD_INPUT", "Couldn't change the group", () => M.createCommit({ state, cipherSuite: cs }, { extraProposals: proposals, ratchetTreeExtension: true }));
  r.consumed.forEach(M.zeroOutUint8Array);
  if (r.commit.wireformat !== "mls_private_message") throw new SessionError("INTERNAL", "Commit wasn't a private message");
  return {
    state: r.newState,
    commit: b64u(M.encodeMlsMessage(r.commit)),
    welcome: r.welcome ? b64u(M.encodeMlsMessage({ welcome: r.welcome, wireformat: "mls_welcome", version: "mls10" })) : null,
  };
}

/**
 * Add devices by their key packages. Returns { state, commit, welcome }: send `commit` to the
 * existing members (a group envelope) and `welcome` to the new devices (inside direct envelopes).
 * Each key package's credential is checked; one that doesn't verify refuses the whole change.
 */
export async function addMembers(state, keyPackages) {
  const proposals = keyPackages.map((p) => ({ proposalType: "add", add: { keyPackage: decodeAs(p, "mls_key_package").keyPackage } }));
  if (proposals.length === 0) throw new SessionError("BAD_INPUT", "Nobody to add");
  return commit(state, proposals);
}

/**
 * Remove every member the predicate picks ({ actor, device, leaf }). From the commit on, the
 * removed devices can't read anything, whatever state they kept.
 */
export async function removeMembers(state, predicate) {
  const out = describe(state).members.filter((m) => m.leaf !== COMMITTER_LEAF && predicate(m));
  if (out.length === 0) throw new SessionError("BAD_INPUT", "Nobody to remove");
  return commit(state, out.map((m) => ({ proposalType: "remove", remove: { removed: m.leaf } })));
}

/**
 * Give a member device fresh keys: its old leaf is removed and the new key package added in one
 * commit. A member that fears its state was copied sends the committer a new key package (over
 * a direct session) and gets a welcome back.
 */
export async function replaceMember(state, keyPackage) {
  const who = keyPackageOwner(keyPackage);
  const old = describe(state).members.find((m) => m.actor === who.actor && m.device === who.device);
  if (!old) throw new SessionError("BAD_INPUT", "That device isn't in the group");
  if (old.leaf === COMMITTER_LEAF) throw new SessionError("BAD_INPUT", "The committer refreshes itself with refresh()");
  return commit(state, [{ proposalType: "remove", remove: { removed: old.leaf } }, { proposalType: "add", add: { keyPackage: decodeAs(keyPackage, "mls_key_package").keyPackage } }]);
}

/** A commit that changes nothing but the keys: new group secrets from the committer's new path. */
export const refresh = (state) => commit(state, []);

/** Join from a welcome, with the key package secret it was made for. */
export async function join({ welcome, keyPackage, actors }) {
  const cs = await impl();
  const w = decodeAs(welcome, "mls_welcome").welcome;
  const kp = decodeAs(keyPackage.package, "mls_key_package").keyPackage;
  const state = await wrap("UNTRUSTED", "Couldn't join the group", () => M.joinGroup(w, kp, unpackKeys(keyPackage.keys), M.emptyPskIndex, cs, undefined, undefined, config(actors)));
  if (!GROUP.test(text(state.groupContext.groupId))) throw new SessionError("BAD_MESSAGE", "Not a Secure Net group");
  return state;
}

// ---- Messages ----

/** Seal bytes for the group. Returns { state, message }. */
export async function seal(state, plaintext) {
  const cs = await impl();
  const r = await wrap("BAD_INPUT", "Couldn't seal for the group", () => M.createApplicationMessage(state, typeof plaintext === "string" ? utf8(plaintext) : plaintext, cs));
  r.consumed.forEach(M.zeroOutUint8Array);
  return { state: r.newState, message: b64u(M.encodeMlsMessage({ privateMessage: r.privateMessage, wireformat: "mls_private_message", version: "mls10" })) };
}

/**
 * Open a group message. Returns { state, kind: "message", plaintext } or { state, kind: "commit" }.
 * A commit is accepted only from the committer; proposals from anyone are refused (members ask
 * the committer over direct sessions instead). The state given is never changed.
 */
export async function open(state, message) {
  const cs = await impl();
  const pm = decodeAs(message, "mls_private_message").privateMessage;
  let refused = null;
  const gate = (incoming) => {
    if (incoming.kind === "commit" && incoming.senderLeafIndex === COMMITTER_LEAF) return "accept";
    refused = incoming.kind === "commit" ? "A commit from someone other than the group's committer" : "A proposal (members ask the committer directly)";
    return "reject";
  };
  const r = await wrap("DECRYPT_FAILED", "The group message couldn't be opened", () => M.processPrivateMessage(state, pm, M.emptyPskIndex, cs, gate));
  if (refused) throw new SessionError("NOT_ALLOWED", refused);
  r.consumed?.forEach(M.zeroOutUint8Array);
  if (r.kind === "applicationMessage") return { state: r.newState, kind: "message", plaintext: r.message };
  return { state: r.newState, kind: "commit" };
}

/** Save and load a group's state (bytes as base64url). `actors` is needed again on load. */
export const saveState = (state) => b64u(M.encodeGroupState(state));
export function loadState(saved, { actors }) {
  const decoded = M.decodeGroupState(fromB64u(saved), 0);
  if (!decoded) throw new SessionError("BAD_INPUT", "Not a saved group state");
  return { ...decoded[0], clientConfig: config(actors) };
}
