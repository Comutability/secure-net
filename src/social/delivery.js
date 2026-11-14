// End-to-end delivery (CVP-019): how activities travel, and what sites can see.
//
// Three envelope modes. A site carries every one of them, and can read only the first:
//
//   public    the signed activity in the clear, for posts addressed to "public"
//   direct    a CVP-016 session message to one device: direct messages, follows, and the sender
//             keys that let followers read followers-only posts
//   audience  one sender-key message (CVP-016 groups) for everyone in an audience: followers-only
//             posts and group posts, encrypted once however many people receive them
//
// Inside the encryption is the activity, still signed by the device that made it, so whoever
// opens it can check who wrote it with quantum-resistant signatures.
import { canonicalBytes, canonicalJson } from "../core/canonical.js";
import { b64u, fromB64u, utf8, concat } from "../core/bytes.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { SessionError } from "../session/primitives.js";
import { encrypt as encrypt1 } from "../session/session.js";
import * as v2 from "../session/v2.js";
import { createSenderKey, distribution, acceptDistribution, groupEncrypt, groupDecrypt } from "../session/group.js";
import { actorIdOf } from "./actor.js";
import { ACTIVITY } from "./activity.js";
import { ACTOR } from "./actor.js";
import { isActorId, isObjectId, newId, ownerOf, PUBLIC } from "./vocabulary.js";

export const MODES = Object.freeze(["public", "direct", "audience", "group"]);
export const DELIVERY_LIMITS = Object.freeze({ items: 100, envelopeBytes: 512 * 1024, requestBytes: 4 * 1024 * 1024 });
const KID = /^[A-Za-z0-9_-]{22}$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** Problems with an envelope's outer form (what a site checks before storing it). */
export function envelopeProblems(env) {
  if (!env || typeof env !== "object" || (env.v !== 1 && env.v !== 2)) return ["Not a version 1 or 2 envelope"];
  if (!MODES.includes(env.mode)) return [`Unknown mode "${env.mode}"`];
  if (env.v === 2) return envelope2Problems(env);
  if (env.mode === "group") return ["Group envelopes are version 2"];
  const out = [];
  if (env.mode === "public") {
    if (env.activity?.kind !== ACTIVITY || !env.activity.sig) out.push("A public envelope carries one signed activity");
    else if (![...(env.activity.body?.to || []), ...(env.activity.body?.cc || [])].includes(PUBLIC)) out.push("Only activities addressed to public may travel in the clear");
  } else if (env.mode === "direct") {
    if (!KID.test(env.device || "")) out.push("A direct envelope names the recipient device");
    if (!KID.test(env.session || "")) out.push("A direct envelope carries its session tag");
    if (env.message?.v !== 1 || typeof env.message?.c !== "string") out.push("A direct envelope carries one CVP-016 message");
  } else {
    if (!isObjectId(env.audience)) out.push("An audience envelope names its audience");
    if (env.message?.v !== 1 || env.message?.group !== env.audience || typeof env.message?.sig !== "string") out.push("An audience envelope carries one sender-key message for that audience");
  }
  for (const k of Object.keys(env)) if (!["v", "mode", "activity", "device", "session", "message", "audience"].includes(k)) out.push(`Unexpected field ${k}: envelopes carry nothing else, so they leak nothing else`);
  if (out.length === 0 && canonicalBytes(env).length > DELIVERY_LIMITS.envelopeBytes) out.push("Envelope is too large");
  return out;
}

const B64U = /^[A-Za-z0-9_-]+$/;

/**
 * Version 2 envelopes. A direct one names the recipient device and nothing else: no session tag,
 * and the message inside has an encrypted header and (on first messages) an encrypted sender. A
 * group one names the group and carries one MLS message (CVP-022).
 */
function envelope2Problems(env) {
  const out = [];
  let allowed;
  if (env.mode === "direct") {
    allowed = ["v", "mode", "device", "message"];
    if (!KID.test(env.device || "")) out.push("A direct envelope names the recipient device");
    const m = env.message;
    if (m?.v !== 2 || typeof m.h !== "string" || !B64U.test(m.h) || typeof m.c !== "string" || !B64U.test(m.c)) out.push("A version 2 direct envelope carries one version 2 CVP-016 message");
    else for (const k of Object.keys(m)) if (!["v", "h", "c", "x"].includes(k)) out.push(`Unexpected message field ${k}`);
  } else if (env.mode === "group") {
    allowed = ["v", "mode", "group", "message"];
    if (!isObjectId(env.group)) out.push("A group envelope names its group");
    if (typeof env.message !== "string" || !B64U.test(env.message)) out.push("A group envelope carries one MLS message");
  } else return [`Version 2 has no ${env.mode} envelope`];
  for (const k of Object.keys(env)) if (!allowed.includes(k)) out.push(`Unexpected field ${k}: envelopes carry nothing else, so they leak nothing else`);
  if (out.length === 0 && canonicalBytes(env).length > DELIVERY_LIMITS.envelopeBytes) out.push("Envelope is too large");
  return out;
}

/**
 * The tag a version 1 direct envelope carries so the recipient device knows which session opens it: derived
 * from the session's handshake hash, the same at both ends. A site sees which envelopes belong to
 * the same conversation, but not who is in it.
 */
export const sessionTag = (state) => b64u(sha256(concat(utf8("secure-net/social/v1/session\n"), fromB64u(state.ad)))).slice(0, 22);

const encode = (payload) => canonicalJson(payload);
function decode(bytes) {
  let p;
  try {
    p = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new SessionError("BAD_MESSAGE", "Payload isn't JSON");
  }
  if (!p || p.v !== 1 || (p.activity === undefined && p.senderKeys === undefined && p.actor === undefined && p.delivery === undefined && p.groups === undefined)) throw new SessionError("BAD_MESSAGE", "Not a version 1 payload");
  if (p.delivery !== undefined && !(typeof p.delivery === "string" && TOKEN.test(p.delivery))) throw new SessionError("BAD_MESSAGE", "Bad delivery token");
  if (p.groups !== undefined && !(Array.isArray(p.groups) && p.groups.length <= 20 && p.groups.every((g) => g && isObjectId(g.group) && typeof g.welcome === "string" && B64U.test(g.welcome)))) throw new SessionError("BAD_MESSAGE", "Bad group welcomes");
  if (p.actor !== undefined && p.actor?.kind !== ACTOR) throw new SessionError("BAD_MESSAGE", "Payload actor isn't an actor document");
  if (p.activity !== undefined && p.activity?.kind !== ACTIVITY) throw new SessionError("BAD_MESSAGE", "Payload activity isn't a signed activity");
  if (p.senderKeys !== undefined && !Array.isArray(p.senderKeys)) throw new SessionError("BAD_MESSAGE", "Bad sender keys");
  return p;
}

// ---- Public ----

/** The envelope for a public activity. */
export function publicEnvelope(record) {
  const env = { v: 1, mode: "public", activity: record };
  const p = envelopeProblems(env);
  if (p.length) throw new SessionError("BAD_INPUT", p.join("; "));
  return env;
}

// ---- Direct ----

/**
 * Seal a payload { activity?, senderKeys?, actor? } for several devices over their sessions
 * (sessions: device kid -> CVP-016 state). Returns { sessions, items: [{ to, envelope }] }, where
 * `to` is the recipient actor (the mailbox the envelope goes to).
 */
export async function sealDirect(sessions, { activity, senderKeys, actor, delivery, groups }) {
  const payload = { v: 1 };
  if (activity) payload.activity = activity;
  if (senderKeys?.length) payload.senderKeys = senderKeys;
  if (actor) payload.actor = actor;
  if (delivery) payload.delivery = delivery;
  if (groups?.length) payload.groups = groups;
  const unsigned = activity && activity.sig === undefined;
  const text = encode(payload);
  const out = { ...sessions };
  const items = [];
  for (const [device, state] of Object.entries(sessions)) {
    const to = actorIdOf(state.peer.account);
    if (state.v === 2) {
      const r = await v2.encrypt(state, text);
      out[device] = r.state;
      items.push({ to, envelope: { v: 2, mode: "direct", device, message: r.message } });
    } else {
      // An unsigned activity is only safe where the receiver knows to treat it as unsigned.
      if (unsigned || delivery || groups?.length) throw new SessionError("BAD_INPUT", "Unsigned activities, delivery tokens and group welcomes need a version 2 session");
      const r = await encrypt1(state, text);
      out[device] = r.state;
      items.push({ to, envelope: { v: 1, mode: "direct", device, session: sessionTag(r.state), message: r.message } });
    }
  }
  return { sessions: out, items };
}

/**
 * Read a direct payload once the session layer has decrypted it, and check it came from the
 * device the session is with. A signed activity must be signed by that device; an unsigned one
 * (version 2 sessions only) is returned as `unsigned` and must name that device. Sender keys are
 * recorded as that device's. An actor document in the payload must be the sender's own.
 * Returns { activity?, unsigned?, senderKeys, actor?, delivery?, groups }.
 */
export function openDirectPayload(plaintext, { fromDevice, fromActor, version = 1 }) {
  const p = decode(plaintext);
  if (p.activity && (p.activity.body?.device !== fromDevice || p.activity.body?.actor !== fromActor)) {
    throw new SessionError("UNTRUSTED", "The activity wasn't made by the device that sent it");
  }
  const unsigned = p.activity && p.activity.sig === undefined;
  if (version !== 2 && (unsigned || p.delivery !== undefined || p.groups !== undefined)) throw new SessionError("UNTRUSTED", "Unsigned activities, delivery tokens and group welcomes need a version 2 session");
  const senderKeys = (p.senderKeys || []).map((d) => {
    if (ownerOf(d?.group) !== fromActor) throw new SessionError("UNTRUSTED", "A sender key for someone else's audience");
    return acceptDistribution(d, { from: fromDevice });
  });
  if (p.actor && p.actor.body?.id !== fromActor) throw new SessionError("UNTRUSTED", "An actor document for someone else");
  return { activity: unsigned ? undefined : p.activity, unsigned: unsigned ? p.activity : undefined, senderKeys, actor: p.actor, delivery: p.delivery, groups: p.groups || [] };
}

// ---- Sealed sending (version 2) ----

/** A new delivery token: 32 random bytes. An actor gives it to the people it talks to, inside direct envelopes. */
export const newDeliveryToken = () => b64u(globalThis.crypto.getRandomValues(new Uint8Array(32)));

/** What the actor's site keeps instead of the token, so the site's database can't be used to send. */
export const deliveryVerifier = (token) => {
  if (!TOKEN.test(token || "")) throw new SessionError("BAD_INPUT", "Not a delivery token");
  return b64u(sha256(concat(utf8("secure-net/social/v2/delivery-token\n"), fromB64u(token))));
};

/**
 * The body of a sealed delivery: version 2 direct envelopes handed straight to the recipient's
 * site by a device that doesn't say who it is. Each item carries the recipient's delivery token.
 */
export function sealedBody(items) {
  if (!Array.isArray(items) || items.length === 0 || items.length > DELIVERY_LIMITS.items) throw new SessionError("BAD_INPUT", `1 to ${DELIVERY_LIMITS.items} items per request`);
  return { v: 1, items: readSealedBody({ v: 1, items }, "BAD_INPUT") };
}

/** Check a sealed delivery body; returns the items [{ to, envelope, token }]. */
export function readSealedBody(body, code = "BAD_MESSAGE") {
  if (!body || body.v !== 1 || !Array.isArray(body.items) || body.items.length === 0 || body.items.length > DELIVERY_LIMITS.items) throw new SessionError(code, "Not a version 1 sealed delivery");
  for (const it of body.items) {
    if (!isActorId(it?.to) || !TOKEN.test(it.token || "")) throw new SessionError(code, "Each item names the recipient actor and carries its delivery token");
    if (it.envelope?.v !== 2 || it.envelope.mode !== "direct") throw new SessionError(code, "Only version 2 direct envelopes may be sent sealed");
    const p = envelopeProblems(it.envelope);
    if (p.length) throw new SessionError(code, p.join("; "));
    for (const k of Object.keys(it)) if (!["to", "envelope", "token"].includes(k)) throw new SessionError(code, `Unexpected field ${k}`);
  }
  return body.items;
}

// ---- Audiences (followers-only and group posts) ----

/**
 * A new audience this device posts to: its followers, or a group's members. The audience id is
 * an object id of the actor's, so anyone can tell whose audience it is.
 */
export function createAudience(actorId, { kind = "followers" } = {}) {
  const id = newId(actorId);
  return { id, kind, key: createSenderKey(id), members: [] };
}

const memberKey = (m) => `${m.actor}/${m.device}`;

/**
 * Add member devices ({ actor, device }). Returns { audience, send }: send the current sender key
 * (`send.senderKey`) to `send.to` over direct sessions. New members can't read anything sealed
 * before they joined, because the key only moves forward.
 */
export function addMembers(audience, members) {
  const have = new Set(audience.members.map(memberKey));
  const fresh = members.filter((m) => isActorId(m.actor) && KID.test(m.device) && !have.has(memberKey(m)));
  return { audience: { ...audience, members: [...audience.members, ...fresh] }, send: { to: fresh, senderKey: distribution(audience.key) } };
}

/**
 * Remove members (unfollowed, blocked, left the group, or a device removed). The audience gets a
 * new sender key, which goes to every remaining member: whoever was removed can't read what's
 * sealed next. Returns { audience, send }.
 */
export function removeMembers(audience, predicate) {
  const members = audience.members.filter((m) => !predicate(m));
  const key = createSenderKey(audience.id);
  return { audience: { ...audience, members, key }, send: { to: members, senderKey: distribution(key) } };
}

/** Seal a signed activity once for the whole audience. Returns { audience, envelope }. */
export async function sealToAudience(audience, record) {
  const { key, message } = await groupEncrypt(audience.key, encode({ v: 1, activity: record }));
  return { audience: { ...audience, key }, envelope: { v: 1, mode: "audience", audience: audience.id, message } };
}

/**
 * Open an audience envelope with the sender key accepted from that device. The activity inside
 * must be signed by the same device. Returns { view, activity }.
 */
export async function openAudience(view, envelope) {
  if (envelope?.mode !== "audience" || envelope.audience !== view.group || envelope.message?.group !== view.group) throw new SessionError("BAD_MESSAGE", "Not for this audience");
  const { state, plaintext } = await groupDecrypt(view, envelope.message);
  const p = decode(plaintext);
  if (!p.activity || p.activity.body?.device !== view.from || p.activity.body?.actor !== ownerOf(view.group)) {
    throw new SessionError("UNTRUSTED", "The activity wasn't made by the device whose key sealed it");
  }
  return { view: state, activity: p.activity };
}

/** The id under which a receiver keeps a sender key: audience and key id together. */
export const viewKey = (audienceId, senderKeyId) => `${audienceId}#${senderKeyId}`;

// ---- Site to site ----

/** The body of a delivery request between sites (CVP-019, "Site to site"). */
export function deliveryBody(items) {
  if (!Array.isArray(items) || items.length === 0 || items.length > DELIVERY_LIMITS.items) throw new SessionError("BAD_INPUT", `1 to ${DELIVERY_LIMITS.items} items per request`);
  for (const it of items) {
    if (!isActorId(it.to)) throw new SessionError("BAD_INPUT", "Each item names the recipient actor");
    const p = envelopeProblems(it.envelope);
    if (p.length) throw new SessionError("BAD_INPUT", p.join("; "));
  }
  return { v: 1, items };
}

/** Check a delivery request body; returns the items. */
export function readDeliveryBody(body) {
  if (!body || body.v !== 1 || !Array.isArray(body.items) || body.items.length === 0 || body.items.length > DELIVERY_LIMITS.items) {
    throw new SessionError("BAD_MESSAGE", "Not a version 1 delivery");
  }
  for (const it of body.items) {
    if (!isActorId(it?.to)) throw new SessionError("BAD_MESSAGE", "Item without a recipient");
    const p = envelopeProblems(it.envelope);
    if (p.length) throw new SessionError("BAD_MESSAGE", p.join("; "));
  }
  return body.items;
}

