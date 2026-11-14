// One-to-one sessions, version 2 (CVP-016 version 2).
//
// What changed from version 1 (session.js), and why:
//
//   - The handshake transcript binds the prekeys' public keys, not only their ids.
//   - The initiator's identity (device list and device id) is encrypted in the first message, so
//     a site carrying it can't tell who is writing.
//   - Message headers are encrypted, so messages of one session can't be linked to each other,
//     ordered or counted by anyone but the two devices.
//   - The ML-KEM-768 keys and ciphertexts that keep the ratchet quantum-resistant travel in small
//     pieces inside the encrypted headers, instead of whole in every message. An ordinary message
//     is well under 1 KB instead of 3.1 KB. The price is that a new ML-KEM secret enters the root
//     key once per completed exchange (about 22 messages of back-and-forth) rather than at every
//     ratchet step.
//   - Keys kept for messages that haven't arrived are deleted after a time.
//
// State is plain JSON and every call returns a new state, so a message that fails leaves the
// session exactly as it was. Store the returned state before showing the message.
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u, fromB64u, utf8, concat, sha256B64u } from "../core/bytes.js";
import { canonicalBytes } from "../core/canonical.js";
import { verifyBundle, verifyDeviceList } from "./keys.js";
import { SessionError, dh, dhKeyPair, kemKeyPair, encapsulate, decapsulate, kdfChain, random, toBytes } from "./primitives.js";

export const VERSION = 2;
/** How far ahead of the last message a message may be, in one chain. */
export const MAX_SKIP = 1000;
/** How many keys for not-yet-arrived messages a session keeps, across chains. */
export const MAX_STORED = 2000;
/** How long a key for a not-yet-arrived message is kept. */
export const SKIPPED_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Bytes of ML-KEM key or ciphertext carried per message. */
export const CHUNK = 256;
const EK_LEN = 1184;
const CT_LEN = 1088;

const L_TRANSCRIPT = utf8("secure-net/session/v2/transcript");
const L_HANDSHAKE = utf8("secure-net/session/v2/handshake");
const L_IDENTITY = utf8("secure-net/session/v2/identity");
const L_ROOT = utf8("secure-net/session/v2/root");
const L_MESSAGE = utf8("secure-net/session/v2/message");
const ZERO32 = new Uint8Array(32);
const FF32 = new Uint8Array(32).fill(0xff);
const EMPTY = new Uint8Array(0);

const clone = (s) => JSON.parse(JSON.stringify(s));
const B64U = /^[A-Za-z0-9_-]+$/;
const isB64u = (s) => typeof s === "string" && B64U.test(s);
const isKey32 = (k) => {
  try {
    return isB64u(k) && fromB64u(k).length === 32;
  } catch {
    return false;
  }
};
const bad = (msg) => new SessionError("BAD_MESSAGE", msg);

// ---- AES-256-GCM ----

async function aead(key, iv, plaintext, ad) {
  const k = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: ad }, k, plaintext));
}

async function aeadOpen(key, iv, ciphertext, ad) {
  const k = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: ad }, k, ciphertext));
  } catch {
    return null;
  }
}

// ---- Derivations (spec/CVP-016, version 2) ----

/** What the transcript covers. Exported so tests and other implementations can check the binding. */
export function transcriptOf(initiator, responder, x, keys) {
  return {
    v: VERSION,
    initiator,
    responder,
    ek: x.ek,
    ct: sha256B64u(fromB64u(x.ct)),
    signed: { id: x.signed, pub: keys.signed },
    pq: { id: x.pq, pub: sha256B64u(fromB64u(keys.pq)) },
    oneTime: x.oneTime == null ? null : { id: x.oneTime, pub: keys.oneTime },
  };
}
const transcriptHash = (t) => sha256(concat(L_TRANSCRIPT, canonicalBytes(t)));

/** The handshake output: the first root key and the two first header keys. */
function handshakeKeys(dhs, ss, th) {
  const out = hkdf(sha256, concat(FF32, ...dhs, ss), ZERO32, concat(L_HANDSHAKE, th), 96);
  return { rk: out.slice(0, 32), hka: out.slice(32, 64), nhkb: out.slice(64) };
}

/** One step of the root chain: a chain key, the next header key, and the new root key. */
export function kdfRoot2(rk, dhOut, ss = EMPTY) {
  const out = hkdf(sha256, concat(dhOut, ss), rk, L_ROOT, 96);
  return { rk: out.slice(0, 32), ck: out.slice(32, 64), nhk: out.slice(64) };
}

function messageKey(mk) {
  const out = hkdf(sha256, mk, ZERO32, L_MESSAGE, 44);
  return { key: out.slice(0, 32), iv: out.slice(32) };
}

/** The key that hides the initiator's identity: from the ephemeral key and the prekeys only. */
function identityKey(dhs, ss, x) {
  const pub = canonicalBytes({ ek: x.ek, ct: sha256B64u(fromB64u(x.ct)), signed: x.signed, pq: x.pq, oneTime: x.oneTime ?? null });
  const out = hkdf(sha256, concat(FF32, ...dhs, ss), ZERO32, concat(L_IDENTITY, sha256(pub)), 44);
  return { key: out.slice(0, 32), iv: out.slice(32) };
}

// ---- Encrypted headers ----

async function sealHeader(hk, header, th) {
  const iv = random(12);
  return b64u(concat(iv, await aead(fromB64u(hk), iv, canonicalBytes(header), th)));
}

async function openHeader(hk, h, th) {
  if (!hk) return null;
  let raw;
  try {
    raw = fromB64u(h);
  } catch {
    return null;
  }
  if (raw.length < 12 + 16) return null;
  const pt = await aeadOpen(fromB64u(hk), raw.slice(0, 12), raw.slice(12), th);
  if (!pt) return null;
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    throw bad("Bad message header");
  }
  const int = (n) => Number.isSafeInteger(n) && n >= 0;
  if (!header || !isKey32(header.dh) || !int(header.n) || !int(header.pn)) throw bad("Bad message header");
  if (header.pe != null && !(int(header.pe) && header.pe >= 1)) throw bad("Bad message header");
  if (header.k != null && (typeof header.k !== "object" || !int(header.k.e))) throw bad("Bad message header");
  return header;
}

// ---- The sparse ML-KEM exchange ----
//
// Epochs are numbered from 1. In each, one side sends an ML-KEM-768 key in pieces ("ek"), the
// other answers with the ciphertext in pieces ("ct"), and the first side then mixes the shared
// secret into the root key at its next new sending chain, saying so in that chain's headers
// (`pe`). The initiator sends the key in odd epochs, the responder in even ones.

const pieces = (len) => Math.ceil(len / CHUNK);
function split(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i += CHUNK) out.push(b64u(bytes.slice(i, i + CHUNK)));
  return out;
}

function newEpoch(e, weSendKey) {
  if (weSendKey) {
    const kp = kemKeyPair();
    return { e, role: "ek", sk: kp.sk, out: split(fromB64u(kp.pk)), i: 0, got: {}, seen: false, ss: null };
  }
  return { e, role: "ct", out: null, i: 0, got: {}, acked: false, ss: null };
}

/** What to put in the next header for the exchange, if anything. */
function pieceToSend(pq) {
  if (pq.role === "ek") {
    if (pq.ss) return { e: pq.e, t: "ack" };
    if (pq.seen) return undefined;
  } else if (!pq.out || pq.acked) return undefined;
  const i = pq.i % pq.out.length;
  pq.i += 1;
  return { e: pq.e, t: pq.role, i, d: pq.out[i] };
}

function keep(pq, k, total) {
  const n = pieces(total);
  if (!Number.isSafeInteger(k.i) || k.i < 0 || k.i >= n || !isB64u(k.d)) throw bad("Bad key piece");
  const want = k.i === n - 1 ? total - CHUNK * (n - 1) : CHUNK;
  if (fromB64u(k.d).length !== want) throw bad("Bad key piece");
  pq.got[k.i] = k.d;
  if (Object.keys(pq.got).length < n) return null;
  const whole = concat(...Array.from({ length: n }, (_, i) => fromB64u(pq.got[i])));
  pq.got = {};
  return b64u(whole);
}

/** Take in the piece a (decrypted, authenticated) header carried. */
function pieceReceived(pq, k) {
  if (!k || k.e !== pq.e) return;
  if (pq.role === "ct") {
    if (k.t === "ack") pq.acked = true;
    else if (k.t === "ek" && !pq.ss) {
      const ek = keep(pq, k, EK_LEN);
      if (!ek) return;
      try {
        const enc = encapsulate(ek);
        pq.out = split(fromB64u(enc.ct));
        pq.i = 0;
        pq.ss = b64u(enc.ss);
      } catch {
        // Not a usable key: collect it again rather than lose the message it came with.
      }
    }
  } else if (k.t === "ct" && !pq.ss) {
    pq.seen = true;
    const ct = keep(pq, k, CT_LEN);
    if (!ct) return;
    pq.ss = b64u(decapsulate(ct, pq.sk));
    pq.sk = null;
    pq.out = null;
  }
}

/** The derivations, for test vectors and other implementations. Not needed to use sessions. */
export const derive = Object.freeze({ transcriptHash, handshakeKeys, kdfRoot2, messageKey, identityKey, split, pieces });

/** Where the post-quantum exchange stands: the epoch in progress and how many have been mixed in. */
export const pqStatus = (state) => ({ epoch: state.pq.e, mixed: state.mixed, role: state.pq.role });

// ---- Handshake ----

const party = (account, dev) => ({ account, device: dev.kid, sign: dev.sign, dh: dev.dh });

function newState({ keys, th, peer, self, initiator }) {
  return {
    v: VERSION, ad: b64u(th), rk: b64u(keys.rk), peer, self, initiator,
    dhs: null, dhr: null, hks: null, hkr: null, nhks: null, nhkr: null, cks: null, ckr: null,
    ns: 0, nr: 0, pn: 0, pe: null, mixed: 0, pq: newEpoch(1, initiator), skipped: [], pending: null,
  };
}

/**
 * Start a session with one of someone's devices, from a bundle their site handed out.
 *   me: { device, deviceList }   your device (with secrets) and your account's signed device list
 *   accountKey                    the account key you trust for them
 *   minSeq                        the highest device-list seq you've seen for them
 */
export async function initiate({ me, bundle, accountKey, minSeq = 0, now = Date.now() }) {
  const v = verifyBundle(bundle, { accountKey, minSeq, now });
  const myAccount = me.deviceList.body.account;
  const myDev = me.deviceList.body.devices.find((d) => d.kid === me.device.kid);
  if (!myDev || myDev.dh !== me.device.dh.pk) throw new SessionError("BAD_INPUT", "Your device isn't on your own device list");

  const ek = dhKeyPair();
  const enc = encapsulate(v.pq.pub);
  const x = { ek: ek.pk, ct: enc.ct, signed: v.signed.id, pq: v.pq.id, oneTime: v.oneTime?.id ?? null };
  const hidden = [dh(ek.sk, v.signed.pub)];
  if (v.oneTime) hidden.push(dh(ek.sk, v.oneTime.pub));
  const ik = identityKey(hidden, enc.ss, x);
  x.id = b64u(await aead(ik.key, ik.iv, canonicalBytes({ list: me.deviceList, device: me.device.kid }), EMPTY));

  const dhs = [dh(me.device.dh.sk, v.signed.pub), dh(ek.sk, v.device.dh), ...hidden];
  const th = transcriptHash(transcriptOf(party(myAccount, myDev), party(accountKey, v.device), x, { signed: v.signed.pub, pq: v.pq.pub, oneTime: v.oneTime?.pub }));
  const keys = handshakeKeys(dhs, enc.ss, th);

  const s = newState({ keys, th, peer: { account: accountKey, device: v.device.kid }, self: me.device.kid, initiator: true });
  s.dhs = dhKeyPair();
  s.dhr = v.signed.pub;
  const step = kdfRoot2(keys.rk, dh(s.dhs.sk, s.dhr));
  s.rk = b64u(step.rk);
  s.cks = b64u(step.ck);
  s.nhks = b64u(step.nhk);
  s.hks = b64u(keys.hka);
  s.nhkr = b64u(keys.nhkb);
  s.pending = x;
  return s;
}

/** Whether a message starts a new session (rather than continuing one you have). */
export const isInitial = (message) => Boolean(message?.x);

/** An id for a first message's handshake. Remember these while a signed prekey is live and refuse repeats. */
export const handshakeId = (message) => (isKey32(message?.x?.ek) ? sha256B64u(fromB64u(message.x.ek)).slice(0, 22) : null);

function prekeysFor(me, x) {
  if (!x || typeof x !== "object" || !isKey32(x.ek) || !isB64u(x.ct) || !isB64u(x.id)) throw bad("Not a first message");
  const secret = (id, type, want) => {
    const k = id == null ? null : me.prekeys[id];
    if (!k || k.type !== type || (want === "oneTime" && !k.oneTime) || (want === "signed" && (k.oneTime || k.lastResort)) || (want === "pq" && !k.oneTime && !k.lastResort)) {
      throw new SessionError("UNKNOWN_PREKEY", "That prekey is unknown or already used");
    }
    return k;
  };
  const spk = secret(x.signed, "x25519", "signed");
  const pq = secret(x.pq, "ml-kem-768", "pq");
  const opk = x.oneTime == null ? null : secret(x.oneTime, "x25519", "oneTime");
  const hidden = [dh(spk.sk, x.ek)];
  if (opk) hidden.push(dh(opk.sk, x.ek));
  return { spk, pq, opk, hidden, ss: decapsulate(x.ct, pq.sk) };
}

async function openIdentity(me, x) {
  const p = prekeysFor(me, x);
  const ik = identityKey(p.hidden, p.ss, x);
  const pt = await aeadOpen(ik.key, ik.iv, fromB64u(x.id), EMPTY);
  if (!pt) throw new SessionError("DECRYPT_FAILED", "The first message couldn't be opened");
  let id;
  try {
    id = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    throw bad("Not a first message");
  }
  if (!id?.list?.body || typeof id.device !== "string") throw bad("Not a first message");
  return { ...p, id };
}

/**
 * Who a first message says it is from. Only the device it was sent to can tell (it needs the
 * prekey secrets). Use it to look up the account key you trust for them, then call respond().
 * Nothing here is verified yet.
 */
export async function initialSender({ me, message }) {
  const { id } = await openIdentity(me, message?.x);
  return { account: id.list.body.account, device: id.device, handshake: handshakeId(message) };
}

/**
 * Accept a first message on the device it was sent to.
 *   me: { device, deviceList, prekeys }
 *   accountKey   the account key you trust for the sender (see initialSender)
 * Returns { state, plaintext, prekeys }: prekeys without the one-time prekeys this used.
 */
export async function respond({ me, message, accountKey, minSeq = 0, now = Date.now() }) {
  const x = message?.x;
  const { spk, pq, opk, hidden, ss, id } = await openIdentity(me, x);
  const list = verifyDeviceList(id.list, { accountKey, minSeq });
  const theirDev = list.devices.find((d) => d.kid === id.device);
  if (!theirDev) throw new SessionError("UNTRUSTED", "The sending device isn't on its account's device list");
  const myDev = me.deviceList.body.devices.find((d) => d.kid === me.device.kid);
  if (!myDev) throw new SessionError("BAD_INPUT", "Your device isn't on your own device list");

  const dhs = [dh(spk.sk, theirDev.dh), dh(me.device.dh.sk, x.ek), ...hidden];
  const th = transcriptHash(transcriptOf(party(list.account, theirDev), party(me.deviceList.body.account, myDev), x, { signed: spk.pk, pq: pq.pk, oneTime: opk?.pk }));
  const keys = handshakeKeys(dhs, ss, th);

  const s = newState({ keys, th, peer: { account: list.account, device: theirDev.kid }, self: me.device.kid, initiator: false });
  s.dhs = { sk: spk.sk, pk: spk.pk };
  s.nhks = b64u(keys.nhkb);
  s.nhkr = b64u(keys.hka);
  const out = await decrypt(s, message, { now });
  const prekeys = { ...me.prekeys };
  if (opk) delete prekeys[x.oneTime];
  if (pq.oneTime) delete prekeys[x.pq];
  return { ...out, prekeys };
}

// ---- Ratchet ----

const adOf = (s, message) => concat(fromB64u(s.ad), canonicalBytes(message.x ? { h: message.h, x: message.x } : { h: message.h }));

/** Encrypt for the peer. Returns { state, message }; message is JSON for the relay. */
export async function encrypt(state, plaintext) {
  if (state?.v !== VERSION) throw new SessionError("BAD_INPUT", "Not a version 2 session");
  if (!state.cks) throw new SessionError("NOT_READY", "This session can't send until it has received a message");
  const s = clone(state);
  const { mk, ck } = kdfChain(fromB64u(s.cks));
  s.cks = b64u(ck);
  const h = { dh: s.dhs.pk, pn: s.pn, n: s.ns };
  if (s.pe != null) h.pe = s.pe;
  const k = pieceToSend(s.pq);
  if (k) h.k = k;
  s.ns += 1;
  const message = { v: VERSION, h: await sealHeader(s.hks, h, fromB64u(s.ad)) };
  if (s.pending) message.x = s.pending;
  const { key, iv } = messageKey(mk);
  message.c = b64u(await aead(key, iv, toBytes(plaintext), adOf(s, message)));
  return { state: s, message };
}

function skipTo(s, until, now) {
  if (!s.ckr) return;
  if (until - s.nr > MAX_SKIP) throw new SessionError("TOO_FAR_AHEAD", "Too many messages missing");
  let ck = fromB64u(s.ckr);
  while (s.nr < until) {
    const step = kdfChain(ck);
    s.skipped.push({ hk: s.hkr, n: s.nr, mk: b64u(step.mk), t: now });
    ck = step.ck;
    s.nr += 1;
  }
  s.ckr = b64u(ck);
  if (s.skipped.length > MAX_STORED) s.skipped.splice(0, s.skipped.length - MAX_STORED);
}

function ratchet(s, h) {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.hks = s.nhks;
  s.hkr = s.nhkr;
  s.dhr = h.dh;
  // The peer mixed an ML-KEM secret into this chain. We must be the side that made that secret
  // (we encapsulated, so we have had it since before the peer could), and for this very epoch.
  let ssIn = EMPTY;
  if (h.pe != null) {
    if (s.pq.role !== "ct" || h.pe !== s.pq.e || !s.pq.ss) throw bad("The post-quantum exchange is out of step");
    ssIn = fromB64u(s.pq.ss);
  }
  let step = kdfRoot2(fromB64u(s.rk), dh(s.dhs.sk, s.dhr), ssIn);
  s.ckr = b64u(step.ck);
  s.nhkr = b64u(step.nhk);
  if (h.pe != null) {
    s.pq = newEpoch(h.pe + 1, true);
    s.mixed += 1;
  }
  s.dhs = dhKeyPair();
  // Our turn: if we hold a finished secret (we sent the key and have the whole ciphertext), mix
  // it into our new sending chain and say so in its headers.
  let ssOut = EMPTY;
  s.pe = null;
  if (s.pq.role === "ek" && s.pq.ss) {
    ssOut = fromB64u(s.pq.ss);
    s.pe = s.pq.e;
    s.pq = newEpoch(s.pq.e + 1, false);
    s.mixed += 1;
  }
  step = kdfRoot2(step.rk, dh(s.dhs.sk, s.dhr), ssOut);
  s.rk = b64u(step.rk);
  s.cks = b64u(step.ck);
  s.nhks = b64u(step.nhk);
}

function checkOuter(message) {
  if (!message || message.v !== VERSION) throw bad("Unsupported message version");
  if (!isB64u(message.h) || !isB64u(message.c)) throw bad("Bad message");
}

/**
 * Whether this session can open the message's header, without changing anything. With encrypted
 * headers a message doesn't say which session it belongs to: try each session with the sender's
 * device, or each session on the device.
 */
export async function canOpen(state, message) {
  if (state?.v !== VERSION || message?.v !== VERSION || !isB64u(message.h)) return false;
  const th = fromB64u(state.ad);
  const keys = new Set([state.hkr, state.nhkr, ...state.skipped.map((k) => k.hk)]);
  for (const hk of keys) {
    try {
      if (await openHeader(hk, message.h, th)) return true;
    } catch {
      return true;
    }
  }
  return false;
}

/** Decrypt a message from the peer. Returns { state, plaintext } (plaintext is bytes). */
export async function decrypt(state, message, { now = Date.now() } = {}) {
  if (state?.v !== VERSION) throw new SessionError("BAD_INPUT", "Not a version 2 session");
  checkOuter(message);
  const s = clone(state);
  s.skipped = s.skipped.filter((k) => now - k.t <= SKIPPED_TTL_MS);
  const th = fromB64u(s.ad);
  let h = null;
  let mk = null;
  let seenOld = false;

  // 1. A message we were waiting for, from this or an earlier chain.
  for (const hk of new Set(s.skipped.map((k) => k.hk))) {
    const header = await openHeader(hk, message.h, th);
    if (!header) continue;
    const at = s.skipped.findIndex((k) => k.hk === hk && k.n === header.n);
    if (at >= 0) {
      h = header;
      mk = fromB64u(s.skipped[at].mk);
      s.skipped.splice(at, 1);
    } else if (hk !== s.hkr) seenOld = true;
    break;
  }
  if (!mk && seenOld) throw new SessionError("REPLAY", "Message already received");

  if (!mk) {
    // 2. The current receiving chain.
    h = await openHeader(s.hkr, message.h, th);
    if (h) {
      if (h.dh !== s.dhr) throw bad("Bad message header");
      if (h.n < s.nr) throw new SessionError("REPLAY", "Message already received");
    } else {
      // 3. A new chain: the peer has moved its ratchet on.
      h = await openHeader(s.nhkr, message.h, th);
      if (!h) throw new SessionError("DECRYPT_FAILED", "The message couldn't be decrypted");
      if (h.dh === s.dhr) throw bad("Bad message header");
      skipTo(s, h.pn, now);
      ratchet(s, h);
    }
    skipTo(s, h.n, now);
    const step = kdfChain(fromB64u(s.ckr));
    mk = step.mk;
    s.ckr = b64u(step.ck);
    s.nr += 1;
  }

  const { key, iv } = messageKey(mk);
  const plaintext = await aeadOpen(key, iv, fromB64u(message.c), adOf(s, message));
  if (!plaintext) throw new SessionError("DECRYPT_FAILED", "The message couldn't be decrypted");
  pieceReceived(s.pq, h.k);
  // Hearing back means the peer has the session, so stop sending the handshake.
  if (s.pending && !message.x) s.pending = null;
  return { state: s, plaintext };
}
