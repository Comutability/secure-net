// A reference client for CVP-017 to 019: what an app does on a person's device. One device per
// client here, to keep it readable; the protocol itself is per device throughout, so a second
// device is another client sharing the account (CVP-016 device lists).
//
// Policy choices an app would make differently are marked "policy": this one accepts every
// follow, pins actors on first contact, and keeps everything in memory.
import { createAccount, createDevice, signDeviceList, createPrekeys } from "../session/keys.js";
import { initiate, respond, decrypt, isInitial, initialSender, handshakeId } from "../session/session.js";
import * as v2 from "../session/v2.js";
import { SessionError } from "../session/primitives.js";
import { createActorDocument, verifyActorDocument, parseHandle, actorIdOf } from "./actor.js";
import { signActivity, verifyActivity, sessionActivity, verifySessionActivity } from "./activity.js";
import { publicEnvelope, sealDirect, openDirectPayload, createAudience, addMembers, removeMembers, sealToAudience, openAudience, viewKey, sessionTag, newDeliveryToken, deliveryVerifier, sealedBody } from "./delivery.js";
import { PUBLIC, FOLLOWERS, isActorId } from "./vocabulary.js";
import { createRepo, appendToRepo, exportRepo } from "./repo.js";

const text = (b) => new TextDecoder().decode(b);

export class SocialClient {
  /**
   * sessions: the highest CVP-016 version this client starts (2 by default; 1 behaves as a client
   * from before version 2). deniable: whether direct activities go unsigned over version 2
   * sessions (policy: on, as Signal does; turn it off to be able to prove what you were sent).
   */
  constructor({ handle, network, type = "Person", name, sessions = 2, deniable = true }) {
    const h = parseHandle(handle);
    if (!h) throw new SessionError("BAD_INPUT", "A handle looks like name@host");
    this.handle = h.handle;
    this.network = network;
    this.site = network.site(h.host);
    this.type = type;
    this.name = name;
    this.account = createAccount();
    this.device = createDevice();
    this.id = actorIdOf(this.account.publicKey);
    this.deviceList = signDeviceList(this.account, [this.device], { seq: 1 });
    this.seq = 0;
    this.sessions = {}; // peer device kid -> CVP-016 session state
    this.byTag = new Map(); // session tag -> peer device kid
    this.handshakes = new Set();
    this.known = new Map(); // actor id -> verified actor document body (pinned on first contact: policy)
    this.records = new Map(); // actor id -> actor document record
    this.followers = createAudience(this.id); // this device's followers audience
    this.views = new Map(); // viewKey -> sender key view
    this.following = new Set();
    this.pending = new Map(); // Follow activity id -> actor id
    this.timeline = [];
    this.likes = new Map(); // object id -> Set of actor ids
    this.repo = createRepo(this.id); // our public activities, signed as a set (CVP-020)
    this.actorSent = new Map(); // actor id -> seq of our actor document they've been sent
    this.maxSessions = sessions;
    this.deniable = deniable;
    this.token = sessions >= 2 ? newDeliveryToken() : null; // our delivery token, given to the people we talk to
    this.tokenSent = new Set(); // actor ids who have our current token
    this.tokens = new Map(); // actor id -> their delivery token
    this.peerVersion = new Map(); // peer device kid -> highest session version seen from it
  }

  /** Publish the actor document and prekeys to our site. */
  register() {
    this.seq += 1;
    this.actorRecord = createActorDocument(this.account, { handle: this.handle, type: this.type, name: this.name, devices: this.deviceList, seq: this.seq });
    this.site.publishActor(this.actorRecord);
    const { secrets, published } = createPrekeys(this.device, { oneTime: 10, pqOneTime: 10, sessions: this.maxSessions });
    this.prekeys = secrets;
    this.site.publishPrekeys(this.id, this.device.kid, published);
    if (this.token) this.site.setDeliveryVerifiers(this.id, [deliveryVerifier(this.token)]);
    this.remember(this.actorRecord);
    return this;
  }

  /** Check and keep an actor document; a lower seq than one seen is refused. */
  remember(record) {
    const prev = this.known.get(record?.body?.id);
    const body = verifyActorDocument(record, { id: record?.body?.id, minSeq: prev?.seq ?? 0 });
    this.known.set(body.id, body);
    this.records.set(body.id, record);
    return body;
  }

  hostOf(actorId) {
    const a = this.known.get(actorId);
    if (!a) throw new SessionError("UNKNOWN_ACTOR", "Look this actor up first");
    return parseHandle(a.handle).host;
  }

  /** Look someone up by handle (CVP-017, "Discovery"). */
  lookup(handle) {
    const h = parseHandle(handle);
    const record = this.network.site(h.host).actor({ handle: h.name });
    if (record.moved) {
      // The actor has moved. Believe it only if the site they moved to serves the same actor.
      const body = verifyActorDocument(record.moved);
      const there = this.network.site(parseHandle(body.handle).host).actor({ id: body.id });
      verifyActorDocument(there, { id: body.id, handle: body.handle });
      return this.remember(there);
    }
    verifyActorDocument(record, { handle: h.handle });
    return this.remember(record);
  }

  /** Sessions with every device of an actor, starting any that are missing. */
  async sessionsFor(actorId) {
    const actor = this.known.get(actorId);
    const out = {};
    for (const d of actor.devices.body.devices) {
      if (d.kid === this.device.kid) continue;
      if (!this.sessions[d.kid]) {
        const bundle = this.network.site(this.hostOf(actorId)).bundle(actorId, d.kid);
        const me = { device: this.device, deviceList: this.deviceList };
        const args = { me, bundle, accountKey: actor.account, minSeq: actor.devices.body.seq };
        // The version a device speaks is in its signed prekey, so a site can't talk us down by
        // editing it; and once a device has spoken version 2 we never go back to 1 with it.
        const theirs = Math.min(this.maxSessions, sessionVersionOf(bundle));
        if (theirs < (this.peerVersion.get(d.kid) || 1)) throw new SessionError("DOWNGRADE", "That device spoke a newer session version before");
        if (theirs >= 2) this.sessions[d.kid] = await v2.initiate(args);
        else {
          this.sessions[d.kid] = initiate(args);
          this.byTag.set(sessionTag(this.sessions[d.kid]), d.kid);
        }
        this.peerVersion.set(d.kid, theirs);
      }
      out[d.kid] = this.sessions[d.kid];
    }
    return out;
  }

  /**
   * An activity that will only ever travel in direct envelopes to these actors: unsigned if this
   * client is set to deniable and every session involved is version 2, signed otherwise.
   */
  async direct(recipients, activity) {
    let all2 = this.deniable;
    for (const a of recipients) all2 = Object.values(await this.sessionsFor(a)).every((st) => st.v === 2) && all2;
    return all2 ? sessionActivity(this.device, this.id, activity) : this.sign(activity, { encrypted: true });
  }

  /** Send a payload to every device of an actor. */
  async sendDirect(actorId, payload) {
    const sessions = await this.sessionsFor(actorId);
    const all2 = Object.values(sessions).every((st) => st.v === 2);
    const out = { ...payload };
    // Our actor document goes along the first time, and again only when it has changed.
    if (this.actorSent.get(actorId) !== this.actorRecord.body.seq) out.actor = this.actorRecord;
    // So does our delivery token, so they can write back without their site or ours learning who.
    if (all2 && this.token && !this.tokenSent.has(actorId)) out.delivery = this.token;
    // Sealed sending needs their token and sessions they have already answered: a first message
    // goes through our site, which vouches for it (CVP-019, "Sealed sending").
    const sealedOk = all2 && Object.values(sessions).every((st) => !st.pending);
    const { sessions: next, items } = await sealDirect(sessions, out);
    this.actorSent.set(actorId, this.actorRecord.body.seq);
    if (out.delivery) this.tokenSent.add(actorId);
    Object.assign(this.sessions, next);
    return this.deliver(actorId, items.map((it) => it.envelope), { sealed: sealedOk });
  }

  /**
   * Send envelopes that need no sender (version 2 direct, or group) to one actor: sealed, straight
   * to their site, if we hold their delivery token; through our own site otherwise.
   */
  async deliver(actorId, envelopes, { sealed = true } = {}) {
    const host = this.hostOf(actorId);
    const token = this.tokens.get(actorId);
    if (sealed && token) {
      try {
        this.network.site(host).receiveSealed(this.network.record({ sealed: true, to: host, body: sealedBody(envelopes.map((envelope) => ({ to: actorId, envelope, token }))) }).body);
        return "sealed";
      } catch (e) {
        if (e.code !== "UNTRUSTED") throw e;
        this.tokens.delete(actorId);
      }
    }
    await this.site.send(this.id, envelopes.map((envelope) => ({ host, to: actorId, envelope })));
    return "site";
  }

  /** Process an activity that another module has already authenticated (groups). */
  handleActivity(body, how) {
    return this.#handle(body, how);
  }

  /** Replace our delivery token (to cut off someone who has it). People we talk to get the new one with our next message. */
  rotateDeliveryToken() {
    const old = this.token;
    this.token = newDeliveryToken();
    this.tokenSent.clear();
    this.site.setDeliveryVerifiers(this.id, [deliveryVerifier(this.token), deliveryVerifier(old)]);
  }

  sign(activity, { encrypted }) {
    return signActivity(this.device, this.id, activity, { encrypted });
  }

  /** Followers' actor ids (each may have several devices in the audience). */
  followerIds() {
    return [...new Set(this.followers.members.map((m) => m.actor))];
  }

  /**
   * Post a Note. to: "public" (signed, readable by anyone, also sent to followers), "followers"
   * (end-to-end encrypted to them), or a list of actor ids (a direct message).
   */
  async post(content, { to = FOLLOWERS, summary, object: custom } = {}) {
    const object = custom ?? { type: "Note", content, mediaType: "text/plain", ...(summary ? { summary } : {}) };
    if (to === PUBLIC) {
      const record = this.sign({ type: "Create", to: [PUBLIC], cc: [FOLLOWERS], object }, { encrypted: false });
      this.repo = appendToRepo(this.repo, this.device, record);
      this.site.publishRepo(exportRepo(this.repo, this.actorRecord));
      const env = publicEnvelope(record);
      const targets = [this.id, ...this.followerIds()];
      await this.site.send(this.id, targets.map((a) => ({ host: this.hostOf(a), to: a, envelope: env })));
      return record;
    }
    if (to === FOLLOWERS) {
      const record = this.sign({ type: "Create", to: [FOLLOWERS], object }, { encrypted: true });
      const { audience, envelope } = await sealToAudience(this.followers, record);
      this.followers = audience;
      await this.site.send(this.id, this.followerIds().map((a) => ({ host: this.hostOf(a), to: a, envelope })));
      return record;
    }
    if (!Array.isArray(to) || !to.every(isActorId)) throw new SessionError("BAD_INPUT", "to must be public, followers or a list of actor ids");
    const record = await this.direct(to, { type: "Create", to, object });
    for (const a of to) await this.sendDirect(a, { activity: record });
    return record;
  }

  /**
   * Move to another site, keeping the same actor id, keys, followers and sessions (CVP-017,
   * "Moving"). The new site gets the actor document, prekeys and repository; the old site is told
   * to point lookups at the new one; and everyone we talk to gets the new document, end to end.
   */
  async migrate(newHandle) {
    const h = parseHandle(newHandle);
    const to = this.network.site(h.host);
    const from = this.site;
    this.seq += 1;
    this.handle = h.handle;
    this.actorRecord = createActorDocument(this.account, { handle: this.handle, type: this.type, name: this.name, devices: this.deviceList, seq: this.seq });
    to.publishActor(this.actorRecord);
    const { secrets, published } = createPrekeys(this.device, { oneTime: 10, pqOneTime: 10 });
    this.prekeys = { ...this.prekeys, ...secrets };
    to.publishPrekeys(this.id, this.device.kid, published);
    if (this.repo.head) to.publishRepo(exportRepo(this.repo, this.actorRecord));
    from.release(this.actorRecord);
    this.site = to;
    this.remember(this.actorRecord);
    for (const a of new Set([...this.followerIds(), ...this.following])) {
      await this.sendDirect(a, { activity: await this.direct([a], { type: "Update", to: [a], object: { type: this.type, id: this.id } }) });
    }
  }

  async follow(handle) {
    const target = this.lookup(handle);
    const record = await this.direct([target.id], { type: "Follow", to: [target.id], object: target.id });
    this.pending.set(record.body.id, target.id);
    await this.sendDirect(target.id, { activity: record });
  }

  async unfollow(actorId) {
    const follow = [...this.pending.entries()].find(([, a]) => a === actorId)?.[0];
    this.following.delete(actorId);
    if (!follow) return;
    await this.sendDirect(actorId, { activity: await this.direct([actorId], { type: "Undo", to: [actorId], object: follow }) });
  }

  async like(objectId, authorId) {
    await this.sendDirect(authorId, { activity: await this.direct([authorId], { type: "Like", to: [authorId], object: objectId }) });
  }

  /** Stop someone reading our followers-only posts: remove them and give everyone else a new key. */
  async removeFollower(actorId) {
    const { audience, send } = removeMembers(this.followers, (m) => m.actor === actorId);
    this.followers = audience;
    for (const a of new Set(send.to.map((m) => m.actor))) await this.sendDirect(a, { senderKeys: [send.senderKey] });
  }

  /** Collect and process our mailbox. Returns what was shown, as { kind, ...}. */
  async sync() {
    const shown = [];
    for (const { envelope, from } of this.site.collect(this.id)) {
      try {
        const r = await this.#open(envelope, from);
        if (r) shown.push(r);
      } catch (e) {
        shown.push({ kind: "refused", reason: e.code || e.message });
      }
    }
    return shown;
  }

  async #open(env, fromHost) {
    if (env.mode === "public") {
      const author = env.activity.body.actor;
      if (!this.known.has(author)) this.remember(this.network.site(fromHost).actor({ id: author }));
      return this.#handle(verifyActivity(env.activity, this.known.get(author)), "public");
    }
    if (env.mode === "audience") {
      const key = viewKey(env.audience, env.message.id);
      const view = this.views.get(key);
      if (!view) return { kind: "unreadable", reason: "no key for this audience (not a member when it was sealed)" };
      const { view: next, activity } = await openAudience(view, env);
      this.views.set(key, next);
      return this.#handle(verifyActivity(activity, this.known.get(activity.body.actor), { encrypted: true }), "followers");
    }
    if (env.mode === "group") {
      // Groups (CVP-022) live in their own module, which needs an MLS library: see groups/client.js.
      if (!this.onGroupEnvelope) return { kind: "unreadable", reason: "this client doesn't do groups" };
      return this.onGroupEnvelope(env);
    }
    // direct
    if (env.device !== this.device.kid) return null;
    const { peer, plaintext, version } = env.v === 2 ? await this.#openDirect2(env) : await this.#openDirect1(env);
    const state = this.sessions[peer];
    const fromActor = actorIdOf(state.peer.account);
    const p = openDirectPayload(plaintext, { fromDevice: peer, fromActor, version });
    if (p.actor) this.remember(p.actor);
    if (p.delivery) this.tokens.set(fromActor, p.delivery);
    for (const v of p.senderKeys) this.views.set(viewKey(v.group, v.id), v);
    for (const g of p.groups) await this.onWelcome?.(g, fromActor);
    if (p.unsigned) return this.#handle(verifySessionActivity(p.unsigned, this.known.get(fromActor), { fromDevice: peer }), "direct", { deniable: true });
    if (!p.activity) return { kind: "keys", from: fromActor };
    return this.#handle(verifyActivity(p.activity, this.known.get(fromActor), { encrypted: true }), "direct");
  }

  async #openDirect1(env) {
    let peer = this.byTag.get(env.session);
    if (!peer && isInitial(env.message)) {
      const who = initialSender(env.message);
      if ((this.peerVersion.get(who.device) || 1) > 1) throw new SessionError("DOWNGRADE", "That device spoke a newer session version before");
      if (this.handshakes.has(who.handshake)) throw new SessionError("REPLAY", "First message already received");
      const r = await respond({ me: { device: this.device, deviceList: this.deviceList, prekeys: this.prekeys }, message: env.message, accountKey: who.account }); // trust on first use: policy
      this.handshakes.add(handshakeId(env.message));
      this.prekeys = r.prekeys;
      peer = r.state.peer.device;
      this.sessions[peer] = r.state;
      this.byTag.set(sessionTag(r.state), peer);
      return { peer, plaintext: r.plaintext, version: 1 };
    }
    if (!peer) throw new SessionError("UNKNOWN_SESSION", "No session for that tag");
    const r = await decrypt(this.sessions[peer], env.message);
    this.sessions[peer] = r.state;
    return { peer, plaintext: r.plaintext, version: 1 };
  }

  async #openDirect2(env) {
    if (this.maxSessions < 2) throw new SessionError("BAD_MESSAGE", "Unsupported message version");
    // Nothing on the envelope says which session it belongs to: find the one whose header key opens it.
    for (const [peer, state] of Object.entries(this.sessions)) {
      if (state.v !== 2 || !(await v2.canOpen(state, env.message))) continue;
      const r = await v2.decrypt(state, env.message);
      this.sessions[peer] = r.state;
      return { peer, plaintext: r.plaintext, version: 2 };
    }
    if (!v2.isInitial(env.message)) throw new SessionError("UNKNOWN_SESSION", "No session opens that message");
    const me = { device: this.device, deviceList: this.deviceList, prekeys: this.prekeys };
    const who = await v2.initialSender({ me, message: env.message });
    if (this.handshakes.has(who.handshake)) throw new SessionError("REPLAY", "First message already received");
    const r = await v2.respond({ me, message: env.message, accountKey: who.account }); // trust on first use: policy
    this.handshakes.add(who.handshake);
    this.prekeys = r.prekeys;
    const peer = r.state.peer.device;
    this.sessions[peer] = r.state;
    this.peerVersion.set(peer, 2);
    return { peer, plaintext: r.plaintext, version: 2 };
  }

  async #handle(a, how, { deniable = false } = {}) {
    const author = this.known.get(a.actor);
    const who = `@${author.handle}`;
    switch (a.type) {
      case "Create":
        this.timeline.push({ id: a.object.id, from: who, how, content: a.object.content, type: a.object.type, object: a.object, deniable });
        return { kind: "post", from: who, how, content: a.object.content ?? a.object.name, id: a.object.id, type: a.object.type, deniable };
      case "Update":
        return a.object?.id === a.actor ? { kind: "profile-updated", from: who } : { kind: "other", type: a.type, from: who };
      case "Follow": {
        if (a.object !== this.id) return null;
        // policy: accept everyone. Their devices join the audience; they get its key with the Accept.
        const devices = author.devices.body.devices.map((d) => ({ actor: a.actor, device: d.kid }));
        const { audience, send } = addMembers(this.followers, devices);
        this.followers = audience;
        const accept = await this.direct([a.actor], { type: "Accept", to: [a.actor], object: a.id });
        await this.sendDirect(a.actor, { activity: accept, senderKeys: [send.senderKey] });
        return { kind: "followed-by", from: who };
      }
      case "Accept":
        if (this.pending.get(a.object) === a.actor) this.following.add(a.actor);
        return { kind: "accepted", from: who };
      case "Undo": {
        if (!this.followers.members.some((m) => m.actor === a.actor)) return null;
        await this.removeFollower(a.actor);
        return { kind: "unfollowed-by", from: who };
      }
      case "Like": {
        if (!this.likes.has(a.object)) this.likes.set(a.object, new Set());
        this.likes.get(a.object).add(a.actor);
        return { kind: "like", from: who, object: a.object };
      }
      default:
        return { kind: "other", type: a.type, from: who };
    }
  }
}

/** The highest session version a bundle's device says it speaks (from its signed prekey; verified by initiate). */
export const sessionVersionOf = (bundle) => (Number.isSafeInteger(bundle?.signed?.body?.sessions) && bundle.signed.body.sessions >= 1 ? bundle.signed.body.sessions : 1);
