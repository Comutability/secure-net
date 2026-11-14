// Groups for the reference client (CVP-022 with CVP-019 group envelopes). Kept apart from
// social/client.js so that only apps that want groups need an MLS library installed.
//
//   const alice = withGroups(new SocialClient({ ... }).register());
//   await alice.enableGroups();
//   const group = await alice.createGroup();
//   await alice.invite(group, bob.id);
//   await alice.postToGroup(group, "hello");
import { canonicalJson } from "../core/canonical.js";
import { SessionError } from "../session/primitives.js";
import { verifyActivity, ACTIVITY } from "../social/activity.js";
import * as G from "./mls.js";

const text = (b) => new TextDecoder().decode(b);

export function withGroups(client) {
  const actors = (id) => client.known.get(id);
  client.groups = new Map(); // group id -> MLS state
  client.keyPackages = []; // unused key package secrets

  /** Make key packages and publish them, so others can add this device to groups. */
  client.enableGroups = async (count = 5) => {
    const made = [];
    for (let i = 0; i < count; i += 1) made.push(await G.createKeyPackage(client.device, client.id));
    client.keyPackages.push(...made.map((k) => k.secret));
    client.site.publishKeyPackages(client.id, client.device.kid, made.map((k) => k.published));
    return client;
  };

  const others = (state) => [...new Set(G.describe(state).members.map((m) => m.actor))].filter((a) => a !== client.id);
  const envelope = (group, message) => ({ v: 2, mode: "group", group, message });
  const fanOut = async (group, message, to) => {
    for (const a of to) await client.deliver(a, [envelope(group, message)]);
  };

  /** Create a group. This device becomes its committer. */
  client.createGroup = async () => {
    const own = await G.createKeyPackage(client.device, client.id);
    const state = await G.createGroup({ keyPackage: own.secret, actors });
    const id = G.describe(state).group;
    client.groups.set(id, state);
    return id;
  };

  const change = async (group, make, { welcomeTo = [] } = {}) => {
    let before = client.groups.get(group);
    if (!before) throw new SessionError("BAD_INPUT", "Not a group of ours");
    const existing = others(before);
    if (welcomeTo.length && existing.length) {
      // Members check every leaf against its actor's document, so they need the newcomers'
      // documents before the commit that adds them. Actor documents certify themselves.
      const intro = await G.seal(before, canonicalJson({ v: 1, actors: welcomeTo.map((a) => client.records.get(a)) }));
      before = intro.state;
      await fanOut(group, intro.message, existing);
    }
    const r = await make(before);
    client.groups.set(group, r.state);
    await fanOut(group, r.commit, existing);
    // Newcomers likewise get everyone's documents with their welcome.
    const everyone = [client.id, ...existing].map((a) => client.records.get(a));
    for (const a of welcomeTo) await client.sendDirect(a, { groups: [{ group, welcome: r.welcome, actors: everyone }] });
  };

  /** Add every device of an actor (look them up first). Only the committer can. */
  client.invite = async (group, actorId) => {
    const actor = client.known.get(actorId);
    if (!actor) throw new SessionError("UNKNOWN_ACTOR", "Look this actor up first");
    const site = client.network.site(client.hostOf(actorId));
    const packages = actor.devices.body.devices.map((d) => site.keyPackage(actorId, d.kid));
    await change(group, (s) => G.addMembers(s, packages), { welcomeTo: [actorId] });
  };

  /** Remove every device of an actor. They can't read anything sent afterwards. */
  client.removeFromGroup = (group, actorId) => change(group, (s) => G.removeMembers(s, (m) => m.actor === actorId));

  /** New group secrets from the committer, for example on a schedule. */
  client.refreshGroup = (group) => change(group, (s) => G.refresh(s));

  /** Post to a group. The activity is signed on this device, then sealed once for the whole group. */
  client.postToGroup = async (group, content) => {
    const state = client.groups.get(group);
    if (!state) throw new SessionError("BAD_INPUT", "Not a group of ours");
    const record = client.sign({ type: "Create", to: [group], object: { type: "Note", content, context: group } }, { encrypted: true });
    const r = await G.seal(state, canonicalJson({ v: 1, activity: record }));
    client.groups.set(group, r.state);
    await fanOut(group, r.message, others(state));
    return record;
  };

  /** A welcome arrived over a direct session: join with whichever unused key package it was made for. */
  client.onWelcome = async ({ group, welcome, actors: documents = [] }, fromActor) => {
    for (const record of documents) client.remember(record);
    for (let i = 0; i < client.keyPackages.length; i += 1) {
      let state;
      try {
        state = await G.join({ welcome, keyPackage: client.keyPackages[i], actors });
      } catch {
        continue;
      }
      const d = G.describe(state);
      // The welcome must be for the group it says, and must come from that group's committer.
      const committer = d.members.find((m) => m.leaf === G.COMMITTER_LEAF);
      if (d.group !== group || committer?.actor !== fromActor) throw new SessionError("UNTRUSTED", "A welcome that isn't from its group's committer");
      client.keyPackages.splice(i, 1);
      client.groups.set(group, state);
      return;
    }
    throw new SessionError("UNKNOWN_PREKEY", "No key package of ours opens that welcome");
  };

  client.onGroupEnvelope = async (env) => {
    const state = client.groups.get(env.group);
    if (!state) return { kind: "unreadable", reason: "not a member of this group" };
    const r = await G.open(state, env.message);
    client.groups.set(env.group, r.state);
    if (r.kind === "commit") {
      const d = G.describe(r.state);
      if (!d.members.some((m) => m.actor === client.id && m.device === client.device.kid)) client.groups.delete(env.group);
      return { kind: "group-changed", group: env.group, members: d.members.length };
    }
    let p;
    try {
      p = JSON.parse(text(r.plaintext));
    } catch {
      throw new SessionError("BAD_MESSAGE", "Payload isn't JSON");
    }
    if (p?.v === 1 && Array.isArray(p.actors) && p.activity === undefined) {
      for (const record of p.actors) client.remember(record);
      return { kind: "keys", group: env.group };
    }
    const a = p?.activity;
    if (p?.v !== 1 || a?.kind !== ACTIVITY) throw new SessionError("BAD_MESSAGE", "Not a version 1 payload");
    // MLS says a member sealed it. The signature inside says which device wrote it; that device
    // must be a member, and it must have written it for this group.
    const author = G.describe(state).members.find((m) => m.actor === a.body?.actor && m.device === a.body?.device);
    if (!author) throw new SessionError("UNTRUSTED", "The activity wasn't made by a member of the group");
    const body = verifyActivity(a, client.known.get(author.actor), { encrypted: true });
    if (!(body.to || []).includes(env.group)) throw new SessionError("UNTRUSTED", "The activity wasn't written for this group");
    return client.handleActivity(body, "group");
  };

  return client;
}
