//! JSON API operations for the wire, tokens, the commons ledger, governance, portable identity,
//! consent and extensions. Same conventions as `api`: JavaScript argument names, byte strings in
//! base64url, keys as `{ kid, publicKey, secretKey }`, and public keys for checking given as a
//! `keys` object from key id to public key. Times are given (`now`, `at`), never read.
use std::collections::HashSet;

use serde_json::{json, Value};

use crate::bytes::{b64u, from_b64u};
use crate::error::{Error, Result};
use crate::governance::{debate, vote};
use crate::signed::SigningKey;
use crate::wire::{features, federation, sealed};
use crate::{commons, consent, extensions, portable, tokens};

fn s<'a>(req: &'a Value, k: &str) -> &'a str {
    req[k].as_str().unwrap_or("")
}

fn list<'a>(req: &'a Value, k: &str) -> &'a [Value] {
    req[k].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn key(req: &Value, k: &str) -> Result<SigningKey> {
    serde_json::from_value(req[k].clone()).map_err(|e| Error::new("BAD_INPUT", format!("{k}: {e}")))
}

fn keys(req: &Value, k: &str) -> Result<Vec<SigningKey>> {
    serde_json::from_value(if req[k].is_null() { json!([]) } else { req[k].clone() }).map_err(|e| Error::new("BAD_INPUT", format!("{k}: {e}")))
}

fn int(req: &Value, k: &str) -> Result<i64> {
    crate::js::safe_int(&req[k]).ok_or_else(|| Error::new("BAD_INPUT", format!("{k}: a whole number is required")))
}

fn strings(req: &Value, k: &str) -> Vec<String> {
    list(req, k).iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
}

fn fields(req: &Value) -> federation::RequestFields<'_> {
    let f = &req["fields"];
    federation::RequestFields { method: s(f, "method"), to: s(f, "to"), path: s(f, "path"), from: s(f, "from"), date: s(f, "date"), nonce: s(f, "nonce"), digest: s(f, "digest"), user: s(f, "user") }
}

/// Run one of these operations, or None if `op` isn't one of them.
pub fn call(op: &str, req: &Value) -> Option<Result<Value>> {
    let key_map = req["keys"].clone();
    let key_for = move |kid: &str| key_map[kid].as_str().map(str::to_string);
    let run = || -> Result<Value> {
        Ok(match op {
            "ed25519.verify" => json!(crate::ed25519::verify_b64u(s(req, "publicKey"), s(req, "signature"), &from_b64u(s(req, "message"))?)),
            "js.dateParse" => json!(crate::js::date_parse(s(req, "text"))),
            // wire
            "wire.features" => features::features(),
            "wire.describeSite" => features::describe_site(req.get("features")),
            "wire.negotiate" => features::negotiate(&req["ours"], &req["theirs"]),
            "wire.endpointsOf" => federation::endpoints_of(&req["doc"]),
            "wire.normHost" => json!(federation::norm_host(s(req, "host"))),
            "wire.digestOf" => json!(federation::digest_of(s(req, "body").as_bytes())),
            "wire.signatureBase" => json!(federation::signature_base(&fields(req))),
            "wire.signRequest" => json!(federation::sign_request(&fields(req), s(req, "secretKey"))?),
            "wire.verifyRequest" => json!(federation::verify_request(&fields(req), s(req, "signature"), s(req, "publicKey"))),
            "wire.freshEnough" => json!(federation::fresh_enough(s(req, "date"), int(req, "now")?)),
            "wire.isPrivate" => json!(federation::is_private(s(req, "ip"))),
            "relay.context" => json!(sealed::relay_context(s(req, "from"), s(req, "to"), s(req, "path"))),
            "relay.generateKeys" => sealed::generate_keys()?,
            "relay.seal" => {
                let (sealed, reply) = sealed::seal(s(req, "public"), s(req, "text"), s(req, "context"))?;
                json!({ "sealed": sealed, "replyKey": b64u(&reply) })
            }
            "relay.open" => {
                let (text, reply) = sealed::open(s(req, "secret"), s(req, "sealed"), s(req, "context"))?;
                json!({ "text": text, "replyKey": b64u(&reply) })
            }
            "relay.sealReply" => json!(sealed::seal_reply(&from_b64u(s(req, "replyKey"))?, s(req, "text"), s(req, "context"))?),
            "relay.openReply" => json!(sealed::open_reply(&from_b64u(s(req, "replyKey"))?, s(req, "sealed"), s(req, "context"))?),
            "relay.sign" => json!(sealed::sign(s(req, "secret"), s(req, "text"))?),
            "relay.verify" => json!(sealed::verify(s(req, "public"), s(req, "text"), s(req, "signature"))),
            "relay.keysOf" => sealed::relay_keys_of(&req["doc"]).unwrap_or(Value::Null),
            "relay.keysAcceptable" => json!(sealed::relay_keys_acceptable(&req["pinned"], &req["current"])),
            // tokens
            "tokens.issuerKey" => tokens::issuer_key(&from_b64u(s(req, "seed"))?, s(req, "scope"))?,
            "tokens.request" => tokens::request_tokens(crate::js::safe_int(&req["n"]).unwrap_or(1).max(0) as usize)?,
            "tokens.issue" => tokens::issue_tokens(&req["key"], list(req, "request"))?,
            "tokens.finish" => tokens::finish_tokens(list(req, "pending"), &req["response"], s(req, "publicKey"))?,
            "tokens.nullifier" => json!(tokens::nullifier(&req["token"])),
            "tokens.check" => json!(tokens::check_token(&req["key"], &req["token"])),
            "tokens.spend" => {
                let mut spent: HashSet<String> = strings(req, "spent").into_iter().collect();
                let id = tokens::spend_token(&req["key"], &req["token"], &mut spent)?;
                let mut all: Vec<String> = spent.into_iter().collect();
                all.sort();
                json!({ "nullifier": id, "spent": all })
            }
            "tokens.fingerprint" => json!(tokens::key_fingerprint(s(req, "publicKey"))?),
            // commons ledger
            "ledger.empty" => commons::empty_state(),
            "ledger.apply" => commons::apply_block(&req["state"], &req["block"])?,
            "ledger.replay" => commons::replay(list(req, "blocks"))?,
            "ledger.makeBlock" => commons::make_block(&req["state"], req["events"].clone(), &key(req, "key")?, &keys(req, "cosigners")?, s(req, "at"))?,
            "ledger.genesis" => commons::genesis(&req["spec"], &key(req, "key")?, &keys(req, "cosigners")?, s(req, "at"))?,
            "ledger.addCosignature" => commons::add_cosignature(&req["block"], &key(req, "key")?)?,
            "ledger.reconcile" => commons::reconcile(list(req, "local"), list(req, "remote"))?,
            "ledger.announceHost" => commons::announce_host(&req["state"], s(req, "site"), s(req, "role"), crate::js::safe_int(&req["validForS"]).unwrap_or(600), int(req, "at")?, &key(req, "siteKey")?)?,
            "ledger.chooseHost" => commons::choose_host(&req["state"], list(req, "announcements"), int(req, "now")?, &strings(req, "unreachable").into_iter().collect()),
            "ledger.describe" => commons::describe(&req["state"]),
            "ledger.blockId" => json!(commons::block_id(&req["block"])?),
            "ledger.actionHash" => json!(commons::action_hash(&req["event"])?),
            // votes
            "vote.propose" => vote::propose(&req["params"], &key(req, "key")?)?,
            "vote.checkMotion" => vote::check_motion(&req["motion"], &key_for)?.clone(),
            "vote.motionId" => json!(vote::motion_id(&req["motion"])?),
            "vote.cast" => vote::cast_ballot(&req["motion"], &req["choice"], &key(req, "key")?, crate::js::safe_int(&req["seq"]).unwrap_or(1))?,
            "vote.castSecret" => vote::cast_secret_ballot(&req["motion"], &req["choice"], &req["token"])?,
            "vote.ballotId" => json!(vote::ballot_id(&req["ballot"])?),
            "vote.tally" => {
                let mut spent: HashSet<String> = strings(req, "spent").into_iter().collect();
                let issuer = Some(&req["issuerKey"]).filter(|k| !k.is_null());
                vote::tally(&req["motion"], list(req, "received"), vote::TallyKeys { key_for: &key_for, issuer_key: issuer, spent: &mut spent })?
            }
            "vote.signResult" => vote::sign_result(&req["body"], &key(req, "key")?)?,
            "vote.verifyResult" => vote::verify_result(&req["motion"], &req["result"], list(req, "received"), &key_for, s(req, "tallierKey"))?,
            // debates
            "debate.post" => debate::post(s(req, "kind"), &req["body"], &key(req, "key")?, s(req, "at"))?,
            "debate.itemId" => json!(debate::item_id(&req["record"])?),
            "debate.arrange" => {
                let can: Option<Vec<String>> = req["canPost"].as_array().map(|_| strings(req, "canPost"));
                let mods = strings(req, "moderators");
                let debaters = strings(req, "debaters");
                let can_post = can.map(|c| move |kid: &str| c.iter().any(|x| x == kid));
                let can_ref: Option<&dyn Fn(&str) -> bool> = can_post.as_ref().map(|f| f as &dyn Fn(&str) -> bool);
                let is_mod = |kid: &str| mods.iter().any(|x| x == kid);
                debate::arrange(&req["motion"], list(req, "records"), debate::Roles { key_for: &key_for, can_post: can_ref, is_moderator: &is_mod, debaters: &debaters })?
            }
            // portable identity
            "persona.create" => portable::create_persona(&key(req, "account")?, &req["community"], s(req, "name"), s(req, "at"))?,
            "persona.check" => portable::check_persona_link(&req["link"])?,
            "migration.notice" => portable::migration_notice(&req["subject"], s(req, "from"), s(req, "to"), &req["seq"], &req["keepOldUntil"], s(req, "at"), &key(req, "owner")?)?,
            "migration.accept" => portable::accept_migration(&req["notice"], s(req, "ownerPub"), &req["last"])?,
            "migration.currentSite" => portable::current_site(list(req, "notices"), s(req, "ownerPub"), &req["start"]),
            // consent
            "consent.grant" => consent::grant(&req["grant"], &key(req, "key")?, int(req, "now")?)?,
            "consent.revoke" => consent::revoke(&req["capsule"], &key(req, "key")?, s(req, "reason"), int(req, "now")?)?,
            "consent.check" => consent::check(&req["capsule"], s(req, "grantorPub"), &req["actor"], &req["action"], &req["resource"], int(req, "now")?, list(req, "revocations"))?,
            "consent.id" => json!(consent::capsule_id(&req["capsule"])?),
            // extensions and themes
            "ext.manifestProblems" => json!(extensions::manifest_problems(&req["manifest"])),
            "ext.publish" => extensions::publish(&req["body"], &key(req, "key")?)?,
            "ext.checkManifest" => {
                let code = match req["code"].as_str() {
                    Some(c) => Some(from_b64u(c)?),
                    None => None,
                };
                extensions::check_manifest(&req["record"], s(req, "publisherPub"), code.as_deref())
            }
            "ext.explain" => json!(extensions::explain_permissions(&req["manifest"])),
            "theme.problems" => json!(extensions::theme_problems(&req["theme"])),
            "theme.publish" => extensions::publish_theme(&req["body"], &key(req, "key")?)?,
            "theme.check" => extensions::check_theme(&req["record"], s(req, "publisherPub")),
            "theme.id" => json!(extensions::theme_id(&req["record"])?),
            "theme.contrast" => json!(extensions::contrast(s(req, "a"), s(req, "b"))),
            _ => return Err(Error::new("BAD_INPUT", format!("unknown op \"{op}\""))),
        })
    };
    let prefixes = ["ed25519.", "js.", "wire.", "relay.", "tokens.", "ledger.", "vote.", "debate.", "persona.", "migration.", "consent.", "ext.", "theme."];
    prefixes.iter().any(|p| op.starts_with(p)).then(run)
}

/// The social protocol's operations.
pub fn call_social(op: &str, req: &Value) -> Option<Result<Value>> {
    use crate::session::keys::Device;
    use crate::social::{activity as act, actor, delivery as dl, lexicon as lex, repo, vocabulary as voc};
    let device = |k: &str| -> Result<Device> { serde_json::from_value(req[k].clone()).map_err(|e| Error::new("BAD_INPUT", format!("{k}: {e}"))) };
    let now = || int(req, "now");
    let run = || -> Result<Value> {
        Ok(match op {
            "social.objectProblems" => json!(voc::object_problems(req.get("object"), req.get("actor"), req["encrypted"] == true, req["at"].as_str().unwrap_or("object"))),
            "social.activityProblems" => json!(voc::activity_problems(&req["activity"], req["encrypted"] == true)?),
            "social.newId" => json!(voc::new_id(s(req, "actor"))?),
            "social.parseHandle" => match actor::parse_handle(s(req, "handle")) {
                Some((name, host, handle)) => json!({ "name": name, "host": host, "handle": handle }),
                None => Value::Null,
            },
            "social.createActor" => actor::create_actor_document(&key(req, "account")?, &req["params"])?,
            "social.verifyActor" => actor::verify_actor_document(&req["record"], req["id"].as_str(), req.get("handle"), crate::js::safe_int(&req["minSeq"]).unwrap_or(0))?,
            "social.deviceKeyAt" => json!(actor::device_key_at(&req["actor"], &req["device"], &req["at"])),
            "social.discoveryUrl" => json!(actor::discovery_url(s(req, "handle"), req["endpoint"].as_str().unwrap_or("/.well-known/commonveil/actor"))?),
            "social.signActivity" => act::sign_activity(&device("device")?, s(req, "actor"), &req["activity"], req["encrypted"] == true, now()?)?,
            "social.sessionActivity" => act::session_activity(&device("device")?, s(req, "actor"), &req["activity"], now()?)?,
            "social.verifyActivity" => act::verify_activity(&req["record"], &req["actorDoc"], req["encrypted"] == true, now()?)?,
            "social.verifySessionActivity" => act::verify_session_activity(&req["record"], &req["actorDoc"], s(req, "fromDevice"), now()?)?,
            "social.activityDigest" => json!(act::activity_digest(&req["record"])?),
            "social.lexiconProblems" => json!(lex::lexicon_problems(&req["lexicon"])),
            "social.createLexicon" => lex::create_lexicon(&key(req, "account")?, &req["body"])?,
            "social.verifyLexicon" => lex::verify_lexicon(&req["record"], &req["actorDoc"], crate::js::safe_int(&req["minRevision"]).unwrap_or(0))?,
            "social.extensionProblems" => json!(lex::extension_problems(&req["object"], &req["lexicon"])),
            "social.merkleRoot" => json!(repo::merkle_root(&strings(req, "ids"))),
            "social.inclusionProof" => json!(repo::inclusion_proof(&strings(req, "ids"), int(req, "index")?)?),
            "social.verifyInclusion" => json!(repo::verify_inclusion(s(req, "id"), int(req, "index")?, int(req, "count")?, &strings(req, "proof"), s(req, "root"))),
            "social.createRepo" => repo::create_repo(s(req, "actor")),
            "social.appendToRepo" => repo::append_to_repo(&req["repo"], &device("device")?, &req["record"], now()?)?,
            "social.removeFromRepo" => repo::remove_from_repo(&req["repo"], &device("device")?, &req["id"], now()?)?,
            "social.exportRepo" => repo::export_repo(&req["repo"], &req["actorRecord"]),
            "social.verifyRepo" => repo::verify_repo(&req["exported"], req["id"].as_str(), crate::js::safe_int(&req["minSeq"]).unwrap_or(0), now()?)?,
            "social.envelopeProblems" => json!(dl::envelope_problems(&req["envelope"])?),
            "social.publicEnvelope" => dl::public_envelope(&req["record"])?,
            "social.sessionTag" => json!(dl::session_tag(s(&req["state"], "ad"))?),
            "social.sealDirect" => dl::seal_direct(req["sessions"].as_object().ok_or_else(|| Error::new("BAD_INPUT", "sessions"))?, &req["payload"])?,
            "social.openDirectPayload" => dl::open_direct_payload(&from_b64u(s(req, "plaintext"))?, s(req, "fromDevice"), s(req, "fromActor"), crate::js::safe_int(&req["version"]).unwrap_or(1))?,
            "social.newDeliveryToken" => json!(dl::new_delivery_token()),
            "social.deliveryVerifier" => json!(dl::delivery_verifier(s(req, "token"))?),
            "social.sealedBody" => dl::sealed_body(list(req, "items"))?,
            "social.readSealedBody" => json!(dl::read_sealed_body(&req["body"], "BAD_MESSAGE")?),
            "social.createAudience" => dl::create_audience(s(req, "actor"), req["kind"].as_str().unwrap_or("followers"))?,
            "social.addMembers" => dl::add_members(&req["audience"], list(req, "members"))?,
            "social.removeMembers" => {
                let gone = strings(req, "actors");
                dl::remove_members(&req["audience"], &|m: &Value| m["actor"].as_str().is_some_and(|a| gone.iter().any(|g| g == a)))?
            }
            "social.sealToAudience" => dl::seal_to_audience(&req["audience"], &req["record"])?,
            "social.openAudience" => dl::open_audience(&req["view"], &req["envelope"])?,
            "social.viewKey" => json!(dl::view_key(s(req, "audience"), s(req, "senderKey"))),
            "social.deliveryBody" => dl::delivery_body(list(req, "items"))?,
            "social.readDeliveryBody" => json!(dl::read_delivery_body(&req["body"])?),
            _ => return Err(Error::new("BAD_INPUT", format!("unknown op \"{op}\""))),
        })
    };
    op.starts_with("social.").then(run)
}

/// MLS groups (CVP-022).
pub fn call_groups(op: &str, req: &Value) -> Option<Result<Value>> {
    use crate::groups::mls as g;
    use crate::session::keys::Device;
    if !op.starts_with("groups.") {
        return None;
    }
    let s = |k: &str| req[k].as_str().unwrap_or("");
    let actors = || if req["actors"].is_object() { req["actors"].clone() } else { json!({}) };
    let run = || -> Result<Value> {
        Ok(match op {
            "groups.newGroupId" => json!(g::new_group_id()),
            "groups.createKeyPackage" => {
                let device: Device = serde_json::from_value(req["device"].clone()).map_err(|e| Error::new("BAD_INPUT", format!("device: {e}")))?;
                g::create_key_package(&device, s("actor"))?
            }
            "groups.keyPackageOwner" => g::key_package_owner(s("published"))?,
            "groups.createGroup" => g::create_group(req["group"].as_str(), &req["keyPackage"])?,
            "groups.describe" => g::describe(&req["state"])?,
            "groups.isCommitter" => json!(g::is_committer(&req["state"])?),
            "groups.addMembers" => g::add_members(&req["state"], req["keyPackages"].as_array().map(Vec::as_slice).unwrap_or(&[]), &actors())?,
            "groups.removeMembers" => {
                // Who goes: members whose actor is in `actors_out` or whose device is in `devices_out`.
                let pick = |k: &str| req[k].as_array().cloned().unwrap_or_default();
                let (a, d) = (pick("actorsOut"), pick("devicesOut"));
                g::remove_members(&req["state"], &|m| a.contains(&m["actor"]) || d.contains(&m["device"]))?
            }
            "groups.replaceMember" => g::replace_member(&req["state"], s("keyPackage"), &actors())?,
            "groups.refresh" => g::refresh(&req["state"])?,
            "groups.join" => g::join(s("welcome"), &req["keyPackage"], &actors())?,
            "groups.seal" => {
                let bytes = match req.get("bytes") {
                    Some(b) => crate::bytes::from_b64u(b.as_str().unwrap_or(""))?,
                    None => s("plaintext").as_bytes().to_vec(),
                };
                g::seal(&req["state"], &bytes)?
            }
            "groups.open" => g::open(&req["state"], s("message"), &actors())?,
            "groups.validateCredential" => json!(g::validate_credential_json(s("identity"), s("key"), &actors())?),
            _ => return Err(Error::new("BAD_INPUT", format!("Unknown operation {op}"))),
        })
    };
    Some(run())
}
