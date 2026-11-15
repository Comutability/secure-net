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
