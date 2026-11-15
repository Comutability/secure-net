//! The `cv.*` operations of the JSON API: Commonveil's cryptography with the JavaScript's
//! argument names and JSON shapes. Byte strings here are standard base64, as Commonveil stores
//! them. Times (`now`) are milliseconds since 1970.
//!
//! Recovery operations take the phrase and never return the secrets it derives.
use serde_json::{json, Value};

use super::encoding::{from_b64, to_b64};
use super::server_keys::{ChainKeys, GrantArgs};
use super::{canonical as cn, device, envelope, identity as id, kem, keyring as kr, lock, owner, primitives as pr, recovery as rc, server_keys as sk};
use crate::error::{Error, Result};

fn s<'a>(req: &'a Value, k: &str) -> &'a str {
    req[k].as_str().unwrap_or("")
}

fn opt<'a>(req: &'a Value, k: &str) -> Option<&'a str> {
    req[k].as_str().filter(|v| !v.is_empty())
}

fn int(req: &Value, k: &str) -> Result<i64> {
    kr::as_int(&req[k]).ok_or_else(|| Error::new("BAD_INPUT", format!("{k}: a whole number is required")))
}

fn list<'a>(req: &'a Value, k: &str) -> &'a [Value] {
    req[k].as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn chain_of(req: &Value) -> Result<id::Chain> {
    id::verify_account_chain(s(req, "userId"), list(req, "statements"))
}

fn key32(b64: &str) -> Result<[u8; 32]> {
    from_b64(b64)?.as_slice().try_into().map_err(|_| Error::new("BAD_FORMAT", "keys are 32 bytes"))
}

/// Run a `cv.*` operation, or None if `op` isn't one.
pub fn call(op: &str, req: &Value) -> Option<Result<Value>> {
    let now = || int(req, "now");
    let run = || -> Result<Value> {
        Ok(match op {
            // primitives
            "cv.generatePair" => {
                let (p, q) = pr::generate_pair()?;
                json!({ "priv": p, "pub": q })
            }
            "cv.signText" => json!(pr::sign_with_pkcs8(s(req, "priv"), s(req, "text").as_bytes())?),
            "cv.verifyText" => json!(pr::verify_with_raw(s(req, "pub"), s(req, "signature"), s(req, "text"))),
            "cv.sealTo" => pr::seal_to(s(req, "pub"), &from_b64(s(req, "plaintext"))?, s(req, "context"))?,
            "cv.openSealed" => json!(to_b64(&pr::open_sealed(&pr::secret_from_pkcs8(s(req, "priv"))?, s(req, "pub"), &req["sealed"], s(req, "context"))?)),
            // post-quantum
            "cv.kemKeygen" => kem::kem_keygen(match opt(req, "seed") { Some(x) => Some(from_b64(x)?), None => None }.as_deref())?,
            "cv.kemPublic" => json!(kem::kem_public_from_secret(s(req, "priv"))?),
            "cv.kemSeal" => kem::kem_seal(s(req, "pub"), &from_b64(s(req, "plaintext"))?, s(req, "context"))?,
            "cv.kemOpen" => json!(to_b64(&kem::kem_open(s(req, "priv"), &req["sealed"], s(req, "context"))?)),
            // canonical text
            "cv.canonical" => {
                let fields: Vec<String> = list(req, "fields").iter().map(|f| f.as_str().map(str::to_string).ok_or_else(|| Error::new("BAD_FORMAT", "Signed fields must be strings"))).collect::<Result<_>>()?;
                json!(cn::canonical(s(req, "context"), &fields)?)
            }
            "cv.statementText" => json!(cn::statement_text(&req["statement"])?),
            "cv.certText" => json!(cn::cert_text(&req["cert"])?),
            // keyring
            "cv.createKeyVersion" => kr::create_key_version(int(req, "version")?, now()?)?,
            "cv.newKeyring" => kr::new_keyring(s(req, "userId"), req["first"].clone())?,
            "cv.withVersion" => kr::with_version(&req["keyring"], req["keyVersion"].clone())?,
            "cv.validateKeyring" => kr::validate_keyring(&req["keyring"], opt(req, "userId"))?.clone(),
            "cv.assertKeyringConsistent" => {
                kr::assert_keyring_consistent(kr::validate_keyring(&req["keyring"], None)?)?;
                json!(true)
            }
            "cv.sealKeyringToDevice" => kr::seal_keyring_to_device(&req["keyring"], s(&req["device"], "device_id"), s(&req["device"], "box_pub"), opt(req, "kemPub"))?,
            "cv.openKeyringFromDevice" => kr::open_keyring_from_device(kr::OpenFromDevice {
                box_priv: s(req, "boxPriv"),
                box_pub: s(req, "boxPub"),
                kem_priv: opt(req, "kemPriv"),
                user_id: s(req, "userId"),
                device_id: s(req, "deviceId"),
                keyring_version: int(req, "keyringVersion")?,
                sealed: &req["sealed"],
            })?,
            "cv.sealKeyringForRecovery" => kr::seal_keyring_for_recovery(&req["keyring"], s(req, "recoveryPub"), opt(req, "recoveryKemPub"))?,
            // envelopes
            "cv.encryptEnvelope" => envelope::encrypt_envelope(&req["scope"], list(req, "recipients"), &req["payload"])?,
            "cv.decryptEnvelope" => envelope::decrypt_envelope(&req["scope"], &req["envelope"], s(req, "userId"), &req["keyring"])?,
            // identity
            "cv.makeAccountStatement" => id::make_account_statement(s(req, "userId"), &req["keyVersion"], s(req, "recoveryPub"), s(req, "recoveryKemPub"), &req["signer"], now()?)?,
            "cv.verifyAccountChain" => chain_of(req)?.to_json(),
            "cv.compareWithPin" => json!(id::compare_with_pin(&chain_of(req)?, &req["pin"])),
            "cv.pinFromChain" => id::pin_from_chain(&chain_of(req)?, req["verified"] == true, now()?)?,
            "cv.anchorChain" => {
                let k = Some(&req["keyring"]).filter(|k| !k.is_null());
                let p = Some(&req["pin"]).filter(|p| !p.is_null());
                json!(id::anchor_chain(&chain_of(req)?, k, p)?)
            }
            "cv.assertKeyringMatchesChain" => {
                id::assert_keyring_matches_chain(&req["keyring"], &chain_of(req)?)?;
                json!(true)
            }
            "cv.makeDeviceCert" => id::make_device_cert(s(req, "userId"), &req["device"], &req["keyVersion"], s(req, "kemPub"), now()?)?,
            "cv.verifyDeviceCert" => json!(id::verify_device_cert(&req["cert"], &chain_of(req)?)),
            "cv.signDeviceKem" => json!(id::sign_device_kem(s(req, "userId"), &req["device"])?),
            "cv.verifyDeviceKem" => json!(id::verify_device_kem(s(req, "userId"), s(req, "deviceId"), s(req, "signPub"), s(req, "kemPub"), s(req, "signature"))),
            "cv.makeDeviceProof" => id::make_device_proof(s(req, "userId"), &req["device"], s(req, "action"), s(req, "payloadJson"), now()?)?,
            "cv.verifyDeviceProof" => json!(id::verify_device_proof(s(req, "userId"), s(req, "signPub"), s(req, "action"), s(req, "payloadJson"), &req["proof"])),
            "cv.signItem" => json!(id::sign_item(s(&req["device"], "sign_priv"), &req["item"])?),
            "cv.verifyItem" => json!(id::verify_item(s(req, "signPub"), s(req, "signature"), &req["item"])),
            "cv.safetyFingerprint" => json!(id::safety_fingerprint(s(req, "userId"), s(req, "digest"))?),
            "cv.safetyNumber" => json!(id::safety_number((s(&req["a"], "user_id"), s(&req["a"], "digest")), (s(&req["b"], "user_id"), s(&req["b"], "digest")))?),
            "cv.linkCode" => json!(id::link_code(id::LinkCode {
                user_id: s(req, "userId"),
                device_id: s(req, "deviceId"),
                sign_pub: s(req, "signPub"),
                box_pub: s(req, "boxPub"),
                kem_pub: s(req, "kemPub"),
                account_digest: s(req, "accountDigest"),
            })?),
            // devices
            "cv.createDeviceKeys" => device::create_device_keys(s(req, "label"), now()?)?,
            "cv.publicDevice" => device::public_device(&req["device"]),
            // recovery (phrase in, never secrets out)
            "cv.generatePhrase" => json!(rc::generate_recovery_phrase()),
            "cv.isValidPhrase" => json!(rc::is_valid_phrase(s(req, "phrase"))),
            "cv.recoveryPublic" => {
                let k = rc::derive_recovery_key(s(req, "phrase"))?;
                json!({ "publicKey": k.public_key, "kemPublicKey": k.kem_public_key })
            }
            "cv.recoveryAnchorMac" => json!(rc::recovery_anchor_mac(&rc::derive_recovery_key(s(req, "phrase"))?.anchor_key[..], &req["statement"])?),
            "cv.verifyRecoveryAnchor" => json!(rc::verify_recovery_anchor(&rc::derive_recovery_key(s(req, "phrase"))?.anchor_key[..], &req["statement"])),
            "cv.openKeyringWithPhrase" => {
                let k = rc::derive_recovery_key(s(req, "phrase"))?;
                rc::open_keyring_with_recovery_key(&k, s(req, "userId"), int(req, "keyringVersion")?, s(req, "recoveryPub"), s(req, "recoveryKemPub"), &req["sealed"])?
            }
            // lock
            "cv.createLock" => {
                let iterations = kr::as_int(&req["iterations"]).unwrap_or(i64::from(lock::LOCK_ITERATIONS));
                let iterations = u32::try_from(iterations).ok().filter(|i| *i >= 1).ok_or_else(|| Error::new("BAD_INPUT", "iterations"))?;
                let (record, key) = lock::create_lock(s(req, "passcode"), int(req, "idleMinutes")?, iterations)?;
                json!({ "record": record, "key": to_b64(&key[..]) })
            }
            "cv.unlock" => json!(to_b64(&lock::unlock(s(req, "passcode"), &req["record"])?[..])),
            "cv.sealKeyringText" => lock::seal_keyring_text(&key32(s(req, "key"))?, s(req, "userId"), s(req, "text"))?,
            "cv.openKeyringText" => json!(lock::open_keyring_text(&key32(s(req, "key"))?, s(req, "userId"), &req["stored"])?.as_str()),
            // owner key
            "cv.privateKeyFromPhrase" => json!(owner::private_key_from_phrase(s(req, "phrase"))?.as_str()),
            "cv.phraseFromPrivateKey" => json!(owner::phrase_from_private_key(s(req, "key"))?.as_str()),
            "cv.ownerPublic" => json!(owner::owner_public(&owner::owner_key(s(req, "input"))?)),
            "cv.signOwner" => json!(owner::sign_owner(&owner::owner_key(s(req, "input"))?, s(req, "host"), s(req, "purpose"), s(req, "challenge"))),
            "cv.verifyOwner" => json!(owner::verify_owner(s(req, "publicKey"), s(req, "signature"), s(req, "host"), s(req, "purpose"), s(req, "challenge"))),
            // servers
            "cv.stepAt" => json!(sk::step_at(s(req, "chainId"), s(req, "startedAt"), int(req, "atMs")?)?),
            "cv.ratchetTo" => json!(to_b64(&sk::ratchet_to(&from_b64(s(req, "key"))?, s(req, "chainId"), int(req, "generation")?, int(req, "fromStep")?, int(req, "toStep")?)?[..])),
            "cv.generationCommit" => json!(sk::generation_commit(s(req, "chainId"), int(req, "generation")?, &from_b64(s(req, "key"))?)),
            "cv.makeGeneration" => {
                let started = match opt(req, "startedAt") {
                    Some(t) => t.to_string(),
                    None => super::encoding::iso_from_ms(now()?)?,
                };
                let (st, key) = sk::make_generation(s(req, "serverId"), s(req, "chainId"), int(req, "generation")?, s(req, "userId"), &req["device"], &started)?;
                json!({ "generation": st, "key": to_b64(&key[..]) })
            }
            "cv.verifyGeneration" => json!(sk::verify_generation(&req["generation"], s(req, "signPub"))),
            "cv.makeGrant" => sk::make_grant(GrantArgs {
                server_id: s(req, "serverId"),
                chain_id: s(req, "chainId"),
                generation: int(req, "generation")?,
                step: int(req, "step")?,
                key: &from_b64(s(req, "key"))?,
                recipient: &req["recipient"],
                user_id: s(req, "userId"),
                device: &req["device"],
                now: now()?,
            })?,
            "cv.verifyGrant" => json!(sk::verify_grant_signature(&req["grant"], s(req, "signPub"))),
            "cv.openGrant" => json!(to_b64(&sk::open_grant(&req["grant"], s(req, "userId"), &req["keyring"])?)),
            "cv.encryptServerItem" => sk::encrypt_server_item(&req["scope"], &from_b64(s(req, "chainKey"))?, &req["payload"])?,
            "cv.decryptServerItem" => sk::decrypt_server_item(&req["base"], &req["envelope"], &mut ChainKeys::from_json(&req["keys"])?)?,
            "cv.signServerItem" => json!(sk::sign_server_item(s(&req["device"], "sign_priv"), &req["item"])?),
            "cv.verifyServerItem" => json!(sk::verify_server_item(s(req, "signPub"), s(req, "signature"), &req["item"])),
            "cv.sealInvitePreview" => json!(sk::seal_invite_preview(s(req, "code"), s(req, "secret"), &req["preview"])?),
            "cv.openInvitePreview" => sk::open_invite_preview(s(req, "code"), s(req, "secret"), s(req, "sealed")).unwrap_or(Value::Null),
            _ => return Err(Error::new("BAD_INPUT", format!("unknown op \"{op}\""))),
        })
    };
    op.starts_with("cv.").then(run)
}
