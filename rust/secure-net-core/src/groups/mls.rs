//! Groups (CVP-022), matching `src/groups/mls.js`: the IETF's Messaging Layer Security (RFC 9420),
//! profiled for Secure Net. Like the JavaScript, this doesn't implement MLS: it uses OpenMLS and
//! fixes the profile on top.
//!
//!   Ciphersuite  MLS_256_XWING_AES256GCM_SHA512_MLDSA87 (code point 0x0057, as ts-mls numbers
//!                it). OpenMLS is patched to add it, from primitives it already has: see
//!                `rust/vendor/*/SECURE_NET_PATCH.md`.
//!   Credential   a record signed by the Secure Net device naming the actor, the device and the
//!                MLS signature key. Every key package, every leaf of a group joined and every
//!                leaf a commit adds or changes is checked.
//!   Committer    only leaf 0 (the device that created the group) may commit.
//!   Framing      everything goes as an MLS PrivateMessage.
//!
//! Wire messages (key packages, welcomes, commits, messages) are interchangeable with the
//! JavaScript's. Saved state is not: a state is OpenMLS's own storage, base64url, with the group
//! id and the device's MLS signature key: `{ v: 1, group, sign, storage }`, where `storage` is
//! OpenMLS's key-value store as `[[key, value], ...]` (base64url).
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

use crate::bytes::{b64u, from_b64u, sha256_b64u};
use crate::canonical::canonical_json;
use crate::error::{Error, Result};
use crate::session::keys::Device;
use crate::signed::{check_signature, sign};
use crate::social::actor::device_key_at;

pub const SUITE: &str = "MLS_256_XWING_AES256GCM_SHA512_MLDSA87";
pub const CREDENTIAL: &str = "group.credential";
/// The leaf that may commit.
pub const COMMITTER_LEAF: u32 = 0;
const CS: Ciphersuite = Ciphersuite::MLS_256_XWING_AES256GCM_SHA512_MLDSA87;

fn err(code: &'static str, msg: impl Into<String>) -> Error {
    Error::new(code, msg)
}

fn wrap<T, E: std::fmt::Debug>(code: &'static str, what: &str, r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| err(code, format!("{what}: {e:?}")))
}

/// `^group:[A-Za-z0-9_-]{16,64}$`
pub fn is_group_id(s: &str) -> bool {
    s.strip_prefix("group:").is_some_and(|r| (16..=64).contains(&r.len()) && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'))
}

/// A new group id.
pub fn new_group_id() -> String {
    format!("group:{}", b64u(&crate::bytes::random::<18>()))
}

// ---- The provider: RustCrypto with storage we can save and load ----

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

impl Provider {
    fn load(saved: &Value) -> Result<Self> {
        // Saved as `[[key, value], ...]`, both base64url, sorted by key.
        let bad = || err("BAD_INPUT", "Not a saved group state");
        let mut values = std::collections::HashMap::new();
        for pair in saved.as_array().ok_or_else(bad)? {
            let (Some(k), Some(v)) = (pair[0].as_str(), pair[1].as_str()) else { return Err(bad()) };
            values.insert(from_b64u(k)?, from_b64u(v)?);
        }
        Ok(Self { crypto: RustCrypto::default(), storage: MemoryStorage { values: std::sync::RwLock::new(values) } })
    }
    fn save(&self) -> Value {
        let values = self.storage.values.read().expect("storage lock");
        let mut pairs: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
        pairs.sort();
        Value::Array(pairs.into_iter().map(|(k, v)| json!([b64u(k), b64u(v)])).collect())
    }
}

fn caps() -> Capabilities {
    Capabilities::builder().ciphersuites(vec![CS]).build()
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .capabilities(caps())
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(256)
        .build()
}

fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY).padding_size(256).build()
}

// ---- Credentials ----

fn read_credential(credential: &Credential) -> Option<Value> {
    if credential.credential_type() != CredentialType::Basic {
        return None;
    }
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    let record: Value = serde_json::from_slice(basic.identity()).ok()?;
    let b = &record["body"];
    (record["kind"] == CREDENTIAL && b["actor"].is_string() && b["device"].is_string() && b["key"].is_string()).then_some(record)
}

/// The check every member makes on every leaf (RFC 9420's authentication service), as in the
/// JavaScript. `actors` maps actor ids to the verified actor document bodies you hold.
pub fn validate_credential(credential: &Credential, signature_key: &[u8], actors: &Value) -> bool {
    let Some(record) = read_credential(credential) else { return false };
    let b = &record["body"];
    if b["key"].as_str() != Some(sha256_b64u(signature_key).as_str()) {
        return false;
    }
    let actor = &actors[b["actor"].as_str().unwrap_or("")];
    if !actor.is_object() || actor["id"] != b["actor"] {
        return false;
    }
    let Some(key) = device_key_at(actor, &b["device"], &Value::Null) else { return false };
    if !key.contains('.') || record["sig"]["kid"] != b["device"] {
        return false;
    }
    check_signature(&record, &record["sig"], &key)
}

/// The same check, for a JSON caller: `credential` is the credential's identity bytes (base64url).
pub fn validate_credential_json(identity: &str, signature_key: &str, actors: &Value) -> Result<bool> {
    let cred: Credential = BasicCredential::new(from_b64u(identity)?).into();
    Ok(validate_credential(&cred, &from_b64u(signature_key)?, actors))
}

fn leaf_ok(leaf: &LeafNode, actors: &Value) -> bool {
    validate_credential(leaf.credential(), leaf.signature_key().as_slice(), actors)
}

// ---- Wire messages ----

fn decode(b64: &str) -> Option<MlsMessageBodyIn> {
    let bytes = from_b64u(b64).ok()?;
    let mut slice = bytes.as_slice();
    let m = MlsMessageIn::tls_deserialize(&mut slice).ok()?;
    slice.is_empty().then(|| m.extract())
}

fn encode(m: &MlsMessageOut) -> Result<String> {
    Ok(b64u(&wrap("INTERNAL", "Couldn't encode", m.tls_serialize_detached())?))
}

fn key_package_in(b64: &str) -> Result<KeyPackageIn> {
    match decode(b64) {
        Some(MlsMessageBodyIn::KeyPackage(k)) => Ok(k),
        _ => Err(err("BAD_MESSAGE", "Not an MLS key package")),
    }
}

/// A key package for a device: `{ published, secret }`. Publish `published`; keep `secret` on
/// the device until a welcome uses it.
pub fn create_key_package(device: &Device, actor_id: &str) -> Result<Value> {
    let p = Provider::default();
    let keys = wrap("INTERNAL", "Couldn't make MLS keys", SignatureKeyPair::new(CS.signature_algorithm()))?;
    wrap("INTERNAL", "Couldn't store MLS keys", keys.store(p.storage()))?;
    let record = sign(CREDENTIAL, &json!({ "actor": actor_id, "device": device.kid, "key": sha256_b64u(keys.public()) }), &device.sign)?;
    let credential = CredentialWithKey { credential: BasicCredential::new(canonical_json(&record)?.into_bytes()).into(), signature_key: keys.public().into() };
    let bundle = wrap("INTERNAL", "Couldn't make the key package", KeyPackage::builder().leaf_node_capabilities(caps()).build(CS, &p, &keys, credential))?;
    let published = encode(&MlsMessageOut::from(bundle.key_package().clone()))?;
    Ok(json!({ "published": published, "secret": { "package": published, "sign": b64u(keys.public()), "storage": p.save() } }))
}

/// Who a key package says it is for. Not verified: adding it to a group verifies it.
pub fn key_package_owner(published: &str) -> Result<Value> {
    let kp = key_package_in(published)?;
    let cred = kp.unverified_credential().credential;
    let record = read_credential(&cred).ok_or_else(|| err("BAD_MESSAGE", "Key package has no Secure Net credential"))?;
    Ok(json!({ "actor": record["body"]["actor"], "device": record["body"]["device"] }))
}

// ---- Group state ----

struct Loaded {
    p: Provider,
    group: MlsGroup,
    signer: SignatureKeyPair,
    id: String,
    sign: String,
}

fn load(state: &Value) -> Result<Loaded> {
    let id = state["group"].as_str().filter(|g| state["v"] == 1 && is_group_id(g)).ok_or_else(|| err("BAD_INPUT", "Not a saved group state"))?.to_string();
    let sign = state["sign"].as_str().ok_or_else(|| err("BAD_INPUT", "Not a saved group state"))?.to_string();
    let p = Provider::load(&state["storage"])?;
    let group = MlsGroup::load(p.storage(), &GroupId::from_slice(id.as_bytes())).ok().flatten().ok_or_else(|| err("BAD_INPUT", "Not a saved group state"))?;
    let signer = SignatureKeyPair::read(p.storage(), &from_b64u(&sign)?, CS.signature_algorithm()).ok_or_else(|| err("BAD_INPUT", "Not a saved group state"))?;
    Ok(Loaded { p, group, signer, id, sign })
}

fn save(l: &Loaded) -> Value {
    json!({ "v": 1, "group": l.id, "sign": l.sign, "storage": l.p.save() })
}

fn members(group: &MlsGroup) -> Vec<Value> {
    group
        .members()
        .filter_map(|m| read_credential(&m.credential).map(|r| json!({ "actor": r["body"]["actor"], "device": r["body"]["device"], "leaf": m.index.u32() })))
        .collect()
}

/// The group's id, epoch and members (`[{ actor, device, leaf }]`), and our own leaf.
pub fn describe(state: &Value) -> Result<Value> {
    let l = load(state)?;
    Ok(json!({ "group": l.id, "epoch": l.group.epoch().as_u64(), "members": members(&l.group), "leaf": l.group.own_leaf_index().u32() }))
}

/// Whether this state belongs to the group's committer.
pub fn is_committer(state: &Value) -> Result<bool> {
    Ok(load(state)?.group.own_leaf_index().u32() == COMMITTER_LEAF)
}

/// Create a group with one member, this device (from one of its key package secrets), which
/// becomes its committer.
pub fn create_group(group_id: Option<&str>, key_package: &Value) -> Result<Value> {
    let id = group_id.map(str::to_string).unwrap_or_else(new_group_id);
    if !is_group_id(&id) {
        return Err(err("BAD_INPUT", "Not a group id"));
    }
    let p = Provider::load(&key_package["storage"])?;
    let sign = key_package["sign"].as_str().ok_or_else(|| err("BAD_INPUT", "Not a key package secret"))?.to_string();
    let signer = SignatureKeyPair::read(p.storage(), &from_b64u(&sign)?, CS.signature_algorithm()).ok_or_else(|| err("BAD_INPUT", "Not a key package secret"))?;
    let kp = key_package_in(key_package["package"].as_str().unwrap_or(""))?;
    let cred = kp.unverified_credential();
    let credential = CredentialWithKey { credential: cred.credential, signature_key: cred.signature_key };
    let group = wrap("BAD_INPUT", "Couldn't create the group", MlsGroup::new_with_group_id(&p, &signer, &create_config(), GroupId::from_slice(id.as_bytes()), credential))?;
    Ok(save(&Loaded { p, group, signer, id, sign }))
}

fn commit(state: &Value, adds: Vec<KeyPackage>, removes: Vec<LeafNodeIndex>) -> Result<Value> {
    let mut l = load(state)?;
    if l.group.own_leaf_index().u32() != COMMITTER_LEAF {
        return Err(err("NOT_ALLOWED", "Only the group's committer changes the group"));
    }
    let bundle = {
        let b = l.group.commit_builder().consume_proposal_store(false).force_self_update(true).propose_adds(adds).propose_removals(removes);
        let b = wrap("BAD_INPUT", "Couldn't change the group", b.load_psks(l.p.storage()))?;
        let b = wrap("BAD_INPUT", "Couldn't change the group", b.build(l.p.rand(), l.p.crypto(), &l.signer, |_| true))?;
        wrap("BAD_INPUT", "Couldn't change the group", b.stage_commit(&l.p))?
    };
    let (commit, welcome, _) = bundle.into_messages();
    wrap("INTERNAL", "Couldn't apply the change", l.group.merge_pending_commit(&l.p))?;
    let commit = encode(&commit)?;
    if !matches!(decode(&commit), Some(MlsMessageBodyIn::PrivateMessage(_))) {
        return Err(err("INTERNAL", "Commit wasn't a private message"));
    }
    let welcome = welcome.map(|w| encode(&w)).transpose()?;
    Ok(json!({ "state": save(&l), "commit": commit, "welcome": welcome }))
}

fn checked_packages(key_packages: &[Value], actors: &Value) -> Result<Vec<KeyPackage>> {
    let crypto = RustCrypto::default();
    key_packages
        .iter()
        .map(|k| {
            let kp = wrap("BAD_INPUT", "Couldn't change the group", key_package_in(k.as_str().unwrap_or(""))?.validate(&crypto, ProtocolVersion::Mls10))?;
            if kp.ciphersuite() != CS {
                return Err(err("BAD_INPUT", "Couldn't change the group: wrong ciphersuite"));
            }
            if !leaf_ok(kp.leaf_node(), actors) {
                return Err(err("BAD_INPUT", "Couldn't change the group: a credential didn't verify"));
            }
            Ok(kp)
        })
        .collect()
}

/// Add devices by their key packages: `{ state, commit, welcome }`. Each key package's credential
/// is checked; one that doesn't verify refuses the whole change.
pub fn add_members(state: &Value, key_packages: &[Value], actors: &Value) -> Result<Value> {
    if key_packages.is_empty() {
        return Err(err("BAD_INPUT", "Nobody to add"));
    }
    is_committer(state)?.then_some(()).ok_or_else(|| err("NOT_ALLOWED", "Only the group's committer changes the group"))?;
    commit(state, checked_packages(key_packages, actors)?, vec![])
}

/// Remove every member `pick` chooses (never the committer).
pub fn remove_members(state: &Value, pick: &dyn Fn(&Value) -> bool) -> Result<Value> {
    let out: Vec<LeafNodeIndex> = describe(state)?["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["leaf"] != COMMITTER_LEAF && pick(m))
        .map(|m| LeafNodeIndex::new(m["leaf"].as_u64().unwrap_or(0) as u32))
        .collect();
    if out.is_empty() {
        return Err(err("BAD_INPUT", "Nobody to remove"));
    }
    commit(state, vec![], out)
}

/// Give a member device fresh keys: its old leaf removed and the new key package added in one
/// commit.
pub fn replace_member(state: &Value, key_package: &str, actors: &Value) -> Result<Value> {
    let who = key_package_owner(key_package)?;
    let d = describe(state)?;
    let old = d["members"].as_array().into_iter().flatten().find(|m| m["actor"] == who["actor"] && m["device"] == who["device"]).cloned().ok_or_else(|| err("BAD_INPUT", "That device isn't in the group"))?;
    if old["leaf"] == COMMITTER_LEAF {
        return Err(err("BAD_INPUT", "The committer refreshes itself with refresh()"));
    }
    is_committer(state)?.then_some(()).ok_or_else(|| err("NOT_ALLOWED", "Only the group's committer changes the group"))?;
    let adds = checked_packages(&[json!(key_package)], actors)?;
    commit(state, adds, vec![LeafNodeIndex::new(old["leaf"].as_u64().unwrap_or(0) as u32)])
}

/// A commit that changes nothing but the keys.
pub fn refresh(state: &Value) -> Result<Value> {
    commit(state, vec![], vec![])
}

/// Join from a welcome, with the key package secret it was made for.
pub fn join(welcome: &str, key_package: &Value, actors: &Value) -> Result<Value> {
    let Some(MlsMessageBodyIn::Welcome(w)) = decode(welcome) else { return Err(err("BAD_MESSAGE", "Not an MLS welcome")) };
    let p = Provider::load(&key_package["storage"])?;
    let sign = key_package["sign"].as_str().ok_or_else(|| err("BAD_INPUT", "Not a key package secret"))?.to_string();
    let signer = SignatureKeyPair::read(p.storage(), &from_b64u(&sign)?, CS.signature_algorithm()).ok_or_else(|| err("BAD_INPUT", "Not a key package secret"))?;
    let staged = wrap("UNTRUSTED", "Couldn't join the group", StagedWelcome::new_from_welcome(&p, &join_config(), w, None))?;
    let group = wrap("UNTRUSTED", "Couldn't join the group", staged.into_group(&p))?;
    if group.ciphersuite() != CS {
        return Err(err("UNTRUSTED", "Couldn't join the group: wrong ciphersuite"));
    }
    let id = String::from_utf8(group.group_id().as_slice().to_vec()).ok().filter(|g| is_group_id(g)).ok_or_else(|| err("BAD_MESSAGE", "Not a Secure Net group"))?;
    for m in group.members() {
        if !validate_credential(&m.credential, &m.signature_key, actors) {
            return Err(err("UNTRUSTED", "Couldn't join the group: a member's credential didn't verify"));
        }
    }
    Ok(save(&Loaded { p, group, signer, id, sign }))
}

// ---- Messages ----

/// Seal bytes for the group: `{ state, message }`.
pub fn seal(state: &Value, plaintext: &[u8]) -> Result<Value> {
    let mut l = load(state)?;
    let m = wrap("BAD_INPUT", "Couldn't seal for the group", l.group.create_message(&l.p, &l.signer, plaintext))?;
    Ok(json!({ "state": save(&l), "message": encode(&m)? }))
}

/// Open a group message: `{ state, kind: "message", plaintext }` or `{ state, kind: "commit",
/// removed }`. A commit is accepted only from the committer, and only if every leaf it adds or
/// changes verifies; proposals are refused. The state given is never changed.
pub fn open(state: &Value, message: &str, actors: &Value) -> Result<Value> {
    let Some(MlsMessageBodyIn::PrivateMessage(pm)) = decode(message) else { return Err(err("BAD_MESSAGE", "Not an MLS private message")) };
    let mut l = load(state)?;
    let processed = wrap("DECRYPT_FAILED", "The group message couldn't be opened", l.group.process_message(&l.p, ProtocolMessage::from(pm)))?;
    let committer = matches!(processed.sender(), Sender::Member(i) if i.u32() == COMMITTER_LEAF);
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(a) => Ok(json!({ "state": save(&l), "kind": "message", "plaintext": b64u(&a.into_bytes()) })),
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            if !committer {
                return Err(err("NOT_ALLOWED", "A commit from someone other than the group's committer"));
            }
            let added_ok = sc.add_proposals().all(|a| leaf_ok(a.add_proposal().key_package().leaf_node(), actors));
            if !added_ok || !sc.update_path_leaf_node().is_none_or(|leaf| leaf_ok(leaf, actors)) {
                return Err(err("DECRYPT_FAILED", "The group message couldn't be opened: a credential didn't verify"));
            }
            let removed = sc.self_removed();
            wrap("DECRYPT_FAILED", "The group message couldn't be opened", l.group.merge_staged_commit(&l.p, *sc))?;
            Ok(json!({ "state": save(&l), "kind": "commit", "removed": removed }))
        }
        _ => Err(err("NOT_ALLOWED", "A proposal (members ask the committer directly)")),
    }
}
