//! Experimental, application-independent account-transfer primitives (SNIP-0007).
//! Pure verification of hybrid-signed migration authorisations and opaque encrypted chunks.
//! These are NOT a live transfer service, reviewed protocol extension or zero-knowledge proof.
//! Any client can create its own actor; the relay never generates identity keys.
use crate::bytes::{from_b64u, sha256_b64u};
use crate::canonical::canonical_bytes;
use crate::error::{Error, Result};
use crate::signed::{key_id, sign, verify, SigningKey};
use crate::wire::federation::norm_host;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const INTENT_KIND: &str = "transfer.intent";
pub const FORMAT_VERSION: u64 = 1;
pub const MAX_CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CHUNKS: u64 = 16_384;
pub const MAX_TOTAL_BYTES: u64 = MAX_CHUNK_BYTES as u64 * MAX_CHUNKS;
pub const MAX_AUTH_AGE_MS: i64 = 15 * 60 * 1000;
const CLOCK_SKEW_MS: i64 = 60_000;

fn fail<T>(code: &'static str, msg: &str) -> Result<T> {
    Err(Error::new(code, msg))
}
fn hash_ok(s: &str) -> bool {
    s.len() == 43 && from_b64u(s).is_ok_and(|b| b.len() == 32)
}
fn canonical_host(s: &str) -> bool {
    norm_host(s).as_deref() == Some(s)
}
fn challenge_ok(s: &str) -> bool {
    (32..=128).contains(&s.len()) && from_b64u(s).is_ok_and(|b| (24..=96).contains(&b.len()))
}

fn validate_body(b: &Value, now: i64) -> Result<()> {
    if b["v"] != FORMAT_VERSION {
        return fail("BAD_VERSION", "Unsupported transfer intent");
    }
    let from = b["from"]
        .as_str()
        .ok_or_else(|| Error::new("BAD_HOST", "Missing source"))?;
    let to = b["to"]
        .as_str()
        .ok_or_else(|| Error::new("BAD_HOST", "Missing destination"))?;
    if !canonical_host(from) || !canonical_host(to) || from == to {
        return fail("BAD_HOST", "Invalid or repeated site");
    }
    if b["seq"].as_u64().is_none_or(|n| n == 0) {
        return fail("BAD_SEQ", "Sequence must be positive");
    }
    if !b["challenge"].as_str().is_some_and(challenge_ok) {
        return fail("BAD_CHALLENGE", "Invalid destination challenge");
    }
    if !b["ciphertext_root"].as_str().is_some_and(hash_ok) {
        return fail("BAD_ROOT", "Invalid ciphertext commitment");
    }
    let chunks = b["chunks"]
        .as_u64()
        .ok_or_else(|| Error::new("BAD_CHUNKS", "Bad chunk count"))?;
    let bytes = b["bytes"]
        .as_u64()
        .ok_or_else(|| Error::new("BAD_BYTES", "Bad transfer length"))?;
    if chunks == 0
        || chunks > MAX_CHUNKS
        || bytes == 0
        || bytes > MAX_TOTAL_BYTES
        || bytes > chunks * MAX_CHUNK_BYTES as u64
        || bytes < chunks
    {
        return fail("SIZE_LIMIT", "Transfer size exceeds bounded policy");
    }
    let issued = b["issued_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing issue time"))?;
    let expires = b["expires_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing expiry"))?;
    if issued > now.saturating_add(CLOCK_SKEW_MS)
        || expires < now
        || expires <= issued
        || expires - issued > MAX_AUTH_AGE_MS
    {
        return fail("EXPIRED", "Challenge lifetime invalid");
    }
    Ok(())
}

/// Clients sign the intent using their own independent hybrid actor key. No Commonveil
/// account is needed. No plaintext messages, recipient names or contact graphs appear here.
pub fn create_intent(
    owner: &SigningKey,
    source: &str,
    destination: &str,
    seq: u64,
    challenge: &str,
    root: &str,
    chunks: u64,
    total_bytes: u64,
    issued_ms: i64,
    expires_ms: i64,
) -> Result<Value> {
    if !owner.public_key.contains('.') {
        return fail("NOT_PQ", "Hybrid actor key required");
    }
    let body = json!({
        "v": FORMAT_VERSION, "actor": key_id(&owner.public_key)?,
        "from": source, "to": destination, "seq": seq,
        "challenge": challenge, "ciphertext_root": root, "chunks": chunks, "bytes": total_bytes,
        "issued_ms": issued_ms, "expires_ms": expires_ms
    });
    validate_body(&body, issued_ms)?;
    sign(INTENT_KIND, &body, owner)
}

/// The caller MUST separately verify and pin actor documents, persist the highest sequence,
/// issue destination-bound challenges and consume each challenge exactly once. A signature
/// proves possession, not a zero-knowledge credential.
pub fn verify_intent(
    record: &Value,
    pinned_actor_public: &str,
    expected_actor: &str,
    expected_destination: &str,
    expected_challenge: &str,
    last_seq: u64,
    now_ms: i64,
) -> Result<Value> {
    if !pinned_actor_public.contains('.') {
        return fail("NOT_PQ", "No classical downgrade");
    }
    let actor = key_id(pinned_actor_public)?;
    if actor != expected_actor {
        return fail("WRONG_ACTOR", "Actor differs from pinned identity");
    }
    let body = verify(
        record,
        |kid| (kid == actor).then(|| pinned_actor_public.to_string()),
        Some(&[INTENT_KIND]),
    )?;
    validate_body(body, now_ms)?;
    if body["actor"] != actor {
        return fail("WRONG_ACTOR", "Transfer names another actor");
    }
    if body["to"] != expected_destination {
        return fail("WRONG_SITE", "Wrong destination");
    }
    if body["challenge"] != expected_challenge {
        return fail("BAD_CHALLENGE", "Wrong challenge");
    }
    if body["seq"].as_u64().is_none_or(|seq| seq <= last_seq) {
        return fail("REPLAYED", "Stale transfer sequence");
    }
    Ok(body.clone())
}

/// A transfer requires every hop to advertise the required protocol capabilities, without
/// depending on any application name or identity provider. No downgrade is permitted.
pub fn require_features(advertised: &Value) -> Result<()> {
    for (feature, minimum) in [
        ("cvp.actors", 1),
        ("cvp.sessions", 2),
        ("cvp.delivery", 2),
        ("cvp.sealed-relay", 1),
        ("cvp.pq-signatures", 1),
        ("cvp.transfer", 1),
    ] {
        if advertised[feature].as_u64().is_none_or(|v| v < minimum) {
            return fail(
                "UNSUPPORTED",
                "Destination does not support the required secure transfer features",
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub index: u64,
    pub digest: String,
    pub bytes: u64,
}

/// Commitment to ordered ciphertext chunks and their lengths. It is not encryption:
/// devices must use an independently reviewed AEAD with unique nonces and recipient-bound keys.
pub fn ciphertext_root(parts: &[Chunk]) -> Result<String> {
    if parts.is_empty() || parts.len() as u64 > MAX_CHUNKS {
        return fail("BAD_CHUNKS", "Invalid chunk list");
    }
    let mut total = 0_u64;
    let mut rows = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        if p.index != i as u64
            || !hash_ok(&p.digest)
            || p.bytes == 0
            || p.bytes > MAX_CHUNK_BYTES as u64
        {
            return fail("BAD_CHUNK", "Unordered, invalid, or oversized chunk");
        }
        total = total
            .checked_add(p.bytes)
            .ok_or_else(|| Error::new("SIZE_LIMIT", "Overflow"))?;
        if total > MAX_TOTAL_BYTES {
            return fail("SIZE_LIMIT", "Oversized transfer");
        }
        rows.push(json!({"i": p.index, "sha256": p.digest, "bytes": p.bytes}));
    }
    Ok(sha256_b64u(&canonical_bytes(
        &json!({"v": FORMAT_VERSION, "chunks": rows}),
    )?))
}

/// Metadata-only state. A host MUST durably write ciphertext and then transact its digest
/// metadata separately, before it acknowledges any chunk. No decryption keys are stored.
#[derive(Clone, Debug)]
pub struct TransferTracker {
    root: String,
    expected_count: u64,
    expected_bytes: u64,
    parts: BTreeMap<u64, Chunk>,
    bytes: u64,
    verified: bool,
}
impl TransferTracker {
    pub fn new(body: &Value) -> Result<Self> {
        validate_body(body, body["issued_ms"].as_i64().unwrap_or(0))?;
        Ok(Self {
            root: body["ciphertext_root"].as_str().unwrap_or("").into(),
            expected_count: body["chunks"].as_u64().unwrap_or(0),
            expected_bytes: body["bytes"].as_u64().unwrap_or(0),
            parts: BTreeMap::new(),
            bytes: 0,
            verified: false,
        })
    }
    /// True for a first receipt, false for a byte-identical retry.
    pub fn accept(&mut self, index: u64, ciphertext: &[u8]) -> Result<bool> {
        if self.verified {
            return fail("SEALED", "Transfer was already verified");
        }
        if index >= self.expected_count
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_CHUNK_BYTES
        {
            return fail("BAD_CHUNK", "Invalid ciphertext length or index");
        }
        let part = Chunk {
            index,
            digest: sha256_b64u(ciphertext),
            bytes: ciphertext.len() as u64,
        };
        if let Some(old) = self.parts.get(&index) {
            if old == &part {
                return Ok(false);
            }
            return fail("CONFLICT", "Conflicting retransmission");
        }
        let total = self
            .bytes
            .checked_add(part.bytes)
            .ok_or_else(|| Error::new("SIZE_LIMIT", "Overflow"))?;
        if total > self.expected_bytes {
            return fail("SIZE_LIMIT", "More data than signed");
        }
        self.bytes = total;
        self.parts.insert(index, part);
        Ok(true)
    }
    pub fn received_count(&self) -> usize {
        self.parts.len()
    }
    pub fn is_verified(&self) -> bool {
        self.verified
    }
    /// Ciphertext receipt alone does NOT mean user-readable data has been imported.
    pub fn verify_ciphertext(&mut self) -> Result<()> {
        if self.parts.len() as u64 != self.expected_count || self.bytes != self.expected_bytes {
            return fail("INCOMPLETE", "Not all chunks received");
        }
        let ordered: Vec<_> = self.parts.values().cloned().collect();
        if ciphertext_root(&ordered)? != self.root {
            return fail("BAD_ROOT", "Ciphertext integrity failure");
        }
        self.verified = true;
        Ok(())
    }
}
