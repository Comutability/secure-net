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
#[derive(Clone, Copy, Debug)]
pub struct IntentInput<'a> {
    pub source: &'a str,
    pub destination: &'a str,
    pub seq: u64,
    pub challenge: &'a str,
    pub root: &'a str,
    pub chunks: u64,
    pub total_bytes: u64,
    pub issued_ms: i64,
    pub expires_ms: i64,
}

pub fn create_intent(owner: &SigningKey, input: &IntentInput<'_>) -> Result<Value> {
    if !owner.public_key.contains('.') {
        return fail("NOT_PQ", "Hybrid actor key required");
    }
    let body = json!({
        "v": FORMAT_VERSION, "actor": key_id(&owner.public_key)?,
        "from": input.source, "to": input.destination, "seq": input.seq,
        "challenge": input.challenge, "ciphertext_root": input.root,
        "chunks": input.chunks, "bytes": input.total_bytes,
        "issued_ms": input.issued_ms, "expires_ms": input.expires_ms
    });
    validate_body(&body, input.issued_ms)?;
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

/// A bounded, resumable view of missing ciphertext chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingPage {
    pub indices: Vec<u64>,
    pub next_cursor: Option<u64>,
    pub received: usize,
    pub expected: u64,
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
    // Production receivers must use the public signed-root chunk manifest to validate
    // each ciphertext part before acknowledging durable storage.
    expected_manifest: Option<Vec<Chunk>>,
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
            expected_manifest: None,
        })
    }

    /// Validate the complete, ordered ciphertext manifest against the signed intent root.
    pub fn with_manifest(body: &Value, manifest: &[Chunk]) -> Result<Self> {
        let mut tracker = Self::new(body)?;
        let root = ciphertext_root(manifest)?;
        let total: u64 = manifest.iter().map(|part| part.bytes).sum();
        if root != tracker.root
            || manifest.len() as u64 != tracker.expected_count
            || total != tracker.expected_bytes
        {
            return fail(
                "BAD_MANIFEST",
                "Ciphertext manifest differs from the signed commitment",
            );
        }
        tracker.expected_manifest = Some(manifest.to_vec());
        Ok(tracker)
    }

    /// Rebuild state after a crash from the ciphertext blobs already durably stored.
    /// The caller must verify intent signatures, expiry and actor sequence separately.
    pub fn resume(
        body: &Value,
        manifest: &[Chunk],
        stored_blobs: &BTreeMap<u64, Vec<u8>>,
    ) -> Result<Self> {
        let mut tracker = Self::with_manifest(body, manifest)?;
        for (&index, ciphertext) in stored_blobs {
            tracker.accept(index, ciphertext)?;
        }
        Ok(tracker)
    }

    /// Return at most 256 missing indices at or beyond the requested cursor.
    /// The next cursor denotes the next index to scan, not a plaintext import receipt.
    pub fn missing_page(&self, cursor: u64, limit: usize) -> Result<MissingPage> {
        if limit == 0 || limit > 256 || cursor > self.expected_count {
            return fail("BAD_CURSOR", "Invalid missing-chunk page request");
        }
        let mut indices = Vec::new();
        let mut next_cursor = None;
        for index in cursor..self.expected_count {
            if !self.parts.contains_key(&index) {
                indices.push(index);
                if indices.len() == limit {
                    if index + 1 < self.expected_count {
                        next_cursor = Some(index + 1);
                    }
                    break;
                }
            }
        }
        Ok(MissingPage {
            indices,
            next_cursor,
            received: self.parts.len(),
            expected: self.expected_count,
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
        if let Some(manifest) = &self.expected_manifest {
            if manifest.get(index as usize) != Some(&part) {
                return fail(
                    "BAD_CHUNK",
                    "Ciphertext does not match the signed chunk manifest",
                );
            }
        }
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

/// Draft SNIP-0007 recipient-encrypted private reconciliation report envelope.
/// The server checks framing and digest only. It cannot authenticate GCM or
/// prove the submitted bytes are encrypted. Production consumers need a
/// verified recipient device and non-extractable cryptographic keys.
pub const REPORT_MAGIC: &[u8; 6] = b"CVRPT\x01";
pub const MAX_REPORT_BYTES: usize = 64 * 1024;
pub const MIN_REPORT_BYTES: usize = 48;

/// Check the experimental CVRPT v1 framing and return the exact uploaded
/// bytes' SHA-256 digest for the independent owner's hybrid-signed statement.
/// The bytes following the header are opaque to the destination.
pub fn encrypted_report_digest(bytes: &[u8]) -> Result<String> {
    if bytes.len() < MIN_REPORT_BYTES || bytes.len() > MAX_REPORT_BYTES {
        return fail(
            "BAD_REPORT_SIZE",
            "Encrypted reconciliation report is outside the bounded range",
        );
    }
    if !bytes.starts_with(REPORT_MAGIC) {
        return fail(
            "BAD_REPORT_MAGIC",
            "Unsupported encrypted reconciliation report version",
        );
    }
    Ok(sha256_b64u(bytes))
}

/// Domain-separated associated-data inputs for an experimental AES-256-GCM
/// recipient report. The owning client must authenticate these values before
/// encryption, and independently authenticate/decrypt them after downloading.
#[derive(Clone, Copy, Debug)]
pub struct ReportContext<'a> {
    pub actor_id: &'a str,
    pub stage_id: &'a str,
    pub destination: &'a str,
    pub ciphertext_root: &'a str,
    pub recipient_device_id: &'a str,
}

/// Exact UTF-8 associated data used by the reference browser report helper.
/// This function does not access a private key or encrypt messages.
pub fn report_associated_data(context: &ReportContext<'_>) -> Result<Vec<u8>> {
    let valid_id = |s: &str, min: usize, max: usize| {
        (min..=max).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    let destination = context.destination;
    if !valid_id(context.actor_id, 16, 90)
        || !valid_id(context.stage_id, 20, 90)
        || !valid_id(context.recipient_device_id, 12, 90)
        || !hash_ok(context.ciphertext_root)
        || destination.len() > 253
        || !destination.contains('.')
        || destination == "localhost"
        || destination.ends_with(".localhost")
        || !canonical_host(destination)
        || destination.bytes().all(|c| c.is_ascii_digit() || c == b'.')
    {
        return fail(
            "BAD_CONTEXT",
            "Unsafe or non-canonical encrypted report context",
        );
    }
    let fields = json!([
        context.actor_id,
        context.stage_id,
        context.destination,
        context.ciphertext_root,
        context.recipient_device_id
    ]);
    let mut out = b"secure-net/transfer.report/v1\n".to_vec();
    out.extend_from_slice(fields.to_string().as_bytes());
    Ok(out)
}

/// Proposed client statement, not evidence of actual decryption or site migration.
/// A destination must verify that the reported encrypted digest matches bytes
/// already stored, and must independently authenticate the recipient device.
pub const RECONCILE_KIND: &str = "transfer.reconcile";
pub const MAX_RECONCILE_AGE_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug)]
pub struct ReconcileInput<'a> {
    pub stage_id: &'a str,
    pub destination: &'a str,
    pub ciphertext_root: &'a str,
    pub challenge: &'a str,
    pub encrypted_report_sha256: &'a str,
    pub issued_ms: i64,
    pub expires_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct ExpectedReconciliation<'a> {
    pub owner_public: &'a str,
    pub actor_id: &'a str,
    pub stage_id: &'a str,
    pub destination: &'a str,
    pub ciphertext_root: &'a str,
    pub challenge: &'a str,
    pub encrypted_report_sha256: &'a str,
    pub now_ms: i64,
}

fn valid_stage_id(stage: &str) -> bool {
    (20..=90).contains(&stage.len())
        && stage
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn validate_reconciliation_body(body: &Value, now_ms: i64) -> Result<()> {
    let fields = body
        .as_object()
        .ok_or_else(|| Error::new("BAD_RECONCILIATION", "Not an object"))?;
    const KEYS: [&str; 10] = [
        "v",
        "actor",
        "stage_id",
        "to",
        "ciphertext_root",
        "challenge",
        "encrypted_report_sha256",
        "client_checked",
        "issued_ms",
        "expires_ms",
    ];
    if fields.len() != KEYS.len() || KEYS.iter().any(|key| !fields.contains_key(*key)) {
        return fail(
            "BAD_RECONCILIATION",
            "Unexpected fields in client assertion",
        );
    }
    if body["v"] != FORMAT_VERSION
        || !body["actor"]
            .as_str()
            .is_some_and(|a| (16..=90).contains(&a.len()))
        || !body["stage_id"].as_str().is_some_and(valid_stage_id)
        || !body["to"].as_str().is_some_and(canonical_host)
        || !body["ciphertext_root"].as_str().is_some_and(hash_ok)
        || !body["challenge"].as_str().is_some_and(challenge_ok)
        || !body["encrypted_report_sha256"]
            .as_str()
            .is_some_and(hash_ok)
        || body["client_checked"] != true
    {
        return fail(
            "BAD_RECONCILIATION",
            "Missing or malformed reconciliation fields",
        );
    }
    let issued = body["issued_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing issue time"))?;
    let expires = body["expires_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing expiry"))?;
    if issued > now_ms.saturating_add(CLOCK_SKEW_MS)
        || expires < now_ms
        || expires <= issued
        || expires.saturating_sub(issued) > MAX_RECONCILE_AGE_MS
    {
        return fail(
            "EXPIRED",
            "Client attestation expired or exceeds five minutes",
        );
    }
    Ok(())
}

/// Produce an independently owned hybrid-signed *claim* that the owner has
/// checked a staged archive and a separately encrypted private report.
/// No Commonveil login, contact graph or plaintext is part of this record.
pub fn create_reconciliation(owner: &SigningKey, input: &ReconcileInput<'_>) -> Result<Value> {
    if !owner.public_key.contains('.') {
        return fail("NOT_PQ", "A hybrid actor key is required");
    }
    let body = json!({
        "v": FORMAT_VERSION,
        "actor": key_id(&owner.public_key)?,
        "stage_id": input.stage_id,
        "to": input.destination,
        "ciphertext_root": input.ciphertext_root,
        "challenge": input.challenge,
        "encrypted_report_sha256": input.encrypted_report_sha256,
        "client_checked": true,
        "issued_ms": input.issued_ms,
        "expires_ms": input.expires_ms,
    });
    validate_reconciliation_body(&body, input.issued_ms)?;
    sign(RECONCILE_KIND, &body, owner)
}

/// Provider-neutral verification of a signed client assertion against the
/// previously verified stage, destination, challenge, ciphertext commitment
/// and exact digest of a staged report. A successful signature is NOT proof
/// of readable history, successful import, ZK credentials or signed cutover.
pub fn verify_reconciliation(
    record: &Value,
    expected: &ExpectedReconciliation<'_>,
) -> Result<Value> {
    if !expected.owner_public.contains('.') {
        return fail("NOT_PQ", "A hybrid actor key is required");
    }
    let actual_actor = key_id(expected.owner_public)?;
    if expected.actor_id != actual_actor {
        return fail(
            "WRONG_ACTOR",
            "Expected actor does not match the pinned owner key",
        );
    }
    let outer = record
        .as_object()
        .ok_or_else(|| Error::new("BAD_RECONCILIATION", "Not a signed object"))?;
    const OUTER: [&str; 3] = ["kind", "body", "sig"];
    if outer.len() != OUTER.len() || OUTER.iter().any(|key| !outer.contains_key(*key)) {
        return fail(
            "BAD_RECONCILIATION",
            "Unexpected unsigned envelope metadata",
        );
    }
    let signature = record["sig"]
        .as_object()
        .ok_or_else(|| Error::new("BAD_RECONCILIATION", "Missing signature"))?;
    const SIG: [&str; 4] = ["kid", "alg", "value", "pq"];
    if signature.len() != SIG.len() || SIG.iter().any(|key| !signature.contains_key(*key)) {
        return fail("BAD_RECONCILIATION", "Unexpected signature metadata");
    }
    let body = verify(
        record,
        |kid| (kid == actual_actor).then(|| expected.owner_public.to_string()),
        Some(&[RECONCILE_KIND]),
    )?;
    validate_reconciliation_body(body, expected.now_ms)?;
    for (key, value, code) in [
        ("actor", expected.actor_id, "WRONG_ACTOR"),
        ("stage_id", expected.stage_id, "WRONG_STAGE"),
        ("to", expected.destination, "WRONG_SITE"),
        ("ciphertext_root", expected.ciphertext_root, "BAD_ROOT"),
        ("challenge", expected.challenge, "BAD_CHALLENGE"),
        (
            "encrypted_report_sha256",
            expected.encrypted_report_sha256,
            "BAD_REPORT_DIGEST",
        ),
    ] {
        if body[key] != value {
            return fail(code, "Reconciliation is not bound to this stage and report");
        }
    }
    Ok(body.clone())
}

/// Provisional SNIP-0007 receiver/device consent profile. These signed
/// records do NOT transfer secrets, authorise an actor move or prove a KEM
/// decapsulation key is available. A recipient device signs its request,
/// then the independently owned actor signs a grant over that exact request.
pub const RECIPIENT_REQUEST_KIND: &str = "transfer.recipient-request";
pub const RECIPIENT_GRANT_KIND: &str = "transfer.recipient-grant";
const MAX_RECIPIENT_CONSENT_MS: i64 = 5 * 60 * 1000;

/// The transfer details a recipient must independently check, supplied by
/// the verified actor and stage, never inferred from the requesting device.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedRecipient<'a> {
    pub actor_id: &'a str,
    pub stage_id: &'a str,
    pub destination: &'a str,
    pub ciphertext_root: &'a str,
    pub challenge: &'a str,
    pub now_ms: i64,
}

/// Input for a device-generated request. The only KEM value in this
/// record is the recipient's public MLKEM768-P256 key. It carries no
/// encryption seed, ephemeral shared secret or private decryption key.
#[derive(Clone, Copy, Debug)]
pub struct RecipientRequestInput<'a> {
    pub expected: ExpectedRecipient<'a>,
    pub recipient_kem_public: &'a str,
    pub expires_ms: i64,
}

fn recipient_time(body: &Value, now_ms: i64) -> Result<()> {
    let issued = body["issued_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing issue time"))?;
    let expires = body["expires_ms"]
        .as_i64()
        .ok_or_else(|| Error::new("BAD_TIME", "Missing expiry"))?;
    if issued > now_ms.saturating_add(CLOCK_SKEW_MS)
        || expires < now_ms
        || expires <= issued
        || expires.saturating_sub(issued) > MAX_RECIPIENT_CONSENT_MS
    {
        return fail(
            "EXPIRED",
            "Recipient approval expired or exceeds five minutes",
        );
    }
    Ok(())
}

/// Refuse all unsigned outer fields, unusual signature metadata and any
/// classical-only downgrade before accepting a hybrid-signed consent record.
fn strict_recipient_envelope(record: &Value, public: &str, kind: &str) -> Result<Value> {
    if !public.contains('.') {
        return fail("NOT_PQ", "Independent hybrid signing key required");
    }
    let outer = record
        .as_object()
        .ok_or_else(|| Error::new("BAD_CONSENT", "No signed envelope"))?;
    if outer.len() != 3
        || ["kind", "body", "sig"]
            .iter()
            .any(|k| !outer.contains_key(*k))
    {
        return fail("BAD_CONSENT", "Unsigned metadata is forbidden");
    }
    let sig = record["sig"]
        .as_object()
        .ok_or_else(|| Error::new("BAD_CONSENT", "Missing signature"))?;
    if sig.len() != 4
        || ["kid", "alg", "value", "pq"]
            .iter()
            .any(|k| !sig.contains_key(*k))
    {
        return fail("BAD_CONSENT", "Unexpected signing metadata");
    }
    let kid = key_id(public)?;
    let body = verify(
        record,
        |id| (id == kid).then(|| public.to_string()),
        Some(&[kind]),
    )?;
    Ok(body.clone())
}

fn exact_fields(body: &Value, keys: &[&str]) -> Result<()> {
    let fields = body
        .as_object()
        .ok_or_else(|| Error::new("BAD_CONSENT", "Missing consent object"))?;
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return fail("BAD_CONSENT", "Unknown or missing consent fields");
    }
    Ok(())
}

/// A new compatible client can create and sign its own request. The actor
/// hasn't approved it yet; do not disclose an encrypted report to the
/// requesting device solely because this function succeeded.
pub fn create_recipient_request(
    device: &SigningKey,
    input: &RecipientRequestInput<'_>,
) -> Result<Value> {
    if !device.public_key.contains('.') {
        return fail("NOT_PQ", "A hybrid device signing key is required");
    }
    let body = json!({
        "v": FORMAT_VERSION,
        "actor": input.expected.actor_id,
        "stage_id": input.expected.stage_id,
        "to": input.expected.destination,
        "ciphertext_root": input.expected.ciphertext_root,
        "challenge": input.expected.challenge,
        "recipient_id": device.kid,
        "recipient_sign_public": device.public_key,
        "recipient_kem_alg": crate::cv::kem::KEM_NAME,
        "recipient_kem_pub": input.recipient_kem_public,
        "issued_ms": input.expected.now_ms,
        "expires_ms": input.expires_ms,
    });
    validate_recipient_body(&body, &input.expected)?;
    sign(RECIPIENT_REQUEST_KIND, &body, device)
}

fn validate_recipient_body(body: &Value, expected: &ExpectedRecipient<'_>) -> Result<()> {
    const KEYS: [&str; 12] = [
        "v",
        "actor",
        "stage_id",
        "to",
        "ciphertext_root",
        "challenge",
        "recipient_id",
        "recipient_sign_public",
        "recipient_kem_alg",
        "recipient_kem_pub",
        "issued_ms",
        "expires_ms",
    ];
    exact_fields(body, &KEYS)?;
    if body["v"] != FORMAT_VERSION
        || body["actor"] != expected.actor_id
        || !valid_stage_id(expected.stage_id)
        || body["stage_id"] != expected.stage_id
        || !canonical_host(expected.destination)
        || body["to"] != expected.destination
        || !hash_ok(expected.ciphertext_root)
        || body["ciphertext_root"] != expected.ciphertext_root
        || !challenge_ok(expected.challenge)
        || body["challenge"] != expected.challenge
        || body["recipient_kem_alg"] != crate::cv::kem::KEM_NAME
        || !body["recipient_kem_pub"]
            .as_str()
            .is_some_and(crate::cv::kem::is_kem_public)
    {
        return fail(
            "BAD_CONSENT",
            "Device request does not match the pinned transfer",
        );
    }
    let device_public = body["recipient_sign_public"]
        .as_str()
        .ok_or_else(|| Error::new("BAD_CONSENT", "Missing device key"))?;
    if !device_public.contains('.')
        || key_id(device_public).ok().as_deref() != body["recipient_id"].as_str()
        || body["recipient_id"] == expected.actor_id
    {
        return fail(
            "BAD_DEVICE",
            "Recipient key is not an independent hybrid device key",
        );
    }
    recipient_time(body, expected.now_ms)
}

/// Only validates the recipient's signing key and its signed public KEM
/// advertisement, not possession of the KEM private key or approval by
/// the owning actor. A separate owner signature is mandatory.
pub fn verify_recipient_request(record: &Value, expected: &ExpectedRecipient<'_>) -> Result<Value> {
    let public = record["body"]["recipient_sign_public"]
        .as_str()
        .ok_or_else(|| Error::new("BAD_DEVICE", "No recipient signing key"))?;
    let body = strict_recipient_envelope(record, public, RECIPIENT_REQUEST_KIND)?;
    validate_recipient_body(&body, expected)?;
    Ok(body)
}

/// The actor separately approves an exact request signature, its recipient
/// and KEM public key, limited to the same short stage-bound lifetime.
pub fn create_recipient_grant(
    owner: &SigningKey,
    recipient_request: &Value,
    expected: &ExpectedRecipient<'_>,
    expires_ms: i64,
) -> Result<Value> {
    if key_id(&owner.public_key)? != expected.actor_id || !owner.public_key.contains('.') {
        return fail(
            "WRONG_ACTOR",
            "Owner must control the expected hybrid actor",
        );
    }
    let request = verify_recipient_request(recipient_request, expected)?;
    let body = json!({
        "v": FORMAT_VERSION,
        "actor": expected.actor_id,
        "stage_id": expected.stage_id,
        "to": expected.destination,
        "ciphertext_root": expected.ciphertext_root,
        "recipient_id": request["recipient_id"],
        "recipient_request_sha256": crate::signed::record_id(recipient_request)?,
        "owner_approved": true,
        "issued_ms": expected.now_ms,
        "expires_ms": expires_ms,
    });
    validate_recipient_grant_body(&body, &request, recipient_request, expected)?;
    sign(RECIPIENT_GRANT_KIND, &body, owner)
}

fn validate_recipient_grant_body(
    body: &Value,
    request: &Value,
    signed_request: &Value,
    expected: &ExpectedRecipient<'_>,
) -> Result<()> {
    const KEYS: [&str; 10] = [
        "v",
        "actor",
        "stage_id",
        "to",
        "ciphertext_root",
        "recipient_id",
        "recipient_request_sha256",
        "owner_approved",
        "issued_ms",
        "expires_ms",
    ];
    exact_fields(body, &KEYS)?;
    if body["v"] != FORMAT_VERSION
        || body["actor"] != expected.actor_id
        || body["stage_id"] != expected.stage_id
        || body["to"] != expected.destination
        || body["ciphertext_root"] != expected.ciphertext_root
        || body["recipient_id"] != request["recipient_id"]
        || body["recipient_request_sha256"] != crate::signed::record_id(signed_request)?
        || body["owner_approved"] != true
    {
        return fail(
            "BAD_GRANT",
            "Grant does not approve this exact signed recipient request",
        );
    }
    recipient_time(body, expected.now_ms)?;
    if body["issued_ms"].as_i64() < request["issued_ms"].as_i64()
        || body["expires_ms"].as_i64() > request["expires_ms"].as_i64()
    {
        return fail(
            "BAD_GRANT",
            "Grant may not outlive the device's signed request",
        );
    }
    Ok(())
}

/// Both the receiving device and actor must sign the same transfer binding.
/// This does not wrap or hand over a history key. A destination must still
/// persist one-use challenge consumption and obtain separate KEM proof.
pub fn verify_recipient_grant(
    signed_request: &Value,
    signed_grant: &Value,
    owner_public: &str,
    expected: &ExpectedRecipient<'_>,
) -> Result<Value> {
    if key_id(owner_public)? != expected.actor_id || !owner_public.contains('.') {
        return fail("WRONG_ACTOR", "Untrusted owner signing key");
    }
    let request = verify_recipient_request(signed_request, expected)?;
    let grant = strict_recipient_envelope(signed_grant, owner_public, RECIPIENT_GRANT_KIND)?;
    validate_recipient_grant_body(&grant, &request, signed_request, expected)?;
    Ok(grant)
}
