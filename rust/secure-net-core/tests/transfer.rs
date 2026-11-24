use secure_net_core::bytes::{b64u, sha256_b64u};
use secure_net_core::signed::{key_id, SigningKey};
use secure_net_core::transfer::{
    ciphertext_root, create_intent, require_features, verify_intent, Chunk, IntentInput,
    TransferTracker,
};
use serde_json::json;

const NOW: i64 = 1_800_000_000_000;
const SOURCE: &str = "old.example";
const DEST: &str = "new.example";

fn challenge() -> String {
    b64u(&[7_u8; 32])
}
fn parts() -> (Vec<Vec<u8>>, Vec<Chunk>) {
    let chunks = vec![b"sealed one".to_vec(), b"sealed two".to_vec()];
    let meta = chunks
        .iter()
        .enumerate()
        .map(|(i, b)| Chunk {
            index: i as u64,
            digest: sha256_b64u(b),
            bytes: b.len() as u64,
        })
        .collect();
    (chunks, meta)
}
fn intent(owner: &SigningKey, seq: u64) -> serde_json::Value {
    let (_, parts) = parts();
    create_intent(
        owner,
        &IntentInput {
            source: SOURCE,
            destination: DEST,
            seq,
            challenge: &challenge(),
            root: &ciphertext_root(&parts).unwrap(),
            chunks: 2,
            total_bytes: parts.iter().map(|p| p.bytes).sum(),
            issued_ms: NOW,
            expires_ms: NOW + 600_000,
        },
    )
    .unwrap()
}

#[test]
fn independent_hybrid_actor_can_authorise_a_transfer_without_commonveil() {
    let owner = SigningKey::generate(true);
    let actor = key_id(&owner.public_key).unwrap();
    let record = intent(&owner, 9);
    let verified = verify_intent(
        &record,
        &owner.public_key,
        &actor,
        DEST,
        &challenge(),
        8,
        NOW + 1000,
    )
    .unwrap();
    assert_eq!(verified["actor"], actor);
    assert_eq!(verified["seq"], 9);
}

#[test]
fn forged_replayed_and_wrong_destination_intents_fail_closed() {
    let owner = SigningKey::generate(true);
    let attacker = SigningKey::generate(true);
    let actor = owner.kid.clone();
    let good = intent(&owner, 5);
    assert_eq!(
        verify_intent(&good, &owner.public_key, &actor, DEST, &challenge(), 5, NOW)
            .unwrap_err()
            .code,
        "REPLAYED"
    );
    assert_eq!(
        verify_intent(
            &good,
            &owner.public_key,
            &actor,
            SOURCE,
            &challenge(),
            0,
            NOW
        )
        .unwrap_err()
        .code,
        "WRONG_SITE"
    );
    assert_eq!(
        verify_intent(
            &good,
            &owner.public_key,
            &actor,
            DEST,
            &b64u(&[9_u8; 32]),
            0,
            NOW
        )
        .unwrap_err()
        .code,
        "BAD_CHALLENGE"
    );
    assert_eq!(
        verify_intent(
            &good,
            &owner.public_key,
            &attacker.kid,
            DEST,
            &challenge(),
            0,
            NOW
        )
        .unwrap_err()
        .code,
        "WRONG_ACTOR"
    );
    assert_eq!(
        verify_intent(
            &good,
            &owner.public_key,
            &actor,
            DEST,
            &challenge(),
            0,
            NOW + 601_000
        )
        .unwrap_err()
        .code,
        "EXPIRED"
    );

    let forged = intent(&attacker, 6);
    assert_eq!(
        verify_intent(
            &forged,
            &owner.public_key,
            &actor,
            DEST,
            &challenge(),
            0,
            NOW
        )
        .unwrap_err()
        .code,
        "UNKNOWN_SIGNER"
    );
    let mut tampered = good.clone();
    tampered["body"]["ciphertext_root"] = json!(sha256_b64u(b"wrong"));
    assert_eq!(
        verify_intent(
            &tampered,
            &owner.public_key,
            &actor,
            DEST,
            &challenge(),
            0,
            NOW
        )
        .unwrap_err()
        .code,
        "BAD_SIGNATURE"
    );
}

#[test]
fn downgrade_and_unsafe_capabilities_are_rejected() {
    let classical = SigningKey::generate(false);
    let (_, parts) = parts();
    assert_eq!(
        create_intent(
            &classical,
            &IntentInput {
                source: SOURCE,
                destination: DEST,
                seq: 1,
                challenge: &challenge(),
                root: &ciphertext_root(&parts).unwrap(),
                chunks: 2,
                total_bytes: 20,
                issued_ms: NOW,
                expires_ms: NOW + 600_000
            }
        )
        .unwrap_err()
        .code,
        "NOT_PQ"
    );
    let independent_site = json!({
        "cvp.actors": 1, "cvp.sessions": 2, "cvp.delivery": 2,
        "cvp.sealed-relay": 1, "cvp.pq-signatures": 1, "cvp.transfer": 1
    });
    assert!(require_features(&independent_site).is_ok());
    for feature in [
        "cvp.actors",
        "cvp.sessions",
        "cvp.delivery",
        "cvp.sealed-relay",
        "cvp.pq-signatures",
        "cvp.transfer",
    ] {
        let mut downgrade = independent_site.clone();
        downgrade[feature] = json!(0);
        assert_eq!(
            require_features(&downgrade).unwrap_err().code,
            "UNSUPPORTED"
        );
    }
}

#[test]
fn missing_reordered_or_corrupt_chunks_do_not_finish() {
    let owner = SigningKey::generate(true);
    let record = intent(&owner, 1);
    let mut store = TransferTracker::new(&record["body"]).unwrap();
    let (chunks, _) = parts();
    assert!(store.accept(1, &chunks[1]).unwrap());
    assert_eq!(store.verify_ciphertext().unwrap_err().code, "INCOMPLETE");
    assert!(store.accept(0, &chunks[0]).unwrap());
    assert!(
        !store.accept(0, &chunks[0]).unwrap(),
        "identical retry is idempotent"
    );
    assert_eq!(store.accept(0, b"evil").unwrap_err().code, "CONFLICT");
    store.verify_ciphertext().unwrap();
    assert!(store.is_verified());
    assert_eq!(store.accept(0, &chunks[0]).unwrap_err().code, "SEALED");

    let mut corrupt = TransferTracker::new(&record["body"]).unwrap();
    corrupt.accept(0, &chunks[0]).unwrap();
    corrupt.accept(1, b"evil bytes").unwrap();
    assert_eq!(corrupt.verify_ciphertext().unwrap_err().code, "BAD_ROOT");
}

#[test]
fn moving_twice_keeps_the_actor_key_and_advances_sequences() {
    let owner = SigningKey::generate(true);
    let actor = owner.kid.clone();
    let first = intent(&owner, 1);
    verify_intent(
        &first,
        &owner.public_key,
        &actor,
        DEST,
        &challenge(),
        0,
        NOW,
    )
    .unwrap();
    let second = create_intent(
        &owner,
        &IntentInput {
            source: DEST,
            destination: "third.example",
            seq: 2,
            challenge: &challenge(),
            root: first["body"]["ciphertext_root"].as_str().unwrap(),
            chunks: 2,
            total_bytes: first["body"]["bytes"].as_u64().unwrap(),
            issued_ms: NOW + 1000,
            expires_ms: NOW + 100_000,
        },
    )
    .unwrap();
    verify_intent(
        &second,
        &owner.public_key,
        &actor,
        "third.example",
        &challenge(),
        1,
        NOW + 1001,
    )
    .unwrap();
    assert_eq!(
        verify_intent(
            &first,
            &owner.public_key,
            &actor,
            DEST,
            &challenge(),
            2,
            NOW
        )
        .unwrap_err()
        .code,
        "REPLAYED"
    );
}

#[test]
fn signed_manifest_rejects_corruption_before_chunk_receipt() {
    let owner = SigningKey::generate(true);
    let record = intent(&owner, 4);
    let (chunks, manifest) = parts();
    let mut tracker = TransferTracker::with_manifest(&record["body"], &manifest).unwrap();
    assert_eq!(
        tracker.accept(1, b"not sealed two").unwrap_err().code,
        "BAD_CHUNK"
    );
    assert_eq!(
        tracker.received_count(),
        0,
        "never acknowledge corrupted ciphertext"
    );
    assert!(tracker.accept(1, &chunks[1]).unwrap());
    assert!(!tracker.accept(1, &chunks[1]).unwrap(), "idempotent retry");
    let mut tampered = manifest.clone();
    tampered[0].bytes += 1;
    assert_eq!(
        TransferTracker::with_manifest(&record["body"], &tampered)
            .unwrap_err()
            .code,
        "BAD_MANIFEST"
    );
    let missing = tracker.missing_page(0, 10).unwrap();
    assert_eq!(missing.indices, vec![0]);
    assert_eq!(missing.next_cursor, None);
}

#[test]
fn incomplete_migration_restores_from_durable_ciphertext_and_resumes() {
    use std::collections::BTreeMap;
    let owner = SigningKey::generate(true);
    let record = intent(&owner, 6);
    let (chunks, manifest) = parts();
    let mut saved = BTreeMap::new();
    saved.insert(1, chunks[1].clone());
    let mut restarted = TransferTracker::resume(&record["body"], &manifest, &saved).unwrap();
    let page = restarted.missing_page(0, 1).unwrap();
    assert_eq!(page.indices, vec![0]);
    assert_eq!(page.received, 1);
    assert_eq!(page.expected, 2);
    assert_eq!(page.next_cursor, Some(1));
    assert_eq!(
        restarted.missing_page(1, 1).unwrap().indices,
        Vec::<u64>::new()
    );
    assert_eq!(restarted.missing_page(3, 1).unwrap_err().code, "BAD_CURSOR");
    assert_eq!(restarted.missing_page(0, 0).unwrap_err().code, "BAD_CURSOR");
    restarted.accept(0, &chunks[0]).unwrap();
    assert!(restarted.missing_page(0, 10).unwrap().indices.is_empty());
    restarted.verify_ciphertext().unwrap();
    assert!(restarted.is_verified());

    let mut corrupt_disk = saved;
    corrupt_disk.insert(0, b"corrupted on disk".to_vec());
    assert_eq!(
        TransferTracker::resume(&record["body"], &manifest, &corrupt_disk)
            .unwrap_err()
            .code,
        "BAD_CHUNK"
    );
}

#[test]
fn missing_page_is_bounded_and_deterministic_for_out_of_order_receipts() {
    let owner = SigningKey::generate(true);
    let chunks = [
        b"one".to_vec(),
        b"two".to_vec(),
        b"three".to_vec(),
        b"four".to_vec(),
    ];
    let manifest: Vec<Chunk> = chunks
        .iter()
        .enumerate()
        .map(|(index, blob)| Chunk {
            index: index as u64,
            digest: sha256_b64u(blob),
            bytes: blob.len() as u64,
        })
        .collect();
    let root = ciphertext_root(&manifest).unwrap();
    let record = create_intent(
        &owner,
        &IntentInput {
            source: SOURCE,
            destination: DEST,
            seq: 3,
            challenge: &challenge(),
            root: &root,
            chunks: 4,
            total_bytes: manifest.iter().map(|x| x.bytes).sum(),
            issued_ms: NOW,
            expires_ms: NOW + 600_000,
        },
    )
    .unwrap();
    let mut tracker = TransferTracker::with_manifest(&record["body"], &manifest).unwrap();
    tracker.accept(3, &chunks[3]).unwrap();
    tracker.accept(1, &chunks[1]).unwrap();
    let first = tracker.missing_page(0, 1).unwrap();
    assert_eq!(first.indices, vec![0]);
    assert_eq!(first.next_cursor, Some(1));
    let second = tracker.missing_page(first.next_cursor.unwrap(), 1).unwrap();
    assert_eq!(second.indices, vec![2]);
    assert_eq!(second.next_cursor, Some(3));
    assert_eq!(
        tracker.missing_page(3, 1).unwrap().indices,
        Vec::<u64>::new()
    );
    tracker.accept(0, &chunks[0]).unwrap();
    tracker.accept(2, &chunks[2]).unwrap();
    tracker.verify_ciphertext().unwrap();
}

#[test]
fn report_envelope_has_one_version_and_a_bounded_digest() {
    use secure_net_core::transfer::{
        encrypted_report_digest, MAX_REPORT_BYTES, MIN_REPORT_BYTES, REPORT_MAGIC,
    };
    let mut report = Vec::from(REPORT_MAGIC.as_slice());
    report.extend_from_slice(&[7_u8; 12]); // illustrative random-nonce bytes
    report.extend_from_slice(&[11_u8; 48]); // opaque ciphertext and tag
    assert_eq!(
        encrypted_report_digest(&report).unwrap(),
        sha256_b64u(&report)
    );
    assert_eq!(
        encrypted_report_digest(&report[..MIN_REPORT_BYTES - 1])
            .unwrap_err()
            .code,
        "BAD_REPORT_SIZE"
    );
    assert_eq!(
        encrypted_report_digest(&vec![1_u8; MAX_REPORT_BYTES + 1])
            .unwrap_err()
            .code,
        "BAD_REPORT_SIZE"
    );
    let mut changed_magic = report.clone();
    changed_magic[0] ^= 1;
    assert_eq!(
        encrypted_report_digest(&changed_magic).unwrap_err().code,
        "BAD_REPORT_MAGIC"
    );
    let mut later_version = report.clone();
    later_version[5] = 2;
    assert_eq!(
        encrypted_report_digest(&later_version).unwrap_err().code,
        "BAD_REPORT_MAGIC"
    );
    // We can commit to uploaded bytes, never claim to have decrypted them.
    report[30] ^= 1;
    assert_ne!(
        encrypted_report_digest(&report).unwrap(),
        sha256_b64u(&changed_magic)
    );
}

#[test]
fn report_aad_matches_device_bound_reference_and_rejects_cross_site_replay() {
    use secure_net_core::transfer::{report_associated_data, ReportContext};
    let actor = "a".repeat(22);
    let stage = "b".repeat(24);
    let root = "A".repeat(43);
    let device = "d".repeat(22);
    let ctx = ReportContext {
        actor_id: &actor,
        stage_id: &stage,
        destination: "destination.example",
        ciphertext_root: &root,
        recipient_device_id: &device,
    };
    let aad = report_associated_data(&ctx).unwrap();
    assert_eq!(
        String::from_utf8(aad.clone()).unwrap(),
        format!(
            "secure-net/transfer.report/v1\n{}",
            json!([actor, stage, "destination.example", root, device])
        )
    );
    let different_destination = ReportContext {
        destination: "another.example",
        ..ctx
    };
    assert_ne!(report_associated_data(&different_destination).unwrap(), aad);
    for bad in ["localhost", "127.0.0.1", "INVALID.EXAMPLE", "site..example"] {
        assert_eq!(
            report_associated_data(&ReportContext {
                destination: bad,
                ..ctx
            })
            .unwrap_err()
            .code,
            "BAD_CONTEXT"
        );
    }
}

#[test]
fn report_aad_and_envelope_digest_match_language_neutral_test_vector() {
    use secure_net_core::bytes::from_b64u;
    use secure_net_core::transfer::{
        encrypted_report_digest, report_associated_data, ReportContext,
    };
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../spec/vectors/transfer-report-v1.json"
    ))
    .unwrap();
    let ctx = &v["context"];
    let fields = ReportContext {
        actor_id: ctx["actor_id"].as_str().unwrap(),
        stage_id: ctx["stage_id"].as_str().unwrap(),
        destination: ctx["destination"].as_str().unwrap(),
        ciphertext_root: ctx["ciphertext_root"].as_str().unwrap(),
        recipient_device_id: ctx["recipient_device_id"].as_str().unwrap(),
    };
    assert_eq!(
        String::from_utf8(report_associated_data(&fields).unwrap()).unwrap(),
        v["aad_utf8"].as_str().unwrap(),
    );
    let synthetic_bytes = from_b64u(v["synthetic_report_b64url"].as_str().unwrap()).unwrap();
    assert_eq!(
        encrypted_report_digest(&synthetic_bytes).unwrap(),
        v["synthetic_report_sha256_b64url"].as_str().unwrap(),
    );
}

fn reconciliation_fixture(owner: &SigningKey) -> (serde_json::Value, String) {
    use secure_net_core::transfer::{create_reconciliation, ReconcileInput};
    let blob = b"CVRPT\x01abcdefghijklopaque-encrypted-report-body-and-tag";
    let digest = sha256_b64u(blob);
    let statement = create_reconciliation(
        owner,
        &ReconcileInput {
            stage_id: "stage00000000000000000000",
            destination: DEST,
            ciphertext_root: &sha256_b64u(b"transfer-manifest"),
            challenge: &challenge(),
            encrypted_report_sha256: &digest,
            issued_ms: NOW,
            expires_ms: NOW + 120_000,
        },
    )
    .unwrap();
    (statement, digest)
}

#[test]
fn independent_hybrid_actor_can_sign_private_report_attestation_without_a_service_identity() {
    use secure_net_core::transfer::{verify_reconciliation, ExpectedReconciliation};
    let owner = SigningKey::generate(true);
    let (statement, digest) = reconciliation_fixture(&owner);
    let root = sha256_b64u(b"transfer-manifest");
    let nonce = challenge();
    let expected = ExpectedReconciliation {
        owner_public: &owner.public_key,
        actor_id: &owner.kid,
        stage_id: "stage00000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        encrypted_report_sha256: &digest,
        now_ms: NOW + 1000,
    };
    let verified = verify_reconciliation(&statement, &expected).unwrap();
    assert_eq!(verified["actor"], owner.kid);
    assert_eq!(verified["encrypted_report_sha256"], digest);
    assert_eq!(verified["client_checked"], true);
}

#[test]
fn signed_reconciliation_refuses_wrong_stage_site_hash_challenge_and_replay() {
    use secure_net_core::transfer::{verify_reconciliation, ExpectedReconciliation};
    let owner = SigningKey::generate(true);
    let (statement, digest) = reconciliation_fixture(&owner);
    let root = sha256_b64u(b"transfer-manifest");
    let nonce = challenge();
    let expected = ExpectedReconciliation {
        owner_public: &owner.public_key,
        actor_id: &owner.kid,
        stage_id: "stage00000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        encrypted_report_sha256: &digest,
        now_ms: NOW + 1000,
    };
    let wrong_stage = ExpectedReconciliation {
        stage_id: "a".repeat(24).leak(),
        ..expected
    };
    assert_eq!(
        verify_reconciliation(&statement, &wrong_stage)
            .unwrap_err()
            .code,
        "WRONG_STAGE"
    );
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                destination: "different.example",
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "WRONG_SITE"
    );
    let wrong_hash = sha256_b64u(b"different encrypted report");
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                encrypted_report_sha256: &wrong_hash,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "BAD_REPORT_DIGEST"
    );
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                challenge: &sha256_b64u(b"other nonce"),
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "BAD_CHALLENGE"
    );
    let wrong_root = sha256_b64u(b"different archive");
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                ciphertext_root: &wrong_root,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "BAD_ROOT"
    );
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                now_ms: NOW + 121_000,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "EXPIRED"
    );
    let impostor = SigningKey::generate(true);
    assert_eq!(
        verify_reconciliation(
            &statement,
            &ExpectedReconciliation {
                owner_public: &impostor.public_key,
                actor_id: &impostor.kid,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "UNKNOWN_SIGNER"
    );
}

#[test]
fn reconciliation_schema_rejects_unsigned_metadata_and_classical_downgrade() {
    use secure_net_core::transfer::{
        create_reconciliation, verify_reconciliation, ExpectedReconciliation, ReconcileInput,
    };
    let owner = SigningKey::generate(true);
    let (statement, digest) = reconciliation_fixture(&owner);
    let root = sha256_b64u(b"transfer-manifest");
    let nonce = challenge();
    let expected = ExpectedReconciliation {
        owner_public: &owner.public_key,
        actor_id: &owner.kid,
        stage_id: "stage00000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        encrypted_report_sha256: &digest,
        now_ms: NOW,
    };
    let mut envelope = statement.clone();
    envelope["plaintext_message"] = json!("secret text");
    assert_eq!(
        verify_reconciliation(&envelope, &expected)
            .unwrap_err()
            .code,
        "BAD_RECONCILIATION"
    );
    let mut malicious_signature = statement.clone();
    malicious_signature["sig"]["name"] = json!("contact name");
    assert_eq!(
        verify_reconciliation(&malicious_signature, &expected)
            .unwrap_err()
            .code,
        "BAD_RECONCILIATION"
    );
    let mut body = statement["body"].clone();
    body["filename"] = json!("secret-report.json");
    let signed_extra = secure_net_core::signed::sign("transfer.reconcile", &body, &owner).unwrap();
    assert_eq!(
        verify_reconciliation(&signed_extra, &expected)
            .unwrap_err()
            .code,
        "BAD_RECONCILIATION"
    );
    let mut tampered = statement.clone();
    tampered["body"]["client_checked"] = json!(false);
    assert_eq!(
        verify_reconciliation(&tampered, &expected)
            .unwrap_err()
            .code,
        "BAD_SIGNATURE"
    );
    let classic = SigningKey::generate(false);
    assert_eq!(
        create_reconciliation(
            &classic,
            &ReconcileInput {
                stage_id: "stage00000000000000000000",
                destination: DEST,
                ciphertext_root: &root,
                challenge: &nonce,
                encrypted_report_sha256: &digest,
                issued_ms: NOW,
                expires_ms: NOW + 120_000,
            }
        )
        .unwrap_err()
        .code,
        "NOT_PQ"
    );
}

fn recipient_fixture(
    owner: &SigningKey,
    device: &SigningKey,
) -> (serde_json::Value, serde_json::Value, String, String) {
    use secure_net_core::transfer::{
        create_recipient_grant, create_recipient_request, ExpectedRecipient, RecipientRequestInput,
    };
    let root = sha256_b64u(b"owner-approved-encrypted-archive");
    let nonce = challenge();
    let kem = secure_net_core::cv::kem::kem_keygen(None).unwrap();
    let kem_pub = kem["kem_pub"].as_str().unwrap();
    let expected = ExpectedRecipient {
        actor_id: &owner.kid,
        stage_id: "stage000000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let request = create_recipient_request(
        device,
        &RecipientRequestInput {
            expected,
            recipient_kem_public: kem_pub,
            expires_ms: NOW + 120_000,
        },
    )
    .unwrap();
    let grant = create_recipient_grant(owner, &request, &expected, NOW + 60_000).unwrap();
    (request, grant, root, nonce)
}

#[test]
fn independent_device_request_and_actor_grant_are_both_hybrid_signed_and_site_bound() {
    use secure_net_core::transfer::{
        verify_recipient_grant, verify_recipient_request, ExpectedRecipient,
    };
    let owner = SigningKey::generate(true);
    let device = SigningKey::generate(true);
    let (request, grant, root, nonce) = recipient_fixture(&owner, &device);
    let expected = ExpectedRecipient {
        actor_id: &owner.kid,
        stage_id: "stage000000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW + 1000,
    };
    let r = verify_recipient_request(&request, &expected).unwrap();
    assert_eq!(r["recipient_id"], device.kid);
    assert_eq!(r["recipient_kem_alg"], "MLKEM768-P256");
    assert!(r["recipient_kem_pub"].as_str().unwrap().len() > 1600);
    let g = verify_recipient_grant(&request, &grant, &owner.public_key, &expected).unwrap();
    assert_eq!(g["actor"], owner.kid);
    assert_eq!(g["recipient_id"], device.kid);
    assert_eq!(g["owner_approved"], true);
    assert!(!request.to_string().contains("kem_priv"));
    assert!(!grant.to_string().contains("kem_priv"));
}

#[test]
fn recipient_grant_prevents_request_substitution_cross_site_and_expired_approval() {
    use secure_net_core::transfer::{verify_recipient_grant, ExpectedRecipient};
    let owner = SigningKey::generate(true);
    let device = SigningKey::generate(true);
    let (request, grant, root, nonce) = recipient_fixture(&owner, &device);
    let expected = ExpectedRecipient {
        actor_id: &owner.kid,
        stage_id: "stage000000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW + 1000,
    };
    let other_device = SigningKey::generate(true);
    let (other_request, _, _, _) = recipient_fixture(&owner, &other_device);
    assert_eq!(
        verify_recipient_grant(&other_request, &grant, &owner.public_key, &expected)
            .unwrap_err()
            .code,
        "BAD_GRANT"
    );
    let wrong_host = ExpectedRecipient {
        destination: "attacker.example",
        ..expected
    };
    assert_eq!(
        verify_recipient_grant(&request, &grant, &owner.public_key, &wrong_host)
            .unwrap_err()
            .code,
        "BAD_CONSENT"
    );
    let wrong_stage = ExpectedRecipient {
        stage_id: "another0000000000000000000",
        ..expected
    };
    assert_eq!(
        verify_recipient_grant(&request, &grant, &owner.public_key, &wrong_stage)
            .unwrap_err()
            .code,
        "BAD_CONSENT"
    );
    let wrong_nonce = sha256_b64u(b"another nonce");
    assert_eq!(
        verify_recipient_grant(
            &request,
            &grant,
            &owner.public_key,
            &ExpectedRecipient {
                challenge: &wrong_nonce,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "BAD_CONSENT"
    );
    let wrong_root = sha256_b64u(b"altered archive");
    assert_eq!(
        verify_recipient_grant(
            &request,
            &grant,
            &owner.public_key,
            &ExpectedRecipient {
                ciphertext_root: &wrong_root,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "BAD_CONSENT"
    );
    assert_eq!(
        verify_recipient_grant(
            &request,
            &grant,
            &owner.public_key,
            &ExpectedRecipient {
                now_ms: NOW + 121_000,
                ..expected
            }
        )
        .unwrap_err()
        .code,
        "EXPIRED"
    );
    let impostor = SigningKey::generate(true);
    assert_eq!(
        verify_recipient_grant(&request, &grant, &impostor.public_key, &expected)
            .unwrap_err()
            .code,
        "WRONG_ACTOR"
    );
}

#[test]
fn independent_recipient_grants_reject_forgery_metadata_downgrade_and_key_leaks() {
    use secure_net_core::signed::sign;
    use secure_net_core::transfer::{
        create_recipient_grant, create_recipient_request, verify_recipient_grant,
        verify_recipient_request, ExpectedRecipient, RecipientRequestInput,
    };
    let owner = SigningKey::generate(true);
    let device = SigningKey::generate(true);
    let (request, grant, root, nonce) = recipient_fixture(&owner, &device);
    let expected = ExpectedRecipient {
        actor_id: &owner.kid,
        stage_id: "stage000000000000000000000",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let mut forged = grant.clone();
    forged["body"]["owner_approved"] = json!(false);
    assert_eq!(
        verify_recipient_grant(&request, &forged, &owner.public_key, &expected)
            .unwrap_err()
            .code,
        "BAD_SIGNATURE"
    );
    let mut outer_metadata = request.clone();
    outer_metadata["plaintext_contact"] = json!("Private Alice");
    assert_eq!(
        verify_recipient_request(&outer_metadata, &expected)
            .unwrap_err()
            .code,
        "BAD_CONSENT"
    );
    let mut signed_metadata = request["body"].clone();
    signed_metadata["private_filename"] = json!("secret.txt");
    let signed = sign("transfer.recipient-request", &signed_metadata, &device).unwrap();
    assert_eq!(
        verify_recipient_request(&signed, &expected)
            .unwrap_err()
            .code,
        "BAD_CONSENT"
    );
    let mut extra_signature = grant.clone();
    extra_signature["sig"]["private_note"] = json!("not allowed");
    assert_eq!(
        verify_recipient_grant(&request, &extra_signature, &owner.public_key, &expected)
            .unwrap_err()
            .code,
        "BAD_CONSENT"
    );
    let classic_device = SigningKey::generate(false);
    let kem = secure_net_core::cv::kem::kem_keygen(None).unwrap();
    assert_eq!(
        create_recipient_request(
            &classic_device,
            &RecipientRequestInput {
                expected,
                recipient_kem_public: kem["kem_pub"].as_str().unwrap(),
                expires_ms: NOW + 60_000,
            }
        )
        .unwrap_err()
        .code,
        "NOT_PQ"
    );
    assert_eq!(
        create_recipient_request(
            &owner,
            &RecipientRequestInput {
                expected,
                recipient_kem_public: kem["kem_pub"].as_str().unwrap(),
                expires_ms: NOW + 60_000,
            }
        )
        .unwrap_err()
        .code,
        "BAD_DEVICE"
    );
    assert_eq!(
        create_recipient_request(
            &device,
            &RecipientRequestInput {
                expected,
                recipient_kem_public: "invalid-key",
                expires_ms: NOW + 60_000,
            }
        )
        .unwrap_err()
        .code,
        "BAD_CONSENT"
    );
    assert_eq!(
        create_recipient_grant(&classic_device, &request, &expected, NOW + 60_000)
            .unwrap_err()
            .code,
        "WRONG_ACTOR"
    );
    assert_eq!(
        create_recipient_grant(&owner, &request, &expected, NOW + 130_000)
            .unwrap_err()
            .code,
        "BAD_GRANT"
    );
}

fn possession_fixture() -> (
    SigningKey,
    SigningKey,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    String,
    String,
    String,
) {
    use secure_net_core::transfer::{
        create_recipient_grant, create_recipient_request, ExpectedRecipient, RecipientRequestInput,
    };
    let actor = SigningKey::generate(true);
    let device = SigningKey::generate(true);
    let kem = secure_net_core::cv::kem::kem_keygen(None).unwrap();
    let private = kem["kem_priv"].as_str().unwrap().to_string();
    let root = sha256_b64u(b"test-opaque-archive-root");
    let nonce = challenge();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let request = create_recipient_request(
        &device,
        &RecipientRequestInput {
            expected,
            recipient_kem_public: kem["kem_pub"].as_str().unwrap(),
            expires_ms: NOW + 120_000,
        },
    )
    .unwrap();
    let grant = create_recipient_grant(&actor, &request, &expected, NOW + 115_000).unwrap();
    (actor, device, request, grant, kem, private, root, nonce)
}

#[test]
fn user_approved_recipient_proves_kem_private_key_without_sharing_any_secret() {
    use secure_net_core::transfer::{
        create_recipient_possession_offer, create_recipient_possession_proof,
        verify_recipient_possession_proof, ExpectedRecipient,
    };
    let (actor, device, request, grant, _, private, root, nonce) = possession_fixture();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let mut offer =
        create_recipient_possession_offer(&request, &grant, &actor.public_key, &expected).unwrap();
    assert_eq!(offer.public["expires_ms"], NOW + 115_000);
    let proof = create_recipient_possession_proof(
        &device,
        &private,
        &offer.public,
        &request,
        &grant,
        &actor.public_key,
        &expected,
    )
    .unwrap();
    assert!(!offer.public.to_string().contains(&private));
    assert!(!proof.to_string().contains(&private));
    assert!(!offer.public.to_string().contains("kem_priv"));
    assert!(!proof.to_string().contains("kem_priv"));
    let result = verify_recipient_possession_proof(
        &mut offer.verifier,
        &proof,
        &request,
        &grant,
        &actor.public_key,
        &expected,
    )
    .unwrap();
    assert_eq!(result["recipient_possession_verified"], true);
    assert_eq!(result["imported"], false);
    assert_eq!(result["cutover"], false);
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &proof,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "REPLAYED"
    );
}

#[test]
fn recipient_possession_rejects_wrong_private_key_tampered_offer_and_wrong_device() {
    use secure_net_core::transfer::{
        create_recipient_possession_offer, create_recipient_possession_proof, ExpectedRecipient,
    };
    let (actor, device, request, grant, _, private, root, nonce) = possession_fixture();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let offer =
        create_recipient_possession_offer(&request, &grant, &actor.public_key, &expected).unwrap();
    let wrong_priv = secure_net_core::cv::kem::kem_keygen(None).unwrap();
    assert_eq!(
        create_recipient_possession_proof(
            &device,
            wrong_priv["kem_priv"].as_str().unwrap(),
            &offer.public,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "KEM_FAILED"
    );
    let impostor = SigningKey::generate(true);
    assert_eq!(
        create_recipient_possession_proof(
            &impostor,
            &private,
            &offer.public,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "WRONG_DEVICE"
    );
    let mut tampered = offer.public.clone();
    tampered["challenge_id"] = json!(secure_net_core::bytes::random_b64u(32));
    assert_eq!(
        create_recipient_possession_proof(
            &device,
            &private,
            &tampered,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "KEM_FAILED"
    );
    let mut unsafe_metadata = offer.public.clone();
    unsafe_metadata["recipient_secret"] = json!("should not be here");
    assert_eq!(
        create_recipient_possession_proof(
            &device,
            &private,
            &unsafe_metadata,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "BAD_CHALLENGE"
    );
}

#[test]
fn recipient_possession_refuses_forged_proof_wrong_site_and_expiry() {
    use secure_net_core::transfer::{
        create_recipient_possession_offer, create_recipient_possession_proof,
        verify_recipient_possession_proof, ExpectedRecipient,
    };
    let (actor, device, request, grant, _, private, root, nonce) = possession_fixture();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let mut offer =
        create_recipient_possession_offer(&request, &grant, &actor.public_key, &expected).unwrap();
    let proof = create_recipient_possession_proof(
        &device,
        &private,
        &offer.public,
        &request,
        &grant,
        &actor.public_key,
        &expected,
    )
    .unwrap();
    let mut tampered_proof = proof.clone();
    tampered_proof["body"]["proof_sha256"] = json!(sha256_b64u(b"fake"));
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &tampered_proof,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "BAD_SIGNATURE"
    );
    let mut leaky = proof.clone();
    leaky["plaintext"] = json!("not a public protocol field");
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &leaky,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "BAD_CONSENT"
    );
    let mut invalid_digest = proof["body"].clone();
    invalid_digest["proof_sha256"] = json!("wrong-format");
    let signed_invalid =
        secure_net_core::signed::sign("transfer.recipient-proof", &invalid_digest, &device)
            .unwrap();
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &signed_invalid,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "BAD_PROOF"
    );
    let mut forged_body = proof["body"].clone();
    forged_body["proof_sha256"] = json!(sha256_b64u(b"wrong secret"));
    let wrong_but_signed =
        secure_net_core::signed::sign("transfer.recipient-proof", &forged_body, &device).unwrap();
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &wrong_but_signed,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap_err()
        .code,
        "BAD_PROOF"
    );
    let host = ExpectedRecipient {
        destination: "wrong.example",
        ..expected
    };
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &proof,
            &request,
            &grant,
            &actor.public_key,
            &host
        )
        .unwrap_err()
        .code,
        "BAD_CONSENT"
    );
    let expired = ExpectedRecipient {
        now_ms: NOW + 116_000,
        ..expected
    };
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &proof,
            &request,
            &grant,
            &actor.public_key,
            &expired
        )
        .unwrap_err()
        .code,
        "EXPIRED"
    );
    // Rejected attempts must never consume a valid challenge.
    assert_eq!(
        verify_recipient_possession_proof(
            &mut offer.verifier,
            &proof,
            &request,
            &grant,
            &actor.public_key,
            &expected
        )
        .unwrap()["recipient_possession_verified"],
        true
    );
}

#[test]
fn recipient_possession_private_snapshot_survives_restart_but_refuses_corruption() {
    use secure_net_core::transfer::{
        create_recipient_possession_offer, ExpectedRecipient, RecipientPossessionState,
    };
    let (actor, _, request, grant, _, _, root, nonce) = possession_fixture();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let offer =
        create_recipient_possession_offer(&request, &grant, &actor.public_key, &expected).unwrap();
    let snapshot = offer.verifier.private_snapshot();
    assert_eq!(snapshot["v"], 1);
    assert_eq!(snapshot["used"], false);
    assert_eq!(snapshot["challenge_id"], offer.public["challenge_id"]);
    assert_eq!(snapshot["request_id"], offer.public["request_id"]);
    assert_eq!(snapshot["grant_id"], offer.public["grant_id"]);
    assert!(snapshot.get("kem_priv").is_none());
    assert!(snapshot.get("challenge_plaintext").is_none());
    let persisted = serde_json::to_vec(&snapshot).unwrap();
    let reopened: serde_json::Value = serde_json::from_slice(&persisted).unwrap();
    let restored = RecipientPossessionState::restore_private_snapshot(&reopened).unwrap();
    assert_eq!(restored.private_snapshot(), snapshot);
    for (key, value) in [
        ("challenge_id", json!("short")),
        ("request_id", json!("not-a-hash")),
        ("proof_digest", json!("bad")),
        ("expires_ms", json!(-1)),
        ("used", json!("false")),
        ("v", json!(2)),
    ] {
        let mut corrupt = snapshot.clone();
        corrupt[key] = value;
        assert!(
            RecipientPossessionState::restore_private_snapshot(&corrupt).is_err(),
            "{key}"
        );
    }
    let mut excess = snapshot.clone();
    excess["private_contact"] = json!("not permitted");
    assert_eq!(
        RecipientPossessionState::restore_private_snapshot(&excess)
            .err()
            .unwrap()
            .code,
        "BAD_CONSENT"
    );
}

#[test]
fn recipient_possession_uses_durable_atomic_commit_before_ack_and_rejects_replayed_snapshots() {
    use secure_net_core::transfer::{
        create_recipient_possession_offer, create_recipient_possession_proof,
        verify_recipient_possession_with_atomic_consume, ExpectedRecipient,
        RecipientPossessionState,
    };
    use std::io::Write;
    let (actor, device, request, grant, _, private, root, nonce) = possession_fixture();
    let expected = ExpectedRecipient {
        actor_id: &actor.kid,
        stage_id: "recstage000000000000000001",
        destination: DEST,
        ciphertext_root: &root,
        challenge: &nonce,
        now_ms: NOW,
    };
    let offer =
        create_recipient_possession_offer(&request, &grant, &actor.public_key, &expected).unwrap();
    let pending_snapshot = offer.verifier.private_snapshot();
    let proof = create_recipient_possession_proof(
        &device,
        &private,
        &offer.public,
        &request,
        &grant,
        &actor.public_key,
        &expected,
    )
    .unwrap();
    // An unavailable private durable store MUST refuse the success receipt,
    // while retaining the ability to retry once the database is healthy.
    let mut verifier =
        RecipientPossessionState::restore_private_snapshot(&pending_snapshot).unwrap();
    let err = verify_recipient_possession_with_atomic_consume(
        &mut verifier,
        &proof,
        &request,
        &grant,
        &actor.public_key,
        &expected,
        |_| {
            Err(secure_net_core::error::Error::new(
                "STORAGE",
                "durable commit unavailable",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(err.code, "STORAGE");
    assert_eq!(verifier.private_snapshot()["used"], false);

    // Use create_new as a simple test-only compare-and-set ledger. Real
    // destinations need a database transaction, size quotas and shared
    // anti-rollback state across processes, not an independent file per node.
    let dir = std::env::temp_dir().join(format!(
        "sn-test-private-possession-{}",
        secure_net_core::bytes::random_b64u(20)
    ));
    std::fs::create_dir(&dir).unwrap();
    let consumed = dir.join("used");
    let persist = |key: &secure_net_core::transfer::RecipientConsumeKey<'_>| {
        assert_eq!(key.challenge_id, offer.public["challenge_id"]);
        assert_eq!(key.recipient_id, device.kid);
        assert_eq!(key.request_id, offer.public["request_id"]);
        assert_eq!(key.grant_id, offer.public["grant_id"]);
        assert_eq!(key.proof_digest.len(), 32);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&consumed)
        {
            Ok(mut f) => {
                f.write_all(b"consumed")
                    .map_err(|_| secure_net_core::error::Error::new("STORAGE", "write failed"))?;
                f.sync_all()
                    .map_err(|_| secure_net_core::error::Error::new("STORAGE", "sync failed"))?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(secure_net_core::error::Error::new(
                "STORAGE",
                "commit failed",
            )),
        }
    };
    let accepted = verify_recipient_possession_with_atomic_consume(
        &mut verifier,
        &proof,
        &request,
        &grant,
        &actor.public_key,
        &expected,
        persist,
    )
    .unwrap();
    assert_eq!(accepted["recipient_possession_verified"], true);
    assert_eq!(accepted["cutover"], false);
    assert_eq!(verifier.private_snapshot()["used"], true);

    // Simulate recovery from an old, unconsumed in-memory copy. The durable
    // commit marker still exists, so even this stale copy cannot re-ack.
    let mut stale = RecipientPossessionState::restore_private_snapshot(&pending_snapshot).unwrap();
    assert_eq!(
        verify_recipient_possession_with_atomic_consume(
            &mut stale,
            &proof,
            &request,
            &grant,
            &actor.public_key,
            &expected,
            persist
        )
        .unwrap_err()
        .code,
        "REPLAYED"
    );
    assert_eq!(stale.private_snapshot()["used"], false);
    let restored_committed =
        RecipientPossessionState::restore_private_snapshot(&verifier.private_snapshot()).unwrap();
    assert_eq!(restored_committed.private_snapshot()["used"], true);
    std::fs::remove_dir_all(dir).unwrap();
}
