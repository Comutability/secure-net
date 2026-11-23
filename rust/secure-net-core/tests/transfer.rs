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
