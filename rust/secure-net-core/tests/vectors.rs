//! The Rust implementation against the JavaScript reference's test vectors (spec/vectors).
use secure_net_core::bytes::{b64u, from_b64u, sha256};
use secure_net_core::canonical::{canonical_json, canonicalize_text};
use secure_net_core::session::keys::{link_code, safety_number};
use secure_net_core::session::primitives::*;
use secure_net_core::signed::{check_signature, key_id, record_id, signing_bytes, SigningKey};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file")).expect("vector JSON")
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}
fn arr<const N: usize>(v: &Value) -> [u8; N] {
    hx(v).try_into().expect("length")
}

#[test]
fn cvp002_canonical_json() {
    let v = vectors("cvp-002-v1.json");
    for case in v["canonical"].as_array().unwrap() {
        let out = canonicalize_text(case["json"].as_str().unwrap()).unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(out, case["canonical"].as_str().unwrap(), "{}", case["name"]);
        assert_eq!(hex::encode(out.as_bytes()), case["canonicalUtf8"].as_str().unwrap(), "{}", case["name"]);
    }
    for case in v["refused"].as_array().unwrap() {
        assert!(canonicalize_text(case["json"].as_str().unwrap()).is_err(), "should refuse: {}", case["name"]);
    }
}

#[test]
fn cvp002_signing_bytes_and_records() {
    let v = vectors("cvp-002-v1.json");
    let sb = &v["signingBytes"];
    assert_eq!(hex::encode(signing_bytes(sb["kind"].as_str().unwrap(), &sb["body"]).unwrap()), sb["hex"].as_str().unwrap());

    let c = &v["classical"];
    let key = SigningKey::from_secrets(&hx(&c["secretKey"]), None).unwrap();
    assert_eq!(key.public_key, c["publicKey"].as_str().unwrap());
    let rec = &c["record"];
    assert_eq!(key.kid, rec["sig"]["kid"].as_str().unwrap());
    let mine = key.sign_deterministic_for_vectors(rec["kind"].as_str().unwrap(), &rec["body"]).unwrap();
    assert_eq!(mine["sig"]["value"], rec["sig"]["value"], "Ed25519 is deterministic");
    assert!(check_signature(rec, &rec["sig"], &key.public_key));
    assert_eq!(record_id(rec).unwrap(), c["recordId"].as_str().unwrap());

    let hy = &v["hybrid"];
    let key = SigningKey::from_secrets(&hx(&hy["ed25519Secret"]), Some(&hx(&hy["mldsa65Seed"]))).unwrap();
    assert_eq!(key.public_key, hy["publicKey"].as_str().unwrap());
    let rec = &hy["record"];
    assert_eq!(key.kid, rec["sig"]["kid"].as_str().unwrap());
    assert!(check_signature(rec, &rec["sig"], &key.public_key), "the JavaScript's hybrid signature verifies here");
    let mine = key.sign_deterministic_for_vectors(rec["kind"].as_str().unwrap(), &rec["body"]).unwrap();
    assert_eq!(mine["sig"]["pq"], rec["sig"]["pq"], "deterministic ML-DSA-65 gives the JavaScript's exact signature");
    assert_eq!(record_id(rec).unwrap(), hy["recordId"].as_str().unwrap());
    // A fresh, hedged signature differs but verifies.
    let fresh = secure_net_core::signed::sign(rec["kind"].as_str().unwrap(), &rec["body"], &key).unwrap();
    assert_ne!(fresh["sig"]["pq"], rec["sig"]["pq"]);
    assert!(check_signature(&fresh, &fresh["sig"], &key.public_key));

    for case in v["mustRefuse"].as_array().unwrap() {
        let rec = &case["record"];
        assert!(!check_signature(rec, &rec["sig"], case["publicKey"].as_str().unwrap()), "must refuse: {}", case["name"]);
    }
    assert_eq!(key_id(&key.public_key).unwrap(), key.kid);
}

#[test]
fn cvp016_primitives() {
    let v = vectors("cvp-016-v1.json");
    let x = &v["x25519"];
    let a = dh_key_pair_from(arr(&x["aSecret"]));
    let bp = dh_key_pair_from(arr(&x["bSecret"]));
    assert_eq!(hex::encode(from_b64u(&a.pk).unwrap()), x["aPublic"].as_str().unwrap());
    assert_eq!(hex::encode(from_b64u(&bp.pk).unwrap()), x["bPublic"].as_str().unwrap());
    let shared = dh(&a.sk, &bp.pk).unwrap();
    assert_eq!(shared, dh(&bp.sk, &a.pk).unwrap());
    if let Some(s) = x.get("shared") {
        assert_eq!(hex::encode(shared), s.as_str().unwrap());
    }
    // A low-order point gives an all-zero result, which is refused.
    assert_eq!(dh(&a.sk, &b64u(&[0u8; 32])).unwrap_err().code, "BAD_KEY");

    let k = &v["mlkem768"];
    let pair = kem_key_pair_from(arr(&k["seed"]));
    assert_eq!(hex::encode(sha256(&from_b64u(&pair.pk).unwrap())), k["publicKeySha256"].as_str().unwrap());
    let (ct, ss) = encapsulate(&pair.pk, Some(arr(&k["coins"]))).unwrap();
    assert_eq!(hex::encode(sha256(&from_b64u(&ct).unwrap())), k["cipherTextSha256"].as_str().unwrap());
    assert_eq!(hex::encode(ss), k["sharedSecret"].as_str().unwrap());
    assert_eq!(decapsulate(&ct, &pair.sk).unwrap(), ss);
    assert_eq!(from_b64u(&pair.sk).unwrap().len(), 2400, "the FIPS 203 decapsulation key, as the JavaScript stores it");

    let t = &v["transcript"];
    assert_eq!(hex::encode(transcript_hash(&t["input"]).unwrap()), t["hash"].as_str().unwrap());

    let h = &v["handshake"];
    let dhs: Vec<[u8; 32]> = h["dh"].as_array().unwrap().iter().map(arr).collect();
    let th = hx(&h["transcriptHash"]);
    assert_eq!(hex::encode(handshake_secret(&dhs, &hx(&h["mlkem"]), &th)), h["secret"].as_str().unwrap());
    assert_eq!(hex::encode(handshake_secret(&dhs[..3], &hx(&h["mlkem"]), &th)), h["threeDh"].as_str().unwrap());

    let r = &v["root"];
    let (rk, ck) = kdf_root(&hx(&r["rk"]), &hx(&r["dh"]), &hx(&r["mlkem"]));
    assert_eq!(hex::encode(rk), r["out"]["rk"].as_str().unwrap());
    assert_eq!(hex::encode(ck), r["out"]["ck"].as_str().unwrap());
    if let Some(no) = r.get("withoutMlkem") {
        let (rk, ck) = kdf_root(&hx(&r["rk"]), &hx(&r["dh"]), &[]);
        assert_eq!(hex::encode(rk), no["rk"].as_str().unwrap());
        assert_eq!(hex::encode(ck), no["ck"].as_str().unwrap());
    }

    let c = &v["chain"];
    let (mk, next) = kdf_chain(&hx(&c["ck"]));
    assert_eq!(hex::encode(mk), c["mk"].as_str().unwrap());
    assert_eq!(hex::encode(next), c["next"].as_str().unwrap());

    let m = &v["message"];
    let (key, iv) = message_keys(&hx(&m["mk"]), "message");
    assert_eq!(hex::encode(key), m["key"].as_str().unwrap());
    assert_eq!(hex::encode(iv), m["iv"].as_str().unwrap());
    let sealed = seal(&hx(&m["mk"]), m["plaintext"].as_str().unwrap().as_bytes(), &hx(&m["ad"]), "message");
    assert_eq!(hex::encode(&sealed), m["ciphertext"].as_str().unwrap());
    assert_eq!(open(&hx(&m["mk"]), &sealed, &hx(&m["ad"]), "message").unwrap(), m["plaintext"].as_str().unwrap().as_bytes());
    assert_eq!(open(&hx(&m["mk"]), &sealed, b"other", "message").unwrap_err().code, "DECRYPT_FAILED");

    let codes = &v["codes"];
    assert_eq!(link_code("S", "D"), codes["linkCode"].as_str().unwrap());
    assert_eq!(safety_number("A", "B"), codes["safetyNumber"].as_str().unwrap());
    assert_eq!(safety_number("B", "A"), codes["safetyNumber"].as_str().unwrap(), "either order");
    let _ = canonical_json;
}

#[test]
fn the_key_decides_the_algorithm_not_the_signature() {
    let v = vectors("cvp-002-v1.json");
    let c = &v["classical"];
    let mut rec = c["record"].clone();
    rec["sig"]["alg"] = Value::String("Ed25519+ML-DSA-65".into());
    rec["sig"]["pq"] = Value::String("AAAA".into());
    assert!(!check_signature(&rec, &rec["sig"], c["publicKey"].as_str().unwrap()), "an Ed25519 key's record claiming to be hybrid");
}
