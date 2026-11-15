//! The social protocol's test vectors (spec/vectors cvp-017 to cvp-021, and cvp-019-v2): every
//! accepted record verifies, every refused one is refused, every example is judged the same, and
//! every root, proof, tag and verifier is reproduced.
use secure_net_core::bytes::b64u;
use secure_net_core::signed::{key_id, record_id, SigningKey};
use secure_net_core::social::activity::verify_activity;
use secure_net_core::social::actor::verify_actor_document;
use secure_net_core::social::delivery::{delivery_verifier, envelope_problems, read_delivery_body, read_sealed_body, session_tag};
use secure_net_core::social::lexicon::{authority_of, extension_problems, verify_lexicon};
use secure_net_core::social::repo::{inclusion_proof, merkle_root, verify_inclusion, verify_repo};
use secure_net_core::social::vocabulary::activity_problems;
use serde_json::{json, Value};

fn vectors(name: &str) -> Value {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("vector file")).expect("vector JSON")
}
fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}
fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}
fn int(v: &Value) -> i64 {
    v.as_i64().unwrap()
}

#[test]
fn cvp017_actor_documents() {
    let v = vectors("cvp-017-v1.json");
    for k in ["account", "device"] {
        let key = &v["keys"][k];
        let made = SigningKey::from_secrets(&hx(&key["ed25519Seed"]), Some(&hx(&key["mldsa65Seed"]))).unwrap();
        assert_eq!(made.public_key, key["publicKey"].as_str().unwrap(), "{k} key from its seeds");
        assert_eq!(key_id(&made.public_key).unwrap(), key["kid"].as_str().unwrap());
    }
    let x = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(hx(&v["keys"]["device"]["x25519Secret"])).unwrap());
    assert_eq!(b64u(x25519_dalek::PublicKey::from(&x).as_bytes()), v["keys"]["device"]["x25519Public"].as_str().unwrap());

    let a = &v["actor"];
    let body = verify_actor_document(&a["record"], None, Some(&a["lookedUpAs"]), 0).unwrap();
    assert_eq!(body["id"], a["actorId"]);
    assert_eq!(record_id(&a["record"]).unwrap(), a["recordId"].as_str().unwrap());
    for c in v["mustRefuse"].as_array().unwrap() {
        let handle = c.get("lookup");
        let min = c.get("minSeq").and_then(Value::as_i64).unwrap_or(0);
        assert!(verify_actor_document(&c["record"], None, handle, min).is_err(), "must refuse: {}", c["name"]);
    }
}

#[test]
fn cvp018_activities() {
    let v = vectors("cvp-018-v1.json");
    for e in v["examples"].as_array().unwrap() {
        let ok = activity_problems(&e["activity"], e["encrypted"] == true).map(|p| p.is_empty()).unwrap_or(false);
        assert_eq!(ok, e["valid"] == true, "{}", e["name"]);
    }
    let actor = &vectors("cvp-017-v1.json")["actor"]["record"];
    let doc = verify_actor_document(actor, None, None, 0).unwrap();
    let s = &v["signed"];
    verify_activity(&s["record"], &doc, false, int(&s["now"])).unwrap();
    assert_eq!(record_id(&s["record"]).unwrap(), s["recordId"].as_str().unwrap());
    let mut altered = s["record"].clone();
    altered["body"]["object"]["content"] = json!("Built apart.");
    assert!(verify_activity(&altered, &doc, false, int(&s["now"])).is_err());
}

#[test]
fn cvp019_envelopes_and_delivery_v1() {
    let v = vectors("cvp-019-v1.json");
    let t = &v["sessionTag"];
    assert_eq!(session_tag(&b64u(&hx(&t["handshakeHash"]))).unwrap(), t["tag"].as_str().unwrap());
    for e in v["envelopes"].as_array().unwrap() {
        let ok = envelope_problems(&e["envelope"]).map(|p| p.is_empty()).unwrap_or(false);
        assert_eq!(ok, e["valid"] == true, "{}", e["name"]);
    }
    assert_eq!(read_delivery_body(&v["deliveryBody"]).unwrap().len(), 1);
}

#[test]
fn cvp019_delivery_v2() {
    let v = vectors("cvp-019-v2.json");
    let t = &v["deliveryToken"];
    assert_eq!(delivery_verifier(t["token"].as_str().unwrap()).unwrap(), t["verifier"].as_str().unwrap());
    for e in v["envelopes"].as_array().unwrap() {
        let n = envelope_problems(&e["envelope"]).map(|p| p.len() as i64).unwrap_or(-1);
        assert_eq!(n, int(&e["problems"]), "{}", e["envelope"]);
    }
    for s in v["sealed"].as_array().unwrap() {
        let r = read_sealed_body(&s["body"], "BAD_MESSAGE");
        assert_eq!(r.is_ok(), s["accepted"] == true, "{}", s["body"]);
        if let (Err(e), Some(code)) = (&r, s["code"].as_str()) {
            assert_eq!(e.code, code, "{}", s["body"]);
        }
    }
}

#[test]
fn cvp020_repositories() {
    let v = vectors("cvp-020-v1.json");
    for r in v["roots"].as_array().unwrap() {
        assert_eq!(merkle_root(&strings(&r["ids"])), r["root"].as_str().unwrap());
    }
    let all = strings(&v["roots"].as_array().unwrap().last().unwrap()["ids"]);
    for p in v["proofs"].as_array().unwrap() {
        let proof = strings(&p["proof"]);
        assert_eq!(inclusion_proof(&all, int(&p["index"])).unwrap(), proof);
        assert!(verify_inclusion(p["id"].as_str().unwrap(), int(&p["index"]), int(&p["count"]), &proof, p["root"].as_str().unwrap()));
        assert!(!verify_inclusion(p["id"].as_str().unwrap(), int(&p["index"]) + 1, int(&p["count"]), &proof, p["root"].as_str().unwrap()));
    }
    let repo = &v["repository"];
    let id = repo["export"]["actor"]["body"]["id"].as_str().unwrap().to_string();
    verify_repo(&repo["export"], Some(&id), 0, int(&repo["now"])).unwrap();
    for c in v["mustRefuse"].as_array().unwrap() {
        assert!(verify_repo(&c["repo"], Some(&id), 0, int(&repo["now"])).is_err(), "must refuse: {}", c["name"]);
    }
}

#[test]
fn cvp021_lexicons() {
    let v = vectors("cvp-021-v1.json");
    assert_eq!(authority_of(&v["authority"]["nsid"]).as_deref(), v["authority"]["domain"].as_str());
    let publisher = verify_actor_document(&v["publisher"], None, None, 0).unwrap();
    let lex = verify_lexicon(&v["lexicon"], &publisher, 0).unwrap();
    let alice = verify_actor_document(&vectors("cvp-017-v1.json")["actor"]["record"], None, None, 0).unwrap();
    assert!(verify_lexicon(&v["lexicon"], &alice, 0).is_err(), "the wrong domain");
    let not_publisher = verify_actor_document(&v["notPublisher"], None, None, 0).unwrap();
    assert!(verify_lexicon(&v["lexicon"], &not_publisher, 0).is_err(), "an ordinary user of the domain");
    for o in v["objects"].as_array().unwrap() {
        assert_eq!(extension_problems(&o["object"], &lex).is_empty(), o["valid"] == true, "{}", o["name"]);
    }
}
