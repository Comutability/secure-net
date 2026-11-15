//! Sessions version 2 against spec/vectors/cvp-016-v2.json.
use secure_net_core::canonical::canonical_json;
use secure_net_core::session::v2::{handshake_keys, identity_key, kdf_root2, message_key, transcript_hash, transcript_of};
use serde_json::Value;

fn v() -> Value {
    serde_json::from_str(include_str!("../../../spec/vectors/cvp-016-v2.json")).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}

#[test]
fn transcript() {
    let t = &v()["transcript"];
    let k = &t["prekeyPublicKeys"];
    let obj = transcript_of(t["initiator"].clone(), t["responder"].clone(), &t["x"], k["signed"].as_str().unwrap(), k["pq"].as_str().unwrap(), k["oneTime"].as_str()).unwrap();
    assert_eq!(obj, t["object"]);
    assert_eq!(canonical_json(&obj).unwrap(), t["canonical"].as_str().unwrap());
    assert_eq!(hex::encode(transcript_hash(&obj).unwrap()), t["hash"].as_str().unwrap());
}

#[test]
fn handshake_and_identity() {
    let all = v();
    let hs = &all["handshake"];
    let dhs: Vec<[u8; 32]> = hs["dh"].as_array().unwrap().iter().map(h32).collect();
    let (rk, hka, nhkb) = handshake_keys(&dhs, &h(&hs["mlkem"]), &h(&hs["transcriptHash"]));
    assert_eq!(hex::encode(rk), hs["rootKey"].as_str().unwrap());
    assert_eq!(hex::encode(hka), hs["initiatorHeaderKey"].as_str().unwrap());
    assert_eq!(hex::encode(nhkb), hs["responderNextHeaderKey"].as_str().unwrap());
    let (rk, hka, nhkb) = handshake_keys(&dhs[..3], &h(&hs["mlkem"]), &h(&hs["transcriptHash"]));
    assert_eq!(hex::encode(rk), hs["threeDh"]["rootKey"].as_str().unwrap());
    assert_eq!(hex::encode(hka), hs["threeDh"]["initiatorHeaderKey"].as_str().unwrap());
    assert_eq!(hex::encode(nhkb), hs["threeDh"]["responderNextHeaderKey"].as_str().unwrap());

    let ik = &all["identityKey"];
    let dhs: Vec<[u8; 32]> = ik["dh"].as_array().unwrap().iter().map(h32).collect();
    let (key, iv) = identity_key(&dhs, &h(&ik["mlkem"]), &ik["x"]).unwrap();
    assert_eq!(hex::encode(key), ik["key"].as_str().unwrap());
    assert_eq!(hex::encode(iv), ik["iv"].as_str().unwrap());
}

#[test]
fn root_message_and_header() {
    let all = v();
    let r = &all["root"];
    for (ss, want) in [(vec![], &r["withoutMlkem"]), (h(&r["mlkem"]), &r["withMlkem"])] {
        let (rk, ck, nhk) = kdf_root2(&h(&r["rootKey"]), &h(&r["dh"]), &ss);
        assert_eq!(hex::encode(rk), want["rootKey"].as_str().unwrap());
        assert_eq!(hex::encode(ck), want["chainKey"].as_str().unwrap());
        assert_eq!(hex::encode(nhk), want["nextHeaderKey"].as_str().unwrap());
    }
    let m = &all["message"];
    let (key, iv) = message_key(&h(&m["messageKey"]));
    assert_eq!(hex::encode(key), m["key"].as_str().unwrap());
    assert_eq!(hex::encode(iv), m["iv"].as_str().unwrap());
    let hd = &all["header"];
    assert_eq!(canonical_json(&hd["object"]).unwrap(), hd["canonical"].as_str().unwrap());
    assert_eq!(all["limits"]["maxSkip"], 1000);
    assert_eq!(all["pieces"]["chunk"], 256);
}
