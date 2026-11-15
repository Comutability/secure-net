//! Commonveil's hybrid KEM against vectors made by @noble/post-quantum (tests/vectors/cv-kem.json),
//! with the randomness fixed so keys, ciphertexts and shared secrets must match byte for byte.
use secure_net_core::cv::kem::{decapsulate, encapsulate_with, keygen_from};
use serde_json::Value;

#[test]
fn hybrid_kem_matches_noble() {
    let v: Value = serde_json::from_str(include_str!("vectors/cv-kem.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let h = |k: &str| hex::decode(c[k].as_str().unwrap()).unwrap();
        let seed = h("seed");
        let pk = keygen_from(&seed).unwrap();
        assert_eq!(pk, h("publicKey"));
        let rand: [u8; 160] = h("rand").try_into().unwrap();
        let (ct, ss) = encapsulate_with(&pk, &rand).unwrap();
        assert_eq!(ct, h("cipherText"));
        assert_eq!(&ss[..], h("sharedSecret").as_slice());
        assert_eq!(&decapsulate(&ct, &seed).unwrap()[..], h("sharedSecret").as_slice());
    }
}
