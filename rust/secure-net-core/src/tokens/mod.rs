//! Private, one-use tokens from RFC 9497 VOPRF with P256-SHA256 (CVP-013), matching
//! `src/tokens/voprf.js`. The VOPRF itself is the `voprf` crate; this module keeps the
//! JavaScript's formats (base64url scalars and compressed points) and rules.
use getrandom::SysRng;
use serde_json::{json, Value};
use voprf::{BlindedElement, EvaluationElement, Group, Proof, VoprfClient, VoprfServer};

use crate::bytes::{b64u, equal_bytes, from_b64u, random, sha256, sha256_b64u};
use crate::error::{Error, Result};

type Cs = p256::NistP256;
pub const SUITE: &str = "P256-SHA256";
const MAX_BATCH: usize = 64;

fn err(code: &'static str, msg: &str) -> Error {
    Error::new(code, msg)
}

fn server(secret_key: &str) -> Result<VoprfServer<Cs>> {
    VoprfServer::<Cs>::new_with_key(&from_b64u(secret_key)?).map_err(|_| err("BAD_KEY", "Not an issuer key"))
}

/// An issuer key for one scope (one vote, say), derived from a secret seed (RFC 9497 DeriveKeyPair).
pub fn issuer_key(seed: &[u8], scope: &str) -> Result<Value> {
    let s = VoprfServer::<Cs>::new_from_seed(seed, format!("secure-net/tokens/v1/{scope}").as_bytes()).map_err(|_| err("BAD_KEY", "Couldn't derive an issuer key"))?;
    let bytes = s.serialize();
    let (sk, _) = bytes.split_at(32);
    Ok(json!({ "scope": scope, "secretKey": b64u(sk), "publicKey": b64u(&<Cs as Group>::serialize_elem(s.get_public_key())) }))
}

/// Make n tokens to be signed: `{ pending, request }`.
pub fn request_tokens(n: usize) -> Result<Value> {
    if !(1..=MAX_BATCH).contains(&n) {
        return Err(Error::new("BAD_COUNT", format!("Between 1 and {MAX_BATCH} tokens at a time")));
    }
    let mut pending = Vec::with_capacity(n);
    let mut request = Vec::with_capacity(n);
    for _ in 0..n {
        let input = random::<32>();
        let r = VoprfClient::<Cs>::blind(&input, &mut SysRng).map_err(|_| err("BAD_COUNT", "Couldn't blind a token"))?;
        let state = r.state.serialize();
        let (blind, blinded) = state.split_at(32);
        pending.push(json!({ "input": b64u(&input), "blind": b64u(blind), "blinded": b64u(blinded) }));
        request.push(json!(b64u(blinded)));
    }
    Ok(json!({ "pending": pending, "request": request }))
}

/// The issuer's answer. Check who's asking (and how many they've had) before calling this.
pub fn issue_tokens(key: &Value, request: &[Value]) -> Result<Value> {
    if request.is_empty() || request.len() > MAX_BATCH {
        return Err(Error::new("BAD_COUNT", format!("Between 1 and {MAX_BATCH} tokens at a time")));
    }
    let bad = || err("BAD_REQUEST", "Those aren't valid blinded values");
    let s = server(key["secretKey"].as_str().unwrap_or("")).map_err(|_| bad())?;
    let blinded = request
        .iter()
        .map(|r| BlindedElement::<Cs>::deserialize(&from_b64u(r.as_str().ok_or_else(bad)?).map_err(|_| bad())?).map_err(|_| bad()))
        .collect::<Result<Vec<_>>>()?;
    let out = s.batch_blind_evaluate(&mut SysRng, &blinded).map_err(|_| bad())?;
    Ok(json!({ "evaluated": out.messages.iter().map(|m| b64u(&m.serialize())).collect::<Vec<_>>(), "proof": b64u(&out.proof.serialize()) }))
}

/// Turn the issuer's answer into tokens, checking its proof against the issuer's published key.
pub fn finish_tokens(pending: &[Value], response: &Value, public_key: &str) -> Result<Value> {
    let evaluated = response["evaluated"].as_array().filter(|e| e.len() == pending.len()).ok_or_else(|| err("BAD_RESPONSE", "The issuer's answer doesn't match the request"))?;
    let bad = || err("BAD_PROOF", "The issuer's proof doesn't match its published key");
    let s = |v: &Value, k: &str| from_b64u(v[k].as_str().unwrap_or("-")).map_err(|_| bad());
    let mut inputs = Vec::new();
    let mut clients = Vec::new();
    for p in pending {
        inputs.push(s(p, "input")?);
        clients.push(VoprfClient::<Cs>::deserialize(&[s(p, "blind")?, s(p, "blinded")?].concat()).map_err(|_| bad())?);
    }
    let messages = evaluated
        .iter()
        .map(|e| EvaluationElement::<Cs>::deserialize(&from_b64u(e.as_str().unwrap_or("-")).map_err(|_| bad())?).map_err(|_| bad()))
        .collect::<Result<Vec<_>>>()?;
    let proof = Proof::<Cs>::deserialize(&from_b64u(response["proof"].as_str().unwrap_or("-")).map_err(|_| bad())?).map_err(|_| bad())?;
    let pk = <Cs as Group>::deserialize_elem(&from_b64u(public_key).map_err(|_| bad())?).map_err(|_| bad())?;
    let outputs = VoprfClient::batch_finalize(&inputs, &clients, &messages, &proof, pk).map_err(|_| bad())?;
    let mut tokens = Vec::new();
    for (p, o) in pending.iter().zip(outputs) {
        let o = o.map_err(|_| bad())?;
        tokens.push(json!({ "input": p["input"], "output": b64u(&o) }));
    }
    Ok(Value::Array(tokens))
}

/// A token's spend id: stable for a token, revealing nothing else.
pub fn nullifier(token: &Value) -> String {
    sha256_b64u(format!("secure-net/nullifier/v1\n{}", crate::cv::canonical::js_string(&token["input"])).as_bytes())
}

/// Whether a token is one this issuer made (not whether it's been spent).
pub fn check_token(key: &Value, token: &Value) -> bool {
    let (Ok(s), Ok(input), Ok(output)) = (
        server(key["secretKey"].as_str().unwrap_or("")),
        from_b64u(token["input"].as_str().unwrap_or("-")),
        from_b64u(token["output"].as_str().unwrap_or("-")),
    ) else {
        return false;
    };
    s.evaluate(&input).is_ok_and(|want| equal_bytes(&want, &output))
}

/// Spend a token: its nullifier, or INVALID / SPENT.
pub fn spend_token(key: &Value, token: &Value, spent: &mut std::collections::HashSet<String>) -> Result<String> {
    if !check_token(key, token) {
        return Err(err("INVALID", "Not a token from this issuer"));
    }
    let id = nullifier(token);
    if !spent.insert(id.clone()) {
        return Err(err("SPENT", "This token has already been used"));
    }
    Ok(id)
}

pub fn key_fingerprint(public_key: &str) -> Result<String> {
    Ok(b64u(&sha256(&from_b64u(public_key)?))[..22].to_string())
}
