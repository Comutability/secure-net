//! Secure Net in Rust, for JavaScript hosts.
//!
//! One function, `call`, takes a JSON request and returns a JSON reply, exactly as
//! `secure_net_core::api` describes. Build it with
//!   cargo build --release --target wasm32-unknown-unknown -p secure-net-wasm
//!   wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/secure_net_wasm.wasm
use wasm_bindgen::prelude::*;

/// Run one request: `{ "op": ..., ... }` in, `{ "ok": ... }` or `{ "error": { code, message } }` out.
#[wasm_bindgen]
pub fn call(request: &str) -> String {
    secure_net_core::api::call_text(request)
}

/// The version of this build.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
