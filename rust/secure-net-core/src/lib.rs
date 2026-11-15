//! Secure Net in Rust.
//!
//! A port of the JavaScript reference library (`src/` in this repository). It is checked against
//! the same test vectors (`spec/vectors/`) and against the JavaScript code itself, message by
//! message, so the two can be used side by side. Nothing here has been independently reviewed.
//!
//! What is here so far:
//!   - [`canonical`]: canonical JSON (CVP-002, section 1).
//!   - [`bytes`]: base64url, hashing and key ids.
//!   - [`signed`]: signed records, Ed25519 and Ed25519 + ML-DSA-65 (CVP-002).
//!   - [`session`]: the primitives, accounts, devices, prekeys and version 1 one-to-one sessions
//!     of CVP-016.
//!
//! [`api`] runs any of these from one JSON request, for the command line and WebAssembly.
//!
//! Every protocol object is the same JSON the JavaScript library uses, so state saved by one can
//! be loaded by the other.
#![forbid(unsafe_code)]

pub mod api;
pub mod api_more;
pub mod bytes;
pub mod canonical;
pub mod commons;
pub mod consent;
pub mod cv;
pub mod ed25519;
pub mod js;
pub mod portable;
pub mod wire;
pub mod error;
pub mod extensions;
pub mod governance;
pub mod session;
pub mod signed;
pub mod social;
pub mod groups;
pub mod tokens;

pub use error::Error;

/// The JSON value type used for every protocol object.
pub type Value = serde_json::Value;
