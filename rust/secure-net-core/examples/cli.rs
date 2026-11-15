//! A small command-line front end, used by the JavaScript test `test/rust-interop.test.mjs` to
//! run conversations that alternate between the two implementations. It reads one JSON request
//! on standard input and writes one JSON reply (see `secure_net_core::api`).
//!
//!   echo '{"op":"canonical","value":{"b":1,"a":2}}' | cargo run --example cli
use std::io::Read;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("read standard input");
    println!("{}", secure_net_core::api::call_text(&input));
}
