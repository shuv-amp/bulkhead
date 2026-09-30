//! The Vault program Harbor forwards to, fixed at build time.
//!
//! Harbor signs every forwarded call with its caller PDA, which the Vault
//! trusts as "this protocol", so it must forward to that one Vault program and
//! no other (docs/15, A11). The default is the devnet Vault; a local run builds
//! Harbor for its own Vault with `BULKHEAD_VAULT_ID=<base58>`.
use std::{env, fs, path::Path};

const DEFAULT: &str = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A 32-byte address from base58 (big-endian accumulation; panics on anything else).
fn decode(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for c in s.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("BULKHEAD_VAULT_ID: {s:?} is not base58"));
        let mut carry = digit as u32;
        for b in out.iter_mut().rev() {
            carry += *b as u32 * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        assert!(
            carry == 0,
            "BULKHEAD_VAULT_ID: {s:?} is longer than 32 bytes"
        );
    }
    out
}

fn main() {
    println!("cargo:rerun-if-env-changed=BULKHEAD_VAULT_ID");
    println!("cargo:rerun-if-changed=build.rs");
    let id = env::var("BULKHEAD_VAULT_ID").unwrap_or_else(|_| DEFAULT.to_string());
    let bytes = decode(id.trim());
    let out = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("vault_id.rs");
    fs::write(
        out,
        format!("/// The Vault program this Harbor forwards to (build.rs).\npub const VAULT_PROGRAM: [u8; 32] = {bytes:?};\n"),
    )
    .expect("write vault_id.rs");
}
