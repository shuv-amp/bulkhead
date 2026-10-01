//! Bakes the Vault program id into Harbor.
//!
//! `BULKHEAD_VAULT_ID` is a base58 address. When it is unset, Harbor is bound
//! to the devnet Vault so `scripts/verify-deployed.sh` reproduces that binary.
//! Local validators pass the id of the Vault they just built.

use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_VAULT: &str = "HK5FbaLtvNSPHj9HYbuStfVxXktkoMejJ9GEjn8WCY1b";
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58 decode into the 32-byte big-endian form Solana uses for addresses.
fn decode_base58(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for c in s.bytes() {
        let v = ALPHABET
            .iter()
            .position(|a| *a == c)
            .unwrap_or_else(|| panic!("BULKHEAD_VAULT_ID is not base58: {s}"))
            as u32;
        let mut carry = v;
        for byte in out.iter_mut().rev() {
            let x = (*byte as u32) * 58 + carry;
            *byte = (x & 0xff) as u8;
            carry = x >> 8;
        }
        if carry != 0 {
            panic!("BULKHEAD_VAULT_ID does not fit in 32 bytes: {s}");
        }
    }
    out
}

fn main() {
    println!("cargo:rerun-if-env-changed=BULKHEAD_VAULT_ID");
    let id = env::var("BULKHEAD_VAULT_ID").unwrap_or_else(|_| DEFAULT_VAULT.to_string());
    let bytes = decode_base58(&id);
    // `cloud/lib/solana.mjs` `key()` of the devnet Vault. A shift of the
    // previous carry, instead of `x >> 8`, keeps only the last byte.
    if id == DEFAULT_VAULT {
        const DEVNET_VAULT: [u8; 32] = [
            242, 92, 64, 180, 42, 194, 119, 37, 95, 150, 122, 128, 49, 149, 166, 174, 64, 6, 230,
            221, 111, 5, 16, 121, 154, 41, 114, 223, 120, 42, 246, 166,
        ];
        if bytes != DEVNET_VAULT {
            panic!("devnet Vault id decoded to the wrong bytes");
        }
    }
    let list = bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let dest = PathBuf::from(env::var("OUT_DIR").unwrap()).join("vault_id.rs");
    fs::write(
        dest,
        format!("pub const VAULT_ID_BYTES: [u8; 32] = [{list}];\n"),
    )
    .unwrap();
    println!("cargo:rustc-env=BULKHEAD_VAULT_ID_B58={id}");
}
