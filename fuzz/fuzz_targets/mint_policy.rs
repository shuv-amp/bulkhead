//! The Token-2022 mint policy (`docs/05 §7`) against an independent statement
//! of it: parse every TLV entry first, then decide. A mint the program accepts
//! must carry only allowlisted extensions, and the two must agree on every input.
#![no_main]
use bulkhead_vault::mint_policy_decimals;
use libfuzzer_sys::fuzz_target;

fn reference(d: &[u8], token_2022: bool) -> Option<u8> {
    if d.len() < 82 || d.len() == 355 || d[45] != 1 {
        return None; // too short, a multisig, or not initialized
    }
    if d.len() == 82 {
        return Some(d[44]); // a classic mint: no extensions
    }
    if !token_2022 || d.len() <= 165 || d[165] != 1 {
        return None; // extensions exist only on Token-2022, after the account type
    }
    let mut entries: Vec<(u16, &[u8])> = Vec::new();
    let mut o = 166;
    while d.len() - o >= 4 {
        let ty = u16::from_le_bytes([d[o], d[o + 1]]);
        let len = u16::from_le_bytes([d[o + 2], d[o + 3]]) as usize;
        let end = o + 4 + len;
        if end > d.len() {
            return None; // an entry that does not fit, even the terminator's
        }
        if ty == 0 {
            break;
        }
        entries.push((ty, &d[o + 4..end]));
        o = end;
    }
    for (ty, value) in entries {
        let ok = match ty {
            1 | 10 | 18 | 19 | 20 | 21 | 22 | 23 | 25 | 28 => true,
            3 => value.len() == 32 && value.iter().all(|&b| b == 0),
            6 => value.first().copied() != Some(2),
            _ => false,
        };
        if !ok {
            return None;
        }
    }
    Some(d[44])
}

// Raw bytes, so a seed file means exactly what it says: the low bit of the
// first byte is the flag, the rest is the account data.
fuzz_target!(|data: &[u8]| {
    let Some((&flag, rest)) = data.split_first() else {
        return;
    };
    let (token_2022, d) = (flag & 1 == 1, rest.to_vec());
    assert_eq!(
        mint_policy_decimals(&d, token_2022).ok(),
        reference(&d, token_2022)
    );
});
