//! Token account fields against an independent statement of what counts as a
//! token account: initialized, not a multisig, and longer than 165 bytes only
//! as a Token-2022 Account (type 2).
#![no_main]
use bulkhead_vault::token_account_fields;
use libfuzzer_sys::fuzz_target;

fn reference(d: &[u8], token_2022: bool) -> Option<([u8; 32], [u8; 32], u64)> {
    let ok = d.len() >= 165
        && d.len() != 355
        && d[108] != 0
        && (d.len() == 165 || (token_2022 && d[165] == 2));
    ok.then(|| {
        let k = |o: usize| <[u8; 32]>::try_from(&d[o..o + 32]).unwrap();
        (
            k(0),
            k(32),
            u64::from_le_bytes(d[64..72].try_into().unwrap()),
        )
    })
}

// Raw bytes, so a seed file means exactly what it says: the low bit of the
// first byte is the flag, the rest is the account data.
fuzz_target!(|data: &[u8]| {
    let Some((&flag, rest)) = data.split_first() else {
        return;
    };
    let (token_2022, d) = (flag & 1 == 1, rest.to_vec());
    assert_eq!(
        token_account_fields(&d, token_2022).ok(),
        reference(&d, token_2022)
    );
});
