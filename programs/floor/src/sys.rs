//! The three runtime syscalls Floor uses directly. This is the only file with
//! `unsafe`; each call passes pointers to live Rust slices for the duration of
//! the call, which is exactly the contract of these syscalls.
#![allow(unsafe_code)]

/// Log one line ("Program log: ...").
pub fn log(msg: &str) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_(msg.as_ptr(), msg.len() as u64);
    }
    #[cfg(not(target_os = "solana"))]
    let _ = msg;
}

/// Emit a structured event ("Program data: <base64>"), the same channel Anchor
/// events use, so indexers and the Cloud guardian can parse it.
pub fn event(fields: &[&[u8]]) {
    #[cfg(target_os = "solana")]
    unsafe {
        pinocchio::syscalls::sol_log_data(fields.as_ptr() as *const u8, fields.len() as u64);
    }
    #[cfg(not(target_os = "solana"))]
    let _ = fields;
}

/// `a == b` using the `sol_memcmp_` syscall: about `len / 250` compute units
/// instead of a byte loop (which would cost millions for a large program).
pub fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    #[cfg(target_os = "solana")]
    {
        let mut result: i32 = 0;
        // The syscall compares at most this many bytes per call cheaply; chunking
        // keeps each call's length well inside the u64 argument and CU model.
        for (x, y) in a.chunks(1 << 16).zip(b.chunks(1 << 16)) {
            unsafe {
                pinocchio::syscalls::sol_memcmp_(
                    x.as_ptr(),
                    y.as_ptr(),
                    x.len() as u64,
                    &mut result as *mut i32,
                );
            }
            if result != 0 {
                return false;
            }
        }
        true
    }
    #[cfg(not(target_os = "solana"))]
    {
        a == b
    }
}

/// True if every byte is zero, compared in chunks against a static zero block.
pub fn all_zero(bytes: &[u8]) -> bool {
    static ZEROS: [u8; 4096] = [0; 4096];
    bytes
        .chunks(ZEROS.len())
        .all(|c| bytes_equal(c, &ZEROS[..c.len()]))
}
