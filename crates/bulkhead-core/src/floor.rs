//! Tier 0 ("Floor") logic: the pure checks the Floor program runs.
//!
//! Floor holds a program's loader-v3 upgrade authority. Facts this module
//! encodes (sources in docs/06-FLOOR.md §8):
//! - A program may CPI loader-v3 only for `Upgrade`, `SetAuthority`,
//!   `SetAuthorityChecked` and `Close` (agave `program-runtime/src/cpi.rs`).
//!   Floor therefore never *writes* a buffer. Anyone writes one, hands its
//!   authority to Floor, and Floor *verifies* the bytes on-chain. Once Floor is
//!   the authority nobody can write to it again, so the bytes are frozen.
//! - `Upgrade` copies the buffer into programdata and zero-fills the rest, and
//!   a program can be upgraded at most once per slot. The new code is visible
//!   from the next slot.
//! - SIMD-0500 (`disable_sbpf_v0_v1_v2_deployment`) makes `Upgrade` accept only
//!   sBPF v3 (`e_flags == 3`; agave's `max_sbpf_version` is V3). After it
//!   activates, a stopped v0/v1/v2 program can only come back as a v3 build.
//! - Loader-v4 was abandoned (its feature id is
//!   `LoaderV4WasAbandoned11111111111111111111111`), so swapping in an abort
//!   binary through loader-v3 is the only way to stop a program.
//!
//! What Floor adds to the bare abort pattern (Dean Little's `sbpf-asm-abort`):
//! - the stop is separated from the power to deploy code;
//! - the abort binary is pre-staged and verified, so stopping is one small
//!   instruction any single live guardian can send;
//! - undoing a stop is cheap and cannot smuggle in new code: a **snapshot**
//!   buffer, verified on-chain to be byte-identical to the live program, can be
//!   restored by a guardian quorum in one instruction;
//! - the abort binary says why it fails (a log line and a distinctive error).

use crate::consts::{EM_BPF, EM_SBPF, MIN_UPGRADE_DELAY_S};

// ---------------------------------------------------------------------------
// ELF version check (SIMD-0500)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfInfo {
    pub e_machine: u16,
    pub e_flags: u32,
}

/// Reads `e_machine` (offset 18) and `e_flags` (offset 48) from a 64-bit
/// little-endian ELF header used by the Solana loaders.
pub fn elf_info(header: &[u8]) -> Option<ElfInfo> {
    if header.len() < 52 || &header[0..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        return None;
    }
    let e_machine = u16::from_le_bytes([header[18], header[19]]);
    let e_flags = u32::from_le_bytes([header[48], header[49], header[50], header[51]]);
    if e_machine != EM_BPF && e_machine != EM_SBPF {
        return None;
    }
    Some(ElfInfo { e_machine, e_flags })
}

/// sBPF version number that `e_flags` must equal for loader-v3 to accept a
/// deployment once SIMD-0500 is active. `e_flags` 4 decodes to V4, which agave
/// does not enable (`max_sbpf_version = V3`); 5+ is reserved.
pub const SBPF_V3_FLAGS: u32 = 3;

/// True if loader-v3 will still accept this ELF once SIMD-0500 is active.
pub fn deployable_after_simd0500(info: Option<ElfInfo>) -> bool {
    matches!(info, Some(i) if i.e_machine == EM_BPF && i.e_flags == SBPF_V3_FLAGS)
}

/// Earliest time a proposed upgrade can execute. `requested_delay_s` below the
/// constant minimum is raised to it.
pub fn upgrade_eta(now_s: i64, requested_delay_s: i64) -> i64 {
    now_s + requested_delay_s.max(MIN_UPGRADE_DELAY_S)
}

// ---------------------------------------------------------------------------
// Loader-v3 account layout (solana-loader-v3-interface `state.rs`)
// ---------------------------------------------------------------------------

/// Offset of the program bytes inside a buffer account.
pub const BUFFER_DATA_OFFSET: usize = 37;
/// Offset of the program bytes inside a programdata account.
pub const PROGRAMDATA_DATA_OFFSET: usize = 45;
/// Size of a program account.
pub const PROGRAM_ACCOUNT_LEN: usize = 36;

const TAG_BUFFER: u32 = 1;
const TAG_PROGRAM: u32 = 2;
const TAG_PROGRAMDATA: u32 = 3;

fn tag(data: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(0..4)?.try_into().ok()?))
}

fn opt_pubkey(data: &[u8], at: usize) -> Option<Option<[u8; 32]>> {
    match *data.get(at)? {
        0 => Some(None),
        1 => Some(Some(data.get(at + 1..at + 33)?.try_into().ok()?)),
        _ => None,
    }
}

/// Buffer account → its authority (`None` = no authority). `None` overall if
/// the data is not a well-formed buffer header.
pub fn buffer_authority(data: &[u8]) -> Option<Option<[u8; 32]>> {
    if tag(data)? != TAG_BUFFER || data.len() < BUFFER_DATA_OFFSET {
        return None;
    }
    opt_pubkey(data, 4)
}

/// Program account → its programdata address.
pub fn program_programdata(data: &[u8]) -> Option<[u8; 32]> {
    if tag(data)? != TAG_PROGRAM || data.len() < PROGRAM_ACCOUNT_LEN {
        return None;
    }
    data.get(4..36)?.try_into().ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramDataHeader {
    /// Slot of the last deploy or upgrade.
    pub slot: u64,
    pub upgrade_authority: Option<[u8; 32]>,
}

/// Programdata account → its header.
pub fn programdata_header(data: &[u8]) -> Option<ProgramDataHeader> {
    if tag(data)? != TAG_PROGRAMDATA || data.len() < PROGRAMDATA_DATA_OFFSET {
        return None;
    }
    Some(ProgramDataHeader {
        slot: u64::from_le_bytes(data.get(4..12)?.try_into().ok()?),
        upgrade_authority: opt_pubkey(data, 12)?,
    })
}

// ---------------------------------------------------------------------------
// Snapshot: a buffer that restores exactly the code that is live now
// ---------------------------------------------------------------------------

/// True if upgrading from `buffer_program` would leave `programdata_program`
/// (the region after the programdata header) byte-for-byte unchanged:
/// `Upgrade` copies the buffer to the front and zero-fills the rest, so the
/// buffer must equal the prefix and everything after it must be zero.
///
/// The Floor program performs the same comparison with the `sol_memcmp_`
/// syscall (a few thousand compute units for a 500 KB program).
pub fn snapshot_matches(buffer_program: &[u8], programdata_program: &[u8]) -> bool {
    let n = buffer_program.len();
    n > 0
        && n <= programdata_program.len()
        && programdata_program[..n] == *buffer_program
        && programdata_program[n..].iter().all(|&b| b == 0)
}

/// How long an ELF says it is: the furthest byte that its file header, its
/// program and section header tables, its segments and its sections occupy.
/// `None` if `elf` is not a 64-bit little-endian ELF whose tables lie inside
/// it, or if it has more than 64 segments or 1,024 sections.
///
/// A snapshot must be at least this long, not only identical. The loader
/// deploys the buffer's own bytes, so a binary cut before its trailing zeros
/// (the last section header's zero fields) matched the live code but could not
/// be redeployed: pinned by anyone, it took the quorum's restore away
/// (docs/09, finding 88). A `NOBITS` section holds no file bytes, but the
/// loader's v0 checks still require its offset and size to lie inside the
/// binary, so it counts like any other (finding 115).
pub fn elf_extent(elf: &[u8]) -> Option<usize> {
    if elf.len() < 64 || elf[..4] != *b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return None;
    }
    let u16_at = |at: usize| -> Option<usize> {
        Some(u16::from_le_bytes(elf.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize)
    };
    let u64_at = |at: usize| -> Option<usize> {
        usize::try_from(u64::from_le_bytes(
            elf.get(at..at.checked_add(8)?)?.try_into().ok()?,
        ))
        .ok()
    };
    let (phoff, shoff) = (u64_at(0x20)?, u64_at(0x28)?);
    let (phentsize, phnum) = (u16_at(0x36)?, u16_at(0x38)?);
    let (shentsize, shnum) = (u16_at(0x3a)?, u16_at(0x3c)?);
    if phnum > 64 || shnum > 1024 || (phnum > 0 && phentsize < 56) || (shnum > 0 && shentsize < 64)
    {
        return None;
    }
    let mut end = 64usize;
    let table = |off: usize, n: usize, size: usize| -> Option<usize> {
        off.checked_add(n.checked_mul(size)?)
    };
    if phnum > 0 {
        end = end.max(table(phoff, phnum, phentsize)?);
    }
    if shnum > 0 {
        end = end.max(table(shoff, shnum, shentsize)?);
    }
    for i in 0..phnum {
        let h = phoff.checked_add(i.checked_mul(phentsize)?)?;
        end = end.max(u64_at(h.checked_add(8)?)?.checked_add(u64_at(h.checked_add(32)?)?)?);
    }
    for i in 0..shnum {
        let h = shoff.checked_add(i.checked_mul(shentsize)?)?;
        end = end.max(u64_at(h.checked_add(24)?)?.checked_add(u64_at(h.checked_add(32)?)?)?);
    }
    if end > elf.len() {
        return None;
    }
    Some(end)
}

/// A snapshot the loader can redeploy: `snapshot_matches`, and at least as
/// long as the live ELF says it is (`elf_extent`; finding 88).
pub fn snapshot_restorable(buffer_program: &[u8], programdata_program: &[u8]) -> bool {
    match elf_extent(programdata_program) {
        Some(extent) => {
            buffer_program.len() >= extent && snapshot_matches(buffer_program, programdata_program)
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Restore rules
// ---------------------------------------------------------------------------

/// Which buffer a restore installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreSource {
    /// The pinned snapshot: provably the code that ran before the abort.
    Snapshot,
    /// A buffer the owner proposed (a fix). New code.
    Proposed,
}

/// Whether a restore may execute now.
/// - `Snapshot`: a live guardian quorum, instantly. It cannot introduce new
///   code, so no delay protects anyone; the quorum only judges whether the old
///   code is safe to run again.
/// - `Proposed`: fast if a live quorum approved exactly this Floor-owned (so
///   frozen) buffer; otherwise only after the delay, if no guardian vetoed and
///   the proposal has not expired.
#[allow(clippy::too_many_arguments)]
pub fn can_restore(
    source: RestoreSource,
    buffer: &[u8; 32],
    approved_buffer: &[u8; 32],
    quorum_ok: bool,
    vetoed: bool,
    now_s: i64,
    eta_s: i64,
    expires_s: i64,
) -> bool {
    match source {
        RestoreSource::Snapshot => quorum_ok,
        RestoreSource::Proposed => {
            (quorum_ok && buffer == approved_buffer)
                || (!vetoed && now_s >= eta_s && now_s < expires_s)
        }
    }
}

/// Whether Floor may close a buffer it holds (issue #37). A buffer stops being
/// the pin when it is replaced or the live code changes, and a proposal's
/// buffer is orphaned by a cancel or a stop; nothing else ever closes them, so
/// their rent would be locked for good. Three buffers are never closed: the
/// staged abort buffer (the stop), the pinned snapshot (the quorum's restore),
/// and the buffer the pending proposal names (`pending_buffer`, zero when the
/// proposal is not an upgrade or restore).
pub fn buffer_closable(
    buffer: &[u8; 32],
    abort_buffer: &[u8; 32],
    snapshot_buffer: &[u8; 32],
    pending_buffer: &[u8; 32],
) -> bool {
    *buffer != [0; 32]
        && buffer != abort_buffer
        && buffer != snapshot_buffer
        && buffer != pending_buffer
}

// ---------------------------------------------------------------------------
// The abort binary, assembled here from source
// ---------------------------------------------------------------------------
//
//     rodata (vaddr 0):  ABORT_MESSAGE, zero-padded to 8 bytes
//     text (vaddr 2^32):
//         mov64 r1, 0                 ; message address (rodata starts at 0)
//         mov64 r2, ABORT_MESSAGE.len()
//         syscall sol_log_            ; call imm=murmur3("sol_log_"), src=0
//         mov64 r0, FLOOR_ABORT_CODE  ; InstructionError::Custom(0x464C4F52)
//         exit
//
// The layout follows the sBPF v3 strict ELF rules (SIMD-0189, solana-sbpf
// `load_with_strict_parser`): a canonical 64-byte header with e_flags = 3,
// program headers immediately after it, a read-only PT_LOAD at vaddr 0 and an
// executable PT_LOAD at vaddr 2^32, each starting where the previous one ends.
// The Python reference builds the same bytes independently, and the LiteSVM
// tests deploy it through a real loader-v3 `Upgrade`.

/// Error every instruction returns once a program is stopped. ASCII "FLOR".
pub const FLOOR_ABORT_CODE: u32 = 0x464C_4F52;

/// The line the stopped program logs on every call.
pub const ABORT_MESSAGE: &[u8] =
    b"Program stopped by its Bulkhead Floor guardians. The stop moves no funds. Restart needs a guardian quorum.";

/// murmur3_32 with seed 0, the hash solana-sbpf uses for syscall ids.
pub const fn murmur3_32(data: &[u8]) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;
    let mut h: u32 = 0;
    let n = data.len();
    let mut i = 0;
    while i + 4 <= n {
        let mut k = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe654_6b64);
        i += 4;
    }
    let mut k: u32 = 0;
    let rem = n - i;
    if rem >= 3 {
        k ^= (data[i + 2] as u32) << 16;
    }
    if rem >= 2 {
        k ^= (data[i + 1] as u32) << 8;
    }
    if rem >= 1 {
        k ^= data[i] as u32;
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= n as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

const MM_BYTECODE_START: u64 = 1 << 32;
const EHDR: usize = 64;
const PHDR: usize = 56;
const INSN: usize = 8;
const PF_X: u32 = 1;
const PF_R: u32 = 4;

const fn pad8(n: usize) -> usize {
    n.div_ceil(INSN) * INSN
}

const RODATA_LEN: usize = pad8(ABORT_MESSAGE.len());
const TEXT_LEN: usize = 5 * INSN;
const TEXT_LEN_MINIMAL: usize = 2 * INSN;

/// Size of [`ABORT_ELF`].
pub const ABORT_ELF_LEN: usize = EHDR + 2 * PHDR + RODATA_LEN + TEXT_LEN;
/// Size of [`ABORT_ELF_MINIMAL`].
pub const ABORT_ELF_MINIMAL_LEN: usize = EHDR + PHDR + TEXT_LEN_MINIMAL;

const fn put(mut out: [u8; 512], at: usize, bytes: &[u8]) -> [u8; 512] {
    let mut i = 0;
    while i < bytes.len() {
        out[at + i] = bytes[i];
        i += 1;
    }
    out
}

const fn ehdr(out: [u8; 512], entry: u64, phnum: u16) -> [u8; 512] {
    let out = put(out, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0]); // 64-bit, LE, v1, SysV
    let out = put(out, 16, &3u16.to_le_bytes()); // e_type ET_DYN
    let out = put(out, 18, &EM_BPF.to_le_bytes());
    let out = put(out, 20, &1u32.to_le_bytes()); // e_version
    let out = put(out, 24, &entry.to_le_bytes());
    let out = put(out, 32, &(EHDR as u64).to_le_bytes()); // e_phoff
    let out = put(out, 48, &SBPF_V3_FLAGS.to_le_bytes());
    let out = put(out, 52, &(EHDR as u16).to_le_bytes());
    let out = put(out, 54, &(PHDR as u16).to_le_bytes());
    let out = put(out, 56, &phnum.to_le_bytes());
    put(out, 58, &64u16.to_le_bytes()) // e_shentsize (no sections)
}

const fn phdr(
    out: [u8; 512],
    at: usize,
    flags: u32,
    offset: usize,
    vaddr: u64,
    len: usize,
) -> [u8; 512] {
    let out = put(out, at, &1u32.to_le_bytes()); // PT_LOAD
    let out = put(out, at + 4, &flags.to_le_bytes());
    let out = put(out, at + 8, &(offset as u64).to_le_bytes());
    let out = put(out, at + 16, &vaddr.to_le_bytes());
    let out = put(out, at + 24, &vaddr.to_le_bytes()); // p_paddr
    let out = put(out, at + 32, &(len as u64).to_le_bytes()); // p_filesz
    put(out, at + 40, &(len as u64).to_le_bytes()) // p_memsz
}

/// One immediate-form sBPF instruction: opcode, dst register, src register 0,
/// offset 0, immediate. (`CALL_IMM` with src 0 is a syscall.)
const fn insn(opc: u8, dst: u8, imm: i32) -> [u8; 8] {
    let i = imm.to_le_bytes();
    [opc, dst, 0, 0, i[0], i[1], i[2], i[3]]
}

const MOV64_IMM: u8 = 0xb7;
const CALL_IMM: u8 = 0x85;
const EXIT: u8 = 0x95;

const fn build_abort() -> [u8; 512] {
    let text_at = EHDR + 2 * PHDR + RODATA_LEN;
    let out = ehdr([0u8; 512], MM_BYTECODE_START, 2);
    let out = phdr(out, EHDR, PF_R, EHDR + 2 * PHDR, 0, RODATA_LEN);
    let out = phdr(out, EHDR + PHDR, PF_X, text_at, MM_BYTECODE_START, TEXT_LEN);
    let out = put(out, EHDR + 2 * PHDR, ABORT_MESSAGE);
    let out = put(out, text_at, &insn(MOV64_IMM, 1, 0));
    let len = ABORT_MESSAGE.len() as i32;
    let out = put(out, text_at + 8, &insn(MOV64_IMM, 2, len));
    let sol_log = murmur3_32(b"sol_log_") as i32;
    let out = put(out, text_at + 16, &insn(CALL_IMM, 0, sol_log));
    let code = FLOOR_ABORT_CODE as i32;
    let out = put(out, text_at + 24, &insn(MOV64_IMM, 0, code));
    put(out, text_at + 32, &insn(EXIT, 0, 0))
}

const fn build_abort_minimal() -> [u8; 512] {
    let text_at = EHDR + PHDR;
    let out = ehdr([0u8; 512], MM_BYTECODE_START, 1);
    let out = phdr(
        out,
        EHDR,
        PF_X,
        text_at,
        MM_BYTECODE_START,
        TEXT_LEN_MINIMAL,
    );
    let code = FLOOR_ABORT_CODE as i32;
    let out = put(out, text_at, &insn(MOV64_IMM, 0, code));
    put(out, text_at + 8, &insn(EXIT, 0, 0))
}

const fn take<const N: usize>(src: [u8; 512]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = src[i];
        i += 1;
    }
    out
}

/// The canonical abort binary: logs [`ABORT_MESSAGE`], fails with
/// [`FLOOR_ABORT_CODE`].
pub const ABORT_ELF: [u8; ABORT_ELF_LEN] = take(build_abort());
/// Fallback with no syscall (in case a future runtime ever changes logging):
/// only fails with [`FLOOR_ABORT_CODE`]. Floor accepts either.
pub const ABORT_ELF_MINIMAL: [u8; ABORT_ELF_MINIMAL_LEN] = take(build_abort_minimal());

/// True if `program` (a buffer's bytes after its header) is exactly one of the
/// two canonical abort binaries.
pub fn is_canonical_abort(program: &[u8]) -> bool {
    program == ABORT_ELF.as_slice() || program == ABORT_ELF_MINIMAL.as_slice()
}
