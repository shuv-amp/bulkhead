//! Floor errors. Codes start at 7000 so they never collide with programs'
//! own ranges (native 0+, Anchor 6000+) or with the abort code `0x464C4F52`.

use pinocchio::error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FloorError {
    InvalidInstruction = 7000,
    NotAFloorConfig,
    WrongConfigAddress,
    WrongAuthorityAddress,
    AlreadyRegistered,
    NotLoaderV3,
    ProgramMismatch,
    NotCurrentAuthority,
    InvalidGuardians,
    InvalidThreshold,
    InvalidInterval,
    InvalidDelay,
    MissingSignature,
    NotOwner,
    NotLiveGuardian,
    NoQuorum,
    NotLive,
    NotAborted,
    NotCanonicalAbort,
    NoAbortBuffer,
    AbortAlreadyStaged,
    WrongBuffer,
    BufferNotFrozen,
    SnapshotMismatch,
    NoValidSnapshot,
    ProposalPending,
    NoProposal,
    WrongProposalKind,
    NotExecutable,
    Vetoed,
    Expired,
    CannotEject,
    WrongSysvar,
    WrongProgram,
    Overflow,
    AbortDoesNotFit,
}

impl From<FloorError> for ProgramError {
    fn from(e: FloorError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
