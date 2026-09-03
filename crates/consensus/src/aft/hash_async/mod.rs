//! Setup-free hash-only asynchronous fallback for the normative PQ AFT
//! profile.
//!
//! This module is an original event-driven implementation of the construction
//! in Das et al., CCS 2024 / ePrint 2024/677. The implementation keeps the
//! paper's static-adversary and private-authenticated-channel assumptions
//! explicit; it must not be cited as adaptively secure.

mod adapter;
mod asks;
mod certificate;
mod gather;
mod gf256;
mod journal;
mod node;
mod proposal_store;
mod reliable;
mod session;
mod signing_fence;

pub use asks::{AsksDealerMaterial, AsksParticipant, AsksReconstruction};
pub use certificate::{
    verify_async_executed_block_certificate, verify_async_ordering_certificate,
    verify_async_parent_proof, verify_async_proposal_availability_certificate,
    AsyncExecutedBlockVotePool, AsyncOrderingVotePool, AsyncProposalAvailabilityVotePool,
    VerifiedAsyncExecutedBlockCertificateV1, VerifiedAsyncOrderingCertificateV1,
    VerifiedAsyncParentProofV1, VerifiedAsyncProposalAvailabilityCertificateV1,
};
pub use gather::{
    IndexCoverGatherAction, IndexCoverGatherState, IndexGatherAction, IndexGatherState,
};
pub use journal::DurableHashAsyncNode;
pub use node::{HashAsyncAction, HashAsyncNode};
pub use proposal_store::DurableAsyncProposalStore;
pub use reliable::{RaAction, RbcAction, ReliableAgreementState, ReliableBroadcastState};
pub use session::{HashAsyncSession, HashAsyncSessionAction};
pub use signing_fence::DurableCrossPathSigningFence;

/// Defensive maximum for one value replicated through RBC/RA in the fallback
/// control plane. Proposals themselves are immutable references, not payloads.
pub const MAX_ASYNC_CONTROL_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub use adapter::{CrossPathDecision, CrossPathDecisionFence, HashAsyncOrderingAdapter};
