// Path: crates/types/src/app/consensus.rs

use crate::app::guardianized::{
    canonical_asymptote_observer_canonical_abort_hash,
    canonical_asymptote_observer_canonical_close_hash,
    canonical_asymptote_observer_challenges_hash, canonical_asymptote_observer_transcripts_hash,
    CollapseState, FinalityTier, GuardianWitnessRecoveryBinding, SealedFinalityProof,
};
use crate::app::{
    timestamp_millis_to_legacy_seconds, to_root_hash, AccountId, ActiveKeyRecord, BlockHeader,
    ChainTransaction, SignatureSuite, StateRoot,
};
use crate::app::{GuardianLogCheckpoint, GuardianQuorumCertificate};
use crate::codec;
use crate::error::StateError;
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

mod state_keys {
    use super::*;
    include!("consensus/state_keys.rs");
}

mod validator_sets {
    use super::*;
    include!("consensus/validator_sets.rs");
}

mod artifacts {
    use super::*;
    include!("consensus/artifacts.rs");
}

mod collapse {
    use super::*;
    include!("consensus/collapse.rs");
}

#[cfg(test)]
#[path = "consensus/tests.rs"]
mod tests;

mod messages {
    use super::*;
    include!("consensus/messages.rs");
}

use artifacts::recovered_segment_fold_start_height;
use collapse::{
    encode_systematic_gf256_k_of_n_shards, encode_systematic_xor_k_of_k_plus_1_shards,
    is_systematic_xor_parity_coding, recover_systematic_gf256_k_of_n_slot_payload_bytes,
    recover_systematic_xor_k_of_k_plus_1_slot_payload_bytes,
};

pub use artifacts::*;
pub use collapse::*;
pub use messages::*;
pub use state_keys::*;
pub use validator_sets::*;
