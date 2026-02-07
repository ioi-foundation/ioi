use serde::{Deserialize, Serialize};

/// Public inputs for the Ethereum Beacon Update circuit.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BeaconPublicInputs {
    /// The trusted state root before this update.
    pub previous_state_root: [u8; 32],
    /// The new state root being attested to.
    pub new_state_root: [u8; 32],
    /// The slot number of the new header.
    pub slot: u64,
}

/// Public inputs for the State Inclusion circuit.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StateInclusionPublicInputs {
    /// The state root against which inclusion is being proven.
    pub state_root: [u8; 32],
    /// The account/storage key being verified.
    pub key: Vec<u8>,
    /// The RLP-encoded value being verified.
    pub value: Vec<u8>,
    /// The proof scheme identifier (0=Mpt, 1=Verkle).
    pub scheme_id: u8,
}