use serde::{Deserialize, Serialize};
use parity_scale_codec::{Encode, Decode};
use crate::app::AccountId;

/// The specific hardware requirements.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HardwareSpecs {
    pub provider_type: String, // e.g. "akash", "aws"
    pub region: String,
    pub instance_type: String, // e.g. "gpu-h100"
    pub image: String,         // Docker image hash
}

/// The immutable, on-chain record of a compute request.
/// This acts as the "Challenge" in the challenge-response protocol.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct JobTicket {
    pub request_id: u64,
    pub owner: AccountId,
    pub specs: HardwareSpecs,
    pub max_bid: u64,
    pub expiry_height: u64, // Consensus block height deadline
    pub security_tier: u8,
    pub nonce: u64,         // Anti-replay within the service
}

/// The proof submitted by a Solver to claim the reward.
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct ProvisioningReceipt {
    pub request_id: u64,
    /// The Hash of the canonical JobTicket. 
    /// The Provider MUST include this in their signed acknowledgment.
    pub ticket_root: [u8; 32], 
    pub provider_id: Vec<u8>,       // Provider's public key identifier
    pub endpoint_uri: String,
    pub machine_id: String,         // Unique hardware ID / instance ID
    /// A signature from the Provider over (ticket_root || machine_id || endpoint_uri)
    pub provider_signature: Vec<u8>, 
}