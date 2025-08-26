// Path: crates/types/src/app/mod.rs
//! Core application-level data structures like Blocks and Transactions.

use crate::ibc::{UniversalExecutionReceipt, UniversalProofFormat};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;
use serde::{Deserialize, Serialize};

/// A versioned entry in the state tree, containing the actual value
/// along with metadata about when it was last modified.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StateEntry {
    /// The raw value stored by the application or contract.
    pub value: Vec<u8>,
    /// The block height at which this entry was last updated.
    pub block_height: u64,
}

/// Represents the current status of the blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChainStatus {
    /// The current block height.
    pub height: u64,
    /// The timestamp of the latest block.
    pub latest_timestamp: u64,
    /// The total number of transactions processed.
    pub total_transactions: u64,
    /// A flag indicating if the chain is actively running.
    pub is_running: bool,
}

/// A block in the blockchain, generic over the transaction type.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Block<T: Clone> {
    /// The header of the block containing metadata.
    pub header: BlockHeader,
    /// A list of transactions included in the block.
    pub transactions: Vec<T>,
}

/// The header of a block, containing metadata and commitments.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The hash of the previous block's header.
    pub prev_hash: Vec<u8>,
    /// The root hash of the state tree after applying this block's transactions.
    pub state_root: Vec<u8>,
    /// The root hash of the transactions in this block.
    pub transactions_root: Vec<u8>,
    /// The timestamp when the block was created.
    pub timestamp: u64,
    /// The full, sorted list of PeerIds (in bytes) that constituted the validator
    /// set when this block was created.
    pub validator_set: Vec<Vec<u8>>,
    /// The public key (in bytes) of the block producer.
    pub producer: Vec<u8>,
    /// The signature of the block header's hash, signed by the producer.
    pub signature: Vec<u8>,
}

impl BlockHeader {
    /// Creates a hash of the header's core fields for signing.
    pub fn hash(&self) -> Vec<u8> {
        let mut temp = self.clone();
        // Clear the signature before hashing to create a stable payload.
        temp.signature = vec![];
        let serialized = serde_json::to_vec(&temp).unwrap();
        DcryptSha256::digest(&serialized).unwrap().to_bytes()
    }
}

// --- NEW/MODIFIED DATA STRUCTURES FOR IDENTITY AND TRANSACTIONS ---

/// A unique identifier for an on-chain account, derived from the initial public key hash. This address is stable and does not change.
pub type AccountId = [u8; 32];

/// Defines the cryptographic algorithm suite used for a key or signature.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureSuite {
    /// The Ed25519 signature scheme.
    #[default]
    Ed25519,
    /// The CRYSTALS-Dilithium2 post-quantum signature scheme.
    Dilithium2,
}

/// A cryptographic credential defining an account's active key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The algorithm used by this credential.
    pub suite: SignatureSuite,
    /// The SHA-256 hash of the public key.
    pub public_key_hash: [u8; 32],
    /// The block height at which this credential becomes active.
    pub activation_height: u64,
    /// Optional location of the full public key on a Layer 2 or DA layer.
    pub l2_location: Option<String>,
}

/// A cryptographic proof required to execute a key rotation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RotationProof {
    /// The full public key of the key being rotated.
    pub old_public_key: Vec<u8>,
    /// A signature from the old key over the rotation challenge.
    pub old_signature: Vec<u8>,
    /// The full public key of the new key being staged.
    pub new_public_key: Vec<u8>,
    /// A signature from the new key over the rotation challenge.
    pub new_signature: Vec<u8>,
    /// The signature suite of the new key.
    pub target_suite: SignatureSuite,
    /// Optional location of the new public key on a Layer 2 or DA layer.
    pub l2_location: Option<String>,
}

/// The header containing all data required for a valid, replay-protected signature.
/// This data is part of the canonical sign bytes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignHeader {
    /// The stable identifier of the signing account.
    pub account_id: AccountId,
    /// The per-account transaction nonce for replay protection.
    pub nonce: u64,
    /// The ID of the target chain to prevent cross-chain replays.
    pub chain_id: u32,
    /// The version of the transaction format.
    pub tx_version: u8,
}

/// A generic structure holding the signature and related data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureProof {
    /// The signature suite used.
    pub suite: SignatureSuite,
    /// The full public key of the signer.
    pub public_key: Vec<u8>,
    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

// --- UTXO-related structs ---

/// An input for a UTXO transaction, pointing to a previous output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// The hash of the transaction containing the output being spent.
    pub tx_hash: Vec<u8>,
    /// The index of the output in the previous transaction.
    pub output_index: u32,
    /// The signature authorizing the spending of the output.
    pub signature: Vec<u8>,
}

/// An output for a UTXO transaction, creating a new unspent output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// The value of the output.
    pub value: u64,
    /// The public key of the recipient.
    pub public_key: Vec<u8>,
}

/// A transaction following the UTXO model.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXOTransaction {
    /// A list of inputs to be spent.
    pub inputs: Vec<Input>,
    /// A list of new outputs to be created.
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    /// Computes the hash of the transaction.
    pub fn hash(&self) -> Vec<u8> {
        let serialized = serde_json::to_vec(self).unwrap();
        DcryptSha256::digest(&serialized).unwrap().to_bytes()
    }
}

// --- EVOLVED TRANSACTION ENUMS ---

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ChainTransaction {
    /// A transaction initiated by a user or application.
    Application(ApplicationTransaction),
    /// A privileged transaction for system-level changes.
    System(SystemTransaction),
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ApplicationTransaction {
    /// A transaction for a UTXO-based ledger.
    UTXO(UTXOTransaction),
    /// A transaction to deploy a new smart contract.
    DeployContract {
        /// The header containing replay protection data.
        header: SignHeader,
        /// The bytecode of the contract.
        code: Vec<u8>,
        /// The signature and public key of the deployer.
        signature_proof: SignatureProof,
    },
    /// A transaction to call a method on an existing smart contract.
    CallContract {
        /// The header containing replay protection data.
        header: SignHeader,
        /// The address of the contract to call.
        address: Vec<u8>,
        /// The ABI-encoded input data for the contract call.
        input_data: Vec<u8>,
        /// The maximum gas allowed for this transaction.
        gas_limit: u64,
        /// The signature and public key of the caller.
        signature_proof: SignatureProof,
    },
}

impl ApplicationTransaction {
    /// Creates a stable, serializable payload for signing by clearing signature fields.
    /// This MUST use a canonical binary encoding like BCS to prevent malleability.
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, bcs::Error> {
        let mut temp = self.clone();
        match &mut temp {
            ApplicationTransaction::DeployContract {
                signature_proof, ..
            }
            | ApplicationTransaction::CallContract {
                signature_proof, ..
            } => {
                *signature_proof = SignatureProof::default();
            }
            ApplicationTransaction::UTXO(_) => {}
        }
        bcs::to_bytes(&temp)
    }
}

/// A privileged transaction for performing system-level state changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SystemTransaction {
    /// The header containing replay protection data.
    pub header: SignHeader,
    /// The specific action being requested.
    pub payload: SystemPayload,
    /// The signature and public key of the caller.
    pub signature_proof: SignatureProof,
}

impl SystemTransaction {
    /// Creates a stable, serializable payload for signing by clearing signature fields.
    /// This MUST use a canonical binary encoding like BCS to prevent malleability.
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, bcs::Error> {
        let mut temp = self.clone();
        temp.signature_proof = SignatureProof::default();
        bcs::to_bytes(&temp)
    }
}

/// A voting option for a governance proposal.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteOption {
    /// A vote in favor of the proposal.
    Yes,
    /// A vote against the proposal.
    No,
    /// A stronger vote against, indicating a potential veto.
    NoWithVeto,
    /// A vote to abstain, which counts towards quorum but not the threshold.
    Abstain,
}

/// An off-chain attestation signed by a single validator for an oracle request.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OracleAttestation {
    /// The ID of the on-chain request this attestation is for.
    pub request_id: u64,
    /// The data value fetched by the validator.
    pub value: Vec<u8>,
    /// The UNIX timestamp of when the data was fetched.
    pub timestamp: u64,
    /// The validator's signature over `(request_id, value, timestamp)`.
    pub signature: Vec<u8>,
}

impl OracleAttestation {
    /// Creates a deterministic, domain-separated signing payload.
    pub fn to_signing_payload(&self, chain_id: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DEPOT_ORACLE_ATTESTATION_V1::");
        bytes.extend_from_slice(chain_id.as_bytes());
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&DcryptSha256::digest(&self.value).unwrap().to_bytes());
        DcryptSha256::digest(&bytes).unwrap().to_bytes()
    }
}

/// A verifiable proof of off-chain consensus, submitted with the final oracle result.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OracleConsensusProof {
    /// A collection of individual `OracleAttestation`s from a quorum of validators.
    /// Future versions may replace this with an aggregate signature.
    pub attestations: Vec<OracleAttestation>,
}

/// The specific action being requested by a SystemTransaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SystemPayload {
    /// Updates the set of authorities for a Proof-of-Authority chain.
    UpdateAuthorities {
        /// The new list of authority PeerIDs.
        new_authorities: Vec<Vec<u8>>,
    },
    /// Stakes a certain amount for a validator.
    Stake {
        /// The amount to stake.
        amount: u64,
    },
    /// Unstakes a certain amount for a validator.
    Unstake {
        /// The amount to unstake.
        amount: u64,
    },
    /// Schedules a forkless upgrade of a core service module.
    SwapModule {
        /// The type of service to upgrade (e.g., Governance, Custom("fee")).
        service_type: String, // Using String for simplicity in proposals
        /// The new WASM blob for the module.
        module_wasm: Vec<u8>,
        /// The block height at which the upgrade becomes active.
        activation_height: u64,
    },
    /// Casts a vote on a governance proposal.
    Vote {
        /// The unique identifier of the proposal being voted on.
        proposal_id: u64,
        /// The voter's chosen option.
        option: VoteOption,
    },
    /// Submits a request for external data to be brought on-chain by the oracle.
    RequestOracleData {
        /// The URL or identifier for the data to be fetched.
        url: String,
        /// A unique ID for this request, specified by the user.
        request_id: u64,
    },
    /// Submits the final, tallied result and consensus proof for an oracle request.
    SubmitOracleData {
        /// The ID of the request being fulfilled.
        request_id: u64,
        /// The final, aggregated value for the oracle data.
        final_value: Vec<u8>,
        /// The cryptographic proof of consensus from the validator set.
        consensus_proof: OracleConsensusProof,
    },
    /// Verifies a receipt from a foreign chain.
    VerifyForeignReceipt {
        /// The universal receipt containing the canonical operation data.
        receipt: UniversalExecutionReceipt,
        /// The universal proof format containing the cryptographic proof and witness.
        proof: UniversalProofFormat,
    },
    /// Initiates a key rotation for the transaction's signer.
    RotateKey(RotationProof),
}
