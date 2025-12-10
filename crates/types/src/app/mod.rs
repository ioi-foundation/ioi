// Path: crates/types/src/app/mod.rs
//! Core application-level data structures like Blocks and Transactions.

/// Data structures for agentic semantic consensus.
pub mod agentic;
/// Data structures related to consensus, such as the canonical validator set
pub mod consensus;
/// Data structures for on-chain identity, including the canonical AccountId.
pub mod identity;
/// Data structures for reporting and penalizing misbehavior.
pub mod penalties;
/// Data structures for deterministic block timing.
pub mod timing;

pub use consensus::*;
// Only re-export types that are actually defined in identity.rs
pub use agentic::*;
pub use identity::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, BinaryMeasurement, BootAttestation,
    ChainId, Credential, GuardianReport, SignatureSuite,
};
pub use penalties::*;
pub use timing::*;

use crate::error::{CoreError, StateError};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// A fixed-size, 32-byte hash of a transaction.
pub type TxHash = [u8; 32];

/// Represents the proven outcome of a key's existence in the state.
/// This enum is canonically encoded for transport and storage.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Membership {
    /// The key is present in the state with the associated value.
    Present(Vec<u8>),
    /// The key is provably absent from the state.
    Absent,
}

impl Membership {
    /// Consumes the Membership enum and returns an Option<Vec<u8>>, which is a
    /// common pattern for application logic using the verified result.
    pub fn into_option(self) -> Option<Vec<u8>> {
        match self {
            Membership::Present(v) => Some(v),
            Membership::Absent => None,
        }
    }
}

/// A versioned entry in the state tree, containing the actual value
/// along with metadata about when it was last modified.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct StateEntry {
    /// The raw value stored by the application or contract.
    pub value: Vec<u8>,
    /// The block height at which this entry was last updated.
    pub block_height: u64,
}

/// Represents the current status of the blockchain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode, Default)]
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Block<T: Clone> {
    /// The header of the block containing metadata.
    pub header: BlockHeader,
    /// A list of transactions included in the block.
    pub transactions: Vec<T>,
}

/// The full, potentially variable-length cryptographic commitment over the state.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct StateRoot(pub Vec<u8>);

/// A fixed-size, 32-byte hash of a StateRoot, used as a key for anchored state views.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StateAnchor(pub [u8; 32]);

/// A fixed-size, 32-byte cryptographic hash of a state tree's root.
/// This is used as a key in versioning maps to avoid heap allocations.
pub type RootHash = [u8; 32];

/// A helper to convert arbitrary commitment bytes into a fixed-size RootHash.
///
/// - If `bytes` are already 32 bytes (e.g., IAVL/SMT), we use them directly.
/// - Otherwise (e.g., Verkle KZG commitment), we hash the bytes with SHA-256 to
///   obtain a stable 32-byte key suitable for indexing historical versions.
pub fn to_root_hash<C: AsRef<[u8]>>(c: C) -> Result<RootHash, StateError> {
    let s = c.as_ref();
    if s.len() == 32 {
        // Exact fit: treat as canonical root hash
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Ok(out)
    } else {
        // Map arbitrary-length commitments to a 32-byte key via SHA-256
        let digest = dcrypt::algorithms::hash::Sha256::digest(s)
            .map_err(|e| StateError::Backend(e.to_string()))?
            .to_bytes();
        let len = digest.len();
        digest.try_into().map_err(|_| {
            StateError::InvalidValue(format!("Invalid hash length: expected 32, got {}", len))
        })
    }
}

impl Encode for StateRoot {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        self.0.encode_to(dest);
    }
}
impl Decode for StateRoot {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(StateRoot(Vec::<u8>::decode(input)?))
    }
}

impl Encode for StateAnchor {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        self.0.encode_to(dest);
    }
}
impl Decode for StateAnchor {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(StateAnchor(<[u8; 32]>::decode(input)?))
    }
}

impl StateRoot {
    /// Computes the deterministic anchor key for this state root.
    pub fn to_anchor(&self) -> Result<StateAnchor, CoreError> {
        let hash = DcryptSha256::digest(&self.0)
            .map_err(|e| CoreError::Custom(e.to_string()))?
            .to_bytes();
        let len = hash.len();
        Ok(StateAnchor(hash.try_into().map_err(|_| {
            CoreError::Custom(format!("Invalid hash length: expected 32, got {}", len))
        })?))
    }
}

// Add conversions to make them easier to work with
impl AsRef<[u8]> for StateRoot {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for StateAnchor {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The header of a block, containing metadata and commitments.
///
/// MODIFIED: Includes Oracle-anchored fields `oracle_counter` and `oracle_trace_hash`
/// to enforce non-equivocation via the Signing Oracle.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The view/round in which this block was produced.
    pub view: u64,
    /// The hash of the parent block's header.
    pub parent_hash: [u8; 32],
    /// The state root committed by the parent block (the state against which this block is verified).
    pub parent_state_root: StateRoot,
    /// The state root this block commits to after applying its transactions.
    pub state_root: StateRoot,
    /// The root hash of the transactions in this block.
    pub transactions_root: Vec<u8>,
    /// The UNIX timestamp (in seconds) when the block was created.
    pub timestamp: u64,
    /// The total gas consumed by transactions in this block.
    pub gas_used: u64,
    /// The full, sorted list of PeerIds (in bytes) that constituted the validator
    /// set when this block was created.
    pub validator_set: Vec<Vec<u8>>,
    /// The stable AccountId of the block producer.
    pub producer_account_id: AccountId,
    /// The signature suite of the key used to sign this block.
    pub producer_key_suite: SignatureSuite,
    /// The hash of the public key used to sign this block.
    pub producer_pubkey_hash: [u8; 32],
    /// The full public key bytes. Mandatory if state stores only hashes.
    pub producer_pubkey: Vec<u8>,

    // --- Oracle-Anchored Signing Extensions ---
    // These fields enable non-equivocation enforcement by binding signatures
    // to a monotonic counter and execution trace from a trusted Signing Oracle.
    // This is a prerequisite for protocols like A-DMFT.
    /// The monotonic counter from the Signing Oracle.
    /// Enforces strict ordering of signatures to prevent equivocation.
    pub oracle_counter: u64,
    /// The cryptographic trace hash from the Signing Oracle.
    /// Links this block signature to the previous signature history.
    pub oracle_trace_hash: [u8; 32],
    // ------------------------------------------
    /// The signature of the block header's canonical preimage.
    /// Signed payload is: Preimage || oracle_counter || oracle_trace_hash
    pub signature: Vec<u8>,
}

/// A container for the result of a signing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// The raw cryptographic signature bytes.
    pub signature: Vec<u8>,
    /// The monotonic counter value enforced by the Signing Oracle.
    pub counter: u64,
    /// The execution trace hash binding this signature to the Oracle's history.
    pub trace_hash: [u8; 32],
}

/// A domain tag to prevent hash collisions for different signature purposes.
#[derive(Encode, Decode)]
pub enum SigDomain {
    /// The domain for version 1 of the block header signing preimage.
    BlockHeaderV1,
}

impl BlockHeader {
    /// Creates a hash of the header's core fields for signing.
    pub fn hash(&self) -> Result<Vec<u8>, CoreError> {
        let mut temp = self.clone();
        temp.signature = vec![];
        let serialized = crate::codec::to_bytes_canonical(&temp).map_err(CoreError::Custom)?;
        let digest =
            DcryptSha256::digest(&serialized).map_err(|e| CoreError::Custom(e.to_string()))?;
        Ok(digest.to_bytes())
    }

    /// Creates the canonical, domain-separated byte string that is hashed for signing.
    ///
    /// NOTE: This does *not* include the `oracle_counter` or `oracle_trace_hash`, as those
    /// are outputs of the signing process. The Oracle constructs the final signed payload
    /// by appending those values to the hash of this preimage.
    pub fn to_preimage_for_signing(&self) -> Result<Vec<u8>, CoreError> {
        crate::codec::to_bytes_canonical(&(
            SigDomain::BlockHeaderV1 as u8,
            self.height,
            self.view,
            self.parent_hash,
            &self.parent_state_root.0,
            &self.state_root.0,
            &self.transactions_root,
            self.timestamp,
            self.gas_used,
            &self.validator_set,
            &self.producer_account_id,
            &self.producer_key_suite,
            &self.producer_pubkey_hash,
            &self.producer_pubkey,
        ))
        .map_err(CoreError::Custom)
    }
}

/// A cryptographic proof required to execute a key rotation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
pub struct SignHeader {
    /// The stable identifier of the signing account.
    pub account_id: AccountId,
    /// The per-account transaction nonce for replay protection.
    pub nonce: u64,
    /// The ID of the target chain to prevent cross-chain replays.
    pub chain_id: ChainId,
    /// The version of the transaction format.
    pub tx_version: u8,
}

/// A generic structure holding the signature and related data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct SignatureProof {
    /// The signature suite used.
    pub suite: SignatureSuite,
    /// The full public key of the signer.
    pub public_key: Vec<u8>,
    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

/// An input for a UTXO transaction, pointing to a previous output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Input {
    /// The hash of the transaction containing the output being spent.
    pub tx_hash: Vec<u8>,
    /// The index of the output in the previous transaction.
    pub output_index: u32,
    /// The signature authorizing the spending of the output.
    pub signature: Vec<u8>,
}

/// An output for a UTXO transaction, creating a new unspent output.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Output {
    /// The value of the output.
    pub value: u64,
    /// The public key of the recipient.
    pub public_key: Vec<u8>,
}

/// A transaction following the UTXO model.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct UTXOTransaction {
    /// A list of inputs to be spent.
    pub inputs: Vec<Input>,
    /// A list of new outputs to be created.
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    /// Creates a stable, serializable payload for hashing or signing.
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, String> {
        crate::codec::to_bytes_canonical(self)
    }
    /// Computes the hash of the transaction.
    pub fn hash(&self) -> Result<Vec<u8>, CoreError> {
        let serialized = self.to_sign_bytes().map_err(CoreError::Custom)?;
        let digest =
            DcryptSha256::digest(&serialized).map_err(|e| CoreError::Custom(e.to_string()))?;
        Ok(digest.to_bytes())
    }
}

/// The category of a governance proposal.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ProposalType {
    /// A proposal to change a registered on-chain parameter.
    ParameterChange,
    /// A proposal to perform a coordinated software upgrade.
    SoftwareUpgrade,
    /// A generic proposal for signaling community intent, with no on-chain execution.
    Text,
    /// A custom proposal type for application-specific governance.
    Custom(String),
}

/// The final tally of votes for a governance proposal.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TallyResult {
    /// The total voting power that voted "Yes".
    pub yes: u64,
    /// The total voting power that voted "No".
    pub no: u64,
    /// The total voting power that voted "No with Veto".
    pub no_with_veto: u64,
    /// The total voting power that chose to abstain.
    pub abstain: u64,
}

/// The current status of a governance proposal in its lifecycle.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum ProposalStatus {
    /// The proposal is in the deposit period.
    DepositPeriod,
    /// The proposal is in the voting period.
    VotingPeriod,
    /// The proposal has passed.
    Passed,
    /// The proposal has been rejected.
    Rejected,
}

/// A governance proposal submitted to the chain.
#[derive(Serialize, Deserialize, Debug, Clone, Encode, Decode)]
pub struct Proposal {
    /// The unique identifier for the proposal.
    pub id: u64,
    /// The title of the proposal.
    pub title: String,
    /// A detailed description of the proposal.
    pub description: String,
    /// The type of the proposal.
    pub proposal_type: ProposalType,
    /// The current status of the proposal.
    pub status: ProposalStatus,
    /// The address of the account that submitted the proposal.
    pub submitter: Vec<u8>,
    /// The block height at which the proposal was submitted.
    pub submit_height: u64,
    /// The block height at which the deposit period ends.
    pub deposit_end_height: u64,
    /// The block height at which the voting period starts.
    pub voting_start_height: u64,
    /// The block height at which the voting period ends.
    pub voting_end_height: u64,
    /// The total amount deposited for this proposal.
    pub total_deposit: u64,
    /// The final tally of votes, populated after the voting period ends.
    pub final_tally: Option<TallyResult>,
}

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ChainTransaction {
    /// A transaction initiated by a user or application.
    Application(ApplicationTransaction),
    /// A privileged transaction for system-level changes.
    System(Box<SystemTransaction>),
    /// [NEW] A semantic transition proposed by a DIM committee.
    Semantic {
        /// The canonical result (JSON/Blob).
        result: Vec<u8>,
        /// The proof (BLS Aggregate) that the committee agreed on this result.
        proof: CommitteeCertificate,
        /// The transaction header (must match a committee leader/relayer).
        header: SignHeader,
    },
}

impl ChainTransaction {
    /// Computes the canonical SHA-256 hash of the transaction.
    /// This is the single source of truth for transaction identity.
    pub fn hash(&self) -> Result<TxHash, CoreError> {
        let bytes = crate::codec::to_bytes_canonical(self).map_err(CoreError::Custom)?;

        let digest = DcryptSha256::digest(&bytes).map_err(|e| CoreError::Crypto(e.to_string()))?;

        let hash_bytes = digest.to_bytes();
        hash_bytes
            .try_into()
            .map_err(|_| CoreError::Crypto("Invalid hash length".into()))
    }
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, String> {
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
        crate::codec::to_bytes_canonical(&temp)
    }
}

/// A privileged transaction for performing system-level state changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, String> {
        let mut temp = self.clone();
        temp.signature_proof = SignatureProof::default();
        crate::codec::to_bytes_canonical(&temp)
    }
}

/// A voting option for a governance proposal.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
    pub fn to_signing_payload(&self, domain: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        let value_hash = DcryptSha256::digest(&self.value)
            .map_err(|e| CoreError::Crypto(e.to_string()))?
            .to_bytes();
        bytes.extend_from_slice(&value_hash);
        Ok(DcryptSha256::digest(&bytes)
            .map_err(|e| CoreError::Crypto(e.to_string()))?
            .to_bytes())
    }
}

/// A verifiable proof of off-chain consensus, submitted with the final oracle result.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OracleConsensusProof {
    /// A collection of individual `OracleAttestation`s from a quorum of validators.
    pub attestations: Vec<OracleAttestation>,
}

/// The specific action being requested by a SystemTransaction.
/// All system-level state changes are dispatched through the `CallService` variant,
/// ensuring consistent application of permissions and namespacing.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SystemPayload {
    /// A generic payload to call a method on any registered on-chain service.
    /// This is the unified entrypoint for all system and user-level service logic.
    CallService {
        /// The unique, lowercase, alphanumeric identifier of the target service (e.g., "identity_hub", "ibc").
        service_id: String,
        /// The versioned method name to call (e.g., "rotate_key@v1").
        method: String,
        /// The SCALE-encoded parameters for the method call.
        params: Vec<u8>,
    },
}

// --- Debug RPC Data Structures ---

/// Parameters for pinning a specific block height to prevent it from being pruned.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugPinHeightParams {
    /// The block height to pin.
    pub height: u64,
}

/// Parameters for unpinning a previously pinned block height.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugUnpinHeightParams {
    /// The block height to unpin.
    pub height: u64,
}

/// Parameters for triggering an immediate Garbage Collection pass.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugTriggerGcParams {}

/// Response containing statistics from a triggered GC pass.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DebugTriggerGcResponse {
    /// The number of block heights pruned from the index.
    pub heights_pruned: usize,
    /// The number of state tree nodes deleted from storage.
    pub nodes_deleted: usize,
}
