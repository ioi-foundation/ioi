// Path: crates/types/src/app/mod.rs
//! Core application-level data structures like Blocks and Transactions.

/// Data structures for the Agency Firewall action requests.
pub mod action;
/// Data structures for agentic semantic consensus.
pub mod agentic;
/// Data structures related to consensus, such as the canonical validator set
pub mod consensus;
/// Data structures for unified kernel events.
pub mod events;
/// Data structures for on-chain identity, including the canonical AccountId.
pub mod identity;
/// Data structures for reporting and penalizing misbehavior.
pub mod penalties;
/// Data structures for economic settlement.
pub mod settlement;
/// Data structures for deterministic block timing.
pub mod timing; // [NEW]

pub use action::*;
pub use consensus::*;
// Explicitly re-export the new agentic types
pub use agentic::{
    AgentSkill, CommitteeCertificate, InferenceOptions, LlmToolDefinition, RedactionEntry,
    RedactionMap, RedactionType, StepTrace,
};
pub use events::*;
pub use identity::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, BinaryMeasurement, BootAttestation,
    ChainId, Credential, GuardianReport, SignatureSuite,
};
pub use penalties::*;
pub use settlement::*;
pub use timing::*; // [NEW]

// [NEW] Moved ContextSlice here from drivers
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// The atomic unit of data within the Sovereign Context Substrate (SCS).
/// Unlike a file, a Context Slice is intent-bound and carries its own provenance.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ContextSlice {
    /// Unique content-addressed identifier for this slice.
    pub slice_id: [u8; 32],

    /// The ID of the frame in the SCS that this slice corresponds to.
    /// This allows the Provider to request the surrounding context if needed.
    pub frame_id: u64,

    /// The actual data chunks (e.g. XML fragments, JSON objects).
    /// Replaces the old single `data` vector to support zero-copy scatter/gather.
    pub chunks: Vec<Vec<u8>>,

    /// The Merkle Root of the mHNSW index at the time this frame was captured.
    /// This is used by the Provider to verify the integrity of the vector index
    /// before performing retrieval.
    pub mhnsw_root: [u8; 32],

    /// Cryptographic proof linking this slice to the root substrate state.
    /// Renamed from provenance_proof for consistency with IPC.
    pub traversal_proof: Option<Vec<u8>>,

    /// The hash of the intent that authorized this retrieval.
    /// [NOTE] Re-added to satisfy legacy checks or policy requirements if needed.
    /// Can be derived or checked against the request context.
    pub intent_id: [u8; 32],
}

use crate::error::{CoreError, StateError};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;

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
pub fn to_root_hash<C: AsRef<[u8]>>(c: C) -> Result<RootHash, StateError> {
    let s = c.as_ref();
    if s.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Ok(out)
    } else {
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

// -----------------------------------------------------------------------------
// Block Header
// -----------------------------------------------------------------------------

/// The header of a block, containing metadata and commitments.
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
    /// The monotonic counter from the Signing Oracle.
    /// Enforces strict ordering of signatures to prevent equivocation.
    pub oracle_counter: u64,
    /// The cryptographic trace hash from the Signing Oracle.
    /// Links this block signature to the previous signature history.
    pub oracle_trace_hash: [u8; 32],
    // ------------------------------------------

    /// Proof that the PARENT block was accepted by the network.
    /// This provides the "chaining" of security in Chained BFT.
    /// A valid QC proves that >= 2/3 of validators voted for parent_hash.
    pub parent_qc: QuorumCertificate,

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
            &self.parent_qc, // Include QC in signature preimage
        ))
        .map_err(CoreError::Custom)
    }
}

// -----------------------------------------------------------------------------
// Account Abstraction & Authorization
// -----------------------------------------------------------------------------

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

/// Authorization for a Session Key to act on behalf of a Master Identity.
/// Implements the "Burner Wallet" pattern.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SessionAuthorization {
    /// The public key of the session (ephemeral) keypair.
    pub session_key_pub: Vec<u8>,
    /// Optional session ID binding.
    pub session_id: Option<[u8; 32]>,
    /// The hash of the policy restricting this session (capabilities, spend limits).
    pub policy_hash: [u8; 32],
    /// Maximum Labor Gas this session can spend.
    pub max_spend: u64,
    /// Block height or timestamp when this authorization expires.
    pub expiry: u64,
    /// Signature from the Master Identity (AccountId) over this struct.
    pub signer_sig: Vec<u8>,
}

/// The header containing all data required for a valid, replay-protected signature.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, Encode, Decode)]
pub struct SignHeader {
    /// The stable identifier of the signing account (Master Identity).
    pub account_id: AccountId,
    /// The per-account transaction nonce for replay protection.
    pub nonce: u64,
    /// The ID of the target chain to prevent cross-chain replays.
    pub chain_id: ChainId,
    /// The version of the transaction format.
    pub tx_version: u8,
    /// [NEW] Optional session authorization allowing a delegate key to sign.
    pub session_auth: Option<SessionAuthorization>,
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

// -----------------------------------------------------------------------------
// Transaction Types (Agentic Economy)
// -----------------------------------------------------------------------------

/// A top-level enum representing any transaction the chain can process.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ChainTransaction {
    /// A privileged transaction for kernel-level changes (Identity, Governance).
    System(Box<SystemTransaction>),
    /// A transaction for the agentic economy (Bonding, Settlement, Bridging).
    Settlement(SettlementTransaction),
    /// A semantic transition proposed by a DIM committee.
    Semantic {
        /// The canonical result (JSON/Blob).
        result: Vec<u8>,
        /// The proof (BLS Aggregate) that the committee agreed on this result.
        proof: CommitteeCertificate,
        /// The transaction header (must match a committee leader/relayer).
        header: SignHeader,
    },
    /// A transaction initiated by a user or application (e.g. Deploy/Call Contract).
    Application(ApplicationTransaction),
}

impl ChainTransaction {
    /// Computes the canonical SHA-256 hash of the transaction.
    pub fn hash(&self) -> Result<TxHash, CoreError> {
        let bytes = crate::codec::to_bytes_canonical(self).map_err(CoreError::Custom)?;
        let digest = DcryptSha256::digest(&bytes).map_err(|e| CoreError::Crypto(e.to_string()))?;
        let hash_bytes = digest.to_bytes();
        hash_bytes
            .try_into()
            .map_err(|_| CoreError::Crypto("Invalid hash length".into()))
    }

    /// Computes the 6-byte short ID of the transaction for compact block propagation.
    pub fn short_id(&self) -> ShortTxId {
        let hash = self.hash().unwrap_or([0u8; 32]);
        let mut out = [0u8; 6];
        out.copy_from_slice(&hash[0..6]);
        out
    }
}

/// An enum wrapping all possible user-level transaction models.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ApplicationTransaction {
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

/// A transaction for economic settlement in the Agentic Economy.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SettlementTransaction {
    /// The header containing replay protection data.
    pub header: SignHeader,
    /// The specific settlement action.
    pub payload: SettlementPayload,
    /// The signature and public key of the caller.
    pub signature_proof: SignatureProof,
}

impl SettlementTransaction {
    /// Creates a stable, serializable payload for signing by clearing signature fields.
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, String> {
        let mut temp = self.clone();
        temp.signature_proof = SignatureProof::default();
        crate::codec::to_bytes_canonical(&temp)
    }
}

// -----------------------------------------------------------------------------
// Universal Artifacts (Receipts & Intent Contracts)
// -----------------------------------------------------------------------------

/// A cryptographic proof of external network activity performed by the Guardian.
/// This matches Whitepaper §4.3: Sovereign Connectors.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ExternalTrafficProof {
    /// The DNS name of the remote server (e.g., "api.openai.com").
    pub domain: String,
    /// The SHA-256 hash of the server's TLS certificate leaf.
    pub server_cert_hash: [u8; 32],
    /// The timestamp of the TLS handshake.
    pub handshake_time: u64,
    /// Signature by the local Guardian confirming it performed this connection.
    pub guardian_signature: Vec<u8>,
}

/// A canonical receipt proving the execution of a unit of work.
/// This matches Whitepaper §8: Proof of Execution.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Receipt {
    /// Hash of the canonical ActionRequest or BurstPacket.
    pub canonical_payload_hash: [u8; 32],
    /// Commitment to the inputs used (e.g. ContextSlice hash).
    pub inputs_commitment: [u8; 32],
    /// Commitment to the outputs produced.
    pub outputs_commitment: [u8; 32],
    /// The hash of the model snapshot used for inference.
    pub model_snapshot_id: [u8; 32],
    /// The hash of the active policy governing this action.
    pub policy_hash: [u8; 32],
    /// Optional session ID if part of a session.
    pub session_id: Option<[u8; 32]>,
    /// Hash link to the prior receipt in the chain (Chain of Custody).
    pub prev_receipt_hash: [u8; 32],
    /// Identifier of the entity signing this receipt.
    pub signer_id: AccountId,
    /// Cryptographic signature over the above fields.
    pub signature: Vec<u8>,
    /// Optional proof if this receipt resulted from an external API call via the Guardian.
    pub external_proof: Option<ExternalTrafficProof>,
}

/// The types of outcomes an Intent Contract can specify.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OutcomeType {
    /// A raw computation result.
    Result,
    /// A verified receipt of execution.
    Receipt,
    /// A ZK-proven certificate of correctness.
    Certificate,
}

/// The optimization objective for the Intent Contract matching engine.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OptimizationObjective {
    /// Minimize labor gas cost.
    Cost,
    /// Minimize execution latency.
    Latency,
    /// Maximize provider reputation/uptime.
    Reliability,
    /// Maximize data privacy (e.g. TEE required).
    Privacy,
}

/// An Intent Contract Schema (ICS), defining the constraints for an agentic task.
/// This matches Whitepaper §3.3.5 and §10.1.1.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct IntentContract {
    /// Maximum price willing to pay (in Labor Gas).
    pub max_price: u64,
    /// Deadline for execution (block height or timestamp).
    pub deadline_epoch: u64,
    /// Minimum confidence score required from the model/provider (0-100).
    pub min_confidence_score: u8,
    /// List of allowed provider identities (allowlist). Empty means any.
    pub allowed_providers: Vec<AccountId>,
    /// Type of outcome expected.
    pub outcome_type: OutcomeType,
    /// Optimization preference.
    pub optimize_for: OptimizationObjective,
}

/// A summary of the final state of a session, used for settlement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SettlementSummary {
    /// The unique session ID.
    pub session_id: [u8; 32],
    /// The account ID of the provider.
    pub provider_id: AccountId,
    /// The account ID of the payer.
    pub payer_id: AccountId,
    /// Hash of the terms agreed upon.
    pub terms_hash: [u8; 32],
    /// The final sequence number of the payment ticket.
    pub final_seq: u64,
    /// The final amount to be paid.
    pub final_amount: u128,
    /// The Merkle root of the receipt history included in this payment step.
    pub final_receipt_root: [u8; 32],
    /// The close mode (0 = Cooperative, 1 = Unilateral).
    pub mode: u8,
}

/// A package of evidence submitted to dispute a session or receipt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ChallengePackage {
    /// The specific receipt being contested.
    pub contested_receipt: Receipt,
    /// A Merkle proof connecting the receipt to the session's receipt_root.
    pub inclusion_proof: Vec<u8>, // Merkle Proof to receipt_root
                                  // Additional evidence fields...
}

// -----------------------------------------------------------------------------
// Governance & System Types
// -----------------------------------------------------------------------------

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SystemPayload {
    /// A generic payload to call a method on any registered on-chain service.
    CallService {
        /// The ID of the service to call.
        service_id: String,
        /// The method name to invoke.
        method: String,
        /// The encoded parameters for the call.
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