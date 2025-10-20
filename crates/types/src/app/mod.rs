// Path: crates/types/src/app/mod.rs
//! Core application-level data structures like Blocks and Transactions.

/// Data structures related to consensus, such as the canonical validator set
pub mod consensus;
/// Data structures for on-chain identity, including the canonical AccountId.
pub mod identity;
/// Data structures for reporting and penalizing misbehavior.
pub mod penalties;

pub use consensus::*;
pub use identity::*;
pub use penalties::*;

use crate::error::{CoreError, StateError};
use crate::ibc::{Finality, Header, InclusionProof, Packet};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use dcrypt::algorithms::ByteSerializable;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeader {
    /// The height of this block.
    pub height: u64,
    /// The hash of the parent block's header.
    pub parent_hash: [u8; 32],
    /// The state root committed by the parent block (the state against which this block is verified).
    pub parent_state_root: StateRoot,
    /// The state root this block commits to after applying its transactions.
    pub state_root: StateRoot,
    /// The root hash of the transactions in this block.
    pub transactions_root: Vec<u8>,
    /// The timestamp when the block was created.
    pub timestamp: u64,
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
    /// The signature of the block header's canonical preimage, signed by the producer's active consensus key.
    pub signature: Vec<u8>,
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
        let serialized =
            crate::codec::to_bytes_canonical(&temp).map_err(|e| CoreError::Custom(e))?;
        let digest =
            DcryptSha256::digest(&serialized).map_err(|e| CoreError::Custom(e.to_string()))?;
        Ok(digest.to_bytes())
    }

    /// Creates the canonical, domain-separated byte string that is hashed for signing.
    pub fn to_preimage_for_signing(&self) -> Result<Vec<u8>, CoreError> {
        crate::codec::to_bytes_canonical(&(
            SigDomain::BlockHeaderV1 as u8,
            self.height,
            self.parent_hash,
            &self.parent_state_root.0,
            &self.state_root.0,
            &self.transactions_root,
            self.timestamp,
            &self.producer_account_id,
            &self.producer_key_suite,
            &self.producer_pubkey_hash,
            &self.producer_pubkey,
        ))
        .map_err(CoreError::Custom)
    }
}

/// Defines the cryptographic algorithm suite used for a key or signature.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default, Encode, Decode)]
pub enum SignatureSuite {
    /// The Ed25519 signature scheme.
    #[default]
    Ed25519,
    /// The CRYSTALS-Dilithium2 post-quantum signature scheme.
    Dilithium2,
}

/// A cryptographic credential defining an account's active key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
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
    pub fn to_sign_bytes(&self) -> Result<Vec<u8>, bcs::Error> {
        let mut temp = self.clone();
        temp.signature_proof = SignatureProof::default();
        bcs::to_bytes(&temp)
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SystemPayload {
    /// **[CORE]** Updates the set of authorities for a Proof-of-Authority chain.
    UpdateAuthorities {
        /// The new list of authority AccountIds.
        new_authorities: Vec<AccountId>,
    },
    /// **[CORE]** Stakes a certain amount for a validator.
    Stake {
        /// The protobuf-encoded libp2p public key of the staker.
        public_key: Vec<u8>,
        /// The amount to stake.
        amount: u64,
    },
    /// **[CORE]** Unstakes a certain amount for a validator.
    Unstake {
        /// The amount to unstake.
        amount: u64,
    },
    /// **[CORE]** Schedules a forkless upgrade of a core service module.
    SwapModule {
        /// The unique ID of the service to be installed or upgraded.
        service_id: String,
        /// The SHA-256 hash of the service's TOML manifest.
        manifest_hash: [u8; 32],
        /// The SHA-256 hash of the service's WASM or EVM bytecode artifact.
        artifact_hash: [u8; 32],
        /// The block height at which the upgrade becomes active.
        activation_height: u64,
    },
    /// **[CORE]** Stores a service module's manifest and artifact on-chain for a future upgrade.
    StoreModule {
        /// The TOML manifest content.
        manifest: String,
        /// The raw WASM or EVM bytecode.
        artifact: Vec<u8>,
    },
    /// **[CORE]** Reports misbehavior by another agentic component, providing verifiable evidence.
    ReportMisbehavior {
        /// The full report, including the offender, facts, and proof.
        report: FailureReport,
    },

    // --- NEW: GENERIC SERVICE DISPATCH ---
    /// **[NEW]** A generic payload to call a method on any registered on-chain service.
    CallService {
        /// The unique, lowercase, alphanumeric identifier of the target service (e.g., "identity_hub", "ibc").
        service_id: String,
        /// The versioned method name to call (e.g., "rotate_key@v1").
        method: String,
        /// The SCALE-encoded parameters for the method call.
        params: Vec<u8>,
    },

    // --- DEPRECATED PAYLOADS (to be removed in a future version) ---
    /// Casts a vote on a governance proposal.
    #[deprecated(
        note = "Use CallService { service_id: \"governance\", method: \"vote@v1\", params: SCALE_ENCODE((proposal_id, option)) }"
    )]
    Vote {
        /// The unique identifier of the proposal being voted on.
        proposal_id: u64,
        /// The voter's chosen option.
        option: VoteOption,
    },
    /// Submits a request for external data to be brought on-chain by the oracle.
    #[deprecated(
        note = "Use CallService { service_id: \"oracle\", method: \"request_data@v1\", params: SCALE_ENCODE((url, request_id)) }"
    )]
    RequestOracleData {
        /// The URL or identifier for the data to be fetched.
        url: String,
        /// A unique ID for this request, specified by the user.
        request_id: u64,
    },
    /// Submits the final, tallied result and consensus proof for an oracle request.
    #[deprecated(
        note = "Use CallService { service_id: \"oracle\", method: \"submit_data@v1\", params: SCALE_ENCODE((request_id, final_value, proof)) }"
    )]
    SubmitOracleData {
        /// The ID of the request being fulfilled.
        request_id: u64,
        /// The final, aggregated value for the oracle data.
        final_value: Vec<u8>,
        /// The cryptographic proof of consensus from the validator set.
        consensus_proof: OracleConsensusProof,
    },
    /// Initiates a key rotation for the transaction's signer.
    #[deprecated(
        note = "Use CallService { service_id: \"identity_hub\", method: \"rotate_key@v1\", params: SCALE_ENCODE(proof) }"
    )]
    RotateKey(RotationProof),

    /// Explicitly submit a header update to an on-chain light client.
    #[cfg_attr(not(feature = "svc-ibc"), allow(dead_code))]
    #[deprecated(
        note = "Use CallService { service_id: \"ibc\", method: \"verify_header@v1\", params: SCALE_ENCODE((chain_id, header, finality)) }"
    )]
    VerifyHeader {
        /// The unique identifier of the target chain's light client.
        chain_id: String,
        /// The header to verify and store.
        header: Header,
        /// The finality proof for the header (e.g., Tendermint commit).
        finality: Finality,
    },
    /// Submits a ZK proof to be verified by a ZkDriver, targeting a specific verifier.
    #[deprecated(
        note = "Use CallService { service_id: \"zk_verifier\", method: \"submit_proof@v1\", ... }"
    )]
    SubmitProof {
        /// The identifier of the verifier that should handle this proof.
        target_verifier_id: String,
        /// The raw bytes of the ZK proof.
        proof_bytes: Vec<u8>,
        /// The raw bytes of the public inputs for the ZK proof.
        public_inputs: Vec<u8>,
    },
    /// Send an IBC-style packet.
    #[cfg_attr(not(feature = "svc-ibc"), allow(dead_code))]
    #[deprecated(
        note = "Use CallService { service_id: \"ibc_channel_manager\", method: \"send_packet@v1\", ... }"
    )]
    SendPacket {
        /// The port on the source chain.
        source_port: String,
        /// The channel on the source chain.
        source_channel: String,
        /// The packet data to be sent.
        packet: Packet,
        /// The block height on the destination chain after which the packet times out.
        timeout_height: u64,
        /// The timestamp on the destination chain after which the packet times out.
        timeout_timestamp: u64,
    },
    /// Receive an IBC-style packet, proven against a verified header.
    #[cfg_attr(not(feature = "svc-ibc"), allow(dead_code))]
    #[deprecated(
        note = "Use CallService { service_id: \"ibc_channel_manager\", method: \"recv_packet@v1\", ... }"
    )]
    RecvPacket {
        /// The packet that was received.
        packet: Packet,
        /// A cryptographic proof of the packet's inclusion on the source chain.
        proof: InclusionProof,
        /// The height on the source chain at which the proof was generated.
        proof_height: u64,
    },
    /// Acknowledge a received packet.
    #[cfg_attr(not(feature = "svc-ibc"), allow(dead_code))]
    #[deprecated(
        note = "Use CallService { service_id: \"ibc_channel_manager\", method: \"acknowledge_packet@v1\", ... }"
    )]
    AcknowledgePacket {
        /// The original packet that is being acknowledged.
        packet: Packet,
        /// The acknowledgement data from the receiving application.
        acknowledgement: Vec<u8>,
        /// A cryptographic proof of the acknowledgement's inclusion on the acknowledging chain.
        proof: InclusionProof,
        /// The height on the acknowledging chain at which the proof was generated.
        proof_height: u64,
    },
    /// Submits a receipt from a foreign chain for verification.
    #[deprecated(note = "Use IBC packets for interoperability.")]
    VerifyForeignReceipt {
        /// The chain ID of the foreign chain where the event originated.
        chain_id: u32,
        /// A unique identifier for the receipt, derived from its content on the foreign chain.
        unique_leaf_id: [u8; 32],
        /// The raw, opaque receipt data.
        receipt: Vec<u8>,
        /// A cryptographic proof of the receipt's inclusion in the foreign chain's state.
        proof: Vec<u8>,
    },
}
