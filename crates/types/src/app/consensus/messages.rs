// --- BFT Voting Structures ---

/// A vote for a specific block hash at a specific height/view.
/// This is the message broadcast by validators to attest to a block's validity.
///
/// [MODIFIED] Now uses generic Vec<u8> which can hold either a classical Ed25519 signature
/// OR a BLS signature share depending on the active scheme.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// The block height this vote is for.
    pub height: u64,
    /// The consensus view/round this vote is for.
    pub view: u64,
    /// The hash of the block being voted for.
    pub block_hash: [u8; 32],
    /// The Account ID of the validator casting the vote.
    pub voter: AccountId,
    /// The cryptographic signature (Ed25519 or BLS Share).
    pub signature: Vec<u8>,
}

/// A vote from a validator to change the view at a specific height.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ViewChangeVote {
    /// The block height whose proposer timed out.
    pub height: u64,
    /// The recovery view being requested for that height.
    pub view: u64,
    /// The validator casting the timeout vote.
    pub voter: AccountId,
    /// The validator's signature over the `(height, view)` timeout payload.
    pub signature: Vec<u8>,
}

/// A proof that a majority of validators agreed to move to a new view.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// The block height for which the timeout quorum was formed.
    pub height: u64,
    /// The recovery view authorized by the timeout quorum.
    pub view: u64,
    /// The set of timeout votes that established the quorum.
    pub votes: Vec<ViewChangeVote>,
}

/// A cryptographic proof that a quorum (2/3+1) of validators approved a block.
/// This certificate allows a block to be considered finalized (or committed) by the network.
///
/// [MODIFIED] Added `aggregated_signature` and `signers_bitfield` for BLS optimization.
/// The `signatures` field remains for legacy/Ed25519 compatibility or as a fallback.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize, Default)]
pub struct QuorumCertificate {
    /// The height of the certified block.
    pub height: u64,
    /// The view of the certified block.
    pub view: u64,
    /// The hash of the certified block.
    pub block_hash: [u8; 32],

    // --- Legacy / Ed25519 (Explicit List) ---
    /// The individual signatures proving the quorum.
    pub signatures: Vec<(AccountId, Vec<u8>)>,

    // --- Scalable / BLS (Aggregated) ---
    /// The aggregated BLS signature.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// A bitfield representing which validators from the canonical set signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
}

// --- Protocol Apex: Aft deterministic Echo Protocol Structures ---

/// An Echo message broadcast by validators upon receiving a valid proposal.
/// Validates the leader's intent across Mirror partitions before voting.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct EchoMessage {
    /// The block height.
    pub height: u64,
    /// The consensus view.
    pub view: u64,
    /// The hash of the block proposal being echoed.
    pub block_hash: [u8; 32],
    /// The raw signature provided by the leader on the block header.
    /// This proves the leader actually committed to this proposal.
    pub leader_signature: Vec<u8>,
    /// The oracle counter from the leader's header, ensuring monotonicity.
    pub oracle_counter: u64,
    /// The identity of the node sending this Echo.
    pub sender_id: AccountId,
    /// The sender's signature over the Echo payload:
    /// H("ECHO_V1" || chain_id || height || view || block_hash || leader_sig)
    pub signature: Vec<u8>,
}

/// Cryptographic evidence that a validator has equivocated (signed two different
/// payloads for the same slot). This implies a hardware TEE breach.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ProofOfDivergence {
    /// The account ID of the equivocating validator.
    pub offender: AccountId,

    /// The first conflicting block header (containing the signature).
    pub evidence_a: BlockHeader,

    /// The second conflicting block header (containing the signature).
    pub evidence_b: BlockHeader,
    /// Optional conflicting guardian certificates extracted from the evidentiary headers.
    #[serde(default)]
    pub guardian_certificates: Vec<GuardianQuorumCertificate>,
    /// Optional witness-log checkpoints relevant to the divergence proof.
    #[serde(default)]
    pub log_checkpoints: Vec<GuardianLogCheckpoint>,
}

/// A high-priority divergence alert broadcast when conflicting signed evidence is detected.
/// In guardianized deployments this triggers quarantine and evidence propagation,
/// not a production engine switch.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct PanicMessage {
    /// The cryptographic proof of the hardware violation.
    pub proof: ProofOfDivergence,
    /// Signature of the node raising the alarm (to prevent griefing).
    pub sender_sig: Vec<u8>,
}

// --- Research-only witness/audit sampling structures ---

/// A probabilistic confidence report for witness/audit research flows.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct ConfidenceVote {
    /// The hash of the block being voted for (the preferred tip).
    pub block_hash: [u8; 32],
    /// The block height.
    pub height: u64,
    /// The local confidence score (C_B) for this block.
    pub confidence: u32,
    /// The VRF proof authorizing this vote (Anti-Sybil).
    pub vrf_proof: Vec<u8>,
    /// The voter's signature.
    pub signature: Vec<u8>,
}

/// A request to sample a peer's preferred tip for witness/audit observations.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SampleRequest {
    /// The height we are querying about.
    pub height: u64,
}

/// The response to a research-only witness/audit sample request.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SampleResponse {
    /// The responder's preferred block hash at that height.
    pub block_hash: [u8; 32],
    /// The responder's current confidence score.
    pub confidence: u32,
}

// --- Legacy recovery / governance structures ---

/// Governance payload for an explicit aft epoch reset or recovery ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftEpochUpgrade {
    /// The new Epoch ID.
    pub new_epoch: u64,
    /// List of BootAttestations from patched Guardians.
    pub attestations: Vec<crate::app::BootAttestation>,
}
