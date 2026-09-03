// Versioned wire and evidence types for the normative hash-only asynchronous
// AFT fallback.
//
// The agreement construction follows Das, Duan, Liu, Momose, Ren, and
// Shoup, CCS 2024 / ePrint 2024/677. Its security model is intentionally
// represented on wire: a static Byzantine adversary, `n = 3f + 1`, eventual
// delivery over pairwise private authenticated channels, hash-function
// security in the random-oracle model, and no private threshold setup or DKG.

/// First AFT hash-only asynchronous protocol version.
pub const AFT_ASYNC_PROTOCOL_VERSION_V1: u16 = 1;
/// First AFT hash-only asynchronous wire schema.
pub const AFT_ASYNC_SCHEMA_VERSION_V1: u16 = 1;
/// Maximum proposal payload carried directly by the normative strict-PQ
/// fallback dissemination message. Larger proposals require a separately
/// specified immutable retrieval profile and are not admitted by V1.
pub const AFT_ASYNC_MAX_INLINE_PROPOSAL_BYTES_V1: usize = 8 * 1024 * 1024;
/// Stable theorem/model identifier for the normative profile.
pub const AFT_ASYNC_ASSUMPTION_ID_V1: &str = "AFT-AASYNC-DDLMSR24-STATIC-RO-V1";

const AFT_ASYNC_INSTANCE_DOMAIN_V1: &[u8] = b"ioi/aft/async-instance/v1";
const AFT_ASYNC_PROPOSAL_DOMAIN_V1: &[u8] = b"ioi/aft/async-proposal/v1";
const AFT_ASYNC_PROPOSAL_PAYLOAD_DOMAIN_V1: &[u8] = b"ioi/aft/async-proposal-payload/v1";
const AFT_ASYNC_PROPOSAL_BINDING_DOMAIN_V1: &[u8] = b"ioi/aft/async-proposal-binding/v1";
const AFT_ASYNC_AVAILABILITY_VOTE_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-proposal-availability-vote/v1";
const AFT_ASYNC_AVAILABILITY_CERTIFICATE_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-proposal-availability-certificate/v1";
const AFT_ASYNC_BATCH_DOMAIN_V1: &[u8] = b"ioi/aft/async-batch/v1";
const AFT_ASYNC_ORDER_DOMAIN_V1: &[u8] = b"ioi/aft/async-order/v1";
const AFT_ASYNC_ORDERING_DECISION_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-ordering-decision/v1";
const AFT_ASYNC_TRANSCRIPT_DOMAIN_V1: &[u8] = b"ioi/aft/async-transcript-summary/v1";
const AFT_ASYNC_DECISION_VOTE_DOMAIN_V1: &[u8] = b"ioi/aft/async-decision-vote/v1";
const AFT_ASYNC_CERTIFICATE_DOMAIN_V1: &[u8] = b"ioi/aft/async-order-certificate/v1";
const AFT_ASYNC_SELECTED_BATCH_WITNESS_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-selected-batch-witness/v1";
const AFT_ASYNC_EXECUTED_BLOCK_DECISION_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-executed-block-decision/v1";
const AFT_ASYNC_EXECUTED_BLOCK_VOTE_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-executed-block-vote/v1";
const AFT_ASYNC_EXECUTED_BLOCK_CERTIFICATE_DOMAIN_V1: &[u8] =
    b"ioi/aft/async-executed-block-certificate/v1";
const AFT_ASYNC_PARENT_PROOF_DOMAIN_V1: &[u8] = b"ioi/aft/async-parent-proof/v1";

fn async_hash<T: Encode>(domain: &[u8], value: &T) -> Result<[u8; 32], String> {
    let bytes = codec::to_bytes_canonical(&(domain.to_vec(), value))?;
    let digest = DcryptSha256::digest(&bytes).map_err(|error| error.to_string())?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| "invalid SHA-256 digest length".into())
}

/// Canonical digest carried by reliable-broadcast messages.
pub fn aft_async_rbc_value_hash(value: &[u8]) -> Result<[u8; 32], String> {
    async_hash(b"ioi/aft/async-rbc-value/v1", &value.to_vec())
}

/// Canonical digest carried by reliable-agreement messages.
pub fn aft_async_ra_value_hash(value: &[u8]) -> Result<[u8; 32], String> {
    async_hash(b"ioi/aft/async-ra-value/v1", &value.to_vec())
}

/// Canonical commitment to immutable proposal payload bytes. Availability
/// holders recompute this before signing a validate-and-hold vote.
pub fn aft_async_proposal_payload_hash(payload: &[u8]) -> Result<[u8; 32], String> {
    async_hash(AFT_ASYNC_PROPOSAL_PAYLOAD_DOMAIN_V1, &payload.to_vec())
}

/// Returns the canonical header reference for a QC whose complete proof stays
/// in the fallback-start witness. Quorum certificates for the same block can
/// contain different valid signer/signature representations; copying those
/// bytes into the virtual block header would make deterministic execution
/// produce different block hashes at correct nodes.
pub fn aft_async_canonical_qc_reference(qc: &QuorumCertificate) -> QuorumCertificate {
    QuorumCertificate {
        height: qc.height,
        view: qc.view,
        block_hash: qc.block_hash,
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    }
}

/// Returns the non-authoritative QC-shaped reference used by the first
/// optimistic child of an asynchronously finalized parent. Acceptance always
/// requires a separate [`AftAsyncParentProofV1`]; these empty-signature bytes
/// alone are never quorum evidence.
pub fn aft_async_canonical_parent_reference(
    parent_header: &BlockHeader,
) -> Result<QuorumCertificate, String> {
    let block_hash: [u8; 32] = parent_header
        .hash()
        .map_err(|error| error.to_string())?
        .as_slice()
        .try_into()
        .map_err(|_| "AFT asynchronous parent hash is not 32 bytes")?;
    Ok(QuorumCertificate {
        height: parent_header.height,
        view: parent_header.view,
        block_hash,
        signatures: Vec::new(),
        aggregated_signature: Vec::new(),
        signers_bitfield: Vec::new(),
    })
}

/// Domain-separated ASKS share commitment.
pub fn aft_async_asks_share_commitment(
    instance_hash: [u8; 32],
    view: u64,
    dealer: u16,
    owner: u16,
    share: &[u8; 32],
) -> Result<[u8; 32], String> {
    async_hash(
        b"ioi/aft/async-asks-share/v1",
        &(instance_hash, view, dealer, owner, share),
    )
}

/// Hashes a reconstructed ASKS polynomial constant into the rank secret.
pub fn aft_async_asks_secret(
    instance_hash: [u8; 32],
    view: u64,
    dealer: u16,
    constant: &[u8; 32],
) -> Result<[u8; 32], String> {
    async_hash(
        b"ioi/aft/async-asks-secret/v1",
        &(instance_hash, view, dealer, constant),
    )
}

/// Adversary model proved by the initial setup-free construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncAdversaryModelV1 {
    /// Corrupt parties are fixed before protocol execution.
    Static,
}

/// Termination semantics of the initial asynchronous construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncTerminationV1 {
    /// Almost-sure termination with expected constant protocol views under
    /// eventual delivery between honest parties.
    RandomizedAsynchronous,
}

/// Exact, non-negotiable assumptions attached to an asynchronous decision.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncAssumptionProfileV1 {
    /// Stable theorem/model identifier carried by every decision.
    pub assumption_id: String,
    /// Corruption timing covered by the selected construction.
    pub adversary_model: AftAsyncAdversaryModelV1,
    /// Progress semantics promised by the selected construction.
    pub termination: AftAsyncTerminationV1,
    /// Whether pairwise confidentiality and sender authentication are required.
    pub private_authenticated_channels_required: bool,
    /// Whether the channel must also be PQ for an end-to-end PQ claim.
    pub pq_authenticated_channels_required_for_end_to_end_pq: bool,
    /// Whether the protocol depends on secret threshold material established
    /// before the instance starts.
    pub private_threshold_setup: bool,
    /// Whether signatures or signature shares create protocol randomness.
    pub digital_signatures_used_for_randomness: bool,
    /// Whether the initial proof models the hash function as a random oracle.
    pub hash_random_oracle_model: bool,
}

impl Default for AftAsyncAssumptionProfileV1 {
    fn default() -> Self {
        Self {
            assumption_id: AFT_ASYNC_ASSUMPTION_ID_V1.into(),
            adversary_model: AftAsyncAdversaryModelV1::Static,
            termination: AftAsyncTerminationV1::RandomizedAsynchronous,
            private_authenticated_channels_required: true,
            pq_authenticated_channels_required_for_end_to_end_pq: true,
            private_threshold_setup: false,
            digital_signatures_used_for_randomness: false,
            hash_random_oracle_model: true,
        }
    }
}

impl AftAsyncAssumptionProfileV1 {
    /// Only the exact reviewed profile is accepted. This prevents a future
    /// decoder default from erasing the static-adversary or channel boundary.
    pub fn validate_normative(&self) -> Result<(), String> {
        if self != &Self::default() {
            return Err("AFT asynchronous assumption profile is not the normative static hash-only profile".into());
        }
        Ok(())
    }
}

/// Exact unit-weight resilience geometry for the normative asynchronous path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncGeometryV1 {
    /// Total number of unit-weight participants.
    pub n: u16,
    /// Maximum number of statically Byzantine participants.
    pub f: u16,
    /// `n-f = 2f+1` delivery/agreement threshold.
    pub quorum: u16,
}

impl AftAsyncGeometryV1 {
    /// Derives the only admitted geometry from its participant count.
    pub fn exact(n: u16) -> Result<Self, String> {
        if n < 4 || (n - 1).checked_rem(3) != Some(0) {
            return Err("normative AFT asynchronous geometry requires n = 3f + 1 with f >= 1".into());
        }
        let f = (n - 1) / 3;
        Ok(Self {
            n,
            f,
            quorum: n - f,
        })
    }

    /// Verifies exact `n=3f+1`, `q=2f+1` geometry.
    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::exact(self.n)?;
        if *self != expected {
            return Err("AFT asynchronous geometry is not exact n=3f+1, q=2f+1".into());
        }
        Ok(())
    }

    /// Returns whether an index belongs to this configuration.
    pub fn contains(&self, member: u16) -> bool {
        member < self.n
    }
}

/// One durable fallback instance, cryptographically bound to the D2
/// transition and its optimistic safety lock.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncInstanceV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Network/configuration/epoch boundary.
    pub scope: AftFallbackScopeV1,
    /// Ordering height handled by this instance.
    pub height: u64,
    /// Deterministic D2 fallback namespace.
    pub fallback_instance_id: [u8; 32],
    /// Commitment to the verified D2 transition certificate.
    pub fallback_start_hash: [u8; 32],
    /// Complete D2 transition evidence, retained so an offline verifier can
    /// recompute `fallback_start_hash` and every lock/scope binding.
    pub fallback_start: FallbackStartCertificateV1,
    /// Optimistic safety lock every proposal must extend.
    pub locked_root: [u8; 32],
    /// Exact resilience geometry.
    pub geometry: AftAsyncGeometryV1,
    /// Explicit proof and network model.
    pub assumptions: AftAsyncAssumptionProfileV1,
}

impl AftAsyncInstanceV1 {
    /// Builds an asynchronous instance from one verified D2 transition.
    pub fn from_fallback_start(
        start: &FallbackStartCertificateV1,
        geometry: AftAsyncGeometryV1,
    ) -> Result<Self, String> {
        start.validate_shape()?;
        geometry.validate()?;
        let instance = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            scope: start.scope,
            height: start.height,
            fallback_instance_id: start.fallback_instance_id,
            fallback_start_hash: start.certificate_hash()?,
            fallback_start: start.clone(),
            locked_root: start.locked_root,
            geometry,
            assumptions: AftAsyncAssumptionProfileV1::default(),
        };
        instance.validate()?;
        Ok(instance)
    }

    /// Validates version, scope, model, geometry, and transition bindings.
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous instance version".into());
        }
        self.scope.validate()?;
        self.geometry.validate()?;
        self.assumptions.validate_normative()?;
        if self.height == 0 {
            return Err("AFT asynchronous instance cannot target genesis".into());
        }
        let expected = FallbackStartCertificateV1::derive_instance_id(self.scope, self.height)?;
        if self.fallback_instance_id != expected {
            return Err("AFT asynchronous instance id does not match its scope and height".into());
        }
        self.fallback_start.validate_shape()?;
        if self.fallback_start.scope != self.scope
            || self.fallback_start.height != self.height
            || self.fallback_start.fallback_instance_id != self.fallback_instance_id
            || self.fallback_start.locked_root != self.locked_root
            || self.fallback_start.certificate_hash()? != self.fallback_start_hash
        {
            return Err("AFT asynchronous instance does not match its fallback-start evidence".into());
        }
        Ok(())
    }

    /// Returns the canonical *semantic* instance commitment used on every
    /// message.
    ///
    /// The complete fallback-start certificate remains part of this value and
    /// is validated above for portable auditability. Its raw bytes are not an
    /// agreement coordinate, however: two correct nodes can form the same
    /// exact-q timeout chain from different valid signer subsets. Hashing that
    /// representation would split one fallback height into several protocol
    /// instances. The commitment therefore binds the derived safe state and
    /// every authority/model coordinate, while deliberately excluding the
    /// replaceable proof representation (QC signatures and timeout voters).
    pub fn instance_hash(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        async_hash(
            AFT_ASYNC_INSTANCE_DOMAIN_V1,
            &(
                self.protocol_version,
                self.schema_version,
                self.scope,
                self.height,
                self.fallback_instance_id,
                (
                    self.fallback_start.highest_qc.height,
                    self.fallback_start.highest_qc.view,
                    self.fallback_start.highest_qc.block_hash,
                ),
                (
                    self.fallback_start.locked_qc.height,
                    self.fallback_start.locked_qc.view,
                    self.fallback_start.locked_qc.block_hash,
                ),
                self.locked_root,
                self.geometry,
                &self.assumptions,
            ),
        )
    }

    /// Tests whether two independently witnessed values address the same
    /// agreement instance. Both witnesses are fully validated before their
    /// semantic commitments are compared.
    pub fn consensus_equivalent(&self, other: &Self) -> Result<bool, String> {
        Ok(self.instance_hash()? == other.instance_hash()?)
    }
}

/// Immutable proposal descriptor over which validators attest
/// validate-and-hold availability. It deliberately excludes the availability
/// certificate hash, avoiding a recursive commitment.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncProposalDescriptorV1 {
    /// Exact asynchronous instance this proposal belongs to.
    pub instance_hash: [u8; 32],
    /// Unit-weight proposer index in the effective configuration.
    pub proposer: u16,
    /// Commitment to the immutable proposal payload.
    pub proposal_hash: [u8; 32],
    /// Exact payload length validators committed to retain.
    pub payload_len: u64,
    /// Optimistic/fallback lock root extended by the proposal.
    pub parent_root: [u8; 32],
}

/// Canonical V1 proposal payload ordered by message ACS. Transaction
/// signatures and state-dependent admissibility remain runtime obligations;
/// this type binds the immutable candidate set and fallback lock.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncBatchProposalV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Exact asynchronous instance commitment.
    pub instance_hash: [u8; 32],
    /// Target block height.
    pub height: u64,
    /// Optimistic lock extended by this batch.
    pub parent_root: [u8; 32],
    /// Bounded candidate transactions in proposer order.
    pub transactions: Vec<ChainTransaction>,
}

impl AftAsyncBatchProposalV1 {
    /// Creates the typed payload for one validated local transaction batch.
    pub fn new(
        instance: &AftAsyncInstanceV1,
        transactions: Vec<ChainTransaction>,
    ) -> Result<Self, String> {
        let proposal = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance_hash: instance.instance_hash()?,
            height: instance.height,
            parent_root: instance.locked_root,
            transactions,
        };
        proposal.validate_for(instance)?;
        Ok(proposal)
    }

    /// Validates instance/lock bindings and refuses duplicate transaction
    /// hashes. Runtime signature and state checks are deliberately additional.
    pub fn validate_for(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
            || self.instance_hash != instance.instance_hash()?
            || self.height != instance.height
            || self.parent_root != instance.locked_root
            || self.transactions.len() > 100_000
        {
            return Err("AFT asynchronous batch proposal is out of scope or oversized".into());
        }
        let mut hashes = std::collections::BTreeSet::new();
        for transaction in &self.transactions {
            let hash = transaction.hash().map_err(|error| error.to_string())?;
            if !hashes.insert(hash) {
                return Err("AFT asynchronous batch proposal duplicates a transaction".into());
            }
        }
        Ok(())
    }
}

impl AftAsyncProposalDescriptorV1 {
    /// Validates the complete instance and lock binding.
    pub fn validate_for(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        instance.validate()?;
        if self.instance_hash != instance.instance_hash()?
            || !instance.geometry.contains(self.proposer)
            || self.proposal_hash == [0; 32]
            || self.payload_len == 0
            || self.parent_root != instance.locked_root
        {
            return Err("AFT asynchronous proposal descriptor is malformed or crosses its instance/lock".into());
        }
        Ok(())
    }

    /// Returns the non-recursive proposal commitment signed by holders.
    pub fn binding_hash(&self) -> Result<[u8; 32], String> {
        async_hash(AFT_ASYNC_PROPOSAL_BINDING_DOMAIN_V1, self)
    }
}

/// Rooted PQ validate-and-hold statement for one immutable proposal.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncProposalAvailabilityVoteV1 {
    /// Exact proposal descriptor commitment.
    pub proposal_binding_hash: [u8; 32],
    /// Unit-weight holder index.
    pub member_index: u16,
    /// Stable validator account bound to that index.
    pub voter: AccountId,
    /// Normative suite: ML-DSA-44.
    pub signature_suite: SignatureSuite,
    /// PQ signature over [`Self::signing_bytes`].
    pub signature: Vec<u8>,
}

impl AftAsyncProposalAvailabilityVoteV1 {
    /// Builds the domain-separated validate-and-hold statement. A signer must
    /// call this only after durably retaining and hash-checking the payload.
    pub fn signing_bytes(
        descriptor: &AftAsyncProposalDescriptorV1,
        member_index: u16,
        voter: AccountId,
    ) -> Result<Vec<u8>, String> {
        let proposal_binding_hash = descriptor.binding_hash()?;
        codec::to_bytes_canonical(&(
            AFT_ASYNC_AVAILABILITY_VOTE_DOMAIN_V1.to_vec(),
            AFT_ASYNC_PROTOCOL_VERSION_V1,
            AFT_ASYNC_SCHEMA_VERSION_V1,
            proposal_binding_hash,
            member_index,
            voter,
        ))
    }

    /// Validates decision-independent vote shape and proposal binding.
    pub fn validate_for(
        &self,
        descriptor: &AftAsyncProposalDescriptorV1,
        instance: &AftAsyncInstanceV1,
    ) -> Result<(), String> {
        descriptor.validate_for(instance)?;
        if self.proposal_binding_hash != descriptor.binding_hash()?
            || !instance.geometry.contains(self.member_index)
            || self.signature_suite != SignatureSuite::ML_DSA_44
            || self.signature.is_empty()
        {
            return Err("AFT asynchronous proposal availability vote is malformed or rebound".into());
        }
        Ok(())
    }
}

/// Exact-q rooted PQ evidence that `2f+1` validators validated and retained
/// the immutable proposal bytes before the reference entered ACS.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncProposalAvailabilityCertificateV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Complete non-recursive proposal descriptor.
    pub descriptor: AftAsyncProposalDescriptorV1,
    /// Exactly `q=2f+1` rooted votes in member-index order.
    pub votes: Vec<AftAsyncProposalAvailabilityVoteV1>,
}

impl AftAsyncProposalAvailabilityCertificateV1 {
    /// Validates versions, descriptor binding, exact quorum and canonical
    /// distinct PQ vote shape before rooted-key verification.
    pub fn validate_shape(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous availability certificate version".into());
        }
        self.descriptor.validate_for(instance)?;
        if self.votes.len() != instance.geometry.quorum as usize {
            return Err("AFT asynchronous availability certificate does not contain exact q votes".into());
        }
        let mut prior = None;
        let mut voters = std::collections::BTreeSet::new();
        for vote in &self.votes {
            vote.validate_for(&self.descriptor, instance)?;
            if !voters.insert(vote.voter)
                || prior.is_some_and(|index| index >= vote.member_index)
            {
                return Err("AFT asynchronous availability votes are duplicate or non-canonical".into());
            }
            prior = Some(vote.member_index);
        }
        Ok(())
    }

    /// Returns the portable availability-certificate commitment.
    pub fn certificate_hash(&self, instance: &AftAsyncInstanceV1) -> Result<[u8; 32], String> {
        self.validate_shape(instance)?;
        async_hash(AFT_ASYNC_AVAILABILITY_CERTIFICATE_DOMAIN_V1, self)
    }

    /// Derives the only proposal reference this certificate can authorize.
    pub fn proposal_ref(
        &self,
        instance: &AftAsyncInstanceV1,
    ) -> Result<AftAsyncProposalRefV1, String> {
        self.validate_shape(instance)?;
        Ok(AftAsyncProposalRefV1 {
            proposer: self.descriptor.proposer,
            proposal_hash: self.descriptor.proposal_hash,
            payload_len: self.descriptor.payload_len,
            availability_certificate_hash: self.certificate_hash(instance)?,
            parent_root: self.descriptor.parent_root,
        })
    }
}

/// Immutable proposal reference admitted to message ACS only after its exact-q
/// rooted availability certificate has been verified.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncProposalRefV1 {
    /// Unit-weight proposer index in the effective configuration.
    pub proposer: u16,
    /// Commitment to the immutable proposal payload.
    pub proposal_hash: [u8; 32],
    /// Exact payload length for retrieval and resource bounds.
    pub payload_len: u64,
    /// Commitment to separately verified availability evidence.
    pub availability_certificate_hash: [u8; 32],
    /// Optimistic/fallback lock root extended by the proposal.
    pub parent_root: [u8; 32],
}

impl AftAsyncProposalRefV1 {
    /// Verifies membership, non-empty commitments, and lock propagation.
    pub fn validate_for(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        instance.validate()?;
        if !instance.geometry.contains(self.proposer) {
            return Err("AFT asynchronous proposal names an out-of-range proposer".into());
        }
        if self.proposal_hash == [0; 32]
            || self.availability_certificate_hash == [0; 32]
            || self.payload_len == 0
        {
            return Err("AFT asynchronous proposal has an empty commitment or payload".into());
        }
        if self.parent_root != instance.locked_root {
            return Err("AFT asynchronous proposal does not extend the fallback lock".into());
        }
        Ok(())
    }

    /// Returns the domain-separated proposal-reference commitment.
    pub fn commitment(&self) -> Result<[u8; 32], String> {
        async_hash(AFT_ASYNC_PROPOSAL_DOMAIN_V1, self)
    }

    /// Verifies that a fully checked availability certificate authorizes this
    /// exact immutable reference.
    pub fn validate_availability_binding(
        &self,
        instance: &AftAsyncInstanceV1,
        certificate: &AftAsyncProposalAvailabilityCertificateV1,
    ) -> Result<(), String> {
        if certificate.proposal_ref(instance)? != *self {
            return Err("AFT asynchronous proposal reference does not match its availability certificate".into());
        }
        Ok(())
    }
}

/// Purpose-separated identifiers for reliable-broadcast instances.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncRbcPurposeV1 {
    /// Availability-certified proposal reference RBC.
    Proposal,
    /// Index-ACS proposal-set RBC.
    AcsInput,
    /// VABA prevote RBC for one view.
    VabaPrevote {
        /// VABA view.
        view: u64,
    },
    /// VABA vote RBC for one view.
    VabaVote {
        /// VABA view.
        view: u64,
    },
    /// ASKS commitment-vector RBC.
    AsksCommitments {
        /// VABA view whose rank sharing this serves.
        view: u64,
        /// ASKS dealer index.
        dealer: u16,
    },
}

/// Bracha-style reliable-broadcast phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncRbcPhaseV1 {
    /// Dealer's initial value.
    Value,
    /// Authenticated echo of the dealer value.
    Echo,
    /// Threshold-amplified readiness statement.
    Ready,
}

/// Purpose-separated identifiers for reliable-agreement instances.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncRaPurposeV1 {
    /// Agreement that one ASKS sharing phase completed.
    AsksSharing {
        /// VABA view.
        view: u64,
        /// ASKS dealer index.
        dealer: u16,
    },
    /// Agreement that one candidate may enter cover gather.
    CoverValidation {
        /// VABA view.
        view: u64,
        /// Candidate participant index.
        candidate: u16,
    },
    /// One cross-view VABA termination gadget.
    VabaDecision,
}

/// Reliable-agreement phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncRaPhaseV1 {
    /// Echo of a locally admissible input.
    Echo,
    /// Threshold-amplified readiness statement.
    Ready,
}

/// Index-cover-gather message kind.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncGatherMessageV1 {
    /// First frozen `n-f` validation set.
    Inform {
        /// Canonical participant indices.
        indices: Vec<u16>,
    },
    /// Acknowledgement that one INFORM set is locally validated.
    Ack {
        /// Sender of the acknowledged INFORM.
        inform_sender: u16,
    },
    /// Validation set frozen after `n-f` INFORM acknowledgements.
    Prepare {
        /// Canonical participant indices.
        indices: Vec<u16>,
    },
    /// Cover-binding withdrawal after `n-f` RA instances finish.
    Withdraw,
}

/// ASKS message. Shares travel only in the private authenticated channel; the
/// commitment vector is reliably broadcast via the RBC variant below.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncAsksMessageV1 {
    /// Dealer-to-recipient private polynomial share.
    Share {
        /// VABA view.
        view: u64,
        /// Dealer participant index.
        dealer: u16,
        /// Intended recipient participant index.
        recipient: u16,
        /// Byte-wise GF(256) polynomial evaluation.
        share: [u8; 32],
    },
    /// Public reconstruction of one previously committed share.
    Reconstruct {
        /// VABA view.
        view: u64,
        /// Dealer participant index.
        dealer: u16,
        /// Owner participant index and authenticated sender.
        owner: u16,
        /// Previously committed share.
        share: [u8; 32],
    },
}

/// Canonical top-level message delivered only after the pairwise PQ channel
/// authenticates and decrypts its sender.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncMessageBodyV1 {
    /// Reliable-broadcast traffic.
    Rbc {
        /// Purpose-separation tag.
        purpose: AftAsyncRbcPurposeV1,
        /// Designated dealer.
        dealer: u16,
        /// RBC phase.
        phase: AftAsyncRbcPhaseV1,
        /// Domain-separated digest of `value`.
        value_hash: [u8; 32],
        /// Bounded value carried in every phase for availability.
        value: Vec<u8>,
    },
    /// Reliable-agreement traffic.
    ReliableAgreement {
        /// Purpose-separation tag.
        purpose: AftAsyncRaPurposeV1,
        /// RA phase.
        phase: AftAsyncRaPhaseV1,
        /// Domain-separated digest of `value`.
        value_hash: [u8; 32],
        /// Bounded agreement value.
        value: Vec<u8>,
    },
    /// Private-share or reconstruction traffic for ASKS.
    Asks(AftAsyncAsksMessageV1),
    /// Index-gather or cover-gather traffic.
    Gather {
        /// VABA view whose gather instance is addressed.
        view: u64,
        /// Gather message.
        message: AftAsyncGatherMessageV1,
    },
}

/// Instance-bound asynchronous protocol envelope. The sender is checked
/// against the authenticated channel identity by networking ingress.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncMessageV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Canonical asynchronous-instance commitment.
    pub instance_hash: [u8; 32],
    /// Claimed participant index, rebound to channel identity at ingress.
    pub sender: u16,
    /// Purpose-separated protocol payload.
    pub body: AftAsyncMessageBodyV1,
}

impl AftAsyncMessageV1 {
    /// Performs structural and instance validation before protocol dispatch.
    pub fn validate_for(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous message version".into());
        }
        if self.instance_hash != instance.instance_hash()? {
            return Err("AFT asynchronous message crosses an instance boundary".into());
        }
        if !instance.geometry.contains(self.sender) {
            return Err("AFT asynchronous message names an out-of-range sender".into());
        }
        match &self.body {
            AftAsyncMessageBodyV1::Rbc {
                dealer,
                value_hash,
                value,
                ..
            } => {
                if !instance.geometry.contains(*dealer) || *value_hash == [0; 32] {
                    return Err("AFT asynchronous RBC has an invalid dealer or digest".into());
                }
                if !value.is_empty()
                    && aft_async_rbc_value_hash(value)? != *value_hash
                {
                    return Err("AFT asynchronous RBC value does not match its digest".into());
                }
            }
            AftAsyncMessageBodyV1::ReliableAgreement {
                value_hash, value, ..
            } => {
                if *value_hash == [0; 32]
                    || (!value.is_empty()
                        && aft_async_ra_value_hash(value)? != *value_hash)
                {
                    return Err("AFT asynchronous RA value does not match its digest".into());
                }
            }
            AftAsyncMessageBodyV1::Asks(message) => match message {
                AftAsyncAsksMessageV1::Share {
                    dealer, recipient, ..
                } => {
                    if self.sender != *dealer
                        || !instance.geometry.contains(*dealer)
                        || !instance.geometry.contains(*recipient)
                    {
                        return Err("AFT ASKS share is not dealer-authenticated or in range".into());
                    }
                }
                AftAsyncAsksMessageV1::Reconstruct { dealer, owner, .. } => {
                    if self.sender != *owner
                        || !instance.geometry.contains(*dealer)
                        || !instance.geometry.contains(*owner)
                    {
                        return Err("AFT ASKS reconstruction is not owner-authenticated or in range".into());
                    }
                }
            },
            AftAsyncMessageBodyV1::Gather { message, .. } => match message {
                AftAsyncGatherMessageV1::Inform { indices }
                | AftAsyncGatherMessageV1::Prepare { indices } => {
                    validate_index_set(indices, instance.geometry.n, instance.geometry.quorum)?;
                }
                AftAsyncGatherMessageV1::Ack { inform_sender } => {
                    if !instance.geometry.contains(*inform_sender) {
                        return Err("AFT gather ACK names an out-of-range INFORM sender".into());
                    }
                }
                AftAsyncGatherMessageV1::Withdraw => {}
            },
        }
        Ok(())
    }
}

/// Canonical ordering decision produced by message ACS and the AFT adapter.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncOrderingDecisionV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Exact fallback instance and assumptions.
    pub instance: AftAsyncInstanceV1,
    /// Canonically ordered availability-certified proposal references.
    pub selected: Vec<AftAsyncProposalRefV1>,
    /// Commitment to the selected proposal set.
    pub batch_root: [u8; 32],
    /// Commitment to instance, lock, batch, and canonical ordering.
    pub ordering_root: [u8; 32],
    /// Fold commitment to the durable protocol transcript.
    pub transcript_root: [u8; 32],
}

/// Canonical common transcript surface. It contains only values guaranteed to
/// converge at every honest participant: the VABA-selected ACS proposer, that
/// proposer's delivered index set, and the corresponding delivered proposal
/// commitments. Arrival-order and private-channel traffic never enter this
/// root because honest participants need not observe those identically.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncTranscriptSummaryV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Exact asynchronous-instance commitment.
    pub instance_hash: [u8; 32],
    /// Participant index selected by index VABA.
    pub acs_winner: u16,
    /// Canonical `n-f`-or-larger set delivered by the winner's ACS-input RBC.
    pub selected_indices: Vec<u16>,
    /// Proposal commitments corresponding to `selected_indices`, in the same
    /// order.
    pub proposal_commitments: Vec<[u8; 32]>,
}

impl AftAsyncTranscriptSummaryV1 {
    /// Builds the common transcript surface from delivered protocol outputs.
    pub fn new(
        instance: &AftAsyncInstanceV1,
        acs_winner: u16,
        mut selected: Vec<AftAsyncProposalRefV1>,
    ) -> Result<Self, String> {
        if !instance.geometry.contains(acs_winner) {
            return Err("AFT asynchronous transcript winner is outside membership".into());
        }
        selected.sort_by_key(|proposal| proposal.proposer);
        let selected_indices = selected.iter().map(|proposal| proposal.proposer).collect();
        let proposal_commitments = selected
            .iter()
            .map(AftAsyncProposalRefV1::commitment)
            .collect::<Result<Vec<_>, _>>()?;
        let summary = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance_hash: instance.instance_hash()?,
            acs_winner,
            selected_indices,
            proposal_commitments,
        };
        summary.validate(instance)?;
        Ok(summary)
    }

    /// Validates the common set and its proposal-commitment cardinality.
    pub fn validate(&self, instance: &AftAsyncInstanceV1) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
            || self.instance_hash != instance.instance_hash()?
            || !instance.geometry.contains(self.acs_winner)
        {
            return Err("AFT asynchronous transcript has an invalid version, instance, or winner".into());
        }
        validate_index_set(
            &self.selected_indices,
            instance.geometry.n,
            instance.geometry.quorum,
        )?;
        if self.proposal_commitments.len() != self.selected_indices.len()
            || self.proposal_commitments.contains(&[0; 32])
        {
            return Err("AFT asynchronous transcript proposal commitments are malformed".into());
        }
        Ok(())
    }

    /// Returns the common transcript root committed by the ordering decision.
    pub fn transcript_root(&self, instance: &AftAsyncInstanceV1) -> Result<[u8; 32], String> {
        self.validate(instance)?;
        async_hash(AFT_ASYNC_TRANSCRIPT_DOMAIN_V1, self)
    }
}

impl AftAsyncOrderingDecisionV1 {
    /// Canonicalizes a selected set and derives both decision roots.
    pub fn new(
        instance: AftAsyncInstanceV1,
        mut selected: Vec<AftAsyncProposalRefV1>,
        transcript_root: [u8; 32],
    ) -> Result<Self, String> {
        selected.sort_by_key(|proposal| (proposal.proposal_hash, proposal.proposer));
        let batch_root = async_hash(AFT_ASYNC_BATCH_DOMAIN_V1, &selected)?;
        let ordering_root = async_hash(
            AFT_ASYNC_ORDER_DOMAIN_V1,
            &(
                instance.instance_hash()?,
                instance.locked_root,
                batch_root,
                &selected,
            ),
        )?;
        let decision = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance,
            selected,
            batch_root,
            ordering_root,
            transcript_root,
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Validates the exact selected-set, lock, and root bindings.
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous ordering decision version".into());
        }
        self.instance.validate()?;
        if self.selected.len() < self.instance.geometry.quorum as usize {
            return Err("AFT asynchronous selected set is below n-f".into());
        }
        let mut previous = None;
        let mut proposers = std::collections::BTreeSet::new();
        for proposal in &self.selected {
            proposal.validate_for(&self.instance)?;
            let key = (proposal.proposal_hash, proposal.proposer);
            if previous.is_some_and(|old| old >= key) || !proposers.insert(proposal.proposer) {
                return Err("AFT asynchronous selected proposals are non-canonical or duplicate a proposer".into());
            }
            previous = Some(key);
        }
        if self.batch_root != async_hash(AFT_ASYNC_BATCH_DOMAIN_V1, &self.selected)? {
            return Err("AFT asynchronous batch root is invalid".into());
        }
        let expected_order = async_hash(
            AFT_ASYNC_ORDER_DOMAIN_V1,
            &(
                self.instance.instance_hash()?,
                self.instance.locked_root,
                self.batch_root,
                &self.selected,
            ),
        )?;
        if self.ordering_root != expected_order || self.transcript_root == [0; 32] {
            return Err("AFT asynchronous ordering or transcript root is invalid".into());
        }
        Ok(())
    }

    /// Returns the domain-separated decision commitment signed by validators.
    pub fn decision_hash(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        async_hash(
            AFT_ASYNC_ORDERING_DECISION_DOMAIN_V1,
            &(
                self.protocol_version,
                self.schema_version,
                self.instance.instance_hash()?,
                &self.selected,
                self.batch_root,
                self.ordering_root,
                self.transcript_root,
            ),
        )
    }
}

/// PQ signature over one exact asynchronous ordering decision. Signatures are
/// for portable evidence; they do not supply protocol randomness.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncDecisionVoteV1 {
    /// Exact ordering decision commitment this vote authorizes.
    pub decision_hash: [u8; 32],
    /// Unit-weight member index.
    pub member_index: u16,
    /// Stable validator account bound to that member index.
    pub voter: AccountId,
    /// Signature suite; the normative profile admits only ML-DSA-44.
    pub signature_suite: SignatureSuite,
    /// Signature over [`Self::signing_bytes`].
    pub signature: Vec<u8>,
}

impl AftAsyncDecisionVoteV1 {
    /// Builds the complete domain-separated vote preimage.
    pub fn signing_bytes(
        decision: &AftAsyncOrderingDecisionV1,
        member_index: u16,
        voter: AccountId,
    ) -> Result<Vec<u8>, String> {
        decision.validate()?;
        let decision_hash = decision.decision_hash()?;
        codec::to_bytes_canonical(&(
            AFT_ASYNC_DECISION_VOTE_DOMAIN_V1.to_vec(),
            AFT_ASYNC_PROTOCOL_VERSION_V1,
            AFT_ASYNC_SCHEMA_VERSION_V1,
            decision_hash,
            member_index,
            voter,
        ))
    }

    /// Verifies the carried decision binding and normative PQ shape before
    /// rooted-key signature verification.
    pub fn validate_for(&self, decision: &AftAsyncOrderingDecisionV1) -> Result<(), String> {
        if self.decision_hash != decision.decision_hash()?
            || !decision.instance.geometry.contains(self.member_index)
            || self.signature_suite != SignatureSuite::ML_DSA_44
            || self.signature.is_empty()
        {
            return Err("AFT asynchronous decision vote is malformed or bound to another decision".into());
        }
        Ok(())
    }
}

/// Portable `2f+1`-signed evidence for a hash-only asynchronous ordering
/// decision. Rooted-key verification remains a verifier obligation.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncOrderingCertificateV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Agreed asynchronous ordering decision.
    pub decision: AftAsyncOrderingDecisionV1,
    /// Common protocol output surface whose commitment equals the decision's
    /// `transcript_root`.
    pub transcript: AftAsyncTranscriptSummaryV1,
    /// Exactly `q=2f+1` rooted PQ votes in member-index order.
    pub votes: Vec<AftAsyncDecisionVoteV1>,
}

/// One selected proposal together with the validate-and-hold evidence whose
/// commitment appears in the ordering decision. This is the offline witness
/// connecting an ordering root to concrete transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncSelectedProposalWitnessV1 {
    /// Typed canonical proposal payload.
    pub proposal: AftAsyncBatchProposalV1,
    /// Exact-q rooted availability evidence for those bytes.
    pub availability_certificate: AftAsyncProposalAvailabilityCertificateV1,
}

/// Portable witness for the deterministic de-duplicated batch selected by
/// asynchronous ordering.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncSelectedBatchWitnessV1 {
    /// Entries in the exact canonical order of `ordering.decision.selected`.
    pub selected: Vec<AftAsyncSelectedProposalWitnessV1>,
}

impl AftAsyncSelectedBatchWitnessV1 {
    /// Revalidates every payload/hash/availability binding and returns the
    /// canonical first-occurrence transaction batch.
    pub fn canonical_transactions(
        &self,
        ordering: &AftAsyncOrderingCertificateV1,
    ) -> Result<Vec<ChainTransaction>, String> {
        ordering.validate_shape()?;
        if self.selected.len() != ordering.decision.selected.len() {
            return Err("AFT asynchronous selected-batch witness has wrong cardinality".into());
        }
        let instance = &ordering.decision.instance;
        let mut seen = std::collections::BTreeSet::new();
        let mut transactions = Vec::new();
        for (entry, selected_ref) in self.selected.iter().zip(&ordering.decision.selected) {
            entry.proposal.validate_for(instance)?;
            let payload = codec::to_bytes_canonical(&entry.proposal)?;
            if aft_async_proposal_payload_hash(&payload)? != selected_ref.proposal_hash
                || u64::try_from(payload.len()).ok() != Some(selected_ref.payload_len)
            {
                return Err("AFT asynchronous selected proposal bytes do not match ordering".into());
            }
            entry
                .availability_certificate
                .validate_shape(instance)?;
            selected_ref.validate_availability_binding(
                instance,
                &entry.availability_certificate,
            )?;
            for transaction in &entry.proposal.transactions {
                let hash = transaction.hash().map_err(|error| error.to_string())?;
                if seen.insert(hash) {
                    transactions.push(transaction.clone());
                }
            }
        }
        Ok(transactions)
    }

    /// Commitment carried by an executed-block decision.
    pub fn witness_hash(
        &self,
        ordering: &AftAsyncOrderingCertificateV1,
    ) -> Result<[u8; 32], String> {
        self.canonical_transactions(ordering)?;
        async_hash(AFT_ASYNC_SELECTED_BATCH_WITNESS_DOMAIN_V1, self)
    }
}

/// Common decision signed only after deterministic execution of the ordered
/// batch. It binds the ordering/availability transcript to one canonical
/// block, without pretending that an ordering root is itself a block hash.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncExecutedBlockDecisionV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Exact fallback instance and assumption profile.
    pub instance: AftAsyncInstanceV1,
    /// Commitment to the canonical ordering decision. Valid exact-q
    /// certificates may contain different signer subsets, so their byte hashes
    /// are evidence identities rather than consensus identities.
    pub ordering_decision_hash: [u8; 32],
    /// Commitment to `batch_witness` after full binding validation.
    pub batch_witness_hash: [u8; 32],
    /// Canonical hash of the fully executed block header.
    pub block_hash: [u8; 32],
}

impl AftAsyncExecutedBlockDecisionV1 {
    /// Constructs a block decision only from a fully bound selected-batch
    /// witness and a non-empty executed header hash.
    pub fn new(
        ordering: AftAsyncOrderingCertificateV1,
        batch_witness: AftAsyncSelectedBatchWitnessV1,
        block_hash: [u8; 32],
    ) -> Result<Self, String> {
        if block_hash == [0; 32] {
            return Err("AFT asynchronous executed block has an empty hash".into());
        }
        let batch_witness_hash = batch_witness.witness_hash(&ordering)?;
        let decision = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance: ordering.decision.instance.clone(),
            ordering_decision_hash: ordering.decision.decision_hash()?,
            batch_witness_hash,
            block_hash,
        };
        decision.validate_shape()?;
        Ok(decision)
    }

    /// Structural and commitment validation before rooted signature checks.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
            || self.block_hash == [0; 32]
        {
            return Err("unsupported or empty AFT asynchronous executed-block decision".into());
        }
        self.instance.validate()?;
        if self.ordering_decision_hash == [0; 32] || self.batch_witness_hash == [0; 32] {
            return Err("AFT asynchronous executed-block evidence has an empty commitment".into());
        }
        Ok(())
    }

    /// Revalidates the external ordering and payload witness committed by this
    /// compact decision. Payload bytes stay out of every vote and certificate.
    pub fn validate_bindings(
        &self,
        ordering: &AftAsyncOrderingCertificateV1,
        batch_witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<(), String> {
        self.validate_shape()?;
        ordering.validate_shape()?;
        if !ordering
            .decision
            .instance
            .consensus_equivalent(&self.instance)?
            || ordering.decision.decision_hash()? != self.ordering_decision_hash
            || batch_witness.witness_hash(ordering)? != self.batch_witness_hash
        {
            return Err("AFT asynchronous executed-block ordering or batch witness is rebound".into());
        }
        Ok(())
    }

    /// Exact domain-separated commitment signed by validators.
    pub fn decision_hash(&self) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        async_hash(
            AFT_ASYNC_EXECUTED_BLOCK_DECISION_DOMAIN_V1,
            &(
                self.protocol_version,
                self.schema_version,
                self.instance.instance_hash()?,
                self.ordering_decision_hash,
                self.batch_witness_hash,
                self.block_hash,
            ),
        )
    }
}

/// Rooted PQ vote for one executed asynchronous block decision.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncExecutedBlockVoteV1 {
    /// Exact decision commitment.
    pub decision_hash: [u8; 32],
    /// Unit-weight member index.
    pub member_index: u16,
    /// Stable rooted validator account.
    pub voter: AccountId,
    /// Normative suite: ML-DSA-44.
    pub signature_suite: SignatureSuite,
    /// Signature over [`Self::signing_bytes`].
    pub signature: Vec<u8>,
}

impl AftAsyncExecutedBlockVoteV1 {
    /// Complete domain-separated preimage.
    pub fn signing_bytes(
        decision: &AftAsyncExecutedBlockDecisionV1,
        member_index: u16,
        voter: AccountId,
    ) -> Result<Vec<u8>, String> {
        let decision_hash = decision.decision_hash()?;
        codec::to_bytes_canonical(&(
            AFT_ASYNC_EXECUTED_BLOCK_VOTE_DOMAIN_V1.to_vec(),
            AFT_ASYNC_PROTOCOL_VERSION_V1,
            AFT_ASYNC_SCHEMA_VERSION_V1,
            decision_hash,
            member_index,
            voter,
        ))
    }

    /// Refuses rebinding and non-PQ vote shapes.
    pub fn validate_for(&self, decision: &AftAsyncExecutedBlockDecisionV1) -> Result<(), String> {
        if self.decision_hash != decision.decision_hash()?
            || !decision.instance.geometry.contains(self.member_index)
            || self.signature_suite != SignatureSuite::ML_DSA_44
            || self.signature.is_empty()
        {
            return Err("AFT asynchronous executed-block vote is malformed or rebound".into());
        }
        Ok(())
    }
}

/// Exact-q rooted certificate binding asynchronous ordering to one executed
/// canonical block.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncExecutedBlockCertificateV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Fully witnessed executed-block decision.
    pub decision: AftAsyncExecutedBlockDecisionV1,
    /// Ordering certificate whose commitment is carried by `decision`.
    pub ordering: AftAsyncOrderingCertificateV1,
    /// Exactly q rooted PQ votes in member-index order.
    pub votes: Vec<AftAsyncExecutedBlockVoteV1>,
}

impl AftAsyncExecutedBlockCertificateV1 {
    /// Structural exact-quorum validation before rooted signature checks.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous executed-block certificate".into());
        }
        self.decision.validate_shape()?;
        self.ordering.validate_shape()?;
        if !self
            .ordering
            .decision
            .instance
            .consensus_equivalent(&self.decision.instance)?
            || self.ordering.decision.decision_hash()? != self.decision.ordering_decision_hash
        {
            return Err("AFT asynchronous executed-block ordering certificate is rebound".into());
        }
        let instance = &self.decision.instance;
        if self.votes.len() != instance.geometry.quorum as usize {
            return Err("AFT asynchronous executed-block certificate does not contain exact q votes".into());
        }
        let mut prior = None;
        let mut voters = std::collections::BTreeSet::new();
        for vote in &self.votes {
            vote.validate_for(&self.decision)?;
            if !voters.insert(vote.voter)
                || prior.is_some_and(|index| index >= vote.member_index)
            {
                return Err("AFT asynchronous executed-block votes are duplicate or non-canonical".into());
            }
            prior = Some(vote.member_index);
        }
        Ok(())
    }

    /// Portable certificate commitment.
    pub fn certificate_hash(&self) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        async_hash(AFT_ASYNC_EXECUTED_BLOCK_CERTIFICATE_DOMAIN_V1, self)
    }

    /// Adds the external payload witness to complete the certificate chain.
    pub fn validate_with_witness(
        &self,
        witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<(), String> {
        self.validate_shape()?;
        self.decision.validate_bindings(&self.ordering, witness)
    }
}

/// Evidence-preserving bridge from an asynchronously finalized virtual block
/// to the next optimistic proposal. The block header retains only a canonical
/// empty-signature reference in `parent_qc`; this separate typed object is the
/// authority that makes that reference usable. It must never be decoded or
/// exported as a native quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncParentProofV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Canonical SCALE bytes of the asynchronously finalized parent header.
    pub parent_header_bytes: Vec<u8>,
    /// Exact-q ordering-to-execution certificate for that parent.
    pub executed_certificate: AftAsyncExecutedBlockCertificateV1,
    /// Availability-backed payload witness committed by the certificate.
    pub batch_witness: AftAsyncSelectedBatchWitnessV1,
}

impl AftAsyncParentProofV1 {
    /// Constructs a typed predecessor proof from the exact finalized header
    /// and its complete asynchronous evidence chain.
    pub fn new(
        parent_header: &BlockHeader,
        executed_certificate: AftAsyncExecutedBlockCertificateV1,
        batch_witness: AftAsyncSelectedBatchWitnessV1,
    ) -> Result<Self, String> {
        let proof = Self {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            parent_header_bytes: codec::to_bytes_canonical(parent_header)?,
            executed_certificate,
            batch_witness,
        };
        proof.validate_shape()?;
        Ok(proof)
    }

    /// Reconstructs the exact canonical parent header.
    pub fn parent_header(&self) -> Result<BlockHeader, String> {
        let header: BlockHeader = codec::from_bytes_canonical(&self.parent_header_bytes)?;
        if codec::to_bytes_canonical(&header)? != self.parent_header_bytes {
            return Err("AFT asynchronous parent header is not canonical".into());
        }
        Ok(header)
    }

    /// Validates every non-cryptographic binding. Rooted membership and all
    /// signatures are deliberately rechecked by the consensus verifier.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous parent proof version".into());
        }
        self.executed_certificate
            .validate_with_witness(&self.batch_witness)?;
        let header = self.parent_header()?;
        let instance = &self.executed_certificate.decision.instance;
        let header_hash: [u8; 32] = header
            .hash()
            .map_err(|error| error.to_string())?
            .as_slice()
            .try_into()
            .map_err(|_| "AFT asynchronous parent header hash is not 32 bytes")?;
        let transactions = self
            .batch_witness
            .canonical_transactions(&self.executed_certificate.ordering)?;
        if header_hash != self.executed_certificate.decision.block_hash
            || header.height != instance.height
            || (header.height > 1
                && header.parent_hash != instance.fallback_start.highest_qc.block_hash)
            || header.parent_qc
                != aft_async_canonical_qc_reference(&instance.fallback_start.highest_qc)
            || header.transactions_root != crate::app::canonical_transactions_root(&transactions)?
            || !header.signature.is_empty()
            || header.oracle_counter != 0
            || header.oracle_trace_hash != [0; 32]
            || header.guardian_certificate.is_some()
            || header.sealed_finality_proof.is_some()
            || header.canonical_order_certificate.is_some()
            || header.timeout_certificate.is_some()
            || header.aft_timeout_certificate.is_some()
        {
            return Err("AFT asynchronous parent proof does not bind the virtual header".into());
        }
        Ok(())
    }

    /// Semantic authority identity used by timeout votes that cross this
    /// predecessor. Replaceable exact-q signer subsets do not change it, while
    /// every concrete proof supplied for the hash must still verify in full.
    pub fn proof_hash(&self) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        let header = self.parent_header()?;
        async_hash(
            AFT_ASYNC_PARENT_PROOF_DOMAIN_V1,
            &(
                self.protocol_version,
                self.schema_version,
                aft_async_canonical_parent_reference(&header)?,
                self.executed_certificate.decision.decision_hash()?,
            ),
        )
    }
}

/// Versioned body carried by the strict PQ asynchronous-consensus channel.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub enum AftAsyncCarrierBodyV1 {
    /// Immutable proposal bytes disseminated before any holder signs.
    ProposalPayload {
        /// Complete proposal binding.
        descriptor: AftAsyncProposalDescriptorV1,
        /// Canonical bytes whose hash and length match the descriptor.
        payload: Vec<u8>,
    },
    /// One validate-and-hold vote paired with its immutable descriptor.
    ProposalAvailabilityVote {
        /// Proposal descriptor the holder validated and retained.
        descriptor: AftAsyncProposalDescriptorV1,
        /// Rooted PQ holder vote.
        vote: AftAsyncProposalAvailabilityVoteV1,
    },
    /// Exact-q availability evidence authorizing a proposal reference.
    ProposalAvailabilityCertificate(AftAsyncProposalAvailabilityCertificateV1),
    /// One RBC/RA/ASKS/gather protocol message.
    Message(AftAsyncMessageV1),
    /// One rooted ML-DSA vote for the locally converged decision.
    DecisionVote(AftAsyncDecisionVoteV1),
    /// Exact-q portable ordering certificate.
    OrderingCertificate(AftAsyncOrderingCertificateV1),
    /// One rooted vote binding ordering evidence to an executed block.
    ExecutedBlockVote(AftAsyncExecutedBlockVoteV1),
    /// Exact-q portable executed-block certificate.
    ExecutedBlockCertificate(AftAsyncExecutedBlockCertificateV1),
}

/// Single versioned payload family for all hash-only fallback traffic. The
/// surrounding PQ channel authenticates the account; consensus rebinds that
/// account and `instance_hash` to rooted membership before use.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftAsyncCarrierV1 {
    /// Protocol version.
    pub protocol_version: u16,
    /// Wire-schema version.
    pub schema_version: u16,
    /// Exact asynchronous instance commitment.
    pub instance_hash: [u8; 32],
    /// Purpose-separated carrier body.
    pub body: AftAsyncCarrierBodyV1,
}

impl AftAsyncCarrierV1 {
    /// Performs context-free shape validation at the network boundary.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
            || self.instance_hash == [0; 32]
        {
            return Err("unsupported or empty AFT asynchronous carrier".into());
        }
        match &self.body {
            AftAsyncCarrierBodyV1::ProposalPayload {
                descriptor,
                payload,
            } => {
                if descriptor.instance_hash != self.instance_hash
                    || payload.is_empty()
                    || payload.len() > AFT_ASYNC_MAX_INLINE_PROPOSAL_BYTES_V1
                    || u64::try_from(payload.len()).ok() != Some(descriptor.payload_len)
                    || aft_async_proposal_payload_hash(payload)? != descriptor.proposal_hash
                {
                    return Err("AFT asynchronous carrier has a malformed proposal payload".into());
                }
            }
            AftAsyncCarrierBodyV1::ProposalAvailabilityVote { descriptor, vote } => {
                if descriptor.instance_hash != self.instance_hash
                    || vote.proposal_binding_hash == [0; 32]
                    || vote.signature_suite != SignatureSuite::ML_DSA_44
                    || vote.signature.is_empty()
                {
                    return Err("AFT asynchronous carrier has a malformed availability vote".into());
                }
            }
            AftAsyncCarrierBodyV1::ProposalAvailabilityCertificate(certificate) => {
                if certificate.protocol_version != self.protocol_version
                    || certificate.schema_version != self.schema_version
                    || certificate.descriptor.instance_hash != self.instance_hash
                {
                    return Err("AFT asynchronous availability certificate crosses its carrier boundary".into());
                }
            }
            AftAsyncCarrierBodyV1::Message(message) => {
                if message.protocol_version != self.protocol_version
                    || message.schema_version != self.schema_version
                    || message.instance_hash != self.instance_hash
                {
                    return Err("AFT asynchronous message crosses its carrier boundary".into());
                }
            }
            AftAsyncCarrierBodyV1::DecisionVote(vote) => {
                if vote.decision_hash == [0; 32]
                    || vote.signature_suite != SignatureSuite::ML_DSA_44
                    || vote.signature.is_empty()
                {
                    return Err("AFT asynchronous carrier has a malformed decision vote".into());
                }
            }
            AftAsyncCarrierBodyV1::OrderingCertificate(certificate) => {
                certificate.validate_shape()?;
                if certificate.decision.instance.instance_hash()? != self.instance_hash {
                    return Err("AFT asynchronous certificate crosses its carrier instance".into());
                }
            }
            AftAsyncCarrierBodyV1::ExecutedBlockVote(vote) => {
                if vote.decision_hash == [0; 32]
                    || vote.signature_suite != SignatureSuite::ML_DSA_44
                    || vote.signature.is_empty()
                {
                    return Err("AFT asynchronous carrier has a malformed executed-block vote".into());
                }
            }
            AftAsyncCarrierBodyV1::ExecutedBlockCertificate(certificate) => {
                certificate.validate_shape()?;
                if certificate
                    .decision
                    .instance
                    .instance_hash()?
                    != self.instance_hash
                {
                    return Err("AFT asynchronous executed-block certificate crosses its carrier instance".into());
                }
            }
        }
        Ok(())
    }
}

impl AftAsyncOrderingCertificateV1 {
    /// Validates versions, decision roots, exact quorum size, PQ suite, and
    /// canonical distinct votes before cryptographic verification.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || self.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported AFT asynchronous ordering certificate version".into());
        }
        self.decision.validate()?;
        self.transcript.validate(&self.decision.instance)?;
        if self.transcript.transcript_root(&self.decision.instance)?
            != self.decision.transcript_root
        {
            return Err("AFT asynchronous certificate transcript root is invalid".into());
        }
        let selected_by_index = self
            .decision
            .selected
            .iter()
            .map(|proposal| {
                Ok::<(u16, [u8; 32]), String>((
                    proposal.proposer,
                    proposal.commitment()?,
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
        for (position, index) in self.transcript.selected_indices.iter().enumerate() {
            if selected_by_index.get(index) != Some(&self.transcript.proposal_commitments[position]) {
                return Err("AFT asynchronous transcript does not name the decision's selected proposals".into());
            }
        }
        if self.votes.len() != self.decision.instance.geometry.quorum as usize {
            return Err("AFT asynchronous ordering certificate does not contain exact q votes".into());
        }
        let mut prior = None;
        let mut voters = std::collections::BTreeSet::new();
        for vote in &self.votes {
            vote.validate_for(&self.decision)?;
            if !voters.insert(vote.voter)
                || prior.is_some_and(|index| index >= vote.member_index)
            {
                return Err("AFT asynchronous ordering vote is malformed, non-PQ, duplicate, or non-canonical".into());
            }
            prior = Some(vote.member_index);
        }
        Ok(())
    }

    /// Returns the domain-separated portable certificate commitment.
    pub fn certificate_hash(&self) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        async_hash(AFT_ASYNC_CERTIFICATE_DOMAIN_V1, self)
    }
}

/// Validates a sorted, duplicate-free member-index set.
pub fn validate_index_set(indices: &[u16], n: u16, minimum: u16) -> Result<(), String> {
    if indices.len() < minimum as usize {
        return Err("AFT asynchronous index set is below its threshold".into());
    }
    let mut previous = None;
    for index in indices {
        if *index >= n || previous.is_some_and(|old| old >= *index) {
            return Err("AFT asynchronous index set is out of range or non-canonical".into());
        }
        previous = Some(*index);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{ChainId, SignHeader, SignatureProof, SystemPayload, SystemTransaction};

    fn account(byte: u8) -> AccountId {
        AccountId::from([byte; 32])
    }

    fn fallback_start_with_voters(voters: [u8; 3]) -> FallbackStartCertificateV1 {
        let scope = AftFallbackScopeV1 {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 1,
        };
        let tc = |view| AftTimeoutCertificateV1 {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height: 9,
            view,
            votes: voters
                .iter()
                .copied()
                .map(|voter| AftTimeoutVoteV1 {
                    protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                    schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                    scope,
                    height: 9,
                    view,
                    highest_qc: QuorumCertificate::default(),
                    highest_qc_async_parent_proof_hash: None,
                    locked_qc: QuorumCertificate::default(),
                    locked_qc_async_parent_proof_hash: None,
                    voter: account(voter),
                    signature: vec![voter, view as u8],
                })
                .collect(),
        };
        FallbackStartCertificateV1::new(
            scope,
            9,
            AftFallbackTriggerCertificateV1 {
                height: 9,
                consecutive_timeout_certificates: vec![tc(1), tc(2), tc(3)],
            },
        )
        .unwrap()
    }

    fn fallback_start() -> FallbackStartCertificateV1 {
        fallback_start_with_voters([1, 2, 3])
    }

    fn instance() -> AftAsyncInstanceV1 {
        AftAsyncInstanceV1::from_fallback_start(&fallback_start(), AftAsyncGeometryV1::exact(4).unwrap())
            .unwrap()
    }

    #[test]
    fn assumption_profile_refuses_adaptive_or_signature_randomness_claims() {
        let mut profile = AftAsyncAssumptionProfileV1::default();
        profile.digital_signatures_used_for_randomness = true;
        assert!(profile.validate_normative().is_err());
        profile = AftAsyncAssumptionProfileV1::default();
        profile.private_threshold_setup = true;
        assert!(profile.validate_normative().is_err());
    }

    #[test]
    fn geometry_is_exact_and_not_a_weighted_compatibility_profile() {
        assert_eq!(AftAsyncGeometryV1::exact(4).unwrap().quorum, 3);
        assert_eq!(AftAsyncGeometryV1::exact(7).unwrap().quorum, 5);
        assert!(AftAsyncGeometryV1::exact(5).is_err());
        assert!(AftAsyncGeometryV1 { n: 4, f: 1, quorum: 2 }.validate().is_err());
    }

    #[test]
    fn proposal_and_instance_are_bound_to_fallback_lock() {
        let instance = instance();
        let mut rebound = instance.clone();
        rebound.scope.network_id[0] ^= 1;
        rebound.fallback_instance_id =
            FallbackStartCertificateV1::derive_instance_id(rebound.scope, rebound.height).unwrap();
        assert!(rebound.validate().is_err());
        let mut replaced_start = instance.clone();
        replaced_start.fallback_start.locked_root[0] ^= 1;
        assert!(replaced_start.validate().is_err());
        let mut proposal = AftAsyncProposalRefV1 {
            proposer: 0,
            proposal_hash: [3; 32],
            payload_len: 12,
            availability_certificate_hash: [4; 32],
            parent_root: instance.locked_root,
        };
        proposal.validate_for(&instance).unwrap();
        proposal.parent_root = [9; 32];
        assert!(proposal.validate_for(&instance).is_err());
    }

    #[test]
    fn semantic_instance_ignores_valid_timeout_witness_representation() {
        let first = AftAsyncInstanceV1::from_fallback_start(
            &fallback_start_with_voters([1, 2, 3]),
            AftAsyncGeometryV1::exact(4).unwrap(),
        )
        .unwrap();
        let second_start = fallback_start_with_voters([2, 3, 4]);
        let second = AftAsyncInstanceV1::from_fallback_start(
            &second_start,
            AftAsyncGeometryV1::exact(4).unwrap(),
        )
        .unwrap();

        assert_ne!(first.fallback_start_hash, second.fallback_start_hash);
        assert_ne!(first.fallback_start, second.fallback_start);
        assert_eq!(first.instance_hash().unwrap(), second.instance_hash().unwrap());
        assert!(first.consensus_equivalent(&second).unwrap());

        let mut changed_safe_state = second_start;
        for vote in changed_safe_state
            .trigger_certificate
            .consecutive_timeout_certificates
            .iter_mut()
            .flat_map(|certificate| certificate.votes.iter_mut())
        {
            vote.highest_qc = QuorumCertificate {
                height: 8,
                view: 4,
                block_hash: [0xA4; 32],
                ..QuorumCertificate::default()
            };
        }
        changed_safe_state = FallbackStartCertificateV1::new(
            changed_safe_state.scope,
            changed_safe_state.height,
            changed_safe_state.trigger_certificate,
        )
        .unwrap();
        let changed = AftAsyncInstanceV1::from_fallback_start(
            &changed_safe_state,
            AftAsyncGeometryV1::exact(4).unwrap(),
        )
        .unwrap();
        assert_ne!(first.instance_hash().unwrap(), changed.instance_hash().unwrap());
    }

    #[test]
    fn decision_commitments_ignore_replaceable_fallback_witness_bytes() {
        let first = instance();
        let second = AftAsyncInstanceV1::from_fallback_start(
            &fallback_start_with_voters([2, 3, 4]),
            AftAsyncGeometryV1::exact(4).unwrap(),
        )
        .unwrap();
        let proposals = (0..3)
            .map(|proposer| AftAsyncProposalRefV1 {
                proposer,
                proposal_hash: [proposer as u8 + 10; 32],
                payload_len: 1,
                availability_certificate_hash: [proposer as u8 + 20; 32],
                parent_root: first.locked_root,
            })
            .collect::<Vec<_>>();
        let transcript = AftAsyncTranscriptSummaryV1::new(&first, 0, proposals.clone()).unwrap();
        let first_ordering = AftAsyncOrderingDecisionV1::new(
            first.clone(),
            proposals.clone(),
            transcript.transcript_root(&first).unwrap(),
        )
        .unwrap();
        let second_ordering = AftAsyncOrderingDecisionV1::new(
            second.clone(),
            proposals,
            transcript.transcript_root(&second).unwrap(),
        )
        .unwrap();
        assert_ne!(first_ordering, second_ordering);
        assert_eq!(
            first_ordering.decision_hash().unwrap(),
            second_ordering.decision_hash().unwrap()
        );

        let first_executed = AftAsyncExecutedBlockDecisionV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance: first,
            ordering_decision_hash: first_ordering.decision_hash().unwrap(),
            batch_witness_hash: [0xB1; 32],
            block_hash: [0xC1; 32],
        };
        let second_executed = AftAsyncExecutedBlockDecisionV1 {
            instance: second,
            ..first_executed.clone()
        };
        assert_ne!(first_executed, second_executed);
        assert_eq!(
            first_executed.decision_hash().unwrap(),
            second_executed.decision_hash().unwrap()
        );
    }

    #[test]
    fn ordering_is_canonical_and_cannot_use_fewer_than_n_minus_f_proposals() {
        let instance = instance();
        let locked_root = instance.locked_root;
        let proposal = |proposer, byte| AftAsyncProposalRefV1 {
            proposer,
            proposal_hash: [byte; 32],
            payload_len: 1,
            availability_certificate_hash: [byte + 20; 32],
            parent_root: locked_root,
        };
        assert!(AftAsyncOrderingDecisionV1::new(
            instance.clone(),
            vec![proposal(0, 3), proposal(1, 2)],
            [8; 32]
        )
        .is_err());
        let decision = AftAsyncOrderingDecisionV1::new(
            instance,
            vec![proposal(0, 3), proposal(1, 2), proposal(2, 1)],
            [8; 32],
        )
        .unwrap();
        assert_eq!(decision.selected[0].proposal_hash, [1; 32]);
    }

    #[test]
    fn wire_messages_refuse_cross_instance_and_mismatched_value_digest() {
        let instance = instance();
        let value = vec![1, 2, 3];
        let value_hash = aft_async_rbc_value_hash(&value).unwrap();
        let mut message = AftAsyncMessageV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            instance_hash: instance.instance_hash().unwrap(),
            sender: 0,
            body: AftAsyncMessageBodyV1::Rbc {
                purpose: AftAsyncRbcPurposeV1::Proposal,
                dealer: 0,
                phase: AftAsyncRbcPhaseV1::Value,
                value_hash,
                value,
            },
        };
        message.validate_for(&instance).unwrap();
        if let AftAsyncMessageBodyV1::Rbc { value_hash, .. } = &mut message.body {
            *value_hash = [9; 32];
        }
        assert!(message.validate_for(&instance).is_err());
        message.instance_hash = [6; 32];
        assert!(message.validate_for(&instance).is_err());
    }

    #[test]
    fn typed_batch_refuses_instance_lock_rebinding_and_duplicate_transactions() {
        let instance = instance();
        let transaction = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id: account(42),
                nonce: 1,
                chain_id: ChainId(7),
                tx_version: 1,
                session_auth: None,
            },
            payload: SystemPayload::CallService {
                service_id: "guardian_registry".into(),
                method: "test_aft_async_batch@v1".into(),
                params: vec![1, 2, 3],
            },
            signature_proof: SignatureProof::default(),
        }));
        let proposal = AftAsyncBatchProposalV1::new(&instance, vec![transaction.clone()]).unwrap();
        proposal.validate_for(&instance).unwrap();

        let mut rebound = proposal.clone();
        rebound.parent_root[0] ^= 1;
        assert!(rebound.validate_for(&instance).is_err());

        let duplicate =
            AftAsyncBatchProposalV1::new(&instance, vec![transaction.clone(), transaction]);
        assert!(duplicate.is_err());
    }

    #[test]
    fn executed_block_certificate_binds_ordering_payloads_and_exact_q() {
        let instance = instance();
        let mut entries = Vec::new();
        for proposer in 0..instance.geometry.quorum {
            let transaction = ChainTransaction::System(Box::new(SystemTransaction {
                header: SignHeader {
                    account_id: account(proposer as u8 + 40),
                    nonce: u64::from(proposer) + 1,
                    chain_id: ChainId(7),
                    tx_version: 1,
                    session_auth: None,
                },
                payload: SystemPayload::CallService {
                    service_id: "guardian_registry".into(),
                    method: format!("async_{proposer}@v1"),
                    params: vec![proposer as u8],
                },
                signature_proof: SignatureProof::default(),
            }));
            let proposal = AftAsyncBatchProposalV1::new(&instance, vec![transaction]).unwrap();
            let payload = codec::to_bytes_canonical(&proposal).unwrap();
            let descriptor = AftAsyncProposalDescriptorV1 {
                instance_hash: instance.instance_hash().unwrap(),
                proposer,
                proposal_hash: aft_async_proposal_payload_hash(&payload).unwrap(),
                payload_len: payload.len() as u64,
                parent_root: instance.locked_root,
            };
            let binding = descriptor.binding_hash().unwrap();
            let availability_certificate = AftAsyncProposalAvailabilityCertificateV1 {
                protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
                schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
                descriptor,
                votes: (0..instance.geometry.quorum)
                    .map(|member_index| AftAsyncProposalAvailabilityVoteV1 {
                        proposal_binding_hash: binding,
                        member_index,
                        voter: account(member_index as u8 + 1),
                        signature_suite: SignatureSuite::ML_DSA_44,
                        signature: vec![1],
                    })
                    .collect(),
            };
            let proposal_ref = availability_certificate.proposal_ref(&instance).unwrap();
            entries.push((
                proposal_ref,
                AftAsyncSelectedProposalWitnessV1 {
                    proposal,
                    availability_certificate,
                },
            ));
        }
        let transcript = AftAsyncTranscriptSummaryV1::new(
            &instance,
            0,
            entries.iter().map(|entry| entry.0.clone()).collect(),
        )
        .unwrap();
        let decision = AftAsyncOrderingDecisionV1::new(
            instance.clone(),
            entries.iter().map(|entry| entry.0.clone()).collect(),
            transcript.transcript_root(&instance).unwrap(),
        )
        .unwrap();
        entries.sort_by_key(|entry| (entry.0.proposal_hash, entry.0.proposer));
        let decision_hash = decision.decision_hash().unwrap();
        let ordering = AftAsyncOrderingCertificateV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            decision,
            transcript,
            votes: (0..instance.geometry.quorum)
                .map(|member_index| AftAsyncDecisionVoteV1 {
                    decision_hash,
                    member_index,
                    voter: account(member_index as u8 + 1),
                    signature_suite: SignatureSuite::ML_DSA_44,
                    signature: vec![2],
                })
                .collect(),
        };
        let batch_witness = AftAsyncSelectedBatchWitnessV1 {
            selected: entries.into_iter().map(|entry| entry.1).collect(),
        };
        let executed = AftAsyncExecutedBlockDecisionV1::new(
            ordering.clone(),
            batch_witness.clone(),
            [0xA5; 32],
        )
        .unwrap();
        let executed_hash = executed.decision_hash().unwrap();
        let certificate = AftAsyncExecutedBlockCertificateV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            decision: executed,
            ordering,
            votes: (0..instance.geometry.quorum)
                .map(|member_index| AftAsyncExecutedBlockVoteV1 {
                    decision_hash: executed_hash,
                    member_index,
                    voter: account(member_index as u8 + 1),
                    signature_suite: SignatureSuite::ML_DSA_44,
                    signature: vec![3],
                })
                .collect(),
        };
        certificate.validate_with_witness(&batch_witness).unwrap();

        let mut rebound = certificate.clone();
        rebound.decision.block_hash[0] ^= 1;
        assert!(rebound.validate_with_witness(&batch_witness).is_err());

        let mut missing_vote = certificate;
        missing_vote.votes.pop();
        assert!(missing_vote.validate_shape().is_err());
    }
}
