// AFT assurance schema v1. Production authorization consumes this
// coordinate-wise form directly; the older scalar lattice remains only as
// theorem/reference data and is not promoted into a production vector.

use std::cmp::{max, min};

/// Domain separator for canonical GuaranteeVectorV1 commitments.
pub const GUARANTEE_VECTOR_V1_COMMITMENT_DOMAIN: &[u8] =
    b"ioi::aft::guarantee-vector::v1\0";

/// The fixed wire-version discriminator carried in every v1 vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeVectorVersion {
    /// First coordinate-wise assurance schema.
    V1,
}

/// Wire version for a separately represented assurance transformation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeTransformVersionV1 {
    /// First coordinate-specific transform schema.
    V1,
}

/// Exactly one coordinate a transformation proposes to establish. Keeping
/// this exhaustive prevents a proof about one property from changing another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeCoordinateV1 {
    /// Conflict safety, finality, committee geometry, and exact scope.
    Safety,
    /// Termination, network, adversary, and liveness geometry.
    Liveness,
    /// Consensus primitive posture.
    ConsensusPq,
    /// Authenticated-channel cryptographic posture.
    ChannelPq,
    /// Adapter and external-endpoint cryptographic posture.
    ExternalizationPq,
    /// Transferable attribution strength.
    Accountability,
    /// Publication, custody, and retention.
    Availability,
    /// External-resource mutation semantics.
    Externalization,
    /// Distinct enforceably slashable collateral.
    SlashableCollateral,
    /// Profile-bound empirical latency.
    MeasuredLatency,
}

/// Exhaustive transform-rule namespace. A named rule is only a request until
/// the corresponding independent evidence verifier is registered and passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeTransformRuleV1 {
    /// Establish safety from a separately verified proof.
    EstablishSafetyFromIndependentProof,
    /// Establish liveness from a separately verified proof.
    EstablishLivenessFromIndependentProof,
    /// Establish consensus PQ from a complete primitive verification.
    EstablishConsensusPqFromPrimitiveVerification,
    /// Establish channel PQ from a verified authenticated transcript/profile.
    EstablishChannelPqFromTranscriptVerification,
    /// Establish externalization PQ from endpoint and adapter verification.
    EstablishExternalizationPqFromEndpointVerification,
    /// Establish attribution from independently verified conflicting evidence.
    EstablishAccountabilityFromConflictProof,
    /// Establish availability from a verified custody proof.
    EstablishAvailabilityFromCustodyProof,
    /// Establish resource semantics from an independently verified proof.
    EstablishExternalizationFromResourceProof,
    /// Establish a collateral floor from a verified bond/distinctness proof.
    EstablishSlashableCollateralFromBondProof,
    /// Attach an empirical measurement under a committed benchmark profile.
    EstablishMeasuredLatencyFromBenchmarkEvidence,
}

impl GuaranteeTransformRuleV1 {
    fn coordinate(self) -> GuaranteeCoordinateV1 {
        match self {
            Self::EstablishSafetyFromIndependentProof => GuaranteeCoordinateV1::Safety,
            Self::EstablishLivenessFromIndependentProof => GuaranteeCoordinateV1::Liveness,
            Self::EstablishConsensusPqFromPrimitiveVerification => {
                GuaranteeCoordinateV1::ConsensusPq
            }
            Self::EstablishChannelPqFromTranscriptVerification => GuaranteeCoordinateV1::ChannelPq,
            Self::EstablishExternalizationPqFromEndpointVerification => {
                GuaranteeCoordinateV1::ExternalizationPq
            }
            Self::EstablishAccountabilityFromConflictProof => {
                GuaranteeCoordinateV1::Accountability
            }
            Self::EstablishAvailabilityFromCustodyProof => GuaranteeCoordinateV1::Availability,
            Self::EstablishExternalizationFromResourceProof => {
                GuaranteeCoordinateV1::Externalization
            }
            Self::EstablishSlashableCollateralFromBondProof => {
                GuaranteeCoordinateV1::SlashableCollateral
            }
            Self::EstablishMeasuredLatencyFromBenchmarkEvidence => {
                GuaranteeCoordinateV1::MeasuredLatency
            }
        }
    }
}

/// A proposed strengthening is distinct from evidence and from requirements.
/// Its hashes make the exact new proof, theorem, verifier, inputs, and claimed
/// output portable; none of those fields makes it verified by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeTransformV1 {
    /// Transformation wire version.
    pub schema_version: GuaranteeTransformVersionV1,
    /// The only coordinate the rule may change.
    pub coordinate: GuaranteeCoordinateV1,
    /// Exhaustive rule identifier.
    pub rule: GuaranteeTransformRuleV1,
    /// Commitments to every input vector.
    pub input_vector_hashes: BTreeSet<[u8; 32]>,
    /// Commitment to evidence not already present in the inputs.
    pub new_evidence_hash: [u8; 32],
    /// The theorem that permits the coordinate change.
    pub theorem_id: String,
    /// Commitment to the independent verifier implementation/profile.
    pub verifier_profile_hash: [u8; 32],
    /// Commitment to the exact claimed transformed vector.
    pub claimed_output_hash: [u8; 32],
}

impl GuaranteeTransformV1 {
    /// Structural metadata validation is not proof verification.
    pub fn validate_metadata(&self) -> Result<(), GuaranteeVectorError> {
        if self.coordinate != self.rule.coordinate() {
            return Err(GuaranteeVectorError::TransformCoordinateMismatch);
        }
        if self.input_vector_hashes.is_empty()
            || self.new_evidence_hash == [0; 32]
            || self.verifier_profile_hash == [0; 32]
            || self.claimed_output_hash == [0; 32]
            || self.theorem_id.trim().is_empty()
        {
            return Err(GuaranteeVectorError::IncompleteTransformationEvidence);
        }
        Ok(())
    }
}

/// Adversary model proved by the evidence, not one inferred by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversaryModelV1 {
    /// No adversary theorem has been attached.
    Unspecified,
    /// Byzantine identities are fixed before the execution begins.
    StaticByzantine,
    /// Byzantine identities may change during the execution.
    AdaptiveByzantine,
}

/// Progress theorem class. Different non-empty classes are deliberately not
/// ordered: their assumptions differ, so composition retains a class only
/// when every constituent agrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationV1 {
    /// The evidence makes no progress claim.
    NotClaimed,
    /// Deterministic termination after eventual synchrony.
    DeterministicEventualSynchrony,
    /// Probabilistic termination without a synchrony bound.
    RandomizedAsynchronous,
}

/// Network assumption consumed by a liveness theorem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkAssumptionV1 {
    /// No network theorem has been attached.
    Unspecified,
    /// Messages are eventually delivered within an unknown fixed bound.
    EventualSynchrony,
    /// Asynchronous pairwise private authenticated channels are available.
    AsynchronousPrivateAuthenticatedChannels,
}

/// Conflict-safety construction proved by the evidence. Legacy guardian
/// majority is named separately so it cannot masquerade as quorum-intersection
/// BFT merely because both once shared the scalar `LiveTierBft` rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyModelV1 {
    /// No conflict-safety construction has been established.
    Unspecified,
    /// Observer or witness evidence with no consensus-authority claim.
    Observational,
    /// Historical guardian strict-majority profile; not the target BFT core.
    LegacyGuardianMajority,
    /// Byzantine quorum intersection with explicit committee geometry.
    QuorumIntersectionBft,
    /// Unanimous boundary close with one-honest-signer conflict safety.
    UnanimousAllButOne,
    /// An all-but-one close additionally bound to a declared freshness anchor.
    AnchoredUnanimousAllButOne,
}

/// Cryptographic primitive families named by the receipt. `Unresolved` is a
/// fail-closed marker and can never participate in an end-to-end PQ claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveSuiteV1 {
    /// One or more load-bearing primitives have not been identified.
    Unresolved,
    /// SHA-256-class hash commitments.
    Sha256,
    /// Classical Ed25519 signatures.
    Ed25519,
    /// Classical BLS12-381 aggregate or threshold signatures.
    Bls12381,
    /// ML-DSA-44 post-quantum signatures.
    MlDsa44,
    /// A versioned standardized hash-based signature profile.
    HashBasedSignature,
    /// A post-quantum authenticated private-channel profile.
    PqAuthenticatedChannel,
    /// A classically authenticated channel profile.
    ClassicalAuthenticatedChannel,
}

/// Transferable blame strength. Ordered weakest-first for evidence meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountabilityV1 {
    /// No transferable blame claim.
    None,
    /// Evidence is meaningful only relative to a named holder's view.
    HolderRelative,
    /// Evidence can be verified by an unrelated third party.
    Transferable,
    /// A conflict names every member of the responsible configuration.
    FullConfiguration,
}

/// External-resource mutation contract proved by the adapter profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalizationModeV1 {
    /// No external-resource consequence is claimed.
    NotClaimed,
    /// Invocation is attempted without an atomic resource deduplication contract.
    BestEffort,
    /// The resource exposes an atomic idempotency register or equivalent CAS.
    IdempotencyRegister,
}

/// Safety coordinates. Configuration and conflict-domain commitments are
/// optional only for legacy migration; new production evidence must populate
/// them before it can authorize a scoped effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyCoordinateV1 {
    /// Exact conflict-safety construction.
    pub model: SafetyModelV1,
    /// Weakest finality theorem established by the evidence.
    pub finality_rank: Option<GuaranteeRank>,
    /// Committee cardinality, when bound by the certificate.
    pub committee_n: Option<u32>,
    /// Maximum Byzantine members tolerated by the theorem.
    pub fault_bound_f: Option<u32>,
    /// Minimum certificate quorum.
    pub quorum_q: Option<u32>,
    /// Commitment to the exact membership/configuration.
    pub configuration_hash: Option<[u8; 32]>,
    /// Commitment to the independent conflict domain.
    pub conflict_domain_hash: Option<[u8; 32]>,
}

/// Liveness coordinates. `private_authenticated_channels` is explicit so a
/// hash-only protocol cannot launder an unspecified transport into a PQ claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessCoordinateV1 {
    /// Termination theorem class.
    pub termination: TerminationV1,
    /// Network model consumed by the termination theorem.
    pub network: NetworkAssumptionV1,
    /// Corruption model consumed by the termination theorem.
    pub adversary: AdversaryModelV1,
    /// Committee cardinality for the liveness theorem.
    pub committee_n: Option<u32>,
    /// Byzantine fault bound for the liveness theorem.
    pub fault_bound_f: Option<u32>,
    /// Whether the theorem assumes pairwise private authenticated channels.
    pub private_authenticated_channels: bool,
}

/// Cryptographic coordinates. `end_to_end_pq` is serialized for portable
/// receipts but is valid only when it exactly equals the conjunction of all
/// load-bearing PQ coordinates and no suite remains unresolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoCoordinateV1 {
    /// All load-bearing consensus primitives are post-quantum.
    pub consensus_pq: bool,
    /// Confidentiality and peer authentication are post-quantum.
    pub channel_pq: bool,
    /// The adapter and external endpoint verification chain is post-quantum.
    pub externalization_pq: bool,
    /// Validated conjunction of the three preceding PQ coordinates.
    pub end_to_end_pq: bool,
    /// True means a private threshold setup or DKG is load-bearing.
    pub private_threshold_setup: bool,
    /// Exhaustive primitive families consumed by verification.
    pub primitive_suites: BTreeSet<PrimitiveSuiteV1>,
}

impl CryptoCoordinateV1 {
    fn derived_end_to_end_pq(&self) -> bool {
        self.consensus_pq
            && self.channel_pq
            && self.externalization_pq
            && !self.primitive_suites.contains(&PrimitiveSuiteV1::Unresolved)
    }

    fn recompute_end_to_end_pq(&mut self) {
        self.end_to_end_pq = self.derived_end_to_end_pq();
    }
}

/// Availability and custody claims kept distinct from conflict safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityCoordinateV1 {
    /// Published artifacts are retrievable under the named assumptions.
    pub publication_retrievable: bool,
    /// Minimum independent custody holders, when established.
    pub custody_threshold: Option<u32>,
    /// Retention horizon in protocol-defined units.
    pub retention_horizon: Option<u64>,
}

/// Externalization claim and the exact adapter/resource profile that earned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalizationCoordinateV1 {
    /// External-resource contract class.
    pub mode: ExternalizationModeV1,
    /// Whether the modeled resource mutation is proved at-most-once.
    pub at_most_once: bool,
    /// Commitment to the exact adapter and resource semantics.
    pub adapter_profile_hash: Option<[u8; 32]>,
}

/// Mechanically verifiable economic assurance. This is slashable collateral,
/// not a generic claim about the adversary's acquisition or violation cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlashableCollateralV1 {
    /// Commitment to the collateral asset identifier.
    pub asset_id_hash: [u8; 32],
    /// Minimum distinct slashable amount in canonical unsigned decimal base
    /// units. A string avoids JSON/JCS precision limits for large assets.
    pub amount_base_units: String,
    /// Commitment to the complete collateral set.
    pub collateral_set_hash: [u8; 32],
    /// State root at which bonds and encumbrances were checked.
    pub bond_snapshot_root: [u8; 32],
    /// Protocol height/time through which the collateral remains locked.
    pub locked_until: u64,
    /// Commitment to the objective fault-evidence predicate.
    pub evidence_rule_hash: [u8; 32],
    /// Commitment to the enforceable slashing contract.
    pub slashing_contract_hash: [u8; 32],
    /// Optional commitment to oracle and valuation assumptions.
    pub valuation_assumptions_hash: Option<[u8; 32]>,
}

/// Policy floor for one native collateral asset. Different assets are not
/// ordered or converted by the consensus verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlashableCollateralRequirementV1 {
    /// Exact asset in which the floor is denominated.
    pub asset_id_hash: [u8; 32],
    /// Minimum independently verified distinct base units.
    pub minimum_amount_base_units: String,
}

/// Measured latency belongs to a named profile and percentile; it is never a
/// theorem-wide scalar that silently crosses crypto profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredLatencyV1 {
    /// Commitment to the benchmark and crypto/network profile.
    pub profile_hash: [u8; 32],
    /// Percentile in basis points, where 10_000 means p100.
    pub percentile_bps: u16,
    /// Observed duration at the named percentile.
    pub milliseconds: u64,
}

/// Portable coordinate-wise assurance statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeVectorV1 {
    /// Wire schema discriminator.
    pub schema_version: GuaranteeVectorVersion,
    /// Conflict-safety coordinates.
    pub safety: SafetyCoordinateV1,
    /// Progress coordinates.
    pub liveness: LivenessCoordinateV1,
    /// Cryptographic posture and primitive census.
    pub crypto: CryptoCoordinateV1,
    /// Transferable fault-attribution strength.
    pub accountability: AccountabilityV1,
    /// Publication and custody coordinates.
    pub availability: AvailabilityCoordinateV1,
    /// External consequence semantics.
    pub externalization: ExternalizationCoordinateV1,
    /// Optional distinct slashable-collateral floor.
    pub slashable_collateral: Option<SlashableCollateralV1>,
    /// Optional measured, profile-scoped latency.
    pub measured_latency: Option<MeasuredLatencyV1>,
    /// Union of assumptions consumed by every constituent.
    pub assumptions: BTreeSet<AssumptionId>,
    /// Theorems applied by the verifier.
    pub theorem_ids: BTreeSet<String>,
    /// Legacy/profile identities participating in this vector.
    pub certificate_profiles: BTreeSet<CertificateProfile>,
    /// Commitments to the verified evidence objects.
    pub constituent_hashes: BTreeSet<[u8; 32]>,
    /// Commitments to independently verified strengthening transforms.
    pub transformation_hashes: BTreeSet<[u8; 32]>,
}

/// Strict policy requirements are a different type and operation from an
/// evidence meet. This prevents callers from using a policy join as evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GuaranteeRequirementsV1 {
    /// Lowest acceptable conflict-safety rank.
    pub minimum_finality_rank: Option<GuaranteeRank>,
    /// Required exact configuration commitment.
    pub configuration_hash: Option<[u8; 32]>,
    /// Required exact conflict-domain commitment.
    pub conflict_domain_hash: Option<[u8; 32]>,
    /// Require post-quantum consensus primitives.
    pub require_consensus_pq: bool,
    /// Require post-quantum confidentiality and peer authentication.
    pub require_channel_pq: bool,
    /// Require a post-quantum externalization verification chain.
    pub require_externalization_pq: bool,
    /// Require the validated conjunction of all PQ coordinates.
    pub require_end_to_end_pq: bool,
    /// Refuse any private threshold setup or DKG dependency.
    pub require_no_private_threshold_setup: bool,
    /// Lowest acceptable transferable-accountability class.
    pub minimum_accountability: Option<AccountabilityV1>,
    /// Require the publication/custody verifier to establish retrievability.
    pub require_publication_retrievable: bool,
    /// Lowest acceptable external-resource contract.
    pub minimum_externalization: Option<ExternalizationModeV1>,
    /// Require modeled at-most-once resource mutation.
    pub require_at_most_once: bool,
    /// Optional floor on distinct, objectively slashable native collateral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_slashable_collateral: Option<SlashableCollateralRequirementV1>,
}

/// Opaque policy input produced only by the assurance verifier. Callers may
/// inspect or serialize the achieved vector, but cannot turn a raw claimed
/// vector into an authorization input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGuaranteeV1 {
    achieved: GuaranteeVectorV1,
}

impl VerifiedGuaranteeV1 {
    /// Borrow the verifier-derived achieved vector.
    pub fn achieved(&self) -> &GuaranteeVectorV1 {
        &self.achieved
    }

    /// Consume the opaque wrapper after verification.
    pub fn into_achieved(self) -> GuaranteeVectorV1 {
        self.achieved
    }

    /// Attach a coordinate produced by the independent economic-assurance
    /// verifier. This is crate-private so raw claims cannot mint the opaque
    /// policy input. A differing existing coordinate fails closed.
    pub(crate) fn with_verified_collateral(
        &self,
        collateral: SlashableCollateralV1,
        proof_commitment: [u8; 32],
    ) -> Result<Self, GuaranteeVectorError> {
        if self
            .achieved
            .slashable_collateral
            .as_ref()
            .is_some_and(|existing| existing != &collateral)
        {
            return Err(GuaranteeVectorError::ConflictingVerifiedCollateral);
        }
        let mut achieved = self.achieved.clone();
        achieved.slashable_collateral = Some(collateral);
        achieved.constituent_hashes.insert(proof_commitment);
        achieved.theorem_ids.insert("T11".into());
        achieved.validate()?;
        Ok(Self { achieved })
    }
}

/// The L-M certificate-only verifier. It derives the meet itself and never
/// trusts a wrapper's reported output. Coordinate transforms are a separate
/// trace and default to refusal until an independent rule verifier lands.
#[derive(Debug, Default, Clone, Copy)]
pub struct CertificateOnlyGuaranteeVerifierV1;

impl CertificateOnlyGuaranteeVerifierV1 {
    /// Recompute the conservative evidence meet from verified labels.
    pub fn verify(
        constituents: &[GuaranteeVectorV1],
    ) -> Result<VerifiedGuaranteeV1, GuaranteeVectorError> {
        let achieved = GuaranteeVectorV1::evidence_meet(constituents)?;
        Ok(VerifiedGuaranteeV1 { achieved })
    }

    /// Verify that a wrapper's report is exactly the recomputed meet. Any
    /// requested strengthening is refused until its independent rule lands.
    pub fn verify_claim(
        constituents: &[GuaranteeVectorV1],
        claimed: &GuaranteeVectorV1,
        transformations: &[GuaranteeTransformV1],
    ) -> Result<VerifiedGuaranteeV1, GuaranteeVectorError> {
        let verified = Self::verify(constituents)?;
        for transformation in transformations {
            transformation.validate_metadata()?;
        }
        if !transformations.is_empty() {
            return Err(GuaranteeVectorError::UnsupportedTransformation);
        }
        claimed.validate()?;
        if claimed != verified.achieved() {
            return Err(GuaranteeVectorError::ClaimDiffersFromVerifiedMeet);
        }
        Ok(verified)
    }
}

/// Typed validation, composition, encoding, and policy-join refusals.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuaranteeVectorError {
    /// No evidence was supplied to the meet.
    #[error("evidence composition is empty")]
    EmptyComposition,
    /// The serialized aggregate PQ bit contradicts its source coordinates.
    #[error("end_to_end_pq does not equal the validated PQ conjunction")]
    InvalidEndToEndPq,
    /// At-most-once was asserted without an atomic resource contract.
    #[error("at_most_once requires an idempotency-register profile")]
    InvalidAtMostOnce,
    /// At-most-once was asserted without committing to exact adapter semantics.
    #[error("at_most_once requires an adapter profile commitment")]
    MissingAtMostOnceProfile,
    /// Some, but not all, committee geometry fields were supplied.
    #[error("committee coordinates must be either entirely present or entirely absent")]
    IncompleteBftCoordinates,
    /// The supplied committee tuple does not meet the declared safety model.
    #[error("committee coordinates violate the declared safety-model geometry")]
    InvalidBftCoordinates,
    /// Quorum-intersection BFT was claimed without exact committee geometry.
    #[error("quorum-intersection BFT requires exact n, f, and q")]
    MissingBftCoordinates,
    /// A serialized end-to-end PQ claim names a classical or empty suite.
    #[error("end_to_end_pq requires a complete PQ-only primitive census")]
    InvalidPqPrimitiveCensus,
    /// End-to-end PQ was asserted without a finality-bearing committed chain.
    #[error("end_to_end_pq requires finality-bearing committed constituents")]
    MissingPqConstituents,
    /// A legacy certificate profile in the chain is explicitly non-PQ.
    #[error("end_to_end_pq includes a certificate profile labelled non-PQ")]
    NonPqCertificateProfile,
    /// Unknown or not-yet-verified strengthening transformations fail closed.
    #[error("unknown guarantee transformation is not supported")]
    UnsupportedTransformation,
    /// The rule and the coordinate it is allowed to change disagree.
    #[error("guarantee transformation rule targets a different coordinate")]
    TransformCoordinateMismatch,
    /// A transformation omitted its input, evidence, theorem, verifier, or output commitment.
    #[error("guarantee transformation lacks independently verifiable metadata")]
    IncompleteTransformationEvidence,
    /// A wrapper-reported output was not exactly the certificate-derived meet.
    #[error("claimed guarantee vector differs from the verified evidence meet")]
    ClaimDiffersFromVerifiedMeet,
    /// The collateral amount is not canonical unsigned decimal base units.
    #[error("slashable collateral amount is not canonical unsigned decimal")]
    InvalidCollateralAmount,
    /// Two independently verified collateral coordinates disagree.
    #[error("verified collateral coordinate conflicts with the existing vector")]
    ConflictingVerifiedCollateral,
    /// The measured percentile lies outside its canonical range.
    #[error("percentile basis points must be in 1..=10000")]
    InvalidLatencyPercentile,
    /// Two policies demand incompatible exact scope commitments.
    #[error("incompatible exact requirement for {0}")]
    IncompatibleRequirement(&'static str),
    /// RFC 8785/JCS encoding failed.
    #[error("canonical encoding failed: {0}")]
    CanonicalEncoding(String),
    /// Domain-separated commitment construction failed.
    #[error("commitment hashing failed: {0}")]
    CommitmentHash(String),
}

impl GuaranteeVectorV1 {
    /// Validates cross-coordinate claims. Deserialization alone never makes a
    /// receipt trustworthy; authorization and offline verification call this.
    pub fn validate(&self) -> Result<(), GuaranteeVectorError> {
        if self.crypto.end_to_end_pq != self.crypto.derived_end_to_end_pq() {
            return Err(GuaranteeVectorError::InvalidEndToEndPq);
        }
        if self.externalization.at_most_once
            && self.externalization.mode != ExternalizationModeV1::IdempotencyRegister
        {
            return Err(GuaranteeVectorError::InvalidAtMostOnce);
        }
        if self.externalization.at_most_once
            && self.externalization.adapter_profile_hash.is_none()
        {
            return Err(GuaranteeVectorError::MissingAtMostOnceProfile);
        }
        let geometry = (
            self.safety.committee_n,
            self.safety.fault_bound_f,
            self.safety.quorum_q,
        );
        match geometry {
            (Some(n), Some(f), Some(q)) => match self.safety.model {
                SafetyModelV1::QuorumIntersectionBft => {
                    if n < f.saturating_mul(3).saturating_add(1)
                        || q < f.saturating_mul(2).saturating_add(1)
                        || q.saturating_mul(2) <= n.saturating_add(f)
                        || q > n.saturating_sub(f)
                        || q > n
                    {
                        return Err(GuaranteeVectorError::InvalidBftCoordinates);
                    }
                }
                SafetyModelV1::UnanimousAllButOne
                | SafetyModelV1::AnchoredUnanimousAllButOne => {
                    if n < 2 || f != n - 1 || q != n {
                        return Err(GuaranteeVectorError::InvalidBftCoordinates);
                    }
                }
                _ => return Err(GuaranteeVectorError::InvalidBftCoordinates),
            },
            (None, None, None) => {}
            _ => return Err(GuaranteeVectorError::IncompleteBftCoordinates),
        }
        if self.safety.model == SafetyModelV1::QuorumIntersectionBft
            && matches!(geometry, (None, None, None))
        {
            return Err(GuaranteeVectorError::MissingBftCoordinates);
        }
        if self.crypto.end_to_end_pq
            && (self.crypto.primitive_suites.is_empty()
                || !self
                    .crypto
                    .primitive_suites
                    .contains(&PrimitiveSuiteV1::PqAuthenticatedChannel)
                || self.crypto.primitive_suites.iter().any(|suite| {
                    matches!(
                        suite,
                        PrimitiveSuiteV1::Unresolved
                            | PrimitiveSuiteV1::Ed25519
                            | PrimitiveSuiteV1::Bls12381
                            | PrimitiveSuiteV1::ClassicalAuthenticatedChannel
                    )
                }))
        {
            return Err(GuaranteeVectorError::InvalidPqPrimitiveCensus);
        }
        if self.crypto.end_to_end_pq
            && (self.safety.finality_rank.is_none()
                || self.constituent_hashes.is_empty()
                || self.certificate_profiles.is_empty())
        {
            return Err(GuaranteeVectorError::MissingPqConstituents);
        }
        if self.crypto.end_to_end_pq
            && self
                .certificate_profiles
                .iter()
                .any(|profile| !label_of(*profile).pq)
        {
            return Err(GuaranteeVectorError::NonPqCertificateProfile);
        }
        if !self.transformation_hashes.is_empty() {
            // M4 will replace this blanket refusal with an exhaustive registry
            // of coordinate-specific transforms and their proof commitments.
            return Err(GuaranteeVectorError::UnsupportedTransformation);
        }
        if let Some(collateral) = &self.slashable_collateral {
            let amount = collateral.amount_base_units.as_bytes();
            if amount.is_empty()
                || amount.iter().any(|byte| !byte.is_ascii_digit())
                || (amount.len() > 1 && amount[0] == b'0')
            {
                return Err(GuaranteeVectorError::InvalidCollateralAmount);
            }
        }
        if let Some(latency) = &self.measured_latency {
            if latency.percentile_bps == 0 || latency.percentile_bps > 10_000 {
                return Err(GuaranteeVectorError::InvalidLatencyPercentile);
            }
        }
        Ok(())
    }

    /// RFC 8785/JCS bytes are the canonical portable wire representation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GuaranteeVectorError> {
        self.validate()?;
        serde_jcs::to_vec(self)
            .map_err(|error| GuaranteeVectorError::CanonicalEncoding(error.to_string()))
    }

    /// Domain-separated SHA-256 commitment to the canonical vector.
    pub fn commitment(&self) -> Result<[u8; 32], GuaranteeVectorError> {
        let canonical = self.canonical_bytes()?;
        let mut material = Vec::with_capacity(
            GUARANTEE_VECTOR_V1_COMMITMENT_DOMAIN.len() + canonical.len(),
        );
        material.extend_from_slice(GUARANTEE_VECTOR_V1_COMMITMENT_DOMAIN);
        material.extend_from_slice(&canonical);
        let digest = DcryptSha256::digest(&material)
            .map_err(|error| GuaranteeVectorError::CommitmentHash(error.to_string()))?;
        digest
            .as_ref()
            .try_into()
            .map_err(|_| GuaranteeVectorError::CommitmentHash("SHA-256 returned non-32-byte digest".into()))
    }

    /// Conservative evidence meet. Incomparable liveness/network claims and
    /// mismatched exact scopes collapse to `Unspecified`/`None`, never to the
    /// stronger sibling. Boolean PQ claims use AND.
    pub fn evidence_meet(vectors: &[GuaranteeVectorV1]) -> Result<Self, GuaranteeVectorError> {
        let (first, rest) = vectors
            .split_first()
            .ok_or(GuaranteeVectorError::EmptyComposition)?;
        first.validate()?;
        let mut out = first.clone();
        for next in rest {
            next.validate()?;
            out.safety.finality_rank = meet_optional_rank(
                out.safety.finality_rank,
                next.safety.finality_rank,
            );
            out.safety.model = retain_equal_value(
                out.safety.model,
                next.safety.model,
                SafetyModelV1::Unspecified,
            );
            out.safety.committee_n = retain_equal(out.safety.committee_n, next.safety.committee_n);
            out.safety.fault_bound_f =
                retain_equal(out.safety.fault_bound_f, next.safety.fault_bound_f);
            out.safety.quorum_q = retain_equal(out.safety.quorum_q, next.safety.quorum_q);
            out.safety.configuration_hash = retain_equal(
                out.safety.configuration_hash,
                next.safety.configuration_hash,
            );
            out.safety.conflict_domain_hash = retain_equal(
                out.safety.conflict_domain_hash,
                next.safety.conflict_domain_hash,
            );
            out.liveness.termination = retain_equal_value(
                out.liveness.termination,
                next.liveness.termination,
                TerminationV1::NotClaimed,
            );
            out.liveness.network = retain_equal_value(
                out.liveness.network,
                next.liveness.network,
                NetworkAssumptionV1::Unspecified,
            );
            out.liveness.adversary = retain_equal_value(
                out.liveness.adversary,
                next.liveness.adversary,
                AdversaryModelV1::Unspecified,
            );
            out.liveness.committee_n =
                retain_equal(out.liveness.committee_n, next.liveness.committee_n);
            out.liveness.fault_bound_f =
                retain_equal(out.liveness.fault_bound_f, next.liveness.fault_bound_f);
            out.liveness.private_authenticated_channels &=
                next.liveness.private_authenticated_channels;
            out.crypto.consensus_pq &= next.crypto.consensus_pq;
            out.crypto.channel_pq &= next.crypto.channel_pq;
            out.crypto.externalization_pq &= next.crypto.externalization_pq;
            out.crypto.private_threshold_setup |= next.crypto.private_threshold_setup;
            out.crypto
                .primitive_suites
                .extend(next.crypto.primitive_suites.iter().copied());
            out.crypto.recompute_end_to_end_pq();
            out.accountability = min(out.accountability, next.accountability);
            out.availability.publication_retrievable &=
                next.availability.publication_retrievable;
            out.availability.custody_threshold = meet_min_option(
                out.availability.custody_threshold,
                next.availability.custody_threshold,
            );
            out.availability.retention_horizon = meet_min_option(
                out.availability.retention_horizon,
                next.availability.retention_horizon,
            );
            out.externalization.mode = min(out.externalization.mode, next.externalization.mode);
            out.externalization.at_most_once &= next.externalization.at_most_once;
            out.externalization.adapter_profile_hash = retain_equal(
                out.externalization.adapter_profile_hash,
                next.externalization.adapter_profile_hash,
            );
            out.slashable_collateral = retain_equal(
                out.slashable_collateral,
                next.slashable_collateral.clone(),
            );
            out.measured_latency = retain_equal(
                out.measured_latency,
                next.measured_latency.clone(),
            );
            out.assumptions.extend(next.assumptions.iter().copied());
            out.theorem_ids.extend(next.theorem_ids.iter().cloned());
            out.certificate_profiles
                .extend(next.certificate_profiles.iter().copied());
            out.constituent_hashes
                .extend(next.constituent_hashes.iter().copied());
            out.transformation_hashes
                .extend(next.transformation_hashes.iter().copied());
        }
        out.validate()?;
        Ok(out)
    }
}

impl GuaranteeRequirementsV1 {
    /// Joins policy requirements by selecting the stricter lower bound. Exact
    /// scope commitments must agree; a conflict is a typed refusal.
    pub fn join(&self, other: &Self) -> Result<Self, GuaranteeVectorError> {
        Ok(Self {
            minimum_finality_rank: join_optional_rank(
                self.minimum_finality_rank,
                other.minimum_finality_rank,
            ),
            configuration_hash: join_exact(
                self.configuration_hash,
                other.configuration_hash,
                "configuration_hash",
            )?,
            conflict_domain_hash: join_exact(
                self.conflict_domain_hash,
                other.conflict_domain_hash,
                "conflict_domain_hash",
            )?,
            require_consensus_pq: self.require_consensus_pq || other.require_consensus_pq,
            require_channel_pq: self.require_channel_pq || other.require_channel_pq,
            require_externalization_pq: self.require_externalization_pq
                || other.require_externalization_pq,
            require_end_to_end_pq: self.require_end_to_end_pq || other.require_end_to_end_pq,
            require_no_private_threshold_setup: self.require_no_private_threshold_setup
                || other.require_no_private_threshold_setup,
            minimum_accountability: join_ordered(
                self.minimum_accountability,
                other.minimum_accountability,
            ),
            require_publication_retrievable: self.require_publication_retrievable
                || other.require_publication_retrievable,
            minimum_externalization: join_ordered(
                self.minimum_externalization,
                other.minimum_externalization,
            ),
            require_at_most_once: self.require_at_most_once || other.require_at_most_once,
            minimum_slashable_collateral: join_collateral_requirement(
                self.minimum_slashable_collateral.as_ref(),
                other.minimum_slashable_collateral.as_ref(),
            )?,
        })
    }

    /// Returns true only when a verifier-derived vector satisfies every joined
    /// lower bound and exact scope requirement. Raw vectors are not accepted.
    pub fn is_satisfied_by(&self, verified: &VerifiedGuaranteeV1) -> bool {
        let achieved = verified.achieved();
        optional_at_least(achieved.safety.finality_rank, self.minimum_finality_rank)
            && optional_exact(
                achieved.safety.configuration_hash,
                self.configuration_hash,
            )
            && optional_exact(
                achieved.safety.conflict_domain_hash,
                self.conflict_domain_hash,
            )
            && (!self.require_consensus_pq || achieved.crypto.consensus_pq)
            && (!self.require_channel_pq || achieved.crypto.channel_pq)
            && (!self.require_externalization_pq || achieved.crypto.externalization_pq)
            && (!self.require_end_to_end_pq || achieved.crypto.end_to_end_pq)
            && (!self.require_no_private_threshold_setup
                || !achieved.crypto.private_threshold_setup)
            && optional_at_least(
                Some(achieved.accountability),
                self.minimum_accountability,
            )
            && (!self.require_publication_retrievable
                || achieved.availability.publication_retrievable)
            && optional_at_least(
                Some(achieved.externalization.mode),
                self.minimum_externalization,
            )
            && (!self.require_at_most_once || achieved.externalization.at_most_once)
            && collateral_requirement_satisfied(
                achieved.slashable_collateral.as_ref(),
                self.minimum_slashable_collateral.as_ref(),
            )
    }
}

/// Conservative v1 label for every legacy certificate profile. Existing
/// profiles do not establish a complete PQ channel + execution chain, so none
/// can produce `end_to_end_pq=true` during migration.
pub fn guarantee_vector_of(profile: CertificateProfile) -> GuaranteeVectorV1 {
    use CertificateProfile::*;
    let legacy = label_of(profile);
    let (termination, network) = match profile {
        LiveQuorumCert
        | ClassicalSignedLiveQuorumCert
        | PqLiveQuorumCert
        | GuardianCommitteeCert => (
            TerminationV1::DeterministicEventualSynchrony,
            NetworkAssumptionV1::EventualSynchrony,
        ),
        HashAsyncOrderingCert => (
            TerminationV1::RandomizedAsynchronous,
            NetworkAssumptionV1::AsynchronousPrivateAuthenticatedChannels,
        ),
        _ => (TerminationV1::NotClaimed, NetworkAssumptionV1::Unspecified),
    };
    let primitive_suites = match profile {
        LiveQuorumCert => BTreeSet::from([PrimitiveSuiteV1::Sha256, PrimitiveSuiteV1::Bls12381]),
        ClassicalSignedLiveQuorumCert => {
            BTreeSet::from([PrimitiveSuiteV1::Sha256, PrimitiveSuiteV1::Ed25519])
        }
        PqLiveQuorumCert | HashAsyncOrderingCert => {
            BTreeSet::from([PrimitiveSuiteV1::Sha256, PrimitiveSuiteV1::MlDsa44])
        }
        GuardianCommitteeCert
        | WitnessCert
        | ObserverCert
        | UnanimousBoundaryClose
        | AnchoredBoundaryClose
        | RegenesisRoot => {
            BTreeSet::from([PrimitiveSuiteV1::Sha256, PrimitiveSuiteV1::Ed25519])
        }
        PqUnanimousBoundaryClose | PqAnchoredBoundaryClose => BTreeSet::from([
            PrimitiveSuiteV1::Sha256,
            PrimitiveSuiteV1::HashBasedSignature,
        ]),
        HashPcdReference => BTreeSet::from([PrimitiveSuiteV1::Sha256]),
    };
    let accountability = match profile {
        UnanimousBoundaryClose
        | PqUnanimousBoundaryClose
        | AnchoredBoundaryClose
        | PqAnchoredBoundaryClose => AccountabilityV1::FullConfiguration,
        _ => AccountabilityV1::None,
    };
    let safety_model = match profile {
        LiveQuorumCert | GuardianCommitteeCert => SafetyModelV1::LegacyGuardianMajority,
        ClassicalSignedLiveQuorumCert | PqLiveQuorumCert | HashAsyncOrderingCert => {
            SafetyModelV1::Unspecified
        }
        WitnessCert | ObserverCert => SafetyModelV1::Observational,
        UnanimousBoundaryClose | PqUnanimousBoundaryClose => {
            SafetyModelV1::UnanimousAllButOne
        }
        AnchoredBoundaryClose | PqAnchoredBoundaryClose => {
            SafetyModelV1::AnchoredUnanimousAllButOne
        }
        HashPcdReference | RegenesisRoot => SafetyModelV1::Unspecified,
    };
    let theorem_ids = match profile {
        LiveQuorumCert
        | ClassicalSignedLiveQuorumCert
        | PqLiveQuorumCert
        | HashAsyncOrderingCert
        | GuardianCommitteeCert => BTreeSet::from(["T4a".to_string()]),
        UnanimousBoundaryClose
        | PqUnanimousBoundaryClose
        | AnchoredBoundaryClose
        | PqAnchoredBoundaryClose => {
            BTreeSet::from(["T1".to_string(), "T7".to_string()])
        }
        WitnessCert | ObserverCert | HashPcdReference | RegenesisRoot => BTreeSet::new(),
    };
    GuaranteeVectorV1 {
        schema_version: GuaranteeVectorVersion::V1,
        safety: SafetyCoordinateV1 {
            model: safety_model,
            finality_rank: legacy.finality_rank,
            committee_n: None,
            fault_bound_f: None,
            quorum_q: None,
            configuration_hash: None,
            conflict_domain_hash: None,
        },
        liveness: LivenessCoordinateV1 {
            termination,
            network,
            adversary: if profile == HashAsyncOrderingCert {
                AdversaryModelV1::StaticByzantine
            } else {
                AdversaryModelV1::Unspecified
            },
            committee_n: None,
            fault_bound_f: None,
            private_authenticated_channels: profile == HashAsyncOrderingCert,
        },
        crypto: CryptoCoordinateV1 {
            // The legacy profile label does not prove the complete consensus,
            // channel, and externalization chains required by v1.
            consensus_pq: matches!(
                profile,
                PqLiveQuorumCert
                    | HashAsyncOrderingCert
                    | PqUnanimousBoundaryClose
                    | PqAnchoredBoundaryClose
            ),
            channel_pq: false,
            externalization_pq: false,
            end_to_end_pq: false,
            private_threshold_setup: matches!(profile, LiveQuorumCert),
            primitive_suites,
        },
        accountability,
        availability: AvailabilityCoordinateV1 {
            publication_retrievable: legacy.assumes.contains(&AssumptionId::A4),
            custody_threshold: None,
            retention_horizon: None,
        },
        externalization: ExternalizationCoordinateV1 {
            mode: ExternalizationModeV1::NotClaimed,
            at_most_once: false,
            adapter_profile_hash: None,
        },
        slashable_collateral: None,
        measured_latency: None,
        assumptions: legacy.assumes,
        theorem_ids,
        certificate_profiles: BTreeSet::from([profile]),
        constituent_hashes: BTreeSet::new(),
        transformation_hashes: BTreeSet::new(),
    }
}

fn meet_optional_rank(
    left: Option<GuaranteeRank>,
    right: Option<GuaranteeRank>,
) -> Option<GuaranteeRank> {
    match (left, right) {
        (Some(left), Some(right)) => Some(min(left, right)),
        (Some(rank), None) | (None, Some(rank)) => Some(rank),
        (None, None) => None,
    }
}

fn join_optional_rank(
    left: Option<GuaranteeRank>,
    right: Option<GuaranteeRank>,
) -> Option<GuaranteeRank> {
    match (left, right) {
        (Some(left), Some(right)) => Some(max(left, right)),
        (Some(rank), None) | (None, Some(rank)) => Some(rank),
        (None, None) => None,
    }
}

fn retain_equal<T: PartialEq>(left: Option<T>, right: Option<T>) -> Option<T> {
    if left == right { left } else { None }
}

fn retain_equal_value<T: Copy + PartialEq>(left: T, right: T, fallback: T) -> T {
    if left == right { left } else { fallback }
}

fn meet_min_option<T: Ord>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(min(left, right)),
        _ => None,
    }
}

fn join_exact<T: Copy + PartialEq>(
    left: Option<T>,
    right: Option<T>,
    coordinate: &'static str,
) -> Result<Option<T>, GuaranteeVectorError> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => {
            Err(GuaranteeVectorError::IncompatibleRequirement(coordinate))
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn join_ordered<T: Ord>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(max(left, right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn optional_at_least<T: Ord>(achieved: Option<T>, required: Option<T>) -> bool {
    match required {
        Some(required) => achieved.is_some_and(|achieved| achieved >= required),
        None => true,
    }
}

fn optional_exact<T: PartialEq>(achieved: Option<T>, required: Option<T>) -> bool {
    required.is_none() || achieved == required
}

fn join_collateral_requirement(
    left: Option<&SlashableCollateralRequirementV1>,
    right: Option<&SlashableCollateralRequirementV1>,
) -> Result<Option<SlashableCollateralRequirementV1>, GuaranteeVectorError> {
    match (left, right) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => {
            validate_canonical_decimal(&value.minimum_amount_base_units)?;
            Ok(Some(value.clone()))
        }
        (Some(left), Some(right)) => {
            if left.asset_id_hash != right.asset_id_hash {
                return Err(GuaranteeVectorError::IncompatibleRequirement(
                    "slashable_collateral.asset_id_hash",
                ));
            }
            validate_canonical_decimal(&left.minimum_amount_base_units)?;
            validate_canonical_decimal(&right.minimum_amount_base_units)?;
            let minimum_amount_base_units = if decimal_cmp(
                &left.minimum_amount_base_units,
                &right.minimum_amount_base_units,
            ) == std::cmp::Ordering::Less
            {
                right.minimum_amount_base_units.clone()
            } else {
                left.minimum_amount_base_units.clone()
            };
            Ok(Some(SlashableCollateralRequirementV1 {
                asset_id_hash: left.asset_id_hash,
                minimum_amount_base_units,
            }))
        }
    }
}

fn collateral_requirement_satisfied(
    achieved: Option<&SlashableCollateralV1>,
    required: Option<&SlashableCollateralRequirementV1>,
) -> bool {
    let Some(required) = required else {
        return true;
    };
    let Some(achieved) = achieved else {
        return false;
    };
    achieved.asset_id_hash == required.asset_id_hash
        && validate_canonical_decimal(&required.minimum_amount_base_units).is_ok()
        && validate_canonical_decimal(&achieved.amount_base_units).is_ok()
        && decimal_cmp(
            &achieved.amount_base_units,
            &required.minimum_amount_base_units,
        ) != std::cmp::Ordering::Less
}

fn validate_canonical_decimal(value: &str) -> Result<(), GuaranteeVectorError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        Err(GuaranteeVectorError::InvalidCollateralAmount)
    } else {
        Ok(())
    }
}

fn decimal_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}
