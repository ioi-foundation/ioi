// Versioned transition evidence from optimistic AFT into one asynchronous
// fallback instance.

/// Protocol version for the first AFT fallback-start certificate.
pub const AFT_FALLBACK_PROTOCOL_VERSION_V1: u16 = 1;
/// Schema version for the first AFT fallback-start certificate.
pub const AFT_FALLBACK_SCHEMA_VERSION_V1: u16 = 1;
/// The normative optimistic profile enters fallback after timeout
/// certificates for views 1, 2, and 3 at one height.
pub const AFT_FALLBACK_TRIGGER_VIEW_V1: u64 = 3;

/// Protocol version for configuration-scoped AFT timeout evidence.
pub const AFT_TIMEOUT_PROTOCOL_VERSION_V1: u16 = 1;
/// Schema version for configuration-scoped AFT timeout evidence.
pub const AFT_TIMEOUT_SCHEMA_VERSION_V1: u16 = 1;

const AFT_FALLBACK_INSTANCE_DOMAIN_V1: &[u8] = b"ioi/aft/fallback-instance/v1";
const AFT_FALLBACK_CERTIFICATE_DOMAIN_V1: &[u8] = b"ioi/aft/fallback-start/v1";
const AFT_TIMEOUT_VOTE_DOMAIN_V1: &[u8] = b"ioi/aft/timeout-vote/v1";

/// Configuration scope shared by every message and durable transition for one
/// AFT fallback profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode, Serialize, Deserialize)]
pub struct AftFallbackScopeV1 {
    /// Genesis/network commitment. A certificate from another network is never
    /// admissible merely because membership happens to match.
    pub network_id: [u8; 32],
    /// Canonical hash of the effective validator set.
    pub configuration_hash: [u8; 32],
    /// First height at which that validator set is effective.
    pub epoch: u64,
}

impl AftFallbackScopeV1 {
    /// Refuses placeholder and pre-genesis scopes.
    pub fn validate(&self) -> Result<(), String> {
        if self.network_id == [0u8; 32] {
            return Err("AFT fallback scope has an empty network id".into());
        }
        if self.configuration_hash == [0u8; 32] {
            return Err("AFT fallback scope has an empty configuration hash".into());
        }
        if self.epoch == 0 {
            return Err("AFT fallback scope has a zero epoch".into());
        }
        Ok(())
    }
}

/// One locally authenticated timeout safe-state snapshot. QC-shaped
/// asynchronous references carry the semantic hash of the separate typed
/// predecessor proof that authorizes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AftTimeoutSafeStateV1 {
    /// Highest safe-state reference below the timed-out height.
    pub highest_qc: QuorumCertificate,
    /// Typed async-parent proof hash for `highest_qc`, when applicable.
    pub highest_qc_async_parent_proof_hash: Option<[u8; 32]>,
    /// Current lock reference.
    pub locked_qc: QuorumCertificate,
    /// Typed async-parent proof hash for `locked_qc`, when applicable.
    pub locked_qc_async_parent_proof_hash: Option<[u8; 32]>,
}

/// A versioned timeout vote whose signature is portable only inside one
/// network, validator configuration, and epoch.
///
/// This is the normative PQ AFT timeout vote. The legacy `ViewChangeVote`
/// signs only `(height, view)` and is retained solely for explicitly classical
/// compatibility profiles.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftTimeoutVoteV1 {
    /// Timeout protocol version.
    pub protocol_version: u16,
    /// Timeout wire-schema version.
    pub schema_version: u16,
    /// Network/configuration/epoch authority boundary.
    pub scope: AftFallbackScopeV1,
    /// Height whose optimistic view timed out.
    pub height: u64,
    /// New view requested by this vote.
    pub view: u64,
    /// Highest authenticated QC known to the voter when it abandoned the
    /// optimistic view. The signature binds this safe-state contribution.
    pub highest_qc: QuorumCertificate,
    /// Semantic hash of the separately supplied typed async-parent proof when
    /// `highest_qc` is only its canonical empty-signature reference.
    pub highest_qc_async_parent_proof_hash: Option<[u8; 32]>,
    /// Authenticated lock held by the voter at the same transition point.
    /// Genesis uses the canonical height-zero sentinel QC.
    pub locked_qc: QuorumCertificate,
    /// Semantic hash of the separately supplied typed async-parent proof when
    /// `locked_qc` is only its canonical empty-signature reference.
    pub locked_qc_async_parent_proof_hash: Option<[u8; 32]>,
    /// Enrolled validator casting the vote.
    pub voter: AccountId,
    /// PQ signature over [`Self::signing_bytes`].
    pub signature: Vec<u8>,
}

impl AftTimeoutVoteV1 {
    /// Creates the unsigned canonical shape used by signing code.
    pub fn unsigned(
        scope: AftFallbackScopeV1,
        height: u64,
        view: u64,
        voter: AccountId,
        highest_qc: QuorumCertificate,
        locked_qc: QuorumCertificate,
    ) -> Self {
        Self::unsigned_with_parent_proofs(
            scope,
            height,
            view,
            voter,
            highest_qc,
            None,
            locked_qc,
            None,
        )
    }

    /// Creates an unsigned timeout vote whose QC-shaped async references are
    /// explicitly bound to separately verifiable typed parent proofs.
    #[allow(clippy::too_many_arguments)]
    pub fn unsigned_with_parent_proofs(
        scope: AftFallbackScopeV1,
        height: u64,
        view: u64,
        voter: AccountId,
        highest_qc: QuorumCertificate,
        highest_qc_async_parent_proof_hash: Option<[u8; 32]>,
        locked_qc: QuorumCertificate,
        locked_qc_async_parent_proof_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height,
            view,
            highest_qc,
            highest_qc_async_parent_proof_hash,
            locked_qc,
            locked_qc_async_parent_proof_hash,
            voter,
            signature: Vec::new(),
        }
    }

    /// Canonical, domain-separated preimage. Every authority coordinate is
    /// covered directly by the validator signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_unsigned_shape()?;
        codec::to_bytes_canonical(&(
            AFT_TIMEOUT_VOTE_DOMAIN_V1.to_vec(),
            self.protocol_version,
            self.schema_version,
            self.scope,
            self.height,
            self.view,
            &self.highest_qc,
            self.highest_qc_async_parent_proof_hash,
            &self.locked_qc,
            self.locked_qc_async_parent_proof_hash,
            self.voter,
        ))
    }

    /// Refuses unknown versions and nonsensical consensus coordinates.
    pub fn validate_unsigned_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_TIMEOUT_PROTOCOL_VERSION_V1 {
            return Err(format!(
                "unsupported AFT timeout protocol version {}",
                self.protocol_version
            ));
        }
        if self.schema_version != AFT_TIMEOUT_SCHEMA_VERSION_V1 {
            return Err(format!(
                "unsupported AFT timeout schema version {}",
                self.schema_version
            ));
        }
        self.scope.validate()?;
        if self.height == 0 {
            return Err("AFT timeout vote cannot target genesis height zero".into());
        }
        if self.view == 0 {
            return Err("AFT timeout vote cannot request view zero".into());
        }
        validate_timeout_safe_state(self.height, &self.highest_qc, &self.locked_qc)?;
        validate_async_parent_proof_hash(
            &self.highest_qc,
            self.highest_qc_async_parent_proof_hash,
            "high QC",
        )?;
        validate_async_parent_proof_hash(
            &self.locked_qc,
            self.locked_qc_async_parent_proof_hash,
            "locked QC",
        )?;
        Ok(())
    }

    /// Complete wire-shape validation before signature verification.
    pub fn validate_shape(&self) -> Result<(), String> {
        self.validate_unsigned_shape()?;
        if self.signature.is_empty() {
            return Err("AFT timeout vote has an empty signature".into());
        }
        Ok(())
    }
}

/// A portable `2f+1` timeout certificate for the normative PQ optimistic
/// profile. Quorum and enrolled-key verification remain engine obligations.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftTimeoutCertificateV1 {
    /// Timeout protocol version.
    pub protocol_version: u16,
    /// Timeout wire-schema version.
    pub schema_version: u16,
    /// Network/configuration/epoch authority boundary.
    pub scope: AftFallbackScopeV1,
    /// Height whose optimistic view timed out.
    pub height: u64,
    /// New view authorized by the certificate.
    pub view: u64,
    /// Distinct configuration-scoped timeout votes.
    pub votes: Vec<AftTimeoutVoteV1>,
}

impl AftTimeoutCertificateV1 {
    /// Constructs a v1 certificate from its signed votes.
    pub fn new(
        scope: AftFallbackScopeV1,
        height: u64,
        view: u64,
        mut votes: Vec<AftTimeoutVoteV1>,
    ) -> Result<Self, String> {
        votes.sort_by_key(|vote| vote.voter);
        let certificate = Self {
            protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
            schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
            scope,
            height,
            view,
            votes,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    /// Refuses version, scope, coordinate, and duplicate-voter ambiguity.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_TIMEOUT_PROTOCOL_VERSION_V1 {
            return Err(format!(
                "unsupported AFT timeout certificate protocol version {}",
                self.protocol_version
            ));
        }
        if self.schema_version != AFT_TIMEOUT_SCHEMA_VERSION_V1 {
            return Err(format!(
                "unsupported AFT timeout certificate schema version {}",
                self.schema_version
            ));
        }
        self.scope.validate()?;
        if self.height == 0 || self.view == 0 {
            return Err("AFT timeout certificate has a zero height or view".into());
        }
        if self.votes.is_empty() {
            return Err("AFT timeout certificate contains no votes".into());
        }
        let mut voters = std::collections::BTreeSet::new();
        let mut previous_voter = None;
        for vote in &self.votes {
            vote.validate_shape()?;
            if vote.scope != self.scope || vote.height != self.height || vote.view != self.view {
                return Err(
                    "AFT timeout certificate vote does not match certificate scope/coordinates"
                        .into(),
                );
            }
            if !voters.insert(vote.voter) {
                return Err("AFT timeout certificate contains a duplicate voter".into());
            }
            if previous_voter.is_some_and(|previous| previous >= vote.voter) {
                return Err("AFT timeout certificate voters are not canonically ordered".into());
            }
            previous_voter = Some(vote.voter);
        }
        Ok(())
    }
}

/// Proof that the configured consecutive timeout window formed at one height.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct AftFallbackTriggerCertificateV1 {
    /// Height at which the optimistic path exhausted its trigger window.
    pub height: u64,
    /// Exactly one timeout certificate for every view from one through the
    /// normative trigger view, in ascending order.
    pub consecutive_timeout_certificates: Vec<AftTimeoutCertificateV1>,
}

impl AftFallbackTriggerCertificateV1 {
    /// Deterministically collapses the safe-state contributions signed by the
    /// timeout quorums. A fallback issuer cannot substitute local or stale
    /// evidence after collecting the votes.
    pub fn attested_safe_state(
        &self,
    ) -> Result<(QuorumCertificate, QuorumCertificate), String> {
        let ((highest_qc, _), (locked_qc, _)) =
            self.attested_safe_state_with_parent_proofs()?;
        Ok((highest_qc, locked_qc))
    }

    /// Deterministically carries the semantic async-parent proof hashes paired
    /// with the selected high and lock references.
    pub fn attested_safe_state_with_parent_proofs(
        &self,
    ) -> Result<
        (
            (QuorumCertificate, Option<[u8; 32]>),
            (QuorumCertificate, Option<[u8; 32]>),
        ),
        String,
    > {
        self.validate_shape()?;
        let votes = self
            .consecutive_timeout_certificates
            .iter()
            .flat_map(|certificate| certificate.votes.iter())
            .collect::<Vec<_>>();
        let highest_vote = votes
            .iter()
            .copied()
            .max_by_key(|vote| qc_rank(&vote.highest_qc))
            .ok_or_else(|| "AFT fallback trigger has no high-QC contribution".to_string())?;
        let locked_vote = votes
            .iter()
            .copied()
            .max_by_key(|vote| qc_rank(&vote.locked_qc))
            .ok_or_else(|| "AFT fallback trigger has no lock contribution".to_string())?;
        let highest_qc = highest_vote.highest_qc.clone();
        let locked_qc = locked_vote.locked_qc.clone();
        validate_timeout_safe_state(self.height, &highest_qc, &locked_qc)?;
        Ok((
            (
                highest_qc,
                highest_vote.highest_qc_async_parent_proof_hash,
            ),
            (
                locked_qc,
                locked_vote.locked_qc_async_parent_proof_hash,
            ),
        ))
    }

    /// Refuses gaps, reordered views, cross-height members, and surplus
    /// certificates. Cryptographic quorum verification remains engine-owned.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.height == 0 {
            return Err("AFT fallback trigger cannot target genesis height zero".into());
        }
        if self.consecutive_timeout_certificates.len()
            != AFT_FALLBACK_TRIGGER_VIEW_V1 as usize
        {
            return Err("AFT fallback trigger does not contain the complete consecutive TC chain"
                .into());
        }
        for (index, certificate) in self.consecutive_timeout_certificates.iter().enumerate() {
            let expected_view = index as u64 + 1;
            certificate.validate_shape()?;
            if certificate.height != self.height || certificate.view != expected_view {
                return Err(format!(
                    "AFT fallback trigger TC at index {index} does not bind height {} and view {expected_view}",
                    self.height
                ));
            }
            if certificate.votes.is_empty() {
                return Err(format!(
                    "AFT fallback trigger TC for view {expected_view} contains no votes"
                ));
            }
        }
        Ok(())
    }
}

/// Durable, idempotent evidence that one height crossed from optimistic AFT
/// into its pessimistic asynchronous instance.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct FallbackStartCertificateV1 {
    /// AFT fallback protocol version.
    pub protocol_version: u16,
    /// Wire schema version.
    pub schema_version: u16,
    /// Network, configuration, and epoch boundary.
    pub scope: AftFallbackScopeV1,
    /// Ordering height entering the asynchronous path.
    pub height: u64,
    /// Deterministic identifier derived only from the configuration scope and
    /// height. Correct nodes can therefore carry different safe-state evidence
    /// while still addressing exactly one fallback instance.
    pub fallback_instance_id: [u8; 32],
    /// The complete canonical timeout chain through view three. Later timeout
    /// certificates do not create parallel instances.
    pub trigger_certificate: AftFallbackTriggerCertificateV1,
    /// Highest authenticated QC known when the transition was persisted.
    pub highest_qc: QuorumCertificate,
    /// Semantic typed-proof hash paired with an async high-QC reference.
    pub highest_qc_async_parent_proof_hash: Option<[u8; 32]>,
    /// Authenticated lock known when the transition was persisted. Genesis uses
    /// the height-zero sentinel QC.
    pub locked_qc: QuorumCertificate,
    /// Semantic typed-proof hash paired with an async lock-QC reference.
    pub locked_qc_async_parent_proof_hash: Option<[u8; 32]>,
    /// Explicit root binding for consumers that need not decode the full lock.
    /// It must equal `locked_qc.block_hash`.
    pub locked_root: [u8; 32],
}

impl FallbackStartCertificateV1 {
    /// Constructs a v1 certificate and computes the instance id.
    pub fn new(
        scope: AftFallbackScopeV1,
        height: u64,
        trigger_certificate: AftFallbackTriggerCertificateV1,
    ) -> Result<Self, String> {
        let (
            (highest_qc, highest_qc_async_parent_proof_hash),
            (locked_qc, locked_qc_async_parent_proof_hash),
        ) = trigger_certificate.attested_safe_state_with_parent_proofs()?;
        let certificate = Self {
            protocol_version: AFT_FALLBACK_PROTOCOL_VERSION_V1,
            schema_version: AFT_FALLBACK_SCHEMA_VERSION_V1,
            scope,
            height,
            fallback_instance_id: Self::derive_instance_id(scope, height)?,
            trigger_certificate,
            highest_qc,
            highest_qc_async_parent_proof_hash,
            locked_root: locked_qc.block_hash,
            locked_qc,
            locked_qc_async_parent_proof_hash,
        };
        certificate.validate_shape()?;
        Ok(certificate)
    }

    /// Stable instance identifier. Trigger arrival order, high-QC freshness,
    /// and lock freshness can never fork the namespace.
    pub fn derive_instance_id(
        scope: AftFallbackScopeV1,
        height: u64,
    ) -> Result<[u8; 32], String> {
        let bytes = codec::to_bytes_canonical(&(
            AFT_FALLBACK_INSTANCE_DOMAIN_V1.to_vec(),
            AFT_FALLBACK_PROTOCOL_VERSION_V1,
            AFT_FALLBACK_SCHEMA_VERSION_V1,
            scope,
            height,
        ))?;
        let digest = DcryptSha256::digest(&bytes).map_err(|error| error.to_string())?;
        digest
            .as_ref()
            .try_into()
            .map_err(|_| "invalid SHA-256 digest length".into())
    }

    /// Canonical commitment to every certificate field.
    pub fn certificate_hash(&self) -> Result<[u8; 32], String> {
        self.validate_shape()?;
        let bytes = codec::to_bytes_canonical(&(
            AFT_FALLBACK_CERTIFICATE_DOMAIN_V1.to_vec(),
            self,
        ))?;
        let digest = DcryptSha256::digest(&bytes).map_err(|error| error.to_string())?;
        digest
            .as_ref()
            .try_into()
            .map_err(|_| "invalid SHA-256 digest length".into())
    }

    /// Returns whether two fully validated certificates name the same
    /// fallback transition for consensus purposes.
    ///
    /// Exact-q timeout certificates can legitimately contain different
    /// signer subsets at different correct nodes. Those witness bytes remain
    /// committed by `certificate_hash` for auditability, but they cannot split
    /// one fallback height when scope and quorum-attested safe state agree.
    pub fn consensus_equivalent(&self, other: &Self) -> Result<bool, String> {
        self.validate_shape()?;
        other.validate_shape()?;
        Ok(self.scope == other.scope
            && self.height == other.height
            && self.fallback_instance_id == other.fallback_instance_id
            && qc_rank(&self.highest_qc) == qc_rank(&other.highest_qc)
            && qc_rank(&self.locked_qc) == qc_rank(&other.locked_qc)
            && self.locked_root == other.locked_root)
    }

    /// Structural validation. Signature and quorum verification remains a
    /// consensus-engine obligation against an enrolled configuration.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.protocol_version != AFT_FALLBACK_PROTOCOL_VERSION_V1 {
            return Err(format!(
                "unsupported AFT fallback protocol version {}",
                self.protocol_version
            ));
        }
        if self.schema_version != AFT_FALLBACK_SCHEMA_VERSION_V1 {
            return Err(format!(
                "unsupported AFT fallback schema version {}",
                self.schema_version
            ));
        }
        self.scope.validate()?;
        if self.height == 0 {
            return Err("AFT fallback cannot start at genesis height zero".into());
        }
        let expected = Self::derive_instance_id(self.scope, self.height)?;
        if self.fallback_instance_id != expected {
            return Err("AFT fallback instance id does not match scope and height".into());
        }
        if self.trigger_certificate.height != self.height {
            return Err("AFT fallback trigger height does not match certificate height".into());
        }
        self.trigger_certificate.validate_shape()?;
        if self
            .trigger_certificate
            .consecutive_timeout_certificates
            .iter()
            .any(|certificate| certificate.scope != self.scope)
        {
            return Err("AFT fallback trigger certificate crosses configuration scope".into());
        }
        let (
            (attested_highest_qc, attested_highest_proof_hash),
            (attested_locked_qc, attested_locked_proof_hash),
        ) = self
            .trigger_certificate
            .attested_safe_state_with_parent_proofs()?;
        if self.highest_qc != attested_highest_qc
            || self.highest_qc_async_parent_proof_hash != attested_highest_proof_hash
            || self.locked_qc != attested_locked_qc
            || self.locked_qc_async_parent_proof_hash != attested_locked_proof_hash
        {
            return Err(
                "AFT fallback safe state is not the deterministic quorum-attested state".into(),
            );
        }
        if self.highest_qc.height >= self.height {
            return Err("AFT fallback high QC is not below the fallback height".into());
        }
        if self.locked_qc.height > self.highest_qc.height {
            return Err("AFT fallback lock is above its high QC".into());
        }
        if self.locked_root != self.locked_qc.block_hash {
            return Err("AFT fallback locked root does not match its lock QC".into());
        }
        Ok(())
    }
}

fn qc_rank(qc: &QuorumCertificate) -> (u64, u64, [u8; 32]) {
    (qc.height, qc.view, qc.block_hash)
}

fn validate_timeout_safe_state(
    timeout_height: u64,
    highest_qc: &QuorumCertificate,
    locked_qc: &QuorumCertificate,
) -> Result<(), String> {
    if highest_qc.height >= timeout_height {
        return Err("AFT timeout high QC is not below the timed-out height".into());
    }
    if locked_qc.height > highest_qc.height {
        return Err("AFT timeout lock is above the voter's high QC".into());
    }
    if highest_qc.height == 0 && highest_qc != &QuorumCertificate::default() {
        return Err("AFT timeout high QC uses a non-canonical genesis sentinel".into());
    }
    if locked_qc.height == 0 && locked_qc != &QuorumCertificate::default() {
        return Err("AFT timeout lock uses a non-canonical genesis sentinel".into());
    }
    Ok(())
}

fn validate_async_parent_proof_hash(
    qc: &QuorumCertificate,
    proof_hash: Option<[u8; 32]>,
    label: &str,
) -> Result<(), String> {
    if proof_hash == Some([0; 32]) {
        return Err(format!("AFT timeout {label} has an empty async-parent proof hash"));
    }
    if qc.height == 0 && proof_hash.is_some() {
        return Err(format!(
            "AFT timeout {label} attaches an async-parent proof to genesis"
        ));
    }
    let carries_native_evidence = !qc.signatures.is_empty()
        || !qc.aggregated_signature.is_empty()
        || !qc.signers_bitfield.is_empty();
    if carries_native_evidence && proof_hash.is_some() {
        return Err(format!(
            "AFT timeout {label} ambiguously carries native and async-parent authority"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> AftFallbackScopeV1 {
        AftFallbackScopeV1 {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 7,
        }
    }

    fn trigger() -> AftFallbackTriggerCertificateV1 {
        let scope = scope();
        AftFallbackTriggerCertificateV1 {
            height: 9,
            consecutive_timeout_certificates: (1..=AFT_FALLBACK_TRIGGER_VIEW_V1)
                .map(|view| AftTimeoutCertificateV1 {
                    protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                    schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                    scope,
                    height: 9,
                    view,
                    votes: vec![AftTimeoutVoteV1 {
                        protocol_version: AFT_TIMEOUT_PROTOCOL_VERSION_V1,
                        schema_version: AFT_TIMEOUT_SCHEMA_VERSION_V1,
                        scope,
                        height: 9,
                        view,
                        highest_qc: qc(8, 8),
                        highest_qc_async_parent_proof_hash: None,
                        locked_qc: qc(7, 7),
                        locked_qc_async_parent_proof_hash: None,
                        voter: AccountId([3; 32]),
                        signature: vec![4],
                    }],
                })
                .collect(),
        }
    }

    fn qc(height: u64, root: u8) -> QuorumCertificate {
        QuorumCertificate {
            height,
            view: 0,
            block_hash: [root; 32],
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        }
    }

    #[test]
    fn instance_id_ignores_safe_state_arrival_order() {
        let first = FallbackStartCertificateV1::new(scope(), 9, trigger())
            .expect("first certificate");
        let mut other_trigger = trigger();
        for vote in other_trigger
            .consecutive_timeout_certificates
            .iter_mut()
            .flat_map(|certificate| certificate.votes.iter_mut())
        {
            vote.highest_qc = qc(8, 6);
            vote.locked_qc = qc(6, 5);
        }
        let second = FallbackStartCertificateV1::new(scope(), 9, other_trigger)
            .expect("second certificate");
        assert_eq!(first.fallback_instance_id, second.fallback_instance_id);
        assert_ne!(first.certificate_hash().unwrap(), second.certificate_hash().unwrap());
        assert!(!first.consensus_equivalent(&second).unwrap());
    }

    #[test]
    fn semantic_equivalence_ignores_timeout_witness_representation() {
        let first = FallbackStartCertificateV1::new(scope(), 9, trigger())
            .expect("first certificate");
        let mut other_trigger = trigger();
        for certificate in &mut other_trigger.consecutive_timeout_certificates {
            certificate.votes[0].voter = AccountId([7; 32]);
            certificate.votes[0].signature = vec![8];
        }
        let second = FallbackStartCertificateV1::new(scope(), 9, other_trigger)
            .expect("second certificate");

        assert_ne!(first.certificate_hash().unwrap(), second.certificate_hash().unwrap());
        assert!(first.consensus_equivalent(&second).unwrap());
    }

    #[test]
    fn mutations_of_scope_trigger_and_lock_fail_closed() {
        let certificate = FallbackStartCertificateV1::new(scope(), 9, trigger()).unwrap();

        let mut mutated = certificate.clone();
        mutated.scope.configuration_hash[0] ^= 1;
        assert!(mutated.validate_shape().is_err());

        let mut mutated = certificate.clone();
        mutated.trigger_certificate.consecutive_timeout_certificates[1].view += 1;
        assert!(mutated.validate_shape().is_err());

        let mut mutated = certificate.clone();
        mutated.locked_root[0] ^= 1;
        assert!(mutated.validate_shape().is_err());

        let mut mutated = certificate;
        mutated.protocol_version += 1;
        assert!(mutated.validate_shape().is_err());
    }

    #[test]
    fn timeout_preimage_binds_every_authority_coordinate_and_certificate_order() {
        let base = AftTimeoutVoteV1::unsigned(
            scope(),
            9,
            2,
            AccountId([7; 32]),
            qc(8, 8),
            qc(7, 7),
        );
        let base_bytes = base.signing_bytes().unwrap();

        let mut mutated = base.clone();
        mutated.scope.network_id[0] ^= 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.scope.configuration_hash[0] ^= 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.scope.epoch += 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.height += 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.view += 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.highest_qc.block_hash[0] ^= 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base.clone();
        mutated.locked_qc.block_hash[0] ^= 1;
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);
        let mut mutated = base;
        mutated.voter = AccountId([8; 32]);
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);

        let make_vote = |voter: u8| AftTimeoutVoteV1 {
            signature: vec![1],
            ..AftTimeoutVoteV1::unsigned(
                scope(),
                9,
                2,
                AccountId([voter; 32]),
                qc(8, 8),
                qc(7, 7),
            )
        };
        let certificate = AftTimeoutCertificateV1::new(
            scope(),
            9,
            2,
            vec![make_vote(9), make_vote(7), make_vote(8)],
        )
        .unwrap();
        assert_eq!(
            certificate
                .votes
                .iter()
                .map(|vote| vote.voter)
                .collect::<Vec<_>>(),
            vec![AccountId([7; 32]), AccountId([8; 32]), AccountId([9; 32])]
        );
        let mut reordered = certificate;
        reordered.votes.swap(0, 1);
        assert!(reordered.validate_shape().is_err());
    }

    #[test]
    fn timeout_async_parent_proof_hash_is_bound_and_fail_closed() {
        let parent_proof_hash = [11; 32];
        let base = AftTimeoutVoteV1::unsigned_with_parent_proofs(
            scope(),
            9,
            2,
            AccountId([7; 32]),
            qc(8, 8),
            Some(parent_proof_hash),
            qc(8, 8),
            Some(parent_proof_hash),
        );
        let base_bytes = base.signing_bytes().expect("typed parent reference");

        let mut mutated = base.clone();
        mutated.highest_qc_async_parent_proof_hash = Some([12; 32]);
        assert_ne!(mutated.signing_bytes().unwrap(), base_bytes);

        let mut empty_hash = base.clone();
        empty_hash.locked_qc_async_parent_proof_hash = Some([0; 32]);
        assert!(empty_hash.validate_unsigned_shape().is_err());

        let mut genesis_proof = base.clone();
        genesis_proof.locked_qc = QuorumCertificate::default();
        assert!(genesis_proof.validate_unsigned_shape().is_err());

        let mut ambiguous = base;
        ambiguous.highest_qc.signatures.push((AccountId([9; 32]), vec![1]));
        assert!(ambiguous.validate_unsigned_shape().is_err());
    }
}
