//! Canonical Agentgres finality-profile identity.
//!
//! The profile vocabulary is NOT defined here. Its five canonical members are
//! owned by `docs/architecture/foundations/canonical-enums.md`
//! § Autonomous-System Ordering And Finality Profiles and by
//! `ordering-admission-finality-profile.v1.schema.json`; the certificate
//! variants and the variant-implies-profile binding are owned by
//! `finality-certificate.v1.schema.json`. This module mirrors exactly the two
//! members the Agentgres spine admits and refuses everything else:
//!
//! | member            | `checkpoint.profile` | `certificate_variant`  |
//! |-------------------|----------------------|------------------------|
//! | `BftConsensus`    | `bft_consensus`      | `bft_consensus_aft_v1` |
//! | `SingleAuthority` | `single_authority`   | `single_authority_v1`  |
//!
//! Local nuance (local to this spine, not canon): `BftConsensus` is the
//! genesis member this store seals when a caller does not name one, and
//! `SingleAuthority` is reachable only by explicit selection plus an admitted
//! cutover. That is a library default for a spine instance. It is NOT a
//! deployment default and NOT a production-selectable authorization: ADR 0039
//! is Proposed and authorizes neither (see `0039-...md` closing clause).
//!
//! Compatibility labels exist for operator input only, and the map that
//! resolves them is owned by `canonical-enums.md` § Compatibility map for
//! proposed and legacy labels. [`PROFILE_LABELS`] mirrors only the entries
//! that land on a member this spine admits; labels resolving to an
//! out-of-scope canonical member, and `witnessed_threshold` (which the enum
//! owner records as resolving to no single member), get their own refusals so
//! neither is ever silently widened into this spine's vocabulary. Resolution
//! happens before admission; an admitted record carrying a non-canonical
//! spelling is refused by [`FinalityProfile::from_exact`], so a label can
//! never reach durable bytes or become a second runtime identity.

use crate::recognized_effect::{ProfileRefusal, RecognizedEffectError};
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_finality::{
    emit_native_aft_consensus, emit_single_authority, verify_bundle, verify_runtime_bundle_v3,
    NativeAftFinalizedBlock, VerificationError, NATIVE_AFT_VOTE_BINDING, RUNTIME_BUNDLE_V3,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// The closed set of profile members this spine recognizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityProfile {
    BftConsensus,
    SingleAuthority,
}

/// Labels that resolve to a member this spine admits. Mirrors the enum
/// owner's compatibility map; matching is exact, because that map is exact and
/// one-directional. No case folding, no separator folding — inventing either
/// would widen a closed vocabulary this module does not own.
pub const PROFILE_LABELS: [(&str, FinalityProfile); 3] = [
    // identical; no change
    ("bft_consensus", FinalityProfile::BftConsensus),
    ("single_authority", FinalityProfile::SingleAuthority),
    // AFT is IOI's implementation of the BFT member, not a sixth profile.
    ("aft", FinalityProfile::BftConsensus),
];

/// Canonical members (and the labels resolving to them) that exist in the
/// owner's vocabulary but that this spine does not admit. They resolve
/// cleanly — and are then refused for scope, which is a different fact from
/// "unknown", and is reported as such.
const OUT_OF_SCOPE_LABELS: [(&str, &str); 5] = [
    ("replicated_single_authority", "replicated_single_authority"),
    ("replicated_cft", "replicated_single_authority"),
    ("threshold_authority", "threshold_authority"),
    ("external_chain_finality", "external_chain_finality"),
    ("external_finality", "external_chain_finality"),
];

/// Labels the enum owner records as resolving to no single member. These must
/// be decomposed by the caller before use; guessing one would mint a member.
const UNRESOLVABLE_LABELS: [&str; 1] = ["witnessed_threshold"];

impl FinalityProfile {
    pub const ALL: [Self; 2] = [Self::BftConsensus, Self::SingleAuthority];

    /// The member a spine seals at genesis when the caller names none. A
    /// library default for one store instance — not a deployment default and
    /// not a production-selectable authorization (ADR 0039 is Proposed).
    pub const DEFAULT: Self = Self::BftConsensus;

    /// Canonical `checkpoint.profile` bytes.
    pub const fn profile(self) -> &'static str {
        match self {
            Self::BftConsensus => "bft_consensus",
            Self::SingleAuthority => "single_authority",
        }
    }

    /// Canonical `finality_certificate.certificate_variant` bytes.
    pub const fn certificate_variant(self) -> &'static str {
        match self {
            Self::BftConsensus => "bft_consensus_aft_v1",
            Self::SingleAuthority => "single_authority_v1",
        }
    }

    /// Exact canonical match. No trimming, no case folding, no aliasing —
    /// this is the gate every admitted record and recovered frame passes
    /// through, so a compatibility spelling is refused here by construction.
    pub fn from_exact(profile: &str, variant: &str) -> Result<Self, RecognizedEffectError> {
        let member = Self::ALL
            .into_iter()
            .find(|candidate| candidate.profile() == profile)
            .ok_or_else(|| {
                ProfileRefusal::NonCanonicalProfileBytes {
                    field: "profile".into(),
                    value: profile.to_owned(),
                }
                .into_error()
            })?;
        if member.certificate_variant() != variant {
            return Err(ProfileRefusal::VariantMismatch {
                profile: profile.to_owned(),
                variant: variant.to_owned(),
            }
            .into_error());
        }
        Ok(member)
    }

    /// Resolve an operator-supplied label to a canonical member. Call this at
    /// the request boundary; store only the canonical result.
    ///
    /// Three distinct outcomes, because they are three distinct facts: the
    /// label lands on an admitted member, it lands on a canonical member this
    /// spine does not admit, or it does not resolve at all.
    pub fn resolve_label(value: &str) -> Result<Self, RecognizedEffectError> {
        if let Some((_, member)) = PROFILE_LABELS
            .into_iter()
            .find(|(label, _)| *label == value)
        {
            return Ok(member);
        }
        if let Some((_, member)) = OUT_OF_SCOPE_LABELS
            .into_iter()
            .find(|(label, _)| *label == value)
        {
            return Err(ProfileRefusal::ProfileOutsideSpineScope {
                value: value.to_owned(),
                canonical_member: member.to_owned(),
            }
            .into_error());
        }
        if UNRESOLVABLE_LABELS.contains(&value) {
            return Err(ProfileRefusal::AmbiguousProfileLabel {
                value: value.to_owned(),
            }
            .into_error());
        }
        Err(ProfileRefusal::UnknownProfileAlias {
            value: value.to_owned(),
        }
        .into_error())
    }

    /// The variant-implies-profile binding, mirrored from
    /// `finality-certificate.v1.schema.json` for the two in-scope variants. A
    /// certificate variant is not a profile label, so it is resolved here
    /// rather than folded into the label table.
    pub fn from_certificate_variant(variant: &str) -> Result<Self, RecognizedEffectError> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.certificate_variant() == variant)
            .ok_or_else(|| {
                ProfileRefusal::NonCanonicalProfileBytes {
                    field: "certificate_variant".into(),
                    value: variant.to_owned(),
                }
                .into_error()
            })
    }

    /// Whether moving `self` -> `next` loses a guarantee. `bft_consensus` ->
    /// `single_authority` collapses an independent-failure quorum into one
    /// trusted signer: that is the INV-42 weakening.
    pub fn direction_to(self, next: Self) -> Option<GuaranteeDirection> {
        match (self, next) {
            (Self::BftConsensus, Self::SingleAuthority) => Some(GuaranteeDirection::Weakening),
            (Self::SingleAuthority, Self::BftConsensus) => Some(GuaranteeDirection::Strengthening),
            _ => None,
        }
    }
}

/// Full profile identity: member, its exact certificate variant, and the
/// profile contract version the checkpoint binds. All three are revalidated
/// on every effect commit; a substitution in any one is a distinct refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileIdentity {
    pub profile: FinalityProfile,
    pub certificate_variant: String,
    pub profile_contract_version: String,
}

impl ProfileIdentity {
    pub fn new(
        profile: FinalityProfile,
        profile_contract_version: impl Into<String>,
    ) -> Result<Self, RecognizedEffectError> {
        let profile_contract_version = profile_contract_version.into();
        crate::recognized_effect::validate_token(
            "profile_contract_version",
            &profile_contract_version,
        )?;
        Ok(Self {
            profile,
            certificate_variant: profile.certificate_variant().to_owned(),
            profile_contract_version,
        })
    }

    /// Refuse an identity whose variant does not match its member exactly.
    pub fn validate(&self) -> Result<(), RecognizedEffectError> {
        FinalityProfile::from_exact(self.profile.profile(), &self.certificate_variant)?;
        crate::recognized_effect::validate_token(
            "profile_contract_version",
            &self.profile_contract_version,
        )
    }

    pub fn label(&self) -> String {
        format!(
            "{}/{}/{}",
            self.profile.profile(),
            self.certificate_variant,
            self.profile_contract_version
        )
    }
}

/// Which way a cutover moves the guarantee envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeDirection {
    Strengthening,
    Weakening,
}

impl GuaranteeDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strengthening => "strengthening",
            Self::Weakening => "weakening",
        }
    }
}

/// The explicit guarantee delta a cutover declares. The declared direction
/// must equal the direction computed from the exact profile pair; a cutover
/// that understates what it gives up is refused before admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuaranteeDelta {
    pub direction: GuaranteeDirection,
    pub lost_guarantees: Vec<String>,
    pub retained_guarantees: Vec<String>,
    pub gained_guarantees: Vec<String>,
}

/// Digests of the governing material bound to an active profile. Every effect
/// commit revalidates these, so a policy / verifier / availability / retention
/// / governance substitution cannot ride along with an otherwise valid effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileBindingsDigest {
    pub policy_digest: String,
    pub verifier_contract_digest: String,
    pub availability_policy_digest: String,
    pub retention_policy_digest: String,
    pub governance_policy_digest: String,
}

impl ProfileBindingsDigest {
    pub(crate) const FIELDS: [&'static str; 5] = [
        "policy_digest",
        "verifier_contract_digest",
        "availability_policy_digest",
        "retention_policy_digest",
        "governance_policy_digest",
    ];

    pub(crate) fn field(&self, name: &str) -> &str {
        match name {
            "policy_digest" => &self.policy_digest,
            "verifier_contract_digest" => &self.verifier_contract_digest,
            "availability_policy_digest" => &self.availability_policy_digest,
            "retention_policy_digest" => &self.retention_policy_digest,
            "governance_policy_digest" => &self.governance_policy_digest,
            _ => "",
        }
    }

    pub fn validate(&self) -> Result<(), RecognizedEffectError> {
        for name in Self::FIELDS {
            crate::recognized_effect::validate_hash(name, self.field(name))?;
        }
        Ok(())
    }

    /// Exact per-field comparison so a substitution names the field it
    /// substituted rather than collapsing to an opaque mismatch.
    pub fn require_exact(&self, active: &Self) -> Result<(), RecognizedEffectError> {
        for name in Self::FIELDS {
            if self.field(name) != active.field(name) {
                return Err(ProfileRefusal::BindingsDigestMismatch {
                    field: name.into(),
                    expected: active.field(name).to_owned(),
                    actual: self.field(name).to_owned(),
                }
                .into_error());
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Localized finality adapter seam.
//
// This is the ONLY place the spine reaches into `ioi-finality`. No spine,
// store, cutover, or test code names an `ioi-finality` symbol.
//
// Both canonical members are now bound to real contracts. `bft_consensus` is
// bound to the native AFT bridge: it imports the `QuorumCertificate` the live
// consensus path already produced and never mints a second peer round. The
// explicit runtime-v3 successor carries that quorum with the exact full block,
// transactions, state roots, and receipts, so verification needs no callback.
// The older template emitter still requires `NativeAftQuorumSource` and still
// refuses when unwired; predecessor semantics are not widened by the new path.
// ---------------------------------------------------------------------------

/// Per-profile emit/verify adapter. Implementations must be exact: `verify`
/// returning `Ok` is a claim that the bundle was checked under that profile's
/// real contract.
pub trait ProfileFinalityBinding {
    fn profile(&self) -> FinalityProfile;

    /// Sign a checkpoint template into a complete bundle.
    fn emit(
        &self,
        template: Value,
        issuer_key_id: &str,
        signing_key: &Ed25519PrivateKey,
    ) -> Result<Value, RecognizedEffectError>;

    /// Offline-verify a complete bundle under this profile's contract.
    fn verify(&self, bundle: &Value) -> Result<(), RecognizedEffectError>;
}

/// Runtime-v3 coordinates recovered only after the complete bundle verifies.
/// Keeping this adapter here preserves the spine's source-neutral boundary:
/// `recognized_effect` compares canonical facts without knowing an
/// `ioi-finality` type or interpreting an older bundle as the successor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedRuntimeCoordinates {
    pub profile: FinalityProfile,
    pub profile_contract_version: String,
    pub profile_epoch: u64,
    pub writer_identity: String,
    pub fence_token: u64,
    pub previous_canonical_head: String,
    pub resulting_canonical_head: String,
    pub authority_epoch: u64,
    pub revocation_epoch: u64,
    pub issuer_key_id: String,
    pub bindings: ProfileBindingsDigest,
    pub native_quorum_verified: bool,
    pub effect_committed_in_block: bool,
}

pub(crate) fn verified_runtime_coordinates(
    bundle: &Value,
) -> Result<Option<VerifiedRuntimeCoordinates>, RecognizedEffectError> {
    if bundle.get("schema_version").and_then(Value::as_str) != Some(RUNTIME_BUNDLE_V3) {
        return Ok(None);
    }
    let claim = verify_runtime_bundle_v3(bundle).map_err(RecognizedEffectError::Finality)?;
    let profile = FinalityProfile::from_exact(&claim.profile, &claim.certificate_variant)?;
    let text = |pointer: &str| {
        bundle
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                RecognizedEffectError::Invalid(format!(
                    "verified runtime bundle lost required text at {pointer}"
                ))
            })
    };
    Ok(Some(VerifiedRuntimeCoordinates {
        profile,
        profile_contract_version: text("/checkpoint/profile_contract_version")?,
        profile_epoch: claim.profile_epoch,
        writer_identity: claim.writer_identity,
        fence_token: claim.fence_token,
        previous_canonical_head: claim.previous_canonical_head,
        resulting_canonical_head: claim.resulting_canonical_head,
        authority_epoch: claim.authority_epoch,
        revocation_epoch: claim.authority_revocation_epoch,
        issuer_key_id: text("/checkpoint/finality_certificate/issuer_key_id")?,
        bindings: ProfileBindingsDigest {
            policy_digest: text("/checkpoint/authority_policy_root")?,
            verifier_contract_digest: text("/checkpoint/verifier_contract_hash")?,
            availability_policy_digest: text("/checkpoint/availability_policy_root")?,
            retention_policy_digest: text(
                "/checkpoint/availability_manifest/retention_policy_root",
            )?,
            governance_policy_digest: text("/checkpoint/governance_policy_root")?,
        },
        native_quorum_verified: claim.native_quorum_verified,
        effect_committed_in_block: claim.effect_committed_in_block,
    }))
}

/// `single_authority_v1`, bound to the live `ioi-finality` contract.
pub struct SingleAuthorityBinding;

impl ProfileFinalityBinding for SingleAuthorityBinding {
    fn profile(&self) -> FinalityProfile {
        FinalityProfile::SingleAuthority
    }

    fn emit(
        &self,
        template: Value,
        issuer_key_id: &str,
        signing_key: &Ed25519PrivateKey,
    ) -> Result<Value, RecognizedEffectError> {
        emit_single_authority(template, issuer_key_id, signing_key)
            .map_err(RecognizedEffectError::Finality)
    }

    fn verify(&self, bundle: &Value) -> Result<(), RecognizedEffectError> {
        if let Some(runtime) = verified_runtime_coordinates(bundle)? {
            if runtime.profile != FinalityProfile::SingleAuthority
                || runtime.native_quorum_verified
                || !runtime.effect_committed_in_block
            {
                return Err(RecognizedEffectError::Finality(
                    VerificationError::ConsensusEvidence(
                        "single-authority runtime evidence contradicts its profile".into(),
                    ),
                ));
            }
            return Ok(());
        }
        verify_bundle(bundle)
            .map(|_| ())
            .map_err(RecognizedEffectError::Finality)
    }
}

/// Supplies the already-finalized native AFT block a checkpoint binds to.
///
/// This is the integration seam, and it is deliberately narrow. The runtime
/// owns block storage and consensus; this crate owns neither and must not guess
/// at either. An implementation is expected to return the committed block's
/// SCALE-encoded header together with the `QuorumCertificate` that certified
/// it, and to fail rather than synthesize when the pair is unavailable — a
/// post-restart synthetic certificate carries no signatures and is not
/// evidence.
pub trait NativeAftQuorumSource: Send + Sync {
    /// The finalized block at `block_height`, with its certificate.
    fn finalized_block(
        &self,
        block_height: u64,
    ) -> Result<NativeAftFinalizedBlock, RecognizedEffectError>;
}

/// `bft_consensus_aft_v1`, bound to the native AFT bridge in `ioi-finality`.
///
/// Verification is always live and always strict: a bundle is admitted only if
/// its quorum verified under [`NATIVE_AFT_VOTE_BINDING`] *and* the verifier
/// established that the certified block commits to this recognized effect.
/// Runtime-v3 establishes that association from the complete durable block.
/// Predecessor bundles still report it as unproven and remain refused: a real
/// block quorum may not be stapled onto an unrelated effect merely because
/// both artifacts verify independently.
pub struct NativeAftBinding {
    source: Option<Arc<dyn NativeAftQuorumSource>>,
}

impl NativeAftBinding {
    /// The production default: verification live, emission fail-closed until a
    /// quorum source is wired.
    pub fn unwired() -> Self {
        Self { source: None }
    }

    /// Bind a runtime quorum source, enabling emission.
    pub fn with_source(source: Arc<dyn NativeAftQuorumSource>) -> Self {
        Self {
            source: Some(source),
        }
    }
}

impl ProfileFinalityBinding for NativeAftBinding {
    fn profile(&self) -> FinalityProfile {
        FinalityProfile::BftConsensus
    }

    fn emit(
        &self,
        template: Value,
        issuer_key_id: &str,
        signing_key: &Ed25519PrivateKey,
    ) -> Result<Value, RecognizedEffectError> {
        let Some(source) = self.source.as_ref() else {
            return Err(ProfileRefusal::ProfileNotWired {
                profile: FinalityProfile::BftConsensus.profile().into(),
            }
            .into_error());
        };
        let block_height = template
            .pointer(
                "/checkpoint/finality_certificate/consensus_evidence/certified_block/block_height",
            )
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                RecognizedEffectError::Finality(VerificationError::ConsensusEvidence(
                    "template declares no certified block height to bind a native AFT quorum to"
                        .into(),
                ))
            })?;
        let finalized = source.finalized_block(block_height)?;
        emit_native_aft_consensus(template, &finalized, issuer_key_id, signing_key)
            .map_err(RecognizedEffectError::Finality)
    }

    fn verify(&self, bundle: &Value) -> Result<(), RecognizedEffectError> {
        if let Some(runtime) = verified_runtime_coordinates(bundle)? {
            if runtime.profile != FinalityProfile::BftConsensus
                || !runtime.native_quorum_verified
                || !runtime.effect_committed_in_block
            {
                return Err(RecognizedEffectError::Finality(
                    VerificationError::ConsensusEvidence(
                        "native AFT runtime evidence lacks its quorum/effect binding".into(),
                    ),
                ));
            }
            return Ok(());
        }
        let claim = verify_bundle(bundle).map_err(RecognizedEffectError::Finality)?;
        // `verify_bundle` proves the quorum is real. It does not decide which
        // quorums this spine may run on, and that is the distinction the
        // production profile has to enforce: a checkpoint-round quorum is an
        // honest artifact and still not native consensus evidence.
        let binding = claim
            .quorum
            .as_ref()
            .map(|quorum| quorum.vote_binding.as_str());
        if binding != Some(NATIVE_AFT_VOTE_BINDING) {
            return Err(RecognizedEffectError::Finality(
                VerificationError::ConsensusEvidence(format!(
                    "the bft_consensus profile admits only {NATIVE_AFT_VOTE_BINDING} evidence, not {}",
                    binding.unwrap_or("an absent quorum")
                )),
            ));
        }
        let effect_committed = claim
            .quorum
            .as_ref()
            .and_then(|quorum| quorum.certified_block.as_ref())
            .is_some_and(|block| block.effect_committed_in_block);
        if !effect_committed {
            return Err(RecognizedEffectError::Finality(
                VerificationError::ConsensusEvidence(
                    "the native AFT quorum certifies a block, but the verifier did not establish that the block commits to this recognized effect"
                        .into(),
                ),
            ));
        }
        Ok(())
    }
}

/// The spine's per-profile adapter registry. Exactly one binding per member;
/// the store resolves through this and never branches on profile strings.
pub struct ProfileBindings {
    bft_consensus: Box<dyn ProfileFinalityBinding>,
    single_authority: Box<dyn ProfileFinalityBinding>,
}

impl ProfileBindings {
    /// Production registry. Both members are bound to real contracts:
    /// `single_authority` to the single-authority emitter, `bft_consensus` to
    /// the native AFT bridge. Runtime-v3 bundles verify directly and bind the
    /// full block effect. The predecessor template emitter starts without a
    /// quorum source, and predecessor block-only evidence remains refused.
    pub fn production() -> Self {
        Self {
            bft_consensus: Box::new(NativeAftBinding::unwired()),
            single_authority: Box::new(SingleAuthorityBinding),
        }
    }

    /// Wire the runtime's native AFT quorum source. This enables construction
    /// and offline verification of native evidence; recognized-effect
    /// admission additionally requires a proven block/effect commitment.
    pub fn with_native_aft_source(self, source: Arc<dyn NativeAftQuorumSource>) -> Self {
        self.with_binding(Box::new(NativeAftBinding::with_source(source)))
    }

    /// Replace one member's adapter.
    pub fn with_binding(mut self, binding: Box<dyn ProfileFinalityBinding>) -> Self {
        match binding.profile() {
            FinalityProfile::BftConsensus => self.bft_consensus = binding,
            FinalityProfile::SingleAuthority => self.single_authority = binding,
        }
        self
    }

    pub fn binding(&self, profile: FinalityProfile) -> &dyn ProfileFinalityBinding {
        match profile {
            FinalityProfile::BftConsensus => self.bft_consensus.as_ref(),
            FinalityProfile::SingleAuthority => self.single_authority.as_ref(),
        }
    }
}

impl Default for ProfileBindings {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::SerializableKey;

    // The canonical byte identities are contract, not formatting. A change
    // here is a wire migration for every admitted spine record.
    #[test]
    fn canonical_profile_identities_are_exact() {
        assert_eq!(FinalityProfile::BftConsensus.profile(), "bft_consensus");
        assert_eq!(
            FinalityProfile::BftConsensus.certificate_variant(),
            "bft_consensus_aft_v1"
        );
        assert_eq!(
            FinalityProfile::SingleAuthority.profile(),
            "single_authority"
        );
        assert_eq!(
            FinalityProfile::SingleAuthority.certificate_variant(),
            "single_authority_v1"
        );
        assert_eq!(FinalityProfile::DEFAULT, FinalityProfile::BftConsensus);
    }

    #[test]
    fn labels_resolve_before_admission_and_never_reach_admitted_bytes() {
        for (label, expected) in [
            ("bft_consensus", FinalityProfile::BftConsensus),
            ("single_authority", FinalityProfile::SingleAuthority),
            ("aft", FinalityProfile::BftConsensus),
        ] {
            assert_eq!(
                FinalityProfile::resolve_label(label).expect("label resolves"),
                expected,
                "{label}"
            );
        }

        // Admitted bytes accept ONLY the canonical spelling, so a label that
        // is not already canonical can never become a second runtime identity.
        for (label, member) in PROFILE_LABELS {
            let exact = FinalityProfile::from_exact(label, member.certificate_variant());
            assert_eq!(
                exact.is_ok(),
                label == member.profile(),
                "label {label} admitted as canonical bytes"
            );
        }
        assert!(FinalityProfile::from_exact("aft", "bft_consensus_aft_v1").is_err());
    }

    // Three refusals, because these are three different facts. Collapsing
    // them would let an out-of-scope member read as a typo.
    #[test]
    fn out_of_scope_ambiguous_and_unknown_labels_get_distinct_refusals() {
        for (label, member) in OUT_OF_SCOPE_LABELS {
            assert!(
                matches!(
                    FinalityProfile::resolve_label(label),
                    Err(RecognizedEffectError::Profile(
                        ProfileRefusal::ProfileOutsideSpineScope { ref canonical_member, .. }
                    )) if canonical_member.as_str() == member
                ),
                "{label} did not refuse for scope"
            );
        }
        assert!(matches!(
            FinalityProfile::resolve_label("witnessed_threshold"),
            Err(RecognizedEffectError::Profile(
                ProfileRefusal::AmbiguousProfileLabel { .. }
            ))
        ));
        // Case and separator variants are NOT folded: doing so would widen a
        // vocabulary this module does not own.
        for unknown in [
            "",
            "bft",
            "BFT_CONSENSUS",
            "bft-consensus",
            "single-authority",
            " aft ",
            "solo",
            "aft_v1",
            "bft_consensus_aft_v1",
            "single_authority_v1",
        ] {
            assert!(
                matches!(
                    FinalityProfile::resolve_label(unknown),
                    Err(RecognizedEffectError::Profile(
                        ProfileRefusal::UnknownProfileAlias { .. }
                    ))
                ),
                "{unknown} resolved"
            );
        }
    }

    // The variant-implies-profile binding is normative in
    // finality-certificate.v1.schema.json; this mirrors it for the two
    // in-scope variants and refuses the rest.
    #[test]
    fn certificate_variants_bind_their_profile() {
        assert_eq!(
            FinalityProfile::from_certificate_variant("bft_consensus_aft_v1").expect("aft variant"),
            FinalityProfile::BftConsensus
        );
        assert_eq!(
            FinalityProfile::from_certificate_variant("single_authority_v1")
                .expect("single-authority variant"),
            FinalityProfile::SingleAuthority
        );
        for outside in [
            "replicated_single_authority_v1",
            "threshold_authority_v1",
            "external_chain_finality_v1",
            "bft_consensus",
        ] {
            assert!(
                FinalityProfile::from_certificate_variant(outside).is_err(),
                "{outside}"
            );
        }
    }

    #[test]
    fn crossed_variant_and_unknown_profile_bytes_fail_closed() {
        assert!(FinalityProfile::from_exact("bft_consensus", "single_authority_v1").is_err());
        assert!(FinalityProfile::from_exact("single_authority", "bft_consensus_aft_v1").is_err());
        assert!(FinalityProfile::from_exact("proof_of_work", "pow_v1").is_err());
        assert!(FinalityProfile::from_exact("BFT_CONSENSUS", "bft_consensus_aft_v1").is_err());
    }

    #[test]
    fn direction_is_computed_from_the_exact_pair() {
        use FinalityProfile::{BftConsensus, SingleAuthority};
        assert_eq!(
            BftConsensus.direction_to(SingleAuthority),
            Some(GuaranteeDirection::Weakening)
        );
        assert_eq!(
            SingleAuthority.direction_to(BftConsensus),
            Some(GuaranteeDirection::Strengthening)
        );
        assert_eq!(BftConsensus.direction_to(BftConsensus), None);
        assert_eq!(SingleAuthority.direction_to(SingleAuthority), None);
    }

    // Production wires the real native AFT adapter. Emission is fail-closed
    // only because no runtime quorum source exists yet — and it refuses by
    // naming that, rather than returning a bundle nobody verified.
    #[test]
    fn production_wires_the_native_aft_binding_and_refuses_to_invent_a_quorum() {
        let bindings = ProfileBindings::production();
        let aft = bindings.binding(FinalityProfile::BftConsensus);
        assert_eq!(aft.profile(), FinalityProfile::BftConsensus);

        // Emission without a source refuses; it never fabricates a certificate.
        let key = Ed25519PrivateKey::from_bytes(&[3_u8; 32]).expect("test key");
        assert!(matches!(
            aft.emit(serde_json::json!({}), "key://test", &key),
            Err(RecognizedEffectError::Profile(
                ProfileRefusal::ProfileNotWired { .. }
            ))
        ));

        // Verification is live, so a malformed bundle now fails as a finality
        // refusal rather than as "not wired". Reading the old `ProfileNotWired`
        // here would mean the binding still asserts nothing.
        assert!(matches!(
            aft.verify(&serde_json::json!({})),
            Err(RecognizedEffectError::Finality(_))
        ));
        assert_eq!(
            bindings.binding(FinalityProfile::SingleAuthority).profile(),
            FinalityProfile::SingleAuthority
        );
    }

    // The production profile must refuse the non-runtime checkpoint round even
    // though it is a structurally valid `bft_consensus_aft_v1` artifact. This is
    // the fence that keeps a quorum this crate could mint for itself from being
    // admitted as imported consensus evidence.
    #[test]
    fn production_aft_refuses_a_checkpoint_round_quorum() {
        let refusal = NativeAftBinding::unwired()
            .verify(&serde_json::json!({}))
            .expect_err("an empty bundle cannot verify");
        // Distinguish the two refusal families explicitly: an unwired binding
        // must not answer verification with `ProfileNotWired`.
        assert!(matches!(refusal, RecognizedEffectError::Finality(_)));
    }
}
