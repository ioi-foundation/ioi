//! Source-control publication plane: the compiler for one immutable,
//! receipted `ScmPublicationEffect`.
//!
//! Registered contract:
//! `schema://ioi/components/connectors-tools/scm-publication-effect/v1`
//! (`ioi.scm-publication-effect.v1`), canonical owner
//! `docs/architecture/components/connectors-tools/contracts.md#scmpublicationeffect`.
//!
//! Every input that decides where bytes land, what bytes land, and what the
//! remote head was is resolved from server truth (INV-37): the destination
//! comes from an admitted connector binding, the change set comes from the
//! bound proposal, and the expected heads come from a daemon-made observation.
//! The caller names a proposal, a work run, a binding, and a target-ref leaf —
//! nothing else it says can move the effect.
//!
//! Every refusal is named. The compiler is total over its inputs: it either
//! returns a compiled publication or a verdict carrying exactly one refusal
//! dimension, and `verify_scm_publication_effect` is total over any JSON value
//! at all, so a stored or presented effect can always be adjudicated.
//!
//! Three shapes are unrepresentable rather than merely rejected: the record
//! has no field through which a forced overwrite of the remote head can be
//! expressed, no `change_set_kind` other than the enumerated proposal-bound
//! file set, and no way to state an overall success over a failed sub-effect —
//! `overall_outcome` is derived from the two sub-effect outcomes and is never
//! an input.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::app::generated::architecture_contracts::validate_architecture_contract;

use super::system_activation::jcs_hash;

/// Registered source-control publication effect contract.
pub const SCM_PUBLICATION_EFFECT_CONTRACT: &str =
    "schema://ioi/components/connectors-tools/scm-publication-effect/v1";
/// Registered wire schema version of one publication effect.
pub const SCM_PUBLICATION_EFFECT_SCHEMA_VERSION: &str = "ioi.scm-publication-effect.v1";

/// Content domain of the whole-effect commitment (mirrors the registered
/// invariant `scm_publication_effect.content_commitment.recomputes`).
pub const SCM_PUBLICATION_COMMITMENT_PROFILE: &str =
    "ioi.scm-publication-effect-commitment-jcs-sha256.v1";
/// Content domain of the enumerated file-set digest (mirrors
/// `scm_publication_effect.change_set.file_set_digest.recomputes`).
pub const SCM_PUBLICATION_FILE_SET_PROFILE: &str =
    "ioi.scm-publication-effect-file-set-jcs-sha256.v1";
/// Content domain of the idempotency key (mirrors
/// `scm_publication_effect.idempotency.key.recomputes`).
pub const SCM_PUBLICATION_IDEMPOTENCY_PROFILE: &str =
    "ioi.scm-publication-effect-idempotency-jcs-sha256.v1";
/// Content domain of one durable proposal record's content commitment. The
/// commitment the effect carries is this recipe, so the shipped set is the set
/// the proposal committed to.
pub const SCM_PUBLICATION_PROPOSAL_PROFILE: &str =
    "ioi.hypervisor.scm-publication-proposal-jcs-sha256.v1";
/// Content domain of one durable destination-binding record's revision hash.
pub const SCM_DESTINATION_BINDING_PROFILE: &str =
    "ioi.hypervisor.scm-destination-binding-jcs-sha256.v1";
/// Content domain of the owner-allocated publication effect identity. The
/// identity is allocated before hashing and never derived from the effect
/// hash it will carry.
pub const SCM_PUBLICATION_ALLOCATION_PROFILE: &str =
    "ioi.hypervisor.scm-publication-effect-allocation-jcs-sha256.v1";

/// Durable record family holding admitted destination bindings.
pub const SCM_DESTINATION_BINDING_FAMILY: &str = "scm-destination-bindings";
/// Durable record family holding proposal-bound change sets.
pub const SCM_PUBLICATION_PROPOSAL_FAMILY: &str = "scm-publication-proposals";
/// Durable record family holding committed publication effects.
pub const SCM_PUBLICATION_EFFECT_FAMILY: &str = "scm-publication-effects";
/// Durable record family holding the two per-effect sub-effect receipts.
pub const SCM_PUBLICATION_RECEIPT_FAMILY: &str = "scm-publication-receipts";

/// Schema version of one durable destination-binding record.
pub const SCM_DESTINATION_BINDING_SCHEMA_VERSION: &str =
    "ioi.hypervisor.scm-destination-binding.v1";
/// Schema version of one durable publication-proposal record.
pub const SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION: &str =
    "ioi.hypervisor.scm-publication-proposal.v1";
/// Schema version of one durable sub-effect receipt record.
pub const SCM_PUBLICATION_RECEIPT_SCHEMA_VERSION: &str =
    "ioi.hypervisor.scm-publication-receipt.v1";

/// The exact three nonclaims every publication effect carries.
pub const SCM_PUBLICATION_NONCLAIMS: [&str; 3] = [
    "grants_no_authority",
    "no_remote_acceptance_beyond_receipt_evidence",
    "asserts_no_review_approval",
];

/// The single admitted destination resolution.
pub const SCM_DESTINATION_RESOLUTION: &str = "admitted_connector_binding";
/// The single admitted change-set kind.
pub const SCM_CHANGE_SET_KIND: &str = "proposal_bound_file_set";
/// The single admitted compare-and-swap mechanism.
pub const SCM_CAS_MECHANISM: &str = "expected_head_compare_and_swap";
/// The single admitted remote update mode. There is no other value, and no
/// field through which a forced overwrite could be requested.
pub const SCM_REMOTE_UPDATE_MODE: &str = "expected_head_advance_or_refuse";
/// The single admitted stale-head disposition.
pub const SCM_STALE_HEAD_DISPOSITION: &str = "refuse_never_overwrite";

/// Every named refusal dimension of the publication plane's falsifiable claim.
/// The first eleven are pinned one-for-one by a registered negative fixture.
pub const SCM_PUBLICATION_REFUSAL_DIMENSIONS: [&str; 15] = [
    "absent_expected_head",
    "stale_expected_head",
    "remote_overwrite_requested",
    "unbound_destination",
    "whole_workspace_change_set",
    "change_set_unbound_from_proposal",
    "review_request_failure_reported_as_success",
    "shared_effect_receipt",
    "replay_without_prior_effect",
    "idempotency_key_reuse_over_changed_material",
    "detached_content_commitment",
    "remote_advance_detached_from_change_set",
    "review_request_receipt_absent",
    "refusal_code_absent",
    "effect_contract_invalid",
];

/// The publication sub-effect outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmPublicationOutcome {
    /// The declared change set advanced the target ref under the compare-and-swap.
    Published,
    /// Some declared material landed and the effect is not closed.
    PartiallyApplied,
    /// Nothing landed; the crossing failed closed on a named refusal code.
    Refused,
}

impl ScmPublicationOutcome {
    /// Stable wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::PartiallyApplied => "partially_applied",
            Self::Refused => "refused",
        }
    }

    /// Parse a stable wire value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "published" => Some(Self::Published),
            "partially_applied" => Some(Self::PartiallyApplied),
            "refused" => Some(Self::Refused),
            _ => None,
        }
    }
}

/// The review-request sub-effect outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmReviewRequestOutcome {
    /// A review request was opened on the remote.
    Opened,
    /// A review request was attempted and the remote refused or errored.
    Failed,
    /// The estate refused to attempt the review request.
    Refused,
    /// No review request was asked for.
    NotRequested,
    /// A review request was asked for but the publication never reached it.
    NotAttempted,
}

impl ScmReviewRequestOutcome {
    /// Stable wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "opened",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::NotRequested => "not_requested",
            Self::NotAttempted => "not_attempted",
        }
    }

    /// Parse a stable wire value.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "opened" => Some(Self::Opened),
            "failed" => Some(Self::Failed),
            "refused" => Some(Self::Refused),
            "not_requested" => Some(Self::NotRequested),
            "not_attempted" => Some(Self::NotAttempted),
            _ => None,
        }
    }
}

/// The overall outcome. It is always DERIVED from the two sub-effect outcomes
/// and is never accepted as an input, so reporting success over a failed or
/// skipped sub-effect has no construction path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmOverallOutcome {
    /// Published, and a review request was opened.
    PublishedWithReviewRequest,
    /// Published, and no review request was asked for.
    PublishedReviewRequestNotRequested,
    /// Published, and the review request failed.
    ReviewRequestFailed,
    /// Partially applied; the review request was never attempted.
    PartiallyApplied,
    /// Refused; nothing landed.
    Refused,
}

impl ScmOverallOutcome {
    /// Stable wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublishedWithReviewRequest => "published_with_review_request",
            Self::PublishedReviewRequestNotRequested => "published_review_request_not_requested",
            Self::ReviewRequestFailed => "review_request_failed",
            Self::PartiallyApplied => "partially_applied",
            Self::Refused => "refused",
        }
    }
}

/// Derive the one honest overall outcome from the two sub-effect outcomes.
/// `None` means the pair states nothing the contract can express — for example
/// a publication reported as published over a failed review request while
/// claiming an overall success.
pub fn derive_overall_outcome(
    publication: ScmPublicationOutcome,
    review_request: ScmReviewRequestOutcome,
) -> Option<ScmOverallOutcome> {
    match (publication, review_request) {
        (ScmPublicationOutcome::Published, ScmReviewRequestOutcome::Opened) => {
            Some(ScmOverallOutcome::PublishedWithReviewRequest)
        }
        (ScmPublicationOutcome::Published, ScmReviewRequestOutcome::NotRequested) => {
            Some(ScmOverallOutcome::PublishedReviewRequestNotRequested)
        }
        (ScmPublicationOutcome::Published, ScmReviewRequestOutcome::Failed) => {
            Some(ScmOverallOutcome::ReviewRequestFailed)
        }
        (ScmPublicationOutcome::PartiallyApplied, ScmReviewRequestOutcome::NotAttempted) => {
            Some(ScmOverallOutcome::PartiallyApplied)
        }
        (
            ScmPublicationOutcome::Refused,
            ScmReviewRequestOutcome::Refused | ScmReviewRequestOutcome::NotAttempted,
        ) => Some(ScmOverallOutcome::Refused),
        _ => None,
    }
}

/// The target-ref precondition the compare-and-swap was computed against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScmTargetRefPrecondition {
    /// The target ref exists and must still be at the declared head.
    ExpectedHead,
    /// The target ref must not exist yet.
    MustNotExist,
}

impl ScmTargetRefPrecondition {
    /// Stable wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExpectedHead => "expected_head",
            Self::MustNotExist => "must_not_exist",
        }
    }
}

/// What a daemon-made observation of the remote target ref found. `Unobserved`
/// is a first-class state: an observation that did not happen is never allowed
/// to become an unconditional advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedTargetRef {
    /// The target ref does not exist on the remote.
    Absent,
    /// The target ref exists at exactly this revision.
    Present(String),
    /// The remote head could not be observed at all.
    Unobserved,
}

/// A total admit/refuse verdict with exactly one named dimension on refusal.
#[derive(Debug, Clone, PartialEq)]
pub struct ScmPublicationVerdict {
    /// Whether the evaluated claim is admitted.
    pub admitted: bool,
    /// Named refusal dimension, absent only on admit.
    pub refusal_dimension: Option<&'static str>,
    /// Human-readable refusal reason, absent only on admit.
    pub refusal_reason: Option<String>,
}

impl ScmPublicationVerdict {
    /// Refuse with exactly one declared dimension.
    pub fn refuse(dimension: &'static str, reason: impl Into<String>) -> Self {
        debug_assert!(SCM_PUBLICATION_REFUSAL_DIMENSIONS.contains(&dimension));
        Self {
            admitted: false,
            refusal_dimension: Some(dimension),
            refusal_reason: Some(reason.into()),
        }
    }

    /// Admit.
    pub fn admit() -> Self {
        Self {
            admitted: true,
            refusal_dimension: None,
            refusal_reason: None,
        }
    }
}

/// What the caller names. Nothing here resolves a destination, a change set,
/// or a remote head; those are server truth. The three "requested_*" fields
/// exist only so an attempted defect earns its own named refusal instead of
/// being silently dropped.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScmPublicationSubmission {
    /// The bound proposal the change set must come from.
    pub proposal_ref: String,
    /// The work run the publication is attributed to.
    pub work_run_ref: String,
    /// The admitted destination binding to publish through.
    pub destination_binding_ref: String,
    /// The leaf name of the target ref inside the binding's namespace.
    pub target_ref_name: String,
    /// Whether a review request should be opened after a successful advance.
    pub review_request_requested: bool,
    /// Any caller attempt to steer the remote update mode.
    pub requested_remote_update_mode: Option<String>,
    /// Any caller attempt to force the remote head.
    pub force_requested: bool,
    /// Any caller-supplied remote destination text.
    pub caller_supplied_remote: Option<String>,
    /// Any caller attempt to select the change-set kind.
    pub requested_change_set_kind: Option<String>,
    /// Any caller-asserted idempotency disposition.
    pub asserted_submission_disposition: Option<String>,
}

/// The exact durable truth one publication compiles against. Every field is
/// resolved from durable estate records or a daemon-made observation.
#[derive(Debug, Clone, PartialEq)]
pub struct ScmPublicationServerTruth<'a> {
    /// The admitted destination-binding record.
    pub destination_binding: &'a Value,
    /// The durable proposal record carrying the enumerated file set.
    pub proposal: &'a Value,
    /// The observed state of the remote target ref.
    pub observed_target_ref: ObservedTargetRef,
    /// The observed head of the binding's base ref.
    pub observed_base_head: &'a str,
    /// When the observation was made.
    pub observed_at: &'a str,
    /// Evidence ref for the observation itself.
    pub observation_evidence_ref: &'a str,
    /// Authority grants presented for the crossing.
    pub authority_grant_refs: &'a [String],
    /// Authority scopes the crossing consumed.
    pub authority_scope_refs: &'a [String],
    /// The issued capability lease.
    pub capability_lease_ref: &'a str,
    /// The admission receipt of the authority crossing.
    pub admission_receipt_ref: &'a str,
    /// Every publication effect already committed by this estate.
    pub prior_effects: &'a [Value],
}

/// A pure, server-derived publication plan. Nothing here is stamped with a
/// remote outcome yet; the plan is what the estate will attempt and the exact
/// material every commitment recomputes over.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledScmPublication {
    /// Owner-allocated effect identity, allocated before hashing.
    pub publication_effect_id: String,
    /// Short allocation tail used to name the per-effect receipts.
    pub allocation_tail: String,
    /// Repository tail (`repository://<tail>`), the estate's naming root.
    pub repository_tail: String,
    /// Bound work subject.
    pub work_subject: Value,
    /// Presented authority.
    pub authority: Value,
    /// Resolved destination.
    pub destination: Value,
    /// The enumerated change set, minus the resulting revision.
    pub change_set_without_result: Value,
    /// The compare-and-swap preconditions, minus the resulting head and proof.
    pub remote_cas_without_result: Value,
    /// The recomputed file-set digest.
    pub file_set_digest: String,
    /// The recomputed idempotency key.
    pub idempotency_key: String,
    /// The derived submission disposition.
    pub submission_disposition: String,
    /// The prior effect this submission converges against, when replaying.
    pub prior_effect: Option<(String, String)>,
    /// The exact prior effect record on a converged replay: the convergent
    /// answer is the prior effect restated, never a second remote crossing.
    pub converged_prior_effect: Option<Value>,
    /// Whether a review request was asked for.
    pub review_request_requested: bool,
    /// The remote destination the port must contact, from the binding only.
    pub remote_url: String,
    /// The target ref the compare-and-swap advances.
    pub target_ref: String,
    /// The base ref the change set was computed onto.
    pub base_ref: String,
    /// The base revision the change set was computed onto.
    pub base_revision_id: String,
    /// The expected target head, absent only when the ref must not exist.
    pub expected_target_head: Option<String>,
}

impl CompiledScmPublication {
    /// The receipt ref for the publication sub-effect at the given outcome.
    pub fn publication_receipt_ref(&self, outcome: ScmPublicationOutcome) -> String {
        let leaf = match outcome {
            ScmPublicationOutcome::Published => "publication",
            ScmPublicationOutcome::PartiallyApplied => "publication-partial",
            ScmPublicationOutcome::Refused => "publication-refusal",
        };
        format!(
            "receipt://{}/scm-publication/{leaf}/{}",
            self.repository_tail, self.allocation_tail
        )
    }

    /// The receipt ref for the review-request sub-effect. Always a different
    /// path segment from every publication receipt, so one receipt can never
    /// stand for both sub-effects.
    pub fn review_request_receipt_ref(&self) -> String {
        format!(
            "receipt://{}/scm-publication/review-request/{}",
            self.repository_tail, self.allocation_tail
        )
    }

    /// Evidence ref for the publication transcript.
    pub fn publication_evidence_ref(&self) -> String {
        format!(
            "evidence://{}/scm/publication-transcript/{}",
            self.repository_tail, self.allocation_tail
        )
    }

    /// Evidence ref for the review-request transcript.
    pub fn review_request_evidence_ref(&self) -> String {
        format!(
            "evidence://{}/scm/review-request-transcript/{}",
            self.repository_tail, self.allocation_tail
        )
    }

    /// Receipt ref standing for the compare-and-swap proof.
    pub fn compare_and_swap_proof_ref(&self) -> String {
        format!(
            "receipt://{}/scm-publication/compare-and-swap/{}",
            self.repository_tail, self.allocation_tail
        )
    }
}

/// The two receipted sub-effect outcomes the remote port reports back.
/// `overall_outcome` is deliberately absent: it is derived, never supplied.
#[derive(Debug, Clone, PartialEq)]
pub struct ScmPublicationSubEffects {
    /// Publication outcome.
    pub publication_outcome: ScmPublicationOutcome,
    /// Publication receipt.
    pub publication_receipt_ref: String,
    /// Named refusal code, required whenever the publication did not fully land.
    pub publication_refusal_code: Option<String>,
    /// Publication evidence refs (at least one).
    pub publication_evidence_refs: Vec<String>,
    /// Review-request outcome.
    pub review_request_outcome: ScmReviewRequestOutcome,
    /// Review-request receipt, required whenever it was opened or failed.
    pub review_request_receipt_ref: Option<String>,
    /// Named review-request refusal code, required on failure or refusal.
    pub review_request_refusal_code: Option<String>,
    /// Review-request evidence refs.
    pub review_request_evidence_refs: Vec<String>,
    /// The revision the change set produced, absent on refusal.
    pub resulting_revision_id: Option<String>,
    /// Evidence ref proving the compare-and-swap.
    pub proof_ref: String,
}

/// One fully built, contract-validated publication effect.
#[derive(Debug, Clone, PartialEq)]
pub struct ScmPublicationArtifacts {
    /// The immutable effect record.
    pub effect: Value,
    /// The effect content commitment.
    pub publication_effect_hash: String,
    /// The derived overall outcome.
    pub overall_outcome: ScmOverallOutcome,
}

fn opt_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn text<'a>(value: &'a Value, pointer: &str) -> &'a str {
    opt_str(value, pointer).unwrap_or("")
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn canonical_revision(value: &str) -> bool {
    value.strip_prefix("scm-revision:").is_some_and(|tail| {
        (40..=64).contains(&tail.len())
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

/// The exact content commitment of one publication effect: every field except
/// `publication_effect_hash`, mirroring the registered portable invariant
/// field for field.
pub fn scm_publication_effect_commitment(effect: &Value) -> Result<String, String> {
    let mut material = Map::new();
    material.insert(
        "domain".to_owned(),
        json!(SCM_PUBLICATION_COMMITMENT_PROFILE),
    );
    for field in [
        "schema_version",
        "publication_effect_id",
        "work_subject",
        "authority",
        "destination",
        "change_set",
        "remote_cas",
        "idempotency",
        "effects",
        "overall_outcome",
        "nonclaims",
        "committed_at",
    ] {
        material.insert(
            field.to_owned(),
            effect
                .get(field)
                .cloned()
                .ok_or_else(|| format!("publication effect lacks '{field}'"))?,
        );
    }
    jcs_hash(&Value::Object(material))
}

/// The exact file-set digest: the bound proposal, its content commitment, the
/// base revision, and the enumerated rows — nothing else.
pub fn scm_publication_file_set_digest(
    proposal_ref: &str,
    proposal_content_commitment: &str,
    base_revision_id: &str,
    files: &Value,
) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": SCM_PUBLICATION_FILE_SET_PROFILE,
        "proposal_ref": proposal_ref,
        "proposal_content_commitment": proposal_content_commitment,
        "base_revision_id": base_revision_id,
        "files": files,
    }))
}

/// The exact idempotency key: the bound proposal, the admitted binding, the
/// target ref and its precondition, the expected head, and the file-set
/// digest. An exact resubmission carries this key; any changed material does
/// not.
#[allow(clippy::too_many_arguments)]
pub fn scm_publication_idempotency_key(
    proposal_ref: &str,
    proposal_hash: &str,
    destination_binding_ref: &str,
    destination_binding_hash: &str,
    repository_ref: &str,
    target_ref: &str,
    target_ref_precondition: &str,
    expected_target_head: Option<&str>,
    file_set_digest: &str,
) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": SCM_PUBLICATION_IDEMPOTENCY_PROFILE,
        "proposal_ref": proposal_ref,
        "proposal_hash": proposal_hash,
        "destination_binding_ref": destination_binding_ref,
        "destination_binding_hash": destination_binding_hash,
        "repository_ref": repository_ref,
        "target_ref": target_ref,
        "target_ref_precondition": target_ref_precondition,
        "expected_target_head": expected_target_head,
        "file_set_digest": file_set_digest,
    }))
}

/// The content commitment of one durable proposal record. The effect carries
/// this value as both `work_subject.proposal_hash` and
/// `change_set.proposal_content_commitment`.
pub fn scm_publication_proposal_commitment(proposal: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": SCM_PUBLICATION_PROPOSAL_PROFILE,
        "proposal_ref": proposal.get("proposal_ref").cloned().unwrap_or(Value::Null),
        "change_set_kind": proposal.get("change_set_kind").cloned().unwrap_or(Value::Null),
        "base_revision_id": proposal.get("base_revision_id").cloned().unwrap_or(Value::Null),
        "files": proposal.get("files").cloned().unwrap_or(Value::Null),
    }))
}

/// The revision hash of one durable destination binding: every field except
/// the hash it carries.
pub fn scm_destination_binding_hash(binding: &Value) -> Result<String, String> {
    let mut material = binding
        .as_object()
        .cloned()
        .ok_or("destination binding is not an object")?;
    material.remove("destination_binding_hash");
    material.insert("domain".to_owned(), json!(SCM_DESTINATION_BINDING_PROFILE));
    jcs_hash(&Value::Object(material))
}

/// Adjudicate any presented or stored publication effect. TOTAL: every input
/// produces a verdict, never a panic and never an error, and every refusal
/// names exactly one dimension.
///
/// The check order is the canon order, so each registered negative fixture
/// lands on its own dimension: unrepresentable literals first, then the
/// destination binding, then the proposal binding, then the compare-and-swap,
/// then the sub-effect honesty, then idempotency, then the whole-record
/// content commitment.
pub fn verify_scm_publication_effect(effect: &Value) -> ScmPublicationVerdict {
    if !effect.is_object() {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "a publication effect must be an object",
        );
    }
    if text(effect, "/schema_version") != SCM_PUBLICATION_EFFECT_SCHEMA_VERSION {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the record does not declare the registered publication effect schema version",
        );
    }

    // 1 — literals that make the forbidden shapes unrepresentable.
    if text(effect, "/change_set/change_set_kind") != SCM_CHANGE_SET_KIND {
        return ScmPublicationVerdict::refuse(
            "whole_workspace_change_set",
            "a change set that is not the enumerated proposal-bound file set has no representation",
        );
    }
    if text(effect, "/remote_cas/mechanism") != SCM_CAS_MECHANISM
        || text(effect, "/remote_cas/remote_update_mode") != SCM_REMOTE_UPDATE_MODE
        || text(effect, "/remote_cas/stale_head_disposition") != SCM_STALE_HEAD_DISPOSITION
    {
        return ScmPublicationVerdict::refuse(
            "remote_overwrite_requested",
            "the remote head advances only under the expected-head compare-and-swap; an overwrite \
             has no representation",
        );
    }
    if text(effect, "/destination/resolution") != SCM_DESTINATION_RESOLUTION {
        return ScmPublicationVerdict::refuse(
            "unbound_destination",
            "the destination resolves only from an admitted connector binding",
        );
    }

    // 2 — the admitted binding must cover the repository the effect names.
    let binding_ref = text(effect, "/destination/destination_binding_ref");
    let repository_ref = text(effect, "/destination/repository_ref");
    let Some(repository_tail) = repository_ref.strip_prefix("repository://") else {
        return ScmPublicationVerdict::refuse(
            "unbound_destination",
            "the repository ref is not a canonical repository identity",
        );
    };
    if !binding_ref.starts_with(&format!("scm-destination-binding://{repository_tail}/")) {
        return ScmPublicationVerdict::refuse(
            "unbound_destination",
            "the destination binding does not cover the repository the effect names",
        );
    }
    let target_ref = text(effect, "/destination/target_ref");
    let base_ref = text(effect, "/destination/base_ref");
    for (label, value) in [("target", target_ref), ("base", base_ref)] {
        if !value.starts_with(&format!("scm-ref://{repository_tail}/")) {
            return ScmPublicationVerdict::refuse(
                "unbound_destination",
                format!("the {label} ref lies outside the bound repository"),
            );
        }
    }

    // 3 — every row is attributed to the one bound proposal.
    let proposal_ref = text(effect, "/work_subject/proposal_ref");
    let proposal_hash = text(effect, "/work_subject/proposal_hash");
    let commitment = text(effect, "/change_set/proposal_content_commitment");
    if commitment.is_empty() || commitment != proposal_hash {
        return ScmPublicationVerdict::refuse(
            "change_set_unbound_from_proposal",
            "the change set does not carry the exact content commitment of the bound proposal",
        );
    }
    let Some(files) = effect
        .pointer("/change_set/files")
        .and_then(Value::as_array)
    else {
        return ScmPublicationVerdict::refuse(
            "change_set_unbound_from_proposal",
            "the change set enumerates no file rows",
        );
    };
    if files.is_empty() {
        return ScmPublicationVerdict::refuse(
            "change_set_unbound_from_proposal",
            "the change set enumerates no file rows",
        );
    }
    let mut paths: Vec<&str> = Vec::with_capacity(files.len());
    for row in files {
        if text(row, "/proposal_ref") != proposal_ref {
            return ScmPublicationVerdict::refuse(
                "change_set_unbound_from_proposal",
                "a published file row is not attributed to the one bound proposal",
            );
        }
        paths.push(text(row, "/path"));
    }
    paths.sort_unstable();
    let unique = paths.len();
    paths.dedup();
    if paths.len() != unique {
        return ScmPublicationVerdict::refuse(
            "change_set_unbound_from_proposal",
            "a repository-relative path appears more than once in the published change set",
        );
    }
    let base_revision_id = text(effect, "/change_set/base_revision_id");
    match scm_publication_file_set_digest(
        proposal_ref,
        commitment,
        base_revision_id,
        effect.pointer("/change_set/files").unwrap_or(&Value::Null),
    ) {
        Ok(digest) if digest == text(effect, "/change_set/file_set_digest") => {}
        _ => {
            return ScmPublicationVerdict::refuse(
                "change_set_unbound_from_proposal",
                "the file-set digest does not recompute over the declared rows",
            )
        }
    }

    // 4 — the compare-and-swap.
    let precondition = text(effect, "/remote_cas/target_ref_precondition");
    let expected_target_head = effect
        .pointer("/remote_cas/expected_target_head")
        .and_then(Value::as_str);
    match precondition {
        "expected_head" => {
            if !expected_target_head.is_some_and(canonical_revision) {
                return ScmPublicationVerdict::refuse(
                    "absent_expected_head",
                    "an expected-head compare-and-swap without a declared head is a refusal, never \
                     an unconditional advance",
                );
            }
        }
        "must_not_exist" => {
            if expected_target_head.is_some() {
                return ScmPublicationVerdict::refuse(
                    "absent_expected_head",
                    "a must-not-exist precondition cannot declare an expected head",
                );
            }
        }
        _ => {
            return ScmPublicationVerdict::refuse(
                "absent_expected_head",
                "the target ref precondition is not a declared member",
            )
        }
    }
    if text(effect, "/remote_cas/expected_base_head") != base_revision_id
        || !canonical_revision(base_revision_id)
    {
        return ScmPublicationVerdict::refuse(
            "stale_expected_head",
            "the declared base head is detached from the change-set base; a stale compare-and-swap \
             is refused, never reconciled by overwriting",
        );
    }
    if effect.pointer("/remote_cas/resulting_target_head")
        != effect.pointer("/change_set/resulting_revision_id")
    {
        return ScmPublicationVerdict::refuse(
            "remote_advance_detached_from_change_set",
            "the resulting remote head does not equal the revision the change set produced",
        );
    }

    // 5 — the two sub-effects are separately receipted and honestly reported.
    let publication_receipt = text(effect, "/effects/publication/receipt_ref");
    let review_receipt = effect
        .pointer("/effects/review_request/receipt_ref")
        .and_then(Value::as_str);
    if publication_receipt.is_empty() {
        return ScmPublicationVerdict::refuse(
            "shared_effect_receipt",
            "the publication sub-effect carries no receipt of its own",
        );
    }
    if review_receipt == Some(publication_receipt) {
        return ScmPublicationVerdict::refuse(
            "shared_effect_receipt",
            "one receipt cannot stand for both sub-effects",
        );
    }
    let Some(publication_outcome) =
        ScmPublicationOutcome::parse(text(effect, "/effects/publication/outcome"))
    else {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the publication sub-effect outcome is not a declared member",
        );
    };
    let Some(review_outcome) =
        ScmReviewRequestOutcome::parse(text(effect, "/effects/review_request/outcome"))
    else {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the review-request sub-effect outcome is not a declared member",
        );
    };
    if matches!(
        review_outcome,
        ScmReviewRequestOutcome::Opened | ScmReviewRequestOutcome::Failed
    ) && review_receipt.is_none_or(str::is_empty)
    {
        return ScmPublicationVerdict::refuse(
            "review_request_receipt_absent",
            "an opened or failed review request carries its own receipt",
        );
    }
    if matches!(
        publication_outcome,
        ScmPublicationOutcome::Refused | ScmPublicationOutcome::PartiallyApplied
    ) && opt_str(effect, "/effects/publication/refusal_code").is_none_or(str::is_empty)
    {
        return ScmPublicationVerdict::refuse(
            "refusal_code_absent",
            "a refused or partially applied publication declares the exact code it failed closed on",
        );
    }
    if matches!(
        review_outcome,
        ScmReviewRequestOutcome::Failed | ScmReviewRequestOutcome::Refused
    ) && opt_str(effect, "/effects/review_request/refusal_code").is_none_or(str::is_empty)
    {
        return ScmPublicationVerdict::refuse(
            "refusal_code_absent",
            "a failed or refused review request declares the exact code, never an empty success",
        );
    }
    let Some(derived) = derive_overall_outcome(publication_outcome, review_outcome) else {
        return ScmPublicationVerdict::refuse(
            "review_request_failure_reported_as_success",
            "the declared sub-effect outcomes state no overall outcome the contract can express",
        );
    };
    if text(effect, "/overall_outcome") != derived.as_str() {
        return ScmPublicationVerdict::refuse(
            "review_request_failure_reported_as_success",
            format!(
                "the overall outcome is detached from the sub-effects; the honest outcome is '{}'",
                derived.as_str()
            ),
        );
    }
    if publication_outcome == ScmPublicationOutcome::Refused
        && (effect.pointer("/change_set/resulting_revision_id") != Some(&Value::Null)
            || effect.pointer("/remote_cas/resulting_target_head") != Some(&Value::Null))
    {
        return ScmPublicationVerdict::refuse(
            "remote_advance_detached_from_change_set",
            "a refused publication can name no resulting revision and no resulting remote head",
        );
    }

    // 6 — idempotency.
    let disposition = text(effect, "/idempotency/submission_disposition");
    if matches!(
        disposition,
        "converged_replay" | "refused_conflicting_replay"
    ) {
        let prior_ref = opt_str(effect, "/idempotency/prior_effect_ref");
        let prior_hash = opt_str(effect, "/idempotency/prior_effect_hash");
        if prior_ref.is_none_or(str::is_empty) || prior_hash.is_none_or(str::is_empty) {
            return ScmPublicationVerdict::refuse(
                "replay_without_prior_effect",
                "a replay disposition must name the prior effect and its content commitment",
            );
        }
    } else if disposition != "first_admission" {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the submission disposition is not a declared member",
        );
    }
    match scm_publication_idempotency_key(
        proposal_ref,
        proposal_hash,
        binding_ref,
        text(effect, "/destination/destination_binding_hash"),
        repository_ref,
        target_ref,
        precondition,
        expected_target_head,
        text(effect, "/change_set/file_set_digest"),
    ) {
        Ok(key) if key == text(effect, "/idempotency/idempotency_key") => {}
        _ => {
            return ScmPublicationVerdict::refuse(
                "idempotency_key_reuse_over_changed_material",
                "the idempotency key does not recompute over the submitted material; changed \
                 material cannot claim an earlier key",
            )
        }
    }

    // 7 — the whole-record content commitment.
    let nonclaims = effect
        .get("nonclaims")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if nonclaims.len() != SCM_PUBLICATION_NONCLAIMS.len()
        || !SCM_PUBLICATION_NONCLAIMS
            .iter()
            .all(|declared| nonclaims.iter().any(|carried| carried == declared))
    {
        return ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the record does not carry exactly the three declared nonclaims",
        );
    }
    match scm_publication_effect_commitment(effect) {
        Ok(hash) if hash == text(effect, "/publication_effect_hash") && canonical_hash(&hash) => {}
        _ => {
            return ScmPublicationVerdict::refuse(
                "detached_content_commitment",
                "the publication effect hash does not recompute over the committed material",
            )
        }
    }
    ScmPublicationVerdict::admit()
}

fn refuse_compile(
    dimension: &'static str,
    reason: impl Into<String>,
) -> Result<CompiledScmPublication, ScmPublicationVerdict> {
    Err(ScmPublicationVerdict::refuse(dimension, reason))
}

/// Compile one publication attempt against durable server truth.
///
/// TOTAL over its inputs: it returns either a compiled plan or a verdict with
/// exactly one named refusal dimension. No caller-supplied text ever reaches
/// the destination, the change set, or the compare-and-swap.
pub fn compile_scm_publication(
    truth: &ScmPublicationServerTruth<'_>,
    submission: &ScmPublicationSubmission,
) -> Result<CompiledScmPublication, ScmPublicationVerdict> {
    // --- caller attempts that the record has no shape for ---------------
    if let Some(remote) = submission.caller_supplied_remote.as_deref() {
        if !remote.is_empty() {
            return refuse_compile(
                "unbound_destination",
                "the destination resolves from the admitted binding; caller-supplied remote text \
                 is never an input",
            );
        }
    }
    if submission.force_requested {
        return refuse_compile(
            "remote_overwrite_requested",
            "a forced overwrite of the remote head has no representation in this plane",
        );
    }
    if let Some(mode) = submission.requested_remote_update_mode.as_deref() {
        if mode != SCM_REMOTE_UPDATE_MODE {
            return refuse_compile(
                "remote_overwrite_requested",
                format!("'{mode}' is not the one admitted remote update mode"),
            );
        }
    }
    if let Some(kind) = submission.requested_change_set_kind.as_deref() {
        if kind != SCM_CHANGE_SET_KIND {
            return refuse_compile(
                "whole_workspace_change_set",
                format!("'{kind}' is not the one admitted change-set kind"),
            );
        }
    }

    // --- destination: the admitted binding, and only the admitted binding ---
    let binding = truth.destination_binding;
    if text(binding, "/schema_version") != SCM_DESTINATION_BINDING_SCHEMA_VERSION {
        return refuse_compile(
            "unbound_destination",
            "the resolved record is not an admitted destination binding",
        );
    }
    let binding_ref = text(binding, "/destination_binding_ref").to_owned();
    if binding_ref.is_empty() || binding_ref != submission.destination_binding_ref {
        return refuse_compile(
            "unbound_destination",
            "the resolved binding is not the binding the submission named",
        );
    }
    let declared_binding_hash = text(binding, "/destination_binding_hash").to_owned();
    match scm_destination_binding_hash(binding) {
        Ok(hash) if hash == declared_binding_hash => {}
        _ => {
            return refuse_compile(
                "unbound_destination",
                "the destination binding revision hash does not recompute; the binding is not \
                 admitted material",
            )
        }
    }
    let repository_ref = text(binding, "/repository_ref").to_owned();
    let Some(repository_tail) = repository_ref
        .strip_prefix("repository://")
        .map(str::to_owned)
        .filter(|tail| !tail.is_empty())
    else {
        return refuse_compile(
            "unbound_destination",
            "the binding names no canonical repository identity",
        );
    };
    if !binding_ref.starts_with(&format!("scm-destination-binding://{repository_tail}/")) {
        return refuse_compile(
            "unbound_destination",
            "the destination binding does not cover the repository it names",
        );
    }
    let namespace = text(binding, "/target_ref_namespace").to_owned();
    if !namespace.starts_with(&format!("scm-ref://{repository_tail}/")) || !namespace.ends_with('/')
    {
        return refuse_compile(
            "unbound_destination",
            "the binding's target-ref namespace lies outside the repository it covers",
        );
    }
    let base_ref = text(binding, "/base_ref").to_owned();
    if !base_ref.starts_with(&format!("scm-ref://{repository_tail}/")) {
        return refuse_compile(
            "unbound_destination",
            "the binding's base ref lies outside the repository it covers",
        );
    }
    let leaf = submission.target_ref_name.trim();
    if leaf.is_empty()
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return refuse_compile(
            "unbound_destination",
            "the target-ref leaf must be a single bounded name inside the binding's namespace",
        );
    }
    let target_ref = format!("{namespace}{leaf}");
    let remote_url = text(binding, "/remote_url").to_owned();
    if remote_url.is_empty() {
        return refuse_compile(
            "unbound_destination",
            "the admitted binding carries no remote destination",
        );
    }
    let connector_ref = text(binding, "/connector_ref").to_owned();
    let connector_revision_hash = text(binding, "/connector_revision_hash").to_owned();
    if !connector_ref.starts_with("connector://") || !canonical_hash(&connector_revision_hash) {
        return refuse_compile(
            "unbound_destination",
            "the admitted binding names no connector revision",
        );
    }

    // --- change set: the bound proposal, enumerated, and nothing else ------
    let proposal = truth.proposal;
    if text(proposal, "/schema_version") != SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION {
        return refuse_compile(
            "change_set_unbound_from_proposal",
            "the resolved record is not a publication proposal",
        );
    }
    let proposal_ref = text(proposal, "/proposal_ref").to_owned();
    if proposal_ref.is_empty() || proposal_ref != submission.proposal_ref {
        return refuse_compile(
            "change_set_unbound_from_proposal",
            "the resolved proposal is not the proposal the submission named",
        );
    }
    if text(proposal, "/change_set_kind") != SCM_CHANGE_SET_KIND {
        return refuse_compile(
            "whole_workspace_change_set",
            "the proposal does not declare an enumerated proposal-bound file set",
        );
    }
    let base_revision_id = text(proposal, "/base_revision_id").to_owned();
    if !canonical_revision(&base_revision_id) {
        return refuse_compile(
            "change_set_unbound_from_proposal",
            "the proposal declares no canonical base revision",
        );
    }
    let Some(rows) = proposal.get("files").and_then(Value::as_array) else {
        return refuse_compile(
            "whole_workspace_change_set",
            "a proposal without enumerated file rows is a workspace snapshot, not a change set",
        );
    };
    if rows.is_empty() || rows.len() > 512 {
        return refuse_compile(
            "whole_workspace_change_set",
            "the enumerated change set must carry between one and 512 declared rows",
        );
    }
    let mut files = Vec::with_capacity(rows.len());
    let mut paths: Vec<String> = Vec::with_capacity(rows.len());
    for row in rows {
        let path = text(row, "/path").to_owned();
        let change_kind = text(row, "/change_kind").to_owned();
        let row_proposal = text(row, "/proposal_ref");
        if row_proposal != proposal_ref {
            return refuse_compile(
                "change_set_unbound_from_proposal",
                "a declared file row is not attributed to the one bound proposal",
            );
        }
        if path.is_empty() || path.len() > 256 || path.contains("..") || path.starts_with('/') {
            return refuse_compile(
                "change_set_unbound_from_proposal",
                "a declared file row names no bounded repository-relative path",
            );
        }
        if !matches!(change_kind.as_str(), "added" | "modified" | "removed") {
            return refuse_compile(
                "change_set_unbound_from_proposal",
                "a declared file row names no declared change kind",
            );
        }
        let content_digest = row.get("content_digest").cloned().unwrap_or(Value::Null);
        match (&content_digest, change_kind.as_str()) {
            (Value::Null, "removed") => {}
            (Value::String(digest), "added" | "modified") if canonical_hash(digest) => {}
            _ => {
                return refuse_compile(
                    "change_set_unbound_from_proposal",
                    "a declared file row's post-image digest does not match its change kind",
                )
            }
        }
        paths.push(path.clone());
        files.push(json!({
            "path": path,
            "change_kind": change_kind,
            "content_digest": content_digest,
            "proposal_ref": proposal_ref,
        }));
    }
    let mut sorted = paths.clone();
    sorted.sort();
    let total = sorted.len();
    sorted.dedup();
    if sorted.len() != total {
        return refuse_compile(
            "change_set_unbound_from_proposal",
            "a repository-relative path appears more than once in the declared change set",
        );
    }
    let files = Value::Array(files);
    let proposal_commitment = match scm_publication_proposal_commitment(proposal) {
        Ok(commitment) => commitment,
        Err(error) => return refuse_compile("change_set_unbound_from_proposal", error),
    };
    if proposal_commitment != text(proposal, "/proposal_hash") {
        return refuse_compile(
            "change_set_unbound_from_proposal",
            "the proposal content commitment does not recompute; the set that would ship is not \
             the set the proposal committed to",
        );
    }
    let file_set_digest = match scm_publication_file_set_digest(
        &proposal_ref,
        &proposal_commitment,
        &base_revision_id,
        &files,
    ) {
        Ok(digest) => digest,
        Err(error) => return refuse_compile("change_set_unbound_from_proposal", error),
    };

    // --- compare-and-swap: observed heads only ---------------------------
    if !canonical_revision(truth.observed_base_head) {
        return refuse_compile(
            "stale_expected_head",
            "the base head was not observed as a canonical revision",
        );
    }
    if truth.observed_base_head != base_revision_id {
        return refuse_compile(
            "stale_expected_head",
            format!(
                "the change set was computed onto {base_revision_id} but the base ref now stands \
                 at {}; a detached compare-and-swap is refused, never overwritten",
                truth.observed_base_head
            ),
        );
    }
    let (precondition, expected_target_head) = match &truth.observed_target_ref {
        ObservedTargetRef::Unobserved => {
            return refuse_compile(
                "absent_expected_head",
                "the remote target head could not be observed; an absent expected head is a \
                 refusal, never an unconditional advance",
            )
        }
        ObservedTargetRef::Absent => (ScmTargetRefPrecondition::MustNotExist, None),
        ObservedTargetRef::Present(head) => {
            if !canonical_revision(head) {
                return refuse_compile(
                    "absent_expected_head",
                    "the observed remote head is not a canonical revision",
                );
            }
            (ScmTargetRefPrecondition::ExpectedHead, Some(head.clone()))
        }
    };

    // --- authority -------------------------------------------------------
    if truth.authority_grant_refs.is_empty() || truth.authority_grant_refs.len() > 8 {
        return refuse_compile(
            "effect_contract_invalid",
            "the crossing presented no bounded authority grant set",
        );
    }
    if truth.authority_scope_refs.is_empty() || truth.authority_scope_refs.len() > 8 {
        return refuse_compile(
            "effect_contract_invalid",
            "the crossing consumed no bounded authority scope set",
        );
    }

    // --- idempotency -----------------------------------------------------
    let idempotency_key = match scm_publication_idempotency_key(
        &proposal_ref,
        &proposal_commitment,
        &binding_ref,
        &declared_binding_hash,
        &repository_ref,
        &target_ref,
        precondition.as_str(),
        expected_target_head.as_deref(),
        &file_set_digest,
    ) {
        Ok(key) => key,
        Err(error) => return refuse_compile("idempotency_key_reuse_over_changed_material", error),
    };

    let mut same_key: Vec<&Value> = truth
        .prior_effects
        .iter()
        .filter(|prior| text(prior, "/idempotency/idempotency_key") == idempotency_key)
        .collect();
    same_key.sort_by_key(|prior| text(prior, "/publication_effect_id").to_owned());
    let anchor = same_key
        .iter()
        .find(|prior| text(prior, "/idempotency/submission_disposition") == "first_admission")
        .copied();

    if let Some(asserted) = submission.asserted_submission_disposition.as_deref() {
        if matches!(asserted, "converged_replay" | "refused_conflicting_replay") && anchor.is_none()
        {
            return refuse_compile(
                "replay_without_prior_effect",
                "a replay disposition names a prior effect this estate never admitted",
            );
        }
        if !matches!(
            asserted,
            "first_admission" | "converged_replay" | "refused_conflicting_replay"
        ) {
            return refuse_compile(
                "effect_contract_invalid",
                "the asserted submission disposition is not a declared member",
            );
        }
    }
    // A prior effect that shares the key but not the material means the key
    // was claimed over changed material: refuse rather than converge. A prior
    // that does not verify at all refuses on ITS OWN named dimension — the
    // caller is told exactly which durable record is untrustworthy, never a
    // generic failure.
    for prior in &same_key {
        let prior_verdict = verify_scm_publication_effect(prior);
        if !prior_verdict.admitted {
            let dimension = prior_verdict
                .refusal_dimension
                .unwrap_or("detached_content_commitment");
            return Err(ScmPublicationVerdict::refuse(
                dimension,
                format!(
                    "the prior effect '{}' under this idempotency key does not verify ({})",
                    text(prior, "/publication_effect_id"),
                    prior_verdict.refusal_reason.unwrap_or_default()
                ),
            ));
        }
        let matches_material = text(prior, "/work_subject/proposal_ref") == proposal_ref
            && text(prior, "/work_subject/proposal_hash") == proposal_commitment
            && text(prior, "/destination/destination_binding_ref") == binding_ref
            && text(prior, "/destination/destination_binding_hash") == declared_binding_hash
            && text(prior, "/destination/repository_ref") == repository_ref
            && text(prior, "/destination/target_ref") == target_ref
            && text(prior, "/remote_cas/target_ref_precondition") == precondition.as_str()
            && prior
                .pointer("/remote_cas/expected_target_head")
                .and_then(Value::as_str)
                == expected_target_head.as_deref()
            && text(prior, "/change_set/file_set_digest") == file_set_digest;
        if !matches_material {
            return refuse_compile(
                "idempotency_key_reuse_over_changed_material",
                "an earlier effect already claimed this idempotency key over different material",
            );
        }
    }

    let (submission_disposition, prior_effect, converged_prior_effect) = match anchor {
        None => ("first_admission".to_owned(), None, None),
        Some(prior) => (
            "converged_replay".to_owned(),
            Some((
                text(prior, "/publication_effect_id").to_owned(),
                text(prior, "/publication_effect_hash").to_owned(),
            )),
            Some(prior.clone()),
        ),
    };

    // --- identity: allocated before hashing ------------------------------
    let allocation_material = json!({
        "domain": SCM_PUBLICATION_ALLOCATION_PROFILE,
        "idempotency_key": idempotency_key,
        "submission_disposition": submission_disposition,
        "prior_effect_ref": prior_effect.as_ref().map(|(reference, _)| reference.clone()),
    });
    let allocation_root = match jcs_hash(&allocation_material) {
        Ok(root) => root,
        Err(error) => return refuse_compile("effect_contract_invalid", error),
    };
    let allocation_tail = allocation_root
        .trim_start_matches("sha256:")
        .chars()
        .take(24)
        .collect::<String>();
    let publication_effect_id =
        format!("scm-publication-effect://{repository_tail}/{allocation_tail}");

    let work_subject = json!({
        "proposal_ref": proposal_ref,
        "proposal_hash": proposal_commitment,
        "work_run_ref": submission.work_run_ref,
    });
    let authority = json!({
        "authority_grant_refs": truth.authority_grant_refs,
        "authority_scope_refs": truth.authority_scope_refs,
        "capability_lease_ref": truth.capability_lease_ref,
        "admission_receipt_ref": truth.admission_receipt_ref,
    });
    let destination = json!({
        "resolution": SCM_DESTINATION_RESOLUTION,
        "connector_ref": connector_ref,
        "connector_revision_hash": connector_revision_hash,
        "destination_binding_ref": binding_ref,
        "destination_binding_hash": declared_binding_hash,
        "repository_ref": repository_ref,
        "target_ref": target_ref,
        "base_ref": base_ref,
    });
    let change_set_without_result = json!({
        "change_set_kind": SCM_CHANGE_SET_KIND,
        "proposal_content_commitment": proposal_commitment,
        "base_revision_id": base_revision_id,
        "files": files,
        "file_set_digest": file_set_digest,
    });
    let remote_cas_without_result = json!({
        "mechanism": SCM_CAS_MECHANISM,
        "remote_update_mode": SCM_REMOTE_UPDATE_MODE,
        "stale_head_disposition": SCM_STALE_HEAD_DISPOSITION,
        "target_ref_precondition": precondition.as_str(),
        "expected_target_head": expected_target_head,
        "expected_base_head": base_revision_id,
        "observed_at": truth.observed_at,
        "observation_evidence_ref": truth.observation_evidence_ref,
    });

    Ok(CompiledScmPublication {
        publication_effect_id,
        allocation_tail,
        repository_tail,
        work_subject,
        authority,
        destination,
        change_set_without_result,
        remote_cas_without_result,
        file_set_digest,
        idempotency_key,
        submission_disposition,
        prior_effect,
        converged_prior_effect,
        review_request_requested: submission.review_request_requested,
        remote_url,
        target_ref,
        base_ref,
        base_revision_id,
        expected_target_head,
    })
}

/// Build one immutable publication effect from the compiled plan and the two
/// reported sub-effect outcomes.
///
/// `overall_outcome` is derived here and nowhere else. The built artifact is
/// validated against the registered contract AND re-adjudicated by
/// `verify_scm_publication_effect` before it is returned, so nothing that
/// fails the contract can reach a durable write.
pub fn build_scm_publication_effect(
    compiled: &CompiledScmPublication,
    sub_effects: &ScmPublicationSubEffects,
    committed_at: &str,
) -> Result<ScmPublicationArtifacts, ScmPublicationVerdict> {
    let Some(overall) = derive_overall_outcome(
        sub_effects.publication_outcome,
        sub_effects.review_request_outcome,
    ) else {
        return Err(ScmPublicationVerdict::refuse(
            "review_request_failure_reported_as_success",
            format!(
                "a '{}' publication over a '{}' review request states no expressible overall \
                 outcome; success over a failed sub-effect has no construction path",
                sub_effects.publication_outcome.as_str(),
                sub_effects.review_request_outcome.as_str()
            ),
        ));
    };
    if sub_effects
        .review_request_receipt_ref
        .as_deref()
        .is_some_and(|reference| reference == sub_effects.publication_receipt_ref)
    {
        return Err(ScmPublicationVerdict::refuse(
            "shared_effect_receipt",
            "the publication and the review request must carry distinct receipts",
        ));
    }
    let resulting = match sub_effects.publication_outcome {
        ScmPublicationOutcome::Refused => {
            if sub_effects.resulting_revision_id.is_some() {
                return Err(ScmPublicationVerdict::refuse(
                    "remote_advance_detached_from_change_set",
                    "a refused publication can name no resulting revision",
                ));
            }
            Value::Null
        }
        _ => match sub_effects.resulting_revision_id.as_deref() {
            Some(revision) if canonical_revision(revision) => json!(revision),
            _ => {
                return Err(ScmPublicationVerdict::refuse(
                    "remote_advance_detached_from_change_set",
                    "a landed publication must name the canonical revision it produced",
                ))
            }
        },
    };

    let mut change_set = compiled.change_set_without_result.clone();
    change_set["resulting_revision_id"] = resulting.clone();
    let mut remote_cas = compiled.remote_cas_without_result.clone();
    remote_cas["resulting_target_head"] = resulting;
    remote_cas["proof_ref"] = json!(sub_effects.proof_ref);

    let effects = json!({
        "publication": {
            "effect_kind": "scm_publication",
            "outcome": sub_effects.publication_outcome.as_str(),
            "receipt_ref": sub_effects.publication_receipt_ref,
            "refusal_code": sub_effects.publication_refusal_code,
            "evidence_refs": sub_effects.publication_evidence_refs,
        },
        "review_request": {
            "effect_kind": "scm_review_request",
            "outcome": sub_effects.review_request_outcome.as_str(),
            "receipt_ref": sub_effects.review_request_receipt_ref,
            "refusal_code": sub_effects.review_request_refusal_code,
            "evidence_refs": sub_effects.review_request_evidence_refs,
        },
    });
    let idempotency = json!({
        "idempotency_key": compiled.idempotency_key,
        "submission_disposition": compiled.submission_disposition,
        "prior_effect_ref": compiled
            .prior_effect
            .as_ref()
            .map(|(reference, _)| reference.clone()),
        "prior_effect_hash": compiled
            .prior_effect
            .as_ref()
            .map(|(_, hash)| hash.clone()),
    });

    let mut effect = json!({
        "schema_version": SCM_PUBLICATION_EFFECT_SCHEMA_VERSION,
        "publication_effect_id": compiled.publication_effect_id,
        "publication_effect_hash": Value::Null,
        "work_subject": compiled.work_subject,
        "authority": compiled.authority,
        "destination": compiled.destination,
        "change_set": change_set,
        "remote_cas": remote_cas,
        "idempotency": idempotency,
        "effects": effects,
        "overall_outcome": overall.as_str(),
        "nonclaims": SCM_PUBLICATION_NONCLAIMS,
        "committed_at": committed_at,
    });
    let publication_effect_hash = scm_publication_effect_commitment(&effect)
        .map_err(|error| ScmPublicationVerdict::refuse("detached_content_commitment", error))?;
    effect["publication_effect_hash"] = json!(publication_effect_hash);

    if let Err(error) = validate_architecture_contract(SCM_PUBLICATION_EFFECT_CONTRACT, &effect) {
        return Err(ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            format!("the built effect does not satisfy the registered contract: {error}"),
        ));
    }
    let verdict = verify_scm_publication_effect(&effect);
    if !verdict.admitted {
        return Err(verdict);
    }
    Ok(ScmPublicationArtifacts {
        effect,
        publication_effect_hash,
        overall_outcome: overall,
    })
}

/// Restate one converged replay: the prior effect, re-identified under the new
/// allocation and marked as the replay it is, with the prior's exact remote
/// outcomes and receipts. A replay performs no second remote crossing, so it
/// mints no second receipt.
pub fn build_converged_replay_effect(
    compiled: &CompiledScmPublication,
    committed_at: &str,
) -> Result<ScmPublicationArtifacts, ScmPublicationVerdict> {
    let Some(prior) = compiled.converged_prior_effect.as_ref() else {
        return Err(ScmPublicationVerdict::refuse(
            "replay_without_prior_effect",
            "a converged replay must name the prior effect it converges against",
        ));
    };
    let Some(publication_outcome) =
        ScmPublicationOutcome::parse(text(prior, "/effects/publication/outcome"))
    else {
        return Err(ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the prior effect declares no publication outcome",
        ));
    };
    let Some(review_request_outcome) =
        ScmReviewRequestOutcome::parse(text(prior, "/effects/review_request/outcome"))
    else {
        return Err(ScmPublicationVerdict::refuse(
            "effect_contract_invalid",
            "the prior effect declares no review-request outcome",
        ));
    };
    let sub_effects = ScmPublicationSubEffects {
        publication_outcome,
        publication_receipt_ref: text(prior, "/effects/publication/receipt_ref").to_owned(),
        publication_refusal_code: opt_str(prior, "/effects/publication/refusal_code")
            .map(str::to_owned),
        publication_evidence_refs: string_rows(prior, "/effects/publication/evidence_refs"),
        review_request_outcome,
        review_request_receipt_ref: opt_str(prior, "/effects/review_request/receipt_ref")
            .map(str::to_owned),
        review_request_refusal_code: opt_str(prior, "/effects/review_request/refusal_code")
            .map(str::to_owned),
        review_request_evidence_refs: string_rows(prior, "/effects/review_request/evidence_refs"),
        resulting_revision_id: opt_str(prior, "/change_set/resulting_revision_id")
            .map(str::to_owned),
        proof_ref: text(prior, "/remote_cas/proof_ref").to_owned(),
    };
    let mut replay = compiled.clone();
    // A replay restates the prior observation window, so the effect converges
    // to identical material rather than drifting on a fresh observation stamp.
    replay.remote_cas_without_result["observed_at"] = prior
        .pointer("/remote_cas/observed_at")
        .cloned()
        .unwrap_or(Value::Null);
    replay.remote_cas_without_result["observation_evidence_ref"] = prior
        .pointer("/remote_cas/observation_evidence_ref")
        .cloned()
        .unwrap_or(Value::Null);
    build_scm_publication_effect(&replay, &sub_effects, committed_at)
}

fn string_rows(value: &Value, pointer: &str) -> Vec<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Build one durable sub-effect receipt record. Each sub-effect is receipted
/// separately: the record names exactly one effect kind and one outcome.
pub fn build_scm_publication_receipt(
    effect: &Value,
    effect_kind: &str,
    committed_at: &str,
) -> Result<Value, String> {
    let pointer = match effect_kind {
        "scm_publication" => "/effects/publication",
        "scm_review_request" => "/effects/review_request",
        other => return Err(format!("'{other}' is not a publication sub-effect kind")),
    };
    let sub_effect = effect
        .pointer(pointer)
        .cloned()
        .ok_or_else(|| format!("the effect carries no '{effect_kind}' sub-effect"))?;
    let receipt_ref = sub_effect
        .get("receipt_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("the '{effect_kind}' sub-effect carries no receipt"))?;
    Ok(json!({
        "schema_version": SCM_PUBLICATION_RECEIPT_SCHEMA_VERSION,
        "receipt_ref": receipt_ref,
        "effect_kind": effect_kind,
        "outcome": sub_effect.get("outcome").cloned().unwrap_or(Value::Null),
        "refusal_code": sub_effect.get("refusal_code").cloned().unwrap_or(Value::Null),
        "evidence_refs": sub_effect.get("evidence_refs").cloned().unwrap_or(json!([])),
        "publication_effect_id": effect.get("publication_effect_id").cloned().unwrap_or(Value::Null),
        "publication_effect_hash": effect.get("publication_effect_hash").cloned().unwrap_or(Value::Null),
        "idempotency_key": effect.pointer("/idempotency/idempotency_key").cloned().unwrap_or(Value::Null),
        "repository_ref": effect.pointer("/destination/repository_ref").cloned().unwrap_or(Value::Null),
        "target_ref": effect.pointer("/destination/target_ref").cloned().unwrap_or(Value::Null),
        "authority_grant_refs": effect.pointer("/authority/authority_grant_refs").cloned().unwrap_or(json!([])),
        "capability_lease_ref": effect.pointer("/authority/capability_lease_ref").cloned().unwrap_or(Value::Null),
        "host_mutation": effect_kind == "scm_publication",
        "committed_at": committed_at,
    }))
}

/// Content root of one durable publication-plane record. Every family in this
/// plane is content-addressed by this recipe.
pub fn scm_publication_artifact_root(record: &Value) -> Result<String, String> {
    jcs_hash(&json!({
        "domain": "ioi.hypervisor.scm-publication-artifact-jcs-sha256.v1",
        "artifact": record,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture parses")
    }

    macro_rules! registered_fixture {
        ($name:literal) => {
            fixture(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../docs/architecture/_meta/schemas/fixtures/scm-publication-effect-v1/",
                $name
            )))
        };
    }

    fn positive_published_with_review_request() -> Value {
        registered_fixture!("positive-published-with-review-request.json")
    }

    // ---- the registered positives are admitted ------------------------

    #[test]
    fn registered_positive_fixtures_are_admitted_and_contract_valid() {
        for (name, effect) in [
            (
                "positive-published-with-review-request",
                positive_published_with_review_request(),
            ),
            (
                "positive-review-request-failed",
                registered_fixture!("positive-review-request-failed.json"),
            ),
            (
                "positive-refused-stale-remote-head",
                registered_fixture!("positive-refused-stale-remote-head.json"),
            ),
            (
                "positive-converged-replay",
                registered_fixture!("positive-converged-replay.json"),
            ),
            (
                "positive-new-target-ref",
                registered_fixture!("positive-new-target-ref.json"),
            ),
        ] {
            validate_architecture_contract(SCM_PUBLICATION_EFFECT_CONTRACT, &effect)
                .unwrap_or_else(|error| panic!("{name} must satisfy the contract: {error}"));
            let verdict = verify_scm_publication_effect(&effect);
            assert!(
                verdict.admitted,
                "{name} must be admitted, refused as {:?}: {:?}",
                verdict.refusal_dimension, verdict.refusal_reason
            );
        }
    }

    // ---- one test per registered NEGATIVE fixture ---------------------

    fn assert_refuses(effect: &Value, dimension: &str, label: &str) {
        assert!(
            validate_architecture_contract(SCM_PUBLICATION_EFFECT_CONTRACT, effect).is_err(),
            "{label} must fail the registered contract"
        );
        let verdict = verify_scm_publication_effect(effect);
        assert!(!verdict.admitted, "{label} must be refused");
        assert_eq!(
            verdict.refusal_dimension,
            Some(dimension),
            "{label} must refuse by name; reason was {:?}",
            verdict.refusal_reason
        );
    }

    #[test]
    fn negative_absent_expected_head_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-absent-expected-head.json"),
            "absent_expected_head",
            "negative-absent-expected-head",
        );
    }

    #[test]
    fn negative_stale_expected_head_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-stale-expected-head.json"),
            "stale_expected_head",
            "negative-stale-expected-head",
        );
    }

    #[test]
    fn negative_overwrite_remote_head_requested_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-overwrite-remote-head-requested.json"),
            "remote_overwrite_requested",
            "negative-overwrite-remote-head-requested",
        );
    }

    #[test]
    fn negative_unbound_destination_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-unbound-destination.json"),
            "unbound_destination",
            "negative-unbound-destination",
        );
    }

    #[test]
    fn negative_whole_workspace_change_set_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-whole-workspace-change-set.json"),
            "whole_workspace_change_set",
            "negative-whole-workspace-change-set",
        );
    }

    #[test]
    fn negative_change_set_unbound_from_proposal_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-change-set-unbound-from-proposal.json"),
            "change_set_unbound_from_proposal",
            "negative-change-set-unbound-from-proposal",
        );
    }

    #[test]
    fn negative_review_request_failure_reported_as_success_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-review-request-failure-reported-as-success.json"),
            "review_request_failure_reported_as_success",
            "negative-review-request-failure-reported-as-success",
        );
    }

    #[test]
    fn negative_shared_effect_receipt_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-shared-effect-receipt.json"),
            "shared_effect_receipt",
            "negative-shared-effect-receipt",
        );
    }

    #[test]
    fn negative_replay_without_prior_effect_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-replay-without-prior-effect.json"),
            "replay_without_prior_effect",
            "negative-replay-without-prior-effect",
        );
    }

    #[test]
    fn negative_idempotency_key_mismatch_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-idempotency-key-mismatch.json"),
            "idempotency_key_reuse_over_changed_material",
            "negative-idempotency-key-mismatch",
        );
    }

    #[test]
    fn negative_content_commitment_mismatch_refuses_by_name() {
        assert_refuses(
            &registered_fixture!("negative-content-commitment-mismatch.json"),
            "detached_content_commitment",
            "negative-content-commitment-mismatch",
        );
    }

    #[test]
    fn every_registered_negative_fixture_refuses_on_a_distinct_dimension() {
        let mut dimensions = Vec::new();
        for effect in [
            registered_fixture!("negative-absent-expected-head.json"),
            registered_fixture!("negative-stale-expected-head.json"),
            registered_fixture!("negative-overwrite-remote-head-requested.json"),
            registered_fixture!("negative-unbound-destination.json"),
            registered_fixture!("negative-whole-workspace-change-set.json"),
            registered_fixture!("negative-change-set-unbound-from-proposal.json"),
            registered_fixture!("negative-review-request-failure-reported-as-success.json"),
            registered_fixture!("negative-shared-effect-receipt.json"),
            registered_fixture!("negative-replay-without-prior-effect.json"),
            registered_fixture!("negative-idempotency-key-mismatch.json"),
            registered_fixture!("negative-content-commitment-mismatch.json"),
        ] {
            let verdict = verify_scm_publication_effect(&effect);
            let dimension = verdict.refusal_dimension.expect("named refusal");
            assert!(
                SCM_PUBLICATION_REFUSAL_DIMENSIONS.contains(&dimension),
                "{dimension} must be a declared dimension"
            );
            dimensions.push(dimension);
        }
        let mut unique = dimensions.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            dimensions.len(),
            "each registered negative fixture pins its own refusal dimension"
        );
    }

    #[test]
    fn verifier_is_total_over_arbitrary_values() {
        for value in [
            Value::Null,
            json!(7),
            json!("effect"),
            json!([]),
            json!({}),
            json!({"schema_version": SCM_PUBLICATION_EFFECT_SCHEMA_VERSION}),
        ] {
            let verdict = verify_scm_publication_effect(&value);
            assert!(!verdict.admitted);
            assert!(verdict.refusal_dimension.is_some());
        }
    }

    // ---- compile-path fixtures ----------------------------------------

    fn digest(seed: u8) -> String {
        format!("sha256:{}", format!("{seed:02x}").repeat(32))
    }

    fn revision(seed: u8) -> String {
        format!("scm-revision:{}", format!("{seed:02x}").repeat(20))
    }

    fn binding() -> Value {
        let mut record = json!({
            "schema_version": SCM_DESTINATION_BINDING_SCHEMA_VERSION,
            "destination_binding_ref": "scm-destination-binding://acme/hypervisor/revision/0001",
            "destination_binding_hash": Value::Null,
            "connector_ref": "connector://acme/scm/primary",
            "connector_revision_hash": digest(0x0a),
            "repository_ref": "repository://acme/hypervisor",
            "base_ref": "scm-ref://acme/hypervisor/heads/integration",
            "target_ref_namespace": "scm-ref://acme/hypervisor/heads/",
            "remote_url": "file:///srv/remotes/hypervisor.git",
            "admission_receipt_ref": "receipt://acme/scm-publication/admission/0001",
        });
        record["destination_binding_hash"] =
            json!(scm_destination_binding_hash(&record).expect("binding hash"));
        record
    }

    fn proposal() -> Value {
        let mut record = json!({
            "schema_version": SCM_PUBLICATION_PROPOSAL_SCHEMA_VERSION,
            "proposal_ref": "proposal://acme/hypervisor/change/0001",
            "proposal_hash": Value::Null,
            "change_set_kind": SCM_CHANGE_SET_KIND,
            "base_revision_id": revision(0x11),
            "files": [
                {
                    "path": "crates/node/src/lib.rs",
                    "change_kind": "modified",
                    "content_digest": digest(0x21),
                    "proposal_ref": "proposal://acme/hypervisor/change/0001",
                },
                {
                    "path": "docs/notes.md",
                    "change_kind": "removed",
                    "content_digest": Value::Null,
                    "proposal_ref": "proposal://acme/hypervisor/change/0001",
                },
            ],
        });
        record["proposal_hash"] =
            json!(scm_publication_proposal_commitment(&record).expect("proposal commitment"));
        record
    }

    fn grants() -> Vec<String> {
        vec!["grant://acme/wallet-network/scm-publication/0001".to_owned()]
    }

    fn scopes() -> Vec<String> {
        vec!["scope:scm.publication.advance-target-ref".to_owned()]
    }

    struct Bench {
        binding: Value,
        proposal: Value,
        grants: Vec<String>,
        scopes: Vec<String>,
        priors: Vec<Value>,
    }

    impl Bench {
        fn new() -> Self {
            Self {
                binding: binding(),
                proposal: proposal(),
                grants: grants(),
                scopes: scopes(),
                priors: Vec::new(),
            }
        }

        fn truth(&self, observed: ObservedTargetRef) -> ScmPublicationServerTruth<'_> {
            ScmPublicationServerTruth {
                destination_binding: &self.binding,
                proposal: &self.proposal,
                observed_target_ref: observed,
                observed_base_head: "scm-revision:1111111111111111111111111111111111111111",
                observed_at: "2026-07-29T09:14:00Z",
                observation_evidence_ref: "evidence://acme/hypervisor/scm/head-observation/0001",
                authority_grant_refs: &self.grants,
                authority_scope_refs: &self.scopes,
                capability_lease_ref: "lease://acme/scm-publication/0001",
                admission_receipt_ref: "receipt://acme/scm-publication/admission/0001",
                prior_effects: &self.priors,
            }
        }
    }

    fn submission() -> ScmPublicationSubmission {
        ScmPublicationSubmission {
            proposal_ref: "proposal://acme/hypervisor/change/0001".to_owned(),
            work_run_ref: "work-run://acme/hypervisor/0001".to_owned(),
            destination_binding_ref: "scm-destination-binding://acme/hypervisor/revision/0001"
                .to_owned(),
            target_ref_name: "proposal-0001".to_owned(),
            review_request_requested: true,
            ..ScmPublicationSubmission::default()
        }
    }

    fn landed(compiled: &CompiledScmPublication, opened: bool) -> ScmPublicationSubEffects {
        ScmPublicationSubEffects {
            publication_outcome: ScmPublicationOutcome::Published,
            publication_receipt_ref: compiled
                .publication_receipt_ref(ScmPublicationOutcome::Published),
            publication_refusal_code: None,
            publication_evidence_refs: vec![compiled.publication_evidence_ref()],
            review_request_outcome: if opened {
                ScmReviewRequestOutcome::Opened
            } else {
                ScmReviewRequestOutcome::Failed
            },
            review_request_receipt_ref: Some(compiled.review_request_receipt_ref()),
            review_request_refusal_code: if opened {
                None
            } else {
                Some("review-request-rejected-by-remote".to_owned())
            },
            review_request_evidence_refs: vec![compiled.review_request_evidence_ref()],
            resulting_revision_id: Some(revision(0x33)),
            proof_ref: compiled.compare_and_swap_proof_ref(),
        }
    }

    #[test]
    fn positive_ladder_walks_a_publication_with_both_receipts_through_the_contract() {
        let bench = Bench::new();
        let compiled = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("compile admits the bound publication");
        assert_eq!(compiled.submission_disposition, "first_admission");
        assert_eq!(
            compiled.target_ref,
            "scm-ref://acme/hypervisor/heads/proposal-0001"
        );
        assert_eq!(compiled.remote_url, "file:///srv/remotes/hypervisor.git");

        let artifacts = build_scm_publication_effect(
            &compiled,
            &landed(&compiled, true),
            "2026-07-29T09:14:31Z",
        )
        .expect("the landed publication builds");
        assert_eq!(
            artifacts.overall_outcome,
            ScmOverallOutcome::PublishedWithReviewRequest
        );
        validate_architecture_contract(SCM_PUBLICATION_EFFECT_CONTRACT, &artifacts.effect)
            .expect("built artifact satisfies the registered contract");
        assert!(verify_scm_publication_effect(&artifacts.effect).admitted);

        // BOTH sub-effects are separately receipted.
        let publication_receipt = build_scm_publication_receipt(
            &artifacts.effect,
            "scm_publication",
            "2026-07-29T09:14:31Z",
        )
        .expect("publication receipt");
        let review_receipt = build_scm_publication_receipt(
            &artifacts.effect,
            "scm_review_request",
            "2026-07-29T09:14:31Z",
        )
        .expect("review-request receipt");
        assert_ne!(
            publication_receipt["receipt_ref"], review_receipt["receipt_ref"],
            "one receipt can never stand for both sub-effects"
        );
        assert_eq!(publication_receipt["host_mutation"], json!(true));
        assert_eq!(review_receipt["host_mutation"], json!(false));
    }

    #[test]
    fn new_target_ref_compiles_to_a_must_not_exist_precondition() {
        let bench = Bench::new();
        let compiled =
            compile_scm_publication(&bench.truth(ObservedTargetRef::Absent), &submission())
                .expect("compile admits a new target ref");
        assert_eq!(
            compiled.remote_cas_without_result["target_ref_precondition"],
            json!("must_not_exist")
        );
        assert_eq!(
            compiled.remote_cas_without_result["expected_target_head"],
            Value::Null
        );
    }

    #[test]
    fn unobserved_remote_head_refuses_absent_expected_head() {
        let bench = Bench::new();
        let verdict =
            compile_scm_publication(&bench.truth(ObservedTargetRef::Unobserved), &submission())
                .expect_err("an unobserved head never advances");
        assert_eq!(verdict.refusal_dimension, Some("absent_expected_head"));
    }

    #[test]
    fn change_set_base_detached_from_the_observed_base_refuses_stale_expected_head() {
        let bench = Bench::new();
        let mut truth = bench.truth(ObservedTargetRef::Present(revision(0x22)));
        truth.observed_base_head = "scm-revision:4444444444444444444444444444444444444444";
        let verdict = compile_scm_publication(&truth, &submission())
            .expect_err("a base head that moved is a stale compare-and-swap");
        assert_eq!(verdict.refusal_dimension, Some("stale_expected_head"));
    }

    #[test]
    fn caller_requested_overwrite_refuses_by_name() {
        let bench = Bench::new();
        let truth = bench.truth(ObservedTargetRef::Present(revision(0x22)));
        let mut forced = submission();
        forced.force_requested = true;
        assert_eq!(
            compile_scm_publication(&truth, &forced)
                .expect_err("force has no representation")
                .refusal_dimension,
            Some("remote_overwrite_requested")
        );
        let mut moded = submission();
        moded.requested_remote_update_mode = Some("overwrite_remote_head".to_owned());
        assert_eq!(
            compile_scm_publication(&truth, &moded)
                .expect_err("no other update mode exists")
                .refusal_dimension,
            Some("remote_overwrite_requested")
        );
    }

    #[test]
    fn caller_supplied_destination_refuses_unbound_destination() {
        let bench = Bench::new();
        let truth = bench.truth(ObservedTargetRef::Present(revision(0x22)));
        let mut free_text = submission();
        free_text.caller_supplied_remote = Some("https://evil.example/target.git".to_owned());
        assert_eq!(
            compile_scm_publication(&truth, &free_text)
                .expect_err("free caller text never resolves a destination")
                .refusal_dimension,
            Some("unbound_destination")
        );
        let mut escaping = submission();
        escaping.target_ref_name = "../../elsewhere".to_owned();
        assert_eq!(
            compile_scm_publication(&truth, &escaping)
                .expect_err("the target leaf cannot escape the binding namespace")
                .refusal_dimension,
            Some("unbound_destination")
        );
    }

    #[test]
    fn whole_workspace_change_set_refuses_at_compile() {
        let mut bench = Bench::new();
        let truth_submission = submission();
        let mut workspace = submission();
        workspace.requested_change_set_kind = Some("whole_workspace_snapshot".to_owned());
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &workspace
            )
            .expect_err("a workspace snapshot is not a change set")
            .refusal_dimension,
            Some("whole_workspace_change_set")
        );
        bench.proposal["files"] = json!([]);
        bench.proposal["proposal_hash"] =
            json!(scm_publication_proposal_commitment(&bench.proposal).unwrap());
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &truth_submission
            )
            .expect_err("an unenumerated proposal is a workspace snapshot")
            .refusal_dimension,
            Some("whole_workspace_change_set")
        );
    }

    #[test]
    fn foreign_file_row_refuses_change_set_unbound_from_proposal() {
        let mut bench = Bench::new();
        bench.proposal["files"][1]["proposal_ref"] =
            json!("proposal://acme/hypervisor/change/0999");
        bench.proposal["proposal_hash"] =
            json!(scm_publication_proposal_commitment(&bench.proposal).unwrap());
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &submission()
            )
            .expect_err("a foreign row cannot ride along")
            .refusal_dimension,
            Some("change_set_unbound_from_proposal")
        );
    }

    #[test]
    fn detached_proposal_commitment_refuses_change_set_unbound_from_proposal() {
        let mut bench = Bench::new();
        bench.proposal["proposal_hash"] = json!(digest(0x99));
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &submission()
            )
            .expect_err("a detached proposal commitment refuses")
            .refusal_dimension,
            Some("change_set_unbound_from_proposal")
        );
    }

    #[test]
    fn review_request_failure_cannot_be_built_as_overall_success() {
        let bench = Bench::new();
        let compiled = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("compile admits");
        // The honest pairing builds and states the failure.
        let honest = build_scm_publication_effect(
            &compiled,
            &landed(&compiled, false),
            "2026-07-29T09:14:31Z",
        )
        .expect("a failed review request is its own honest outcome");
        assert_eq!(
            honest.overall_outcome,
            ScmOverallOutcome::ReviewRequestFailed
        );
        assert_eq!(
            honest.effect["overall_outcome"],
            json!("review_request_failed")
        );
        // A refused publication over an opened review request states nothing
        // the contract can express, so no artifact exists at all.
        let mut impossible = landed(&compiled, true);
        impossible.publication_outcome = ScmPublicationOutcome::Refused;
        impossible.publication_refusal_code = Some("expected-target-head-moved".to_owned());
        impossible.resulting_revision_id = None;
        assert_eq!(
            build_scm_publication_effect(&compiled, &impossible, "2026-07-29T09:14:31Z")
                .expect_err("an unexpressible pairing has no artifact")
                .refusal_dimension,
            Some("review_request_failure_reported_as_success")
        );
    }

    #[test]
    fn one_receipt_for_both_sub_effects_refuses_at_build() {
        let bench = Bench::new();
        let compiled = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("compile admits");
        let mut shared = landed(&compiled, true);
        shared.review_request_receipt_ref = Some(shared.publication_receipt_ref.clone());
        assert_eq!(
            build_scm_publication_effect(&compiled, &shared, "2026-07-29T09:14:31Z")
                .expect_err("one receipt cannot stand for both sub-effects")
                .refusal_dimension,
            Some("shared_effect_receipt")
        );
    }

    #[test]
    fn asserted_replay_without_a_prior_effect_refuses_by_name() {
        let bench = Bench::new();
        let mut replay = submission();
        replay.asserted_submission_disposition = Some("converged_replay".to_owned());
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &replay
            )
            .expect_err("a replay names a prior effect this estate never admitted")
            .refusal_dimension,
            Some("replay_without_prior_effect")
        );
    }

    #[test]
    fn replay_of_the_exact_submission_converges_instead_of_duplicating() {
        let mut bench = Bench::new();
        let first = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("first admission compiles");
        let first_artifacts =
            build_scm_publication_effect(&first, &landed(&first, true), "2026-07-29T09:14:31Z")
                .expect("first admission builds");

        bench.priors.push(first_artifacts.effect.clone());
        let replayed = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("an exact resubmission compiles");
        assert_eq!(replayed.submission_disposition, "converged_replay");
        assert_eq!(replayed.idempotency_key, first.idempotency_key);
        assert_eq!(
            replayed.prior_effect,
            Some((
                first.publication_effect_id.clone(),
                first_artifacts.publication_effect_hash.clone()
            ))
        );
        let replay_artifacts = build_converged_replay_effect(&replayed, "2026-07-29T09:20:00Z")
            .expect("replay builds");
        // The replay names the prior, reuses the prior's receipts (no second
        // remote crossing happened), and reports the prior's exact outcome.
        assert_eq!(
            replay_artifacts.effect["effects"]["publication"]["receipt_ref"],
            first_artifacts.effect["effects"]["publication"]["receipt_ref"]
        );
        assert_eq!(
            replay_artifacts.effect["change_set"]["resulting_revision_id"],
            first_artifacts.effect["change_set"]["resulting_revision_id"]
        );
        assert!(verify_scm_publication_effect(&replay_artifacts.effect).admitted);

        // A SECOND replay converges to the byte-identical record.
        bench.priors.push(replay_artifacts.effect.clone());
        let again = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("a second resubmission compiles");
        let again_artifacts =
            build_converged_replay_effect(&again, "2026-07-29T09:20:00Z").expect("replay builds");
        assert_eq!(again_artifacts.effect, replay_artifacts.effect);
    }

    #[test]
    fn idempotency_key_reuse_over_changed_material_refuses_by_name() {
        // A DIFFERENT submission (a different target ref, so different bound
        // material) that claims THIS submission's idempotency key. The key
        // recomputes over the bound material, so the claim cannot stand: the
        // earlier effect is not this one and convergence is refused, never
        // assumed.
        let mut bench = Bench::new();
        let mine = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("this submission compiles");
        let mut other_submission = submission();
        other_submission.target_ref_name = "proposal-0002".to_owned();
        let other = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &other_submission,
        )
        .expect("the other submission compiles");
        assert_ne!(
            mine.idempotency_key, other.idempotency_key,
            "changed material is a different submission"
        );
        let mut prior =
            build_scm_publication_effect(&other, &landed(&other, true), "2026-07-29T09:14:31Z")
                .expect("the other submission builds")
                .effect;
        prior["idempotency"]["idempotency_key"] = json!(mine.idempotency_key);
        prior["publication_effect_hash"] =
            json!(scm_publication_effect_commitment(&prior).unwrap());
        bench.priors.push(prior);
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &submission()
            )
            .expect_err("a key claimed over changed material refuses")
            .refusal_dimension,
            Some("idempotency_key_reuse_over_changed_material")
        );
    }

    #[test]
    fn a_prior_effect_with_a_detached_commitment_refuses_by_name() {
        let mut bench = Bench::new();
        let first = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("first admission compiles");
        let mut prior =
            build_scm_publication_effect(&first, &landed(&first, true), "2026-07-29T09:14:31Z")
                .expect("first admission builds")
                .effect;
        prior["publication_effect_hash"] = json!(digest(0x55));
        bench.priors.push(prior);
        assert_eq!(
            compile_scm_publication(
                &bench.truth(ObservedTargetRef::Present(revision(0x22))),
                &submission()
            )
            .expect_err("a prior whose commitment does not recompute refuses")
            .refusal_dimension,
            Some("detached_content_commitment")
        );
    }

    #[test]
    fn a_refused_publication_names_its_code_and_advances_nothing() {
        let bench = Bench::new();
        let compiled = compile_scm_publication(
            &bench.truth(ObservedTargetRef::Present(revision(0x22))),
            &submission(),
        )
        .expect("compile admits");
        let refused = ScmPublicationSubEffects {
            publication_outcome: ScmPublicationOutcome::Refused,
            publication_receipt_ref: compiled
                .publication_receipt_ref(ScmPublicationOutcome::Refused),
            publication_refusal_code: Some("expected-target-head-moved".to_owned()),
            publication_evidence_refs: vec![compiled.publication_evidence_ref()],
            review_request_outcome: ScmReviewRequestOutcome::NotAttempted,
            review_request_receipt_ref: None,
            review_request_refusal_code: None,
            review_request_evidence_refs: Vec::new(),
            resulting_revision_id: None,
            proof_ref: compiled.compare_and_swap_proof_ref(),
        };
        let artifacts = build_scm_publication_effect(&compiled, &refused, "2026-07-29T09:14:31Z")
            .expect("an honest refusal is a representable effect");
        assert_eq!(artifacts.overall_outcome, ScmOverallOutcome::Refused);
        assert_eq!(
            artifacts.effect["change_set"]["resulting_revision_id"],
            Value::Null
        );
        assert_eq!(
            artifacts.effect["remote_cas"]["resulting_target_head"],
            Value::Null
        );
        assert_eq!(
            artifacts.effect["effects"]["publication"]["refusal_code"],
            json!("expected-target-head-moved")
        );
        validate_architecture_contract(SCM_PUBLICATION_EFFECT_CONTRACT, &artifacts.effect)
            .expect("a refusal is contract-valid");
    }

    #[test]
    fn declared_refusal_dimensions_are_unique_and_named() {
        let mut sorted = SCM_PUBLICATION_REFUSAL_DIMENSIONS.to_vec();
        sorted.sort_unstable();
        let total = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), total);
    }
}
