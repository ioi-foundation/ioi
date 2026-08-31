//! `OntologyOverlay`, `OntologyCrosswalk` and `SemanticMappingDecision` — local divergence, the
//! cross-domain map, and the receipted challengeable application of that map (M05.2).
//!
//! WHAT IS TRUTH HERE, stated once so nothing later can quietly disagree: the Agentgres
//! owner-namespaced operation chain for one FAMILY is the only durable record. This module writes no
//! file of its own, so there is no second store to drift even in principle. Everything served is a
//! PROJECTION rebuilt from that chain on every read, including every content hash, which is
//! re-derived and compared rather than trusted. The read index is a PROCESS-LOCAL cache of one
//! (head, revision count) pair per scoped family; it is consulted only AFTER the answer exists, so it
//! can report agreement and can never be an answer source. A restart discards it whole, and deleting
//! or corrupting it therefore cannot alter truth — there is nothing on disk to delete.
//!
//! THREE FAMILIES, THREE IDENTITIES, THREE LIFECYCLES. Canon maps all three onto two base envelopes,
//! and this module keeps them apart where it matters:
//!
//!   * an OVERLAY is a `DomainOntologyEnvelope` addressed under its BASE family's own path
//!     (`ontology://<ns>/<name>/overlay/<slug>/revision/<n>`). It diverges without forking: it binds
//!     each base revision by ref AND by that owner's committed hash, it may only mint terms in its
//!     own overlay namespace, and its dispositions cannot remove or redefine base meaning.
//!   * a CROSSWALK is an `OntologyMappingEnvelope` under `.../crosswalk/revision/<n>`. It DECLARES
//!     how one exact revision's terms relate to another's, with relation, loss, named ambiguity and
//!     a declared risk posture.
//!   * a DECISION is an `OntologyMappingEnvelope` under `.../decision/revision/<n>`. It APPLIES one
//!     exact crosswalk revision to one concrete target, under named reviewer lineage.
//!
//! Distinct path segments mean distinct family refs, which mean distinct Agentgres streams and
//! distinct request-resource scopes. An overlay can never be addressed as a base version, and an
//! application can never be addressed as the declaration it applied.
//!
//! FIVE PROPERTIES ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//!
//! 1. DECLARING IS NOT APPLYING, AND APPLYING ACROSS A BOUNDARY WAITS ON TERMS (INV-30). A
//!    cross-domain crosswalk may be declared and superseded and challenged; it can never project as
//!    `active`, because activation is application. A cross-domain DECISION is refused by name at
//!    admission: the terms-acceptance owner is `M11.1` and it has no landed resolver in this build,
//!    so a cross-domain application is never admitted on the strength of a caller-supplied
//!    acceptance. The registered shape for that acceptance exists so the resolver can land behind
//!    this seam without a wire change.
//!
//! 2. THE CALLER NEVER AUTHORS EVIDENCE (INV-37). Revision ordinal, version label, predecessor refs
//!    and hashes, every endpoint's committed content hash, `domain_relationship`, the decider, the
//!    decision receipt, transaction time, challenge standing, status and the admission block are all
//!    RESOLVED — from the owner of the thing being bound, or from the admission acknowledgement. A
//!    caller may ASSERT what it believes those to be; a disagreement is a typed refusal by cause,
//!    never an accepted substitution.
//!
//! 3. A CHALLENGE CHANGES STANDING WITHOUT EDITING WHAT IT CHALLENGED. Challenges and resolutions are
//!    their own operations on the SAME stream as the revisions they name. `challenge_state` and
//!    `status` are folded out of that stream and live OUTSIDE the content commitment, so a mapping's
//!    bytes and its committed hash never move when its standing does. That is what makes an
//!    immutable record challengeable rather than mutable.
//!
//! 4. AMBIGUITY IS ADJUDICATED, NEVER GUESSED. Every ambiguous term the applied crosswalk named must
//!    carry an explicit disposition on the decision, and `refused_ambiguous` is a real disposition
//!    that keeps the term out of the application. An undisposed ambiguity refuses before admission.
//!    The same rule holds for every source term the crosswalk left unmapped.
//!
//! 5. MEANING GRANTS NOTHING (NN 9). Every projected record carries its authority nonclaim, a
//!    decision additionally carries `legal_conformity_claim: not_determined`, and nothing in this
//!    module consults, mints, widens or presents a capability, lease, policy decision or effect
//!    admission. Admitting a mapping is not permission to act on what it means.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use agentgres::mux::ExactProjection;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::assurance_transition_routes::resolve_challenge_resolution_receipt;
use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation, WriteCaller,
};
use super::ontology_version_routes::resolve_admitted_revision;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

/// The Agentgres owner namespace overlay streams live in. Overlays are `DomainOntologyEnvelope`
/// records, so they do not share a namespace with the mapping envelopes.
const OVERLAY_NAMESPACE: &str = "hypervisor-ontology-overlays";
/// Both mapping profiles share one owner namespace and are separated by RESOURCE KIND, so a
/// crosswalk stream and a decision stream can never be the same stream.
const MAPPING_NAMESPACE: &str = "hypervisor-ontology-mappings";

const OVERLAY_KIND: &str = "ontology-overlay-family";
const CROSSWALK_KIND: &str = "ontology-crosswalk-family";
const DECISION_KIND: &str = "ontology-mapping-decision-family";

const OVERLAY_CONTRACT: &str = "schema://ioi/foundations/ontology-overlay/v1";
const CROSSWALK_CONTRACT: &str = "schema://ioi/foundations/ontology-crosswalk/v1";
const DECISION_CONTRACT: &str = "schema://ioi/foundations/semantic-mapping-decision/v1";

const OVERLAY_SCHEMA: &str = "ioi.ontology-overlay.v1";
const CROSSWALK_SCHEMA: &str = "ioi.ontology-crosswalk.v1";
const DECISION_SCHEMA: &str = "ioi.semantic-mapping-decision.v1";

const OVERLAY_ADMIT_OP: &str = "ontology_overlay.revision.admit";
const CROSSWALK_ADMIT_OP: &str = "ontology_crosswalk.revision.admit";
const DECISION_ADMIT_OP: &str = "semantic_mapping_decision.revision.admit";
const CHALLENGE_OPEN_OP: &str = "ontology_mapping.challenge.admit";
const CHALLENGE_RESOLVE_OP: &str = "ontology_mapping.challenge.resolve";

const OVERLAY_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.ontology-overlay-admission.v1";
const CROSSWALK_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.ontology-crosswalk-admission.v1";
const DECISION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.semantic-mapping-decision-admission.v1";
const CHALLENGE_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.ontology-mapping-challenge.v1";

const OVERLAY_COMMITMENT: &str = "ioi.ontology-overlay-content-commitment-jcs-sha256.v1";
const CROSSWALK_COMMITMENT: &str = "ioi.ontology-crosswalk-content-commitment-jcs-sha256.v1";
const DECISION_COMMITMENT: &str = "ioi.semantic-mapping-decision-content-commitment-jcs-sha256.v1";

const OVERLAY_NONCLAIM: &str = "ontology_overlay_grants_no_authority";
const CROSSWALK_NONCLAIM: &str = "ontology_crosswalk_grants_no_authority";
const DECISION_NONCLAIM: &str = "semantic_mapping_decision_grants_no_authority";

/// The exact registered challenge contract this module admits. v1 cannot address a semantic-plane
/// subject at all — its `challenged_ref` pattern predates the widening — so a v1 envelope is refused
/// by name rather than downgraded into.
const CHALLENGE_CONTRACT: &str = "schema://ioi/foundations/objects/verifier-challenge-envelope/v2";
/// The exact registered contract a resolution's receipt must come from. Naming it in the record is
/// what keeps "resolved" from meaning "somebody said so".
const RESOLUTION_CONTRACT: &str = "schema://ioi/foundations/assurance-transition-receipt/v2";

/// The owner seam every endpoint revision is re-resolved through. There is one reader per family and
/// it belongs to that family's owner; a second reader would be a second interpretation of its truth.
const BASE_RESOLVER: &str = "ontology_version_routes::resolve_admitted_revision";
const OVERLAY_RESOLVER: &str = "semantic_mapping_routes::resolve_admitted_overlay";
const CROSSWALK_RESOLVER: &str = "semantic_mapping_routes::resolve_admitted_crosswalk";

/// The unit that owns the terms-acceptance resolver a cross-domain application waits on.
const TERMS_ACCEPTANCE_OWNER: &str = "M11.1";

const MAX_ORDINAL: u64 = 999_999_999;
const MAX_TERMS: usize = 256;
const MAX_MAPPINGS: usize = 512;
const MAX_BASES: usize = 32;
const MAX_REVIEWERS: usize = 32;
const MAX_TARGETS: usize = 64;
const MAX_REFS: usize = 64;

const TERM_RELATIONS: &[&str] = &["exact", "broader", "narrower", "related", "unmapped"];
const LOSS_CLASSES: &[&str] = &[
    "none",
    "lossy_precision",
    "lossy_scope",
    "lossy_units",
    "unmapped",
];
const RISK_CLASSES: &[&str] = &["low", "moderate", "high", "unacceptable"];
const COMPATIBILITY_RESULTS: &[&str] = &[
    "exact",
    "compatible",
    "lossy",
    "requires_adapter",
    "incompatible",
];
const OVERLAY_DISPOSITIONS: &[&str] = &["relabelled", "narrowed", "annotated", "hidden"];
const TERM_KINDS: &[&str] = &["entity", "relationship", "event", "action"];
const REVIEW_ROLES: &[&str] = &[
    "source_domain_reviewer",
    "target_domain_reviewer",
    "mapping_owner",
    "independent_verifier",
];
const REVIEW_DECISIONS: &[&str] = &[
    "approved",
    "approved_with_conditions",
    "rejected",
    "abstained",
];
const AMBIGUITY_DISPOSITIONS: &[&str] = &[
    "adjudicated_exact",
    "adjudicated_broader",
    "adjudicated_narrower",
    "refused_ambiguous",
];
const UNMAPPED_DISPOSITIONS: &[&str] = &[
    "carried_as_unmapped",
    "excluded_from_application",
    "escalated",
];
const CHALLENGE_KINDS: &[&str] = &["mapping", "evidence", "rule", "verifier", "result"];
const RESOLUTIONS: &[&str] = &["upheld", "rejected"];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn refuse(code: &str, message: impl Into<String>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

// ------------------------------------------------------------------ coordinates and canonical hashes

fn canonical_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn version_label(ordinal: u64) -> String {
    format!("v{ordinal}")
}

/// A ref may carry no character that could smuggle a separator or a second identity past a prefix
/// comparison. Applied before any parsing so an identity that has to be repaired is refused instead.
fn transportable_ref(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || !byte.is_ascii()
                || matches!(byte, b'?' | b'#' | b'\\' | b'%')
        })
}

fn digest_over(record: &Value, domain: &str, fields: &[&str]) -> Result<String, String> {
    let mut material = Map::new();
    material.insert("domain".into(), json!(domain));
    for field in fields {
        material.insert(
            (*field).to_string(),
            record.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    serde_jcs::to_vec(&Value::Object(material))
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| format!("commitment could not be canonicalised: {error}"))
}

/// The exact material the registered invariant
/// `ontology_overlay.content_hash.commits_bases_divergence_and_valid_time` commits.
///
/// `transaction_time`, `admission`, `admission_domain_ref`, `status` and `schema_version` are
/// DELIBERATELY absent: when a divergence was held true is content, when it was recorded is
/// admission. Keeping the two apart is what lets a predecessor's transaction interval close without
/// its content hash moving.
const OVERLAY_MATERIAL: &[&str] = &[
    "overlay_id",
    "overlay_family_ref",
    "ontology_family_ref",
    "ontology_record_profile",
    "namespace",
    "name",
    "overlay_name",
    "owner_id",
    "governing_scope_ref",
    "version",
    "revision_ordinal",
    "predecessor_version_ref",
    "predecessor_content_hash",
    "base_ontology_version_refs",
    "base_ontology_bindings",
    "base_resolved_by",
    "added_terms",
    "overlaid_terms",
    "invariant_refs",
    "compatibility_profile_ref",
    "deprecation_policy_ref",
    "policy_hash",
    "valid_time",
    "migration",
    "fork_nonclaim",
    "authority_nonclaim",
    "global_canonicality_nonclaim",
];

/// The exact material
/// `ontology_crosswalk.content_hash.commits_endpoints_mappings_risk_and_valid_time` commits.
/// `challenge_state` is absent for the same reason `transaction_time` is: a challenge moves standing,
/// not bytes.
const CROSSWALK_MATERIAL: &[&str] = &[
    "ontology_mapping_id",
    "mapping_family_ref",
    "mapping_record_profile",
    "namespace",
    "name",
    "owner_id",
    "governing_scope_ref",
    "version",
    "revision_ordinal",
    "predecessor_version_ref",
    "predecessor_content_hash",
    "source_ontology_ref",
    "target_ontology_ref",
    "source_and_target_version_refs",
    "source_binding",
    "target_binding",
    "endpoint_resolved_by",
    "domain_relationship",
    "term_mappings",
    "ambiguous_term_refs",
    "compatibility_result",
    "mapping_risk",
    "verifier_obligation_refs",
    "mapped_object_relationship_event_and_action_refs",
    "mapping_profile_ref",
    "deprecation_and_migration_policy_ref",
    "policy_hash",
    "valid_time",
    "migration",
    "cross_domain_application_nonclaim",
    "correctness_nonclaim",
    "authority_nonclaim",
    "global_canonicality_nonclaim",
];

/// The exact material
/// `semantic_mapping_decision.content_hash.commits_crosswalk_reviewers_dispositions_and_valid_time`
/// commits. The decision receipt is absent because it is the ADMITTING batch's receipt: it cannot be
/// inside the bytes it attests.
const DECISION_MATERIAL: &[&str] = &[
    "ontology_mapping_id",
    "mapping_family_ref",
    "mapping_record_profile",
    "namespace",
    "name",
    "owner_id",
    "governing_scope_ref",
    "version",
    "revision_ordinal",
    "predecessor_version_ref",
    "predecessor_content_hash",
    "applied_crosswalk_ref",
    "applied_crosswalk_binding",
    "crosswalk_resolved_by",
    "source_ontology_ref",
    "target_ontology_ref",
    "source_and_target_version_refs",
    "source_binding",
    "target_binding",
    "domain_relationship",
    "application_target_refs",
    "decided_by_ref",
    "decision_timestamp",
    "reviewer_lineage",
    "mapping_risk_acceptance",
    "ambiguity_dispositions",
    "unmapped_term_dispositions",
    "terms_acceptance",
    "compatibility_result",
    "policy_bound_view_refs",
    "validation_and_challenge_refs",
    "policy_hash",
    "valid_time",
    "migration",
    "correctness_nonclaim",
    "authority_nonclaim",
    "legal_conformity_claim",
    "global_canonicality_nonclaim",
];

// ------------------------------------------------------------------------------- family descriptors

/// The three record families this module owns, each with its own stream, contract and commitment.
///
/// Kept as one descriptor rather than three copied modules because the CHAIN mechanics — exact-head
/// admission, replay, projection, content-hash re-derivation, cache reporting — are genuinely the
/// same mechanics. What differs is the record shape, and that lives in each family's own builder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Family {
    Overlay,
    Crosswalk,
    Decision,
}

impl Family {
    fn owner_namespace(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_NAMESPACE,
            Self::Crosswalk | Self::Decision => MAPPING_NAMESPACE,
        }
    }

    fn resource_kind(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_KIND,
            Self::Crosswalk => CROSSWALK_KIND,
            Self::Decision => DECISION_KIND,
        }
    }

    fn contract_id(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_CONTRACT,
            Self::Crosswalk => CROSSWALK_CONTRACT,
            Self::Decision => DECISION_CONTRACT,
        }
    }

    fn schema_version(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_SCHEMA,
            Self::Crosswalk => CROSSWALK_SCHEMA,
            Self::Decision => DECISION_SCHEMA,
        }
    }

    fn admit_op(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_ADMIT_OP,
            Self::Crosswalk => CROSSWALK_ADMIT_OP,
            Self::Decision => DECISION_ADMIT_OP,
        }
    }

    fn payload_schema(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_PAYLOAD_SCHEMA,
            Self::Crosswalk => CROSSWALK_PAYLOAD_SCHEMA,
            Self::Decision => DECISION_PAYLOAD_SCHEMA,
        }
    }

    fn commitment_domain(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_COMMITMENT,
            Self::Crosswalk => CROSSWALK_COMMITMENT,
            Self::Decision => DECISION_COMMITMENT,
        }
    }

    fn material(self) -> &'static [&'static str] {
        match self {
            Self::Overlay => OVERLAY_MATERIAL,
            Self::Crosswalk => CROSSWALK_MATERIAL,
            Self::Decision => DECISION_MATERIAL,
        }
    }

    /// The record's own identity field. Overlays are ontology envelopes and carry `overlay_id`;
    /// both mapping profiles carry `ontology_mapping_id`.
    fn id_field(self) -> &'static str {
        match self {
            Self::Overlay => "overlay_id",
            Self::Crosswalk | Self::Decision => "ontology_mapping_id",
        }
    }

    fn authority_nonclaim(self) -> &'static str {
        match self {
            Self::Overlay => OVERLAY_NONCLAIM,
            Self::Crosswalk => CROSSWALK_NONCLAIM,
            Self::Decision => DECISION_NONCLAIM,
        }
    }

    /// Only the two mapping profiles carry a challenge lifecycle. Canon gives challengeability to the
    /// `OntologyMappingEnvelope`, not to the ontology envelope an overlay is a profile of, so an
    /// overlay challenge is refused as the category error it is rather than silently accepted.
    fn is_challengeable(self) -> bool {
        matches!(self, Self::Crosswalk | Self::Decision)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overlay => "ontology_overlay",
            Self::Crosswalk => "ontology_crosswalk",
            Self::Decision => "semantic_mapping_decision",
        }
    }
}

fn content_hash(family: Family, record: &Value) -> Result<String, String> {
    digest_over(record, family.commitment_domain(), family.material())
}

// -------------------------------------------------------------------------------- identity parsing

/// The coordinates one overlay revision identity names.
struct OverlayCoordinates {
    namespace: String,
    name: String,
    overlay_name: String,
    ordinal: u64,
}

/// The coordinates one mapping revision identity names, for either mapping profile.
struct MappingCoordinates {
    namespace: String,
    name: String,
    ordinal: u64,
}

fn overlay_family_ref(namespace: &str, name: &str, overlay: &str) -> String {
    format!("ontology://{namespace}/{name}/overlay/{overlay}")
}

fn base_family_ref(namespace: &str, name: &str) -> String {
    format!("ontology://{namespace}/{name}")
}

fn mapping_family_ref(family: Family, namespace: &str, name: &str) -> String {
    let profile = match family {
        Family::Crosswalk => "crosswalk",
        Family::Decision => "decision",
        Family::Overlay => "overlay",
    };
    format!("ontology-mapping://{namespace}/{name}/{profile}")
}

/// Parse a positive, unpadded ordinal, or refuse it.
///
/// One revision has exactly one spelling. A signed, zero, zero-padded or oversized run of digits is
/// rejected rather than repaired, because two spellings that resolve to one revision would let a
/// binding claim it bound something other than what it bound.
fn parse_ordinal(segment: &str) -> Option<u64> {
    if segment.is_empty()
        || segment.len() > 9
        || segment.starts_with('0')
        || !segment.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    segment.parse().ok().filter(|value| *value > 0)
}

/// STRICT AND TOTAL. `ontology://<ns>/<name>/overlay/<slug>/revision/<n>` and nothing else — a base
/// revision identity has four segments and is refused here, which is what keeps an overlay from ever
/// being addressed as the version it overlays.
fn parse_overlay_identity(overlay_id: &str) -> Option<OverlayCoordinates> {
    if !transportable_ref(overlay_id, 400) {
        return None;
    }
    let mut segments = overlay_id.strip_prefix("ontology://")?.split('/');
    let namespace = segments.next()?;
    let name = segments.next()?;
    let overlay_marker = segments.next()?;
    let overlay_name = segments.next()?;
    let revision_marker = segments.next()?;
    let ordinal = segments.next()?;
    if segments.next().is_some()
        || overlay_marker != "overlay"
        || revision_marker != "revision"
        || !canonical_token(namespace, 63)
        || !canonical_token(name, 63)
        || !canonical_token(overlay_name, 63)
    {
        return None;
    }
    Some(OverlayCoordinates {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        overlay_name: overlay_name.to_owned(),
        ordinal: parse_ordinal(ordinal).filter(|value| *value <= MAX_ORDINAL)?,
    })
}

/// `ontology-mapping://<ns>/<name>/<crosswalk|decision>/revision/<n>`, for the exact profile asked
/// for. Asking for a crosswalk and being handed a decision ref is a refusal, not a coercion.
fn parse_mapping_identity(family: Family, mapping_id: &str) -> Option<MappingCoordinates> {
    if !transportable_ref(mapping_id, 400) {
        return None;
    }
    let expected_profile = match family {
        Family::Crosswalk => "crosswalk",
        Family::Decision => "decision",
        Family::Overlay => return None,
    };
    let mut segments = mapping_id.strip_prefix("ontology-mapping://")?.split('/');
    let namespace = segments.next()?;
    let name = segments.next()?;
    let profile = segments.next()?;
    let revision_marker = segments.next()?;
    let ordinal = segments.next()?;
    if segments.next().is_some()
        || profile != expected_profile
        || revision_marker != "revision"
        || !canonical_token(namespace, 63)
        || !canonical_token(name, 63)
    {
        return None;
    }
    Some(MappingCoordinates {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        ordinal: parse_ordinal(ordinal).filter(|value| *value <= MAX_ORDINAL)?,
    })
}

/// An ENDPOINT is either a base revision or an overlay revision. Which one it is decides which
/// owner seam resolves it, so the classification happens once, here, and the longer form is tested
/// first: `ontology://ns/name/overlay/slug/revision/1` also parses as nothing else, but a naive
/// order would try the base parser and report a malformed base identity instead of an overlay.
enum Endpoint {
    Base(String),
    Overlay(OverlayCoordinates),
}

fn classify_endpoint(reference: &str) -> Option<Endpoint> {
    if let Some(coordinates) = parse_overlay_identity(reference) {
        return Some(Endpoint::Overlay(coordinates));
    }
    if !transportable_ref(reference, 400) {
        return None;
    }
    let mut segments = reference.strip_prefix("ontology://")?.split('/');
    let namespace = segments.next()?;
    let name = segments.next()?;
    let marker = segments.next()?;
    let ordinal = segments.next()?;
    if segments.next().is_some()
        || marker != "revision"
        || !canonical_token(namespace, 63)
        || !canonical_token(name, 63)
        || parse_ordinal(ordinal).is_none()
    {
        return None;
    }
    Some(Endpoint::Base(reference.to_owned()))
}

// -------------------------------------------------------------------------- durable chain projection

/// One admitted revision, exactly as the chain holds it.
struct AdmittedRevision {
    record: Value,
    head: String,
    seq: u64,
    admission_batch_seq: u64,
    admission_root: String,
    expected_predecessor_head: Value,
    recorded_at_ms: u64,
}

/// One admitted challenge event against an exact revision of this family.
struct ChallengeEvent {
    challenge_id: String,
    subject_ref: String,
    resolution: Option<String>,
    receipt_ref: Option<String>,
}

/// Split one family's stream into its revisions and its challenge events.
///
/// A frame this build does not implement is reported as UNREADABLE rather than projected as though
/// it were the current version: a downgrade is no more acceptable on the way out of the chain than on
/// the way in.
fn project_stream(
    family: Family,
    history: &[ExactProjection],
) -> Result<(Vec<AdmittedRevision>, Vec<ChallengeEvent>), String> {
    let mut revisions = Vec::new();
    let mut challenges = Vec::new();
    for entry in history {
        let payload = &entry.operation.payload;
        let op = entry.operation.op_kind.as_str();
        if op == family.admit_op() {
            if payload.get("schema_version").and_then(Value::as_str)
                != Some(family.payload_schema())
            {
                return Err(format!(
                    "{} admission carries an unknown payload schema",
                    family.label()
                ));
            }
            let record = payload
                .get("record")
                .cloned()
                .ok_or_else(|| format!("{} admission carries no record", family.label()))?;
            if record.get("schema_version").and_then(Value::as_str) != Some(family.schema_version())
            {
                return Err(format!(
                    "{} chain holds a revision this build does not implement (expected {})",
                    family.label(),
                    family.schema_version()
                ));
            }
            // The served content hash is RE-DERIVED, never trusted: a tampered log frame or a
            // rebuilt index cannot make this module serve bytes that do not hash to what they claim.
            let derived = content_hash(family, &record)?;
            if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
                return Err(format!(
                    "{} admitted content does not match its committed hash",
                    family.label()
                ));
            }
            revisions.push(AdmittedRevision {
                record,
                head: entry.head.clone(),
                seq: entry.seq,
                admission_batch_seq: entry.admission_batch_seq,
                admission_root: entry.admission_root.clone(),
                expected_predecessor_head: entry
                    .operation
                    .expected_head
                    .clone()
                    .map_or(Value::Null, Value::String),
                recorded_at_ms: entry.operation.recorded_at_ms,
            });
        } else if op == CHALLENGE_OPEN_OP || op == CHALLENGE_RESOLVE_OP {
            if payload.get("schema_version").and_then(Value::as_str)
                != Some(CHALLENGE_PAYLOAD_SCHEMA)
            {
                return Err(format!(
                    "{} challenge carries an unknown payload schema",
                    family.label()
                ));
            }
            let field = |key: &str| {
                payload
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            challenges.push(ChallengeEvent {
                challenge_id: field("verifier_challenge_id"),
                subject_ref: field("challenged_ref"),
                resolution: (op == CHALLENGE_RESOLVE_OP).then(|| field("resolution")),
                receipt_ref: (op == CHALLENGE_RESOLVE_OP).then(|| field("resolution_receipt_ref")),
            });
        } else {
            return Err(format!(
                "{} stream carries an unknown operation '{op}'",
                family.label()
            ));
        }
    }
    Ok((revisions, challenges))
}

/// The standing one revision holds, folded out of the challenge events that name it.
///
/// OPEN BEATS RESOLVED, AND UPHELD BEATS REJECTED. A revision with any unresolved challenge is
/// `challenged` however many earlier challenges were dismissed; a revision whose challenges are all
/// resolved is `upheld` if ANY was upheld, because one sustained finding is not cancelled by a
/// neighbour that failed. Nothing is dropped: both the resolved set and its receipts stay addressable
/// on a rejected standing too, which is what "negative results survive" means for this family.
fn fold_challenge_state(subject_ref: &str, events: &[ChallengeEvent]) -> Value {
    let mut open: Vec<String> = Vec::new();
    let mut resolved: Vec<String> = Vec::new();
    let mut receipts: Vec<String> = Vec::new();
    let mut upheld = false;
    for event in events
        .iter()
        .filter(|event| event.subject_ref == subject_ref)
    {
        match event.resolution.as_deref() {
            None => {
                if !open.contains(&event.challenge_id) {
                    open.push(event.challenge_id.clone());
                }
            }
            Some(outcome) => {
                open.retain(|candidate| candidate != &event.challenge_id);
                if !resolved.contains(&event.challenge_id) {
                    resolved.push(event.challenge_id.clone());
                }
                if let Some(receipt) = event.receipt_ref.as_ref() {
                    if !receipt.is_empty() && !receipts.contains(receipt) {
                        receipts.push(receipt.clone());
                    }
                }
                upheld = upheld || outcome == "upheld";
            }
        }
    }
    let standing = if !open.is_empty() {
        "challenged"
    } else if resolved.is_empty() {
        "unchallenged"
    } else if upheld {
        "upheld"
    } else {
        "rejected"
    };
    json!({
        "standing": standing,
        "open_challenge_refs": open,
        "resolved_challenge_refs": resolved,
        "resolution_receipt_refs": receipts,
        "challenge_contract_ref": CHALLENGE_CONTRACT,
    })
}

/// The projected status of one revision, given its standing and whether a successor closed it.
///
/// STANDING OUTRANKS SUPERSESSION. An old revision under an open challenge still reads `challenged`,
/// because the question "is this mapping disputed" outlives "is this mapping current". A cross-domain
/// declaration, an incompatible result and an unacceptable risk all top out at `validated`: each is
/// recordable so the fact itself stays addressable, and none of them is usable.
fn projected_status(record: &Value, standing: &str, superseded: bool) -> &'static str {
    match standing {
        "upheld" => return "revoked",
        "challenged" => return "challenged",
        _ => {}
    }
    if superseded {
        return "deprecated";
    }
    let cross_domain =
        record.get("domain_relationship").and_then(Value::as_str) == Some("cross_domain");
    let incompatible =
        record.get("compatibility_result").and_then(Value::as_str) == Some("incompatible");
    let unacceptable = record
        .pointer("/mapping_risk/risk_class")
        .and_then(Value::as_str)
        == Some("unacceptable")
        || record
            .pointer("/mapping_risk_acceptance/accepted_risk_class")
            .and_then(Value::as_str)
            == Some("unacceptable")
        || record
            .pointer("/applied_crosswalk_binding/risk_class")
            .and_then(Value::as_str)
            == Some("unacceptable");
    let rejected_review = record
        .get("reviewer_lineage")
        .and_then(Value::as_array)
        .is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("review_decision").and_then(Value::as_str) == Some("rejected"))
        });
    let applied_under_challenge = matches!(
        record
            .pointer("/applied_crosswalk_binding/challenge_standing")
            .and_then(Value::as_str),
        Some("challenged") | Some("upheld")
    );
    if cross_domain || incompatible || unacceptable || rejected_review || applied_under_challenge {
        "validated"
    } else {
        "active"
    }
}

/// Assemble one family's registered contract document for one admitted revision.
fn contract_document(
    family: Family,
    revision: &AdmittedRevision,
    family_ref: &str,
    challenges: &[ChallengeEvent],
    superseded_at: Option<&str>,
) -> Result<Value, String> {
    let mut document = revision.record.clone();
    let identity = document
        .get(family.id_field())
        .and_then(Value::as_str)
        .ok_or_else(|| format!("admitted {} carries no identity", family.label()))?
        .to_string();
    let committed = document
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tail = stream_tail(family.resource_kind(), family_ref);
    document["admission_domain_ref"] = json!(format!(
        "agentgres://domain/{}",
        agentgres::refs::event_stream_domain(family.owner_namespace(), &tail)
    ));
    document["transaction_time"] = json!({
        "recorded_at": admitted_stamp(revision.recorded_at_ms),
        "superseded_at": superseded_at.map_or(Value::Null, |value| json!(value)),
    });
    let receipt_ref = agentgres::refs::event_stream_receipt_ref(
        family.owner_namespace(),
        &tail,
        revision.admission_batch_seq,
        &revision.admission_root,
    );
    let mut admission = json!({
        "content_hash": committed,
        "owner_namespace": family.owner_namespace(),
        "stream_tail": tail,
        "agentgres_operation_ref": agentgres::refs::event_stream_operation_ref(
            family.owner_namespace(), &tail, revision.seq, &revision.head,
        ),
        "agentgres_receipt_ref": receipt_ref,
        "admission_seq": revision.seq,
        "admission_head": revision.head,
        "admission_root": revision.admission_root,
        "expected_predecessor_head": revision.expected_predecessor_head,
    });
    admission[family.id_field()] = json!(identity);
    document["admission"] = admission;
    if family.is_challengeable() {
        let state = fold_challenge_state(&identity, challenges);
        let standing = state
            .get("standing")
            .and_then(Value::as_str)
            .unwrap_or("unchallenged")
            .to_owned();
        document["challenge_state"] = state;
        document["status"] = json!(projected_status(
            &document,
            &standing,
            superseded_at.is_some()
        ));
    } else {
        document["status"] = json!(if superseded_at.is_some() {
            "deprecated"
        } else {
            "active"
        });
    }
    if family == Family::Decision {
        // The canonical decision receipt IS the admitting batch's receipt. Minting a second receipt
        // beside it would be a second attestation of one admission, which is the shape the registered
        // invariant refuses.
        document["mapping_decision_receipt_ref"] =
            document["admission"]["agentgres_receipt_ref"].clone();
    }
    validate_architecture_contract(family.contract_id(), &document).map_err(|reason| {
        format!(
            "projected {} is not registered-valid: {reason}",
            family.label()
        )
    })?;
    Ok(document)
}

/// The whole lineage of one family, rebuilt from the chain and contract-validated.
fn project_lineage(
    family: Family,
    history: &[ExactProjection],
    family_ref: &str,
) -> Result<Vec<Value>, String> {
    let (revisions, challenges) = project_stream(family, history)?;
    let mut documents = Vec::with_capacity(revisions.len());
    for (index, revision) in revisions.iter().enumerate() {
        let superseded_at = revisions
            .get(index + 1)
            .map(|next| admitted_stamp(next.recorded_at_ms));
        documents.push(contract_document(
            family,
            revision,
            family_ref,
            &challenges,
            superseded_at.as_deref(),
        )?);
    }
    Ok(documents)
}

fn ordinal_of(document: &Value) -> u64 {
    document
        .get("revision_ordinal")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

// -------------------------------------------------- rebuildable, process-local, and never an answer

/// One (admitted head, revision count) pair per scoped family. Process-local and never durable.
static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

/// Keyed by SCOPE as well as family, so one tenant's cache row can never answer for another's.
fn projection_cache_key(scope: &RequestResourceScope, family_ref: &str) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        scope.principal_ref, scope.tenant_ref, family_ref
    )
}

/// Record what the cache held for this family BEFORE the freshly projected lineage replaced it.
///
/// The lineage is already computed when this is called, so the cache cannot contribute to the answer
/// — it is consulted only to report agreement. Reporting it lets a verifier assert rebuild by
/// POSITIVE detection: an unchanged answer is also consistent with a cache that was never dropped,
/// which would prove nothing.
fn projection_cache_state(cache_key: &str, lineage: &[Value]) -> &'static str {
    let head = lineage
        .last()
        .and_then(|document| document.pointer("/admission/admission_head"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let observed = (head, lineage.len());
    let Ok(mut cache) = PROJECTION_CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
    else {
        return "unavailable_rebuilt_from_agentgres";
    };
    let state = match cache.get(cache_key) {
        None => "rebuilt_from_agentgres",
        Some(held) if *held == observed => "agreed_with_agentgres",
        Some(_) => "stale_rebuilt_from_agentgres",
    };
    cache.insert(cache_key.to_string(), observed);
    state
}

// ---------------------------------------------------------------------------------- read path helpers

/// The projected revisions AND the true head of the stream they came from.
///
/// THE TWO ARE NOT THE SAME THING, and conflating them is a real defect this gate caught. A challenge
/// is its own operation on this family's stream, so after one is admitted the stream head is the
/// CHALLENGE's head while the last REVISION still carries the older one. Exact-head admission is
/// about the chain, so every compare-and-swap below names the stream head; deriving it from the last
/// revision would make the second challenge — and every successor after any challenge — conflict
/// forever.
fn read_lineage_and_head(
    family: Family,
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    family_ref: &str,
) -> Result<(Vec<Value>, Option<String>), Reply> {
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        family.resource_kind(),
        family_ref,
        family.owner_namespace(),
        &stream_tail(family.resource_kind(), family_ref),
    )
    .map_err(mutation_refusal_reply)?;
    let stream_head = history.last().map(|entry| entry.head.clone());
    let lineage = project_lineage(family, &history, family_ref).map_err(|reason| {
        bad(
            StatusCode::BAD_GATEWAY,
            &format!("{}_projection_failed", family.label()),
            reason,
        )
    })?;
    Ok((lineage, stream_head))
}

fn read_lineage(
    family: Family,
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    family_ref: &str,
) -> Result<Vec<Value>, Reply> {
    read_lineage_and_head(family, data_dir, identity, scope, family_ref).map(|(lineage, _)| lineage)
}

fn authorized_lineage(
    family: Family,
    data_dir: &str,
    identity: &RequestIdentity,
    family_ref: &str,
) -> Result<Vec<Value>, Reply> {
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        family.resource_kind(),
        family_ref,
        None,
    )
    .map_err(scope_refusal_reply)?;
    read_lineage(family, data_dir, identity, &scope, family_ref)
}

// ---------------------------------------------------------------------------- shared shape checking

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// Refuse any key a nested caller object is not permitted to carry.
///
/// PRE-ADMISSION, ALWAYS. The registered contracts close these objects with
/// `additionalProperties: false`, but that check runs during PROJECTION — which is after the durable
/// append. A stray key reaching the chain would therefore be permanently unprojectable: the family
/// would answer 502 forever with the offending bytes already admitted.
fn require_closed_object<'a>(
    entry: &'a Value,
    permitted: &[&str],
    at: &str,
) -> Result<&'a Map<String, Value>, Reply> {
    let Some(object) = entry.as_object() else {
        return Err(refuse(
            "semantic_mapping_nested_entry_malformed",
            format!("every {at} entry must be an object with exactly {permitted:?}"),
        ));
    };
    if let Some(unknown) = object.keys().find(|key| !permitted.contains(&key.as_str())) {
        return Err(refuse(
            "semantic_mapping_nested_entry_unknown_field",
            format!(
                "{at} entry carries '{unknown}', which the registered contract does not define; an unknown field would only be caught after the durable write"
            ),
        ));
    }
    Ok(object)
}

fn require_member(value: &str, permitted: &[&str], at: &str) -> Result<String, Reply> {
    if permitted.contains(&value) {
        return Ok(value.to_owned());
    }
    Err(refuse(
        "semantic_mapping_vocabulary_member_unknown",
        format!("{at} must be one of {permitted:?}, not '{value}'"),
    ))
}

fn validate_valid_time(body: &Value) -> Result<Value, Reply> {
    let Some(interval) = body.get("valid_time") else {
        return Err(refuse(
            "semantic_mapping_valid_time_required",
            "valid_time is required: a record with no valid time cannot say 'held then, not now'",
        ));
    };
    require_closed_object(interval, &["starts_at", "ends_at"], "valid_time")?;
    let starts_at = str_field(interval, "starts_at");
    if parse_time(starts_at).is_none() {
        return Err(refuse(
            "semantic_mapping_valid_time_not_canonical",
            "valid_time.starts_at must be an RFC3339 instant",
        ));
    }
    let ends_at = match interval.get("ends_at") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) => {
            let Some(end) = parse_time(value) else {
                return Err(refuse(
                    "semantic_mapping_valid_time_not_canonical",
                    "valid_time.ends_at must be an RFC3339 instant or null",
                ));
            };
            if Some(end) <= parse_time(starts_at) {
                return Err(refuse(
                    "semantic_mapping_valid_time_not_ordered",
                    "valid_time.ends_at must be strictly after starts_at; an interval that ends before it begins holds nothing",
                ));
            }
            json!(value)
        }
        Some(_) => {
            return Err(refuse(
                "semantic_mapping_valid_time_not_canonical",
                "valid_time.ends_at must be a string or null",
            ))
        }
    };
    Ok(json!({ "starts_at": starts_at, "ends_at": ends_at }))
}

fn parse_time(value: &str) -> Option<u64> {
    (value.len() >= 20 && value.ends_with('Z') || value.len() >= 25)
        .then(|| agentgres::parse_rfc3339_ms(value))
        .filter(|ms| *ms > 0)
}

fn optional_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<Value, Reply> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value))
            if transportable_ref(value, 260)
                && schemes.iter().any(|scheme| value.starts_with(scheme)) =>
        {
            Ok(json!(value))
        }
        Some(_) => Err(refuse(
            "semantic_mapping_ref_not_canonical",
            format!("{key} must be null or one of {schemes:?}"),
        )),
    }
}

fn ref_set(body: &Value, key: &str, schemes: &[&str], max: usize) -> Result<Value, Reply> {
    let items = body.get(key).cloned().unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "semantic_mapping_ref_set_malformed",
            format!("{key} must be an array of refs"),
        ));
    };
    if entries.len() > max {
        return Err(refuse(
            "semantic_mapping_ref_set_too_large",
            format!("{key} carries more than {max} refs"),
        ));
    }
    let mut seen: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(value) = entry.as_str() else {
            return Err(refuse(
                "semantic_mapping_ref_not_canonical",
                format!("{key} entries must be strings"),
            ));
        };
        if !transportable_ref(value, 260) || !schemes.iter().any(|scheme| value.starts_with(scheme))
        {
            return Err(refuse(
                "semantic_mapping_ref_not_canonical",
                format!("{key} declares '{value}', which is not one of {schemes:?}"),
            ));
        }
        if seen.iter().any(|previous| previous == value) {
            return Err(refuse(
                "semantic_mapping_ref_duplicated",
                format!("{key} declares '{value}' twice"),
            ));
        }
        seen.push(value.to_owned());
    }
    Ok(Value::Array(seen.into_iter().map(Value::from).collect()))
}

fn require_sha256(body: &Value, key: &str) -> Result<String, Reply> {
    let value = str_field(body, key);
    if is_sha256(value) {
        return Ok(value.to_owned());
    }
    Err(refuse(
        "semantic_mapping_hash_not_canonical",
        format!("{key} must be a canonical lowercase sha256: hash"),
    ))
}

fn require_scoped_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<String, Reply> {
    let value = str_field(body, key);
    if transportable_ref(value, 260) && schemes.iter().any(|scheme| value.starts_with(scheme)) {
        return Ok(value.to_owned());
    }
    Err(refuse(
        "semantic_mapping_ref_not_canonical",
        format!("{key} must be one of {schemes:?}"),
    ))
}

// -------------------------------------------------------------- the exact endpoint resolution seams

/// One admitted endpoint, reduced to the coordinates a mapping must BIND.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedEndpoint {
    family_ref: String,
    revision_ref: String,
    content_hash: String,
    namespace: String,
    name: String,
    revision_ordinal: u64,
    record_profile: &'static str,
    resolver: &'static str,
    status: String,
}

impl ResolvedEndpoint {
    fn binding(&self) -> Value {
        json!({
            "ontology_ref": self.family_ref,
            "ontology_version_ref": self.revision_ref,
            "content_hash": self.content_hash,
            "namespace": self.namespace,
            "name": self.name,
            "revision_ordinal": self.revision_ordinal,
            "record_profile": self.record_profile,
        })
    }
}

/// Resolve one EXACT admitted overlay revision for a caller entitled to see it.
///
/// THE ONE READER FOR THIS FAMILY. A crosswalk that wanted an overlay endpoint could re-read the
/// overlay chain for itself; then this family would have two interpretations of its own truth. It has
/// one, it is here, and it is the same `authorized_lineage` the query route serves from — same owner
/// scope, same projection, same content-hash re-derivation. It adds no storage reader, consults no
/// index, and never widens the caller's scope.
///
/// GRANTS NOTHING. It returns coordinates and a hash.
pub(crate) fn resolve_admitted_overlay(
    data_dir: &str,
    identity: &RequestIdentity,
    overlay_id: &str,
) -> Result<Value, Reply> {
    let Some(coordinates) = parse_overlay_identity(overlay_id) else {
        return Err(refuse(
            "ontology_overlay_identity_not_canonical",
            "an overlay revision is addressed as 'ontology://<namespace>/<name>/overlay/<overlay>/revision/<n>' with canonical tokens and an unpadded positive ordinal; a spelling that needs normalising is refused rather than repaired",
        ));
    };
    let family_ref = overlay_family_ref(
        &coordinates.namespace,
        &coordinates.name,
        &coordinates.overlay_name,
    );
    // AUTHORIZATION IS THE OWNER SEAM'S, UNCHANGED. A caller with no scope here and a caller who
    // owns nothing here receive the same refusal, so this cannot be used as an existence oracle.
    let lineage = authorized_lineage(Family::Overlay, data_dir, identity, &family_ref)?;
    lineage
        .into_iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "ontology_overlay_revision_absent",
                format!(
                    "this overlay has no revision {} — an absent revision is a typed absence, never an empty success",
                    coordinates.ordinal
                ),
            )
        })
}

/// Resolve either kind of endpoint through ITS OWN owner, never through a shared guess.
fn resolve_endpoint(
    data_dir: &str,
    identity: &RequestIdentity,
    reference: &str,
    at: &str,
) -> Result<ResolvedEndpoint, Reply> {
    let Some(endpoint) = classify_endpoint(reference) else {
        return Err(refuse(
            "semantic_mapping_endpoint_not_canonical",
            format!(
                "{at} must be an exact base revision 'ontology://<ns>/<name>/revision/<n>' or an exact overlay revision '.../overlay/<overlay>/revision/<n>'; a family ref names a lineage rather than a revision and a map whose ends can move maps nothing in particular"
            ),
        ));
    };
    match endpoint {
        Endpoint::Base(reference) => {
            let resolved = resolve_admitted_revision(data_dir, identity, &reference)?;
            if !is_sha256(&resolved.content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "semantic_mapping_endpoint_hash_not_canonical",
                    "the endpoint owner resolved this revision to a content hash that is not a canonical sha256; a mapping is not sealed over a malformed binding",
                ));
            }
            Ok(ResolvedEndpoint {
                family_ref: resolved.ontology_family_ref,
                revision_ref: resolved.ontology_id,
                content_hash: resolved.content_hash,
                namespace: resolved.namespace,
                name: resolved.name,
                revision_ordinal: resolved.revision_ordinal,
                record_profile: "ontology_version",
                resolver: BASE_RESOLVER,
                status: resolved.status,
            })
        }
        Endpoint::Overlay(coordinates) => {
            let document = resolve_admitted_overlay(data_dir, identity, reference)?;
            let field = |key: &str| {
                document
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let content_hash = field("content_hash");
            if !is_sha256(&content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "semantic_mapping_endpoint_hash_not_canonical",
                    "the overlay owner resolved this revision to a content hash that is not a canonical sha256",
                ));
            }
            Ok(ResolvedEndpoint {
                family_ref: field("overlay_family_ref"),
                revision_ref: field("overlay_id"),
                content_hash,
                namespace: coordinates.namespace,
                name: coordinates.name,
                revision_ordinal: coordinates.ordinal,
                record_profile: "ontology_overlay",
                resolver: OVERLAY_RESOLVER,
                status: field("status"),
            })
        }
    }
}

/// Resolve one EXACT admitted crosswalk revision, with its CURRENT standing.
///
/// The standing travels with the binding because a decision seals it: "we applied a mapping nobody
/// had challenged" becomes a checkable historical claim rather than a memory.
pub(crate) fn resolve_admitted_crosswalk(
    data_dir: &str,
    identity: &RequestIdentity,
    mapping_id: &str,
) -> Result<Value, Reply> {
    let Some(coordinates) = parse_mapping_identity(Family::Crosswalk, mapping_id) else {
        return Err(refuse(
            "ontology_crosswalk_identity_not_canonical",
            "a crosswalk revision is addressed as 'ontology-mapping://<namespace>/<name>/crosswalk/revision/<n>'; a decision ref names a different family and is refused rather than coerced",
        ));
    };
    let family_ref =
        mapping_family_ref(Family::Crosswalk, &coordinates.namespace, &coordinates.name);
    let lineage = authorized_lineage(Family::Crosswalk, data_dir, identity, &family_ref)?;
    lineage
        .into_iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "ontology_crosswalk_revision_absent",
                format!(
                    "this crosswalk has no revision {} — an absent revision is a typed absence, never an empty success",
                    coordinates.ordinal
                ),
            )
        })
}

/// One admitted mapping revision, reduced to what an assurance subject resolver needs.
///
/// THE M06 CONSUMPTION SEAM. `AssuranceTransitionReceipt` v1's wire is subject-general and names
/// `ontology_mapping_revision` as a family it may address; this is the reader that makes that family
/// RESOLVABLE, and it lives in the owner rather than in the receipt module so the receipt never
/// acquires a second interpretation of a mapping's truth. It returns an identity, a profile, a
/// standing and a hash. It grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedMappingRevision {
    pub(crate) ontology_mapping_id: String,
    pub(crate) mapping_family_ref: String,
    pub(crate) mapping_record_profile: String,
    pub(crate) content_hash: String,
    pub(crate) challenge_standing: String,
    pub(crate) status: String,
}

pub(crate) fn resolve_admitted_mapping_revision(
    data_dir: &str,
    identity: &RequestIdentity,
    mapping_id: &str,
) -> Result<ResolvedMappingRevision, Reply> {
    // Which profile the ref names is decided by the ref itself, not by trying one reader and falling
    // back to the other: a fallback would let a malformed crosswalk id be reported as an absent
    // decision, and the two are different findings.
    let family = if parse_mapping_identity(Family::Crosswalk, mapping_id).is_some() {
        Family::Crosswalk
    } else if parse_mapping_identity(Family::Decision, mapping_id).is_some() {
        Family::Decision
    } else {
        return Err(refuse(
            "ontology_mapping_identity_not_canonical",
            "a mapping revision is addressed as 'ontology-mapping://<namespace>/<name>/<crosswalk|decision>/revision/<n>' with canonical tokens and an unpadded positive ordinal",
        ));
    };
    let coordinates = parse_mapping_identity(family, mapping_id)
        .expect("identity already parsed for this exact family");
    let family_ref = mapping_family_ref(family, &coordinates.namespace, &coordinates.name);
    let lineage = authorized_lineage(family, data_dir, identity, &family_ref)?;
    let Some(document) = lineage
        .iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "ontology_mapping_revision_absent",
            format!(
                "this mapping family has no revision {} — an absent revision is a typed absence, never an empty success",
                coordinates.ordinal
            ),
        ));
    };
    let field = |key: &str| {
        document
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let resolved = ResolvedMappingRevision {
        ontology_mapping_id: field("ontology_mapping_id"),
        mapping_family_ref: field("mapping_family_ref"),
        mapping_record_profile: field("mapping_record_profile"),
        content_hash: field("content_hash"),
        challenge_standing: document
            .pointer("/challenge_state/standing")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        status: field("status"),
    };
    // The projection is already contract-validated, so a disagreement here means the chain answered
    // with a revision other than the one addressed. That is an unreadable chain, not a caveat.
    if resolved.ontology_mapping_id != mapping_id
        || resolved.mapping_family_ref != family_ref
        || !is_sha256(&resolved.content_hash)
        || resolved.challenge_standing.is_empty()
        || resolved.status.is_empty()
    {
        return Err(bad(
            StatusCode::BAD_GATEWAY,
            "ontology_mapping_projection_failed",
            format!(
                "the chain resolved '{mapping_id}' to a revision that does not bind that identity"
            ),
        ));
    }
    Ok(resolved)
}

// ------------------------------------------------------------------------------ shared admission leg

/// Everything the chain decides for a successor, read once from the durable lineage.
struct LineagePosition {
    ordinal: u64,
    predecessor_ref: Value,
    predecessor_hash: Value,
    current_head: Option<String>,
}

fn lineage_position(
    lineage: &[Value],
    id_field: &str,
    stream_head: Option<String>,
) -> LineagePosition {
    let predecessor = lineage.last();
    LineagePosition {
        ordinal: predecessor.map_or(1, |document| ordinal_of(document) + 1),
        predecessor_ref: predecessor
            .and_then(|document| document.get(id_field).cloned())
            .unwrap_or(Value::Null),
        predecessor_hash: predecessor
            .and_then(|document| document.get("content_hash").cloned())
            .unwrap_or(Value::Null),
        current_head: stream_head,
    }
}

/// Exact-head admission, checked here so the refusal names the semantic fact rather than surfacing as
/// a bare substrate conflict. The substrate CAS below is still the authority.
fn check_expected_head(
    family: Family,
    body: &Value,
    position: &LineagePosition,
) -> Result<Option<String>, Reply> {
    let expected_head = match body.get("expected_head") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return Err(refuse(
                &format!("{}_expected_head_not_canonical", family.label()),
                "expected_head must be the exact current Agentgres head of this family, or null for the first revision",
            ))
        }
    };
    if expected_head != position.current_head {
        return Err(bad(
            StatusCode::CONFLICT,
            &format!("{}_expected_head_conflict", family.label()),
            match (&expected_head, &position.current_head) {
                (None, Some(_)) => "this family already has revisions; a successor must name the exact current head".to_string(),
                (Some(_), None) => "this family has no revisions yet; the first revision names no predecessor head".to_string(),
                _ => "expected_head does not name the exact current head of this family; re-read the head and re-derive the revision".to_string(),
            },
        ));
    }
    Ok(expected_head)
}

/// Server-resolved values a caller may ASSERT but never AUTHOR.
///
/// Each disagreement is refused by its own cause, because "gap", "fork", "wrong predecessor" and
/// "wrong hash" have different remedies and a single generic conflict would hide which one happened.
fn check_lineage_assertions(
    family: Family,
    body: &Value,
    position: &LineagePosition,
) -> Result<(), Reply> {
    if let Some(asserted) = body
        .get("expected_revision_ordinal")
        .and_then(Value::as_u64)
    {
        if asserted != position.ordinal {
            return Err(refuse(
                &format!("{}_revision_gap", family.label()),
                format!(
                    "this family's next revision is {}, not {asserted}; revisions are contiguous and never skip",
                    position.ordinal
                ),
            ));
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_version_ref") {
        if asserted != &position.predecessor_ref {
            return Err(refuse(
                &format!("{}_predecessor_substituted", family.label()),
                "expected_predecessor_version_ref does not name this family's exact current revision",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &position.predecessor_hash {
            return Err(refuse(
                &format!("{}_predecessor_hash_substituted", family.label()),
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_version").and_then(Value::as_str) {
        if asserted != version_label(position.ordinal) {
            return Err(refuse(
                &format!("{}_version_label_substituted", family.label()),
                format!(
                    "this revision is {}, not '{asserted}'",
                    version_label(position.ordinal)
                ),
            ));
        }
    }
    Ok(())
}

fn migration_block(position: &LineagePosition, compatibility: &str) -> Value {
    json!({
        "from_version_ref": position.predecessor_ref,
        "from_content_hash": position.predecessor_hash,
        "from_revision_ordinal": position.ordinal - 1,
        "compatibility": compatibility,
        "reinterprets_predecessor": false,
    })
}

/// A successor declares how it relates to what it succeeds. An undeclared migration is a silent
/// change of meaning, which is precisely what an immutable lineage exists to prevent.
fn resolve_compatibility(
    family: Family,
    body: &Value,
    position: &LineagePosition,
) -> Result<&'static str, Reply> {
    let declared = str_field(body, "compatibility");
    if position.ordinal == 1 {
        if !declared.is_empty() && declared != "initial" {
            return Err(refuse(
                &format!("{}_migration_compatibility_invalid", family.label()),
                "the first revision of a family migrates from nothing; its compatibility is 'initial'",
            ));
        }
        return Ok("initial");
    }
    match declared {
        "additive" => Ok("additive"),
        "breaking" => Ok("breaking"),
        _ => Err(refuse(
            &format!("{}_migration_compatibility_invalid", family.label()),
            "a successor must declare compatibility 'additive' or 'breaking'; an undeclared migration silently reinterprets its predecessor",
        )),
    }
}

/// Seal, assert-check and admit one built record, then read the answer back OFF THE CHAIN.
#[allow(clippy::too_many_arguments)]
fn admit_revision(
    family: Family,
    data_dir: &str,
    caller: &WriteCaller,
    scope: &RequestResourceScope,
    family_ref: &str,
    body: &Value,
    mut record: Value,
    expected_head: Option<String>,
) -> Reply {
    let derived = match content_hash(family, &record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("{}_content_hash_failed", family.label()),
                reason,
            )
        }
    };
    if let Some(asserted) = body.get("expected_content_hash").and_then(Value::as_str) {
        if asserted != derived {
            return refuse(
                &format!("{}_content_hash_substituted", family.label()),
                "expected_content_hash does not match the hash this exact content commits to",
            );
        }
    }
    record["content_hash"] = json!(derived);

    let payload = json!({
        "schema_version": family.payload_schema(),
        "owner_ref": caller.owner_ref,
        "resource_ref": family_ref,
        "record": record,
    });
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    // The SHARED admission boundary — the same one every owner-scoped daemon mutation crosses. It is
    // reached with an explicit `recorded_at_ms` because transaction time is this family's own fact.
    // That value is outside replay identity, so an exact retry still replays the ORIGINAL operation.
    let commit = match admit_owner_scoped_mutation(
        data_dir,
        expected_head.is_none(),
        ScopedMutation {
            identity: &caller.identity,
            scope,
            resource_kind: family.resource_kind(),
            resource_ref: family_ref,
            owner_namespace: family.owner_namespace(),
            stream_tail: &stream_tail(family.resource_kind(), family_ref),
            op_kind: family.admit_op(),
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };

    // Read back from the chain: the response is a projection of durable truth, never of the value
    // this handler happened to build.
    let lineage = match read_lineage(family, data_dir, &caller.identity, scope, family_ref) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    let Some(admitted) = lineage
        .iter()
        .find(|document| {
            document.pointer("/admission/admission_head") == Some(&json!(commit.projection.head))
        })
        .cloned()
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            &format!("{}_projection_disagrees_with_ack", family.label()),
            "the admitted head is absent from this family's projected lineage",
        );
    };
    let mut reply = json!({
        "ok": true,
        "replayed": commit.replayed,
        "expected_head_for_successor": commit.projection.head,
        "receipt_ref": commit.receipt_ref,
        "operation_ref": commit.operation_ref,
        "request_fingerprint": commit.request_fingerprint,
        "authority_nonclaim": family.authority_nonclaim(),
    });
    // The record is keyed by its OWN family label, so a caller cannot read a crosswalk out of a
    // decision response by reaching for a shared generic key.
    reply[family.label()] = admitted;
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(reply),
    )
}

/// Reach a prior admission for this idempotency key, if the substrate already holds one.
///
/// REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer head
/// than the one it originally compare-and-swapped against, so checking `expected_head` first would
/// turn every real duplicate into a conflict and make the idempotency key unusable — which is exactly
/// what it is for.
fn replay_prior_admission(
    family: Family,
    data_dir: &str,
    caller: &WriteCaller,
    scope: &RequestResourceScope,
    family_ref: &str,
    lineage: &[Value],
) -> Result<Option<Reply>, Reply> {
    match prior_admission_for_key_on_stream(
        data_dir,
        &caller.identity,
        scope,
        family.resource_kind(),
        family_ref,
        family.owner_namespace(),
        &stream_tail(family.resource_kind(), family_ref),
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let Some(document) = lineage
                .iter()
                .find(|document| {
                    document.pointer("/admission/admission_head") == Some(&json!(prior.head))
                })
                .cloned()
            else {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    &format!("{}_projection_disagrees_with_ack", family.label()),
                    "this key's admitted head is absent from the family's projected lineage",
                ));
            };
            let mut reply = json!({
                "ok": true,
                "replayed": true,
                "expected_head_for_successor": lineage
                    .last()
                    .and_then(|head| head.pointer("/admission/admission_head"))
                    .cloned()
                    .unwrap_or(Value::Null),
                "receipt_ref": document
                    .pointer("/admission/agentgres_receipt_ref")
                    .cloned()
                    .unwrap_or(Value::Null),
                "operation_ref": document
                    .pointer("/admission/agentgres_operation_ref")
                    .cloned()
                    .unwrap_or(Value::Null),
                "authority_nonclaim": family.authority_nonclaim(),
            });
            reply[family.label()] = document;
            Ok(Some((StatusCode::OK, Json(reply))))
        }
        Ok(None) => Ok(None),
        Err(error) => Err(mutation_refusal_reply(error)),
    }
}

// ------------------------------------------------------------------------------- overlay producer

/// POST /v1/hypervisor/ontology-overlays — admit one immutable overlay revision against the exact
/// current head of its Agentgres chain.
pub(crate) async fn handle_ontology_overlay_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST. Validating content before authenticating answers 422 where 401 is owed and
    // tells an anonymous caller which fields this route wants.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let namespace = str_field(&body, "namespace").to_owned();
    let name = str_field(&body, "name").to_owned();
    let overlay_name = str_field(&body, "overlay_name").to_owned();
    if !canonical_token(&namespace, 63)
        || !canonical_token(&name, 63)
        || !canonical_token(&overlay_name, 63)
    {
        return refuse(
            "ontology_overlay_coordinates_not_canonical",
            "namespace, name and overlay_name must each be a lowercase 1..63 character token",
        );
    }
    let base_family = base_family_ref(&namespace, &name);
    let family_ref = overlay_family_ref(&namespace, &name, &overlay_name);

    let governing_scope_ref = match require_scoped_ref(
        &body,
        "governing_scope_ref",
        &[
            "domain://",
            "org://",
            "project://",
            "service://",
            "system://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy_hash = match require_sha256(&body, "policy_hash") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let valid_time = match validate_valid_time(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let invariant_refs = match ref_set(&body, "invariant_refs", &["invariant://"], 128) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let compatibility_profile_ref =
        match optional_ref(&body, "compatibility_profile_ref", &["compatibility://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let deprecation_policy_ref = match optional_ref(&body, "deprecation_policy_ref", &["policy://"])
    {
        Ok(value) => value,
        Err(response) => return response,
    };

    // THE BASE SET, RESOLVED THROUGH ITS OWNER. Each base is re-resolved by ref AND carries that
    // owner's committed hash, so an overlay can never claim to overlay bytes nobody admitted.
    let declared_bases = match ref_set(
        &body,
        "base_ontology_version_refs",
        &["ontology://"],
        MAX_BASES,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let base_refs: Vec<String> = declared_bases
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if base_refs.is_empty() {
        return refuse(
            "ontology_overlay_base_required",
            "an overlay overlays at least one exact base revision; an overlay with no base is a fork that has not admitted it yet",
        );
    }
    let mut bindings = Vec::with_capacity(base_refs.len());
    for reference in &base_refs {
        let resolved = match resolve_endpoint(
            &st.data_dir,
            &caller.identity,
            reference,
            "base_ontology_version_refs",
        ) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        if resolved.record_profile != "ontology_version" {
            return refuse(
                "ontology_overlay_base_is_not_a_version",
                format!("'{reference}' is an overlay revision; an overlay overlays a base ontology version, and stacking overlays is not represented in v1"),
            );
        }
        if resolved.family_ref != base_family {
            return refuse(
                "ontology_overlay_base_is_of_another_family",
                format!(
                    "'{reference}' belongs to '{}', not to '{base_family}' — an overlay never relocates itself under another domain's lineage",
                    resolved.family_ref
                ),
            );
        }
        bindings.push(json!({
            "ontology_version_ref": resolved.revision_ref,
            "content_hash": resolved.content_hash,
            "revision_ordinal": resolved.revision_ordinal,
            "record_status": if resolved.status == "deprecated" { "deprecated" } else { "active" },
        }));
    }

    // THE DIVERGENCE. Added terms are minted in the OVERLAY's own namespace; overlaid terms name
    // BASE terms and may only be relabelled, narrowed, annotated or hidden.
    let added_terms = match overlay_added_terms(&body, &family_ref) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let overlaid_terms = match overlay_overlaid_terms(&body, &base_family) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if added_terms.as_array().map_or(0, Vec::len) == 0
        && overlaid_terms.as_array().map_or(0, Vec::len) == 0
    {
        return refuse(
            "ontology_overlay_declares_no_divergence",
            "an overlay that adds nothing and overlays nothing is not an overlay; it is a second name for its base",
        );
    }

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        OVERLAY_KIND,
        &family_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) = match read_lineage_and_head(
        Family::Overlay,
        &st.data_dir,
        &caller.identity,
        &scope,
        &family_ref,
    ) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    match replay_prior_admission(
        Family::Overlay,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &lineage,
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }

    let position = lineage_position(&lineage, "overlay_id", stream_head);
    let expected_head = match check_expected_head(Family::Overlay, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = check_lineage_assertions(Family::Overlay, &body, &position) {
        return response;
    }
    let compatibility = match resolve_compatibility(Family::Overlay, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };

    let record = json!({
        "schema_version": OVERLAY_SCHEMA,
        "overlay_id": format!("{family_ref}/revision/{}", position.ordinal),
        "overlay_family_ref": family_ref,
        "ontology_family_ref": base_family,
        "ontology_record_profile": "ontology_overlay",
        "namespace": namespace,
        "name": name,
        "overlay_name": overlay_name,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": governing_scope_ref,
        "version": version_label(position.ordinal),
        "revision_ordinal": position.ordinal,
        "predecessor_version_ref": position.predecessor_ref,
        "predecessor_content_hash": position.predecessor_hash,
        "base_ontology_version_refs": base_refs,
        "base_ontology_bindings": bindings,
        "base_resolved_by": BASE_RESOLVER,
        "added_terms": added_terms,
        "overlaid_terms": overlaid_terms,
        "invariant_refs": invariant_refs,
        "compatibility_profile_ref": compatibility_profile_ref,
        "deprecation_policy_ref": deprecation_policy_ref,
        "policy_hash": policy_hash,
        "valid_time": valid_time,
        "migration": migration_block(&position, compatibility),
        "fork_nonclaim": "ontology_overlay_does_not_fork_or_redefine_its_base",
        "authority_nonclaim": OVERLAY_NONCLAIM,
        "global_canonicality_nonclaim": "ontology_overlay_asserts_no_globally_canonical_ontology",
    });
    admit_revision(
        Family::Overlay,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &body,
        record,
        expected_head,
    )
}

/// Terms the overlay contributes, each minted in the OVERLAY's own namespace path.
fn overlay_added_terms(body: &Value, overlay_family: &str) -> Result<Value, Reply> {
    let items = body
        .get("added_terms")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_overlay_term_set_malformed",
            "added_terms must be an array of {term_id,label,term_kind} terms",
        ));
    };
    if entries.len() > MAX_TERMS {
        return Err(refuse(
            "ontology_overlay_term_set_too_large",
            format!("added_terms carries more than {MAX_TERMS} terms"),
        ));
    }
    let prefix = format!("{overlay_family}/term/");
    let mut seen: Vec<String> = Vec::new();
    let mut canonical = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(entry, &["term_id", "label", "term_kind"], "added_terms")?;
        let term_id = str_field(entry, "term_id");
        let label = str_field(entry, "label");
        let term_kind = require_member(str_field(entry, "term_kind"), TERM_KINDS, "term_kind")?;
        let Some(slug) = term_id.strip_prefix(&prefix) else {
            return Err(refuse(
                "ontology_overlay_added_term_in_foreign_namespace",
                format!(
                    "added_terms declares '{term_id}', which is not a term of this overlay's own namespace — minting a term inside the BASE family's namespace is an edit of the base, which is a fork"
                ),
            ));
        };
        if !canonical_token(slug, 63) {
            return Err(refuse(
                "ontology_overlay_term_id_not_canonical",
                format!("added_terms declares a non-canonical term id '{term_id}'"),
            ));
        }
        if label.is_empty() || label.len() > 160 {
            return Err(refuse(
                "ontology_overlay_term_label_required",
                format!("added_terms term '{term_id}' needs a 1..160 character label"),
            ));
        }
        if seen.iter().any(|previous| previous == term_id) {
            return Err(refuse(
                "ontology_overlay_term_duplicated",
                format!("added_terms declares '{term_id}' twice"),
            ));
        }
        seen.push(term_id.to_owned());
        // REBUILT, not forwarded: what is admitted is what this function constructed from validated
        // parts, so nothing the caller sent travels to the chain unexamined.
        canonical.push(json!({ "term_id": term_id, "label": label, "term_kind": term_kind }));
    }
    Ok(Value::Array(canonical))
}

/// Base terms this overlay locally diverges on.
fn overlay_overlaid_terms(body: &Value, base_family: &str) -> Result<Value, Reply> {
    let items = body
        .get("overlaid_terms")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_overlay_term_set_malformed",
            "overlaid_terms must be an array of {base_term_id,overlay_disposition,overlay_label}",
        ));
    };
    if entries.len() > MAX_TERMS {
        return Err(refuse(
            "ontology_overlay_term_set_too_large",
            format!("overlaid_terms carries more than {MAX_TERMS} terms"),
        ));
    }
    let prefix = format!("{base_family}/term/");
    let mut seen: Vec<String> = Vec::new();
    let mut canonical = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &["base_term_id", "overlay_disposition", "overlay_label"],
            "overlaid_terms",
        )?;
        let base_term_id = str_field(entry, "base_term_id");
        let overlay_label = str_field(entry, "overlay_label");
        let disposition = require_member(
            str_field(entry, "overlay_disposition"),
            OVERLAY_DISPOSITIONS,
            "overlay_disposition",
        )?;
        let Some(slug) = base_term_id.strip_prefix(&prefix) else {
            return Err(refuse(
                "ontology_overlay_overlaid_term_is_not_a_base_term",
                format!(
                    "overlaid_terms declares '{base_term_id}', which is not a term of '{base_family}' — an overlay diverges on its OWN base's terms and never on another domain's"
                ),
            ));
        };
        if !canonical_token(slug, 63) {
            return Err(refuse(
                "ontology_overlay_term_id_not_canonical",
                format!("overlaid_terms declares a non-canonical term id '{base_term_id}'"),
            ));
        }
        if overlay_label.is_empty() || overlay_label.len() > 160 {
            return Err(refuse(
                "ontology_overlay_term_label_required",
                format!("overlaid_terms term '{base_term_id}' needs a 1..160 character label"),
            ));
        }
        if seen.iter().any(|previous| previous == base_term_id) {
            return Err(refuse(
                "ontology_overlay_term_duplicated",
                format!("overlaid_terms declares '{base_term_id}' twice"),
            ));
        }
        seen.push(base_term_id.to_owned());
        canonical.push(json!({
            "base_term_id": base_term_id,
            "overlay_disposition": disposition,
            "overlay_label": overlay_label,
        }));
    }
    Ok(Value::Array(canonical))
}

// ----------------------------------------------------------------------------- crosswalk producer

/// One declared correspondence, already checked for shape and membership.
struct DeclaredMappings {
    rows: Value,
    ambiguous: Vec<String>,
    unmapped: usize,
}

/// Every declared correspondence states its RELATION and its LOSS, and an unmapped source term is
/// recorded as unmapped rather than omitted. Silent field equivalence is what canon forbids, and a
/// row with no loss statement is exactly that.
fn declared_mappings(
    body: &Value,
    source_family: &str,
    target_family: &str,
) -> Result<DeclaredMappings, Reply> {
    let items = body
        .get("term_mappings")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_crosswalk_term_mappings_malformed",
            "term_mappings must be an array of {source_term_id,target_term_id,relation,loss}",
        ));
    };
    if entries.is_empty() {
        return Err(refuse(
            "ontology_crosswalk_declares_no_correspondence",
            "a crosswalk with no declared correspondence maps nothing; an empty map is an absence, not a mapping",
        ));
    }
    if entries.len() > MAX_MAPPINGS {
        return Err(refuse(
            "ontology_crosswalk_term_mappings_too_large",
            format!("term_mappings carries more than {MAX_MAPPINGS} rows"),
        ));
    }
    let source_prefix = format!("{source_family}/term/");
    let target_prefix = format!("{target_family}/term/");
    let mut rows = Vec::with_capacity(entries.len());
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut source_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unmapped = 0usize;
    for entry in entries {
        require_closed_object(
            entry,
            &["source_term_id", "target_term_id", "relation", "loss"],
            "term_mappings",
        )?;
        let source_term_id = str_field(entry, "source_term_id");
        let relation = require_member(str_field(entry, "relation"), TERM_RELATIONS, "relation")?;
        let loss = require_member(str_field(entry, "loss"), LOSS_CLASSES, "loss")?;
        let Some(slug) = source_term_id.strip_prefix(&source_prefix) else {
            return Err(refuse(
                "ontology_crosswalk_source_term_is_of_another_family",
                format!(
                    "term_mappings declares '{source_term_id}', which is not a term of the bound source '{source_family}'"
                ),
            ));
        };
        if !canonical_token(slug, 63) {
            return Err(refuse(
                "ontology_crosswalk_term_id_not_canonical",
                format!("term_mappings declares a non-canonical source term '{source_term_id}'"),
            ));
        }
        let target_term_id = match entry.get("target_term_id") {
            None | Some(Value::Null) => {
                // An unmapped row states BOTH that it is unmapped and that the loss is unmapped;
                // a null target under any other relation is a correspondence that names nothing.
                if relation != "unmapped" || loss != "unmapped" {
                    return Err(refuse(
                        "ontology_crosswalk_unmapped_row_is_not_declared_unmapped",
                        format!(
                            "term_mappings leaves '{source_term_id}' with no target but declares relation '{relation}' and loss '{loss}'; an unmapped term is recorded as unmapped, never dropped into a relation it does not have"
                        ),
                    ));
                }
                unmapped += 1;
                Value::Null
            }
            Some(Value::String(value)) => {
                if relation == "unmapped" || loss == "unmapped" {
                    return Err(refuse(
                        "ontology_crosswalk_mapped_row_is_declared_unmapped",
                        format!("term_mappings maps '{source_term_id}' to '{value}' while declaring it unmapped"),
                    ));
                }
                let Some(target_slug) = value.strip_prefix(&target_prefix) else {
                    return Err(refuse(
                        "ontology_crosswalk_target_term_is_of_another_family",
                        format!(
                            "term_mappings declares target '{value}', which is not a term of the bound target '{target_family}'"
                        ),
                    ));
                };
                if !canonical_token(target_slug, 63) {
                    return Err(refuse(
                        "ontology_crosswalk_term_id_not_canonical",
                        format!("term_mappings declares a non-canonical target term '{value}'"),
                    ));
                }
                json!(value)
            }
            Some(_) => {
                return Err(refuse(
                    "ontology_crosswalk_term_mappings_malformed",
                    "target_term_id must be a term ref or null",
                ))
            }
        };
        let pair = (
            source_term_id.to_owned(),
            target_term_id.as_str().unwrap_or("").to_owned(),
        );
        if pairs.contains(&pair) {
            return Err(refuse(
                "ontology_crosswalk_correspondence_declared_twice",
                format!(
                    "term_mappings declares the same correspondence for '{source_term_id}' twice; a repeated pair is an ambiguity pretending to be a mapping"
                ),
            ));
        }
        pairs.push(pair);
        *source_counts.entry(source_term_id.to_owned()).or_insert(0) += 1;
        rows.push(json!({
            "source_term_id": source_term_id,
            "target_term_id": target_term_id,
            "relation": relation,
            "loss": loss,
        }));
    }
    // AMBIGUITY IS DERIVED, NOT DECLARED. A source term with more than one target IS ambiguous; a
    // caller cannot understate the set by omitting a name, because the set is computed from the rows.
    let ambiguous: Vec<String> = source_counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(term, _)| term)
        .collect();
    Ok(DeclaredMappings {
        rows: Value::Array(rows),
        ambiguous,
        unmapped,
    })
}

/// POST /v1/hypervisor/ontology-crosswalks — declare one immutable crosswalk revision between two
/// exact admitted endpoints.
pub(crate) async fn handle_ontology_crosswalk_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let namespace = str_field(&body, "namespace").to_owned();
    let name = str_field(&body, "name").to_owned();
    if !canonical_token(&namespace, 63) || !canonical_token(&name, 63) {
        return refuse(
            "ontology_crosswalk_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family_ref = mapping_family_ref(Family::Crosswalk, &namespace, &name);

    let governing_scope_ref = match require_scoped_ref(
        &body,
        "governing_scope_ref",
        &[
            "domain://",
            "org://",
            "project://",
            "service://",
            "system://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy_hash = match require_sha256(&body, "policy_hash") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let valid_time = match validate_valid_time(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // BOTH ENDPOINTS, RESOLVED THROUGH THEIR OWN OWNERS, UNDER THE CALLER'S OWN SCOPE. A caller who
    // cannot see the target family's chain cannot mint a crosswalk that names it: the refusal comes
    // from that family's owner seam, not from a permission this module invented.
    let source = match resolve_endpoint(
        &st.data_dir,
        &caller.identity,
        str_field(&body, "source_ontology_version_ref"),
        "source_ontology_version_ref",
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let target = match resolve_endpoint(
        &st.data_dir,
        &caller.identity,
        str_field(&body, "target_ontology_version_ref"),
        "target_ontology_version_ref",
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if source.revision_ref == target.revision_ref {
        return refuse(
            "ontology_crosswalk_endpoints_are_one_revision",
            "a map from a revision to itself declares nothing",
        );
    }
    if source.resolver != target.resolver && source.record_profile == target.record_profile {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ontology_crosswalk_resolver_disagreement",
            "two endpoints of the same profile resolved through different owner seams",
        );
    }
    // SERVER-DERIVED, NEVER ASSERTED. `domain_relationship` is the discriminator the terms fence
    // keys on, so it is computed from the two owner-qualified namespaces rather than believed.
    let domain_relationship = if source.namespace == target.namespace {
        "in_domain"
    } else {
        "cross_domain"
    };
    if let Some(asserted) = body
        .get("expected_domain_relationship")
        .and_then(Value::as_str)
    {
        if asserted != domain_relationship {
            return refuse(
                "ontology_crosswalk_domain_relationship_substituted",
                format!(
                    "these endpoints are '{domain_relationship}'; the relationship is derived from the owner-qualified namespaces and is never accepted from the caller"
                ),
            );
        }
    }

    let mappings = match declared_mappings(&body, &source.family_ref, &target.family_ref) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let compatibility_result = match require_member(
        str_field(&body, "compatibility_result"),
        COMPATIBILITY_RESULTS,
        "compatibility_result",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let risk_class =
        match require_member(str_field(&body, "risk_class"), RISK_CLASSES, "risk_class") {
            Ok(value) => value,
            Err(response) => return response,
        };
    let declared_loss = match require_member(
        str_field(&body, "declared_loss"),
        LOSS_CLASSES,
        "declared_loss",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // A map that leaves terms unmapped, or maps them ambiguously, cannot declare itself lossless.
    if declared_loss == "none" && (mappings.unmapped > 0 || !mappings.ambiguous.is_empty()) {
        return refuse(
            "ontology_crosswalk_declared_loss_understates_the_rows",
            "declared_loss is 'none' while the declared rows leave terms unmapped or ambiguous; the posture must cover what the map actually does",
        );
    }
    if compatibility_result == "exact" && declared_loss != "none" {
        return refuse(
            "ontology_crosswalk_exact_result_declares_loss",
            "compatibility_result 'exact' cannot coexist with a declared loss",
        );
    }
    let residual_risk_refs = match ref_set(
        &body,
        "residual_risk_refs",
        &["policy://", "finding://", "evidence://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let verifier_obligation_refs = match ref_set(
        &body,
        "verifier_obligation_refs",
        &["verifier_path://", "test://", "schema://", "evidence://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mapped_refs = match ref_set(
        &body,
        "mapped_object_relationship_event_and_action_refs",
        &["object-model://", "ontology-action://", "schema://"],
        128,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mapping_profile_ref =
        match optional_ref(&body, "mapping_profile_ref", &["artifact://", "mapping://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let deprecation_and_migration_policy_ref = match optional_ref(
        &body,
        "deprecation_and_migration_policy_ref",
        &["policy://"],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CROSSWALK_KIND,
        &family_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) = match read_lineage_and_head(
        Family::Crosswalk,
        &st.data_dir,
        &caller.identity,
        &scope,
        &family_ref,
    ) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    match replay_prior_admission(
        Family::Crosswalk,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &lineage,
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let position = lineage_position(&lineage, "ontology_mapping_id", stream_head);
    let expected_head = match check_expected_head(Family::Crosswalk, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = check_lineage_assertions(Family::Crosswalk, &body, &position) {
        return response;
    }
    let compatibility = match resolve_compatibility(Family::Crosswalk, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };

    let record = json!({
        "schema_version": CROSSWALK_SCHEMA,
        "ontology_mapping_id": format!("{family_ref}/revision/{}", position.ordinal),
        "mapping_family_ref": family_ref,
        "mapping_record_profile": "ontology_crosswalk",
        "namespace": namespace,
        "name": name,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": governing_scope_ref,
        "version": version_label(position.ordinal),
        "revision_ordinal": position.ordinal,
        "predecessor_version_ref": position.predecessor_ref,
        "predecessor_content_hash": position.predecessor_hash,
        "source_ontology_ref": source.family_ref,
        "target_ontology_ref": target.family_ref,
        "source_and_target_version_refs": [source.revision_ref, target.revision_ref],
        "source_binding": source.binding(),
        "target_binding": target.binding(),
        "endpoint_resolved_by": source.resolver,
        "domain_relationship": domain_relationship,
        "term_mappings": mappings.rows,
        "ambiguous_term_refs": mappings.ambiguous,
        "compatibility_result": compatibility_result,
        "mapping_risk": {
            "risk_class": risk_class,
            "declared_loss": declared_loss,
            "ambiguous_term_count": mappings.ambiguous.len(),
            "unmapped_source_term_count": mappings.unmapped,
            "residual_risk_refs": residual_risk_refs,
        },
        "verifier_obligation_refs": verifier_obligation_refs,
        "mapped_object_relationship_event_and_action_refs": mapped_refs,
        "mapping_profile_ref": mapping_profile_ref,
        "deprecation_and_migration_policy_ref": deprecation_and_migration_policy_ref,
        "policy_hash": policy_hash,
        "valid_time": valid_time,
        "migration": migration_block(&position, compatibility),
        "cross_domain_application_nonclaim": "ontology_crosswalk_declaration_is_not_cross_domain_application",
        "correctness_nonclaim": "ontology_crosswalk_admission_is_not_a_correctness_claim",
        "authority_nonclaim": CROSSWALK_NONCLAIM,
        "global_canonicality_nonclaim": "ontology_crosswalk_asserts_no_globally_canonical_ontology",
    });
    admit_revision(
        Family::Crosswalk,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &body,
        record,
        expected_head,
    )
}

// ------------------------------------------------------------------------------ decision producer

/// Reviewer lineage, checked once so a decision cannot be approved by a quorum of one wearing four
/// hats. A reviewer holds one role; a repeated pair is refused.
fn reviewer_lineage(body: &Value) -> Result<Value, Reply> {
    let items = body
        .get("reviewer_lineage")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "semantic_mapping_decision_reviewer_lineage_malformed",
            "reviewer_lineage must be an array of {reviewer_ref,review_role,reviewed_at,review_decision}",
        ));
    };
    if entries.is_empty() {
        return Err(refuse(
            "semantic_mapping_decision_reviewer_required",
            "a decision names at least one reviewer; an unreviewed application is a config row, which is the thing this object exists instead of",
        ));
    }
    if entries.len() > MAX_REVIEWERS {
        return Err(refuse(
            "semantic_mapping_decision_reviewer_lineage_too_large",
            format!("reviewer_lineage carries more than {MAX_REVIEWERS} rows"),
        ));
    }
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &[
                "reviewer_ref",
                "review_role",
                "reviewed_at",
                "review_decision",
            ],
            "reviewer_lineage",
        )?;
        let reviewer_ref = require_scoped_ref(
            entry,
            "reviewer_ref",
            &[
                "user://",
                "org://",
                "worker://",
                "service://",
                "system://",
                "domain://",
            ],
        )?;
        let review_role =
            require_member(str_field(entry, "review_role"), REVIEW_ROLES, "review_role")?;
        let review_decision = require_member(
            str_field(entry, "review_decision"),
            REVIEW_DECISIONS,
            "review_decision",
        )?;
        let reviewed_at = str_field(entry, "reviewed_at");
        if parse_time(reviewed_at).is_none() {
            return Err(refuse(
                "semantic_mapping_decision_review_time_not_canonical",
                "reviewed_at must be an RFC3339 instant",
            ));
        }
        let key = (reviewer_ref.clone(), review_role.clone());
        if seen.contains(&key) {
            return Err(refuse(
                "semantic_mapping_decision_reviewer_counted_twice",
                format!("'{reviewer_ref}' already holds the '{review_role}' role in this lineage"),
            ));
        }
        seen.push(key);
        rows.push(json!({
            "reviewer_ref": reviewer_ref,
            "review_role": review_role,
            "reviewed_at": reviewed_at,
            "review_decision": review_decision,
        }));
    }
    Ok(Value::Array(rows))
}

/// Every ambiguous term the crosswalk named receives exactly one explicit disposition, and no term
/// the crosswalk did NOT name may be disposed of. An undisposed ambiguity refuses before admission:
/// a guessed authoritative value is the failure mode this whole object exists to prevent.
fn ambiguity_dispositions(body: &Value, required: &BTreeSet<String>) -> Result<Value, Reply> {
    let items = body
        .get("ambiguity_dispositions")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "semantic_mapping_decision_ambiguity_dispositions_malformed",
            "ambiguity_dispositions must be an array of {source_term_id,disposition,adjudicated_by_ref}",
        ));
    };
    let mut disposed: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &["source_term_id", "disposition", "adjudicated_by_ref"],
            "ambiguity_dispositions",
        )?;
        let source_term_id = str_field(entry, "source_term_id").to_owned();
        let disposition = require_member(
            str_field(entry, "disposition"),
            AMBIGUITY_DISPOSITIONS,
            "disposition",
        )?;
        let adjudicated_by_ref = require_scoped_ref(
            entry,
            "adjudicated_by_ref",
            &[
                "user://",
                "org://",
                "worker://",
                "service://",
                "system://",
                "domain://",
            ],
        )?;
        if !required.contains(&source_term_id) {
            return Err(refuse(
                "semantic_mapping_decision_disposes_of_an_unnamed_ambiguity",
                format!(
                    "'{source_term_id}' is not one of the ambiguities the applied crosswalk named; adjudicating a term the map did not call ambiguous decides something the map never asked"
                ),
            ));
        }
        if !disposed.insert(source_term_id.clone()) {
            return Err(refuse(
                "semantic_mapping_decision_ambiguity_disposed_of_twice",
                format!("'{source_term_id}' already carries a disposition in this decision"),
            ));
        }
        rows.push(json!({
            "source_term_id": source_term_id,
            "disposition": disposition,
            "adjudicated_by_ref": adjudicated_by_ref,
        }));
    }
    if let Some(missing) = required.difference(&disposed).next() {
        return Err(refuse(
            "semantic_mapping_decision_ambiguity_undisposed",
            format!(
                "the applied crosswalk names '{missing}' as ambiguous and this decision disposes of it in no way; an ambiguous mapping is adjudicated explicitly or refused, never guessed"
            ),
        ));
    }
    Ok(Value::Array(rows))
}

/// The same rule for every source term the crosswalk left unmapped: dropping one silently is the
/// defect this list exists to prevent.
fn unmapped_dispositions(body: &Value, required: &BTreeSet<String>) -> Result<Value, Reply> {
    let items = body
        .get("unmapped_term_dispositions")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "semantic_mapping_decision_unmapped_dispositions_malformed",
            "unmapped_term_dispositions must be an array of {source_term_id,disposition}",
        ));
    };
    let mut disposed: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &["source_term_id", "disposition"],
            "unmapped_term_dispositions",
        )?;
        let source_term_id = str_field(entry, "source_term_id").to_owned();
        let disposition = require_member(
            str_field(entry, "disposition"),
            UNMAPPED_DISPOSITIONS,
            "disposition",
        )?;
        if !required.contains(&source_term_id) {
            return Err(refuse(
                "semantic_mapping_decision_disposes_of_a_mapped_term",
                format!("'{source_term_id}' is not one of the terms the applied crosswalk left unmapped"),
            ));
        }
        if !disposed.insert(source_term_id.clone()) {
            return Err(refuse(
                "semantic_mapping_decision_unmapped_term_disposed_of_twice",
                format!("'{source_term_id}' already carries a disposition in this decision"),
            ));
        }
        rows.push(json!({ "source_term_id": source_term_id, "disposition": disposition }));
    }
    if let Some(missing) = required.difference(&disposed).next() {
        return Err(refuse(
            "semantic_mapping_decision_unmapped_term_undisposed",
            format!(
                "the applied crosswalk leaves '{missing}' unmapped and this decision disposes of it in no way; an unmapped term is carried, excluded or escalated, never dropped"
            ),
        ));
    }
    Ok(Value::Array(rows))
}

/// POST /v1/hypervisor/semantic-mapping-decisions — apply one exact crosswalk revision to one
/// concrete target, under named reviewer lineage.
pub(crate) async fn handle_semantic_mapping_decision_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let namespace = str_field(&body, "namespace").to_owned();
    let name = str_field(&body, "name").to_owned();
    if !canonical_token(&namespace, 63) || !canonical_token(&name, 63) {
        return refuse(
            "semantic_mapping_decision_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family_ref = mapping_family_ref(Family::Decision, &namespace, &name);

    // THE APPLIED CROSSWALK, RESOLVED THROUGH ITS OWNER. Everything the decision says about the map
    // — endpoints, compatibility, risk, declared loss, standing — is carried VERBATIM out of this
    // projection rather than re-asserted by the decider.
    let applied_ref = str_field(&body, "applied_crosswalk_ref").to_owned();
    let crosswalk = match resolve_admitted_crosswalk(&st.data_dir, &caller.identity, &applied_ref) {
        Ok(document) => document,
        Err(response) => return response,
    };
    let cw = |key: &str| {
        crosswalk
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let cw_pointer = |pointer: &str| {
        crosswalk
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let domain_relationship = cw("domain_relationship");
    let challenge_standing = cw_pointer("/challenge_state/standing");
    let risk_class = cw_pointer("/mapping_risk/risk_class");
    let declared_loss = cw_pointer("/mapping_risk/declared_loss");
    let compatibility_result = cw("compatibility_result");

    // INV-30, FAIL-CLOSED BY NAME. Cross-domain application binds only when each required party's
    // governed decision accepts the exact terms root. That acceptance has an owner — M11.1 — and no
    // landed resolver in this build. So a cross-domain application is refused HERE, naming the unit
    // it waits on, rather than admitted on the strength of a caller-supplied acceptance. This is the
    // same discipline the assurance-subject seam uses: a build that cannot resolve a prerequisite
    // never admits a record on the strength of its shape.
    if domain_relationship == "cross_domain" {
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "semantic_mapping_terms_acceptance_unresolvable",
            format!(
                "'{applied_ref}' maps across a domain boundary, and cross-domain application binds only under each participating domain's accepted terms (INV-30). The terms-acceptance resolver is owned by {TERMS_ACCEPTANCE_OWNER} and has not landed in this build, so this application is refused rather than admitted on an unverifiable acceptance. Declaring the crosswalk is unaffected."
            ),
        );
    }
    if body
        .get("terms_acceptance")
        .is_some_and(|value| !value.is_null())
    {
        return refuse(
            "semantic_mapping_decision_terms_acceptance_not_applicable",
            "an in-domain application crosses no boundary and accepts no terms; a terms acceptance here would be evidence of a negotiation that did not happen",
        );
    }
    if challenge_standing == "upheld" {
        return refuse(
            "semantic_mapping_decision_applies_a_revoked_crosswalk",
            format!("'{applied_ref}' had its challenge upheld and is revoked; a revoked map is not applied"),
        );
    }
    if risk_class == "unacceptable" {
        return refuse(
            "semantic_mapping_decision_accepts_an_unacceptable_risk",
            format!("'{applied_ref}' declares an unacceptable mapping risk; accepting it is not an option this route offers"),
        );
    }

    let source_binding = crosswalk
        .get("source_binding")
        .cloned()
        .unwrap_or(Value::Null);
    let target_binding = crosswalk
        .get("target_binding")
        .cloned()
        .unwrap_or(Value::Null);
    let endpoint_refs = crosswalk
        .get("source_and_target_version_refs")
        .cloned()
        .unwrap_or(Value::Null);
    let required_ambiguous: BTreeSet<String> = crosswalk
        .get("ambiguous_term_refs")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let required_unmapped: BTreeSet<String> = crosswalk
        .get("term_mappings")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|row| row.get("relation").and_then(Value::as_str) == Some("unmapped"))
                .filter_map(|row| row.get("source_term_id").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let reviewers = match reviewer_lineage(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let ambiguity = match ambiguity_dispositions(&body, &required_ambiguous) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let unmapped = match unmapped_dispositions(&body, &required_unmapped) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let application_target_refs = match ref_set(
        &body,
        "application_target_refs",
        &[
            "packet://",
            "handoff://",
            "object://",
            "query://",
            "ontology-action://",
            "artifact://",
        ],
        MAX_TARGETS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if application_target_refs.as_array().map_or(0, Vec::len) == 0 {
        return refuse(
            "semantic_mapping_decision_application_target_required",
            "an application with no target is a declaration wearing a decision's clothes",
        );
    }
    let accepted_by_ref = match require_scoped_ref(
        &body,
        "accepted_by_ref",
        &[
            "user://",
            "org://",
            "worker://",
            "service://",
            "system://",
            "domain://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let residual_risk_refs = match ref_set(
        &body,
        "residual_risk_refs",
        &["policy://", "finding://", "evidence://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy_bound_view_refs = match ref_set(
        &body,
        "policy_bound_view_refs",
        &["view://", "restricted_view://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let validation_and_challenge_refs = match ref_set(
        &body,
        "validation_and_challenge_refs",
        &["test://", "verifier-challenge://", "evidence://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let governing_scope_ref = match require_scoped_ref(
        &body,
        "governing_scope_ref",
        &[
            "domain://",
            "org://",
            "project://",
            "service://",
            "system://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy_hash = match require_sha256(&body, "policy_hash") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let valid_time = match validate_valid_time(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // The DECIDER is the authenticated owner, not a name the body supplies. A caller may assert it.
    let decided_by_ref = caller.owner_ref.clone();
    if let Some(asserted) = body.get("expected_decided_by_ref").and_then(Value::as_str) {
        if asserted != decided_by_ref {
            return refuse(
                "semantic_mapping_decision_decider_substituted",
                "expected_decided_by_ref does not name the authenticated owner making this decision",
            );
        }
    }

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        DECISION_KIND,
        &family_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) = match read_lineage_and_head(
        Family::Decision,
        &st.data_dir,
        &caller.identity,
        &scope,
        &family_ref,
    ) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    match replay_prior_admission(
        Family::Decision,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &lineage,
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let position = lineage_position(&lineage, "ontology_mapping_id", stream_head);
    let expected_head = match check_expected_head(Family::Decision, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Err(response) = check_lineage_assertions(Family::Decision, &body, &position) {
        return response;
    }
    let compatibility = match resolve_compatibility(Family::Decision, &body, &position) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // The decision timestamp is the admitting instant's own stamp, not a caller-chosen moment.
    let decision_timestamp = super::iso_now();

    let record = json!({
        "schema_version": DECISION_SCHEMA,
        "ontology_mapping_id": format!("{family_ref}/revision/{}", position.ordinal),
        "mapping_family_ref": family_ref,
        "mapping_record_profile": "semantic_mapping_decision",
        "namespace": namespace,
        "name": name,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": governing_scope_ref,
        "version": version_label(position.ordinal),
        "revision_ordinal": position.ordinal,
        "predecessor_version_ref": position.predecessor_ref,
        "predecessor_content_hash": position.predecessor_hash,
        "applied_crosswalk_ref": applied_ref,
        "applied_crosswalk_binding": {
            "mapping_family_ref": cw("mapping_family_ref"),
            "ontology_mapping_id": cw("ontology_mapping_id"),
            "content_hash": cw("content_hash"),
            "revision_ordinal": crosswalk.get("revision_ordinal").cloned().unwrap_or(Value::Null),
            "compatibility_result": compatibility_result,
            "risk_class": risk_class,
            "declared_loss": declared_loss,
            "challenge_standing": challenge_standing,
        },
        "crosswalk_resolved_by": CROSSWALK_RESOLVER,
        "source_ontology_ref": cw("source_ontology_ref"),
        "target_ontology_ref": cw("target_ontology_ref"),
        "source_and_target_version_refs": endpoint_refs,
        "source_binding": source_binding,
        "target_binding": target_binding,
        "domain_relationship": domain_relationship,
        "application_target_refs": application_target_refs,
        "decided_by_ref": decided_by_ref,
        "decision_timestamp": decision_timestamp,
        "reviewer_lineage": reviewers,
        "mapping_risk_acceptance": {
            "accepted_risk_class": risk_class,
            "accepted_loss": declared_loss,
            "accepted_by_ref": accepted_by_ref,
            "residual_risk_refs": residual_risk_refs,
        },
        "ambiguity_dispositions": ambiguity,
        "unmapped_term_dispositions": unmapped,
        "terms_acceptance": Value::Null,
        "compatibility_result": compatibility_result,
        "policy_bound_view_refs": policy_bound_view_refs,
        "validation_and_challenge_refs": validation_and_challenge_refs,
        "policy_hash": policy_hash,
        "valid_time": valid_time,
        "migration": migration_block(&position, compatibility),
        "correctness_nonclaim": "semantic_mapping_decision_is_not_a_correctness_claim",
        "authority_nonclaim": DECISION_NONCLAIM,
        "legal_conformity_claim": "not_determined",
        "global_canonicality_nonclaim": "semantic_mapping_decision_asserts_no_globally_canonical_ontology",
    });
    admit_revision(
        Family::Decision,
        &st.data_dir,
        &caller,
        &scope,
        &family_ref,
        &body,
        record,
        expected_head,
    )
}

// ------------------------------------------------------------------------------- challenge routes

/// Admit a challenge against, or a resolution of a challenge against, one exact mapping revision.
///
/// THE CHALLENGE IS AN OPERATION ON THE SUBJECT'S OWN STREAM. It does not edit the revision it names
/// and it does not mint a second record beside it; it appends, and the revision's STANDING is folded
/// out of the stream on every read. That is what lets an immutable object be challengeable.
async fn handle_challenge(
    family: Family,
    st: Arc<DaemonState>,
    headers: HeaderMap,
    body: Value,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if !family.is_challengeable() {
        return refuse(
            "ontology_mapping_family_is_not_challengeable",
            "only an OntologyMappingEnvelope profile carries a challenge lifecycle",
        );
    }
    let challenged_ref = str_field(&body, "challenged_ref").to_owned();
    let Some(coordinates) = parse_mapping_identity(family, &challenged_ref) else {
        return refuse(
            "ontology_mapping_challenged_ref_not_canonical",
            "challenged_ref must be an exact revision of this family; a challenge against 'the mapping' rather than one revision of it challenges nothing in particular",
        );
    };
    // The registered challenge contract is pinned. v1's `challenged_ref` pattern cannot express a
    // semantic-plane subject at all, so a caller naming v1 is refused rather than downgraded into.
    let declared_contract = str_field(&body, "challenge_contract_ref");
    if !declared_contract.is_empty() && declared_contract != CHALLENGE_CONTRACT {
        return refuse(
            "ontology_mapping_challenge_contract_unsupported",
            format!(
                "this family admits challenges under {CHALLENGE_CONTRACT}; '{declared_contract}' is refused rather than downgraded into"
            ),
        );
    }
    let challenge_id =
        match require_scoped_ref(&body, "verifier_challenge_id", &["verifier-challenge://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let challenger_ref = match require_scoped_ref(
        &body,
        "challenger_ref",
        &[
            "participant-lease://",
            "system://",
            "worker://",
            "org://",
            "user://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let challenge_kind = match require_member(
        str_field(&body, "challenge_kind"),
        CHALLENGE_KINDS,
        "challenge_kind",
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let adjudicator_policy_ref =
        match require_scoped_ref(&body, "adjudicator_policy_ref", &["policy://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
    let evidence_refs = match ref_set(
        &body,
        "challenge_evidence_refs",
        &["evidence://", "artifact://", "receipt://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };

    // A RESOLUTION IS A DIFFERENT OPERATION FROM A CHALLENGE. It names the outcome and the exact
    // assurance receipt that stands behind it; a standing that changed with no receipt is a verdict
    // nobody stands behind, so the receipt is required rather than optional.
    let resolution = str_field(&body, "resolution").to_owned();
    let (op_kind, resolution, receipt_ref) = if resolution.is_empty() {
        (CHALLENGE_OPEN_OP, String::new(), String::new())
    } else {
        let outcome = match require_member(&resolution, RESOLUTIONS, "resolution") {
            Ok(value) => value,
            Err(response) => return response,
        };
        let declared_resolution_contract = str_field(&body, "resolution_contract_ref");
        if !declared_resolution_contract.is_empty()
            && declared_resolution_contract != RESOLUTION_CONTRACT
        {
            return refuse(
                "ontology_mapping_resolution_contract_unsupported",
                format!("a resolution is receipted under {RESOLUTION_CONTRACT}"),
            );
        }
        // SHAPE ONLY, HERE. Whether this string names a receipt this daemon actually admitted is a
        // question about the SUBJECT's assurance ladder, and the subject is not resolved yet; the
        // owner seam is reached below, once it is.
        let receipt = match require_scoped_ref(&body, "resolution_receipt_ref", &["receipt://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
        (CHALLENGE_RESOLVE_OP, outcome, receipt)
    };

    let family_ref = mapping_family_ref(family, &coordinates.namespace, &coordinates.name);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        family.resource_kind(),
        &family_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) =
        match read_lineage_and_head(family, &st.data_dir, &caller.identity, &scope, &family_ref) {
            Ok(pair) => pair,
            Err(response) => return response,
        };
    // The subject must EXIST before it can be challenged. Appending a challenge against a revision
    // this family never admitted would leave a permanently dangling standing nobody can resolve.
    let Some(subject) = lineage
        .iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
        .cloned()
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "ontology_mapping_challenged_revision_absent",
            format!(
                "this family has no revision {} to challenge — an absent subject is a typed absence, never an accepted challenge",
                coordinates.ordinal
            ),
        );
    };
    let standing = subject
        .pointer("/challenge_state/standing")
        .and_then(Value::as_str)
        .unwrap_or("unchallenged");
    let open: Vec<&str> = subject
        .pointer("/challenge_state/open_challenge_refs")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let resolved: Vec<&str> = subject
        .pointer("/challenge_state/resolved_challenge_refs")
        .and_then(Value::as_array)
        .map(|entries| entries.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if op_kind == CHALLENGE_OPEN_OP {
        if open.contains(&challenge_id.as_str()) || resolved.contains(&challenge_id.as_str()) {
            return refuse(
                "ontology_mapping_challenge_already_admitted",
                format!("'{challenge_id}' already stands against this revision"),
            );
        }
    } else if !open.contains(&challenge_id.as_str()) {
        return refuse(
            "ontology_mapping_challenge_not_open",
            format!(
                "'{challenge_id}' is not an open challenge against this revision; resolving a challenge that was never admitted would change a standing nobody contested"
            ),
        );
    }
    let _ = standing;

    // ------------------------------------------------------ the receipt becomes evidence, or refuses
    //
    // A `receipt://`-shaped string is not a receipt. Before this seam existed, a resolution accepted
    // any such string and called the standing change receipted — caller-authored evidence, which is
    // exactly what INV-37 forbids. The M06 owner now re-resolves it off the SUBJECT's own assurance
    // ladder and binds the subject, the subject's owner-resolved bytes, and the exact challenge.
    if op_kind == CHALLENGE_RESOLVE_OP {
        let subject_hash = subject
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let resolved = match resolve_challenge_resolution_receipt(
            &st.data_dir,
            &caller.identity,
            &receipt_ref,
            &challenged_ref,
            &subject_hash,
            &challenge_id,
        ) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
        // The LADDER decides what the challenge resolved to; this route may not disagree with it.
        if resolved.resolution != resolution {
            return refuse(
                "ontology_mapping_resolution_disagrees_with_its_receipt",
                format!(
                    "this request resolves the challenge '{resolution}' while '{}' records '{}'; the receipt is the evidence, not the request",
                    resolved.receipt_ref, resolved.resolution
                ),
            );
        }
    }

    let payload = json!({
        "schema_version": CHALLENGE_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": family_ref,
        "verifier_challenge_id": challenge_id,
        "challenged_ref": challenged_ref,
        "challenger_ref": challenger_ref,
        "challenge_kind": challenge_kind,
        "challenge_evidence_refs": evidence_refs,
        "adjudicator_policy_ref": adjudicator_policy_ref,
        "challenge_contract_ref": CHALLENGE_CONTRACT,
        "resolution_contract_ref": RESOLUTION_CONTRACT,
        "resolution": resolution,
        "resolution_receipt_ref": receipt_ref,
    });
    // The STREAM head, not the last revision's: a challenge already admitted against this family
    // moved the stream on without minting a revision.
    let expected_head = stream_head;
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        false,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: family.resource_kind(),
            resource_ref: &family_ref,
            owner_namespace: family.owner_namespace(),
            stream_tail: &stream_tail(family.resource_kind(), &family_ref),
            op_kind,
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    // Read the standing back OFF THE CHAIN, so the answer is the fold rather than the intent.
    let lineage = match read_lineage(family, &st.data_dir, &caller.identity, &scope, &family_ref) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    let Some(subject) = lineage
        .iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
        .cloned()
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            "ontology_mapping_projection_disagrees_with_ack",
            "the challenged revision is absent from this family's projected lineage",
        );
    };
    let mut reply = json!({
        "ok": true,
        "replayed": commit.replayed,
        "challenge_state": subject.get("challenge_state").cloned().unwrap_or(Value::Null),
        "status": subject.get("status").cloned().unwrap_or(Value::Null),
        "expected_head_for_successor": commit.projection.head,
        "receipt_ref": commit.receipt_ref,
        "operation_ref": commit.operation_ref,
        "verdict_nonclaim": "ontology_mapping_challenge_admission_is_not_an_adjudication",
        "authority_nonclaim": family.authority_nonclaim(),
    });
    reply[family.label()] = subject;
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(reply),
    )
}

pub(crate) async fn handle_ontology_crosswalk_challenge(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    handle_challenge(Family::Crosswalk, st, headers, body).await
}

pub(crate) async fn handle_semantic_mapping_decision_challenge(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    handle_challenge(Family::Decision, st, headers, body).await
}

// ----------------------------------------------------------------------------------- query consumer

#[derive(serde::Deserialize)]
pub(crate) struct LineageQuery {
    namespace: Option<String>,
    name: Option<String>,
    overlay_name: Option<String>,
    revision: Option<u64>,
    as_of_valid_time: Option<String>,
    as_of_transaction_time: Option<String>,
}

/// Exact lookup, whole lineage, or a bitemporal cell.
///
/// With no coordinates this answers the caller's family inventory. With them it answers one lineage,
/// optionally narrowed by `revision` (exact), `as_of_transaction_time` ("as the record stood then")
/// and `as_of_valid_time` ("what was held true then"). The two narrowings are INDEPENDENT, which is
/// the whole point of keeping the axes apart.
async fn handle_query(
    family: Family,
    st: Arc<DaemonState>,
    headers: HeaderMap,
    query: LineageQuery,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let (Some(namespace), Some(name)) = (query.namespace.as_deref(), query.name.as_deref()) else {
        return match authorized_request_resource_refs(
            &st.data_dir,
            &identity,
            family.resource_kind(),
        ) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "families": refs.into_iter().collect::<Vec<_>>(),
                    "record_profile": family.label(),
                    "authority_nonclaim": family.authority_nonclaim(),
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if !canonical_token(namespace, 63) || !canonical_token(name, 63) {
        return refuse(
            "semantic_mapping_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family_ref = match family {
        Family::Overlay => {
            let Some(overlay_name) = query.overlay_name.as_deref() else {
                return refuse(
                    "ontology_overlay_coordinates_not_canonical",
                    "an overlay lineage is addressed by namespace, name AND overlay_name",
                );
            };
            if !canonical_token(overlay_name, 63) {
                return refuse(
                    "ontology_overlay_coordinates_not_canonical",
                    "overlay_name must be a lowercase 1..63 character token",
                );
            }
            overlay_family_ref(namespace, name, overlay_name)
        }
        other => mapping_family_ref(other, namespace, name),
    };
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        family.resource_kind(),
        &family_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let lineage = match read_lineage(family, &st.data_dir, &identity, &scope, &family_ref) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&projection_cache_key(&scope, &family_ref), &lineage);

    // TRANSACTION-TIME travel first: it decides which revisions had been RECORDED yet.
    let mut visible: Vec<&Value> = lineage.iter().collect();
    if let Some(as_of) = query.as_of_transaction_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "semantic_mapping_as_of_not_canonical",
                "as_of_transaction_time must be an RFC3339 instant",
            );
        };
        visible.retain(|document| {
            document
                .pointer("/transaction_time/recorded_at")
                .and_then(Value::as_str)
                .and_then(parse_time)
                .is_some_and(|recorded| recorded <= as_of_ms)
        });
    }
    // VALID-TIME travel second, and INDEPENDENTLY: "what was held true then" is a different question
    // from "what had been recorded then", and collapsing them is how a bitemporal store stops being
    // able to say "true then, corrected now".
    if let Some(as_of) = query.as_of_valid_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "semantic_mapping_as_of_not_canonical",
                "as_of_valid_time must be an RFC3339 instant",
            );
        };
        visible.retain(|document| {
            let starts = document
                .pointer("/valid_time/starts_at")
                .and_then(Value::as_str)
                .and_then(parse_time);
            let ends = document
                .pointer("/valid_time/ends_at")
                .and_then(Value::as_str)
                .and_then(parse_time);
            starts.is_some_and(|start| start <= as_of_ms) && ends.is_none_or(|end| as_of_ms < end)
        });
    }
    if let Some(revision) = query.revision {
        visible.retain(|document| ordinal_of(document) == revision);
        if visible.is_empty() {
            return bad(
                StatusCode::NOT_FOUND,
                "semantic_mapping_revision_absent",
                format!(
                    "this family has no revision {revision} under the requested time coordinates"
                ),
            );
        }
    }
    let records: Vec<Value> = visible.into_iter().cloned().collect();
    let mut reply = json!({
        "ok": true,
        "family_ref": family_ref,
        "record_profile": family.label(),
        "revision_count": records.len(),
        "lineage_revision_count": lineage.len(),
        "current_head": lineage
            .last()
            .and_then(|document| document.pointer("/admission/admission_head"))
            .cloned()
            .unwrap_or(Value::Null),
        // POSITIVE detection of the rebuild. An unchanged answer is also consistent with a cache that
        // was never dropped, which would prove nothing; this reports which of the two happened.
        "projection_index_state": index_state,
        "projection_source": "agentgres_owner_scoped_chain",
        "authority_nonclaim": family.authority_nonclaim(),
    });
    reply["records"] = Value::Array(records);
    (StatusCode::OK, Json(reply))
}

pub(crate) async fn handle_ontology_overlay_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<LineageQuery>,
) -> Reply {
    handle_query(Family::Overlay, st, headers, query).await
}

pub(crate) async fn handle_ontology_crosswalk_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<LineageQuery>,
) -> Reply {
    handle_query(Family::Crosswalk, st, headers, query).await
}

pub(crate) async fn handle_semantic_mapping_decision_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<LineageQuery>,
) -> Reply {
    handle_query(Family::Decision, st, headers, query).await
}
