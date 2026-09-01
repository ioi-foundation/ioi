//! `AssuranceTransitionReceipt` — one step of the canonical assurance ladder as an immutable,
//! exact-head object on the Agentgres chain (M06 prerequisite for M05.2/M05.3).
//!
//! WHAT IS TRUTH HERE, stated once so nothing later can quietly disagree: the Agentgres
//! owner-namespaced operation chain for one SUBJECT is the only durable record. This module writes NO
//! file of its own, so there is no second store to drift even in principle. One subject is one
//! stream, so its ladder is a head-linked chain and a successor must name the exact current head.
//! Everything served is a PROJECTION rebuilt from that chain on every read, including the content
//! hash, which is re-derived and compared rather than trusted.
//!
//! FOUR PROPERTIES ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//!
//! 1. THE SUBJECT IS RESOLVED, NEVER ASSERTED. `subject_ref` is handed to the subject family's own
//!    current owner, and `subject_content_hash` is that owner's committed hash carried verbatim. A
//!    URI whose prefix merely LOOKS like a family is not proof the subject exists: the ontology
//!    revision family goes through `ontology_version_routes::resolve_admitted_revision`, the
//!    mapping-revision family through `semantic_mapping_routes::resolve_admitted_mapping_revision`
//!    and the assertion family through `provenance_assertion_routes::resolve_admitted_assertion` —
//!    each the one reader its owner already publishes — and every other family is refused BY NAME.
//!    That refusal is the whole point: a ladder that admits unresolvable subjects has moved nothing.
//!
//! 2. STAGES DO NOT SKIP, AND THE PROOF IS PORTABLE. `transition_ordinal` is derived from the
//!    subject's own chain length and `to_stage_ordinal` is pinned to `to_stage` by the registered
//!    schema; a registered invariant then requires the two to be equal. So a transition that jumps
//!    `attested -> verified` carries ladder position 3 at chain position 2 and fails OFFLINE, with no
//!    daemon present. The runtime refusal below and the portable invariant are two independent fences
//!    on the same claim.
//!
//! 3. THE CALLER NEVER AUTHORS EVIDENCE (INV-37). Actor, ordinal, both stages, the predecessor refs,
//!    the subject's content hash, the resolver seam, transaction time, the resulting head hash and
//!    the whole admission block are RESOLVED. A caller may only ASSERT what it believes them to be,
//!    and each disagreement refuses by its own cause. `outcome_class`, `evidence_refs`,
//!    `does_not_assert` and `valid_time` are CONTENT the actor declares — that is a different thing
//!    from evidence, and it is inside the content commitment.
//!
//! 4. A RECEIPT IS NOT A VERDICT AND GRANTS NOTHING (NN 20). Every projected transition carries
//!    `authority_nonclaim` and `verdict_nonclaim` explicitly, and nothing here consults, mints,
//!    widens or presents a capability, lease, policy decision or effect admission. Reaching `settled`
//!    is not proof that value moved; that remains the owning settlement adapter's to attest. Negative
//!    outcomes are retained verbatim and are never normalised toward `positive` (NN 21).
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use agentgres::mux::ExactProjection;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation, WriteCaller,
};
use super::ontology_version_routes::resolve_admitted_revision;
use super::provenance_assertion_routes::resolve_admitted_assertion;
use super::semantic_mapping_routes::resolve_admitted_mapping_revision;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
    RequestScopeRefusal,
};
use super::work_result_routes::{
    resolve_admitted_work_result, work_truth_visibility_reader, WORK_RESULT_COMMITMENT_DOMAIN,
};
use super::DaemonState;

/// The Agentgres owner namespace every assurance-transition stream lives in. It is DATA to the
/// substrate: nothing below this module branches on it.
const OWNER_NAMESPACE: &str = "hypervisor-assurance-transitions";
/// The scoped resource is the SUBJECT, not the transition — one subject, one ladder, one chain.
const RESOURCE_KIND: &str = "assurance-transition-subject";
const ADMIT_OP: &str = "assurance_transition.stage.admit";
const ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.assurance-transition-admission.v1";
/// THE CONTRACT THIS BUILD EMITS. v1 remains registered, remains valid, and remains READABLE off the
/// chain below: a frame written before this build is projected and validated AS v1, never coerced
/// into v2. Emitting v2 is a forward choice; reinterpreting v1 would be a rewrite of history.
const CONTRACT_ID: &str = "schema://ioi/foundations/assurance-transition-receipt/v2";
const PREDECESSOR_CONTRACT_ID: &str = "schema://ioi/foundations/assurance-transition-receipt/v1";
const CONTENT_COMMITMENT_DOMAIN: &str = "ioi.assurance-transition-content-commitment-jcs-sha256.v2";
const PREDECESSOR_COMMITMENT_DOMAIN: &str =
    "ioi.assurance-transition-content-commitment-jcs-sha256.v1";
/// The exact wire contract this build implements. A caller naming any other version is refused, not
/// downgraded — see the first gate in `validate_proposal`.
const SCHEMA_VERSION: &str = "ioi.assurance-transition-receipt.v2";
const PREDECESSOR_SCHEMA_VERSION: &str = "ioi.assurance-transition-receipt.v1";
const RECEIPT_TYPE: &str = "assurance_transition";
const RECEIPT_PROFILE_REF: &str = "schema://ioi/foundations/assurance-transition-receipt/v2";
/// The exact registered challenge contract a resolution may cite. v1 cannot address a semantic-plane
/// subject at all, so it is refused by name rather than downgraded into.
const CHALLENGE_CONTRACT: &str = "schema://ioi/foundations/objects/verifier-challenge-envelope/v2";
const CHALLENGE_RESOLVER: &str =
    "assurance_transition_routes::resolve_challenge_resolution_receipt";
const ADJUDICATED_STAGE: &str = "adjudicated";
const RESOLUTIONS: &[&str] = &["upheld", "rejected"];
const REVIEW_DECISIONS: &[&str] = &["upheld", "rejected", "abstained"];
const UPHELD_OUTCOMES: &[&str] = &["negative", "invalid", "exploit", "disputed"];
const REJECTED_OUTCOMES: &[&str] = &["positive", "no_fault", "inconclusive"];
const MAX_REVIEWERS: usize = 32;
/// The registered `principalRef` scheme set, transcribed from the contract this module emits. Only
/// the resolution block needs it: `actor_ref` is taken from the authenticated identity and is never
/// a field a request authors.
const PRINCIPAL_SCHEMES: &[&str] = &[
    "system://",
    "user://",
    "wallet://",
    "org://",
    "project://",
    "domain://",
    "worker://",
    "agent://",
    "service://",
    "provider://",
    "policy://",
    "governance://",
    "runtime://",
];
const AUTHORITY_NONCLAIM: &str = "assurance_transition_grants_no_authority";
const VERDICT_NONCLAIM: &str = "assurance_transition_is_not_a_verdict";

/// Frozen by `docs/architecture/foundations/canonical-enums.md`. This module registers and DRIVES the
/// ladder; it does not choose its members, and the order is the canonical one.
const STAGES: &[&str] = &[
    "attested",
    "evidenced",
    "verified",
    "accepted",
    "adjudicated",
    "settled",
];

/// ACC-8 clause 2, verbatim. Retained as declared; nothing here maps a member toward `positive`.
const OUTCOME_CLASSES: &[&str] = &[
    "positive",
    "negative",
    "inconclusive",
    "invalid",
    "exploit",
    "superseded",
    "disputed",
    "no_fault",
];

/// The closed nonclaim vocabulary. A transition must disclaim at least one of these explicitly.
const NONCLAIM_TOKENS: &[&str] = &[
    "correctness",
    "external_world_occurrence",
    "causality",
    "acceptance",
    "adjudication",
    "settlement",
    "economic_value",
    "authority",
];

/// The nonclaims a stage short of acceptance/settlement may not omit — the runtime half of NN 20.
const PRE_ACCEPTANCE_STAGES: &[&str] = &["attested", "evidenced", "verified"];
const REQUIRED_PRE_ACCEPTANCE_NONCLAIMS: &[&str] = &["acceptance", "settlement"];

const MAX_EVIDENCE_REFS: usize = 128;
const EVIDENCE_SCHEMES: &[&str] = &[
    "evidence://",
    "assurance-evidence://",
    "artifact://",
    "receipt://",
];

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

// ------------------------------------------------------------------ the subject-resolution seam

/// The families a v1 record may NAME. Naming is not resolving: which of these this build can actually
/// resolve is the separate, deliberately smaller set in `resolve_subject`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SubjectFamily {
    WorkResult,
    OntologyRevision,
    OntologyMappingRevision,
    OntologyAssertion,
    Finding,
    Attempt,
}

impl SubjectFamily {
    fn label(self) -> &'static str {
        match self {
            Self::WorkResult => "work_result",
            Self::OntologyRevision => "ontology_revision",
            Self::OntologyMappingRevision => "ontology_mapping_revision",
            Self::OntologyAssertion => "ontology_assertion",
            Self::Finding => "finding",
            Self::Attempt => "attempt",
        }
    }

    /// Classify a subject ref by its scheme.
    ///
    /// ORDER MATTERS AND IS NOT INCIDENTAL. `ontology-assertion://` and `ontology-mapping://` both
    /// begin with the letters of `ontology`, so the longer schemes are tested FIRST; testing
    /// `ontology://` first would silently classify an assertion as a revision and hand it to the
    /// revision resolver, which is precisely the confusion this discriminator exists to prevent.
    fn classify(subject_ref: &str) -> Option<Self> {
        if subject_ref.starts_with("ontology-assertion://") {
            Some(Self::OntologyAssertion)
        } else if subject_ref.starts_with("ontology-mapping://") {
            Some(Self::OntologyMappingRevision)
        } else if subject_ref.starts_with("ontology://") {
            Some(Self::OntologyRevision)
        } else if subject_ref.starts_with("work-result://") {
            Some(Self::WorkResult)
        } else if subject_ref.starts_with("finding://") {
            Some(Self::Finding)
        } else if subject_ref.starts_with("attempt://") {
            Some(Self::Attempt)
        } else {
            None
        }
    }

    /// The owner unit that will supply this family's resolver. Named so a refusal tells the caller
    /// which unit it is waiting on rather than reading as a generic "no".
    fn owning_unit(self) -> &'static str {
        match self {
            Self::OntologyRevision => "M05.1",
            Self::OntologyMappingRevision => "M05.2",
            Self::OntologyAssertion => "M05.3",
            Self::WorkResult => "M04.1",
            Self::Finding | Self::Attempt => "M04.8",
        }
    }
}

/// One subject, resolved by its owner: what it is, which bytes it currently commits to, and who said
/// so. `content_hash` is the OWNER's, carried verbatim and never recomputed here.
struct ResolvedSubject {
    family: SubjectFamily,
    content_hash: String,
    resolved_by: String,
}

/// Resolve `subject_ref` through the current owner of its family, or refuse.
///
/// THE ONE PLACE A SUBJECT BECOMES REAL. The v1 wire was subject-general from birth so that later
/// units could add their resolvers behind this seam WITHOUT a wire change; M05.2 has now done exactly
/// that for the crosswalk/decision family and M05.3 for the assertion family, each through its
/// owner's published reader. Every
/// family still without a landed owner reader remains well-formed on the wire and REFUSED BY NAME
/// here, because a build that cannot resolve a family must never admit a transition over it on the
/// strength of a URI prefix.
///
/// `headers` are threaded in for ONE reason: the `work-result://` owner answers visibility from the
/// request the way it always has (`work_truth_visibility_reader`), and this seam must inherit that
/// answer rather than compute a second one. The three semantic-plane arms below ignore it and are
/// behaviourally unchanged.
fn resolve_subject(
    data_dir: &str,
    identity: &RequestIdentity,
    headers: &HeaderMap,
    subject_ref: &str,
) -> Result<ResolvedSubject, Reply> {
    let Some(family) = SubjectFamily::classify(subject_ref) else {
        return Err(refuse(
            "assurance_transition_subject_scheme_unknown",
            "subject_ref must name one of the registered assurance subjects: work-result://, ontology://, ontology-mapping://, ontology-assertion://, finding:// or attempt://",
        ));
    };
    match family {
        // THE REAL ONE. This calls the ontology-version owner's OWN published reader rather than
        // re-reading its chain here: same owner scope, same projection, same content-hash
        // re-derivation. A second reader would be a second interpretation of that family's truth.
        SubjectFamily::OntologyRevision => {
            let revision = resolve_admitted_revision(data_dir, identity, subject_ref)?;
            // The owner already re-derives and checks this hash. It is checked AGAIN here, at the
            // seam, because this module is about to seal the value inside its own content
            // commitment: a neighbour's invariant that silently weakened would otherwise be
            // discovered as a permanently unprojectable durable record rather than as a refusal.
            if !is_sha256(&revision.content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "assurance_transition_subject_hash_not_canonical",
                    "the subject owner resolved this subject to a content hash that is not a canonical sha256; a transition is not sealed over a malformed binding",
                ));
            }
            Ok(ResolvedSubject {
                family,
                content_hash: revision.content_hash,
                resolved_by: "ontology_version_routes::resolve_admitted_revision".to_string(),
            })
        }
        // THE SECOND REAL ONE, LANDED BY M05.2. Same discipline as the revision arm: the mapping
        // owner's OWN published reader, so the receipt never acquires a second interpretation of a
        // mapping's truth, and the caller's scope is the mapping owner's scope unchanged.
        SubjectFamily::OntologyMappingRevision => {
            let mapping = resolve_admitted_mapping_revision(data_dir, identity, subject_ref)?;
            if !is_sha256(&mapping.content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "assurance_transition_subject_hash_not_canonical",
                    "the subject owner resolved this subject to a content hash that is not a canonical sha256; a transition is not sealed over a malformed binding",
                ));
            }
            Ok(ResolvedSubject {
                family,
                content_hash: mapping.content_hash,
                resolved_by: "semantic_mapping_routes::resolve_admitted_mapping_revision".to_string(),
            })
        }
        // THE THIRD REAL ONE, LANDED BY M05.3. Same discipline again: the assertion owner's OWN
        // published reader, under the caller's own scope, with the hash carried verbatim.
        SubjectFamily::OntologyAssertion => {
            let assertion = resolve_admitted_assertion(data_dir, identity, subject_ref)?;
            if !is_sha256(&assertion.content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "assurance_transition_subject_hash_not_canonical",
                    "the subject owner resolved this subject to a content hash that is not a canonical sha256; a transition is not sealed over a malformed binding",
                ));
            }
            Ok(ResolvedSubject {
                family,
                content_hash: assertion.content_hash,
                resolved_by: "provenance_assertion_routes::resolve_admitted_assertion".to_string(),
            })
        }
        // THE FOURTH REAL ONE, LANDED BY M06.1 — the general WorkResult ladder this contract was
        // shaped for. Same discipline as every arm above: the WorkResult owner's OWN published
        // reader, under that owner's OWN visibility answer, with the hash carried verbatim.
        //
        // The one thing this arm does differently, because the family is different: a WorkResult
        // record CHANGES when its owner admits an `outcome_delta_refs` or `review_refs` backlink.
        // The owner therefore commits the WHOLE record, so each admitted version has a DISTINCT
        // hash. A transition sealed over version 1 keeps naming version 1's bytes after version 2
        // lands — which is the point. The URI was never the stable thing.
        SubjectFamily::WorkResult => {
            let reader = work_truth_visibility_reader(data_dir, headers)
                .map_err(|(status, body)| (status, body))?;
            let resolved =
                resolve_admitted_work_result(data_dir, reader.as_deref(), subject_ref).map_err(
                    |(code, message)| {
                        // Absence and not-entitled share one code by construction in the owner's
                        // resolver; keep the transport status uniform too so the pair cannot be
                        // separated by a 404-vs-403 side channel.
                        bad(StatusCode::UNPROCESSABLE_ENTITY, &code, message)
                    },
                )?;
            if !is_sha256(&resolved.content_hash) {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    "assurance_transition_subject_hash_not_canonical",
                    "the subject owner resolved this subject to a content hash that is not a canonical sha256; a transition is not sealed over a malformed binding",
                ));
            }
            Ok(ResolvedSubject {
                family,
                content_hash: resolved.content_hash,
                resolved_by: "work_result_routes::resolve_admitted_work_result".to_string(),
            })
        }
        // FAIL CLOSED, BY NAME. Not "unsupported subject" — the exact family and the exact unit that
        // owns its reader, so this refusal can never be mistaken for the subject being absent.
        // `finding` and `attempt` remain here, named, with no landed resolver.
        other => Err(bad(
            StatusCode::NOT_IMPLEMENTED,
            "assurance_transition_subject_family_unresolvable",
            format!(
                "the '{}' subject family is nameable on this contract but has no landed owner resolver in this build; {} owns it, and a transition is never admitted on the strength of a URI prefix",
                other.label(),
                other.owning_unit()
            ),
        )),
    }
}

// ---------------------------------------------------------------- canonical content commitment

/// The exact material the registered invariant
/// `assurance_transition.content_hash.commits_subject_stage_outcome_and_valid_time` commits.
///
/// `transaction_time` and the admission block are DELIBERATELY absent: when a stage was claimed true
/// is content, when it was recorded is admission. Keeping the two apart is what lets a predecessor's
/// transaction interval close without its content hash moving.
const CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "transition_id",
    "subject_ref",
    "subject_family",
    "subject_content_hash",
    "subject_resolved_by",
    "from_stage",
    "to_stage",
    "to_stage_ordinal",
    "transition_ordinal",
    "outcome_class",
    "actor_ref",
    "evidence_refs",
    "does_not_assert",
    "expected_predecessor_transition_ref",
    "expected_predecessor_transition_hash",
    "valid_time",
    "challenge_resolution",
];

/// v1's material, unchanged. Kept so a v1 frame on the chain is re-derived with the SAME commitment
/// it was written under: re-hashing an old record with v2's material would report every v1 frame as
/// tampered, which is reinterpretation by another name.
const PREDECESSOR_CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "transition_id",
    "subject_ref",
    "subject_family",
    "subject_content_hash",
    "subject_resolved_by",
    "from_stage",
    "to_stage",
    "to_stage_ordinal",
    "transition_ordinal",
    "outcome_class",
    "actor_ref",
    "evidence_refs",
    "does_not_assert",
    "expected_predecessor_transition_ref",
    "expected_predecessor_transition_hash",
    "valid_time",
];

fn digest_over(record: &Value, domain: &str, fields: &[&str]) -> Result<String, String> {
    let mut material = Map::new();
    material.insert("domain".into(), json!(domain));
    for field in fields {
        let value = record
            .get(*field)
            .ok_or_else(|| format!("commitment material is missing {field}"))?;
        material.insert((*field).to_string(), value.clone());
    }
    serde_jcs::to_vec(&Value::Object(material))
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| format!("commitment could not be canonicalized: {error}"))
}

fn content_hash(record: &Value) -> Result<String, String> {
    digest_over(record, CONTENT_COMMITMENT_DOMAIN, CONTENT_MATERIAL_FIELDS)
}

/// Re-derive one admitted record's hash under the commitment ITS OWN version declared.
fn content_hash_for_version(record: &Value, schema_version: &str) -> Result<String, String> {
    if schema_version == PREDECESSOR_SCHEMA_VERSION {
        return digest_over(
            record,
            PREDECESSOR_COMMITMENT_DOMAIN,
            PREDECESSOR_CONTENT_MATERIAL_FIELDS,
        );
    }
    content_hash(record)
}

fn parse_time(value: &str) -> Option<u64> {
    (value.len() >= 20 && value.ends_with('Z') || value.len() >= 25)
        .then(|| agentgres::parse_rfc3339_ms(value))
        .filter(|ms| *ms > 0)
}

/// A stable, filesystem-safe slug for one subject ref, used only inside the transition IDENTITY.
///
/// It is a rendering of the subject, never a substitute for it: the subject ref itself and its
/// owner-resolved hash are both inside the content commitment, so two subjects that happened to slug
/// alike would still commit differently and still live on different streams.
fn subject_slug(subject_ref: &str) -> String {
    let body: String = subject_ref
        .bytes()
        .map(|byte| {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() {
                byte as char
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = body.trim_matches('-');
    let digest = sha256_of(subject_ref.as_bytes());
    // The digest tail keeps the identity injective where the slug is lossy.
    format!(
        "{}~{}",
        trimmed.chars().take(96).collect::<String>(),
        &digest[7..23]
    )
}

fn transition_ref(family: SubjectFamily, subject_ref: &str, ordinal: usize) -> String {
    format!(
        "assurance-transition://{}/{}/transition/{}",
        family.label(),
        subject_slug(subject_ref),
        ordinal
    )
}

// ------------------------------------------------------------------------------- request validation

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// The caller-declared CONTENT of one transition, already checked for shape.
///
/// Everything here is a claim the actor makes and stands behind. Nothing here is evidence the caller
/// authored about the system's own state — that distinction is INV-37, and it is why `actor_ref`,
/// the stages, the ordinals and every hash are absent from this struct.
struct ProposedTransition {
    /// `Value::Null` on an ordinary ladder step; a validated resolution object when this transition
    /// adjudicates a named challenge.
    challenge_resolution: Value,
    subject_ref: String,
    outcome_class: String,
    evidence_refs: Value,
    does_not_assert: Value,
    valid_time: Value,
}

fn validate_valid_time(body: &Value) -> Result<Value, Reply> {
    let Some(valid_time) = body.get("valid_time").and_then(Value::as_object) else {
        return Err(refuse(
            "assurance_transition_valid_time_required",
            "valid_time is content: a stage claimed true over no interval cannot be contradicted later, which is the whole reason the axis exists",
        ));
    };
    let unknown = valid_time
        .keys()
        .find(|key| !matches!(key.as_str(), "starts_at" | "ends_at"));
    if let Some(unknown) = unknown {
        return Err(refuse(
            "assurance_transition_valid_time_unknown_field",
            format!("valid_time carries no field '{unknown}'"),
        ));
    }
    let starts_at = valid_time
        .get("starts_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(starts_ms) = parse_time(starts_at) else {
        return Err(refuse(
            "assurance_transition_valid_time_not_parseable",
            "valid_time.starts_at must be an RFC3339 instant",
        ));
    };
    let ends_at = valid_time.get("ends_at").cloned().unwrap_or(Value::Null);
    match &ends_at {
        Value::Null => {}
        Value::String(value) => {
            let Some(ends_ms) = parse_time(value) else {
                return Err(refuse(
                    "assurance_transition_valid_time_not_parseable",
                    "valid_time.ends_at must be an RFC3339 instant or null",
                ));
            };
            if ends_ms <= starts_ms {
                return Err(refuse(
                    "assurance_transition_valid_time_not_ordered",
                    "valid_time.ends_at must be strictly after starts_at; an interval that ends before it begins is held true never",
                ));
            }
        }
        _ => {
            return Err(refuse(
                "assurance_transition_valid_time_not_parseable",
                "valid_time.ends_at must be an RFC3339 instant or null",
            ))
        }
    }
    Ok(json!({ "starts_at": starts_at, "ends_at": ends_at }))
}

/// The optional caller assertions about server-derived facts whose JSON TYPE is fixed.
///
/// `expected_predecessor_transition_ref` and `_hash` are deliberately absent: null is a MEANINGFUL
/// value for them (a genesis transition advances from nothing), and they are compared as whole JSON
/// values, so a wrong type simply fails to equal the stored one and refuses by its own cause.
/// `expected_head` is absent for the reason stated at its own gate: it carries its own typed
/// refusal and a stale value is the normal, correct content of a retry.
const STRING_ASSERTIONS: &[&str] = &[
    "subject_content_hash",
    "subject_family",
    "expected_content_hash",
    "to_stage",
];
const UNSIGNED_ASSERTIONS: &[&str] = &["expected_transition_ordinal"];

/// Refuse a caller assertion that is PRESENT BUT MALFORMED, rather than reading it as absent.
///
/// THE THIRD STATE IS THE WHOLE POINT. `body.get(k).and_then(Value::as_str)` has two outcomes where
/// the wire has three: absent, present-and-well-typed, and present-and-malformed. Collapsing the
/// third into the first means a caller who sends `expected_content_hash: 12345` has its assertion
/// SILENTLY DROPPED and receives a success — and a success is read as "everything you asserted
/// holds". That is the same defect class as answering a replay without comparing intent: a record
/// that says more than anyone checked.
///
/// Checked once here, before either the fresh or the replay path branches, so the two cannot drift
/// into treating the same malformed body differently.
fn validate_assertion_types(body: &Value) -> Result<(), Reply> {
    for key in STRING_ASSERTIONS {
        match body.get(*key) {
            None | Some(Value::String(_)) => {}
            Some(_) => {
                return Err(refuse(
                    "assurance_transition_assertion_not_canonical",
                    format!(
                        "'{key}' must be a string when present; a malformed assertion is refused rather than ignored, because ignoring it would return a success that reads as confirmation of a claim nobody compared"
                    ),
                ))
            }
        }
    }
    for key in UNSIGNED_ASSERTIONS {
        match body.get(*key) {
            None => {}
            Some(value) if value.as_u64().is_some() => {}
            Some(_) => {
                return Err(refuse(
                    "assurance_transition_assertion_not_canonical",
                    format!(
                        "'{key}' must be a non-negative integer when present; a malformed assertion is refused rather than ignored, because ignoring it would return a success that reads as confirmation of a claim nobody compared"
                    ),
                ))
            }
        }
    }
    Ok(())
}

/// Validate the optional challenge-resolution block, or refuse it.
///
/// WHAT THIS BLOCK IS FOR. A challenge against a semantic-plane subject is resolved by ADJUDICATION,
/// and "adjudicated" is a rung of the canonical ladder. v1 could carry the stage but not the fact:
/// its `evidence_refs` grammar admits only `evidence|assurance-evidence|artifact|receipt`, so the
/// exact `verifier-challenge://` identity being resolved was unrepresentable, and it had no typed
/// resolution or adjudicator lineage. v2 adds exactly that and nothing else.
///
/// THE SUBJECT IS NOT TAKEN FROM HERE. `challenged_subject_ref` and `challenged_subject_content_hash`
/// are RE-STATED by the caller and then overwritten below with the values this transition's own
/// owner-resolved subject already carries, so the two can never disagree; the registered invariants
/// then pin that agreement portably. A caller that asserts a different subject is refused by name
/// rather than silently corrected.
fn validate_challenge_resolution(body: &Value, to_stage: &str) -> Result<Value, Reply> {
    let block = match body.get("challenge_resolution") {
        None | Some(Value::Null) => return Ok(Value::Null),
        Some(Value::Object(_)) => body
            .get("challenge_resolution")
            .cloned()
            .unwrap_or(Value::Null),
        Some(_) => {
            return Err(refuse(
                "assurance_transition_challenge_resolution_malformed",
                "challenge_resolution must be an object or null",
            ))
        }
    };
    if to_stage != ADJUDICATED_STAGE {
        return Err(refuse(
            "assurance_transition_challenge_resolution_outside_adjudication",
            format!(
                "a challenge resolution IS an adjudication; this transition advances to '{to_stage}', and 'resolved' is not claimable at another rung of the ladder"
            ),
        ));
    }
    let permitted = [
        "verifier_challenge_id",
        "challenged_subject_ref",
        "challenged_subject_content_hash",
        "resolution",
        "adjudicator_ref",
        "adjudicator_policy_ref",
        "reviewer_lineage",
        "challenge_contract_ref",
        "challenge_resolved_by",
    ];
    let Some(object) = block.as_object() else {
        return Err(refuse(
            "assurance_transition_challenge_resolution_malformed",
            "challenge_resolution must be an object",
        ));
    };
    if let Some(unknown) = object.keys().find(|key| !permitted.contains(&key.as_str())) {
        return Err(refuse(
            "assurance_transition_challenge_resolution_unknown_field",
            format!(
                "challenge_resolution carries '{unknown}', which the registered contract does not define"
            ),
        ));
    }
    let field = |key: &str| {
        block
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_owned()
    };
    let challenge_id = field("verifier_challenge_id");
    if !challenge_id.starts_with("verifier-challenge://")
        || challenge_id.len() > 480
        || challenge_id
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(refuse(
            "assurance_transition_challenge_id_not_canonical",
            "verifier_challenge_id must be an exact 'verifier-challenge://' identity",
        ));
    }
    let resolution = field("resolution");
    if !RESOLUTIONS.contains(&resolution.as_str()) {
        return Err(refuse(
            "assurance_transition_challenge_resolution_unknown",
            format!("resolution must be one of {RESOLUTIONS:?}"),
        ));
    }
    // AN UPHELD CHALLENGE IS NOT A CLEAN PASS. Coupling the typed resolution to the subject's own
    // outcome class is what stops a sustained finding being recorded as a positive step.
    let outcome_class = str_field(body, "outcome_class");
    let permitted_outcomes = if resolution == "upheld" {
        UPHELD_OUTCOMES
    } else {
        REJECTED_OUTCOMES
    };
    if !permitted_outcomes.contains(&outcome_class) {
        return Err(refuse(
            "assurance_transition_resolution_outcome_disagreement",
            format!(
                "a '{resolution}' challenge resolution cannot carry outcome_class '{outcome_class}'; permitted here: {permitted_outcomes:?}"
            ),
        ));
    }
    let adjudicator_ref = field("adjudicator_ref");
    if !PRINCIPAL_SCHEMES
        .iter()
        .any(|scheme| adjudicator_ref.starts_with(scheme))
    {
        return Err(refuse(
            "assurance_transition_adjudicator_not_canonical",
            "adjudicator_ref must be a canonical principal ref",
        ));
    }
    let policy_ref = field("adjudicator_policy_ref");
    if !policy_ref.starts_with("policy://") || policy_ref.len() > 480 {
        return Err(refuse(
            "assurance_transition_adjudicator_policy_not_canonical",
            "adjudicator_policy_ref must be a 'policy://' ref",
        ));
    }
    let declared_contract = field("challenge_contract_ref");
    if !declared_contract.is_empty() && declared_contract != CHALLENGE_CONTRACT {
        return Err(refuse(
            "assurance_transition_challenge_contract_unsupported",
            format!(
                "a resolution cites {CHALLENGE_CONTRACT}; '{declared_contract}' is refused rather than downgraded into, because the v1 challenged_ref pattern cannot address a semantic-plane subject at all"
            ),
        ));
    }
    let rows = block
        .get("reviewer_lineage")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() || rows.len() > MAX_REVIEWERS {
        return Err(refuse(
            "assurance_transition_resolution_reviewer_required",
            "a resolution names at least one reviewer and at most 32; an unreviewed adjudication is a verdict nobody stands behind",
        ));
    }
    let mut seen: Vec<String> = Vec::with_capacity(rows.len());
    let mut lineage = Vec::with_capacity(rows.len());
    for row in &rows {
        let Some(entry) = row.as_object() else {
            return Err(refuse(
                "assurance_transition_resolution_reviewer_malformed",
                "each reviewer_lineage entry is {reviewer_ref,reviewed_at,review_decision}",
            ));
        };
        if entry.len() != 3
            || !entry.contains_key("reviewer_ref")
            || !entry.contains_key("reviewed_at")
            || !entry.contains_key("review_decision")
        {
            return Err(refuse(
                "assurance_transition_resolution_reviewer_malformed",
                "each reviewer_lineage entry is exactly {reviewer_ref,reviewed_at,review_decision}",
            ));
        }
        let reviewer_ref = row
            .get("reviewer_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let reviewed_at = row
            .get("reviewed_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let decision = row
            .get("review_decision")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !PRINCIPAL_SCHEMES
            .iter()
            .any(|scheme| reviewer_ref.starts_with(scheme))
        {
            return Err(refuse(
                "assurance_transition_resolution_reviewer_not_canonical",
                "reviewer_ref must be a canonical principal ref",
            ));
        }
        if parse_time(&reviewed_at).is_none() {
            return Err(refuse(
                "assurance_transition_resolution_review_time_not_canonical",
                "reviewed_at must be an RFC3339 instant",
            ));
        }
        if !REVIEW_DECISIONS.contains(&decision.as_str()) {
            return Err(refuse(
                "assurance_transition_resolution_review_decision_unknown",
                format!("review_decision must be one of {REVIEW_DECISIONS:?}"),
            ));
        }
        if seen.iter().any(|previous| previous == &reviewer_ref) {
            return Err(refuse(
                "assurance_transition_resolution_reviewer_counted_twice",
                format!("'{reviewer_ref}' already appears in this resolution's lineage"),
            ));
        }
        seen.push(reviewer_ref.clone());
        lineage.push(json!({
            "reviewer_ref": reviewer_ref,
            "reviewed_at": reviewed_at,
            "review_decision": decision,
        }));
    }
    // REBUILT, not forwarded. The subject fields are filled in by the caller of this function from
    // the owner-resolved subject, so nothing the request sent about the subject reaches the chain.
    Ok(json!({
        "verifier_challenge_id": challenge_id,
        "challenged_subject_ref": Value::Null,
        "challenged_subject_content_hash": Value::Null,
        "resolution": resolution,
        "adjudicator_ref": adjudicator_ref,
        "adjudicator_policy_ref": policy_ref,
        "reviewer_lineage": lineage,
        "challenge_contract_ref": CHALLENGE_CONTRACT,
        "challenge_resolved_by": CHALLENGE_RESOLVER,
    }))
}

fn validate_proposal(body: &Value) -> Result<ProposedTransition, Reply> {
    // UNKNOWN CONTRACT VERSIONS ARE REFUSED, NEVER DOWNGRADED. A caller naming a version this build
    // does not implement is told so, rather than having its bytes reinterpreted as v1.
    match body.get("schema_version") {
        None | Some(Value::Null) => {}
        Some(Value::String(declared)) if declared == SCHEMA_VERSION => {}
        Some(_) => {
            return Err(refuse(
                "assurance_transition_unsupported_schema_version",
                format!("this build implements {SCHEMA_VERSION} only; a record naming another version is refused rather than downgraded"),
            ))
        }
    }

    // Assertion TYPES first, so a malformed one can never reach either path as an absence.
    validate_assertion_types(body)?;

    let subject_ref = str_field(body, "subject_ref");
    if subject_ref.is_empty()
        || subject_ref.len() > 460
        || subject_ref
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(refuse(
            "assurance_transition_subject_ref_not_canonical",
            "subject_ref must be a non-empty whitespace-free canonical ref of at most 460 bytes",
        ));
    }

    // OUTCOME CLASS IS TAKEN VERBATIM. There is deliberately no defaulting, no coercion and no
    // mapping table here: a negative result that arrives as `negative` is stored as `negative`
    // (NN 21, ACC-8 clause 2). An absent or unknown member refuses rather than becoming `positive`.
    let outcome_class = str_field(body, "outcome_class");
    if !OUTCOME_CLASSES.contains(&outcome_class) {
        return Err(refuse(
            "assurance_transition_outcome_class_invalid",
            format!(
                "outcome_class must be one of {}; an absent or unknown class is refused rather than normalised toward success",
                OUTCOME_CLASSES.join(", ")
            ),
        ));
    }

    let Some(evidence) = body.get("evidence_refs").and_then(Value::as_array) else {
        return Err(refuse(
            "assurance_transition_evidence_required",
            "each transition names its evidence; a stage asserted with no evidence ref is prose wearing a receipt's shape",
        ));
    };
    if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_REFS {
        return Err(refuse(
            "assurance_transition_evidence_required",
            format!("evidence_refs must carry between 1 and {MAX_EVIDENCE_REFS} refs"),
        ));
    }
    let mut evidence_refs = Vec::with_capacity(evidence.len());
    for entry in evidence {
        let Some(value) = entry.as_str() else {
            return Err(refuse(
                "assurance_transition_evidence_not_canonical",
                "every evidence ref must be a string",
            ));
        };
        if !EVIDENCE_SCHEMES
            .iter()
            .any(|scheme| value.starts_with(scheme))
            || value.len() > 460
            || value.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(refuse(
                "assurance_transition_evidence_not_canonical",
                format!("evidence ref '{value}' must be an evidence://, assurance-evidence://, artifact:// or receipt:// ref"),
            ));
        }
        if evidence_refs.contains(&value.to_string()) {
            return Err(refuse(
                "assurance_transition_evidence_duplicated",
                format!(
                    "evidence ref '{value}' is listed twice; a repeated ref is not more evidence"
                ),
            ));
        }
        evidence_refs.push(value.to_string());
    }

    // THE NONCLAIM SET IS NON-EMPTY BY CONSTRUCTION. This is NN 20 as a field rather than a
    // paragraph: a transition that disclaims nothing has collapsed "who stands behind what" into a
    // bare success flag, which is exactly the reading the ladder exists to refuse.
    let Some(nonclaims) = body.get("does_not_assert").and_then(Value::as_array) else {
        return Err(refuse(
            "assurance_transition_does_not_assert_required",
            "does_not_assert is required and non-empty: a stage that disclaims nothing claims everything",
        ));
    };
    if nonclaims.is_empty() {
        return Err(refuse(
            "assurance_transition_does_not_assert_empty",
            "does_not_assert must name at least one nonclaim; an empty set is the collapse of NN 20 into a success flag",
        ));
    }
    let mut does_not_assert = Vec::with_capacity(nonclaims.len());
    for entry in nonclaims {
        let Some(value) = entry.as_str() else {
            return Err(refuse(
                "assurance_transition_does_not_assert_invalid",
                "every nonclaim must be a string",
            ));
        };
        if !NONCLAIM_TOKENS.contains(&value) {
            return Err(refuse(
                "assurance_transition_does_not_assert_invalid",
                format!(
                    "nonclaim '{value}' is not one of {}",
                    NONCLAIM_TOKENS.join(", ")
                ),
            ));
        }
        if does_not_assert.contains(&value.to_string()) {
            return Err(refuse(
                "assurance_transition_does_not_assert_invalid",
                format!("nonclaim '{value}' is listed twice"),
            ));
        }
        does_not_assert.push(value.to_string());
    }

    let valid_time = validate_valid_time(body)?;

    Ok(ProposedTransition {
        subject_ref: subject_ref.to_string(),
        outcome_class: outcome_class.to_string(),
        evidence_refs: json!(evidence_refs),
        does_not_assert: json!(does_not_assert),
        valid_time,
        // Carried verbatim; it cannot be checked yet because whether this transition IS an
        // adjudication is a fact about the subject's chain position, not about the request.
        challenge_resolution: body
            .get("challenge_resolution")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

/// The fields that make one transition request the SAME LOGICAL COMMAND as another.
///
/// An idempotency key answers "did this exact command already land?", so it is only meaningful
/// alongside the command it keyed. The substrate refuses same-key-different-bytes at the admission
/// boundary, but a replay that is answered from the projected ladder never REACHES that boundary —
/// so without this comparison a caller could reuse a key with a different outcome class, different
/// evidence, a different validity interval or a subject whose owner has since re-hashed it, and
/// receive the ORIGINAL transition back as though the new intent had been recorded. That is a silent
/// substitution of one claim for another, and it is worst exactly where it matters most: quietly
/// answering "yes, your NEGATIVE finding was recorded" with a stored POSITIVE one.
const REPLAY_INTENT_FIELDS: &[&str] = &[
    "subject_ref",
    "subject_content_hash",
    "outcome_class",
    "evidence_refs",
    "does_not_assert",
    "valid_time",
    // Reusing one key to resolve a DIFFERENT challenge, or to flip upheld to rejected, is a
    // different logical command wearing the same key.
    "challenge_resolution",
];

/// Compare a prior admitted transition against the intent of the request now replaying its key.
///
/// Returns the name of the FIRST field that differs, so the refusal names the actual divergence
/// rather than reporting a generic conflict a caller cannot act on.
fn replay_intent_divergence(
    prior: &Value,
    proposal: &ProposedTransition,
    subject: &ResolvedSubject,
    body: &Value,
) -> Option<&'static str> {
    let now = json!({
        "subject_ref": proposal.subject_ref,
        "subject_content_hash": subject.content_hash,
        "outcome_class": proposal.outcome_class,
        "evidence_refs": proposal.evidence_refs,
        "does_not_assert": proposal.does_not_assert,
        "valid_time": proposal.valid_time,
        "challenge_resolution": proposal.challenge_resolution,
    });
    if let Some(field) = REPLAY_INTENT_FIELDS
        .iter()
        .find(|field| prior.get(*field) != now.get(*field))
    {
        return Some(field);
    }
    // A caller that ASSERTS a stage is asserting one about THIS command. A key replayed under a
    // different asserted stage is a different command even when every content field matches.
    match body.get("to_stage").and_then(Value::as_str) {
        Some(asserted) if Some(asserted) != prior.get("to_stage").and_then(Value::as_str) => {
            Some("to_stage")
        }
        _ => None,
    }
}

/// Check a replaying caller's ASSERTIONS ABOUT SERVER-DERIVED FACTS against the exact command this
/// key already admitted.
///
/// The semantic comparison above asks "is this the same command?". This asks a different question
/// that the ordinary admission path asks and the replay path previously skipped: "are the things
/// this caller CLAIMS to know about the server's own derivation actually true?"
///
/// The two are not the same, and the gap between them was reachable. Every one of these fields is
/// OPTIONAL and is compared, on the ordinary path, against a value the server derived — the subject
/// owner's current hash, the ladder's current predecessor, the next ordinal, the hash the content
/// commits to. On a replay none of that ran, so a request whose six semantic fields matched could
/// still carry a contradictory `expected_content_hash` or a fabricated predecessor and receive
/// `200 replayed: true`. A success response is read as "everything you asserted holds", so
/// answering one while a caller's assertion is false is the receipt telling a lie about itself.
///
/// Compared against the STORED command, not against today's derivation: the stored transition IS
/// what that key admitted, and its own recorded values are the only correct answer to "what did the
/// server derive when this landed?".
///
/// `expected_head` is DELIBERATELY ABSENT. A genuine retry follows an ambiguous response and
/// necessarily still carries the head it originally compare-and-swapped against, which is stale by
/// construction; refusing it would break the exact case the idempotency key exists to serve.
/// Server-authored identity fields are absent for the opposite reason: a caller never authors them,
/// so there is no assertion to check.
fn replay_assertion_divergence(prior: &Value, body: &Value) -> Option<Reply> {
    let stored = |key: &str| prior.get(key).cloned().unwrap_or(Value::Null);

    if let Some(asserted) = body.get("subject_content_hash") {
        if *asserted != stored("subject_content_hash") {
            return Some(refuse(
                "assurance_transition_subject_hash_substituted",
                "subject_content_hash does not match the hash the transition this key already admitted was bound to; a replay confirms one exact command and never accepts a new claim about its subject",
            ));
        }
    }
    if let Some(asserted) = body.get("subject_family") {
        if *asserted != stored("subject_family") {
            return Some(refuse(
                "assurance_transition_subject_family_substituted",
                "subject_family does not match the family the transition this key already admitted names",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_transition_ref") {
        if *asserted != stored("expected_predecessor_transition_ref") {
            return Some(refuse(
                "assurance_transition_predecessor_substituted",
                "expected_predecessor_transition_ref does not name the predecessor the transition this key already admitted advanced from",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_transition_hash") {
        if *asserted != stored("expected_predecessor_transition_hash") {
            return Some(refuse(
                "assurance_transition_predecessor_hash_substituted",
                "expected_predecessor_transition_hash does not match the predecessor hash the transition this key already admitted advanced from",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_transition_ordinal") {
        if *asserted != stored("transition_ordinal") {
            return Some(refuse(
                "assurance_transition_ordinal_gap",
                "expected_transition_ordinal does not match the ladder position the transition this key already admitted occupies",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_content_hash") {
        if *asserted != stored("content_hash") {
            return Some(refuse(
                "assurance_transition_content_hash_substituted",
                "expected_content_hash does not match the hash the transition this key already admitted commits to",
            ));
        }
    }
    None
}

// ----------------------------------------------------------------------- durable ladder projection

/// One admitted transition, exactly as the chain holds it.
struct AdmittedTransition {
    /// The contract version this frame was WRITTEN under, carried so the projection validates each
    /// record against its own registered contract instead of the current one.
    version: String,
    record: Value,
    head: String,
    seq: u64,
    admission_batch_seq: u64,
    admission_root: String,
    expected_predecessor_head: Value,
    recorded_at_ms: u64,
}

fn project_admitted(entry: &ExactProjection) -> Result<AdmittedTransition, String> {
    if entry.operation.op_kind != ADMIT_OP {
        return Err(format!(
            "assurance-transition stream carries an unknown operation '{}'",
            entry.operation.op_kind
        ));
    }
    let payload = &entry.operation.payload;
    if payload.get("schema_version").and_then(Value::as_str) != Some(ADMISSION_PAYLOAD_SCHEMA) {
        return Err("assurance-transition admission carries an unknown payload schema".into());
    }
    let record = payload
        .get("transition_record")
        .cloned()
        .ok_or_else(|| "assurance-transition admission carries no transition record".to_string())?;
    // THE READ SIDE REFUSES AN UNKNOWN CONTRACT VERSION TOO. A frame written by a build this one does
    // not implement is reported as unreadable rather than projected as though it were v1.
    let version = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if (version != SCHEMA_VERSION && version != PREDECESSOR_SCHEMA_VERSION)
        || record.get("receipt_type").and_then(Value::as_str) != Some(RECEIPT_TYPE)
    {
        return Err(format!(
            "assurance-transition chain holds a record this build does not implement (expected {SCHEMA_VERSION} or {PREDECESSOR_SCHEMA_VERSION} / {RECEIPT_TYPE})"
        ));
    }
    // The served content hash is RE-DERIVED, never trusted, and re-derived under the commitment the
    // record's OWN version declared — so an older frame is checked as what it is rather than
    // reported as tampered for not being the current version.
    let derived = content_hash_for_version(&record, &version)?;
    if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
        return Err(
            "assurance-transition admitted content does not match its committed hash".into(),
        );
    }
    Ok(AdmittedTransition {
        version,
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
    })
}

/// Assemble the registered contract document for one admitted transition.
///
/// `superseded_at` closes the predecessor's TRANSACTION interval when a later stage lands. Nothing
/// inside the content commitment moves, which is why an earlier stage stays addressable and
/// uninterpreted after the ladder advances past it.
fn contract_document(
    transition: &AdmittedTransition,
    subject_ref: &str,
    superseded_at: Option<&str>,
) -> Result<Value, String> {
    let mut document = transition.record.clone();
    let transition_id = document
        .get("transition_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "admitted transition carries no transition_id".to_string())?
        .to_string();
    let content_hash = document
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tail = stream_tail(RESOURCE_KIND, subject_ref);
    document["admission_domain_ref"] = json!(format!(
        "agentgres://domain/{}",
        agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
    ));
    document["transaction_time"] = json!({
        "recorded_at": admitted_stamp(transition.recorded_at_ms),
        "superseded_at": superseded_at.map_or(Value::Null, |value| json!(value)),
    });
    document["admission"] = json!({
        "transition_id": transition_id,
        "content_hash": content_hash,
        "owner_namespace": OWNER_NAMESPACE,
        "stream_tail": tail,
        "agentgres_operation_ref": agentgres::refs::event_stream_operation_ref(
            OWNER_NAMESPACE, &tail, transition.seq, &transition.head,
        ),
        "agentgres_receipt_ref": agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE, &tail, transition.admission_batch_seq, &transition.admission_root,
        ),
        "admission_seq": transition.seq,
        "admission_head": transition.head,
        "admission_root": transition.admission_root,
        "expected_predecessor_head": transition.expected_predecessor_head,
    });
    document["authority_nonclaim"] = json!(AUTHORITY_NONCLAIM);
    document["verdict_nonclaim"] = json!(VERDICT_NONCLAIM);
    let contract = if transition.version == PREDECESSOR_SCHEMA_VERSION {
        PREDECESSOR_CONTRACT_ID
    } else {
        CONTRACT_ID
    };
    validate_architecture_contract(contract, &document).map_err(|reason| {
        format!("projected assurance transition is not registered-valid: {reason}")
    })?;
    Ok(document)
}

/// The whole ladder of one subject, rebuilt from the chain and contract-validated.
fn project_ladder(history: &[ExactProjection], subject_ref: &str) -> Result<Vec<Value>, String> {
    let transitions = history
        .iter()
        .map(project_admitted)
        .collect::<Result<Vec<_>, _>>()?;
    let mut documents = Vec::with_capacity(transitions.len());
    for (index, transition) in transitions.iter().enumerate() {
        let superseded_at = transitions
            .get(index + 1)
            .map(|next| admitted_stamp(next.recorded_at_ms));
        documents.push(contract_document(
            transition,
            subject_ref,
            superseded_at.as_deref(),
        )?);
    }
    Ok(documents)
}

fn ordinal_of(document: &Value) -> u64 {
    document
        .get("transition_ordinal")
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

// ------------------------------------------------------------- rebuildable, process-local, non-truth

/// One (admitted head, transition count) pair per AUTHORIZED READER AND SUBJECT. Process-local and
/// never durable.
static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

/// The cache key: the authorized reader's identity AND the subject, never the subject alone.
///
/// Keying by `subject_ref` alone would make one entry shared by every principal who can name that
/// subject, and the reported state is OBSERVABLE. A reader would then see `stale_rebuilt_…` exactly
/// when somebody else's ladder had moved — a status side channel that leaks the existence and
/// activity of another principal's transitions without ever returning one of their rows, which is
/// precisely the inference the owner-scoped refusal is built to deny. The cache stays non-truth
/// either way; this keeps it from also being a signal.
fn projection_cache_key(scope: &RequestResourceScope, subject_ref: &str) -> String {
    sha256_of(
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            scope.principal_ref, scope.tenant_ref, scope.owner_ref, subject_ref
        )
        .as_bytes(),
    )
}

/// Record what the cache held for this reader-and-subject BEFORE the freshly projected ladder
/// replaced it.
///
/// The ladder is already computed when this is called, so the cache cannot contribute to the answer —
/// it is consulted only to report agreement. Reporting it lets a verifier assert rebuild by POSITIVE
/// detection: an unchanged answer is also consistent with a cache that was never dropped.
fn projection_cache_state(cache_key: &str, ladder: &[Value]) -> &'static str {
    let head = ladder
        .last()
        .and_then(|document| document.pointer("/admission/admission_head"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let observed = (head, ladder.len());
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

// --------------------------------------------------------------------------------- read path helpers

/// Read one subject's ladder, optionally AS IT STOOD at a transaction instant.
///
/// THE SLICE IS TAKEN BEFORE THE PROJECTION, NOT AFTER, and that ordering is the whole correctness
/// of transaction-time travel here. `project_ladder` derives each row's `superseded_at` from the
/// transition that FOLLOWS it, so projecting the whole chain and then filtering rows would hand a
/// caller asking "as of T" a row stamped with a supersession that had not happened at T — a fact
/// from its future, leaked through a field the caller did not select on. Truncating the history
/// first means the slice is projected as a complete ladder in its own right: the last row in it is
/// genuinely open, and the count and reached stage are the ones that were true then.
///
/// The chain is append-only and admission timestamps are monotonic along it, so the slice is a
/// prefix.
fn read_ladder_as_of(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    subject_ref: &str,
    as_of_ms: Option<u64>,
) -> Result<Vec<Value>, Reply> {
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        RESOURCE_KIND,
        subject_ref,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, subject_ref),
    )
    .map_err(mutation_refusal_reply)?;
    let sliced: Vec<ExactProjection> = match as_of_ms {
        None => history,
        Some(as_of) => history
            .into_iter()
            .filter(|entry| entry.operation.recorded_at_ms <= as_of)
            .collect(),
    };
    project_ladder(&sliced, subject_ref).map_err(|reason| {
        bad(
            StatusCode::BAD_GATEWAY,
            "assurance_transition_projection_failed",
            reason,
        )
    })
}

fn read_ladder(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    subject_ref: &str,
) -> Result<Vec<Value>, Reply> {
    read_ladder_as_of(data_dir, identity, scope, subject_ref, None)
}

/// Authorize, then read. Returns the bound scope so the caller can key its non-truth cache by the
/// READER as well as the subject.
fn authorized_ladder_as_of(
    data_dir: &str,
    identity: &RequestIdentity,
    subject_ref: &str,
    as_of_ms: Option<u64>,
) -> Result<(Vec<Value>, RequestResourceScope), Reply> {
    let scope =
        authorize_request_resource_scope(data_dir, identity, RESOURCE_KIND, subject_ref, None)
            .map_err(scope_refusal_reply)?;
    let ladder = read_ladder_as_of(data_dir, identity, &scope, subject_ref, as_of_ms)?;
    Ok((ladder, scope))
}

// ------------------------------------------------------------------------------------ producer route

/// POST /v1/hypervisor/assurance-transitions — admit one ladder step over one owner-resolved subject
/// against the exact current head of that subject's Agentgres chain.
pub(crate) async fn handle_assurance_transition_admit(
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
    let proposal = match validate_proposal(&body) {
        Ok(proposal) => proposal,
        Err(response) => return response,
    };

    // THE SUBJECT IS RESOLVED BEFORE ANY SCOPE IS BOUND OR ANY BYTE IS WRITTEN. A family with no
    // landed resolver stops here, so an unresolvable subject can never acquire a stream, a scope or a
    // durable transition on the strength of its spelling.
    let subject = match resolve_subject(
        &st.data_dir,
        &caller.identity,
        &headers,
        &proposal.subject_ref,
    ) {
        Ok(subject) => subject,
        Err(response) => return response,
    };

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &proposal.subject_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let ladder = match read_ladder(
        &st.data_dir,
        &caller.identity,
        &scope,
        &proposal.subject_ref,
    ) {
        Ok(ladder) => ladder,
        Err(response) => return response,
    };
    let predecessor = ladder.last().cloned();

    // REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer
    // head than the one it originally compare-and-swapped against, so checking `expected_head` first
    // would turn every real duplicate into a conflict and make the idempotency key unusable.
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        RESOURCE_KIND,
        &proposal.subject_ref,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, &proposal.subject_ref),
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let Some(document) = ladder
                .iter()
                .find(|document| {
                    document.pointer("/admission/admission_head") == Some(&json!(prior.head))
                })
                .cloned()
            else {
                return bad(
                    StatusCode::BAD_GATEWAY,
                    "assurance_transition_projection_disagrees_with_ack",
                    "this key's admitted head is absent from the subject's projected ladder",
                );
            };
            // REPLAY ONLY AN IDENTICAL COMMAND. Reaching the stored answer without first comparing
            // what is being asked would turn the idempotency key into a way to receive one claim in
            // answer to a different one.
            if let Some(field) = replay_intent_divergence(&document, &proposal, &subject, &body) {
                return bad(
                    StatusCode::CONFLICT,
                    "assurance_transition_replay_intent_changed",
                    format!(
                        "this idempotency key already admitted a transition whose '{field}' differs from this request; a key replays one exact command and is never a way to receive a stored transition in answer to a changed one"
                    ),
                );
            }
            // AND THE CALLER'S ASSERTIONS STILL HAVE TO BE TRUE. Ordinary admission checks every
            // caller-supplied claim about a server-derived fact; returning the stored success
            // without running those checks would let a `200 replayed: true` stand as confirmation
            // of assertions nobody ever compared.
            if let Some(response) = replay_assertion_divergence(&document, &body) {
                return response;
            }
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "assurance_transition": document,
                    "expected_head_for_successor": ladder
                        .last()
                        .and_then(|head| head.pointer("/admission/admission_head"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "receipt_ref": document.pointer("/admission/agentgres_receipt_ref").cloned().unwrap_or(Value::Null),
                    "operation_ref": document.pointer("/admission/agentgres_operation_ref").cloned().unwrap_or(Value::Null),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
                    "verdict_nonclaim": VERDICT_NONCLAIM,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }

    let expected_head = match body.get("expected_head") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return refuse(
                "assurance_transition_expected_head_not_canonical",
                "expected_head must be the exact current Agentgres head of this subject's ladder, or null for the first transition",
            )
        }
    };
    let current_head = predecessor
        .as_ref()
        .and_then(|document| document.pointer("/admission/admission_head"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if expected_head != current_head {
        return bad(
            StatusCode::CONFLICT,
            "assurance_transition_expected_head_conflict",
            match (&expected_head, &current_head) {
                (None, Some(_)) => "this subject already has transitions; a successor must name the exact current head".to_string(),
                (Some(_), None) => "this subject has no transitions yet; the first transition names no predecessor head".to_string(),
                _ => "expected_head does not name the exact current head of this subject's ladder; re-read the head and re-derive the transition".to_string(),
            },
        );
    }

    // THE LADDER POSITION IS DERIVED, NOT ACCEPTED. Chain length decides which member comes next, so
    // a caller cannot reach `settled` by asking for it.
    let ordinal = predecessor
        .as_ref()
        .map_or(1, |document| ordinal_of(document) as usize + 1);
    if ordinal > STAGES.len() {
        return refuse(
            "assurance_transition_ladder_exhausted",
            "this subject has already reached the final ladder member; there is no stage past settled",
        );
    }
    let to_stage = STAGES[ordinal - 1];
    // THE RESOLUTION IS CHECKED WHERE THE STAGE IS KNOWN, and its subject fields are then filled in
    // from the OWNER-RESOLVED subject rather than from the request, so the receipt's own subject and
    // the subject it claims to have adjudicated cannot disagree even in principle.
    let mut challenge_resolution = match validate_challenge_resolution(&body, to_stage) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if challenge_resolution.is_object() {
        challenge_resolution["challenged_subject_ref"] = json!(proposal.subject_ref);
        challenge_resolution["challenged_subject_content_hash"] = json!(subject.content_hash);
        if let Some(asserted) = body
            .pointer("/challenge_resolution/challenged_subject_ref")
            .and_then(Value::as_str)
        {
            if asserted != proposal.subject_ref {
                return refuse(
                    "assurance_transition_resolution_subject_substituted",
                    "challenged_subject_ref does not name the subject this transition is about; a resolution of a challenge against another subject is a different fact",
                );
            }
        }
        if let Some(asserted) = body
            .pointer("/challenge_resolution/challenged_subject_content_hash")
            .and_then(Value::as_str)
        {
            if asserted != subject.content_hash {
                return refuse(
                    "assurance_transition_resolution_subject_hash_substituted",
                    "challenged_subject_content_hash does not match the bytes the subject owner resolved for this subject",
                );
            }
        }
    }
    let from_stage = if ordinal == 1 {
        Value::Null
    } else {
        json!(STAGES[ordinal - 2])
    };

    // A caller may ASSERT the stage it believes it is reaching; a disagreement is refused BY ITS OWN
    // CAUSE. This is the runtime half of the no-skip rule — the registered invariant is the other,
    // and it holds offline where this code is not present.
    if let Some(asserted) = body.get("to_stage").and_then(Value::as_str) {
        if asserted != to_stage {
            let asserted_position = STAGES.iter().position(|stage| *stage == asserted);
            return refuse(
                "assurance_transition_stage_skip",
                match asserted_position {
                    Some(position) if position + 1 > ordinal => format!(
                        "this subject's next ladder member is '{to_stage}' at position {ordinal}, not '{asserted}' at position {}; a stage is not reached by skipping the one before it",
                        position + 1
                    ),
                    Some(_) => format!(
                        "this subject's next ladder member is '{to_stage}'; '{asserted}' is already behind it and the ladder does not move backwards"
                    ),
                    None => format!("'{asserted}' is not a member of the assurance ladder"),
                },
            );
        }
    }
    if let Some(asserted) = body
        .get("expected_transition_ordinal")
        .and_then(Value::as_u64)
    {
        if asserted as usize != ordinal {
            return refuse(
                "assurance_transition_ordinal_gap",
                format!("this subject's next transition is {ordinal}, not {asserted}; ladder positions are contiguous and never skip"),
            );
        }
    }

    let predecessor_ref = predecessor
        .as_ref()
        .and_then(|document| document.get("transition_id").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .as_ref()
        .and_then(|document| document.get("content_hash").cloned())
        .unwrap_or(Value::Null);
    if let Some(asserted) = body.get("expected_predecessor_transition_ref") {
        if asserted != &predecessor_ref {
            return refuse(
                "assurance_transition_predecessor_substituted",
                "expected_predecessor_transition_ref does not name this subject's exact current transition",
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_transition_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "assurance_transition_predecessor_hash_substituted",
                "expected_predecessor_transition_hash does not match this subject's exact current content hash",
            );
        }
    }

    // A pre-acceptance stage may not omit the acceptance/settlement nonclaims. Enforced here as well
    // as in the schema so the refusal names the ladder fact rather than surfacing as a shape error.
    if PRE_ACCEPTANCE_STAGES.contains(&to_stage) {
        let declared: Vec<&str> = proposal
            .does_not_assert
            .as_array()
            .map(|entries| entries.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if let Some(missing) = REQUIRED_PRE_ACCEPTANCE_NONCLAIMS
            .iter()
            .find(|required| !declared.contains(*required))
        {
            return refuse(
                "assurance_transition_nonclaim_incomplete",
                format!(
                    "a transition to '{to_stage}' must explicitly disclaim '{missing}': a stage short of acceptance that does not say so is read as acceptance by omission"
                ),
            );
        }
    }

    // The subject family and its owner-resolved hash are SERVER facts. A caller may assert them; a
    // disagreement refuses rather than being accepted as a substitution.
    if let Some(asserted) = body.get("subject_content_hash").and_then(Value::as_str) {
        if asserted != subject.content_hash {
            return refuse(
                "assurance_transition_subject_hash_substituted",
                "subject_content_hash does not match the hash this subject's own owner currently commits to; the binding is the owner's, never the caller's",
            );
        }
    }
    if let Some(asserted) = body.get("subject_family").and_then(Value::as_str) {
        if asserted != subject.family.label() {
            return refuse(
                "assurance_transition_subject_family_substituted",
                "subject_family does not match the family this subject_ref actually names",
            );
        }
    }

    let transition_id = transition_ref(subject.family, &proposal.subject_ref, ordinal);
    let mut record = json!({
        "schema_version": SCHEMA_VERSION,
        "receipt_id": format!("receipt://{}", &transition_id["assurance-transition://".len()..]),
        "receipt_type": RECEIPT_TYPE,
        "receipt_profile_ref": RECEIPT_PROFILE_REF,
        "transition_id": transition_id,
        "subject_ref": proposal.subject_ref,
        "subject_family": subject.family.label(),
        "subject_content_hash": subject.content_hash,
        "subject_resolved_by": subject.resolved_by,
        "from_stage": from_stage,
        "to_stage": to_stage,
        "to_stage_ordinal": ordinal,
        "transition_ordinal": ordinal,
        "outcome_class": proposal.outcome_class,
        // THE ACTOR IS THE AUTHENTICATED PRINCIPAL, FULL STOP.
        //
        // Deliberately `identity.principal_ref` and NOT `owner_ref`. `owner_ref` is request-scoped
        // OWNER CONTEXT that the caller supplies in the body; it is authorized as a tenant the
        // caller may act within, which is a different question from WHO ACTED. Two principals in one
        // organization share an `owner_ref`, so recording it as the actor would make every
        // transition in that org attributable to the org rather than to the principal who stood
        // behind it — and it would let the caller choose its own attribution from a set it is
        // merely a member of. "Who stands behind this stage" is never a field a request authors.
        "actor_ref": caller.identity.principal_ref,
        "evidence_refs": proposal.evidence_refs,
        "does_not_assert": proposal.does_not_assert,
        "valid_time": proposal.valid_time,
        "expected_predecessor_transition_ref": predecessor_ref,
        "expected_predecessor_transition_hash": predecessor_hash,
        "predecessor_contract_ref": PREDECESSOR_CONTRACT_ID,
        "challenge_resolution": challenge_resolution,
    });
    let derived_hash = match content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "assurance_transition_content_hash_failed",
                reason,
            )
        }
    };
    if let Some(asserted) = body.get("expected_content_hash").and_then(Value::as_str) {
        if asserted != derived_hash {
            return refuse(
                "assurance_transition_content_hash_substituted",
                "expected_content_hash does not match the hash this exact content commits to",
            );
        }
    }
    record["content_hash"] = json!(derived_hash);
    // The resulting stage head is this transition's own committed hash: after this admission, the
    // subject's ladder head IS these bytes.
    record["resulting_stage_head_hash"] = json!(derived_hash);

    let payload = json!({
        "schema_version": ADMISSION_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": proposal.subject_ref,
        "transition_record": record,
    });
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    // The SHARED admission boundary — the same one every owner-scoped daemon mutation crosses.
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        expected_head.is_none(),
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &proposal.subject_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &stream_tail(RESOURCE_KIND, &proposal.subject_ref),
            op_kind: ADMIT_OP,
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
    let ladder = match read_ladder(
        &st.data_dir,
        &caller.identity,
        &scope,
        &proposal.subject_ref,
    ) {
        Ok(ladder) => ladder,
        Err(response) => return response,
    };
    let Some(admitted) = ladder
        .iter()
        .find(|document| {
            document.pointer("/admission/admission_head") == Some(&json!(commit.projection.head))
        })
        .cloned()
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            "assurance_transition_projection_disagrees_with_ack",
            "the admitted head is absent from this subject's projected ladder",
        );
    };
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "assurance_transition": admitted,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "verdict_nonclaim": VERDICT_NONCLAIM,
        })),
    )
}

// ------------------------------------------------------------------------------------ consumer route

#[derive(serde::Deserialize)]
pub(crate) struct LadderQuery {
    subject_ref: Option<String>,
    to_stage: Option<String>,
    outcome_class: Option<String>,
    as_of_transaction_time: Option<String>,
}

/// GET /v1/hypervisor/assurance-transitions — one subject's whole ladder, or a transaction-time cell.
///
/// With no `subject_ref` this answers the caller's subject inventory. With one it answers that
/// subject's ladder, optionally narrowed by `to_stage`, `outcome_class` and `as_of_transaction_time`
/// ("as the ladder stood then"). The outcome narrowing exists so that NEGATIVE results are queryable
/// as first-class, which is ACC-8 clause 2: a ladder whose failures cannot be asked for has not
/// retained them in any sense that matters.
pub(crate) async fn handle_assurance_transition_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<LadderQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(subject_ref) = query.subject_ref.as_deref() else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "assurance_subjects": refs.into_iter().collect::<Vec<_>>(),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
                    "verdict_nonclaim": VERDICT_NONCLAIM,
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if SubjectFamily::classify(subject_ref).is_none() {
        return refuse(
            "assurance_transition_subject_scheme_unknown",
            "subject_ref must name one of the registered assurance subject families",
        );
    }
    if let Some(stage) = query.to_stage.as_deref() {
        if !STAGES.contains(&stage) {
            return refuse(
                "assurance_transition_stage_unknown",
                format!("to_stage must be one of {}", STAGES.join(", ")),
            );
        }
    }
    if let Some(outcome) = query.outcome_class.as_deref() {
        if !OUTCOME_CLASSES.contains(&outcome) {
            return refuse(
                "assurance_transition_outcome_class_invalid",
                format!(
                    "outcome_class must be one of {}",
                    OUTCOME_CLASSES.join(", ")
                ),
            );
        }
    }

    // TRANSACTION TIME IS RESOLVED FIRST, because it selects WHICH LADDER is being asked about. The
    // stage and outcome narrowings then select rows WITHIN that ladder. Doing it the other way round
    // would make every aggregate below a fact about the present wearing a historical query's answer.
    let as_of_ms = match query.as_of_transaction_time.as_deref() {
        None => None,
        Some(as_of) => match parse_time(as_of) {
            Some(parsed) => Some(parsed),
            None => {
                return refuse(
                    "assurance_transition_as_of_transaction_time_not_parseable",
                    "as_of_transaction_time must be an RFC3339 instant",
                )
            }
        },
    };

    let (ladder, scope) =
        match authorized_ladder_as_of(&st.data_dir, &identity, subject_ref, as_of_ms) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    // A HISTORICAL SLICE NEVER TOUCHES THE CACHE. The cache reports agreement about the subject's
    // CURRENT head; letting a time-travel read write a truncated head into it would make the next
    // ordinary read report a spurious `stale_rebuilt_…`, turning a question about the past into a
    // false statement about the present.
    let index_state = if as_of_ms.is_some() {
        "not_consulted_historical_slice"
    } else {
        projection_cache_state(&projection_cache_key(&scope, subject_ref), &ladder)
    };

    let mut visible: Vec<&Value> = ladder.iter().collect();
    if let Some(stage) = query.to_stage.as_deref() {
        visible.retain(|document| document.get("to_stage").and_then(Value::as_str) == Some(stage));
    }
    if let Some(outcome) = query.outcome_class.as_deref() {
        visible.retain(|document| {
            document.get("outcome_class").and_then(Value::as_str) == Some(outcome)
        });
    }

    // The reached stage is the LAST member of THE LADDER AS ASKED FOR — the historical slice under a
    // transaction-time query, the whole chain otherwise. A stage/outcome narrowing selects rows; it
    // never changes how far the subject had got.
    let reached_stage = ladder
        .last()
        .and_then(|document| document.get("to_stage").cloned())
        .unwrap_or(Value::Null);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "subject_ref": subject_ref,
            "as_of_transaction_time": query.as_of_transaction_time,
            "transition_count": ladder.len(),
            "matched_transition_count": visible.len(),
            "reached_stage": reached_stage,
            "transitions": visible.into_iter().cloned().collect::<Vec<_>>(),
            "rebuildable_index_state": index_state,
            "truth_source": "agentgres_owner_scoped_chain",
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "verdict_nonclaim": VERDICT_NONCLAIM,
        })),
    )
}

// ============================================================== the Verified Work Graph projection
//
// M06.1. `economic-flywheel-and-pricing-boundaries.md` § Verified Work Graph says the graph "is not
// a single database, chain, or UI" and that it "preserves these states independently". Both
// sentences are implemented literally below: this endpoint OWNS NO BYTES. Every value it answers is
// re-derived, on each request, from two existing owners — the WorkResult owner's admitted record and
// that subject's Agentgres assurance chain. Delete nothing, corrupt nothing, restart anything: the
// answer is recomputed or it is refused.

const GRAPH_CONTRACT_ID: &str = "schema://ioi/foundations/verified-work-graph-projection/v1";
const GRAPH_SCHEMA_VERSION: &str = "ioi.verified-work-graph-projection.v1";
const GRAPH_FAMILY_PREFIX: &str = "schema://ioi/foundations/verified-work-graph-projection/";
const GRAPH_AUTHORITY_NONCLAIM: &str = "verified_work_graph_grants_no_authority";
const GRAPH_VERDICT_NONCLAIM: &str = "verified_work_graph_is_not_a_verdict";

/// The closed nonclaim set this projection carries on EVERY answer.
///
/// "Verified" in the graph's name is an assurance PATH, not a claim that anything here is true,
/// accepted, adjudicated, settled, or worth money. Canon states the negative list; carrying it as
/// data rather than prose is what stops a consumer reading a claim in by omission.
const GRAPH_NONCLAIMS: &[&str] = &[
    "authority",
    "verdict",
    "correctness",
    "acceptance",
    "adjudication",
    "settlement",
    "payment_or_economic_value",
    "external_world_occurrence",
    "deployment",
    "provider_connectivity",
    "legality",
    "live_medical_suitability",
];

#[derive(serde::Deserialize)]
pub(crate) struct GraphQuery {
    work_result_ref: Option<String>,
    projection_contract_ref: Option<String>,
}

/// GET /v1/hypervisor/verified-work-graph — one WorkResult's assurance posture, rebuilt.
///
/// THE STAGES ARE EXPOSED INDEPENDENTLY. Each of the six frozen ladder members gets its own row with
/// its own `reached` flag, so nothing about `accepted` can be inferred from `verified`, and nothing
/// about `settled` from `accepted`. A ladder that stopped at `evidenced` answers four rows with
/// `reached: false` and null everything — which is a different statement from "not applicable" and a
/// very different statement from "fine".
///
/// OUTCOMES ARE CARRIED VERBATIM ON BOTH SIDES. The WorkResult vocabulary and the assurance
/// vocabulary overlap in five members and disagree in three (`exploit_found` vs `exploit`; the
/// ladder alone has `disputed` and `no_fault`). They are reported in separate fields and NEITHER is
/// mapped onto the other. Collapsing them would be the normalisation NN 21 forbids, wearing the
/// costume of a convenience.
pub(crate) async fn handle_verified_work_graph(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<GraphQuery>,
) -> Reply {
    // THE CONSUMER'S CONTRACT VERSION IS SETTLED BEFORE ANYTHING IS READ. A consumer that asks for a
    // version this build does not emit is refused, never quietly served v1 bytes under its own
    // preferred label — that is the downgrade this gate exists to deny.
    if let Some(asked) = query.projection_contract_ref.as_deref() {
        if asked != GRAPH_CONTRACT_ID {
            let (code, message) = if asked.starts_with(GRAPH_FAMILY_PREFIX) {
                (
                    "verified_work_graph_contract_version_downgraded",
                    format!(
                        "this build emits '{GRAPH_CONTRACT_ID}' only; '{asked}' names another version of the same family and is refused rather than served under a label it did not produce"
                    ),
                )
            } else {
                (
                    "verified_work_graph_contract_version_unknown",
                    format!(
                        "'{asked}' is not a Verified Work Graph projection contract; this build emits '{GRAPH_CONTRACT_ID}'"
                    ),
                )
            };
            return refuse(code, message);
        }
    }

    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(work_result_ref) = query.work_result_ref.as_deref() else {
        return refuse(
            "verified_work_graph_work_result_ref_required",
            "work_result_ref must name the exact work-result:// subject this projection is about",
        );
    };
    // A PREFIX IS NOT PROOF, RESTATED AT THE CONSUMER. The classifier keeps the graph from being
    // pointed at an ontology revision or a finding and answering as though it had a WorkResult.
    if SubjectFamily::classify(work_result_ref) != Some(SubjectFamily::WorkResult) {
        return refuse(
            "verified_work_graph_subject_family_invalid",
            "work_result_ref must be a work-result:// identity; this projection is over WorkResult owner truth only",
        );
    }

    // OWNER TRUTH FIRST. The WorkResult owner answers whether this reader may see this result at
    // all, and what bytes it currently commits. If it refuses, no ladder is read and no scope is
    // bound — a graph over a result the caller cannot see must not become an existence oracle.
    let reader = match work_truth_visibility_reader(&st.data_dir, &headers) {
        Ok(reader) => reader,
        Err((status, body)) => return (status, body),
    };
    let resolved =
        match resolve_admitted_work_result(&st.data_dir, reader.as_deref(), work_result_ref) {
            Ok(resolved) => resolved,
            Err((code, message)) => return bad(StatusCode::UNPROCESSABLE_ENTITY, &code, message),
        };

    // NO BOUND SCOPE MEANS NO LADDER VISIBLE TO THIS CALLER — which is an ANSWER, not a refusal.
    //
    // This is the one place the graph deliberately differs from the assurance query route, and the
    // reason is indistinguishability. A WorkResult that nobody has attested yet and a WorkResult
    // whose ladder belongs to another principal must look the same to this caller; if the first
    // answered "none" and the second answered 403, the status code would itself be the oracle,
    // announcing that somebody else's assurance exists. Both therefore answer the empty graph.
    // EVERY OTHER scope refusal — unauthenticated, invalid principal, tenant authority, substrate
    // unavailable — still propagates unchanged, so this widens nothing.
    let (ladder, index_state) = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        RESOURCE_KIND,
        work_result_ref,
        None,
    ) {
        Ok(scope) => {
            let ladder = match read_ladder(&st.data_dir, &identity, &scope, work_result_ref) {
                Ok(ladder) => ladder,
                Err(response) => return response,
            };
            let state =
                projection_cache_state(&projection_cache_key(&scope, work_result_ref), &ladder);
            (ladder, state)
        }
        Err(RequestScopeRefusal::ResourceScopeRequired) => {
            (Vec::new(), "not_consulted_no_bound_scope")
        }
        Err(other) => return scope_refusal_reply(other),
    };

    // ---- the six frozen members, each answered on its own terms
    let mut stages = Vec::with_capacity(STAGES.len());
    for (index, stage) in STAGES.iter().enumerate() {
        let row = ladder
            .iter()
            .find(|document| document.get("to_stage").and_then(Value::as_str) == Some(*stage));
        stages.push(json!({
            "stage": stage,
            "stage_ordinal": index + 1,
            "reached": row.is_some(),
            "transition_ref": row.and_then(|d| d.get("transition_id").cloned()).unwrap_or(Value::Null),
            "transition_content_hash": row.and_then(|d| d.get("content_hash").cloned()).unwrap_or(Value::Null),
            "outcome_class": row.and_then(|d| d.get("outcome_class").cloned()).unwrap_or(Value::Null),
            "actor_ref": row.and_then(|d| d.get("actor_ref").cloned()).unwrap_or(Value::Null),
            "recorded_at": row
                .and_then(|d| d.pointer("/transaction_time/recorded_at").cloned())
                .unwrap_or(Value::Null),
            "bound_work_result_content_hash": row
                .and_then(|d| d.get("subject_content_hash").cloned())
                .unwrap_or(Value::Null),
        }));
    }

    // ---- every ladder member counted, including the ones nobody likes to report
    let mut census = Map::new();
    for outcome in OUTCOME_CLASSES {
        let count = ladder
            .iter()
            .filter(|document| {
                document.get("outcome_class").and_then(Value::as_str) == Some(*outcome)
            })
            .count();
        census.insert((*outcome).to_string(), json!(count));
    }

    // ---- the distinct WorkResult versions this ladder actually bound
    //
    // An owner-admitted backlink gives the same URI new bytes and therefore a new hash. Reporting
    // the DISTINCT bound hashes, in the order they were first bound, is how a consumer sees that a
    // transition attests bytes that are no longer current — instead of a URI that silently means
    // something new.
    let mut bound_versions: Vec<Value> = Vec::new();
    for document in &ladder {
        let Some(hash) = document.get("subject_content_hash").and_then(Value::as_str) else {
            continue;
        };
        if bound_versions
            .iter()
            .any(|entry| entry.get("content_hash").and_then(Value::as_str) == Some(hash))
        {
            continue;
        }
        bound_versions.push(json!({
            "content_hash": hash,
            "first_bound_at_transition_ordinal": ordinal_of(document),
        }));
    }
    let current_binding_state = if ladder.is_empty() {
        "no_transition"
    } else if bound_versions.len() == 1
        && bound_versions[0]
            .get("content_hash")
            .and_then(Value::as_str)
            == Some(resolved.content_hash.as_str())
    {
        "current_bytes_bound"
    } else {
        // Either the ladder bound several versions, or the one it bound is no longer what the owner
        // commits. Both are reported rather than smoothed: a graph that hid this would let a stale
        // attestation read as a current one.
        "bound_to_superseded_bytes"
    };

    let reached_stage = ladder
        .last()
        .and_then(|document| document.get("to_stage").cloned())
        .unwrap_or(Value::Null);
    let reached_stage_ordinal = ladder
        .last()
        .and_then(|document| document.get("to_stage_ordinal").and_then(Value::as_u64))
        .unwrap_or(0);

    let document = json!({
        "schema_version": GRAPH_SCHEMA_VERSION,
        "projection_contract_ref": GRAPH_CONTRACT_ID,
        "projection_kind": "read_projection",
        "work_result_ref": work_result_ref,
        "work_result_content_hash": resolved.content_hash,
        "work_result_commitment_domain": WORK_RESULT_COMMITMENT_DOMAIN,
        "work_result_resolved_by": "work_result_routes::resolve_admitted_work_result",
        "work_result_outcome_class": resolved.outcome_class,
        "work_result_status": resolved.status,
        "subject_family": SubjectFamily::WorkResult.label(),
        "stages": stages,
        "reached_stage": reached_stage,
        "reached_stage_ordinal": reached_stage_ordinal,
        "transition_count": ladder.len(),
        "transitions": ladder,
        "outcome_class_census": Value::Object(census),
        "bound_work_result_content_hashes": bound_versions,
        "current_binding_state": current_binding_state,
        "transition_authority_nonclaim": AUTHORITY_NONCLAIM,
        "transition_verdict_nonclaim": VERDICT_NONCLAIM,
        "rebuildable_index_state": index_state,
        "truth_source": "work_result_owner_and_agentgres_owner_scoped_chain",
        "does_not_assert": GRAPH_NONCLAIMS,
        "authority_nonclaim": GRAPH_AUTHORITY_NONCLAIM,
        "verdict_nonclaim": GRAPH_VERDICT_NONCLAIM,
    });

    // THE PROJECTION IS VALIDATED AGAINST ITS OWN REGISTERED CONTRACT BEFORE IT IS SERVED. A
    // projection that cannot satisfy the contract it names is a defect to refuse, not bytes to ship.
    if let Err(reason) = validate_architecture_contract(GRAPH_CONTRACT_ID, &document) {
        return bad(
            StatusCode::BAD_GATEWAY,
            "verified_work_graph_projection_invalid",
            format!("the derived Verified Work Graph is not registered-valid: {reason}"),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "verified_work_graph": document })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_family_classification_prefers_the_longer_scheme() {
        // The trap this guards: `ontology-assertion://` and `ontology-mapping://` both begin with the
        // letters of `ontology`, so a naive prefix order hands an assertion to the revision resolver.
        assert_eq!(
            SubjectFamily::classify("ontology-assertion://d/a/assertion/1"),
            Some(SubjectFamily::OntologyAssertion)
        );
        assert_eq!(
            SubjectFamily::classify("ontology-mapping://d/b/crosswalk/1"),
            Some(SubjectFamily::OntologyMappingRevision)
        );
        assert_eq!(
            SubjectFamily::classify("ontology://d/c/revision/1"),
            Some(SubjectFamily::OntologyRevision)
        );
        assert_eq!(
            SubjectFamily::classify("work-result://room/1"),
            Some(SubjectFamily::WorkResult)
        );
        assert_eq!(SubjectFamily::classify("goal-run://x/1"), None);
    }

    #[test]
    fn every_ladder_member_is_the_canonical_enum_in_canonical_order() {
        assert_eq!(
            STAGES,
            &[
                "attested",
                "evidenced",
                "verified",
                "accepted",
                "adjudicated",
                "settled"
            ]
        );
    }

    /// Load one registered fixture by file name.
    ///
    /// The fixtures are read from the repository rather than from an inlined copy on purpose: the
    /// point of this regression is that the bytes a relying party would be handed are the bytes the
    /// GENERATED projection accepts.
    fn registered_fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/architecture/_meta/schemas/fixtures/assurance-transition-receipt-v1")
            .join(format!("{name}.json"));
        let bytes = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("fixture {} is readable: {error}", path.display()));
        serde_json::from_str(&bytes)
            .unwrap_or_else(|error| panic!("fixture {} is JSON: {error}", path.display()))
    }

    /// Load one registered successor fixture without reinterpreting the predecessor corpus.
    fn registered_successor_fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/architecture/_meta/schemas/fixtures/assurance-transition-receipt-v2")
            .join(format!("{name}.json"));
        let bytes = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("fixture {} is readable: {error}", path.display()));
        serde_json::from_str(&bytes)
            .unwrap_or_else(|error| panic!("fixture {} is JSON: {error}", path.display()))
    }

    /// EVERY REGISTERED FIXTURE, THROUGH THE GENERATED RUST PROJECTION.
    ///
    /// This exists because `npm run check:architecture-contracts` does NOT validate fixtures — it
    /// proves only that the generated files are up to date with the registry. Fixture validity is
    /// asserted by the generated golden test in `ioi-types`, which is a whole-workspace build away
    /// and therefore easy to skip. A positive fixture that could never pass the contract it
    /// illustrates is worse than no fixture: it is a worked example of an invalid record.
    #[test]
    fn every_registered_fixture_agrees_with_the_generated_projection() {
        for name in [
            "positive-genesis-attested",
            "positive-exploit-outcome-retained",
            "positive-verified-negative-outcome",
            "positive-settled-adjudicated-predecessor",
        ] {
            let document = registered_fixture(name);
            assert!(
                validate_architecture_contract(PREDECESSOR_CONTRACT_ID, &document).is_ok(),
                "positive predecessor fixture {name} must remain registered-valid: {:?}",
                validate_architecture_contract(PREDECESSOR_CONTRACT_ID, &document),
            );
        }
        for name in [
            "negative-stage-skip-attested-to-verified",
            "negative-empty-does-not-assert",
            "negative-verified-omits-acceptance-nonclaim",
            "negative-unknown-outcome-class",
            "negative-unsupported-subject-scheme",
            "negative-genesis-carries-predecessor",
            "negative-missing-verdict-nonclaim",
            "negative-ladder-position-ahead-of-chain",
            "negative-content-hash-substituted",
            "negative-subject-substituted",
            "negative-subject-hash-echoes-own-hash",
            "negative-identity-family-mismatch",
            "negative-admission-binds-other-transition",
            "negative-admission-content-hash-substituted",
        ] {
            let document = registered_fixture(name);
            assert!(
                validate_architecture_contract(PREDECESSOR_CONTRACT_ID, &document).is_err(),
                "negative predecessor fixture {name} must be refused by its registered contract",
            );
        }

        for name in [
            "positive-adjudication-without-a-named-challenge",
            "positive-genesis-attested-preserves-v1-semantics",
            "positive-rejected-challenge-resolution-is-retained",
            "positive-upheld-challenge-resolution",
        ] {
            let document = registered_successor_fixture(name);
            assert!(
                validate_architecture_contract(CONTRACT_ID, &document).is_ok(),
                "positive successor fixture {name} must be registered-valid: {:?}",
                validate_architecture_contract(CONTRACT_ID, &document),
            );
        }
        for name in [
            "negative-content-hash-omits-the-challenge-resolution",
            "negative-rejected-challenge-reported-as-negative",
            "negative-resolution-challenge-ref-is-not-a-challenge",
            "negative-resolution-names-another-revisions-bytes",
            "negative-resolution-names-another-subject",
            "negative-resolution-omits-its-resolver-seam",
            "negative-resolution-outside-adjudication",
            "negative-resolution-with-no-reviewer",
            "negative-successor-contract-ref-substituted",
            "negative-upheld-challenge-reported-as-positive",
            "negative-v1-challenge-envelope-in-the-resolution",
            "negative-v1-receipt-profile-on-v2",
            "negative-v1-schema-version-on-v2",
        ] {
            let document = registered_successor_fixture(name);
            assert!(
                validate_architecture_contract(CONTRACT_ID, &document).is_err(),
                "negative successor fixture {name} must be refused by its registered contract",
            );
        }
    }

    /// The admission block a positive fixture carries must be one the PRODUCER could have written.
    ///
    /// A fixture whose refs merely look plausible is a shape that happens to parse; these are the
    /// exact forms `contract_document` builds from `agentgres::refs`, so a runtime change that moved
    /// them would leave the corpus describing a record this daemon never emits.
    #[test]
    fn every_non_admission_fixture_matches_the_producer_ref_shapes() {
        // Excluded because their whole purpose is a BROKEN admission block. Named here rather than
        // silently skipped, and separately held to producer fidelity by the test below.
        const ADMISSION_TARGETED: &[&str] = &[
            "negative-admission-binds-other-transition",
            "negative-admission-content-hash-substituted",
        ];
        let corpus = [
            "positive-genesis-attested",
            "positive-exploit-outcome-retained",
            "positive-verified-negative-outcome",
            "positive-settled-adjudicated-predecessor",
            "negative-stage-skip-attested-to-verified",
            "negative-empty-does-not-assert",
            "negative-verified-omits-acceptance-nonclaim",
            "negative-unknown-outcome-class",
            "negative-unsupported-subject-scheme",
            "negative-genesis-carries-predecessor",
            "negative-missing-verdict-nonclaim",
            "negative-ladder-position-ahead-of-chain",
            "negative-content-hash-substituted",
            "negative-subject-substituted",
            "negative-subject-hash-echoes-own-hash",
            "negative-identity-family-mismatch",
        ];
        assert!(
            corpus.iter().all(|name| !ADMISSION_TARGETED.contains(name)),
            "the admission-targeted negatives are excluded from this sweep, not listed in it",
        );
        for name in corpus {
            let document = registered_fixture(name);
            let subject = document["subject_ref"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} carries subject_ref"));
            // Derived from the fixture's OWN subject: a shared constant would let a record drift
            // onto another subject's stream and still pass.
            let tail = stream_tail(RESOURCE_KIND, subject);
            let admission = &document["admission"];
            let seq = admission["admission_seq"]
                .as_u64()
                .unwrap_or_else(|| panic!("{name} carries admission_seq"));
            let head = admission["admission_head"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} carries admission_head"));
            let root = admission["admission_root"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} carries admission_root"));

            assert_eq!(
                admission["owner_namespace"].as_str(),
                Some(OWNER_NAMESPACE),
                "{name}: owner namespace",
            );
            assert_eq!(
                admission["stream_tail"].as_str(),
                Some(tail.as_str()),
                "{name}: dotted stream tail over its own subject",
            );
            assert!(
                is_sha256(head),
                "{name}: admission_head is a digest: {head}"
            );
            assert!(
                is_sha256(root),
                "{name}: admission_root is a digest: {root}"
            );
            match admission["expected_predecessor_head"].as_str() {
                None => assert!(
                    admission["expected_predecessor_head"].is_null(),
                    "{name}: predecessor head is a digest or null",
                ),
                Some(previous) => assert!(
                    is_sha256(previous),
                    "{name}: predecessor head is a digest: {previous}",
                ),
            }
            assert_eq!(
                admission["agentgres_operation_ref"].as_str(),
                Some(
                    agentgres::refs::event_stream_operation_ref(OWNER_NAMESPACE, &tail, seq, head)
                        .as_str()
                ),
                "{name}: operation ref is the one agentgres::refs builds",
            );
            assert_eq!(
                admission["agentgres_receipt_ref"].as_str(),
                Some(
                    agentgres::refs::event_stream_receipt_ref(OWNER_NAMESPACE, &tail, seq, root)
                        .as_str()
                ),
                "{name}: receipt ref is the one agentgres::refs builds",
            );
            assert_eq!(
                document["admission_domain_ref"].as_str(),
                Some(
                    format!(
                        "agentgres://domain/{}",
                        agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
                    )
                    .as_str()
                ),
                "{name}: admission domain ref",
            );
        }
    }

    /// The excluded pair is excluded for its DEFECT, not for its ref shapes.
    ///
    /// Without this, "excluded" becomes a place where a fixture with a wrong stream tail could hide.
    /// Each still sits on its own subject's stream with real digests; only the one field it targets
    /// diverges.
    #[test]
    fn admission_targeted_negatives_diverge_only_in_the_field_they_target() {
        for (name, broken) in [
            ("negative-admission-binds-other-transition", "transition_id"),
            (
                "negative-admission-content-hash-substituted",
                "content_hash",
            ),
        ] {
            let document = registered_fixture(name);
            let subject = document["subject_ref"].as_str().expect("subject_ref");
            let tail = stream_tail(RESOURCE_KIND, subject);
            let admission = &document["admission"];
            assert_eq!(
                admission["stream_tail"].as_str(),
                Some(tail.as_str()),
                "{name}: still on its own subject's stream",
            );
            assert!(
                is_sha256(admission["admission_head"].as_str().expect("head")),
                "{name}: still carries a real head",
            );
            assert_ne!(
                admission[broken], document[broken],
                "{name}: the targeted field is the one that diverges",
            );
        }
    }

    /// Every optional assertion is TRI-STATE at the type level.
    ///
    /// Absent is silence, present-and-well-typed is a claim to check, and present-and-malformed is a
    /// refusal. The unit-level proof matters alongside the live one because this is the single gate
    /// both the fresh and the replay path depend on: if it ever went two-state again, both paths
    /// would start dropping assertions in the same invisible way.
    #[test]
    fn malformed_assertions_are_refused_rather_than_read_as_absent() {
        for key in STRING_ASSERTIONS {
            let body = json!({ *key: 12345 });
            assert!(
                validate_assertion_types(&body).is_err(),
                "a numeric '{key}' is refused rather than ignored",
            );
            let well_typed = json!({ *key: "anything" });
            assert!(
                validate_assertion_types(&well_typed).is_ok(),
                "a string '{key}' is a claim to check, not a refusal",
            );
        }
        for key in UNSIGNED_ASSERTIONS {
            for malformed in [json!("1"), json!(-1), json!(1.5), json!(null)] {
                let body = json!({ *key: malformed });
                assert!(
                    validate_assertion_types(&body).is_err(),
                    "a non-unsigned '{key}' is refused rather than ignored",
                );
            }
            assert!(validate_assertion_types(&json!({ *key: 2 })).is_ok());
        }
        // Absence stays silence: an empty body asserts nothing and is not a refusal.
        assert!(validate_assertion_types(&json!({})).is_ok());
        // The two predecessor refs are deliberately outside this gate — null is meaningful for them
        // and they are compared as whole JSON values, so a wrong type refuses by its own cause.
        assert!(validate_assertion_types(
            &json!({ "expected_predecessor_transition_ref": 7, "expected_head": 9 })
        )
        .is_ok());
    }

    /// The echo rule, isolated.
    ///
    /// It cannot be isolated in a FIXTURE: `subject_content_hash` sits inside the commitment, so any
    /// record where it equals `content_hash` is a hash fixed point and necessarily trips the
    /// commitment rule as well. The registered negative therefore fails two rules by construction —
    /// that is a property of the design, not a defect in the corpus — and the single-rule evidence
    /// lives here instead of being claimed there.
    #[test]
    fn subject_hash_echo_rule_fires_on_its_own_finding() {
        let mut document =
            registered_successor_fixture("positive-genesis-attested-preserves-v1-semantics");
        let echoed = document["content_hash"].clone();
        document["subject_content_hash"] = echoed;
        let error = validate_architecture_contract(CONTRACT_ID, &document)
            .expect_err("an echoed subject hash is refused");
        assert!(
            error.contains("assurance_transition.subject_hash.is_not_this_records_own_hash"),
            "the echo rule is among the findings: {error}",
        );
    }

    #[test]
    fn transition_identity_binds_the_subject_family_and_ordinal() {
        let id = transition_ref(
            SubjectFamily::OntologyRevision,
            "ontology://clinical-intake/patient-intake/revision/2",
            3,
        );
        assert!(id.starts_with("assurance-transition://ontology_revision/"));
        assert!(id.ends_with("/transition/3"));
    }

    #[test]
    fn two_subjects_never_share_one_transition_identity() {
        let left = transition_ref(
            SubjectFamily::OntologyRevision,
            "ontology://clinical-intake/patient-intake/revision/2",
            1,
        );
        let right = transition_ref(
            SubjectFamily::OntologyRevision,
            "ontology://clinical-intake/patient-intake/revision/3",
            1,
        );
        assert_ne!(left, right);
    }

    #[test]
    fn outcome_classes_carry_every_negative_member_acc8_requires() {
        for required in [
            "negative",
            "inconclusive",
            "invalid",
            "exploit",
            "superseded",
            "disputed",
            "no_fault",
        ] {
            assert!(OUTCOME_CLASSES.contains(&required), "missing {required}");
        }
    }

    #[test]
    fn content_commitment_excludes_transaction_time_and_admission() {
        assert!(!CONTENT_MATERIAL_FIELDS.contains(&"transaction_time"));
        assert!(!CONTENT_MATERIAL_FIELDS.contains(&"admission"));
        assert!(CONTENT_MATERIAL_FIELDS.contains(&"valid_time"));
        assert!(CONTENT_MATERIAL_FIELDS.contains(&"subject_content_hash"));
        assert!(CONTENT_MATERIAL_FIELDS.contains(&"outcome_class"));
        assert!(CONTENT_MATERIAL_FIELDS.contains(&"does_not_assert"));
    }

    // -------------------------------------------------- M06.1: the Verified Work Graph projection

    #[test]
    fn work_result_is_the_only_family_this_build_newly_resolves() {
        // M06.1 wires exactly ONE arm. Finding and Attempt stay nameable and fail closed BY NAME,
        // and this asserts the boundary rather than trusting the comment above it.
        assert_eq!(SubjectFamily::WorkResult.owning_unit(), "M04.1");
        assert_eq!(SubjectFamily::Finding.owning_unit(), "M04.8");
        assert_eq!(SubjectFamily::Attempt.owning_unit(), "M04.8");
        assert_eq!(SubjectFamily::WorkResult.label(), "work_result");
        // The three M05 arms are untouched: their owning units are still the units that landed them.
        assert_eq!(SubjectFamily::OntologyRevision.owning_unit(), "M05.1");
        assert_eq!(
            SubjectFamily::OntologyMappingRevision.owning_unit(),
            "M05.2"
        );
        assert_eq!(SubjectFamily::OntologyAssertion.owning_unit(), "M05.3");
    }

    #[test]
    fn graph_nonclaims_are_the_complete_closed_canonical_set() {
        // Canon's negative list for the Verified Work Graph, as data. A future edit that quietly
        // drops one — settlement and economic value being the tempting ones — fails here and again
        // at the registered schema, which pins the same twelve.
        for required in [
            "authority",
            "verdict",
            "correctness",
            "acceptance",
            "adjudication",
            "settlement",
            "payment_or_economic_value",
            "external_world_occurrence",
            "deployment",
            "provider_connectivity",
            "legality",
            "live_medical_suitability",
        ] {
            assert!(
                GRAPH_NONCLAIMS.contains(&required),
                "the graph must disclaim {required}"
            );
        }
        assert_eq!(GRAPH_NONCLAIMS.len(), 12, "the nonclaim set is closed");
    }

    #[test]
    fn the_two_outcome_vocabularies_are_never_mapped_onto_each_other() {
        // THE NORMALISATION TRAP, PINNED. The WorkResult vocabulary and the assurance vocabulary
        // overlap in five members and genuinely disagree in three. A projection that "helpfully"
        // translated `exploit_found` into `exploit` would be collapsing a distinction two owners
        // maintain, which is the normalisation NN 21 forbids. The graph reports both verbatim in
        // separate fields, so this asserts the disagreement is REAL and therefore worth preserving.
        assert!(OUTCOME_CLASSES.contains(&"exploit"));
        assert!(!OUTCOME_CLASSES.contains(&"exploit_found"));
        assert!(OUTCOME_CLASSES.contains(&"disputed"));
        assert!(OUTCOME_CLASSES.contains(&"no_fault"));
    }

    #[test]
    fn the_graph_contract_is_registered_and_its_positives_validate() {
        // The projection validates every answer against this contract before serving it, so the
        // contract has to be present in the generated registry the daemon actually links.
        for fixture in [
            "positive-no-transition-graph.json",
            "positive-negative-outcome-retained.json",
            "positive-superseded-bytes-across-two-versions.json",
        ] {
            let document = graph_fixture(fixture);
            validate_architecture_contract(GRAPH_CONTRACT_ID, &document).unwrap_or_else(|error| {
                panic!("{fixture} must satisfy {GRAPH_CONTRACT_ID}: {error}")
            });
        }
    }

    #[test]
    fn a_downgraded_or_unknown_graph_contract_is_refused_not_served() {
        // The consumer-path version gate, exercised on the exact strings a consumer would send.
        // A downgrade is named distinctly from an unrecognised id so the refusal tells the caller
        // whether it asked for the wrong VERSION or the wrong FAMILY.
        assert!("schema://ioi/foundations/verified-work-graph-projection/v0"
            .starts_with(GRAPH_FAMILY_PREFIX));
        assert!("schema://ioi/foundations/verified-work-graph-projection/v2"
            .starts_with(GRAPH_FAMILY_PREFIX));
        assert!(!"schema://ioi/foundations/assurance-transition-receipt/v2"
            .starts_with(GRAPH_FAMILY_PREFIX));
        assert!(GRAPH_CONTRACT_ID.starts_with(GRAPH_FAMILY_PREFIX));
        // And the registry rejects a downgraded ref in the bytes themselves.
        let downgraded = graph_fixture("negative-downgraded-projection-contract-ref.json");
        assert!(validate_architecture_contract(GRAPH_CONTRACT_ID, &downgraded).is_err());
    }

    #[test]
    fn the_graph_refuses_to_declare_itself_a_store() {
        // "The graph is not a single database, chain, or UI." The only legal projection_kind is
        // read_projection, so a later edit cannot turn this family into a second truth store
        // without the contract refusing it.
        let durable = graph_fixture("negative-projection-kind-declared-durable.json");
        assert!(
            validate_architecture_contract(GRAPH_CONTRACT_ID, &durable).is_err(),
            "a projection declaring itself durable must be refused"
        );
    }

    #[test]
    fn an_empty_ladder_cannot_borrow_a_reached_stage() {
        // Stage independence has a floor: with no transition at all, nothing is reached. A
        // projection that read the WorkResult's own `status` and reported a stage from it would be
        // manufacturing assurance out of the subject's self-description.
        let borrowed = graph_fixture("negative-empty-ladder-claims-a-reached-stage.json");
        assert!(validate_architecture_contract(GRAPH_CONTRACT_ID, &borrowed).is_err());
    }

    #[test]
    fn a_stale_or_skipped_stage_row_carries_nothing() {
        // An unreached row populated with an outcome is the shape a skimming consumer misreads.
        let populated = graph_fixture("negative-unreached-stage-carries-an-outcome.json");
        assert!(validate_architecture_contract(GRAPH_CONTRACT_ID, &populated).is_err());
    }

    #[test]
    fn a_projection_may_not_strip_the_transitions_own_nonclaims() {
        for fixture in [
            "negative-projection-strips-the-transition-authority-nonclaim.json",
            "negative-projection-strips-the-transition-verdict-nonclaim.json",
        ] {
            let document = graph_fixture(fixture);
            let error = validate_architecture_contract(GRAPH_CONTRACT_ID, &document)
                .expect_err("a stripped nonclaim must refuse");
            assert!(
                error.contains("retain_their_own"),
                "{fixture} must fail the retention rule, got: {error}"
            );
        }
    }

    #[test]
    fn a_row_about_another_work_result_or_family_is_refused() {
        let foreign = graph_fixture("negative-transition-names-another-work-result.json");
        let error = validate_architecture_contract(GRAPH_CONTRACT_ID, &foreign)
            .expect_err("a foreign subject row must refuse");
        assert!(
            error.contains("every_row_binds_this_projections_work_result"),
            "{error}"
        );

        let family = graph_fixture("negative-transition-from-another-subject-family.json");
        let error = validate_architecture_contract(GRAPH_CONTRACT_ID, &family)
            .expect_err("a foreign family row must refuse");
        assert!(
            error.contains("every_row_binds_the_work_result_family"),
            "{error}"
        );
    }

    #[test]
    fn duplicate_bound_versions_collapse_a_distinction_and_are_refused() {
        // The mutable-version distinction is the whole reason the version list exists.
        let duplicate = graph_fixture("negative-duplicate-bound-version-hash.json");
        let error = validate_architecture_contract(GRAPH_CONTRACT_ID, &duplicate)
            .expect_err("duplicate versions must refuse");
        assert!(
            error.contains("are_distinct_work_result_content_hashes"),
            "{error}"
        );
    }

    /// Load one registered Verified Work Graph fixture from the canonical corpus.
    fn graph_fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(
                "../../docs/architecture/_meta/schemas/fixtures/verified-work-graph-projection-v1",
            )
            .join(name);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("registered fixture {name} is readable: {error}"));
        serde_json::from_slice(&bytes).expect("registered fixture is JSON")
    }
}

// ------------------------------------------------- the challenge-resolution consumption seam (M06.1)

/// One admitted challenge resolution, reduced to what a semantic-plane owner needs to change a
/// mapping's or an assertion's standing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedChallengeResolution {
    pub(crate) receipt_ref: String,
    pub(crate) transition_id: String,
    pub(crate) subject_ref: String,
    pub(crate) subject_content_hash: String,
    pub(crate) verifier_challenge_id: String,
    pub(crate) resolution: String,
    pub(crate) outcome_class: String,
    pub(crate) actor_ref: String,
}

/// Resolve one EXACT admitted challenge-resolution receipt for a caller entitled to see it.
///
/// WHY THIS EXISTS. Before it, a semantic-plane resolution accepted any string beginning `receipt://`
/// and called the standing change receipted. That is caller-authored evidence: the exact defect INV-37
/// exists to prevent, and the one this seam closes. A receipt is now a RECORD THIS DAEMON ADMITTED,
/// found on the subject's own assurance chain, or the resolution refuses.
///
/// IT LIVES HERE, IN THE RECEIPT OWNER. M05.2 and M05.3 could each have re-read this chain; then the
/// assurance ladder would have three interpretations of its own truth. It has one, it is this
/// function, and it reads through the same owner-scoped projection the query route serves from —
/// same scope check, same content-hash re-derivation, same contract validation.
///
/// WHAT IT BINDS, AND WHY EACH IS NECESSARY:
///   * THE SUBJECT. The receipt must be about the exact revision whose standing is changing. A
///     well-formed receipt over a neighbouring subject would otherwise resolve this one.
///   * THE SUBJECT'S BYTES. The owner-resolved hash must match, so a resolution cannot be re-pointed
///     at a later revision of the same lineage.
///   * THE CHALLENGE. The receipt must name the exact `verifier-challenge://` identity being
///     resolved. This is the binding v1 structurally could not carry, and it is why v2 exists.
///   * THE TENANT. The read is owner-scoped, so a receipt admitted under another tenant is not
///     merely mismatched — it is unreachable, and the refusal is the same one an absent subject
///     gives, so this cannot be used as an existence oracle.
///   * THE STAGE. Only an `adjudicated` transition carries a resolution at all, which the contract
///     already pins; a receipt from any other rung has no resolution block to find.
///
/// IT IS NOT A VERDICT AND GRANTS NOTHING. It returns what the ladder recorded. Whether that
/// resolution SHOULD change a mapping's standing is the semantic owner's rule, not this seam's.
pub(crate) fn resolve_challenge_resolution_receipt(
    data_dir: &str,
    identity: &RequestIdentity,
    receipt_ref: &str,
    expected_subject_ref: &str,
    expected_subject_hash: &str,
    expected_challenge_id: &str,
) -> Result<ResolvedChallengeResolution, Reply> {
    if !receipt_ref.starts_with("receipt://")
        || receipt_ref.len() > 480
        || receipt_ref
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii())
    {
        return Err(refuse(
            "assurance_transition_receipt_ref_not_canonical",
            "resolution_receipt_ref must be an exact 'receipt://' identity admitted by this daemon",
        ));
    }
    // THE SUBJECT DECIDES THE STREAM. A receipt is looked for on the ladder of the subject whose
    // standing is changing, so a receipt that exists somewhere else is simply not found here — there
    // is no global receipt lookup to widen and no second index to consult.
    let (ladder, _scope) = authorized_ladder_as_of(data_dir, identity, expected_subject_ref, None)?;
    // EXACT RECEIPT IDENTITY, AND NOTHING NEAR IT. Deliberately an equality against the admitting
    // batch's own ref, never a nearest match, a prefix, or a fall back to the newest adjudication on
    // this ladder: each of those would let a receipt this daemon never issued borrow the standing of
    // one it did. Isolating the decision here is what lets a battery weaken the DECISION rather than
    // only rename the error below — a renamed code proves an assertion reads a code, not that a
    // fence exists.
    let matched = ladder.iter().find(|entry| {
        entry
            .pointer("/admission/agentgres_receipt_ref")
            .and_then(Value::as_str)
            == Some(receipt_ref)
    });
    let Some(document) = matched else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "assurance_transition_receipt_absent",
            format!(
                "no transition on this subject's assurance ladder was admitted under '{receipt_ref}' — a receipt-shaped string is not a receipt, and an absent one is a typed absence rather than an accepted resolution"
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
    let pointer = |path: &str| {
        document
            .pointer(path)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let resolution = pointer("/challenge_resolution/resolution");
    if resolution.is_empty() {
        return Err(refuse(
            "assurance_transition_receipt_resolves_no_challenge",
            format!(
                "'{receipt_ref}' is an admitted assurance transition, but it adjudicates no named challenge; an ordinary ladder step is not the resolution of a dispute"
            ),
        ));
    }
    let subject_ref = field("subject_ref");
    let subject_content_hash = field("subject_content_hash");
    let challenge_id = pointer("/challenge_resolution/verifier_challenge_id");
    if subject_ref != expected_subject_ref {
        return Err(refuse(
            "assurance_transition_receipt_subject_mismatch",
            format!("'{receipt_ref}' adjudicates '{subject_ref}', not the subject being resolved"),
        ));
    }
    if subject_content_hash != expected_subject_hash {
        return Err(refuse(
            "assurance_transition_receipt_subject_hash_mismatch",
            "the receipt binds a different revision's bytes than the one whose standing is changing; a resolution cannot be re-pointed at a later revision of the same lineage",
        ));
    }
    if challenge_id != expected_challenge_id {
        return Err(refuse(
            "assurance_transition_receipt_challenge_mismatch",
            format!(
                "'{receipt_ref}' resolves '{challenge_id}', not the challenge being resolved; this is the binding v1 could not carry and the reason v2 exists"
            ),
        ));
    }
    Ok(ResolvedChallengeResolution {
        receipt_ref: receipt_ref.to_owned(),
        transition_id: field("transition_id"),
        subject_ref,
        subject_content_hash,
        verifier_challenge_id: challenge_id,
        resolution,
        outcome_class: field("outcome_class"),
        actor_ref: field("actor_ref"),
    })
}
