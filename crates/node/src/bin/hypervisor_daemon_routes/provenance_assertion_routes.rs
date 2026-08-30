//! `ProvenanceAssertion` — the assertion/query/challenge/resolution graph as immutable objects
//! (M05.3).
//!
//! WHAT IS TRUTH HERE: the Agentgres owner-namespaced operation chain for one assertion FAMILY is the
//! only durable record. This module writes no file of its own. Everything served is a PROJECTION
//! rebuilt from that chain on every read, including the content hash, which is re-derived and
//! compared rather than trusted. The read index is a process-local (head, count) cache consulted only
//! AFTER the answer exists, so it can report agreement and can never be an answer source; a restart
//! discards it whole, and there is nothing on disk to delete or corrupt.
//!
//! v2 IS AN EXPLICIT SUCCESSOR AND REINTERPRETS NOTHING. The bounded exact-single-source oracle slice
//! that produces `ioi.ontology-assertion.v1` records keeps its own contract, its own route and its own
//! store; those records remain valid, addressable and unaltered at v1. This module admits v2 records
//! only, on its own chain, and refuses a v1 `schema_version` by name rather than reading it as v2. The
//! registry records the succession (`successor_of`, `predecessor_remains_valid: true`,
//! `migration_policy: explicit_adapter_required`) and each v2 record repeats it in its own bytes, so
//! the succession is auditable without the registry.
//!
//! WHAT v2 ADDS, AND WHY EACH IS STRUCTURAL:
//!
//! 1. POLARITY. An affirmative assertion claims the proposition holds; a NEGATIVE one claims it does
//!    not. Both are recorded claims with sources and evidence, and neither is the absence of a
//!    record. Collapsing "asserted false" into "nothing asserted" is exactly the loss canon's
//!    negative-results rule forbids.
//!
//! 2. STRUCTURED UNCERTAINTY. A bare number cannot distinguish "0.0 confident" from "we do not know",
//!    and a confidence with no stated kind cannot be compared across estimators. `held_unknown`
//!    carries `uncertainty_kind: unknown`, a null confidence and an EMPTY consequence scope: a domain
//!    that declines to claim also declines to license consequences.
//!
//! 3. RETAINED CONTRADICTION. A contradicted assertion keeps pointing at what contradicts it and
//!    keeps its own sources and evidence. `retained` is a `const true` on the wire, so "resolve the
//!    contradiction by deleting one side" is unrepresentable rather than discouraged. Evidence
//!    records which side it bears on, so a bundle cannot look unanimous by omission.
//!
//! 4. THE PREDICATE IS A TERM THE BOUND REVISION ACTUALLY DECLARES. This is the one claim the
//!    registered corpus structurally cannot check: a well-formed, correctly-namespaced, canonical term
//!    the revision never declared passes every schema and every portable invariant. It is refused
//!    here, live, through the ontology owner's own published term reader.
//!
//! 5. CHALLENGE AND RESOLUTION AS OPERATIONS, NOT EDITS. A challenge appends to the assertion's own
//!    stream; standing is folded out of that stream on every read and lives OUTSIDE the content
//!    commitment, so an assertion's bytes never move when its standing does. A resolution binds an
//!    `AssuranceTransitionReceipt` v1 ref — evidence, never a verdict — and
//!    `VerifierChallengeEnvelope` v1 is refused by name because its `challenged_ref` pattern cannot
//!    address a semantic-plane subject at all.
//!
//! ADMISSION RECORDS OPERATIONAL TRUTH, NEVER UNIVERSAL TRUTH (NN 8, NN 14). Every projected record
//! carries `provenance_assertion_admission_is_not_universal_truth` and
//! `provenance_assertion_grants_no_authority`, and nothing here consults, mints or widens a
//! capability, lease, policy decision or effect admission.
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
use super::ontology_version_routes::resolve_admitted_term;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

const OWNER_NAMESPACE: &str = "hypervisor-provenance-assertions";
const RESOURCE_KIND: &str = "provenance-assertion-family";
const ADMIT_OP: &str = "provenance_assertion.revision.admit";
const CHALLENGE_OPEN_OP: &str = "provenance_assertion.challenge.admit";
const CHALLENGE_RESOLVE_OP: &str = "provenance_assertion.challenge.resolve";
const ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.provenance-assertion-admission.v1";
const CHALLENGE_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.provenance-assertion-challenge.v1";
const CONTRACT_ID: &str = "schema://ioi/foundations/ontology-assertion/v2";
const PREDECESSOR_CONTRACT: &str = "schema://ioi/foundations/ontology-assertion/v1";
const SCHEMA_VERSION: &str = "ioi.ontology-assertion.v2";
const ASSERTION_PROFILE: &str = "provenance_assertion";
const CONTENT_COMMITMENT_DOMAIN: &str = "ioi.provenance-assertion-content-commitment-jcs-sha256.v2";
const AUTHORITY_NONCLAIM: &str = "provenance_assertion_grants_no_authority";
const UNIVERSALITY_NONCLAIM: &str = "provenance_assertion_admission_is_not_universal_truth";
const REINTERPRETATION_NONCLAIM: &str = "provenance_assertion_v2_does_not_reinterpret_v1_records";
const CHALLENGE_CONTRACT: &str = "schema://ioi/foundations/objects/verifier-challenge-envelope/v2";
const RESOLUTION_CONTRACT: &str = "schema://ioi/foundations/assurance-transition-receipt/v1";
const ONTOLOGY_RESOLVER: &str = "ontology_version_routes::resolve_admitted_term";

const MAX_ORDINAL: u64 = 999_999_999;
const MAX_SOURCES: usize = 64;
const MAX_EVIDENCE: usize = 128;
const MAX_CONTRADICTIONS: usize = 128;
const MAX_REFS: usize = 64;

const POLARITIES: &[&str] = &["affirmative", "negative"];
const SOURCE_CLASSES: &[&str] = &[
    "observation",
    "oracle",
    "human_reviewer",
    "worker",
    "derived",
    "external_system",
    "self_report",
];
const EVIDENCE_CLASSES: &[&str] = &["direct", "corroborating", "contradicting", "inconclusive"];
const EVIDENCE_SIDES: &[&str] = &["affirmative", "negative", "neither"];
const UNCERTAINTY_KINDS: &[&str] = &[
    "point_confidence",
    "qualitative",
    "unknown",
    "disputed_estimate",
];
const CONTRADICTION_CLASSES: &[&str] = &[
    "none",
    "direct_negation",
    "value_conflict",
    "scope_conflict",
    "temporal_conflict",
];
const SUPERSESSION_REASONS: &[&str] = &[
    "none",
    "corrected",
    "refined",
    "retracted",
    "reclassified",
    "superseded_by_evidence",
];
const CHALLENGE_KINDS: &[&str] = &["evidence", "result", "rule", "verifier", "mapping"];
const RESOLUTIONS: &[&str] = &["upheld", "rejected"];

/// The exact material the registered invariant
/// `provenance_assertion.content_hash.commits_claim_sources_evidence_uncertainty_and_valid_time`
/// commits. `transaction_time`, `admission`, `admission_domain_ref`, `challenge_state`, `status` and
/// `schema_version` are DELIBERATELY absent: what was claimed is content; when it was recorded and
/// how its standing later moved are facts about the chain.
const CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "assertion_id",
    "assertion_family_ref",
    "assertion_profile",
    "namespace",
    "name",
    "owner_id",
    "governing_scope_ref",
    "version",
    "revision_ordinal",
    "predecessor_version_ref",
    "predecessor_content_hash",
    "ontology_ref",
    "ontology_binding",
    "ontology_resolved_by",
    "fact_class_ref",
    "subject_ref",
    "predicate_ref",
    "object_or_value_ref",
    "polarity",
    "valid_time",
    "source_attribution",
    "evidence_lineage",
    "uncertainty",
    "contradiction_state",
    "supersession",
    "applicability_scope_ref",
    "permitted_consequence_scope_refs",
    "causal_or_counterfactual_context_ref",
    "oracle_evidence_profile_ref",
    "oracle_evidence_admission_receipt_ref",
    "predecessor_contract_ref",
    "reinterpretation_nonclaim",
    "policy_hash",
    "migration",
    "universality_nonclaim",
    "authority_nonclaim",
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

fn family_ref(namespace: &str, name: &str) -> String {
    format!("ontology-assertion://{namespace}/{name}")
}

fn version_label(ordinal: u64) -> String {
    format!("v{ordinal}")
}

fn parse_time(value: &str) -> Option<u64> {
    (value.len() >= 20 && value.ends_with('Z') || value.len() >= 25)
        .then(|| agentgres::parse_rfc3339_ms(value))
        .filter(|ms| *ms > 0)
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

fn content_hash(record: &Value) -> Result<String, String> {
    digest_over(record, CONTENT_COMMITMENT_DOMAIN, CONTENT_MATERIAL_FIELDS)
}

/// The coordinates one `ontology-assertion://…/revision/N` identity names.
struct AssertionCoordinates {
    namespace: String,
    name: String,
    ordinal: u64,
}

/// STRICT AND TOTAL, for the same reason its siblings are: an identity that has to be normalised
/// before it can be compared is not an exact identity, and a later unit is about to BIND whatever
/// comes out of here.
fn parse_assertion_identity(assertion_id: &str) -> Option<AssertionCoordinates> {
    if !transportable_ref(assertion_id, 400) {
        return None;
    }
    let mut segments = assertion_id
        .strip_prefix("ontology-assertion://")?
        .split('/');
    let namespace = segments.next()?;
    let name = segments.next()?;
    let marker = segments.next()?;
    let ordinal = segments.next()?;
    if segments.next().is_some()
        || marker != "revision"
        || !canonical_token(namespace, 63)
        || !canonical_token(name, 63)
        || ordinal.is_empty()
        || ordinal.len() > 9
        || ordinal.starts_with('0')
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let ordinal: u64 = ordinal.parse().ok()?;
    if ordinal == 0 || ordinal > MAX_ORDINAL {
        return None;
    }
    Some(AssertionCoordinates {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        ordinal,
    })
}

// -------------------------------------------------------------------------- durable chain projection

struct AdmittedRevision {
    record: Value,
    head: String,
    seq: u64,
    admission_batch_seq: u64,
    admission_root: String,
    expected_predecessor_head: Value,
    recorded_at_ms: u64,
}

struct ChallengeEvent {
    challenge_id: String,
    subject_ref: String,
    resolution: Option<String>,
    receipt_ref: Option<String>,
}

/// Split one family's stream into its revisions and its challenge events.
///
/// A v1 record, or a frame written by a build this one does not implement, is reported as UNREADABLE
/// rather than projected as though it were v2. That is the mechanical half of "v2 does not
/// reinterpret v1": the read side refuses the downgrade too.
fn project_stream(
    history: &[ExactProjection],
) -> Result<(Vec<AdmittedRevision>, Vec<ChallengeEvent>), String> {
    let mut revisions = Vec::new();
    let mut challenges = Vec::new();
    for entry in history {
        let payload = &entry.operation.payload;
        let op = entry.operation.op_kind.as_str();
        if op == ADMIT_OP {
            if payload.get("schema_version").and_then(Value::as_str)
                != Some(ADMISSION_PAYLOAD_SCHEMA)
            {
                return Err(
                    "provenance-assertion admission carries an unknown payload schema".into(),
                );
            }
            let record = payload
                .get("assertion_record")
                .cloned()
                .ok_or_else(|| "provenance-assertion admission carries no record".to_string())?;
            if record.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION)
                || record.get("assertion_profile").and_then(Value::as_str)
                    != Some(ASSERTION_PROFILE)
            {
                return Err(format!(
                    "provenance-assertion chain holds a record this build does not implement (expected {SCHEMA_VERSION} / {ASSERTION_PROFILE}); a v1 record is read at v1 by its own owner and is never reinterpreted here"
                ));
            }
            let derived = content_hash(&record)?;
            if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
                return Err(
                    "provenance-assertion admitted content does not match its committed hash"
                        .into(),
                );
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
                return Err(
                    "provenance-assertion challenge carries an unknown payload schema".into(),
                );
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
                "provenance-assertion stream carries an unknown operation '{op}'"
            ));
        }
    }
    Ok((revisions, challenges))
}

/// OPEN BEATS RESOLVED, AND UPHELD BEATS REJECTED. Nothing is dropped: the resolved set and its
/// receipts stay addressable on a rejected standing too, so a dismissed challenge is retained as
/// evidence that the assertion was contested and survived.
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
        "resolution_contract_ref": RESOLUTION_CONTRACT,
    })
}

/// The projected status of one revision.
///
/// STANDING OUTRANKS SUPERSESSION AND CONTRADICTION, in that order. An upheld challenge REJECTS the
/// claim; an open challenge makes it DISPUTED; a successor makes it SUPERSEDED; naming contradictions
/// makes it CONTRADICTED; declining to claim keeps it HELD_UNKNOWN. Only a claim that is none of
/// those is ADMITTED, and only an admitted claim carries a consequence scope.
fn projected_status(record: &Value, standing: &str, superseded: bool) -> &'static str {
    match standing {
        "upheld" => return "rejected",
        "challenged" => return "disputed",
        _ => {}
    }
    if record
        .pointer("/uncertainty/uncertainty_kind")
        .and_then(Value::as_str)
        == Some("unknown")
    {
        return "held_unknown";
    }
    if superseded {
        return "superseded";
    }
    let contradicted = record
        .pointer("/contradiction_state/contradicting_assertion_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| !refs.is_empty());
    if contradicted {
        return "contradicted";
    }
    let has_evidence = record
        .get("evidence_lineage")
        .and_then(Value::as_array)
        .is_some_and(|rows| !rows.is_empty());
    let has_scope = record
        .get("permitted_consequence_scope_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| !refs.is_empty());
    if has_evidence && has_scope {
        "admitted"
    } else {
        // A claim with no evidence or no bounded consequence scope is not admitted; it is a claim the
        // domain has recorded and is still waiting on.
        "evidence_pending"
    }
}

fn contract_document(
    revision: &AdmittedRevision,
    family: &str,
    challenges: &[ChallengeEvent],
    superseded_at: Option<&str>,
) -> Result<Value, String> {
    let mut document = revision.record.clone();
    let assertion_id = document
        .get("assertion_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "admitted assertion carries no assertion_id".to_string())?
        .to_string();
    let committed = document
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let tail = stream_tail(RESOURCE_KIND, family);
    document["admission_domain_ref"] = json!(format!(
        "agentgres://domain/{}",
        agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
    ));
    document["transaction_time"] = json!({
        "recorded_at": admitted_stamp(revision.recorded_at_ms),
        "superseded_at": superseded_at.map_or(Value::Null, |value| json!(value)),
    });
    document["admission"] = json!({
        "assertion_id": assertion_id,
        "content_hash": committed,
        "owner_namespace": OWNER_NAMESPACE,
        "stream_tail": tail,
        "agentgres_operation_ref": agentgres::refs::event_stream_operation_ref(
            OWNER_NAMESPACE, &tail, revision.seq, &revision.head,
        ),
        "agentgres_receipt_ref": agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE, &tail, revision.admission_batch_seq, &revision.admission_root,
        ),
        "admission_seq": revision.seq,
        "admission_head": revision.head,
        "admission_root": revision.admission_root,
        "expected_predecessor_head": revision.expected_predecessor_head,
    });
    let state = fold_challenge_state(&assertion_id, challenges);
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
    validate_architecture_contract(CONTRACT_ID, &document).map_err(|reason| {
        format!("projected provenance assertion is not registered-valid: {reason}")
    })?;
    Ok(document)
}

fn project_lineage(history: &[ExactProjection], family: &str) -> Result<Vec<Value>, String> {
    let (revisions, challenges) = project_stream(history)?;
    let mut documents = Vec::with_capacity(revisions.len());
    for (index, revision) in revisions.iter().enumerate() {
        let superseded_at = revisions
            .get(index + 1)
            .map(|next| admitted_stamp(next.recorded_at_ms));
        documents.push(contract_document(
            revision,
            family,
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

static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

fn projection_cache_key(scope: &RequestResourceScope, family: &str) -> String {
    format!(
        "{}\u{0}{}\u{0}{}",
        scope.principal_ref, scope.tenant_ref, family
    )
}

/// The lineage is already computed when this is called, so the cache cannot contribute to the answer.
/// Reporting the pre-existing state lets a verifier assert rebuild by POSITIVE detection: an
/// unchanged answer is also consistent with a cache that was never dropped, which proves nothing.
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

/// The projected revisions AND the true head of the stream they came from.
///
/// THE TWO ARE NOT THE SAME THING. A challenge is its own operation on this family's stream, so after
/// one is admitted the stream head is the CHALLENGE's head while the last revision still carries the
/// older one. Exact-head admission is about the chain, so every compare-and-swap names the stream
/// head; deriving it from the last revision would make every write after any challenge conflict.
fn read_lineage_and_head(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    family: &str,
) -> Result<(Vec<Value>, Option<String>), Reply> {
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        RESOURCE_KIND,
        family,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, family),
    )
    .map_err(mutation_refusal_reply)?;
    let stream_head = history.last().map(|entry| entry.head.clone());
    let lineage = project_lineage(&history, family).map_err(|reason| {
        bad(
            StatusCode::BAD_GATEWAY,
            "provenance_assertion_projection_failed",
            reason,
        )
    })?;
    Ok((lineage, stream_head))
}

fn read_lineage(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    family: &str,
) -> Result<Vec<Value>, Reply> {
    read_lineage_and_head(data_dir, identity, scope, family).map(|(lineage, _)| lineage)
}

fn authorized_lineage(
    data_dir: &str,
    identity: &RequestIdentity,
    family: &str,
) -> Result<Vec<Value>, Reply> {
    let scope = authorize_request_resource_scope(data_dir, identity, RESOURCE_KIND, family, None)
        .map_err(scope_refusal_reply)?;
    read_lineage(data_dir, identity, &scope, family)
}

// ------------------------------------------------------- the exact admitted-assertion resolution seam

/// One admitted assertion, reduced to what an assurance subject resolver needs.
///
/// THE M06 CONSUMPTION SEAM. `AssuranceTransitionReceipt` v1's wire names `ontology_assertion` as a
/// family it may address; this is the reader that makes that family RESOLVABLE, and it lives in the
/// owner so the receipt never acquires a second interpretation of an assertion's truth. It returns an
/// identity, a standing, a status and a hash. It grants nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedProvenanceAssertion {
    pub(crate) assertion_id: String,
    pub(crate) assertion_family_ref: String,
    pub(crate) content_hash: String,
    pub(crate) challenge_standing: String,
    pub(crate) status: String,
}

pub(crate) fn resolve_admitted_assertion(
    data_dir: &str,
    identity: &RequestIdentity,
    assertion_id: &str,
) -> Result<ResolvedProvenanceAssertion, Reply> {
    let Some(coordinates) = parse_assertion_identity(assertion_id) else {
        return Err(refuse(
            "provenance_assertion_identity_not_canonical",
            "an assertion revision is addressed as 'ontology-assertion://<namespace>/<name>/revision/<n>' with canonical tokens and an unpadded positive ordinal; a spelling that needs normalising is refused rather than repaired",
        ));
    };
    let family = family_ref(&coordinates.namespace, &coordinates.name);
    // AUTHORIZATION IS THE OWNER SEAM'S, UNCHANGED, so this cannot be used as an existence oracle for
    // another domain's assertions.
    let lineage = authorized_lineage(data_dir, identity, &family)?;
    let Some(document) = lineage
        .iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "provenance_assertion_revision_absent",
            format!(
                "this assertion family has no revision {} — an absent revision is a typed absence, never an empty success",
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
    let resolved = ResolvedProvenanceAssertion {
        assertion_id: field("assertion_id"),
        assertion_family_ref: field("assertion_family_ref"),
        content_hash: field("content_hash"),
        challenge_standing: document
            .pointer("/challenge_state/standing")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        status: field("status"),
    };
    if resolved.assertion_id != assertion_id
        || resolved.assertion_family_ref != family
        || !is_sha256(&resolved.content_hash)
        || resolved.challenge_standing.is_empty()
        || resolved.status.is_empty()
    {
        return Err(bad(
            StatusCode::BAD_GATEWAY,
            "provenance_assertion_projection_failed",
            format!(
                "the chain resolved '{assertion_id}' to a record that does not bind that identity"
            ),
        ));
    }
    Ok(resolved)
}

// ------------------------------------------------------------------------------- request validation

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

fn require_closed_object<'a>(
    entry: &'a Value,
    permitted: &[&str],
    at: &str,
) -> Result<&'a Map<String, Value>, Reply> {
    let Some(object) = entry.as_object() else {
        return Err(refuse(
            "provenance_assertion_nested_entry_malformed",
            format!("every {at} entry must be an object with exactly {permitted:?}"),
        ));
    };
    if let Some(unknown) = object.keys().find(|key| !permitted.contains(&key.as_str())) {
        return Err(refuse(
            "provenance_assertion_nested_entry_unknown_field",
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
        "provenance_assertion_vocabulary_member_unknown",
        format!("{at} must be one of {permitted:?}, not '{value}'"),
    ))
}

fn require_scoped_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<String, Reply> {
    let value = str_field(body, key);
    if transportable_ref(value, 260) && schemes.iter().any(|scheme| value.starts_with(scheme)) {
        return Ok(value.to_owned());
    }
    Err(refuse(
        "provenance_assertion_ref_not_canonical",
        format!("{key} must be one of {schemes:?}"),
    ))
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
            "provenance_assertion_ref_not_canonical",
            format!("{key} must be null or one of {schemes:?}"),
        )),
    }
}

fn ref_set(body: &Value, key: &str, schemes: &[&str], max: usize) -> Result<Value, Reply> {
    let items = body.get(key).cloned().unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "provenance_assertion_ref_set_malformed",
            format!("{key} must be an array of refs"),
        ));
    };
    if entries.len() > max {
        return Err(refuse(
            "provenance_assertion_ref_set_too_large",
            format!("{key} carries more than {max} refs"),
        ));
    }
    let mut seen: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(value) = entry.as_str() else {
            return Err(refuse(
                "provenance_assertion_ref_not_canonical",
                format!("{key} entries must be strings"),
            ));
        };
        if !transportable_ref(value, 260) || !schemes.iter().any(|scheme| value.starts_with(scheme))
        {
            return Err(refuse(
                "provenance_assertion_ref_not_canonical",
                format!("{key} declares '{value}', which is not one of {schemes:?}"),
            ));
        }
        if seen.iter().any(|previous| previous == value) {
            return Err(refuse(
                "provenance_assertion_ref_duplicated",
                format!("{key} declares '{value}' twice"),
            ));
        }
        seen.push(value.to_owned());
    }
    Ok(Value::Array(seen.into_iter().map(Value::from).collect()))
}

fn validate_valid_time(body: &Value) -> Result<Value, Reply> {
    let Some(interval) = body.get("valid_time") else {
        return Err(refuse(
            "provenance_assertion_valid_time_required",
            "valid_time is required: an assertion that cannot say WHEN it is held true cannot hold a contradiction honestly",
        ));
    };
    require_closed_object(interval, &["starts_at", "ends_at"], "valid_time")?;
    let starts_at = str_field(interval, "starts_at");
    if parse_time(starts_at).is_none() {
        return Err(refuse(
            "provenance_assertion_valid_time_not_canonical",
            "valid_time.starts_at must be an RFC3339 instant",
        ));
    }
    let ends_at = match interval.get("ends_at") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) => {
            let Some(end) = parse_time(value) else {
                return Err(refuse(
                    "provenance_assertion_valid_time_not_canonical",
                    "valid_time.ends_at must be an RFC3339 instant or null",
                ));
            };
            if Some(end) <= parse_time(starts_at) {
                return Err(refuse(
                    "provenance_assertion_valid_time_not_ordered",
                    "valid_time.ends_at must be strictly after starts_at",
                ));
            }
            json!(value)
        }
        Some(_) => {
            return Err(refuse(
                "provenance_assertion_valid_time_not_canonical",
                "valid_time.ends_at must be a string or null",
            ))
        }
    };
    Ok(json!({ "starts_at": starts_at, "ends_at": ends_at }))
}

/// Who or what said so. Non-empty by construction: an unattributed assertion is a rendering of a log,
/// which is exactly what this object exists instead of.
fn source_attribution(body: &Value) -> Result<Value, Reply> {
    let items = body
        .get("source_attribution")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "provenance_assertion_source_attribution_malformed",
            "source_attribution must be an array of {source_ref,source_class,observed_at}",
        ));
    };
    if entries.is_empty() {
        return Err(refuse(
            "provenance_assertion_source_required",
            "an assertion names at least one source; an unattributed claim is a rendering of a log",
        ));
    }
    if entries.len() > MAX_SOURCES {
        return Err(refuse(
            "provenance_assertion_source_attribution_too_large",
            format!("source_attribution carries more than {MAX_SOURCES} rows"),
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &["source_ref", "source_class", "observed_at"],
            "source_attribution",
        )?;
        let source_ref = require_scoped_ref(
            entry,
            "source_ref",
            &[
                "source://",
                "observation://",
                "attempt://",
                "system://",
                "domain://",
                "user://",
                "worker://",
                "service://",
                "org://",
                "artifact://",
            ],
        )?;
        let source_class = require_member(
            str_field(entry, "source_class"),
            SOURCE_CLASSES,
            "source_class",
        )?;
        let observed_at = str_field(entry, "observed_at");
        if parse_time(observed_at).is_none() {
            return Err(refuse(
                "provenance_assertion_observation_time_not_canonical",
                "observed_at must be an RFC3339 instant",
            ));
        }
        if seen.iter().any(|previous| previous == &source_ref) {
            return Err(refuse(
                "provenance_assertion_source_attributed_twice",
                format!("'{source_ref}' is attributed twice; a repeated source would let one observation read as corroboration"),
            ));
        }
        seen.push(source_ref.clone());
        rows.push(json!({
            "source_ref": source_ref,
            "source_class": source_class,
            "observed_at": observed_at,
        }));
    }
    Ok(Value::Array(rows))
}

/// Evidence, each row recording WHICH SIDE it bears on so a bundle cannot look unanimous by omission.
fn evidence_lineage(body: &Value) -> Result<Value, Reply> {
    let items = body
        .get("evidence_lineage")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "provenance_assertion_evidence_lineage_malformed",
            "evidence_lineage must be an array of {evidence_ref,evidence_class,supports}",
        ));
    };
    if entries.len() > MAX_EVIDENCE {
        return Err(refuse(
            "provenance_assertion_evidence_lineage_too_large",
            format!("evidence_lineage carries more than {MAX_EVIDENCE} rows"),
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    let mut rows = Vec::with_capacity(entries.len());
    for entry in entries {
        require_closed_object(
            entry,
            &["evidence_ref", "evidence_class", "supports"],
            "evidence_lineage",
        )?;
        let evidence_ref = require_scoped_ref(
            entry,
            "evidence_ref",
            &[
                "evidence://",
                "receipt://",
                "artifact://",
                "assurance-evidence://",
            ],
        )?;
        let evidence_class = require_member(
            str_field(entry, "evidence_class"),
            EVIDENCE_CLASSES,
            "evidence_class",
        )?;
        let supports = require_member(str_field(entry, "supports"), EVIDENCE_SIDES, "supports")?;
        // A row cannot say "this contradicts" and "this supports the claim" at once; that pair is how
        // contradicting evidence gets filed as corroboration.
        if evidence_class == "contradicting" && supports == "affirmative" {
            return Err(refuse(
                "provenance_assertion_contradicting_evidence_filed_as_support",
                format!("'{evidence_ref}' is declared contradicting while supporting the affirmative side"),
            ));
        }
        if seen.iter().any(|previous| previous == &evidence_ref) {
            return Err(refuse(
                "provenance_assertion_evidence_counted_twice",
                format!("'{evidence_ref}' appears twice; counting one artifact twice is how a thin evidence set looks thick"),
            ));
        }
        seen.push(evidence_ref.clone());
        rows.push(json!({
            "evidence_ref": evidence_ref,
            "evidence_class": evidence_class,
            "supports": supports,
        }));
    }
    Ok(Value::Array(rows))
}

/// Structured uncertainty. `unknown` is a distinct epistemic state from zero confidence, and a point
/// confidence with no number is an estimate that cannot be read.
fn uncertainty(body: &Value) -> Result<Value, Reply> {
    let Some(block) = body.get("uncertainty") else {
        return Err(refuse(
            "provenance_assertion_uncertainty_required",
            "uncertainty is required: a claim with no stated epistemic posture cannot be compared with one that has one",
        ));
    };
    require_closed_object(
        block,
        &["uncertainty_kind", "confidence", "estimator_ref"],
        "uncertainty",
    )?;
    let kind = require_member(
        str_field(block, "uncertainty_kind"),
        UNCERTAINTY_KINDS,
        "uncertainty_kind",
    )?;
    let estimator_ref = optional_ref(
        block,
        "estimator_ref",
        &[
            "worker://",
            "system://",
            "user://",
            "service://",
            "org://",
            "domain://",
            "policy://",
            "artifact://",
        ],
    )?;
    let confidence = match block.get("confidence") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Number(number)) => {
            let Some(value) = number.as_f64() else {
                return Err(refuse(
                    "provenance_assertion_confidence_not_canonical",
                    "confidence must be a number in [0,1] or null",
                ));
            };
            if !(0.0..=1.0).contains(&value) {
                return Err(refuse(
                    "provenance_assertion_confidence_out_of_range",
                    "confidence must be within [0,1]",
                ));
            }
            json!(number)
        }
        Some(_) => {
            return Err(refuse(
                "provenance_assertion_confidence_not_canonical",
                "confidence must be a number in [0,1] or null",
            ))
        }
    };
    if kind == "unknown" && (!confidence.is_null() || !estimator_ref.is_null()) {
        return Err(refuse(
            "provenance_assertion_unknown_carries_a_confidence",
            "an 'unknown' posture carries no confidence and no estimator; declining to claim is not claiming zero",
        ));
    }
    if kind == "point_confidence" && (confidence.is_null() || estimator_ref.is_null()) {
        return Err(refuse(
            "provenance_assertion_point_confidence_incomplete",
            "a point confidence states both the number and who estimated it; a number with no estimator cannot be compared across estimators",
        ));
    }
    Ok(json!({
        "uncertainty_kind": kind,
        "confidence": confidence,
        "estimator_ref": estimator_ref,
    }))
}

/// Contradictions are RETAINED. `retained` is fixed true on the wire, so "resolve the contradiction by
/// deleting one side" is unrepresentable rather than merely discouraged.
fn contradiction_state(body: &Value) -> Result<Value, Reply> {
    let block = body
        .get("contradiction_state")
        .cloned()
        .unwrap_or_else(|| json!({ "contradiction_class": "none" }));
    require_closed_object(
        &block,
        &[
            "contradiction_class",
            "contradicting_assertion_refs",
            "retained",
        ],
        "contradiction_state",
    )?;
    let class = require_member(
        str_field(&block, "contradiction_class"),
        CONTRADICTION_CLASSES,
        "contradiction_class",
    )?;
    let refs = ref_set(
        &block,
        "contradicting_assertion_refs",
        &["ontology-assertion://", "finding://"],
        MAX_CONTRADICTIONS,
    )?;
    let count = refs.as_array().map_or(0, Vec::len);
    if class == "none" && count > 0 {
        return Err(refuse(
            "provenance_assertion_contradiction_class_understates_the_refs",
            "contradiction_class 'none' cannot coexist with named contradictions; calling the record clean while naming what disputes it is the same defect from the other side",
        ));
    }
    if class != "none" && count == 0 {
        return Err(refuse(
            "provenance_assertion_contradiction_class_names_nothing",
            "a contradiction class with no named contradiction is a label rather than a finding",
        ));
    }
    if block
        .get("retained")
        .is_some_and(|value| value != &json!(true))
    {
        return Err(refuse(
            "provenance_assertion_contradiction_not_retained",
            "contradictions are retained; a record that drops one has not resolved it",
        ));
    }
    Ok(json!({
        "contradiction_class": class,
        "contradicting_assertion_refs": refs,
        "retained": true,
    }))
}

fn supersession(body: &Value, self_id: &str) -> Result<Value, Reply> {
    let block = body
        .get("supersession")
        .cloned()
        .unwrap_or_else(|| json!({ "supersession_reason": "none" }));
    require_closed_object(
        &block,
        &["supersedes_ref", "supersession_reason"],
        "supersession",
    )?;
    let supersedes_ref = optional_ref(&block, "supersedes_ref", &["ontology-assertion://"])?;
    let reason = require_member(
        str_field(&block, "supersession_reason"),
        SUPERSESSION_REASONS,
        "supersession_reason",
    )?;
    if supersedes_ref.as_str() == Some(self_id) {
        return Err(refuse(
            "provenance_assertion_supersedes_itself",
            "an assertion that supersedes itself is a cycle, not a correction",
        ));
    }
    if supersedes_ref.is_null() != (reason == "none") {
        return Err(refuse(
            "provenance_assertion_supersession_incomplete",
            "a record that names a supersession target states why, and 'none' is reserved for a record that supersedes nothing; supersession without a reason is a deletion with extra steps",
        ));
    }
    Ok(json!({
        "supersedes_ref": supersedes_ref,
        "supersession_reason": reason,
    }))
}

// ------------------------------------------------------------------------------------ producer route

/// POST /v1/hypervisor/provenance-assertions — admit one immutable assertion revision against the
/// exact current head of its Agentgres chain.
pub(crate) async fn handle_provenance_assertion_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST. Validating content before authenticating answers 422 where 401 is owed.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // A caller naming the PREDECESSOR contract is refused by name. Reading a v1 request as a v2
    // record is the exact reinterpretation this version exists to avoid.
    let declared = str_field(&body, "schema_version");
    if !declared.is_empty() && declared != SCHEMA_VERSION {
        return refuse(
            "provenance_assertion_schema_version_unsupported",
            format!(
                "this route admits {SCHEMA_VERSION} only; '{declared}' is refused rather than downgraded into, and a v1 record stays valid and addressable through its own owner"
            ),
        );
    }
    let namespace = str_field(&body, "namespace").to_owned();
    let name = str_field(&body, "name").to_owned();
    if !canonical_token(&namespace, 63) || !canonical_token(&name, 63) {
        return refuse(
            "provenance_assertion_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family = family_ref(&namespace, &name);

    // THE PREDICATE MUST BE A TERM THE BOUND REVISION ACTUALLY DECLARES. This is the one claim the
    // registered corpus structurally cannot check, and it is checked HERE, through the ontology
    // owner's own published term reader, under the caller's own scope.
    let ontology_version_ref = str_field(&body, "ontology_version_ref").to_owned();
    let predicate_ref = str_field(&body, "predicate_ref").to_owned();
    let term = match resolve_admitted_term(
        &st.data_dir,
        &caller.identity,
        &ontology_version_ref,
        &predicate_ref,
    ) {
        Ok(term) => term,
        Err(response) => return response,
    };
    if !is_sha256(&term.content_hash) {
        return bad(
            StatusCode::BAD_GATEWAY,
            "provenance_assertion_ontology_hash_not_canonical",
            "the ontology owner resolved this revision to a content hash that is not a canonical sha256; an assertion is not sealed over a malformed binding",
        );
    }
    let Some((binding_namespace, binding_name)) = term
        .ontology_family_ref
        .strip_prefix("ontology://")
        .and_then(|tail| tail.split_once('/'))
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            "provenance_assertion_projection_failed",
            "the ontology owner resolved a family ref this build cannot decompose",
        );
    };
    let revision_ordinal = ontology_version_ref
        .rsplit('/')
        .next()
        .and_then(|segment| segment.parse::<u64>().ok())
        .unwrap_or(0);
    // A FACT CLASS, WHERE PRESENT, IS ALSO A TERM OF THE SAME REVISION. A class the revision never
    // declared would file the claim under a category nobody admitted.
    let fact_class_ref = match optional_ref(&body, "fact_class_ref", &["ontology://"]) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(class_ref) = fact_class_ref.as_str() {
        if let Err(response) = resolve_admitted_term(
            &st.data_dir,
            &caller.identity,
            &ontology_version_ref,
            class_ref,
        ) {
            return response;
        }
    }

    let subject_ref = match require_scoped_ref(
        &body,
        "subject_ref",
        &[
            "object://",
            "ontology-assertion://",
            "artifact://",
            "system://",
            "domain://",
            "work-result://",
            "attempt://",
            "finding://",
            "org://",
            "project://",
            "user://",
            "worker://",
            "service://",
            "environment://",
            "package://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let polarity = match require_member(str_field(&body, "polarity"), POLARITIES, "polarity") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let object_or_value_ref = match body.get("object_or_value_ref") {
        None => Value::Null,
        Some(Value::String(value)) if value.len() <= 2048 && !value.is_empty() => json!(value),
        Some(Value::Number(number)) => json!(number),
        Some(Value::Bool(flag)) => json!(flag),
        Some(Value::Null) => Value::Null,
        Some(_) => {
            return refuse(
                "provenance_assertion_object_or_value_not_canonical",
                "object_or_value_ref must be a string, number, boolean or null",
            )
        }
    };
    let valid_time = match validate_valid_time(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let sources = match source_attribution(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let evidence = match evidence_lineage(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let uncertainty_block = match uncertainty(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let contradictions = match contradiction_state(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let applicability_scope_ref = match optional_ref(
        &body,
        "applicability_scope_ref",
        &[
            "policy://",
            "system://",
            "domain://",
            "org://",
            "project://",
        ],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let consequence_scopes = match ref_set(
        &body,
        "permitted_consequence_scope_refs",
        &["policy://"],
        MAX_REFS,
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // DECLINING TO CLAIM ALSO DECLINES TO LICENSE CONSEQUENCES. A held-unknown posture with a
    // consequence scope is a domain saying "we do not know" and "you may act on it" at once.
    if uncertainty_block
        .get("uncertainty_kind")
        .and_then(Value::as_str)
        == Some("unknown")
        && consequence_scopes.as_array().map_or(0, Vec::len) > 0
    {
        return refuse(
            "provenance_assertion_unknown_licenses_a_consequence",
            "an 'unknown' posture carries no permitted consequence scope; a domain that declines to claim also declines to license acting on the claim",
        );
    }
    let causal_ref = match optional_ref(
        &body,
        "causal_or_counterfactual_context_ref",
        &["artifact://", "finding://"],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let oracle_profile = match optional_ref(
        &body,
        "oracle_evidence_profile_ref",
        &["oracle-evidence-profile://"],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let oracle_receipt = match optional_ref(
        &body,
        "oracle_evidence_admission_receipt_ref",
        &["receipt://"],
    ) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // v1's rule survives into v2 unchanged: the profile and its qualified admission receipt travel
    // together or neither is present.
    if oracle_profile.is_null() != oracle_receipt.is_null() {
        return refuse(
            "provenance_assertion_oracle_profile_and_receipt_disagree",
            "an oracle/evidence profile and its qualified admission receipt travel together; neither substitutes for the other",
        );
    }
    if !oracle_profile.is_null() && fact_class_ref.is_null() {
        return refuse(
            "provenance_assertion_oracle_profile_without_a_fact_class",
            "an oracle-governed assertion states the fact class its profile qualified",
        );
    }
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
    let policy_hash = {
        let value = str_field(&body, "policy_hash");
        if !is_sha256(value) {
            return refuse(
                "provenance_assertion_hash_not_canonical",
                "policy_hash must be a canonical lowercase sha256: hash",
            );
        }
        value.to_owned()
    };

    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &family,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) =
        match read_lineage_and_head(&st.data_dir, &caller.identity, &scope, &family) {
            Ok(pair) => pair,
            Err(response) => return response,
        };
    // REPLAY BEFORE PRECONDITIONS: a retry after an ambiguous response necessarily observes a newer
    // head than the one it compare-and-swapped against.
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        RESOURCE_KIND,
        &family,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, &family),
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
                return bad(
                    StatusCode::BAD_GATEWAY,
                    "provenance_assertion_projection_disagrees_with_ack",
                    "this key's admitted head is absent from the family's projected lineage",
                );
            };
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "provenance_assertion": document,
                    "expected_head_for_successor": lineage
                        .last()
                        .and_then(|head| head.pointer("/admission/admission_head"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
                    "universality_nonclaim": UNIVERSALITY_NONCLAIM,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }

    let predecessor = lineage.last().cloned();
    let ordinal = predecessor
        .as_ref()
        .map_or(1, |document| ordinal_of(document) + 1);
    let predecessor_ref = predecessor
        .as_ref()
        .and_then(|document| document.get("assertion_id").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .as_ref()
        .and_then(|document| document.get("content_hash").cloned())
        .unwrap_or(Value::Null);
    let expected_head = match body.get("expected_head") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return refuse(
                "provenance_assertion_expected_head_not_canonical",
                "expected_head must be the exact current Agentgres head of this family, or null for the first revision",
            )
        }
    };
    let current_head = stream_head;
    if expected_head != current_head {
        return bad(
            StatusCode::CONFLICT,
            "provenance_assertion_expected_head_conflict",
            match (&expected_head, &current_head) {
                (None, Some(_)) => "this family already has revisions; a successor must name the exact current head".to_string(),
                (Some(_), None) => "this family has no revisions yet; the first revision names no predecessor head".to_string(),
                _ => "expected_head does not name the exact current head of this family; re-read the head and re-derive the revision".to_string(),
            },
        );
    }
    // Server-resolved values a caller may ASSERT but never AUTHOR, each refused by its own cause.
    if let Some(asserted) = body
        .get("expected_revision_ordinal")
        .and_then(Value::as_u64)
    {
        if asserted != ordinal {
            return refuse(
                "provenance_assertion_revision_gap",
                format!("this family's next revision is {ordinal}, not {asserted}; revisions are contiguous and never skip"),
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_version_ref") {
        if asserted != &predecessor_ref {
            return refuse(
                "provenance_assertion_predecessor_substituted",
                "expected_predecessor_version_ref does not name this family's exact current revision",
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "provenance_assertion_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            );
        }
    }
    if let Some(asserted) = body
        .get("expected_ontology_content_hash")
        .and_then(Value::as_str)
    {
        if asserted != term.content_hash {
            return refuse(
                "provenance_assertion_ontology_hash_substituted",
                "expected_ontology_content_hash does not match the hash the ontology owner committed for this revision",
            );
        }
    }
    let compatibility = if predecessor.is_none() {
        "initial"
    } else {
        match str_field(&body, "compatibility") {
            "additive" => "additive",
            "breaking" => "breaking",
            _ => {
                return refuse(
                    "provenance_assertion_migration_compatibility_invalid",
                    "a successor must declare compatibility 'additive' or 'breaking'; an undeclared successor silently reinterprets the claim it succeeds",
                )
            }
        }
    };
    let assertion_id = format!("{family}/revision/{ordinal}");
    let supersession_block = match supersession(&body, &assertion_id) {
        Ok(value) => value,
        Err(response) => return response,
    };

    let mut record = json!({
        "schema_version": SCHEMA_VERSION,
        "assertion_id": assertion_id,
        "assertion_family_ref": family,
        "assertion_profile": ASSERTION_PROFILE,
        "namespace": namespace,
        "name": name,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": governing_scope_ref,
        "version": version_label(ordinal),
        "revision_ordinal": ordinal,
        "predecessor_version_ref": predecessor_ref,
        "predecessor_content_hash": predecessor_hash,
        "ontology_ref": term.ontology_family_ref,
        "ontology_binding": {
            "ontology_version_ref": term.ontology_id,
            "content_hash": term.content_hash,
            "namespace": binding_namespace,
            "name": binding_name,
            "revision_ordinal": revision_ordinal,
            "record_status": if term.status == "deprecated" { "deprecated" } else { "active" },
        },
        "ontology_resolved_by": ONTOLOGY_RESOLVER,
        "fact_class_ref": fact_class_ref,
        "subject_ref": subject_ref,
        "predicate_ref": term.term_id,
        "object_or_value_ref": object_or_value_ref,
        "polarity": polarity,
        "valid_time": valid_time,
        "source_attribution": sources,
        "evidence_lineage": evidence,
        "uncertainty": uncertainty_block,
        "contradiction_state": contradictions,
        "supersession": supersession_block,
        "applicability_scope_ref": applicability_scope_ref,
        "permitted_consequence_scope_refs": consequence_scopes,
        "causal_or_counterfactual_context_ref": causal_ref,
        "oracle_evidence_profile_ref": oracle_profile,
        "oracle_evidence_admission_receipt_ref": oracle_receipt,
        "predecessor_contract_ref": PREDECESSOR_CONTRACT,
        "reinterpretation_nonclaim": REINTERPRETATION_NONCLAIM,
        "policy_hash": policy_hash,
        "migration": {
            "from_version_ref": predecessor_ref,
            "from_content_hash": predecessor_hash,
            "from_revision_ordinal": ordinal - 1,
            "compatibility": compatibility,
            "reinterprets_predecessor": false,
        },
        "universality_nonclaim": UNIVERSALITY_NONCLAIM,
        "authority_nonclaim": AUTHORITY_NONCLAIM,
    });
    let derived = match content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "provenance_assertion_content_hash_failed",
                reason,
            )
        }
    };
    if let Some(asserted) = body.get("expected_content_hash").and_then(Value::as_str) {
        if asserted != derived {
            return refuse(
                "provenance_assertion_content_hash_substituted",
                "expected_content_hash does not match the hash this exact content commits to",
            );
        }
    }
    record["content_hash"] = json!(derived);

    let payload = json!({
        "schema_version": ADMISSION_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": family,
        "assertion_record": record,
    });
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        expected_head.is_none(),
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &family,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &stream_tail(RESOURCE_KIND, &family),
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
    let lineage = match read_lineage(&st.data_dir, &caller.identity, &scope, &family) {
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
            "provenance_assertion_projection_disagrees_with_ack",
            "the admitted head is absent from this family's projected lineage",
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
            "provenance_assertion": admitted,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "predecessor_contract_ref": PREDECESSOR_CONTRACT,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "universality_nonclaim": UNIVERSALITY_NONCLAIM,
        })),
    )
}

// ------------------------------------------------------------------------------- challenge route

/// POST /v1/hypervisor/provenance-assertions/challenges — admit a challenge against, or a resolution
/// of a challenge against, one exact assertion revision.
///
/// The challenge does not edit the assertion it names and does not mint a second record beside it; it
/// appends to the assertion's own stream, and STANDING is folded out of that stream on every read.
pub(crate) async fn handle_provenance_assertion_challenge(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let challenged_ref = str_field(&body, "challenged_ref").to_owned();
    let Some(coordinates) = parse_assertion_identity(&challenged_ref) else {
        return refuse(
            "provenance_assertion_challenged_ref_not_canonical",
            "challenged_ref must be an exact assertion revision; a challenge against 'the assertion' rather than one revision of it challenges nothing in particular",
        );
    };
    let declared_contract = str_field(&body, "challenge_contract_ref");
    if !declared_contract.is_empty() && declared_contract != CHALLENGE_CONTRACT {
        return refuse(
            "provenance_assertion_challenge_contract_unsupported",
            format!(
                "this family admits challenges under {CHALLENGE_CONTRACT}; '{declared_contract}' is refused rather than downgraded into, because the v1 challenged_ref pattern cannot address a semantic-plane subject at all"
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
    let resolution = str_field(&body, "resolution").to_owned();
    let (op_kind, resolution, receipt_ref) = if resolution.is_empty() {
        (CHALLENGE_OPEN_OP, String::new(), String::new())
    } else {
        let outcome = match require_member(&resolution, RESOLUTIONS, "resolution") {
            Ok(value) => value,
            Err(response) => return response,
        };
        let declared_resolution = str_field(&body, "resolution_contract_ref");
        if !declared_resolution.is_empty() && declared_resolution != RESOLUTION_CONTRACT {
            return refuse(
                "provenance_assertion_resolution_contract_unsupported",
                format!("a resolution is receipted under {RESOLUTION_CONTRACT}"),
            );
        }
        // A standing that changed with no receipt is a verdict nobody stands behind.
        let receipt = match require_scoped_ref(&body, "resolution_receipt_ref", &["receipt://"]) {
            Ok(value) => value,
            Err(response) => return response,
        };
        (CHALLENGE_RESOLVE_OP, outcome, receipt)
    };

    let family = family_ref(&coordinates.namespace, &coordinates.name);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &family,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let (lineage, stream_head) =
        match read_lineage_and_head(&st.data_dir, &caller.identity, &scope, &family) {
            Ok(pair) => pair,
            Err(response) => return response,
        };
    let Some(subject) = lineage
        .iter()
        .find(|document| ordinal_of(document) == coordinates.ordinal)
        .cloned()
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "provenance_assertion_challenged_revision_absent",
            format!(
                "this family has no revision {} to challenge — an absent subject is a typed absence, never an accepted challenge",
                coordinates.ordinal
            ),
        );
    };
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
                "provenance_assertion_challenge_already_admitted",
                format!("'{challenge_id}' already stands against this revision"),
            );
        }
    } else if !open.contains(&challenge_id.as_str()) {
        return refuse(
            "provenance_assertion_challenge_not_open",
            format!(
                "'{challenge_id}' is not an open challenge against this revision; resolving a challenge that was never admitted would change a standing nobody contested"
            ),
        );
    }

    let payload = json!({
        "schema_version": CHALLENGE_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": family,
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
    // The STREAM head, not the last revision's.
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
            resource_kind: RESOURCE_KIND,
            resource_ref: &family,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &stream_tail(RESOURCE_KIND, &family),
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
    let lineage = match read_lineage(&st.data_dir, &caller.identity, &scope, &family) {
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
            "provenance_assertion_projection_disagrees_with_ack",
            "the challenged revision is absent from this family's projected lineage",
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
            "provenance_assertion": subject.clone(),
            "challenge_state": subject.get("challenge_state").cloned().unwrap_or(Value::Null),
            "status": subject.get("status").cloned().unwrap_or(Value::Null),
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "verdict_nonclaim": "provenance_assertion_challenge_admission_is_not_an_adjudication",
            "authority_nonclaim": AUTHORITY_NONCLAIM,
        })),
    )
}

// ------------------------------------------------------------------------------------ query consumer

#[derive(serde::Deserialize)]
pub(crate) struct AssertionQuery {
    namespace: Option<String>,
    name: Option<String>,
    revision: Option<u64>,
    subject_ref: Option<String>,
    predicate_ref: Option<String>,
    polarity: Option<String>,
    status: Option<String>,
    as_of_valid_time: Option<String>,
    as_of_transaction_time: Option<String>,
}

/// GET /v1/hypervisor/provenance-assertions — the queryable plane.
///
/// With no coordinates this answers the caller's family inventory. With them it answers one lineage,
/// narrowable by exact revision, by subject/predicate/polarity/status, and INDEPENDENTLY by
/// `as_of_transaction_time` ("as the record stood then") and `as_of_valid_time` ("what was held true
/// then"). Keeping the two axes apart is what lets this plane answer "true then, corrected now"; a
/// filter that ANDed them could not.
pub(crate) async fn handle_provenance_assertion_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<AssertionQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let (Some(namespace), Some(name)) = (query.namespace.as_deref(), query.name.as_deref()) else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "assertion_families": refs.into_iter().collect::<Vec<_>>(),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
                    "universality_nonclaim": UNIVERSALITY_NONCLAIM,
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if !canonical_token(namespace, 63) || !canonical_token(name, 63) {
        return refuse(
            "provenance_assertion_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family = family_ref(namespace, name);
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        RESOURCE_KIND,
        &family,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let lineage = match read_lineage(&st.data_dir, &identity, &scope, &family) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&projection_cache_key(&scope, &family), &lineage);

    let mut visible: Vec<&Value> = lineage.iter().collect();
    if let Some(as_of) = query.as_of_transaction_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "provenance_assertion_as_of_not_canonical",
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
    if let Some(as_of) = query.as_of_valid_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "provenance_assertion_as_of_not_canonical",
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
    let matches = |document: &Value, key: &str, wanted: &Option<String>| {
        wanted
            .as_deref()
            .is_none_or(|value| document.get(key).and_then(Value::as_str) == Some(value))
    };
    visible.retain(|document| {
        matches(document, "subject_ref", &query.subject_ref)
            && matches(document, "predicate_ref", &query.predicate_ref)
            && matches(document, "polarity", &query.polarity)
            && matches(document, "status", &query.status)
    });
    if let Some(revision) = query.revision {
        visible.retain(|document| ordinal_of(document) == revision);
        if visible.is_empty() {
            return bad(
                StatusCode::NOT_FOUND,
                "provenance_assertion_revision_absent",
                format!("this family has no revision {revision} under the requested coordinates"),
            );
        }
    }
    let records: Vec<Value> = visible.into_iter().cloned().collect();
    // A census the caller can read WITHOUT re-deriving it: negative results and disputes are counted
    // here precisely because a plane that only reports its successes has not reported anything.
    let count_status = |wanted: &str| {
        records
            .iter()
            .filter(|document| document.get("status").and_then(Value::as_str) == Some(wanted))
            .count()
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "assertion_family_ref": family,
            "revision_count": records.len(),
            "lineage_revision_count": lineage.len(),
            "negative_polarity_count": records
                .iter()
                .filter(|document| document.get("polarity").and_then(Value::as_str) == Some("negative"))
                .count(),
            "contradicted_count": count_status("contradicted"),
            "disputed_count": count_status("disputed"),
            "rejected_count": count_status("rejected"),
            "held_unknown_count": count_status("held_unknown"),
            "superseded_count": count_status("superseded"),
            "current_head": lineage
                .last()
                .and_then(|document| document.pointer("/admission/admission_head"))
                .cloned()
                .unwrap_or(Value::Null),
            "projection_index_state": index_state,
            "projection_source": "agentgres_owner_scoped_chain",
            "records": records,
            "predecessor_contract_ref": PREDECESSOR_CONTRACT,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "universality_nonclaim": UNIVERSALITY_NONCLAIM,
        })),
    )
}
