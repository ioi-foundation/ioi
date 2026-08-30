//! `OntologyVersion` — immutable, owner-qualified ontology revisions on the canonical Agentgres
//! chain (M05.1).
//!
//! WHAT IS TRUTH HERE, stated once so nothing later can quietly disagree: the Agentgres
//! owner-namespaced operation chain for one ontology FAMILY is the only durable record — this module
//! writes NO file of its own, so there is no second store to drift even in principle. One family is
//! one stream, so revisions form a head-linked chain and a successor must name the exact current
//! head. Everything served is a PROJECTION rebuilt from that chain on every read, including the
//! content hash, which is re-derived and compared rather than trusted.
//!
//! The read index is therefore a PROCESS-LOCAL cache holding one (head, revision count) pair per
//! family. It is never an answer source — the lineage is projected before the cache is consulted at
//! all — so it exists to report agreement, and a restart discards it whole. That is what makes
//! "deleting or corrupting the index cannot alter truth" structural rather than asserted: there is
//! nothing on disk to delete, and the chain's own WAL discards an unacked torn tail on replay.
//!
//! FOUR PROPERTIES ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//!
//! 1. IDENTITY IS OWNER-QUALIFIED AND CROSS-NAMESPACE. A family is addressed as
//!    `ontology://<namespace>/<name>`, and the request-resource scope reserved for that ref pins the
//!    admitting principal and tenant. Two domains may hold `patient-intake` simultaneously and
//!    neither can append to, read, or supersede the other's lineage. No ontology is presumed
//!    globally canonical (NN 8).
//!
//! 2. THE CALLER NEVER AUTHORS EVIDENCE (INV-37). Revision ordinal, version label, predecessor refs,
//!    predecessor content hash, content hash, transaction time and the admission block are all
//!    RESOLVED from the durable predecessor and the admission acknowledgement. A caller may only
//!    ASSERT what it believes those values to be; a disagreement is a typed refusal, never an
//!    accepted substitution. That is why `expected_*` exists and why there is no writable
//!    `transaction_time`.
//!
//! 3. VALID TIME AND TRANSACTION TIME ARE DIFFERENT AXES. Valid time is CONTENT — it is inside the
//!    content-hash commitment, so "true from June" cannot be edited without minting a new revision.
//!    Transaction time is ADMISSION — it comes from the admitted operation, so "recorded on the
//!    30th" is a fact about the chain. A predecessor's transaction interval CLOSES when a successor
//!    is admitted; its content bytes and content hash never move. That is what "versioned migration
//!    without reinterpreting v1" means mechanically.
//!
//! 4. MEANING GRANTS NOTHING (NN 9). Every projected revision carries
//!    `authority_nonclaim: ontology_version_grants_no_authority`, and nothing in this module
//!    consults, mints, widens or presents a capability, lease, policy decision or effect admission.
//!    Admitting a term is not permission to act on it.
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
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

/// The Agentgres owner namespace every ontology-version stream lives in. It is DATA to the
/// substrate: nothing below this module branches on it.
const OWNER_NAMESPACE: &str = "hypervisor-ontology-versions";
/// The scoped resource is the FAMILY, not the revision — one lineage, one head-linked chain.
const RESOURCE_KIND: &str = "ontology-version-family";
const ADMIT_OP: &str = "ontology_version.revision.admit";
const ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.ontology-version-admission.v1";
const CONTRACT_ID: &str = "schema://ioi/foundations/ontology-version/v1";
const CONTENT_COMMITMENT_DOMAIN: &str = "ioi.ontology-version-content-commitment-jcs-sha256.v1";
const AUTHORITY_NONCLAIM: &str = "ontology_version_grants_no_authority";
const MAX_TERMS_PER_SET: usize = 256;
const MAX_TERM_MAPPINGS: usize = 512;
const TERM_SETS: &[&str] = &[
    "entity_types",
    "relationship_types",
    "event_types",
    "action_types",
];
const DISPOSITIONS: &[&str] = &[
    "retained", "renamed", "added", "removed", "narrowed", "widened",
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

// ---------------------------------------------------------------- coordinates and canonical hashes

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

fn family_ref(namespace: &str, name: &str) -> String {
    format!("ontology://{namespace}/{name}")
}

fn revision_ref(namespace: &str, name: &str, ordinal: u64) -> String {
    format!("ontology://{namespace}/{name}/revision/{ordinal}")
}

fn version_label(ordinal: u64) -> String {
    format!("v{ordinal}")
}

fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// The exact material the registered invariant
/// `ontology_version.content_hash.commits_semantic_content_and_valid_time` commits.
///
/// `transaction_time` is DELIBERATELY absent: when a fact was true is content, when it was recorded
/// is admission. Keeping the two apart is what lets a predecessor's transaction interval close
/// without its content hash moving.
const CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "ontology_family_ref",
    "namespace",
    "name",
    "version",
    "revision_ordinal",
    "predecessor_version_ref",
    "predecessor_content_hash",
    "entity_types",
    "relationship_types",
    "event_types",
    "action_types",
    "invariant_refs",
    "governing_scope_ref",
    "compatibility_profile_ref",
    "deprecation_policy_ref",
    "policy_hash",
    "valid_time",
];

/// The SEMANTIC content alone — the same declaration minus its lineage coordinates.
///
/// This exists because the content hash necessarily differs between any two revisions: ordinal,
/// version label and predecessor refs are inside it, so comparing content hashes could never detect
/// "this edit changes nothing". Comparing what the revision actually MEANS can.
const SEMANTIC_MATERIAL_FIELDS: &[&str] = &[
    "ontology_family_ref",
    "namespace",
    "name",
    "entity_types",
    "relationship_types",
    "event_types",
    "action_types",
    "valid_time",
    "invariant_refs",
    "governing_scope_ref",
    "compatibility_profile_ref",
    "deprecation_policy_ref",
    "policy_hash",
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

fn semantic_digest(record: &Value) -> Result<String, String> {
    digest_over(
        record,
        "ioi.ontology-version-semantic-content-jcs-sha256.v1",
        SEMANTIC_MATERIAL_FIELDS,
    )
}

fn parse_time(value: &str) -> Option<u64> {
    // Deterministic RFC3339 -> epoch-ms, shared with the substrate's own operation timestamps.
    // A malformed stamp reads as absent rather than as zero-o'clock.
    (value.len() >= 20 && value.ends_with('Z') || value.len() >= 25)
        .then(|| agentgres::parse_rfc3339_ms(value))
        .filter(|ms| *ms > 0)
}

// ------------------------------------------------------------------------------- request validation

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// The caller-supplied semantic content of one revision, already checked for shape.
#[derive(Debug)]
struct ProposedContent {
    namespace: String,
    name: String,
    governing_scope_ref: String,
    policy_hash: String,
    compatibility_profile_ref: Value,
    deprecation_policy_ref: Value,
    invariant_refs: Value,
    term_sets: BTreeMap<String, Value>,
    valid_time: Value,
    compatibility: String,
    term_mappings: Value,
}

fn term_set(body: &Value, key: &str, namespace: &str, name: &str) -> Result<Value, Reply> {
    let items = body.get(key).cloned().unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_version_term_set_malformed",
            format!("{key} must be an array of {{term_id,label}} terms"),
        ));
    };
    if entries.len() > MAX_TERMS_PER_SET {
        return Err(refuse(
            "ontology_version_term_set_too_large",
            format!("{key} carries more than {MAX_TERMS_PER_SET} terms"),
        ));
    }
    let prefix = format!("ontology://{namespace}/{name}/term/");
    let mut seen = Vec::new();
    for entry in entries {
        let term_id = str_field(entry, "term_id");
        let label = str_field(entry, "label");
        if !term_id.starts_with(&prefix) {
            return Err(refuse(
                "ontology_version_term_foreign_namespace",
                format!(
                    "{key} declares '{term_id}', which is not a term of this owner-qualified family — a version never mints terms in another domain's namespace"
                ),
            ));
        }
        if !canonical_token(&term_id[prefix.len()..], 63) {
            return Err(refuse(
                "ontology_version_term_id_not_canonical",
                format!("{key} declares a non-canonical term id '{term_id}'"),
            ));
        }
        if label.is_empty() || label.len() > 160 {
            return Err(refuse(
                "ontology_version_term_label_required",
                format!("{key} term '{term_id}' needs a 1..160 character label"),
            ));
        }
        if seen.iter().any(|seen: &String| seen == term_id) {
            return Err(refuse(
                "ontology_version_term_duplicated",
                format!("{key} declares '{term_id}' twice"),
            ));
        }
        seen.push(term_id.to_string());
    }
    Ok(items)
}

fn optional_ref(body: &Value, key: &str, scheme: &str) -> Result<Value, Reply> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value))
            if value.starts_with(scheme) && value.len() <= scheme.len() + 240 =>
        {
            Ok(json!(value))
        }
        Some(_) => Err(refuse(
            "ontology_version_ref_not_canonical",
            format!("{key} must be null or a '{scheme}' ref"),
        )),
    }
}

fn validate_proposal(body: &Value) -> Result<ProposedContent, Reply> {
    if body.get("transaction_time").is_some_and(|v| !v.is_null()) {
        return Err(refuse(
            "ontology_version_transaction_time_server_resolved",
            "transaction_time is the admission's own fact and is resolved by the daemon; a caller that could write it could backdate the record of when it was recorded",
        ));
    }
    for authored in ["admission", "content_hash", "ontology_id", "status"] {
        if body.get(authored).is_some_and(|v| !v.is_null()) {
            return Err(refuse(
                "ontology_version_field_server_resolved",
                format!(
                    "{authored} is resolved from durable Agentgres truth and cannot be supplied"
                ),
            ));
        }
    }
    let namespace = str_field(body, "namespace").to_string();
    let name = str_field(body, "name").to_string();
    if !canonical_token(&namespace, 63) || !canonical_token(&name, 63) {
        return Err(refuse(
            "ontology_version_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token; identity is owner-qualified, so both are required",
        ));
    }
    let governing_scope_ref = str_field(body, "governing_scope_ref").to_string();
    if ![
        "domain://",
        "org://",
        "project://",
        "service://",
        "system://",
    ]
    .iter()
    .any(|scheme| governing_scope_ref.starts_with(scheme))
        || governing_scope_ref.len() > 248
    {
        return Err(refuse(
            "ontology_version_governing_scope_required",
            "governing_scope_ref must name the scope this local meaning governs",
        ));
    }
    let policy_hash = str_field(body, "policy_hash").to_string();
    if !is_sha256(&policy_hash) {
        return Err(refuse(
            "ontology_version_policy_hash_required",
            "policy_hash must be a sha256: digest of the policy set this revision was admitted under",
        ));
    }
    let compatibility_profile_ref =
        optional_ref(body, "compatibility_profile_ref", "compatibility://")?;
    let deprecation_policy_ref = optional_ref(body, "deprecation_policy_ref", "policy://")?;
    let invariant_refs = match body.get("invariant_refs") {
        None | Some(Value::Null) => json!([]),
        Some(Value::Array(entries)) if entries.len() <= 128 => {
            for entry in entries {
                if !entry
                    .as_str()
                    .is_some_and(|value| value.starts_with("invariant://") && value.len() <= 252)
                {
                    return Err(refuse(
                        "ontology_version_invariant_ref_not_canonical",
                        "every invariant_refs entry must be an 'invariant://' ref",
                    ));
                }
            }
            json!(entries)
        }
        Some(_) => {
            return Err(refuse(
                "ontology_version_invariant_refs_malformed",
                "invariant_refs must be an array of at most 128 'invariant://' refs",
            ))
        }
    };
    let mut term_sets = BTreeMap::new();
    for key in TERM_SETS {
        term_sets.insert((*key).to_string(), term_set(body, key, &namespace, &name)?);
    }
    if term_sets
        .values()
        .all(|set| set.as_array().is_some_and(Vec::is_empty))
    {
        return Err(refuse(
            "ontology_version_declares_no_terms",
            "a revision with no entity, relationship, event or action term declares no meaning at all",
        ));
    }
    let valid_time = validate_valid_time(body)?;
    let compatibility = str_field(body, "compatibility").to_string();
    let term_mappings = validate_term_mappings(body, &namespace, &name)?;
    Ok(ProposedContent {
        namespace,
        name,
        governing_scope_ref,
        policy_hash,
        compatibility_profile_ref,
        deprecation_policy_ref,
        invariant_refs,
        term_sets,
        valid_time,
        compatibility,
        term_mappings,
    })
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

fn validate_valid_time(body: &Value) -> Result<Value, Reply> {
    let valid_time = body.get("valid_time").cloned().unwrap_or(Value::Null);
    let starts_at = str_field(&valid_time, "starts_at").to_string();
    let Some(starts_ms) = parse_time(&starts_at) else {
        return Err(refuse(
            "ontology_version_valid_time_required",
            "valid_time.starts_at must be an RFC3339 instant: a domain that cannot say when a meaning became true cannot hold 'true then, not now'",
        ));
    };
    let ends_at = match valid_time.get("ends_at") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) => {
            let Some(ends_ms) = parse_time(value) else {
                return Err(refuse(
                    "ontology_version_valid_time_not_parseable",
                    "valid_time.ends_at must be an RFC3339 instant or null",
                ));
            };
            if ends_ms <= starts_ms {
                return Err(refuse(
                    "ontology_version_valid_time_not_ordered",
                    "valid_time.ends_at must be strictly after valid_time.starts_at",
                ));
            }
            json!(value)
        }
        Some(_) => {
            return Err(refuse(
                "ontology_version_valid_time_not_parseable",
                "valid_time.ends_at must be an RFC3339 instant or null",
            ))
        }
    };
    Ok(json!({ "starts_at": starts_at, "ends_at": ends_at }))
}

fn validate_term_mappings(body: &Value, namespace: &str, name: &str) -> Result<Value, Reply> {
    let mappings = body
        .get("term_mappings")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let Some(entries) = mappings.as_array() else {
        return Err(refuse(
            "ontology_version_term_mappings_malformed",
            "term_mappings must be an array of {from_term_id,to_term_id,disposition}",
        ));
    };
    if entries.len() > MAX_TERM_MAPPINGS {
        return Err(refuse(
            "ontology_version_term_mappings_too_large",
            format!("term_mappings carries more than {MAX_TERM_MAPPINGS} entries"),
        ));
    }
    let prefix = format!("ontology://{namespace}/{name}/term/");
    for entry in entries {
        if entry.get("reinterprets_predecessor").is_some() {
            return Err(refuse(
                "ontology_version_migration_reinterpretation_refused",
                "a migration never reinterprets the revision it succeeds; the predecessor's bytes and content hash are frozen",
            ));
        }
        let from_term_id = str_field(entry, "from_term_id");
        if !from_term_id.starts_with(&prefix) {
            return Err(refuse(
                "ontology_version_term_foreign_namespace",
                format!("term_mappings maps '{from_term_id}', which is not a term of this family"),
            ));
        }
        match entry.get("to_term_id") {
            Some(Value::Null) | None => {}
            Some(Value::String(to_term_id)) if to_term_id.starts_with(&prefix) => {}
            Some(_) => {
                return Err(refuse(
                    "ontology_version_term_foreign_namespace",
                    "term_mappings may only map to a term of this family, or to null for a removal",
                ))
            }
        }
        if !DISPOSITIONS.contains(&str_field(entry, "disposition")) {
            return Err(refuse(
                "ontology_version_term_disposition_unsupported",
                format!("every term mapping needs a disposition from {DISPOSITIONS:?}"),
            ));
        }
    }
    Ok(mappings)
}

// ----------------------------------------------------------------------- durable lineage projection

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

fn project_admitted(entry: &ExactProjection) -> Result<AdmittedRevision, String> {
    if entry.operation.op_kind != ADMIT_OP {
        return Err(format!(
            "ontology-version stream carries an unknown operation '{}'",
            entry.operation.op_kind
        ));
    }
    let payload = &entry.operation.payload;
    if payload.get("schema_version").and_then(Value::as_str) != Some(ADMISSION_PAYLOAD_SCHEMA) {
        return Err("ontology-version admission carries an unknown payload schema".into());
    }
    let record = payload
        .get("version_record")
        .cloned()
        .ok_or_else(|| "ontology-version admission carries no version record".to_string())?;
    // The served content hash is RE-DERIVED, never trusted: a tampered log frame or a rebuilt index
    // cannot make this module serve bytes that do not hash to what they claim.
    let derived = content_hash(&record)?;
    if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
        return Err("ontology-version admitted content does not match its committed hash".into());
    }
    Ok(AdmittedRevision {
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

/// Assemble the registered `OntologyVersion` contract document for one admitted revision.
///
/// `superseded_at` closes the predecessor's TRANSACTION interval. Nothing inside the content
/// commitment moves, which is precisely why v1 remains addressable and unreinterpreted.
fn contract_document(
    revision: &AdmittedRevision,
    family: &str,
    superseded_at: Option<&str>,
) -> Result<Value, String> {
    let mut document = revision.record.clone();
    let ontology_id = document
        .get("ontology_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "admitted revision carries no ontology_id".to_string())?
        .to_string();
    let content_hash = document
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
        "ontology_id": ontology_id,
        "content_hash": content_hash,
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
    document["authority_nonclaim"] = json!(AUTHORITY_NONCLAIM);
    document["status"] = json!(if superseded_at.is_some() {
        "deprecated"
    } else {
        "active"
    });
    validate_architecture_contract(CONTRACT_ID, &document).map_err(|reason| {
        format!("projected ontology version is not registered-valid: {reason}")
    })?;
    Ok(document)
}

/// The whole lineage of one family, rebuilt from the chain and contract-validated.
fn project_lineage(history: &[ExactProjection], family: &str) -> Result<Vec<Value>, String> {
    let revisions = history
        .iter()
        .map(project_admitted)
        .collect::<Result<Vec<_>, _>>()?;
    let mut documents = Vec::with_capacity(revisions.len());
    for (index, revision) in revisions.iter().enumerate() {
        let superseded_at = revisions
            .get(index + 1)
            .map(|next| admitted_stamp(next.recorded_at_ms));
        documents.push(contract_document(
            revision,
            family,
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

// ------------------------------------------------------------- rebuildable, process-local, non-truth

/// One (admitted head, revision count) pair per family. Process-local and never durable.
static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

/// Record what the cache held for this family BEFORE the freshly projected lineage replaced it.
///
/// The lineage is already computed when this is called, so the cache cannot contribute to the
/// answer — it is consulted only to report agreement. Reporting it lets a verifier assert rebuild by
/// POSITIVE detection: an unchanged answer is also consistent with a cache that was never dropped,
/// which would prove nothing.
fn projection_cache_state(family: &str, lineage: &[Value]) -> &'static str {
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
    let state = match cache.get(family) {
        None => "rebuilt_from_agentgres",
        Some(held) if *held == observed => "agreed_with_agentgres",
        Some(_) => "stale_rebuilt_from_agentgres",
    };
    cache.insert(family.to_string(), observed);
    state
}

// --------------------------------------------------------------------------------- read path helpers

fn read_lineage(
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    family: &str,
) -> Result<Vec<Value>, Reply> {
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
    project_lineage(&history, family).map_err(|reason| {
        bad(
            StatusCode::BAD_GATEWAY,
            "ontology_version_projection_failed",
            reason,
        )
    })
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

// ------------------------------------------------------------------------------------ producer route

/// POST /v1/hypervisor/ontology-versions — admit one immutable revision of one owner-qualified
/// ontology family against the exact current head of its Agentgres chain.
pub(crate) async fn handle_ontology_version_admit(
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
    let family = family_ref(&proposal.namespace, &proposal.name);
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
    let lineage = match read_lineage(&st.data_dir, &caller.identity, &scope, &family) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    // Read the durable lineage BEFORE deriving anything a retry cannot reproduce. Everything below
    // is a function of this projection plus the request body.
    let predecessor = lineage.last().cloned();

    // REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer
    // head than the one it originally compare-and-swapped against, so checking `expected_head` first
    // would turn every real duplicate into a conflict and make the idempotency key unusable — which
    // is exactly what it is for. The substrate owns replay; this only reaches the answer it holds.
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
                    "ontology_version_projection_disagrees_with_ack",
                    "this key's admitted head is absent from the family's projected lineage",
                );
            };
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "ontology_version": document,
                    "expected_head_for_successor": lineage
                        .last()
                        .and_then(|head| head.pointer("/admission/admission_head"))
                        .cloned()
                        .unwrap_or(Value::Null),
                    "receipt_ref": document.pointer("/admission/agentgres_receipt_ref").cloned().unwrap_or(Value::Null),
                    "operation_ref": document.pointer("/admission/agentgres_operation_ref").cloned().unwrap_or(Value::Null),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
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
                "ontology_version_expected_head_not_canonical",
                "expected_head must be the exact current Agentgres head of this family, or null for the first revision",
            )
        }
    };
    let current_head = predecessor
        .as_ref()
        .and_then(|document| document.pointer("/admission/admission_head"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    // Exact-head admission, checked here so the refusal names the ontology fact rather than surfacing
    // as a bare substrate conflict. The substrate CAS below is still the authority.
    if expected_head != current_head {
        return bad(
            StatusCode::CONFLICT,
            "ontology_version_expected_head_conflict",
            match (&expected_head, &current_head) {
                (None, Some(_)) => "this family already has revisions; a successor must name the exact current head".to_string(),
                (Some(_), None) => "this family has no revisions yet; the first revision names no predecessor head".to_string(),
                _ => "expected_head does not name the exact current head of this family; re-read the head and re-derive the revision".to_string(),
            },
        );
    }

    let ordinal = predecessor
        .as_ref()
        .map_or(1, |document| ordinal_of(document) + 1);
    let predecessor_ref = predecessor
        .as_ref()
        .and_then(|document| document.get("ontology_id").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .as_ref()
        .and_then(|document| document.get("content_hash").cloned())
        .unwrap_or(Value::Null);

    // Server-resolved values a caller may ASSERT but never AUTHOR. Each disagreement is refused by
    // its own cause, because "gap", "fork", "wrong predecessor" and "wrong hash" have different
    // remedies and a single generic conflict would hide which one happened.
    if let Some(asserted) = body
        .get("expected_revision_ordinal")
        .and_then(Value::as_u64)
    {
        if asserted != ordinal {
            return refuse(
                "ontology_version_revision_gap",
                format!("this family's next revision is {ordinal}, not {asserted}; revisions are contiguous and never skip"),
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_version_ref") {
        if asserted != &predecessor_ref {
            return refuse(
                "ontology_version_predecessor_substituted",
                "expected_predecessor_version_ref does not name this family's exact current revision",
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "ontology_version_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            );
        }
    }
    if let Some(document) = predecessor.as_ref() {
        if document.get("namespace") != Some(&json!(proposal.namespace))
            || document.get("name") != Some(&json!(proposal.name))
        {
            return refuse(
                "ontology_version_namespace_substituted",
                "a successor cannot move its family into another namespace or local name",
            );
        }
    }

    let compatibility = if predecessor.is_none() {
        if !proposal.compatibility.is_empty() && proposal.compatibility != "initial" {
            return refuse(
                "ontology_version_migration_compatibility_invalid",
                "the first revision of a family migrates from nothing; its compatibility is 'initial'",
            );
        }
        "initial"
    } else {
        match proposal.compatibility.as_str() {
            "additive" | "breaking" => proposal.compatibility.as_str(),
            _ => {
                return refuse(
                    "ontology_version_migration_compatibility_invalid",
                    "a successor must declare compatibility 'additive' or 'breaking'; an undeclared migration is a silent schema change",
                )
            }
        }
    };
    let mapping_count = proposal.term_mappings.as_array().map_or(0, Vec::len);
    if predecessor.is_none() && mapping_count > 0 {
        return refuse(
            "ontology_version_migration_not_applicable",
            "the first revision of a family has nothing to migrate from",
        );
    }
    if predecessor.is_some() && mapping_count == 0 {
        return refuse(
            "ontology_version_migration_required",
            "a successor must state how each affected term migrates; an unexplained successor silently reinterprets its predecessor",
        );
    }

    let mut record = json!({
        "schema_version": "ioi.ontology-version.v1",
        "ontology_id": revision_ref(&proposal.namespace, &proposal.name, ordinal),
        "ontology_family_ref": family,
        "ontology_record_profile": "ontology_version",
        "namespace": proposal.namespace,
        "name": proposal.name,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": proposal.governing_scope_ref,
        "version": version_label(ordinal),
        "revision_ordinal": ordinal,
        "predecessor_version_ref": predecessor_ref,
        "predecessor_content_hash": predecessor_hash,
        "invariant_refs": proposal.invariant_refs,
        "compatibility_profile_ref": proposal.compatibility_profile_ref,
        "deprecation_policy_ref": proposal.deprecation_policy_ref,
        "policy_hash": proposal.policy_hash,
        "valid_time": proposal.valid_time,
        "migration": {
            "from_version_ref": predecessor_ref,
            "from_content_hash": predecessor_hash,
            "from_revision_ordinal": ordinal - 1,
            "compatibility": compatibility,
            "reinterprets_predecessor": false,
            "term_mappings": proposal.term_mappings,
        },
    });
    for (key, value) in proposal.term_sets {
        record[key] = value;
    }
    let derived_hash = match content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ontology_version_content_hash_failed",
                reason,
            )
        }
    };
    if let Some(asserted) = body.get("expected_content_hash").and_then(Value::as_str) {
        if asserted != derived_hash {
            return refuse(
                "ontology_version_content_hash_substituted",
                "expected_content_hash does not match the hash this exact content commits to",
            );
        }
    }
    if let Some(asserted) = body.get("expected_version").and_then(Value::as_str) {
        if asserted != version_label(ordinal) {
            return refuse(
                "ontology_version_version_label_substituted",
                format!(
                    "this revision is {}, not '{asserted}'",
                    version_label(ordinal)
                ),
            );
        }
    }
    // "Changes nothing" is a question about MEANING, so it is asked of the semantic digest. The
    // content hash could never answer it: ordinal, version and predecessor refs are inside that
    // commitment, so two successive revisions differ there by construction.
    if let Some(previous) = predecessor.as_ref() {
        let (proposed_meaning, previous_meaning) =
            match (semantic_digest(&record), semantic_digest(previous)) {
                (Ok(proposed), Ok(previous)) => (proposed, previous),
                (Err(reason), _) | (_, Err(reason)) => {
                    return bad(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ontology_version_content_hash_failed",
                        reason,
                    )
                }
            };
        if proposed_meaning == previous_meaning {
            return refuse(
                "ontology_version_no_op_revision",
                "this revision declares exactly the meaning its predecessor already declares; an edit that changes nothing is a replayed head, not a successor",
            );
        }
    }
    record["content_hash"] = json!(derived_hash);

    let payload = json!({
        "schema_version": ADMISSION_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": family,
        "version_record": record,
    });
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    // The SHARED admission boundary — the same one every owner-scoped daemon mutation crosses. It is
    // reached with an explicit `recorded_at_ms` because transaction time is this family's own fact and
    // a zero stamp would date every revision to the epoch. The value is outside replay identity, so
    // an exact retry still replays the ORIGINAL admitted operation and its original timestamp.
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

    // Read back from the chain: the response is a projection of durable truth, never of the value
    // this handler happened to build.
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
            "ontology_version_projection_disagrees_with_ack",
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
            "ontology_version": admitted,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
        })),
    )
}

// ------------------------------------------------------------------------------------ consumer route

#[derive(serde::Deserialize)]
pub(crate) struct LineageQuery {
    namespace: Option<String>,
    name: Option<String>,
    revision: Option<u64>,
    as_of_valid_time: Option<String>,
    as_of_transaction_time: Option<String>,
}

/// GET /v1/hypervisor/ontology-versions — exact lookup, whole lineage, or a bitemporal cell.
///
/// With no `namespace`/`name` this answers the caller's family inventory. With both it answers one
/// lineage, optionally narrowed by `revision` (exact), `as_of_transaction_time` ("as the record stood
/// then") and `as_of_valid_time` ("what was held true then"). The two narrowings are INDEPENDENT,
/// which is the whole point of keeping the axes apart.
pub(crate) async fn handle_ontology_version_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<LineageQuery>,
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
                    "ontology_families": refs.into_iter().collect::<Vec<_>>(),
                    "authority_nonclaim": AUTHORITY_NONCLAIM,
                })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    if !canonical_token(namespace, 63) || !canonical_token(name, 63) {
        return refuse(
            "ontology_version_coordinates_not_canonical",
            "namespace and name must each be a lowercase 1..63 character token",
        );
    }
    let family = family_ref(namespace, name);
    let lineage = match authorized_lineage(&st.data_dir, &identity, &family) {
        Ok(lineage) => lineage,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&family, &lineage);

    // TRANSACTION-TIME travel first: it decides which revisions had been RECORDED yet.
    let mut visible: Vec<&Value> = lineage.iter().collect();
    if let Some(as_of) = query.as_of_transaction_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "ontology_version_as_of_transaction_time_not_parseable",
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
    // VALID-TIME travel second: among what had been recorded, what was held TRUE at that instant.
    if let Some(as_of) = query.as_of_valid_time.as_deref() {
        let Some(as_of_ms) = parse_time(as_of) else {
            return refuse(
                "ontology_version_as_of_valid_time_not_parseable",
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
            starts.is_some_and(|starts| starts <= as_of_ms)
                && ends.is_none_or(|ends| as_of_ms < ends)
        });
    }
    if let Some(revision) = query.revision {
        visible.retain(|document| ordinal_of(document) == revision);
        if visible.is_empty() {
            return bad(
                StatusCode::NOT_FOUND,
                "ontology_version_revision_absent",
                format!(
                    "this family has no revision {revision} under the requested time coordinates"
                ),
            );
        }
    }
    let resolved = visible.last().cloned().cloned().unwrap_or(Value::Null);
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ontology_family_ref": family,
            "revision_count": lineage.len(),
            "matched_revision_count": visible.len(),
            // Under a transaction-time narrowing this is the head AS IT STOOD THEN, which is what
            // makes "recorded then, corrected now" a different answer from "true then, not now".
            "resolved_ontology_version": resolved,
            "lineage": visible.into_iter().cloned().collect::<Vec<_>>(),
            "rebuildable_index_state": index_state,
            "truth_source": "agentgres_owner_scoped_chain",
            "authority_nonclaim": AUTHORITY_NONCLAIM,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::super::substrate_store::{request_identity_for_test, reset_handle_for_test};
    use super::*;

    fn caller(principal: &str, key: &str) -> WriteCaller {
        WriteCaller {
            identity: request_identity_for_test(principal, ["org://acme-clinic".to_string()]),
            owner_ref: "org://acme-clinic".to_string(),
            idempotency_key: key.to_string(),
        }
    }

    fn proposal(namespace: &str, name: &str, terms: &[&str], starts_at: &str) -> Value {
        json!({
            "owner_ref": "org://acme-clinic",
            "idempotency_key": "unused-here",
            "namespace": namespace,
            "name": name,
            "governing_scope_ref": format!("domain://{namespace}/intake"),
            "policy_hash": format!("sha256:{}", "1a".repeat(32)),
            "entity_types": terms
                .iter()
                .map(|term| json!({
                    "term_id": format!("ontology://{namespace}/{name}/term/{term}"),
                    "label": term,
                }))
                .collect::<Vec<_>>(),
            "valid_time": { "starts_at": starts_at, "ends_at": null },
        })
    }

    /// Admit one revision through the same server-side derivation the route uses, returning the
    /// projected contract document and the head a successor must name.
    fn admit(
        data_dir: &str,
        caller: &WriteCaller,
        body: &Value,
        expected_head: Option<&str>,
    ) -> Result<(Value, String), String> {
        let content = validate_proposal(body).map_err(|(_, Json(body))| body.to_string())?;
        let family = family_ref(&content.namespace, &content.name);
        let scope = bind_request_resource_scope(
            data_dir,
            &caller.identity,
            RESOURCE_KIND,
            &family,
            &caller.owner_ref,
            &caller.owner_ref,
            &caller.idempotency_key,
        )
        .map_err(|error| error.message())?;
        let tail = stream_tail(RESOURCE_KIND, &family);
        let history = read_owner_scoped_history(
            data_dir,
            &caller.identity,
            &scope,
            RESOURCE_KIND,
            &family,
            OWNER_NAMESPACE,
            &tail,
        )
        .map_err(|error| error.message())?;
        let lineage = project_lineage(&history, &family)?;
        let predecessor = lineage.last().cloned();
        let ordinal = predecessor.as_ref().map_or(1, |d| ordinal_of(d) + 1);
        let predecessor_ref = predecessor
            .as_ref()
            .and_then(|d| d.get("ontology_id").cloned())
            .unwrap_or(Value::Null);
        let predecessor_hash = predecessor
            .as_ref()
            .and_then(|d| d.get("content_hash").cloned())
            .unwrap_or(Value::Null);
        let mut record = json!({
            "schema_version": "ioi.ontology-version.v1",
            "ontology_id": revision_ref(&content.namespace, &content.name, ordinal),
            "ontology_family_ref": family,
            "ontology_record_profile": "ontology_version",
            "namespace": content.namespace,
            "name": content.name,
            "owner_id": caller.owner_ref,
            "governing_scope_ref": content.governing_scope_ref,
            "version": version_label(ordinal),
            "revision_ordinal": ordinal,
            "predecessor_version_ref": predecessor_ref,
            "predecessor_content_hash": predecessor_hash,
            "invariant_refs": content.invariant_refs,
            "compatibility_profile_ref": content.compatibility_profile_ref,
            "deprecation_policy_ref": content.deprecation_policy_ref,
            "policy_hash": content.policy_hash,
            "valid_time": content.valid_time,
            "migration": {
                "from_version_ref": predecessor_ref,
                "from_content_hash": predecessor_hash,
                "from_revision_ordinal": ordinal - 1,
                "compatibility": if ordinal == 1 { "initial" } else { "breaking" },
                "reinterprets_predecessor": false,
                "term_mappings": if ordinal == 1 {
                    json!([])
                } else {
                    json!([{
                        "from_term_id": format!("ontology://{}/{}/term/patient", content.namespace, content.name),
                        "to_term_id": format!("ontology://{}/{}/term/patient", content.namespace, content.name),
                        "disposition": "retained",
                    }])
                },
            },
        });
        for (key, value) in content.term_sets {
            record[key] = value;
        }
        record["content_hash"] = json!(content_hash(&record)?);
        let payload = json!({
            "schema_version": ADMISSION_PAYLOAD_SCHEMA,
            "owner_ref": caller.owner_ref,
            "resource_ref": family,
            "version_record": record,
        });
        let commit = admit_owner_scoped_mutation(
            data_dir,
            expected_head.is_none(),
            ScopedMutation {
                identity: &caller.identity,
                scope: &scope,
                resource_kind: RESOURCE_KIND,
                resource_ref: &family,
                owner_namespace: OWNER_NAMESPACE,
                stream_tail: &tail,
                op_kind: ADMIT_OP,
                expected_head,
                payload: &payload,
                idempotency_key: &caller.idempotency_key,
                recorded_at_ms: 1_756_000_000_000 + ordinal * 3_600_000,
            },
        )
        .map_err(|error| error.message())?;
        let lineage = project_lineage(
            &read_owner_scoped_history(
                data_dir,
                &caller.identity,
                &scope,
                RESOURCE_KIND,
                &family,
                OWNER_NAMESPACE,
                &tail,
            )
            .map_err(|error| error.message())?,
            &family,
        )?;
        let head = commit.projection.head.clone();
        let document = lineage
            .iter()
            .find(|d| d.pointer("/admission/admission_head") == Some(&json!(head)))
            .cloned()
            .ok_or_else(|| "admitted head is absent from the lineage".to_string())?;
        Ok((document, head))
    }

    #[test]
    fn a_successor_leaves_its_predecessor_addressable_and_unreinterpreted() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let caller = caller("user://acme", "genesis-1");
        let (v1, head) = admit(
            data_dir,
            &caller,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        assert_eq!(
            v1["ontology_id"],
            "ontology://acme-clinic/patient-intake/revision/1"
        );
        assert_eq!(v1["version"], "v1");
        assert_eq!(v1["status"], "active");
        let v1_content_hash = v1["content_hash"].clone();

        let successor_caller = caller_with_key(&caller, "successor-2");
        let (v2, _head) = admit(
            data_dir,
            &successor_caller,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        assert_eq!(v2["revision_ordinal"], 2);
        assert_eq!(v2["predecessor_version_ref"], v1["ontology_id"]);
        assert_eq!(v2["predecessor_content_hash"], v1_content_hash);
        assert_eq!(v2["migration"]["reinterprets_predecessor"], json!(false));

        // v1 is still addressable, its CONTENT is byte-identical, and only its transaction interval
        // closed. That is the whole "versioned migration without reinterpreting v1" claim.
        let scope = authorize_request_resource_scope(
            data_dir,
            &caller.identity,
            RESOURCE_KIND,
            "ontology://acme-clinic/patient-intake",
            None,
        )
        .unwrap();
        let lineage = read_lineage(
            data_dir,
            &caller.identity,
            &scope,
            "ontology://acme-clinic/patient-intake",
        )
        .unwrap();
        let replayed_v1 = &lineage[0];
        assert_eq!(replayed_v1["content_hash"], v1_content_hash);
        assert_eq!(replayed_v1["entity_types"], v1["entity_types"]);
        assert_eq!(replayed_v1["valid_time"], v1["valid_time"]);
        assert_eq!(replayed_v1["status"], "deprecated");
        assert_eq!(
            replayed_v1["transaction_time"]["superseded_at"],
            v2["transaction_time"]["recorded_at"]
        );
        reset_handle_for_test();
    }

    fn caller_with_key(base: &WriteCaller, key: &str) -> WriteCaller {
        WriteCaller {
            identity: base.identity.clone(),
            owner_ref: base.owner_ref.clone(),
            idempotency_key: key.to_string(),
        }
    }

    #[test]
    fn a_stale_head_forks_nothing_and_the_chain_is_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let owner = caller("user://acme", "genesis-1");
        let (_v1, head) = admit(
            data_dir,
            &owner,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        let (_v2, _) = admit(
            data_dir,
            &caller_with_key(&owner, "successor-2"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        // A third revision offered against v1's head is a fork attempt.
        let forked = admit(
            data_dir,
            &caller_with_key(&owner, "fork-3"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "visitor"],
                "2026-07-01T00:00:00Z",
            ),
            Some(&head),
        );
        assert!(forked.is_err(), "a stale head must not admit");
        let scope = authorize_request_resource_scope(
            data_dir,
            &owner.identity,
            RESOURCE_KIND,
            "ontology://acme-clinic/patient-intake",
            None,
        )
        .unwrap();
        let lineage = read_lineage(
            data_dir,
            &owner.identity,
            &scope,
            "ontology://acme-clinic/patient-intake",
        )
        .unwrap();
        assert_eq!(lineage.len(), 2, "a refused fork appended nothing");
        reset_handle_for_test();
    }

    #[test]
    fn two_namespaces_hold_the_same_local_name_without_colliding() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let acme = caller("user://acme", "acme-genesis");
        let (acme_v1, _) = admit(
            data_dir,
            &acme,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        let harbor = WriteCaller {
            identity: request_identity_for_test(
                "user://harbor",
                ["org://harbor-clinic".to_string()],
            ),
            owner_ref: "org://harbor-clinic".to_string(),
            idempotency_key: "harbor-genesis".to_string(),
        };
        let (harbor_v1, _) = admit(
            data_dir,
            &harbor,
            &proposal(
                "harbor-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        assert_ne!(acme_v1["ontology_id"], harbor_v1["ontology_id"]);
        assert_ne!(acme_v1["content_hash"], harbor_v1["content_hash"]);
        // Neither owner can reach the other's lineage.
        assert!(authorize_request_resource_scope(
            data_dir,
            &acme.identity,
            RESOURCE_KIND,
            "ontology://harbor-clinic/patient-intake",
            None,
        )
        .is_err());
        reset_handle_for_test();
    }

    #[test]
    fn this_family_writes_no_durable_artifact_beside_its_chain() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let owner = caller("user://acme", "genesis-1");
        let (_v1, head) = admit(
            data_dir,
            &owner,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        admit(
            data_dir,
            &caller_with_key(&owner, "successor-2"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        // Everything this family produced lives under the shared substrate directory. A directory of
        // its own would BE the second store this module exists without.
        let entries: Vec<String> = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("ontology"))
            .collect();
        assert!(
            entries.is_empty(),
            "an ontology-version directory appeared beside the chain: {entries:?}"
        );
        reset_handle_for_test();
    }

    #[test]
    fn the_projection_cache_is_reported_and_can_never_be_the_answer() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let owner = caller("user://acme", "genesis-1");
        let (v1, head) = admit(
            data_dir,
            &owner,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        let family = "ontology://acme-clinic/patient-intake";
        let scope = authorize_request_resource_scope(
            data_dir,
            &owner.identity,
            RESOURCE_KIND,
            family,
            None,
        )
        .unwrap();

        // Poison the cache with a head and a length the chain never had.
        PROJECTION_CACHE
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap()
            .insert(
                family.to_string(),
                (format!("sha256:{}", "ff".repeat(64 / 2)), 9),
            );
        let lineage = read_lineage(data_dir, &owner.identity, &scope, family).unwrap();
        assert_eq!(lineage.len(), 1, "the cache cannot invent revisions");
        assert_eq!(lineage[0], v1, "the cache cannot restate content");
        assert_eq!(
            projection_cache_state(family, &lineage),
            "stale_rebuilt_from_agentgres",
            "the poisoned entry is REPORTED as disagreeing, not quietly accepted"
        );
        assert_eq!(
            projection_cache_state(family, &lineage),
            "agreed_with_agentgres",
            "and it was replaced by the projection rather than consulted for it"
        );

        // A successor moves the head, so the entry held a moment ago is now stale — and the stale
        // entry still contributes nothing to the answer.
        admit(
            data_dir,
            &caller_with_key(&owner, "successor-2"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        let after = read_lineage(data_dir, &owner.identity, &scope, family).unwrap();
        assert_eq!(after.len(), 2);
        assert_eq!(
            projection_cache_state(family, &after),
            "stale_rebuilt_from_agentgres"
        );
        reset_handle_for_test();
    }

    #[test]
    fn the_lineage_replays_identically_after_the_writer_handle_is_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let owner = caller("user://acme", "genesis-1");
        let (_v1, head) = admit(
            data_dir,
            &owner,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        let (_v2, _) = admit(
            data_dir,
            &caller_with_key(&owner, "successor-2"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        let family = "ontology://acme-clinic/patient-intake";
        let scope = authorize_request_resource_scope(
            data_dir,
            &owner.identity,
            RESOURCE_KIND,
            family,
            None,
        )
        .unwrap();
        let before = read_lineage(data_dir, &owner.identity, &scope, family).unwrap();

        // Drop the process-local writer handle: the answer must be reconstructed from the durable
        // log, byte for byte, or "survives restart" is a claim about a warm cache.
        reset_handle_for_test();
        let after = read_lineage(data_dir, &owner.identity, &scope, family).unwrap();
        assert_eq!(
            serde_json::to_string(&before).unwrap(),
            serde_json::to_string(&after).unwrap()
        );
        reset_handle_for_test();
    }

    #[test]
    fn valid_time_and_transaction_time_answer_different_questions() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        reset_handle_for_test();
        let owner = caller("user://acme", "genesis-1");
        let (v1, head) = admit(
            data_dir,
            &owner,
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            ),
            None,
        )
        .unwrap();
        let (v2, _) = admit(
            data_dir,
            &caller_with_key(&owner, "successor-2"),
            &proposal(
                "acme-clinic",
                "patient-intake",
                &["patient", "guardian"],
                "2026-06-01T00:00:00Z",
            ),
            Some(&head),
        )
        .unwrap();
        let v1_recorded = v1["transaction_time"]["recorded_at"]
            .as_str()
            .unwrap()
            .to_string();
        let v2_recorded = v2["transaction_time"]["recorded_at"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(v1_recorded, v2_recorded);
        // "True then": at 2026-03-01 only v1's valid interval had opened, even though v2 is recorded.
        assert!(
            parse_time("2026-03-01T00:00:00Z").unwrap()
                < parse_time("2026-06-01T00:00:00Z").unwrap()
        );
        // "Recorded then": before v2 was recorded, the head was v1 — a different fact from the above.
        assert!(parse_time(&v1_recorded).unwrap() < parse_time(&v2_recorded).unwrap());
        assert_eq!(v1["valid_time"]["starts_at"], "2026-01-01T00:00:00Z");
        assert_eq!(v2["valid_time"]["starts_at"], "2026-06-01T00:00:00Z");
        reset_handle_for_test();
    }

    #[test]
    fn server_resolved_fields_are_never_accepted_from_a_caller() {
        for field in [
            "transaction_time",
            "admission",
            "content_hash",
            "ontology_id",
            "status",
        ] {
            let mut body = proposal(
                "acme-clinic",
                "patient-intake",
                &["patient"],
                "2026-01-01T00:00:00Z",
            );
            body[field] = json!("substituted");
            let refusal =
                validate_proposal(&body).expect_err("a caller may not author admission evidence");
            let code = refusal.1 .0["error"]["code"].as_str().unwrap().to_string();
            assert!(
                code == "ontology_version_transaction_time_server_resolved"
                    || code == "ontology_version_field_server_resolved",
                "{field} was accepted with code {code}"
            );
        }
    }

    #[test]
    fn a_term_from_another_namespace_is_refused() {
        let mut body = proposal(
            "acme-clinic",
            "patient-intake",
            &["patient"],
            "2026-01-01T00:00:00Z",
        );
        body["entity_types"] = json!([
            { "term_id": "ontology://harbor-clinic/patient-intake/term/patient", "label": "Patient" }
        ]);
        let refusal =
            validate_proposal(&body).expect_err("a foreign term is not this family's meaning");
        assert_eq!(
            refusal.1 .0["error"]["code"],
            "ontology_version_term_foreign_namespace"
        );
    }

    #[test]
    fn valid_time_is_required_and_ordered() {
        let mut body = proposal(
            "acme-clinic",
            "patient-intake",
            &["patient"],
            "2026-01-01T00:00:00Z",
        );
        body["valid_time"] = json!({});
        assert_eq!(
            validate_proposal(&body)
                .expect_err("valid time is first class")
                .1
                 .0["error"]["code"],
            "ontology_version_valid_time_required"
        );
        body["valid_time"] =
            json!({ "starts_at": "2026-06-01T00:00:00Z", "ends_at": "2026-01-01T00:00:00Z" });
        assert_eq!(
            validate_proposal(&body)
                .expect_err("an inverted interval is not a fact")
                .1
                 .0["error"]["code"],
            "ontology_version_valid_time_not_ordered"
        );
    }

    #[test]
    fn the_content_commitment_covers_valid_time_but_not_transaction_time() {
        let base = json!({
            "ontology_family_ref": "ontology://acme-clinic/patient-intake",
            "namespace": "acme-clinic",
            "name": "patient-intake",
            "version": "v1",
            "revision_ordinal": 1,
            "predecessor_version_ref": null,
            "predecessor_content_hash": null,
            "entity_types": [],
            "relationship_types": [],
            "event_types": [],
            "action_types": [],
            "invariant_refs": [],
            "governing_scope_ref": "domain://acme-clinic/intake",
            "compatibility_profile_ref": null,
            "deprecation_policy_ref": null,
            "policy_hash": format!("sha256:{}", "1a".repeat(32)),
            "valid_time": { "starts_at": "2026-01-01T00:00:00Z", "ends_at": null },
        });
        let baseline = content_hash(&base).unwrap();

        let mut retimed = base.clone();
        retimed["valid_time"] = json!({ "starts_at": "2026-02-01T00:00:00Z", "ends_at": null });
        assert_ne!(
            content_hash(&retimed).unwrap(),
            baseline,
            "valid time is content"
        );

        let mut recorded = base.clone();
        recorded["transaction_time"] =
            json!({ "recorded_at": "2026-08-30T00:00:00Z", "superseded_at": null });
        assert_eq!(
            content_hash(&recorded).unwrap(),
            baseline,
            "transaction time is admission, not content"
        );

        for field in [
            "namespace",
            "version",
            "predecessor_version_ref",
            "policy_hash",
        ] {
            let mut substituted = base.clone();
            substituted[field] = json!("substituted-value");
            assert_ne!(
                content_hash(&substituted).unwrap(),
                baseline,
                "{field} must be inside the content commitment"
            );
        }
    }
}
