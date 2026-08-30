//! `OntologyActionContract` — the binding that compiles meaning and grants nothing (M05.4).
//!
//! WHAT IS TRUTH HERE, stated once so nothing later can quietly disagree: the Agentgres
//! owner-namespaced operation chain for one ACTION FAMILY is the only durable record. This module
//! writes NO file of its own, so there is no second store to drift even in principle. One family is
//! one stream, so revisions form a head-linked chain and a successor must name the exact current
//! head. Everything served is a PROJECTION rebuilt from that chain on every read, including the
//! content hash, which is re-derived and compared rather than trusted.
//!
//! The read index is therefore a PROCESS-LOCAL cache holding one (head, revision count) pair per
//! authorized reader and family. It is never an answer source — the lineage is projected before the
//! cache is consulted at all — so it exists to report agreement, and a restart discards it whole.
//!
//! FIVE PROPERTIES ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//!
//! 1. BOTH BINDINGS ARE RESOLVED BY THEIR OWNERS, NEVER ASSERTED BY THE CALLER. The ontology side
//!    goes through `ontology_version_routes::resolve_admitted_action_type` — the seam M05.1
//!    publishes for exactly this consumer — and carries that owner's committed hash verbatim. The
//!    tool side goes through
//!    `RuntimeToolContractRegistry::resolve_exact`, which admits one snapshot only when the
//!    revision ref and content hash identify it TOGETHER and it is released and unrevoked. A URI
//!    that merely looks like a revision is never proof one exists; a caller may ASSERT either hash
//!    and a disagreement refuses by its own cause.
//!
//! 2. THE TYPED IO CONTRACT IS BOUND TO SCHEMA BYTES, NOT TO A NAME. `bound_tool_input_schema_hash`
//!    and `bound_tool_output_schema_hash` are SHA-256 over the JCS bytes of the resolved tool
//!    revision's own declared schemas, taken here from the resolved snapshot. Binding the tool ref
//!    alone would leave the typed contract free to move underneath an admitted action.
//!
//! 3. THE CALLER NEVER AUTHORS EVIDENCE (INV-37). Revision ordinal, version label, predecessor refs
//!    and hash, both owner-resolved binding hashes, the derived family ref, the resolver names, the
//!    content hash, transaction time and the whole admission block are RESOLVED. `risk_class`,
//!    `effect_recovery_class`, the profile refs, `does_not_assert` and `valid_time` are CONTENT the
//!    author declares — a different thing from evidence, and inside the content commitment.
//!
//! 4. MEANING GRANTS NOTHING (NN 9). This is the module's single most load-bearing boundary and it
//!    is enforced by ABSENCE as much as by fields: nothing here consults, mints, widens, presents or
//!    redeems a capability, lease, policy decision, authority grant, provider connection, provider
//!    credential or effect admission, and nothing here dispatches a tool. `required_gates` carries
//!    the exact six gates the compiled action must still pass, `does_not_assert` carries the closed
//!    nonclaim set, and the registered schema and invariant profile enforce both OFFLINE. The
//!    contract is the compile step; every gate still runs somewhere else.
//!
//! 5. THE SEMANTIC ACTION IS RESOLVED, NOT MERELY WELL-FORMED. Binding a revision is not binding an
//!    action: a term can be well formed, correctly namespaced, and still be something the revision
//!    never declared. So the ontology owner publishes a seam that answers both halves against ONE
//!    projection of its own chain — which bytes the exact revision commits, and whether this action
//!    is among the `action_types` those bytes declare. An unknown same-family term is refused before
//!    any scope is bound and before any byte is written, exactly like a foreign-namespace one. The
//!    committed `ontology_content_hash` then makes the same fact re-checkable offline by anyone
//!    holding the revision bytes, so the runtime check and the portable evidence agree.
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
use super::ontology_version_routes::resolve_admitted_action_type;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
    RequestScopeRefusal,
};
use super::DaemonState;

/// The Agentgres owner namespace every action-contract stream lives in. It is DATA to the
/// substrate: nothing below this module branches on it.
const OWNER_NAMESPACE: &str = "hypervisor-ontology-action-contracts";
/// The scoped resource is the FAMILY, not the revision — one lineage, one head-linked chain.
const RESOURCE_KIND: &str = "ontology-action-contract-family";
const ADMIT_OP: &str = "ontology_action_contract.revision.admit";
const ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.ontology-action-contract-admission.v1";
const CONTRACT_ID: &str = "schema://ioi/foundations/objects/ontology-action-contract/v1";
const CONTENT_COMMITMENT_DOMAIN: &str =
    "ioi.ontology-action-contract-content-commitment-jcs-sha256.v1";
/// The exact wire contract this build implements. A caller naming any other version is refused, not
/// downgraded — see the first gate in `validate_proposal`.
const SCHEMA_VERSION: &str = "ioi.ontology-action-contract.v1";
const RECORD_PROFILE: &str = "ontology_action_contract";
const AUTHORITY_NONCLAIM: &str = "ontology_action_contract_grants_no_authority";
const INVOCATION_NONCLAIM: &str = "ontology_action_contract_does_not_invoke_or_dispatch";
const ONTOLOGY_RESOLVER: &str = "ontology_version_routes::resolve_admitted_action_type";
const TOOL_RESOLVER: &str = "runtime_tool_contract_registry::resolve_exact";
const TOOL_CLASS_VOCABULARY: &str = "runtime_tool_declared_verbatim";

/// ACC-6 clause 5 as an ordered constant. This module DRIVES the ladder; it does not choose its
/// members, and a compiled action passes every one of them somewhere that is not here.
const REQUIRED_GATES: &[&str] = &[
    "capability",
    "policy",
    "authority",
    "daemon_admission",
    "evidence",
    "verification",
];

/// Frozen by `docs/architecture/foundations/canonical-enums.md`. `physical_action` is the peer
/// top-tier class outside the monotonic ladder and additionally requires a safety profile.
const RISK_CLASSES: &[&str] = &[
    "read",
    "draft",
    "local_write",
    "write_reversible",
    "external_message",
    "commerce",
    "funds",
    "credential_access",
    "policy_widening",
    "secret_export",
    "identity_change",
    "system_destructive",
    "physical_action",
];
const PHYSICAL_ACTION_RISK_CLASS: &str = "physical_action";

/// Frozen by the same owner: what may happen after timeout, provider failure or an ambiguous effect.
const EFFECT_RECOVERY_CLASSES: &[&str] = &[
    "replayable",
    "checkpointable",
    "compensatable",
    "reconciliation_required",
    "non_retryable",
];

/// The closed nonclaim vocabulary. Six of these are mandatory — see `REQUIRED_NONCLAIMS`.
///
/// `action_term_membership` is DELIBERATELY ABSENT. It was here while this module could only check
/// that the compiled term belonged to the right family, and a nonclaim was the honest way to say the
/// rest was undecided. The owner seam now decides it, so retaining the token would let a record
/// disclaim a binding the admission path actually enforces — a nonclaim that understates the object
/// is as much a misstatement as one that overstates it.
const NONCLAIM_TOKENS: &[&str] = &[
    "authority",
    "capability_grant",
    "lease",
    "policy_decision",
    "effect_admission",
    "invocation",
    "connection_is_authority",
    "credential_is_authority",
    "domain_correctness",
    "physical_safety_clearance",
];
/// NN 9 as a runtime refusal as well as a schema shape. A contract that omits any of these has
/// collapsed "compiles meaning into a request" into "confers permission to act on it".
const REQUIRED_NONCLAIMS: &[&str] = &[
    "authority",
    "capability_grant",
    "lease",
    "policy_decision",
    "effect_admission",
    "invocation",
];

const MAX_REFS_PER_SET: usize = 64;
const MAX_APPROVAL_REFS: usize = 32;
const MAX_RECEIPT_OBLIGATIONS: usize = 32;
const MAX_REVISION_ORDINAL: u64 = 999_999_999;

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

/// A canonical lowercase `sha256:<64 hex>`. Used as a fail-closed check at both owner seams: a
/// neighbour's invariant that silently weakened would otherwise surface here as a permanently
/// unprojectable durable record rather than as a refusal.
fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn canonical_action_revision_ref(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ontology-action://") else {
        return false;
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    parts.len() == 5
        && canonical_token(parts[0], 63)
        && canonical_token(parts[1], 63)
        && canonical_token(parts[2], 63)
        && parts[3] == "revision"
        && !parts[4].starts_with('0')
        && parts[4]
            .parse::<u64>()
            .is_ok_and(|ordinal| ordinal > 0 && ordinal <= MAX_REVISION_ORDINAL)
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

fn family_ref(namespace: &str, name: &str, action_slug: &str) -> String {
    format!("ontology-action://{namespace}/{name}/{action_slug}")
}

fn revision_ref(namespace: &str, name: &str, action_slug: &str, ordinal: u64) -> String {
    format!(
        "{}/revision/{ordinal}",
        family_ref(namespace, name, action_slug)
    )
}

fn typed_tool_schema_ref(direction: &str, schema_hash: &str) -> String {
    format!("schema://runtime-tool-contract/{direction}/{schema_hash}")
}

fn version_label(ordinal: u64) -> String {
    format!("v{ordinal}")
}

// ---------------------------------------------------------------- canonical content commitment

/// The exact material the registered invariant
/// `ontology_action_contract.content_hash.commits_both_bindings_effect_semantics_and_valid_time`
/// commits.
///
/// `transaction_time`, `admission`, `admission_domain_ref`, `status` and `schema_version` are
/// DELIBERATELY absent: when a compiled meaning is held true is content, when it was recorded is
/// admission. Keeping the two apart is what lets a predecessor's transaction interval close without
/// its content hash moving — which is precisely what "an earlier revision stays addressable and
/// unreinterpreted" means mechanically.
const CONTENT_MATERIAL_FIELDS: &[&str] = &[
    "ontology_action_id",
    "action_family_ref",
    "action_record_profile",
    "namespace",
    "name",
    "action_slug",
    "owner_id",
    "governing_scope_ref",
    "version",
    "revision_ordinal",
    "predecessor_revision_ref",
    "predecessor_content_hash",
    "ontology_family_ref",
    "ontology_revision_ref",
    "ontology_content_hash",
    "ontology_resolved_by",
    "action_type_ref",
    "runtime_tool_contract_revision_ref",
    "runtime_tool_contract_content_hash",
    "runtime_tool_resolved_by",
    "bound_tool_id",
    "bound_tool_risk_class",
    "bound_tool_effect_class",
    "bound_tool_class_vocabulary",
    "bound_tool_input_schema_hash",
    "bound_tool_output_schema_hash",
    "bound_tool_primitive_capabilities_required",
    "bound_tool_authority_scopes_required",
    "typed_input_schema_ref",
    "typed_output_schema_ref",
    "target_object_model_refs",
    "precondition_refs",
    "postcondition_and_invariant_refs",
    "expected_state_transition_ref",
    "risk_class",
    "effect_recovery_class",
    "idempotency_and_retry_profile_ref",
    "ambiguous_effect_and_reconciliation_profile_ref",
    "compensation_profile_ref",
    "preview_and_dry_run_profile_ref",
    "approval_and_revocation_refs",
    "local_policy_and_authority_scope_refs",
    "verifier_and_evidence_refs",
    "physical_safety_profile_ref",
    "receipt_obligations",
    "required_gates",
    "required_gate_count",
    "policy_hash",
    "does_not_assert",
    "constants",
    "authority_nonclaim",
    "invocation_nonclaim",
    "valid_time",
    "migration",
];

fn digest_over(record: &Value, domain: &str, fields: &[&str]) -> Result<String, String> {
    let mut material = Map::new();
    material.insert("domain".into(), json!(domain));
    for field in fields {
        material.insert(
            (*field).to_string(),
            record.get(*field).cloned().unwrap_or(Value::Null),
        );
    }
    let bytes = serde_jcs::to_vec(&Value::Object(material))
        .map_err(|error| format!("action contract could not be canonicalised: {error}"))?;
    Ok(sha256_of(&bytes))
}

fn content_hash(record: &Value) -> Result<String, String> {
    digest_over(record, CONTENT_COMMITMENT_DOMAIN, CONTENT_MATERIAL_FIELDS)
}

// -------------------------------------------------------------------------- caller-content shape

/// The caller-supplied content of one revision, already checked for shape.
#[derive(Debug)]
struct ProposedContract {
    namespace: String,
    name: String,
    action_slug: String,
    governing_scope_ref: String,
    policy_hash: String,
    ontology_revision_ref: String,
    action_type_ref: String,
    runtime_tool_contract_revision_ref: String,
    runtime_tool_contract_content_hash: String,
    typed_input_schema_ref: String,
    typed_output_schema_ref: String,
    target_object_model_refs: Value,
    precondition_refs: Value,
    postcondition_and_invariant_refs: Value,
    expected_state_transition_ref: String,
    risk_class: String,
    effect_recovery_class: String,
    idempotency_and_retry_profile_ref: String,
    ambiguous_effect_and_reconciliation_profile_ref: String,
    compensation_profile_ref: Value,
    preview_and_dry_run_profile_ref: Value,
    approval_and_revocation_refs: Value,
    local_policy_and_authority_scope_refs: Value,
    verifier_and_evidence_refs: Value,
    physical_safety_profile_ref: Value,
    receipt_obligations: Value,
    does_not_assert: Value,
    valid_time: Value,
    compatibility: Option<String>,
}

fn parse_time(value: &str) -> Option<u64> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|stamp| stamp.unix_timestamp() as u64)
}

fn validate_valid_time(body: &Value) -> Result<Value, Reply> {
    let Some(valid_time) = body.get("valid_time").and_then(Value::as_object) else {
        return Err(refuse(
            "ontology_action_contract_valid_time_required",
            "valid_time is required: when a compiled meaning is held true is CONTENT, and it is a different axis from when the revision was recorded",
        ));
    };
    if let Some(unknown) = valid_time
        .keys()
        .find(|key| !matches!(key.as_str(), "starts_at" | "ends_at"))
    {
        return Err(refuse(
            "ontology_action_contract_valid_time_unknown_field",
            format!(
                "valid_time carries '{unknown}', which the registered contract does not define"
            ),
        ));
    }
    let starts_at = valid_time
        .get("starts_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(start) = parse_time(starts_at) else {
        return Err(refuse(
            "ontology_action_contract_valid_time_not_canonical",
            "valid_time.starts_at must be an RFC 3339 timestamp",
        ));
    };
    let ends_at = match valid_time.get("ends_at") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) => {
            let Some(end) = parse_time(value) else {
                return Err(refuse(
                    "ontology_action_contract_valid_time_not_canonical",
                    "valid_time.ends_at must be null or an RFC 3339 timestamp",
                ));
            };
            if end <= start {
                return Err(refuse(
                    "ontology_action_contract_valid_time_inverted",
                    "valid_time.ends_at must be strictly after starts_at; an interval that closes before it opens is not a validity window",
                ));
            }
            json!(value)
        }
        Some(_) => {
            return Err(refuse(
                "ontology_action_contract_valid_time_not_canonical",
                "valid_time.ends_at must be null or an RFC 3339 timestamp",
            ))
        }
    };
    Ok(json!({ "starts_at": starts_at, "ends_at": ends_at }))
}

/// A required, closed set of prefixed refs, rebuilt rather than forwarded.
fn ref_set(
    body: &Value,
    key: &str,
    schemes: &[&str],
    min_items: usize,
    max_items: usize,
) -> Result<Value, Reply> {
    let items = body.get(key).cloned().unwrap_or_else(|| json!([]));
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_action_contract_ref_set_malformed",
            format!("{key} must be an array of {schemes:?} refs"),
        ));
    };
    if entries.len() < min_items {
        return Err(refuse(
            "ontology_action_contract_ref_set_incomplete",
            format!(
                "{key} needs at least {min_items} ref(s); an empty obligation is not an obligation"
            ),
        ));
    }
    if entries.len() > max_items {
        return Err(refuse(
            "ontology_action_contract_ref_set_too_large",
            format!("{key} carries more than {max_items} refs"),
        ));
    }
    let mut canonical: Vec<Value> = Vec::with_capacity(entries.len());
    let mut seen: Vec<String> = Vec::new();
    for entry in entries {
        let Some(value) = entry.as_str().map(str::trim) else {
            return Err(refuse(
                "ontology_action_contract_ref_not_canonical",
                format!("{key} carries a non-string entry"),
            ));
        };
        if value.len() > 248
            || value.bytes().any(|byte| {
                byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii()
            })
        {
            return Err(refuse(
                "ontology_action_contract_ref_not_canonical",
                format!("{key} carries a ref that is oversized or non-ASCII: '{value}'"),
            ));
        }
        if !schemes
            .iter()
            .any(|scheme| value.starts_with(scheme) && value.len() > scheme.len())
        {
            return Err(refuse(
                "ontology_action_contract_ref_scheme_unknown",
                format!("{key} carries '{value}', which uses none of the schemes {schemes:?} this field admits"),
            ));
        }
        if seen.iter().any(|previous| previous == value) {
            return Err(refuse(
                "ontology_action_contract_ref_duplicated",
                format!("{key} declares '{value}' twice"),
            ));
        }
        seen.push(value.to_string());
        canonical.push(json!(value));
    }
    Ok(Value::Array(canonical))
}

fn required_ref(body: &Value, key: &str, schemes: &[&str]) -> Result<String, Reply> {
    let value = str_field(body, key);
    if value.is_empty()
        || value.len() > 248
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii())
        || !schemes
            .iter()
            .any(|scheme| value.starts_with(scheme) && value.len() > scheme.len())
    {
        return Err(refuse(
            "ontology_action_contract_ref_not_canonical",
            format!("{key} is required and must be a canonical ASCII ref using one of {schemes:?}"),
        ));
    }
    Ok(value.to_string())
}

fn optional_ref(body: &Value, key: &str, scheme: &str) -> Result<Value, Reply> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(value))
            if value.starts_with(scheme)
                && value.len() > scheme.len()
                && value.len() <= scheme.len() + 240
                && !value.bytes().any(|byte| {
                    byte.is_ascii_whitespace() || byte.is_ascii_control() || !byte.is_ascii()
                }) =>
        {
            Ok(json!(value))
        }
        Some(_) => Err(refuse(
            "ontology_action_contract_ref_not_canonical",
            format!("{key} must be null or a canonical '{scheme}' ref"),
        )),
    }
}

fn validate_nonclaims(body: &Value) -> Result<Value, Reply> {
    let items = body.get("does_not_assert").cloned().unwrap_or(Value::Null);
    let Some(entries) = items.as_array() else {
        return Err(refuse(
            "ontology_action_contract_nonclaims_required",
            "does_not_assert is required: a contract that disclaims nothing has collapsed 'compiles meaning' into 'confers permission', which is the reading NN 9 refuses",
        ));
    };
    let mut declared: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(token) = entry.as_str() else {
            return Err(refuse(
                "ontology_action_contract_nonclaim_not_canonical",
                "does_not_assert carries a non-string entry",
            ));
        };
        if !NONCLAIM_TOKENS.contains(&token) {
            return Err(refuse(
                "ontology_action_contract_nonclaim_unknown",
                format!("'{token}' is not a member of the closed nonclaim vocabulary {NONCLAIM_TOKENS:?}"),
            ));
        }
        if declared.iter().any(|previous| previous == token) {
            return Err(refuse(
                "ontology_action_contract_nonclaim_duplicated",
                format!("does_not_assert declares '{token}' twice"),
            ));
        }
        declared.push(token.to_string());
    }
    if let Some(missing) = REQUIRED_NONCLAIMS
        .iter()
        .find(|required| !declared.iter().any(|token| token == *required))
    {
        return Err(refuse(
            "ontology_action_contract_nonclaim_incomplete",
            format!(
                "a compiled action contract must explicitly disclaim '{missing}': a contract that does not say so is read as claiming it by omission"
            ),
        ));
    }
    Ok(Value::Array(
        declared.into_iter().map(Value::String).collect(),
    ))
}

fn validate_proposal(body: &Value) -> Result<ProposedContract, Reply> {
    // THE VERSION GATE IS FIRST AND IT REFUSES RATHER THAN DOWNGRADING. A caller naming a contract
    // version this build does not implement is told so; it is never quietly served as v1.
    match body.get("schema_version") {
        None | Some(Value::Null) => {}
        Some(Value::String(declared)) if declared == SCHEMA_VERSION => {}
        Some(declared) => {
            return Err(refuse(
                "ontology_action_contract_schema_version_unsupported",
                format!(
                    "this build implements {SCHEMA_VERSION} only; '{declared}' is refused rather than downgraded, because serving an unknown version as v1 is how a contract silently loses a field"
                ),
            ))
        }
    }

    let namespace = str_field(body, "namespace").to_string();
    let name = str_field(body, "name").to_string();
    let action_slug = str_field(body, "action_slug").to_string();
    for (label, token) in [
        ("namespace", &namespace),
        ("name", &name),
        ("action_slug", &action_slug),
    ] {
        if !canonical_token(token, 63) {
            return Err(refuse(
                "ontology_action_contract_identity_not_canonical",
                format!("{label} must be a 1..63 character lowercase token of [a-z0-9-] starting alphanumeric"),
            ));
        }
    }

    let governing_scope_ref = required_ref(
        body,
        "governing_scope_ref",
        &[
            "domain://",
            "org://",
            "project://",
            "service://",
            "system://",
        ],
    )?;
    let policy_hash = str_field(body, "policy_hash").to_string();
    if !is_sha256(&policy_hash) {
        return Err(refuse(
            "ontology_action_contract_policy_hash_not_canonical",
            "policy_hash must be a lowercase 'sha256:<64 hex>' commitment to the exact local policy snapshot in force when this revision was compiled",
        ));
    }

    let ontology_revision_ref = required_ref(body, "ontology_revision_ref", &["ontology://"])?;
    let action_type_ref = required_ref(body, "action_type_ref", &["ontology://"])?;
    let runtime_tool_contract_revision_ref =
        required_ref(body, "runtime_tool_contract_revision_ref", &["tool://"])?;
    let runtime_tool_contract_content_hash =
        str_field(body, "runtime_tool_contract_content_hash").to_string();
    if !is_sha256(&runtime_tool_contract_content_hash) {
        return Err(refuse(
            "ontology_action_contract_tool_hash_not_canonical",
            "runtime_tool_contract_content_hash must be the tool owner's lowercase 'sha256:<64 hex>' commitment; the revision ref alone never identifies an admitted snapshot",
        ));
    }

    let typed_input_schema_ref = required_ref(
        body,
        "typed_input_schema_ref",
        &["schema://", "artifact://"],
    )?;
    let typed_output_schema_ref = required_ref(
        body,
        "typed_output_schema_ref",
        &["schema://", "artifact://"],
    )?;
    let target_object_model_refs = ref_set(
        body,
        "target_object_model_refs",
        &["object-model://"],
        1,
        MAX_REFS_PER_SET,
    )?;
    let precondition_refs = ref_set(
        body,
        "precondition_refs",
        &["policy://", "invariant://", "state://"],
        1,
        MAX_REFS_PER_SET,
    )?;
    let postcondition_and_invariant_refs = ref_set(
        body,
        "postcondition_and_invariant_refs",
        &["policy://", "invariant://", "state://"],
        1,
        MAX_REFS_PER_SET,
    )?;
    let expected_state_transition_ref = required_ref(
        body,
        "expected_state_transition_ref",
        &["transition://", "state-delta://"],
    )?;

    let risk_class = str_field(body, "risk_class").to_string();
    if !RISK_CLASSES.contains(&risk_class.as_str()) {
        return Err(refuse(
            "ontology_action_contract_risk_class_unknown",
            format!(
                "risk_class must be a member of the canonical ladder {RISK_CLASSES:?}; this is a new contract surface, so a pre-consolidation runtime string is refused rather than mapped"
            ),
        ));
    }
    let effect_recovery_class = str_field(body, "effect_recovery_class").to_string();
    if !EFFECT_RECOVERY_CLASSES.contains(&effect_recovery_class.as_str()) {
        return Err(refuse(
            "ontology_action_contract_effect_recovery_class_unknown",
            format!("effect_recovery_class must be one of {EFFECT_RECOVERY_CLASSES:?}"),
        ));
    }

    let idempotency_and_retry_profile_ref =
        required_ref(body, "idempotency_and_retry_profile_ref", &["policy://"])?;
    let ambiguous_effect_and_reconciliation_profile_ref = required_ref(
        body,
        "ambiguous_effect_and_reconciliation_profile_ref",
        &["policy://"],
    )?;
    let compensation_profile_ref = optional_ref(body, "compensation_profile_ref", "policy://")?;
    let preview_and_dry_run_profile_ref =
        optional_ref(body, "preview_and_dry_run_profile_ref", "policy://")?;
    let approval_and_revocation_refs = ref_set(
        body,
        "approval_and_revocation_refs",
        &["approval-policy://", "revocation://"],
        1,
        MAX_APPROVAL_REFS,
    )?;
    // REQUIREMENTS, NEVER HOLDINGS. A `grant://` member names the grant class an invoker must
    // present. Nothing in this module resolves, mints, widens or redeems one.
    let local_policy_and_authority_scope_refs = ref_set(
        body,
        "local_policy_and_authority_scope_refs",
        &["policy://", "grant://", "scope:"],
        1,
        MAX_REFS_PER_SET,
    )?;
    let verifier_and_evidence_refs = ref_set(
        body,
        "verifier_and_evidence_refs",
        &["verifier-path://", "evidence://", "schema://"],
        1,
        MAX_REFS_PER_SET,
    )?;
    let physical_safety_profile_ref =
        optional_ref(body, "physical_safety_profile_ref", "safety://")?;
    // The peer top-tier class carries an obligation the ladder members do not. Enforced here as well
    // as by the registered invariant, so the refusal names the safety fact rather than surfacing as
    // a shape error after a durable write.
    if risk_class == PHYSICAL_ACTION_RISK_CLASS && physical_safety_profile_ref.is_null() {
        return Err(refuse(
            "ontology_action_contract_physical_safety_profile_required",
            "an action contract that can affect the physical world binds the Physical Action Safety profile before any actuator command is eligible",
        ));
    }
    let receipt_obligations = ref_set(
        body,
        "receipt_obligations",
        &["receipt://"],
        1,
        MAX_RECEIPT_OBLIGATIONS,
    )?;
    let does_not_assert = validate_nonclaims(body)?;
    let valid_time = validate_valid_time(body)?;
    let compatibility = match body.get("compatibility") {
        None | Some(Value::Null) => None,
        Some(Value::String(value))
            if matches!(value.as_str(), "initial" | "additive" | "breaking") =>
        {
            Some(value.clone())
        }
        Some(_) => {
            return Err(refuse(
                "ontology_action_contract_compatibility_not_canonical",
                "compatibility must be 'initial', 'additive', or 'breaking' when present",
            ))
        }
    };

    // INV-37. Everything below is RESOLVED by this module or by another owner. A caller may ASSERT
    // any of them through an `expected_*` field and receive a typed refusal on disagreement; it may
    // never author them directly, because a record whose evidence its own subject supplied is not
    // evidence.
    for authored in [
        "ontology_action_id",
        "action_family_ref",
        "action_record_profile",
        "ontology_family_ref",
        "ontology_content_hash",
        "ontology_resolved_by",
        "runtime_tool_resolved_by",
        "bound_tool_id",
        "bound_tool_risk_class",
        "bound_tool_effect_class",
        "bound_tool_class_vocabulary",
        "bound_tool_input_schema_hash",
        "bound_tool_output_schema_hash",
        "bound_tool_primitive_capabilities_required",
        "bound_tool_authority_scopes_required",
        "required_gates",
        "required_gate_count",
        "constants",
        "authority_nonclaim",
        "invocation_nonclaim",
        "content_hash",
        "revision_ordinal",
        "version",
        "predecessor_revision_ref",
        "predecessor_content_hash",
        "transaction_time",
        "migration",
        "admission",
        "admission_domain_ref",
        "status",
        "owner_id",
    ] {
        if body.get(authored).is_some() {
            return Err(refuse(
                "ontology_action_contract_caller_authored_evidence",
                format!(
                    "'{authored}' is resolved by an owner, never authored by the caller (INV-37); assert what you believe it to be with the matching 'expected_*' field and receive a typed refusal on disagreement"
                ),
            ));
        }
    }

    Ok(ProposedContract {
        namespace,
        name,
        action_slug,
        governing_scope_ref,
        policy_hash,
        ontology_revision_ref,
        action_type_ref,
        runtime_tool_contract_revision_ref,
        runtime_tool_contract_content_hash,
        typed_input_schema_ref,
        typed_output_schema_ref,
        target_object_model_refs,
        precondition_refs,
        postcondition_and_invariant_refs,
        expected_state_transition_ref,
        risk_class,
        effect_recovery_class,
        idempotency_and_retry_profile_ref,
        ambiguous_effect_and_reconciliation_profile_ref,
        compensation_profile_ref,
        preview_and_dry_run_profile_ref,
        approval_and_revocation_refs,
        local_policy_and_authority_scope_refs,
        verifier_and_evidence_refs,
        physical_safety_profile_ref,
        receipt_obligations,
        does_not_assert,
        valid_time,
        compatibility,
    })
}

// ---------------------------------------------------------------------- the two resolution seams

/// The ontology side of the binding, resolved by its owner.
struct ResolvedSemantics {
    ontology_family_ref: String,
    ontology_revision_ref: String,
    ontology_content_hash: String,
}

/// Resolve the exact admitted semantic action: the revision that defines it, and the action itself.
///
/// THE READER IS M05.1'S OWN. This module adds no storage reader, consults no index and never widens
/// the caller's scope: `resolve_admitted_action_type` is the seam that owner publishes for this
/// consumer, it projects from that family's canonical Agentgres chain, and its committed hash is
/// carried verbatim. Membership of the action in the revision's `action_types` is that owner's
/// answer, taken from the same contract-validated projection as the hash — not re-derived here and
/// not read from a copy.
fn resolve_semantics(
    data_dir: &str,
    identity: &RequestIdentity,
    ontology_revision_ref: &str,
    action_type_ref: &str,
) -> Result<ResolvedSemantics, Reply> {
    // THE ACTION IS RESOLVED, NOT MERELY WELL-FORMED. This is the owner seam that answers both
    // halves at once: which bytes the exact revision commits, AND whether this action is one of the
    // things those bytes actually declare. A term that is well formed and correctly namespaced but
    // absent from the revision's `action_types` is refused here — before any scope is bound and
    // before any byte is written — because a contract that compiled meaning nobody admitted would
    // pass every shape check while binding nothing.
    let action =
        resolve_admitted_action_type(data_dir, identity, ontology_revision_ref, action_type_ref)?;
    // Checked AGAIN at the seam, because this module is about to seal the value inside its own
    // content commitment: a neighbour's invariant that silently weakened would otherwise be
    // discovered as a permanently unprojectable durable record rather than as a refusal.
    if !is_sha256(&action.content_hash) {
        return Err(bad(
            StatusCode::BAD_GATEWAY,
            "ontology_action_contract_ontology_hash_not_canonical",
            "the ontology owner resolved this revision to a content hash that is not a canonical sha256; an action contract is not sealed over a malformed binding",
        ));
    }
    Ok(ResolvedSemantics {
        ontology_family_ref: action.ontology_family_ref,
        ontology_revision_ref: action.ontology_id,
        ontology_content_hash: action.content_hash,
    })
}

/// The tool side of the binding, resolved by its owner.
struct ResolvedTool {
    tool_id: String,
    revision_ref: String,
    content_hash: String,
    risk_class: String,
    effect_class: String,
    input_schema_hash: String,
    output_schema_hash: String,
    primitive_capabilities_required: Value,
    authority_scopes_required: Value,
}

/// Resolve one EXACT released RuntimeToolContract revision through its owner's own resolver.
///
/// `resolve_exact` admits a snapshot only when the revision ref and content hash identify it
/// TOGETHER, and only when it is released and unrevoked. That is the whole reason this seam takes
/// both: a mutable tool family id is never an admission pin, by the connector/tool contract owner's
/// own rule, and a revoked revision must not become the durable binding of a compiled action.
///
/// THE CLASS STRINGS ARE CARRIED VERBATIM. `canonical-enums.md` records that several runtime
/// surfaces still declare pre-consolidation risk/effect strings. Mapping one onto the canonical
/// ladder here would invent an equivalence this module has no authority to assert, so the tool's own
/// words are retained under an explicit vocabulary label and this record's canonical assessment
/// stays in its own `risk_class`.
fn resolve_tool(
    st: &DaemonState,
    revision_ref: &str,
    content_hash: &str,
) -> Result<ResolvedTool, Reply> {
    let Ok(registry) = st.runtime_tool_contract_registry.read() else {
        return Err(bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "ontology_action_contract_tool_registry_unavailable",
            "the RuntimeToolContract registry could not be read; a binding is never guessed while its owner is unavailable",
        ));
    };
    let resolved = registry
        .resolve_exact(revision_ref, content_hash)
        .map_err(|error| {
            refuse(
                "ontology_action_contract_tool_unresolved",
                format!(
                    "the RuntimeToolContract owner refused this exact revision and hash ({}): {}",
                    error.code, error.message
                ),
            )
        })?;
    let contract = resolved.contract;
    if !is_sha256(&contract.content_hash) {
        return Err(bad(
            StatusCode::BAD_GATEWAY,
            "ontology_action_contract_tool_hash_not_canonical",
            "the tool owner resolved this revision to a content hash that is not a canonical sha256",
        ));
    }
    // THE TYPED IO CONTRACT IS BOUND TO BYTES. Hashing the owner's own declared schemas is what makes
    // "this action's input and output are THESE shapes" survive a later tool revision: a successor
    // that changes either schema no longer matches this admitted commitment.
    let input_schema_hash = serde_jcs::to_vec(&contract.input_schema)
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| {
            bad(
                StatusCode::BAD_GATEWAY,
                "ontology_action_contract_tool_schema_uncanonicalisable",
                format!("the bound tool's input schema could not be canonicalised: {error}"),
            )
        })?;
    let output_schema_hash = serde_jcs::to_vec(&contract.output_schema)
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| {
            bad(
                StatusCode::BAD_GATEWAY,
                "ontology_action_contract_tool_schema_uncanonicalisable",
                format!("the bound tool's output schema could not be canonicalised: {error}"),
            )
        })?;
    Ok(ResolvedTool {
        tool_id: contract.tool_id,
        revision_ref: contract.revision_ref,
        content_hash: contract.content_hash,
        risk_class: contract.risk_class,
        effect_class: contract.effect_class,
        input_schema_hash,
        output_schema_hash,
        primitive_capabilities_required: json!(contract.primitive_capabilities_required),
        authority_scopes_required: json!(contract.authority_scopes_required),
    })
}

// ------------------------------------------------------------------------------- chain projection

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
            "action-contract stream carries an unknown operation '{}'",
            entry.operation.op_kind
        ));
    }
    let payload = &entry.operation.payload;
    if payload.get("schema_version").and_then(Value::as_str) != Some(ADMISSION_PAYLOAD_SCHEMA) {
        return Err("action-contract admission carries an unknown payload schema".into());
    }
    let record = payload
        .get("action_contract_record")
        .cloned()
        .ok_or_else(|| "action-contract admission carries no contract record".to_string())?;
    // THE READ SIDE REFUSES AN UNKNOWN CONTRACT VERSION TOO. A frame written by a build this one does
    // not implement is reported as unreadable rather than projected as though it were v1 — a
    // downgrade is no more acceptable on the way out of the chain than on the way in.
    if record.get("schema_version").and_then(Value::as_str) != Some(SCHEMA_VERSION)
        || record.get("action_record_profile").and_then(Value::as_str) != Some(RECORD_PROFILE)
    {
        return Err(format!(
            "action-contract chain holds a revision this build does not implement (expected {SCHEMA_VERSION} / {RECORD_PROFILE})"
        ));
    }
    // The served content hash is RE-DERIVED, never trusted: a tampered log frame or a rebuilt index
    // cannot make this module serve bytes that do not hash to what they claim.
    let derived = content_hash(&record)?;
    if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
        return Err("action-contract admitted content does not match its committed hash".into());
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

/// Validate the complete registered contract before the canonical operation chain is mutated.
///
/// Admission refs and transaction time do not exist until Agentgres accepts the operation, so the
/// preflight uses the schema's explicit `admission: null` form and a fixed transaction-time cell.
/// Those fields are outside the content commitment. The actual non-null admission document is
/// independently rebuilt and validated by `contract_document` after commit. This first fence is
/// what prevents a producer/schema mismatch from appending an invalid record and poisoning every
/// later projection of the family.
fn validate_contract_before_admission(record: &Value, family: &str) -> Result<(), String> {
    let mut document = record.clone();
    let tail = stream_tail(RESOURCE_KIND, family);
    document["admission_domain_ref"] = json!(format!(
        "agentgres://domain/{}",
        agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
    ));
    document["transaction_time"] = json!({
        "recorded_at": "1970-01-01T00:00:00Z",
        "superseded_at": null,
    });
    document["admission"] = Value::Null;
    document["status"] = json!("active");
    validate_architecture_contract(CONTRACT_ID, &document)
        .map_err(|reason| format!("prospective action contract is not registered-valid: {reason}"))
}

/// Assemble the registered `OntologyActionContract` document for one admitted revision.
///
/// `superseded_at` closes the predecessor's TRANSACTION interval. Nothing inside the content
/// commitment moves, which is precisely why an earlier revision remains addressable and
/// unreinterpreted.
fn contract_document(
    revision: &AdmittedRevision,
    family: &str,
    superseded_at: Option<&str>,
) -> Result<Value, String> {
    let mut document = revision.record.clone();
    let ontology_action_id = document
        .get("ontology_action_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "admitted revision carries no ontology_action_id".to_string())?
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
        "ontology_action_id": ontology_action_id,
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
    document["status"] = json!(if superseded_at.is_some() {
        "deprecated"
    } else {
        "active"
    });
    validate_architecture_contract(CONTRACT_ID, &document)
        .map_err(|reason| format!("projected action contract is not registered-valid: {reason}"))?;
    Ok(document)
}

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

// -------------------------------------------------- rebuildable, process-local, never truth

/// One (admitted head, revision count) pair per authorized reader and family. Process-local, never
/// durable, and KEYED BY THE READER: an entry shared by every principal who could name a family
/// would make `stale_rebuilt_…` a side channel announcing that somebody else's lineage moved.
static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

fn projection_cache_key(scope: &RequestResourceScope, family: &str) -> String {
    sha256_of(
        format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            scope.principal_ref, scope.tenant_ref, scope.owner_ref, family
        )
        .as_bytes(),
    )
}

/// Record what the cache held for this reader and family BEFORE the freshly projected lineage
/// replaced it.
///
/// The lineage is already computed when this is called, so the cache cannot contribute to the
/// answer — it is consulted only to report agreement. Reporting it lets a verifier assert rebuild by
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

// -------------------------------------------------------------------------------- read helpers

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
            "ontology_action_contract_projection_failed",
            reason,
        )
    })
}

fn authorized_lineage(
    data_dir: &str,
    identity: &RequestIdentity,
    family: &str,
) -> Result<(Vec<Value>, RequestResourceScope), Reply> {
    let scope = authorize_request_resource_scope(data_dir, identity, RESOURCE_KIND, family, None)
        .map_err(scope_refusal_reply)?;
    let lineage = read_lineage(data_dir, identity, &scope, family)?;
    Ok((lineage, scope))
}

// ----------------------------------------------------------------------- idempotent replay intent

fn compatibility_for_ordinal(proposal: &ProposedContract, ordinal: u64) -> Result<&str, Reply> {
    match (ordinal, proposal.compatibility.as_deref()) {
        (1, None | Some("initial")) => Ok("initial"),
        (2.., Some(value @ ("additive" | "breaking"))) => Ok(value),
        (1, Some(_)) => Err(refuse(
            "ontology_action_contract_compatibility_not_initial",
            "the first revision of a family has 'initial' compatibility",
        )),
        (2.., _) => Err(refuse(
            "ontology_action_contract_compatibility_required",
            "a successor declares 'additive' or 'breaking'; compatibility is part of the immutable revision commitment",
        )),
        _ => Err(refuse(
            "ontology_action_contract_compatibility_not_canonical",
            "revision ordinal must be positive before compatibility can be derived",
        )),
    }
}

/// The intent a replayed key must still be asking about.
///
/// REPLAY ONLY AN IDENTICAL COMMAND. Answering from the projected lineage without first comparing
/// what is being asked would turn the idempotency key into a way to receive one contract in answer
/// to a different one — the same key with a widened risk class, a different tool binding or a
/// shorter nonclaim set would receive the original back and read as "your request was recorded".
/// EVERY caller-authored material input of one proposal, as one intention document.
///
/// STRUCTURALLY EXHAUSTIVE ON PURPOSE, AND THIS IS THE WHOLE POINT OF THE FUNCTION. It destructures
/// `ProposedContract` field by field, so adding a member to that struct FAILS TO COMPILE until the
/// new field is placed here. The first cut of this module kept a hand-written twelve-name list
/// beside a twenty-eight-field struct, and the sixteen it omitted — target object models,
/// pre/postconditions, the expected transition, all four behaviour profiles, approval/revocation,
/// local policy and authority requirements, verifier/evidence, receipt obligations and the governing
/// scope — could all be changed under an already-admitted key and receive `200 replayed: true` for
/// the ORIGINAL contract. A caller could compile one meaning, then quietly answer a different
/// question with the first one's receipt. A list that must be remembered is not a fence.
///
/// TWO CLASSES OF FIELD ARE DELIBERATELY EXCLUDED, and each is excluded for a stated reason:
///
///   * Exact ontology/tool revision refs and the tool hash are compared from the request itself on
///     replay. They are canonical identities, so no current registry lookup is needed to answer a
///     historical retry after restart or revocation; fresh admission still resolves all three.
///   * `expected_head` is not compared at all. A genuine retry after an ambiguous response
///     necessarily carries the PRE-ADMISSION head, so requiring it to match would turn every real
///     duplicate into a conflict and make the idempotency key unusable — which is the same reason
///     replay is checked before the head precondition in the first place.
///
/// Server-authored projection fields — ordinals, resolver names, admission, transaction time, the
/// derived family refs, the gate ladder, the content hash — are never caller intent and are not here.
fn proposal_intent(
    proposal: &ProposedContract,
    ordinal: u64,
) -> Result<BTreeMap<&'static str, Value>, Reply> {
    let ProposedContract {
        namespace,
        name,
        action_slug,
        governing_scope_ref,
        policy_hash,
        ontology_revision_ref,
        action_type_ref,
        runtime_tool_contract_revision_ref,
        runtime_tool_contract_content_hash,
        typed_input_schema_ref,
        typed_output_schema_ref,
        target_object_model_refs,
        precondition_refs,
        postcondition_and_invariant_refs,
        expected_state_transition_ref,
        risk_class,
        effect_recovery_class,
        idempotency_and_retry_profile_ref,
        ambiguous_effect_and_reconciliation_profile_ref,
        compensation_profile_ref,
        preview_and_dry_run_profile_ref,
        approval_and_revocation_refs,
        local_policy_and_authority_scope_refs,
        verifier_and_evidence_refs,
        physical_safety_profile_ref,
        receipt_obligations,
        does_not_assert,
        valid_time,
        compatibility: _,
    } = proposal;
    let compatibility = compatibility_for_ordinal(proposal, ordinal)?;
    Ok(BTreeMap::from([
        ("namespace", json!(namespace)),
        ("name", json!(name)),
        ("action_slug", json!(action_slug)),
        ("governing_scope_ref", json!(governing_scope_ref)),
        ("policy_hash", json!(policy_hash)),
        ("ontology_revision_ref", json!(ontology_revision_ref)),
        ("action_type_ref", json!(action_type_ref)),
        (
            "runtime_tool_contract_revision_ref",
            json!(runtime_tool_contract_revision_ref),
        ),
        (
            "runtime_tool_contract_content_hash",
            json!(runtime_tool_contract_content_hash),
        ),
        ("typed_input_schema_ref", json!(typed_input_schema_ref)),
        ("typed_output_schema_ref", json!(typed_output_schema_ref)),
        ("target_object_model_refs", target_object_model_refs.clone()),
        ("precondition_refs", precondition_refs.clone()),
        (
            "postcondition_and_invariant_refs",
            postcondition_and_invariant_refs.clone(),
        ),
        (
            "expected_state_transition_ref",
            json!(expected_state_transition_ref),
        ),
        ("risk_class", json!(risk_class)),
        ("effect_recovery_class", json!(effect_recovery_class)),
        (
            "idempotency_and_retry_profile_ref",
            json!(idempotency_and_retry_profile_ref),
        ),
        (
            "ambiguous_effect_and_reconciliation_profile_ref",
            json!(ambiguous_effect_and_reconciliation_profile_ref),
        ),
        ("compensation_profile_ref", compensation_profile_ref.clone()),
        (
            "preview_and_dry_run_profile_ref",
            preview_and_dry_run_profile_ref.clone(),
        ),
        (
            "approval_and_revocation_refs",
            approval_and_revocation_refs.clone(),
        ),
        (
            "local_policy_and_authority_scope_refs",
            local_policy_and_authority_scope_refs.clone(),
        ),
        (
            "verifier_and_evidence_refs",
            verifier_and_evidence_refs.clone(),
        ),
        (
            "physical_safety_profile_ref",
            physical_safety_profile_ref.clone(),
        ),
        ("receipt_obligations", receipt_obligations.clone()),
        ("does_not_assert", does_not_assert.clone()),
        ("valid_time", valid_time.clone()),
        ("compatibility", json!(compatibility)),
    ]))
}

/// The exact caller-authored field on which this request diverges from the one this key admitted.
///
/// Compared over the WHOLE intention document, so the answer is "no field differs" or the name of
/// one that does. A key replays one exact command; it is never a way to receive a stored contract in
/// answer to a different one.
fn replay_intent_divergence(
    document: &Value,
    proposal: &ProposedContract,
) -> Result<Option<&'static str>, Reply> {
    let ordinal = ordinal_of(document);
    Ok(proposal_intent(proposal, ordinal)?
        .into_iter()
        .find(|(field, expected)| {
            let stored = if *field == "compatibility" {
                document.pointer("/migration/compatibility")
            } else {
                document.get(*field)
            };
            stored.unwrap_or(&Value::Null) != expected
        })
        .map(|(field, _)| field))
}

/// One caller-supplied `expected_*` assertion, read WITHOUT letting a wrong type become an absence.
///
/// `Value::as_str` and `Value::as_u64` answer `None` for two completely different situations: the
/// field is absent, and the field is present but is a number, an object, an array or a bool. Reading
/// an assertion through `.get(key).and_then(Value::as_str)` therefore SILENTLY SKIPS it whenever the
/// caller sends the wrong type — `expected_content_hash: 12345` was compared against nothing at all
/// and the request proceeded as though the caller had asserted nothing. An assertion this route
/// cannot read is not an assertion it may ignore: the caller made a claim about a server-derived
/// fact, and the only honest answers are "it matches", "it does not", and "that is not a claim I can
/// read". This type makes the third case impossible to drop on the floor.
enum Asserted<T> {
    Absent,
    Present(T),
    Malformed,
}

fn asserted_str<'a>(body: &'a Value, key: &str) -> Asserted<&'a str> {
    match body.get(key) {
        None => Asserted::Absent,
        Some(Value::String(value)) => Asserted::Present(value.as_str()),
        Some(_) => Asserted::Malformed,
    }
}

fn asserted_u64(body: &Value, key: &str) -> Asserted<u64> {
    match body.get(key) {
        None => Asserted::Absent,
        Some(value) => match value.as_u64() {
            Some(number) => Asserted::Present(number),
            None => Asserted::Malformed,
        },
    }
}

/// Refuse every caller assertion this route cannot READ, before any of them is compared.
///
/// SHAPE BEFORE LINEAGE, AND THAT ORDER IS THE POINT. Each `expected_*` value is compared where its
/// fact is derived, which for the ordinal and the content hash is after the exact-head precondition.
/// So a malformed assertion sent to a family that already has revisions was answered with
/// `expected_head_conflict` — a refusal about a completely different thing, with the unreadable claim
/// still unexamined. A request whose assertions cannot be parsed is malformed as a REQUEST, and that
/// is decided here, before the lineage is consulted at all.
fn validate_assertion_shapes(body: &Value) -> Result<(), Reply> {
    for (key, required) in [
        (
            "expected_ontology_content_hash",
            "a 'sha256:<64 hex>' string",
        ),
        ("expected_bound_tool_id", "a 'tool://' string"),
        ("expected_content_hash", "a 'sha256:<64 hex>' string"),
    ] {
        if matches!(asserted_str(body, key), Asserted::Malformed) {
            return Err(assertion_not_canonical(key, required));
        }
    }
    for key in ["expected_ontology_content_hash", "expected_content_hash"] {
        if let Asserted::Present(value) = asserted_str(body, key) {
            if !is_sha256(value) {
                return Err(assertion_not_canonical(
                    key,
                    "a canonical lowercase 'sha256:<64 hex>' string",
                ));
            }
        }
    }
    if let Asserted::Present(value) = asserted_str(body, "expected_bound_tool_id") {
        if !value.starts_with("tool://") || value.len() <= "tool://".len() || value.len() > 248 {
            return Err(assertion_not_canonical(
                "expected_bound_tool_id",
                "a non-empty canonical 'tool://' ref",
            ));
        }
    }
    match body.get("expected_predecessor_revision_ref") {
        None | Some(Value::Null) => {}
        Some(Value::String(value)) if canonical_action_revision_ref(value) => {}
        Some(_) => {
            return Err(assertion_not_canonical(
                "expected_predecessor_revision_ref",
                "null or a canonical 'ontology-action://.../revision/N' ref",
            ))
        }
    }
    match body.get("expected_predecessor_content_hash") {
        None | Some(Value::Null) => {}
        Some(Value::String(value)) if is_sha256(value) => {}
        Some(_) => {
            return Err(assertion_not_canonical(
                "expected_predecessor_content_hash",
                "null or a canonical lowercase 'sha256:<64 hex>' string",
            ))
        }
    }
    if matches!(
        asserted_u64(body, "expected_revision_ordinal"),
        Asserted::Malformed
    ) {
        return Err(assertion_not_canonical(
            "expected_revision_ordinal",
            "a non-negative integer",
        ));
    }
    Ok(())
}

fn assertion_not_canonical(key: &str, required: &str) -> Reply {
    refuse(
        "ontology_action_contract_assertion_not_canonical",
        format!(
            "'{key}' is present but is not {required}; an assertion this route cannot read is refused rather than skipped, because skipping it would let a caller appear to have checked a server-derived fact it never checked"
        ),
    )
}

/// The caller-supplied `expected_*` assertions, checked against the EXACT STORED admitted document.
///
/// WHY A REPLAY PATH NEEDS ITS OWN ASSERTION CHECKER. `expected_*` fields are the caller saying what
/// it believes a server-derived fact to be; a disagreement is a refusal, never an accepted
/// substitution. On the fresh-admission path each one is checked at the point its fact is derived.
/// The replay path returns BEFORE most of those points are reached, so a caller reusing an admitted
/// key could assert a false ordinal, a false predecessor, or a false content hash and receive `200`
/// with the stored contract — the assertion silently skipped rather than answered. Reusing a key is
/// not a way to have a claim about the record go unexamined.
///
/// The comparison is against the STORED document, which is the honest referent on this path: the
/// caller is asking about a revision that already exists, so "what this revision's ordinal is" is a
/// fact the chain already holds. Each mismatch fails closed with the SAME cause-specific code the
/// fresh path uses, so a caller cannot tell the two paths apart by the shape of its refusal, and
/// nothing is appended.
///
/// `expected_head` IS DELIBERATELY ABSENT. A genuine retry after an ambiguous response carries the
/// head it originally compare-and-swapped against, which is by then stale — requiring it to match
/// would turn every real duplicate into a conflict and make the idempotency key unusable. That is
/// the same reason replay is resolved before the head precondition at all.
fn replay_assertion_divergence(document: &Value, body: &Value) -> Option<Reply> {
    match asserted_str(body, "expected_ontology_content_hash") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return Some(assertion_not_canonical(
                "expected_ontology_content_hash",
                "a 'sha256:<64 hex>' string",
            ))
        }
        Asserted::Present(asserted) => {
            if Some(asserted)
                != document
                    .get("ontology_content_hash")
                    .and_then(Value::as_str)
            {
                return Some(refuse(
                    "ontology_action_contract_ontology_hash_substituted",
                    "expected_ontology_content_hash does not match the exact ontology commitment stored for the revision this key admitted",
                ));
            }
        }
    }
    match asserted_str(body, "expected_bound_tool_id") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return Some(assertion_not_canonical(
                "expected_bound_tool_id",
                "a 'tool://' string",
            ))
        }
        Asserted::Present(asserted) => {
            if Some(asserted) != document.get("bound_tool_id").and_then(Value::as_str) {
                return Some(refuse(
                    "ontology_action_contract_tool_identity_substituted",
                    "expected_bound_tool_id does not match the exact RuntimeToolContract owner stored for the revision this key admitted",
                ));
            }
        }
    }
    match asserted_u64(body, "expected_revision_ordinal") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return Some(assertion_not_canonical(
                "expected_revision_ordinal",
                "a non-negative integer",
            ))
        }
        Asserted::Present(asserted) => {
            let stored = document.get("revision_ordinal").and_then(Value::as_u64);
            if Some(asserted) != stored {
                return Some(refuse(
                    "ontology_action_contract_ordinal_gap",
                    format!(
                        "this key already admitted revision {}, not {asserted}; a reused key answers for the revision it minted and never for one the caller would prefer",
                        stored.unwrap_or_default()
                    ),
                ));
            }
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_revision_ref") {
        if asserted
            != document
                .get("predecessor_revision_ref")
                .unwrap_or(&Value::Null)
        {
            return Some(refuse(
                "ontology_action_contract_predecessor_substituted",
                "expected_predecessor_revision_ref does not name the exact predecessor of the revision this key admitted",
            ));
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted
            != document
                .get("predecessor_content_hash")
                .unwrap_or(&Value::Null)
        {
            return Some(refuse(
                "ontology_action_contract_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match the exact predecessor commitment of the revision this key admitted",
            ));
        }
    }
    match asserted_str(body, "expected_content_hash") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return Some(assertion_not_canonical(
                "expected_content_hash",
                "a 'sha256:<64 hex>' string",
            ))
        }
        Asserted::Present(asserted) => {
            if Some(asserted) != document.get("content_hash").and_then(Value::as_str) {
                return Some(refuse(
                    "ontology_action_contract_content_hash_substituted",
                    "expected_content_hash does not match the hash the revision this key admitted actually commits to",
                ));
            }
        }
    }
    None
}

fn replay_existing_admission(
    data_dir: &str,
    caller: &WriteCaller,
    scope: &RequestResourceScope,
    family: &str,
    lineage: &[Value],
    body: &Value,
    proposal: &ProposedContract,
) -> Result<Option<Reply>, Reply> {
    let prior = prior_admission_for_key_on_stream(
        data_dir,
        &caller.identity,
        scope,
        RESOURCE_KIND,
        family,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, family),
        &caller.idempotency_key,
    )
    .map_err(mutation_refusal_reply)?;
    let Some(prior) = prior else {
        return Ok(None);
    };
    let Some(document) = lineage
        .iter()
        .find(|document| document.pointer("/admission/admission_head") == Some(&json!(prior.head)))
    else {
        return Err(bad(
            StatusCode::BAD_GATEWAY,
            "ontology_action_contract_projection_disagrees_with_ack",
            "this key's admitted head is absent from the family's projected lineage",
        ));
    };
    match replay_intent_divergence(document, proposal)? {
        Some(field) => {
            return Err(bad(
                StatusCode::CONFLICT,
                "ontology_action_contract_replay_intent_changed",
                format!(
                    "this idempotency key already admitted a contract whose '{field}' differs from this request; a key replays one exact command and is never a way to receive a stored contract in answer to a changed one"
                ),
            ))
        }
        None => {}
    }
    if let Some(response) = replay_assertion_divergence(document, body) {
        return Err(response);
    }
    Ok(Some((
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": true,
            "ontology_action_contract": document,
            "expected_head_for_successor": lineage
                .last()
                .and_then(|head| head.pointer("/admission/admission_head"))
                .cloned()
                .unwrap_or(Value::Null),
            "receipt_ref": document.pointer("/admission/agentgres_receipt_ref").cloned().unwrap_or(Value::Null),
            "operation_ref": document.pointer("/admission/agentgres_operation_ref").cloned().unwrap_or(Value::Null),
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "invocation_nonclaim": INVOCATION_NONCLAIM,
        })),
    )))
}

// ------------------------------------------------------------------------------- producer route

/// POST /v1/hypervisor/ontology-action-contracts — admit one immutable revision of one
/// owner-qualified action-contract family against the exact current head of its Agentgres chain.
pub(crate) async fn handle_ontology_action_contract_admit(
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
    // Assertion SHAPE is decided here, before any owner is consulted and before the lineage is read,
    // so an unreadable claim is answered as itself rather than surfacing as a head conflict on a
    // family that happens to have revisions already.
    if let Err(response) = validate_assertion_shapes(&body) {
        return response;
    }

    let family = family_ref(&proposal.namespace, &proposal.name, &proposal.action_slug);
    // Historical replay is answered from immutable admitted bytes before consulting mutable
    // current owner state. A tool may be revoked after this revision was admitted, and a dynamic
    // registry may be reconstructed differently after restart; neither fact rewrites the command
    // that this key already committed. Only an existing, already-authorized scope is inspected at
    // this point, so an unresolvable fresh proposal still creates no scope or operation.
    let existing = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &family,
        Some(&caller.owner_ref),
    ) {
        Ok(scope) => {
            let lineage = match read_lineage(&st.data_dir, &caller.identity, &scope, &family) {
                Ok(lineage) => lineage,
                Err(response) => return response,
            };
            match replay_existing_admission(
                &st.data_dir,
                &caller,
                &scope,
                &family,
                &lineage,
                &body,
                &proposal,
            ) {
                Ok(Some(response)) => return response,
                Ok(None) => Some((scope, lineage)),
                Err(response) => return response,
            }
        }
        Err(RequestScopeRefusal::ResourceScopeRequired) => None,
        Err(error) => return scope_refusal_reply(error),
    };

    // BOTH BINDINGS RESOLVE BEFORE ANY SCOPE IS BOUND OR ANY BYTE IS WRITTEN. An unresolvable
    // revision or an unreleased tool stops here, so neither can acquire a stream, a scope or a
    // durable contract on the strength of its spelling.
    let semantics = match resolve_semantics(
        &st.data_dir,
        &caller.identity,
        &proposal.ontology_revision_ref,
        &proposal.action_type_ref,
    ) {
        Ok(semantics) => semantics,
        Err(response) => return response,
    };
    let tool = match resolve_tool(
        &st,
        &proposal.runtime_tool_contract_revision_ref,
        &proposal.runtime_tool_contract_content_hash,
    ) {
        Ok(tool) => tool,
        Err(response) => return response,
    };
    let expected_action_type_ref = format!(
        "{}/term/{}",
        semantics.ontology_family_ref, proposal.action_slug
    );
    if proposal.action_type_ref != expected_action_type_ref {
        return refuse(
            "ontology_action_contract_action_identity_substituted",
            "action_slug must name the exact action term resolved from the bound ontology revision; local aliases require an admitted mapping decision and are not invented by this contract",
        );
    }
    let expected_input_schema_ref = typed_tool_schema_ref("input", &tool.input_schema_hash);
    let expected_output_schema_ref = typed_tool_schema_ref("output", &tool.output_schema_hash);
    if proposal.typed_input_schema_ref != expected_input_schema_ref
        || proposal.typed_output_schema_ref != expected_output_schema_ref
    {
        return refuse(
            "ontology_action_contract_typed_schema_binding_substituted",
            "typed input/output schema refs must be the canonical content-addressed refs derived from the exact RuntimeToolContract schema bytes",
        );
    }
    // Two owners, two commitments. An implementation that resolved one and copied it into both slots
    // would read as bound twice and be bound once; the registered invariant catches it offline and
    // this catches it before the durable write.
    if semantics.ontology_content_hash == tool.content_hash {
        return bad(
            StatusCode::BAD_GATEWAY,
            "ontology_action_contract_bindings_collapsed",
            "the ontology and tool owners resolved to one identical commitment; two distinct bindings are required and a collapsed pair binds half of what it claims",
        );
    }

    // A caller may ASSERT an owner-resolved value; a disagreement refuses BY ITS OWN CAUSE rather
    // than being accepted as a substitution.
    match asserted_str(&body, "expected_ontology_content_hash") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return assertion_not_canonical(
                "expected_ontology_content_hash",
                "a 'sha256:<64 hex>' string",
            )
        }
        Asserted::Present(asserted) => {
            if asserted != semantics.ontology_content_hash {
                return refuse(
                    "ontology_action_contract_ontology_hash_substituted",
                    "expected_ontology_content_hash does not match the hash the ontology owner currently commits to; the binding is that owner's, never the caller's",
                );
            }
        }
    }
    match asserted_str(&body, "expected_bound_tool_id") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return assertion_not_canonical("expected_bound_tool_id", "a 'tool://' string")
        }
        Asserted::Present(asserted) => {
            if asserted != tool.tool_id {
                return refuse(
                    "ontology_action_contract_tool_identity_substituted",
                    "expected_bound_tool_id does not match the tool the resolved revision actually belongs to",
                );
            }
        }
    }

    let (scope, lineage) = match existing {
        Some(existing) => existing,
        None => {
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
            (scope, lineage)
        }
    };
    let predecessor = lineage.last().cloned();

    let expected_head = match body.get("expected_head") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return refuse(
                "ontology_action_contract_expected_head_not_canonical",
                "expected_head must be the exact current Agentgres head of this family's lineage, or null for the first revision",
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
            "ontology_action_contract_expected_head_conflict",
            match (&expected_head, &current_head) {
                (None, Some(_)) => "this family already has revisions; a successor must name the exact current head".to_string(),
                (Some(_), None) => "this family has no revisions yet; the first revision names no predecessor head".to_string(),
                _ => "expected_head does not name the exact current head of this family's lineage; re-read the head and re-derive the revision".to_string(),
            },
        );
    }

    // THE ORDINAL IS DERIVED, NOT ACCEPTED. Chain length decides which revision comes next, so a
    // caller cannot mint revision 7 of a family that has two.
    let ordinal = predecessor
        .as_ref()
        .map_or(1, |document| ordinal_of(document) + 1);
    if ordinal > MAX_REVISION_ORDINAL {
        return refuse(
            "ontology_action_contract_lineage_exhausted",
            "this family has reached the largest revision ordinal the registered contract admits",
        );
    }
    match asserted_u64(&body, "expected_revision_ordinal") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return assertion_not_canonical("expected_revision_ordinal", "a non-negative integer")
        }
        Asserted::Present(asserted) => {
            if asserted != ordinal {
                return refuse(
                    "ontology_action_contract_ordinal_gap",
                    format!("this family's next revision is {ordinal}, not {asserted}; revision ordinals are contiguous and never skip"),
                );
            }
        }
    }

    let predecessor_ref = predecessor
        .as_ref()
        .and_then(|document| document.get("ontology_action_id").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .as_ref()
        .and_then(|document| document.get("content_hash").cloned())
        .unwrap_or(Value::Null);
    if let Some(asserted) = body.get("expected_predecessor_revision_ref") {
        if asserted != &predecessor_ref {
            return refuse(
                "ontology_action_contract_predecessor_substituted",
                "expected_predecessor_revision_ref does not name this family's exact current revision",
            );
        }
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "ontology_action_contract_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            );
        }
    }

    let compatibility = match compatibility_for_ordinal(&proposal, ordinal) {
        Ok(value) => value.to_string(),
        Err(response) => return response,
    };

    let ontology_action_id = revision_ref(
        &proposal.namespace,
        &proposal.name,
        &proposal.action_slug,
        ordinal,
    );
    let mut record = json!({
        "schema_version": SCHEMA_VERSION,
        "ontology_action_id": ontology_action_id,
        "action_family_ref": family,
        "action_record_profile": RECORD_PROFILE,
        "namespace": proposal.namespace,
        "name": proposal.name,
        "action_slug": proposal.action_slug,
        "owner_id": caller.owner_ref,
        "governing_scope_ref": proposal.governing_scope_ref,
        "version": version_label(ordinal),
        "revision_ordinal": ordinal,
        "predecessor_revision_ref": predecessor_ref,
        "predecessor_content_hash": predecessor_hash,
        "ontology_family_ref": semantics.ontology_family_ref,
        "ontology_revision_ref": semantics.ontology_revision_ref,
        "ontology_content_hash": semantics.ontology_content_hash,
        "ontology_resolved_by": ONTOLOGY_RESOLVER,
        "action_type_ref": proposal.action_type_ref,
        "runtime_tool_contract_revision_ref": tool.revision_ref,
        "runtime_tool_contract_content_hash": tool.content_hash,
        "runtime_tool_resolved_by": TOOL_RESOLVER,
        "bound_tool_id": tool.tool_id,
        "bound_tool_risk_class": tool.risk_class,
        "bound_tool_effect_class": tool.effect_class,
        "bound_tool_class_vocabulary": TOOL_CLASS_VOCABULARY,
        "bound_tool_input_schema_hash": tool.input_schema_hash,
        "bound_tool_output_schema_hash": tool.output_schema_hash,
        "bound_tool_primitive_capabilities_required": tool.primitive_capabilities_required,
        "bound_tool_authority_scopes_required": tool.authority_scopes_required,
        "typed_input_schema_ref": proposal.typed_input_schema_ref,
        "typed_output_schema_ref": proposal.typed_output_schema_ref,
        "target_object_model_refs": proposal.target_object_model_refs,
        "precondition_refs": proposal.precondition_refs,
        "postcondition_and_invariant_refs": proposal.postcondition_and_invariant_refs,
        "expected_state_transition_ref": proposal.expected_state_transition_ref,
        "risk_class": proposal.risk_class,
        "effect_recovery_class": proposal.effect_recovery_class,
        "idempotency_and_retry_profile_ref": proposal.idempotency_and_retry_profile_ref,
        "ambiguous_effect_and_reconciliation_profile_ref": proposal.ambiguous_effect_and_reconciliation_profile_ref,
        "compensation_profile_ref": proposal.compensation_profile_ref,
        "preview_and_dry_run_profile_ref": proposal.preview_and_dry_run_profile_ref,
        "approval_and_revocation_refs": proposal.approval_and_revocation_refs,
        "local_policy_and_authority_scope_refs": proposal.local_policy_and_authority_scope_refs,
        "verifier_and_evidence_refs": proposal.verifier_and_evidence_refs,
        "physical_safety_profile_ref": proposal.physical_safety_profile_ref,
        "receipt_obligations": proposal.receipt_obligations,
        // ACC-6 CLAUSE 5. Never caller-supplied, never conditional, never shortened.
        "required_gates": REQUIRED_GATES,
        "required_gate_count": REQUIRED_GATES.len(),
        "policy_hash": proposal.policy_hash,
        "does_not_assert": proposal.does_not_assert,
        "constants": {
            "authority_nonclaim_token": "authority",
            "capability_gate": "capability",
            "policy_gate": "policy",
            "authority_gate": "authority",
            "daemon_admission_gate": "daemon_admission",
            "evidence_gate": "evidence",
            "verification_gate": "verification",
        },
        "authority_nonclaim": AUTHORITY_NONCLAIM,
        "invocation_nonclaim": INVOCATION_NONCLAIM,
        "valid_time": proposal.valid_time,
        "migration": {
            "from_revision_ref": predecessor_ref,
            "from_content_hash": predecessor_hash,
            "from_revision_ordinal": ordinal - 1,
            "compatibility": compatibility,
            // A migration NEVER reinterprets its predecessor. The earlier revision's bytes and
            // content hash do not move; only its transaction interval closes.
            "reinterprets_predecessor": false,
        },
    });
    let derived_hash = match content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ontology_action_contract_content_hash_failed",
                reason,
            )
        }
    };
    match asserted_str(&body, "expected_content_hash") {
        Asserted::Absent => {}
        Asserted::Malformed => {
            return assertion_not_canonical("expected_content_hash", "a 'sha256:<64 hex>' string")
        }
        Asserted::Present(asserted) => {
            if asserted != derived_hash {
                return refuse(
                    "ontology_action_contract_content_hash_substituted",
                    "expected_content_hash does not match the hash this exact content commits to",
                );
            }
        }
    }
    record["content_hash"] = json!(derived_hash);

    if let Err(reason) = validate_contract_before_admission(&record, &family) {
        return refuse(
            "ontology_action_contract_registered_contract_refused",
            format!(
                "the proposed action contract does not satisfy its registered contract before admission: {reason}"
            ),
        );
    }

    let payload = json!({
        "schema_version": ADMISSION_PAYLOAD_SCHEMA,
        "owner_ref": caller.owner_ref,
        "resource_ref": family,
        "action_contract_record": record,
    });
    let recorded_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    // The SHARED admission boundary — the same one every owner-scoped daemon mutation crosses. This
    // module mints no second admitter and writes no record file of its own.
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
            "ontology_action_contract_projection_disagrees_with_ack",
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
            "ontology_action_contract": admitted,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "invocation_nonclaim": INVOCATION_NONCLAIM,
        })),
    )
}

// ------------------------------------------------------------------------------- consumer route

#[derive(serde::Deserialize)]
pub(crate) struct ActionContractQuery {
    namespace: Option<String>,
    name: Option<String>,
    action_slug: Option<String>,
    revision: Option<u64>,
    risk_class: Option<String>,
    as_of_transaction_time: Option<String>,
}

/// GET /v1/hypervisor/ontology-action-contracts — exact lookup, whole lineage, or a transaction-time
/// cell.
///
/// With no coordinates this answers the caller's family inventory. With `namespace`, `name` and
/// `action_slug` it answers one lineage, optionally narrowed by `revision` (exact),
/// `as_of_transaction_time` ("as the record stood then") and `risk_class`.
///
/// The transaction-time slice TRUNCATES THE HISTORY BEFORE PROJECTING rather than filtering rows out
/// of the present. Filtering would return today's supersession stamps against yesterday's question:
/// `superseded_at` is derived from the FOLLOWING revision, so a row filtered out of the present
/// carries a supersession that had not happened at the instant asked about.
pub(crate) async fn handle_ontology_action_contract_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<ActionContractQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let (Some(namespace), Some(name), Some(action_slug)) = (
        query.namespace.as_deref(),
        query.name.as_deref(),
        query.action_slug.as_deref(),
    ) else {
        let refs = match authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND) {
            Ok(refs) => refs,
            Err(error) => return scope_refusal_reply(error),
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "action_contract_families": refs,
                "authority_nonclaim": AUTHORITY_NONCLAIM,
                "invocation_nonclaim": INVOCATION_NONCLAIM,
            })),
        );
    };
    if !canonical_token(namespace, 63)
        || !canonical_token(name, 63)
        || !canonical_token(action_slug, 63)
    {
        return refuse(
            "ontology_action_contract_identity_not_canonical",
            "namespace, name and action_slug must each be a canonical lowercase token",
        );
    }
    let family = family_ref(namespace, name, action_slug);

    let (mut lineage, scope) = match query.as_of_transaction_time.as_deref() {
        None => match authorized_lineage(&st.data_dir, &identity, &family) {
            Ok(pair) => pair,
            Err(response) => return response,
        },
        Some(stamp) => {
            let Some(as_of) = parse_time(stamp) else {
                return refuse(
                    "ontology_action_contract_transaction_time_not_canonical",
                    "as_of_transaction_time must be an RFC 3339 timestamp",
                );
            };
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
            let history = match read_owner_scoped_history(
                &st.data_dir,
                &identity,
                &scope,
                RESOURCE_KIND,
                &family,
                OWNER_NAMESPACE,
                &stream_tail(RESOURCE_KIND, &family),
            ) {
                Ok(history) => history,
                Err(error) => return mutation_refusal_reply(error),
            };
            let truncated: Vec<ExactProjection> = history
                .into_iter()
                .filter(|entry| entry.operation.recorded_at_ms / 1000 <= as_of)
                .collect();
            match project_lineage(&truncated, &family) {
                Ok(lineage) => (lineage, scope),
                Err(reason) => {
                    return bad(
                        StatusCode::BAD_GATEWAY,
                        "ontology_action_contract_projection_failed",
                        reason,
                    )
                }
            }
        }
    };

    // The cache is consulted only AFTER the lineage exists, and a historical slice does not touch it
    // at all: a truncated view is not this family's current state and must not become the entry a
    // later present-tense read compares itself against.
    let index_state = if query.as_of_transaction_time.is_some() {
        "not_consulted_historical_slice"
    } else {
        projection_cache_state(&projection_cache_key(&scope, &family), &lineage)
    };

    if let Some(revision) = query.revision {
        lineage.retain(|document| ordinal_of(document) == revision);
    }
    if let Some(risk_class) = query.risk_class.as_deref() {
        lineage.retain(|document| {
            document.get("risk_class").and_then(Value::as_str) == Some(risk_class)
        });
    }
    if lineage.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "ontology_action_contract_absent",
                    "message": "no admitted revision of this family matches those coordinates — an absent revision is a typed absence, never an empty success",
                },
                "action_family_ref": family,
                "index_state": index_state,
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "action_family_ref": family,
            "revisions": lineage,
            "revision_count": lineage.len(),
            "index_state": index_state,
            "authority_nonclaim": AUTHORITY_NONCLAIM,
            "invocation_nonclaim": INVOCATION_NONCLAIM,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ACC-6 clause 5 lives or dies on this list being the canonical six, in the canonical order,
    /// with nothing removed. The registered schema and invariant enforce it offline; this enforces
    /// it in the source a mutation would edit.
    #[test]
    fn the_gate_ladder_is_the_canonical_six_in_canonical_order() {
        assert_eq!(
            REQUIRED_GATES,
            &[
                "capability",
                "policy",
                "authority",
                "daemon_admission",
                "evidence",
                "verification"
            ]
        );
        assert_eq!(REQUIRED_GATES.len(), 6);
    }

    /// The six mandatory nonclaims are the ones whose omission would let a compiled contract be
    /// read as conferring the thing it does not confer. `action_term_membership` is deliberately not
    /// among them and not in the vocabulary at all: the owner seam decides membership, so a record
    /// disclaiming it would understate a binding this path actually enforces.
    #[test]
    fn every_mandatory_nonclaim_is_a_member_of_the_closed_vocabulary() {
        assert_eq!(REQUIRED_NONCLAIMS.len(), 6);
        assert!(!NONCLAIM_TOKENS.contains(&"action_term_membership"));
        for required in REQUIRED_NONCLAIMS {
            assert!(
                NONCLAIM_TOKENS.contains(required),
                "mandatory nonclaim '{required}' is not in the closed vocabulary"
            );
        }
        for mandatory in ["authority", "capability_grant", "lease", "invocation"] {
            assert!(REQUIRED_NONCLAIMS.contains(&mandatory));
        }
    }

    /// The content commitment covers content and NOT admission. Committing transaction time or the
    /// admission block would move a predecessor's hash the moment a successor closed its interval,
    /// which is exactly the reinterpretation an immutable revision exists to refuse.
    #[test]
    fn content_commitment_excludes_transaction_time_and_admission() {
        for excluded in [
            "transaction_time",
            "admission",
            "admission_domain_ref",
            "status",
            "content_hash",
        ] {
            assert!(
                !CONTENT_MATERIAL_FIELDS.contains(&excluded),
                "'{excluded}' must not be inside the content commitment"
            );
        }
        for included in [
            "ontology_revision_ref",
            "ontology_content_hash",
            "runtime_tool_contract_revision_ref",
            "runtime_tool_contract_content_hash",
            "bound_tool_input_schema_hash",
            "bound_tool_output_schema_hash",
            "required_gates",
            "does_not_assert",
            "risk_class",
            "valid_time",
            "migration",
        ] {
            assert!(
                CONTENT_MATERIAL_FIELDS.contains(&included),
                "'{included}' must be inside the content commitment"
            );
        }
    }

    /// Two families never share one revision identity, and a revision identity always extends its
    /// own family.
    #[test]
    fn revision_identity_extends_its_own_family_and_is_unique_per_family() {
        let one = revision_ref("acme", "intake", "schedule", 2);
        let two = revision_ref("acme", "intake", "dispatch", 2);
        let three = revision_ref("other", "intake", "schedule", 2);
        assert_ne!(one, two);
        assert_ne!(one, three);
        assert!(one.starts_with(&format!(
            "{}/revision/",
            family_ref("acme", "intake", "schedule")
        )));
        assert_eq!(version_label(2), "v2");
    }

    /// The canonical ladder is the enum owner's, carried whole, with the peer top-tier class present
    /// and the pre-consolidation runtime strings absent.
    #[test]
    fn risk_classes_are_the_canonical_ladder_plus_the_peer_physical_class() {
        assert_eq!(RISK_CLASSES.len(), 13);
        assert_eq!(RISK_CLASSES[0], "read");
        assert_eq!(RISK_CLASSES[11], "system_destructive");
        assert!(RISK_CLASSES.contains(&PHYSICAL_ACTION_RISK_CLASS));
        for legacy in ["low", "write", "mutation", "external_effect", "destructive"] {
            assert!(
                !RISK_CLASSES.contains(&legacy),
                "'{legacy}' is a pre-consolidation runtime string and is not canonical here"
            );
        }
        assert_eq!(EFFECT_RECOVERY_CLASSES.len(), 5);
    }

    /// A canonical sha256 is lowercase, prefixed and exactly 64 hex digits. This is the fail-closed
    /// check at both owner seams, so a weakened neighbour surfaces as a refusal.
    #[test]
    fn sha256_recognition_is_exact_and_case_closed() {
        assert!(is_sha256(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_sha256(&format!("sha256:{}", "a".repeat(63))));
        assert!(!is_sha256(&format!("sha1:{}", "a".repeat(64))));
        assert!(!is_sha256(""));
    }

    /// The registered fixture corpus, exercised against the SAME validator the projection path uses.
    ///
    /// WHY THIS TEST EXISTS AND WHY IT IS HERE. A registered corpus can be internally consistent and
    /// still be fiction: nothing in a JSON schema knows what `agentgres::refs` actually emits. The
    /// first cut of these fixtures carried invented `agentgres://event-stream/…/operation/1` and
    /// `receipt://event-stream/…/receipt/1` refs — plausible, uniform, and matching no producer in
    /// the tree. They would have passed every offline gate while documenting an admission shape that
    /// cannot occur. So the positives are checked against the OWNER PRODUCER HELPERS THEMSELVES,
    /// called here, not against a pattern that would accept the invention too.
    #[test]
    fn the_registered_fixture_corpus_is_producer_real_and_fails_where_it_claims_to() {
        const POSITIVES: &[(&str, &str)] = &[
            (
                "positive-genesis-external-message",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/positive-genesis-external-message.json"),
            ),
            (
                "positive-successor-physical-action",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/positive-successor-physical-action.json"),
            ),
        ];
        const NEGATIVES: &[(&str, &str)] = &[
            (
                "negative-action-term-from-another-family",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-action-term-from-another-family.json"),
            ),
            (
                "negative-bindings-collapsed-into-one-hash",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-bindings-collapsed-into-one-hash.json"),
            ),
            (
                "negative-content-hash-substituted",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-content-hash-substituted.json"),
            ),
            (
                "negative-gate-removed-from-the-ladder",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-gate-removed-from-the-ladder.json"),
            ),
            (
                "negative-migration-source-is-not-the-predecessor",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-migration-source-is-not-the-predecessor.json"),
            ),
            (
                "negative-mutable-latest-ontology-binding",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-mutable-latest-ontology-binding.json"),
            ),
            (
                "negative-physical-action-without-safety-profile",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-physical-action-without-safety-profile.json"),
            ),
            (
                "negative-retired-action-term-membership-nonclaim",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-retired-action-term-membership-nonclaim.json"),
            ),
            (
                "negative-tool-revision-of-another-tool",
                include_str!("../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/negative-tool-revision-of-another-tool.json"),
            ),
        ];

        for (name, body) in POSITIVES {
            let document: Value = serde_json::from_str(body).expect("fixture is JSON");
            validate_architecture_contract(CONTRACT_ID, &document).unwrap_or_else(|reason| {
                panic!("{name} must pass the registered contract: {reason}")
            });

            // THE PRODUCER IS THE ORACLE. Every admission ref, the domain ref and the stream tail are
            // recomputed here by calling the same helpers `contract_document` calls, over the
            // fixture's own family, sequence, head and root. An invented shape cannot survive this.
            let family = document["action_family_ref"].as_str().expect("family ref");
            let tail = stream_tail(RESOURCE_KIND, family);
            let admission = &document["admission"];
            let seq = admission["admission_seq"].as_u64().expect("admission seq");
            let head = admission["admission_head"]
                .as_str()
                .expect("admission head");
            let root = admission["admission_root"]
                .as_str()
                .expect("admission root");
            assert_eq!(admission["stream_tail"], json!(tail), "{name} stream tail");
            assert_eq!(
                document["admission_domain_ref"],
                json!(format!(
                    "agentgres://domain/{}",
                    agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
                )),
                "{name} admission domain ref"
            );
            assert_eq!(
                admission["agentgres_operation_ref"],
                json!(agentgres::refs::event_stream_operation_ref(
                    OWNER_NAMESPACE,
                    &tail,
                    seq,
                    head
                )),
                "{name} operation ref"
            );
            assert_eq!(
                admission["agentgres_receipt_ref"],
                json!(agentgres::refs::event_stream_receipt_ref(
                    OWNER_NAMESPACE,
                    &tail,
                    seq,
                    root
                )),
                "{name} receipt ref"
            );
            assert_eq!(
                admission["owner_namespace"],
                json!(OWNER_NAMESPACE),
                "{name} owner namespace"
            );
            // And the served commitment is the one this module derives, not one the fixture asserts.
            assert_eq!(
                json!(content_hash(&document).expect("content hash")),
                document["content_hash"],
                "{name} content hash"
            );
        }

        // THE NEGATIVES ARE REAL EXAMPLES WITH ONE DEFECT EACH, AND THAT IS LOAD-BEARING. A negative
        // that were ALSO malformed in its admission block could fail for the wrong reason and still
        // look like evidence for the rule it names. None of the defects below is an admission-binding
        // defect, so every one of them must reproduce the producer shapes exactly — the same
        // rederivation the positives get.
        for (name, body) in NEGATIVES {
            let document: Value = serde_json::from_str(body).expect("fixture is JSON");
            assert!(
                validate_architecture_contract(CONTRACT_ID, &document).is_err(),
                "{name} must be refused by the registered contract"
            );
            // Repair exactly the named defect and require the same bytes to become valid. This is
            // stronger than merely observing generic rejection: a negative carrying a second,
            // unnamed defect would remain red after its advertised defect was repaired.
            let mut repaired = document.clone();
            match *name {
                "negative-action-term-from-another-family" => {
                    repaired["action_type_ref"] = json!(format!(
                        "{}/term/{}",
                        repaired["ontology_family_ref"]
                            .as_str()
                            .expect("ontology family"),
                        repaired["action_slug"].as_str().expect("action slug")
                    ));
                }
                "negative-bindings-collapsed-into-one-hash" => {
                    repaired["runtime_tool_contract_content_hash"] =
                        json!(format!("sha256:{}", "2b".repeat(32)));
                }
                "negative-content-hash-substituted" => {}
                "negative-gate-removed-from-the-ladder" => {
                    repaired["required_gates"] = json!(REQUIRED_GATES);
                    repaired["required_gate_count"] = json!(REQUIRED_GATES.len());
                }
                "negative-migration-source-is-not-the-predecessor" => {
                    repaired["migration"]["from_revision_ref"] =
                        repaired["predecessor_revision_ref"].clone();
                    repaired["migration"]["from_content_hash"] =
                        repaired["predecessor_content_hash"].clone();
                    repaired["migration"]["from_revision_ordinal"] = json!(
                        repaired["revision_ordinal"]
                            .as_u64()
                            .expect("revision ordinal")
                            - 1
                    );
                }
                "negative-mutable-latest-ontology-binding" => {
                    repaired["ontology_revision_ref"] = json!(format!(
                        "{}/revision/1",
                        repaired["ontology_family_ref"]
                            .as_str()
                            .expect("ontology family")
                    ));
                }
                "negative-physical-action-without-safety-profile" => {
                    repaired["physical_safety_profile_ref"] =
                        json!("safety://acme-clinic/physical-action/v1");
                }
                "negative-retired-action-term-membership-nonclaim" => {
                    repaired["does_not_assert"] = Value::Array(
                        repaired["does_not_assert"]
                            .as_array()
                            .expect("nonclaims")
                            .iter()
                            .filter(|value| value.as_str() != Some("action_term_membership"))
                            .cloned()
                            .collect(),
                    );
                }
                "negative-tool-revision-of-another-tool" => {
                    repaired["runtime_tool_contract_revision_ref"] = json!(format!(
                        "{}/revision/0123456789abcdef",
                        repaired["bound_tool_id"].as_str().expect("bound tool")
                    ));
                }
                other => panic!("unaccounted negative fixture {other}"),
            }
            repaired["content_hash"] =
                json!(content_hash(&repaired).expect("repaired content hash"));
            repaired["admission"]["content_hash"] = repaired["content_hash"].clone();
            validate_architecture_contract(CONTRACT_ID, &repaired).unwrap_or_else(|reason| {
                panic!("{name} has an unnamed defect after its named defect is repaired: {reason}")
            });
            let family = document["action_family_ref"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} carries no action family ref"));
            let tail = stream_tail(RESOURCE_KIND, family);
            let admission = &document["admission"];
            assert!(
                admission.is_object(),
                "{name} must carry a real admission block beside its intended defect"
            );
            let seq = admission["admission_seq"].as_u64().expect("admission seq");
            let head = admission["admission_head"]
                .as_str()
                .expect("admission head");
            let root = admission["admission_root"]
                .as_str()
                .expect("admission root");
            assert_eq!(admission["stream_tail"], json!(tail), "{name} stream tail");
            assert_eq!(
                admission["owner_namespace"],
                json!(OWNER_NAMESPACE),
                "{name} owner namespace"
            );
            assert_eq!(
                document["admission_domain_ref"],
                json!(format!(
                    "agentgres://domain/{}",
                    agentgres::refs::event_stream_domain(OWNER_NAMESPACE, &tail)
                )),
                "{name} admission domain ref"
            );
            assert_eq!(
                admission["agentgres_operation_ref"],
                json!(agentgres::refs::event_stream_operation_ref(
                    OWNER_NAMESPACE,
                    &tail,
                    seq,
                    head
                )),
                "{name} operation ref"
            );
            assert_eq!(
                admission["agentgres_receipt_ref"],
                json!(agentgres::refs::event_stream_receipt_ref(
                    OWNER_NAMESPACE,
                    &tail,
                    seq,
                    root
                )),
                "{name} receipt ref"
            );

            // The two ADMISSION-TARGETED negatives are the exception, and they are checked to differ
            // from a valid record in exactly their intended binding and nothing else: one carries a
            // content hash the commitment does not produce, the other still binds the admission block
            // to whatever hash it declares. Neither is allowed to become a second, unnamed defect.
            let declared = document["content_hash"].as_str().expect("content hash");
            let derived = content_hash(&document).expect("content hash derives");
            if *name == "negative-content-hash-substituted" {
                assert_ne!(
                    derived, declared,
                    "the content-hash negative must actually carry a substituted hash"
                );
                assert_eq!(
                    admission["content_hash"], document["content_hash"],
                    "and its admission must still bind the hash it declares, so the ONLY defect is the substitution"
                );
            } else {
                assert_eq!(
                    json!(derived),
                    document["content_hash"],
                    "{name} must carry a canonical content hash, so its ONLY defect is the one it names"
                );
                assert_eq!(
                    admission["content_hash"], document["content_hash"],
                    "{name} admission must bind its own content hash"
                );
            }
        }
    }

    #[test]
    fn registered_contract_is_validated_before_admission_and_refuses_prefix_only_refs() {
        let mut record: Value = serde_json::from_str(include_str!(
            "../../../../../docs/architecture/_meta/schemas/fixtures/ontology-action-contract-v1/positive-genesis-external-message.json"
        ))
        .expect("positive action contract fixture is JSON");
        let family = record["action_family_ref"]
            .as_str()
            .expect("fixture family")
            .to_string();
        let object = record.as_object_mut().expect("fixture object");
        for projection_only in [
            "admission_domain_ref",
            "transaction_time",
            "admission",
            "status",
        ] {
            object.remove(projection_only);
        }
        record["content_hash"] = json!(content_hash(&record).expect("content hash"));
        validate_contract_before_admission(&record, &family)
            .expect("the complete positive producer record passes before admission");

        record["typed_input_schema_ref"] = json!("schema://");
        record["content_hash"] = json!(content_hash(&record).expect("mutated content hash"));
        assert!(
            validate_contract_before_admission(&record, &family).is_err(),
            "a prefix-only ref must be refused before it can append an unprojectable operation"
        );
    }

    /// EVERY caller-authored material input is compared before a key replays a stored contract.
    ///
    /// The names below are the twenty-nine members of `ProposedContract` minus the three that are
    /// bound from their owners' resolved values instead of the caller's raw text, plus those three
    /// under the names the stored document uses. The count is asserted too: `proposal_intent`
    /// destructures the struct exhaustively, so a new field cannot be silently omitted — but a new
    /// field COULD be added to both the struct and the map while this list stayed stale, and the
    /// count is what turns that into a failure here rather than a quiet narrowing.
    #[test]
    fn replay_intent_covers_every_caller_authored_material_field() {
        let proposal = ProposedContract {
            namespace: "acme-clinic".into(),
            name: "patient-intake".into(),
            action_slug: "schedule-followup".into(),
            governing_scope_ref: "domain://acme-clinic/intake".into(),
            policy_hash: format!("sha256:{}", "1a".repeat(32)),
            ontology_revision_ref: "ontology://acme-clinic/patient-intake/revision/1".into(),
            action_type_ref: "ontology://acme-clinic/patient-intake/term/schedule-followup".into(),
            runtime_tool_contract_revision_ref:
                "tool://ioi/runtime/mail.send/revision/0123456789abcdef".into(),
            runtime_tool_contract_content_hash: format!("sha256:{}", "2b".repeat(32)),
            typed_input_schema_ref: "schema://acme/in/v1".into(),
            typed_output_schema_ref: "schema://acme/out/v1".into(),
            target_object_model_refs: json!(["object-model://acme/appointment"]),
            precondition_refs: json!(["state://acme/unscheduled"]),
            postcondition_and_invariant_refs: json!(["invariant://acme/one-open"]),
            expected_state_transition_ref: "transition://acme/unscheduled-to-scheduled".into(),
            risk_class: "external_message".into(),
            effect_recovery_class: "reconciliation_required".into(),
            idempotency_and_retry_profile_ref: "policy://acme/idempotency".into(),
            ambiguous_effect_and_reconciliation_profile_ref: "policy://acme/reconciliation".into(),
            compensation_profile_ref: json!("policy://acme/compensation"),
            preview_and_dry_run_profile_ref: Value::Null,
            approval_and_revocation_refs: json!(["approval-policy://acme/outbound"]),
            local_policy_and_authority_scope_refs: json!(["policy://acme/outbound"]),
            verifier_and_evidence_refs: json!(["evidence://acme/response"]),
            physical_safety_profile_ref: Value::Null,
            receipt_obligations: json!(["receipt://acme/action-admission"]),
            does_not_assert: json!(["authority"]),
            valid_time: json!({ "starts_at": "2026-01-01T00:00:00Z", "ends_at": null }),
            compatibility: Some("additive".into()),
        };
        let intent = proposal_intent(&proposal, 2).expect("successor compatibility is canonical");
        for field in [
            "namespace",
            "name",
            "action_slug",
            "governing_scope_ref",
            "policy_hash",
            "ontology_revision_ref",
            "action_type_ref",
            "runtime_tool_contract_revision_ref",
            "runtime_tool_contract_content_hash",
            "typed_input_schema_ref",
            "typed_output_schema_ref",
            "target_object_model_refs",
            "precondition_refs",
            "postcondition_and_invariant_refs",
            "expected_state_transition_ref",
            "risk_class",
            "effect_recovery_class",
            "idempotency_and_retry_profile_ref",
            "ambiguous_effect_and_reconciliation_profile_ref",
            "compensation_profile_ref",
            "preview_and_dry_run_profile_ref",
            "approval_and_revocation_refs",
            "local_policy_and_authority_scope_refs",
            "verifier_and_evidence_refs",
            "physical_safety_profile_ref",
            "receipt_obligations",
            "does_not_assert",
            "valid_time",
            "compatibility",
        ] {
            assert!(
                intent.contains_key(field),
                "'{field}' must be compared before a key replays a stored contract"
            );
        }
        assert_eq!(
            intent.len(),
            29,
            "the intention document is every caller-authored material input and nothing else"
        );

        // A document that agrees on every field replays; changing any ONE of them diverges, and the
        // divergence names the field rather than reporting a generic mismatch.
        let mut document = Value::Object(
            intent
                .iter()
                .filter(|(field, _)| **field != "compatibility")
                .map(|(field, value)| ((*field).to_string(), value.clone()))
                .collect(),
        );
        document["revision_ordinal"] = json!(2);
        document["migration"] = json!({ "compatibility": "additive" });
        assert!(matches!(
            replay_intent_divergence(&document, &proposal),
            std::result::Result::Ok(None)
        ));
        for field in intent.keys() {
            let mut altered = document.clone();
            if *field == "compatibility" {
                altered["migration"]["compatibility"] = json!("breaking");
            } else {
                altered[*field] = json!("changed-under-the-same-key");
            }
            assert!(
                matches!(
                    replay_intent_divergence(&altered, &proposal),
                    std::result::Result::Ok(Some(changed)) if changed == *field
                ),
                "changing '{field}' under an admitted key must be a typed conflict, not a replay"
            );
        }
    }
}
