//! Canonical automation object family (M04.2).
//!
//! The legacy `AutomationWorkflow` executor remains mounted in `orchestration_routes`; it is an
//! execution precedent, not the canonical object model.  This plane keeps the four canonical
//! lifetimes separate:
//!
//! * WorkflowTemplate — immutable directed-work graph revision;
//! * AutomationSpec — immutable standing activation over one exact template revision;
//! * AutomationInstallationBinding — immutable successor-versioned local enablement/narrowing;
//! * AutomationRun — one admission that freezes the exact three revisions it resolved.
//!
//! Released definitions are never patched.  A caller creates a successor and an admitted run
//! retains its original tuple forever.  All hashes are daemon-derived from JCS; client-supplied
//! identity or hash fields are refused rather than trusted.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{iso_now, read_record_dir, DaemonState};

const TEMPLATE_DIR: &str = "workflow-template-revisions";
const SPEC_DIR: &str = "automation-spec-revisions";
const BINDING_DIR: &str = "automation-installation-revisions";
const RUN_DIR: &str = "canonical-automation-runs";

/// Serializes every canonical automation read-to-successor and read-to-run-admission critical
/// section. The durable records are immutable, but without this daemon-wide writer lock two
/// concurrent successors could both observe one head and fork the lineage, or a run could resolve
/// an enabled installation while its disabling successor commits. No `.await` executes while the
/// lock is held.
static AUTOMATION_CONTRACT_MUTATION_LOCK: Mutex<()> = Mutex::new(());

type Reply = (StatusCode, Json<Value>);

fn reply(status: StatusCode, value: Value) -> Reply {
    (status, Json(value))
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    reply(
        status,
        json!({ "ok": false, "error": { "code": code, "message": message.into() } }),
    )
}

fn identity_or_refusal(st: &DaemonState, headers: &HeaderMap) -> Result<String, Reply> {
    super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map(|identity| identity.principal_ref)
        .map_err(|error| {
            use super::substrate_store::RequestScopeRefusal;
            let status = match error {
                RequestScopeRefusal::AuthenticationRequired
                | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
                RequestScopeRefusal::TenantAuthorityRequired
                | RequestScopeRefusal::ResourceScopeRequired
                | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
                RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            };
            refuse(status, error.code(), error.message())
        })
}

fn object(body: &Value) -> Result<&Map<String, Value>, Reply> {
    body.as_object().ok_or_else(|| {
        refuse(
            StatusCode::BAD_REQUEST,
            "automation_contract_body_invalid",
            "the request body must be a JSON object",
        )
    })
}

fn ensure_allowed(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), Reply> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    let unknown = body
        .keys()
        .filter(|key| !allowed.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "automation_contract_unknown_field",
            format!("unknown or server-owned fields: {}", unknown.join(", ")),
        ))
    }
}

fn required_text(body: &Map<String, Value>, key: &str) -> Result<String, Reply> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "automation_contract_field_required",
                format!("{key} must be a non-empty string"),
            )
        })
}

fn optional_text(body: &Map<String, Value>, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn require_sha256(value: &str, field: &str) -> Result<(), Reply> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "automation_contract_hash_invalid",
            format!("{field} must be a lowercase sha256: digest"),
        ))
    }
}

fn hash(value: &Value) -> Result<String, Reply> {
    serde_jcs::to_vec(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            refuse(
                StatusCode::BAD_REQUEST,
                "automation_contract_not_canonicalizable",
                format!("request material cannot be canonicalized: {error}"),
            )
        })
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn tail(prefix: &str) -> String {
    format!("{prefix}_{:x}", nanos())
}

fn digest_tail(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

fn store(st: &DaemonState, family: &str, key: &str, record: &Value) -> Result<(), Reply> {
    super::durable_fs::persist_record_durable(&st.data_dir, family, key, record).map_err(|error| {
        let code = if error.visible() {
            "automation_contract_durability_unconfirmed"
        } else {
            "automation_contract_not_committed"
        };
        refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            code,
            format!(
                "canonical automation record was not durably admitted: {}",
                error.detail()
            ),
        )
    })
}

fn find_by(records: Vec<Value>, field: &str, expected: &str) -> Option<Value> {
    records
        .into_iter()
        .find(|record| record.get(field).and_then(Value::as_str) == Some(expected))
}

fn find_owned_by(
    records: Vec<Value>,
    field: &str,
    expected: &str,
    identity: &str,
) -> Option<Value> {
    records.into_iter().find(|record| {
        record.get(field).and_then(Value::as_str) == Some(expected)
            && record.get("owner_ref").and_then(Value::as_str) == Some(identity)
    })
}

fn workflow_template_slot(record: &Value) -> Result<String, String> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        "schema://ioi/foundations/workflow-template/v1",
        record,
    )
    .map_err(|error| format!("contract-invalid WorkflowTemplate: {error}"))?;
    let template_tail = record
        .get("workflow_template_id")
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix("workflow-template://"))
        .ok_or_else(|| "WorkflowTemplate identity is not canonical".to_string())?;
    let stored_hash = record
        .get("content_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "WorkflowTemplate content_hash is absent".to_string())?;
    let mut material = record.clone();
    let object = material
        .as_object_mut()
        .ok_or_else(|| "WorkflowTemplate is not an object".to_string())?;
    for field in [
        "revision_ref",
        "content_hash",
        "registry_lifecycle_ref",
        "registry_status",
    ] {
        object.remove(field);
    }
    let expected_hash = serde_jcs::to_vec(&material)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| format!("WorkflowTemplate is not canonicalizable: {error}"))?;
    if stored_hash != expected_hash {
        return Err(format!(
            "WorkflowTemplate content hash changed: stored {stored_hash}, recomputed {expected_hash}"
        ));
    }
    let expected_revision = format!("workflow-template://{template_tail}/revision/{expected_hash}");
    if record.get("revision_ref").and_then(Value::as_str) != Some(expected_revision.as_str()) {
        return Err("WorkflowTemplate revision_ref does not bind its exact content".to_string());
    }
    Ok(format!(
        "{template_tail}--{}.json",
        digest_tail(&expected_hash)
    ))
}

fn strict_workflow_templates(data_dir: &str) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, TEMPLATE_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "WorkflowTemplate registry cannot be pinned: {error}"
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("WorkflowTemplate registry cannot be enumerated: {error}"))?;
    names.sort();
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        if !name.ends_with(".json") {
            return Err(format!(
                "unexpected WorkflowTemplate registry occupant: {name}"
            ));
        }
        let bytes = super::durable_fs::read_slot_strict(&directory, &name)
            .map_err(|error| format!("WorkflowTemplate slot {name} is unreadable: {error}"))?
            .ok_or_else(|| format!("WorkflowTemplate slot {name} vanished during census"))?
            .1;
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("WorkflowTemplate slot {name} is malformed: {error}"))?;
        let expected_name = workflow_template_slot(&record)?;
        if name != expected_name {
            return Err(format!(
                "WorkflowTemplate slot {name} belongs at {expected_name}"
            ));
        }
        records.push(record);
    }
    Ok(records)
}

pub(crate) fn resolve_released_workflow_templates(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    revision_refs: &[String],
) -> Result<Vec<Value>, String> {
    if revision_refs.iter().collect::<BTreeSet<_>>().len() != revision_refs.len() {
        return Err("WorkflowTemplate revision selection contains a duplicate".to_string());
    }
    let records = strict_workflow_templates(data_dir)?;
    revision_refs
        .iter()
        .map(|revision_ref| {
            let mut matches = records.iter().filter(|record| {
                let owner = record
                    .get("owner_ref")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                (owner == identity.principal_ref.as_str() || identity.authorizes_tenant(owner))
                    && record.get("revision_ref").and_then(Value::as_str)
                        == Some(revision_ref.as_str())
            });
            let record = matches.next().ok_or_else(|| {
                format!("released visible WorkflowTemplate {revision_ref} is absent")
            })?;
            if matches.next().is_some() {
                return Err(format!(
                    "released visible WorkflowTemplate {revision_ref} is ambiguous"
                ));
            }
            if record.get("registry_status").and_then(Value::as_str) != Some("released") {
                return Err(format!("WorkflowTemplate {revision_ref} is not released"));
            }
            Ok(record.clone())
        })
        .collect()
}

fn run_is_owned_by(record: &Value, identity: &str) -> bool {
    record
        .pointer("/resolution_receipt/material/admitted_by_ref")
        .and_then(Value::as_str)
        == Some(identity)
}

fn chain_head(revisions: &[Value]) -> Option<&Value> {
    let named_predecessors = revisions
        .iter()
        .filter_map(|record| {
            record
                .get("predecessor_revision_ref")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let mut heads = revisions.iter().filter(|record| {
        record
            .get("revision_ref")
            .and_then(Value::as_str)
            .is_some_and(|revision_ref| !named_predecessors.contains(revision_ref))
    });
    let head = heads.next()?;
    if heads.next().is_some() {
        None
    } else {
        Some(head)
    }
}

fn registry_status(body: &Map<String, Value>) -> Result<&str, Reply> {
    let status = body
        .get("registry_status")
        .and_then(Value::as_str)
        .unwrap_or("released");
    if matches!(
        status,
        "draft" | "evaluable" | "released" | "deprecated" | "revoked"
    ) {
        Ok(status)
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "automation_registry_status_invalid",
            "registry_status must be draft, evaluable, released, deprecated, or revoked",
        ))
    }
}

fn string_array(body: &Map<String, Value>, key: &str) -> Result<Value, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(json!([]));
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "automation_contract_array_invalid",
            format!("{key} must be an array of unique non-empty strings"),
        ));
    };
    let mut seen = BTreeSet::new();
    for item in items {
        let Some(item) = item.as_str().filter(|item| !item.is_empty()) else {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "automation_contract_array_invalid",
                format!("{key} must contain only non-empty strings"),
            ));
        };
        if !seen.insert(item) {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "automation_contract_array_duplicate",
                format!("{key} contains a duplicate"),
            ));
        }
    }
    Ok(value.clone())
}

const TEMPLATE_FIELDS: &[&str] = &[
    "owner_ref",
    "display_name",
    "description",
    "version",
    "graph_ref",
    "graph_hash",
    "parameter_schema_ref",
    "input_contract_refs",
    "output_contract_refs",
    "step_contract_refs",
    "dependency_and_handoff_refs",
    "acceptance_and_review_contract_refs",
    "delivery_contract_ref",
    "selection_hint_refs",
    "runtime_tool_contract_requirement_refs",
    "required_primitive_capabilities",
    "authority_scope_requirement_refs",
    "resource_and_budget_requirement_refs",
    "receipt_policy_ref",
    "allowed_override_schema_ref",
    "provenance_refs",
    "evaluation_refs",
    "registry_status",
];

fn build_template(
    body: &Map<String, Value>,
    identity: &str,
    template_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, TEMPLATE_FIELDS)?;
    let owner_ref = required_text(body, "owner_ref")?;
    if owner_ref != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "automation_contract_owner_mismatch",
            "owner_ref must equal the authenticated principal for this admission lane",
        ));
    }
    let graph_hash = required_text(body, "graph_hash")?;
    require_sha256(&graph_hash, "graph_hash")?;
    let workflow_template_id = format!("workflow-template://{template_tail}");
    let predecessor_revision_ref = predecessor
        .and_then(|record| record.get("revision_ref"))
        .cloned()
        .unwrap_or(Value::Null);
    let selection_hint_refs = body
        .get("selection_hint_refs")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !selection_hint_refs.is_object() {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "workflow_template_selection_hints_invalid",
            "selection_hint_refs must be an object of non-authoritative hints",
        ));
    }
    let mut material = json!({
        "schema_version": "ioi.workflow-template.v1",
        "workflow_template_id": workflow_template_id,
        "version": optional_text(body, "version").unwrap_or_else(|| "1.0.0".into()),
        "predecessor_revision_ref": predecessor_revision_ref,
        "owner_ref": owner_ref,
        "display_name": required_text(body, "display_name")?,
        "description": optional_text(body, "description").unwrap_or_default(),
        "graph_ref": required_text(body, "graph_ref")?,
        "graph_hash": graph_hash,
        "parameter_schema_ref": body.get("parameter_schema_ref").cloned().unwrap_or(Value::Null),
        "input_contract_refs": string_array(body, "input_contract_refs")?,
        "output_contract_refs": string_array(body, "output_contract_refs")?,
        "step_contract_refs": string_array(body, "step_contract_refs")?,
        "dependency_and_handoff_refs": string_array(body, "dependency_and_handoff_refs")?,
        "acceptance_and_review_contract_refs": string_array(body, "acceptance_and_review_contract_refs")?,
        "delivery_contract_ref": body.get("delivery_contract_ref").cloned().unwrap_or(Value::Null),
        "selection_hint_refs": selection_hint_refs,
        "runtime_tool_contract_requirement_refs": string_array(body, "runtime_tool_contract_requirement_refs")?,
        "required_primitive_capabilities": string_array(body, "required_primitive_capabilities")?,
        "authority_scope_requirement_refs": string_array(body, "authority_scope_requirement_refs")?,
        "resource_and_budget_requirement_refs": string_array(body, "resource_and_budget_requirement_refs")?,
        "receipt_policy_ref": body.get("receipt_policy_ref").cloned().unwrap_or(Value::Null),
        "allowed_override_schema_ref": body.get("allowed_override_schema_ref").cloned().unwrap_or(Value::Null),
        "provenance_refs": string_array(body, "provenance_refs")?,
        "evaluation_refs": string_array(body, "evaluation_refs")?,
    });
    let content_hash = hash(&material)?;
    material["content_hash"] = json!(content_hash);
    material["revision_ref"] = json!(format!(
        "workflow-template://{template_tail}/revision/{}",
        material["content_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(registry_status(body)?);
    Ok(material)
}

pub(crate) async fn create_workflow_template(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    create_workflow_template_as(&st, &identity, &body)
}

/// The same admission for a principal the caller has ALREADY resolved — the route above after its
/// identity seam, or the Run now bridge for the daemon's own dispatch (R-240).
pub(crate) fn create_workflow_template_as(st: &DaemonState, identity: &str, body: &Value) -> Reply {
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(body) => body,
        Err(reply) => return reply,
    };
    let template_tail = tail("wft");
    let record = match build_template(body, &identity, &template_tail, None) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let key = format!(
        "{template_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, TEMPLATE_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "workflow_template": record }),
    )
}

pub(crate) async fn create_workflow_template_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(template_tail): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let template_id = format!("workflow-template://{template_tail}");
    let revisions = read_record_dir(&st.data_dir, TEMPLATE_DIR)
        .into_iter()
        .filter(|record| {
            record["workflow_template_id"] == template_id && record["owner_ref"] == identity
        })
        .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(&revisions) else {
        return if revisions.is_empty() {
            refuse(
                StatusCode::NOT_FOUND,
                "workflow_template_not_found",
                "no template revision exists for that id",
            )
        } else {
            refuse(
                StatusCode::CONFLICT,
                "workflow_template_lineage_ambiguous",
                "the template has more than one live lineage head; successor admission refuses guesswork",
            )
        };
    };
    if predecessor["registry_status"] == "revoked" {
        return refuse(
            StatusCode::CONFLICT,
            "workflow_template_revoked",
            "a revoked template cannot produce a successor",
        );
    }
    let body = match object(&body) {
        Ok(body) => body,
        Err(reply) => return reply,
    };
    let record = match build_template(body, &identity, &template_tail, Some(predecessor)) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let key = format!(
        "{template_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, TEMPLATE_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "workflow_template": record }),
    )
}

pub(crate) async fn list_workflow_templates(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, TEMPLATE_DIR)
        .into_iter()
        .filter(|record| record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "workflow_templates": records }),
    )
}

const SPEC_FIELDS: &[&str] = &[
    "owner_ref",
    "display_name",
    "description",
    "version",
    "workflow_template_revision_ref",
    "workflow_template_content_hash",
    "activation_kind",
    "activation_parameter_schema_ref",
    "trigger_contract_ref",
    "schedule_contract_ref",
    "monitor_contract_ref",
    "service_contract_ref",
    "queue_contract_ref",
    "review_contract_refs",
    "delivery_contract_ref",
    "concurrency_policy_ref",
    "idempotency_policy_ref",
    "authority_requirement_refs",
    "allowed_activation_override_schema_ref",
    "receipt_policy_ref",
    "registry_status",
];

fn build_spec(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
    spec_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, SPEC_FIELDS)?;
    let owner_ref = required_text(body, "owner_ref")?;
    if owner_ref != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "automation_contract_owner_mismatch",
            "owner_ref must equal the authenticated principal",
        ));
    }
    let template_ref = required_text(body, "workflow_template_revision_ref")?;
    let template_hash = required_text(body, "workflow_template_content_hash")?;
    require_sha256(&template_hash, "workflow_template_content_hash")?;
    let Some(template) = find_owned_by(
        read_record_dir(&st.data_dir, TEMPLATE_DIR),
        "revision_ref",
        &template_ref,
        identity,
    ) else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "workflow_template_revision_not_found",
            "the exact template revision does not exist",
        ));
    };
    if template["content_hash"] != template_hash {
        return Err(refuse(
            StatusCode::CONFLICT,
            "workflow_template_hash_mismatch",
            "the template ref and content hash do not identify the same immutable revision",
        ));
    }
    if template["registry_status"] != "released" {
        return Err(refuse(
            StatusCode::CONFLICT,
            "workflow_template_not_released",
            "only a released template revision may back a standing automation",
        ));
    }
    let activation_kind = required_text(body, "activation_kind")?;
    if !matches!(
        activation_kind.as_str(),
        "manual" | "schedule" | "webhook" | "event" | "monitor" | "service" | "queue"
    ) {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "automation_activation_kind_invalid",
            "activation_kind is not canonical",
        ));
    }
    let mut material = json!({
        "schema_version": "ioi.hypervisor.automation-spec.v1",
        "automation_id": format!("automation://{spec_tail}"),
        "version": optional_text(body, "version").unwrap_or_else(|| "1.0.0".into()),
        "predecessor_revision_ref": predecessor.and_then(|record| record.get("revision_ref")).cloned().unwrap_or(Value::Null),
        "owner_ref": owner_ref,
        "display_name": required_text(body, "display_name")?,
        "description": optional_text(body, "description").unwrap_or_default(),
        "workflow_template_revision_ref": template_ref,
        "workflow_template_content_hash": template_hash,
        "activation_kind": activation_kind,
        "activation_parameter_schema_ref": body.get("activation_parameter_schema_ref").cloned().unwrap_or(Value::Null),
        "trigger_contract_ref": body.get("trigger_contract_ref").cloned().unwrap_or(Value::Null),
        "schedule_contract_ref": body.get("schedule_contract_ref").cloned().unwrap_or(Value::Null),
        "monitor_contract_ref": body.get("monitor_contract_ref").cloned().unwrap_or(Value::Null),
        "service_contract_ref": body.get("service_contract_ref").cloned().unwrap_or(Value::Null),
        "queue_contract_ref": body.get("queue_contract_ref").cloned().unwrap_or(Value::Null),
        "review_contract_refs": string_array(body, "review_contract_refs")?,
        "delivery_contract_ref": body.get("delivery_contract_ref").cloned().unwrap_or(Value::Null),
        "concurrency_policy_ref": body.get("concurrency_policy_ref").cloned().unwrap_or(Value::Null),
        "idempotency_policy_ref": body.get("idempotency_policy_ref").cloned().unwrap_or(Value::Null),
        "authority_requirement_refs": string_array(body, "authority_requirement_refs")?,
        "allowed_activation_override_schema_ref": body.get("allowed_activation_override_schema_ref").cloned().unwrap_or(Value::Null),
        "receipt_policy_ref": body.get("receipt_policy_ref").cloned().unwrap_or(Value::Null),
    });
    let content_hash = hash(&material)?;
    material["content_hash"] = json!(content_hash);
    material["revision_ref"] = json!(format!(
        "automation://{spec_tail}/revision/{}",
        material["content_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(registry_status(body)?);
    Ok(material)
}

pub(crate) async fn create_automation_spec(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    create_automation_spec_as(&st, &identity, &body)
}

/// The same admission for a principal the caller has ALREADY resolved — the route above after its
/// identity seam, or the Run now bridge for the daemon's own dispatch (R-240).
pub(crate) fn create_automation_spec_as(st: &DaemonState, identity: &str, body: &Value) -> Reply {
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let spec_tail = tail("autospec");
    let record = match build_spec(&st, body, &identity, &spec_tail, None) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{spec_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, SPEC_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "automation_spec": record }),
    )
}

pub(crate) async fn create_automation_spec_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(spec_tail): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let automation_id = format!("automation://{spec_tail}");
    let revisions = read_record_dir(&st.data_dir, SPEC_DIR)
        .into_iter()
        .filter(|record| {
            record["automation_id"] == automation_id && record["owner_ref"] == identity
        })
        .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(&revisions) else {
        return if revisions.is_empty() {
            refuse(
                StatusCode::NOT_FOUND,
                "automation_spec_not_found",
                "no spec revision exists for that id",
            )
        } else {
            refuse(
                StatusCode::CONFLICT,
                "automation_spec_lineage_ambiguous",
                "the spec has more than one live lineage head; successor admission refuses guesswork",
            )
        };
    };
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let record = match build_spec(&st, body, &identity, &spec_tail, Some(predecessor)) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{spec_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, SPEC_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "automation_spec": record }),
    )
}

pub(crate) async fn list_automation_specs(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, SPEC_DIR)
        .into_iter()
        .filter(|record| record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "automation_specs": records }),
    )
}

const BINDING_FIELDS: &[&str] = &[
    "owner_ref",
    "scope_ref",
    "automation_spec_revision_ref",
    "automation_spec_content_hash",
    "enabled",
    "narrowed_activation_kinds",
    "narrowed_authority_requirement_refs",
    "parameter_constraint_ref",
    "activation_override_constraint_ref",
    "admission_receipt_ref",
    "registry_status",
];

fn build_binding(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
    binding_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, BINDING_FIELDS)?;
    let owner_ref = required_text(body, "owner_ref")?;
    if owner_ref != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "automation_contract_owner_mismatch",
            "owner_ref must equal the authenticated principal",
        ));
    }
    let spec_ref = required_text(body, "automation_spec_revision_ref")?;
    let spec_hash = required_text(body, "automation_spec_content_hash")?;
    require_sha256(&spec_hash, "automation_spec_content_hash")?;
    let Some(spec) = find_owned_by(
        read_record_dir(&st.data_dir, SPEC_DIR),
        "revision_ref",
        &spec_ref,
        identity,
    ) else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "automation_spec_revision_not_found",
            "the exact AutomationSpec revision does not exist",
        ));
    };
    if spec["content_hash"] != spec_hash {
        return Err(refuse(
            StatusCode::CONFLICT,
            "automation_spec_hash_mismatch",
            "the spec ref and hash do not identify the same revision",
        ));
    }
    if spec["registry_status"] != "released" {
        return Err(refuse(
            StatusCode::CONFLICT,
            "automation_spec_not_released",
            "only a released AutomationSpec may be installed",
        ));
    }
    let enabled = body
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "automation_installation_enabled_required",
                "enabled must be a boolean",
            )
        })?;
    let mut material = json!({
        "schema_version": "ioi.hypervisor.automation-installation-binding.v1",
        "binding_id": format!("install://automation/{binding_tail}"),
        "predecessor_revision_ref": predecessor.and_then(|record| record.get("revision_ref")).cloned().unwrap_or(Value::Null),
        "owner_ref": owner_ref,
        "scope_ref": required_text(body, "scope_ref")?,
        "automation_spec_revision_ref": spec_ref,
        "automation_spec_content_hash": spec_hash,
        "enabled": enabled,
        "narrowed_activation_kinds": string_array(body, "narrowed_activation_kinds")?,
        "narrowed_authority_requirement_refs": string_array(body, "narrowed_authority_requirement_refs")?,
        "parameter_constraint_ref": body.get("parameter_constraint_ref").cloned().unwrap_or(Value::Null),
        "activation_override_constraint_ref": body.get("activation_override_constraint_ref").cloned().unwrap_or(Value::Null),
        "admission_receipt_ref": required_text(body, "admission_receipt_ref")?,
    });
    let binding_hash = hash(&material)?;
    material["binding_hash"] = json!(binding_hash);
    material["revision_ref"] = json!(format!(
        "install://automation/{binding_tail}/revision/{}",
        material["binding_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(registry_status(body)?);
    Ok(material)
}

pub(crate) async fn create_automation_installation(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    create_automation_installation_as(&st, &identity, &body)
}

/// The same admission for a principal the caller has ALREADY resolved — the route above after its
/// identity seam, or the Run now bridge for the daemon's own dispatch (R-240).
pub(crate) fn create_automation_installation_as(
    st: &DaemonState,
    identity: &str,
    body: &Value,
) -> Reply {
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let binding_tail = tail("autoinstall");
    let record = match build_binding(&st, body, &identity, &binding_tail, None) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{binding_tail}--{}",
        digest_tail(record["binding_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, BINDING_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "automation_installation_binding": record }),
    )
}

pub(crate) async fn create_automation_installation_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(binding_tail): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let binding_id = format!("install://automation/{binding_tail}");
    let revisions = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|record| record["binding_id"] == binding_id && record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(&revisions) else {
        return if revisions.is_empty() {
            refuse(
                StatusCode::NOT_FOUND,
                "automation_installation_not_found",
                "no installation revision exists for that id",
            )
        } else {
            refuse(
                StatusCode::CONFLICT,
                "automation_installation_lineage_ambiguous",
                "the installation has more than one live lineage head; successor admission refuses guesswork",
            )
        };
    };
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let record = match build_binding(&st, body, &identity, &binding_tail, Some(predecessor)) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{binding_tail}--{}",
        digest_tail(record["binding_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, BINDING_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "automation_installation_binding": record }),
    )
}

pub(crate) async fn list_automation_installations(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|record| record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "automation_installation_bindings": records }),
    )
}

const RUN_FIELDS: &[&str] = &[
    "automation_spec_revision_ref",
    "automation_spec_content_hash",
    "automation_installation_binding_revision_ref",
    "automation_installation_binding_hash",
    "activation_kind",
    "activation_event_ref",
    "admitted_parameter_set_ref",
    "admitted_parameter_set_hash",
    "admitted_activation_override_set_ref",
    "admitted_activation_override_set_hash",
];

pub(crate) async fn admit_automation_run(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    admit_automation_run_as(&st, &identity, &body)
}

/// The same admission for a principal the caller has ALREADY resolved — the route above after its
/// identity seam, or the Run now bridge for the daemon's own dispatch (R-240).
pub(crate) fn admit_automation_run_as(st: &DaemonState, identity: &str, body: &Value) -> Reply {
    let _mutation = AUTOMATION_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    if let Err(reply) = ensure_allowed(body, RUN_FIELDS) {
        return reply;
    }
    let spec_ref = match required_text(body, "automation_spec_revision_ref") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let spec_hash = match required_text(body, "automation_spec_content_hash") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let binding_ref = match required_text(body, "automation_installation_binding_revision_ref") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let binding_hash = match required_text(body, "automation_installation_binding_hash") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let activation_kind = match required_text(body, "activation_kind") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let Some(spec) = find_owned_by(
        read_record_dir(&st.data_dir, SPEC_DIR),
        "revision_ref",
        &spec_ref,
        &identity,
    ) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "automation_spec_revision_not_found",
            "the exact AutomationSpec revision does not exist",
        );
    };
    let Some(binding) = find_owned_by(
        read_record_dir(&st.data_dir, BINDING_DIR),
        "revision_ref",
        &binding_ref,
        &identity,
    ) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "automation_installation_revision_not_found",
            "the exact installation revision does not exist",
        );
    };
    if spec["content_hash"] != spec_hash || binding["binding_hash"] != binding_hash {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_resolution_hash_mismatch",
            "a requested revision/hash pair does not resolve exactly",
        );
    }
    if binding["automation_spec_revision_ref"] != spec_ref
        || binding["automation_spec_content_hash"] != spec_hash
    {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_binding_spec_mismatch",
            "the installation does not bind the requested AutomationSpec revision",
        );
    }
    if binding["owner_ref"] != identity {
        return refuse(
            StatusCode::FORBIDDEN,
            "automation_run_owner_mismatch",
            "the authenticated principal does not own the requested installation binding",
        );
    }
    let binding_id = binding["binding_id"].as_str().unwrap_or("");
    let binding_lineage = read_record_dir(&st.data_dir, BINDING_DIR)
        .into_iter()
        .filter(|record| record["binding_id"].as_str() == Some(binding_id))
        .collect::<Vec<_>>();
    if chain_head(&binding_lineage).and_then(|head| head["revision_ref"].as_str())
        != Some(binding_ref.as_str())
    {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_installation_superseded",
            "only the single current installation-binding head may admit a run",
        );
    }
    if binding["enabled"] != true
        || binding["registry_status"] != "released"
        || spec["registry_status"] != "released"
    {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_installation_ineligible",
            "the exact spec and installation must be released and enabled at admission",
        );
    }
    if spec["activation_kind"] != activation_kind {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_activation_kind_mismatch",
            "activation_kind must equal the standing spec",
        );
    }
    let narrowed = binding["narrowed_activation_kinds"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !narrowed.is_empty()
        && !narrowed
            .iter()
            .any(|value| value.as_str() == Some(activation_kind.as_str()))
    {
        return refuse(
            StatusCode::FORBIDDEN,
            "automation_run_activation_narrowed",
            "the installation binding narrows away this activation kind",
        );
    }
    for pair in [
        ("admitted_parameter_set_ref", "admitted_parameter_set_hash"),
        (
            "admitted_activation_override_set_ref",
            "admitted_activation_override_set_hash",
        ),
    ] {
        if body.get(pair.0).map(Value::is_null).unwrap_or(true)
            != body.get(pair.1).map(Value::is_null).unwrap_or(true)
        {
            return refuse(
                StatusCode::BAD_REQUEST,
                "automation_run_ref_hash_pair_required",
                format!(
                    "{} and {} must be supplied together or both null",
                    pair.0, pair.1
                ),
            );
        }
        if let Some(hash_value) = optional_text(body, pair.1) {
            if let Err(reply) = require_sha256(&hash_value, pair.1) {
                return reply;
            }
        }
    }
    let template_ref = spec["workflow_template_revision_ref"].clone();
    let template_hash = spec["workflow_template_content_hash"].clone();
    let Some(template) = find_owned_by(
        read_record_dir(&st.data_dir, TEMPLATE_DIR),
        "revision_ref",
        template_ref.as_str().unwrap_or(""),
        &identity,
    ) else {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_template_revision_missing",
            "the spec's exact template revision is no longer resolvable",
        );
    };
    if template["content_hash"] != template_hash || template["registry_status"] != "released" {
        return refuse(
            StatusCode::CONFLICT,
            "automation_run_template_ineligible",
            "the exact template revision/hash is mismatched or not released",
        );
    }
    let run_tail = tail("autorun");
    let run_ref = format!("automation-run://{run_tail}");
    let admitted_at = iso_now();
    let resolution_material = json!({
        "domain": "ioi.automation-run-resolution-receipt-jcs-sha256.v1",
        "automation_run_ref": run_ref,
        "automation_spec_revision_ref": spec_ref,
        "automation_spec_content_hash": spec_hash,
        "automation_installation_binding_revision_ref": binding_ref,
        "automation_installation_binding_hash": binding_hash,
        "automation_installation_admission_receipt_ref": binding["admission_receipt_ref"],
        "workflow_template_revision_ref": template_ref,
        "workflow_template_content_hash": template_hash,
        "activation_kind": activation_kind,
        "activation_event_ref": body.get("activation_event_ref").cloned().unwrap_or(Value::Null),
        "admitted_parameter_set_ref": body.get("admitted_parameter_set_ref").cloned().unwrap_or(Value::Null),
        "admitted_parameter_set_hash": body.get("admitted_parameter_set_hash").cloned().unwrap_or(Value::Null),
        "admitted_activation_override_set_ref": body.get("admitted_activation_override_set_ref").cloned().unwrap_or(Value::Null),
        "admitted_activation_override_set_hash": body.get("admitted_activation_override_set_hash").cloned().unwrap_or(Value::Null),
        "admitted_by_ref": identity,
        "admitted_at": admitted_at,
    });
    let receipt_root = match hash(&resolution_material) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let resolution_receipt = json!({
        "schema_version": "ioi.automation-run-resolution-receipt.v1",
        "receipt_id": format!("receipt://automation-run-resolution/{}", digest_tail(&receipt_root)),
        "receipt_type": "automation_run_resolution",
        "receipt_root": receipt_root,
        "assurance_stage": "attested",
        "material": resolution_material,
    });
    let record = json!({
        "schema_version": "ioi.hypervisor.automation-run.v1",
        "automation_run_ref": resolution_receipt["material"]["automation_run_ref"],
        "automation_spec_revision_ref": resolution_receipt["material"]["automation_spec_revision_ref"],
        "automation_spec_content_hash": resolution_receipt["material"]["automation_spec_content_hash"],
        "automation_installation_binding_revision_ref": resolution_receipt["material"]["automation_installation_binding_revision_ref"],
        "automation_installation_binding_hash": resolution_receipt["material"]["automation_installation_binding_hash"],
        "workflow_template_revision_ref": resolution_receipt["material"]["workflow_template_revision_ref"],
        "workflow_template_content_hash": resolution_receipt["material"]["workflow_template_content_hash"],
        "activation_kind": resolution_receipt["material"]["activation_kind"],
        "activation_event_ref": resolution_receipt["material"]["activation_event_ref"],
        "admitted_parameter_set_ref": resolution_receipt["material"]["admitted_parameter_set_ref"],
        "admitted_parameter_set_hash": resolution_receipt["material"]["admitted_parameter_set_hash"],
        "admitted_activation_override_set_ref": resolution_receipt["material"]["admitted_activation_override_set_ref"],
        "admitted_activation_override_set_hash": resolution_receipt["material"]["admitted_activation_override_set_hash"],
        "resolution_receipt": resolution_receipt,
        "status": "queued",
        "admitted_at": admitted_at,
        "session_refs": [],
        "work_run_refs": [],
        "work_result_refs": [],
        "authority_lease_refs": [],
        "artifact_refs": [],
        "receipt_refs": [resolution_receipt["receipt_id"].clone()],
        "agentgres_operation_refs": [],
    });
    if let Err(reply) = store(&st, RUN_DIR, &run_tail, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "automation_run": record }),
    )
}

/// THE AUTOMATION PLANE'S PUBLISHED READER FOR THE WORK PROJECTION (M08.9): the same identity
/// resolution and the same ownership test the list route applies, BEFORE anything downstream
/// counts or searches. Returns the admitted run records unshaped.
pub(crate) fn automation_runs_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = identity_or_refusal(st, headers)?;
    Ok(read_record_dir(&st.data_dir, RUN_DIR)
        .into_iter()
        .filter(|record| run_is_owned_by(record, &identity))
        .collect())
}

pub(crate) async fn list_automation_runs(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, RUN_DIR)
        .into_iter()
        .filter(|record| run_is_owned_by(record, &identity))
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "automation_runs": records }),
    )
}

pub(crate) async fn get_automation_run(
    State(st): State<Arc<DaemonState>>,
    AxumPath(run_tail): AxumPath<String>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let run_ref = format!("automation-run://{run_tail}");
    match find_by(
        read_record_dir(&st.data_dir, RUN_DIR),
        "automation_run_ref",
        &run_ref,
    )
    .filter(|record| run_is_owned_by(record, &identity))
    {
        Some(record) => reply(
            StatusCode::OK,
            json!({ "ok": true, "automation_run": record }),
        ),
        None => refuse(
            StatusCode::NOT_FOUND,
            "automation_run_not_found",
            "no canonical AutomationRun has that id",
        ),
    }
}

// ---- Run now → a canonical AutomationRun (R-240) -----------------------------------------------
//
// canon-to-code-delta row 76: "connect an admitted AutomationRun to the shared lifecycle/execution
// plane WITHOUT REWRITING ITS FROZEN TUPLE". The product's automations are the legacy plane and its
// "Run now" really executes (orchestration_routes::handle_automation_start); nothing ever admitted a
// canonical run for it, so no product run reached Work, the inbox or its receipts. The bridge does
// not add a runtime: the legacy executor stays THE executor, and each execution it performs for a
// signed-in principal is (1) admitted as a canonical AutomationRun over that principal's manual chain
// for the automation's exact steps and (2) given a lifecycle in the shared work-lifecycle plane —
// queued → running → succeeded | failed — keyed by the run ref, with the execution as evidence. The
// frozen run record is never rewritten; readers derive its current status from the plane.

/// The canonical chain a principal's "Run now" of one legacy automation resolves to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManualChain {
    pub(crate) spec_ref: String,
    pub(crate) spec_hash: String,
    pub(crate) binding_ref: String,
    pub(crate) binding_hash: String,
}

/// A legacy execution's canonical run, and the head its next lifecycle record must name.
#[derive(Debug, Clone)]
pub(crate) struct BridgedRun {
    pub(crate) run_ref: String,
    pub(crate) principal_ref: String,
    head: String,
    ordinal: u64,
}

/// The graph a legacy automation's steps ARE: a stable ref per automation and the JCS digest of its
/// exact steps, so an edit to the steps resolves to a new template rather than re-meaning an old one.
pub(crate) fn legacy_automation_graph(
    automation_id: &str,
    steps: &Value,
) -> Result<(String, String), String> {
    let digest = hash(steps).map_err(|(_, Json(reply))| reply.to_string())?;
    Ok((
        format!("workflow://graph/automation/{automation_id}"),
        digest,
    ))
}

/// Pure reads: the principal's template for exactly this graph, its spec for this activation kind
/// (a spec is ONE standing activation), and that spec's enabled HEAD binding (none of its
/// successors). `None` when any link is missing.
pub(crate) fn find_chain(
    data_dir: &str,
    principal_ref: &str,
    graph_ref: &str,
    graph_hash: &str,
    activation_kind: &str,
) -> Option<ManualChain> {
    let owned =
        |record: &Value| record.get("owner_ref").and_then(Value::as_str) == Some(principal_ref);
    let text = |record: &Value, key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let template = read_record_dir(data_dir, TEMPLATE_DIR)
        .into_iter()
        .find(|t| {
            owned(t) && text(t, "graph_ref") == graph_ref && text(t, "graph_hash") == graph_hash
        })?;
    let template_ref = text(&template, "revision_ref");
    let spec = read_record_dir(data_dir, SPEC_DIR).into_iter().find(|s| {
        owned(s)
            && text(s, "workflow_template_revision_ref") == template_ref
            && text(s, "activation_kind") == activation_kind
    })?;
    let spec_ref = text(&spec, "revision_ref");
    let bindings = read_record_dir(data_dir, BINDING_DIR);
    let is_head = |b: &Value| {
        let revision = text(b, "revision_ref");
        !bindings.iter().any(|other| {
            other
                .get("predecessor_revision_ref")
                .and_then(Value::as_str)
                == Some(revision.as_str())
        })
    };
    let binding = bindings.iter().find(|b| {
        owned(b)
            && text(b, "automation_spec_revision_ref") == spec_ref
            && b.get("enabled") == Some(&json!(true))
            && is_head(b)
    })?;
    Some(ManualChain {
        spec_ref,
        spec_hash: text(&spec, "content_hash"),
        binding_ref: text(binding, "revision_ref"),
        binding_hash: text(binding, "binding_hash"),
    })
}

fn bridge_step(label: &str, (status, Json(reply)): Reply) -> Result<Value, (String, String)> {
    if status.is_success() && reply.get("ok") == Some(&json!(true)) {
        return Ok(reply);
    }
    let code = reply
        .pointer("/error/code")
        .or_else(|| reply.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("automation_bridge_refused");
    let message = reply
        .pointer("/error/message")
        .or_else(|| reply.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("");
    Err((code.to_string(), format!("{label}: {message}")))
}

/// Mint the principal's chain for this automation's exact steps and one activation kind: a released
/// template, a spec for that activation over it, the INSTALLATION DECISION admitted as an owner-scoped
/// write (its Agentgres receipt is the binding's admission receipt — a real record of the principal
/// installing their own automation's activation, never a literal), and an enabled binding carrying it.
fn mint_chain(
    st: &DaemonState,
    identity: &super::substrate_store::RequestIdentity,
    owner_tenant: &str,
    display_name: &str,
    graph_ref: &str,
    graph_hash: &str,
    activation_kind: &str,
) -> Result<ManualChain, (String, String)> {
    let principal = identity.principal_ref.as_str();
    let template = bridge_step(
        "workflow template",
        create_workflow_template_as(
            st,
            principal,
            &json!({
                "owner_ref": principal, "display_name": display_name, "graph_ref": graph_ref, "graph_hash": graph_hash,
                "required_primitive_capabilities": ["prim:process.execute"], "registry_status": "released",
            }),
        ),
    )?;
    let template = &template["workflow_template"];
    let label = if activation_kind == "manual" {
        "run now"
    } else {
        activation_kind
    };
    let spec = bridge_step(
        "automation spec",
        create_automation_spec_as(
            st,
            principal,
            &json!({
                "owner_ref": principal, "display_name": format!("{display_name} · {label}"),
                "workflow_template_revision_ref": template["revision_ref"], "workflow_template_content_hash": template["content_hash"],
                "activation_kind": activation_kind, "concurrency_policy_ref": "policy://automation/concurrency/serial",
                "idempotency_policy_ref": "policy://automation/idempotency/exact", "authority_requirement_refs": ["scope:process.execute"],
                "receipt_policy_ref": "policy://receipts/automation", "registry_status": "released",
            }),
        ),
    )?;
    let spec = &spec["automation_spec"];
    let spec_ref = spec["revision_ref"].as_str().unwrap_or("").to_string();
    let decision = super::mutation_event_foundation::admit_owner_scoped_write(
        &st.data_dir,
        &super::mutation_event_foundation::WriteCaller {
            identity: identity.clone(),
            owner_ref: owner_tenant.to_string(),
            idempotency_key: format!("automation-installation-decision:{principal}:{spec_ref}"),
        },
        "hypervisor-automation-installations",
        "automation-installation-decision",
        &spec_ref,
        "automation_installation.self_admit",
        None,
        &json!({
            "installed_by_principal_ref": principal, "scope_ref": principal,
            "automation_spec_revision_ref": spec_ref, "automation_spec_content_hash": spec["content_hash"],
            "narrowed_activation_kinds": [activation_kind], "narrowed_authority_requirement_refs": ["scope:process.execute"],
        }),
    )
    .map_err(|(_, Json(reply))| {
        let code = reply.get("code").or_else(|| reply.pointer("/error/code")).and_then(Value::as_str).unwrap_or("automation_installation_decision_refused");
        (code.to_string(), "installation decision was not admitted".to_string())
    })?;
    let binding = bridge_step(
        "installation binding",
        create_automation_installation_as(
            st,
            principal,
            &json!({
                "owner_ref": principal, "scope_ref": principal,
                "automation_spec_revision_ref": spec_ref, "automation_spec_content_hash": spec["content_hash"],
                "enabled": true, "narrowed_activation_kinds": [activation_kind], "narrowed_authority_requirement_refs": ["scope:process.execute"],
                "admission_receipt_ref": decision.receipt_ref, "registry_status": "released",
            }),
        ),
    )?;
    let binding = &binding["automation_installation_binding"];
    Ok(ManualChain {
        spec_ref,
        spec_hash: spec["content_hash"].as_str().unwrap_or("").to_string(),
        binding_ref: binding["revision_ref"].as_str().unwrap_or("").to_string(),
        binding_hash: binding["binding_hash"].as_str().unwrap_or("").to_string(),
    })
}

fn lifecycle_record(
    run: &BridgedRun,
    from: Option<&str>,
    to: &str,
    key: &str,
    evidence: &[String],
    at_ms: i64,
) -> Value {
    let tail = run.run_ref.trim_start_matches("automation-run://");
    json!({
        "schema_version": "ioi.work-lifecycle-record.v1",
        "record_id": format!("work-lifecycle://{tail}/{}", run.ordinal),
        "record_hash": "",
        "record_type": "phase_transition",
        "object_kind": "automation_run",
        "object_ref": run.run_ref,
        "owner_ref": run.principal_ref,
        "expected_head": if run.head.is_empty() { Value::Null } else { json!(run.head) },
        "resulting_head": "",
        "idempotency_key": key,
        "authority_class": "automation_controller",
        "authority_ref": "actor://daemon/automation-controller",
        "authority_grant_refs": [],
        "decision_receipt_ref": Value::Null,
        "evidence_refs": evidence,
        "receipt_refs": [],
        "phase_transition": { "from_phase": from, "to_phase": to },
        "child_reference": Value::Null,
        "occurred_at_ms": at_ms,
    })
}

fn append_phase(
    data_dir: &str,
    run: &mut BridgedRun,
    from: Option<&str>,
    to: &str,
    key: &str,
    evidence: &[String],
) -> Result<(), String> {
    let at_ms = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0);
    let record = lifecycle_record(run, from, to, key, evidence, at_ms);
    let report = super::work_lifecycle_routes::WorkLifecycleStore::new(data_dir.to_string())
        .append_gated(
            &record,
            &super::work_lifecycle_routes::ObjectKindContinuityGate,
        )
        .map_err(|error| format!("{}: {error:?}", error.code()))?;
    run.head = report.resulting_head;
    run.ordinal += 1;
    Ok(())
}

/// The daemon's OWN dispatch of an automation (a scheduler tick or an accepted webhook): it crosses
/// with the per-boot internal token, not a session, and runs as the automation's stored executor.
pub(crate) struct InternalDispatch {
    pub(crate) principal_ref: String,
    pub(crate) owner_ref: String,
    pub(crate) activation_kind: String,
}

/// One legacy execution, admitted canonically BEFORE it executes: the chain for the automation's exact
/// steps and this activation (found, else minted), the run, and its lifecycle to `running`. A person's
/// Run now resolves its identity from the session (activation `manual`); the daemon's own dispatch
/// resolves the executor principal through the workload-broker seam the environment routes use
/// (activation `schedule` / `webhook`). A refusal is returned typed and the legacy execution proceeds
/// without a canonical run — it is named on the execution record, never hidden.
pub(crate) async fn bridge_run_now(
    st: &Arc<DaemonState>,
    headers: &HeaderMap,
    automation_id: &str,
    automation: &Value,
    execution_id: &str,
    dispatch: Option<&InternalDispatch>,
) -> Result<BridgedRun, (String, String)> {
    let (identity, owner_tenant, activation_kind) = match dispatch {
        None => {
            let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
                .map_err(|error| (error.code().to_string(), error.message()))?;
            let owner = identity
                .tenant_refs
                .iter()
                .find(|t| t.as_str() == "org://local")
                .or_else(|| identity.tenant_refs.iter().find(|t| t.starts_with("org://")))
                .or_else(|| identity.tenant_refs.iter().find(|t| t.starts_with("project://")))
                .cloned()
                .ok_or_else(|| ("automation_bridge_owner_tenant_required".to_string(), "the principal belongs to no organization, so the installation decision would have no owner".to_string()))?;
            (identity, owner, "manual".to_string())
        }
        Some(dispatch) => {
            if !matches!(dispatch.activation_kind.as_str(), "schedule" | "webhook") {
                return Err(("automation_bridge_activation_unknown".to_string(), format!("an internal dispatch names activation '{}'; only schedule and webhook dispatches exist", dispatch.activation_kind)));
            }
            let identity = super::substrate_store::resolve_workload_broker_identity(
                &st.data_dir,
                &dispatch.principal_ref,
                &dispatch.owner_ref,
                "automation-dispatch",
            )
            .map_err(|error| (error.code().to_string(), error.message()))?;
            (
                identity,
                dispatch.owner_ref.clone(),
                dispatch.activation_kind.clone(),
            )
        }
    };
    let steps = automation
        .get("steps")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let (graph_ref, graph_hash) = legacy_automation_graph(automation_id, &steps)
        .map_err(|m| ("automation_bridge_graph_unhashable".to_string(), m))?;
    let chain = match find_chain(
        &st.data_dir,
        &identity.principal_ref,
        &graph_ref,
        &graph_hash,
        &activation_kind,
    ) {
        Some(chain) => chain,
        None => {
            let name = automation
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(automation_id);
            mint_chain(
                st,
                &identity,
                &owner_tenant,
                name,
                &graph_ref,
                &graph_hash,
                &activation_kind,
            )?
        }
    };
    let event = if activation_kind == "manual" {
        "run-now"
    } else {
        activation_kind.as_str()
    };
    let admitted = bridge_step(
        "automation run",
        admit_automation_run_as(
            st,
            &identity.principal_ref,
            &json!({
                "automation_spec_revision_ref": chain.spec_ref, "automation_spec_content_hash": chain.spec_hash,
                "automation_installation_binding_revision_ref": chain.binding_ref, "automation_installation_binding_hash": chain.binding_hash,
                "activation_kind": activation_kind, "activation_event_ref": format!("event://automation/{automation_id}/{event}/{execution_id}"),
            }),
        ),
    )?;
    let run_ref = admitted
        .pointer("/automation_run/automation_run_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut run = BridgedRun {
        run_ref,
        principal_ref: identity.principal_ref.clone(),
        head: String::new(),
        ordinal: 0,
    };
    let evidence = vec![format!("automation-execution://{execution_id}")];
    append_phase(
        &st.data_dir,
        &mut run,
        None,
        "queued",
        &format!("{execution_id}:queued"),
        &evidence,
    )
    .and_then(|()| {
        append_phase(
            &st.data_dir,
            &mut run,
            Some("queued"),
            "running",
            &format!("{execution_id}:running"),
            &evidence,
        )
    })
    .map_err(|m| ("automation_run_lifecycle_refused".to_string(), m))?;
    Ok(run)
}

/// The execution finished: the run's lifecycle moves to `succeeded` or `failed`, carrying the
/// execution (and its transcript, when one was recorded) as evidence.
pub(crate) fn bridge_run_finished(
    data_dir: &str,
    run: &mut BridgedRun,
    failed: bool,
    execution_id: &str,
    transcript_ref: Option<&str>,
) -> Result<(), String> {
    let mut evidence = vec![format!("automation-execution://{execution_id}")];
    if let Some(reference) = transcript_ref.filter(|r| !r.is_empty()) {
        evidence.push(reference.to_string());
    }
    let to = if failed { "failed" } else { "succeeded" };
    append_phase(
        data_dir,
        run,
        Some("running"),
        to,
        &format!("{execution_id}:{to}"),
        &evidence,
    )
}

/// The display name of the spec a run was admitted under (its automation's own name), for readers
/// that show a run to a person; `None` when the revision is not held here.
pub(crate) fn spec_display_name(data_dir: &str, spec_revision_ref: &str) -> Option<String> {
    read_record_dir(data_dir, SPEC_DIR)
        .into_iter()
        .find(|spec| spec.get("revision_ref").and_then(Value::as_str) == Some(spec_revision_ref))
        .and_then(|spec| {
            spec.get("display_name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|name| !name.is_empty())
}

/// The run's CURRENT status and when it last moved: the lifecycle plane's active phase and last
/// transition when it holds a chain for this run, else the frozen admission status (and no time). The
/// run record itself is never rewritten.
pub(crate) fn current_run_view(data_dir: &str, run: &Value) -> (String, Option<String>) {
    let frozen = run
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("queued")
        .to_string();
    let Some(run_ref) = run.get("automation_run_ref").and_then(Value::as_str) else {
        return (frozen, None);
    };
    let Ok(projection) =
        super::work_lifecycle_routes::WorkLifecycleStore::new(data_dir.to_string())
            .read_projection(run_ref)
    else {
        return (frozen, None);
    };
    let phase = projection
        .get("active_phase")
        .and_then(Value::as_str)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    let moved = projection
        .get("last_occurred_at_ms")
        .and_then(Value::as_i64)
        .filter(|ms| *ms > 0)
        .and_then(|ms| {
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()
        })
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        });
    match phase {
        Some(phase) => (phase, moved),
        None => (frozen, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge_dir(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ioi-auto-bridge-{tag}-{}", tail("t")));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_str().unwrap().to_string()
    }

    fn seed_chain(data_dir: &str, owner: &str, graph_hash: &str, enabled: bool) {
        let put = |family: &str, key: &str, record: Value| {
            super::super::persist_record(data_dir, family, key, &record).unwrap()
        };
        put(
            TEMPLATE_DIR,
            "wft_a",
            json!({ "owner_ref": owner, "graph_ref": "workflow://graph/automation/auto_1", "graph_hash": graph_hash, "revision_ref": "workflow-template://wft_a/revision/sha256:1", "content_hash": "sha256:t" }),
        );
        put(
            SPEC_DIR,
            "spec_a",
            json!({ "owner_ref": owner, "workflow_template_revision_ref": "workflow-template://wft_a/revision/sha256:1", "activation_kind": "manual", "revision_ref": "automation://spec_a/revision/sha256:2", "content_hash": "sha256:s" }),
        );
        put(
            BINDING_DIR,
            "bind_a",
            json!({ "owner_ref": owner, "automation_spec_revision_ref": "automation://spec_a/revision/sha256:2", "enabled": enabled, "revision_ref": "install://automation/bind_a/revision/sha256:3", "binding_hash": "sha256:b", "predecessor_revision_ref": Value::Null }),
        );
    }

    #[test]
    fn run_now_resolves_the_principals_manual_chain_for_exactly_these_steps() {
        let dir = bridge_dir("find");
        seed_chain(&dir, "user://alice", "sha256:steps", true);
        let chain = find_chain(
            &dir,
            "user://alice",
            "workflow://graph/automation/auto_1",
            "sha256:steps",
            "manual",
        )
        .expect("the seeded chain resolves");
        assert_eq!(chain.spec_ref, "automation://spec_a/revision/sha256:2");
        assert_eq!(
            chain.binding_ref,
            "install://automation/bind_a/revision/sha256:3"
        );
        // Another principal's chain is never theirs; edited steps are a different graph.
        assert!(find_chain(
            &dir,
            "user://bob",
            "workflow://graph/automation/auto_1",
            "sha256:steps",
            "manual"
        )
        .is_none());
        assert!(find_chain(
            &dir,
            "user://alice",
            "workflow://graph/automation/auto_1",
            "sha256:edited",
            "manual"
        )
        .is_none());
        // A binding with a successor is not the head: the chain does not resolve through it.
        super::super::persist_record(&dir, BINDING_DIR, "bind_b", &json!({ "owner_ref": "user://alice", "automation_spec_revision_ref": "automation://spec_a/revision/sha256:2", "enabled": false, "revision_ref": "install://automation/bind_a/revision/sha256:4", "binding_hash": "sha256:b2", "predecessor_revision_ref": "install://automation/bind_a/revision/sha256:3" })).unwrap();
        assert!(
            find_chain(
                &dir,
                "user://alice",
                "workflow://graph/automation/auto_1",
                "sha256:steps",
                "manual"
            )
            .is_none(),
            "a disabling successor retires the chain"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_manual_chain_never_answers_for_a_scheduled_dispatch() {
        // A spec is ONE standing activation: the scheduler's dispatch resolves its own schedule spec,
        // never the principal's Run now spec over the same template.
        let dir = bridge_dir("kinds");
        seed_chain(&dir, "user://alice", "sha256:steps", true);
        assert!(find_chain(
            &dir,
            "user://alice",
            "workflow://graph/automation/auto_1",
            "sha256:steps",
            "manual"
        )
        .is_some());
        assert!(find_chain(
            &dir,
            "user://alice",
            "workflow://graph/automation/auto_1",
            "sha256:steps",
            "schedule"
        )
        .is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_disabled_binding_is_not_a_chain_and_a_run_without_lifecycle_reads_frozen() {
        let dir = bridge_dir("disabled");
        seed_chain(&dir, "user://alice", "sha256:steps", false);
        assert!(find_chain(
            &dir,
            "user://alice",
            "workflow://graph/automation/auto_1",
            "sha256:steps",
            "manual"
        )
        .is_none());
        // No lifecycle chain for this run: the frozen admission status, and no transition time.
        let run =
            json!({ "automation_run_ref": "automation-run://autorun_none", "status": "queued" });
        assert_eq!(current_run_view(&dir, &run), ("queued".to_string(), None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_automations_graph_is_its_exact_steps() {
        let (graph_ref, a) =
            legacy_automation_graph("auto_1", &json!([{ "kind": "command", "body": "echo a" }]))
                .unwrap();
        let (_, b) =
            legacy_automation_graph("auto_1", &json!([{ "kind": "command", "body": "echo b" }]))
                .unwrap();
        assert_eq!(graph_ref, "workflow://graph/automation/auto_1");
        assert!(
            a.starts_with("sha256:") && a != b,
            "an edit to the steps is a new graph"
        );
    }

    #[test]
    fn server_owned_identity_and_hash_fields_are_not_accepted_as_template_input() {
        let body = json!({
            "owner_ref": "user://owner",
            "display_name": "build",
            "graph_ref": "workflow://graph/build",
            "graph_hash": format!("sha256:{}", "a".repeat(64)),
            "content_hash": format!("sha256:{}", "b".repeat(64)),
        });
        let reply = build_template(body.as_object().unwrap(), "user://owner", "wft_test", None)
            .expect_err("client-supplied content hash must be refused");
        assert_eq!(reply.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn template_successor_changes_revision_without_rewriting_predecessor() {
        let first_body = json!({
            "owner_ref": "user://owner",
            "display_name": "build",
            "graph_ref": "workflow://graph/build-v1",
            "graph_hash": format!("sha256:{}", "a".repeat(64)),
            "registry_status": "released",
        });
        let first = build_template(
            first_body.as_object().unwrap(),
            "user://owner",
            "wft_test",
            None,
        )
        .unwrap();
        let frozen = first.clone();
        let second_body = json!({
            "owner_ref": "user://owner",
            "display_name": "build",
            "version": "2.0.0",
            "graph_ref": "workflow://graph/build-v2",
            "graph_hash": format!("sha256:{}", "b".repeat(64)),
            "registry_status": "released",
        });
        let second = build_template(
            second_body.as_object().unwrap(),
            "user://owner",
            "wft_test",
            Some(&first),
        )
        .unwrap();
        assert_ne!(first["revision_ref"], second["revision_ref"]);
        assert_eq!(second["predecessor_revision_ref"], first["revision_ref"]);
        assert_eq!(
            first, frozen,
            "successor construction must not mutate its predecessor"
        );
    }

    #[test]
    fn forked_lineage_has_no_guessable_head() {
        let first_ref = "workflow-template://wft_test/revision/sha256:first";
        let revisions = vec![
            json!({
                "revision_ref": first_ref,
                "predecessor_revision_ref": null,
            }),
            json!({
                "revision_ref": "workflow-template://wft_test/revision/sha256:second",
                "predecessor_revision_ref": first_ref,
            }),
            json!({
                "revision_ref": "workflow-template://wft_test/revision/sha256:third",
                "predecessor_revision_ref": first_ref,
            }),
        ];
        assert!(
            chain_head(&revisions).is_none(),
            "a pre-existing fork must refuse rather than select one live head"
        );
    }

    #[test]
    fn owner_scoped_resolution_never_returns_a_foreign_record() {
        let record = json!({
            "revision_ref": "automation://test/revision/sha256:exact",
            "owner_ref": "user://owner-a",
        });
        assert!(find_owned_by(
            vec![record.clone()],
            "revision_ref",
            record["revision_ref"].as_str().unwrap(),
            "user://owner-b",
        )
        .is_none());
        assert!(find_owned_by(
            vec![record.clone()],
            "revision_ref",
            record["revision_ref"].as_str().unwrap(),
            "user://owner-a",
        )
        .is_some());
    }
}
