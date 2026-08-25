//! Canonical reusable GoalRun profile and agent-harness adapter revisions.
//!
//! These records are inert, immutable definitions. They do not create GoalRuns, execute a
//! harness, grant authority, or attest compatibility. Admission derives owner and content
//! identity, validates the generated contracts, and permits only one successor from one exact
//! owner-scoped lineage head.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::DaemonState;

const PROFILE_DIR: &str = "goal-run-profile-revisions";
const ADAPTER_DIR: &str = "agent-harness-adapter-revisions";
const PROFILE_CONTRACT: &str = "schema://ioi/applications/ioi-ai/goal-run-profile/v1";
const ADAPTER_CONTRACT: &str = "schema://ioi/components/daemon-runtime/agent-harness-adapter/v1";
const PROFILE_HASH_DOMAIN: &str = "ioi.goal-run-profile-release-jcs-sha256.v1";
const ADAPTER_HASH_DOMAIN: &str = "ioi.agent-harness-adapter-release-jcs-sha256.v1";

type Reply = (StatusCode, Json<Value>);

static MUTATION_LOCK: Mutex<()> = Mutex::new(());

fn reply(status: StatusCode, body: Value) -> Reply {
    (status, Json(body))
}

fn success(field: &str, value: Value) -> Value {
    let mut body = Map::new();
    body.insert("ok".into(), Value::Bool(true));
    body.insert(field.into(), value);
    Value::Object(body)
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    reply(
        status,
        json!({"ok":false,"error":{"code":code,"message":message.into()}}),
    )
}

fn identity(st: &DaemonState, headers: &HeaderMap) -> Result<String, Reply> {
    let posture = super::lifecycle_routes::deployment_auth_posture(&st.data_dir, headers);
    if posture == "exposed_untrusted" {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "goal_profile_authenticated_principal_required",
            "portable goal definitions are unavailable on an exposed deployment without enforced identity",
        ));
    }
    if let Some(principal) = super::lifecycle_routes::resolve_principal(&st.data_dir, headers) {
        let Some(principal_id) = principal
            .get("principal_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Err(refuse(
                StatusCode::UNAUTHORIZED,
                "goal_profile_principal_unresolved",
                "the authenticated session did not resolve a principal identity",
            ));
        };
        return Ok(format!("user://{principal_id}"));
    }
    Err(refuse(
        StatusCode::UNAUTHORIZED,
        "goal_profile_authentication_required",
        "authentication is required before reading or admitting portable goal definitions",
    ))
}

fn object(value: &Value) -> Result<&Map<String, Value>, Reply> {
    value.as_object().ok_or_else(|| {
        refuse(
            StatusCode::BAD_REQUEST,
            "goal_profile_request_invalid",
            "the request must be a closed JSON object",
        )
    })
}

fn ensure_allowed(body: &Map<String, Value>, allowed: &[&str]) -> Result<(), Reply> {
    let unknown = body
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "goal_profile_unknown_field",
            format!("unknown or server-owned fields: {}", unknown.join(", ")),
        ))
    }
}

fn required_text(body: &Map<String, Value>, field: &str) -> Result<String, Reply> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 500)
        .map(str::to_owned)
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "goal_profile_field_required",
                format!("{field} must be a non-empty bounded string"),
            )
        })
}

fn optional_text(body: &Map<String, Value>, field: &str) -> Option<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 500)
        .map(str::to_owned)
}

fn string_array(body: &Map<String, Value>, field: &str) -> Result<Value, Reply> {
    let values = match body.get(field) {
        None => Vec::new(),
        Some(Value::Array(values)) if values.len() <= 256 => values.clone(),
        _ => {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "goal_profile_array_invalid",
                format!("{field} must be an array of at most 256 unique strings"),
            ))
        }
    };
    let mut seen = BTreeSet::new();
    for value in &values {
        let Some(value) = value.as_str().filter(|value| {
            !value.is_empty() && value.len() <= 500 && !value.chars().any(char::is_control)
        }) else {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "goal_profile_array_invalid",
                format!("{field} contains an invalid string"),
            ));
        };
        if !seen.insert(value) {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "goal_profile_array_invalid",
                format!("{field} contains a duplicate"),
            ));
        }
    }
    Ok(Value::Array(values))
}

fn nullable(body: &Map<String, Value>, field: &str) -> Value {
    body.get(field).cloned().unwrap_or(Value::Null)
}

fn status(body: &Map<String, Value>) -> Result<&str, Reply> {
    let status = body
        .get("registry_status")
        .and_then(Value::as_str)
        .unwrap_or("draft");
    if matches!(
        status,
        "draft" | "evaluable" | "released" | "deprecated" | "revoked"
    ) {
        Ok(status)
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "goal_profile_status_invalid",
            "registry_status is not a canonical registry state",
        ))
    }
}

fn hash(value: &Value) -> Result<String, Reply> {
    serde_jcs::to_vec(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            refuse(
                StatusCode::BAD_REQUEST,
                "goal_profile_canonicalization_failed",
                error.to_string(),
            )
        })
}

fn canonical_slot_name(family: &str, record: &Value) -> Result<String, String> {
    let (identity_field, identity_prefix, domain, kind) = match family {
        PROFILE_DIR => (
            "goal_run_profile_id",
            "goal-run-profile://",
            PROFILE_HASH_DOMAIN,
            "goal_run_profile",
        ),
        ADAPTER_DIR => (
            "adapter_id",
            "agent-harness-adapter://",
            ADAPTER_HASH_DOMAIN,
            "agent_harness_adapter",
        ),
        _ => return Err(format!("unknown portable-definition family: {family}")),
    };
    let identity = record
        .get(identity_field)
        .and_then(Value::as_str)
        .and_then(|value| value.strip_prefix(identity_prefix))
        .ok_or_else(|| format!("{identity_field} is not canonical"))?;
    let stored_hash = record
        .get("content_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "content_hash is absent".to_string())?;
    let mut material = record.clone();
    let object = material
        .as_object_mut()
        .ok_or_else(|| "portable definition is not an object".to_string())?;
    for field in [
        "revision_ref",
        "content_hash",
        "registry_lifecycle_ref",
        "registry_status",
    ] {
        object.remove(field);
    }
    let bytes = serde_jcs::to_vec(&json!({"domain":domain,"kind":kind,"body":material}))
        .map_err(|error| format!("portable definition is not canonicalizable: {error}"))?;
    let expected_hash = format!("sha256:{:x}", Sha256::digest(bytes));
    if stored_hash != expected_hash {
        return Err(format!(
            "content_hash mismatch: stored {stored_hash}, recomputed {expected_hash}"
        ));
    }
    let expected_revision = format!("{identity_prefix}{identity}/revision/{expected_hash}");
    if record.get("revision_ref").and_then(Value::as_str) != Some(expected_revision.as_str()) {
        return Err("revision_ref does not bind the exact identity and content hash".to_string());
    }
    Ok(format!("{identity}--{}.json", digest_tail(&expected_hash)))
}

fn tail(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}_{nanos:x}")
}

fn digest_tail(hash: &str) -> &str {
    hash.strip_prefix("sha256:").unwrap_or(hash)
}

fn validate(contract: &str, record: &Value) -> Result<(), Reply> {
    validate_architecture_contract(contract, record).map_err(|error| {
        refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "goal_profile_contract_invalid",
            error,
        )
    })
}

fn strict_records(data_dir: &str, family: &str) -> Result<Vec<Value>, Reply> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                error.to_string(),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        refuse(
            StatusCode::CONFLICT,
            "goal_profile_registry_unreadable",
            error.to_string(),
        )
    })?;
    names.sort();
    let contract = if family == PROFILE_DIR {
        PROFILE_CONTRACT
    } else {
        ADAPTER_CONTRACT
    };
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        if !name.ends_with(".json") {
            return Err(refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                format!("unexpected canonical registry occupant: {name}"),
            ));
        }
        let bytes = super::durable_fs::read_slot_strict(&directory, &name)
            .map_err(|error| {
                refuse(
                    StatusCode::CONFLICT,
                    "goal_profile_registry_unreadable",
                    error.to_string(),
                )
            })?
            .ok_or_else(|| {
                refuse(
                    StatusCode::CONFLICT,
                    "goal_profile_registry_unreadable",
                    format!("canonical registry occupant vanished during census: {name}"),
                )
            })?
            .1;
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                format!("malformed canonical registry occupant {name}: {error}"),
            )
        })?;
        validate(contract, &record).map_err(|_| {
            refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                format!("contract-invalid canonical registry occupant: {name}"),
            )
        })?;
        let expected_name = canonical_slot_name(family, &record).map_err(|error| {
            refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                format!("non-canonical registry occupant {name}: {error}"),
            )
        })?;
        if name != expected_name {
            return Err(refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                format!(
                    "registry occupant {name} belongs at its exact content-addressed slot {expected_name}"
                ),
            ));
        }
        records.push(record);
    }
    Ok(records)
}

fn store(st: &DaemonState, family: &str, key: &str, record: &Value) -> Result<(), Reply> {
    match super::durable_fs::open_family_dir_pinned(&st.data_dir, family) {
        Ok(directory) => {
            let name = format!("{key}.json");
            match super::durable_fs::read_slot_strict(&directory, &name) {
                Ok(Some((_file, bytes))) => {
                    let existing: Value = serde_json::from_slice(&bytes).map_err(|error| {
                        refuse(
                            StatusCode::CONFLICT,
                            "goal_profile_registry_unreadable",
                            format!("the canonical slot is malformed: {error}"),
                        )
                    })?;
                    if existing != *record {
                        return Err(refuse(
                            StatusCode::CONFLICT,
                            "goal_profile_immutable_revision_conflict",
                            "an immutable content-addressed slot already contains different bytes",
                        ));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(refuse(
                        StatusCode::CONFLICT,
                        "goal_profile_registry_unreadable",
                        error.to_string(),
                    ))
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(refuse(
                StatusCode::CONFLICT,
                "goal_profile_registry_unreadable",
                error.to_string(),
            ))
        }
    }
    super::durable_fs::persist_record_durable(&st.data_dir, family, key, record).map_err(|error| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "goal_profile_persistence_failed",
            format!("{error:?}"),
        )
    })
}

fn chain_head<'a>(
    records: &'a [Value],
    identity_field: &str,
    predecessor_field: &str,
) -> Option<&'a Value> {
    let predecessors = records
        .iter()
        .filter_map(|record| record.get(predecessor_field).and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut heads = records.iter().filter(|record| {
        record
            .get(identity_field)
            .and_then(Value::as_str)
            .is_some_and(|reference| !predecessors.contains(reference))
    });
    let head = heads.next()?;
    if heads.next().is_some() {
        None
    } else {
        Some(head)
    }
}

const PROFILE_FIELDS: &[&str] = &[
    "owner_ref",
    "display_name",
    "description",
    "version",
    "applicable_goal_class_refs",
    "compatible_domain_object_schema_refs",
    "orchestration_policy_ref",
    "constraint_derivation_policy_refs",
    "workflow_template_revision_refs",
    "role_topology_requirement_refs",
    "harness_requirement_refs",
    "pinned_harness_profile_revision_refs",
    "skill_requirement_refs",
    "pinned_skill_manifest_revision_refs",
    "worker_requirement_refs",
    "model_route_requirement_refs",
    "service_requirement_refs",
    "runtime_tool_contract_requirement_refs",
    "primitive_capability_requirements",
    "context_requirement_profile_refs",
    "input_contract_ref",
    "output_contract_ref",
    "acceptance_contract_refs",
    "verifier_requirement_refs",
    "budget_time_and_resource_ceiling_refs",
    "stop_policy_ref",
    "recovery_policy_ref",
    "escalation_policy_ref",
    "learning_boundary_requirement_ref",
    "pinned_learning_boundary_profile_ref",
    "allowed_override_schema_ref",
    "compatibility_refs",
    "provenance_refs",
    "evaluation_and_benchmark_refs",
    "promotion_policy_ref",
    "revocation_and_recall_policy_ref",
    "registry_status",
];

fn build_profile(
    body: &Map<String, Value>,
    identity: &str,
    profile_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, PROFILE_FIELDS)?;
    if required_text(body, "owner_ref")? != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "goal_profile_owner_mismatch",
            "owner_ref must equal the authenticated principal",
        ));
    }
    let profile_id = format!("goal-run-profile://{profile_tail}");
    let mut material = json!({
        "schema_version":"ioi.goal-run-profile.v1",
        "goal_run_profile_id":profile_id,
        "version":optional_text(body,"version").unwrap_or_else(|| "1.0.0".into()),
        "predecessor_revision_ref":predecessor.and_then(|record| record.get("revision_ref")).cloned().unwrap_or(Value::Null),
        "owner_ref":identity,
        "display_name":required_text(body,"display_name")?,
        "description":optional_text(body,"description").unwrap_or_default(),
        "applicable_goal_class_refs":string_array(body,"applicable_goal_class_refs")?,
        "compatible_domain_object_schema_refs":string_array(body,"compatible_domain_object_schema_refs")?,
        "orchestration_policy_ref":required_text(body,"orchestration_policy_ref")?,
        "constraint_derivation_policy_refs":string_array(body,"constraint_derivation_policy_refs")?,
        "workflow_template_revision_refs":string_array(body,"workflow_template_revision_refs")?,
        "role_topology_requirement_refs":string_array(body,"role_topology_requirement_refs")?,
        "harness_requirement_refs":string_array(body,"harness_requirement_refs")?,
        "pinned_harness_profile_revision_refs":string_array(body,"pinned_harness_profile_revision_refs")?,
        "skill_requirement_refs":string_array(body,"skill_requirement_refs")?,
        "pinned_skill_manifest_revision_refs":string_array(body,"pinned_skill_manifest_revision_refs")?,
        "worker_requirement_refs":string_array(body,"worker_requirement_refs")?,
        "model_route_requirement_refs":string_array(body,"model_route_requirement_refs")?,
        "service_requirement_refs":string_array(body,"service_requirement_refs")?,
        "runtime_tool_contract_requirement_refs":string_array(body,"runtime_tool_contract_requirement_refs")?,
        "primitive_capability_requirements":string_array(body,"primitive_capability_requirements")?,
        "context_requirement_profile_refs":string_array(body,"context_requirement_profile_refs")?,
        "input_contract_ref":required_text(body,"input_contract_ref")?,
        "output_contract_ref":required_text(body,"output_contract_ref")?,
        "acceptance_contract_refs":string_array(body,"acceptance_contract_refs")?,
        "verifier_requirement_refs":string_array(body,"verifier_requirement_refs")?,
        "budget_time_and_resource_ceiling_refs":string_array(body,"budget_time_and_resource_ceiling_refs")?,
        "stop_policy_ref":required_text(body,"stop_policy_ref")?,
        "recovery_policy_ref":required_text(body,"recovery_policy_ref")?,
        "escalation_policy_ref":required_text(body,"escalation_policy_ref")?,
        "learning_boundary_requirement_ref":nullable(body,"learning_boundary_requirement_ref"),
        "pinned_learning_boundary_profile_ref":nullable(body,"pinned_learning_boundary_profile_ref"),
        "allowed_override_schema_ref":nullable(body,"allowed_override_schema_ref"),
        "compatibility_refs":string_array(body,"compatibility_refs")?,
        "provenance_refs":string_array(body,"provenance_refs")?,
        "evaluation_and_benchmark_refs":string_array(body,"evaluation_and_benchmark_refs")?,
        "promotion_policy_ref":nullable(body,"promotion_policy_ref"),
        "revocation_and_recall_policy_ref":nullable(body,"revocation_and_recall_policy_ref"),
    });
    let content_hash = hash(&json!({
        "domain":PROFILE_HASH_DOMAIN,
        "kind":"goal_run_profile",
        "body":material,
    }))?;
    material["content_hash"] = json!(content_hash);
    material["revision_ref"] = json!(format!(
        "{profile_id}/revision/{}",
        material["content_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(status(body)?);
    validate(PROFILE_CONTRACT, &material)?;
    Ok(material)
}

const ADAPTER_FIELDS: &[&str] = &[
    "owner_ref",
    "adapter_family",
    "transport_kind",
    "compatible_harness_profile_revision_refs",
    "supported_task_brief_schema_refs",
    "supported_event_and_result_schema_refs",
    "supported_runtime_and_model_route_refs",
    "rendering_and_normalization_contract_refs",
    "required_runtime_tool_contract_revision_refs",
    "capability_and_context_requirement_refs",
    "provenance_evaluation_and_conformance_refs",
    "registry_status",
];

fn build_adapter(
    body: &Map<String, Value>,
    identity: &str,
    adapter_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, ADAPTER_FIELDS)?;
    if required_text(body, "owner_ref")? != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "goal_profile_owner_mismatch",
            "owner_ref must equal the authenticated principal",
        ));
    }
    let adapter_id = format!("agent-harness-adapter://{adapter_tail}");
    let mut material = json!({
        "schema_version":"ioi.agent-harness-adapter.v1",
        "adapter_id":adapter_id,
        "predecessor_revision_ref":predecessor.and_then(|record| record.get("revision_ref")).cloned().unwrap_or(Value::Null),
        "owner_ref":identity,
        "adapter_family":required_text(body,"adapter_family")?,
        "transport_kind":required_text(body,"transport_kind")?,
        "compatible_harness_profile_revision_refs":string_array(body,"compatible_harness_profile_revision_refs")?,
        "supported_task_brief_schema_refs":string_array(body,"supported_task_brief_schema_refs")?,
        "supported_event_and_result_schema_refs":string_array(body,"supported_event_and_result_schema_refs")?,
        "supported_runtime_and_model_route_refs":string_array(body,"supported_runtime_and_model_route_refs")?,
        "rendering_and_normalization_contract_refs":string_array(body,"rendering_and_normalization_contract_refs")?,
        "required_runtime_tool_contract_revision_refs":string_array(body,"required_runtime_tool_contract_revision_refs")?,
        "capability_and_context_requirement_refs":string_array(body,"capability_and_context_requirement_refs")?,
        "provenance_evaluation_and_conformance_refs":string_array(body,"provenance_evaluation_and_conformance_refs")?,
    });
    let content_hash = hash(&json!({
        "domain":ADAPTER_HASH_DOMAIN,
        "kind":"agent_harness_adapter",
        "body":material,
    }))?;
    material["content_hash"] = json!(content_hash);
    material["revision_ref"] = json!(format!(
        "{adapter_id}/revision/{}",
        material["content_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(status(body)?);
    validate(ADAPTER_CONTRACT, &material)?;
    Ok(material)
}

async fn create_definition(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    body: Value,
    kind: &str,
) -> Reply {
    let identity = match identity(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _guard = MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let (family, record, response_field) = if kind == "profile" {
        let tail = tail("grp");
        let record = match build_profile(body, &identity, &tail, None) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        (PROFILE_DIR, record, "goal_run_profile")
    } else {
        let tail = tail("aha");
        let record = match build_adapter(body, &identity, &tail, None) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        (ADAPTER_DIR, record, "agent_harness_adapter")
    };
    let key = format!(
        "{}--{}",
        if kind == "profile" {
            record["goal_run_profile_id"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("goal-run-profile://")
        } else {
            record["adapter_id"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("agent-harness-adapter://")
        },
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = strict_records(&st.data_dir, family) {
        return reply;
    }
    if let Err(reply) = store(&st, family, &key, &record) {
        return reply;
    }
    reply(StatusCode::CREATED, success(response_field, record))
}

async fn create_successor(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    object_tail: String,
    body: Value,
    kind: &str,
) -> Reply {
    let identity = match identity(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _guard = MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (family, identity_field, prefix, response_field) = if kind == "profile" {
        (
            PROFILE_DIR,
            "goal_run_profile_id",
            "goal-run-profile://",
            "goal_run_profile",
        )
    } else {
        (
            ADAPTER_DIR,
            "adapter_id",
            "agent-harness-adapter://",
            "agent_harness_adapter",
        )
    };
    let object_id = format!("{prefix}{object_tail}");
    let records = match strict_records(&st.data_dir, family) {
        Ok(records) => records,
        Err(reply) => return reply,
    }
    .into_iter()
    .filter(|record| record[identity_field] == object_id && record["owner_ref"] == identity)
    .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(&records, "revision_ref", "predecessor_revision_ref") else {
        return refuse(
            if records.is_empty() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            if records.is_empty() {
                "goal_profile_definition_not_found"
            } else {
                "goal_profile_lineage_ambiguous"
            },
            "no single owner-scoped definition head is eligible for a successor",
        );
    };
    if predecessor["registry_status"] == "revoked" {
        return refuse(
            StatusCode::CONFLICT,
            "goal_profile_definition_revoked",
            "a revoked definition cannot produce a successor",
        );
    }
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let record = if kind == "profile" {
        match build_profile(body, &identity, &object_tail, Some(predecessor)) {
            Ok(value) => value,
            Err(reply) => return reply,
        }
    } else {
        match build_adapter(body, &identity, &object_tail, Some(predecessor)) {
            Ok(value) => value,
            Err(reply) => return reply,
        }
    };
    let key = format!(
        "{object_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, family, &key, &record) {
        return reply;
    }
    reply(StatusCode::CREATED, success(response_field, record))
}

async fn list_definitions(st: Arc<DaemonState>, headers: HeaderMap, kind: &str) -> Reply {
    let identity = match identity(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let (family, response_field) = if kind == "profile" {
        (PROFILE_DIR, "goal_run_profiles")
    } else {
        (ADAPTER_DIR, "agent_harness_adapters")
    };
    let mut records = match strict_records(&st.data_dir, family) {
        Ok(records) => records,
        Err(reply) => return reply,
    }
    .into_iter()
    .filter(|record| record["owner_ref"] == identity)
    .collect::<Vec<_>>();
    records.sort_by_key(|record| record["revision_ref"].as_str().unwrap_or("").to_owned());
    reply(StatusCode::OK, success(response_field, json!(records)))
}

pub(crate) async fn create_goal_run_profile(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    create_definition(st, headers, body, "profile").await
}

pub(crate) async fn create_goal_run_profile_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    create_successor(st, headers, id, body, "profile").await
}

pub(crate) async fn list_goal_run_profiles(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    list_definitions(st, headers, "profile").await
}

pub(crate) async fn create_agent_harness_adapter(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    create_definition(st, headers, body, "adapter").await
}

pub(crate) async fn create_agent_harness_adapter_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    create_successor(st, headers, id, body, "adapter").await
}

pub(crate) async fn list_agent_harness_adapters(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    list_definitions(st, headers, "adapter").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forked_definition_lineage_has_no_guessable_head() {
        let first = json!({"revision_ref":"goal-run-profile://one/revision/sha256:a","predecessor_revision_ref":null});
        let fork_a = json!({"revision_ref":"goal-run-profile://one/revision/sha256:b","predecessor_revision_ref":first["revision_ref"]});
        let fork_b = json!({"revision_ref":"goal-run-profile://one/revision/sha256:c","predecessor_revision_ref":first["revision_ref"]});
        assert!(chain_head(
            &[first, fork_a, fork_b],
            "revision_ref",
            "predecessor_revision_ref"
        )
        .is_none());
    }

    #[test]
    fn content_domains_keep_profile_and_adapter_identity_distinct() {
        let body = json!({"same":"body"});
        let profile =
            hash(&json!({"domain":PROFILE_HASH_DOMAIN,"kind":"goal_run_profile","body":body}))
                .unwrap();
        let adapter =
            hash(&json!({"domain":ADAPTER_HASH_DOMAIN,"kind":"agent_harness_adapter","body":body}))
                .unwrap();
        assert_ne!(profile, adapter);
    }
}
