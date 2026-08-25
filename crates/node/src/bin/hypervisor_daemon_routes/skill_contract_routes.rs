//! Canonical reusable-skill object family (M04.3).
//!
//! This plane deliberately does not reuse the legacy `ioi.hypervisor.skill-entry.v1` intelligence
//! record. That predecessor is a mutable procedure body. The canonical family has three separate
//! lifetimes: immutable `SkillManifest` definitions, immutable successor-versioned `SkillEntry`
//! owner bindings, and immutable run-scoped `ActiveSkillSetSnapshot` resolutions. A manifest may
//! import a legacy record as provenance, but the legacy record is never relabelled as canonical.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{read_record_dir, DaemonState};

const MANIFEST_DIR: &str = "canonical-skill-manifest-revisions";
const ENTRY_DIR: &str = "canonical-skill-entry-revisions";
const SNAPSHOT_DIR: &str = "canonical-active-skill-set-snapshots";
const RESOLUTION_RECEIPT_DIR: &str = "canonical-active-skill-set-resolution-receipts";
const LEGACY_SKILL_DIR: &str = "skill-entries";
const AUTOMATION_RUN_DIR: &str = "canonical-automation-runs";

static SKILL_CONTRACT_MUTATION_LOCK: Mutex<()> = Mutex::new(());

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

fn object(value: &Value) -> Result<&Map<String, Value>, Reply> {
    value.as_object().ok_or_else(|| {
        refuse(
            StatusCode::BAD_REQUEST,
            "skill_contract_body_invalid",
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
            "skill_contract_unknown_field",
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
                "skill_contract_field_required",
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
            "skill_contract_hash_invalid",
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
                "skill_contract_not_canonicalizable",
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
        refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            if error.visible() {
                "skill_contract_durability_unconfirmed"
            } else {
                "skill_contract_not_committed"
            },
            format!(
                "canonical skill record did not durably commit: {}",
                error.detail()
            ),
        )
    })
}

fn store_exact_or_replay(
    st: &DaemonState,
    family: &str,
    key: &str,
    identity_field: &str,
    record: &Value,
) -> Result<(), Reply> {
    if let Some(existing) = read_record_dir(&st.data_dir, family)
        .into_iter()
        .find(|candidate| candidate.get(identity_field) == record.get(identity_field))
    {
        return if existing == *record {
            Ok(())
        } else {
            Err(refuse(
                StatusCode::CONFLICT,
                "skill_contract_identity_collision",
                format!("{identity_field} already names different durable bytes"),
            ))
        };
    }
    store(st, family, key, record)
}

fn validate_contract(contract_id: &str, value: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract_id,
        value,
    )
    .map_err(|error| {
        refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "skill_contract_generated_schema_invalid",
            error,
        )
    })
}

fn string_array(body: &Map<String, Value>, key: &str) -> Result<Value, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(json!([]));
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "skill_contract_array_invalid",
            format!("{key} must be an array of unique non-empty strings"),
        ));
    };
    let mut seen = BTreeSet::new();
    for item in items {
        let Some(item) = item.as_str().filter(|item| !item.is_empty()) else {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "skill_contract_array_invalid",
                format!("{key} must contain only non-empty strings"),
            ));
        };
        if !seen.insert(item) {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "skill_contract_array_duplicate",
                format!("{key} contains a duplicate"),
            ));
        }
    }
    Ok(value.clone())
}

fn find_owned_by(
    records: Vec<Value>,
    field: &str,
    expected: &str,
    owner_field: &str,
    identity: &str,
) -> Option<Value> {
    records.into_iter().find(|record| {
        record.get(field).and_then(Value::as_str) == Some(expected)
            && record.get(owner_field).and_then(Value::as_str) == Some(identity)
    })
}

fn chain_head<'a>(
    revisions: &'a [Value],
    revision_field: &str,
    prior_field: &str,
) -> Option<&'a Value> {
    let predecessors = revisions
        .iter()
        .filter_map(|record| record.get(prior_field).and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut heads = revisions.iter().filter(|record| {
        record
            .get(revision_field)
            .and_then(Value::as_str)
            .is_some_and(|revision| !predecessors.contains(revision))
    });
    let head = heads.next()?;
    if heads.next().is_some() {
        None
    } else {
        Some(head)
    }
}

const MANIFEST_FIELDS: &[&str] = &[
    "owner_ref",
    "display_name",
    "description",
    "version",
    "instruction_entrypoint_ref",
    "procedure_and_reference_refs",
    "example_refs",
    "support_asset_refs",
    "dependency_skill_revision_refs",
    "runtime_tool_contract_requirement_refs",
    "capability_requirement_refs",
    "input_and_output_contract_refs",
    "context_requirement_profile_refs",
    "compatible_goal_run_profile_revision_refs",
    "compatible_harness_profile_revision_refs",
    "compatible_runtime_and_kernel_refs",
    "provenance_refs",
    "source_rights_and_license_refs",
    "evaluation_and_benchmark_refs",
    "promotion_policy_ref",
    "revocation_and_recall_policy_ref",
    "registry_status",
    "legacy_skill_entry_ref",
];

fn manifest_status(body: &Map<String, Value>) -> Result<&str, Reply> {
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
            "skill_manifest_status_invalid",
            "registry_status must be draft, evaluable, released, deprecated, or revoked",
        ))
    }
}

fn legacy_skill(st: &DaemonState, legacy_ref: &str) -> Result<Value, Reply> {
    read_record_dir(&st.data_dir, LEGACY_SKILL_DIR)
        .into_iter()
        .find(|record| record.get("skill_ref").and_then(Value::as_str) == Some(legacy_ref))
        .ok_or_else(|| {
            refuse(
                StatusCode::NOT_FOUND,
                "legacy_skill_entry_not_found",
                "the incompatible legacy intelligence record does not exist",
            )
        })
}

fn build_manifest(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
    skill_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, MANIFEST_FIELDS)?;
    if required_text(body, "owner_ref")? != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "skill_contract_owner_mismatch",
            "owner_ref must equal the authenticated principal on this bounded lane",
        ));
    }
    let legacy = optional_text(body, "legacy_skill_entry_ref")
        .map(|reference| legacy_skill(st, &reference).map(|record| (reference, record)))
        .transpose()?;
    let legacy_title = legacy
        .as_ref()
        .and_then(|(_, record)| record.get("title").and_then(Value::as_str));
    let display_name = optional_text(body, "display_name")
        .or_else(|| legacy_title.map(str::to_owned))
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "skill_contract_field_required",
                "display_name is required when no legacy title is imported",
            )
        })?;
    let mut provenance = string_array(body, "provenance_refs")?
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some((reference, _)) = &legacy {
        if !provenance
            .iter()
            .any(|value| value.as_str() == Some(reference.as_str()))
        {
            provenance.push(json!(reference));
        }
    }
    let mut material = json!({
        "schema_version": "ioi.skill-manifest.v1",
        "skill_id": format!("skill://{skill_tail}"),
        "version": optional_text(body, "version").unwrap_or_else(|| "1.0.0".into()),
        "predecessor_revision_ref": predecessor.and_then(|record| record.get("revision_ref")).cloned().unwrap_or(Value::Null),
        "owner_ref": identity,
        "display_name": display_name,
        "description": optional_text(body, "description").or_else(|| legacy.as_ref().and_then(|(_, record)| record.get("description").and_then(Value::as_str).map(str::to_owned))).unwrap_or_default(),
        "instruction_entrypoint_ref": required_text(body, "instruction_entrypoint_ref")?,
        "procedure_and_reference_refs": string_array(body, "procedure_and_reference_refs")?,
        "example_refs": string_array(body, "example_refs")?,
        "support_asset_refs": string_array(body, "support_asset_refs")?,
        "dependency_skill_revision_refs": string_array(body, "dependency_skill_revision_refs")?,
        "runtime_tool_contract_requirement_refs": string_array(body, "runtime_tool_contract_requirement_refs")?,
        "capability_requirement_refs": string_array(body, "capability_requirement_refs")?,
        "input_and_output_contract_refs": string_array(body, "input_and_output_contract_refs")?,
        "context_requirement_profile_refs": string_array(body, "context_requirement_profile_refs")?,
        "compatible_goal_run_profile_revision_refs": string_array(body, "compatible_goal_run_profile_revision_refs")?,
        "compatible_harness_profile_revision_refs": string_array(body, "compatible_harness_profile_revision_refs")?,
        "compatible_runtime_and_kernel_refs": string_array(body, "compatible_runtime_and_kernel_refs")?,
        "provenance_refs": provenance,
        "source_rights_and_license_refs": string_array(body, "source_rights_and_license_refs")?,
        "evaluation_and_benchmark_refs": string_array(body, "evaluation_and_benchmark_refs")?,
        "promotion_policy_ref": body.get("promotion_policy_ref").cloned().unwrap_or(Value::Null),
        "revocation_and_recall_policy_ref": body.get("revocation_and_recall_policy_ref").cloned().unwrap_or(Value::Null),
    });
    let content_hash = hash(&material)?;
    material["content_hash"] = json!(content_hash);
    material["revision_ref"] = json!(format!(
        "skill://{skill_tail}/revision/{}",
        material["content_hash"].as_str().unwrap_or("")
    ));
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(manifest_status(body)?);
    validate_contract("schema://ioi/foundations/skill-manifest/v1", &material)?;
    Ok(material)
}

pub(crate) async fn create_skill_manifest(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = SKILL_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let skill_tail = tail("skill");
    let record = match build_manifest(&st, body, &identity, &skill_tail, None) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{skill_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, MANIFEST_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "skill_manifest": record }),
    )
}

pub(crate) async fn create_skill_manifest_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(skill_tail): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = SKILL_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let skill_id = format!("skill://{skill_tail}");
    let revisions = read_record_dir(&st.data_dir, MANIFEST_DIR)
        .into_iter()
        .filter(|record| record["skill_id"] == skill_id && record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(&revisions, "revision_ref", "predecessor_revision_ref")
    else {
        return refuse(
            if revisions.is_empty() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            if revisions.is_empty() {
                "skill_manifest_not_found"
            } else {
                "skill_manifest_lineage_ambiguous"
            },
            "no single owner-scoped manifest head is eligible for a successor",
        );
    };
    if predecessor["registry_status"] == "revoked" {
        return refuse(
            StatusCode::CONFLICT,
            "skill_manifest_revoked",
            "a revoked manifest cannot produce a successor",
        );
    }
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let record = match build_manifest(&st, body, &identity, &skill_tail, Some(predecessor)) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{skill_tail}--{}",
        digest_tail(record["content_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, MANIFEST_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "skill_manifest": record }),
    )
}

pub(crate) async fn list_skill_manifests(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, MANIFEST_DIR)
        .into_iter()
        .filter(|record| record["owner_ref"] == identity)
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "skill_manifests": records }),
    )
}

const ENTRY_FIELDS: &[&str] = &[
    "owner_scope_ref",
    "skill_revision_ref",
    "skill_manifest_content_hash",
    "memory_space_ref",
    "compatibility_decision_ref",
    "configuration_ref",
    "allowed_goal_run_profile_revision_refs",
    "policy_refs",
    "revocation_ref",
    "registry_status",
];

fn entry_status(body: &Map<String, Value>) -> Result<&str, Reply> {
    let status = body
        .get("registry_status")
        .and_then(Value::as_str)
        .unwrap_or("active");
    if matches!(
        status,
        "proposed" | "active" | "suspended" | "archived" | "revoked"
    ) {
        Ok(status)
    } else {
        Err(refuse(
            StatusCode::BAD_REQUEST,
            "skill_entry_status_invalid",
            "registry_status must be proposed, active, suspended, archived, or revoked",
        ))
    }
}

fn build_entry(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
    entry_tail: &str,
    predecessor: Option<&Value>,
) -> Result<Value, Reply> {
    ensure_allowed(body, ENTRY_FIELDS)?;
    if required_text(body, "owner_scope_ref")? != identity {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "skill_contract_owner_mismatch",
            "owner_scope_ref must equal the authenticated principal on this bounded lane",
        ));
    }
    let manifest_ref = required_text(body, "skill_revision_ref")?;
    let manifest_hash = required_text(body, "skill_manifest_content_hash")?;
    require_sha256(&manifest_hash, "skill_manifest_content_hash")?;
    let Some(manifest) = find_owned_by(
        read_record_dir(&st.data_dir, MANIFEST_DIR),
        "revision_ref",
        &manifest_ref,
        "owner_ref",
        identity,
    ) else {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "skill_manifest_revision_not_found",
            "the exact owner-scoped SkillManifest revision does not exist",
        ));
    };
    if manifest["content_hash"] != manifest_hash {
        return Err(refuse(
            StatusCode::CONFLICT,
            "skill_manifest_hash_mismatch",
            "the manifest ref and hash do not identify the same immutable revision",
        ));
    }
    if manifest["registry_status"] != "released" {
        return Err(refuse(
            StatusCode::CONFLICT,
            "skill_manifest_not_released",
            "only a released manifest may back an active owner binding",
        ));
    }
    let compatibility_decision_ref = required_text(body, "compatibility_decision_ref")?;
    let mut material = json!({
        "schema_version": "ioi.skill-entry.v1",
        "skill_entry_id": format!("skill-entry://{entry_tail}"),
        "predecessor_binding_revision_ref": predecessor.and_then(|record| record.get("binding_revision_ref")).cloned().unwrap_or(Value::Null),
        "skill_revision_ref": manifest_ref,
        "skill_manifest_content_hash": manifest_hash,
        "owner_scope_ref": identity,
        "memory_space_ref": body.get("memory_space_ref").cloned().unwrap_or(Value::Null),
        "configuration_ref": body.get("configuration_ref").cloned().unwrap_or(Value::Null),
        "allowed_goal_run_profile_revision_refs": string_array(body, "allowed_goal_run_profile_revision_refs")?,
        "policy_refs": string_array(body, "policy_refs")?,
    });
    let binding_hash = hash(&material)?;
    material["binding_hash"] = json!(binding_hash);
    material["binding_revision_ref"] = json!(format!(
        "skill-entry://{entry_tail}/revision/{}",
        material["binding_hash"].as_str().unwrap_or("")
    ));
    material["compatibility_decision_ref"] = json!(compatibility_decision_ref);
    material["admitted_by_ref"] = json!(identity);
    material["admission_receipt_ref"] = json!(format!(
        "receipt://skill-entry-admission/{}",
        digest_tail(material["binding_hash"].as_str().unwrap_or(""))
    ));
    material["revocation_ref"] = body.get("revocation_ref").cloned().unwrap_or(Value::Null);
    material["registry_lifecycle_ref"] = Value::Null;
    material["registry_status"] = json!(entry_status(body)?);
    validate_contract("schema://ioi/foundations/skill-entry/v1", &material)?;
    Ok(material)
}

pub(crate) async fn create_skill_binding(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = SKILL_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let entry_tail = tail("skillentry");
    let record = match build_entry(&st, body, &identity, &entry_tail, None) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{entry_tail}--{}",
        digest_tail(record["binding_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, ENTRY_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "skill_entry": record }),
    )
}

pub(crate) async fn create_skill_binding_successor(
    State(st): State<Arc<DaemonState>>,
    AxumPath(entry_tail): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = SKILL_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry_id = format!("skill-entry://{entry_tail}");
    let revisions = read_record_dir(&st.data_dir, ENTRY_DIR)
        .into_iter()
        .filter(|record| {
            record["skill_entry_id"] == entry_id && record["owner_scope_ref"] == identity
        })
        .collect::<Vec<_>>();
    let Some(predecessor) = chain_head(
        &revisions,
        "binding_revision_ref",
        "predecessor_binding_revision_ref",
    ) else {
        return refuse(
            if revisions.is_empty() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            if revisions.is_empty() {
                "skill_entry_not_found"
            } else {
                "skill_entry_lineage_ambiguous"
            },
            "no single owner-scoped binding head is eligible for a successor",
        );
    };
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let record = match build_entry(&st, body, &identity, &entry_tail, Some(predecessor)) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let key = format!(
        "{entry_tail}--{}",
        digest_tail(record["binding_hash"].as_str().unwrap_or(""))
    );
    if let Err(reply) = store(&st, ENTRY_DIR, &key, &record) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "skill_entry": record }),
    )
}

pub(crate) async fn list_skill_bindings(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, ENTRY_DIR)
        .into_iter()
        .filter(|record| record["owner_scope_ref"] == identity)
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "skill_entries": records }),
    )
}

const SNAPSHOT_FIELDS: &[&str] = &[
    "work_subject_ref",
    "selected_skill_entry_revisions",
    "excluded_candidates",
    "compatibility_and_evaluation_result_refs",
    "resolved_runtime_tool_contracts",
    "context_lease_refs",
];

fn work_subject_ref(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
) -> Result<String, Reply> {
    let reference = required_text(body, "work_subject_ref")?;
    if !reference.starts_with("automation-run://") {
        return Err(refuse(
            StatusCode::NOT_IMPLEMENTED,
            "active_skill_set_subject_lane_unimplemented",
            "this bounded M04.3 lane currently resolves admitted automation-run:// subjects; other canonical subject kinds remain with their owner integrations",
        ));
    }
    let owned = read_record_dir(&st.data_dir, AUTOMATION_RUN_DIR)
        .into_iter()
        .any(|record| {
            record.get("automation_run_ref").and_then(Value::as_str) == Some(reference.as_str())
                && record
                    .pointer("/resolution_receipt/material/admitted_by_ref")
                    .and_then(Value::as_str)
                    == Some(identity)
        });
    if !owned {
        return Err(refuse(
            StatusCode::NOT_FOUND,
            "active_skill_set_work_subject_not_found",
            "the exact owner-scoped automation run does not exist",
        ));
    }
    Ok(reference)
}

pub(crate) struct GoalRunSkillResolution {
    pub(crate) bindings: Vec<Value>,
    pub(crate) runtime_tool_requirement_refs: Vec<String>,
}

fn strict_skill_records(
    data_dir: &str,
    family: &str,
    contract: &str,
) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    };
    let mut names =
        super::durable_fs::enumerate_pinned(&directory).map_err(|error| error.to_string())?;
    names.sort();
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        if !name.ends_with(".json") {
            return Err(format!(
                "unexpected canonical skill-registry occupant: {name}"
            ));
        }
        let bytes = super::durable_fs::read_slot_strict(&directory, &name)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("canonical skill-registry occupant vanished: {name}"))?
            .1;
        let record: Value = serde_json::from_slice(&bytes).map_err(|error| {
            format!("malformed canonical skill-registry occupant {name}: {error}")
        })?;
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            contract, &record,
        )
        .map_err(|error| {
            format!("contract-invalid canonical skill-registry occupant {name}: {error}")
        })?;
        let (identity_field, hash_field, revision_field, prefix, excluded) =
            if family == MANIFEST_DIR {
                (
                    "skill_id",
                    "content_hash",
                    "revision_ref",
                    "skill://",
                    &[
                        "content_hash",
                        "revision_ref",
                        "registry_lifecycle_ref",
                        "registry_status",
                    ][..],
                )
            } else {
                (
                    "skill_entry_id",
                    "binding_hash",
                    "binding_revision_ref",
                    "skill-entry://",
                    &[
                        "binding_hash",
                        "binding_revision_ref",
                        "compatibility_decision_ref",
                        "admitted_by_ref",
                        "admission_receipt_ref",
                        "revocation_ref",
                        "registry_lifecycle_ref",
                        "registry_status",
                    ][..],
                )
            };
        let identity = record
            .get(identity_field)
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix(prefix))
            .filter(|value| !value.is_empty() && !value.contains('/'))
            .ok_or_else(|| {
                format!("canonical skill-registry occupant {name} has an invalid identity")
            })?;
        let declared_hash = record
            .get(hash_field)
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix("sha256:"))
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
            .ok_or_else(|| {
                format!("canonical skill-registry occupant {name} has an invalid hash")
            })?;
        let mut hash_material = record.clone();
        let object = hash_material
            .as_object_mut()
            .ok_or_else(|| format!("canonical skill-registry occupant {name} is not an object"))?;
        for field in excluded {
            object.remove(*field);
        }
        let recomputed = serde_jcs::to_vec(&hash_material)
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
            .map_err(|error| {
                format!("canonical skill-registry occupant {name} is not canonicalizable: {error}")
            })?;
        if recomputed != declared_hash {
            return Err(format!(
                "canonical skill-registry occupant {name} does not reproduce its hash"
            ));
        }
        let expected_revision = format!("{prefix}{identity}/revision/sha256:{declared_hash}");
        if record.get(revision_field).and_then(Value::as_str) != Some(expected_revision.as_str()) {
            return Err(format!(
                "canonical skill-registry occupant {name} has a mismatched revision"
            ));
        }
        let expected_name = format!("{identity}--{declared_hash}.json");
        if name != expected_name {
            return Err(format!(
                "canonical skill-registry occupant {name} belongs at {expected_name}"
            ));
        }
        records.push(record);
    }
    Ok(records)
}

/// Resolve a GoalRunProfile's skill requirements through the canonical skill owner without
/// creating a snapshot or claiming execution. The GoalRun owner supplies the predetermined
/// subject/profile coordinates and freezes the returned exact binding/manifest closure.
pub(crate) fn resolve_goal_run_skills_strict(
    data_dir: &str,
    owner_ref: &str,
    profile_revision_ref: &str,
    requirement_refs: &[String],
    pinned_manifest_refs: &[String],
) -> Result<GoalRunSkillResolution, String> {
    if requirement_refs.is_empty() && pinned_manifest_refs.is_empty() {
        return Ok(GoalRunSkillResolution {
            bindings: Vec::new(),
            runtime_tool_requirement_refs: Vec::new(),
        });
    }
    let manifests = strict_skill_records(
        data_dir,
        MANIFEST_DIR,
        "schema://ioi/foundations/skill-manifest/v1",
    )?;
    let entries = strict_skill_records(
        data_dir,
        ENTRY_DIR,
        "schema://ioi/foundations/skill-entry/v1",
    )?;
    let owner_entries = entries
        .iter()
        .filter(|entry| entry.get("owner_scope_ref").and_then(Value::as_str) == Some(owner_ref))
        .collect::<Vec<_>>();
    let entry_ids = owner_entries
        .iter()
        .filter_map(|entry| entry.get("skill_entry_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let mut eligible = Vec::new();
    for entry_id in entry_ids {
        let lineage = owner_entries
            .iter()
            .filter(|entry| entry.get("skill_entry_id").and_then(Value::as_str) == Some(entry_id))
            .map(|entry| (*entry).clone())
            .collect::<Vec<_>>();
        let head = chain_head(
            &lineage,
            "binding_revision_ref",
            "predecessor_binding_revision_ref",
        )
        .ok_or_else(|| format!("skill binding {entry_id} has no single current head"))?;
        if head.get("registry_status").and_then(Value::as_str) != Some("active")
            || !head.get("revocation_ref").is_some_and(Value::is_null)
        {
            continue;
        }
        let allowed_profiles = head
            .get("allowed_goal_run_profile_revision_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("skill binding {entry_id} has no profile-compatibility set"))?;
        if !allowed_profiles.is_empty()
            && !allowed_profiles
                .iter()
                .any(|value| value.as_str() == Some(profile_revision_ref))
        {
            continue;
        }
        let manifest_ref = head
            .get("skill_revision_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("skill binding {entry_id} has no manifest revision"))?;
        let mut matches = manifests.iter().filter(|manifest| {
            manifest.get("revision_ref").and_then(Value::as_str) == Some(manifest_ref)
                && manifest.get("owner_ref").and_then(Value::as_str) == Some(owner_ref)
        });
        let manifest = matches
            .next()
            .ok_or_else(|| format!("skill binding {entry_id} has no exact owner manifest"))?;
        if matches.next().is_some() {
            return Err(format!(
                "skill binding {entry_id} has an ambiguous owner manifest"
            ));
        }
        if manifest.get("content_hash") != head.get("skill_manifest_content_hash")
            || manifest.get("registry_status").and_then(Value::as_str) != Some("released")
        {
            return Err(format!(
                "skill binding {entry_id} names an ineligible manifest"
            ));
        }
        eligible.push((head.clone(), manifest.clone()));
    }
    let mut selected: Vec<(Value, Value)> = Vec::new();
    let initial = if pinned_manifest_refs.is_empty() {
        requirement_refs
    } else {
        pinned_manifest_refs
    };
    for selection_ref in initial {
        let exact_revision = selection_ref.contains("/revision/");
        let mut matches = eligible.iter().filter(|(_, manifest)| {
            if exact_revision {
                manifest.get("revision_ref").and_then(Value::as_str) == Some(selection_ref.as_str())
            } else {
                manifest.get("skill_id").and_then(Value::as_str) == Some(selection_ref.as_str())
            }
        });
        let pair = matches.next().ok_or_else(|| {
            format!("skill requirement {selection_ref} has no eligible current binding")
        })?;
        if matches.next().is_some() {
            return Err(format!(
                "skill requirement {selection_ref} has more than one eligible binding"
            ));
        }
        if !selected.iter().any(|(entry, _)| {
            entry.get("binding_revision_ref") == pair.0.get("binding_revision_ref")
        }) {
            selected.push(pair.clone());
        }
    }
    if !pinned_manifest_refs.is_empty() {
        for requirement_ref in requirement_refs {
            let exact_revision = requirement_ref.contains("/revision/");
            if !selected.iter().any(|(_, manifest)| {
                let field = if exact_revision {
                    "revision_ref"
                } else {
                    "skill_id"
                };
                manifest.get(field).and_then(Value::as_str) == Some(requirement_ref.as_str())
            }) {
                return Err(format!(
                    "pinned skill manifests do not satisfy requirement {requirement_ref}"
                ));
            }
        }
    }
    let mut cursor = 0;
    while cursor < selected.len() {
        let dependencies = selected[cursor]
            .1
            .get("dependency_skill_revision_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| "selected skill manifest has no dependency set".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|reference| {
                        reference.starts_with("skill://") && reference.contains("/revision/")
                    })
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        "skill dependencies must name exact manifest revisions".to_string()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for dependency_ref in dependencies {
            if selected.iter().any(|(_, manifest)| {
                manifest.get("revision_ref").and_then(Value::as_str)
                    == Some(dependency_ref.as_str())
            }) {
                continue;
            }
            let mut matches = eligible.iter().filter(|(_, manifest)| {
                manifest.get("revision_ref").and_then(Value::as_str)
                    == Some(dependency_ref.as_str())
            });
            let pair = matches.next().ok_or_else(|| {
                format!("skill dependency {dependency_ref} has no eligible current binding")
            })?;
            if matches.next().is_some() {
                return Err(format!(
                    "skill dependency {dependency_ref} has more than one eligible binding"
                ));
            }
            selected.push(pair.clone());
        }
        cursor += 1;
    }
    selected.sort_by(|left, right| {
        left.0
            .get("binding_revision_ref")
            .and_then(Value::as_str)
            .cmp(&right.0.get("binding_revision_ref").and_then(Value::as_str))
    });
    let bindings = selected
        .iter()
        .map(|(entry, manifest)| {
            json!({
                "skill_entry_ref": entry.get("skill_entry_id"),
                "skill_entry_binding_revision_ref": entry.get("binding_revision_ref"),
                "skill_entry_binding_hash": entry.get("binding_hash"),
                "skill_manifest_revision_ref": manifest.get("revision_ref"),
                "skill_manifest_content_hash": manifest.get("content_hash"),
            })
        })
        .collect::<Vec<_>>();
    let mut runtime_tools = selected
        .iter()
        .flat_map(|(_, manifest)| {
            manifest
                .get("runtime_tool_contract_requirement_refs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    runtime_tools.sort();
    runtime_tools.dedup();
    Ok(GoalRunSkillResolution {
        bindings,
        runtime_tool_requirement_refs: runtime_tools,
    })
}

fn resolve_selected_skills(
    st: &DaemonState,
    body: &Map<String, Value>,
    identity: &str,
) -> Result<Vec<Value>, Reply> {
    let requested = body
        .get("selected_skill_entry_revisions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            refuse(
                StatusCode::BAD_REQUEST,
                "active_skill_set_selection_required",
                "selected_skill_entry_revisions must be an array",
            )
        })?;
    let entries = read_record_dir(&st.data_dir, ENTRY_DIR);
    let manifests = read_record_dir(&st.data_dir, MANIFEST_DIR);
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for request in requested {
        let request = object(request)?;
        ensure_allowed(
            request,
            &[
                "binding_revision_ref",
                "binding_hash",
                "inclusion_basis_refs",
            ],
        )?;
        let revision_ref = required_text(request, "binding_revision_ref")?;
        let binding_hash = required_text(request, "binding_hash")?;
        require_sha256(&binding_hash, "binding_hash")?;
        if !seen.insert(revision_ref.clone()) {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "active_skill_set_selection_duplicate",
                "a binding revision may be selected only once",
            ));
        }
        let Some(entry) = find_owned_by(
            entries.clone(),
            "binding_revision_ref",
            &revision_ref,
            "owner_scope_ref",
            identity,
        ) else {
            return Err(refuse(
                StatusCode::NOT_FOUND,
                "skill_entry_revision_not_found",
                "an exact owner-scoped SkillEntry revision does not exist",
            ));
        };
        if entry["binding_hash"] != binding_hash {
            return Err(refuse(
                StatusCode::CONFLICT,
                "skill_entry_hash_mismatch",
                "the binding ref and hash do not identify the same immutable revision",
            ));
        }
        let entry_id = entry["skill_entry_id"].as_str().unwrap_or("");
        let lineage = entries
            .iter()
            .filter(|candidate| {
                candidate["skill_entry_id"] == entry_id && candidate["owner_scope_ref"] == identity
            })
            .cloned()
            .collect::<Vec<_>>();
        if chain_head(
            &lineage,
            "binding_revision_ref",
            "predecessor_binding_revision_ref",
        )
        .and_then(|head| head["binding_revision_ref"].as_str())
            != Some(revision_ref.as_str())
        {
            return Err(refuse(
                StatusCode::CONFLICT,
                "skill_entry_superseded",
                "only the single current binding head may enter a new snapshot",
            ));
        }
        if entry["registry_status"] != "active" || !entry["revocation_ref"].is_null() {
            return Err(refuse(
                StatusCode::CONFLICT,
                "skill_entry_ineligible",
                "a selected binding must be active and unrevoked",
            ));
        }
        let manifest_ref = entry["skill_revision_ref"].as_str().unwrap_or("");
        let Some(manifest) = find_owned_by(
            manifests.clone(),
            "revision_ref",
            manifest_ref,
            "owner_ref",
            identity,
        ) else {
            return Err(refuse(
                StatusCode::CONFLICT,
                "skill_manifest_revision_missing",
                "the binding's exact manifest is no longer resolvable",
            ));
        };
        if manifest["content_hash"] != entry["skill_manifest_content_hash"]
            || manifest["registry_status"] != "released"
        {
            return Err(refuse(
                StatusCode::CONFLICT,
                "skill_manifest_ineligible",
                "the exact manifest is mismatched or not released",
            ));
        }
        selected.push(json!({
            "skill_entry_ref": entry["skill_entry_id"],
            "skill_entry_binding_revision_ref": revision_ref,
            "skill_entry_binding_hash": binding_hash,
            "skill_revision_ref": manifest_ref,
            "manifest_content_hash": entry["skill_manifest_content_hash"],
            "inclusion_basis_refs": string_array(request, "inclusion_basis_refs")?,
        }));
    }
    selected.sort_by(|left, right| {
        left["skill_entry_binding_revision_ref"]
            .as_str()
            .cmp(&right["skill_entry_binding_revision_ref"].as_str())
    });
    Ok(selected)
}

fn typed_object_array(body: &Map<String, Value>, key: &str) -> Result<Vec<Value>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    value.as_array().cloned().ok_or_else(|| {
        refuse(
            StatusCode::BAD_REQUEST,
            "skill_contract_array_invalid",
            format!("{key} must be an array"),
        )
    })
}

pub(crate) async fn create_active_skill_set_snapshot(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let _mutation = SKILL_CONTRACT_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let body = match object(&body) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    if let Err(reply) = ensure_allowed(body, SNAPSHOT_FIELDS) {
        return reply;
    }
    let selected_skills = match resolve_selected_skills(&st, body, &identity) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let mut excluded_candidates = match typed_object_array(body, "excluded_candidates") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    excluded_candidates.sort_by(|left, right| {
        left.get("candidate_ref")
            .and_then(Value::as_str)
            .cmp(&right.get("candidate_ref").and_then(Value::as_str))
    });
    let mut resolved_tools = match typed_object_array(body, "resolved_runtime_tool_contracts") {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    resolved_tools.sort_by(|left, right| {
        left.get("revision_ref")
            .and_then(Value::as_str)
            .cmp(&right.get("revision_ref").and_then(Value::as_str))
    });
    let subject_ref = match work_subject_ref(&st, body, &identity) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let set_material = json!({
        "domain": "ioi.active-skill-set-jcs-sha256.v1",
        "work_subject_ref": subject_ref,
        "selected_skills": selected_skills,
        "excluded_candidates": excluded_candidates,
        "compatibility_and_evaluation_result_refs": match string_array(body, "compatibility_and_evaluation_result_refs") { Ok(value) => value, Err(reply) => return reply },
        "resolved_runtime_tool_contracts": resolved_tools,
        "context_lease_refs": match string_array(body, "context_lease_refs") { Ok(value) => value, Err(reply) => return reply },
    });
    let active_set_hash = match hash(&set_material) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let snapshot_id = format!("active-skill-set://snapshot/{active_set_hash}");
    let receipt_material = json!({
        "domain": "ioi.active-skill-set-resolution-receipt-jcs-sha256.v1",
        "active_skill_set_snapshot_id": snapshot_id,
        "active_set_hash": active_set_hash,
        "work_subject_ref": set_material["work_subject_ref"],
        "resolved_by_ref": identity,
    });
    let receipt_hash = match hash(&receipt_material) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let receipt_ref = format!(
        "receipt://active-skill-set-resolution/{}",
        digest_tail(&receipt_hash)
    );
    let record = json!({
        "schema_version": "ioi.active-skill-set-snapshot.v1",
        "active_skill_set_snapshot_id": receipt_material["active_skill_set_snapshot_id"],
        "work_subject_ref": set_material["work_subject_ref"],
        "selected_skills": set_material["selected_skills"],
        "excluded_candidates": set_material["excluded_candidates"],
        "compatibility_and_evaluation_result_refs": set_material["compatibility_and_evaluation_result_refs"],
        "active_set_hash": receipt_material["active_set_hash"],
        "resolved_runtime_tool_contracts": set_material["resolved_runtime_tool_contracts"],
        "context_lease_refs": set_material["context_lease_refs"],
        "resolution_receipt_ref": receipt_ref,
        "registry_lifecycle_ref": null,
        "registry_status": "admitted",
    });
    if let Err(reply) = validate_contract(
        "schema://ioi/foundations/active-skill-set-snapshot/v1",
        &record,
    ) {
        return reply;
    }
    let receipt = json!({
        "schema_version": "ioi.active-skill-set-resolution-receipt.v1",
        "receipt_ref": record["resolution_receipt_ref"],
        "receipt_hash": receipt_hash,
        "material": receipt_material,
    });
    let key = digest_tail(record["active_set_hash"].as_str().unwrap_or(""));
    // Receipt first makes a process death recoverable: a retry accepts the exact deterministic
    // receipt, then admits the snapshot. A response-loss retry accepts both byte-identical records.
    if let Err(reply) =
        store_exact_or_replay(&st, RESOLUTION_RECEIPT_DIR, key, "receipt_ref", &receipt)
    {
        return reply;
    }
    if let Err(reply) = store_exact_or_replay(
        &st,
        SNAPSHOT_DIR,
        key,
        "active_skill_set_snapshot_id",
        &record,
    ) {
        return reply;
    }
    reply(
        StatusCode::CREATED,
        json!({ "ok": true, "active_skill_set_snapshot": record, "resolution_receipt": receipt }),
    )
}

fn receipt_owner(st: &DaemonState, snapshot: &Value) -> Option<String> {
    let receipt_ref = snapshot.get("resolution_receipt_ref")?.as_str()?;
    read_record_dir(&st.data_dir, RESOLUTION_RECEIPT_DIR)
        .into_iter()
        .find(|receipt| receipt.get("receipt_ref").and_then(Value::as_str) == Some(receipt_ref))
        .and_then(|receipt| {
            receipt
                .pointer("/material/resolved_by_ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

pub(crate) async fn list_active_skill_set_snapshots(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&st.data_dir, SNAPSHOT_DIR)
        .into_iter()
        .filter(|record| receipt_owner(&st, record).as_deref() == Some(identity.as_str()))
        .collect::<Vec<_>>();
    reply(
        StatusCode::OK,
        json!({ "ok": true, "active_skill_set_snapshots": records }),
    )
}

pub(crate) async fn get_active_skill_set_snapshot(
    State(st): State<Arc<DaemonState>>,
    AxumPath(snapshot_hash): AxumPath<String>,
    headers: HeaderMap,
) -> Reply {
    let identity = match identity_or_refusal(&st, &headers) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let snapshot_id = format!("active-skill-set://snapshot/sha256:{snapshot_hash}");
    match read_record_dir(&st.data_dir, SNAPSHOT_DIR)
        .into_iter()
        .find(|record| {
            record["active_skill_set_snapshot_id"] == snapshot_id
                && receipt_owner(&st, record).as_deref() == Some(identity.as_str())
        }) {
        Some(record) => reply(
            StatusCode::OK,
            json!({ "ok": true, "active_skill_set_snapshot": record }),
        ),
        None => refuse(
            StatusCode::NOT_FOUND,
            "active_skill_set_snapshot_not_found",
            "no owner-scoped active skill-set snapshot has that id",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forked_binding_lineage_has_no_guessable_head() {
        let first = "skill-entry://test/revision/sha256:first";
        let records = vec![
            json!({"binding_revision_ref":first,"predecessor_binding_revision_ref":null}),
            json!({"binding_revision_ref":"skill-entry://test/revision/sha256:second","predecessor_binding_revision_ref":first}),
            json!({"binding_revision_ref":"skill-entry://test/revision/sha256:third","predecessor_binding_revision_ref":first}),
        ];
        assert!(chain_head(
            &records,
            "binding_revision_ref",
            "predecessor_binding_revision_ref"
        )
        .is_none());
    }

    #[test]
    fn owner_scoped_resolution_refuses_a_foreign_manifest() {
        let record =
            json!({"revision_ref":"skill://test/revision/sha256:exact","owner_ref":"user://a"});
        assert!(find_owned_by(
            vec![record],
            "revision_ref",
            "skill://test/revision/sha256:exact",
            "owner_ref",
            "user://b"
        )
        .is_none());
    }
}
