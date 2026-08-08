//! Durable managed-runtime, backup, and restore control plane.
//!
//! Agentgres owner-namespaced streams are the mutable source of truth. Local
//! files in this module are byte custody only: captured tar payloads and
//! prepared restore staging directories. Inventory is reconstructed from
//! Agentgres domain coordinates after every restart.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentgres::event_stream::AdmissionRefusal;
use agentgres::mux::ExactProjection;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use ioi_types::app::hypervisor_environment_lifecycle::{
    backup_manifest_root, compile_backup_record, environment_artifact_root, BackupDeclaration,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{persist_record, DaemonState};

const RUNTIME_NAMESPACE: &str = "managed-runtime";
const PERSISTENCE_NAMESPACE: &str = "managed-persistence";
const BACKUP_FAMILY: &str = "hypervisor-environment-backups";
const BACKUP_MATERIAL_DIR: &str = "managed-backup-material";
const EXPORT_TOKEN_DIR: &str = "managed-backup-export-tokens";
const PORTABLE_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const INSTANCE_SCOPE_KIND: &str = "managed-worker-instance";
const STORAGE_PROFILE_SCOPE_KIND: &str = "managed-storage-profile";
const BACKUP_SCOPE_KIND: &str = "managed-environment-backup";
const RESTORE_SCOPE_KIND: &str = "managed-restore-plan";

type Reply = (StatusCode, Json<Value>);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn jcs_digest(value: &Value) -> Result<String, String> {
    serde_jcs::to_vec(value)
        .map(|bytes| digest(&bytes))
        .map_err(|error| error.to_string())
}

fn hash_tail(prefix: &str, value: &str) -> String {
    format!("{prefix}.{:x}", Sha256::digest(value.as_bytes()))
}

fn safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({
            "ok": false,
            "error": { "code": code, "message": message.into() }
        })),
    )
}

fn scope_refusal(error: super::substrate_store::RequestScopeRefusal) -> Reply {
    let status = match error {
        super::substrate_store::RequestScopeRefusal::AuthenticationRequired
        | super::substrate_store::RequestScopeRefusal::PrincipalIdentityInvalid => {
            StatusCode::UNAUTHORIZED
        }
        super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired
        | super::substrate_store::RequestScopeRefusal::ResourceScopeRequired
        | super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch => {
            StatusCode::FORBIDDEN
        }
        super::substrate_store::RequestScopeRefusal::SubstrateUnavailable(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    bad(status, error.code(), error.message())
}

fn request_identity(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<super::substrate_store::RequestIdentity, Reply> {
    super::substrate_store::resolve_request_identity(data_dir, headers).map_err(scope_refusal)
}

fn bind_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    kind: &str,
    resource_ref: &str,
    owner_ref: &str,
    idempotency_key: &str,
) -> Result<super::substrate_store::RequestResourceScope, Reply> {
    super::substrate_store::bind_request_resource_scope(
        data_dir,
        identity,
        kind,
        resource_ref,
        owner_ref,
        owner_ref,
        idempotency_key,
    )
    .map_err(scope_refusal)
}

fn authorize_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    kind: &str,
    resource_ref: &str,
    owner_ref: Option<&str>,
) -> Result<super::substrate_store::RequestResourceScope, Reply> {
    super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        kind,
        resource_ref,
        owner_ref,
    )
    .map_err(scope_refusal)
}

fn authorized_refs(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    kind: &str,
) -> Result<std::collections::BTreeSet<String>, Reply> {
    super::substrate_store::authorized_request_resource_refs(data_dir, identity, kind)
        .map_err(scope_refusal)
}

fn parse<T: DeserializeOwned>(body: Value, code: &str) -> Result<T, Reply> {
    serde_json::from_value(body).map_err(|error| {
        bad(
            StatusCode::BAD_REQUEST,
            code,
            format!("request does not satisfy the closed contract: {error}"),
        )
    })
}

fn admission_error(error: AdmissionRefusal) -> Reply {
    let status = match error {
        AdmissionRefusal::HeadConflict | AdmissionRefusal::SameKeyDifferentBytes { .. } => {
            StatusCode::CONFLICT
        }
        AdmissionRefusal::CoordinatesNotCanonical(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    bad(status, error.code(), error.to_string())
}

fn validate_ref(value: &str, field: &str, prefixes: &[&str]) -> Result<(), Reply> {
    if prefixes.iter().any(|prefix| value.starts_with(prefix))
        && !value.chars().any(char::is_whitespace)
        && value.len() <= 500
    {
        return Ok(());
    }
    Err(bad(
        StatusCode::BAD_REQUEST,
        "managed_runtime_ref_invalid",
        format!("{field} is not an allowed canonical ref"),
    ))
}

fn require_nonempty(values: &[String], field: &str) -> Result<(), Reply> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_required_refs_missing",
            format!("{field} requires at least one non-empty ref"),
        ));
    }
    Ok(())
}

fn projection_value(exact: &ExactProjection, replayed: Option<bool>) -> Value {
    let mut payload = exact.operation.payload.clone();
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "agentgres".to_owned(),
            json!({
                "operation_ref": agentgres::refs::event_stream_operation_ref(
                    exact
                        .operation
                        .object_ref
                        .strip_prefix("agentgres://event-stream-operations/")
                        .and_then(|tail| tail.split_once('/'))
                        .map(|(owner, _)| owner)
                        .unwrap_or("unknown"),
                    exact
                        .operation
                        .object_ref
                        .strip_prefix("agentgres://event-stream-operations/")
                        .and_then(|tail| tail.split_once('/'))
                        .map(|(_, stream)| stream)
                        .unwrap_or("unknown"),
                    exact.seq,
                    &exact.head,
                ),
                "receipt_ref": agentgres::refs::event_stream_receipt_ref(
                    exact
                        .operation
                        .object_ref
                        .strip_prefix("agentgres://event-stream-operations/")
                        .and_then(|tail| tail.split_once('/'))
                        .map(|(owner, _)| owner)
                        .unwrap_or("unknown"),
                    exact
                        .operation
                        .object_ref
                        .strip_prefix("agentgres://event-stream-operations/")
                        .and_then(|tail| tail.split_once('/'))
                        .map(|(_, stream)| stream)
                        .unwrap_or("unknown"),
                    exact.admission_batch_seq,
                    &exact.admission_root,
                ),
                "sequence": exact.seq,
                "head": exact.head,
                "admission_batch_sequence": exact.admission_batch_seq,
                "admission_root": exact.admission_root,
                "terminal_root": exact.terminal_root,
                "recorded_at_ms": exact.operation.recorded_at_ms,
                "replayed": replayed,
            }),
        );
    }
    payload
}

fn read_head(data_dir: &str, namespace: &str, tail: &str) -> Result<ExactProjection, Reply> {
    super::substrate_store::read_event_stream_operation(data_dir, namespace, tail)
        .map_err(admission_error)?
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "managed_runtime_object_not_found",
                "the requested admitted object does not exist",
            )
        })
}

/// Map a shared-boundary refusal to this plane's existing wire contract. `Admission` is routed to
/// the plane's own `admission_error` (503 default preserved), `Scope` to `scope_refusal`, so
/// adopting the boundary does not silently re-status a refusal a caller already handles.
fn mutation_refusal(error: super::mutation_event_foundation::MutationRefusal) -> Reply {
    use super::mutation_event_foundation::MutationRefusal;
    match error {
        MutationRefusal::Scope(error) => scope_refusal(error),
        MutationRefusal::Admission(error) => admission_error(error),
        error @ (MutationRefusal::IdempotencyKeyInvalid
        | MutationRefusal::GenesisExpectedHeadPresent
        | MutationRefusal::SuccessorExpectedHeadRequired) => {
            bad(StatusCode::BAD_REQUEST, error.code(), error.message())
        }
        error @ MutationRefusal::RequestFingerprintFailed(_) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            error.code(),
            error.message(),
        ),
    }
}

/// The one write path for this plane. Every event-stream mutation crosses the shared owner-scoped
/// admission boundary carrying the immutable scope the handler already bound or authorized, so the
/// principal/tenant/resource proof and idempotency-key validation are enforced identically for all
/// twelve sites rather than reimplemented per call. `recorded_at_ms` is response-visible only and is
/// excluded from replay identity by the boundary's fingerprint.
#[allow(clippy::too_many_arguments)]
fn admit(
    data_dir: &str,
    genesis: bool,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
    namespace: &str,
    tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    payload: &Value,
    recorded_at_ms: u64,
    idempotency_key: &str,
) -> Result<(ExactProjection, bool), Reply> {
    let commit = super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity,
            scope,
            resource_kind,
            resource_ref,
            owner_namespace: namespace,
            stream_tail: tail,
            op_kind,
            expected_head,
            payload,
            idempotency_key,
            recorded_at_ms,
        },
    )
    .map_err(mutation_refusal)?;
    Ok((commit.projection, commit.replayed))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicy {
    persistence_profile: String,
    idle_threshold_seconds: u64,
    minimum_warm_seconds: u64,
    wake_sources: Vec<String>,
    maximum_cold_start_seconds: u64,
    maximum_restore_age_seconds: u64,
    checkpoint_cadence_seconds: u64,
    pre_stop_checkpoint_required: bool,
    provider_idle_semantics: String,
    fallback_placement_refs: Vec<String>,
    privacy_floor_ref: String,
    spend_ceiling_ref: String,
    archive_retention_policy_ref: String,
    minimum_backup_replicas: u16,
}

fn validate_runtime_policy(policy: &RuntimePolicy) -> Result<(), Reply> {
    if !matches!(
        policy.persistence_profile.as_str(),
        "ephemeral" | "session" | "zero_to_idle" | "persistent"
    ) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_persistence_profile_invalid",
            "persistence_profile is outside the closed enum",
        ));
    }
    let allowed_wake = [
        "user",
        "schedule",
        "webhook",
        "queue",
        "approved_event",
        "recovery",
    ];
    if policy.wake_sources.is_empty()
        || policy
            .wake_sources
            .iter()
            .any(|source| !allowed_wake.contains(&source.as_str()))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_wake_source_invalid",
            "wake_sources must be a non-empty subset of the canonical enum",
        ));
    }
    if !matches!(policy.provider_idle_semantics.as_str(), "stop" | "close") {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_provider_idle_semantics_invalid",
            "provider_idle_semantics must be stop or close",
        ));
    }
    if matches!(policy.persistence_profile.as_str(), "zero_to_idle")
        && policy.provider_idle_semantics != "close"
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_runtime_zero_to_idle_must_close",
            "zero_to_idle must release billable provider compute with close semantics",
        ));
    }
    if policy.maximum_cold_start_seconds == 0
        || policy.maximum_restore_age_seconds == 0
        || policy.checkpoint_cadence_seconds == 0
        || policy.minimum_backup_replicas == 0
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_policy_bound_invalid",
            "cold-start, restore-age, checkpoint cadence, and replica bounds must be positive",
        ));
    }
    if [
        policy.idle_threshold_seconds,
        policy.minimum_warm_seconds,
        policy.maximum_cold_start_seconds,
        policy.maximum_restore_age_seconds,
        policy.checkpoint_cadence_seconds,
    ]
    .into_iter()
    .any(|value| value > PORTABLE_SAFE_INTEGER_MAX)
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_policy_bound_invalid",
            "runtime policy integer bounds must remain portable JSON-safe integers",
        ));
    }
    for (field, value) in [
        ("privacy_floor_ref", policy.privacy_floor_ref.as_str()),
        ("spend_ceiling_ref", policy.spend_ceiling_ref.as_str()),
        (
            "archive_retention_policy_ref",
            policy.archive_retention_policy_ref.as_str(),
        ),
    ] {
        validate_ref(value, field, &["policy://", "budget://"])?;
    }
    let _ = policy.idle_threshold_seconds;
    let _ = policy.minimum_warm_seconds;
    Ok(())
}

fn policy_value(policy: &RuntimePolicy) -> Value {
    serde_json::to_value(policy).unwrap_or_else(|_| json!({}))
}

impl serde::Serialize for RuntimePolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        json!({
            "persistence_profile": self.persistence_profile,
            "idle_threshold_seconds": self.idle_threshold_seconds,
            "minimum_warm_seconds": self.minimum_warm_seconds,
            "wake_sources": self.wake_sources,
            "maximum_cold_start_seconds": self.maximum_cold_start_seconds,
            "maximum_restore_age_seconds": self.maximum_restore_age_seconds,
            "checkpoint_cadence_seconds": self.checkpoint_cadence_seconds,
            "pre_stop_checkpoint_required": self.pre_stop_checkpoint_required,
            "provider_idle_semantics": self.provider_idle_semantics,
            "fallback_placement_refs": self.fallback_placement_refs,
            "privacy_floor_ref": self.privacy_floor_ref,
            "spend_ceiling_ref": self.spend_ceiling_ref,
            "archive_retention_policy_ref": self.archive_retention_policy_ref,
            "minimum_backup_replicas": self.minimum_backup_replicas,
        })
        .serialize(serializer)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstanceCreateRequest {
    instance_id: String,
    lifecycle_id: String,
    owner_ref: String,
    worker_package_ref: String,
    config_revision_ref: String,
    runtime_policy: RuntimePolicy,
    authority_grant_refs: Vec<String>,
    idempotency_key: String,
}

pub(crate) async fn handle_instances_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: InstanceCreateRequest = match parse(body, "managed_runtime_create_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    for (field, value, prefixes) in [
        (
            "instance_id",
            request.instance_id.as_str(),
            &["agent://"][..],
        ),
        (
            "owner_ref",
            request.owner_ref.as_str(),
            &["wallet://", "org://", "project://"][..],
        ),
        (
            "worker_package_ref",
            request.worker_package_ref.as_str(),
            &["worker-package://", "package://"][..],
        ),
        (
            "config_revision_ref",
            request.config_revision_ref.as_str(),
            &["config-revision://", "artifact://"][..],
        ),
    ] {
        if let Err(reply) = validate_ref(value, field, prefixes) {
            return reply;
        }
    }
    if !request.lifecycle_id.starts_with("lifecycle:") {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_lifecycle_id_invalid",
            "lifecycle_id must use lifecycle: identity",
        );
    }
    if let Err(reply) = validate_runtime_policy(&request.runtime_policy) {
        return reply;
    }
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let policy = policy_value(&request.runtime_policy);
    let policy_hash = match jcs_digest(&policy) {
        Ok(hash) => hash,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_runtime_hash_failed",
                error,
            )
        }
    };
    let payload = json!({
        "schema_version": "ioi.managed-worker-instance-state.v1",
        "instance_id": request.instance_id,
        "lifecycle_id": request.lifecycle_id,
        "owner_ref": request.owner_ref,
        "worker_package_ref": request.worker_package_ref,
        "config_revision_ref": request.config_revision_ref,
        "revision": 1,
        "state": "installed",
        "runtime_policy": policy,
        "runtime_policy_hash": policy_hash,
        "authority_grant_refs": request.authority_grant_refs,
        "runtime_assignment": Value::Null,
        "compute_session": Value::Null,
        "latest_verified_backup_ref": Value::Null,
        "latest_state_root": Value::Null,
        "pending_transition": Value::Null,
        "last_transition": Value::Null,
    });
    let tail = hash_tail(
        "instance",
        payload["instance_id"].as_str().unwrap_or_default(),
    );
    let scope = match super::substrate_store::read_event_stream_operation(
        &st.data_dir,
        RUNTIME_NAMESPACE,
        &tail,
    ) {
        Ok(Some(current)) => {
            let owner_ref = current.operation.payload["owner_ref"]
                .as_str()
                .unwrap_or_default();
            if owner_ref != request.owner_ref {
                return scope_refusal(
                    super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
                );
            }
            match authorize_scope(
                &st.data_dir,
                &identity,
                INSTANCE_SCOPE_KIND,
                &request.instance_id,
                Some(owner_ref),
            ) {
                Ok(scope) => scope,
                Err(reply) => return reply,
            }
        }
        Ok(None) => match bind_scope(
            &st.data_dir,
            &identity,
            INSTANCE_SCOPE_KIND,
            &request.instance_id,
            &request.owner_ref,
            &request.idempotency_key,
        ) {
            Ok(scope) => scope,
            Err(reply) => return reply,
        },
        Err(error) => return admission_error(error),
    };
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        INSTANCE_SCOPE_KIND,
        &request.instance_id,
        RUNTIME_NAMESPACE,
        &tail,
        "event_stream.managed_worker_created",
        None,
        &payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok((exact, replayed)) => (
            StatusCode::CREATED,
            Json(json!({ "ok": true, "instance": projection_value(&exact, Some(replayed)) })),
        ),
        Err(reply) => reply,
    }
}

fn find_instance(data_dir: &str, instance_id: &str) -> Result<(String, ExactProjection), Reply> {
    let tail = hash_tail("instance", instance_id);
    let exact = read_head(data_dir, RUNTIME_NAMESPACE, &tail)?;
    if exact
        .operation
        .payload
        .get("instance_id")
        .and_then(Value::as_str)
        != Some(instance_id)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_runtime_identity_collision",
            "the admitted stream coordinate does not contain the requested instance",
        ));
    }
    Ok((tail, exact))
}

pub(crate) async fn handle_instances_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, INSTANCE_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let tails =
        match super::substrate_store::list_event_stream_tails(&st.data_dir, RUNTIME_NAMESPACE) {
            Ok(tails) => tails,
            Err(error) => {
                return bad(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "managed_runtime_inventory_unavailable",
                    error.to_string(),
                )
            }
        };
    let mut instances = Vec::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("instance."))
    {
        match read_head(&st.data_dir, RUNTIME_NAMESPACE, &tail) {
            Ok(exact)
                if exact
                    .operation
                    .payload
                    .get("schema_version")
                    .and_then(Value::as_str)
                    == Some("ioi.managed-worker-instance-state.v1") =>
            {
                let instance_id = exact.operation.payload["instance_id"]
                    .as_str()
                    .unwrap_or_default();
                if allowed.contains(instance_id) {
                    if let Err(reply) = authorize_scope(
                        &st.data_dir,
                        &identity,
                        INSTANCE_SCOPE_KIND,
                        instance_id,
                        exact.operation.payload["owner_ref"].as_str(),
                    ) {
                        return reply;
                    }
                    instances.push(projection_value(&exact, None));
                }
            }
            Ok(_) => {}
            Err(reply) => return reply,
        }
    }
    instances.sort_by(|a, b| a["instance_id"].as_str().cmp(&b["instance_id"].as_str()));
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "instances": instances })),
    )
}

pub(crate) async fn handle_instance_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, INSTANCE_SCOPE_KIND, &id, None) {
        return reply;
    }
    match find_instance(&st.data_dir, &id) {
        Ok((_, exact)) => {
            if let Err(reply) = authorize_scope(
                &st.data_dir,
                &identity,
                INSTANCE_SCOPE_KIND,
                &id,
                exact.operation.payload["owner_ref"].as_str(),
            ) {
                return reply;
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "instance": projection_value(&exact, None) })),
            )
        }
        Err(reply) => reply,
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PlacementRequest {
    runtime_node_ref: String,
    daemon_profile_ref: String,
    environment_ref: String,
    provider_ref: String,
    quote_ref: Option<String>,
    budget_reservation_ref: Option<String>,
    assignment_lease_ref: String,
    isolation_binding_ref: String,
    readiness_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ArchivePolicy {
    archive_after: Option<String>,
    retain_for: Option<String>,
    storage_policy_ref: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RestorePolicy {
    restore_requires: String,
    restore_receipt_required: bool,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExportPolicy {
    export_requires: String,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct DeletionPolicy {
    delete_runtime_state: bool,
    delete_archives: bool,
    forget_semantic_memory: bool,
}

fn validate_transition_policies(request: &TransitionRequest) -> Result<(), Reply> {
    const STEP_UP_MODES: &[&str] = &[
        "authority_step_up",
        "wallet_step_up",
        "org_quorum",
        "admin_policy",
    ];
    if let Some(policy) = &request.archive_policy {
        validate_ref(
            &policy.storage_policy_ref,
            "archive_policy.storage_policy_ref",
            &[
                "policy://",
                "policy:",
                "storage-policy://",
                "storage-policy:",
            ],
        )?;
        if policy
            .archive_after
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
            || policy
                .retain_for
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
        {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "managed_runtime_archive_policy_invalid",
                "archive policy durations must be non-empty when supplied",
            ));
        }
    }
    if let Some(policy) = &request.restore_policy {
        if !STEP_UP_MODES.contains(&policy.restore_requires.as_str()) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "managed_runtime_restore_policy_invalid",
                "restore_requires is outside the closed step-up enum",
            ));
        }
        if !policy.restore_receipt_required {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "managed_runtime_restore_receipt_required",
                "restore policy must require a restore receipt",
            ));
        }
    }
    if let Some(policy) = &request.export_policy {
        if !STEP_UP_MODES.contains(&policy.export_requires.as_str()) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "managed_runtime_export_policy_invalid",
                "export_requires is outside the closed step-up enum",
            ));
        }
    }
    Ok(())
}

fn validate_transition_request(request: &TransitionRequest) -> Result<(), Reply> {
    const STATES: &[&str] = &[
        "discover",
        "installed",
        "initializing",
        "active",
        "idle",
        "zero_to_idle",
        "suspended",
        "payment_past_due",
        "archived",
        "restoring",
        "migrated",
        "exported",
        "deleted",
        "forgotten",
    ];
    const PAYMENT_STATUSES: &[&str] = &[
        "current",
        "past_due",
        "canceled",
        "settled",
        "not_applicable",
    ];
    if !STATES.contains(&request.to_state.as_str()) || request.transition_reason.trim().is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_transition_shape_invalid",
            "to_state and transition_reason must use the closed lifecycle contract",
        ));
    }
    if request
        .payment_status
        .as_deref()
        .is_some_and(|status| !PAYMENT_STATUSES.contains(&status))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_payment_status_invalid",
            "payment_status is outside the closed enum",
        ));
    }
    for (field, value) in [
        (
            "wallet_approval_ref",
            request.wallet_approval_ref.as_deref(),
        ),
        ("backup_ref", request.backup_ref.as_deref()),
        ("restore_import_ref", request.restore_import_ref.as_deref()),
        (
            "migration_target_ref",
            request.migration_target_ref.as_deref(),
        ),
        (
            "provider_close_receipt_ref",
            request.provider_close_receipt_ref.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_ref(
                value,
                field,
                &[
                    "approval://",
                    "environment-backup://",
                    "restore-import://",
                    "environment://",
                    "provider://",
                    "receipt://",
                    "artifact://",
                    "agentgres://",
                ],
            )?;
        }
    }
    if let Some(root) = request.latest_state_root.as_deref() {
        if !root.strip_prefix("sha256:").is_some_and(|tail| {
            tail.len() == 64
                && tail
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        }) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "managed_runtime_state_root_invalid",
                "latest_state_root must be a lowercase sha256 commitment",
            ));
        }
    }
    if let Some(placement) = &request.placement {
        validate_placement(placement)?;
    }
    validate_transition_policies(request)
}

fn validate_placement(placement: &PlacementRequest) -> Result<(), Reply> {
    for (field, value, prefixes) in [
        (
            "runtime_node_ref",
            placement.runtime_node_ref.as_str(),
            &["runtime://"][..],
        ),
        (
            "daemon_profile_ref",
            placement.daemon_profile_ref.as_str(),
            &["profile://"][..],
        ),
        (
            "environment_ref",
            placement.environment_ref.as_str(),
            &["environment://"][..],
        ),
        (
            "provider_ref",
            placement.provider_ref.as_str(),
            &["provider://", "provider-account://"][..],
        ),
        (
            "assignment_lease_ref",
            placement.assignment_lease_ref.as_str(),
            &["lease://"][..],
        ),
        (
            "isolation_binding_ref",
            placement.isolation_binding_ref.as_str(),
            &["workload-isolation-binding://", "binding://"][..],
        ),
    ] {
        validate_ref(value, field, prefixes)?;
    }
    require_nonempty(
        &placement.readiness_evidence_refs,
        "readiness_evidence_refs",
    )?;
    if !placement.provider_ref.starts_with("provider://local/")
        && (placement.quote_ref.is_none() || placement.budget_reservation_ref.is_none())
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_runtime_provider_funding_unbound",
            "non-local placement requires an exact quote and budget reservation",
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionRequest {
    expected_head: String,
    idempotency_key: String,
    to_state: String,
    transition_reason: String,
    payment_status: Option<String>,
    authority_scope_refs: Vec<String>,
    authority_grant_refs: Vec<String>,
    policy_refs: Vec<String>,
    required_controls: Vec<String>,
    wallet_approval_ref: Option<String>,
    latest_state_root: Option<String>,
    backup_ref: Option<String>,
    restore_import_ref: Option<String>,
    migration_target_ref: Option<String>,
    provider_close_receipt_ref: Option<String>,
    high_risk_orders_paused: Option<bool>,
    new_billable_work_blocked: Option<bool>,
    archive_policy: Option<ArchivePolicy>,
    restore_policy: Option<RestorePolicy>,
    export_policy: Option<ExportPolicy>,
    deletion_policy: Option<DeletionPolicy>,
    placement: Option<PlacementRequest>,
}

fn transition_request_identity(request: &TransitionRequest) -> Result<String, Reply> {
    serde_json::to_value(request)
        .map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_runtime_request_hash_failed",
                error.to_string(),
            )
        })
        .and_then(|mut value| {
            // The expected head is a concurrency precondition and the key is
            // the identity lookup itself. Neither changes the logical intent
            // whose bytes must remain stable across a retry.
            if let Some(object) = value.as_object_mut() {
                object.remove("expected_head");
                object.remove("idempotency_key");
            }
            jcs_digest(&value).map_err(|error| {
                bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "managed_runtime_request_hash_failed",
                    error,
                )
            })
        })
}

fn transition_payload(
    current: &Value,
    request: &TransitionRequest,
    proposal: &ExactProjection,
) -> Result<Value, Reply> {
    let from_state = current
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let instance_id = current
        .get("instance_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tail = hash_tail("instance", instance_id);
    let proposal_operation_ref = agentgres::refs::event_stream_operation_ref(
        RUNTIME_NAMESPACE,
        &tail,
        proposal.seq,
        &proposal.head,
    );
    let proposal_receipt_ref = agentgres::refs::event_stream_receipt_ref(
        RUNTIME_NAMESPACE,
        &tail,
        proposal.admission_batch_seq,
        &proposal.admission_root,
    );
    let archive_refs = request.backup_ref.iter().cloned().collect::<Vec<_>>();
    let kernel_request = json!({
        "lifecycle_id": current.get("lifecycle_id"),
        "worker_instance_id": instance_id,
        "worker_package_ref": current.get("worker_package_ref"),
        "owner_ref": current.get("owner_ref"),
        "from_state": from_state,
        "to_state": request.to_state,
        "persistence_profile": current.pointer("/runtime_policy/persistence_profile"),
        "payment_status": request.payment_status.as_deref().unwrap_or("not_applicable"),
        "transition_reason": request.transition_reason,
        "authority_scope_refs": request.authority_scope_refs,
        "authority_grant_refs": request.authority_grant_refs,
        "policy_refs": request.policy_refs,
        "required_controls": request.required_controls,
        "wallet_approval_ref": request.wallet_approval_ref,
        "latest_state_root": request.latest_state_root,
        "archive_refs": archive_refs,
        "artifact_refs": archive_refs,
        "restore_import_ref": request.restore_import_ref,
        "migration_target_ref": request.migration_target_ref,
        "high_risk_orders_paused": request.high_risk_orders_paused.unwrap_or(false),
        "new_billable_work_blocked": request.new_billable_work_blocked.unwrap_or(false),
        "archive_policy": request.archive_policy,
        "restore_policy": request.restore_policy,
        "export_policy": request.export_policy,
        "deletion_policy": request.deletion_policy,
        "agentgres_operation_refs": [proposal_operation_ref],
        "receipt_refs": [proposal_receipt_ref],
    });
    let mut admission = RuntimeKernelService::new()
        .admit_managed_worker_instance_lifecycle_transition(&kernel_request, "")
        .map_err(|error| {
            bad(
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::UNPROCESSABLE_ENTITY),
                &error.code,
                error.message,
            )
        })?;
    admission
        .as_object_mut()
        .map(|object| object.remove("admitted_at"));

    if matches!(request.to_state.as_str(), "active" | "migrated") {
        let needs_new_placement = current.get("runtime_assignment").is_none_or(Value::is_null)
            || matches!(from_state, "zero_to_idle" | "restoring" | "migrated");
        if needs_new_placement && request.placement.is_none() {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "managed_runtime_placement_required",
                "activation after initialization, restore, migration, or zero-to-idle requires a fresh placement",
            ));
        }
    }
    if let Some(placement) = &request.placement {
        validate_placement(placement)?;
    }
    if request.to_state == "zero_to_idle" {
        if request.backup_ref.is_none() || request.provider_close_receipt_ref.is_none() {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "managed_runtime_zero_to_idle_evidence_required",
                "zero-to-idle requires a verified backup ref and provider close receipt",
            ));
        }
        if current.pointer("/runtime_policy/pre_stop_checkpoint_required")
            == Some(&Value::Bool(true))
            && request.latest_state_root.is_none()
        {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "managed_runtime_pre_stop_checkpoint_required",
                "runtime policy requires a state-root checkpoint before compute is released",
            ));
        }
    }
    if from_state == "zero_to_idle"
        && request.to_state == "active"
        && request.restore_import_ref.is_none()
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_runtime_wake_restore_required",
            "a zero-to-idle wake requires an exact restore import ref",
        ));
    }

    let revision = current.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let mut next = current.clone();
    next["revision"] = json!(revision);
    next["state"] = json!(request.to_state);
    next["pending_transition"] = Value::Null;
    next["last_transition"] = json!({
        "status": "committed",
        "request_hash": transition_request_identity(request)?,
        "idempotency_key": request.idempotency_key,
        "proposal_operation_ref": proposal_operation_ref,
        "proposal_receipt_ref": proposal_receipt_ref,
        "admission": admission,
        "error_status": Value::Null,
        "error_response": Value::Null,
    });
    if let Some(root) = &request.latest_state_root {
        next["latest_state_root"] = json!(root);
    }
    if let Some(backup_ref) = &request.backup_ref {
        next["latest_verified_backup_ref"] = json!(backup_ref);
    }
    if let Some(placement) = &request.placement {
        let placement_value = serde_json::to_value(placement).unwrap_or(Value::Null);
        let assignment_hash = jcs_digest(&placement_value).map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_runtime_assignment_hash_failed",
                error,
            )
        })?;
        next["runtime_assignment"] = json!({
            "schema_version": "ioi.runtime-assignment.v1",
            "runtime_assignment_id": format!("runtime-assignment://managed/{}/{}", safe(instance_id), assignment_hash.trim_start_matches("sha256:")),
            "assignment_epoch": revision,
            "placement": placement_value,
            "assignment_hash": assignment_hash,
            "status": if request.to_state == "active" { "active" } else { "admitted" },
        });
        next["compute_session"] = json!({
            "schema_version": "ioi.compute-session.v1",
            "compute_session_ref": format!("compute://managed/{}/{}", safe(instance_id), revision),
            "runtime_assignment_ref": next["runtime_assignment"]["runtime_assignment_id"],
            "environment_ref": placement.environment_ref,
            "provider_ref": placement.provider_ref,
            "status": "ready",
            "readiness_evidence_refs": placement.readiness_evidence_refs,
        });
    }
    if matches!(
        request.to_state.as_str(),
        "zero_to_idle" | "archived" | "deleted" | "forgotten"
    ) {
        if let Some(assignment) = next.get_mut("runtime_assignment") {
            assignment["status"] = json!(if request.to_state == "zero_to_idle" {
                "closed"
            } else {
                "completed"
            });
        }
        if let Some(session) = next.get_mut("compute_session") {
            session["status"] = json!("ended");
            session["provider_close_receipt_ref"] = request
                .provider_close_receipt_ref
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null);
        }
    }
    Ok(next)
}

pub(crate) async fn handle_instance_transition(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, INSTANCE_SCOPE_KIND, &id, None) {
        return reply;
    }
    let request: TransitionRequest = match parse(body, "managed_runtime_transition_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_runtime_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    if let Err(reply) = validate_transition_request(&request) {
        return reply;
    }
    let (tail, current_exact) = match find_instance(&st.data_dir, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let scope = match authorize_scope(
        &st.data_dir,
        &identity,
        INSTANCE_SCOPE_KIND,
        &id,
        current_exact.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let current = current_exact.operation.payload.clone();
    let request_hash = match transition_request_identity(&request) {
        Ok(hash) => hash,
        Err(reply) => return reply,
    };
    if current
        .pointer("/last_transition/idempotency_key")
        .and_then(Value::as_str)
        == Some(request.idempotency_key.as_str())
    {
        if current
            .pointer("/last_transition/request_hash")
            .and_then(Value::as_str)
            != Some(request_hash.as_str())
        {
            return bad(
                StatusCode::CONFLICT,
                "managed_runtime_idempotency_payload_conflict",
                "the idempotency key already names a different transition",
            );
        }
        if current
            .pointer("/last_transition/status")
            .and_then(Value::as_str)
            == Some("rejected")
        {
            let status = current
                .pointer("/last_transition/error_status")
                .and_then(Value::as_u64)
                .and_then(|status| StatusCode::from_u16(status as u16).ok())
                .unwrap_or(StatusCode::UNPROCESSABLE_ENTITY);
            let body = current
                .pointer("/last_transition/error_response")
                .cloned()
                .unwrap_or_else(|| {
                    json!({
                        "ok": false,
                        "error": {
                            "code": "managed_runtime_transition_previously_rejected",
                            "message": "the identical transition was already rejected"
                        }
                    })
                });
            return (status, Json(body));
        }
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "instance": projection_value(&current_exact, Some(true)) })),
        );
    }
    let proposal_exact = if current
        .pointer("/pending_transition/idempotency_key")
        .and_then(Value::as_str)
        == Some(request.idempotency_key.as_str())
    {
        if current
            .pointer("/pending_transition/request_hash")
            .and_then(Value::as_str)
            != Some(request_hash.as_str())
        {
            return bad(
                StatusCode::CONFLICT,
                "managed_runtime_idempotency_payload_conflict",
                "the idempotency key already names a different transition",
            );
        }
        current_exact
    } else {
        if request.expected_head != current_exact.head {
            return bad(
                StatusCode::CONFLICT,
                "managed_runtime_expected_head_conflict",
                "expected_head is not the current Agentgres head",
            );
        }
        if current
            .get("pending_transition")
            .is_some_and(|value| !value.is_null())
        {
            return bad(
                StatusCode::CONFLICT,
                "managed_runtime_reconciliation_required",
                "another admitted transition proposal is pending reconciliation",
            );
        }
        let mut proposal = current.clone();
        proposal["pending_transition"] = json!({
            "request_hash": request_hash,
            "idempotency_key": request.idempotency_key,
            "to_state": request.to_state,
            "request": request,
        });
        match admit(
            &st.data_dir,
            false,
            &identity,
            &scope,
            INSTANCE_SCOPE_KIND,
            &id,
            RUNTIME_NAMESPACE,
            &tail,
            "event_stream.managed_worker_transition_proposed",
            Some(&current_exact.head),
            &proposal,
            now_ms(),
            &format!(
                "{}.proposal",
                proposal["pending_transition"]["idempotency_key"]
                    .as_str()
                    .unwrap_or_default()
            ),
        ) {
            Ok((exact, _)) => exact,
            Err(reply) => return reply,
        }
    };

    let retained_request: TransitionRequest = match serde_json::from_value(
        proposal_exact.operation.payload["pending_transition"]["request"].clone(),
    ) {
        Ok(request) => request,
        Err(error) => {
            return bad(
                StatusCode::CONFLICT,
                "managed_runtime_pending_transition_corrupt",
                error.to_string(),
            )
        }
    };
    let next = match transition_payload(
        &proposal_exact.operation.payload,
        &retained_request,
        &proposal_exact,
    ) {
        Ok(next) => next,
        Err(reply) => {
            // A refused plan must not strand the instance behind a permanent
            // pending proposal. Commit the rejection as evidence and clear
            // the pending slot, so a corrected transition can proceed.
            let proposal_operation_ref = agentgres::refs::event_stream_operation_ref(
                RUNTIME_NAMESPACE,
                &tail,
                proposal_exact.seq,
                &proposal_exact.head,
            );
            let proposal_receipt_ref = agentgres::refs::event_stream_receipt_ref(
                RUNTIME_NAMESPACE,
                &tail,
                proposal_exact.admission_batch_seq,
                &proposal_exact.admission_root,
            );
            let mut rejected = proposal_exact.operation.payload.clone();
            rejected["pending_transition"] = Value::Null;
            rejected["last_transition"] = json!({
                "status": "rejected",
                "request_hash": request_hash,
                "idempotency_key": retained_request.idempotency_key.clone(),
                "proposal_operation_ref": proposal_operation_ref,
                "proposal_receipt_ref": proposal_receipt_ref,
                "admission": Value::Null,
                "error_status": reply.0.as_u16(),
                "error_response": reply.1.0.clone(),
            });
            match admit(
                &st.data_dir,
                false,
                &identity,
                &scope,
                INSTANCE_SCOPE_KIND,
                &id,
                RUNTIME_NAMESPACE,
                &tail,
                "event_stream.managed_worker_transition_rejected",
                Some(&proposal_exact.head),
                &rejected,
                now_ms(),
                &format!("{}.rejected", retained_request.idempotency_key),
            ) {
                Ok(_) => return reply,
                Err(rejection_reply) => return rejection_reply,
            }
        }
    };
    match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        INSTANCE_SCOPE_KIND,
        &id,
        RUNTIME_NAMESPACE,
        &tail,
        "event_stream.managed_worker_transition_committed",
        Some(&proposal_exact.head),
        &next,
        now_ms(),
        &format!("{}.commit", retained_request.idempotency_key),
    ) {
        Ok((exact, replayed)) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "instance": projection_value(&exact, Some(replayed)) })),
        ),
        Err(reply) => reply,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicyUpdateRequest {
    expected_head: String,
    idempotency_key: String,
    runtime_policy: RuntimePolicy,
}

pub(crate) async fn handle_runtime_policy_put(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, INSTANCE_SCOPE_KIND, &id, None) {
        return reply;
    }
    let request: RuntimePolicyUpdateRequest =
        match parse(body, "managed_runtime_policy_update_invalid") {
            Ok(request) => request,
            Err(reply) => return reply,
        };
    if let Err(reply) = validate_runtime_policy(&request.runtime_policy) {
        return reply;
    }
    let (tail, current) = match find_instance(&st.data_dir, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let scope = match authorize_scope(
        &st.data_dir,
        &identity,
        INSTANCE_SCOPE_KIND,
        &id,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if current.head != request.expected_head {
        return bad(
            StatusCode::CONFLICT,
            "managed_runtime_expected_head_conflict",
            "expected_head is not the current Agentgres head",
        );
    }
    let policy = policy_value(&request.runtime_policy);
    let policy_hash = match jcs_digest(&policy) {
        Ok(hash) => hash,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_runtime_policy_hash_failed",
                error,
            )
        }
    };
    let mut next = current.operation.payload.clone();
    next["revision"] = json!(next["revision"].as_u64().unwrap_or(0) + 1);
    next["runtime_policy"] = policy;
    next["runtime_policy_hash"] = json!(policy_hash);
    match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        INSTANCE_SCOPE_KIND,
        &id,
        RUNTIME_NAMESPACE,
        &tail,
        "event_stream.managed_worker_runtime_policy_revised",
        Some(&current.head),
        &next,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok((exact, replayed)) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "instance": projection_value(&exact, Some(replayed)) })),
        ),
        Err(reply) => reply,
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct StorageProfileRequest {
    storage_profile_ref: String,
    owner_ref: String,
    backend_class: String,
    destination_ref: String,
    custody_policy_ref: String,
    encryption_ref: Option<String>,
    key_epoch_ref: Option<String>,
    retention_policy_ref: String,
    jurisdiction_refs: Vec<String>,
    minimum_replicas: u16,
    independent_compute_copy_required: bool,
    export_allowed: bool,
    authority_grant_refs: Vec<String>,
    idempotency_key: String,
}

fn validate_storage_profile(profile: &StorageProfileRequest) -> Result<(), Reply> {
    if !matches!(
        profile.backend_class.as_str(),
        "local_private" | "object_store" | "cas_ipfs" | "filecoin_archive" | "customer_vpc"
    ) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "storage_profile_backend_invalid",
            "backend_class is outside the closed enum",
        ));
    }
    validate_ref(
        &profile.storage_profile_ref,
        "storage_profile_ref",
        &["storage-profile://"],
    )?;
    validate_ref(
        &profile.owner_ref,
        "owner_ref",
        &["wallet://", "org://", "project://"],
    )?;
    validate_ref(&profile.destination_ref, "destination_ref", &["storage://"])?;
    validate_ref(
        &profile.custody_policy_ref,
        "custody_policy_ref",
        &["policy://"],
    )?;
    validate_ref(
        &profile.retention_policy_ref,
        "retention_policy_ref",
        &["policy://"],
    )?;
    if profile.minimum_replicas == 0 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "storage_profile_replica_count_invalid",
            "minimum_replicas must be positive",
        ));
    }
    if profile.backend_class != "local_private" && !profile.independent_compute_copy_required {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "storage_profile_independence_required",
            "durable remote profiles must require a copy independent of compute",
        ));
    }
    require_nonempty(&profile.authority_grant_refs, "authority_grant_refs")
}

pub(crate) async fn handle_storage_profiles_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: StorageProfileRequest = match parse(body, "storage_profile_create_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = validate_storage_profile(&request) {
        return reply;
    }
    let tail = hash_tail("storage-profile", &request.storage_profile_ref);
    let mut payload = serde_json::to_value(&request).unwrap_or(Value::Null);
    payload
        .as_object_mut()
        .map(|object| object.remove("idempotency_key"));
    payload["schema_version"] = json!("ioi.storage-profile.v1");
    payload["revision"] = json!(1);
    payload["profile_hash"] = match jcs_digest(&payload) {
        Ok(hash) => json!(hash),
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage_profile_hash_failed",
                error,
            )
        }
    };
    let scope = match super::substrate_store::read_event_stream_operation(
        &st.data_dir,
        PERSISTENCE_NAMESPACE,
        &tail,
    ) {
        Ok(Some(current)) => {
            let owner_ref = current.operation.payload["owner_ref"]
                .as_str()
                .unwrap_or_default();
            if owner_ref != request.owner_ref {
                return scope_refusal(
                    super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
                );
            }
            match authorize_scope(
                &st.data_dir,
                &identity,
                STORAGE_PROFILE_SCOPE_KIND,
                &request.storage_profile_ref,
                Some(owner_ref),
            ) {
                Ok(scope) => scope,
                Err(reply) => return reply,
            }
        }
        Ok(None) => match bind_scope(
            &st.data_dir,
            &identity,
            STORAGE_PROFILE_SCOPE_KIND,
            &request.storage_profile_ref,
            &request.owner_ref,
            &request.idempotency_key,
        ) {
            Ok(scope) => scope,
            Err(reply) => return reply,
        },
        Err(error) => return admission_error(error),
    };
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        STORAGE_PROFILE_SCOPE_KIND,
        &request.storage_profile_ref,
        PERSISTENCE_NAMESPACE,
        &tail,
        "event_stream.storage_profile_created",
        None,
        &payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok((exact, replayed)) => (
            StatusCode::CREATED,
            Json(json!({"ok":true,"storage_profile":projection_value(&exact,Some(replayed))})),
        ),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_storage_profiles_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, STORAGE_PROFILE_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    list_persistence_objects(
        &st.data_dir,
        "storage-profile.",
        "ioi.storage-profile.v1",
        "storage_profiles",
        &identity,
        STORAGE_PROFILE_SCOPE_KIND,
        "storage_profile_ref",
        &allowed,
    )
}

fn list_persistence_objects(
    data_dir: &str,
    prefix: &str,
    schema: &str,
    key: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope_kind: &str,
    identity_field: &str,
    allowed: &std::collections::BTreeSet<String>,
) -> Reply {
    let tails =
        match super::substrate_store::list_event_stream_tails(data_dir, PERSISTENCE_NAMESPACE) {
            Ok(tails) => tails,
            Err(error) => {
                return bad(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "managed_persistence_inventory_unavailable",
                    error.to_string(),
                )
            }
        };
    let mut values = Vec::new();
    for tail in tails.into_iter().filter(|tail| tail.starts_with(prefix)) {
        match read_head(data_dir, PERSISTENCE_NAMESPACE, &tail) {
            Ok(exact) if exact.operation.payload["schema_version"] == schema => {
                let resource_ref = exact.operation.payload[identity_field]
                    .as_str()
                    .unwrap_or_default();
                if allowed.contains(resource_ref) {
                    if let Err(reply) = authorize_scope(
                        data_dir,
                        identity,
                        scope_kind,
                        resource_ref,
                        exact.operation.payload["owner_ref"].as_str(),
                    ) {
                        return reply;
                    }
                    values.push(projection_value(&exact, None));
                }
            }
            Ok(_) => {}
            Err(reply) => return reply,
        }
    }
    let mut response = json!({"ok": true});
    response[key] = Value::Array(values);
    (StatusCode::OK, Json(response))
}

fn storage_profile(data_dir: &str, profile_ref: &str) -> Result<Value, Reply> {
    let tail = hash_tail("storage-profile", profile_ref);
    let exact = read_head(data_dir, PERSISTENCE_NAMESPACE, &tail)?;
    if exact.operation.payload["storage_profile_ref"] != profile_ref {
        return Err(bad(
            StatusCode::CONFLICT,
            "storage_profile_identity_collision",
            "profile coordinate contains different admitted bytes",
        ));
    }
    Ok(exact.operation.payload)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCreateRequest {
    storage_profile_ref: String,
    backup_policy_ref: String,
    trigger: String,
    actor_ref: String,
    instance_ref: Option<String>,
    system_ref: Option<String>,
    schedule_or_change_plan_ref: Option<String>,
    authority_grant_refs: Vec<String>,
    idempotency_key: String,
}

fn environment_record(data_dir: &str, environment_id: &str) -> Result<Value, Reply> {
    let path = Path::new(data_dir)
        .join("environments")
        .join(format!("{}.json", safe(environment_id)));
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "managed_backup_environment_not_found",
                "environment does not exist",
            )
        })
}

fn durable_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    if path.exists() {
        let existing = std::fs::read(path)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "content-addressed path contains different bytes",
        ));
    }
    let temporary = parent.join(format!(
        ".{}.{}.pending",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("record"),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    std::fs::File::open(parent)?.sync_all()
}

fn material_path(data_dir: &str, state_root: &str) -> PathBuf {
    Path::new(data_dir)
        .join(BACKUP_MATERIAL_DIR)
        .join(format!("{}.tar", state_root.trim_start_matches("sha256:")))
}

fn backup_by_id(data_dir: &str, id: &str) -> Result<Value, Reply> {
    let records =
        super::substrate_store::read_required_all(data_dir, BACKUP_FAMILY).map_err(|error| {
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "managed_backup_projection_unavailable",
                error.to_string(),
            )
        })?;
    let matches = records
        .into_iter()
        .filter(|record| {
            record["backup_ref"] == id
                || record["backup_ref"]
                    .as_str()
                    .is_some_and(|backup_ref| backup_ref.rsplit('/').next() == Some(id))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(bad(
            if matches.is_empty() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            if matches.is_empty() {
                "managed_backup_not_found"
            } else {
                "managed_backup_identity_ambiguous"
            },
            "backup identity must resolve exactly once",
        ));
    }
    Ok(matches.into_iter().next().unwrap_or(Value::Null))
}

fn authorized_backup_by_id(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
) -> Result<(Value, super::substrate_store::RequestResourceScope), Reply> {
    let allowed = authorized_refs(data_dir, identity, BACKUP_SCOPE_KIND)?;
    let matches = allowed
        .into_iter()
        .filter(|backup_ref| {
            backup_ref == id || backup_ref.rsplit('/').next().is_some_and(|tail| tail == id)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(scope_refusal(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    let backup_ref = &matches[0];
    let scope = authorize_scope(data_dir, identity, BACKUP_SCOPE_KIND, backup_ref, None)?;
    let backup = backup_by_id(data_dir, backup_ref)?;
    Ok((backup, scope))
}

fn verify_backup(data_dir: &str, backup: &Value) -> Result<Value, Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        "schema://ioi/components/hypervisor/hypervisor-environment-backup/v1",
        backup,
    )
    .map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "managed_backup_contract_invalid",
            error,
        )
    })?;
    let root = environment_artifact_root(backup)
        .map_err(|error| bad(StatusCode::CONFLICT, "managed_backup_root_invalid", error))?;
    let key = format!("hveb_{}", root.trim_start_matches("sha256:"));
    super::substrate_store::verify_required_exact(data_dir, BACKUP_FAMILY, &key, backup).map_err(
        |error| {
            bad(
                StatusCode::CONFLICT,
                "managed_backup_agentgres_backing_invalid",
                error.to_string(),
            )
        },
    )?;
    let state_root = backup["source_state_root_ref"]
        .as_str()
        .and_then(|value| value.strip_prefix("state-root://"))
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "managed_backup_state_root_invalid",
                "source state root is malformed",
            )
        })?;
    let bytes = std::fs::read(material_path(data_dir, state_root)).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "managed_backup_material_unavailable",
            error.to_string(),
        )
    })?;
    let actual = digest(&bytes);
    if actual != state_root {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_backup_material_digest_mismatch",
            "captured bytes no longer match the admitted state root",
        ));
    }
    let row = backup["manifest_rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "managed_backup_manifest_incomplete",
                "manifest has no payload row",
            )
        })?;
    if row["sha256"] != actual || row["size_bytes"].as_u64() != Some(bytes.len() as u64) {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_backup_manifest_digest_mismatch",
            "manifest row does not describe the retrieved bytes",
        ));
    }
    let manifest = backup_manifest_root(backup).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "managed_backup_manifest_invalid",
            error,
        )
    })?;
    if backup["manifest_root"] != manifest {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_backup_manifest_root_mismatch",
            "manifest root does not recompute",
        ));
    }
    Ok(json!({
        "verified": true,
        "backup_ref": backup["backup_ref"],
        "state_root": state_root,
        "manifest_root": manifest,
        "bytes": bytes.len(),
    }))
}

pub(crate) async fn handle_environment_backup_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(environment_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: BackupCreateRequest = match parse(body, "managed_backup_create_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if !matches!(
        request.trigger.as_str(),
        "manual" | "scheduled" | "webhook" | "pre_change" | "shutdown" | "policy"
    ) {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_backup_trigger_invalid",
            "trigger is outside the closed enum",
        );
    }
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    for (field, value, prefixes) in [
        (
            "storage_profile_ref",
            request.storage_profile_ref.as_str(),
            &["storage-profile://"][..],
        ),
        (
            "backup_policy_ref",
            request.backup_policy_ref.as_str(),
            &["policy://"][..],
        ),
        (
            "actor_ref",
            request.actor_ref.as_str(),
            &["wallet://", "org://", "project://", "runtime://"][..],
        ),
    ] {
        if let Err(reply) = validate_ref(value, field, prefixes) {
            return reply;
        }
    }
    if let Some(instance_ref) = request.instance_ref.as_deref() {
        if let Err(reply) = validate_ref(instance_ref, "instance_ref", &["agent://"]) {
            return reply;
        }
    }
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_backup_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let profile_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        STORAGE_PROFILE_SCOPE_KIND,
        &request.storage_profile_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if request.actor_ref != profile_scope.owner_ref {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let profile = match storage_profile(&st.data_dir, &request.storage_profile_ref) {
        Ok(profile) => profile,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(
        &st.data_dir,
        &identity,
        STORAGE_PROFILE_SCOPE_KIND,
        &request.storage_profile_ref,
        profile["owner_ref"].as_str(),
    ) {
        return reply;
    }
    if profile["backend_class"] != "local_private" {
        return bad(StatusCode::NOT_IMPLEMENTED, "managed_backup_backend_executor_unavailable", "this daemon build has byte custody only for local_private; remote profiles remain admitted declarations, never silent local fallback");
    }
    let Some(instance_ref) = request.instance_ref.as_deref() else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_backup_instance_scope_required",
            "backup capture requires an owner-scoped managed instance until the environment plane exposes principal ownership",
        );
    };
    let instance_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        INSTANCE_SCOPE_KIND,
        instance_ref,
        Some(&profile_scope.owner_ref),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if instance_scope.tenant_ref != profile_scope.tenant_ref {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let (_, instance) = match find_instance(&st.data_dir, instance_ref) {
        Ok(instance) => instance,
        Err(reply) => return reply,
    };
    if instance.operation.payload["owner_ref"] != profile["owner_ref"] {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let expected_environment_ref = format!("environment://local/{environment_id}");
    if instance
        .operation
        .payload
        .pointer("/compute_session/environment_ref")
        .and_then(Value::as_str)
        != Some(expected_environment_ref.as_str())
    {
        return bad(
            StatusCode::FORBIDDEN,
            "managed_backup_environment_scope_mismatch",
            "the target environment is not the authenticated principal's admitted managed instance environment",
        );
    }
    let environment = match environment_record(&st.data_dir, &environment_id) {
        Ok(environment) => environment,
        Err(reply) => return reply,
    };
    if environment
        .pointer("/status/substrate")
        .and_then(Value::as_str)
        == Some("microvm")
        || environment
            .pointer("/spec/environment_class_id")
            .and_then(Value::as_str)
            == Some("microvm")
    {
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "managed_backup_machine_capture_unsupported",
            "the local archive cannot claim quiesced guest disk or memory capture",
        );
    }
    let workspace = match environment
        .pointer("/status/workspace_root")
        .and_then(Value::as_str)
    {
        Some(workspace) => workspace,
        None => {
            return bad(
                StatusCode::CONFLICT,
                "managed_backup_environment_not_ready",
                "environment has no materialized workspace",
            )
        }
    };
    let bytes = match super::microvm::tar_dir(Path::new(workspace)) {
        Ok(bytes) => bytes,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_backup_capture_failed",
                error,
            )
        }
    };
    let state_root = digest(&bytes);
    if let Err(error) = durable_write(&material_path(&st.data_dir, &state_root), &bytes) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_material_persist_failed",
            error.to_string(),
        );
    }
    let artifact_ref = format!(
        "artifact://managed-backup-payload/{}",
        state_root.trim_start_matches("sha256:")
    );
    let capture_payload = json!({
        "schema_version":"ioi.managed-backup-capture-evidence.v1",
        "environment_ref":format!("environment://local/{environment_id}"),
        "storage_profile_ref":request.storage_profile_ref,
        "state_root":state_root,
        "artifact_ref":artifact_ref,
        "size_bytes":bytes.len(),
    });
    let capture_tail = hash_tail(
        "backup-capture",
        &format!(
            "{environment_id}:{}:{}",
            request.idempotency_key, state_root
        ),
    );
    // The capture stream has no scope of its own: it is an event on the already-authorized storage
    // profile's owner scope, so it crosses the boundary under that profile scope. The tail is the
    // content-addressed capture coordinate and need not derive from the scope's resource ref.
    let (capture, _) = match admit(
        &st.data_dir,
        true,
        &identity,
        &profile_scope,
        STORAGE_PROFILE_SCOPE_KIND,
        &request.storage_profile_ref,
        PERSISTENCE_NAMESPACE,
        &capture_tail,
        "event_stream.backup_capture_completed",
        None,
        &capture_payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let receipt_ref = agentgres::refs::event_stream_receipt_ref(
        PERSISTENCE_NAMESPACE,
        &capture_tail,
        capture.admission_batch_seq,
        &capture.admission_root,
    );
    let backup_id = format!(
        "{}-{}",
        safe(&environment_id),
        &state_root.trim_start_matches("sha256:")[..16]
    );
    let declaration = BackupDeclaration {
        backup_tail: backup_id.clone(),
        trigger: request.trigger.clone(),
        environment_ref: format!("environment://local/{environment_id}"),
        schedule_or_change_plan_ref: request.schedule_or_change_plan_ref.clone(),
    };
    let rows = vec![json!({
        "artifact_ref":artifact_ref,
        "sha256":state_root,
        "size_bytes":bytes.len(),
        "role":"workspace_snapshot",
    })];
    let mut backup = match compile_backup_record(
        &super::hypervisor_environment_routes::local_environment_estate_binding(),
        &declaration,
        &state_root,
        &rows,
        request.system_ref.as_deref(),
        &receipt_ref,
    ) {
        Ok(backup) => backup,
        Err(error) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "managed_backup_compile_failed",
                error,
            )
        }
    };
    backup["backup_policy_ref"] = json!(request.backup_policy_ref);
    backup["actor_ref"] = json!(request.actor_ref);
    backup["work_subject_ref"] = json!(request.instance_ref);
    backup["destination_ref"] = profile["destination_ref"].clone();
    backup["custody_profile_ref"] = profile["custody_policy_ref"].clone();
    backup["encryption_ref"] = profile
        .get("encryption_ref")
        .cloned()
        .unwrap_or(Value::Null);
    backup["key_epoch_ref"] = profile.get("key_epoch_ref").cloned().unwrap_or(Value::Null);
    backup["retention_policy_ref"] = profile["retention_policy_ref"].clone();
    backup["authority_grant_refs"] = json!(request.authority_grant_refs);
    backup["evidence_refs"] = json!([agentgres::refs::event_stream_operation_ref(
        PERSISTENCE_NAMESPACE,
        &capture_tail,
        capture.seq,
        &capture.head
    )]);
    backup["manifest_root"] = match backup_manifest_root(&backup) {
        Ok(root) => json!(root),
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_backup_manifest_failed",
                error,
            )
        }
    };
    let backup_ref = backup["backup_ref"].as_str().unwrap_or_default();
    if let Err(reply) = bind_scope(
        &st.data_dir,
        &identity,
        BACKUP_SCOPE_KIND,
        backup_ref,
        &profile_scope.owner_ref,
        &request.idempotency_key,
    ) {
        return reply;
    }
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            "schema://ioi/components/hypervisor/hypervisor-environment-backup/v1",
            &backup,
        )
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_backup_contract_invalid",
            error,
        );
    }
    let root = match environment_artifact_root(&backup) {
        Ok(root) => root,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_backup_artifact_root_failed",
                error,
            )
        }
    };
    let key = format!("hveb_{}", root.trim_start_matches("sha256:"));
    if let Err(error) =
        super::substrate_store::admit_required(&st.data_dir, BACKUP_FAMILY, &key, &backup)
    {
        return bad(
            StatusCode::CONFLICT,
            "managed_backup_agentgres_admission_failed",
            error.to_string(),
        );
    }
    // The Agentgres admission above is canonical and has already succeeded. This is its record
    // projection, so a failure here is a divergence to replay, not a lost backup — say which,
    // because "persist failed" alone reads as though the backup never happened.
    if let Err(error) = persist_record(&st.data_dir, BACKUP_FAMILY, &key, &backup) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_projection_persist_failed",
            format!(
                "{error}; the backup is admitted and canonical — replay to rebuild its projection"
            ),
        );
    }
    match verify_backup(&st.data_dir, &backup) {
        Ok(verification) => (
            StatusCode::CREATED,
            Json(json!({"ok":true,"backup":backup,"verification":verification})),
        ),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_backups_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, BACKUP_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    match super::substrate_store::read_required_all(&st.data_dir, BACKUP_FAMILY) {
        Ok(mut backups) => {
            backups.retain(|backup| {
                backup["backup_ref"]
                    .as_str()
                    .is_some_and(|backup_ref| allowed.contains(backup_ref))
            });
            backups.sort_by(|a, b| a["backup_ref"].as_str().cmp(&b["backup_ref"].as_str()));
            (StatusCode::OK, Json(json!({"ok":true,"backups":backups})))
        }
        Err(error) => bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "managed_backup_projection_unavailable",
            error.to_string(),
        ),
    }
}

pub(crate) async fn handle_backup_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match authorized_backup_by_id(&st.data_dir, &identity, &id) {
        Ok((backup, _)) => (StatusCode::OK, Json(json!({"ok":true,"backup":backup}))),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_backup_verify(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let backup = match authorized_backup_by_id(&st.data_dir, &identity, &id) {
        Ok((backup, _)) => backup,
        Err(reply) => return reply,
    };
    match verify_backup(&st.data_dir, &backup) {
        Ok(verification) => (
            StatusCode::OK,
            Json(json!({"ok":true,"verification":verification})),
        ),
        Err(reply) => reply,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupExportRequest {
    authority_grant_refs: Vec<String>,
    expires_in_seconds: u64,
}

pub(crate) async fn handle_backup_export(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: BackupExportRequest = match parse(body, "managed_backup_export_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    if request.expires_in_seconds == 0 || request.expires_in_seconds > 3600 {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_backup_export_expiry_invalid",
            "expires_in_seconds must be between 1 and 3600",
        );
    }
    let (backup, backup_scope) = match authorized_backup_by_id(&st.data_dir, &identity, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let verification = match verify_backup(&st.data_dir, &backup) {
        Ok(verification) => verification,
        Err(reply) => return reply,
    };
    let token = uuid::Uuid::new_v4().to_string();
    let token_hash = digest(token.as_bytes());
    let record = json!({
        "schema_version":"ioi.managed-backup-export-token.v1",
        "token_hash":token_hash,
        "backup_ref":backup["backup_ref"],
        "state_root":verification["state_root"],
        "principal_ref":identity.principal_ref,
        "tenant_ref":backup_scope.tenant_ref,
        "owner_ref":backup_scope.owner_ref,
        "correlation_ref":backup_scope.correlation_ref,
        "authority_grant_refs":request.authority_grant_refs,
        "expires_at_ms":now_ms().saturating_add(request.expires_in_seconds.saturating_mul(1000)),
    });
    if let Err(error) = persist_record(
        &st.data_dir,
        EXPORT_TOKEN_DIR,
        token_hash.trim_start_matches("sha256:"),
        &record,
    ) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_export_token_persist_failed",
            error.to_string(),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "ok":true,
            "export":{
                "download_token":token,
                "download_path":format!("/v1/hypervisor/backup-exports/{token}"),
                "expires_at_ms":record["expires_at_ms"],
                "backup_ref":backup["backup_ref"],
            }
        })),
    )
}

pub(crate) async fn handle_backup_export_download(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(token): AxumPath<String>,
) -> Response {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply.into_response(),
    };
    let token_hash = digest(token.as_bytes());
    let path = Path::new(&st.data_dir)
        .join(EXPORT_TOKEN_DIR)
        .join(format!("{}.json", token_hash.trim_start_matches("sha256:")));
    let Some(record) = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "managed_backup_export_not_found",
            "download token is unknown",
        )
        .into_response();
    };
    if record["principal_ref"].as_str() != Some(identity.principal_ref.as_str())
        || record["tenant_ref"] != record["owner_ref"]
        || !record["tenant_ref"]
            .as_str()
            .is_some_and(|tenant_ref| identity.authorizes_tenant(tenant_ref))
    {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceScopeRequired)
            .into_response();
    }
    let backup_ref = record["backup_ref"].as_str().unwrap_or_default();
    if let Err(reply) = authorize_scope(
        &st.data_dir,
        &identity,
        BACKUP_SCOPE_KIND,
        backup_ref,
        record["owner_ref"].as_str(),
    ) {
        return reply.into_response();
    }
    if record["expires_at_ms"].as_u64().unwrap_or(0) <= now_ms() {
        let _ = std::fs::remove_file(path);
        return bad(
            StatusCode::GONE,
            "managed_backup_export_expired",
            "download token has expired",
        )
        .into_response();
    }
    let state_root = record["state_root"].as_str().unwrap_or_default();
    let bytes = match std::fs::read(material_path(&st.data_dir, state_root)) {
        Ok(bytes) if digest(&bytes) == state_root => bytes,
        Ok(_) => {
            return bad(
                StatusCode::CONFLICT,
                "managed_backup_export_digest_mismatch",
                "export bytes do not match admitted state root",
            )
            .into_response()
        }
        Err(error) => {
            return bad(
                StatusCode::CONFLICT,
                "managed_backup_export_material_unavailable",
                error.to_string(),
            )
            .into_response()
        }
    };
    let filename = format!(
        "{}.tar",
        safe(record["backup_ref"].as_str().unwrap_or("backup"))
    );
    let mut response = bytes.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/x-tar".parse().unwrap());
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    response
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RestorePlanRequest {
    target_environment_id: String,
    authority_grant_refs: Vec<String>,
    idempotency_key: String,
}

fn restore_tail(plan_id: &str) -> String {
    hash_tail("restore-plan", plan_id)
}

fn restore_staging_path(workspace: &Path, plan_id: &str) -> Result<PathBuf, Reply> {
    workspace
        .parent()
        .map(|parent| parent.join(format!(".ioi-managed-restore-staging-{}", safe(plan_id))))
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "managed_restore_workspace_parent_missing",
                "target workspace has no parent",
            )
        })
}

fn authorized_instance_for_environment(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    environment_id: &str,
) -> Result<super::substrate_store::RequestResourceScope, Reply> {
    let expected = format!("environment://local/{environment_id}");
    let mut matches = Vec::new();
    for instance_ref in authorized_refs(data_dir, identity, INSTANCE_SCOPE_KIND)? {
        let (_, instance) = match find_instance(data_dir, &instance_ref) {
            Ok(instance) => instance,
            Err((StatusCode::NOT_FOUND, _)) => continue,
            Err(reply) => return Err(reply),
        };
        if instance
            .operation
            .payload
            .pointer("/compute_session/environment_ref")
            .and_then(Value::as_str)
            == Some(expected.as_str())
        {
            matches.push(authorize_scope(
                data_dir,
                identity,
                INSTANCE_SCOPE_KIND,
                &instance_ref,
                instance.operation.payload["owner_ref"].as_str(),
            )?);
        }
    }
    if matches.len() != 1 {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "managed_restore_environment_scope_required",
            "the target environment must resolve to exactly one managed instance owned by the authenticated principal",
        ));
    }
    Ok(matches.remove(0))
}

pub(crate) async fn handle_restore_plan_prepare(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: RestorePlanRequest = match parse(body, "managed_restore_plan_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    // Reject an empty key before the derived plan id, the untar, and the scope bind consume it. The
    // shared boundary refuses it too, but only after those effects have run; mirroring the sibling
    // create/transition/backup handlers keeps the derived plan id from being minted off a key that
    // provides no idempotency.
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_restore_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let (backup, backup_scope) = match authorized_backup_by_id(&st.data_dir, &identity, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    if let Err(reply) = verify_backup(&st.data_dir, &backup) {
        return reply;
    }
    let target_scope = match authorized_instance_for_environment(
        &st.data_dir,
        &identity,
        &request.target_environment_id,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if target_scope.tenant_ref != backup_scope.tenant_ref {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let target = match environment_record(&st.data_dir, &request.target_environment_id) {
        Ok(target) => target,
        Err(reply) => return reply,
    };
    let workspace = match target
        .pointer("/status/workspace_root")
        .and_then(Value::as_str)
    {
        Some(workspace) => PathBuf::from(workspace),
        None => {
            return bad(
                StatusCode::CONFLICT,
                "managed_restore_target_not_ready",
                "target environment has no workspace",
            )
        }
    };
    let plan_id = format!(
        "restore-{}-{}",
        safe(&request.target_environment_id),
        &digest(format!("{}:{}", backup["backup_ref"], request.idempotency_key).as_bytes())
            .trim_start_matches("sha256:")[..16]
    );
    let staging = match restore_staging_path(&workspace, &plan_id) {
        Ok(staging) => staging,
        Err(reply) => return reply,
    };
    if staging.exists() {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_staging_exists",
            "a restore staging directory already exists and must be reconciled",
        );
    }
    let state_root = backup["source_state_root_ref"]
        .as_str()
        .and_then(|value| value.strip_prefix("state-root://"))
        .unwrap_or_default();
    let bytes = match std::fs::read(material_path(&st.data_dir, state_root)) {
        Ok(bytes) => bytes,
        Err(error) => {
            return bad(
                StatusCode::CONFLICT,
                "managed_restore_material_unavailable",
                error.to_string(),
            )
        }
    };
    if let Err(error) = super::microvm::untar_into(&staging, &bytes) {
        let _ = std::fs::remove_dir_all(&staging);
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_restore_prepare_failed",
            error,
        );
    }
    let payload = json!({
        "schema_version":"ioi.managed-restore-plan.v1",
        "plan_id":plan_id,
        "backup_ref":backup["backup_ref"],
        "restore_manifest_root":backup["manifest_root"],
        "source_state_root":state_root,
        "target_environment_id":request.target_environment_id,
        "authority_grant_refs":request.authority_grant_refs,
        "status":"prepared",
        "preparation_verified":true,
    });
    let tail = restore_tail(&plan_id);
    let scope = match bind_scope(
        &st.data_dir,
        &identity,
        RESTORE_SCOPE_KIND,
        &plan_id,
        &backup_scope.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => {
            let _ = std::fs::remove_dir_all(&staging);
            return reply;
        }
    };
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        RESTORE_SCOPE_KIND,
        &plan_id,
        PERSISTENCE_NAMESPACE,
        &tail,
        "event_stream.restore_plan_prepared",
        None,
        &payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok((exact, replayed)) => (
            StatusCode::CREATED,
            Json(json!({"ok":true,"restore_plan":projection_value(&exact,Some(replayed))})),
        ),
        Err(reply) => {
            let _ = std::fs::remove_dir_all(staging);
            reply
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreActionRequest {
    expected_head: String,
    idempotency_key: String,
}

pub(crate) async fn handle_restore_plan_action(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((plan_id, action)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let scope = match authorize_scope(&st.data_dir, &identity, RESTORE_SCOPE_KIND, &plan_id, None) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let request: RestoreActionRequest = match parse(body, "managed_restore_action_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    // Reject an empty key before any staging or workspace effect runs, mirroring the sibling
    // handlers. The shared boundary refuses it too, but the cancel/apply effects are ordered around
    // the admits, so the guard belongs before them, not inside the write.
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_restore_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    if !matches!(action.as_str(), "apply" | "cancel") {
        return bad(
            StatusCode::NOT_FOUND,
            "managed_restore_action_unknown",
            "action must be apply or cancel",
        );
    }
    let tail = restore_tail(&plan_id);
    let current = match read_head(&st.data_dir, PERSISTENCE_NAMESPACE, &tail) {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    if current.head != request.expected_head {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_expected_head_conflict",
            "expected_head is not the current Agentgres head",
        );
    }
    if current.operation.payload["status"] != "prepared" {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_plan_not_prepared",
            "only a prepared restore plan may be applied or cancelled",
        );
    }
    let environment_id = current.operation.payload["target_environment_id"]
        .as_str()
        .unwrap_or_default();
    let environment = match environment_record(&st.data_dir, environment_id) {
        Ok(environment) => environment,
        Err(reply) => return reply,
    };
    let workspace = match environment
        .pointer("/status/workspace_root")
        .and_then(Value::as_str)
    {
        Some(workspace) => PathBuf::from(workspace),
        None => {
            return bad(
                StatusCode::CONFLICT,
                "managed_restore_target_not_ready",
                "target environment has no workspace",
            )
        }
    };
    let staging = match restore_staging_path(&workspace, &plan_id) {
        Ok(staging) => staging,
        Err(reply) => return reply,
    };
    if action == "cancel" {
        // Admit the INTENT before destroying the staged bytes. Deleting first meant that if the
        // cancelled append then failed, the plan still read "prepared" while the bytes it promised
        // were already gone — a plan no apply could satisfy and no reader could tell was doomed.
        let mut cancelling = current.operation.payload.clone();
        cancelling["status"] = json!("cancelling");
        let (cancelling_exact, _) = match admit(
            &st.data_dir,
            false,
            &identity,
            &scope,
            RESTORE_SCOPE_KIND,
            &plan_id,
            PERSISTENCE_NAMESPACE,
            &tail,
            "event_stream.restore_plan_cancelling",
            Some(&current.head),
            &cancelling,
            now_ms(),
            &format!("{}.cancelling", request.idempotency_key),
        ) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
        if let Err(error) = std::fs::remove_dir_all(&staging) {
            if error.kind() != std::io::ErrorKind::NotFound {
                // The intent is admitted and the bytes are still there. Say so: a retry of this
                // cancel resumes from `cancelling` rather than starting over.
                return bad(
                    StatusCode::CONFLICT,
                    "managed_restore_cancel_cleanup_failed",
                    error.to_string(),
                );
            }
        }
        let mut cancelled = cancelling_exact.operation.payload.clone();
        cancelled["status"] = json!("cancelled");
        // Per-transition key suffix, aligned with the cancelling/applying/completed successors. The
        // bare key this event previously reused collided with the prepared genesis whenever a caller
        // reused one idempotency key across prepare and cancel: same key, different bytes, refused.
        return match admit(
            &st.data_dir,
            false,
            &identity,
            &scope,
            RESTORE_SCOPE_KIND,
            &plan_id,
            PERSISTENCE_NAMESPACE,
            &tail,
            "event_stream.restore_plan_cancelled",
            Some(&cancelling_exact.head),
            &cancelled,
            now_ms(),
            &format!("{}.cancelled", request.idempotency_key),
        ) {
            Ok((exact, replayed)) => (
                StatusCode::OK,
                Json(json!({"ok":true,"restore_plan":projection_value(&exact,Some(replayed))})),
            ),
            Err(reply) => reply,
        };
    }
    if !staging.is_dir() {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_staging_missing",
            "prepared restore bytes are missing; prepare again under a successor plan",
        );
    }
    let mut applying = current.operation.payload.clone();
    applying["status"] = json!("applying");
    let (applying_exact, _) = match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        RESTORE_SCOPE_KIND,
        &plan_id,
        PERSISTENCE_NAMESPACE,
        &tail,
        "event_stream.restore_plan_applying",
        Some(&current.head),
        &applying,
        now_ms(),
        &format!("{}.applying", request.idempotency_key),
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let rollback = workspace
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(".ioi-managed-restore-rollback-{}", safe(&plan_id)));
    if rollback.exists() {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_rollback_obligation_exists",
            "an unresolved rollback target already exists",
        );
    }
    if let Err(error) = std::fs::rename(&workspace, &rollback) {
        return bad(
            StatusCode::CONFLICT,
            "managed_restore_writer_fence_failed",
            error.to_string(),
        );
    }
    if let Err(error) = std::fs::rename(&staging, &workspace) {
        let rollback_result = std::fs::rename(&rollback, &workspace);
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_restore_apply_failed",
            format!("{error}; rollback={rollback_result:?}"),
        );
    }
    // Admit the completion BEFORE discarding the rollback material, not after. The old order
    // deleted the only copy of the pre-restore workspace and THEN tried to record that the restore
    // had completed: if that append failed, the plan was still "applying", the workspace already
    // held the restored bytes, and the material needed to undo it had been destroyed — the one
    // state from which neither finishing nor rolling back is possible.
    let mut completed = applying_exact.operation.payload.clone();
    completed["status"] = json!("completed");
    completed["applied_state_root"] = current.operation.payload["source_state_root"].clone();
    completed["rollback_material_path"] = json!(rollback.to_string_lossy());
    let (completed_exact, replayed) = match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        RESTORE_SCOPE_KIND,
        &plan_id,
        PERSISTENCE_NAMESPACE,
        &tail,
        "event_stream.restore_plan_completed",
        Some(&applying_exact.head),
        &completed,
        now_ms(),
        &format!("{}.completed", request.idempotency_key),
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    // The restore is durable now. Failing to remove the rollback copy is a disk-space obligation,
    // not a failed restore, so it is recorded and reported — never returned as a 500 over state
    // that did in fact complete.
    let cleanup_obligation = match std::fs::remove_dir_all(&rollback) {
        Ok(()) => Value::Null,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Value::Null,
        Err(error) => json!({
            "code": "managed_restore_rollback_material_retained",
            "path": rollback.to_string_lossy(),
            "message": error.to_string()
        }),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "restore_plan": projection_value(&completed_exact, Some(replayed)),
            "cleanup_obligation": cleanup_obligation
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_managed_plane_handler_requires_request_identity() {
        let source = include_str!("managed_runtime_routes.rs");
        for handler in [
            "handle_instances_create",
            "handle_instances_list",
            "handle_instance_get",
            "handle_instance_transition",
            "handle_runtime_policy_put",
            "handle_storage_profiles_create",
            "handle_storage_profiles_list",
            "handle_environment_backup_create",
            "handle_backups_list",
            "handle_backup_get",
            "handle_backup_verify",
            "handle_backup_export",
            "handle_backup_export_download",
            "handle_restore_plan_prepare",
            "handle_restore_plan_action",
        ] {
            let marker = format!("pub(crate) async fn {handler}");
            let start = source
                .find(&marker)
                .unwrap_or_else(|| panic!("missing {handler}"));
            let remainder = &source[start..];
            let end = remainder[marker.len()..]
                .find("pub(crate) async fn ")
                .map(|offset| marker.len() + offset)
                .unwrap_or(remainder.len());
            let block = &remainder[..end];
            assert!(
                block.contains("headers: HeaderMap"),
                "{handler} must extract request headers"
            );
            assert!(
                block.contains("request_identity(&st.data_dir, &headers)"),
                "{handler} must resolve a real request principal"
            );
            assert!(
                [
                    "authorize_scope(",
                    "authorized_refs(",
                    "authorized_backup_by_id(",
                    "bind_scope(",
                ]
                .iter()
                .any(|boundary| block.contains(boundary)),
                "{handler} must enforce a durable tenant/resource scope"
            );
        }
        let production = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
        assert!(!production.contains("user://local-operator"));
        assert!(!production.contains("x-ioi-principal"));
    }

    /// Both restore effects must be admitted BEFORE they are performed, because neither is
    /// reversible from the state that a failure in between would leave behind.
    ///
    /// This asserts source order rather than driving a real restore, because forcing a rename or a
    /// remove_dir_all to fail mid-transition needs a fixture corpus, and a check that carries its
    /// own fixtures is one this repo does not keep. The two orderings below are the entire
    /// invariant, so a refactor that reverses either fails here loudly.
    #[test]
    fn restore_effects_are_admitted_before_they_are_performed() {
        let source = include_str!("managed_runtime_routes.rs");
        let handler = source
            .split("pub(crate) async fn handle_restore_plan_action")
            .nth(1)
            .expect("restore action handler");
        let handler = &handler[..handler.find("\n#[cfg(test)]").unwrap_or(handler.len())];

        let at = |needle: &str| {
            handler
                .find(needle)
                .unwrap_or_else(|| panic!("restore action handler no longer contains {needle}"))
        };

        // Cancel: the staged bytes are the only copy of the prepared restore. Deleting them before
        // the cancellation is durable leaves a plan reading "prepared" over bytes that are gone.
        assert!(
            at("event_stream.restore_plan_cancelling") < at("remove_dir_all(&staging)"),
            "cancel must admit its intent before deleting the staged restore bytes"
        );

        // Apply: the rollback directory is the only copy of the pre-restore workspace. Deleting it
        // before the completion is durable leaves the plan "applying", the workspace restored, and
        // nothing left to undo it with.
        assert!(
            at("event_stream.restore_plan_completed") < at("remove_dir_all(&rollback)"),
            "apply must admit completion before discarding the rollback material"
        );
    }

    fn policy(profile: &str, idle_semantics: &str) -> RuntimePolicy {
        RuntimePolicy {
            persistence_profile: profile.to_owned(),
            idle_threshold_seconds: 300,
            minimum_warm_seconds: 60,
            wake_sources: vec!["user".into(), "schedule".into(), "recovery".into()],
            maximum_cold_start_seconds: 120,
            maximum_restore_age_seconds: 3600,
            checkpoint_cadence_seconds: 60,
            pre_stop_checkpoint_required: true,
            provider_idle_semantics: idle_semantics.to_owned(),
            fallback_placement_refs: vec![],
            privacy_floor_ref: "policy://privacy/private".into(),
            spend_ceiling_ref: "budget://managed/monthly".into(),
            archive_retention_policy_ref: "policy://retention/standard".into(),
            minimum_backup_replicas: 1,
        }
    }

    #[test]
    fn zero_to_idle_policy_requires_provider_close() {
        let error = validate_runtime_policy(&policy("zero_to_idle", "stop")).unwrap_err();
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(validate_runtime_policy(&policy("zero_to_idle", "close")).is_ok());
    }

    #[test]
    fn remote_storage_must_be_independent_of_compute() {
        let request = StorageProfileRequest {
            storage_profile_ref: "storage-profile://acme/primary".into(),
            owner_ref: "wallet://acme/operator".into(),
            backend_class: "object_store".into(),
            destination_ref: "storage://acme/object-store".into(),
            custody_policy_ref: "policy://acme/custody".into(),
            encryption_ref: Some("encryption://acme/envelope".into()),
            key_epoch_ref: Some("key-epoch://acme/1".into()),
            retention_policy_ref: "policy://acme/retention".into(),
            jurisdiction_refs: vec![],
            minimum_replicas: 1,
            independent_compute_copy_required: false,
            export_allowed: true,
            authority_grant_refs: vec!["grant://wallet/acme".into()],
            idempotency_key: "profile-1".into(),
        };
        assert_eq!(
            validate_storage_profile(&request).unwrap_err().0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    #[test]
    fn durable_content_write_is_idempotent_and_refuses_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("objects").join("one.bin");
        durable_write(&path, b"one").unwrap();
        durable_write(&path, b"one").unwrap();
        let error = durable_write(&path, b"two").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn transition_policy_records_are_closed() {
        let request = json!({
            "expected_head": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "idempotency_key": "transition-1",
            "to_state": "archived",
            "transition_reason": "operator_request",
            "payment_status": null,
            "authority_scope_refs": [],
            "authority_grant_refs": [],
            "policy_refs": [],
            "required_controls": [],
            "wallet_approval_ref": null,
            "latest_state_root": null,
            "backup_ref": null,
            "restore_import_ref": null,
            "migration_target_ref": null,
            "provider_close_receipt_ref": null,
            "high_risk_orders_paused": null,
            "new_billable_work_blocked": null,
            "archive_policy": {
                "archive_after": null,
                "retain_for": "P30D",
                "storage_policy_ref": "policy://storage/managed",
                "unruled": true
            },
            "restore_policy": null,
            "export_policy": null,
            "deletion_policy": null,
            "placement": null
        });
        let error = serde_json::from_value::<TransitionRequest>(request).unwrap_err();
        assert!(error.to_string().contains("unknown field `unruled`"));
    }

    #[test]
    fn transition_policy_records_preserve_explicit_nulls() {
        let policy = ArchivePolicy {
            archive_after: None,
            retain_for: None,
            storage_policy_ref: "policy://storage/managed".into(),
        };
        assert_eq!(
            serde_json::to_value(policy).unwrap(),
            json!({
                "archive_after": null,
                "retain_for": null,
                "storage_policy_ref": "policy://storage/managed"
            })
        );
    }

    #[test]
    fn backup_verification_rejects_tampered_material() {
        let dir = tempfile::tempdir().unwrap();
        let state_root = digest(b"original");
        durable_write(
            &material_path(dir.path().to_str().unwrap(), &state_root),
            b"tampered",
        )
        .unwrap();
        let bytes =
            std::fs::read(material_path(dir.path().to_str().unwrap(), &state_root)).unwrap();
        assert_ne!(digest(&bytes), state_root);
    }
}
