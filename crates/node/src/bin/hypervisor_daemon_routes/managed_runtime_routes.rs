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
use base64::Engine as _;
use ioi_services::agentic::runtime::kernel::RuntimeKernelService;
use ioi_types::app::hypervisor_environment_lifecycle::{
    backup_manifest_root, compile_backup_record, environment_artifact_root, BackupDeclaration,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{persist_record, AppError, DaemonState};

const RUNTIME_NAMESPACE: &str = "managed-runtime";
const PERSISTENCE_NAMESPACE: &str = "managed-persistence";
const BACKUP_FAMILY: &str = "hypervisor-environment-backups";
const BACKUP_MATERIAL_DIR: &str = "managed-backup-material";
const EXPORT_TOKEN_DIR: &str = "managed-backup-export-tokens";
const PORTABLE_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const INSTANCE_SCOPE_KIND: &str = "managed-worker-instance";
const STORAGE_PROFILE_SCOPE_KIND: &str = "managed-storage-profile";
pub(crate) const BACKUP_SCOPE_KIND: &str = "managed-environment-backup";
const RESTORE_SCOPE_KIND: &str = "managed-restore-plan";
const BACKUP_LIFECYCLE_SCHEMA: &str = "ioi.managed-backup-lifecycle.v1";
const BUNDLE_SCHEMA: &str = "ioi.managed-backup-bundle.v1";
const BUNDLE_MANIFEST_MEMBER: &str = "ioi-backup-bundle.v1.json";
const BUNDLE_PAYLOAD_MEMBER: &str = "payload.tar";
const BUNDLE_QUARANTINE_DIR: &str = "managed-backup-bundle-quarantine";
/// A retention duty longer than a century is a declaration error, not a policy. The ceiling also
/// keeps the derived expiry inside the portable-safe integer range every projection of this plane
/// is bounded by.
const MAX_RETENTION_DURATION_SECONDS: u64 = 100 * 366 * 24 * 3600;
/// One imported bundle is decoded and verified WHOLE before a byte of it is trusted, so this
/// ceiling is the memory and quarantine disk this plane will spend on unverified material. A
/// bundle above it is REFUSED, never truncated. Streaming import of a larger bundle is a named
/// residual, not a silent capability.
/// RESIDUAL, stated because the number alone does not state it: axum runs the `Json` extractor
/// BEFORE the handler body, and the handler is where identity is resolved, so this ceiling is spent
/// on UNAUTHENTICATED material under the default `auto` posture. Halved from 16 MiB on that
/// finding; bounding it properly needs authentication ahead of body buffering, which is a router
/// change wider than this cut.
pub(crate) const MAX_IMPORT_BYTES: usize = 8 * 1024 * 1024;

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

/// Parse one `canonicalDateTime` into milliseconds since the epoch, which may be NEGATIVE for a
/// pre-1970 instant. `None` means the bytes are not a representable instant at all — the only
/// honest "unreadable" answer, and the one a wrapping cast cannot give.
fn parse_contract_instant_ms(value: &str) -> Option<i128> {
    time::OffsetDateTime::parse(value.trim(), &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|instant| i128::from(instant.unix_timestamp()) * 1000)
}

/// Format one millisecond instant as the backup contract's `canonicalDateTime`, truncated to whole
/// seconds. Truncation moves an expiry EARLIER, never later, so the rounding can only shorten a
/// retention duty — the safe direction for a gate that decides whether material may still be used.
fn utc_rfc3339_seconds(timestamp_ms: u64) -> Option<String> {
    let seconds = i64::try_from(timestamp_ms / 1_000).ok()?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Refuse a backup whose recorded retention duty has ended.
///
/// There is no sweeper: expiry is evaluated at every use site as a pure read of the record's own
/// durable bytes, so it can never go stale and needs no clock write. Three states, and the
/// difference between them is the whole point:
///
/// * `null` — no duty was recorded (a record from before this plane carried retention). Reported as
///   ABSENT by every caller that surfaces it, never as "satisfied".
/// * unparseable — FAILS CLOSED. `parse_rfc3339_ms` answers 0 on malformed input, and treating that
///   0 as "no expiry" would turn a corrupted duty into an unlimited one.
/// * in the past — GONE, typed, before the material is read.
fn refuse_if_expired(backup: &Value) -> Result<(), Reply> {
    let Some(raw) = backup["expires_at"].as_str() else {
        return Ok(());
    };
    // Parsed with `time`, NOT with `agentgres::parse_rfc3339_ms`. That shared helper ends in an
    // `i64 as u64` cast, so every pre-1970 instant wraps to roughly 1.8e19 — neither its zero
    // "unreadable" sentinel nor any value at or before now. A merge-blocking review demonstrated
    // that a contract-valid record declaring `1969-01-01T00:00:00Z` imported and then served as
    // LIVE restore material, and that the unreadable branch was reachable for exactly one instant,
    // the epoch itself. The three states this function documents only exist with a parser that can
    // represent a negative instant.
    let Some(expires_at_ms) = parse_contract_instant_ms(raw) else {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_backup_retention_unreadable",
            "the admitted record carries a retention expiry this daemon cannot parse; an unreadable duty fails closed rather than reading as unlimited",
        ));
    };
    if expires_at_ms <= i128::from(now_ms()) {
        return Err(bad(
            StatusCode::GONE,
            "managed_backup_retention_expired",
            format!("this backup's retention duty ended at {raw}; expired material is not restore material"),
        ));
    }
    Ok(())
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

fn environment_owner_refusal(error: AppError) -> Reply {
    let AppError(status, code) = error;
    bad(status, &code, code.clone())
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

pub(crate) fn authorize_scope(
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
    /// How long material captured under this profile stays restorable. The profile names the
    /// governing policy ref beside it; this is the duty in seconds that the capture path turns into
    /// each record's `expires_at`. It is REQUIRED because a storage profile that declares custody
    /// without declaring how long it keeps the bytes is the state this plane shipped in — every
    /// compiled record carried `expires_at: null`, and the registered contract's retention half was
    /// canon nothing enforced.
    retention_duration_seconds: u64,
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
    if profile.retention_duration_seconds == 0
        || profile.retention_duration_seconds > MAX_RETENTION_DURATION_SECONDS
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "storage_profile_retention_duration_invalid",
            format!(
                "retention_duration_seconds must be between 1 and {MAX_RETENTION_DURATION_SECONDS}; a zero or unbounded duty is a declaration error, not a policy"
            ),
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

pub(crate) fn material_path(data_dir: &str, state_root: &str) -> PathBuf {
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

pub(crate) fn authorized_backup_by_id(
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

// ---------------------------------------------------------------------------------------------
// The backup lifecycle stream — the head a restore has to respect.
//
// The trap the resume checkpoint names is live in exactly this design: `expected_head: None` is
// GENESIS-ONLY, so it sets expected-absent and a second admission on the same stream conflicts
// forever. A backup is now an object a restore may have to RE-ESTABLISH — a bundle exported from
// one daemon and imported onto a fresh one — and an object an owner may DELETE through the W1.5
// retention plane. Both need the same thing: a head to compare-and-swap against, and a deletion
// that leaves a TOMBSTONE preserving that head rather than removing the record.
//
// The stream carries only LOCAL custody truth — was this record captured here or imported, under
// which bundle, and is it still restorable. The admitted `HypervisorEnvironmentBackup` record is
// immutable evidence and is never rewritten to say any of it, because its whole bytes are its
// content address (`environment_artifact_root`) and the family is keyed on that digest.
// ---------------------------------------------------------------------------------------------

fn backup_lifecycle_tail(backup_ref: &str) -> String {
    hash_tail("backup-lifecycle", backup_ref)
}

/// This backup's lifecycle head, or `None` when no stream has been established for it yet.
fn read_backup_lifecycle(
    data_dir: &str,
    backup_ref: &str,
) -> Result<Option<ExactProjection>, Reply> {
    super::substrate_store::read_event_stream_operation(
        data_dir,
        PERSISTENCE_NAMESPACE,
        &backup_lifecycle_tail(backup_ref),
    )
    .map_err(admission_error)
}

/// The stream that records one DESTROYED PAYLOAD, keyed on the state root itself.
fn destroyed_material_tail(state_root: &str) -> String {
    hash_tail("backup-material-destroyed", state_root)
}

/// Refuse when the payload identified by `state_root` was destroyed under an executed deletion.
///
/// A TOMBSTONE MUST NAME WHAT WAS DESTROYED, NOT WHAT IT WAS CALLED. Keying the deletion fact on
/// `backup_ref` alone was bypassable by RENAMING, and a merge-blocking review demonstrated it end to
/// end: a backup's coordinate travels INSIDE the bundle, and every tamper-evidence gate an import
/// applies is a self-consistency check over caller-supplied bytes, so a caller could rewrite
/// `backup_ref`, honestly recompute `manifest_root` and `record_artifact_root` — both pure functions
/// of the record — and re-admit the destroyed payload to the exact content-addressed path the
/// deletion had removed, minting a fresh restorable record while the audit trail still said the
/// backup was deleted.
///
/// The state root is the one coordinate a caller cannot rename, because the import verifies it
/// against the payload bytes themselves. Keying here also closes the same bypass on the capture
/// side, where re-creating an environment under a different id reproduces identical content at a
/// different `backup_ref`.
///
/// The consequence is deliberate and is the strong reading of a deletion: material is
/// content-addressed and therefore SHARED, so destroying one backup's payload blocks every other
/// coordinate that resolves to those exact bytes. An owner who ordered content destroyed is owed
/// that, not a second copy of it under another name.
pub(crate) fn refuse_if_material_destroyed_public(
    data_dir: &str,
    state_root: &str,
) -> Result<(), Reply> {
    refuse_if_material_destroyed(data_dir, state_root)
}

fn refuse_if_material_destroyed(data_dir: &str, state_root: &str) -> Result<(), Reply> {
    let head = super::substrate_store::read_event_stream_operation(
        data_dir,
        PERSISTENCE_NAMESPACE,
        &destroyed_material_tail(state_root),
    )
    .map_err(admission_error)?;
    let Some(head) = head else { return Ok(()) };
    Err((
        StatusCode::GONE,
        Json(json!({
            "ok": false,
            "error": {
                "code": "managed_backup_material_destroyed",
                "message": "the payload these bytes identify was destroyed under an executed retention disposition; re-establishing it under any coordinate is the resurrection that deletion forbids",
                "details": {
                    "state_root": state_root,
                    "destroyed_by_disposition_ref": head.operation.payload["destroyed_by_disposition_ref"],
                    "admitted_head": head.head,
                }
            }
        })),
    ))
}

/// Refuse when this backup was deleted — by NAME (its lifecycle head is a tombstone) or by CONTENT
/// (its payload was destroyed). Both are asked, because either alone is bypassable: the name can be
/// rewritten by whoever holds the bundle, and the content can be re-captured under a fresh name.
///
/// Ordering is the point: every caller asks this BEFORE reading material, because the bytes of a
/// deleted backup are gone by construction and answering `managed_backup_material_unavailable`
/// would report an owner's executed retention deletion as a storage fault — the same observable a
/// lost disk produces. The typed answer is what makes the deletion auditable.
fn refuse_if_deleted(data_dir: &str, backup_ref: &str, state_root: &str) -> Result<(), Reply> {
    // BY NAME FIRST, because when both apply the name is the more informative answer: it carries the
    // disposition that ordered the deletion, which is what makes the deletion auditable. The content
    // fact below is the one a caller cannot rename around, so it is what actually closes the hole —
    // but answering with it first would replace a precise audit trail with a broader one.
    if let Some(head) = read_backup_lifecycle(data_dir, backup_ref)? {
        if head.operation.payload["status"] == json!("pruned") {
            return Err((
                StatusCode::GONE,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "managed_backup_tombstoned",
                        "message": "this backup was deleted under an executed retention disposition; its content is destroyed and it is not restore material",
                        "details": {
                            "pruned_by_disposition_ref": head.operation.payload["pruned_by_disposition_ref"],
                            "admitted_head": head.head,
                        }
                    }
                })),
            ));
        }
    }
    refuse_if_material_destroyed(data_dir, state_root)
}

/// The state root one admitted backup record was captured over, without its scheme prefix.
fn record_state_root(backup: &Value) -> &str {
    backup["source_state_root_ref"]
        .as_str()
        .and_then(|value| value.strip_prefix("state-root://"))
        .unwrap_or_default()
}

/// Establish this backup's lifecycle genesis when the stream is absent, and return the head.
///
/// The genesis is derived wholly from the ALREADY-ADMITTED record, so establishing it lazily
/// cannot fork truth — it only gives existing truth a head. That is what lets one code path serve a
/// freshly captured backup, an imported one, and a legacy record admitted before this stream
/// existed, without a migration pass over the family.
fn ensure_backup_lifecycle(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    backup: &Value,
    custody_origin: &Value,
    idempotency_key: &str,
) -> Result<ExactProjection, Reply> {
    let backup_ref = backup["backup_ref"].as_str().unwrap_or_default();
    if let Some(head) = read_backup_lifecycle(data_dir, backup_ref)? {
        return Ok(head);
    }
    let payload = json!({
        "schema_version": BACKUP_LIFECYCLE_SCHEMA,
        "backup_ref": backup_ref,
        "manifest_root": backup["manifest_root"],
        "source_state_root_ref": backup["source_state_root_ref"],
        "expires_at": backup["expires_at"],
        "custody_origin": custody_origin,
        "status": "admitted",
        "pruned_by_disposition_ref": Value::Null,
    });
    admit(
        data_dir,
        true,
        identity,
        scope,
        BACKUP_SCOPE_KIND,
        backup_ref,
        PERSISTENCE_NAMESPACE,
        &backup_lifecycle_tail(backup_ref),
        "event_stream.backup_lifecycle_admitted",
        None,
        &payload,
        now_ms(),
        idempotency_key,
    )
    .map(|(exact, _)| exact)
}

/// Admit the head-preserving TOMBSTONE for one backup.
///
/// This estate has exactly one owner of deletion — the W1.5 data-retention disposition plane, whose
/// executed deletion destroys payload bytes while retaining admission evidence. This function is
/// how that decision becomes visible to restore, and it is deliberately NOT a second delete route:
/// a `DELETE /backups/:id` beside `retention/dispositions/:id/delete` would be a second admission
/// path for the same act, with its own answer to legal holds.
///
/// The retention plane calls this BEFORE it destroys a byte, so a deletion that reaches the
/// filesystem always carries the tombstone that makes it legible. A tombstone that cannot be
/// admitted refuses the deletion outright, with nothing destroyed and a retry that converges.
/// Record, ONCE for the whole estate, that these exact bytes were destroyed under a disposition.
///
/// Both custody lanes write and read this one stream. The legacy environment snapshot/backup store
/// keeps its material under `data_dir/{snapshots,backups}/<id>/workspace.tar` while this plane keys
/// its own on the content address, so the two stores are physically separate — but "this content was
/// destroyed" is one fact about one owner's decision, and splitting it into two streams would let a
/// deletion in either lane be defeated by re-establishing the same bytes in the other. That split is
/// exactly the gap next-legs XI filed open.
///
/// Genesis is correct: a state root is destroyed once and the fact never advances, so an exact retry
/// replays under the same key rather than conflicting, and a second lane arriving at an
/// already-destroyed root reads the existing head instead of admitting a rival one.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_material_destroyed(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    subject_scope_kind: &str,
    subject_ref: &str,
    state_root: &str,
    disposition_ref: &str,
    idempotency_key: &str,
) -> Result<Value, Reply> {
    if let Some(existing) = super::substrate_store::read_event_stream_operation(
        data_dir,
        PERSISTENCE_NAMESPACE,
        &destroyed_material_tail(state_root),
    )
    .map_err(admission_error)?
    {
        return Ok(json!(existing.head));
    }
    let destroyed = json!({
        "schema_version": "ioi.managed-backup-material-destroyed.v1",
        "state_root": state_root,
        "destroyed_by_disposition_ref": disposition_ref,
        // The SUBJECT, not "the backup": this stream is now written by both custody lanes, and a
        // snapshot capture recorded under a field named for a backup is admitted bytes that misname
        // what happened. No reader consumes it; it is provenance for a human reading the log.
        "first_destroyed_subject_ref": subject_ref,
        "first_destroyed_subject_kind": subject_scope_kind,
    });
    let head = admit(
        data_dir,
        true,
        identity,
        scope,
        subject_scope_kind,
        subject_ref,
        PERSISTENCE_NAMESPACE,
        &destroyed_material_tail(state_root),
        "event_stream.backup_material_destroyed",
        None,
        &destroyed,
        now_ms(),
        &format!("{idempotency_key}.destroyed"),
    )?
    .0
    .head;
    Ok(json!(head))
}

pub(crate) fn tombstone_backup(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    backup_id: &str,
    disposition_ref: &str,
    idempotency_key: &str,
) -> Result<Value, Reply> {
    let (backup, scope) = authorized_backup_by_id(data_dir, identity, backup_id)?;
    let backup_ref = backup["backup_ref"].as_str().unwrap_or_default().to_owned();
    let current = ensure_backup_lifecycle(
        data_dir,
        identity,
        &scope,
        &backup,
        &json!({ "kind": "established_from_admitted_record" }),
        &format!("{idempotency_key}.lifecycle"),
    )?;
    if current.operation.payload["status"] == json!("pruned") {
        return Ok(json!({
            "backup_ref": backup_ref,
            "admitted_head": current.head,
            "replayed": true,
        }));
    }
    let mut payload = current.operation.payload.clone();
    payload["status"] = json!("pruned");
    payload["pruned_by_disposition_ref"] = json!(disposition_ref);
    let (exact, replayed) = admit(
        data_dir,
        false,
        identity,
        &scope,
        BACKUP_SCOPE_KIND,
        &backup_ref,
        PERSISTENCE_NAMESPACE,
        &backup_lifecycle_tail(&backup_ref),
        "event_stream.backup_lifecycle_pruned",
        Some(&current.head),
        &payload,
        now_ms(),
        &format!("{idempotency_key}.pruned"),
    )?;
    // AND the fact keyed on WHAT WAS DESTROYED. The lifecycle tombstone above names the record; this
    // names the bytes, and it is the half a caller cannot rename around.
    let state_root = record_state_root(&backup).to_owned();
    let destroyed_head = record_material_destroyed(
        data_dir,
        identity,
        &scope,
        BACKUP_SCOPE_KIND,
        &backup_ref,
        &state_root,
        disposition_ref,
        idempotency_key,
    )?;
    Ok(json!({
        "backup_ref": backup_ref,
        "admitted_head": exact.head,
        "state_root": state_root,
        "destroyed_material_head": destroyed_head,
        "replayed": replayed,
    }))
}

/// The ONE answer to "may this backup be used as restore material". Verify, export, restore-prepare
/// and import all ask it, so none of them can drift into a weaker private opinion.
///
/// The order inside is load-bearing and each step earns its place:
///   1. `status` — the registered contract says only `complete` is eligible restore material.
///   2. the DELETION — by name and by content, before any byte is read, so an executed deletion
///      reads as a deletion rather than as a missing file.
///   3. the retention duty — before any byte is read, for the same reason.
///   4. the bytes — contract validity, Agentgres backing, material digest, manifest recomputation.
fn require_restorable(data_dir: &str, backup: &Value) -> Result<Value, Reply> {
    if backup["status"] != json!("complete") {
        return Err(bad(
            StatusCode::CONFLICT,
            "managed_backup_status_not_restorable",
            format!(
                "only a complete backup is restore material; this record is {}",
                backup["status"]
            ),
        ));
    }
    refuse_if_deleted(
        data_dir,
        backup["backup_ref"].as_str().unwrap_or_default(),
        record_state_root(backup),
    )?;
    refuse_if_expired(backup)?;
    let mut verification = verify_backup(data_dir, backup)?;
    // Surface the duty that was checked. `null` is reported as ABSENT rather than as an unlimited
    // retention: a reader must be able to tell "kept until T" from "no duty was ever recorded".
    verification["retention"] = match backup["expires_at"].as_str() {
        Some(expires_at) => json!({ "recorded": true, "expires_at": expires_at }),
        None => json!({ "recorded": false, "expires_at": Value::Null }),
    };
    Ok(verification)
}

pub(crate) fn verify_backup(data_dir: &str, backup: &Value) -> Result<Value, Reply> {
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
    capture_environment_backup(&st.data_dir, &identity, &environment_id, &request)
}

/// Capture one environment backup for `environment_id`. Split out of the async handler (marketplace
/// `begin_`/`finish_` pattern) with the identity already resolved and the request already parsed, so
/// the capture + canonical admission + census projection run against a real tempdir and the real
/// Agentgres chain in test. Behaviour is byte-identical to the pre-split handler.
fn capture_environment_backup(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    environment_id: &str,
    request: &BackupCreateRequest,
) -> Reply {
    if let Err(error) = super::environment_routes::authorize_environment_owner_identity(
        data_dir,
        identity,
        environment_id,
    ) {
        return environment_owner_refusal(error);
    }
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
        data_dir,
        identity,
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
    let profile = match storage_profile(data_dir, &request.storage_profile_ref) {
        Ok(profile) => profile,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(
        data_dir,
        identity,
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
        data_dir,
        identity,
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
    let (_, instance) = match find_instance(data_dir, instance_ref) {
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
    let environment = match environment_record(data_dir, environment_id) {
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
    // The retention duty this capture is admitted under, derived from the ALREADY-AUTHORIZED
    // storage profile. It is server-resolved for the same reason the manifest rows are (INV-37): a
    // caller that could name its own expiry could name one a century out and call it custody.
    let Some(retention_duration_seconds) = profile["retention_duration_seconds"].as_u64() else {
        return bad(
            StatusCode::CONFLICT,
            "managed_backup_storage_profile_retention_absent",
            "the admitted storage profile records no retention duty. A storage profile is admitted GENESIS-ONLY and cannot be amended in place, so the remedy is to declare a NEW storage_profile_ref carrying retention_duration_seconds and capture against that one",
        );
    };
    let Some(expires_at) = retention_duration_seconds
        .checked_mul(1_000)
        .and_then(|duty_ms| now_ms().checked_add(duty_ms))
        .and_then(utc_rfc3339_seconds)
    else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "managed_backup_retention_expiry_underivable",
            "the profile's retention duty does not resolve to a representable expiry instant",
        );
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
    let estate = super::hypervisor_environment_routes::local_environment_estate_binding();
    let backup_id = format!(
        "{}-{}",
        safe(environment_id),
        &state_root.trim_start_matches("sha256:")[..16]
    );
    // The coordinate this capture will occupy, derived BEFORE any byte is written, because the next
    // check decides whether those bytes may exist at all.
    let backup_ref = format!(
        "environment-backup://{}/{}",
        estate.estate_namespace, backup_id
    );
    // A CAPTURE OVER A TOMBSTONE IS A RESURRECTION, so it refuses.
    //
    // A backup's coordinate is content-addressed — environment plus source state root — so
    // re-capturing an UNCHANGED workspace lands on the exact object an owner already deleted under
    // an executed retention disposition, and would restore its destroyed bytes to the same
    // content-addressed path under a `pruned` head. Refusing costs the operator a re-capture of an
    // untouched environment at the same coordinate; admitting it would mean an executed deletion
    // could be undone by the routine backup schedule that ran after it. The deletion wins.
    if let Err(reply) = refuse_if_deleted(data_dir, &backup_ref, &state_root) {
        return reply;
    }
    // ONE COORDINATE, ONE RECORD — replay an already-captured backup instead of compiling a second.
    //
    // Carrying a retention duty made this necessary and a merge-blocking review proved why. The
    // family is keyed on `environment_artifact_root`, a hash of the WHOLE record, and `expires_at`
    // is derived from the wall clock, so the same logical capture retried a second later compiled
    // different bytes, landed at a different `hveb_` key, and admitted a SECOND record carrying the
    // same `backup_ref`. `backup_by_id` requires a coordinate to resolve exactly once, so read,
    // verify, export, restore — and the retention deletion itself, which resolves its subject the
    // same way — then answered `managed_backup_identity_ambiguous` forever, while both captures had
    // returned 201. Before retention was carried the two records were byte-identical and collapsed
    // onto one key, so this was a regression THIS leg introduced on the most ordinary operation
    // there is: retrying a backup after a timeout.
    //
    // The fix is the coordinate's own meaning. A backup ref is environment plus source state root:
    // identical content at the same environment IS the same backup, so a second capture of it
    // replays the admitted record and admits nothing. Changed content lands on a different ref and
    // takes the normal path.
    if read_backup_lifecycle(data_dir, &backup_ref)
        .ok()
        .flatten()
        .is_some()
    {
        if let Ok(existing) = backup_by_id(data_dir, &backup_ref) {
            return match require_restorable(data_dir, &existing) {
                Ok(verification) => (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "replayed": true,
                        "backup": existing,
                        "verification": verification,
                    })),
                ),
                Err(reply) => reply,
            };
        }
        // A lifecycle head with no resolvable record is a partial capture, not a completed one:
        // fall through and finish it rather than replaying something that is not there.
    }
    if let Err(error) = durable_write(&material_path(data_dir, &state_root), &bytes) {
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
        data_dir,
        true,
        identity,
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
        &estate,
        &declaration,
        &state_root,
        &rows,
        Some(&expires_at),
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
    // The capture's admission evidence is its hash-linked receipt. `receipt://` is one of the
    // `hypervisor-environment-backup/v1` evidence schemes; the agentgres `operation` ref used here
    // before is `agentgres://…`, which the contract's `evidence_refs` pattern rejects — a defect the
    // first end-to-end backup exercised, since no prior test compiled a real backup record through
    // this validation. The operation coordinate remains recoverable from the receipt's batch/root.
    backup["evidence_refs"] = json!([receipt_ref]);
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
    if backup["backup_ref"] != json!(backup_ref) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_coordinate_disagreement",
            "the compiled record's backup_ref is not the coordinate the tombstone gate was asked about",
        );
    }
    let backup_scope = match bind_scope(
        data_dir,
        identity,
        BACKUP_SCOPE_KIND,
        &backup_ref,
        &profile_scope.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
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
        super::substrate_store::admit_required(data_dir, BACKUP_FAMILY, &key, &backup)
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
    if let Err(error) = persist_record(data_dir, BACKUP_FAMILY, &key, &backup) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_projection_persist_failed",
            format!(
                "{error}; the backup is admitted and canonical — replay to rebuild its projection"
            ),
        );
    }
    // Establish the lifecycle head LAST, over a record that is already admitted and projected. The
    // stream describes an object that exists; admitting it earlier would name one that might not.
    let lifecycle = match ensure_backup_lifecycle(
        data_dir,
        identity,
        &backup_scope,
        &backup,
        &json!({ "kind": "captured", "environment_ref": format!("environment://local/{environment_id}") }),
        &format!("{}.lifecycle", request.idempotency_key),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(reply) => return reply,
    };
    match require_restorable(data_dir, &backup) {
        Ok(verification) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "backup": backup,
                "verification": verification,
                "lifecycle": projection_value(&lifecycle, None),
            })),
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
    let backup = match authorized_backup_by_id(&st.data_dir, &identity, &id) {
        Ok((backup, _)) => backup,
        Err(reply) => return reply,
    };
    // A record's own `status` field reads `complete` forever — it describes the CAPTURE, and the
    // registered contract has no field for "an owner deleted this". The lifecycle head does. A read
    // that returned the record alone let a caller conclude that a deleted or expired backup was
    // usable material, which is precisely the honesty gap the tombstone exists to close.
    let lifecycle = match read_backup_lifecycle(
        &st.data_dir,
        backup["backup_ref"].as_str().unwrap_or_default(),
    ) {
        Ok(head) => head
            .map(|head| projection_value(&head, None))
            .unwrap_or(Value::Null),
        Err(reply) => return reply,
    };
    let restorable = match require_restorable(&st.data_dir, &backup) {
        Ok(verification) => json!({ "ok": true, "verification": verification }),
        Err((status, Json(body))) => json!({
            "ok": false,
            "status": status.as_u16(),
            "error": body.get("error").cloned().unwrap_or(Value::Null),
        }),
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "backup": backup,
            "lifecycle": lifecycle,
            "restorable": restorable,
        })),
    )
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
    match require_restorable(&st.data_dir, &backup) {
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
    let verification = match require_restorable(&st.data_dir, &backup) {
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
    // Re-decide restorability at DELIVERY, not only at token mint. A token minted before an owner's
    // retention deletion, or before the duty ran out, must not still hand the bytes over.
    let backup = match backup_by_id(&st.data_dir, backup_ref) {
        Ok(backup) => backup,
        Err(reply) => return reply.into_response(),
    };
    let verification = match require_restorable(&st.data_dir, &backup) {
        Ok(verification) => verification,
        Err(reply) => return reply.into_response(),
    };
    let state_root = record["state_root"].as_str().unwrap_or_default();
    if verification["state_root"] != json!(state_root) {
        return bad(
            StatusCode::CONFLICT,
            "managed_backup_export_state_root_disagreement",
            "the token's state root is not the one the admitted record verifies to",
        )
        .into_response();
    }
    let payload = match std::fs::read(material_path(&st.data_dir, state_root)) {
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
    let bundle = match build_export_bundle(&st.data_dir, &backup, &payload) {
        Ok(bundle) => bundle,
        Err(reply) => return reply.into_response(),
    };
    let bundle_sha256 = digest(&bundle);
    let filename = format!(
        "{}.ioi-backup-bundle.tar",
        safe(record["backup_ref"].as_str().unwrap_or("backup"))
    );
    let mut response = bundle.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, "application/x-tar".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    // The digest a caller must declare back at import. Serving it in a header rather than only in
    // the bytes lets an importer pin what it received without re-deriving trust from the payload.
    if let Ok(value) = bundle_sha256.parse() {
        headers.insert("x-ioi-backup-bundle-sha256", value);
    }
    response
}

// ---------------------------------------------------------------------------------------------
// The portable export bundle, and the fresh-daemon import that consumes it.
//
// Until this cut a backup could not leave the daemon that captured it. The export lane handed back
// the raw workspace tar — payload bytes with no record, no manifest and no provenance — and there
// was no import at all, so the material and the admitted record both lived only in one data
// directory. "A fresh-daemon restore", the unit's own acceptance sentence, was unreachable.
//
// A bundle is a tar of exactly two members: the admitted `HypervisorEnvironmentBackup` record
// VERBATIM, and the captured payload. Verbatim is load-bearing — the record's whole bytes are its
// content address (`environment_artifact_root`) and the family is keyed on that digest, so an
// import re-derives the key from the record it received and any edit to any field lands at a
// different key. The importing daemon therefore never rewrites the record to say it is now locally
// held; where the bytes now live, and that they arrived by import, are LOCAL truth and belong to
// the lifecycle stream.
//
// WHAT AN IMPORT VERIFIES, AND WHAT IT CANNOT. It verifies internal consistency completely: the
// payload against the manifest row and the state root, the manifest root against the rows, the
// record against its registered contract, and the whole bundle against the digest the caller
// declared. It does NOT verify ISSUER: nothing here proves a foreign estate actually produced this
// bundle, because that needs a signature over the record by the source daemon's key and this estate
// has no cross-daemon issuer identity. So an imported record is typed `imported` in its custody
// origin and is never presented as locally captured. That gap is named, not papered over.
// ---------------------------------------------------------------------------------------------

/// Remove one quarantine directory when this guard drops, on every exit path including a refusal.
/// Unverified bytes land in quarantine and nowhere else; leaving them behind would accumulate
/// material this daemon has decided not to trust.
struct Quarantine(PathBuf);

impl Drop for Quarantine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bundle_manifest(backup: &Value, payload: &[u8]) -> Result<Value, Reply> {
    let record_artifact_root = environment_artifact_root(backup).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_artifact_root_failed",
            error,
        )
    })?;
    Ok(json!({
        "schema_version": BUNDLE_SCHEMA,
        "backup": backup,
        "payload_member": BUNDLE_PAYLOAD_MEMBER,
        "payload_sha256": digest(payload),
        "payload_size_bytes": payload.len(),
        "record_artifact_root": record_artifact_root,
        "source": {
            "estate_namespace": super::hypervisor_environment_routes::local_environment_estate_binding().estate_namespace,
            "receipt_refs": backup["receipt_refs"],
            "evidence_refs": backup["evidence_refs"],
        },
    }))
}

/// Assemble the bundle tar. The two members are written into a quarantine directory and archived
/// with the estate's own `tar_dir`, rather than through a hand-rolled writer, so the bundle a
/// foreign daemon parses is produced by the same code path whose reader (`untar_into`, with its
/// path-traversal and member-type validation) is already hardened against hostile input.
fn build_export_bundle(data_dir: &str, backup: &Value, payload: &[u8]) -> Result<Vec<u8>, Reply> {
    let manifest = bundle_manifest(backup, payload)?;
    // Per-REQUEST, not per-payload: two concurrent exports of one backup would otherwise share a
    // staging directory, and each would delete the other's members out from under it mid-archive.
    let staging = Path::new(data_dir)
        .join(BUNDLE_QUARANTINE_DIR)
        .join(format!("export-{}", uuid::Uuid::new_v4()));
    let quarantine = Quarantine(staging.clone());
    let io = |error: std::io::Error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_export_bundle_failed",
            error.to_string(),
        )
    };
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(io)?;
    std::fs::write(
        staging.join(BUNDLE_MANIFEST_MEMBER),
        serde_json::to_vec(&manifest).map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_backup_export_bundle_failed",
                error.to_string(),
            )
        })?,
    )
    .map_err(io)?;
    std::fs::write(staging.join(BUNDLE_PAYLOAD_MEMBER), payload).map_err(io)?;
    let bundle = super::microvm::tar_dir(&staging).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_export_bundle_failed",
            error,
        )
    })?;
    drop(quarantine);
    Ok(bundle)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupImportRequest {
    storage_profile_ref: String,
    bundle_sha256: String,
    bundle_base64: String,
    authority_grant_refs: Vec<String>,
    idempotency_key: String,
}

fn import_refusal(code: &'static str, message: impl Into<String>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

/// POST /v1/hypervisor/backup-imports — re-establish one exported backup on THIS daemon.
///
/// The ordering below is the contract, not an implementation detail:
///   * identity first (rule E), then the caller's own storage-profile authority;
///   * every refusal a pure read can reach — bundle shape, digests, contract, retention, tombstone —
///     lands BEFORE a byte of material is written, so a refused import leaves this daemon exactly as
///     it found it;
///   * the TOMBSTONE gate in particular precedes the material write, because an import over a
///     deleted backup is the resurrection this leg exists to make impossible;
///   * the material is written before the record is admitted, so an interrupted import leaves
///     content-addressed bytes (harmless, and rewritten identically on retry) rather than an
///     admitted record whose bytes are missing, which is a record that lies.
pub(crate) async fn handle_backup_import(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: BackupImportRequest = match parse(body, "managed_backup_import_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "managed_backup_import_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    if let Err(reply) = validate_ref(
        &request.storage_profile_ref,
        "storage_profile_ref",
        &["storage-profile://"],
    ) {
        return reply;
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
        return bad(
            StatusCode::NOT_IMPLEMENTED,
            "managed_backup_backend_executor_unavailable",
            "this daemon build has byte custody only for local_private; remote profiles remain admitted declarations, never silent local fallback",
        );
    }
    if profile["retention_duration_seconds"].as_u64().is_none() {
        return bad(
            StatusCode::CONFLICT,
            "managed_backup_storage_profile_retention_absent",
            "the admitted storage profile records no retention duty, and a profile is admitted GENESIS-ONLY so it cannot be amended in place; import against a NEW storage_profile_ref that declares retention_duration_seconds",
        );
    }

    // ---- the bundle, verified before it is trusted -----------------------------------------
    let bundle = match base64::engine::general_purpose::STANDARD.decode(&request.bundle_base64) {
        Ok(bundle) => bundle,
        Err(error) => {
            return import_refusal(
                "managed_backup_import_bundle_undecodable",
                format!("bundle_base64 is not base64: {error}"),
            )
        }
    };
    if bundle.len() > MAX_IMPORT_BYTES {
        return bad(
            StatusCode::PAYLOAD_TOO_LARGE,
            "managed_backup_import_bundle_too_large",
            format!(
                "bundle is {} bytes; this daemon verifies a bundle whole before trusting it and refuses above {MAX_IMPORT_BYTES}",
                bundle.len()
            ),
        );
    }
    let actual_bundle_sha256 = digest(&bundle);
    if actual_bundle_sha256 != request.bundle_sha256 {
        return import_refusal(
            "managed_backup_import_bundle_digest_mismatch",
            "the received bundle does not match the digest the caller declared for it",
        );
    }
    // Per-REQUEST, so two concurrent imports of the same bundle cannot quarantine into one
    // directory and race each other's extraction.
    let staging = Path::new(&st.data_dir)
        .join(BUNDLE_QUARANTINE_DIR)
        .join(format!("import-{}", uuid::Uuid::new_v4()));
    let quarantine = Quarantine(staging.clone());
    let _ = std::fs::remove_dir_all(&staging);
    if let Err(error) = super::microvm::untar_into(&staging, &bundle) {
        return import_refusal(
            "managed_backup_import_bundle_unreadable",
            format!("bundle is not an admissible archive: {error}"),
        );
    }
    // CLOSED WORLD over the members: exactly the two this format defines, and nothing else. A
    // bundle carrying a third member is refused rather than ignored.
    let mut members = match std::fs::read_dir(&staging) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        Err(error) => {
            return import_refusal("managed_backup_import_bundle_unreadable", error.to_string())
        }
    };
    members.sort();
    if members
        != vec![
            BUNDLE_MANIFEST_MEMBER.to_owned(),
            BUNDLE_PAYLOAD_MEMBER.to_owned(),
        ]
    {
        return import_refusal(
            "managed_backup_import_bundle_members_unexpected",
            format!("a bundle carries exactly {BUNDLE_MANIFEST_MEMBER} and {BUNDLE_PAYLOAD_MEMBER}; this one carries {members:?}"),
        );
    }
    let manifest: Value = match std::fs::read(staging.join(BUNDLE_MANIFEST_MEMBER))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(manifest) => manifest,
        None => {
            return import_refusal(
                "managed_backup_import_manifest_unreadable",
                "the bundle manifest is absent or is not JSON",
            )
        }
    };
    if manifest["schema_version"] != json!(BUNDLE_SCHEMA) {
        return import_refusal(
            "managed_backup_import_manifest_schema_unknown",
            format!("bundle manifest must declare {BUNDLE_SCHEMA}"),
        );
    }
    let payload = match std::fs::read(staging.join(BUNDLE_PAYLOAD_MEMBER)) {
        Ok(payload) => payload,
        Err(error) => {
            return import_refusal(
                "managed_backup_import_payload_unreadable",
                error.to_string(),
            )
        }
    };
    let payload_sha256 = digest(&payload);
    if manifest["payload_sha256"] != json!(payload_sha256)
        || manifest["payload_size_bytes"].as_u64() != Some(payload.len() as u64)
    {
        return import_refusal(
            "managed_backup_import_payload_digest_mismatch",
            "the bundle payload is not the bytes its manifest describes",
        );
    }
    let backup = manifest["backup"].clone();
    if let Err(error) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            "schema://ioi/components/hypervisor/hypervisor-environment-backup/v1",
            &backup,
        )
    {
        return import_refusal("managed_backup_import_contract_invalid", error);
    }
    // The record is content-addressed by its WHOLE bytes, so re-deriving the key here is what makes
    // every field of it tamper-evident: an edit anywhere lands at a different key than the manifest
    // declared, and this comparison catches it.
    let record_artifact_root = match environment_artifact_root(&backup) {
        Ok(root) => root,
        Err(error) => {
            return import_refusal("managed_backup_import_artifact_root_failed", error);
        }
    };
    if manifest["record_artifact_root"] != json!(record_artifact_root) {
        return import_refusal(
            "managed_backup_import_record_tampered",
            "the record does not hash to the artifact root its bundle manifest declared",
        );
    }
    match backup_manifest_root(&backup) {
        Ok(root) if backup["manifest_root"] == json!(root) => {}
        Ok(_) => {
            return import_refusal(
                "managed_backup_import_manifest_root_mismatch",
                "the record's manifest root does not recompute from its own rows",
            )
        }
        Err(error) => return import_refusal("managed_backup_import_manifest_invalid", error),
    }
    // THE BYTES ARE THE BACKUP'S OWN. A bundle whose payload is not the source state root the record
    // was admitted over is refused outright — a restore that cannot verify its own bytes must refuse,
    // never report success over material it cannot vouch for.
    if backup["source_state_root_ref"] != json!(format!("state-root://{payload_sha256}")) {
        return import_refusal(
            "managed_backup_import_material_digest_mismatch",
            "the bundle payload is not the source state root this record was admitted over",
        );
    }
    let row_matches = backup["manifest_rows"]
        .as_array()
        .and_then(|rows| rows.first())
        .is_some_and(|row| {
            row["sha256"] == json!(payload_sha256)
                && row["size_bytes"].as_u64() == Some(payload.len() as u64)
        });
    if !row_matches {
        return import_refusal(
            "managed_backup_import_manifest_row_mismatch",
            "the record's manifest row does not describe the payload the bundle carries",
        );
    }
    if backup["status"] != json!("complete") {
        return import_refusal(
            "managed_backup_import_status_not_restorable",
            format!(
                "only a complete backup is importable material; this record is {}",
                backup["status"]
            ),
        );
    }
    let Some(backup_ref) = backup["backup_ref"].as_str().map(str::to_owned) else {
        return import_refusal(
            "managed_backup_import_record_tampered",
            "the record carries no backup_ref",
        );
    };
    // OWNERSHIP PRECEDES EVERY ANSWER ABOUT THIS COORDINATE. A daemon that already holds this
    // backup must not tell a stranger who merely possesses a bundle that it holds it, that it
    // deleted it, or when its duty ends — each of those is an answer about someone else's record.
    // The scope is READ here and never bound: binding is a write, and a request that is about to be
    // refused must not leave one behind.
    let existing_scope = match super::substrate_store::read_request_scope(
        &st.data_dir,
        BACKUP_SCOPE_KIND,
        &backup_ref,
    ) {
        Ok(scope) => scope,
        Err(refusal) => return scope_refusal(refusal),
    };
    if existing_scope.is_some() {
        if let Err(reply) = authorize_scope(
            &st.data_dir,
            &identity,
            BACKUP_SCOPE_KIND,
            &backup_ref,
            None,
        ) {
            return reply;
        }
    }
    // DELETION PROOF. Before the scope bind, before the material write, before any admission — and
    // asked by CONTENT as well as by name, because the name arrived inside the caller's bundle.
    if let Err(reply) = refuse_if_deleted(&st.data_dir, &backup_ref, &payload_sha256) {
        return reply;
    }
    // RETENTION SURVIVES THE ROUND TRIP. The duty is read from the record exactly as the source
    // daemon compiled it and is never restamped: an import that reset the clock would launder an
    // expiring backup into a fresh one every time it crossed a daemon boundary.
    if let Err(reply) = refuse_if_expired(&backup) {
        return reply;
    }
    // An import onto a daemon that already holds this backup REPLAYS rather than re-admitting: the
    // lifecycle genesis is expected-absent, so a second genesis would conflict forever.
    if let Some(head) = match read_backup_lifecycle(&st.data_dir, &backup_ref) {
        Ok(head) => head,
        Err(reply) => return reply,
    } {
        if head.operation.payload["manifest_root"] != backup["manifest_root"] {
            return bad(
                StatusCode::CONFLICT,
                "managed_backup_import_identity_collision",
                "this daemon already holds a different backup at that coordinate",
            );
        }
        // Answer with the DURABLE record this daemon holds, never with the caller's copy of it. The
        // two are equal on every path that gets here, but echoing the request back is a self-report
        // dressed as a readback.
        let held = match backup_by_id(&st.data_dir, &backup_ref) {
            Ok(held) => held,
            Err(reply) => return reply,
        };
        return match require_restorable(&st.data_dir, &held) {
            Ok(verification) => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "backup": held,
                    "verification": verification,
                    "lifecycle": projection_value(&head, Some(true)),
                })),
            ),
            Err(reply) => reply,
        };
    }
    let backup_scope = match bind_scope(
        &st.data_dir,
        &identity,
        BACKUP_SCOPE_KIND,
        &backup_ref,
        &profile_scope.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if let Err(error) = durable_write(&material_path(&st.data_dir, &payload_sha256), &payload) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_material_persist_failed",
            error.to_string(),
        );
    }
    let key = format!(
        "hveb_{}",
        record_artifact_root.trim_start_matches("sha256:")
    );
    if let Err(error) =
        super::substrate_store::admit_required(&st.data_dir, BACKUP_FAMILY, &key, &backup)
    {
        return bad(
            StatusCode::CONFLICT,
            "managed_backup_agentgres_admission_failed",
            error.to_string(),
        );
    }
    if let Err(error) = persist_record(&st.data_dir, BACKUP_FAMILY, &key, &backup) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_backup_projection_persist_failed",
            format!(
                "{error}; the import is admitted and canonical — replay to rebuild its projection"
            ),
        );
    }
    let lifecycle = match ensure_backup_lifecycle(
        &st.data_dir,
        &identity,
        &backup_scope,
        &backup,
        &json!({
            "kind": "imported",
            "bundle_sha256": actual_bundle_sha256,
            "imported_into_storage_profile_ref": request.storage_profile_ref,
            "source_estate_namespace": manifest.pointer("/source/estate_namespace"),
            "issuer_verified": false,
            "issuer_verification_note": "this estate has no cross-daemon issuer identity; the bundle is verified for internal consistency and custody, never for who produced it",
        }),
        &format!("{}.lifecycle", request.idempotency_key),
    ) {
        Ok(lifecycle) => lifecycle,
        Err(reply) => return reply,
    };
    drop(quarantine);
    match require_restorable(&st.data_dir, &backup) {
        Ok(verification) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "replayed": false,
                "backup": backup,
                "verification": verification,
                "lifecycle": projection_value(&lifecycle, Some(false)),
            })),
        ),
        Err(reply) => reply,
    }
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
    super::environment_routes::authorize_environment_owner_identity(
        data_dir,
        identity,
        environment_id,
    )
    .map_err(environment_owner_refusal)?;
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

/// Points at which a restore filesystem effect can be interrupted between an admitted transition and
/// the effect it promises. Used only by the in-process convergence tests, and modeled on
/// `agentgres::event_stream::force_durability_failure_for_this_thread`: the fault seam ships WITH the
/// state machine, because a resume path whose interruption is unreachable in test is a recovery
/// nobody has watched happen. In production every `restore_effect_interrupted` call compiles to a
/// no-op — the injection body is `#[cfg(test)]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RestoreEffectPoint {
    PrepareBeforeUntar,
    PrepareAfterUntar,
    CancelBeforeRemoval,
    ApplyBeforeRenames,
    ApplyAfterFirstRename,
    ApplyAfterRenames,
}

#[cfg(test)]
thread_local! {
    static RESTORE_EFFECT_FAULT: std::cell::Cell<Option<RestoreEffectPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[must_use = "the guard clears the thread-local restore fault when dropped"]
struct ForcedRestoreEffectFault;

#[cfg(test)]
impl Drop for ForcedRestoreEffectFault {
    fn drop(&mut self) {
        RESTORE_EFFECT_FAULT.with(|cell| cell.set(None));
    }
}

/// Arm an interruption at `point` for the CURRENT THREAD only. Returns a guard that clears it, so a
/// forced fault cannot leak into another test running in parallel.
#[cfg(test)]
fn force_restore_effect_fault_for_this_thread(
    point: RestoreEffectPoint,
) -> ForcedRestoreEffectFault {
    RESTORE_EFFECT_FAULT.with(|cell| cell.set(Some(point)));
    ForcedRestoreEffectFault
}

/// Stop and refuse at `point` when a test has armed exactly that interruption on this thread,
/// simulating a crash after the preceding admitted transition but before this effect runs. The
/// refusal is unreachable in production: the `#[cfg(test)]` body is absent from release builds.
#[inline]
fn restore_effect_interrupted(point: RestoreEffectPoint) -> Result<(), Reply> {
    #[cfg(test)]
    if RESTORE_EFFECT_FAULT.with(std::cell::Cell::get) == Some(point) {
        return Err(bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "managed_restore_effect_interrupted",
            "test-forced restore effect interruption",
        ));
    }
    let _ = point;
    Ok(())
}

/// The rollback custody directory for one plan: the sibling of the workspace that holds the
/// pre-restore bytes while an apply is in flight, named per plan so it never collides with another
/// plan's rollback.
fn restore_rollback_path(workspace: &Path, plan_id: &str) -> Result<PathBuf, Reply> {
    workspace
        .parent()
        .map(|parent| parent.join(format!(".ioi-managed-restore-rollback-{}", safe(plan_id))))
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "managed_restore_workspace_parent_missing",
                "target workspace has no parent",
            )
        })
}

/// Re-decide whether one admitted restore plan's subject is still restore material, and DISCHARGE
/// the staged copy when it is not.
///
/// Removing the staging is deliberate and is not a side effect of a refused request in the sense
/// that rule forbids: those staged bytes ARE the deleted content, so leaving them beside the target
/// workspace would keep the resurrection one rename away and would quietly retain material an owner
/// ordered destroyed. Removal is idempotent, and a removal that fails is reported rather than
/// swallowed — a refusal that claims the copy is gone while it survives is the same class of lie as
/// a deletion that reports success over surviving key material.
fn require_restorable_for_plan(data_dir: &str, plan: &ExactProjection) -> Result<(), Reply> {
    let backup_ref = plan.operation.payload["backup_ref"]
        .as_str()
        .unwrap_or_default();
    let backup = backup_by_id(data_dir, backup_ref)?;
    let verdict = require_restorable(data_dir, &backup);
    if let Err((status, Json(body))) = verdict {
        let staging = plan.operation.payload["target_environment_id"]
            .as_str()
            .and_then(|environment_id| environment_record(data_dir, environment_id).ok())
            .and_then(|environment| {
                environment
                    .pointer("/status/workspace_root")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
            })
            .and_then(|workspace| {
                plan.operation.payload["plan_id"]
                    .as_str()
                    .and_then(|plan_id| restore_staging_path(&workspace, plan_id).ok())
            });
        let discharged = match staging.as_deref() {
            Some(path) => match std::fs::remove_dir_all(path) {
                Ok(()) => json!({ "staged_material_removed": true }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    json!({ "staged_material_removed": false, "reason": "already absent" })
                }
                Err(error) => {
                    return Err(bad(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "managed_restore_staged_material_retained",
                        format!(
                            "this plan's subject is no longer restore material and its staged copy could not be destroyed at {}: {error}",
                            path.display()
                        ),
                    ))
                }
            },
            None => json!({ "staged_material_removed": false, "reason": "staging path unresolvable" }),
        };
        return Err((
            status,
            Json(json!({
                "ok": false,
                "error": body.get("error").cloned().unwrap_or(Value::Null),
                "staged_material": discharged,
            })),
        ));
    }
    Ok(())
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
    prepare_restore_plan(&st.data_dir, &identity, &id, &request)
}

/// Prepare a restore plan as a two-event transition: a `restore_plan_preparing` genesis admitted
/// BEFORE the staging untar (so an interrupted prepare is a resumable intent, never staged bytes with
/// no admitted plan), then a `restore_plan_prepared` successor admitted only once the bytes are
/// staged. Re-presenting the same key resumes rather than restarts: it re-stages when the staging is
/// gone and admits the prepared successor, replays a plan already prepared, and — the terminal-truth
/// fence — refuses a key whose plan is already cancelled or completed instead of staging bytes and
/// replaying a create over an admitted terminal.
///
/// Split out of the async handler (marketplace `begin_`/`finish_` pattern) so the state machine runs
/// against a real tempdir and the real Agentgres chain in test, with the identity already resolved,
/// rather than only through the axum layer.
fn prepare_restore_plan(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    backup_id: &str,
    request: &RestorePlanRequest,
) -> Reply {
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
    let (backup, backup_scope) = match authorized_backup_by_id(data_dir, identity, backup_id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    // Restorability is decided BEFORE the target is resolved, the plan id is minted, or a byte is
    // staged: a tombstoned or expired backup must not reach the staging untar under any ordering.
    if let Err(reply) = require_restorable(data_dir, &backup) {
        return reply;
    }
    let target_scope = match authorized_instance_for_environment(
        data_dir,
        identity,
        &request.target_environment_id,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if target_scope.tenant_ref != backup_scope.tenant_ref {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let target = match environment_record(data_dir, &request.target_environment_id) {
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
    let state_root = backup["source_state_root_ref"]
        .as_str()
        .and_then(|value| value.strip_prefix("state-root://"))
        .unwrap_or_default()
        .to_owned();
    let tail = restore_tail(&plan_id);

    // Read the admitted plan FIRST, before staging, the material read, or any admission. A stream
    // that already reached a terminal transition is answered here so a re-presented key over a
    // cancelled or completed plan stages nothing and admits nothing (the terminal-truth fence), and a
    // plan already past `prepared` replays its current fact rather than re-running the untar.
    let existing = match super::substrate_store::read_event_stream_operation(
        data_dir,
        PERSISTENCE_NAMESPACE,
        &tail,
    ) {
        Ok(existing) => existing,
        Err(error) => return admission_error(error),
    };
    if let Some(current) = &existing {
        match current.operation.payload["status"]
            .as_str()
            .unwrap_or_default()
        {
            "cancelled" | "completed" => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "ok": false,
                        "error": {
                            "code": "managed_restore_plan_terminal",
                            "message": "this idempotency key's restore plan is already cancelled or completed; a new restore of this backup needs a new idempotency_key"
                        },
                        "admitted_head": current.head
                    })),
                );
            }
            "prepared" => {
                return (
                    StatusCode::CREATED,
                    Json(json!({"ok":true,"restore_plan":projection_value(current,Some(true))})),
                );
            }
            "applying" | "cancelling" => {
                return (
                    StatusCode::OK,
                    Json(json!({"ok":true,"restore_plan":projection_value(current,Some(true))})),
                );
            }
            // "preparing": an interrupted prepare. Fall through to resume — re-stage if the bytes are
            // gone, then admit the prepared successor against the preparing genesis head.
            _ => {}
        }
    }

    let scope = match bind_scope(
        data_dir,
        identity,
        RESTORE_SCOPE_KIND,
        &plan_id,
        &backup_scope.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let base = json!({
        "schema_version":"ioi.managed-restore-plan.v1",
        "plan_id":plan_id,
        "backup_ref":backup["backup_ref"],
        "restore_manifest_root":backup["manifest_root"],
        "source_state_root":state_root,
        "target_environment_id":request.target_environment_id,
        "authority_grant_refs":request.authority_grant_refs,
    });

    // GENESIS admitted BEFORE staging. If the untar then fails or the process is interrupted, the
    // plan exists as `preparing` over the source root it named, and a retry re-stages from it: the
    // orphan-staging dead-end (staged bytes with no admitted plan, refused forever as
    // staging_exists) can no longer occur.
    let preparing_head = match &existing {
        Some(current) => current.head.clone(),
        None => {
            let mut preparing = base.clone();
            preparing["status"] = json!("preparing");
            match admit(
                data_dir,
                true,
                identity,
                &scope,
                RESTORE_SCOPE_KIND,
                &plan_id,
                PERSISTENCE_NAMESPACE,
                &tail,
                "event_stream.restore_plan_preparing",
                None,
                &preparing,
                now_ms(),
                &format!("{}.preparing", request.idempotency_key),
            ) {
                Ok((exact, _)) => exact.head,
                Err(reply) => return reply,
            }
        }
    };

    if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::PrepareBeforeUntar) {
        return reply;
    }
    if !staging.exists() {
        let bytes = match std::fs::read(material_path(data_dir, &state_root)) {
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
    }
    if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::PrepareAfterUntar) {
        return reply;
    }

    // SUCCESSOR: the staged bytes are present, so record the plan as prepared. Its expected_head is
    // the preparing genesis; a retry that already admitted prepared replays it here (the boundary's
    // whole-stream idempotency matches the `.prepared` key regardless of the compare-and-swap head).
    let mut prepared = base;
    prepared["status"] = json!("prepared");
    prepared["preparation_verified"] = json!(true);
    match admit(
        data_dir,
        false,
        identity,
        &scope,
        RESTORE_SCOPE_KIND,
        &plan_id,
        PERSISTENCE_NAMESPACE,
        &tail,
        "event_stream.restore_plan_prepared",
        Some(&preparing_head),
        &prepared,
        now_ms(),
        &format!("{}.prepared", request.idempotency_key),
    ) {
        Ok((exact, replayed)) => (
            StatusCode::CREATED,
            Json(json!({"ok":true,"restore_plan":projection_value(&exact,Some(replayed))})),
        ),
        Err(reply) => reply,
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
    let request: RestoreActionRequest = match parse(body, "managed_restore_action_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    act_on_restore_plan(&st.data_dir, &identity, &plan_id, &action, &request)
}

/// Apply or cancel a restore plan through a resume state machine keyed on (admitted status, caller
/// key, on-disk observation) rather than the flat `status == "prepared"` gate the plane shipped.
///
/// * `prepared` + matching expected_head -> the initial transition (admit `cancelling`/`applying`,
///   perform the effects, admit `cancelled`/`completed`).
/// * `cancelling`/`applying` under THIS key -> resume: re-attempt the missing effect and admit the
///   terminal transition. A caller's stale expected_head is intentionally ignored here — the caller
///   key that owns the in-flight transition is the authority, not a head that a partial attempt
///   already moved.
/// * a terminal transition (`cancelled`/`completed`) under THIS key -> replay the terminal response
///   and admit NOTHING, because no earlier fact may be re-admitted over the stream's last word.
/// * anything else (a foreign key, or a plan not yet prepared) -> the plane's existing
///   `managed_restore_plan_not_prepared` 409.
fn act_on_restore_plan(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    plan_id: &str,
    action: &str,
    request: &RestoreActionRequest,
) -> Reply {
    let scope = match authorize_scope(data_dir, identity, RESTORE_SCOPE_KIND, plan_id, None) {
        Ok(scope) => scope,
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
    if !matches!(action, "apply" | "cancel") {
        return bad(
            StatusCode::NOT_FOUND,
            "managed_restore_action_unknown",
            "action must be apply or cancel",
        );
    }
    let tail = restore_tail(plan_id);
    let current = match read_head(data_dir, PERSISTENCE_NAMESPACE, &tail) {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    let status = current.operation.payload["status"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let ak = request.idempotency_key.as_str();

    let environment_id = current.operation.payload["target_environment_id"]
        .as_str()
        .unwrap_or_default();
    if let Err(error) = super::environment_routes::authorize_environment_owner_identity(
        data_dir,
        identity,
        environment_id,
    ) {
        return environment_owner_refusal(error);
    }
    let environment = match environment_record(data_dir, environment_id) {
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
    let staging = match restore_staging_path(&workspace, plan_id) {
        Ok(staging) => staging,
        Err(reply) => return reply,
    };
    let rollback = match restore_rollback_path(&workspace, plan_id) {
        Ok(rollback) => rollback,
        Err(reply) => return reply,
    };

    let not_prepared = || {
        bad(
            StatusCode::CONFLICT,
            "managed_restore_plan_not_prepared",
            "only a prepared restore plan may be applied or cancelled",
        )
    };
    let head_conflict = || {
        bad(
            StatusCode::CONFLICT,
            "managed_restore_expected_head_conflict",
            "expected_head is not the current Agentgres head",
        )
    };

    match action {
        "cancel" => match status.as_str() {
            "prepared" => {
                if current.head != request.expected_head {
                    return head_conflict();
                }
                // Admit the INTENT before destroying the staged bytes. Deleting first meant that if
                // the cancelled append then failed, the plan still read "prepared" while the bytes it
                // promised were already gone.
                let cancelling = match admit_restore_successor(
                    data_dir,
                    identity,
                    &scope,
                    plan_id,
                    &tail,
                    "event_stream.restore_plan_cancelling",
                    &current,
                    "cancelling",
                    &format!("{ak}.cancelling"),
                ) {
                    Ok(exact) => exact,
                    Err(reply) => return reply,
                };
                finalize_cancel(
                    data_dir,
                    identity,
                    &scope,
                    plan_id,
                    &tail,
                    &cancelling,
                    &staging,
                    ak,
                )
            }
            "cancelling" if current.operation.idem_key == format!("{ak}.cancelling") => {
                finalize_cancel(
                    data_dir, identity, &scope, plan_id, &tail, &current, &staging, ak,
                )
            }
            "cancelled" if current.operation.idem_key == format!("{ak}.cancelled") => (
                StatusCode::OK,
                Json(json!({"ok":true,"restore_plan":projection_value(&current,Some(true))})),
            ),
            _ => not_prepared(),
        },
        // "apply"
        _ => match status.as_str() {
            "prepared" => {
                if current.head != request.expected_head {
                    return head_conflict();
                }
                // RESTORABILITY IS RE-DECIDED HERE, NOT INHERITED FROM PREPARE.
                //
                // Everything below this point promotes staged bytes into a live workspace, and the
                // staging happened at prepare — arbitrarily long ago. A retention deletion executed
                // in between purges the material store and admits the tombstone, but it cannot
                // reach a copy already staged beside the target workspace. Deciding once at prepare
                // therefore left the deletion exactly one API call wide: prepare, delete, apply,
                // and the destroyed archive is back on disk under a `pruned` head. The same
                // reasoning covers an expiry that ran out mid-plan.
                if let Err(reply) = require_restorable_for_plan(data_dir, &current) {
                    return reply;
                }
                if !staging.is_dir() {
                    return bad(
                        StatusCode::CONFLICT,
                        "managed_restore_staging_missing",
                        "prepared restore bytes are missing; prepare again under a successor plan",
                    );
                }
                let applying = match admit_restore_successor(
                    data_dir,
                    identity,
                    &scope,
                    plan_id,
                    &tail,
                    "event_stream.restore_plan_applying",
                    &current,
                    "applying",
                    &format!("{ak}.applying"),
                ) {
                    Ok(exact) => exact,
                    Err(reply) => return reply,
                };
                finalize_apply(
                    data_dir, identity, &scope, plan_id, &tail, &applying, &workspace, &staging,
                    &rollback, ak,
                )
            }
            "applying" if current.operation.idem_key == format!("{ak}.applying") => {
                // A resume completes a promotion that was already admitted, so it re-decides too:
                // the interruption it resumes from may have been long enough for the subject to be
                // deleted.
                if let Err(reply) = require_restorable_for_plan(data_dir, &current) {
                    return reply;
                }
                finalize_apply(
                    data_dir, identity, &scope, plan_id, &tail, &current, &workspace, &staging,
                    &rollback, ak,
                )
            }
            "completed"
                if current.operation.idem_key == format!("{ak}.completed")
                    || current.operation.idem_key == format!("{ak}.rollback_retained") =>
            {
                // Terminal replay: admit NOTHING. Releasing the retained rollback material is a
                // filesystem effect (not an admission) and is idempotent, so a replay after a
                // completed append whose durability was unconfirmed — the append landed, the release
                // did not — still discharges the retained copy.
                if rollback.exists() {
                    let _ = std::fs::remove_dir_all(&rollback);
                }
                (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "restore_plan": projection_value(&current, Some(true)),
                        "cleanup_obligation": rollback_obligation_from_payload(&current.operation.payload)
                    })),
                )
            }
            _ => not_prepared(),
        },
    }
}

/// Admit one restore-plan successor: clone the current admitted payload, stamp the new status, and
/// compare-and-swap against the current head under a per-transition key suffix. The suffix keeps each
/// transition from colliding with the genesis or a sibling transition under one reused caller key.
#[allow(clippy::too_many_arguments)]
fn admit_restore_successor(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    plan_id: &str,
    tail: &str,
    op_kind: &str,
    from: &ExactProjection,
    status: &str,
    idempotency_key: &str,
) -> Result<ExactProjection, Reply> {
    let mut payload = from.operation.payload.clone();
    payload["status"] = json!(status);
    admit(
        data_dir,
        false,
        identity,
        scope,
        RESTORE_SCOPE_KIND,
        plan_id,
        PERSISTENCE_NAMESPACE,
        tail,
        op_kind,
        Some(&from.head),
        &payload,
        now_ms(),
        idempotency_key,
    )
    .map(|(exact, _)| exact)
}

/// Finish a cancel from an admitted `cancelling` intent: destroy the staged bytes, then admit the
/// terminal `cancelled`. A crash between the intent and here resumes from `cancelling`.
#[allow(clippy::too_many_arguments)]
fn finalize_cancel(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    plan_id: &str,
    tail: &str,
    cancelling: &ExactProjection,
    staging: &Path,
    ak: &str,
) -> Reply {
    if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::CancelBeforeRemoval) {
        return reply;
    }
    if let Err(error) = std::fs::remove_dir_all(staging) {
        if error.kind() != std::io::ErrorKind::NotFound {
            // The intent is admitted and the bytes are still there. Say so: a retry of this cancel
            // resumes from `cancelling` rather than starting over.
            return bad(
                StatusCode::CONFLICT,
                "managed_restore_cancel_cleanup_failed",
                error.to_string(),
            );
        }
    }
    match admit_restore_successor(
        data_dir,
        identity,
        scope,
        plan_id,
        tail,
        "event_stream.restore_plan_cancelled",
        cancelling,
        "cancelled",
        &format!("{ak}.cancelled"),
    ) {
        Ok(exact) => (
            StatusCode::OK,
            Json(json!({"ok":true,"restore_plan":projection_value(&exact,Some(false))})),
        ),
        Err(reply) => reply,
    }
}

/// Finish an apply from an admitted `applying` intent: perform the workspace/staging renames that are
/// still outstanding (each guarded by its on-disk observation so a resume performs only the steps a
/// prior interrupted apply did not), admit `completed` WHILE the rollback material still exists, then
/// discharge the retained material — recording a durable `restore_plan_rollback_retained` successor
/// if it cannot be removed, rather than the response-only JSON the old apply returned.
#[allow(clippy::too_many_arguments)]
fn finalize_apply(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    plan_id: &str,
    tail: &str,
    applying: &ExactProjection,
    workspace: &Path,
    staging: &Path,
    rollback: &Path,
    ak: &str,
) -> Reply {
    if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::ApplyBeforeRenames) {
        return reply;
    }
    // Writer fence: move the live workspace aside into the rollback custody dir. Skipped when a prior
    // attempt already did it (workspace gone) or a foreign rollback is present.
    if workspace.exists() && !rollback.exists() {
        if let Err(error) = std::fs::rename(workspace, rollback) {
            return bad(
                StatusCode::CONFLICT,
                "managed_restore_writer_fence_failed",
                error.to_string(),
            );
        }
        if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::ApplyAfterFirstRename) {
            return reply;
        }
    }
    // Promote the staged bytes into the workspace. Skipped when a prior attempt already did it.
    if staging.is_dir() {
        if let Err(error) = std::fs::rename(staging, workspace) {
            let rollback_result = std::fs::rename(rollback, workspace);
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "managed_restore_apply_failed",
                format!("{error}; rollback={rollback_result:?}"),
            );
        }
    }
    if let Err(reply) = restore_effect_interrupted(RestoreEffectPoint::ApplyAfterRenames) {
        return reply;
    }
    // Admit completion BEFORE discarding the rollback material. The completed event durably records
    // the rollback material path and a retention obligation, so the obligation is admitted truth
    // rather than a number in a response body a restart forgets.
    let mut completed = applying.operation.payload.clone();
    completed["status"] = json!("completed");
    completed["applied_state_root"] = applying.operation.payload["source_state_root"].clone();
    completed["rollback_material_path"] = json!(rollback.to_string_lossy());
    completed["rollback_retention"] = json!("retained_until_released");
    let completed_exact = match admit(
        data_dir,
        false,
        identity,
        scope,
        RESTORE_SCOPE_KIND,
        plan_id,
        PERSISTENCE_NAMESPACE,
        tail,
        "event_stream.restore_plan_completed",
        Some(&applying.head),
        &completed,
        now_ms(),
        &format!("{ak}.completed"),
    ) {
        Ok((exact, _)) => exact,
        Err(reply) => return reply,
    };
    // The restore is durable. Release the retained rollback copy; if it cannot be removed, admit a
    // `restore_plan_rollback_retained` successor so the retained-material obligation is durable — not
    // a 500 over a restore that did in fact complete, and not a response-only field a reader must
    // trust the reply for.
    let (head_exact, cleanup_obligation) = match std::fs::remove_dir_all(rollback) {
        Ok(()) => (completed_exact, Value::Null),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (completed_exact, Value::Null)
        }
        Err(error) => {
            let mut retained = completed_exact.operation.payload.clone();
            retained["rollback_retention"] = json!("retained");
            retained["rollback_retained_reason"] = json!(error.to_string());
            match admit(
                data_dir,
                false,
                identity,
                scope,
                RESTORE_SCOPE_KIND,
                plan_id,
                PERSISTENCE_NAMESPACE,
                tail,
                "event_stream.restore_plan_rollback_retained",
                Some(&completed_exact.head),
                &retained,
                now_ms(),
                &format!("{ak}.rollback_retained"),
            ) {
                Ok((exact, _)) => {
                    let obligation = rollback_obligation_from_payload(&exact.operation.payload);
                    (exact, obligation)
                }
                Err(reply) => return reply,
            }
        }
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "restore_plan": projection_value(&head_exact, Some(false)),
            "cleanup_obligation": cleanup_obligation
        })),
    )
}

/// The response-visible cleanup obligation derived from a completed plan's admitted payload. A plan
/// carrying `rollback_retention == "retained"` names retained material a caller still owes disk to;
/// any other value is a discharged (or never-retained) obligation.
fn rollback_obligation_from_payload(payload: &Value) -> Value {
    if payload["rollback_retention"] == json!("retained") {
        json!({
            "code": "managed_restore_rollback_material_retained",
            "path": payload["rollback_material_path"],
            "message": payload
                .get("rollback_retained_reason")
                .cloned()
                .unwrap_or(Value::Null)
        })
    } else {
        Value::Null
    }
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
            retention_duration_seconds: 86_400,
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

    // ==================== restore state-machine convergence battery ====================
    //
    // Every test below drives the production functions the routes call — `prepare_restore_plan`,
    // `act_on_restore_plan`, and `capture_environment_backup` — against a real tempdir and the real
    // Agentgres chain, with a full backup/restore corpus, so convergence is read back from durable
    // truth rather than asserted about source order. The interruptions are injected with the
    // thread-local `force_restore_effect_fault_for_this_thread` (mid-effect) and agentgres'
    // `force_durability_failure_for_this_thread` (mid-append), and `reset_handle_for_test` stands in
    // for a restart by forcing the next read to rebuild from the durable log alone.

    use super::super::substrate_store::{
        list_event_stream_tails, read_event_stream_history, read_event_stream_operation,
        request_identity_for_test, reset_handle_for_test, RequestIdentity,
    };
    use std::sync::Mutex;

    /// `force_durability_failure_for_this_thread` is thread-local, but the durability battery is
    /// serialized under this mutex to match the sibling discipline in `mutation_event_foundation`.
    static RESTORE_DURABILITY_FAULT: Mutex<()> = Mutex::new(());

    const TENANT: &str = "org://acme";
    const PRINCIPAL: &str = "user://acme-operator";

    /// A bootable backup/restore corpus: a real Agentgres substrate with a `local_private` storage
    /// profile, a managed instance whose `compute_session.environment_ref` names the target
    /// environment, an on-disk environment record with a materialized workspace, and a completed
    /// backup whose material bytes match the admitted state root and which satisfies the
    /// `hypervisor-environment-backup/v1` contract and `verify_required_exact`. The deep-dive
    /// confirmed no end-to-end backup/restore fixture existed; the state machine tests need one.
    struct RestoreFixture {
        _dir: tempfile::TempDir,
        data_dir: String,
        identity: RequestIdentity,
        backup_id: String,
        environment_id: String,
        workspace: std::path::PathBuf,
    }

    impl RestoreFixture {
        fn prepare(&self, key: &str) -> (StatusCode, Value) {
            let (status, Json(body)) = prepare_restore_plan(
                &self.data_dir,
                &self.identity,
                &self.backup_id,
                &RestorePlanRequest {
                    target_environment_id: self.environment_id.clone(),
                    authority_grant_refs: vec!["grant://acme/1".into()],
                    idempotency_key: key.into(),
                },
            );
            (status, body)
        }

        fn action(
            &self,
            plan_id: &str,
            action: &str,
            key: &str,
            expected_head: &str,
        ) -> (StatusCode, Value) {
            let (status, Json(body)) = act_on_restore_plan(
                &self.data_dir,
                &self.identity,
                plan_id,
                action,
                &RestoreActionRequest {
                    expected_head: expected_head.into(),
                    idempotency_key: key.into(),
                },
            );
            (status, body)
        }

        fn restore_events(&self, plan_id: &str) -> Vec<String> {
            read_event_stream_history(
                &self.data_dir,
                PERSISTENCE_NAMESPACE,
                &restore_tail(plan_id),
            )
            .expect("restore stream is readable")
            .into_iter()
            .map(|exact| exact.operation.op_kind)
            .collect()
        }

        fn restore_status(&self, plan_id: &str) -> String {
            read_event_stream_operation(
                &self.data_dir,
                PERSISTENCE_NAMESPACE,
                &restore_tail(plan_id),
            )
            .expect("restore stream is readable")
            .expect("the plan exists")
            .operation
            .payload["status"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        }

        fn staging(&self, plan_id: &str) -> std::path::PathBuf {
            restore_staging_path(&self.workspace, plan_id).unwrap()
        }

        fn rollback(&self, plan_id: &str) -> std::path::PathBuf {
            restore_rollback_path(&self.workspace, plan_id).unwrap()
        }

        fn workspace_bytes(&self) -> String {
            std::fs::read_to_string(self.workspace.join("data.txt")).unwrap_or_default()
        }

        /// Change the live workspace AFTER the backup so a completed restore is observable: apply must
        /// revert `data.txt` from this drift back to the captured bytes. Kept out of the builder so the
        /// backup exact-retry test can re-tar an unchanged workspace and genuinely replay.
        fn drift_workspace(&self) {
            std::fs::write(self.workspace.join("data.txt"), "drifted after backup").unwrap();
        }
    }

    /// The single admitted restore plan's id, read from durable truth. The interruption tests cannot
    /// read it from a refused prepare's body, so they recover it here.
    fn sole_restore_plan_id(data_dir: &str) -> String {
        let tails = list_event_stream_tails(data_dir, PERSISTENCE_NAMESPACE)
            .expect("persistence tails are enumerable");
        let restore_tails: Vec<String> = tails
            .into_iter()
            .filter(|tail| tail.starts_with("restore-plan."))
            .collect();
        assert_eq!(restore_tails.len(), 1, "expected exactly one restore plan");
        read_event_stream_operation(data_dir, PERSISTENCE_NAMESPACE, &restore_tails[0])
            .expect("readable")
            .expect("the plan exists")
            .operation
            .payload["plan_id"]
            .as_str()
            .expect("plan carries an id")
            .to_owned()
    }

    /// Count admitted capture events across every `backup-capture.*` stream, to prove an exact backup
    /// retry admits no second capture.
    fn capture_event_count(data_dir: &str) -> usize {
        list_event_stream_tails(data_dir, PERSISTENCE_NAMESPACE)
            .unwrap_or_default()
            .into_iter()
            .filter(|tail| tail.starts_with("backup-capture."))
            .filter_map(|tail| {
                read_event_stream_history(data_dir, PERSISTENCE_NAMESPACE, &tail).ok()
            })
            .map(|history| history.len())
            .sum()
    }

    fn plan_id_of(body: &Value) -> String {
        body["restore_plan"]["plan_id"]
            .as_str()
            .unwrap_or_else(|| panic!("prepare response carries no plan_id: {body}"))
            .to_owned()
    }

    fn head_of(body: &Value) -> String {
        body["restore_plan"]["agentgres"]["head"]
            .as_str()
            .unwrap_or_else(|| panic!("prepare response carries no head: {body}"))
            .to_owned()
    }

    /// The original workspace content the backup captures; the restore reverts a later drift back to
    /// exactly this.
    const BACKED_UP_BYTES: &str = "hello restore";

    fn build_restore_fixture() -> RestoreFixture {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap().to_owned();
        reset_handle_for_test();
        let identity = request_identity_for_test(PRINCIPAL, [TENANT.to_string()]);
        let environment_id = "env-acme-1".to_owned();
        let workspace = std::path::Path::new(&data_dir).join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("data.txt"), BACKED_UP_BYTES).unwrap();

        // Mirror the production creation seam: the immutable environment-owner pin lands before
        // the environment record whose workspace the backup captures and restore targets.
        bind_scope(
            &data_dir,
            &identity,
            crate::environment_routes::ENVIRONMENT_SCOPE_KIND,
            &environment_id,
            TENANT,
            "fixture-environment-owner",
        )
        .unwrap();
        std::fs::create_dir_all(std::path::Path::new(&data_dir).join("environments")).unwrap();
        std::fs::write(
            std::path::Path::new(&data_dir)
                .join("environments")
                .join(format!("{}.json", safe(&environment_id))),
            serde_json::to_vec(&json!({
                "status": { "workspace_root": workspace.to_string_lossy(), "substrate": "container" },
                "spec": { "environment_class_id": "container" }
            }))
            .unwrap(),
        )
        .unwrap();

        // Storage profile (local_private) owned by the tenant, admitted through the shared boundary.
        let profile_ref = "storage-profile://acme/primary";
        let profile_scope = bind_scope(
            &data_dir,
            &identity,
            STORAGE_PROFILE_SCOPE_KIND,
            profile_ref,
            TENANT,
            "fixture-profile",
        )
        .unwrap();
        let profile_payload = json!({
            "schema_version": "ioi.storage-profile.v1",
            "storage_profile_ref": profile_ref,
            "owner_ref": TENANT,
            "backend_class": "local_private",
            "destination_ref": "storage://acme/local",
            "custody_policy_ref": "policy://acme/custody",
            "encryption_ref": Value::Null,
            "key_epoch_ref": Value::Null,
            "retention_policy_ref": "policy://acme/retention",
            "retention_duration_seconds": 86_400,
        });
        admit(
            &data_dir,
            true,
            &identity,
            &profile_scope,
            STORAGE_PROFILE_SCOPE_KIND,
            profile_ref,
            PERSISTENCE_NAMESPACE,
            &hash_tail("storage-profile", profile_ref),
            "event_stream.storage_profile_created",
            None,
            &profile_payload,
            now_ms(),
            "fixture-profile",
        )
        .unwrap();

        // Managed instance whose compute session names the target environment.
        let instance_id = "agent://acme/worker-1";
        let instance_scope = bind_scope(
            &data_dir,
            &identity,
            INSTANCE_SCOPE_KIND,
            instance_id,
            TENANT,
            "fixture-instance",
        )
        .unwrap();
        let instance_payload = json!({
            "schema_version": "ioi.managed-worker-instance-state.v1",
            "instance_id": instance_id,
            "owner_ref": TENANT,
            "compute_session": { "environment_ref": format!("environment://local/{environment_id}") },
        });
        admit(
            &data_dir,
            true,
            &identity,
            &instance_scope,
            INSTANCE_SCOPE_KIND,
            instance_id,
            RUNTIME_NAMESPACE,
            &hash_tail("instance", instance_id),
            "event_stream.managed_worker_created",
            None,
            &instance_payload,
            now_ms(),
            "fixture-instance",
        )
        .unwrap();

        // Drive the real capture path to produce a contract-valid backup + its material bytes.
        let backup_request = BackupCreateRequest {
            storage_profile_ref: profile_ref.into(),
            backup_policy_ref: "policy://acme/backups".into(),
            trigger: "manual".into(),
            actor_ref: TENANT.into(),
            instance_ref: Some(instance_id.into()),
            system_ref: None,
            schedule_or_change_plan_ref: None,
            authority_grant_refs: vec!["grant://acme/1".into()],
            idempotency_key: "fixture-backup".into(),
        };
        let (status, Json(body)) =
            capture_environment_backup(&data_dir, &identity, &environment_id, &backup_request);
        assert_eq!(status, StatusCode::CREATED, "fixture backup failed: {body}");
        let backup_ref = body["backup"]["backup_ref"].as_str().unwrap().to_owned();
        let backup_id = backup_ref.rsplit('/').next().unwrap().to_owned();

        RestoreFixture {
            _dir: dir,
            data_dir,
            identity,
            backup_id,
            environment_id,
            workspace,
        }
    }

    #[test]
    fn prepare_exact_retry_stages_once_across_a_handle_reset() {
        let fx = build_restore_fixture();
        let (status, body) = fx.prepare("plan-1");
        assert_eq!(status, StatusCode::CREATED);
        let plan_id = plan_id_of(&body);
        assert_eq!(fx.restore_status(&plan_id), "prepared");
        assert_eq!(
            fx.restore_events(&plan_id),
            vec![
                "event_stream.restore_plan_preparing".to_string(),
                "event_stream.restore_plan_prepared".to_string()
            ],
            "a fresh prepare admits exactly the preparing genesis and the prepared successor"
        );
        assert!(fx.staging(&plan_id).is_dir());

        // Restart, then retry the exact same key. It must replay from the durable log: no third
        // event, no re-stage.
        reset_handle_for_test();
        let (retry_status, retry_body) = fx.prepare("plan-1");
        assert_eq!(retry_status, StatusCode::CREATED);
        assert_eq!(
            retry_body["restore_plan"]["agentgres"]["replayed"],
            json!(true)
        );
        assert_eq!(
            fx.restore_events(&plan_id).len(),
            2,
            "an exact retry of a prepared plan admitted a new event"
        );
    }

    #[test]
    fn prepare_interrupted_before_untar_restages_and_converges() {
        let fx = build_restore_fixture();
        // Crash after the preparing genesis is admitted, before the untar: an intent over a source
        // root, with no staged bytes.
        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::PrepareBeforeUntar);
        let (status, body) = fx.prepare("plan-2");
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body["error"]["code"],
            json!("managed_restore_effect_interrupted")
        );
        let plan_id = sole_restore_plan_id(&fx.data_dir);
        assert_eq!(
            fx.restore_status(&plan_id),
            "preparing",
            "the genesis intent is admitted, the prepared successor is not"
        );
        assert!(!fx.staging(&plan_id).exists(), "the untar never ran");
        assert_eq!(
            fx.restore_events(&plan_id),
            vec!["event_stream.restore_plan_preparing".to_string()]
        );

        // Restart and resume. The prepared successor must be admitted over re-staged bytes.
        reset_handle_for_test();
        let (resume_status, resume_body) = fx.prepare("plan-2");
        assert_eq!(resume_status, StatusCode::CREATED);
        assert_eq!(plan_id_of(&resume_body), plan_id);
        assert_eq!(fx.restore_status(&plan_id), "prepared");
        assert!(
            fx.staging(&plan_id).is_dir(),
            "resume must re-stage the bytes"
        );
        assert_eq!(
            fx.restore_events(&plan_id),
            vec![
                "event_stream.restore_plan_preparing".to_string(),
                "event_stream.restore_plan_prepared".to_string()
            ]
        );
    }

    #[test]
    fn prepare_interrupted_after_untar_admits_prepared_without_restaging() {
        let fx = build_restore_fixture();
        // Crash after the untar, before the prepared successor: staged bytes with a plan still
        // reading `preparing`.
        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::PrepareAfterUntar);
        let (status, _) = fx.prepare("plan-3");
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let plan_id = sole_restore_plan_id(&fx.data_dir);
        assert_eq!(fx.restore_status(&plan_id), "preparing");
        assert!(
            fx.staging(&plan_id).is_dir(),
            "the untar ran, the successor did not admit"
        );

        // Tamper the staged bytes: a resume that wrongly re-untars would revert this marker back to
        // the captured content, so its survival proves the untar was skipped.
        std::fs::write(
            fx.staging(&plan_id).join("data.txt"),
            "resumed-without-restage",
        )
        .unwrap();
        reset_handle_for_test();
        let (resume_status, resume_body) = fx.prepare("plan-3");
        assert_eq!(resume_status, StatusCode::CREATED, "{resume_body}");
        assert_eq!(plan_id_of(&resume_body), plan_id);
        assert_eq!(fx.restore_status(&plan_id), "prepared");
        assert_eq!(
            std::fs::read_to_string(fx.staging(&plan_id).join("data.txt")).unwrap(),
            "resumed-without-restage",
            "resume must NOT re-untar over already-staged bytes"
        );
    }

    #[test]
    fn cancel_interrupted_after_intent_removes_staging_and_converges() {
        let fx = build_restore_fixture();
        let (_, body) = fx.prepare("plan-4");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);
        assert!(fx.staging(&plan_id).is_dir());

        // Crash after the cancelling intent is admitted, before the staged bytes are removed.
        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::CancelBeforeRemoval);
        let (status, _) = fx.action(&plan_id, "cancel", "act-4", &head);
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(fx.restore_status(&plan_id), "cancelling");
        assert!(
            fx.staging(&plan_id).is_dir(),
            "the intent is admitted but the bytes are still there"
        );

        // Restart and retry: resume from `cancelling`, remove the bytes, admit `cancelled`.
        reset_handle_for_test();
        let (resume_status, resume_body) = fx.action(&plan_id, "cancel", "act-4", &head);
        assert_eq!(resume_status, StatusCode::OK, "{resume_body}");
        assert_eq!(fx.restore_status(&plan_id), "cancelled");
        assert!(
            !fx.staging(&plan_id).exists(),
            "resume must remove the staged bytes"
        );
    }

    #[test]
    fn cancel_exact_retry_after_completion_replays_with_zero_new_events() {
        let fx = build_restore_fixture();
        let (_, body) = fx.prepare("plan-5");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);
        let (status, _) = fx.action(&plan_id, "cancel", "act-5", &head);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fx.restore_status(&plan_id), "cancelled");
        let events_before = fx.restore_events(&plan_id).len();

        reset_handle_for_test();
        let (retry_status, retry_body) = fx.action(&plan_id, "cancel", "act-5", &head);
        assert_eq!(retry_status, StatusCode::OK);
        assert_eq!(
            retry_body["restore_plan"]["agentgres"]["replayed"],
            json!(true)
        );
        assert_eq!(
            fx.restore_events(&plan_id).len(),
            events_before,
            "a terminal-cancel replay admitted a new event"
        );
    }

    #[test]
    fn apply_interrupted_before_renames_converges() {
        let fx = build_restore_fixture();
        fx.drift_workspace();
        let (_, body) = fx.prepare("plan-6");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);

        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::ApplyBeforeRenames);
        let (status, _) = fx.action(&plan_id, "apply", "act-6", &head);
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(fx.restore_status(&plan_id), "applying");
        assert!(fx.staging(&plan_id).is_dir());
        assert!(
            !fx.rollback(&plan_id).exists(),
            "no rename ran, so no rollback yet"
        );
        assert_eq!(fx.workspace_bytes(), "drifted after backup");

        reset_handle_for_test();
        let (resume_status, resume_body) = fx.action(&plan_id, "apply", "act-6", &head);
        assert_eq!(resume_status, StatusCode::OK, "{resume_body}");
        assert_eq!(fx.restore_status(&plan_id), "completed");
        assert_eq!(
            fx.workspace_bytes(),
            BACKED_UP_BYTES,
            "the restore reverted the drift"
        );
        assert!(
            !fx.rollback(&plan_id).exists(),
            "the rollback copy was released"
        );
    }

    #[test]
    fn apply_interrupted_after_first_rename_converges() {
        let fx = build_restore_fixture();
        fx.drift_workspace();
        let (_, body) = fx.prepare("plan-7");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);

        // Crash between the writer-fence rename (workspace -> rollback) and the promote rename
        // (staging -> workspace).
        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::ApplyAfterFirstRename);
        let (status, _) = fx.action(&plan_id, "apply", "act-7", &head);
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !fx.workspace.exists(),
            "the workspace was moved to the rollback custody dir"
        );
        assert!(fx.rollback(&plan_id).exists());
        assert!(fx.staging(&plan_id).is_dir());

        reset_handle_for_test();
        let (resume_status, resume_body) = fx.action(&plan_id, "apply", "act-7", &head);
        assert_eq!(resume_status, StatusCode::OK, "{resume_body}");
        assert_eq!(fx.restore_status(&plan_id), "completed");
        assert_eq!(fx.workspace_bytes(), BACKED_UP_BYTES);
        assert!(!fx.rollback(&plan_id).exists());
    }

    #[test]
    fn completed_append_durability_fault_leaves_rollback_then_converges() {
        let _serialized = RESTORE_DURABILITY_FAULT.lock().unwrap();
        let fx = build_restore_fixture();
        fx.drift_workspace();
        let (_, body) = fx.prepare("plan-8");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);

        // Phase 1: reach the state where both renames are done but completion is not yet admitted.
        let guard =
            force_restore_effect_fault_for_this_thread(RestoreEffectPoint::ApplyAfterRenames);
        let (status, _) = fx.action(&plan_id, "apply", "act-8", &head);
        drop(guard);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(fx.restore_status(&plan_id), "applying");
        assert!(fx.rollback(&plan_id).exists());

        // Phase 2: the completed append lands but its durability is unconfirmed. The caller sees an
        // error and the rollback material is left on disk.
        reset_handle_for_test();
        let durability = agentgres::event_stream::force_durability_failure_for_this_thread();
        let (fault_status, _) = fx.action(&plan_id, "apply", "act-8", &head);
        drop(durability);
        assert_eq!(fault_status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            fx.rollback(&plan_id).exists(),
            "a completed-append durability fault must leave the rollback copy on disk"
        );

        // Phase 3: retry with durability restored. The plan converges to completed and the retained
        // rollback material is discharged.
        reset_handle_for_test();
        let (converge_status, converge_body) = fx.action(&plan_id, "apply", "act-8", &head);
        assert_eq!(converge_status, StatusCode::OK, "{converge_body}");
        assert_eq!(fx.restore_status(&plan_id), "completed");
        assert!(
            !fx.rollback(&plan_id).exists(),
            "convergence must release the rollback copy"
        );
        assert_eq!(fx.workspace_bytes(), BACKED_UP_BYTES);
        let completed = fx
            .restore_events(&plan_id)
            .into_iter()
            .filter(|kind| kind == "event_stream.restore_plan_completed")
            .count();
        assert_eq!(completed, 1, "convergence admitted a second completion");
    }

    #[test]
    fn terminal_truth_fence_refuses_prepare_after_a_terminal_transition() {
        // After completion.
        let fx = build_restore_fixture();
        let (_, body) = fx.prepare("plan-9");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);
        assert_eq!(
            fx.action(&plan_id, "apply", "act-9", &head).0,
            StatusCode::OK
        );
        assert_eq!(fx.restore_status(&plan_id), "completed");
        let events_before = fx.restore_events(&plan_id).len();
        let staging_before = fx.staging(&plan_id).exists();

        let (fence_status, fence_body) = fx.prepare("plan-9");
        assert_eq!(fence_status, StatusCode::CONFLICT);
        assert_eq!(
            fence_body["error"]["code"],
            json!("managed_restore_plan_terminal")
        );
        assert_eq!(
            fx.restore_events(&plan_id).len(),
            events_before,
            "the terminal fence admitted a new event"
        );
        assert_eq!(
            fx.staging(&plan_id).exists(),
            staging_before,
            "the terminal fence staged new bytes"
        );

        // After cancellation, the same fence applies.
        let fx2 = build_restore_fixture();
        let (_, body2) = fx2.prepare("plan-9c");
        let plan_id2 = plan_id_of(&body2);
        let head2 = head_of(&body2);
        assert_eq!(
            fx2.action(&plan_id2, "cancel", "act-9c", &head2).0,
            StatusCode::OK
        );
        assert_eq!(fx2.restore_status(&plan_id2), "cancelled");
        let events_before2 = fx2.restore_events(&plan_id2).len();
        let (fence_status2, fence_body2) = fx2.prepare("plan-9c");
        assert_eq!(fence_status2, StatusCode::CONFLICT);
        assert_eq!(
            fence_body2["error"]["code"],
            json!("managed_restore_plan_terminal")
        );
        assert_eq!(fx2.restore_events(&plan_id2).len(), events_before2);
    }

    #[test]
    fn restore_transition_exact_retry_replays_across_a_restart() {
        // A completed apply is a shared-boundary successor transition; retrying its exact command
        // after a restart must replay it and admit nothing new.
        let fx = build_restore_fixture();
        let (_, body) = fx.prepare("plan-10");
        let plan_id = plan_id_of(&body);
        let head = head_of(&body);
        assert_eq!(
            fx.action(&plan_id, "apply", "act-10", &head).0,
            StatusCode::OK
        );
        let events_before = fx.restore_events(&plan_id).len();

        reset_handle_for_test();
        let (retry_status, retry_body) = fx.action(&plan_id, "apply", "act-10", &head);
        assert_eq!(retry_status, StatusCode::OK);
        assert_eq!(
            retry_body["restore_plan"]["agentgres"]["replayed"],
            json!(true)
        );
        assert_eq!(fx.restore_status(&plan_id), "completed");
        assert_eq!(
            fx.restore_events(&plan_id).len(),
            events_before,
            "a completed-apply replay across a restart admitted a new transition"
        );
        // A terminal replay must run NO effects: re-running the apply would move the restored
        // workspace back into rollback and then delete it.
        assert_eq!(
            fx.workspace_bytes(),
            BACKED_UP_BYTES,
            "the replay must not touch the workspace"
        );
    }

    #[test]
    fn backup_capture_exact_retry_writes_one_material_and_one_event() {
        // The fixture captured one backup under `fixture-backup` over an undrifted workspace.
        // Re-driving the exact capture after a restart must replay: no second capture event, no
        // second material file. (The workspace is deliberately NOT drifted here, so the re-tar is
        // byte-identical and the state root matches.)
        let fx = build_restore_fixture();
        assert_eq!(
            capture_event_count(&fx.data_dir),
            1,
            "the fixture captured exactly one backup"
        );
        let request = BackupCreateRequest {
            storage_profile_ref: "storage-profile://acme/primary".into(),
            backup_policy_ref: "policy://acme/backups".into(),
            trigger: "manual".into(),
            actor_ref: TENANT.into(),
            instance_ref: Some("agent://acme/worker-1".into()),
            system_ref: None,
            schedule_or_change_plan_ref: None,
            authority_grant_refs: vec!["grant://acme/1".into()],
            idempotency_key: "fixture-backup".into(),
        };
        reset_handle_for_test();
        let (status, Json(body)) =
            capture_environment_backup(&fx.data_dir, &fx.identity, &fx.environment_id, &request);
        // A retry is a REPLAY, not a second creation. It answers 200 and says so, matching the rest
        // of this plane — and it must, because carrying a wall-clock retention duty means a
        // recompiled record would differ in `expires_at`, land at a different whole-record key, and
        // admit a SECOND record at one `backup_ref`. `backup_by_id` requires a coordinate to resolve
        // exactly once, so that would wedge read, verify, export, restore AND the retention deletion
        // itself behind `managed_backup_identity_ambiguous` — permanently, after two 201s.
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], json!(true));
        assert_eq!(body["replayed"], json!(true), "{body}");
        assert_eq!(
            capture_event_count(&fx.data_dir),
            1,
            "an exact backup retry admitted a second capture event"
        );
        let material_files =
            std::fs::read_dir(std::path::Path::new(&fx.data_dir).join(BACKUP_MATERIAL_DIR))
                .unwrap()
                .count();
        assert_eq!(
            material_files, 1,
            "an exact backup retry wrote a second material file"
        );
        let record_files =
            std::fs::read_dir(std::path::Path::new(&fx.data_dir).join(BACKUP_FAMILY))
                .map(|entries| entries.count())
                .unwrap_or(0);
        assert_eq!(
            record_files, 1,
            "ONE COORDINATE, ONE RECORD: an exact backup retry admitted a second record, which \
             makes its backup_ref unresolvable and takes deletion down with it"
        );
    }
}

/// Cross-plane test support: one admitted, contract-valid backup with real material bytes,
/// built through the REAL capture path — the record is compiled, admitted through the shared
/// mutation boundary, and byte-verified exactly as production does; no fixture corpus.
/// Consumed by the download-intent plane's tests.
#[cfg(test)]
pub(crate) mod backup_fixture {
    use super::*;
    use serde_json::json;

    pub(crate) const FIXTURE_TENANT: &str = "org://acme";
    pub(crate) const FIXTURE_PRINCIPAL: &str = "user://acme-operator";
    pub(crate) const FIXTURE_WORKSPACE_BYTES: &str = "hello download intent";

    pub(crate) struct AdmittedBackupFixture {
        pub(crate) _dir: tempfile::TempDir,
        pub(crate) data_dir: String,
        pub(crate) identity: super::super::substrate_store::RequestIdentity,
        pub(crate) backup_id: String,
        pub(crate) backup_ref: String,
        pub(crate) state_root: String,
    }

    pub(crate) fn admitted_backup_fixture() -> AdmittedBackupFixture {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap().to_owned();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            FIXTURE_PRINCIPAL,
            [FIXTURE_TENANT.to_string()],
        );
        let environment_id = "env-acme-dl".to_owned();
        let workspace = std::path::Path::new(&data_dir).join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("data.txt"), FIXTURE_WORKSPACE_BYTES).unwrap();

        // Mirror the production creation seam: bind environment ownership before its record.
        bind_scope(
            &data_dir,
            &identity,
            crate::environment_routes::ENVIRONMENT_SCOPE_KIND,
            &environment_id,
            FIXTURE_TENANT,
            "dl-fixture-environment-owner",
        )
        .unwrap();
        std::fs::create_dir_all(std::path::Path::new(&data_dir).join("environments")).unwrap();
        std::fs::write(
            std::path::Path::new(&data_dir)
                .join("environments")
                .join(format!("{}.json", safe(&environment_id))),
            serde_json::to_vec(&json!({
                "status": { "workspace_root": workspace.to_string_lossy(), "substrate": "container" },
                "spec": { "environment_class_id": "container" }
            }))
            .unwrap(),
        )
        .unwrap();

        let profile_ref = "storage-profile://acme/download-primary";
        let profile_scope = bind_scope(
            &data_dir,
            &identity,
            STORAGE_PROFILE_SCOPE_KIND,
            profile_ref,
            FIXTURE_TENANT,
            "dl-fixture-profile",
        )
        .unwrap();
        let profile_payload = json!({
            "schema_version": "ioi.storage-profile.v1",
            "storage_profile_ref": profile_ref,
            "owner_ref": FIXTURE_TENANT,
            "backend_class": "local_private",
            "destination_ref": "storage://acme/local",
            "custody_policy_ref": "policy://acme/custody",
            "encryption_ref": Value::Null,
            "key_epoch_ref": Value::Null,
            "retention_policy_ref": "policy://acme/retention",
            "retention_duration_seconds": 86_400,
        });
        admit(
            &data_dir,
            true,
            &identity,
            &profile_scope,
            STORAGE_PROFILE_SCOPE_KIND,
            profile_ref,
            PERSISTENCE_NAMESPACE,
            &hash_tail("storage-profile", profile_ref),
            "event_stream.storage_profile_created",
            None,
            &profile_payload,
            now_ms(),
            "dl-fixture-profile",
        )
        .unwrap();

        let instance_id = "agent://acme/dl-worker-1";
        let instance_scope = bind_scope(
            &data_dir,
            &identity,
            INSTANCE_SCOPE_KIND,
            instance_id,
            FIXTURE_TENANT,
            "dl-fixture-instance",
        )
        .unwrap();
        let instance_payload = json!({
            "schema_version": "ioi.managed-worker-instance-state.v1",
            "instance_id": instance_id,
            "owner_ref": FIXTURE_TENANT,
            "compute_session": { "environment_ref": format!("environment://local/{environment_id}") },
        });
        admit(
            &data_dir,
            true,
            &identity,
            &instance_scope,
            INSTANCE_SCOPE_KIND,
            instance_id,
            RUNTIME_NAMESPACE,
            &hash_tail("instance", instance_id),
            "event_stream.managed_worker_created",
            None,
            &instance_payload,
            now_ms(),
            "dl-fixture-instance",
        )
        .unwrap();

        let backup_request = BackupCreateRequest {
            storage_profile_ref: profile_ref.into(),
            backup_policy_ref: "policy://acme/backups".into(),
            trigger: "manual".into(),
            actor_ref: FIXTURE_TENANT.into(),
            instance_ref: Some(instance_id.into()),
            system_ref: None,
            schedule_or_change_plan_ref: None,
            authority_grant_refs: vec!["grant://acme/1".into()],
            idempotency_key: "dl-fixture-backup".into(),
        };
        let (status, Json(body)) =
            capture_environment_backup(&data_dir, &identity, &environment_id, &backup_request);
        assert_eq!(status, StatusCode::CREATED, "fixture backup failed: {body}");
        let backup_ref = body["backup"]["backup_ref"].as_str().unwrap().to_owned();
        let backup_id = backup_ref.rsplit('/').next().unwrap().to_owned();
        let state_root = body["verification"]["state_root"]
            .as_str()
            .unwrap()
            .to_owned();

        AdmittedBackupFixture {
            _dir: dir,
            data_dir,
            identity,
            backup_id,
            backup_ref,
            state_root,
        }
    }
}
