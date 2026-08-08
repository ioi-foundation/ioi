//! Executable Foundry model-factory control plane.
//!
//! This is a bounded, real vertical slice: immutable recipe revisions execute
//! deterministic built-in transforms; snapshots bind the exact output bytes;
//! a small reference trainer advances in explicit restart-safe steps; every
//! step produces a complete content-addressed checkpoint; and qualification
//! reports fully dimensioned wall-clock measurements. It deliberately does
//! not claim frontier-model capability or production-route activation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use agentgres::event_stream::AdmissionRefusal;
use agentgres::mux::ExactProjection;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::DaemonState;

const NAMESPACE: &str = "foundry-factory";
const DATA_DIR: &str = "foundry-dataset-artifacts";
const CHECKPOINT_DIR: &str = "foundry-checkpoint-artifacts";
const MAX_ROWS: usize = 10_000;
const MAX_ENCODED_ROWS: usize = 8 * 1024 * 1024;
const PORTABLE_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const RECIPE_SCOPE_KIND: &str = "foundry-recipe";
const DATASET_SCOPE_KIND: &str = "foundry-dataset-snapshot";
const PROGRAM_SCOPE_KIND: &str = "foundry-training-program";
const ARTIFACT_INTENT_SCOPE_KIND: &str = "foundry-artifact-intent";
const ARTIFACT_INTENT_RECORDED: &str = "event_stream.foundry_artifact_intent_recorded";
const ARTIFACT_INTENT_ABANDONED: &str = "event_stream.foundry_artifact_intent_abandoned";
const DATASET_PARENT_OP: &str = "event_stream.foundry_dataset_materialized";
const CHECKPOINT_PARENT_OP: &str = "event_stream.foundry_program_checkpointed";

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

fn jcs_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_jcs::to_vec(value).map_err(|error| error.to_string())
}

fn jcs_digest(value: &Value) -> Result<String, String> {
    jcs_bytes(value).map(|bytes| digest(&bytes))
}

fn hash_tail(prefix: &str, identity: &str) -> String {
    format!("{prefix}.{:x}", Sha256::digest(identity.as_bytes()))
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
) -> Result<BTreeSet<String>, Reply> {
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
        && value.len() <= 500
        && !value.chars().any(char::is_whitespace)
    {
        Ok(())
    } else {
        Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_ref_invalid",
            format!("{field} is not an allowed canonical ref"),
        ))
    }
}

fn require_nonempty(values: &[String], field: &str) -> Result<(), Reply> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_required_refs_missing",
            format!("{field} requires at least one non-empty ref"),
        ))
    } else {
        Ok(())
    }
}

/// Map a shared-boundary refusal onto this plane's existing reply vocabulary. Admission refusals go
/// through the plane's own `admission_error` (409 head/same-key, 400 non-canonical, 503 otherwise —
/// deliberately NOT the package plane's 502), and scope refusals through the plane's `scope_refusal`,
/// so re-homing onto the shared admit changes no status code a caller already depends on.
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

/// Admit one Foundry mutation through the shared owner-scoped boundary. `genesis` is expected-absent;
/// a successor MUST carry the exact `expected_head`. The plane keeps its legacy hand-derived
/// `stream_tail` (so list/inventory reads still resolve) while inheriting the substrate's single
/// definition of request identity, idempotency, and durability confirmation.
#[allow(clippy::too_many_arguments)]
fn admit(
    data_dir: &str,
    genesis: bool,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
    stream_tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    payload: &Value,
    recorded_at_ms: u64,
    idempotency_key: &str,
) -> Result<super::mutation_event_foundation::MutationCommit, Reply> {
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity,
            scope,
            resource_kind,
            resource_ref,
            owner_namespace: NAMESPACE,
            stream_tail,
            op_kind,
            expected_head,
            payload,
            idempotency_key,
            recorded_at_ms,
        },
    )
    .map_err(mutation_refusal)
}

fn read_head(data_dir: &str, tail: &str) -> Result<ExactProjection, Reply> {
    super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, tail)
        .map_err(admission_error)?
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "foundry_object_not_found",
                "the requested admitted Foundry object does not exist",
            )
        })
}

fn projection_value(exact: &ExactProjection, replayed: Option<bool>) -> Value {
    let mut payload = exact.operation.payload.clone();
    if let Some(object) = payload.as_object_mut() {
        let coordinates = exact
            .operation
            .object_ref
            .strip_prefix("agentgres://event-stream-operations/")
            .and_then(|suffix| suffix.split_once('/'));
        let owner = coordinates.map(|(owner, _)| owner).unwrap_or(NAMESPACE);
        let tail = coordinates.map(|(_, tail)| tail).unwrap_or("unknown");
        object.insert(
            "agentgres".into(),
            json!({
                "operation_ref":agentgres::refs::event_stream_operation_ref(owner,tail,exact.seq,&exact.head),
                "receipt_ref":agentgres::refs::event_stream_receipt_ref(owner,tail,exact.admission_batch_seq,&exact.admission_root),
                "sequence":exact.seq,
                "head":exact.head,
                "admission_batch_sequence":exact.admission_batch_seq,
                "admission_root":exact.admission_root,
                "terminal_root":exact.terminal_root,
                "recorded_at_ms":exact.operation.recorded_at_ms,
                "replayed":replayed,
            }),
        );
    }
    payload
}

fn durable_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("artifact path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    if path.exists() {
        if std::fs::read(path)? == bytes {
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "content-addressed artifact path contains different bytes",
        ));
    }
    let temporary = parent.join(format!(
        ".{}.{}.pending",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact"),
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

fn artifact_path(data_dir: &str, family: &str, hash: &str) -> PathBuf {
    Path::new(data_dir)
        .join(family)
        .join(format!("{}.json", hash.trim_start_matches("sha256:")))
}

// ---- Foundry artifact-intent durability obligations -------------------------------------------
//
// Two Foundry effects materialize a content-addressed blob on the local filesystem before their
// admitted event: the dataset material (handle_recipe_run) and each per-step checkpoint (program
// `step`). A blob written before its parent event is admitted is an orphan if that admission then
// fails. An artifact intent is a durable obligation admitted BEFORE the blob and BEFORE the parent
// event, keyed by the caller's own idempotency key so an exact retry replays it rather than
// recording a second obligation. Discharge is DERIVED, never stored: the intent is discharged once
// its parent event is admitted under the same key on the parent stream. The intent lives on its own
// hash_tail("artifact-intent", intent_ref) stream in the SAME namespace, so the existing recipe./
// dataset./program. list routes never see it. The identity is content-addressed on the exact
// artifact hash (INV: the trailing segment of intent_ref equals that hash), so an intent can never
// name a blob other than the one whose durability it records.

struct ArtifactIntentSpec<'a> {
    family: &'a str,
    parent_kind: &'a str,
    parent_stream_tail: &'a str,
    parent_resource_ref: &'a str,
    parent_op_kind: &'a str,
    artifact_hash: &'a str,
    artifact_ref: &'a str,
    owner_ref: &'a str,
    idempotency_key: &'a str,
}

fn artifact_intent_ref(family: &str, parent_stream_tail: &str, artifact_hash: &str) -> String {
    format!(
        "foundry-artifact-intent://{family}/{parent_stream_tail}/{}",
        artifact_hash.trim_start_matches("sha256:")
    )
}

fn artifact_intent_payload(spec: &ArtifactIntentSpec<'_>, intent_ref: &str) -> Value {
    json!({
        "schema_version":"ioi.foundry-artifact-intent.v1",
        "intent_ref":intent_ref,
        "artifact_family":spec.family,
        "artifact_hash":spec.artifact_hash,
        "artifact_ref":spec.artifact_ref,
        "parent_kind":spec.parent_kind,
        "parent_stream_tail":spec.parent_stream_tail,
        "parent_resource_ref":spec.parent_resource_ref,
        "parent_op_kind":spec.parent_op_kind,
        "parent_idempotency_key":spec.idempotency_key,
        "owner_ref":spec.owner_ref,
        "status":"pending",
    })
}

/// Bind the intent's owner scope and admit the genesis `foundry_artifact_intent_recorded` event
/// BEFORE the blob is written. Keyed by the caller's own idempotency key: an exact retry replays the
/// same recorded obligation rather than recording a second one, and the intent scope reservation is
/// a pure read on that retry because the scope already exists.
fn record_artifact_intent(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    spec: &ArtifactIntentSpec<'_>,
) -> Result<super::mutation_event_foundation::MutationCommit, Reply> {
    let intent_ref = artifact_intent_ref(spec.family, spec.parent_stream_tail, spec.artifact_hash);
    let tail = hash_tail("artifact-intent", &intent_ref);
    let scope = bind_scope(
        data_dir,
        identity,
        ARTIFACT_INTENT_SCOPE_KIND,
        &intent_ref,
        spec.owner_ref,
        spec.idempotency_key,
    )?;
    let payload = artifact_intent_payload(spec, &intent_ref);
    admit(
        data_dir,
        true,
        identity,
        &scope,
        ARTIFACT_INTENT_SCOPE_KIND,
        &intent_ref,
        &tail,
        ARTIFACT_INTENT_RECORDED,
        None,
        &payload,
        now_ms(),
        spec.idempotency_key,
    )
}

/// The intent's parent effect is admitted iff the parent stream's history contains an entry admitted
/// under the intent's own idempotency key. This is the ONE derivation of "discharged": the parent
/// event (dataset materialization or program checkpoint) carries the same caller key on the parent
/// stream. A pure read; it admits nothing.
fn parent_effect_admitted(
    data_dir: &str,
    parent_stream_tail: &str,
    parent_idempotency_key: &str,
) -> Result<bool, Reply> {
    let history =
        super::substrate_store::read_event_stream_history(data_dir, NAMESPACE, parent_stream_tail)
            .map_err(admission_error)?;
    Ok(history
        .iter()
        .any(|entry| entry.operation.idem_key == parent_idempotency_key))
}

/// A content-addressed blob may be shared across intents and admitted records, so it is deleted only
/// after proving no OTHER referent names it. Conservative by construction: a non-abandoned intent on
/// a different stream, a materialized dataset snapshot with the same content hash, or any program
/// checkpoint with the same artifact hash all retain the blob. This is a global content-identity
/// check, not an owner-scoped read: a blob another tenant still references must never be collected.
fn blob_has_other_referent(
    data_dir: &str,
    this_intent_ref: &str,
    family: &str,
    artifact_hash: &str,
) -> Result<bool, Reply> {
    let tails =
        super::substrate_store::list_event_stream_tails(data_dir, NAMESPACE).map_err(|error| {
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "foundry_inventory_unavailable",
                error.to_string(),
            )
        })?;
    for tail in tails {
        if tail.starts_with("artifact-intent.") {
            let Some(head) =
                super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, &tail)
                    .map_err(admission_error)?
            else {
                continue;
            };
            if head.operation.op_kind != ARTIFACT_INTENT_ABANDONED
                && head.operation.payload["artifact_hash"] == artifact_hash
                && head.operation.payload["intent_ref"] != this_intent_ref
            {
                return Ok(true);
            }
        } else if family == DATA_DIR && tail.starts_with("dataset.") {
            let Some(head) =
                super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, &tail)
                    .map_err(admission_error)?
            else {
                continue;
            };
            if head.operation.payload["content_hash"] == artifact_hash {
                return Ok(true);
            }
        } else if family == CHECKPOINT_DIR && tail.starts_with("program.") {
            let history =
                super::substrate_store::read_event_stream_history(data_dir, NAMESPACE, &tail)
                    .map_err(admission_error)?;
            if history.iter().any(|entry| {
                entry.operation.payload["current_checkpoint"]["artifact_hash"] == artifact_hash
            }) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TokenCountRow {
    token: String,
    count: u64,
}

fn token_count_rows(counts: &BTreeMap<String, u64>) -> Vec<TokenCountRow> {
    counts
        .iter()
        .map(|(token, count)| TokenCountRow {
            token: token.clone(),
            count: *count,
        })
        .collect()
}

fn parse_token_counts(value: &Value) -> Result<BTreeMap<String, u64>, String> {
    if let Some(rows) = value.as_array() {
        let mut counts = BTreeMap::new();
        for row in rows {
            let row: TokenCountRow = serde_json::from_value(row.clone())
                .map_err(|error| format!("invalid token-count row: {error}"))?;
            if row.token.is_empty() || row.count == 0 {
                return Err("token-count rows require a non-empty token and positive count".into());
            }
            if counts
                .last_key_value()
                .is_some_and(|(token, _)| token >= &row.token)
            {
                return Err("token-count rows must be strictly sorted and unique".into());
            }
            counts.insert(row.token, row.count);
        }
        return Ok(counts);
    }
    // Read-only migration for programs admitted by the bounded reference
    // backend before token counts became a closed, generated wire shape. New
    // heads and checkpoint bytes are always emitted as sorted rows.
    if value.is_object() {
        let legacy: BTreeMap<String, u64> = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid legacy token-count map: {error}"))?;
        if legacy
            .iter()
            .any(|(token, count)| token.is_empty() || *count == 0)
        {
            return Err("legacy token counts require non-empty tokens and positive counts".into());
        }
        return Ok(legacy);
    }
    Err("token counts must be canonical sorted rows or a legacy object map".into())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipeOperator {
    kind: String,
    field: Option<String>,
    fields: Option<Vec<String>>,
    from: Option<String>,
    to: Option<String>,
}

fn validate_operator(operator: &RecipeOperator) -> Result<(), Reply> {
    let invalid = || {
        bad(
            StatusCode::BAD_REQUEST,
            "foundry_recipe_operator_invalid",
            format!("operator '{}' has an invalid field shape", operator.kind),
        )
    };
    match operator.kind.as_str() {
        "normalize_whitespace" | "filter_nonempty" => {
            if operator.field.as_deref().is_none_or(str::is_empty)
                || operator.fields.is_some()
                || operator.from.is_some()
                || operator.to.is_some()
            {
                return Err(invalid());
            }
        }
        "select_fields" | "deduplicate" => {
            if operator
                .fields
                .as_ref()
                .is_none_or(|fields| fields.is_empty() || fields.iter().any(String::is_empty))
                || operator.field.is_some()
                || operator.from.is_some()
                || operator.to.is_some()
            {
                return Err(invalid());
            }
        }
        "rename_field" => {
            if operator.from.as_deref().is_none_or(str::is_empty)
                || operator.to.as_deref().is_none_or(str::is_empty)
                || operator.field.is_some()
                || operator.fields.is_some()
            {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipeRevisionRequest {
    recipe_id: String,
    owner_ref: String,
    predecessor_recipe_ref: Option<String>,
    expected_head: Option<String>,
    data_recipe_ref: String,
    source_snapshot_refs: Vec<String>,
    institutional_learning_boundary_ref: String,
    learning_source_rights_claim_refs: Vec<String>,
    tokenizer_ref: String,
    sequence_format_ref: String,
    packing_policy_ref: String,
    loss_mask_policy_ref: String,
    harness_variant_refs: Vec<String>,
    environment_profile_ref: String,
    operators: Vec<RecipeOperator>,
    split_seed: u64,
    idempotency_key: String,
}

fn validate_recipe_request(request: &RecipeRevisionRequest) -> Result<(), Reply> {
    for (field, value, prefixes) in [
        (
            "recipe_id",
            request.recipe_id.as_str(),
            &["foundry-recipe://"][..],
        ),
        (
            "owner_ref",
            request.owner_ref.as_str(),
            &["wallet://", "org://", "project://"][..],
        ),
        (
            "data_recipe_ref",
            request.data_recipe_ref.as_str(),
            &["data-recipe://"][..],
        ),
        (
            "institutional_learning_boundary_ref",
            request.institutional_learning_boundary_ref.as_str(),
            &["learning-boundary://", "policy://"][..],
        ),
        (
            "tokenizer_ref",
            request.tokenizer_ref.as_str(),
            &["tokenizer://", "artifact://"][..],
        ),
        (
            "sequence_format_ref",
            request.sequence_format_ref.as_str(),
            &["format://", "artifact://", "schema://"][..],
        ),
        (
            "packing_policy_ref",
            request.packing_policy_ref.as_str(),
            &["policy://"][..],
        ),
        (
            "loss_mask_policy_ref",
            request.loss_mask_policy_ref.as_str(),
            &["policy://"][..],
        ),
        (
            "environment_profile_ref",
            request.environment_profile_ref.as_str(),
            &["profile://", "environment-profile://"][..],
        ),
    ] {
        validate_ref(value, field, prefixes)?;
    }
    require_nonempty(&request.source_snapshot_refs, "source_snapshot_refs")?;
    require_nonempty(
        &request.learning_source_rights_claim_refs,
        "learning_source_rights_claim_refs",
    )?;
    require_nonempty(&request.harness_variant_refs, "harness_variant_refs")?;
    if request.operators.is_empty() || request.operators.len() > 64 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_recipe_operator_count_invalid",
            "a recipe requires between 1 and 64 operators",
        ));
    }
    for operator in &request.operators {
        validate_operator(operator)?;
    }
    if request.idempotency_key.trim().is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        ));
    }
    if request.split_seed > PORTABLE_SAFE_INTEGER_MAX {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_recipe_split_seed_invalid",
            "split_seed must remain a portable JSON-safe integer",
        ));
    }
    Ok(())
}

/// The content commitment for a recipe revision: a JCS digest of the whole request with only the
/// concurrency precondition (`expected_head`) and the retry key (`idempotency_key`) removed. Because
/// it hashes EVERY remaining field, a same-key resubmission that changed any operator, ref, or seed
/// yields a different hash, which is exactly what makes the prior-key probe's content-hash compare a
/// complete request-identity check rather than a partial one.
fn recipe_content_hash(request: &RecipeRevisionRequest) -> Result<String, Reply> {
    let mut content = serde_json::to_value(request).unwrap_or(Value::Null);
    if let Some(object) = content.as_object_mut() {
        object.remove("expected_head");
        object.remove("idempotency_key");
    }
    jcs_digest(&content).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "foundry_recipe_hash_failed",
            error,
        )
    })
}

pub(crate) async fn handle_recipes_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: RecipeRevisionRequest = match parse(body, "foundry_recipe_revision_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = validate_recipe_request(&request) {
        return reply;
    }
    let content_hash = match recipe_content_hash(&request) {
        Ok(hash) => hash,
        Err(reply) => return reply,
    };
    let tail = hash_tail("recipe", &request.recipe_id);
    let current =
        super::substrate_store::read_event_stream_operation(&st.data_dir, NAMESPACE, &tail)
            .map_err(admission_error);
    let current = match current {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    // Capture the exact scope this handler already authorizes (existing stream) or binds (genesis).
    // The prior-key probe and the admit both replay-check against THIS scope rather than re-reading
    // one, so the idempotency answer and the write share a single scope proof.
    let scope = if let Some(existing) = &current {
        let owner_ref = existing.operation.payload["owner_ref"]
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
            RECIPE_SCOPE_KIND,
            &request.recipe_id,
            Some(owner_ref),
        ) {
            Ok(scope) => scope,
            Err(reply) => return reply,
        }
    } else {
        match bind_scope(
            &st.data_dir,
            &identity,
            RECIPE_SCOPE_KIND,
            &request.recipe_id,
            &request.owner_ref,
            &request.idempotency_key,
        ) {
            Ok(scope) => scope,
            Err(reply) => return reply,
        }
    };
    recipes_create_core(
        &st.data_dir,
        &identity,
        &scope,
        &request,
        &content_hash,
        &tail,
        current,
    )
}

/// Post-scope core of recipe-revision admission. Kept as a sync function taking an already-authorized
/// scope so the idempotency arms — replay, same-key/different-bytes refusal, genesis/successor
/// compare-and-swap — are exercisable without minting a real HTTP identity, while the handler above
/// retains its identity and scope proofs.
fn recipes_create_core(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    request: &RecipeRevisionRequest,
    content_hash: &str,
    tail: &str,
    current: Option<ExactProjection>,
) -> Reply {
    if current.is_some() {
        match super::mutation_event_foundation::prior_admission_for_key_on_stream(
            data_dir,
            identity,
            scope,
            RECIPE_SCOPE_KIND,
            &request.recipe_id,
            NAMESPACE,
            tail,
            &request.idempotency_key,
        ) {
            Ok(Some(prior))
                if prior.operation.op_kind == "event_stream.foundry_recipe_revision_admitted"
                    && prior.operation.payload["recipe_id"] == request.recipe_id
                    && prior.operation.payload["content_hash"] == content_hash =>
            {
                return (
                    StatusCode::CREATED,
                    Json(json!({
                        "ok": true,
                        "recipe": projection_value(&prior, Some(true))
                    })),
                );
            }
            Ok(Some(_)) => {
                return bad(
                    StatusCode::CONFLICT,
                    "foundry_idempotency_payload_conflict",
                    "the idempotency key already names different recipe revision bytes",
                )
            }
            Ok(None) => {}
            Err(refusal) => return mutation_refusal(refusal),
        }
    }
    let (revision, expected_head) = match current {
        None => {
            if request.expected_head.is_some() || request.predecessor_recipe_ref.is_some() {
                return bad(
                    StatusCode::CONFLICT,
                    "foundry_recipe_genesis_predecessor_invalid",
                    "a genesis recipe revision cannot cite a predecessor or expected head",
                );
            }
            (1, None)
        }
        Some(current) => {
            if request.expected_head.as_deref() != Some(current.head.as_str()) {
                return bad(
                    StatusCode::CONFLICT,
                    "foundry_recipe_expected_head_conflict",
                    "expected_head is not the current Agentgres head",
                );
            }
            if request.predecessor_recipe_ref.as_deref()
                != current.operation.payload["recipe_revision_ref"].as_str()
            {
                return bad(
                    StatusCode::CONFLICT,
                    "foundry_recipe_predecessor_conflict",
                    "predecessor_recipe_ref is not the current immutable revision",
                );
            }
            (
                current.operation.payload["revision"].as_u64().unwrap_or(0) + 1,
                Some(current.head),
            )
        }
    };
    let payload = json!({
        "schema_version":"ioi.foundry-recipe-revision.v1",
        "recipe_id":request.recipe_id,
        "recipe_revision_ref":format!("{}/revision/{revision}", request.recipe_id.trim_end_matches('/')),
        "revision":revision,
        "predecessor_recipe_ref":request.predecessor_recipe_ref,
        "owner_ref":request.owner_ref,
        "data_recipe_ref":request.data_recipe_ref,
        "source_snapshot_refs":request.source_snapshot_refs,
        "institutional_learning_boundary_ref":request.institutional_learning_boundary_ref,
        "learning_source_rights_claim_refs":request.learning_source_rights_claim_refs,
        "tokenizer_ref":request.tokenizer_ref,
        "sequence_format_ref":request.sequence_format_ref,
        "packing_policy_ref":request.packing_policy_ref,
        "loss_mask_policy_ref":request.loss_mask_policy_ref,
        "harness_variant_refs":request.harness_variant_refs,
        "environment_profile_ref":request.environment_profile_ref,
        "operators":request.operators,
        "split_seed":request.split_seed,
        "content_hash":content_hash,
        "status":"ready",
    });
    match admit(
        data_dir,
        expected_head.is_none(),
        identity,
        scope,
        RECIPE_SCOPE_KIND,
        &request.recipe_id,
        tail,
        "event_stream.foundry_recipe_revision_admitted",
        expected_head.as_deref(),
        &payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(
                json!({"ok":true,"recipe":projection_value(&commit.projection,Some(commit.replayed))}),
            ),
        ),
        Err(reply) => reply,
    }
}

fn list_heads(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    prefix: &str,
    schema: &str,
    scope_kind: &str,
    identity_field: &str,
    owner_field: Option<&str>,
) -> Result<Vec<Value>, Reply> {
    let allowed = authorized_refs(data_dir, identity, scope_kind)?;
    let tails =
        super::substrate_store::list_event_stream_tails(data_dir, NAMESPACE).map_err(|error| {
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "foundry_inventory_unavailable",
                error.to_string(),
            )
        })?;
    let mut values = Vec::new();
    for tail in tails.into_iter().filter(|tail| tail.starts_with(prefix)) {
        let exact = read_head(data_dir, &tail)?;
        if exact.operation.payload["schema_version"] == schema {
            let resource_ref = exact.operation.payload[identity_field]
                .as_str()
                .unwrap_or_default();
            if allowed.contains(resource_ref) {
                authorize_scope(
                    data_dir,
                    identity,
                    scope_kind,
                    resource_ref,
                    owner_field.and_then(|field| exact.operation.payload[field].as_str()),
                )?;
                values.push(projection_value(&exact, None));
            }
        }
    }
    Ok(values)
}

pub(crate) async fn handle_recipes_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match list_heads(
        &st.data_dir,
        &identity,
        "recipe.",
        "ioi.foundry-recipe-revision.v1",
        RECIPE_SCOPE_KIND,
        "recipe_id",
        Some("owner_ref"),
    ) {
        Ok(mut recipes) => {
            recipes.sort_by(|a, b| a["recipe_id"].as_str().cmp(&b["recipe_id"].as_str()));
            (StatusCode::OK, Json(json!({"ok":true,"recipes":recipes})))
        }
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_recipe_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, RECIPE_SCOPE_KIND, &id, None) {
        return reply;
    }
    let tail = hash_tail("recipe", &id);
    match read_head(&st.data_dir, &tail) {
        Ok(exact) if exact.operation.payload["recipe_id"] == id => {
            if let Err(reply) = authorize_scope(
                &st.data_dir,
                &identity,
                RECIPE_SCOPE_KIND,
                &id,
                exact.operation.payload["owner_ref"].as_str(),
            ) {
                return reply;
            }
            (
                StatusCode::OK,
                Json(json!({"ok":true,"recipe":projection_value(&exact,None)})),
            )
        }
        Ok(_) => bad(
            StatusCode::CONFLICT,
            "foundry_recipe_identity_collision",
            "recipe coordinate contains different bytes",
        ),
        Err(reply) => reply,
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SplitBasisPoints {
    train: u16,
    validation: u16,
    test: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeRunRequest {
    expected_recipe_head: String,
    expected_recipe_content_hash: String,
    rights_grant_refs: Vec<String>,
    input_rows: Vec<Value>,
    splits: SplitBasisPoints,
    idempotency_key: String,
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn row_object_mut(row: &mut Value) -> Result<&mut Map<String, Value>, Reply> {
    row.as_object_mut().ok_or_else(|| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "foundry_recipe_row_invalid",
            "every input row must be a JSON object",
        )
    })
}

fn run_operators(mut rows: Vec<Value>, operators: &[RecipeOperator]) -> Result<Vec<Value>, Reply> {
    for operator in operators {
        match operator.kind.as_str() {
            "normalize_whitespace" => {
                let field = operator.field.as_deref().unwrap_or_default();
                for row in &mut rows {
                    let object = row_object_mut(row)?;
                    if let Some(value) = object.get_mut(field) {
                        let text = value.as_str().ok_or_else(|| {
                            bad(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                "foundry_recipe_field_type_invalid",
                                format!("field '{field}' must be a string"),
                            )
                        })?;
                        *value = json!(normalize_whitespace(text));
                    }
                }
            }
            "filter_nonempty" => {
                let field = operator.field.as_deref().unwrap_or_default();
                rows.retain(|row| {
                    row.get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|text| !text.trim().is_empty())
                });
            }
            "select_fields" => {
                let fields = operator.fields.as_deref().unwrap_or_default();
                for row in &mut rows {
                    let object = row_object_mut(row)?;
                    object.retain(|key, _| fields.contains(&key));
                }
            }
            "rename_field" => {
                let from = operator.from.as_deref().unwrap_or_default();
                let to = operator.to.as_deref().unwrap_or_default();
                for row in &mut rows {
                    let object = row_object_mut(row)?;
                    if object.contains_key(to) && object.contains_key(from) {
                        return Err(bad(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "foundry_recipe_rename_collision",
                            format!("rename would overwrite field '{to}'"),
                        ));
                    }
                    if let Some(value) = object.remove(from) {
                        object.insert(to.to_owned(), value);
                    }
                }
            }
            "deduplicate" => {
                let fields = operator.fields.as_deref().unwrap_or_default();
                let mut seen = BTreeSet::new();
                let mut retained = Vec::new();
                for row in rows {
                    let identity = Value::Array(
                        fields
                            .iter()
                            .map(|field| row.get(field).cloned().unwrap_or(Value::Null))
                            .collect(),
                    );
                    let hash = jcs_digest(&identity).map_err(|error| {
                        bad(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "foundry_recipe_dedup_hash_failed",
                            error,
                        )
                    })?;
                    if seen.insert(hash) {
                        retained.push(row);
                    }
                }
                rows = retained;
            }
            _ => unreachable!("operators validate before execution"),
        }
    }
    Ok(rows)
}

fn split_name(row: &Value, seed: u64, splits: &SplitBasisPoints) -> Result<&'static str, Reply> {
    let identity = json!({"seed":seed,"row":row});
    let bytes = jcs_bytes(&identity).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "foundry_split_hash_failed",
            error,
        )
    })?;
    let hash = Sha256::digest(bytes);
    let bucket = u16::from_be_bytes([hash[0], hash[1]]) as u32 % 10_000;
    if bucket < splits.train as u32 {
        Ok("train")
    } else if bucket < splits.train as u32 + splits.validation as u32 {
        Ok("validation")
    } else {
        Ok("test")
    }
}

pub(crate) async fn handle_recipe_run(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(recipe_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let recipe_scope =
        match authorize_scope(&st.data_dir, &identity, RECIPE_SCOPE_KIND, &recipe_id, None) {
            Ok(scope) => scope,
            Err(reply) => return reply,
        };
    let request: RecipeRunRequest = match parse(body, "foundry_recipe_run_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    if request.input_rows.is_empty() || request.input_rows.len() > MAX_ROWS {
        return bad(
            StatusCode::PAYLOAD_TOO_LARGE,
            "foundry_recipe_row_count_invalid",
            format!("input_rows must contain 1..={MAX_ROWS} rows"),
        );
    }
    if serde_json::to_vec(&request.input_rows).map_or(true, |bytes| bytes.len() > MAX_ENCODED_ROWS)
    {
        return bad(
            StatusCode::PAYLOAD_TOO_LARGE,
            "foundry_recipe_rows_oversize",
            "encoded input_rows exceed the bounded factory limit",
        );
    }
    if u32::from(request.splits.train)
        + u32::from(request.splits.validation)
        + u32::from(request.splits.test)
        != 10_000
        || request.splits.train == 0
    {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_recipe_split_invalid",
            "split basis points must sum to 10000 and train must be non-zero",
        );
    }
    if let Err(reply) = require_nonempty(&request.rights_grant_refs, "rights_grant_refs") {
        return reply;
    }
    let recipe = match read_head(&st.data_dir, &hash_tail("recipe", &recipe_id)) {
        Ok(recipe) => recipe,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(
        &st.data_dir,
        &identity,
        RECIPE_SCOPE_KIND,
        &recipe_id,
        recipe.operation.payload["owner_ref"].as_str(),
    ) {
        return reply;
    }
    if recipe.head != request.expected_recipe_head
        || recipe.operation.payload["content_hash"] != request.expected_recipe_content_hash
    {
        return bad(
            StatusCode::CONFLICT,
            "foundry_recipe_revision_conflict",
            "recipe head or content hash has changed",
        );
    }
    recipe_run_core(&st.data_dir, &identity, &recipe_scope, &recipe, request)
}

/// The pure materialization of a recipe run: run the recipe's operators, assign splits, and encode
/// the deterministic dataset bytes and its content-addressed coordinates. It writes nothing and
/// admits nothing, so the intent -> write -> parent effect sequence can be driven step by step over
/// its output.
struct PreparedDataset {
    snapshot_ref: String,
    content_hash: String,
    tail: String,
    payload: Value,
    bytes: Vec<u8>,
}

fn recipe_run_prepare(
    recipe: &ExactProjection,
    request: &RecipeRunRequest,
) -> Result<PreparedDataset, Reply> {
    let operators: Vec<RecipeOperator> =
        serde_json::from_value(recipe.operation.payload["operators"].clone()).map_err(|error| {
            bad(
                StatusCode::CONFLICT,
                "foundry_recipe_projection_invalid",
                error.to_string(),
            )
        })?;
    let rows = match run_operators(request.input_rows.clone(), &operators) {
        Ok(rows) if !rows.is_empty() => rows,
        Ok(_) => {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "foundry_recipe_empty_output",
                "recipe removed every row; no snapshot was admitted",
            ))
        }
        Err(reply) => return Err(reply),
    };
    let split_seed = recipe.operation.payload["split_seed"].as_u64().unwrap_or(0);
    let mut counts = BTreeMap::new();
    let mut material_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let split = split_name(&row, split_seed, &request.splits)?;
        *counts.entry(split.to_owned()).or_insert(0u64) += 1;
        material_rows.push(json!({"split":split,"row":row}));
    }
    let material = json!({
        "schema_version":"ioi.foundry-dataset-material.v1",
        "recipe_revision_ref":recipe.operation.payload["recipe_revision_ref"],
        "recipe_content_hash":recipe.operation.payload["content_hash"],
        "split_seed":split_seed,
        "splits":request.splits,
        "rows":material_rows,
    });
    let bytes = jcs_bytes(&material).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "foundry_dataset_encode_failed",
            error,
        )
    })?;
    let content_hash = digest(&bytes);
    let snapshot_ref = format!(
        "dataset-snapshot://foundry/{}",
        content_hash.trim_start_matches("sha256:")
    );
    let payload = json!({
        "schema_version":"ioi.foundry-dataset-snapshot.v1",
        "dataset_snapshot_ref":snapshot_ref,
        "recipe_revision_ref":recipe.operation.payload["recipe_revision_ref"],
        "recipe_content_hash":recipe.operation.payload["content_hash"],
        "institutional_learning_boundary_ref":recipe.operation.payload["institutional_learning_boundary_ref"],
        "learning_source_rights_claim_refs":recipe.operation.payload["learning_source_rights_claim_refs"],
        "rights_grant_refs":request.rights_grant_refs,
        "content_manifest_ref":format!("artifact://foundry-dataset/{}", content_hash.trim_start_matches("sha256:")),
        "content_hash":content_hash,
        "row_count":material["rows"].as_array().map(Vec::len).unwrap_or(0),
        "split_counts":counts,
        "status":"materialized",
    });
    let tail = hash_tail("dataset", &snapshot_ref);
    Ok(PreparedDataset {
        snapshot_ref,
        content_hash,
        tail,
        payload,
        bytes,
    })
}

/// Admit the dataset artifact INTENT, write the blob, then admit the parent materialization — in
/// that exact order. The blob is impossible to write without a durable admitted intent recording
/// that it should be collected if the parent admission fails, and an exact retry replays the intent,
/// no-ops the write, and replays the parent.
fn commit_dataset_artifact(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    dataset_scope: &super::substrate_store::RequestResourceScope,
    prepared: &PreparedDataset,
    owner_ref: &str,
    idempotency_key: &str,
) -> Reply {
    let artifact_ref = format!(
        "artifact://foundry-dataset/{}",
        prepared.content_hash.trim_start_matches("sha256:")
    );
    let intent = ArtifactIntentSpec {
        family: DATA_DIR,
        parent_kind: "dataset-snapshot",
        parent_stream_tail: &prepared.tail,
        parent_resource_ref: &prepared.snapshot_ref,
        parent_op_kind: DATASET_PARENT_OP,
        artifact_hash: &prepared.content_hash,
        artifact_ref: &artifact_ref,
        owner_ref,
        idempotency_key,
    };
    if let Err(reply) = record_artifact_intent(data_dir, identity, &intent) {
        return reply;
    }
    if let Err(error) = durable_write(
        &artifact_path(data_dir, DATA_DIR, &prepared.content_hash),
        &prepared.bytes,
    ) {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "foundry_dataset_persist_failed",
            error.to_string(),
        );
    }
    match admit(
        data_dir,
        true,
        identity,
        dataset_scope,
        DATASET_SCOPE_KIND,
        &prepared.snapshot_ref,
        &prepared.tail,
        DATASET_PARENT_OP,
        None,
        &prepared.payload,
        now_ms(),
        idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(
                json!({"ok":true,"dataset_snapshot":projection_value(&commit.projection,Some(commit.replayed))}),
            ),
        ),
        Err(reply) => reply,
    }
}

/// Post-authorization core of a recipe run. Materializes the dataset, binds the dataset scope BEFORE
/// any bytes are written (a snapshot ref owned by another tenant is refused at no disk cost), then
/// commits the artifact through the admitted-intent effect sequence.
fn recipe_run_core(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    recipe_scope: &super::substrate_store::RequestResourceScope,
    recipe: &ExactProjection,
    request: RecipeRunRequest,
) -> Reply {
    let prepared = match recipe_run_prepare(recipe, &request) {
        Ok(prepared) => prepared,
        Err(reply) => return reply,
    };
    let dataset_scope = match bind_scope(
        data_dir,
        identity,
        DATASET_SCOPE_KIND,
        &prepared.snapshot_ref,
        &recipe_scope.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    commit_dataset_artifact(
        data_dir,
        identity,
        &dataset_scope,
        &prepared,
        &recipe_scope.owner_ref,
        &request.idempotency_key,
    )
}

pub(crate) async fn handle_dataset_snapshots_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match list_heads(
        &st.data_dir,
        &identity,
        "dataset.",
        "ioi.foundry-dataset-snapshot.v1",
        DATASET_SCOPE_KIND,
        "dataset_snapshot_ref",
        None,
    ) {
        Ok(snapshots) => (
            StatusCode::OK,
            Json(json!({"ok":true,"dataset_snapshots":snapshots})),
        ),
        Err(reply) => reply,
    }
}

fn dataset_snapshot(data_dir: &str, snapshot_ref: &str) -> Result<Value, Reply> {
    let exact = read_head(data_dir, &hash_tail("dataset", snapshot_ref))?;
    if exact.operation.payload["dataset_snapshot_ref"] != snapshot_ref {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_dataset_identity_collision",
            "snapshot coordinate contains different admitted bytes",
        ));
    }
    Ok(exact.operation.payload)
}

fn load_dataset_material(data_dir: &str, snapshot: &Value) -> Result<Value, Reply> {
    let content_hash = snapshot["content_hash"].as_str().ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "foundry_dataset_hash_missing",
            "snapshot has no content hash",
        )
    })?;
    let bytes =
        std::fs::read(artifact_path(data_dir, DATA_DIR, content_hash)).map_err(|error| {
            bad(
                StatusCode::CONFLICT,
                "foundry_dataset_material_unavailable",
                error.to_string(),
            )
        })?;
    if digest(&bytes) != content_hash {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_dataset_material_tampered",
            "dataset bytes do not match the admitted content hash",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "foundry_dataset_material_invalid",
            error.to_string(),
        )
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramCreateRequest {
    program_id: String,
    owner_ref: String,
    foundry_spec_ref: Option<String>,
    dataset_snapshot_ref: String,
    expected_recipe_content_hash: String,
    training_mode: String,
    trainer_backend_profile_ref: String,
    text_field: String,
    checkpoint_every_rows: u64,
    seed: u64,
    authority_grant_refs: Vec<String>,
    rights_grant_refs: Vec<String>,
    idempotency_key: String,
}

pub(crate) async fn handle_program_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: ProgramCreateRequest = match parse(body, "foundry_program_create_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    for (field, value, prefixes) in [
        (
            "program_id",
            request.program_id.as_str(),
            &["trainpipe://"][..],
        ),
        (
            "owner_ref",
            request.owner_ref.as_str(),
            &["wallet://", "org://", "project://"][..],
        ),
        (
            "dataset_snapshot_ref",
            request.dataset_snapshot_ref.as_str(),
            &["dataset-snapshot://"][..],
        ),
        (
            "trainer_backend_profile_ref",
            request.trainer_backend_profile_ref.as_str(),
            &["trainer-backend://"][..],
        ),
    ] {
        if let Err(reply) = validate_ref(value, field, prefixes) {
            return reply;
        }
    }
    if !matches!(request.training_mode.as_str(), "sft" | "adapter") {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_training_mode_invalid",
            "the bounded backend supports sft or adapter mode",
        );
    }
    if request.trainer_backend_profile_ref != "trainer-backend://ioi/reference-token-frequency/v1" {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, "foundry_trainer_backend_unavailable", "this build executes only the explicitly scoped reference-token-frequency backend; it never falls back from another requested backend");
    }
    if request.text_field.is_empty() || request.checkpoint_every_rows == 0 {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_program_bound_invalid",
            "text_field and positive checkpoint_every_rows are required",
        );
    }
    if request.checkpoint_every_rows > PORTABLE_SAFE_INTEGER_MAX
        || request.seed > PORTABLE_SAFE_INTEGER_MAX
    {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_program_bound_invalid",
            "program integer bounds must remain portable JSON-safe integers",
        );
    }
    if let Err(reply) = require_nonempty(&request.authority_grant_refs, "authority_grant_refs") {
        return reply;
    }
    if let Err(reply) = require_nonempty(&request.rights_grant_refs, "rights_grant_refs") {
        return reply;
    }
    let snapshot_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        DATASET_SCOPE_KIND,
        &request.dataset_snapshot_ref,
        Some(&request.owner_ref),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if snapshot_scope.tenant_ref != request.owner_ref {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch);
    }
    let snapshot = match dataset_snapshot(&st.data_dir, &request.dataset_snapshot_ref) {
        Ok(snapshot) => snapshot,
        Err(reply) => return reply,
    };
    if snapshot["recipe_content_hash"] != request.expected_recipe_content_hash {
        return bad(
            StatusCode::CONFLICT,
            "foundry_program_recipe_drift",
            "dataset snapshot was not materialized by the expected recipe content",
        );
    }
    let payload = json!({
        "schema_version":"ioi.foundry-training-program.v1",
        "program_id":request.program_id,
        "owner_ref":request.owner_ref,
        "foundry_spec_ref":request.foundry_spec_ref,
        "dataset_snapshot_ref":request.dataset_snapshot_ref,
        "dataset_content_hash":snapshot["content_hash"],
        "recipe_content_hash":snapshot["recipe_content_hash"],
        "training_mode":request.training_mode,
        "trainer_backend_profile_ref":request.trainer_backend_profile_ref,
        "backend_scope":"bounded_reference_pipeline_only",
        "text_field":request.text_field,
        "checkpoint_every_rows":request.checkpoint_every_rows,
        "seed":request.seed,
        "authority_grant_refs":request.authority_grant_refs,
        "rights_grant_refs":request.rights_grant_refs,
        "revision":1,
        "status":"admitted",
        "data_cursor":0,
        "processed_rows":0,
        "processed_tokens":0,
        "token_counts":[],
        "checkpoint_refs":[],
        "current_checkpoint":Value::Null,
        "restore_verification":Value::Null,
        "qualification":Value::Null,
        "last_action_idempotency_key":request.idempotency_key,
    });
    let tail = hash_tail("program", &request.program_id);
    let program_scope =
        match super::substrate_store::read_event_stream_operation(&st.data_dir, NAMESPACE, &tail) {
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
                    PROGRAM_SCOPE_KIND,
                    &request.program_id,
                    Some(owner_ref),
                ) {
                    Ok(scope) => scope,
                    Err(reply) => return reply,
                }
            }
            Ok(None) => match bind_scope(
                &st.data_dir,
                &identity,
                PROGRAM_SCOPE_KIND,
                &request.program_id,
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
        &program_scope,
        PROGRAM_SCOPE_KIND,
        &request.program_id,
        &tail,
        "event_stream.foundry_program_admitted",
        None,
        &payload,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(
                json!({"ok":true,"program":projection_value(&commit.projection,Some(commit.replayed))}),
            ),
        ),
        Err(reply) => reply,
    }
}

fn program_head(data_dir: &str, program_id: &str) -> Result<(String, ExactProjection), Reply> {
    let tail = hash_tail("program", program_id);
    let exact = read_head(data_dir, &tail)?;
    if exact.operation.payload["program_id"] != program_id {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_program_identity_collision",
            "program coordinate contains different admitted bytes",
        ));
    }
    Ok((tail, exact))
}

pub(crate) async fn handle_programs_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match list_heads(
        &st.data_dir,
        &identity,
        "program.",
        "ioi.foundry-training-program.v1",
        PROGRAM_SCOPE_KIND,
        "program_id",
        Some("owner_ref"),
    ) {
        Ok(programs) => (StatusCode::OK, Json(json!({"ok":true,"programs":programs}))),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_program_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, PROGRAM_SCOPE_KIND, &id, None) {
        return reply;
    }
    match program_head(&st.data_dir, &id) {
        Ok((_, exact)) => {
            if let Err(reply) = authorize_scope(
                &st.data_dir,
                &identity,
                PROGRAM_SCOPE_KIND,
                &id,
                exact.operation.payload["owner_ref"].as_str(),
            ) {
                return reply;
            }
            (
                StatusCode::OK,
                Json(json!({"ok":true,"program":projection_value(&exact,None)})),
            )
        }
        Err(reply) => reply,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramActionRequest {
    expected_head: String,
    idempotency_key: String,
    max_rows: Option<u64>,
}

fn program_action_op_kind(action: &str) -> Option<&'static str> {
    match action {
        "start" => Some("event_stream.foundry_program_started"),
        "step" => Some("event_stream.foundry_program_checkpointed"),
        "pause" => Some("event_stream.foundry_program_paused"),
        "resume" => Some("event_stream.foundry_program_resumed"),
        "cancel" => Some("event_stream.foundry_program_cancelled"),
        "reconcile" => Some("event_stream.foundry_program_reconciled"),
        _ => None,
    }
}

fn checkpoint_record(
    program: &Value,
    counts: &BTreeMap<String, u64>,
    cursor: u64,
    processed_tokens: u64,
) -> Value {
    json!({
        "schema_version":"ioi.foundry-checkpoint-artifact.v1",
        "program_id":program["program_id"],
        "dataset_snapshot_ref":program["dataset_snapshot_ref"],
        "dataset_content_hash":program["dataset_content_hash"],
        "recipe_content_hash":program["recipe_content_hash"],
        "trainer_backend_profile_ref":program["trainer_backend_profile_ref"],
        "model_state":{"token_counts":token_count_rows(counts),"total_tokens":processed_tokens},
        "optimizer_state":{"kind":"count_accumulator","updates":cursor},
        "scheduler_state":{"kind":"row_cursor","next_row":cursor},
        "rng_state":{"algorithm":"fixed_seed_no_rng_training","seed":program["seed"]},
        "data_cursor":cursor,
        "global_step":cursor,
        "token_count":processed_tokens,
        "status":"complete",
    })
}

/// Pure compute for one bounded training step. It reads the immutable dataset material and folds
/// token counts forward, then builds the next program head and the checkpoint bytes — but it does
/// NOT write the checkpoint blob. Writing is the caller's, sequenced AFTER the artifact intent is
/// admitted, so a checkpoint blob can never be materialized without a durable admitted obligation.
/// Returns `(next_program_head, checkpoint_bytes, checkpoint_hash)`.
fn train_step_compute(
    data_dir: &str,
    program: &Value,
    max_rows: u64,
) -> Result<(Value, Vec<u8>, String), Reply> {
    let snapshot = dataset_snapshot(
        data_dir,
        program["dataset_snapshot_ref"].as_str().unwrap_or_default(),
    )?;
    if snapshot["content_hash"] != program["dataset_content_hash"] {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_program_dataset_drift",
            "dataset snapshot no longer matches the admitted program",
        ));
    }
    let material = load_dataset_material(data_dir, &snapshot)?;
    let train_rows = material["rows"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry["split"] == "train")
        .collect::<Vec<_>>();
    let cursor = program["data_cursor"].as_u64().unwrap_or(0);
    if cursor as usize > train_rows.len() {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_program_cursor_invalid",
            "data cursor exceeds the immutable training split",
        ));
    }
    let stop = cursor
        .saturating_add(max_rows.max(1))
        .min(train_rows.len() as u64);
    let mut counts = parse_token_counts(&program["token_counts"]).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "foundry_program_model_state_invalid",
            error.to_string(),
        )
    })?;
    let mut processed_tokens = program["processed_tokens"].as_u64().unwrap_or(0);
    let field = program["text_field"].as_str().unwrap_or_default();
    for entry in &train_rows[cursor as usize..stop as usize] {
        let text = entry["row"][field].as_str().ok_or_else(|| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "foundry_training_text_field_missing",
                format!("training row lacks string field '{field}'"),
            )
        })?;
        for token in text.split_whitespace().map(|token| token.to_lowercase()) {
            if !token.is_empty() {
                *counts.entry(token).or_insert(0) += 1;
                processed_tokens += 1;
            }
        }
    }
    let checkpoint = checkpoint_record(program, &counts, stop, processed_tokens);
    let bytes = jcs_bytes(&checkpoint).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "foundry_checkpoint_encode_failed",
            error,
        )
    })?;
    let checkpoint_hash = digest(&bytes);
    let program_tail = hash_tail(
        "program",
        program["program_id"].as_str().unwrap_or_default(),
    );
    let checkpoint_ref = format!(
        "checkpoint://foundry/{}/{}/{}",
        program_tail.trim_start_matches("program."),
        stop,
        checkpoint_hash.trim_start_matches("sha256:")
    );
    let checkpoint_projection = json!({
        "checkpoint_ref":checkpoint_ref,
        "artifact_ref":format!("artifact://foundry-checkpoint/{}", checkpoint_hash.trim_start_matches("sha256:")),
        "artifact_hash":checkpoint_hash,
        "data_cursor":stop,
        "global_step":stop,
        "token_count":processed_tokens,
        "complete":true,
        "restore_verified":false,
    });
    let mut next = program.clone();
    next["revision"] = json!(program["revision"].as_u64().unwrap_or(0) + 1);
    next["data_cursor"] = json!(stop);
    next["processed_rows"] = json!(stop);
    next["processed_tokens"] = json!(processed_tokens);
    next["token_counts"] = serde_json::to_value(token_count_rows(&counts)).unwrap_or(json!([]));
    let mut refs = next["checkpoint_refs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    refs.push(json!(checkpoint_ref));
    next["checkpoint_refs"] = Value::Array(refs);
    next["current_checkpoint"] = checkpoint_projection;
    next["status"] = json!(if stop == train_rows.len() as u64 {
        "completed"
    } else {
        "running"
    });
    Ok((next, bytes, checkpoint_hash))
}

pub(crate) async fn handle_program_action(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((id, action)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, PROGRAM_SCOPE_KIND, &id, None) {
        return reply;
    }
    let request: ProgramActionRequest = match parse(body, "foundry_program_action_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    let requested_op_kind = match program_action_op_kind(&action) {
        Some(op_kind) => op_kind,
        None => {
            return bad(
                StatusCode::NOT_FOUND,
                "foundry_program_action_unknown",
                "unknown program action",
            )
        }
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    if request.max_rows == Some(0) {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_program_step_bound_invalid",
            "max_rows must be positive when supplied",
        );
    }
    let action_identity = json!({"action": action.as_str(), "max_rows": request.max_rows});
    let (tail, current) = match program_head(&st.data_dir, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let program_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        PROGRAM_SCOPE_KIND,
        &id,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    program_action_core(
        &st.data_dir,
        &identity,
        &program_scope,
        &id,
        &action,
        &request,
        requested_op_kind,
        action_identity,
        &tail,
        current,
    )
}

/// Post-scope core of a program transition. The idempotent-replay arm, the same-key/different-bytes
/// refusal, the head compare-and-swap, and the bounded step compute all run here over an
/// already-authorized scope, so the transition semantics are exercisable directly while the handler
/// keeps its identity and scope proofs.
#[allow(clippy::too_many_arguments)]
fn program_action_core(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    id: &str,
    action: &str,
    request: &ProgramActionRequest,
    requested_op_kind: &str,
    action_identity: Value,
    tail: &str,
    current: ExactProjection,
) -> Reply {
    match super::mutation_event_foundation::prior_admission_for_key_on_stream(
        data_dir,
        identity,
        scope,
        PROGRAM_SCOPE_KIND,
        id,
        NAMESPACE,
        tail,
        &request.idempotency_key,
    ) {
        Ok(Some(exact))
            if exact.operation.op_kind == requested_op_kind
                && exact.operation.payload["last_action_request"] == action_identity =>
        {
            return (
                StatusCode::OK,
                Json(json!({"ok":true,"program":projection_value(&exact,Some(true))})),
            );
        }
        Ok(Some(_)) => {
            return bad(
                StatusCode::CONFLICT,
                "foundry_idempotency_payload_conflict",
                "the idempotency key already names a different program action",
            )
        }
        Ok(None) => {}
        Err(refusal) => return mutation_refusal(refusal),
    }
    if current.head != request.expected_head {
        return bad(
            StatusCode::CONFLICT,
            "foundry_program_expected_head_conflict",
            "expected_head is not the current Agentgres head",
        );
    }
    let status = current.operation.payload["status"]
        .as_str()
        .unwrap_or_default();
    let mut next = current.operation.payload.clone();
    let op_kind = match action {
        "start" if status == "admitted" => {
            next["status"] = json!("running");
            "event_stream.foundry_program_started"
        }
        "pause" if status == "running" => {
            next["status"] = json!("paused");
            "event_stream.foundry_program_paused"
        }
        "resume" if status == "paused" => {
            next["status"] = json!("running");
            "event_stream.foundry_program_resumed"
        }
        "cancel" if matches!(status, "admitted" | "running" | "paused") => {
            next["status"] = json!("cancelled");
            "event_stream.foundry_program_cancelled"
        }
        "step" if status == "running" => {
            let max_rows = request
                .max_rows
                .unwrap_or(next["checkpoint_every_rows"].as_u64().unwrap_or(1));
            let (stepped, bytes, checkpoint_hash) =
                match train_step_compute(data_dir, &next, max_rows) {
                    Ok(value) => value,
                    Err(reply) => return reply,
                };
            // The checkpoint blob is bound to a durable admitted intent BEFORE it is written and
            // BEFORE the checkpointed successor. One blob per step, so each step records its own
            // content-addressed intent keyed by this transition's idempotency key; an exact retry
            // replays that intent, the write is a no-op, and the successor replays.
            let artifact_ref = format!(
                "artifact://foundry-checkpoint/{}",
                checkpoint_hash.trim_start_matches("sha256:")
            );
            let intent = ArtifactIntentSpec {
                family: CHECKPOINT_DIR,
                parent_kind: "training-program",
                parent_stream_tail: tail,
                parent_resource_ref: id,
                parent_op_kind: CHECKPOINT_PARENT_OP,
                artifact_hash: &checkpoint_hash,
                artifact_ref: &artifact_ref,
                owner_ref: &scope.owner_ref,
                idempotency_key: &request.idempotency_key,
            };
            if let Err(reply) = record_artifact_intent(data_dir, identity, &intent) {
                return reply;
            }
            if let Err(error) = durable_write(
                &artifact_path(data_dir, CHECKPOINT_DIR, &checkpoint_hash),
                &bytes,
            ) {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "foundry_checkpoint_persist_failed",
                    error.to_string(),
                );
            }
            next = stepped;
            "event_stream.foundry_program_checkpointed"
        }
        "reconcile" if matches!(status, "running" | "paused" | "completed") => {
            if !next["current_checkpoint"].is_null() {
                if let Err(reply) =
                    verify_checkpoint_projection(data_dir, &next["current_checkpoint"], &next)
                {
                    return reply;
                }
            }
            next["reconciliation"] = json!({"status":"satisfied","checkpoint_ref":next.pointer("/current_checkpoint/checkpoint_ref")});
            "event_stream.foundry_program_reconciled"
        }
        _ => {
            return bad(
                StatusCode::CONFLICT,
                "foundry_program_transition_invalid",
                format!("action '{action}' is not valid from status '{status}'"),
            )
        }
    };
    next["revision"] = json!(next["revision"].as_u64().unwrap_or(0) + 1);
    next["last_action_request"] = action_identity;
    next["last_action_idempotency_key"] = json!(request.idempotency_key);
    match admit(
        data_dir,
        false,
        identity,
        scope,
        PROGRAM_SCOPE_KIND,
        id,
        tail,
        op_kind,
        Some(&current.head),
        &next,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::OK,
            Json(
                json!({"ok":true,"program":projection_value(&commit.projection,Some(commit.replayed))}),
            ),
        ),
        Err(reply) => reply,
    }
}

fn verify_checkpoint_projection(
    data_dir: &str,
    projection: &Value,
    program: &Value,
) -> Result<Value, Reply> {
    if projection["complete"] != true {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_incomplete",
            "only a complete checkpoint may restore",
        ));
    }
    let hash = projection["artifact_hash"].as_str().ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_hash_missing",
            "checkpoint has no artifact hash",
        )
    })?;
    let bytes = std::fs::read(artifact_path(data_dir, CHECKPOINT_DIR, hash)).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_material_unavailable",
            error.to_string(),
        )
    })?;
    if digest(&bytes) != hash {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_material_tampered",
            "checkpoint bytes do not match the admitted artifact hash",
        ));
    }
    let checkpoint: Value = serde_json::from_slice(&bytes).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_material_invalid",
            error.to_string(),
        )
    })?;
    for field in [
        "program_id",
        "dataset_content_hash",
        "recipe_content_hash",
        "trainer_backend_profile_ref",
    ] {
        if checkpoint[field] != program[field] {
            return Err(bad(
                StatusCode::CONFLICT,
                "foundry_checkpoint_compatibility_failure",
                format!("checkpoint {field} does not match the program"),
            ));
        }
    }
    if checkpoint["status"] != "complete"
        || checkpoint["data_cursor"] != projection["data_cursor"]
        || checkpoint["token_count"] != projection["token_count"]
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_completeness_failure",
            "checkpoint metadata does not match exact bytes",
        ));
    }
    Ok(json!({
        "verified":true,
        "checkpoint_ref":projection["checkpoint_ref"],
        "artifact_hash":hash,
        "data_cursor":checkpoint["data_cursor"],
        "model_state_hash":jcs_digest(&checkpoint["model_state"]).unwrap_or_default(),
        "optimizer_state_hash":jcs_digest(&checkpoint["optimizer_state"]).unwrap_or_default(),
        "scheduler_state_hash":jcs_digest(&checkpoint["scheduler_state"]).unwrap_or_default(),
        "rng_state_hash":jcs_digest(&checkpoint["rng_state"]).unwrap_or_default(),
    }))
}

fn checkpoint_from_histories(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    checkpoint_hash: &str,
) -> Result<(String, Value), Reply> {
    let allowed = authorized_refs(data_dir, identity, PROGRAM_SCOPE_KIND)?;
    let tails =
        super::substrate_store::list_event_stream_tails(data_dir, NAMESPACE).map_err(|error| {
            bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "foundry_inventory_unavailable",
                error.to_string(),
            )
        })?;
    // A checkpoint remains the current checkpoint across pause/resume and
    // reconciliation events. Deduplicate those repeated historical sightings
    // by program tail, while still refusing a hash claimed by two programs.
    let mut found = BTreeMap::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("program."))
    {
        let current = read_head(data_dir, &tail)?;
        let program_id = current.operation.payload["program_id"]
            .as_str()
            .unwrap_or_default();
        if !allowed.contains(program_id) {
            continue;
        }
        authorize_scope(
            data_dir,
            identity,
            PROGRAM_SCOPE_KIND,
            program_id,
            current.operation.payload["owner_ref"].as_str(),
        )?;
        let history = super::substrate_store::read_event_stream_history(data_dir, NAMESPACE, &tail)
            .map_err(admission_error)?;
        for exact in history {
            let checkpoint = &exact.operation.payload["current_checkpoint"];
            if checkpoint["artifact_hash"].as_str().is_some_and(|hash| {
                hash == checkpoint_hash || hash.trim_start_matches("sha256:") == checkpoint_hash
            }) {
                found
                    .entry(tail.clone())
                    .or_insert_with(|| exact.operation.payload.clone());
            }
        }
    }
    if found.len() != 1 {
        return Err(bad(
            if found.is_empty() {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::CONFLICT
            },
            if found.is_empty() {
                "foundry_checkpoint_not_found"
            } else {
                "foundry_checkpoint_ambiguous"
            },
            "checkpoint hash must resolve exactly once",
        ));
    }
    Ok(found.into_iter().next().expect("length checked above"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointVerifyRequest {
    expected_program_head: String,
    idempotency_key: String,
}

pub(crate) async fn handle_checkpoint_verify_restore(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(checkpoint_hash): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: CheckpointVerifyRequest = match parse(body, "foundry_checkpoint_verify_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let (tail, historic_program) =
        match checkpoint_from_histories(&st.data_dir, &identity, &checkpoint_hash) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
    let current = match read_head(&st.data_dir, &tail) {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    let program_id = current.operation.payload["program_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let program_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        PROGRAM_SCOPE_KIND,
        &program_id,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if current.head != request.expected_program_head {
        return bad(
            StatusCode::CONFLICT,
            "foundry_program_expected_head_conflict",
            "expected_program_head is not current",
        );
    }
    let verification = match verify_checkpoint_projection(
        &st.data_dir,
        &historic_program["current_checkpoint"],
        &historic_program,
    ) {
        Ok(verification) => verification,
        Err(reply) => return reply,
    };
    let mut next = current.operation.payload.clone();
    next["revision"] = json!(next["revision"].as_u64().unwrap_or(0) + 1);
    next["restore_verification"] = verification;
    if next.pointer("/current_checkpoint/artifact_hash")
        == historic_program.pointer("/current_checkpoint/artifact_hash")
    {
        next["current_checkpoint"]["restore_verified"] = json!(true);
    }
    match admit(
        &st.data_dir,
        false,
        &identity,
        &program_scope,
        PROGRAM_SCOPE_KIND,
        &program_id,
        &tail,
        "event_stream.foundry_checkpoint_restore_verified",
        Some(&current.head),
        &next,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::OK,
            Json(
                json!({"ok":true,"program":projection_value(&commit.projection,Some(commit.replayed)),"verification":next["restore_verification"]}),
            ),
        ),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_checkpoints_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, PROGRAM_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let tails = match super::substrate_store::list_event_stream_tails(&st.data_dir, NAMESPACE) {
        Ok(tails) => tails,
        Err(error) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "foundry_inventory_unavailable",
                error.to_string(),
            )
        }
    };
    let mut checkpoints = BTreeMap::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("program."))
    {
        let current = match read_head(&st.data_dir, &tail) {
            Ok(current) => current,
            Err(reply) => return reply,
        };
        let program_id = current.operation.payload["program_id"]
            .as_str()
            .unwrap_or_default();
        if !allowed.contains(program_id) {
            continue;
        }
        if let Err(reply) = authorize_scope(
            &st.data_dir,
            &identity,
            PROGRAM_SCOPE_KIND,
            program_id,
            current.operation.payload["owner_ref"].as_str(),
        ) {
            return reply;
        }
        let history =
            match super::substrate_store::read_event_stream_history(&st.data_dir, NAMESPACE, &tail)
            {
                Ok(history) => history,
                Err(error) => return admission_error(error),
            };
        for exact in history {
            let checkpoint = exact.operation.payload["current_checkpoint"].clone();
            if let Some(reference) = checkpoint["checkpoint_ref"].as_str() {
                checkpoints.insert(reference.to_owned(), checkpoint);
            }
        }
    }
    (
        StatusCode::OK,
        Json(json!({"ok":true,"checkpoints":checkpoints.into_values().collect::<Vec<_>>()})),
    )
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualityGate {
    minimum_token_coverage: f64,
    maximum_mean_negative_log_likelihood: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FoundryWorkloadFingerprint {
    runtime_node_ref: String,
    environment_ref: String,
    trainer_backend_profile_ref: String,
    hardware_architecture: String,
    logical_cpu_count: u16,
    memory_bytes: u64,
    operating_system: String,
    daemon_release_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationRequest {
    expected_head: String,
    idempotency_key: String,
    evaluation_rows: Vec<Value>,
    quality_gate: QualityGate,
    workload_fingerprint: FoundryWorkloadFingerprint,
    cost_basis_ref: String,
    failure_schedule_ref: String,
}

fn qualify(program: &Value, request: &QualificationRequest) -> Result<Value, Reply> {
    if program["status"] != "completed" {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_program_not_complete",
            "qualification requires a completed program",
        ));
    }
    if request.evaluation_rows.is_empty() || request.evaluation_rows.len() > MAX_ROWS {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_qualification_rows_invalid",
            "evaluation_rows must be bounded and non-empty",
        ));
    }
    if !request.quality_gate.minimum_token_coverage.is_finite()
        || !(0.0..=1.0).contains(&request.quality_gate.minimum_token_coverage)
        || !request
            .quality_gate
            .maximum_mean_negative_log_likelihood
            .is_finite()
        || request.quality_gate.maximum_mean_negative_log_likelihood <= 0.0
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_quality_gate_invalid",
            "quality gate bounds are invalid",
        ));
    }
    for (field, value, prefixes) in [
        (
            "workload_fingerprint.runtime_node_ref",
            request.workload_fingerprint.runtime_node_ref.as_str(),
            &["runtime://"][..],
        ),
        (
            "workload_fingerprint.environment_ref",
            request.workload_fingerprint.environment_ref.as_str(),
            &["environment://"][..],
        ),
        (
            "workload_fingerprint.trainer_backend_profile_ref",
            request
                .workload_fingerprint
                .trainer_backend_profile_ref
                .as_str(),
            &["trainer-backend://"][..],
        ),
        (
            "workload_fingerprint.daemon_release_ref",
            request.workload_fingerprint.daemon_release_ref.as_str(),
            &["release://"][..],
        ),
    ] {
        validate_ref(value, field, prefixes)?;
    }
    if request.workload_fingerprint.trainer_backend_profile_ref
        != program["trainer_backend_profile_ref"]
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "foundry_workload_backend_mismatch",
            "workload fingerprint must name the program's exact trainer backend",
        ));
    }
    if !matches!(
        request.workload_fingerprint.hardware_architecture.as_str(),
        "x86_64" | "aarch64"
    ) || !matches!(
        request.workload_fingerprint.operating_system.as_str(),
        "linux" | "macos" | "windows"
    ) || request.workload_fingerprint.logical_cpu_count == 0
        || request.workload_fingerprint.memory_bytes == 0
        || request.workload_fingerprint.memory_bytes > PORTABLE_SAFE_INTEGER_MAX
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "foundry_workload_fingerprint_invalid",
            "workload fingerprint dimensions are outside the closed reference-backend profile",
        ));
    }
    validate_ref(
        &request.cost_basis_ref,
        "cost_basis_ref",
        &["cost://", "ledger://", "policy://"],
    )?;
    validate_ref(
        &request.failure_schedule_ref,
        "failure_schedule_ref",
        &["schedule://", "policy://", "artifact://"],
    )?;
    let counts = parse_token_counts(&program["token_counts"]).map_err(|error| {
        bad(
            StatusCode::CONFLICT,
            "foundry_model_state_invalid",
            error.to_string(),
        )
    })?;
    let total = counts.values().copied().sum::<u64>();
    let vocabulary = counts.len().max(1) as f64;
    let field = program["text_field"].as_str().unwrap_or_default();
    let started = Instant::now();
    let mut tokens = 0u64;
    let mut known = 0u64;
    let mut negative_log_likelihood = 0.0f64;
    for row in &request.evaluation_rows {
        let text = row[field].as_str().ok_or_else(|| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "foundry_qualification_text_missing",
                format!("evaluation row lacks string field '{field}'"),
            )
        })?;
        for token in text.split_whitespace().map(|token| token.to_lowercase()) {
            if token.is_empty() {
                continue;
            }
            tokens += 1;
            let count = counts.get(&token).copied().unwrap_or(0);
            if count > 0 {
                known += 1;
            }
            let probability = (count as f64 + 1.0) / (total as f64 + vocabulary + 1.0);
            negative_log_likelihood -= probability.ln();
        }
    }
    if tokens == 0 {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "foundry_qualification_no_tokens",
            "evaluation rows contain no tokens",
        ));
    }
    let elapsed_ns = started.elapsed().as_nanos().max(1) as u64;
    let elapsed_seconds = elapsed_ns as f64 / 1_000_000_000.0;
    let coverage = known as f64 / tokens as f64;
    let mean_nll = negative_log_likelihood / tokens as f64;
    let qualified = coverage >= request.quality_gate.minimum_token_coverage
        && mean_nll <= request.quality_gate.maximum_mean_negative_log_likelihood;
    Ok(json!({
        "schema_version":"ioi.foundry-qualified-measurement.v1",
        "verdict":if qualified { "qualified" } else { "rejected" },
        "quality":{
            "token_coverage":coverage,
            "mean_negative_log_likelihood":mean_nll,
            "gate":request.quality_gate,
        },
        "measurement":{
            "phase":"evaluation",
            "token_numerator":"loss_bearing",
            "denominator":"full_wall_clock",
            "scope":"daemon_cpu_process",
            "raw_tokens":tokens,
            "effective_tokens":tokens,
            "elapsed_nanoseconds":elapsed_ns,
            "tokens_per_second":tokens as f64 / elapsed_seconds,
            "includes_compilation":false,
            "includes_loading":true,
            "includes_evaluation":true,
            "includes_checkpoint":false,
            "includes_failure_and_recovery":false,
            "hardware_software_topology_fingerprint":request.workload_fingerprint,
            "cost_basis_ref":request.cost_basis_ref,
            "failure_schedule_ref":request.failure_schedule_ref,
        },
        "promotion_boundary":{
            "proposal_only":true,
            "governance_approval_required":true,
            "runtime_activation_performed":false,
        }
    }))
}

pub(crate) async fn handle_program_qualify(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = authorize_scope(&st.data_dir, &identity, PROGRAM_SCOPE_KIND, &id, None) {
        return reply;
    }
    let request: QualificationRequest = match parse(body, "foundry_qualification_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let (tail, current) = match program_head(&st.data_dir, &id) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let program_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        PROGRAM_SCOPE_KIND,
        &id,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    if current.head != request.expected_head {
        return bad(
            StatusCode::CONFLICT,
            "foundry_program_expected_head_conflict",
            "expected_head is not current",
        );
    }
    if current
        .operation
        .payload
        .pointer("/restore_verification/verified")
        != Some(&Value::Bool(true))
    {
        return bad(
            StatusCode::CONFLICT,
            "foundry_checkpoint_restore_verification_required",
            "qualification requires destructive checkpoint restore verification first",
        );
    }
    let qualification = match qualify(&current.operation.payload, &request) {
        Ok(qualification) => qualification,
        Err(reply) => return reply,
    };
    let mut next = current.operation.payload.clone();
    next["revision"] = json!(next["revision"].as_u64().unwrap_or(0) + 1);
    next["qualification"] = qualification;
    next["qualification_proposal_ref"] = json!(format!(
        "qualification-proposal://foundry/{}/{}",
        safe(&id),
        request.idempotency_key
    ));
    match admit(
        &st.data_dir,
        false,
        &identity,
        &program_scope,
        PROGRAM_SCOPE_KIND,
        &id,
        &tail,
        "event_stream.foundry_program_qualified",
        Some(&current.head),
        &next,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::OK,
            Json(
                json!({"ok":true,"program":projection_value(&commit.projection,Some(commit.replayed)),"qualification":next["qualification"]}),
            ),
        ),
        Err(reply) => reply,
    }
}

pub(crate) async fn handle_qualification_proposals_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let programs = match list_heads(
        &st.data_dir,
        &identity,
        "program.",
        "ioi.foundry-training-program.v1",
        PROGRAM_SCOPE_KIND,
        "program_id",
        Some("owner_ref"),
    ) {
        Ok(programs) => programs,
        Err(reply) => return reply,
    };
    let proposals = programs
        .into_iter()
        .filter(|program| !program["qualification"].is_null())
        .map(|program| {
            json!({
                "proposal_ref":program["qualification_proposal_ref"],
                "program_id":program["program_id"],
                "checkpoint_ref":program.pointer("/current_checkpoint/checkpoint_ref"),
                "qualification":program["qualification"],
                "status":"proposed",
                "activation_performed":false,
            })
        })
        .collect::<Vec<_>>();
    (
        StatusCode::OK,
        Json(json!({"ok":true,"qualification_proposals":proposals})),
    )
}

/// Owner-filtered projection of the artifact-intent obligations. State is DERIVED, never a stored
/// status a stale read could disagree with: `abandoned` when the intent's head is the terminal
/// abandonment, `discharged` when the parent effect is admitted under the intent's key, otherwise
/// `pending`.
pub(crate) async fn handle_artifact_intents_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, ARTIFACT_INTENT_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let tails = match super::substrate_store::list_event_stream_tails(&st.data_dir, NAMESPACE) {
        Ok(tails) => tails,
        Err(error) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "foundry_inventory_unavailable",
                error.to_string(),
            )
        }
    };
    let mut intents = Vec::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("artifact-intent."))
    {
        let head = match read_head(&st.data_dir, &tail) {
            Ok(head) => head,
            Err(reply) => return reply,
        };
        let intent_ref = head.operation.payload["intent_ref"]
            .as_str()
            .unwrap_or_default();
        if !allowed.contains(intent_ref) {
            continue;
        }
        if let Err(reply) = authorize_scope(
            &st.data_dir,
            &identity,
            ARTIFACT_INTENT_SCOPE_KIND,
            intent_ref,
            head.operation.payload["owner_ref"].as_str(),
        ) {
            return reply;
        }
        let state = if head.operation.op_kind == ARTIFACT_INTENT_ABANDONED {
            "abandoned"
        } else {
            let parent_tail = head.operation.payload["parent_stream_tail"]
                .as_str()
                .unwrap_or_default();
            let parent_key = head.operation.payload["parent_idempotency_key"]
                .as_str()
                .unwrap_or_default();
            match parent_effect_admitted(&st.data_dir, parent_tail, parent_key) {
                Ok(true) => "discharged",
                Ok(false) => "pending",
                Err(reply) => return reply,
            }
        };
        let intent_id = tail.trim_start_matches("artifact-intent.").to_owned();
        let mut projection = projection_value(&head, None);
        if let Some(object) = projection.as_object_mut() {
            object.insert("intent_id".into(), json!(intent_id));
            object.insert("state".into(), json!(state));
        }
        intents.push(projection);
    }
    intents.sort_by(|a, b| a["intent_ref"].as_str().cmp(&b["intent_ref"].as_str()));
    (
        StatusCode::OK,
        Json(json!({"ok":true,"artifact_intents":intents})),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIntentAbandonRequest {
    expected_intent_head: String,
    idempotency_key: String,
}

pub(crate) async fn handle_artifact_intent_abandon(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(intent_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: ArtifactIntentAbandonRequest =
        match parse(body, "foundry_artifact_intent_abandon_invalid") {
            Ok(request) => request,
            Err(reply) => return reply,
        };
    if request.idempotency_key.trim().is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "foundry_idempotency_key_required",
            "idempotency_key is required",
        );
    }
    let tail = format!("artifact-intent.{intent_id}");
    let current = match read_head(&st.data_dir, &tail) {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    let intent_ref = current.operation.payload["intent_ref"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let intent_scope = match authorize_scope(
        &st.data_dir,
        &identity,
        ARTIFACT_INTENT_SCOPE_KIND,
        &intent_ref,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    artifact_intent_abandon_core(
        &st.data_dir,
        &identity,
        &intent_scope,
        &intent_ref,
        &tail,
        current,
        &request,
    )
}

/// Post-scope core of an abandonment. Admits the terminal `foundry_artifact_intent_abandoned`
/// successor BEFORE deleting the blob — the abandoned record IS the recoverable intent, and
/// collection is the effect that follows it — but only after proving the parent effect is absent,
/// so a discharged intent can never strand a referenced blob.
fn artifact_intent_abandon_core(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    intent_scope: &super::substrate_store::RequestResourceScope,
    intent_ref: &str,
    intent_tail: &str,
    current: ExactProjection,
    request: &ArtifactIntentAbandonRequest,
) -> Reply {
    let record = current.operation.payload.clone();
    let family = record["artifact_family"].as_str().unwrap_or_default();
    let artifact_hash = record["artifact_hash"].as_str().unwrap_or_default();
    // Already terminal: idempotent. Re-run collection so a retry can finish a deletion that a prior
    // attempt left as a cleanup obligation, and return the abandoned record.
    if current.operation.op_kind == ARTIFACT_INTENT_ABANDONED {
        let collection = match collect_abandoned_blob(data_dir, intent_ref, family, artifact_hash) {
            Ok(collection) => collection,
            Err(reply) => return reply,
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok":true,
                "artifact_intent":projection_value(&current, Some(true)),
                "collection":collection
            })),
        );
    }
    if current.head != request.expected_intent_head {
        return bad(
            StatusCode::CONFLICT,
            "foundry_artifact_intent_expected_head_conflict",
            "expected_intent_head is not the current Agentgres head",
        );
    }
    // The obligation may be abandoned ONLY while its parent effect is absent. If the parent event is
    // admitted the artifact materialized and the intent is discharged; abandoning it would strand a
    // referenced blob. An admitted parent decides existence — no earlier abandonment may be recorded
    // over it.
    let parent_tail = record["parent_stream_tail"].as_str().unwrap_or_default();
    let parent_key = record["parent_idempotency_key"]
        .as_str()
        .unwrap_or_default();
    match parent_effect_admitted(data_dir, parent_tail, parent_key) {
        Ok(true) => {
            return bad(
                StatusCode::CONFLICT,
                "foundry_artifact_intent_discharged",
                "the artifact intent's parent effect is admitted; a discharged intent cannot be abandoned",
            )
        }
        Ok(false) => {}
        Err(reply) => return reply,
    }
    let mut next = record.clone();
    next["status"] = json!("abandoned");
    next["abandon_idempotency_key"] = json!(request.idempotency_key);
    match admit(
        data_dir,
        false,
        identity,
        intent_scope,
        ARTIFACT_INTENT_SCOPE_KIND,
        intent_ref,
        intent_tail,
        ARTIFACT_INTENT_ABANDONED,
        Some(&current.head),
        &next,
        now_ms(),
        &request.idempotency_key,
    ) {
        Ok(commit) => {
            let collection =
                match collect_abandoned_blob(data_dir, intent_ref, family, artifact_hash) {
                    Ok(collection) => collection,
                    Err(reply) => return reply,
                };
            (
                StatusCode::OK,
                Json(json!({
                    "ok":true,
                    "artifact_intent":projection_value(&commit.projection, Some(commit.replayed)),
                    "collection":collection
                })),
            )
        }
        Err(reply) => reply,
    }
}

/// Conservative collection of an abandoned intent's blob. Content-addressed blobs may be shared, so
/// a blob still named by another live intent or an admitted record is RETAINED, never deleted. A
/// blob already gone is not an error. A deletion that fails for another reason leaves the abandoned
/// record standing and reports a retained cleanup obligation rather than failing the abandonment.
fn collect_abandoned_blob(
    data_dir: &str,
    intent_ref: &str,
    family: &str,
    artifact_hash: &str,
) -> Result<Value, Reply> {
    if blob_has_other_referent(data_dir, intent_ref, family, artifact_hash)? {
        return Ok(json!({
            "blob_deleted":false,
            "retained":"shared_referent",
            "artifact_family":family,
            "artifact_hash":artifact_hash
        }));
    }
    match std::fs::remove_file(artifact_path(data_dir, family, artifact_hash)) {
        Ok(()) => Ok(json!({
            "blob_deleted":true,
            "artifact_family":family,
            "artifact_hash":artifact_hash
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "blob_deleted":false,
            "retained":"already_absent",
            "artifact_family":family,
            "artifact_hash":artifact_hash
        })),
        Err(error) => Ok(json!({
            "blob_deleted":false,
            "retained":"cleanup_obligation",
            "reason":error.to_string(),
            "artifact_family":family,
            "artifact_hash":artifact_hash
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_foundry_plane_handler_requires_request_identity() {
        let source = include_str!("foundry_execution_routes.rs");
        for handler in [
            "handle_recipes_create",
            "handle_recipes_list",
            "handle_recipe_get",
            "handle_recipe_run",
            "handle_dataset_snapshots_list",
            "handle_program_create",
            "handle_programs_list",
            "handle_program_get",
            "handle_program_action",
            "handle_checkpoint_verify_restore",
            "handle_checkpoints_list",
            "handle_program_qualify",
            "handle_qualification_proposals_list",
            "handle_artifact_intents_list",
            "handle_artifact_intent_abandon",
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
                    "list_heads(",
                    "bind_scope("
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

    fn operators() -> Vec<RecipeOperator> {
        vec![
            RecipeOperator {
                kind: "normalize_whitespace".into(),
                field: Some("text".into()),
                fields: None,
                from: None,
                to: None,
            },
            RecipeOperator {
                kind: "filter_nonempty".into(),
                field: Some("text".into()),
                fields: None,
                from: None,
                to: None,
            },
            RecipeOperator {
                kind: "deduplicate".into(),
                field: None,
                fields: Some(vec!["text".into()]),
                from: None,
                to: None,
            },
        ]
    }

    #[test]
    fn recipe_execution_is_deterministic() {
        let input = vec![
            json!({"text":" hello   world "}),
            json!({"text":"hello world"}),
            json!({"text":"second row"}),
        ];
        let first = run_operators(input.clone(), &operators()).unwrap();
        let second = run_operators(input, &operators()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![json!({"text":"hello world"}), json!({"text":"second row"})]
        );
    }

    #[test]
    fn split_assignment_is_stable() {
        let splits = SplitBasisPoints {
            train: 8000,
            validation: 1000,
            test: 1000,
        };
        let row = json!({"text":"stable"});
        assert_eq!(
            split_name(&row, 7, &splits).unwrap(),
            split_name(&row, 7, &splits).unwrap()
        );
    }

    #[test]
    fn checkpoint_bytes_bind_complete_resume_state() {
        let program = json!({
            "program_id":"trainpipe://test/run",
            "dataset_snapshot_ref":"dataset-snapshot://foundry/test",
            "dataset_content_hash":digest(b"dataset"),
            "recipe_content_hash":digest(b"recipe"),
            "trainer_backend_profile_ref":"trainer-backend://ioi/reference-token-frequency/v1",
            "seed":9,
        });
        let counts = BTreeMap::from([("token".to_owned(), 3)]);
        let checkpoint = checkpoint_record(&program, &counts, 2, 3);
        assert_eq!(checkpoint["data_cursor"], 2);
        assert_eq!(
            checkpoint["model_state"]["token_counts"],
            json!([{"token":"token","count":3}])
        );
        assert_eq!(checkpoint["optimizer_state"]["updates"], 2);
        assert_eq!(checkpoint["rng_state"]["seed"], 9);
    }

    #[test]
    fn content_addressed_artifact_refuses_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact.json");
        durable_write(&path, b"one").unwrap();
        durable_write(&path, b"one").unwrap();
        assert_eq!(
            durable_write(&path, b"two").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn legacy_token_maps_migrate_to_deterministic_closed_rows() {
        let legacy = json!({"zeta": 2, "alpha": 1});
        let counts = parse_token_counts(&legacy).expect("legacy map is readable");
        assert_eq!(
            serde_json::to_value(token_count_rows(&counts)).unwrap(),
            json!([
                {"token":"alpha","count":1},
                {"token":"zeta","count":2}
            ])
        );
    }

    #[test]
    fn canonical_token_rows_reject_unsorted_or_duplicate_tokens() {
        assert!(parse_token_counts(&json!([
            {"token":"zeta","count":1},
            {"token":"alpha","count":1}
        ]))
        .is_err());
        assert!(parse_token_counts(&json!([
            {"token":"alpha","count":1},
            {"token":"alpha","count":2}
        ]))
        .is_err());
    }

    #[test]
    fn workload_fingerprint_is_closed() {
        let error = serde_json::from_value::<FoundryWorkloadFingerprint>(json!({
            "runtime_node_ref":"runtime://local/node",
            "environment_ref":"environment://local/foundry",
            "trainer_backend_profile_ref":"trainer-backend://ioi/reference-token-frequency/v1",
            "hardware_architecture":"x86_64",
            "logical_cpu_count":4,
            "memory_bytes":8589934592u64,
            "operating_system":"linux",
            "daemon_release_ref":"release://ioi/hypervisor-daemon/dev",
            "gpu":"unruled"
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `gpu`"));
    }

    fn recipe_request(recipe_id: &str, owner: &str, key: &str) -> RecipeRevisionRequest {
        RecipeRevisionRequest {
            recipe_id: recipe_id.to_owned(),
            owner_ref: owner.to_owned(),
            predecessor_recipe_ref: None,
            expected_head: None,
            data_recipe_ref: "data-recipe://test/one".into(),
            source_snapshot_refs: vec!["snapshot://test/a".into()],
            institutional_learning_boundary_ref: "learning-boundary://test/one".into(),
            learning_source_rights_claim_refs: vec!["rights://test/a".into()],
            tokenizer_ref: "tokenizer://test/one".into(),
            sequence_format_ref: "format://test/one".into(),
            packing_policy_ref: "policy://test/pack".into(),
            loss_mask_policy_ref: "policy://test/mask".into(),
            harness_variant_refs: vec!["harness://test/a".into()],
            environment_profile_ref: "profile://test/one".into(),
            operators: operators(),
            split_seed: 7,
            idempotency_key: key.to_owned(),
        }
    }

    // The re-homed recipe-create scan must still refuse a same-key/different-bytes resubmission with
    // this plane's own conflict code, still replay a byte-identical retry after a daemon restart, and
    // still refuse a stale successor head. The shared prior-key probe changed HOW the prior fact is
    // read (scope-validated, one seam) but not the four arms that decide on it.
    #[test]
    fn recipe_create_core_preserves_scan_refusal_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let recipe_id = "foundry-recipe://test/one";
        let request = recipe_request(recipe_id, "org://local", "recipe-key-1");
        let content_hash = recipe_content_hash(&request).unwrap();
        let tail = hash_tail("recipe", recipe_id);
        let scope = bind_scope(
            data_dir,
            &identity,
            RECIPE_SCOPE_KIND,
            recipe_id,
            "org://local",
            &request.idempotency_key,
        )
        .unwrap();

        let (status, Json(body)) = recipes_create_core(
            data_dir,
            &identity,
            &scope,
            &request,
            &content_hash,
            &tail,
            None,
        );
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["ok"], true);
        assert_eq!(body["recipe"]["agentgres"]["replayed"], false);
        let genesis_head = body["recipe"]["agentgres"]["head"]
            .as_str()
            .unwrap()
            .to_owned();

        // Byte-identical retry AFTER a restart replays the original fact from the durable log, never a
        // second admission.
        super::super::substrate_store::reset_handle_for_test();
        let current =
            super::super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, &tail)
                .unwrap();
        let (status, Json(body)) = recipes_create_core(
            data_dir,
            &identity,
            &scope,
            &request,
            &content_hash,
            &tail,
            current.clone(),
        );
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["recipe"]["agentgres"]["replayed"], true);
        assert_eq!(body["recipe"]["agentgres"]["head"], genesis_head);

        // Same key, changed seed (=> changed content hash): refused as a payload conflict, never
        // swallowed as a replay.
        let mut changed = recipe_request(recipe_id, "org://local", "recipe-key-1");
        changed.split_seed = 99;
        let changed_hash = recipe_content_hash(&changed).unwrap();
        assert_ne!(changed_hash, content_hash);
        let (status, Json(body)) = recipes_create_core(
            data_dir,
            &identity,
            &scope,
            &changed,
            &changed_hash,
            &tail,
            current.clone(),
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"]["code"],
            "foundry_idempotency_payload_conflict"
        );

        // A fresh key naming a stale expected head is a head conflict, not a silent successor.
        let mut successor = recipe_request(recipe_id, "org://local", "recipe-key-2");
        successor.expected_head = Some(format!("sha256:{}", "0".repeat(64)));
        successor.predecessor_recipe_ref = Some(format!("{recipe_id}/revision/1"));
        let successor_hash = recipe_content_hash(&successor).unwrap();
        let (status, Json(body)) = recipes_create_core(
            data_dir,
            &identity,
            &scope,
            &successor,
            &successor_hash,
            &tail,
            current,
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"]["code"],
            "foundry_recipe_expected_head_conflict"
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    fn admitted_program(
        data_dir: &str,
        identity: &super::super::substrate_store::RequestIdentity,
        program_id: &str,
    ) -> super::super::substrate_store::RequestResourceScope {
        let scope = bind_scope(
            data_dir,
            identity,
            PROGRAM_SCOPE_KIND,
            program_id,
            "org://local",
            "program-create",
        )
        .unwrap();
        let payload = json!({
            "schema_version":"ioi.foundry-training-program.v1",
            "program_id": program_id,
            "owner_ref":"org://local",
            "revision": 1,
            "status":"admitted",
            "last_action_idempotency_key":"program-create",
        });
        let tail = hash_tail("program", program_id);
        admit(
            data_dir,
            true,
            identity,
            &scope,
            PROGRAM_SCOPE_KIND,
            program_id,
            &tail,
            "event_stream.foundry_program_admitted",
            None,
            &payload,
            1,
            "program-create",
        )
        .unwrap();
        scope
    }

    // The re-homed program-action scan keeps the same arms: an idempotent replay for the identical
    // action, this plane's payload-conflict code for a same-key/different-action resubmission, and a
    // head conflict for a fresh key on a stale head.
    #[test]
    fn program_action_core_preserves_scan_refusal_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let program_id = "trainpipe://test/run";
        let scope = admitted_program(data_dir, &identity, program_id);

        let start = |key: &str, max_rows: Option<u64>, expected_head: &str| -> Reply {
            let (tail, current) = program_head(data_dir, program_id).unwrap();
            let request = ProgramActionRequest {
                expected_head: expected_head.to_owned(),
                idempotency_key: key.to_owned(),
                max_rows,
            };
            let action_identity = json!({"action":"start","max_rows": request.max_rows});
            program_action_core(
                data_dir,
                &identity,
                &scope,
                program_id,
                "start",
                &request,
                program_action_op_kind("start").unwrap(),
                action_identity,
                &tail,
                current,
            )
        };

        let head0 = program_head(data_dir, program_id).unwrap().1.head;
        let (status, Json(body)) = start("act-1", None, &head0);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["program"]["status"], "running");
        assert_eq!(body["program"]["agentgres"]["replayed"], false);
        let running_head = body["program"]["agentgres"]["head"]
            .as_str()
            .unwrap()
            .to_owned();

        // Byte-identical retry AFTER a restart replays with the same head.
        super::super::substrate_store::reset_handle_for_test();
        let (status, Json(body)) = start("act-1", None, &head0);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["program"]["agentgres"]["replayed"], true);
        assert_eq!(body["program"]["agentgres"]["head"], running_head);

        // Same key, different max_rows names a different logical action → payload conflict.
        let (status, Json(body)) = start("act-1", Some(9), &head0);
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"]["code"],
            "foundry_idempotency_payload_conflict"
        );

        // A fresh key against a stale expected head → head conflict (probe misses, CAS refuses).
        let (status, Json(body)) = start("act-2", None, &format!("sha256:{}", "0".repeat(64)));
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body["error"]["code"],
            "foundry_program_expected_head_conflict"
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    // The durability fault hook is thread-local, but the process-global writer handle is shared, so
    // the delicate window in which an admission is faulted and then retried is serialized here.
    static FAULT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn blob_file_count(data_dir: &str, family: &str) -> usize {
        std::fs::read_dir(Path::new(data_dir).join(family))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                    .count()
            })
            .unwrap_or(0)
    }

    fn admitted_recipe(
        data_dir: &str,
        identity: &super::super::substrate_store::RequestIdentity,
        recipe_id: &str,
    ) -> ExactProjection {
        let request = recipe_request(recipe_id, "org://local", "recipe-create-key");
        let content_hash = recipe_content_hash(&request).unwrap();
        let tail = hash_tail("recipe", recipe_id);
        let scope = bind_scope(
            data_dir,
            identity,
            RECIPE_SCOPE_KIND,
            recipe_id,
            "org://local",
            &request.idempotency_key,
        )
        .unwrap();
        let (status, _) = recipes_create_core(
            data_dir,
            identity,
            &scope,
            &request,
            &content_hash,
            &tail,
            None,
        );
        assert_eq!(status, StatusCode::CREATED);
        read_head(data_dir, &tail).unwrap()
    }

    fn recipe_run_request(key: &str) -> RecipeRunRequest {
        RecipeRunRequest {
            expected_recipe_head: String::new(),
            expected_recipe_content_hash: String::new(),
            rights_grant_refs: vec!["rights://test/grant".into()],
            input_rows: vec![json!({"text":"alpha beta"}), json!({"text":"gamma delta"})],
            splits: SplitBasisPoints {
                train: 10000,
                validation: 0,
                test: 0,
            },
            idempotency_key: key.into(),
        }
    }

    // The happy path: recipe_run_core admits the artifact intent BEFORE the blob and the parent, so a
    // completed run leaves the blob present and the intent DISCHARGED (its parent materialized under
    // the same key). Mutation check: swapping the intent admission to AFTER durable_write in
    // commit_dataset_artifact leaves the intent stream empty here, failing the recorded-op assertion.
    #[test]
    fn recipe_run_binds_the_dataset_blob_to_a_discharged_intent() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let recipe_id = "foundry-recipe://test/run";
        let recipe = admitted_recipe(data_dir, &identity, recipe_id);
        let recipe_scope =
            authorize_scope(data_dir, &identity, RECIPE_SCOPE_KIND, recipe_id, None).unwrap();
        let request = recipe_run_request("run-key-1");
        let prepared = recipe_run_prepare(&recipe, &request).unwrap();
        let intent_ref = artifact_intent_ref(DATA_DIR, &prepared.tail, &prepared.content_hash);
        let intent_tail = hash_tail("artifact-intent", &intent_ref);

        let (status, Json(body)) =
            recipe_run_core(data_dir, &identity, &recipe_scope, &recipe, request);
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["dataset_snapshot"]["status"], "materialized");

        let intent_head = read_head(data_dir, &intent_tail).unwrap();
        assert_eq!(intent_head.operation.op_kind, ARTIFACT_INTENT_RECORDED);
        assert_eq!(
            intent_head.operation.payload["artifact_hash"],
            prepared.content_hash
        );
        // The parent materialized under the intent's key: discharged.
        assert!(parent_effect_admitted(data_dir, &prepared.tail, "run-key-1").unwrap());
        assert!(artifact_path(data_dir, DATA_DIR, &prepared.content_hash).exists());
        super::super::substrate_store::reset_handle_for_test();
    }

    // Post-materialization admission-failure recovery. The intent is admitted and the blob written,
    // then the parent materialization ALONE is faulted: the caller sees a typed durability refusal,
    // the blob is present, and the intent's head is still the pending genesis (never abandoned). An
    // exact retry converges — the intent replays, the write no-ops, the parent is admitted — with no
    // duplicate intent, blob, or parent event. Mutation check: deleting the record_artifact_intent
    // call in commit_dataset_artifact makes the "single intent event" assertion after retry fail
    // (zero intent events), and moving durable_write BEFORE record_artifact_intent makes the
    // "blob present, intent pending" pair unprovable because the fault would land on the intent.
    #[test]
    fn artifact_intent_recovers_a_post_materialization_durability_failure() {
        let _serial = FAULT_TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let recipe_id = "foundry-recipe://test/run";
        let recipe = admitted_recipe(data_dir, &identity, recipe_id);
        let recipe_scope =
            authorize_scope(data_dir, &identity, RECIPE_SCOPE_KIND, recipe_id, None).unwrap();
        let request = recipe_run_request("run-key-fault");
        let prepared = recipe_run_prepare(&recipe, &request).unwrap();
        let intent_ref = artifact_intent_ref(DATA_DIR, &prepared.tail, &prepared.content_hash);
        let intent_tail = hash_tail("artifact-intent", &intent_ref);
        let blob = artifact_path(data_dir, DATA_DIR, &prepared.content_hash);

        // Intent + blob succeed; the parent admission alone faults.
        let dataset_scope = bind_scope(
            data_dir,
            &identity,
            DATASET_SCOPE_KIND,
            &prepared.snapshot_ref,
            &recipe_scope.owner_ref,
            "run-key-fault",
        )
        .unwrap();
        let artifact_ref = format!(
            "artifact://foundry-dataset/{}",
            prepared.content_hash.trim_start_matches("sha256:")
        );
        let spec = ArtifactIntentSpec {
            family: DATA_DIR,
            parent_kind: "dataset-snapshot",
            parent_stream_tail: &prepared.tail,
            parent_resource_ref: &prepared.snapshot_ref,
            parent_op_kind: DATASET_PARENT_OP,
            artifact_hash: &prepared.content_hash,
            artifact_ref: &artifact_ref,
            owner_ref: &recipe_scope.owner_ref,
            idempotency_key: "run-key-fault",
        };
        let intent_commit = record_artifact_intent(data_dir, &identity, &spec).unwrap();
        assert!(!intent_commit.replayed);
        durable_write(&blob, &prepared.bytes).unwrap();

        let forced = agentgres::event_stream::force_durability_failure_for_this_thread();
        let faulted = admit(
            data_dir,
            true,
            &identity,
            &dataset_scope,
            DATASET_SCOPE_KIND,
            &prepared.snapshot_ref,
            &prepared.tail,
            DATASET_PARENT_OP,
            None,
            &prepared.payload,
            now_ms(),
            "run-key-fault",
        );
        drop(forced);
        let (status, Json(body)) = match faulted {
            Ok(_) => panic!("a forced durability fault must not return success"),
            Err(reply) => reply,
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "event_stream_durability_unconfirmed");
        // Blob present, intent PENDING (head is the recorded genesis, not abandoned).
        assert!(blob.exists());
        let intent_head = read_head(data_dir, &intent_tail).unwrap();
        assert_eq!(intent_head.operation.op_kind, ARTIFACT_INTENT_RECORDED);
        assert_eq!(
            super::super::substrate_store::read_event_stream_history(
                data_dir,
                NAMESPACE,
                &intent_tail
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(blob_file_count(data_dir, DATA_DIR), 1);

        // Exact retry converges: intent replays, write no-ops, parent admitted, discharged.
        let (status, Json(body)) = commit_dataset_artifact(
            data_dir,
            &identity,
            &dataset_scope,
            &prepared,
            &recipe_scope.owner_ref,
            "run-key-fault",
        );
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["dataset_snapshot"]["agentgres"]["replayed"], true);
        assert!(parent_effect_admitted(data_dir, &prepared.tail, "run-key-fault").unwrap());
        // No duplicate intent, blob, or parent event.
        assert_eq!(
            super::super::substrate_store::read_event_stream_history(
                data_dir,
                NAMESPACE,
                &intent_tail
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(blob_file_count(data_dir, DATA_DIR), 1);
        assert_eq!(
            super::super::substrate_store::read_event_stream_history(
                data_dir,
                NAMESPACE,
                &prepared.tail
            )
            .unwrap()
            .len(),
            1
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    // A pending intent whose parent never materialized (a crash between the blob write and the parent
    // admission) is a genuine orphan: abandon admits the terminal successor and collects the blob.
    // Mutation check: removing the remove_file call in collect_abandoned_blob leaves the blob on disk
    // and fails the final assertion; refusing to admit the abandon successor fails the op_kind check.
    #[test]
    fn abandon_collects_an_orphan_intent_and_records_collectability() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let content_hash = digest(b"orphan-bytes");
        let snapshot_ref = format!(
            "dataset-snapshot://foundry/{}",
            content_hash.trim_start_matches("sha256:")
        );
        let parent_tail = hash_tail("dataset", &snapshot_ref);
        let artifact_ref = format!(
            "artifact://foundry-dataset/{}",
            content_hash.trim_start_matches("sha256:")
        );
        let spec = ArtifactIntentSpec {
            family: DATA_DIR,
            parent_kind: "dataset-snapshot",
            parent_stream_tail: &parent_tail,
            parent_resource_ref: &snapshot_ref,
            parent_op_kind: DATASET_PARENT_OP,
            artifact_hash: &content_hash,
            artifact_ref: &artifact_ref,
            owner_ref: "org://local",
            idempotency_key: "orphan-key",
        };
        record_artifact_intent(data_dir, &identity, &spec).unwrap();
        let blob = artifact_path(data_dir, DATA_DIR, &content_hash);
        durable_write(&blob, b"orphan-bytes").unwrap();
        assert!(blob.exists());

        let intent_ref = artifact_intent_ref(DATA_DIR, &parent_tail, &content_hash);
        let intent_tail = hash_tail("artifact-intent", &intent_ref);
        let intent_scope = authorize_scope(
            data_dir,
            &identity,
            ARTIFACT_INTENT_SCOPE_KIND,
            &intent_ref,
            Some("org://local"),
        )
        .unwrap();
        let current = read_head(data_dir, &intent_tail).unwrap();
        let request = ArtifactIntentAbandonRequest {
            expected_intent_head: current.head.clone(),
            idempotency_key: "abandon-key".into(),
        };
        let (status, Json(body)) = artifact_intent_abandon_core(
            data_dir,
            &identity,
            &intent_scope,
            &intent_ref,
            &intent_tail,
            current,
            &request,
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["artifact_intent"]["status"], "abandoned");
        assert_eq!(body["collection"]["blob_deleted"], true);
        let head = read_head(data_dir, &intent_tail).unwrap();
        assert_eq!(head.operation.op_kind, ARTIFACT_INTENT_ABANDONED);
        assert!(!blob.exists());
        super::super::substrate_store::reset_handle_for_test();
    }

    // A discharged intent — its parent materialized — cannot be abandoned: abandoning it would strand
    // a referenced blob. Mutation check: dropping the parent_effect_admitted guard in
    // artifact_intent_abandon_core lets the abandon through, failing the CONFLICT assertion.
    #[test]
    fn abandon_refuses_a_discharged_intent() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let recipe_id = "foundry-recipe://test/run";
        let recipe = admitted_recipe(data_dir, &identity, recipe_id);
        let recipe_scope =
            authorize_scope(data_dir, &identity, RECIPE_SCOPE_KIND, recipe_id, None).unwrap();
        let request = recipe_run_request("run-key-2");
        let prepared = recipe_run_prepare(&recipe, &request).unwrap();
        let (status, _) = recipe_run_core(data_dir, &identity, &recipe_scope, &recipe, request);
        assert_eq!(status, StatusCode::CREATED);

        let intent_ref = artifact_intent_ref(DATA_DIR, &prepared.tail, &prepared.content_hash);
        let intent_tail = hash_tail("artifact-intent", &intent_ref);
        let intent_scope = authorize_scope(
            data_dir,
            &identity,
            ARTIFACT_INTENT_SCOPE_KIND,
            &intent_ref,
            Some("org://local"),
        )
        .unwrap();
        let current = read_head(data_dir, &intent_tail).unwrap();
        let abandon = ArtifactIntentAbandonRequest {
            expected_intent_head: current.head.clone(),
            idempotency_key: "abandon-key".into(),
        };
        let (status, Json(body)) = artifact_intent_abandon_core(
            data_dir,
            &identity,
            &intent_scope,
            &intent_ref,
            &intent_tail,
            current,
            &abandon,
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], "foundry_artifact_intent_discharged");
        // The discharged blob is retained.
        assert!(artifact_path(data_dir, DATA_DIR, &prepared.content_hash).exists());
        super::super::substrate_store::reset_handle_for_test();
    }

    // Two checkpoint intents from different programs can name the SAME content-addressed blob.
    // Abandoning one must RETAIN the blob while the other still references it, and only collect it
    // once the last referent is abandoned. Mutation check: making blob_has_other_referent always
    // return false deletes the shared blob on the first abandon, failing the "still exists" assertion.
    #[test]
    fn abandon_retains_a_blob_with_another_referent_then_collects_it() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let content_hash = digest(b"shared-checkpoint-bytes");
        let artifact_ref = format!(
            "artifact://foundry-checkpoint/{}",
            content_hash.trim_start_matches("sha256:")
        );
        let program_a_tail = hash_tail("program", "trainpipe://prog-a");
        let program_b_tail = hash_tail("program", "trainpipe://prog-b");
        let record = |program_tail: &str, program_id: &str, key: &str| {
            let spec = ArtifactIntentSpec {
                family: CHECKPOINT_DIR,
                parent_kind: "training-program",
                parent_stream_tail: program_tail,
                parent_resource_ref: program_id,
                parent_op_kind: CHECKPOINT_PARENT_OP,
                artifact_hash: &content_hash,
                artifact_ref: &artifact_ref,
                owner_ref: "org://local",
                idempotency_key: key,
            };
            record_artifact_intent(data_dir, &identity, &spec).unwrap();
        };
        record(&program_a_tail, "trainpipe://prog-a", "step-a");
        record(&program_b_tail, "trainpipe://prog-b", "step-b");
        let blob = artifact_path(data_dir, CHECKPOINT_DIR, &content_hash);
        durable_write(&blob, b"shared-checkpoint-bytes").unwrap();

        let abandon = |program_tail: &str, key: &str| -> Value {
            let intent_ref = artifact_intent_ref(CHECKPOINT_DIR, program_tail, &content_hash);
            let intent_tail = hash_tail("artifact-intent", &intent_ref);
            let intent_scope = authorize_scope(
                data_dir,
                &identity,
                ARTIFACT_INTENT_SCOPE_KIND,
                &intent_ref,
                Some("org://local"),
            )
            .unwrap();
            let current = read_head(data_dir, &intent_tail).unwrap();
            let request = ArtifactIntentAbandonRequest {
                expected_intent_head: current.head.clone(),
                idempotency_key: key.into(),
            };
            let (status, Json(body)) = artifact_intent_abandon_core(
                data_dir,
                &identity,
                &intent_scope,
                &intent_ref,
                &intent_tail,
                current,
                &request,
            );
            assert_eq!(status, StatusCode::OK);
            body
        };

        // Abandoning A retains the blob: B still references it.
        let body = abandon(&program_a_tail, "abandon-a");
        assert_eq!(body["collection"]["blob_deleted"], false);
        assert_eq!(body["collection"]["retained"], "shared_referent");
        assert!(blob.exists());

        // Abandoning the last referent B collects it.
        let body = abandon(&program_b_tail, "abandon-b");
        assert_eq!(body["collection"]["blob_deleted"], true);
        assert!(!blob.exists());
        super::super::substrate_store::reset_handle_for_test();
    }

    fn admitted_running_program(
        data_dir: &str,
        identity: &super::super::substrate_store::RequestIdentity,
        program_id: &str,
        snapshot_ref: &str,
        dataset_content_hash: &str,
        recipe_content_hash: &str,
    ) -> (
        super::super::substrate_store::RequestResourceScope,
        String,
        ExactProjection,
    ) {
        let scope = bind_scope(
            data_dir,
            identity,
            PROGRAM_SCOPE_KIND,
            program_id,
            "org://local",
            "program-create",
        )
        .unwrap();
        let payload = json!({
            "schema_version":"ioi.foundry-training-program.v1",
            "program_id": program_id,
            "owner_ref":"org://local",
            "dataset_snapshot_ref": snapshot_ref,
            "dataset_content_hash": dataset_content_hash,
            "recipe_content_hash": recipe_content_hash,
            "trainer_backend_profile_ref":"trainer-backend://ioi/reference-token-frequency/v1",
            "text_field":"text",
            "checkpoint_every_rows": 10,
            "seed": 0,
            "revision": 1,
            "status":"running",
            "data_cursor": 0,
            "processed_rows": 0,
            "processed_tokens": 0,
            "token_counts": [],
            "checkpoint_refs": [],
            "current_checkpoint": Value::Null,
            "last_action_idempotency_key":"program-create",
        });
        let tail = hash_tail("program", program_id);
        admit(
            data_dir,
            true,
            identity,
            &scope,
            PROGRAM_SCOPE_KIND,
            program_id,
            &tail,
            "event_stream.foundry_program_admitted",
            None,
            &payload,
            1,
            "program-create",
        )
        .unwrap();
        let head = read_head(data_dir, &tail).unwrap();
        (scope, tail, head)
    }

    // The checkpoint site is bound too: a program step admits a checkpoint intent BEFORE the blob and
    // the checkpointed successor, so a completed step leaves the checkpoint blob present and the
    // intent discharged. Mutation check: removing record_artifact_intent from the step arm leaves the
    // checkpoint intent stream empty, failing the recorded-op assertion.
    #[test]
    fn program_step_binds_the_checkpoint_blob_to_a_discharged_intent() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "user://one",
            ["org://local".to_string()],
        );
        let recipe_id = "foundry-recipe://test/step";
        let recipe = admitted_recipe(data_dir, &identity, recipe_id);
        let recipe_scope =
            authorize_scope(data_dir, &identity, RECIPE_SCOPE_KIND, recipe_id, None).unwrap();
        let recipe_content_hash = recipe.operation.payload["content_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let run = recipe_run_request("ds-key");
        let prepared = recipe_run_prepare(&recipe, &run).unwrap();
        let (status, _) = recipe_run_core(data_dir, &identity, &recipe_scope, &recipe, run);
        assert_eq!(status, StatusCode::CREATED);

        let program_id = "trainpipe://test/step";
        let (program_scope, program_tail, program_head) = admitted_running_program(
            data_dir,
            &identity,
            program_id,
            &prepared.snapshot_ref,
            &prepared.content_hash,
            &recipe_content_hash,
        );
        let request = ProgramActionRequest {
            expected_head: program_head.head.clone(),
            idempotency_key: "step-key".into(),
            max_rows: None,
        };
        let action_identity = json!({"action":"step","max_rows": request.max_rows});
        let (status, Json(body)) = program_action_core(
            data_dir,
            &identity,
            &program_scope,
            program_id,
            "step",
            &request,
            program_action_op_kind("step").unwrap(),
            action_identity,
            &program_tail,
            program_head,
        );
        assert_eq!(status, StatusCode::OK);
        let checkpoint_hash = body["program"]["current_checkpoint"]["artifact_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(artifact_path(data_dir, CHECKPOINT_DIR, &checkpoint_hash).exists());

        let intent_ref = artifact_intent_ref(CHECKPOINT_DIR, &program_tail, &checkpoint_hash);
        let intent_tail = hash_tail("artifact-intent", &intent_ref);
        let intent_head = read_head(data_dir, &intent_tail).unwrap();
        assert_eq!(intent_head.operation.op_kind, ARTIFACT_INTENT_RECORDED);
        assert_eq!(
            intent_head.operation.payload["artifact_family"],
            CHECKPOINT_DIR
        );
        // The checkpointed successor is admitted under the step key: the checkpoint intent is
        // discharged.
        assert!(parent_effect_admitted(data_dir, &program_tail, "step-key").unwrap());
        super::super::substrate_store::reset_handle_for_test();
    }
}
