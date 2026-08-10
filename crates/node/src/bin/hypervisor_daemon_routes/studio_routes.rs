//! Studio blueprints family (OQ-11 ruling) — draft-only, content-addressed, governed promotion.
//!
//! A StudioBlueprint is an authored composition draft: a name, a description, an opaque bounded
//! `graph` document, and an optional `layout_ref` naming a stored `artifact://` layout. This cut
//! builds the OBJECT PLANE only — nothing here generates a surface, mounts a runtime, or grants
//! authority.
//!
//! Three disciplines, all inherited rather than re-invented:
//!   * every mutation goes through the shared owner-scoped admission foundation
//!     (`mutation_event_foundation`) exactly like the ODK families: authenticated identity first,
//!     owner binding, caller idempotency, genesis/successor compare-and-swap, Agentgres admission,
//!     receipt — the read-model record is a projection of the admitted fact, never the authority;
//!   * content identity is a canonical (JCS) sha256 over the four author-editable fields, so two
//!     byte-different requests that mean the same blueprint hash the same and key order can never
//!     mint a "new" version;
//!   * `promote` COMPOSES governance: it creates a real ApprovalRequest through the governance
//!     plane's own handler and records the request on the blueprint. Status stays `"draft"` —
//!     nothing auto-applies on approval; any state change an approval authorizes is a later,
//!     separate plane.

use axum::http::HeaderMap;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{iso_now, persist_record, read_record_dir, DaemonState};

/// Record-directory kind for the read-model projection (also referenced by
/// `governance_routes::resolve_governance_ref` so a `blueprint://` approval subject must resolve).
pub(crate) const KIND_BLUEPRINT: &str = "studio-blueprints";
/// Owner namespace for the admitted streams — a new namespace for the studio plane, mirroring
/// `hypervisor-odk` / `hypervisor-package-registry` (the substrate takes any canonical lowercase
/// namespace; no registration step exists).
const STUDIO_NAMESPACE: &str = "hypervisor-studio";
const BLUEPRINT_SCOPE_KIND: &str = "hypervisor-studio-blueprint";
/// Code-local schema constant is the house pattern; the M6 central-registration gap is filed.
const BLUEPRINT_SCHEMA_VERSION: &str = "ioi.hypervisor.studio.blueprint.v1";
const BLUEPRINT_REF_PREFIX: &str = "blueprint://";

const NAME_MAX: usize = 200;
const DESCRIPTION_MAX: usize = 2000;
const REASON_MAX: usize = 2000;
const LAYOUT_REF_MAX: usize = 300;
/// Bound on the SERIALIZED graph document, refused typed — never truncated.
const GRAPH_MAX_BYTES: usize = 65_536;

// ---------------------------------- small local helpers -----------------------------------------

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
fn persist_required(
    data_dir: &str,
    kind: &str,
    id: &str,
    record: &Value,
    code: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": code,
                    "message": "the durable record could not be committed"
                }
            })),
        )
    })
}
fn sort_by_updated(list: &mut [Value]) {
    list.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(|v| v.as_str()).unwrap_or(""))
    });
}

// ------------------------- shared-foundation admission (odk_admit mirror) ------------------------

fn studio_scope_refusal(
    error: super::substrate_store::RequestScopeRefusal,
) -> (StatusCode, Json<Value>) {
    use super::substrate_store::RequestScopeRefusal;
    let status = match error {
        RequestScopeRefusal::AuthenticationRequired
        | RequestScopeRefusal::PrincipalIdentityInvalid => StatusCode::UNAUTHORIZED,
        RequestScopeRefusal::TenantAuthorityRequired
        | RequestScopeRefusal::ResourceScopeRequired
        | RequestScopeRefusal::ResourceOwnerMismatch => StatusCode::FORBIDDEN,
        RequestScopeRefusal::SubstrateUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
    )
}

fn studio_mutation_refusal(
    error: super::mutation_event_foundation::MutationRefusal,
) -> (StatusCode, Json<Value>) {
    use super::mutation_event_foundation::MutationRefusal;
    match error {
        MutationRefusal::Scope(error) => studio_scope_refusal(error),
        MutationRefusal::Admission(error) => (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "code": error.code(), "message": error.to_string() })),
        ),
        error @ MutationRefusal::RequestFingerprintFailed(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
        ),
        error => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "code": error.code(), "message": error.message() })),
        ),
    }
}

/// Timestamps come from the ADMISSION, never from request-time wall-clock: a payload that carries
/// `iso_now()` can never be byte-identical across a retry, which is what makes an idempotency key
/// meaningless.
fn admitted_stamp_ms(recorded_at_ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    let ms = recorded_at_ms as i128;
    time::OffsetDateTime::from_unix_timestamp_nanos(ms * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(iso_now)
}

fn studio_hash_tail(prefix: &str, identity: &str) -> String {
    use sha2::Digest;
    format!("{prefix}.{:x}", sha2::Sha256::digest(identity.as_bytes()))
}

/// Derive a resource id from owner + caller key so a retried create resolves the SAME resource.
/// A wall-clock id can never be idempotent.
fn studio_derived_id(prefix: &str, owner_ref: &str, idempotency_key: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{owner_ref}\u{0}{idempotency_key}").as_bytes());
    format!("{prefix}_{digest:x}")[..(prefix.len() + 17)].to_string()
}

/// One owner-scoped admission path for the blueprint family — a deliberate mirror of
/// `odk_routes::odk_admit`, so the studio plane cannot drift into a second mutation contract.
/// The caller validates its own shape and hands over a finished record; this does identity,
/// owner binding, caller idempotency, CAS, Agentgres admission, and the read-model projection.
///
/// `previous` is None for a genesis create and Some(existing) for a successor.
struct StudioAdmission<'a> {
    family: &'a str,
    scope_kind: &'a str,
    ref_prefix: &'a str,
    op_kind: &'a str,
    reply_key: &'a str,
    persist_error: &'a str,
}

fn studio_admit(
    data_dir: &str,
    headers: &HeaderMap,
    body: &Value,
    spec: StudioAdmission<'_>,
    id: &str,
    mut record: Value,
    previous: Option<&Value>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return studio_scope_refusal(error),
    };
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if idempotency_key.is_empty() {
        return bad(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried write cannot apply twice",
        );
    }
    // A successor may not move a blueprint between owners, so on a successor the owner comes from
    // the admitted record rather than the request body.
    let owner_ref = match previous {
        Some(existing) => existing["owner_ref"].as_str().unwrap_or("").to_string(),
        None => body
            .get("owner_ref")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("")
            .to_string(),
    };
    if owner_ref.is_empty() {
        return bad(
            "studio_owner_ref_required",
            "owner_ref is required: a blueprint is owned by exactly one org:// or project://",
        );
    }
    let expected_head = body
        .get("expected_head")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if previous.is_some() && expected_head.is_none() {
        return bad(
            "mutation_successor_expected_head_required",
            "expected_head is required: a successor compare-and-swaps against the exact admitted head",
        );
    }

    // Wall-clock never enters the admitted payload: a retry could never be byte-identical, and the
    // substrate would refuse the replay as same-key-different-bytes, making the key meaningless.
    let created_at = previous.map(|existing| existing["created_at"].clone());
    if let Some(object) = record.as_object_mut() {
        object.remove("created_at");
        object.remove("updated_at");
        object.insert("owner_ref".into(), json!(owner_ref));
    }

    let resource_ref = format!("{}{id}", spec.ref_prefix);
    let scope = match super::substrate_store::bind_request_resource_scope(
        data_dir,
        &identity,
        spec.scope_kind,
        &resource_ref,
        &owner_ref,
        &owner_ref,
        idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return studio_scope_refusal(error),
    };
    let tail = studio_hash_tail(spec.scope_kind, &resource_ref);
    match super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        previous.is_none(),
        super::mutation_event_foundation::ScopedMutation {
            identity: &identity,
            scope: &scope,
            resource_kind: spec.scope_kind,
            resource_ref: &resource_ref,
            owner_namespace: STUDIO_NAMESPACE,
            stream_tail: &tail,
            op_kind: spec.op_kind,
            expected_head,
            payload: &record,
            idempotency_key,
            recorded_at_ms: 0,
        },
    ) {
        Ok(commit) => {
            let stamp = admitted_stamp_ms(commit.projection.operation.recorded_at_ms);
            let mut admitted = commit.projection.operation.payload.clone();
            admitted["created_at"] = created_at.unwrap_or_else(|| json!(stamp.clone()));
            admitted["updated_at"] = json!(stamp);
            if let Err(response) =
                persist_required(data_dir, spec.family, id, &admitted, spec.persist_error)
            {
                return response;
            }
            (
                if previous.is_some() {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                Json(json!({
                    "ok": true,
                    spec.reply_key: admitted,
                    "replayed": commit.replayed,
                    "receipt_ref": commit.receipt_ref,
                    "operation_ref": commit.operation_ref
                })),
            )
        }
        Err(error) => studio_mutation_refusal(error),
    }
}

// ------------------------------------- field validation ------------------------------------------

type VErr = (String, String);
fn verr(code: &str, message: String) -> VErr {
    (code.into(), message)
}

/// Present-but-wrong-type or oversized values are REJECTED with typed codes, never silently
/// defaulted or truncated.
fn str_opt_bounded(body: &Value, key: &str, max: usize) -> Result<Option<String>, VErr> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            if s.chars().count() > max {
                return Err(verr(
                    "studio_field_too_long",
                    format!("`{key}` exceeds the bounded length ({max} chars)"),
                ));
            }
            Ok(Some(s.clone()))
        }
        Some(_) => Err(verr(
            "studio_field_type_invalid",
            format!("`{key}` must be a string when present"),
        )),
    }
}

/// `name` is the one human-identity field: required on create, non-blank whenever supplied.
fn validated_name(body: &Value, required: bool) -> Result<Option<String>, VErr> {
    match str_opt_bounded(body, "name", NAME_MAX)? {
        Some(name) if !name.trim().is_empty() => Ok(Some(name.trim().to_string())),
        Some(_) => Err(verr(
            "studio_blueprint_name_invalid",
            format!("`name` must be a non-blank string (at most {NAME_MAX} chars)"),
        )),
        None if required => Err(verr(
            "studio_blueprint_name_invalid",
            format!("`name` is required (a non-blank string, at most {NAME_MAX} chars)"),
        )),
        None => Ok(None),
    }
}

/// `graph` is an opaque authored document — bounded and shape-checked, never interpreted here.
/// An empty graph is `{}`; `null` is a type error, not a clear.
fn validated_graph(body: &Value) -> Result<Option<Value>, VErr> {
    match body.get("graph") {
        None => Ok(None),
        Some(graph @ Value::Object(_)) => {
            let bytes = serde_json::to_vec(graph).map_err(|error| {
                verr(
                    "studio_blueprint_graph_invalid",
                    format!("`graph` could not be serialized: {error}"),
                )
            })?;
            if bytes.len() > GRAPH_MAX_BYTES {
                return Err(verr(
                    "studio_blueprint_graph_too_large",
                    format!(
                        "`graph` serializes to {} bytes; the bound is {GRAPH_MAX_BYTES}",
                        bytes.len()
                    ),
                ));
            }
            Ok(Some(graph.clone()))
        }
        Some(_) => Err(verr(
            "studio_field_type_invalid",
            "`graph` must be a JSON object when present".to_string(),
        )),
    }
}

/// A layout is a stored artifact; only the `artifact://` scheme is honest here. Absent leaves the
/// field unchanged (patch) / unset (create); explicit `null` clears it.
#[derive(Debug)]
enum LayoutRefEdit {
    Unchanged,
    Clear,
    Set(String),
}
fn validated_layout_ref(body: &Value) -> Result<LayoutRefEdit, VErr> {
    match body.get("layout_ref") {
        None => Ok(LayoutRefEdit::Unchanged),
        Some(Value::Null) => Ok(LayoutRefEdit::Clear),
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.chars().count() > LAYOUT_REF_MAX {
                return Err(verr(
                    "studio_layout_ref_invalid",
                    format!("`layout_ref` exceeds the bounded length ({LAYOUT_REF_MAX} chars)"),
                ));
            }
            match s.strip_prefix("artifact://") {
                Some(rest) if !rest.is_empty() => Ok(LayoutRefEdit::Set(s.to_string())),
                _ => Err(verr(
                    "studio_layout_ref_invalid",
                    "`layout_ref` must be an 'artifact://…' ref".to_string(),
                )),
            }
        }
        Some(_) => Err(verr(
            "studio_field_type_invalid",
            "`layout_ref` must be a string when present".to_string(),
        )),
    }
}

/// Content identity over the four author-editable fields. Canonical (JCS) bytes, so key order and
/// whitespace can never change what a blueprint "is"; the substrate's replay identity stays byte-
/// level and untouched.
fn blueprint_content_hash(
    name: &str,
    description: &str,
    graph: &Value,
    layout_ref: &Value,
) -> Result<String, String> {
    use sha2::Digest;
    let material = json!({
        "name": name,
        "description": description,
        "graph": graph,
        "layout_ref": layout_ref,
    });
    serde_jcs::to_vec(&material)
        .map(|bytes| format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
        .map_err(|error| error.to_string())
}

fn content_hash_failed(error: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "ok": false, "error": {
            "code": "studio_blueprint_content_hash_failed",
            "message": format!("the content hash could not be computed: {error}")
        }})),
    )
}

fn not_found() -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "ok": false, "error": {
            "code": "studio_blueprint_not_found",
            "message": "blueprint not found"
        }})),
    )
}

// ---------------------------------------- handlers -----------------------------------------------

/// GET /v1/hypervisor/studio/blueprints — read-model list projection.
pub(crate) async fn handle_studio_blueprint_list(
    State(st): State<Arc<DaemonState>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_BLUEPRINT);
    sort_by_updated(&mut items);
    Json(json!({ "ok": true, "blueprints": items }))
}

/// POST /v1/hypervisor/studio/blueprints — create a StudioBlueprint DRAFT through the shared
/// owner-scoped admission path.
pub(crate) async fn handle_studio_blueprint_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity first: a blueprint write is an owner-scoped mutation, not an anonymous
    // record-directory append.
    if let Err(error) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        return studio_scope_refusal(error);
    }
    let owner_ref = body
        .get("owner_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if owner_ref.is_empty() {
        return bad(
            "studio_owner_ref_required",
            "owner_ref is required: a blueprint is owned by exactly one org:// or project://",
        );
    }
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if idempotency_key.is_empty() {
        return bad(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried blueprint create cannot mint a second record",
        );
    }
    let name = match validated_name(&body, true) {
        Ok(name) => name.unwrap_or_default(),
        Err((c, m)) => return bad(&c, &m),
    };
    let description = match str_opt_bounded(&body, "description", DESCRIPTION_MAX) {
        Ok(description) => description.unwrap_or_default(),
        Err((c, m)) => return bad(&c, &m),
    };
    let graph = match validated_graph(&body) {
        Ok(graph) => graph.unwrap_or_else(|| json!({})),
        Err((c, m)) => return bad(&c, &m),
    };
    let layout_ref = match validated_layout_ref(&body) {
        Ok(LayoutRefEdit::Set(value)) => json!(value),
        Ok(LayoutRefEdit::Unchanged) | Ok(LayoutRefEdit::Clear) => Value::Null,
        Err((c, m)) => return bad(&c, &m),
    };
    let content_hash = match blueprint_content_hash(&name, &description, &graph, &layout_ref) {
        Ok(hash) => hash,
        Err(error) => return content_hash_failed(error),
    };
    // Identity is derived from the owner + caller key, never from wall-clock nanos: a replayed
    // request must resolve to the SAME resource, which a timestamp id can never do.
    let id = studio_derived_id("bp", owner_ref, idempotency_key);
    let record = json!({
        "schema_version": BLUEPRINT_SCHEMA_VERSION,
        "object": "ioi.hypervisor.studio.blueprint",
        "id": id,
        "ref": format!("{BLUEPRINT_REF_PREFIX}{id}"),
        "name": name,
        "description": description,
        "graph": graph,
        "layout_ref": layout_ref,
        "status": "draft",
        "content_hash": content_hash,
        "owner_ref": owner_ref,
    });
    studio_admit(
        &st.data_dir,
        &headers,
        &body,
        StudioAdmission {
            family: KIND_BLUEPRINT,
            scope_kind: BLUEPRINT_SCOPE_KIND,
            ref_prefix: BLUEPRINT_REF_PREFIX,
            op_kind: "event_stream.hypervisor_studio_blueprint_admitted",
            reply_key: "blueprint",
            persist_error: "studio_blueprint_persistence_failed",
        },
        &id,
        record,
        None,
    )
}

/// GET /v1/hypervisor/studio/blueprints/:id — the record plus the exact admitted head, read from
/// the admitted stream (never the read-model record) so a divergence is visible rather than
/// laundered. Without the head the CAS contract is unusable: the client has nothing honest to send.
pub(crate) async fn handle_studio_blueprint_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let mut reply = match load(&st.data_dir, KIND_BLUEPRINT, &id) {
        Some(record) => json!({ "ok": true, "blueprint": record }),
        None => json!({ "ok": false, "reason": "blueprint not found" }),
    };
    if reply["ok"].as_bool() == Some(true) {
        let resource_ref = format!("{BLUEPRINT_REF_PREFIX}{id}");
        let tail = studio_hash_tail(BLUEPRINT_SCOPE_KIND, &resource_ref);
        let head = super::substrate_store::read_event_stream_operation(
            &st.data_dir,
            STUDIO_NAMESPACE,
            &tail,
        )
        .ok()
        .flatten()
        .map(|projection| projection.head);
        reply["admitted_head"] = match head {
            Some(head) => json!(head),
            None => Value::Null,
        };
    }
    Json(reply)
}

/// PATCH /v1/hypervisor/studio/blueprints/:id — successor revision with required `expected_head`
/// compare-and-swap. An identical-content successor is admitted like any other; the substrate's
/// byte-level idempotency handles replays, and no local replay cache second-guesses it.
pub(crate) async fn handle_studio_blueprint_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(previous) = load(&st.data_dir, KIND_BLUEPRINT, &id) else {
        return not_found();
    };
    let mut d = previous.clone();
    match validated_name(&body, false) {
        Ok(Some(name)) => d["name"] = json!(name),
        Ok(None) => {}
        Err((c, m)) => return bad(&c, &m),
    }
    match str_opt_bounded(&body, "description", DESCRIPTION_MAX) {
        Ok(Some(description)) => d["description"] = json!(description),
        Ok(None) => {}
        Err((c, m)) => return bad(&c, &m),
    }
    match validated_graph(&body) {
        Ok(Some(graph)) => d["graph"] = graph,
        Ok(None) => {}
        Err((c, m)) => return bad(&c, &m),
    }
    match validated_layout_ref(&body) {
        Ok(LayoutRefEdit::Set(value)) => d["layout_ref"] = json!(value),
        Ok(LayoutRefEdit::Clear) => d["layout_ref"] = Value::Null,
        Ok(LayoutRefEdit::Unchanged) => {}
        Err((c, m)) => return bad(&c, &m),
    }
    // Content identity is recomputed from the RESULTING fields, so the stored hash always names
    // what the record now says — a stale hash would be a second, quietly wrong source of truth.
    let recomputed = blueprint_content_hash(
        d["name"].as_str().unwrap_or(""),
        d["description"].as_str().unwrap_or(""),
        &d["graph"],
        &d["layout_ref"],
    );
    match recomputed {
        Ok(hash) => d["content_hash"] = json!(hash),
        Err(error) => return content_hash_failed(error),
    }
    studio_admit(
        &st.data_dir,
        &headers,
        &body,
        StudioAdmission {
            family: KIND_BLUEPRINT,
            scope_kind: BLUEPRINT_SCOPE_KIND,
            ref_prefix: BLUEPRINT_REF_PREFIX,
            op_kind: "event_stream.hypervisor_studio_blueprint_revised",
            reply_key: "blueprint",
            persist_error: "studio_blueprint_persistence_failed",
        },
        &id,
        d,
        Some(&previous),
    )
}

/// POST /v1/hypervisor/studio/blueprints/:id/promote — request promotion by COMPOSING governance:
/// a real ApprovalRequest is created through the governance plane's own handler, then a successor
/// blueprint record links to it. Status STAYS `"draft"` — nothing auto-applies; an approval
/// decision is a governance record, and whatever it authorizes is a later, separate plane.
pub(crate) async fn handle_studio_blueprint_promote(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity FIRST — before any record load, so this route is not an unauthenticated
    // record-existence oracle and an anonymous caller cannot mint approval requests.
    if let Err(error) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        return studio_scope_refusal(error);
    }
    let Some(previous) = load(&st.data_dir, KIND_BLUEPRINT, &id) else {
        return not_found();
    };
    // Successor prerequisites are settled BEFORE governance is asked for an approval, so a
    // malformed promote cannot mint an orphan ApprovalRequest.
    let idempotency_key = body
        .get("idempotency_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if idempotency_key.is_empty() {
        return bad(
            "mutation_idempotency_key_invalid",
            "idempotency_key is required so a retried promote cannot apply twice",
        );
    }
    if body
        .get("expected_head")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return bad(
            "mutation_successor_expected_head_required",
            "expected_head is required: a promote compare-and-swaps against the exact admitted head",
        );
    }
    let blueprint_name = previous["name"].as_str().unwrap_or("blueprint");
    let blueprint_ref = format!("{BLUEPRINT_REF_PREFIX}{id}");
    let reason = match str_opt_bounded(&body, "reason", REASON_MAX) {
        Ok(reason) => reason
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                format!("Promotion requested for blueprint '{blueprint_name}' ({blueprint_ref})")
            }),
        Err((c, m)) => return bad(&c, &m),
    };
    // Governance composition — the governance plane's OWN create handler, in-process, so the
    // ApprovalRequest carries governance's validation and shape, not a studio imitation of them.
    let (approval_status, Json(approval_reply)) = super::governance_routes::handle_approval_create(
        State(st.clone()),
        Json(json!({
            "subject_ref": blueprint_ref,
            "request_kind": "studio_blueprint_promotion",
            "reason": reason,
        })),
    )
    .await;
    if !approval_status.is_success() {
        // Propagate the governance refusal VERBATIM — swallowing it would report a studio failure
        // while discarding the composed plane's actual reason.
        return (approval_status, Json(approval_reply));
    }
    let approval = approval_reply
        .get("approval_request")
        .cloned()
        .unwrap_or(Value::Null);
    let approval_id = approval.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let approval_ref = approval.get("ref").and_then(|v| v.as_str()).unwrap_or("");
    if approval_id.is_empty() || approval_ref.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": {
                "code": "studio_blueprint_promotion_approval_malformed",
                "message": "governance created an approval request without an id/ref; the promote was not recorded"
            }})),
        );
    }
    let mut record = previous.clone();
    record["promote_state"] = json!("approval_requested");
    record["approval_request_id"] = json!(approval_id);
    record["approval_request_ref"] = json!(approval_ref);
    // A CAS refusal below leaves the ApprovalRequest standing with no linked successor — visible
    // in the governance inbox and reversible by a reviewer reject. Deliberate: pre-reading the
    // head before the governance call would not close that race, only hide it.
    let (status, Json(mut reply)) = studio_admit(
        &st.data_dir,
        &headers,
        &body,
        StudioAdmission {
            family: KIND_BLUEPRINT,
            scope_kind: BLUEPRINT_SCOPE_KIND,
            ref_prefix: BLUEPRINT_REF_PREFIX,
            op_kind: "event_stream.hypervisor_studio_blueprint_promotion_requested",
            reply_key: "blueprint",
            persist_error: "studio_blueprint_persistence_failed",
        },
        &id,
        record,
        Some(&previous),
    );
    if status.is_success() {
        reply["approval_request"] = approval;
    }
    (status, Json(reply))
}

#[cfg(test)]
mod studio_tests {
    use super::*;

    /// The whole point of dropping nanos(): the same owner + key must resolve to the same
    /// resource, so a retried create cannot mint a second blueprint.
    #[test]
    fn blueprint_identity_is_derived_from_owner_and_caller_key_not_wall_clock() {
        let derive = |owner: &str, key: &str| studio_derived_id("bp", owner, key);
        let a = derive("org://local", "form-submit-1");
        assert_eq!(
            a,
            derive("org://local", "form-submit-1"),
            "a retry is the same resource"
        );
        assert_ne!(
            a,
            derive("org://local", "form-submit-2"),
            "a different key is a different resource"
        );
        assert_ne!(
            a,
            derive("org://other", "form-submit-1"),
            "owner is part of identity"
        );
        assert!(a.starts_with("bp_") && a.len() == 19);
    }

    /// Reader and writer MUST derive the tail from the same constant, or `admitted_head` on GET
    /// would read an empty stream and every compare-and-swap successor would refuse.
    #[test]
    fn blueprint_stream_tail_is_stable_and_resource_bound() {
        let one = studio_hash_tail(BLUEPRINT_SCOPE_KIND, "blueprint://bp_aaa");
        let two = studio_hash_tail(BLUEPRINT_SCOPE_KIND, "blueprint://bp_bbb");
        assert_eq!(
            one,
            studio_hash_tail(BLUEPRINT_SCOPE_KIND, "blueprint://bp_aaa")
        );
        assert_ne!(one, two, "distinct blueprints must not share a stream tail");
        assert!(one.starts_with(&format!("{BLUEPRINT_SCOPE_KIND}.")));
        assert_eq!(STUDIO_NAMESPACE, "hypervisor-studio");
        assert_eq!(BLUEPRINT_SCOPE_KIND, "hypervisor-studio-blueprint");
        assert_eq!(
            BLUEPRINT_SCHEMA_VERSION,
            "ioi.hypervisor.studio.blueprint.v1"
        );
    }

    /// Content identity is canonical: key order can never mint a "different" blueprint, and every
    /// author-editable field is part of the identity.
    #[test]
    fn blueprint_content_hash_is_canonical_and_content_bound() {
        let g1: Value = serde_json::from_str(r#"{"nodes":[{"id":"a"}],"edges":[]}"#).unwrap();
        let g2: Value = serde_json::from_str(r#"{"edges":[],"nodes":[{"id":"a"}]}"#).unwrap();
        let h = blueprint_content_hash("n", "d", &g1, &Value::Null).unwrap();
        assert_eq!(
            h,
            blueprint_content_hash("n", "d", &g2, &Value::Null).unwrap(),
            "key order never changes content identity"
        );
        assert_ne!(
            h,
            blueprint_content_hash("n2", "d", &g1, &Value::Null).unwrap()
        );
        assert_ne!(
            h,
            blueprint_content_hash("n", "d2", &g1, &Value::Null).unwrap()
        );
        assert_ne!(
            h,
            blueprint_content_hash("n", "d", &json!({"nodes": []}), &Value::Null).unwrap()
        );
        assert_ne!(
            h,
            blueprint_content_hash("n", "d", &g1, &json!("artifact://layouts/a1")).unwrap()
        );
        assert!(h.starts_with("sha256:") && h.len() == 71);
    }

    /// Present-but-wrong-type or oversized values are refused typed — never silently defaulted,
    /// truncated, or laundered into a valid record.
    #[test]
    fn blueprint_bounds_refuse_oversize_and_wrong_types() {
        // name: required on create, bounded, typed
        assert_eq!(
            validated_name(&json!({}), true).unwrap_err().0,
            "studio_blueprint_name_invalid"
        );
        assert_eq!(
            validated_name(&json!({ "name": "  " }), true)
                .unwrap_err()
                .0,
            "studio_blueprint_name_invalid"
        );
        assert_eq!(
            validated_name(&json!({ "name": "x".repeat(NAME_MAX + 1) }), true)
                .unwrap_err()
                .0,
            "studio_field_too_long"
        );
        assert_eq!(
            validated_name(&json!({ "name": 7 }), true).unwrap_err().0,
            "studio_field_type_invalid"
        );
        assert!(validated_name(&json!({}), false).unwrap().is_none());
        // description: bounded
        assert_eq!(
            str_opt_bounded(
                &json!({ "description": "x".repeat(DESCRIPTION_MAX + 1) }),
                "description",
                DESCRIPTION_MAX
            )
            .unwrap_err()
            .0,
            "studio_field_too_long"
        );
        // graph: object-only, serialized-size bounded
        assert!(validated_graph(&json!({})).unwrap().is_none());
        assert_eq!(
            validated_graph(&json!({ "graph": [] })).unwrap_err().0,
            "studio_field_type_invalid"
        );
        assert_eq!(
            validated_graph(&json!({ "graph": null })).unwrap_err().0,
            "studio_field_type_invalid"
        );
        assert_eq!(
            validated_graph(&json!({ "graph": { "blob": "x".repeat(GRAPH_MAX_BYTES) } }))
                .unwrap_err()
                .0,
            "studio_blueprint_graph_too_large"
        );
        // layout_ref: artifact:// scheme only, bounded; explicit null clears; absent unchanged
        assert_eq!(
            validated_layout_ref(&json!({ "layout_ref": "s3://bucket/x" }))
                .unwrap_err()
                .0,
            "studio_layout_ref_invalid"
        );
        assert_eq!(
            validated_layout_ref(&json!({ "layout_ref": "artifact://" }))
                .unwrap_err()
                .0,
            "studio_layout_ref_invalid"
        );
        assert_eq!(
            validated_layout_ref(
                &json!({ "layout_ref": format!("artifact://{}", "x".repeat(LAYOUT_REF_MAX)) })
            )
            .unwrap_err()
            .0,
            "studio_layout_ref_invalid"
        );
        assert_eq!(
            validated_layout_ref(&json!({ "layout_ref": 3 }))
                .unwrap_err()
                .0,
            "studio_field_type_invalid"
        );
        assert!(matches!(
            validated_layout_ref(&json!({ "layout_ref": null })).unwrap(),
            LayoutRefEdit::Clear
        ));
        assert!(matches!(
            validated_layout_ref(&json!({})).unwrap(),
            LayoutRefEdit::Unchanged
        ));
        assert!(matches!(
            validated_layout_ref(&json!({ "layout_ref": "artifact://layouts/a1" })).unwrap(),
            LayoutRefEdit::Set(_)
        ));
    }

    /// A refusal must carry the status its class implies: an unauthenticated write answering 200,
    /// or a CAS conflict answering 400, is the failure mode the shared foundation exists to remove.
    #[test]
    fn blueprint_refusals_carry_their_class_status() {
        use super::super::substrate_store::RequestScopeRefusal;
        assert_eq!(
            studio_scope_refusal(RequestScopeRefusal::AuthenticationRequired).0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            studio_scope_refusal(RequestScopeRefusal::ResourceOwnerMismatch).0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            studio_mutation_refusal(
                super::super::mutation_event_foundation::MutationRefusal::IdempotencyKeyInvalid
            )
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            studio_mutation_refusal(
                super::super::mutation_event_foundation::MutationRefusal::GenesisExpectedHeadPresent
            )
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}
