//! Governance / Leases & Limits checkpoints (ADR 0056 Amendment 1, plane 5) —
//! `JustificationCheckpoint` and `JustificationRecord`
//! (docs/architecture/components/hypervisor/identity-access-and-metering.md §Justification
//! checkpoints, §Justification records).
//!
//! A checkpoint puts a JUSTIFICATION OBLIGATION in front of a closed set of interactions a person
//! performs inside one owner tenant. It adds an obligation and never grants anything: it is not an
//! approval, and a justification never widens what the caller may do. `checkpoint_gate` is what the
//! gated routes call once their own checks would pass: no matching checkpoint → proceed; a matching
//! one without a satisfying justification → 428 `justification_required` carrying each prompt; a
//! satisfying one → one immutable record per checkpoint, admitted through the owner-scoped write
//! foundation BEFORE the interaction runs, whose refs the route echoes.
//!
//! Only an interaction the daemon gates is in the catalog, so a checkpoint can never be configured
//! that never fires. The daemon's own dispatch (a scheduled or webhook run) is not a person and is
//! never prompted: callers only gate the human path.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::substrate_store::RequestIdentity;
use super::{persist_record, read_record_dir, DaemonState};

const NAMESPACE: &str = "hypervisor-justification-checkpoints";
const KIND_CHECKPOINT: &str = "justification-checkpoints";
const KIND_RECORD: &str = "justification-records";
const CHECKPOINT_SCHEMA: &str = "ioi.hypervisor.justification_checkpoint.v1";
const RECORD_SCHEMA: &str = "ioi.hypervisor.justification_record.v1";
const CHECKPOINT_CONTRACT: &str = "schema://ioi/components/hypervisor/justification-checkpoint/v1";
const RECORD_CONTRACT: &str = "schema://ioi/components/hypervisor/justification-record/v1";
/// THE CATALOG — every entry is an interaction a route gates through `checkpoint_gate`.
pub(crate) const CATALOG: &[&str] = &[
    "automation.run_now",
    "support_incident.file",
    "health_check.declare",
];
const JUSTIFICATION_KINDS: &[&str] = &["acknowledgment", "response", "dropdown"];
const FREE_TEXT: &[&str] = &["none", "optional", "required"];
const ENABLEMENTS: &[&str] = &["enabled", "paused", "archived"];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}

fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

fn strings(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn is_ref(value: &str) -> bool {
    value.split_once("://").is_some_and(|(scheme, tail)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            && !tail.is_empty()
    }) && value.len() <= 500
        && !value.chars().any(char::is_whitespace)
}

fn validate(contract: &str, what: &str, record: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, record,
    )
    .map_err(|error| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "justification_contract_invalid",
            format!("the {what} would not satisfy its registered contract: {error}"),
        )
    })
}

fn project(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

fn persist(data_dir: &str, kind: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "justification_persistence_failed",
            "the write is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

/// A response pattern compiles within a bounded size (the engine is linear-time, so an
/// administrator's pattern cannot stall a request).
fn compiled(pattern: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .map_err(|error| error.to_string())
}

/// The configuration's own fields, validated; `Err` names the first one that is wrong.
fn declared_fields(body: &Value) -> Result<Value, Reply> {
    let display_name = text(body, "display_name");
    if display_name.is_empty() || display_name.chars().count() > 160 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_name_required",
            "display_name is required and is 1..160 characters",
        ));
    }
    let description = text(body, "description");
    let kinds = strings(body, "interaction_kinds");
    if kinds.is_empty() || kinds.iter().any(|k| !CATALOG.contains(&k.as_str())) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_interaction_invalid",
            format!(
                "interaction_kinds names one or more interactions the daemon gates: {CATALOG:?}"
            ),
        ));
    }
    let mut kinds = kinds;
    kinds.sort();
    kinds.dedup();
    let conditions = body.get("conditions").cloned().unwrap_or(Value::Null);
    let mut item_refs = strings(&conditions, "item_refs");
    let mut exempt = strings(&conditions, "exempt_principal_refs");
    item_refs.sort();
    item_refs.dedup();
    exempt.sort();
    exempt.dedup();
    if item_refs.len() > 50 || item_refs.iter().any(|r| !is_ref(r)) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_condition_invalid",
            "conditions.item_refs names at most 50 object references (scheme://…)",
        ));
    }
    if exempt.len() > 50
        || exempt
            .iter()
            .any(|r| !r.starts_with("user://") || !is_ref(r))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_condition_invalid",
            "conditions.exempt_principal_refs names at most 50 people (user://…)",
        ));
    }
    let prompt = body.get("prompt").cloned().unwrap_or(Value::Null);
    let (title, prompt_body, prompt_description) = (
        text(&prompt, "title"),
        text(&prompt, "body"),
        text(&prompt, "description"),
    );
    if title.is_empty() || title.chars().count() > 45 || prompt_body.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_prompt_invalid",
            "the prompt needs a title of 1..45 characters and a body",
        ));
    }
    let spec = body.get("justification").cloned().unwrap_or(Value::Null);
    let kind = text(&spec, "kind");
    if !JUSTIFICATION_KINDS.contains(&kind) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_kind_invalid",
            format!("justification.kind must be one of {JUSTIFICATION_KINDS:?} (re-authentication waits for an identity step-up plane)"),
        ));
    }
    let pattern = text(&spec, "response_pattern");
    if kind == "response" && !pattern.is_empty() {
        if let Err(error) = compiled(pattern) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "justification_pattern_invalid",
                format!("justification.response_pattern does not compile: {error}"),
            ));
        }
    }
    let mut options = strings(&spec, "options");
    options.dedup();
    if kind == "dropdown" && options.is_empty() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_options_required",
            "a dropdown justification offers at least one reason",
        ));
    }
    let free_text = match text(&spec, "free_text") {
        "" => "none",
        value => value,
    };
    if !FREE_TEXT.contains(&free_text) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_free_text_invalid",
            format!("justification.free_text must be one of {FREE_TEXT:?}"),
        ));
    }
    let enablement = match text(body, "enablement") {
        "" => "enabled",
        value => value,
    };
    if !ENABLEMENTS.contains(&enablement) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_enablement_invalid",
            format!("enablement must be one of {ENABLEMENTS:?}"),
        ));
    }
    Ok(json!({
        "display_name": display_name,
        "description": description,
        "interaction_kinds": kinds,
        "conditions": { "item_refs": item_refs, "exempt_principal_refs": exempt },
        "prompt": { "title": title, "body": prompt_body, "description": prompt_description },
        "justification": {
            "kind": kind,
            "acknowledgment_text": if kind == "acknowledgment" { text(&spec, "acknowledgment_text") } else { "" },
            "response_pattern": if kind == "response" { pattern } else { "" },
            "options": if kind == "dropdown" { options } else { Vec::new() },
            "multiple": kind == "dropdown" && spec.get("multiple").and_then(Value::as_bool).unwrap_or(false),
            "free_text": if kind == "dropdown" { free_text } else { "none" },
        },
        "enablement": enablement,
    }))
}

/// POST /v1/hypervisor/justification-checkpoints — configure a checkpoint in the caller's tenant.
pub(crate) async fn handle_checkpoint_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let fields = match declared_fields(&body) {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    // A checkpoint applies inside the tenant that owns it: a scope elsewhere would put an
    // obligation on people this owner does not govern.
    let scope_ref = match text(&body, "scope_ref") {
        "" => caller.owner_ref.clone(),
        scope => scope.to_string(),
    };
    if scope_ref != caller.owner_ref {
        return bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_scope_invalid",
            "a checkpoint's scope is the tenant that owns it",
        );
    }
    let id = replay_stable_id("jc", &caller.owner_ref, &caller.idempotency_key);
    let checkpoint_ref = format!("justification-checkpoint://{id}");
    let now = super::iso_now();
    let mut record = json!({
        "schema_version": CHECKPOINT_SCHEMA,
        "checkpoint_id": checkpoint_ref,
        "scope_ref": scope_ref,
        "owner_ref": caller.owner_ref,
        "created_by_principal_ref": caller.identity.principal_ref,
        "created_at": now,
        "updated_at": now,
        "admitted_head": Value::Null,
    });
    for (key, value) in fields.as_object().into_iter().flatten() {
        record[key] = value.clone();
    }
    if let Err(response) = validate(CHECKPOINT_CONTRACT, "checkpoint", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_CHECKPOINT,
        &checkpoint_ref,
        "justification_checkpoint.configure",
        None,
        &json!({ "checkpoint_id": checkpoint_ref, "configuration": fields, "scope_ref": record["scope_ref"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        if let Some(existing) = load(&st.data_dir, KIND_CHECKPOINT, &id) {
            return (
                StatusCode::OK,
                Json(
                    json!({ "ok": true, "replayed": true, "checkpoint": existing, "receipt_ref": commit.receipt_ref }),
                ),
            );
        }
    }
    project(&mut record, &commit);
    if let Err(response) = persist(&st.data_dir, KIND_CHECKPOINT, &id, &record) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "replayed": false, "checkpoint": record, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

/// POST /v1/hypervisor/justification-checkpoints/:id/enablement {enablement} — pause, resume or
/// archive a checkpoint (compare-and-swap on its admitted head).
pub(crate) async fn handle_checkpoint_enablement(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let to = text(&body, "enablement");
    if !ENABLEMENTS.contains(&to) {
        return bad(
            StatusCode::BAD_REQUEST,
            "justification_checkpoint_enablement_invalid",
            format!("enablement must be one of {ENABLEMENTS:?}"),
        );
    }
    let Some(record) = load(&st.data_dir, KIND_CHECKPOINT, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "justification_checkpoint_not_found",
            "no checkpoint exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["enablement"].as_str() == Some(to) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "checkpoint": record })),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "justification_checkpoint_expected_head_required",
            "this checkpoint carries no admitted head; it cannot be changed without one",
        );
    };
    let checkpoint_ref = format!("justification-checkpoint://{id}");
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_CHECKPOINT,
        &checkpoint_ref,
        "justification_checkpoint.enablement",
        Some(&expected_head),
        &json!({ "checkpoint_id": checkpoint_ref, "enablement": to }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut successor = record;
    successor["enablement"] = json!(to);
    project(&mut successor, &commit);
    if let Err(response) = validate(CHECKPOINT_CONTRACT, "checkpoint", &successor) {
        return response;
    }
    if let Err(response) = persist(&st.data_dir, KIND_CHECKPOINT, &id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "replayed": commit.replayed, "checkpoint": successor, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

/// THE PUBLISHED READERS — what the caller's tenants may see, newest first. A record is also
/// readable by the person who submitted it.
pub(crate) fn checkpoints_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut checkpoints: Vec<Value> = read_record_dir(&st.data_dir, KIND_CHECKPOINT)
        .into_iter()
        .filter(|c| {
            c["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .collect();
    checkpoints.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    Ok(checkpoints)
}

pub(crate) fn records_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut records: Vec<Value> = read_record_dir(&st.data_dir, KIND_RECORD)
        .into_iter()
        .filter(|r| {
            r["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
                || text(r, "submitted_by_principal_ref") == identity.principal_ref
        })
        .collect();
    records.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    Ok(records)
}

/// GET /v1/hypervisor/justification-checkpoints
pub(crate) async fn handle_checkpoint_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    match checkpoints_for_request(&st, &headers) {
        Ok(checkpoints) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "checkpoints": checkpoints, "catalog": CATALOG })),
        ),
        Err(reply) => reply,
    }
}

/// GET /v1/hypervisor/justification-checkpoints/:id
pub(crate) async fn handle_checkpoint_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(record) = load(&st.data_dir, KIND_CHECKPOINT, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "justification_checkpoint_not_found",
            "no checkpoint exists at this id",
        );
    };
    if !record["owner_ref"]
        .as_str()
        .is_some_and(|owner| identity.authorizes_tenant(owner))
    {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "checkpoint": record })),
    )
}

/// GET /v1/hypervisor/justification-records[?checkpoint=&interaction=&kind=&submitted_by=]
pub(crate) async fn handle_record_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let records = match records_for_request(&st, &headers) {
        Ok(records) => records,
        Err(reply) => return reply,
    };
    let checkpoint = query.get("checkpoint").map(|id| {
        format!(
            "justification-checkpoint://{}",
            id.trim_start_matches("justification-checkpoint://")
        )
    });
    let wanted = |r: &Value, key: &str, value: Option<&String>| {
        value.is_none_or(|v| v.is_empty() || text(r, key) == v)
    };
    let records: Vec<Value> = records
        .into_iter()
        .filter(|r| {
            checkpoint
                .as_deref()
                .is_none_or(|c| text(r, "checkpoint_ref") == c)
        })
        .filter(|r| wanted(r, "interaction_ref", query.get("interaction")))
        .filter(|r| wanted(r, "interaction_kind", query.get("kind")))
        .filter(|r| wanted(r, "submitted_by_principal_ref", query.get("submitted_by")))
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "justification_records": records })),
    )
}

// ---- THE GATE ------------------------------------------------------------------------------------

/// The enabled checkpoints that put an obligation on THIS person doing THIS interaction on these
/// items: the kind is configured, the checkpoint's scope is one of the person's tenants, its item
/// condition is empty or names one of the items, and the person is not exempt.
fn matching(
    checkpoints: &[Value],
    identity: &RequestIdentity,
    kind: &str,
    item_refs: &[String],
) -> Vec<Value> {
    checkpoints
        .iter()
        .filter(|c| text(c, "enablement") == "enabled")
        .filter(|c| strings(c, "interaction_kinds").iter().any(|k| k == kind))
        .filter(|c| identity.authorizes_tenant(text(c, "scope_ref")))
        .filter(|c| {
            let items = strings(&c["conditions"], "item_refs");
            items.is_empty() || items.iter().any(|i| item_refs.contains(i))
        })
        .filter(|c| {
            !strings(&c["conditions"], "exempt_principal_refs").contains(&identity.principal_ref)
        })
        .cloned()
        .collect()
}

/// A given justification against the checkpoint's spec; `Err` says what is missing in the words
/// the prompt page shows.
fn judged(spec: &Value, given: &Value) -> Result<Value, String> {
    let kind = text(spec, "kind");
    let acknowledged = given
        .get("acknowledged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let answer = text(given, "text").chars().take(4000).collect::<String>();
    let selected = strings(given, "selected");
    match kind {
        "acknowledgment" => {
            if !acknowledged {
                return Err("tick the acknowledgment to continue".to_string());
            }
            Ok(json!({ "kind": kind, "acknowledged": true, "text": "", "selected": [] }))
        }
        "response" => {
            if answer.is_empty() {
                return Err("write a justification to continue".to_string());
            }
            let pattern = text(spec, "response_pattern");
            if !pattern.is_empty()
                && !compiled(pattern)
                    .map(|re| re.is_match(&answer))
                    .unwrap_or(false)
            {
                return Err(
                    "the justification does not take the form this checkpoint asks for".to_string(),
                );
            }
            Ok(json!({ "kind": kind, "acknowledged": false, "text": answer, "selected": [] }))
        }
        "dropdown" => {
            let options = strings(spec, "options");
            let multiple = spec
                .get("multiple")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if selected.is_empty() || selected.iter().any(|s| !options.contains(s)) {
                return Err("choose a reason this checkpoint offers".to_string());
            }
            if !multiple && selected.len() != 1 {
                return Err("choose exactly one reason".to_string());
            }
            let free_text = text(spec, "free_text");
            if free_text == "required" && answer.is_empty() {
                return Err("add the explanation this checkpoint requires".to_string());
            }
            let answer = if free_text == "none" {
                String::new()
            } else {
                answer
            };
            Ok(json!({ "kind": kind, "acknowledged": false, "text": answer, "selected": selected }))
        }
        _ => Err("this checkpoint's justification kind is not supported".to_string()),
    }
}

fn prompt_of(checkpoint: &Value, error: Option<&str>) -> Value {
    let spec = &checkpoint["justification"];
    json!({
        "checkpoint_ref": checkpoint["checkpoint_id"],
        "checkpoint_head": checkpoint["admitted_head"],
        "prompt": checkpoint["prompt"],
        "justification": {
            "kind": spec["kind"],
            "acknowledgment_text": spec["acknowledgment_text"],
            "has_pattern": !text(spec, "response_pattern").is_empty(),
            "options": spec["options"],
            "multiple": spec["multiple"],
            "free_text": spec["free_text"],
        },
        "error": error,
    })
}

fn fresh_interaction(kind: &str) -> String {
    format!("interaction://{kind}/{}", uuid::Uuid::new_v4())
}

fn interaction_of(body: &Value, kind: &str) -> String {
    let given = text(body, "interaction_ref");
    let prefix = format!("interaction://{kind}/");
    match given.strip_prefix(&prefix) {
        Some(tail) if uuid::Uuid::parse_str(tail).is_ok() && tail.len() == 36 => given.to_string(),
        _ => fresh_interaction(kind),
    }
}

/// THE OBLIGATION. Called by a gated route for a PERSON's interaction once its own checks would
/// pass. `Ok(record_refs)` means proceed (empty when no checkpoint applies); `Err` is the 428 prompt
/// (or a 409 when a checkpoint changed after it was shown) the caller must answer first.
pub(crate) fn checkpoint_gate(
    st: &DaemonState,
    headers: &HeaderMap,
    kind: &str,
    item_refs: &[String],
    body: &Value,
) -> Result<Vec<String>, Reply> {
    debug_assert!(
        CATALOG.contains(&kind),
        "a gated interaction is in the catalog"
    );
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        // No person, no prompt: the route's own identity check answers an anonymous caller.
        Err(_) => return Ok(Vec::new()),
    };
    let all = read_record_dir(&st.data_dir, KIND_CHECKPOINT);
    let applicable = matching(&all, &identity, kind, item_refs);
    if applicable.is_empty() {
        return Ok(Vec::new());
    }
    let interaction_ref = interaction_of(body, kind);
    let given: Vec<Value> = body
        .get("justifications")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut judged_all = Vec::new();
    let mut prompts = Vec::new();
    let mut changed = false;
    for checkpoint in &applicable {
        let reference = text(checkpoint, "checkpoint_id");
        let answer = given
            .iter()
            .find(|g| text(g, "checkpoint_ref") == reference);
        match answer {
            None => prompts.push(prompt_of(checkpoint, None)),
            Some(answer)
                if text(answer, "checkpoint_head") != text(checkpoint, "admitted_head") =>
            {
                changed = true;
                prompts.push(prompt_of(
                    checkpoint,
                    Some("this checkpoint changed after it was shown — read it again"),
                ));
            }
            Some(answer) => match judged(&checkpoint["justification"], answer) {
                Ok(justification) => judged_all.push((checkpoint.clone(), justification)),
                Err(error) => prompts.push(prompt_of(checkpoint, Some(&error))),
            },
        }
    }
    if !prompts.is_empty() {
        // Every applicable checkpoint is shown, answered or not, so one resubmission can satisfy all.
        let shown: Vec<Value> = applicable
            .iter()
            .map(|c| {
                prompts
                    .iter()
                    .find(|p| p["checkpoint_ref"] == c["checkpoint_id"])
                    .cloned()
                    .unwrap_or_else(|| prompt_of(c, None))
            })
            .collect();
        let (status, code, message) = if changed {
            (
                StatusCode::CONFLICT,
                "justification_checkpoint_changed",
                "a checkpoint changed after it was shown; answer it again",
            )
        } else {
            (
                StatusCode::PRECONDITION_REQUIRED,
                "justification_required",
                "this action needs a justification before it runs",
            )
        };
        return Err((
            status,
            Json(json!({
                "ok": false,
                "error": { "code": code, "message": message },
                "interaction_kind": kind,
                "interaction_ref": interaction_ref,
                "checkpointed_item_refs": item_refs,
                "checkpoints": shown,
            })),
        ));
    }
    let mut refs = Vec::new();
    for (checkpoint, justification) in judged_all {
        let owner_ref = text(&checkpoint, "owner_ref").to_string();
        let checkpoint_ref = text(&checkpoint, "checkpoint_id").to_string();
        let caller = WriteCaller {
            identity: identity.clone(),
            owner_ref: owner_ref.clone(),
            idempotency_key: format!("justification:{interaction_ref}|{checkpoint_ref}"),
        };
        let id = replay_stable_id("jr", &owner_ref, &caller.idempotency_key);
        let record_ref = format!("justification-record://{id}");
        if load(&st.data_dir, KIND_RECORD, &id).is_some() {
            refs.push(record_ref);
            continue;
        }
        let mut record = json!({
            "schema_version": RECORD_SCHEMA,
            "record_id": record_ref,
            "checkpoint_ref": checkpoint_ref,
            "checkpoint_head": checkpoint["admitted_head"],
            "interaction_kind": kind,
            "interaction_ref": interaction_ref,
            "checkpointed_item_refs": item_refs,
            "submitted_by_principal_ref": identity.principal_ref,
            "owner_ref": owner_ref,
            "language": checkpoint["prompt"],
            "justification": justification,
            "created_at": super::iso_now(),
            "admitted_head": Value::Null,
        });
        validate(RECORD_CONTRACT, "justification record", &record)?;
        let commit = admit_owner_scoped_write(
            &st.data_dir,
            &caller,
            NAMESPACE,
            KIND_RECORD,
            &record_ref,
            "justification_record.submit",
            None,
            &json!({ "record_id": record_ref, "checkpoint_ref": record["checkpoint_ref"], "checkpoint_head": record["checkpoint_head"], "interaction_ref": interaction_ref, "justification": record["justification"] }),
        )?;
        record["admitted_head"] = json!(commit.projection.head);
        persist(&st.data_dir, KIND_RECORD, &id, &record)?;
        refs.push(record_ref);
    }
    Ok(refs)
}

/// The obligation authority evaluation reports for an effect a checkpoint covers (read-only).
pub(crate) fn obligations_for(st: &DaemonState, headers: &HeaderMap, kind: &str) -> Vec<Value> {
    let Ok(identity) = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
    else {
        return Vec::new();
    };
    if !CATALOG.contains(&kind) {
        return Vec::new();
    }
    let all = read_record_dir(&st.data_dir, KIND_CHECKPOINT);
    let refs: Vec<Value> = all
        .iter()
        .filter(|c| text(c, "enablement") == "enabled")
        .filter(|c| strings(c, "interaction_kinds").iter().any(|k| k == kind))
        .filter(|c| identity.authorizes_tenant(text(c, "scope_ref")))
        .filter(|c| {
            !strings(&c["conditions"], "exempt_principal_refs").contains(&identity.principal_ref)
        })
        .map(|c| c["checkpoint_id"].clone())
        .collect();
    if refs.is_empty() {
        Vec::new()
    } else {
        vec![json!({ "kind": "justification", "checkpoint_refs": refs })]
    }
}

#[cfg(test)]
mod justification_checkpoint_tests {
    use super::*;

    fn identity(principal: &str, tenants: &[&str]) -> RequestIdentity {
        super::super::substrate_store::request_identity_for_test(
            principal,
            tenants.iter().map(|t| t.to_string()),
        )
    }

    fn checkpoint(kinds: &[&str], items: &[&str], exempt: &[&str], spec: Value) -> Value {
        json!({
            "checkpoint_id": "justification-checkpoint://jc_0123456789abcdef",
            "admitted_head": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "scope_ref": "org://acme",
            "owner_ref": "org://acme",
            "enablement": "enabled",
            "interaction_kinds": kinds,
            "conditions": { "item_refs": items, "exempt_principal_refs": exempt },
            "prompt": { "title": "Why?", "body": "Say why.", "description": "" },
            "justification": spec,
        })
    }

    fn response_spec(pattern: &str) -> Value {
        json!({ "kind": "response", "acknowledgment_text": "", "response_pattern": pattern, "options": [], "multiple": false, "free_text": "none" })
    }

    #[test]
    fn a_checkpoint_applies_only_to_its_kind_scope_items_and_unexempt_people() {
        let items = vec!["automation://auto_1".to_string()];
        let alice = identity("user://alice", &["org://acme"]);
        let outsider = identity("user://mallory", &["org://other"]);
        let all = vec![checkpoint(
            &["automation.run_now"],
            &[],
            &[],
            response_spec(""),
        )];
        assert_eq!(
            matching(&all, &alice, "automation.run_now", &items).len(),
            1
        );
        assert!(
            matching(&all, &alice, "support_incident.file", &items).is_empty(),
            "another interaction"
        );
        assert!(
            matching(&all, &outsider, "automation.run_now", &items).is_empty(),
            "outside its scope"
        );
        let narrowed = vec![checkpoint(
            &["automation.run_now"],
            &["automation://auto_2"],
            &[],
            response_spec(""),
        )];
        assert!(
            matching(&narrowed, &alice, "automation.run_now", &items).is_empty(),
            "another item"
        );
        let exempted = vec![checkpoint(
            &["automation.run_now"],
            &[],
            &["user://alice"],
            response_spec(""),
        )];
        assert!(
            matching(&exempted, &alice, "automation.run_now", &items).is_empty(),
            "exempt"
        );
        let mut paused = checkpoint(&["automation.run_now"], &[], &[], response_spec(""));
        paused["enablement"] = json!("paused");
        assert!(
            matching(&[paused], &alice, "automation.run_now", &items).is_empty(),
            "paused"
        );
    }

    #[test]
    fn a_justification_is_judged_by_the_kind_it_was_asked_in() {
        let ack = json!({ "kind": "acknowledgment", "acknowledgment_text": "I understand", "response_pattern": "", "options": [], "multiple": false, "free_text": "none" });
        assert!(judged(&ack, &json!({ "acknowledged": false })).is_err());
        assert_eq!(
            judged(&ack, &json!({ "acknowledged": true })).unwrap()["acknowledged"],
            true
        );
        let resp = response_spec("^TICKET-[0-9]+");
        assert!(judged(&resp, &json!({ "text": "" })).is_err(), "empty");
        assert!(
            judged(&resp, &json!({ "text": "because" })).is_err(),
            "pattern"
        );
        assert_eq!(
            judged(&resp, &json!({ "text": "TICKET-42 rerun" })).unwrap()["text"],
            "TICKET-42 rerun"
        );
        let drop = json!({ "kind": "dropdown", "acknowledgment_text": "", "response_pattern": "", "options": ["Incident", "Test"], "multiple": false, "free_text": "required" });
        assert!(
            judged(&drop, &json!({ "selected": ["Other"] })).is_err(),
            "not offered"
        );
        assert!(
            judged(&drop, &json!({ "selected": ["Incident", "Test"] })).is_err(),
            "one only"
        );
        assert!(
            judged(&drop, &json!({ "selected": ["Incident"] })).is_err(),
            "free text required"
        );
        let ok = judged(&drop, &json!({ "selected": ["Incident"], "text": "INC-7" })).unwrap();
        assert_eq!(ok["selected"], json!(["Incident"]));
    }

    #[test]
    fn a_declaration_names_catalog_interactions_a_prompt_and_a_real_justification() {
        let ok = json!({ "display_name": "Run now needs a reason", "interaction_kinds": ["automation.run_now"], "prompt": { "title": "Why run this now?", "body": "Say why." }, "justification": { "kind": "response", "response_pattern": "^.{5,}$" } });
        let fields = declared_fields(&ok).expect("valid");
        assert_eq!(fields["justification"]["free_text"], "none");
        let mut off_catalog = ok.clone();
        off_catalog["interaction_kinds"] = json!(["environment.delete"]);
        assert!(
            declared_fields(&off_catalog).is_err(),
            "not a gated interaction"
        );
        let mut long_title = ok.clone();
        long_title["prompt"]["title"] = json!("x".repeat(46));
        assert!(declared_fields(&long_title).is_err());
        let mut reauth = ok.clone();
        reauth["justification"]["kind"] = json!("reauthentication");
        assert!(declared_fields(&reauth).is_err(), "no step-up plane");
        let mut bad_pattern = ok;
        bad_pattern["justification"]["response_pattern"] = json!("(");
        assert!(declared_fields(&bad_pattern).is_err());
    }
}
