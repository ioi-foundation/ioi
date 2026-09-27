//! Change sets (ADR 0056 Amendment 1, plane 4) — `ChangeSet`
//! (docs/architecture/foundations/objects/bounded-improvement.md §ChangeSetEnvelope).
//!
//! A change set is canon's patch branch for a Hypervisor object family: an isolated draft space over
//! one family's head, merged only by that family's own admission. Nobody mutates a family's head
//! directly. A change set pins the head it was opened against (none, when it founds the family),
//! carries an append-only chain of draft bodies shaped as the subject's admission request, validates
//! a draft by running that admission's own checks without persisting, and merges by admitting the
//! draft through the subject's route with the pinned head as the expected head. If the head moved
//! the merge is refused (`change_set_base_moved`) — never a silent rebase. The merge decision is
//! recorded as a `BranchMergePlan`.
//!
//! One change set is ONE Agentgres chain: every transition compare-and-swaps its admitted head, so
//! two concurrent drafts cannot take the same ordinal and a merge cannot race a new draft. Every
//! write is identity-first and owner-scoped through the shared mutation foundation. Nothing here
//! grants anything; a draft is not an admitted revision.
//!
//! First subject kind: `data_recipe` (the Pipeline Builder's drafts). A subject is one adapter:
//! its tip (current revision and head), its draft validation (admission's content checks) and its
//! merge (admission itself).

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, mutation_refusal_reply, replay_stable_id, require_write_caller,
    scope_refusal_reply, stream_tail, MutationCommit, MutationRefusal, WriteCaller,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const NAMESPACE: &str = "hypervisor-change-sets";
/// The chain resource kind (one stream per change set) and the projection's record directory.
const KIND: &str = "change-sets";
const PLAN_KIND: &str = "branch-merge-plans";
const SCHEMA: &str = "ioi.change-set.v1";
const CONTRACT: &str = "schema://ioi/foundations/objects/change-set/v1";
const PLAN_CONTRACT: &str = "schema://ioi/components/agentgres/branch-merge-plan/v1";
const SUBJECT_KINDS: &[&str] = &["data_recipe"];
const MAX_DRAFT_BYTES: usize = 65_536;

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// Keys sorted at every depth, so a body hashes the same however its keys were ordered.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (key, inner) in sorted {
                out.insert(key.clone(), canonical(inner));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn body_hash(body: &Value) -> String {
    let bytes = serde_json::to_vec(&canonical(body)).unwrap_or_default();
    format!("sha256:{:x}", Sha256::digest(&bytes))
}

fn validate(contract: &str, what: &str, record: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, record,
    )
    .map_err(|error| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "change_set_contract_invalid",
            format!("the {what} would not satisfy its registered contract: {error}"),
        )
    })
}

fn persist(kind: &str, data_dir: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "change_set_persistence_failed",
            "the write is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

/// `cs_<16hex>` from a bare id or a `change://` ref.
fn change_set_id(raw: &str) -> Option<String> {
    let id = raw.trim().trim_start_matches("change://");
    let hex = id.strip_prefix("cs_")?;
    (hex.len() == 16
        && hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
    .then(|| id.to_string())
}

fn load(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, KIND)
        .into_iter()
        .find(|record| record["change_set_ref"].as_str() == Some(format!("change://{id}").as_str()))
}

fn chain_head(data_dir: &str, change_set_ref: &str) -> Result<Option<String>, Reply> {
    super::substrate_store::read_event_stream_operation(
        data_dir,
        NAMESPACE,
        &stream_tail(KIND, change_set_ref),
    )
    .map(|projection| projection.map(|p| p.head))
    .map_err(|error| mutation_refusal_reply(MutationRefusal::Admission(error)))
}

/// The caller's change set at `raw_id`, with its chain head (the expected head of the next write).
fn owned(
    st: &DaemonState,
    caller: &WriteCaller,
    raw_id: &str,
) -> Result<(String, Value, String), Reply> {
    let not_found = || {
        bad(
            StatusCode::NOT_FOUND,
            "change_set_not_found",
            "no change set exists at this id",
        )
    };
    let id = change_set_id(raw_id).ok_or_else(not_found)?;
    let record = load(&st.data_dir, &id).ok_or_else(not_found)?;
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    let head = chain_head(&st.data_dir, text(&record, "change_set_ref"))?.ok_or_else(|| {
        bad(
            StatusCode::CONFLICT,
            "change_set_head_missing",
            "this change set has no admitted head; it cannot take a transition without one",
        )
    })?;
    Ok((id, record, head))
}

fn status_of(record: &Value) -> &str {
    record["status"].as_str().unwrap_or("")
}

fn refuse_transition(record: &Value, action: &str) -> Reply {
    bad(
        StatusCode::CONFLICT,
        "change_set_transition_refused",
        format!("a {} change set cannot be {action}", status_of(record)),
    )
}

/// The subject's family token and the draft body with its family pinned to the subject's.
fn pinned_draft(record_family: &str, draft: &Value) -> Result<Value, Reply> {
    let Value::Object(map) = draft else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "change_set_draft_invalid",
            "a draft is the subject's admission request, as an object",
        ));
    };
    if serde_json::to_vec(draft)
        .map(|b| b.len())
        .unwrap_or(usize::MAX)
        > MAX_DRAFT_BYTES
    {
        return Err(bad(
            StatusCode::PAYLOAD_TOO_LARGE,
            "change_set_draft_too_large",
            format!("a draft is at most {MAX_DRAFT_BYTES} bytes"),
        ));
    }
    let family = map
        .get("family")
        .and_then(Value::as_str)
        .unwrap_or(record_family);
    if family != record_family {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "change_set_draft_family_mismatch",
            format!("this change set drafts data-recipe://{record_family}; a draft for {family} belongs to another change set"),
        ));
    }
    // Admission-owned fields are the merge's to supply, never the draft's.
    for minted in [
        "owner_ref",
        "idempotency_key",
        "expected_head",
        "revision_ref",
        "data_recipe_id",
    ] {
        if map.contains_key(minted) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_draft_field_minted",
                format!("{minted} is supplied at merge, never drafted"),
            ));
        }
    }
    let mut pinned = map.clone();
    pinned.insert("family".into(), json!(record_family));
    Ok(Value::Object(pinned))
}

fn family_of(record: &Value) -> String {
    text(&record["subject"], "family_ref")
        .trim_start_matches("data-recipe://")
        .to_string()
}

fn reply(status: StatusCode, commit: &MutationCommit, record: &Value) -> Reply {
    (
        status,
        Json(
            json!({ "ok": true, "replayed": commit.replayed, "change_set": record, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

/// Admit one transition on the change set's chain and persist the updated projection.
fn transition(
    st: &DaemonState,
    caller: &WriteCaller,
    id: &str,
    head: &str,
    op_kind: &str,
    payload: Value,
    mut record: Value,
) -> Result<(MutationCommit, Value), Reply> {
    let change_set_ref = format!("change://{id}");
    record["updated_at"] = json!(iso_now());
    record["admitted_head"] = json!("pending");
    validate(CONTRACT, "change set", &record)?;
    let commit = admit_owner_scoped_write(
        &st.data_dir,
        caller,
        NAMESPACE,
        KIND,
        &change_set_ref,
        op_kind,
        Some(head),
        &payload,
    )?;
    if commit.replayed {
        if let Some(existing) = load(&st.data_dir, id) {
            return Ok((commit, existing));
        }
    }
    record["admitted_head"] = json!(commit.projection.head);
    persist(KIND, &st.data_dir, id, &record)?;
    Ok((commit, record))
}

/// POST /v1/hypervisor/change-sets — open a change set over one family, pinned to its current head
/// (or founding it), optionally with a first draft.
pub(crate) async fn handle_change_set_open(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let subject = &body["subject"];
    let kind = text(subject, "kind");
    if !SUBJECT_KINDS.contains(&kind) {
        return bad(
            StatusCode::BAD_REQUEST,
            "change_set_subject_unsupported",
            format!("a change set's subject kind is one of {SUBJECT_KINDS:?}"),
        );
    }
    let family = text(subject, "family").to_string();
    let tip = match super::data_transformation_routes::data_recipe_tip(
        &st.data_dir,
        &caller.identity,
        &family,
    ) {
        Ok(tip) => tip,
        Err(response) => return response,
    };
    let title = text(&body, "title").to_string();
    if title.is_empty() || title.chars().count() > 200 {
        return bad(
            StatusCode::BAD_REQUEST,
            "change_set_title_required",
            "a change set has a title of at most 200 characters",
        );
    }
    let description = text(&body, "description").to_string();
    if description.chars().count() > 4000 {
        return bad(
            StatusCode::BAD_REQUEST,
            "change_set_description_too_long",
            "a description is at most 4000 characters",
        );
    }
    let id = replay_stable_id("cs", &caller.owner_ref, &caller.idempotency_key);
    let change_set_ref = format!("change://{id}");
    if let Some(existing) = load(&st.data_dir, &id) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "change_set": existing })),
        );
    }
    let now = iso_now();
    let author = caller.identity.principal_ref.clone();
    let mut drafts = Vec::new();
    if let Some(draft) = body.get("draft").filter(|d| !d.is_null()) {
        let pinned = match pinned_draft(&family, draft) {
            Ok(pinned) => pinned,
            Err(response) => return response,
        };
        drafts.push(json!({ "ordinal": 1, "body_hash": body_hash(&pinned), "body": pinned, "author_principal_ref": author, "drafted_at": now }));
    }
    let (base_revision_ref, base_head_ref) = match tip {
        Some((revision, head)) => (json!(revision), json!(head)),
        None => (Value::Null, Value::Null),
    };
    let mut record = json!({
        "schema_version": SCHEMA,
        "change_set_ref": change_set_ref,
        "owner_ref": caller.owner_ref,
        "author_principal_ref": author,
        "subject": { "kind": kind, "family_ref": format!("data-recipe://{family}"), "base_revision_ref": base_revision_ref, "base_head_ref": base_head_ref },
        "title": title,
        "description": description,
        "drafts": drafts,
        "status": "open",
        "validation": Value::Null,
        "merge": Value::Null,
        "decision_note": Value::Null,
        "created_at": now,
        "updated_at": now,
        "admitted_head": "pending",
        "authority_nonclaim": "change_set_grants_no_authority",
        "truth_nonclaim": "a_draft_is_not_an_admitted_revision",
    });
    if let Err(response) = validate(CONTRACT, "change set", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND,
        &change_set_ref,
        "change_set.open",
        None,
        &json!({ "change_set_ref": change_set_ref, "subject": record["subject"], "title": record["title"], "draft_count": record["drafts"].as_array().map_or(0, Vec::len) }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    record["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = persist(KIND, &st.data_dir, &id, &record) {
        return response;
    }
    reply(StatusCode::CREATED, &commit, &record)
}

/// POST /v1/hypervisor/change-sets/:id/drafts — append a draft. A proposed change set returns to open.
pub(crate) async fn handle_change_set_draft(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (id, mut record, head) = match owned(&st, &caller, &raw_id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    if !matches!(status_of(&record), "open" | "proposed") {
        return refuse_transition(&record, "drafted");
    }
    let pinned = match pinned_draft(&family_of(&record), &body["draft"]) {
        Ok(pinned) => pinned,
        Err(response) => return response,
    };
    let ordinal = record["drafts"].as_array().map_or(0, Vec::len) + 1;
    let hash = body_hash(&pinned);
    if let Some(drafts) = record["drafts"].as_array_mut() {
        drafts.push(json!({ "ordinal": ordinal, "body_hash": hash, "body": pinned, "author_principal_ref": caller.identity.principal_ref, "drafted_at": iso_now() }));
    }
    record["status"] = json!("open");
    match transition(
        &st,
        &caller,
        &id,
        &head,
        "change_set.draft",
        json!({ "draft_ordinal": ordinal, "body_hash": hash }),
        record,
    ) {
        Ok((commit, record)) => reply(StatusCode::CREATED, &commit, &record),
        Err(response) => response,
    }
}

/// The latest draft, or a refusal naming that there is none.
fn latest_draft(record: &Value) -> Result<Value, Reply> {
    record["drafts"]
        .as_array()
        .and_then(|drafts| drafts.last().cloned())
        .ok_or_else(|| {
            bad(
                StatusCode::CONFLICT,
                "change_set_draft_required",
                "this change set has no draft yet",
            )
        })
}

/// POST /v1/hypervisor/change-sets/:id/validate — run the subject admission's own checks against the
/// latest draft, without persisting it; the outcome is recorded on the change set.
pub(crate) async fn handle_change_set_validate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (id, mut record, head) = match owned(&st, &caller, &raw_id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    if !matches!(status_of(&record), "open" | "proposed") {
        return refuse_transition(&record, "validated");
    }
    let draft = match latest_draft(&record) {
        Ok(draft) => draft,
        Err(response) => return response,
    };
    let outcome = super::data_transformation_routes::validate_data_recipe_draft(
        &st,
        &caller.identity,
        &draft["body"],
    );
    let findings = match &outcome {
        Ok(_) => Vec::new(),
        Err((code, message)) => vec![json!({ "code": code, "message": message })],
    };
    record["validation"] = json!({
        "draft_ordinal": draft["ordinal"],
        "body_hash": draft["body_hash"],
        "outcome": if outcome.is_ok() { "valid" } else { "invalid" },
        "findings": findings,
        "validated_at": iso_now(),
    });
    let payload = json!({ "draft_ordinal": draft["ordinal"], "body_hash": draft["body_hash"], "outcome": record["validation"]["outcome"] });
    match transition(
        &st,
        &caller,
        &id,
        &head,
        "change_set.validate",
        payload,
        record,
    ) {
        Ok((commit, record)) => reply(StatusCode::OK, &commit, &record),
        Err(response) => response,
    }
}

/// POST /v1/hypervisor/change-sets/:id/propose — ready for review: open → proposed.
pub(crate) async fn handle_change_set_propose(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (id, mut record, head) = match owned(&st, &caller, &raw_id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    if status_of(&record) != "open" {
        return refuse_transition(&record, "proposed");
    }
    if let Err(response) = latest_draft(&record) {
        return response;
    }
    record["status"] = json!("proposed");
    match transition(
        &st,
        &caller,
        &id,
        &head,
        "change_set.propose",
        json!({ "status": "proposed" }),
        record,
    ) {
        Ok((commit, record)) => reply(StatusCode::OK, &commit, &record),
        Err(response) => response,
    }
}

/// POST /v1/hypervisor/change-sets/:id/reject and /abandon — terminal, with a note.
async fn close(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    raw_id: String,
    body: Value,
    to: &str,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (id, mut record, head) = match owned(&st, &caller, &raw_id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let allowed = match to {
        "rejected" => status_of(&record) == "proposed",
        _ => matches!(status_of(&record), "open" | "proposed"),
    };
    if !allowed {
        return refuse_transition(
            &record,
            if to == "rejected" {
                "rejected"
            } else {
                "abandoned"
            },
        );
    }
    let note = text(&body, "note").to_string();
    if note.chars().count() > 2000 {
        return bad(
            StatusCode::BAD_REQUEST,
            "change_set_note_too_long",
            "a note is at most 2000 characters",
        );
    }
    if to == "rejected" && note.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "change_set_rejection_note_required",
            "a rejection says why",
        );
    }
    record["status"] = json!(to);
    record["decision_note"] = if note.is_empty() {
        Value::Null
    } else {
        json!(note)
    };
    let op = if to == "rejected" {
        "change_set.reject"
    } else {
        "change_set.abandon"
    };
    match transition(
        &st,
        &caller,
        &id,
        &head,
        op,
        json!({ "status": to }),
        record,
    ) {
        Ok((commit, record)) => reply(StatusCode::OK, &commit, &record),
        Err(response) => response,
    }
}

pub(crate) async fn handle_change_set_reject(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    close(st, headers, raw_id, body, "rejected").await
}

pub(crate) async fn handle_change_set_abandon(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    close(st, headers, raw_id, body, "abandoned").await
}

/// POST /v1/hypervisor/change-sets/:id/merge — admit the latest draft through the subject's own
/// admission with the pinned head as its expected head, and record the decision as a BranchMergePlan.
/// Refused unless the change set is proposed, its latest draft validated `valid`, and the family's
/// head is still the one it was opened against.
pub(crate) async fn handle_change_set_merge(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (id, mut record, head) = match owned(&st, &caller, &raw_id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    if status_of(&record) != "proposed" {
        return refuse_transition(&record, "merged");
    }
    let draft = match latest_draft(&record) {
        Ok(draft) => draft,
        Err(response) => return response,
    };
    let validation = &record["validation"];
    if validation["outcome"].as_str() != Some("valid")
        || validation["body_hash"] != draft["body_hash"]
    {
        return bad(
            StatusCode::CONFLICT,
            "change_set_unvalidated",
            "the latest draft has not validated valid; validate it before merging",
        );
    }
    let family = family_of(&record);
    let tip = match super::data_transformation_routes::data_recipe_tip(
        &st.data_dir,
        &caller.identity,
        &family,
    ) {
        Ok(tip) => tip,
        Err(response) => return response,
    };
    let base_head = record["subject"]["base_head_ref"]
        .as_str()
        .map(str::to_string);
    let current_head = tip.as_ref().map(|(_, head)| head.clone());
    if current_head != base_head {
        return bad(
            StatusCode::CONFLICT,
            "change_set_base_moved",
            format!(
                "data-recipe://{family} moved since this change set was opened (pinned {}, now {}); open a successor change set on the new head",
                base_head.as_deref().unwrap_or("no revision"),
                current_head.as_deref().unwrap_or("no revision")
            ),
        );
    }
    let ordinal = draft["ordinal"].as_u64().unwrap_or(0);
    let mut admission = draft["body"].clone();
    admission["owner_ref"] = json!(record["owner_ref"]);
    admission["idempotency_key"] = json!(format!("change-set-merge-{id}-{ordinal}"));
    admission["expected_head"] = base_head.clone().map_or(Value::Null, Value::String);
    let (status, Json(admitted)) = super::data_transformation_routes::handle_data_recipe_admit(
        State(st.clone()),
        headers.clone(),
        Json(admission),
    )
    .await;
    if admitted["ok"].as_bool() != Some(true) {
        let code = admitted["code"]
            .as_str()
            .or_else(|| admitted["error"]["code"].as_str())
            .unwrap_or("unknown");
        let message = admitted["message"]
            .as_str()
            .or_else(|| admitted["error"]["message"].as_str())
            .unwrap_or("");
        return bad(
            if status.is_client_error() {
                status
            } else {
                StatusCode::CONFLICT
            },
            "change_set_merge_refused",
            format!("the subject's admission refused the draft ({code}): {message}"),
        );
    }
    let resulting_revision_ref = text(&admitted["data_recipe"], "revision_ref").to_string();
    let resulting_head = text(&admitted, "expected_head_for_successor").to_string();
    let plan_hash = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\u{0}{ordinal}",
                record["change_set_ref"].as_str().unwrap_or("")
            )
            .as_bytes()
        )
    );
    let plan_ref = format!("branch-merge://{plan_hash}");
    let now = iso_now();
    let plan = json!({
        "schema_version": "ioi.agentgres.branch-merge-plan.v1",
        "object_class": "BranchMergePlan",
        "branch_merge_ref": plan_ref,
        "target_branch_ref": format!("execution-branch://data-recipe/{family}/main"),
        "candidate_branch_refs": [format!("execution-branch://change-set/{id}")],
        "diff_refs": [format!("change://{id}/draft/{ordinal}")],
        "memory_diff_refs": [],
        "authority_diff_refs": [],
        "receipt_diff_refs": [admitted["receipt_ref"].as_str().unwrap_or("receipt://unknown")],
        "verification_refs": [format!("gate://change-set/{id}/validation/{ordinal}")],
        "admission_policy_ref": "policy://change-set/exact-head-merge",
        "expected_head_ref": format!("branch-checkpoint://data-recipe/{family}/{}", base_head.as_deref().unwrap_or("genesis")),
        "authority_revalidation": { "revocation_epoch_checked": "epoch:current", "revalidated_at": now, "stale_or_revoked_effects": [] },
        "decision": "admit",
        "decision_receipt_ref": admitted["receipt_ref"],
        "status": "admitted",
        "resulting_main_head": resulting_head,
        "staged_effect_count": 1,
    });
    if let Err(response) = validate(PLAN_CONTRACT, "branch merge plan", &plan) {
        return response;
    }
    if let Err(response) = persist(PLAN_KIND, &st.data_dir, &plan_hash, &plan) {
        return response;
    }
    record["status"] = json!("merged");
    record["merge"] = json!({
        "draft_ordinal": ordinal,
        "resulting_revision_ref": resulting_revision_ref,
        "resulting_head_ref": resulting_head,
        "branch_merge_plan_ref": plan_ref,
        "merged_by_principal_ref": caller.identity.principal_ref,
        "merged_at": now,
    });
    let payload = json!({ "draft_ordinal": ordinal, "resulting_revision_ref": record["merge"]["resulting_revision_ref"], "branch_merge_plan_ref": plan_ref });
    match transition(
        &st,
        &caller,
        &id,
        &head,
        "change_set.merge",
        payload,
        record,
    ) {
        Ok((commit, record)) => (
            StatusCode::OK,
            Json(
                json!({ "ok": true, "replayed": commit.replayed, "change_set": record, "branch_merge_plan": plan, "data_recipe": admitted["data_recipe"], "receipt_ref": commit.receipt_ref }),
            ),
        ),
        Err(response) => response,
    }
}

/// Every change set the caller's tenants own, newest first.
pub(crate) fn change_sets_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut records: Vec<Value> = read_record_dir(&st.data_dir, KIND)
        .into_iter()
        .filter(|r| {
            r["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .collect();
    records.sort_by(|a, b| text(b, "created_at").cmp(text(a, "created_at")));
    Ok(records)
}

/// GET /v1/hypervisor/change-sets[?family=…&status=…]
pub(crate) async fn handle_change_set_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let records = match change_sets_for_request(&st, &headers) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let family = query
        .get("family")
        .map(|f| format!("data-recipe://{}", f.trim_start_matches("data-recipe://")));
    let status = query.get("status");
    let filtered: Vec<Value> = records
        .into_iter()
        .filter(|r| {
            family
                .as_ref()
                .is_none_or(|f| text(&r["subject"], "family_ref") == f)
        })
        .filter(|r| status.is_none_or(|s| status_of(r) == s))
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "change_sets": filtered })),
    )
}

/// GET /v1/hypervisor/change-sets/:id — the change set, and its merge plan when merged.
pub(crate) async fn handle_change_set_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(raw_id): AxumPath<String>,
) -> Reply {
    let records = match change_sets_for_request(&st, &headers) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let Some(id) = change_set_id(&raw_id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "change_set_not_found",
            "no change set exists at this id",
        );
    };
    let Some(record) = records
        .into_iter()
        .find(|r| text(r, "change_set_ref") == format!("change://{id}"))
    else {
        return bad(
            StatusCode::NOT_FOUND,
            "change_set_not_found",
            "no change set exists at this id",
        );
    };
    let plan = record["merge"]["branch_merge_plan_ref"]
        .as_str()
        .and_then(|plan_ref| {
            let hash = plan_ref.trim_start_matches("branch-merge://");
            read_record_dir(&st.data_dir, PLAN_KIND)
                .into_iter()
                .find(|p| text(p, "branch_merge_ref") == format!("branch-merge://{hash}"))
        })
        .unwrap_or(Value::Null);
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "change_set": record, "branch_merge_plan": plan })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_hashes_the_same_however_its_keys_are_ordered() {
        let a =
            json!({ "family": "acme.orders", "steps": ["extract"], "nested": { "b": 1, "a": 2 } });
        let b =
            json!({ "nested": { "a": 2, "b": 1 }, "steps": ["extract"], "family": "acme.orders" });
        assert_eq!(body_hash(&a), body_hash(&b));
        assert_ne!(
            body_hash(&a),
            body_hash(&json!({ "family": "acme.orders" }))
        );
    }

    #[test]
    fn a_change_set_id_is_cs_and_sixteen_lowercase_hex() {
        assert_eq!(
            change_set_id("change://cs_0123456789abcdef").as_deref(),
            Some("cs_0123456789abcdef")
        );
        assert_eq!(
            change_set_id("cs_0123456789abcdef").as_deref(),
            Some("cs_0123456789abcdef")
        );
        assert!(change_set_id("cs_0123456789ABCDEF").is_none());
        assert!(change_set_id("fn_0123456789abcdef").is_none());
        assert!(change_set_id("cs_0123").is_none());
    }

    #[test]
    fn a_draft_is_pinned_to_its_family_and_never_carries_admission_fields() {
        let pinned = pinned_draft("acme.orders", &json!({ "name": "Orders" })).unwrap();
        assert_eq!(pinned["family"], "acme.orders");
        assert!(pinned_draft("acme.orders", &json!({ "family": "other.family" })).is_err());
        for minted in [
            "owner_ref",
            "idempotency_key",
            "expected_head",
            "revision_ref",
        ] {
            assert!(
                pinned_draft("acme.orders", &json!({ minted: "x" })).is_err(),
                "{minted}"
            );
        }
        assert!(pinned_draft("acme.orders", &json!(["not", "an", "object"])).is_err());
    }
}
