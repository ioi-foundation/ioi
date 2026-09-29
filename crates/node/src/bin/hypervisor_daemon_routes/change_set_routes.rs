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
//! The subject kinds are DATA — one table, `SUBJECT_KINDS` (master guide §0.5.3). A subject is one
//! adapter: its ref scheme, whether a change set may found it, the draft members its merge
//! supplies, its tip (current revision and head), its draft validation (admission's own checks)
//! and its merge (admission itself). Change-set v2 (R-240 journey WP-C2) carries two kinds:
//! `data_recipe` (the Pipeline Builder's drafts) and `blueprint` (a Studio blueprint, merged by its
//! own compare-and-swap PATCH). v2 also reserves `basis_refs`, the evidence a change is proposed
//! on; no basis is admitted until one resolves through its own reader. Every change set opened is
//! v2; a v1 record keeps reading and takes its remaining transitions as v1.

use std::future::Future;
use std::pin::Pin;
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
use super::substrate_store::RequestIdentity;
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const NAMESPACE: &str = "hypervisor-change-sets";
/// The chain resource kind (one stream per change set) and the projection's record directory.
const KIND: &str = "change-sets";
const PLAN_KIND: &str = "branch-merge-plans";
const SCHEMA: &str = "ioi.change-set.v2";
const CONTRACT: &str = "schema://ioi/foundations/objects/change-set/v2";
const SCHEMA_V1: &str = "ioi.change-set.v1";
const CONTRACT_V1: &str = "schema://ioi/foundations/objects/change-set/v1";
const PLAN_CONTRACT: &str = "schema://ioi/components/agentgres/branch-merge-plan/v1";
const MAX_DRAFT_BYTES: usize = 65_536;

type Reply = (StatusCode, Json<Value>);

// ------------------------------------ the subject kinds ------------------------------------------

/// A subject's tip as the caller reads it: (current revision, admitted head); None when a change
/// set would found the subject.
type Tip = Option<(String, String)>;
type MergeFuture = Pin<Box<dyn Future<Output = Reply> + Send>>;

/// What a merge hands the subject's own admission.
struct MergeRequest {
    token: String,
    owner_ref: String,
    idempotency_key: String,
    expected_head: Option<String>,
    body: Value,
}

/// One subject kind — the whole of what the change set knows about a family. Nothing outside this
/// table branches on a kind.
struct SubjectKind {
    kind: &'static str,
    /// The subject's ref scheme: `family_ref` is this prefix and the subject's token.
    ref_prefix: &'static str,
    /// Whether a change set may found a subject of this kind (open it with no tip).
    founds: bool,
    /// The draft member pinned to the subject's token, when the admission request names it.
    pinned_member: Option<&'static str>,
    /// Members only the merge supplies — never drafted.
    minted: &'static [&'static str],
    /// The closed set of members a draft may carry, when the subject's request is closed.
    authored: Option<&'static [&'static str]>,
    tip: fn(&DaemonState, &WriteCaller, &str) -> Result<Tip, Reply>,
    /// The subject admission's own checks against a pinned draft, without persisting.
    validate: fn(&DaemonState, &RequestIdentity, &str, &Value) -> Result<String, (String, String)>,
    /// The subject admission itself.
    merge: fn(Arc<DaemonState>, HeaderMap, MergeRequest) -> MergeFuture,
    /// (resulting revision, resulting head) off the admission's reply.
    merged: fn(&Value) -> (String, String),
    /// The admission reply's member that carries the admitted subject.
    reply_key: &'static str,
}

const SUBJECT_KINDS: &[SubjectKind] = &[
    SubjectKind {
        kind: "data_recipe",
        ref_prefix: "data-recipe://",
        founds: true,
        pinned_member: Some("family"),
        minted: &[
            "owner_ref",
            "idempotency_key",
            "expected_head",
            "revision_ref",
            "data_recipe_id",
        ],
        authored: None,
        tip: |st, caller, family| {
            super::data_transformation_routes::data_recipe_tip(
                &st.data_dir,
                &caller.identity,
                family,
            )
        },
        validate: |st, identity, _family, body| {
            super::data_transformation_routes::validate_data_recipe_draft(st, identity, body)
        },
        merge: merge_data_recipe,
        merged: |admitted| {
            (
                text(&admitted["data_recipe"], "revision_ref").to_string(),
                text(admitted, "expected_head_for_successor").to_string(),
            )
        },
        reply_key: "data_recipe",
    },
    SubjectKind {
        kind: "blueprint",
        ref_prefix: "blueprint://",
        founds: false,
        pinned_member: None,
        minted: &["owner_ref", "idempotency_key", "expected_head"],
        authored: Some(super::studio_routes::BLUEPRINT_AUTHORED_MEMBERS),
        tip: blueprint_tip,
        validate: |st, identity, id, body| {
            super::studio_routes::validate_blueprint_draft(&st.data_dir, identity, id, body)
        },
        merge: merge_blueprint,
        merged: |admitted| {
            (
                text(&admitted["blueprint"], "content_hash").to_string(),
                text(admitted, "admitted_head").to_string(),
            )
        },
        reply_key: "blueprint",
    },
];

fn subject_kind(kind: &str) -> Option<&'static SubjectKind> {
    SUBJECT_KINDS.iter().find(|subject| subject.kind == kind)
}

fn unsupported_kind() -> Reply {
    let kinds: Vec<&str> = SUBJECT_KINDS.iter().map(|subject| subject.kind).collect();
    bad(
        StatusCode::BAD_REQUEST,
        "change_set_subject_unsupported",
        format!("a change set's subject kind is one of {kinds:?}"),
    )
}

fn merge_data_recipe(
    st: Arc<DaemonState>,
    headers: HeaderMap,
    request: MergeRequest,
) -> MergeFuture {
    Box::pin(async move {
        let mut admission = request.body;
        admission["owner_ref"] = json!(request.owner_ref);
        admission["idempotency_key"] = json!(request.idempotency_key);
        admission["expected_head"] = request.expected_head.map_or(Value::Null, Value::String);
        super::data_transformation_routes::handle_data_recipe_admit(
            State(st),
            headers,
            Json(admission),
        )
        .await
    })
}

/// A blueprint's tip for a change set owned by `caller.owner_ref`: the blueprint must be one the
/// caller can read, and the change set is owned by the blueprint's own owner.
fn blueprint_tip(st: &DaemonState, caller: &WriteCaller, id: &str) -> Result<Tip, Reply> {
    match super::studio_routes::blueprint_change_subject(&st.data_dir, &caller.identity, id) {
        Ok(Some(tip)) if tip.owner_ref != caller.owner_ref => Err(bad(
            StatusCode::CONFLICT,
            "change_set_subject_owner_mismatch",
            format!(
                "blueprint://{id} is owned by {}; a change set over it is owned by the blueprint's owner",
                tip.owner_ref
            ),
        )),
        Ok(Some(tip)) => Ok(Some((tip.content_hash, tip.head))),
        Ok(None) => Ok(None),
        Err((code, message)) => Err(bad(
            if code == "studio_blueprint_ref_invalid" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::CONFLICT
            },
            &code,
            message,
        )),
    }
}

/// A blueprint merges through its own PATCH — the successor admission, compare-and-swapped against
/// the head the change set pinned. Its owner is the admitted record's, never the request's.
fn merge_blueprint(st: Arc<DaemonState>, headers: HeaderMap, request: MergeRequest) -> MergeFuture {
    Box::pin(async move {
        let mut admission = request.body;
        admission["idempotency_key"] = json!(request.idempotency_key);
        admission["expected_head"] = request.expected_head.map_or(Value::Null, Value::String);
        super::studio_routes::handle_studio_blueprint_patch(
            State(st),
            AxumPath(request.token),
            headers,
            Json(admission),
        )
        .await
    })
}

/// The contract a record is validated against: its own version's. A v1 record keeps reading and
/// takes its remaining transitions as v1; every change set opened is v2.
fn contract_of(record: &Value) -> &'static str {
    if record["schema_version"].as_str() == Some(SCHEMA_V1) {
        CONTRACT_V1
    } else {
        CONTRACT
    }
}

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

/// The draft body pinned to the subject: its pinned member (when the kind has one) set to the
/// subject's token, and nothing the merge supplies or the kind does not author.
fn pinned_draft(subject: &SubjectKind, token: &str, draft: &Value) -> Result<Value, Reply> {
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
    if let Some(member) = subject.pinned_member {
        let named = map.get(member).and_then(Value::as_str).unwrap_or(token);
        if named != token {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_draft_family_mismatch",
                format!(
                    "this change set drafts {}{token}; a draft for {named} belongs to another change set",
                    subject.ref_prefix
                ),
            ));
        }
    }
    // Admission-owned fields are the merge's to supply, never the draft's.
    for minted in subject.minted {
        if map.contains_key(*minted) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_draft_field_minted",
                format!("{minted} is supplied at merge, never drafted"),
            ));
        }
    }
    if let Some(authored) = subject.authored {
        if let Some(stray) = map.keys().find(|key| !authored.contains(&key.as_str())) {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_draft_member_unknown",
                format!(
                    "{stray} is not a member a {} draft carries; it carries only {authored:?}",
                    subject.kind
                ),
            ));
        }
    }
    let mut pinned = map.clone();
    if let Some(member) = subject.pinned_member {
        pinned.insert(member.into(), json!(token));
    }
    Ok(Value::Object(pinned))
}

/// The record's subject kind and its token (the family, or the blueprint's id).
fn subject_of(record: &Value) -> Result<(&'static SubjectKind, String), Reply> {
    let subject = subject_kind(text(&record["subject"], "kind")).ok_or_else(unsupported_kind)?;
    let token = text(&record["subject"], "family_ref")
        .strip_prefix(subject.ref_prefix)
        .unwrap_or("")
        .to_string();
    Ok((subject, token))
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
    validate(contract_of(&record), "change set", &record)?;
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

/// `basis_refs` is reserved (change-set v2): a basis is admitted only once the daemon resolves it
/// through that evidence's own reader, which this build does not consult yet — so an absent, null
/// or empty basis opens, and any basis at all is refused by name rather than recorded unresolved.
fn reserved_basis(body: &Value) -> Result<(), Reply> {
    match body.get("basis_refs") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(refs)) if refs.is_empty() => Ok(()),
        Some(_) => Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "change_set_basis_unresolvable",
            "a change set's basis is admitted only once it resolves through its own reader (an evaluation result through the evaluation plane), which this build does not consult yet; open the change set with no basis",
        )),
    }
}

/// POST /v1/hypervisor/change-sets — open a change set over one subject, pinned to its current head
/// (or founding it, where its kind may be founded), optionally with a first draft.
pub(crate) async fn handle_change_set_open(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let requested = &body["subject"];
    let kind = text(requested, "kind");
    let Some(subject) = subject_kind(kind) else {
        return unsupported_kind();
    };
    if let Err(response) = reserved_basis(&body) {
        return response;
    }
    let family = text(requested, "family").to_string();
    let tip = match (subject.tip)(&st, &caller, &family) {
        Ok(tip) => tip,
        Err(response) => return response,
    };
    if tip.is_none() && !subject.founds {
        return bad(
            StatusCode::NOT_FOUND,
            "change_set_subject_not_found",
            format!(
                "no {kind} you can read answers to {}{family}; a change set drafts over an existing {kind} and never founds one",
                subject.ref_prefix
            ),
        );
    }
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
        let pinned = match pinned_draft(subject, &family, draft) {
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
        "subject": { "kind": subject.kind, "family_ref": format!("{}{family}", subject.ref_prefix), "base_revision_ref": base_revision_ref, "base_head_ref": base_head_ref },
        "title": title,
        "description": description,
        "basis_refs": [],
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
    let (subject, token) = match subject_of(&record) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let pinned = match pinned_draft(subject, &token, &body["draft"]) {
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
    let (subject, token) = match subject_of(&record) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let outcome = (subject.validate)(&st, &caller.identity, &token, &draft["body"]);
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

/// The proposal's own name and description, when the propose body carries them — validated exactly
/// as open validates them. A field that is absent (or null) leaves the record's value unchanged; a
/// present empty description clears it, stored as the empty string open stores for none.
fn proposal_edits(body: &Value) -> Result<(Option<String>, Option<String>), Reply> {
    let present = |key: &str| body.get(key).is_some_and(|value| !value.is_null());
    let title = if present("title") {
        let title = text(body, "title").to_string();
        if title.is_empty() || title.chars().count() > 200 {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_title_required",
                "a change set has a title of at most 200 characters",
            ));
        }
        Some(title)
    } else {
        None
    };
    let description = if present("description") {
        let description = text(body, "description").to_string();
        if description.chars().count() > 4000 {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "change_set_description_too_long",
                "a description is at most 4000 characters",
            ));
        }
        Some(description)
    } else {
        None
    };
    Ok((title, description))
}

/// Mark the record proposed with the proposal's edits applied, and return the propose transition's
/// facts naming only what changed.
fn apply_proposal(record: &mut Value, title: Option<String>, description: Option<String>) -> Value {
    let mut facts = json!({ "status": "proposed" });
    if let Some(title) = title.filter(|title| record["title"].as_str() != Some(title.as_str())) {
        record["title"] = json!(title);
        facts["title"] = json!(title);
    }
    if let Some(description) = description
        .filter(|description| record["description"].as_str() != Some(description.as_str()))
    {
        record["description"] = json!(description);
        facts["description_changed"] = json!(true);
    }
    record["status"] = json!("proposed");
    facts
}

/// POST /v1/hypervisor/change-sets/:id/propose — ready for review: open → proposed. The body may
/// name the proposal (`title`) and describe it (`description`); either, when present, replaces the
/// change set's own at the moment it is proposed.
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
    let (title, description) = match proposal_edits(&body) {
        Ok(edits) => edits,
        Err(response) => return response,
    };
    let facts = apply_proposal(&mut record, title, description);
    match transition(
        &st,
        &caller,
        &id,
        &head,
        "change_set.propose",
        facts,
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
/// Refused unless the change set is proposed, its latest draft validated `valid`, and the subject's
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
    let (subject, token) = match subject_of(&record) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let subject_ref = format!("{}{token}", subject.ref_prefix);
    let tip = match (subject.tip)(&st, &caller, &token) {
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
                "{subject_ref} moved since this change set was opened (pinned {}, now {}); open a successor change set on the new head",
                base_head.as_deref().unwrap_or("no revision"),
                current_head.as_deref().unwrap_or("no revision")
            ),
        );
    }
    let ordinal = draft["ordinal"].as_u64().unwrap_or(0);
    let request = MergeRequest {
        token: token.clone(),
        owner_ref: text(&record, "owner_ref").to_string(),
        idempotency_key: format!("change-set-merge-{id}-{ordinal}"),
        expected_head: base_head.clone(),
        body: draft["body"].clone(),
    };
    let (status, Json(admitted)) = (subject.merge)(st.clone(), headers.clone(), request).await;
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
    let (resulting_revision_ref, resulting_head) = (subject.merged)(&admitted);
    // The branch names carry the subject's own scheme: data-recipe/<family>, blueprint/<bp_id>.
    let branch = format!("{}/{token}", subject.ref_prefix.trim_end_matches("://"));
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
        "target_branch_ref": format!("execution-branch://{branch}/main"),
        "candidate_branch_refs": [format!("execution-branch://change-set/{id}")],
        "diff_refs": [format!("change://{id}/draft/{ordinal}")],
        "memory_diff_refs": [],
        "authority_diff_refs": [],
        "receipt_diff_refs": [admitted["receipt_ref"].as_str().unwrap_or("receipt://unknown")],
        "verification_refs": [format!("gate://change-set/{id}/validation/{ordinal}")],
        "admission_policy_ref": "policy://change-set/exact-head-merge",
        "expected_head_ref": format!("branch-checkpoint://{branch}/{}", base_head.as_deref().unwrap_or("genesis")),
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
        Ok((commit, record)) => {
            let mut reply = json!({ "ok": true, "replayed": commit.replayed, "change_set": record, "branch_merge_plan": plan, "receipt_ref": commit.receipt_ref });
            // The admitted subject, under the member its own admission answers it with.
            reply[subject.reply_key] = admitted[subject.reply_key].clone();
            (StatusCode::OK, Json(reply))
        }
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

/// GET /v1/hypervisor/change-sets[?kind=…&family=…&status=…] — `family` is read in `kind`'s
/// scheme, and in a data recipe's when no kind is named (as v1 read it).
pub(crate) async fn handle_change_set_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let records = match change_sets_for_request(&st, &headers) {
        Ok(records) => records,
        Err(response) => return response,
    };
    let kind = query.get("kind").map(String::as_str);
    let scheme = match subject_kind(kind.unwrap_or("data_recipe")) {
        Some(subject) => subject.ref_prefix,
        None => return unsupported_kind(),
    };
    let family = query
        .get("family")
        .map(|f| format!("{scheme}{}", f.trim_start_matches(scheme)));
    let status = query.get("status");
    let filtered: Vec<Value> = records
        .into_iter()
        .filter(|r| kind.is_none_or(|k| text(&r["subject"], "kind") == k))
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
        let recipe = subject_kind("data_recipe").unwrap();
        let pinned = pinned_draft(recipe, "acme.orders", &json!({ "name": "Orders" })).unwrap();
        assert_eq!(pinned["family"], "acme.orders");
        assert!(pinned_draft(recipe, "acme.orders", &json!({ "family": "other.family" })).is_err());
        for minted in [
            "owner_ref",
            "idempotency_key",
            "expected_head",
            "revision_ref",
        ] {
            assert!(
                pinned_draft(recipe, "acme.orders", &json!({ minted: "x" })).is_err(),
                "{minted}"
            );
        }
        assert!(pinned_draft(recipe, "acme.orders", &json!(["not", "an", "object"])).is_err());
    }

    fn code_of(reply: &Reply) -> String {
        let body = &reply.1 .0;
        body["error"]["code"]
            .as_str()
            .or_else(|| body["code"].as_str())
            .unwrap_or("")
            .to_string()
    }

    /// The kind set is ONE table: two kinds, each with its own scheme, and a blueprint draft carries
    /// only the blueprint's four authored members — never its binding, identity or anything the
    /// merge supplies.
    #[test]
    fn the_subject_kinds_are_one_table_and_a_blueprint_draft_is_closed() {
        let kinds: Vec<(&str, &str, bool)> = SUBJECT_KINDS
            .iter()
            .map(|s| (s.kind, s.ref_prefix, s.founds))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("data_recipe", "data-recipe://", true),
                ("blueprint", "blueprint://", false)
            ]
        );
        assert!(
            subject_kind("automation").is_none(),
            "ADR 0058 adds automation, not this cut"
        );
        assert_eq!(
            code_of(&unsupported_kind()),
            "change_set_subject_unsupported"
        );
        let blueprint = subject_kind("blueprint").unwrap();
        let pinned = pinned_draft(
            blueprint,
            "bp_0123456789abcdef",
            &json!({ "description": "with review", "graph": { "nodes": [] } }),
        )
        .unwrap();
        assert!(
            pinned.get("family").is_none(),
            "a blueprint draft pins no member"
        );
        for (member, code) in [
            ("system_ref", "change_set_draft_member_unknown"),
            ("id", "change_set_draft_member_unknown"),
            ("content_hash", "change_set_draft_member_unknown"),
            ("expected_head", "change_set_draft_field_minted"),
            ("idempotency_key", "change_set_draft_field_minted"),
            ("owner_ref", "change_set_draft_field_minted"),
        ] {
            let refused = pinned_draft(blueprint, "bp_0123456789abcdef", &json!({ member: "x" }))
                .expect_err(member);
            assert_eq!(code_of(&refused), code, "{member}");
        }
        assert_eq!(
            contract_of(&json!({ "schema_version": SCHEMA_V1 })),
            CONTRACT_V1
        );
        assert_eq!(contract_of(&json!({ "schema_version": SCHEMA })), CONTRACT);
        assert!(reserved_basis(&json!({})).is_ok());
        assert!(reserved_basis(&json!({ "basis_refs": null })).is_ok());
        assert!(reserved_basis(&json!({ "basis_refs": [] })).is_ok());
        let refused = reserved_basis(&json!({ "basis_refs": ["evaluation-result://er_1"] }))
            .expect_err("a basis nothing resolves is refused");
        assert_eq!(code_of(&refused), "change_set_basis_unresolvable");
    }

    // ---- the plane end to end, on a daemon state of its own ----------------------------------

    const OPERATOR: &str = "00000000-0000-4000-8000-000000000001";
    const OWNER: &str = "org://local";

    struct Plane {
        _dir: tempfile::TempDir,
        st: Arc<DaemonState>,
        headers: HeaderMap,
    }

    fn plane() -> Plane {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_str().expect("utf8").to_string();
        super::super::lifecycle_routes::ensure_identity_foundation(&data_dir)
            .expect("identity foundation");
        let st = crate::test_daemon_state(&data_dir);
        let (status, issued) =
            super::super::lifecycle_routes::issue_session(&data_dir, OPERATOR, "local");
        assert_eq!(status, StatusCode::OK, "{issued}");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!(
                "Bearer {}",
                issued["session_token"].as_str().expect("token")
            )
            .parse()
            .expect("header"),
        );
        Plane {
            _dir: dir,
            st,
            headers,
        }
    }

    impl Plane {
        async fn blueprint(&self, key: &str) -> String {
            let (status, Json(created)) = super::super::studio_routes::handle_studio_blueprint_create(
                State(self.st.clone()),
                self.headers.clone(),
                Json(json!({ "owner_ref": OWNER, "idempotency_key": key, "name": "Lending desk", "description": "the desk", "graph": { "nodes": [{ "id": "desk" }], "edges": [] } })),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            created["blueprint"]["id"].as_str().unwrap().to_string()
        }

        async fn blueprint_now(&self, id: &str) -> (Value, String) {
            let Json(read) = super::super::studio_routes::handle_studio_blueprint_get(
                State(self.st.clone()),
                AxumPath(id.to_string()),
            )
            .await;
            (
                read["blueprint"].clone(),
                read["admitted_head"].as_str().unwrap_or("").to_string(),
            )
        }

        async fn open(&self, key: &str, subject: Value, draft: Value) -> Reply {
            handle_change_set_open(
                State(self.st.clone()),
                self.headers.clone(),
                Json(json!({ "owner_ref": OWNER, "idempotency_key": key, "subject": subject, "title": "Add the review step", "draft": draft })),
            )
            .await
        }

        async fn step(&self, change_set_ref: &str, verb: &str, key: &str) -> Reply {
            let id = AxumPath(change_set_ref.trim_start_matches("change://").to_string());
            let body =
                Json(json!({ "owner_ref": OWNER, "idempotency_key": key, "note": "not this one" }));
            let st = State(self.st.clone());
            let headers = self.headers.clone();
            match verb {
                "validate" => handle_change_set_validate(st, headers, id, body).await,
                "propose" => handle_change_set_propose(st, headers, id, body).await,
                "merge" => handle_change_set_merge(st, headers, id, body).await,
                "abandon" => handle_change_set_abandon(st, headers, id, body).await,
                other => panic!("no step {other}"),
            }
        }
    }

    /// A v2 blueprint change set proposes, validates by the blueprint's own successor checks, and
    /// merges through the blueprint's own PATCH with the head it pinned: the blueprint's admitted
    /// head moves to the merge's resulting head and it says what the draft said.
    #[tokio::test]
    async fn a_blueprint_change_set_merges_with_its_pinned_head_and_moves_the_blueprints_head() {
        let p = plane();
        let bp = p.blueprint("bp-merge").await;
        let (before, head_before) = p.blueprint_now(&bp).await;
        assert!(head_before.starts_with("sha256:"), "{head_before}");

        let (status, Json(opened)) = p
            .open(
                "cs-merge",
                json!({ "kind": "blueprint", "family": bp }),
                json!({ "description": "the desk, with its review step", "graph": { "nodes": [{ "id": "desk" }, { "id": "review" }], "edges": [] } }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{opened}");
        let cs = &opened["change_set"];
        assert_eq!(cs["schema_version"], SCHEMA);
        assert_eq!(cs["subject"]["kind"], "blueprint");
        assert_eq!(cs["subject"]["family_ref"], format!("blueprint://{bp}"));
        assert_eq!(cs["subject"]["base_head_ref"], head_before);
        assert_eq!(cs["subject"]["base_revision_ref"], before["content_hash"]);
        assert_eq!(cs["basis_refs"], json!([]));
        let cs_ref = cs["change_set_ref"].as_str().unwrap().to_string();

        let (status, Json(validated)) = p.step(&cs_ref, "validate", "cs-merge-validate").await;
        assert_eq!(status, StatusCode::OK, "{validated}");
        assert_eq!(
            validated["change_set"]["validation"]["outcome"], "valid",
            "{validated}"
        );
        let (status, Json(proposed)) = p.step(&cs_ref, "propose", "cs-merge-propose").await;
        assert_eq!(status, StatusCode::OK, "{proposed}");
        let (unchanged, _) = p.blueprint_now(&bp).await;
        assert_eq!(
            unchanged["description"], "the desk",
            "a proposal changes nothing"
        );

        let (status, Json(merged)) = p.step(&cs_ref, "merge", "cs-merge-merge").await;
        assert_eq!(status, StatusCode::OK, "{merged}");
        let (after, head_after) = p.blueprint_now(&bp).await;
        let merge = &merged["change_set"]["merge"];
        assert_eq!(merged["change_set"]["status"], "merged");
        assert_ne!(
            head_after, head_before,
            "the blueprint's admitted head moved"
        );
        assert_eq!(merge["resulting_head_ref"], head_after);
        assert_eq!(merge["resulting_revision_ref"], after["content_hash"]);
        assert_ne!(after["content_hash"], before["content_hash"]);
        assert_eq!(after["description"], "the desk, with its review step");
        assert_eq!(
            after["name"], "Lending desk",
            "what the draft did not author is kept"
        );
        assert_eq!(merged["blueprint"]["content_hash"], after["content_hash"]);
        let plan = &merged["branch_merge_plan"];
        assert_eq!(plan["decision"], "admit");
        assert_eq!(plan["resulting_main_head"], head_after);
        assert_eq!(
            plan["target_branch_ref"],
            format!("execution-branch://blueprint/{bp}/main")
        );
        assert_eq!(
            plan["expected_head_ref"],
            format!("branch-checkpoint://blueprint/{bp}/{head_before}")
        );

        // The listing reads it in the blueprint's own scheme.
        let (_, Json(listed)) = handle_change_set_list(
            State(p.st.clone()),
            p.headers.clone(),
            axum::extract::Query(
                [
                    ("kind".to_string(), "blueprint".to_string()),
                    ("family".to_string(), bp.clone()),
                ]
                .into_iter()
                .collect(),
            ),
        )
        .await;
        assert_eq!(
            listed["change_sets"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
    }

    /// A blueprint whose head moved after the change set pinned it is never merged over: the merge
    /// is refused by name and the blueprint keeps what its other writer admitted.
    #[tokio::test]
    async fn a_blueprint_change_set_is_refused_when_the_head_it_pinned_moved() {
        let p = plane();
        let bp = p.blueprint("bp-stale").await;
        let (_, head_before) = p.blueprint_now(&bp).await;
        let (status, Json(opened)) = p
            .open(
                "cs-stale",
                json!({ "kind": "blueprint", "family": bp }),
                json!({ "description": "the change set's" }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{opened}");
        let cs_ref = opened["change_set"]["change_set_ref"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            p.step(&cs_ref, "validate", "cs-stale-validate").await.0,
            StatusCode::OK
        );
        assert_eq!(
            p.step(&cs_ref, "propose", "cs-stale-propose").await.0,
            StatusCode::OK
        );

        // Another writer moves the head through the blueprint's own PATCH.
        let (status, Json(patched)) = super::super::studio_routes::handle_studio_blueprint_patch(
            State(p.st.clone()),
            AxumPath(bp.clone()),
            p.headers.clone(),
            Json(json!({ "idempotency_key": "other-writer", "expected_head": head_before, "description": "another writer's" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{patched}");

        let refused = p.step(&cs_ref, "merge", "cs-stale-merge").await;
        assert_eq!(refused.0, StatusCode::CONFLICT, "{}", refused.1 .0);
        assert_eq!(code_of(&refused), "change_set_base_moved");
        let (after, _) = p.blueprint_now(&bp).await;
        assert_eq!(after["description"], "another writer's");

        // The blueprint's own PATCH refuses a stale head by itself too (the race past the re-read).
        let (status, Json(stale)) = super::super::studio_routes::handle_studio_blueprint_patch(
            State(p.st.clone()),
            AxumPath(bp.clone()),
            p.headers.clone(),
            Json(json!({ "idempotency_key": "late-writer", "expected_head": head_before, "description": "late" })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{stale}");
    }

    /// A kind outside the table, a blueprint nobody can read, and a basis nothing resolves are each
    /// refused by name before anything is written.
    #[tokio::test]
    async fn an_unknown_kind_a_missing_blueprint_and_an_unresolved_basis_are_refused_by_name() {
        let p = plane();
        let refused = p
            .open(
                "cs-auto",
                json!({ "kind": "automation", "family": "a" }),
                Value::Null,
            )
            .await;
        assert_eq!(
            (refused.0, code_of(&refused)),
            (
                StatusCode::BAD_REQUEST,
                "change_set_subject_unsupported".to_string()
            )
        );
        let refused = p
            .open(
                "cs-none",
                json!({ "kind": "blueprint", "family": "bp_00000000000000000" }),
                Value::Null,
            )
            .await;
        assert_eq!(
            (refused.0, code_of(&refused)),
            (
                StatusCode::NOT_FOUND,
                "change_set_subject_not_found".to_string()
            )
        );
        let bp = p.blueprint("bp-basis").await;
        let refused = handle_change_set_open(
            State(p.st.clone()),
            p.headers.clone(),
            Json(json!({ "owner_ref": OWNER, "idempotency_key": "cs-basis", "subject": { "kind": "blueprint", "family": bp }, "title": "t", "basis_refs": ["evaluation-result://er_1"] })),
        )
        .await;
        assert_eq!(
            (refused.0, code_of(&refused)),
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                "change_set_basis_unresolvable".to_string()
            )
        );
        assert!(
            read_record_dir(&p.st.data_dir, KIND).is_empty(),
            "nothing was opened"
        );
    }

    /// Every change set opened is v2 — a data recipe's too — and a v1 record keeps reading and takes
    /// its remaining transitions as v1.
    #[tokio::test]
    async fn a_v1_record_keeps_reading_and_transitions_as_v1() {
        let p = plane();
        let (status, Json(opened)) = p
            .open(
                "cs-recipe",
                json!({ "kind": "data_recipe", "family": "acme.orders" }),
                json!({ "name": "Orders" }),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{opened}");
        let cs = &opened["change_set"];
        assert_eq!(cs["schema_version"], SCHEMA);
        assert_eq!(cs["subject"]["family_ref"], "data-recipe://acme.orders");
        assert_eq!(
            cs["subject"]["base_head_ref"],
            Value::Null,
            "a data recipe change set may found its family"
        );
        assert_eq!(cs["drafts"][0]["body"]["family"], "acme.orders");

        // Rewrite its projection as the v1 record an earlier build wrote.
        let cs_ref = cs["change_set_ref"].as_str().unwrap().to_string();
        let id = cs_ref.trim_start_matches("change://").to_string();
        let mut v1 = cs.clone();
        v1["schema_version"] = json!(SCHEMA_V1);
        v1.as_object_mut().unwrap().remove("basis_refs");
        validate(CONTRACT_V1, "change set", &v1).expect("the rewritten record is a v1 record");
        persist(KIND, &p.st.data_dir, &id, &v1).expect("persist");

        let (status, Json(abandoned)) = p.step(&cs_ref, "abandon", "cs-recipe-abandon").await;
        assert_eq!(status, StatusCode::OK, "{abandoned}");
        assert_eq!(abandoned["change_set"]["schema_version"], SCHEMA_V1);
        assert!(abandoned["change_set"].get("basis_refs").is_none());
        let stored = load(&p.st.data_dir, &id).unwrap();
        assert_eq!(stored["status"], "abandoned");
        validate(CONTRACT_V1, "change set", &stored).expect("still a v1 record");
    }

    fn refusal_code(
        result: Result<(Option<String>, Option<String>), Reply>,
    ) -> (StatusCode, String) {
        let (status, Json(body)) = result.expect_err("refused");
        (
            status,
            body["error"]["code"].as_str().unwrap_or("").to_string(),
        )
    }

    #[test]
    fn a_proposal_names_itself_validated_as_open_validates() {
        assert_eq!(proposal_edits(&json!({})).unwrap(), (None, None));
        assert_eq!(
            proposal_edits(&json!({ "title": null, "description": null })).unwrap(),
            (None, None)
        );
        assert_eq!(
            proposal_edits(&json!({ "title": "  Add dedupe  ", "description": "" })).unwrap(),
            (Some("Add dedupe".to_string()), Some(String::new()))
        );
        assert!(proposal_edits(&json!({ "title": "t".repeat(200) })).is_ok());
        for title in [json!("t".repeat(201)), json!("   "), json!(""), json!(7)] {
            assert_eq!(
                refusal_code(proposal_edits(&json!({ "title": title }))),
                (
                    StatusCode::BAD_REQUEST,
                    "change_set_title_required".to_string()
                )
            );
        }
        assert!(proposal_edits(&json!({ "description": "d".repeat(4000) })).is_ok());
        assert_eq!(
            refusal_code(proposal_edits(&json!({ "description": "d".repeat(4001) }))),
            (
                StatusCode::BAD_REQUEST,
                "change_set_description_too_long".to_string()
            )
        );
    }

    #[test]
    fn a_proposal_records_only_what_changed() {
        let base = json!({ "title": "Normalise intake", "description": "first", "status": "open" });

        let mut record = base.clone();
        assert_eq!(
            apply_proposal(&mut record, None, None),
            json!({ "status": "proposed" })
        );
        assert_eq!(record["title"], "Normalise intake");
        assert_eq!(record["description"], "first");
        assert_eq!(record["status"], "proposed");

        let mut record = base.clone();
        let facts = apply_proposal(
            &mut record,
            Some("Add dedupe".into()),
            Some("why it matters".into()),
        );
        assert_eq!(
            facts,
            json!({ "status": "proposed", "title": "Add dedupe", "description_changed": true })
        );
        assert_eq!(record["title"], "Add dedupe");
        assert_eq!(record["description"], "why it matters");

        let mut record = base.clone();
        let facts = apply_proposal(
            &mut record,
            Some("Normalise intake".into()),
            Some(String::new()),
        );
        assert_eq!(
            facts,
            json!({ "status": "proposed", "description_changed": true })
        );
        assert_eq!(record["description"], "");
    }
}
