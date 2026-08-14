//! The three ontology backend families ACC-A names and the estate did not have.
//!
//! Next-legs XII took `SURF-ontology` to 12 of 13 real governed controls and then said plainly what
//! still blocked closure: it was BACKEND, not surface. Derived from the router rather than from
//! guessed URLs, there was **no ontology proposal/branch family, no saved object-set/exploration
//! family, and no object-instance search family**, so three of the six journeys ACC-A names could
//! not close at any depth of UI work.
//!
//! WHAT BINDS THIS MODULE:
//!
//!   * **Ordinary governed mutation, NOT an authority crossing.** Ruling OQ-1, its OQ-11
//!     reaffirmation, and next-legs XII all reached the same place: canon's local-canonicality rule
//!     makes authoring your own ontology an ordinary governed mutation, and re-plumbing it through
//!     the CapabilityLease client would invent authority canon does not require and make every
//!     schema edit demand a wallet approval. Identity-first, `expected_revision` CAS, typed
//!     receipts, atomic-with-rollback persistence — the same shape `odk_routes` already carries.
//!
//!   * **NO SECOND SPINE.** Applying a proposal writes through `odk_routes::apply_ontology_change`,
//!     the one writer an ordinary PATCH uses. A proposal apply that re-implemented validation,
//!     revision bumping, health recomputation or receipting would be a second admission path for one
//!     act, with its own answer to `expected_revision`. That mistake has been made twice in this
//!     program and both times the substrate had already ruled the question.
//!
//!   * **A TYPED ABSENCE IS NOT A GAP TO PAPER OVER.** Object-instance search runs over the
//!     materialized object sets the connector-execution plane really produces. Where no corpus has
//!     been materialized the answer is a typed, named empty — never an invented row, and never an
//!     empty list that reads like "no matches".
//!
//!   * **A SAVED SET IS ONE PRINCIPAL'S.** Explorations are per-principal, pinned through the
//!     substrate's own immutable resource scope — never a record's descriptive `owner_ref` and never
//!     a tenant check, because `org://local` is the only constructible organization and every
//!     principal holds it.
//!
//! WHAT THIS DOES NOT DO: it does not cut over the legacy `/__ioi/ontology/*` mounts (W6.1, blocked
//! on OQ-2), and it mints no deletion route — a saved set RETIRES through its own lifecycle
//! transition, and content deletion belongs to the W1.5 data-retention disposition plane.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::odk_routes::{
    apply_ontology_change, check_expected_revision, load, nanos, odk_scope_refusal,
    validate_ontology_change, KIND_ONT,
};
use super::{iso_now, persist_record, read_record_dir, DaemonState};

const KIND_PROPOSAL: &str = "odk-ontology-proposals";
const KIND_SAVED_SET: &str = "odk-saved-object-sets";
const PROPOSAL_SCHEMA: &str = "ioi.hypervisor.odk.ontology-proposal.v1";
const SAVED_SET_SCHEMA: &str = "ioi.hypervisor.odk.saved-object-set.v1";
const SEARCH_SCHEMA: &str = "ioi.hypervisor.odk.object-instance-search-result.v1";
const SAVED_SET_SCOPE_KIND: &str = "hypervisor-odk-saved-object-set";
const MATERIALIZED_SET_DIR: &str = "odk-materialized-object-sets";

const TEXT_MAX: usize = 2000;
const NAME_MAX: usize = 200;
const SEARCH_LIMIT_MAX: u64 = 200;
const SEARCH_LIMIT_DEFAULT: u64 = 50;

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

/// Identity FIRST, before any record read — rule E. A 401 is owed before a 404 that would otherwise
/// answer "does this ontology exist" to a caller with no session.
// IDENTITY IS RESOLVED THROUGH THE CANONICAL SEAM AT EVERY CALL SITE, NOT THROUGH A LOCAL WRAPPER.
//
// A two-line module-local `identity()` helper wrapped `substrate_store::resolve_request_identity`,
// and `check:admission-evidence` — the estate-wide INV-37 ratchet — reported five of these handlers
// as having NO in-handler identity call. It was right about what it could see: the canonical name
// appeared once, in the wrapper, and the handlers named something only this file knows. The audit
// offers a justified pin for exactly this, and a pin would have been the wrong answer: it would
// have taken five mutating handlers OUT of an estate-wide census to keep a seam that bought two
// lines. A convenience that hides the canonical call from a census is the same shape as a name a
// derivation cannot read, which is the defect this whole leg keeps paying for.

fn bounded_string(body: &Value, key: &str, max: usize, required: bool) -> Result<String, Reply> {
    match body.get(key) {
        None | Some(Value::Null) if !required => Ok(String::new()),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if required && trimmed.is_empty() {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "odk_field_required",
                    format!("`{key}` must be a non-empty string"),
                ));
            }
            if trimmed.chars().count() > max {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "odk_field_too_long",
                    format!("`{key}` exceeds the bounded length ({max} chars)"),
                ));
            }
            Ok(trimmed.to_string())
        }
        None | Some(Value::Null) => Err(bad(
            StatusCode::BAD_REQUEST,
            "odk_field_required",
            format!("`{key}` is required"),
        )),
        Some(_) => Err(bad(
            StatusCode::BAD_REQUEST,
            "odk_field_type_invalid",
            format!("`{key}` must be a string"),
        )),
    }
}

/// Resolve an ontology by id or by its `ref`, returning the record and its canonical id.
fn resolve_ontology(data_dir: &str, reference: &str) -> Option<(String, Value)> {
    if let Some(record) = load(data_dir, KIND_ONT, reference) {
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(reference)
            .to_string();
        return Some((id, record));
    }
    read_record_dir(data_dir, KIND_ONT)
        .into_iter()
        .find_map(|record| {
            let matches = record.get("ref").and_then(Value::as_str) == Some(reference)
                || record.get("id").and_then(Value::as_str) == Some(reference);
            matches.then(|| {
                let id = record
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(reference)
                    .to_string();
                (id, record)
            })
        })
}

// =================================================================================================
// FAMILY 1 — ontology proposals. The `propose` journey ACC-A names.
//
// A proposal is a DECLARED, VALIDATED, REVIEWABLE change against one ontology at one revision. It is
// deliberately not a branch of the whole model: canon's ontology evolution is revision-based
// (`expected_revision`), and inventing a parallel branch store would be a second source of truth for
// what an ontology IS. What a proposal adds over a direct PATCH is the review interval — the change
// exists, validated and attributable, before anyone applies it.
// =================================================================================================

/// The change set a proposal carries. Validated AT PROPOSE TIME against the same rules an ordinary
/// edit obeys, because a proposal that could never apply is not a proposal — it is a note.
fn proposal_change_set(body: &Value) -> Result<Value, Reply> {
    let mut change = json!({});
    let mut named = 0usize;
    for key in ["domain", "version", "description"] {
        if let Some(value) = body.get("changes").and_then(|c| c.get(key)) {
            // NO TYPE CHECK HERE. This was a second, hand-maintained copy of the writer's rules and
            // it DISAGREED with them: it refused an explicit `null` that the writer reads as an
            // ABSENT field, so `domain: null` was 400 at propose and a 200 no-op at patch — the very
            // divergence the shared validator was extracted to end. A null is "not named"; every
            // other type decision belongs to the shared validator below, which both planes run.
            if !value.is_null() {
                change[key] = value.clone();
                named += 1;
            }
        }
    }
    if let Some(model) = body
        .get("changes")
        .and_then(|c| c.get("canonical_object_model"))
    {
        // The model is passed through WHATEVER its shape, null included, so the shared validator
        // makes the call. Skipping a null here would read it as "not named" while the writer reads
        // it as present-and-invalid — the two planes disagreeing again, in the other direction.
        change["canonical_object_model"] = model.clone();
        named += 1;
    }
    if named == 0 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "ontology_proposal_change_required",
            "a proposal must name at least one change — an empty proposal proposes nothing",
        ));
    }
    // THE SAME RULES AN ORDINARY EDIT OBEYS, run through the ontology plane's own validator rather
    // than approximated here. Checking only JSON types at propose time was strictly weaker than
    // apply time, so an empty `domain`, an over-length field or a duplicate object-type id was
    // admitted as an "open" proposal that could never be applied.
    if let Err((status, error)) = validate_ontology_change(&change) {
        return Err((status, Json(json!({ "ok": false, "error": error }))));
    }
    Ok(change)
}

/// POST /v1/hypervisor/odk/ontology-proposals
pub(crate) async fn handle_proposal_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let ontology_ref = match bounded_string(&body, "ontology_ref", TEXT_MAX, true) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let title = match bounded_string(&body, "title", NAME_MAX, true) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let rationale = match bounded_string(&body, "rationale", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let change = match proposal_change_set(&body) {
        Ok(change) => change,
        Err(reply) => return reply,
    };
    let Some((ontology_id, ontology)) = resolve_ontology(&st.data_dir, &ontology_ref) else {
        return bad(
            StatusCode::NOT_FOUND,
            "odk_ontology_not_found",
            "no ontology resolves at this ref",
        );
    };
    let current_revision = ontology
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    if let Err((status, code, message)) = check_expected_revision(&body, current_revision) {
        return (
            status,
            Json(
                json!({ "ok": false, "error": { "code": code, "message": message, "current_revision": current_revision } }),
            ),
        );
    }
    let id = format!("ontp_{:x}", nanos());
    let record = json!({
        "schema_version": PROPOSAL_SCHEMA,
        "id": id,
        "ref": format!("ontology-proposal://{id}"),
        "ontology_id": ontology_id,
        "ontology_ref": ontology.get("ref").cloned().unwrap_or_else(|| json!(ontology_ref)),
        "based_on_revision": current_revision,
        "title": title,
        "rationale": rationale,
        "changes": change,
        "status": "open",
        "proposed_by": identity.principal_ref,
        "created_at": iso_now(),
        "applied": Value::Null,
        "withdrawn": Value::Null,
    });
    if persist_record(&st.data_dir, KIND_PROPOSAL, &id, &record).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ontology_proposal_persistence_failed",
            "the proposal could not be persisted; nothing was recorded",
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "ontology_proposal": record })),
    )
}

/// GET /v1/hypervisor/odk/ontology-proposals[?ontology_ref=&status=]
pub(crate) async fn handle_proposal_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    if let Err(reply) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        return reply;
    }
    let wanted_ontology = query.get("ontology_ref").map(String::as_str);
    let wanted_status = query.get("status").map(String::as_str);
    let mut proposals = read_record_dir(&st.data_dir, KIND_PROPOSAL)
        .into_iter()
        .filter(|record| {
            wanted_ontology.is_none_or(|reference| {
                record.get("ontology_ref").and_then(Value::as_str) == Some(reference)
                    || record.get("ontology_id").and_then(Value::as_str) == Some(reference)
            }) && wanted_status
                .is_none_or(|status| record.get("status").and_then(Value::as_str) == Some(status))
        })
        .collect::<Vec<_>>();
    proposals.sort_by(|a, b| {
        b.get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(a.get("created_at").and_then(Value::as_str).unwrap_or(""))
    });
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "schema_version": PROPOSAL_SCHEMA, "ontology_proposals": proposals, "runtimeTruthSource": "daemon-runtime" }),
        ),
    )
}

/// GET /v1/hypervisor/odk/ontology-proposals/:id
pub(crate) async fn handle_proposal_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    if let Err(reply) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        return reply;
    }
    match load(&st.data_dir, KIND_PROPOSAL, &id) {
        Some(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "ontology_proposal": record })),
        ),
        None => bad(
            StatusCode::NOT_FOUND,
            "ontology_proposal_not_found",
            "no proposal exists at this id",
        ),
    }
}

/// POST /v1/hypervisor/odk/ontology-proposals/:id/apply
///
/// THE WRITE GOES THROUGH THE ONTOLOGY PLANE'S OWN WRITER. This handler decides only whether the
/// proposal may be applied; what "applying" means is `odk_routes::apply_ontology_change`, the same
/// function an ordinary PATCH runs.
pub(crate) async fn handle_proposal_apply(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let Some(proposal) = load(&st.data_dir, KIND_PROPOSAL, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "ontology_proposal_not_found",
            "no proposal exists at this id",
        );
    };
    match proposal.get("status").and_then(Value::as_str) {
        Some("open") => {}
        Some("applied") => {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "replayed": true, "ontology_proposal": proposal })),
            )
        }
        Some(other) => {
            return bad(
                StatusCode::CONFLICT,
                "ontology_proposal_not_open",
                format!("this proposal is '{other}' and cannot be applied"),
            )
        }
        None => {
            return bad(
                StatusCode::CONFLICT,
                "ontology_proposal_not_open",
                "this proposal carries no status",
            )
        }
    }
    let ontology_id = proposal
        .get("ontology_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let based_on = proposal
        .get("based_on_revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let Some((_, ontology)) = resolve_ontology(&st.data_dir, &ontology_id) else {
        return bad(
            StatusCode::CONFLICT,
            "odk_ontology_not_found",
            "the ontology this proposal targets no longer resolves",
        );
    };
    let current_revision = ontology
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    // A PROPOSAL IS AN OFFER AGAINST ONE REVISION. If the ontology moved underneath it, applying
    // would silently overwrite whatever landed in between — which is exactly what `upsert-*` merging
    // did to another author's definition before XII made create mean create. The refusal changes
    // nothing and names both revisions so the proposer can rebase.
    if current_revision != based_on {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "ontology_proposal_stale",
                    "message": "the ontology has advanced since this proposal was made; nothing was applied — rebase the proposal onto the current revision",
                    "based_on_revision": based_on,
                    "current_revision": current_revision,
                }
            })),
        );
    }
    // Carry the CAS through to the one writer, so the revision guard is enforced where the write
    // happens rather than only where this handler looked.
    let mut change = proposal
        .get("changes")
        .cloned()
        .unwrap_or_else(|| json!({}));
    change["expected_revision"] = json!(current_revision);
    let (status, Json(applied)) =
        apply_ontology_change(&st.data_dir, &identity, &ontology_id, &change);
    if !status.is_success() || applied.get("ok").and_then(Value::as_bool) != Some(true) {
        return (status, Json(applied));
    }
    let mut successor = proposal;
    successor["status"] = json!("applied");
    successor["applied"] = json!({
        "applied_by": identity.principal_ref,
        "applied_at": iso_now(),
        "resulting_revision": applied.pointer("/ontology/revision").cloned().unwrap_or(Value::Null),
        "ontology_receipt_ref": applied.pointer("/ontology_receipt/receipt_ref").cloned().unwrap_or(Value::Null),
    });
    if persist_record(&st.data_dir, KIND_PROPOSAL, &id, &successor).is_err() {
        // The ONTOLOGY edit is durable and receipted; only the proposal's own projection failed.
        // Saying so exactly is the honest answer — claiming the apply failed would be false, and
        // claiming it succeeded would hide a proposal stuck reading `open` over an applied change.
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ontology_proposal_projection_failed",
            "the ontology edit is applied and receipted, but the proposal's own status could not be persisted; re-read the ontology revision before re-applying",
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "ontology_proposal": successor,
            "ontology": applied.get("ontology").cloned().unwrap_or(Value::Null),
            "ontology_receipt": applied.get("ontology_receipt").cloned().unwrap_or(Value::Null),
        })),
    )
}

/// POST /v1/hypervisor/odk/ontology-proposals/:id/withdraw
pub(crate) async fn handle_proposal_withdraw(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let reason = match bounded_string(&body, "reason", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let Some(proposal) = load(&st.data_dir, KIND_PROPOSAL, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "ontology_proposal_not_found",
            "no proposal exists at this id",
        );
    };
    match proposal.get("status").and_then(Value::as_str) {
        Some("withdrawn") => {
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "replayed": true, "ontology_proposal": proposal })),
            )
        }
        Some("open") => {}
        Some(other) => {
            return bad(
                StatusCode::CONFLICT,
                "ontology_proposal_terminal",
                format!("this proposal is '{other}'; a terminal proposal cannot be withdrawn"),
            )
        }
        None => {
            return bad(
                StatusCode::CONFLICT,
                "ontology_proposal_terminal",
                "this proposal carries no status",
            )
        }
    }
    let mut successor = proposal;
    successor["status"] = json!("withdrawn");
    successor["withdrawn"] = json!({
        "withdrawn_by": identity.principal_ref,
        "withdrawn_at": iso_now(),
        "reason": reason,
    });
    if persist_record(&st.data_dir, KIND_PROPOSAL, &id, &successor).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ontology_proposal_persistence_failed",
            "the withdrawal could not be persisted; the proposal is unchanged",
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "ontology_proposal": successor })),
    )
}

// =================================================================================================
// FAMILY 2 — saved object sets. The `saved-set` journey ACC-A names.
//
// PER-PRINCIPAL, pinned through the substrate's own immutable scope. A saved exploration is one
// person's working state, and the estate has exactly one honest way to say that: the resource scope
// pin. A descriptive `owner_ref` on the record would be a field the record asserts about itself, and
// a tenant check would isolate nothing at all.
// =================================================================================================

fn owner_tenant(identity: &super::substrate_store::RequestIdentity) -> Result<String, Reply> {
    let mut organizations = identity
        .tenant_refs
        .iter()
        .filter(|tenant_ref| tenant_ref.starts_with("org://"));
    let (Some(owner_ref), None) = (organizations.next(), organizations.next()) else {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "saved_object_set_owner_tenant_unresolved",
            "ownership binds to exactly one org:// tenant resolved from the caller's own session",
        ));
    };
    Ok(owner_ref.clone())
}

fn authorize_saved_set(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    id: &str,
) -> Result<Value, Reply> {
    super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        SAVED_SET_SCOPE_KIND,
        id,
        None,
    )
    .map_err(odk_scope_refusal)?;
    load(data_dir, KIND_SAVED_SET, id).ok_or_else(|| {
        bad(
            StatusCode::NOT_FOUND,
            "saved_object_set_not_found",
            "the caller holds a scope at this coordinate but no saved set resolves under it",
        )
    })
}

/// The selection a saved set stores. Bounded and typed; never an opaque blob.
fn saved_set_selection(body: &Value) -> Result<Value, Reply> {
    let Some(selection) = body.get("selection") else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "saved_object_set_selection_required",
            "`selection` is required — a saved set with no selection saves nothing",
        ));
    };
    if !selection.is_object() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "odk_field_type_invalid",
            "`selection` must be an object",
        ));
    }
    let mut out = json!({});
    for key in ["object_type_id", "q"] {
        match selection.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(value)) => {
                if value.chars().count() > TEXT_MAX {
                    return Err(bad(
                        StatusCode::BAD_REQUEST,
                        "odk_field_too_long",
                        format!("`selection.{key}` exceeds the bounded length"),
                    ));
                }
                out[key] = json!(value);
            }
            Some(_) => {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "odk_field_type_invalid",
                    format!("`selection.{key}` must be a string"),
                ))
            }
        }
    }
    if out.as_object().is_none_or(|object| object.is_empty()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "saved_object_set_selection_required",
            "`selection` must carry at least one of `object_type_id` or `q`",
        ));
    }
    Ok(out)
}

/// POST /v1/hypervisor/odk/saved-object-sets
pub(crate) async fn handle_saved_set_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let name = match bounded_string(&body, "name", NAME_MAX, true) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let description = match bounded_string(&body, "description", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let ontology_ref = match bounded_string(&body, "ontology_ref", TEXT_MAX, true) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let selection = match saved_set_selection(&body) {
        Ok(selection) => selection,
        Err(reply) => return reply,
    };
    let Some((ontology_id, ontology)) = resolve_ontology(&st.data_dir, &ontology_ref) else {
        return bad(
            StatusCode::NOT_FOUND,
            "odk_ontology_not_found",
            "no ontology resolves at this ref",
        );
    };
    let owner_ref = match owner_tenant(&identity) {
        Ok(owner_ref) => owner_ref,
        Err(reply) => return reply,
    };
    let id = format!("sos_{:x}", nanos());
    // THE PIN BEFORE THE RECORD. A saved set that existed without an owner pin could be read by
    // whoever guessed its id, and there would be no coordinate to authorize a later edit against.
    if let Err(error) = super::substrate_store::bind_request_resource_scope(
        &st.data_dir,
        &identity,
        SAVED_SET_SCOPE_KIND,
        &id,
        &owner_ref,
        &owner_ref,
        &format!("saved-object-set-owner:{id}"),
    ) {
        return odk_scope_refusal(error);
    }
    let record = json!({
        "schema_version": SAVED_SET_SCHEMA,
        "id": id,
        "ref": format!("saved-object-set://{id}"),
        "name": name,
        "description": description,
        "ontology_id": ontology_id,
        "ontology_ref": ontology.get("ref").cloned().unwrap_or_else(|| json!(ontology_ref)),
        "selection": selection,
        "status": "active",
        "revision": 1,
        "saved_by": identity.principal_ref,
        "created_at": iso_now(),
        "updated_at": iso_now(),
    });
    if persist_record(&st.data_dir, KIND_SAVED_SET, &id, &record).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "saved_object_set_persistence_failed",
            "the saved set could not be persisted; nothing was recorded",
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({ "ok": true, "saved_object_set": record })),
    )
}

/// GET /v1/hypervisor/odk/saved-object-sets — the CALLER'S OWN saved sets.
pub(crate) async fn handle_saved_set_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let authorized = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        SAVED_SET_SCOPE_KIND,
    ) {
        Ok(refs) => refs,
        Err(error) => return odk_scope_refusal(error),
    };
    let mut sets = read_record_dir(&st.data_dir, KIND_SAVED_SET)
        .into_iter()
        .filter(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| authorized.contains(id))
        })
        .collect::<Vec<_>>();
    sets.sort_by(|a, b| {
        b.get("updated_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(a.get("updated_at").and_then(Value::as_str).unwrap_or(""))
    });
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "schema_version": SAVED_SET_SCHEMA, "saved_object_sets": sets, "runtimeTruthSource": "daemon-runtime" }),
        ),
    )
}

/// GET /v1/hypervisor/odk/saved-object-sets/:id
pub(crate) async fn handle_saved_set_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match authorize_saved_set(&st.data_dir, &identity, &id) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "saved_object_set": record })),
        ),
        Err(reply) => reply,
    }
}

/// PATCH /v1/hypervisor/odk/saved-object-sets/:id — `expected_revision` CAS.
pub(crate) async fn handle_saved_set_patch(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let prev = match authorize_saved_set(&st.data_dir, &identity, &id) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    if prev.get("status").and_then(Value::as_str) == Some("retired") {
        return bad(
            StatusCode::CONFLICT,
            "saved_object_set_retired",
            "this saved set is retired; a retired set is history and does not accept edits",
        );
    }
    let current_revision = prev.get("revision").and_then(Value::as_u64).unwrap_or(1);
    if let Err((status, code, message)) = check_expected_revision(&body, current_revision) {
        return (
            status,
            Json(
                json!({ "ok": false, "error": { "code": code, "message": message, "current_revision": current_revision } }),
            ),
        );
    }
    let mut successor = prev.clone();
    let mut changed = Vec::new();
    if body.get("name").is_some() {
        match bounded_string(&body, "name", NAME_MAX, true) {
            Ok(value) => {
                successor["name"] = json!(value);
                changed.push("name");
            }
            Err(reply) => return reply,
        }
    }
    if body.get("description").is_some() {
        match bounded_string(&body, "description", TEXT_MAX, false) {
            Ok(value) => {
                successor["description"] = json!(value);
                changed.push("description");
            }
            Err(reply) => return reply,
        }
    }
    if body.get("selection").is_some() {
        match saved_set_selection(&body) {
            Ok(selection) => {
                successor["selection"] = selection;
                changed.push("selection");
            }
            Err(reply) => return reply,
        }
    }
    if changed.is_empty() {
        return bad(
            StatusCode::BAD_REQUEST,
            "saved_object_set_change_required",
            "a patch must name at least one of `name`, `description` or `selection`",
        );
    }
    successor["revision"] = json!(current_revision + 1);
    successor["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_SAVED_SET, &id, &successor).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "saved_object_set_persistence_failed",
            "the edit could not be persisted; the saved set is unchanged",
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "saved_object_set": successor, "changed": changed })),
    )
}

/// POST /v1/hypervisor/odk/saved-object-sets/:id/retire
///
/// NOT a delete. This estate has exactly one owner of content deletion — the W1.5 data-retention
/// disposition plane — and a `DELETE` here would be a second admission path for that act with its
/// own answer to legal hold. Retiring is a lifecycle transition: the record survives as history.
pub(crate) async fn handle_saved_set_retire(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let reason = match bounded_string(&body, "reason", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let prev = match authorize_saved_set(&st.data_dir, &identity, &id) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    if prev.get("status").and_then(Value::as_str) == Some("retired") {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "saved_object_set": prev })),
        );
    }
    let mut successor = prev;
    successor["status"] = json!("retired");
    successor["retired"] = json!({
        "retired_by": identity.principal_ref,
        "retired_at": iso_now(),
        "reason": reason,
    });
    successor["updated_at"] = json!(iso_now());
    if persist_record(&st.data_dir, KIND_SAVED_SET, &id, &successor).is_err() {
        return bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "saved_object_set_persistence_failed",
            "the retirement could not be persisted; the saved set is unchanged",
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "saved_object_set": successor })),
    )
}

// =================================================================================================
// FAMILY 3 — object-instance search. The `search` journey ACC-A names.
//
// The corpus is REAL: the connector-execution plane materializes ontology-bound object records into
// `odk-materialized-object-sets`, each carrying its objects, its object type, its ontology, and the
// run that produced it. Search reads that and nothing else.
//
// WHERE THERE IS NO CORPUS THE ANSWER IS A NAMED EMPTY, not an empty list. "No materialized object
// set exists for this ontology" and "your query matched nothing" are different facts, and a surface
// that cannot tell them apart shows a user an empty table and lets them conclude the wrong one.
// =================================================================================================

fn search_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// POST /v1/hypervisor/odk/object-instance-search
pub(crate) async fn handle_object_instance_search(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    if let Err(reply) = super::substrate_store::resolve_request_identity(&st.data_dir, &headers)
        .map_err(odk_scope_refusal)
    {
        return reply;
    }
    let ontology_ref = match bounded_string(&body, "ontology_ref", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let object_type_id = match bounded_string(&body, "object_type_id", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let q = match bounded_string(&body, "q", TEXT_MAX, false) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let limit = match body.get("limit") {
        None | Some(Value::Null) => SEARCH_LIMIT_DEFAULT,
        Some(Value::Number(number)) => match number.as_u64() {
            Some(value) if value > 0 && value <= SEARCH_LIMIT_MAX => value,
            _ => {
                return bad(
                    StatusCode::BAD_REQUEST,
                    "object_instance_search_limit_invalid",
                    format!("`limit` must be an integer in 1..={SEARCH_LIMIT_MAX}"),
                )
            }
        },
        Some(_) => {
            return bad(
                StatusCode::BAD_REQUEST,
                "object_instance_search_limit_invalid",
                "`limit` must be an integer",
            )
        }
    };
    // The ontology filter is resolved BEFORE the corpus is walked, so a typo names itself rather
    // than reading as "no results".
    let resolved_ontology = if ontology_ref.is_empty() {
        None
    } else {
        match resolve_ontology(&st.data_dir, &ontology_ref) {
            Some((id, record)) => Some((
                id,
                record
                    .get("ref")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )),
            None => {
                return bad(
                    StatusCode::NOT_FOUND,
                    "odk_ontology_not_found",
                    "no ontology resolves at this ref",
                )
            }
        }
    };
    let sets = read_record_dir(&st.data_dir, MATERIALIZED_SET_DIR);
    let in_scope = sets
        .iter()
        .filter(|set| {
            resolved_ontology.as_ref().is_none_or(|(id, reference)| {
                let set_ref = set
                    .get("ontology_ref")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                set_ref == reference || set_ref == id
            }) && (object_type_id.is_empty()
                || set.get("object_type_id").and_then(Value::as_str)
                    == Some(object_type_id.as_str()))
        })
        .collect::<Vec<_>>();
    let corpus_objects: usize = in_scope
        .iter()
        .map(|set| {
            set.get("objects")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum();
    let needle = q.to_lowercase();
    let mut matches = Vec::new();
    let mut total_matched = 0usize;
    for set in &in_scope {
        let set_ref = set.get("ref").cloned().unwrap_or(Value::Null);
        let run_ref = set
            .get("materializing_run_ref")
            .cloned()
            .unwrap_or(Value::Null);
        let set_object_type = set.get("object_type_id").cloned().unwrap_or(Value::Null);
        let set_ontology = set.get("ontology_ref").cloned().unwrap_or(Value::Null);
        for object in set
            .get("objects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let hit = needle.is_empty() || search_string(object).to_lowercase().contains(&needle);
            if !hit {
                continue;
            }
            total_matched += 1;
            if matches.len() as u64 >= limit {
                continue;
            }
            matches.push(json!({
                "object": object,
                "object_type_id": set_object_type,
                "ontology_ref": set_ontology,
                // PROVENANCE TRAVELS WITH EVERY ROW. An instance with no materializing run behind it
                // is indistinguishable from an invented one.
                "materialized_object_set_ref": set_ref,
                "materializing_run_ref": run_ref,
            }));
        }
    }
    // THE TWO EMPTIES ARE DIFFERENT FACTS and are typed as such.
    let absence = if in_scope.is_empty() {
        json!({
            "code": "object_instance_corpus_absent",
            "message": "no materialized object set exists in this scope, so there is nothing to search — this is not a query that matched nothing",
        })
    } else if total_matched == 0 {
        json!({
            "code": "object_instance_query_unmatched",
            "message": "the corpus was searched and matched nothing",
        })
    } else {
        Value::Null
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema_version": SEARCH_SCHEMA,
            "query": { "ontology_ref": ontology_ref, "object_type_id": object_type_id, "q": q, "limit": limit },
            "corpus": {
                "materialized_object_sets_in_scope": in_scope.len(),
                "object_instances_in_scope": corpus_objects,
            },
            "total_matched": total_matched,
            "truncated": total_matched > matches.len(),
            "results": matches,
            "absence": absence,
            "runtimeTruthSource": "daemon-runtime",
        })),
    )
}
