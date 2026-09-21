//! M01.11 — THE SUBJECT-SCOPED OUTWARD HYPERVISOR MCP GATEWAY.
//!
//! Canon's rule: one immutable versioned `HypervisorMCPGatewayProfile` binds ONE subject and ONE use to
//! exact requirement and exposure-manifest hashes, and an external model or harness receives only the
//! capabilities and leased context that profile admitted. A profile grants no authority by itself — it
//! binds an exposure manifest to authority clients, daemon admission, policy and receipt obligations, and
//! every effectful call still crosses at its owner's gateway.
//!
//! WHAT THIS MODULE OWNS, and what each rule is actually protecting against.
//!
//!   * **THE ADMITTED REVISION IS FROZEN.** `profile_content_hash` is computed over the DECLARED body with
//!     the lifecycle projections removed — status, revocation, quarantine advisories, last use, and the
//!     admission decision and receipt that bind the already-computed hash. Those projections may only
//!     REDUCE effective access. If they entered the hash, revoking a profile would mint a new identity for
//!     an unchanged body and every consumer's pin would break on an event that took nothing away from
//!     them.
//!   * **NARROWING IS A SUCCESSOR; WIDENING IS A SUCCESSOR THAT REPEATS ADMISSION.** Any change to the
//!     declared body creates a successor revision. `widening_findings` names, member by member, what a
//!     successor added: an exposed tool the predecessor did not expose, a scope, a project, a session, a
//!     higher risk ceiling, a later expiry. A widening successor admitted under its predecessor's decision
//!     is refused — `PATCH` is never a privilege-widening or in-place definition-edit shortcut, and the
//!     easy mistake is to treat "it has a decision ref" as admission when the question is whether that
//!     decision admitted THIS body.
//!   * **RESOLVING A REQUIREMENT ISSUES NOTHING.** The resolver evaluates one exact immutable requirement
//!     revision against one proposed use and answers `resolvable` or names what is missing. It writes no
//!     profile and grants no scope. Packaging a requirement and holding a profile are different facts, and
//!     the System manifest and genesis schemas already keep them in different lanes.
//!   * **THE CALL REACHES THE SAME FINAL INVOKER AS THE NATIVE PATH.** `/call` resolves the profile,
//!     checks the tool against the frozen exposure manifest, refuses on readiness, approval posture or
//!     risk ceiling, and then DELEGATES to `lifecycle_routes::handle_mcp_tool_invoke` — the canonical
//!     invoker the native path uses. It does not reimplement invocation. An outward path with its own
//!     invoker would be the second spine the estate's one structural law forbids, and it is exactly how an
//!     outward surface acquires semantics the native path would refuse.
//!
//! WHAT IS DELIBERATELY NOT HERE. Non-tool primitives are M01.10's: they normalize through the registered
//! decision contract, and four of the five have no canonical owner to normalize to. This module exposes
//! what the estate can honestly serve and leaves the rest to that refusal.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{iso_now, persist_record, read_record_dir, DaemonState};

pub(crate) const REQUIREMENT_RECORDS: &str = "mcp-gateway-requirements";
pub(crate) const PROFILE_RECORDS: &str = "mcp-gateway-profiles";

const REQUIREMENT_CONTRACT: &str =
    "schema://ioi/components/connectors-tools/mcp-gateway-requirement-envelope/v1";
const PROFILE_V1_CONTRACT: &str =
    "schema://ioi/components/connectors-tools/hypervisor-mcp-gateway-profile/v1";
const PROFILE_V2_CONTRACT: &str =
    "schema://ioi/components/connectors-tools/hypervisor-mcp-gateway-profile/v2";

const PROFILE_V1_VERSION: &str = "ioi.hypervisor-mcp-gateway-profile.v1";
const PROFILE_V2_VERSION: &str = "ioi.hypervisor-mcp-gateway-profile.v2";

/// The lifecycle projections that BIND the content hash rather than entering it. Canon lists them, and
/// listing them in one place is what stops a later member quietly joining the preimage.
const EXCLUDED_FROM_CONTENT_HASH: &[&str] = &[
    "profile_content_hash",
    "status",
    "revocation_ref",
    "quarantine_advisory_refs",
    "last_use_ref",
    "admission_decision_ref",
    "admission_receipt_ref",
    "receipt_refs",
];

/// The canonical risk ladder, lowest to highest. `physical_action` is a PEER top-tier class outside the
/// monotonic ladder (it carries its own safety envelope), so it is not ordered against the others: a
/// successor that introduces it is a widening whatever the predecessor's ceiling was.
const RISK_LADDER: &[&str] = &[
    "read",
    "draft",
    "local_write",
    "write_reversible",
    "external_message",
    "commerce",
    "funds",
    "credential_access",
    "policy_widening",
    "secret_export",
    "identity_change",
    "system_destructive",
];

fn risk_rank(class: &str) -> Option<usize> {
    RISK_LADDER.iter().position(|entry| *entry == class)
}

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
}

fn canonical_digest(value: &Value) -> Result<String, (StatusCode, Json<Value>)> {
    serde_jcs::to_vec(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mcp_gateway_canonicalization_failed",
                error.to_string(),
            )
        })
}

/// The declared body: everything the admitted revision froze, with the lifecycle projections removed.
fn declared_body(profile: &Value) -> Value {
    let mut body = profile.clone();
    if let Some(map) = body.as_object_mut() {
        for excluded in EXCLUDED_FROM_CONTENT_HASH {
            map.remove(*excluded);
        }
    }
    body
}

fn str_at<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn set_at(value: &Value, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn exposed_tool_names(profile: &Value) -> BTreeSet<String> {
    profile
        .get("exposed_tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .map(|tool| str_at(tool, "mcp_tool_name").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn exposed_resource_uris(profile: &Value) -> BTreeSet<String> {
    profile
        .get("exposed_resources")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| str_at(item, "mcp_resource_uri").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The highest risk class any exposed tool carries. `None` means the profile exposes no tool at all, which
/// is a real posture and not a ceiling of zero.
fn exposed_risk_ceiling(profile: &Value) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    let mut peer: Option<String> = None;
    for tool in profile
        .get("exposed_tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for key in ["risk_class", "effect_class"] {
            let class = str_at(tool, key);
            if class == "physical_action" {
                peer = Some(class.to_owned());
            } else if let Some(rank) = risk_rank(class) {
                if best.as_ref().is_none_or(|(current, _)| rank > *current) {
                    best = Some((rank, class.to_owned()));
                }
            }
        }
    }
    peer.or(best.map(|(_, class)| class))
}

/// WHAT A SUCCESSOR ADDED. Every finding is a widening, and a widening successor must carry its OWN fresh
/// admission decision rather than inheriting its predecessor's. An empty result is a narrowing or an
/// unchanged exposure, which may land under the same admission.
pub(crate) fn widening_findings(previous: &Value, next: &Value) -> Vec<String> {
    let mut findings = Vec::new();
    let added =
        |what: &str, before: &BTreeSet<String>, after: &BTreeSet<String>| -> Option<String> {
            let new: Vec<&String> = after.difference(before).collect();
            (!new.is_empty()).then(|| {
                format!(
                    "{what} gains {}",
                    new.iter()
                        .map(|entry| entry.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
        };
    for (what, before, after) in [
        (
            "the exposed tool set",
            exposed_tool_names(previous),
            exposed_tool_names(next),
        ),
        (
            "the exposed resource set",
            exposed_resource_uris(previous),
            exposed_resource_uris(next),
        ),
        (
            "the authority scope set",
            set_at(previous, "authority_scope_refs"),
            set_at(next, "authority_scope_refs"),
        ),
        (
            "the project set",
            set_at(previous, "project_refs"),
            set_at(next, "project_refs"),
        ),
        (
            "the session set",
            set_at(previous, "session_refs"),
            set_at(next, "session_refs"),
        ),
        (
            "the invocation scope set",
            set_at(previous, "invocation_scope_refs"),
            set_at(next, "invocation_scope_refs"),
        ),
        (
            "the surface set",
            set_at(previous, "surface_refs"),
            set_at(next, "surface_refs"),
        ),
        (
            "the extension application set",
            set_at(previous, "extension_application_refs"),
            set_at(next, "extension_application_refs"),
        ),
    ] {
        if let Some(finding) = added(what, &before, &after) {
            findings.push(finding);
        }
    }
    // A different subject is not a widening of this profile; it is a different profile wearing its name.
    if str_at(previous, "subject_ref") != str_at(next, "subject_ref") {
        findings.push(
            "the subject changes, which is a different profile rather than a wider one".into(),
        );
    }
    match (exposed_risk_ceiling(previous), exposed_risk_ceiling(next)) {
        (_, Some(after)) if after == "physical_action" => {
            findings.push("the exposure reaches the physical-action class, which is outside the ladder and never inherited".into());
        }
        (None, Some(after)) => {
            findings.push(format!("the exposure gains a risk ceiling of {after}"))
        }
        (Some(before), Some(after)) => {
            if let (Some(a), Some(b)) = (risk_rank(&before), risk_rank(&after)) {
                if b > a {
                    findings.push(format!("the risk ceiling rises from {before} to {after}"));
                }
            }
        }
        _ => {}
    }
    if str_at(next, "expires_at") > str_at(previous, "expires_at") {
        findings.push(format!(
            "the expiry extends from {} to {}",
            str_at(previous, "expires_at"),
            str_at(next, "expires_at")
        ));
    }
    findings
}

fn profile_contract_for(version: &str) -> Option<&'static str> {
    match version {
        PROFILE_V1_VERSION => Some(PROFILE_V1_CONTRACT),
        PROFILE_V2_VERSION => Some(PROFILE_V2_CONTRACT),
        _ => None,
    }
}

/// Validate a profile against the contract its OWN schema version names. Versions do not fall back: a
/// document is read as the version it declares or refused, because reading a v2 as a v1 by discarding the
/// kind a v1 does not recognise would admit the builder surface as whatever the v1 reader defaulted to.
fn validate_profile(profile: &Value) -> Result<&'static str, (StatusCode, Json<Value>)> {
    let version = str_at(profile, "schema_version");
    let Some(contract) = profile_contract_for(version) else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_profile_version_unknown",
            format!(
                "'{version}' is not a gateway profile version this daemon reads; the admitted versions are \
                 {PROFILE_V1_VERSION} and {PROFILE_V2_VERSION}, and neither falls back to the other"
            ),
        ));
    };
    validate_architecture_contract(contract, profile).map_err(|error| {
        refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_profile_not_contract_valid",
            format!("{version}: {error}"),
        )
    })?;
    Ok(contract)
}

fn requirement_records(data_dir: &str) -> Vec<Value> {
    read_record_dir(data_dir, REQUIREMENT_RECORDS)
}

fn profile_records(data_dir: &str) -> Vec<Value> {
    read_record_dir(data_dir, PROFILE_RECORDS)
}

/// The CURRENT revision of one profile family: the revision no other revision names as its predecessor.
/// Derived from the chain rather than taken from directory order, because a record directory has no order
/// and `.last()` over one is a bug that reproduces on some runs and not others (R-215's lesson, one plane
/// over).
pub(crate) fn current_revision(records: &[Value], gateway_profile_id: &str) -> Option<Value> {
    let family: Vec<&Value> = records
        .iter()
        .filter(|record| str_at(record, "gateway_profile_id") == gateway_profile_id)
        .collect();
    if family.is_empty() {
        return None;
    }
    let superseded: BTreeSet<String> = family
        .iter()
        .filter_map(|record| {
            record
                .get("predecessor_profile_revision_ref")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let heads: Vec<&&Value> = family
        .iter()
        .filter(|record| !superseded.contains(str_at(record, "profile_revision_ref")))
        .collect();
    // Two heads is a FORK, not a history. Answering with either would be picking one arbitrarily.
    (heads.len() == 1).then(|| (*heads[0]).clone())
}

/// The effective status, which lifecycle state may only REDUCE. Expiry is derived rather than stored,
/// because a stored `active` on a past expiry is a claim the clock disagrees with.
fn effective_status(profile: &Value, now: &str) -> String {
    let stored = str_at(profile, "status");
    if stored != "active" {
        return stored.to_owned();
    }
    if str_at(profile, "expires_at") <= now {
        return "expired".to_owned();
    }
    "active".to_owned()
}

fn projected(profile: &Value, now: &str) -> Value {
    let mut view = profile.clone();
    if let Some(map) = view.as_object_mut() {
        map.insert(
            "effective_status".into(),
            Value::String(effective_status(profile, now)),
        );
    }
    view
}

// ---- requirements -------------------------------------------------------------------------------------

/// GET /v1/mcp/gateway-requirements
pub(crate) async fn handle_gateway_requirement_list(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let mut requirements = requirement_records(&st.data_dir);
    requirements.sort_by(|a, b| str_at(a, "revision_ref").cmp(str_at(b, "revision_ref")));
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-requirement-listing.v1",
            "requirements": requirements,
            "requirement_count": requirement_records(&st.data_dir).len(),
        })),
    )
}

/// POST /v1/mcp/gateway-requirements/resolve
///
/// Evaluates ONE exact immutable revision against one proposed use. It writes nothing and grants nothing:
/// the answer is whether the use fits inside the declared ceiling, and when it does not, which member of
/// the ceiling it exceeded. Canon's sentence — "packaging the requirement never creates that profile and
/// never grants its requested scopes" — is only true if this route stays a read.
pub(crate) async fn handle_gateway_requirement_resolve(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let revision_ref = str_at(&body, "requirement_revision_ref");
    if revision_ref.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_requirement_revision_required",
            "Resolution takes one EXACT immutable revision ref; a family id would resolve a moving ceiling.",
        );
    }
    let Some(requirement) = requirement_records(&st.data_dir)
        .into_iter()
        .find(|record| str_at(record, "revision_ref") == revision_ref)
    else {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_requirement_absent",
            format!("No admitted requirement revision {revision_ref}"),
        );
    };
    // A ceiling is only a ceiling if it is the shape the contract says. Resolving against a record that no
    // longer validates would evaluate a proposed use against whatever happened to be on disk — and the
    // failure would look like an ordinary "resolvable", which is the worst way for this to go wrong.
    if let Err(error) = validate_architecture_contract(REQUIREMENT_CONTRACT, &requirement) {
        return refuse(
            StatusCode::UNPROCESSABLE_ENTITY,
            "mcp_gateway_requirement_not_contract_valid",
            format!("{revision_ref}: {error}"),
        );
    }
    let proposed_scopes = set_at(&body, "proposed_authority_scope_refs");
    let declared_scopes = set_at(&requirement, "authority_scope_requirement_refs");
    let proposed_tools = set_at(&body, "proposed_runtime_tool_contract_refs");
    let declared_tools = set_at(&requirement, "required_runtime_tool_contract_refs");
    let proposed_risk = str_at(&body, "proposed_maximum_risk_class");
    let ceiling = str_at(&requirement, "maximum_risk_class");

    let mut exceeded: Vec<String> = Vec::new();
    for scope in proposed_scopes.difference(&declared_scopes) {
        exceeded.push(format!("the scope {scope} is outside the declared ceiling"));
    }
    for tool in proposed_tools.difference(&declared_tools) {
        exceeded.push(format!("the tool {tool} is outside the declared ceiling"));
    }
    if !proposed_risk.is_empty() {
        match (risk_rank(proposed_risk), risk_rank(ceiling)) {
            (Some(proposed), Some(limit)) if proposed > limit => exceeded.push(format!(
                "the proposed risk class {proposed_risk} exceeds the ceiling {ceiling}"
            )),
            (None, _) if proposed_risk == "physical_action" && ceiling != "physical_action" => exceeded
                .push("the physical-action class is outside the ladder and is never covered by a ceiling below it".into()),
            _ => {}
        }
    }
    let resolvable = exceeded.is_empty();
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-requirement-resolution.v1",
            "requirement_revision_ref": revision_ref,
            "requirement_content_hash": requirement.get("content_hash").cloned().unwrap_or(Value::Null),
            "resolvable": resolvable,
            "exceeded": exceeded,
            // Said on the wire, not only in canon: an evaluation is not an issuance.
            "profile_issued": false,
            "authority_granted": false,
            "reason": if resolvable {
                "The proposed use fits inside this requirement's declared ceiling. Nothing was issued: a profile is admitted separately and may resolve fewer capabilities than the ceiling allows."
            } else {
                "The proposed use exceeds this requirement's declared ceiling; the members it exceeded are named."
            },
        })),
    )
}

// ---- profiles -----------------------------------------------------------------------------------------

/// GET /v1/mcp/gateways
pub(crate) async fn handle_gateway_list(
    State(st): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let now = iso_now();
    let records = profile_records(&st.data_dir);
    let mut families: Vec<String> = records
        .iter()
        .map(|record| str_at(record, "gateway_profile_id").to_owned())
        .collect();
    families.sort();
    families.dedup();
    let profiles: Vec<Value> = families
        .iter()
        .map(|id| match current_revision(&records, id) {
            Some(head) => projected(&head, &now),
            None => json!({
                "gateway_profile_id": id,
                "effective_status": "unreadable",
                // A fork has no head, and answering with one of two heads would be a choice this daemon
                // has no basis to make.
                "head_error": "two uncited revisions name this profile — a fork, not a history",
            }),
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-listing.v1",
            "profiles": profiles,
            "profile_count": families.len(),
        })),
    )
}

/// POST /v1/mcp/gateways — admit one profile revision under a resolved principal.
pub(crate) async fn handle_gateway_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = super::lifecycle_routes::resolve_principal(&st.data_dir, &headers) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "request_principal_required",
            "Admitting a gateway profile is an authority-bearing act; the daemon mints the identity from the caller's own session and never from the body.",
        );
    };
    let Some(profile) = body.get("profile").cloned() else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_profile_required",
            "The request carries the declared profile body under `profile`.",
        );
    };
    if let Err(answer) = validate_profile(&profile) {
        return answer;
    }

    let gateway_profile_id = str_at(&profile, "gateway_profile_id").to_owned();
    let revision_ref = str_at(&profile, "profile_revision_ref").to_owned();
    let records = profile_records(&st.data_dir);
    if records
        .iter()
        .any(|record| str_at(record, "profile_revision_ref") == revision_ref)
    {
        return refuse(
            StatusCode::CONFLICT,
            "mcp_gateway_profile_revision_exists",
            "An admitted revision is immutable; a changed body is a successor with its own revision ref.",
        );
    }

    // THE HASH IS OVER THE DECLARED BODY. A caller-supplied hash is checked, never trusted.
    let computed = match canonical_digest(&declared_body(&profile)) {
        Ok(hash) => hash,
        Err(answer) => return answer,
    };
    if str_at(&profile, "profile_content_hash") != computed {
        return refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_profile_content_hash_mismatch",
            format!(
                "The declared body canonicalizes to {computed}; the profile carries {}. The hash covers the \
                 declared body only — status, revocation, quarantine advisories, last use and the admission \
                 decision and receipt bind it rather than entering it.",
                str_at(&profile, "profile_content_hash")
            ),
        );
    }

    // SUCCESSOR LINEAGE, AND THE WIDENING RULE.
    let predecessor_ref = profile
        .get("predecessor_profile_revision_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut widened: Vec<String> = Vec::new();
    if predecessor_ref.is_empty() {
        if records
            .iter()
            .any(|record| str_at(record, "gateway_profile_id") == gateway_profile_id)
        {
            return refuse(
                StatusCode::CONFLICT,
                "mcp_gateway_profile_second_genesis",
                "This profile already has a genesis revision; a further revision names its predecessor.",
            );
        }
    } else {
        let Some(previous) = records
            .iter()
            .find(|record| str_at(record, "profile_revision_ref") == predecessor_ref)
        else {
            return refuse(
                StatusCode::BAD_REQUEST,
                "mcp_gateway_profile_predecessor_absent",
                format!("No admitted revision {predecessor_ref} to succeed"),
            );
        };
        if str_at(previous, "gateway_profile_id") != gateway_profile_id {
            return refuse(
                StatusCode::BAD_REQUEST,
                "mcp_gateway_profile_predecessor_is_another_family",
                "A successor belongs to the family it succeeds; a cross-family predecessor would file one profile's narrowing as another's.",
            );
        }
        if records
            .iter()
            .any(|record| str_at(record, "predecessor_profile_revision_ref") == predecessor_ref)
        {
            return refuse(
                StatusCode::CONFLICT,
                "mcp_gateway_profile_predecessor_already_succeeded",
                "That revision already has a successor; admitting a second would fork the chain and leave the family with no head.",
            );
        }
        widened = widening_findings(previous, &profile);
        if !widened.is_empty()
            && str_at(&profile, "admission_decision_ref")
                == str_at(previous, "admission_decision_ref")
        {
            return refuse(
                StatusCode::FORBIDDEN,
                "mcp_gateway_profile_widened_without_fresh_admission",
                format!(
                    "This successor widens ({}) and carries its predecessor's admission decision. Widening \
                     repeats admission; inheriting the decision that admitted a narrower body is the \
                     in-place privilege edit canon forbids.",
                    widened.join("; ")
                ),
            );
        }
    }

    let mut record = profile.clone();
    if let Some(map) = record.as_object_mut() {
        map.insert(
            "admitted_by".into(),
            principal
                .get("principal_id")
                .cloned()
                .unwrap_or(Value::Null),
        );
        map.insert("admitted_at".into(), Value::String(iso_now()));
        map.insert(
            "widening_findings".into(),
            Value::Array(widened.iter().cloned().map(Value::String).collect()),
        );
    }
    let record_id = format!(
        "{}",
        sha2::Sha256::digest(revision_ref.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    if let Err(error) = persist_record(&st.data_dir, PROFILE_RECORDS, &record_id, &record) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "mcp_gateway_profile_not_persisted",
            error.to_string(),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-admission.v1",
            "gateway_profile_id": gateway_profile_id,
            "profile_revision_ref": revision_ref,
            "predecessor_profile_revision_ref": if predecessor_ref.is_empty() { Value::Null } else { Value::String(predecessor_ref) },
            "widening_findings": widened,
            "profile": record,
        })),
    )
}

/// GET /v1/mcp/gateways/:gateway_profile_id
pub(crate) async fn handle_gateway_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let records = profile_records(&st.data_dir);
    match current_revision(&records, &gateway_profile_id) {
        Some(head) => (
            StatusCode::OK,
            Json(json!({
                "schema_version": "ioi.runtime.mcp-gateway-projection.v1",
                "profile": projected(&head, &iso_now()),
            })),
        ),
        None => refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No single admitted head for {gateway_profile_id}"),
        ),
    }
}

/// PATCH /v1/mcp/gateways/:gateway_profile_id — suspend, quarantine, expire or revoke.
///
/// This route may only REDUCE. It changes a lifecycle projection and never the declared body, which is why
/// it does not move the content hash: the identity a consumer pinned is still the identity it pinned, and
/// what changed is what that identity may now do.
pub(crate) async fn handle_gateway_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(principal) = super::lifecycle_routes::resolve_principal(&st.data_dir, &headers) else {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "request_principal_required",
            "Changing a gateway profile's lifecycle state is an authority-bearing act.",
        );
    };
    let status = str_at(&body, "status");
    if !["suspended", "quarantined", "expired", "revoked"].contains(&status) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_patch_widens_or_is_unknown",
            "PATCH reduces: suspended, quarantined, expired or revoked. Returning a profile to active, or \
             editing its declared body in place, is a privilege widening and is a successor with a fresh \
             admission instead.",
        );
    }
    let records = profile_records(&st.data_dir);
    let Some(head) = current_revision(&records, &gateway_profile_id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No single admitted head for {gateway_profile_id}"),
        );
    };
    if status == "revoked" && body.get("revocation_ref").and_then(Value::as_str).is_none() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "mcp_gateway_revocation_ref_required",
            "Revocation does not move the content hash, so the revocation ref is the only thing on the \
             record that distinguishes a revoked profile from the active one it used to be.",
        );
    }
    let mut record = head.clone();
    if let Some(map) = record.as_object_mut() {
        map.insert("status".into(), Value::String(status.to_owned()));
        if let Some(revocation) = body.get("revocation_ref") {
            map.insert("revocation_ref".into(), revocation.clone());
        }
        if let Some(advisories) = body.get("quarantine_advisory_refs") {
            map.insert("quarantine_advisory_refs".into(), advisories.clone());
        }
        map.insert(
            "lifecycle_changed_by".into(),
            principal
                .get("principal_id")
                .cloned()
                .unwrap_or(Value::Null),
        );
        map.insert("lifecycle_changed_at".into(), Value::String(iso_now()));
    }
    // The hash must NOT have moved: this is the check that catches a lifecycle route quietly editing the
    // declared body, which is the shape of the privilege edit canon forbids.
    match canonical_digest(&declared_body(&record)) {
        Ok(recomputed) if recomputed == str_at(&head, "profile_content_hash") => {}
        Ok(recomputed) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "mcp_gateway_lifecycle_change_moved_the_content_hash",
                format!(
                    "A lifecycle change recomputed the declared body to {recomputed}; it must remain {}",
                    str_at(&head, "profile_content_hash")
                ),
            );
        }
        Err(answer) => return answer,
    }
    let record_id = sha2::Sha256::digest(str_at(&head, "profile_revision_ref").as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if let Err(error) = persist_record(&st.data_dir, PROFILE_RECORDS, &record_id, &record) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "mcp_gateway_profile_not_persisted",
            error.to_string(),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-lifecycle.v1",
            "gateway_profile_id": gateway_profile_id,
            "profile_revision_ref": str_at(&head, "profile_revision_ref"),
            "status": status,
            "profile_content_hash_unchanged": true,
            "profile": projected(&record, &iso_now()),
        })),
    )
}

/// POST /v1/mcp/gateways/:gateway_profile_id/revoke
pub(crate) async fn handle_gateway_revoke(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Some(map) = body.as_object_mut() {
        map.insert("status".into(), Value::String("revoked".into()));
    } else {
        body = json!({ "status": "revoked" });
    }
    handle_gateway_patch(State(st), AxumPath(gateway_profile_id), headers, Json(body)).await
}

/// GET /v1/mcp/gateways/:gateway_profile_id/manifest — the frozen exposure manifest.
pub(crate) async fn handle_gateway_manifest(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let records = profile_records(&st.data_dir);
    let Some(head) = current_revision(&records, &gateway_profile_id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No single admitted head for {gateway_profile_id}"),
        );
    };
    let now = iso_now();
    let status = effective_status(&head, &now);
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-manifest.v1",
            "gateway_profile_id": gateway_profile_id,
            "profile_revision_ref": str_at(&head, "profile_revision_ref"),
            "exposure_manifest_hash": head.get("exposure_manifest_hash").cloned().unwrap_or(Value::Null),
            "effective_status": status,
            // A quarantined or revoked profile still HAS an exposure manifest; what it does not have is the
            // ability to act on one. Hiding the manifest would make the refusal unreadable.
            "exposed_tools": head.get("exposed_tools").cloned().unwrap_or(json!([])),
            "exposed_resources": head.get("exposed_resources").cloned().unwrap_or(json!([])),
            "authority_granted": false,
        })),
    )
}

/// POST /v1/mcp/gateways/:gateway_profile_id/call
///
/// THE EQUIVALENCE. The gateway resolves the profile, checks the tool against the frozen exposure manifest
/// and the lifecycle state, and then delegates to the CANONICAL invoker the native path uses. Everything
/// this route adds is a narrowing; nothing it does is an invocation of its own.
pub(crate) async fn handle_gateway_call(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::resolve_principal(&st.data_dir, &headers).is_none() {
        return refuse(
            StatusCode::UNAUTHORIZED,
            "request_principal_required",
            "An outward gateway call is made under the caller's own resolved session.",
        );
    }
    let records = profile_records(&st.data_dir);
    let Some(head) = current_revision(&records, &gateway_profile_id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No single admitted head for {gateway_profile_id}"),
        );
    };
    let now = iso_now();
    let status = effective_status(&head, &now);
    if status != "active" {
        return refuse(
            StatusCode::FORBIDDEN,
            "mcp_gateway_profile_not_active",
            format!("This profile reads {status}; lifecycle state reduces effective access before any provider mutation."),
        );
    }
    let tool_name = str_at(&body, "mcp_tool_name");
    let Some(exposed) = head
        .get("exposed_tools")
        .and_then(Value::as_array)
        .and_then(|tools| {
            tools
                .iter()
                .find(|tool| str_at(tool, "mcp_tool_name") == tool_name)
        })
    else {
        return refuse(
            StatusCode::FORBIDDEN,
            "mcp_gateway_tool_outside_the_exposure_manifest",
            format!(
                "'{tool_name}' is not in this profile's frozen exposure manifest. The manifest is what the \
                 profile was admitted for; a tool outside it is not a missing capability but a different \
                 profile's."
            ),
        );
    };
    let readiness = str_at(exposed, "readiness");
    if readiness != "ready" {
        return refuse(
            StatusCode::CONFLICT,
            "mcp_gateway_tool_not_ready",
            format!("The exposed tool reads {readiness}; a profile may expose a tool as discoverable and still refuse this operation."),
        );
    }
    if exposed
        .get("approval_required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !body
            .get("approval_ref")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    {
        return refuse(
            StatusCode::PRECONDITION_REQUIRED,
            "mcp_gateway_tool_approval_required",
            "The exposure declares an approval requirement and the call names no approval.",
        );
    }
    // The invocation is scoped to what the profile bound, not to what the caller asked for.
    let session_refs = set_at(&head, "session_refs");
    let thread_id = str_at(&body, "thread_id").to_owned();
    if !session_refs.is_empty()
        && !session_refs
            .iter()
            .any(|scope| scope.ends_with(&thread_id) && !thread_id.is_empty())
    {
        return refuse(
            StatusCode::FORBIDDEN,
            "mcp_gateway_call_outside_the_bound_session",
            "This profile binds specific sessions; a call naming another is a cross-session substitution.",
        );
    }
    let tool_id = str_at(exposed, "backing_contract_revision_ref").to_owned();
    let invoke_body = body.get("invocation").cloned().unwrap_or(json!({}));

    // ONE FINAL INVOKER. The native path's handler, called as a function — not a second invocation path
    // that would resolve its own contract, write its own receipt and drift from the native semantics.
    let (status_code, Json(answer)) = super::lifecycle_routes::handle_mcp_tool_invoke(
        State(st.clone()),
        AxumPath((thread_id.clone(), tool_id.clone())),
        Json(invoke_body),
    )
    .await;
    (
        status_code,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-call.v1",
            "gateway_profile_id": gateway_profile_id,
            "profile_revision_ref": str_at(&head, "profile_revision_ref"),
            "exposure_manifest_hash": head.get("exposure_manifest_hash").cloned().unwrap_or(Value::Null),
            "mcp_tool_name": tool_name,
            "backing_contract_revision_ref": tool_id,
            "final_invoker": "RuntimeAgentService.handle_action_execution",
            // The gateway narrowed and delegated. It did not invoke, and it did not mint authority.
            "authority_granted": false,
            "native_answer": answer,
        })),
    )
}

/// GET /v1/mcp/gateways/:gateway_profile_id/events
pub(crate) async fn handle_gateway_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let records = profile_records(&st.data_dir);
    let mut revisions: Vec<&Value> = records
        .iter()
        .filter(|record| str_at(record, "gateway_profile_id") == gateway_profile_id)
        .collect();
    if revisions.is_empty() {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No admitted revision for {gateway_profile_id}"),
        );
    }
    revisions.sort_by_key(|record| str_at(record, "admitted_at").to_owned());
    let events: Vec<Value> = revisions
        .iter()
        .map(|record| {
            json!({
                "event": if str_at(record, "status") == "revoked" {
                    "mcp.gateway_profile_revoked"
                } else if str_at(record, "status") == "quarantined" {
                    "mcp.gateway_profile_quarantined"
                } else {
                    "mcp.gateway_profile_registered"
                },
                "profile_revision_ref": str_at(record, "profile_revision_ref"),
                "at": record.get("lifecycle_changed_at").cloned().unwrap_or_else(|| record.get("admitted_at").cloned().unwrap_or(Value::Null)),
                "by": record.get("lifecycle_changed_by").cloned().unwrap_or_else(|| record.get("admitted_by").cloned().unwrap_or(Value::Null)),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-events.v1",
            "gateway_profile_id": gateway_profile_id,
            "events": events,
        })),
    )
}

/// GET /v1/mcp/gateways/:gateway_profile_id/receipts
pub(crate) async fn handle_gateway_receipts(
    State(st): State<Arc<DaemonState>>,
    AxumPath(gateway_profile_id): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    let records = profile_records(&st.data_dir);
    let Some(head) = current_revision(&records, &gateway_profile_id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "mcp_gateway_profile_absent",
            format!("No single admitted head for {gateway_profile_id}"),
        );
    };
    (
        StatusCode::OK,
        Json(json!({
            "schema_version": "ioi.runtime.mcp-gateway-receipts.v1",
            "gateway_profile_id": gateway_profile_id,
            "admission_decision_ref": head.get("admission_decision_ref").cloned().unwrap_or(Value::Null),
            "admission_receipt_ref": head.get("admission_receipt_ref").cloned().unwrap_or(Value::Null),
            "receipt_refs": head.get("receipt_refs").cloned().unwrap_or(json!([])),
        })),
    )
}

/// The profile the outward tool surface resolves, if one is active for this subject. Returned to
/// `operability_routes` so the two existing `/v1/hypervisor/mcp-gateway/tools*` routes stop refusing
/// unconditionally and start refusing only when nothing resolves.
pub(crate) fn active_profile_for_subject(data_dir: &str, subject_ref: &str) -> Option<Value> {
    let records = profile_records(data_dir);
    let now = iso_now();
    let mut families: Vec<String> = records
        .iter()
        .filter(|record| str_at(record, "subject_ref") == subject_ref)
        .map(|record| str_at(record, "gateway_profile_id").to_owned())
        .collect();
    families.sort();
    families.dedup();
    families
        .into_iter()
        .filter_map(|id| current_revision(&records, &id))
        .find(|head| effective_status(head, &now) == "active")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn profile(over: Map<String, Value>) -> Value {
        let mut base = json!({
            "schema_version": PROFILE_V1_VERSION,
            "gateway_profile_id": "mcp-gateway://p",
            "profile_revision_ref": format!("mcp-gateway://p/revision/sha256:{}", "a".repeat(64)),
            "predecessor_profile_revision_ref": Value::Null,
            "profile_content_hash": format!("sha256:{}", "b".repeat(64)),
            "resolved_requirement_revision_refs": [],
            "resolved_requirement_set_hash": format!("sha256:{}", "c".repeat(64)),
            "exposure_manifest_hash": format!("sha256:{}", "d".repeat(64)),
            "display_name": "p",
            "audience": "external_agent",
            "profile_kind": "project_session",
            "subject_ref": "agent://external/a",
            "admission_basis": "not_applicable",
            "surface_refs": [],
            "exposed_tools": [],
            "exposed_resources": [],
            "authority_client_ref": "wallet-client://a",
            "origin_binding_ref": "origin://a",
            "authority_scope_refs": [],
            "privacy_posture_ref": "privacy://a",
            "budget_policy_ref": "policy://a",
            "rate_limit_ref": "policy://b",
            "quarantine_policy_ref": "policy://c",
            "issued_after_required_admission": true,
            "prompt_only_proposal": false,
            "expires_at": "2026-12-31T23:59:59Z",
            "status": "active",
            "manifest_ref": "mcp-manifest://p",
            "admission_decision_ref": "decision://1",
            "admission_receipt_ref": "receipt://1",
            "project_refs": [],
            "session_refs": [],
            "invocation_scope_refs": [],
            "extension_application_refs": []
        });
        if let Some(map) = base.as_object_mut() {
            for (key, value) in over {
                map.insert(key, value);
            }
        }
        base
    }

    fn tool(name: &str, risk: &str) -> Value {
        json!({
            "mcp_tool_name": name,
            "backing_contract_revision_ref": "tool://a/revision/1",
            "backing_contract_content_hash": format!("sha256:{}", "e".repeat(64)),
            "contract_kind": "runtime_tool_contract",
            "risk_class": risk,
            "effect_class": risk,
            "readiness": "ready",
            "dry_run_required": false,
            "approval_required": false,
            "authority_scopes_required": [],
            "receipt_obligations": []
        })
    }

    #[test]
    fn the_content_hash_covers_the_declared_body_and_not_the_lifecycle_projections() {
        let active = profile(Map::new());
        let mut revoked = active.clone();
        revoked["status"] = json!("revoked");
        revoked["revocation_ref"] = json!("revocation://1");
        revoked["last_use_ref"] = json!("event://9");
        assert_eq!(
            canonical_digest(&declared_body(&active)).unwrap(),
            canonical_digest(&declared_body(&revoked)).unwrap(),
            "revoking a profile must not mint a new identity for an unchanged body"
        );
        let mut widened = active.clone();
        widened["exposed_tools"] = json!([tool("t", "read")]);
        assert_ne!(
            canonical_digest(&declared_body(&active)).unwrap(),
            canonical_digest(&declared_body(&widened)).unwrap(),
            "a changed exposure is a changed body"
        );
    }

    #[test]
    fn widening_is_named_member_by_member_and_narrowing_is_not() {
        let mut two = Map::new();
        two.insert(
            "exposed_tools".into(),
            json!([tool("a", "read"), tool("b", "read")]),
        );
        two.insert("authority_scope_refs".into(), json!(["scope:x", "scope:y"]));
        let wide = profile(two);
        let mut one = Map::new();
        one.insert("exposed_tools".into(), json!([tool("a", "read")]));
        one.insert("authority_scope_refs".into(), json!(["scope:x"]));
        let narrow = profile(one);

        assert!(
            widening_findings(&wide, &narrow).is_empty(),
            "dropping a tool and a scope is a narrowing"
        );
        let findings = widening_findings(&narrow, &wide);
        assert!(
            findings.iter().any(|f| f.contains("exposed tool set")),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.contains("authority scope set")),
            "{findings:?}"
        );
    }

    #[test]
    fn a_higher_risk_ceiling_a_later_expiry_and_a_changed_subject_are_each_a_widening() {
        let mut low = Map::new();
        low.insert("exposed_tools".into(), json!([tool("a", "read")]));
        let base = profile(low);

        let mut high = Map::new();
        high.insert("exposed_tools".into(), json!([tool("a", "funds")]));
        assert!(widening_findings(&base, &profile(high))
            .iter()
            .any(|f| f.contains("risk ceiling rises")));

        let mut later = Map::new();
        later.insert("exposed_tools".into(), json!([tool("a", "read")]));
        later.insert("expires_at".into(), json!("2027-12-31T23:59:59Z"));
        assert!(widening_findings(&base, &profile(later))
            .iter()
            .any(|f| f.contains("expiry extends")));

        let mut elsewhere = Map::new();
        elsewhere.insert("exposed_tools".into(), json!([tool("a", "read")]));
        elsewhere.insert("subject_ref".into(), json!("agent://external/b"));
        assert!(widening_findings(&base, &profile(elsewhere))
            .iter()
            .any(|f| f.contains("subject changes")));
    }

    /// `physical_action` sits OUTSIDE the monotonic ladder, so it is never reached by rising through it.
    #[test]
    fn the_physical_action_class_is_never_inherited_from_a_lower_ceiling() {
        let mut low = Map::new();
        low.insert(
            "exposed_tools".into(),
            json!([tool("a", "system_destructive")]),
        );
        let base = profile(low);
        let mut peer = Map::new();
        peer.insert(
            "exposed_tools".into(),
            json!([tool("a", "physical_action")]),
        );
        assert!(widening_findings(&base, &profile(peer))
            .iter()
            .any(|f| f.contains("physical-action")));
    }

    #[test]
    fn the_head_is_derived_from_the_chain_and_a_fork_has_none() {
        let genesis = profile(Map::new());
        let mut successor = Map::new();
        successor.insert(
            "profile_revision_ref".into(),
            json!(format!(
                "mcp-gateway://p/revision/sha256:{}",
                "f".repeat(64)
            )),
        );
        successor.insert(
            "predecessor_profile_revision_ref".into(),
            genesis["profile_revision_ref"].clone(),
        );
        let second = profile(successor);
        // Deliberately reversed: a record directory has no order, and a head taken by position is a bug
        // that reproduces on some runs and not others.
        let chain = vec![second.clone(), genesis.clone()];
        assert_eq!(
            current_revision(&chain, "mcp-gateway://p")
                .map(|head| head["profile_revision_ref"].clone()),
            Some(second["profile_revision_ref"].clone())
        );

        let mut forked = Map::new();
        forked.insert(
            "profile_revision_ref".into(),
            json!(format!(
                "mcp-gateway://p/revision/sha256:{}",
                "9".repeat(64)
            )),
        );
        forked.insert(
            "predecessor_profile_revision_ref".into(),
            genesis["profile_revision_ref"].clone(),
        );
        let fork = vec![genesis, second, profile(forked)];
        assert!(
            current_revision(&fork, "mcp-gateway://p").is_none(),
            "two revisions succeeding one predecessor is a fork, and answering with either would be arbitrary"
        );
    }

    #[test]
    fn an_expiry_in_the_past_reads_expired_whatever_the_record_stored() {
        let mut past = Map::new();
        past.insert("expires_at".into(), json!("2020-01-01T00:00:00Z"));
        let stale = profile(past);
        assert_eq!(str_at(&stale, "status"), "active");
        assert_eq!(effective_status(&stale, "2026-09-21T00:00:00Z"), "expired");
    }

    #[test]
    fn a_version_this_daemon_does_not_read_is_refused_by_name_and_never_defaulted() {
        let mut other = Map::new();
        other.insert(
            "schema_version".into(),
            json!("ioi.hypervisor-mcp-gateway-profile.v3"),
        );
        let (status, Json(answer)) = validate_profile(&profile(other)).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            answer["error"]["code"],
            "mcp_gateway_profile_version_unknown"
        );
    }

    #[test]
    fn the_two_admitted_versions_each_validate_against_their_own_contract() {
        assert_eq!(
            profile_contract_for(PROFILE_V1_VERSION),
            Some(PROFILE_V1_CONTRACT)
        );
        assert_eq!(
            profile_contract_for(PROFILE_V2_VERSION),
            Some(PROFILE_V2_CONTRACT)
        );
        let v1 = profile(Map::new());
        validate_profile(&v1).expect("the v1 fixture is contract-valid");
        let mut v2_over = Map::new();
        v2_over.insert("schema_version".into(), json!(PROFILE_V2_VERSION));
        v2_over.insert("profile_kind".into(), json!("capability_construction_eval"));
        v2_over.insert("invocation_scope_refs".into(), json!(["session://b"]));
        validate_profile(&profile(v2_over)).expect("the v2 builder fixture is contract-valid");
        // The v2-only kind in a v1 document is refused by the v1 contract rather than ignored.
        let mut leaked = Map::new();
        leaked.insert("profile_kind".into(), json!("capability_construction_eval"));
        assert!(validate_profile(&profile(leaked)).is_err());
    }
}
