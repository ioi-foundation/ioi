//! `HypervisorProjectDiscoveryProposal` — discovery reads, proposes, and STOPS (M09.1).
//!
//! Canon: [`providers-and-environments.md`](../../../../../docs/architecture/components/hypervisor/providers-and-environments.md)
//! § *Evidenced Project Discovery*. A policy-bound source snapshot plus a detector revision produce
//! an immutable proposal; a human or policy then accepts ONE exact candidate and ONE admitted
//! override set; only that acceptance may create Project or recipe lineage (`M09.2` owns what is
//! created from it — this module owns the proposal and the acceptance, and nothing downstream).
//!
//! THE BOUNDARY IS THE WHOLE UNIT, so it is structural here rather than documentary:
//!
//! 1. A PROPOSAL CANNOT NAME WHAT ACCEPTANCE EXISTS TO DECIDE. The admission body is a closed
//!    allowlist, and the fields that would let a proposal pre-empt its own acceptance — a project,
//!    a recipe, a placement, a lease, a grant, an environment, a start — are refused by their OWN
//!    code (`project_discovery_proposal_boundary_field`), never as a generic unknown field. The
//!    distinction matters for the same reason the descriptor route learned it: a caller told
//!    "unknown field" about `project_id` receives a refusal that is true and useless, and never
//!    learns that discovery is not the stage that decides it.
//!
//! 2. AN UNACCEPTED PROPOSAL HAS NO EFFECT ANYWHERE. This module writes exactly one stream per
//!    proposal and touches no other family. It mints no `project_id`, authors no recipe, resolves
//!    no placement, binds no route, grants no lease and starts nothing — not as a matter of
//!    restraint but because it holds no writer for any of those planes. The verifier proves it the
//!    only way a negative can be proven: by measuring every other observable family before and
//!    after an admission and requiring them to be unchanged.
//!
//! 3. CONFIDENCE RANKS; IT DOES NOT SELECT. `selected_candidate_id` is REQUIRED on acceptance and
//!    is never defaulted, and nothing in the acceptance path reads `confidence` at all. A proposal
//!    whose best candidate scores 0.99 is accepted by exactly the same explicit act as one whose
//!    best scores 0.01. Canon says confidence is neither correctness nor authority; a route that
//!    would accept "the most confident candidate" on an empty field would make it both.
//!
//! 4. THE COMMITMENT COVERS THE ALLOCATED REF AND THE EXACT ORDERED CANDIDATE SET. Canon requires
//!    `proposal_hash` to cover the complete immutable proposal through `permitted_override_schema_ref`
//!    while excluding only itself, and requires the ref to be allocated BEFORE hashing — so the ref
//!    cannot be the content hash, and is derived from owner + idempotency key instead (a wall-clock
//!    id can never be idempotent). Re-presenting the same key with ANY changed covered field is
//!    refused as a different proposal rather than accepted as an amendment: canon's "same proposal
//!    ref with changed snapshot, detector, candidates, evidence, or override schema fails".
//!
//! 5. AMBIGUITY STAYS VISIBLE. `uncertainty`, `conflict_refs`, `alternative_candidate_refs`,
//!    `missing_requirement_refs` and `reason_codes` are REQUIRED to be present on every candidate,
//!    though each may be empty. An absent member and a declared "this candidate has no conflicts"
//!    are different findings and only one of them is checkable; a route that let them collapse into
//!    each other would let a detector that never looked read as a detector that looked and found
//!    nothing. They are carried back verbatim and are never normalised away.
//!
//! 6. AN OVERRIDE IS ADMITTED ONLY AGAINST A SCHEMA THIS DAEMON CAN RESOLVE. `permitted_override_schema_ref`
//!    is a ref, so "the override is outside the permitted schema" is only checkable if the ref
//!    resolves to a key set. This build resolves exactly one, by name; every other ref is refused
//!    `project_discovery_override_schema_unresolvable` rather than waved through. Fail closed: an
//!    override the daemon cannot check is an override nobody checked.
//!
//! NONCLAIMS. A proposal is evidence, not a verdict: repository files, manifests, comments,
//! scripts, detector output and host probes remain untrusted. This module does not run the
//! detector — it admits what a detector produced — so "static discovery executes no project code"
//! is a property of the detector's own sandbox, which this plane neither provides nor claims. What
//! it does claim is narrower and checkable: nothing admitted here executes, installs, grants or
//! starts anything.
//!
//! Exit surface: `POST /v1/hypervisor/project-discovery-proposals`,
//! `GET /v1/hypervisor/project-discovery-proposals`,
//! `GET /v1/hypervisor/project-discovery-proposals/:id`,
//! `POST /v1/hypervisor/project-discovery-proposals/:id/acceptances`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, replay_stable_id,
    require_write_caller, scope_refusal_reply, stream_tail, ScopedMutation, WriteCaller,
};
use super::odk_routes::domain_separated_hash;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity,
};
use super::DaemonState;

type Reply = (StatusCode, Json<Value>);

const OWNER_NAMESPACE: &str = "hypervisor-project-discovery";
const RESOURCE_KIND: &str = "project-discovery-proposal";
const PROPOSAL_SCHEMA_VERSION: &str = "ioi.hypervisor.project-discovery-proposal.v1";
const ACCEPTANCE_SCHEMA_VERSION: &str = "ioi.hypervisor.project-discovery-acceptance.v1";
const PROPOSAL_HASH_DOMAIN: &str = "ioi.hypervisor-project-discovery-proposal-jcs-sha256.v1";
const OVERRIDE_SET_HASH_DOMAIN: &str =
    "ioi.hypervisor-project-discovery-override-set-jcs-sha256.v1";
const PROPOSAL_OP_KIND: &str = "project_discovery_proposal_admitted";
const ACCEPTANCE_OP_KIND: &str = "project_discovery_acceptance_admitted";

/// The one override schema this build can resolve, and the closed key set it names.
///
/// Each key overrides the correspondingly named `proposed_*` input a candidate carries, which is
/// why the two lists are read side by side: an override vocabulary that drifted from the candidate
/// vocabulary would admit a value with nothing to override.
const PERMITTED_OVERRIDE_SCHEMA_V1: &str = "override-schema://ioi/hypervisor/project-discovery/v1";
const PERMITTED_OVERRIDE_KEYS: &[&str] = &[
    "project_kind",
    "stack_or_runtime",
    "root_ref",
    "initializer_inputs",
    "task_inputs",
    "service_inputs",
    "port_inputs",
    "dependency_inputs",
];

/// Every field the commitment covers: the complete immutable proposal, the allocated ref included,
/// excluding only `proposal_hash`. FLAT AND ENUMERATED, for the reason the descriptor family
/// learned the hard way — a nested preimage is a number only its producer can recompute, which is
/// not a commitment.
const PROPOSAL_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "project_discovery_proposal_ref",
    "source_ref",
    "source_snapshot_ref",
    "source_snapshot_hash",
    "discovery_engine_revision_ref",
    "discovery_engine_hash",
    "discovery_policy_ref",
    "observed_marker_refs",
    "evidence_refs",
    "candidate_roots",
    "information_flow_label_ref",
    "custody_posture_ref",
    "permitted_override_schema_ref",
];

/// Every field an admission request may carry. `project_discovery_proposal_ref` and `proposal_hash`
/// are absent by construction: the server allocates the first and derives the second, and a request
/// that authored either would be authoring its own commitment.
const PROPOSAL_REQUEST_FIELDS: &[&str] = &[
    "schema_version",
    "owner_ref",
    "idempotency_key",
    "source_ref",
    "source_snapshot_ref",
    "source_snapshot_hash",
    "discovery_engine_revision_ref",
    "discovery_engine_hash",
    "discovery_policy_ref",
    "observed_marker_refs",
    "evidence_refs",
    "candidate_roots",
    "information_flow_label_ref",
    "custody_posture_ref",
    "permitted_override_schema_ref",
];

/// The fields a proposal may not carry BY THEIR OWN CAUSE — each names lineage, authority or
/// runtime that only an explicit acceptance, or a plane downstream of it, may create.
const PROPOSAL_BOUNDARY_FIELDS: &[&str] = &[
    "project_id",
    "project_ref",
    "development_environment_recipe_ref",
    "recipe_ref",
    "recipe_resolution_ref",
    "environment_ref",
    "environment_startup_plan_ref",
    "placement_ref",
    "runtime_assignment_ref",
    "capability_lease_ref",
    "lease_ref",
    "grant_ref",
    "authority_requirement_refs",
    "selected_discovery_candidate_id",
    "admitted_discovery_override_set",
];

const ACCEPTANCE_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_proposal_hash",
    "selected_candidate_id",
    "admitted_override_set",
];

/// Every candidate member canon requires to be PRESENT, so that "nothing found" and "never looked"
/// stay different findings.
const CANDIDATE_REQUIRED_REF_SETS: &[&str] = &[
    "conflict_refs",
    "alternative_candidate_refs",
    "missing_requirement_refs",
    "reason_codes",
];

const PROPOSAL_NONCLAIMS: &[&str] = &[
    "project_lineage",
    "recipe_authorship",
    "placement",
    "authority",
    "runtime_start",
    "confidence_is_correctness",
];

fn refuse(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "code": code, "message": message.into() })),
    )
}

fn invalid(code: &str, message: impl Into<String>) -> Reply {
    refuse(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

fn trimmed(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
        .to_string()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Refuse any request field outside a route's closed set, BY ITS MOST SPECIFIC CAUSE.
///
/// The boundary arm comes first on purpose. A closed allowlist placed in front of it would answer
/// `project_id` with "unknown field", and the one caller who most needs to learn that discovery is
/// not the stage that mints a project would be the one caller who is not told.
fn refuse_unknown_request_fields(body: &Value, allowed: &[&str], route: &str) -> Result<(), Reply> {
    let Some(fields) = body.as_object() else {
        return Err(invalid(
            "project_discovery_request_not_an_object",
            "a project-discovery request is a JSON object",
        ));
    };
    for name in fields.keys() {
        let name = name.as_str();
        if allowed.contains(&name) {
            continue;
        }
        if PROPOSAL_BOUNDARY_FIELDS.contains(&name) {
            return Err(invalid(
                "project_discovery_proposal_boundary_field",
                format!(
                    "'{name}' names Project, recipe, placement, authority or runtime lineage; discovery proposes and STOPS. Only explicit acceptance of one exact candidate and one admitted override set may create it, so a proposal carrying it would be deciding the question acceptance exists to ask"
                ),
            ));
        }
        if name == "project_discovery_proposal_ref" || name == "proposal_hash" {
            return Err(invalid(
                "project_discovery_proposal_field_not_caller_authored",
                format!(
                    "'{name}' is derived by the owner of this contract: the ref is allocated before hashing and the hash covers it. A caller that authored either would be authoring its own commitment, and a commitment its subject can choose is not one"
                ),
            ));
        }
        return Err(invalid(
            "project_discovery_request_field_unknown",
            format!(
                "'{name}' is not a field of a project-discovery {route} request; it is refused rather than ignored, because a request accepted with an unrecognised field reads as one where that field was stored. This route accepts exactly {allowed:?}"
            ),
        ));
    }
    Ok(())
}

fn require_ref_array(body: &Value, key: &str, min: usize) -> Result<Value, Reply> {
    let Some(items) = body.get(key).and_then(Value::as_array) else {
        return Err(invalid(
            "project_discovery_ref_set_required",
            format!(
                "'{key}' is required and is an array; it may be empty where canon allows, but it must be PRESENT — an absent member and a declared 'none' are different findings and only one of them is checkable"
            ),
        ));
    };
    if items.len() < min {
        return Err(invalid(
            "project_discovery_ref_set_too_small",
            format!(
                "'{key}' requires at least {min} member(s); saw {}",
                items.len()
            ),
        ));
    }
    for item in items {
        let value = item.as_str().map(str::trim).unwrap_or("");
        if value.is_empty() || value.len() > 500 {
            return Err(invalid(
                "project_discovery_ref_invalid",
                format!("every member of '{key}' is a non-empty ref of at most 500 characters"),
            ));
        }
    }
    Ok(json!(items))
}

fn require_hash(body: &Value, key: &str) -> Result<String, Reply> {
    let value = trimmed(body, key);
    if !value.starts_with("sha256:") || value.len() != "sha256:".len() + 64 {
        return Err(invalid(
            "project_discovery_hash_not_canonical",
            format!("'{key}' is required and is a 'sha256:' hex digest"),
        ));
    }
    Ok(value)
}

fn require_ref(body: &Value, key: &str, prefix: &str) -> Result<String, Reply> {
    let value = trimmed(body, key);
    if !value.starts_with(prefix) || value.len() > 500 {
        return Err(invalid(
            "project_discovery_ref_not_canonical",
            format!("'{key}' is required and is a '{prefix}' ref of at most 500 characters"),
        ));
    }
    Ok(value)
}

/// Validate the ordered candidate set and return it VERBATIM.
///
/// Verbatim is load-bearing: the commitment covers the exact ordered set, so a validator that
/// rebuilt the candidates from the fields it recognised would commit to bytes the caller never
/// sent, and every consumer re-deriving the hash from the stored record would disagree with it.
fn validate_candidate_roots(body: &Value) -> Result<Value, Reply> {
    let Some(candidates) = body.get("candidate_roots").and_then(Value::as_array) else {
        return Err(invalid(
            "project_discovery_candidate_roots_required",
            "candidate_roots is required and is an ordered array of at least one candidate",
        ));
    };
    if candidates.is_empty() {
        return Err(invalid(
            "project_discovery_candidate_roots_required",
            "a proposal with no candidate proposes nothing; author a candidate or record the refusal to propose",
        ));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for candidate in candidates {
        if !candidate.is_object() {
            return Err(invalid(
                "project_discovery_candidate_not_an_object",
                "every candidate root is a JSON object",
            ));
        }
        let candidate_id = trimmed(candidate, "candidate_id");
        if candidate_id.is_empty() || candidate_id.len() > 200 {
            return Err(invalid(
                "project_discovery_candidate_id_invalid",
                "every candidate carries a non-empty candidate_id of at most 200 characters",
            ));
        }
        // A duplicate id would make `selected_candidate_id` ambiguous, and an acceptance that
        // cannot say WHICH candidate it froze has frozen nothing.
        if !seen.insert(candidate_id.clone()) {
            return Err(invalid(
                "project_discovery_candidate_id_duplicated",
                format!(
                    "candidate_id '{candidate_id}' appears more than once; acceptance names one exact candidate, so two candidates may not answer to one name"
                ),
            ));
        }
        require_ref(candidate, "root_ref", "root://")?;
        for key in ["proposed_project_kind", "proposed_stack_or_runtime"] {
            if trimmed(candidate, key).is_empty() {
                return Err(invalid(
                    "project_discovery_candidate_proposal_incomplete",
                    format!("candidate '{candidate_id}' must carry a non-empty '{key}'"),
                ));
            }
        }
        // Confidence is bounded so it is comparable, and it is REQUIRED so that a detector which
        // did not estimate one cannot be read as one that estimated certainty.
        let Some(confidence) = candidate.get("confidence").and_then(Value::as_f64) else {
            return Err(invalid(
                "project_discovery_candidate_confidence_required",
                format!("candidate '{candidate_id}' must carry a numeric confidence in 0.0..=1.0"),
            ));
        };
        if !(0.0..=1.0).contains(&confidence) {
            return Err(invalid(
                "project_discovery_candidate_confidence_out_of_range",
                format!(
                    "candidate '{candidate_id}' has confidence {confidence}, outside 0.0..=1.0"
                ),
            ));
        }
        if !candidate
            .get("uncertainty")
            .is_some_and(|value| !value.is_null())
        {
            return Err(invalid(
                "project_discovery_candidate_uncertainty_required",
                format!(
                    "candidate '{candidate_id}' must carry 'uncertainty'; canon requires ambiguity and unknowns to remain VISIBLE, and an omitted uncertainty reads as an absence of doubt the detector never expressed"
                ),
            ));
        }
        for key in CANDIDATE_REQUIRED_REF_SETS {
            if !candidate.get(*key).is_some_and(Value::is_array) {
                return Err(invalid(
                    "project_discovery_candidate_visibility_member_missing",
                    format!(
                        "candidate '{candidate_id}' must carry '{key}' as an array; it may be empty, but 'this candidate has none' and 'nobody looked' must stay distinguishable"
                    ),
                ));
            }
        }
    }
    Ok(json!(candidates))
}

/// Build the immutable proposal record. The ref is allocated FIRST, then the hash is taken over a
/// record that already carries it, exactly as canon specifies.
/// Takes the owner and key rather than the whole caller: this is a PURE function of the request
/// and the two values that allocate the ref, and passing an identity it never reads would invite a
/// later revision to consult one — at which point the proposal's bytes would depend on who asked.
fn build_proposal(body: &Value, owner_ref: &str, idempotency_key: &str) -> Result<Value, Reply> {
    refuse_unknown_request_fields(body, PROPOSAL_REQUEST_FIELDS, "proposal")?;
    let declared = trimmed(body, "schema_version");
    if declared != PROPOSAL_SCHEMA_VERSION {
        return Err(invalid(
            "project_discovery_proposal_version_required",
            format!(
                "schema_version is required and must be '{PROPOSAL_SCHEMA_VERSION}'; an unversioned request used to mint a proposal whose shape nothing could check"
            ),
        ));
    }
    let proposal_id = replay_stable_id("pdp", owner_ref, idempotency_key);
    let proposal_ref = format!("project-discovery-proposal://{proposal_id}/revision/1");
    let mut record = Map::new();
    record.insert("schema_version".into(), json!(PROPOSAL_SCHEMA_VERSION));
    record.insert(
        "project_discovery_proposal_ref".into(),
        json!(proposal_ref.clone()),
    );
    record.insert(
        "source_ref".into(),
        json!(require_ref(body, "source_ref", "source://")?),
    );
    record.insert(
        "source_snapshot_ref".into(),
        json!(require_ref(
            body,
            "source_snapshot_ref",
            "source-snapshot://"
        )?),
    );
    record.insert(
        "source_snapshot_hash".into(),
        json!(require_hash(body, "source_snapshot_hash")?),
    );
    record.insert(
        "discovery_engine_revision_ref".into(),
        json!(require_ref(
            body,
            "discovery_engine_revision_ref",
            "discovery-engine://"
        )?),
    );
    record.insert(
        "discovery_engine_hash".into(),
        json!(require_hash(body, "discovery_engine_hash")?),
    );
    // The snapshot is POLICY-BOUND per canon, so the policy is a required member rather than an
    // optional annotation: a snapshot nobody bound to a policy is not the thing canon describes.
    record.insert(
        "discovery_policy_ref".into(),
        json!(require_ref(body, "discovery_policy_ref", "policy://")?),
    );
    record.insert(
        "observed_marker_refs".into(),
        require_ref_array(body, "observed_marker_refs", 0)?,
    );
    record.insert(
        "evidence_refs".into(),
        require_ref_array(body, "evidence_refs", 0)?,
    );
    record.insert("candidate_roots".into(), validate_candidate_roots(body)?);
    record.insert(
        "information_flow_label_ref".into(),
        json!(require_ref(
            body,
            "information_flow_label_ref",
            "information-flow-label://"
        )?),
    );
    record.insert(
        "custody_posture_ref".into(),
        json!(require_ref(
            body,
            "custody_posture_ref",
            "custody-posture://"
        )?),
    );
    let override_schema = require_ref(body, "permitted_override_schema_ref", "override-schema://")?;
    record.insert(
        "permitted_override_schema_ref".into(),
        json!(override_schema),
    );
    let record = Value::Object(record);
    let hash = domain_separated_hash(&record, PROPOSAL_HASH_DOMAIN, PROPOSAL_MATERIAL_FIELDS);
    let mut record = record;
    record["proposal_hash"] = json!(hash);
    record["does_not_assert"] = json!(PROPOSAL_NONCLAIMS);
    Ok(record)
}

/// Re-derive a stored proposal's commitment and compare it with the stored one.
///
/// Nothing trusts the number the record carries. A projection that returned `proposal_hash`
/// verbatim would report the commitment of whoever last wrote the bytes, which is precisely the
/// party a commitment exists to constrain.
fn proposal_commitment_holds(record: &Value) -> bool {
    let stored = record.get("proposal_hash").and_then(Value::as_str);
    let derived = domain_separated_hash(record, PROPOSAL_HASH_DOMAIN, PROPOSAL_MATERIAL_FIELDS);
    stored == Some(derived.as_str())
}

fn proposal_from_history(history: &[agentgres::mux::ExactProjection]) -> Option<Value> {
    history
        .iter()
        .find(|entry| entry.operation.op_kind == PROPOSAL_OP_KIND)
        .and_then(|entry| entry.operation.payload.get("proposal").cloned())
}

fn acceptance_from_history(history: &[agentgres::mux::ExactProjection]) -> Option<Value> {
    history
        .iter()
        .find(|entry| entry.operation.op_kind == ACCEPTANCE_OP_KIND)
        .and_then(|entry| entry.operation.payload.get("acceptance").cloned())
}

/// The read projection, rebuilt from the stream on every read — never a stored view.
fn project(
    proposal_ref: &str,
    history: &[agentgres::mux::ExactProjection],
) -> Option<(Value, Option<Value>, String, u64)> {
    let proposal = proposal_from_history(history)?;
    let head = history.last().map(|entry| entry.head.clone())?;
    let seq = history.last().map(|entry| entry.seq)?;
    let _ = proposal_ref;
    Some((proposal, acceptance_from_history(history), head, seq))
}

// ------------------------------------------------------------------------------- admission

/// POST /v1/hypervisor/project-discovery-proposals — admit one immutable proposal.
pub(crate) async fn handle_project_discovery_proposal_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST. Validating content before authenticating answers 422 where 401 is owed and
    // tells an anonymous caller exactly which fields this route wants.
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let record = match build_proposal(&body, &caller.owner_ref, &caller.idempotency_key) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let proposal_ref = record["project_discovery_proposal_ref"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &proposal_ref,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(RESOURCE_KIND, &proposal_ref);

    // REPLAY BEFORE ANYTHING ELSE. A retry under the same key must reach the same answer, and an
    // IMMUTABLE object makes the divergence check unusually simple: the commitment covers every
    // field a caller could have changed, so one hash comparison decides whether this is the same
    // proposal or a different one wearing the same key.
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        &scope,
        RESOURCE_KIND,
        &proposal_ref,
        OWNER_NAMESPACE,
        &tail,
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let stored = prior
                .operation
                .payload
                .get("proposal")
                .cloned()
                .unwrap_or(Value::Null);
            if stored.get("proposal_hash") != record.get("proposal_hash") {
                return refuse(
                    StatusCode::CONFLICT,
                    "project_discovery_proposal_immutable",
                    format!(
                        "'{proposal_ref}' is already admitted and a proposal is immutable: the same ref with a changed snapshot, detector, candidate set, evidence or override schema is a DIFFERENT proposal, not an amendment of this one. Author it under a new idempotency_key"
                    ),
                );
            }
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    "project_discovery_proposal_ref": proposal_ref,
                    "proposal": stored,
                    "admitted_head": prior.head,
                })),
            );
        }
        Ok(None) => {}
        Err(error) => return mutation_refusal_reply(error),
    }

    let recorded_at_ms = now_ms();
    let payload = json!({
        "proposal": record,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        true,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &proposal_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: PROPOSAL_OP_KIND,
            expected_head: None,
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "project_discovery_proposal_ref": proposal_ref,
            "proposal": record,
            "admitted_head": commit.projection.head,
            "operation_ref": commit.operation_ref,
            "receipt_ref": commit.receipt_ref,
        })),
    )
}

// ------------------------------------------------------------------------------- acceptance

/// POST /v1/hypervisor/project-discovery-proposals/:id/acceptances — freeze ONE exact candidate
/// and ONE admitted override set against ONE exact proposal.
pub(crate) async fn handle_project_discovery_acceptance_admit(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        refuse_unknown_request_fields(&body, ACCEPTANCE_REQUEST_FIELDS, "acceptance")
    {
        return response;
    }
    let proposal_ref = format!("project-discovery-proposal://{id}/revision/1");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RESOURCE_KIND,
        &proposal_ref,
        Some(&caller.owner_ref),
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let tail = stream_tail(RESOURCE_KIND, &proposal_ref);
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &caller.identity,
        &scope,
        RESOURCE_KIND,
        &proposal_ref,
        OWNER_NAMESPACE,
        &tail,
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some(proposal) = proposal_from_history(&history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "project_discovery_proposal_unknown",
            "no admitted proposal answers to that ref",
        );
    };
    // The stored bytes are re-committed before they are used as the subject of a freeze. A record
    // whose hash no longer covers its content is not the proposal anyone accepted.
    if !proposal_commitment_holds(&proposal) {
        return refuse(
            StatusCode::CONFLICT,
            "project_discovery_proposal_commitment_broken",
            "the stored proposal does not re-derive its own proposal_hash; it is not the proposal an acceptance could freeze",
        );
    }

    // THE EXACT PROPOSAL, ASSERTED BY THE CALLER. Acceptance binds a specific commitment, so the
    // caller states which one it read. Without this an acceptance authored against one proposal
    // could land against whatever the ref happened to name by the time it arrived.
    let expected = trimmed(&body, "expected_proposal_hash");
    if expected.is_empty() {
        return invalid(
            "project_discovery_acceptance_proposal_hash_required",
            "expected_proposal_hash is required: an acceptance freezes ONE exact proposal, so it names the exact commitment it read",
        );
    }
    if Some(expected.as_str()) != proposal.get("proposal_hash").and_then(Value::as_str) {
        return refuse(
            StatusCode::CONFLICT,
            "project_discovery_acceptance_proposal_hash_mismatch",
            "expected_proposal_hash does not match this proposal's commitment; re-read the proposal and accept the one you actually saw",
        );
    }

    if acceptance_from_history(&history).is_some() {
        return refuse(
            StatusCode::CONFLICT,
            "project_discovery_proposal_already_accepted",
            "this proposal is already accepted; acceptance freezes one candidate and one override set ONCE, and a second freeze would make the lineage ambiguous about which one it descends from",
        );
    }

    // EXPLICIT, NEVER DEFAULTED. Nothing on this path reads `confidence`: canon says confidence is
    // neither correctness nor authority, and a route that selected the most confident candidate on
    // an empty field would quietly make it both.
    let selected = trimmed(&body, "selected_candidate_id");
    if selected.is_empty() {
        return invalid(
            "project_discovery_acceptance_candidate_required",
            "selected_candidate_id is required and is never inferred: confidence ranks candidates, it does not choose one",
        );
    }
    let candidates = proposal
        .get("candidate_roots")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !candidates.iter().any(|candidate| {
        candidate.get("candidate_id").and_then(Value::as_str) == Some(selected.as_str())
    }) {
        return invalid(
            "project_discovery_acceptance_candidate_unknown",
            format!(
                "'{selected}' is not a candidate of this proposal; an acceptance may only freeze a candidate the proposal actually proposed"
            ),
        );
    }

    // AN OVERRIDE IS CHECKED OR IT IS REFUSED. `permitted_override_schema_ref` is a ref, so the
    // question "is this override permitted" is answerable only against a schema this build can
    // resolve. Fail closed rather than admit an override nobody checked.
    let schema_ref = proposal
        .get("permitted_override_schema_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if schema_ref != PERMITTED_OVERRIDE_SCHEMA_V1 {
        return refuse(
            StatusCode::CONFLICT,
            "project_discovery_override_schema_unresolvable",
            format!(
                "this build resolves exactly one permitted-override schema ('{PERMITTED_OVERRIDE_SCHEMA_V1}'); '{schema_ref}' cannot be resolved, so no override set presented against it can be checked, and an unchecked override is not an admitted one"
            ),
        );
    }
    let override_set = body
        .get("admitted_override_set")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let Some(override_map) = override_set.as_object() else {
        return invalid(
            "project_discovery_override_set_not_an_object",
            "admitted_override_set is a JSON object keyed by the permitted override names",
        );
    };
    for key in override_map.keys() {
        if !PERMITTED_OVERRIDE_KEYS.contains(&key.as_str()) {
            return invalid(
                "project_discovery_override_not_permitted",
                format!(
                    "'{key}' is not permitted by '{PERMITTED_OVERRIDE_SCHEMA_V1}', which admits exactly {PERMITTED_OVERRIDE_KEYS:?}. An override outside the proposal's own permitted schema is a change the proposal never offered"
                ),
            );
        }
    }

    let head = match history.last() {
        Some(entry) => entry.head.clone(),
        None => {
            return refuse(
                StatusCode::CONFLICT,
                "project_discovery_proposal_unknown",
                "no admitted proposal answers to that ref",
            )
        }
    };
    // The caller may assert the head it read; if it does, it must be right. An acceptance is a
    // successor, so the compare-and-swap is the substrate's, not this module's opinion of it.
    let asserted_head = trimmed(&body, "expected_head");
    if !asserted_head.is_empty() && asserted_head != head {
        return refuse(
            StatusCode::CONFLICT,
            "event_stream_expected_head_conflict",
            "expected_head is not this proposal's current head; re-read it and retry",
        );
    }

    let override_hash = domain_separated_hash(
        &json!({ "admitted_override_set": override_set.clone() }),
        OVERRIDE_SET_HASH_DOMAIN,
        &["admitted_override_set"],
    );
    let recorded_at_ms = now_ms();
    let acceptance = json!({
        "schema_version": ACCEPTANCE_SCHEMA_VERSION,
        "project_discovery_proposal_ref": proposal_ref,
        "project_discovery_proposal_hash": expected,
        "selected_discovery_candidate_id": selected,
        "admitted_discovery_override_set": override_set,
        "admitted_discovery_override_set_ref": format!("override-set://{id}/revision/1"),
        "admitted_discovery_override_set_hash": override_hash,
        "accepted_by": caller.identity.principal_ref,
        "accepted_at": admitted_stamp(recorded_at_ms),
        // An acceptance freezes a decision; it does not perform it. What is created FROM the freeze
        // is M09.2's, and saying so on the record keeps a consumer from reading this as lineage.
        "does_not_assert": ["project_lineage", "recipe_authorship", "placement", "authority", "runtime_start"],
    });
    let payload = json!({ "acceptance": acceptance });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        false,
        ScopedMutation {
            identity: &caller.identity,
            scope: &scope,
            resource_kind: RESOURCE_KIND,
            resource_ref: &proposal_ref,
            owner_namespace: OWNER_NAMESPACE,
            stream_tail: &tail,
            op_kind: ACCEPTANCE_OP_KIND,
            expected_head: Some(&head),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "project_discovery_proposal_ref": proposal_ref,
            "acceptance": acceptance,
            "admitted_head": commit.projection.head,
            "operation_ref": commit.operation_ref,
            "receipt_ref": commit.receipt_ref,
        })),
    )
}

// ------------------------------------------------------------------------------- reads

/// GET /v1/hypervisor/project-discovery-proposals/:id
pub(crate) async fn handle_project_discovery_proposal_get(
    State(st): State<Arc<DaemonState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let proposal_ref = format!("project-discovery-proposal://{id}/revision/1");
    let scope = match authorize_request_resource_scope(
        &st.data_dir,
        &identity,
        RESOURCE_KIND,
        &proposal_ref,
        None,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let history = match read_owner_scoped_history(
        &st.data_dir,
        &identity,
        &scope,
        RESOURCE_KIND,
        &proposal_ref,
        OWNER_NAMESPACE,
        &stream_tail(RESOURCE_KIND, &proposal_ref),
    ) {
        Ok(history) => history,
        Err(error) => return mutation_refusal_reply(error),
    };
    let Some((proposal, acceptance, head, seq)) = project(&proposal_ref, &history) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "project_discovery_proposal_unknown",
            "no admitted proposal answers to that ref",
        );
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "project_discovery_proposal_ref": proposal_ref,
            "proposal": proposal,
            // RE-DERIVED, not read back. A projection that returned the stored number would report
            // the commitment of whoever last wrote the bytes.
            "commitment_verified": proposal_commitment_holds(&proposal),
            "acceptance": acceptance,
            "accepted": acceptance.is_some(),
            "admitted_head": head,
            "revision_count": seq,
        })),
    )
}

/// GET /v1/hypervisor/project-discovery-proposals
pub(crate) async fn handle_project_discovery_proposal_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let refs = match authorized_request_resource_refs(&st.data_dir, &identity, RESOURCE_KIND) {
        Ok(refs) => refs,
        Err(error) => return scope_refusal_reply(error),
    };
    let mut proposals = Vec::new();
    for proposal_ref in refs {
        let Ok(scope) = authorize_request_resource_scope(
            &st.data_dir,
            &identity,
            RESOURCE_KIND,
            &proposal_ref,
            None,
        ) else {
            continue;
        };
        let Ok(history) = read_owner_scoped_history(
            &st.data_dir,
            &identity,
            &scope,
            RESOURCE_KIND,
            &proposal_ref,
            OWNER_NAMESPACE,
            &stream_tail(RESOURCE_KIND, &proposal_ref),
        ) else {
            continue;
        };
        if let Some((proposal, acceptance, head, _)) = project(&proposal_ref, &history) {
            proposals.push(json!({
                "project_discovery_proposal_ref": proposal_ref,
                "proposal_hash": proposal.get("proposal_hash").cloned().unwrap_or(Value::Null),
                "commitment_verified": proposal_commitment_holds(&proposal),
                "candidate_count": proposal.get("candidate_roots").and_then(Value::as_array).map(Vec::len).unwrap_or(0),
                "accepted": acceptance.is_some(),
                "admitted_head": head,
            }));
        }
    }
    proposals.sort_by(|a, b| {
        a["project_discovery_proposal_ref"]
            .as_str()
            .unwrap_or("")
            .cmp(b["project_discovery_proposal_ref"].as_str().unwrap_or(""))
    });
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema_version": PROPOSAL_SCHEMA_VERSION,
            "project_discovery_proposals": proposals,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "org://local";
    const KEY: &str = "k1";

    fn candidate(id: &str, confidence: f64) -> Value {
        json!({
            "candidate_id": id,
            "root_ref": "root://repo/services/api",
            "proposed_project_kind": "service",
            "proposed_stack_or_runtime": "node20",
            "confidence": confidence,
            "uncertainty": "one lockfile, two package managers",
            "conflict_refs": [],
            "alternative_candidate_refs": [],
            "missing_requirement_refs": [],
            "reason_codes": ["package_json_present"],
        })
    }

    fn body() -> Value {
        json!({
            "schema_version": PROPOSAL_SCHEMA_VERSION,
            "owner_ref": "org://local",
            "idempotency_key": "k1",
            "source_ref": "source://repo/example",
            "source_snapshot_ref": "source-snapshot://repo/example/1",
            "source_snapshot_hash": format!("sha256:{}", "a".repeat(64)),
            "discovery_engine_revision_ref": "discovery-engine://ioi/static/revision/3",
            "discovery_engine_hash": format!("sha256:{}", "b".repeat(64)),
            "discovery_policy_ref": "policy://ioi/discovery/read-only",
            "observed_marker_refs": ["marker://package.json"],
            "evidence_refs": ["evidence://package.json#1"],
            "candidate_roots": [candidate("c1", 0.9)],
            "information_flow_label_ref": "information-flow-label://ioi/internal",
            "custody_posture_ref": "custody-posture://ioi/local",
            "permitted_override_schema_ref": PERMITTED_OVERRIDE_SCHEMA_V1,
        })
    }

    #[test]
    fn the_commitment_covers_the_allocated_ref_and_re_derives() {
        let record = build_proposal(&body(), OWNER, KEY).expect("valid proposal");
        assert!(proposal_commitment_holds(&record));
        assert!(record["project_discovery_proposal_ref"]
            .as_str()
            .unwrap()
            .starts_with("project-discovery-proposal://pdp_"));
        // The ref is INSIDE the preimage: moving it must move the hash, or the commitment does not
        // bind the object it names.
        let mut moved = record.clone();
        moved["project_discovery_proposal_ref"] =
            json!("project-discovery-proposal://other/revision/1");
        assert!(!proposal_commitment_holds(&moved));
    }

    #[test]
    fn every_covered_field_moves_the_commitment_including_candidate_order() {
        let mut two = body();
        two["candidate_roots"] = json!([candidate("c1", 0.9), candidate("c2", 0.2)]);
        let forward = build_proposal(&two, OWNER, KEY).expect("valid");
        let mut reversed = two.clone();
        reversed["candidate_roots"] = json!([candidate("c2", 0.2), candidate("c1", 0.9)]);
        let backward = build_proposal(&reversed, OWNER, KEY).expect("valid");
        assert_ne!(
            forward["proposal_hash"], backward["proposal_hash"],
            "the commitment covers the EXACT ORDERED candidate set, so a reordering is a different proposal"
        );
        for field in [
            "source_snapshot_hash",
            "discovery_engine_hash",
            "discovery_policy_ref",
            "permitted_override_schema_ref",
        ] {
            let mut changed = body();
            changed[field] = json!(match field {
                "source_snapshot_hash" | "discovery_engine_hash" =>
                    format!("sha256:{}", "c".repeat(64)),
                "discovery_policy_ref" => "policy://ioi/discovery/other".to_string(),
                _ => "override-schema://ioi/hypervisor/project-discovery/v2".to_string(),
            });
            let other = build_proposal(&changed, OWNER, KEY).expect("valid");
            let base = build_proposal(&body(), OWNER, KEY).expect("valid");
            assert_ne!(
                base["proposal_hash"], other["proposal_hash"],
                "changing '{field}' must change the commitment"
            );
        }
    }

    #[test]
    fn a_lineage_field_is_refused_by_its_own_cause_not_as_an_unknown_field() {
        for field in ["project_id", "placement_ref", "lease_ref", "recipe_ref"] {
            let mut with_lineage = body();
            with_lineage[field] = json!("x");
            let (_, Json(reply)) = build_proposal(&with_lineage, OWNER, KEY).unwrap_err();
            assert_eq!(
                reply["code"],
                json!("project_discovery_proposal_boundary_field"),
                "'{field}' must name the boundary, not read as an unrecognised field"
            );
        }
        let mut derived = body();
        derived["proposal_hash"] = json!("sha256:x");
        let (_, Json(reply)) = build_proposal(&derived, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_proposal_field_not_caller_authored")
        );
        let mut unknown = body();
        unknown["favourite_colour"] = json!("blue");
        let (_, Json(reply)) = build_proposal(&unknown, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_request_field_unknown")
        );
    }

    #[test]
    fn ambiguity_members_are_required_present_and_kept_verbatim() {
        for member in CANDIDATE_REQUIRED_REF_SETS {
            let mut stripped = body();
            let mut one = candidate("c1", 0.5);
            one.as_object_mut().unwrap().remove(*member);
            stripped["candidate_roots"] = json!([one]);
            let (_, Json(reply)) = build_proposal(&stripped, OWNER, KEY).unwrap_err();
            assert_eq!(
                reply["code"],
                json!("project_discovery_candidate_visibility_member_missing"),
                "'{member}' must be required PRESENT"
            );
        }
        let mut no_uncertainty = body();
        let mut one = candidate("c1", 0.5);
        one.as_object_mut().unwrap().remove("uncertainty");
        no_uncertainty["candidate_roots"] = json!([one]);
        let (_, Json(reply)) = build_proposal(&no_uncertainty, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_candidate_uncertainty_required")
        );
        // Verbatim: a candidate's declared conflicts survive admission unchanged.
        let mut conflicted = body();
        let mut one = candidate("c1", 0.5);
        one["conflict_refs"] = json!(["conflict://two-package-managers"]);
        conflicted["candidate_roots"] = json!([one]);
        let record = build_proposal(&conflicted, OWNER, KEY).expect("valid");
        assert_eq!(
            record["candidate_roots"][0]["conflict_refs"],
            json!(["conflict://two-package-managers"])
        );
    }

    #[test]
    fn a_duplicate_candidate_id_is_refused_because_acceptance_names_one() {
        let mut duplicated = body();
        duplicated["candidate_roots"] = json!([candidate("c1", 0.9), candidate("c1", 0.1)]);
        let (_, Json(reply)) = build_proposal(&duplicated, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_candidate_id_duplicated")
        );
    }

    #[test]
    fn confidence_is_bounded_and_required() {
        let mut missing = body();
        let mut one = candidate("c1", 0.5);
        one.as_object_mut().unwrap().remove("confidence");
        missing["candidate_roots"] = json!([one]);
        let (_, Json(reply)) = build_proposal(&missing, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_candidate_confidence_required")
        );
        let mut out_of_range = body();
        out_of_range["candidate_roots"] = json!([candidate("c1", 1.5)]);
        let (_, Json(reply)) = build_proposal(&out_of_range, OWNER, KEY).unwrap_err();
        assert_eq!(
            reply["code"],
            json!("project_discovery_candidate_confidence_out_of_range")
        );
    }

    #[test]
    fn the_override_vocabulary_matches_the_candidate_vocabulary() {
        // Every permitted override key overrides a `proposed_*` input a candidate can carry. A key
        // with nothing to override would admit a value no consumer could apply.
        for key in PERMITTED_OVERRIDE_KEYS {
            let proposed = format!("proposed_{key}");
            assert!(
                proposed == "proposed_project_kind"
                    || proposed == "proposed_stack_or_runtime"
                    || proposed == "proposed_root_ref"
                    || proposed == "proposed_initializer_inputs"
                    || proposed == "proposed_task_inputs"
                    || proposed == "proposed_service_inputs"
                    || proposed == "proposed_port_inputs"
                    || proposed == "proposed_dependency_inputs",
                "'{key}' has no candidate input to override"
            );
        }
    }

    #[test]
    fn the_proposal_declares_what_it_does_not_assert() {
        let record = build_proposal(&body(), OWNER, KEY).expect("valid");
        for nonclaim in PROPOSAL_NONCLAIMS {
            assert!(
                record["does_not_assert"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(nonclaim)),
                "the record must carry the '{nonclaim}' nonclaim"
            );
        }
    }
}
