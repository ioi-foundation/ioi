//! M10.4 — the governed evaluation plane: five registered families on the shared owner-scoped
//! mutation chain, and the model-swap continuity report derived over them.
//!
//! Canon: `components/hypervisor/evaluations.md` (the plane, its § Registered shapes and its
//! § Conformance Checks) and `foundry.md` § Model-Swap Continuity (the report). The epoch and its
//! exposure ledger stay M10.1's (`improvement_campaign_routes.rs`); this module READS them through
//! that module's published readers and writes only inside its own five families:
//!
//!   * `EvaluationSuiteRevision` — the declaration-only library suite (`eval-suite://`) frozen into
//!     an immutable, RELEASED revision an epoch or run can bind: every task carries its exact source
//!     commitment, so a mutable `latest` cannot enter; only a released revision is run-eligible.
//!   * `EvaluatorRevision` — a versioned, fallible judgment dependency: `evaluator_root` freezes what
//!     judges, and the validity lifecycle (draft → validated → released → active; challenged →
//!     degraded → invalidated; reverified; superseded / retired) is a projection appended around
//!     that root by exact-head successors. Invalidation appends lineage; the dependent set is a
//!     READ projection — old evidence bytes never move.
//!   * `EvaluationRun` — one ADMITTED execution against a frozen AND active epoch: the epoch's frozen
//!     roots are COPIED and re-derived (a caller-supplied root is refused), the suite revision must
//!     be released, the evaluator active, the policy-bound data-view revision current, every
//!     execution evidence ref resolved through its owner, and Search is never a submitter.
//!   * `EvaluationResult` — the immutable observation and its interpretation (the scorecard) as one
//!     record, with a DERIVED verdict floor: a missing required lane is at most `inconclusive`; an
//!     inactive evaluator, an unknown case or undeclared nondeterminism is `invalid`; exhausted
//!     exposure is `blocked`. A sealed-lane result names the exposure entry its protected access
//!     appended (M10.1's ledger is the ONE writer; this module resolves the entry, never appends).
//!     No promotion, nomination or activation member exists on any record here: a body carrying one
//!     is refused by name (`self_promotion_refused`) before the closed fence answers.
//!   * `ModelSwapContinuityReport` — DERIVED: baseline results bound to the incumbent route's own
//!     invocation receipts, candidate results bound to the candidate's, the incumbent's disablement
//!     read from the model-route registry before any candidate evidence is admitted, per-dimension
//!     deltas and the threshold verdict from the declared equivalence envelope. It grants no
//!     authority.
//!
//! THE LAYER LAW. Evaluations is a Hypervisor component; this module imports nothing from the
//! ioi.ai goal-orchestration application, and the gate asserts so. `VerifierChallenge` (a
//! challenge against a Finding) is the application's family and is not this plane's challenge.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::improvement_campaign_routes::{
    epochs_naming_evaluator, resolve_admitted_epoch_binding, resolve_exposure_entry,
};
use super::institutional_learning_boundary_routes::resolve_admitted_boundary_profile;
use super::model_route_rights_routes::{
    authorized_stream, bad, body_str, digest_over, family_token, finish_admission, head_assertion,
    parse_revision_ref, read_stream, reject_authored, replay_for_key, require_exact_head,
    AdmittedRecord, FamilySpec, Reply,
};
use super::model_routes::{canonical_value_hash, load_route_record};
use super::mutation_event_foundation::{
    admitted_stamp, require_write_caller, scope_refusal_reply, WriteCaller,
};
use super::policy_bound_data_view_revision_routes::resolve_admitted_policy_bound_data_view;
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, engine_domain_roots, resolve_request_identity, RequestIdentity,
    RequestResourceScope,
};
use super::{read_record_dir, DaemonState};

// ================================================================================ commitment domains

const SUITE_DOMAIN: &str = "ioi.evaluation-suite-revision-content-commitment-jcs-sha256.v1";
const EVALUATOR_ROOT_DOMAIN: &str = "ioi.evaluator-revision-frozen-root-jcs-sha256.v1";
const EVALUATOR_DOMAIN: &str = "ioi.evaluator-revision-content-commitment-jcs-sha256.v1";
const RUN_DOMAIN: &str = "ioi.evaluation-run-content-commitment-jcs-sha256.v1";
const RESULT_DOMAIN: &str = "ioi.evaluation-result-content-commitment-jcs-sha256.v1";
const REPORT_DOMAIN: &str = "ioi.model-swap-continuity-report-content-commitment-jcs-sha256.v1";
/// The institutional state root the report freezes: the substrate engine's per-domain roots.
const STATE_ROOT_DOMAIN: &str = "ioi.institutional-state-root-jcs-sha256.v1";

const MAX_REVISION: u64 = 1_000_000_000;
const MAX_UNITS: u64 = 1_000_000_000;
const MAX_SEED: u64 = 1_000_000_000_000;
const MAX_TASKS: usize = 4096;
const MAX_OBSERVATIONS: usize = 4096;
const MAX_EVIDENCE: usize = 256;
const MAX_RESULT_REFS: usize = 256;

pub(crate) const LANES: &[&str] = &[
    "visible",
    "sealed",
    "transfer_ood",
    "adversarial",
    "cross_play_ablation",
    "external_reality",
    "production_acceptance",
    "independent_reproduction",
];
const NONDETERMINISM_CLASSES: &[&str] = &["deterministic", "seeded", "declared_nondeterministic"];
const COST_CLASSES: &[&str] = &[
    "negligible",
    "sublinear",
    "comparable",
    "superlinear",
    "unverifiable_at_price",
];
const EVALUATOR_KINDS: &[&str] = &[
    "scorer",
    "judge",
    "rubric_scorer",
    "simulator",
    "formal_verifier",
    "human_panel",
    "reproduction_harness",
];
const VALIDITY_STATUSES: &[&str] = &[
    "draft",
    "validated",
    "released",
    "active",
    "challenged",
    "degraded",
    "invalidated",
    "reverified",
    "superseded",
    "retired",
];
const SUBMITTER_ROLES: &[&str] = &["evaluator", "target_owner", "independent_reproducer"];
const VERDICTS: &[&str] = &["pass", "fail", "inconclusive", "blocked", "invalid"];
const COST_UNITS: &[&str] = &["tokens", "usd_micros", "seconds", "units"];
const UNCERTAINTY_METHODS: &[&str] = &[
    "fixed_test",
    "sequential",
    "anytime_valid",
    "bayesian",
    "frequentist",
    "ranking",
    "human_judgment",
    "simulation",
    "formal_verification",
    "domain_acceptance",
];
const OUTCOMES: &[&str] = &["pass", "fail", "error", "skipped"];
const SEMANTIC_RULES: &[&str] = &["exact_match", "rubric_scored", "declared_equivalence_class"];
const FAILURE_RULES: &[&str] = &["identical", "no_new_failure_classes", "declared"];
const AUTHORITY_NOTE: &str = "grants no authority; proves continuity only for the declared task and eval envelope; a matching model name or a single score is not model independence";

/// Members that would make an evaluation record decide something. Canon: Evaluations cannot
/// nominate a campaign winner, issue an UpgradeDecision, or activate, roll back or recall production
/// state — so a body carrying one of these is refused BY NAME, before the closed fence answers.
const SELF_PROMOTION_MEMBERS: &[&str] = &[
    "promotion_decision",
    "nominate",
    "nomination",
    "activate",
    "activation",
    "upgrade_decision",
    "upgrade_proposal_ref",
    "rollback",
    "recall",
];

// ======================================================================================== families

const SUITE_MATERIAL: &[&str] = &[
    "schema_version",
    "evaluation_suite_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "owner_ref",
    "library_suite_ref",
    "tasks",
    "scorer_revision_refs",
    "rubric_refs",
    "world_refs",
    "required_lanes",
    "nondeterminism_class",
    "declared_seed_policy_ref",
    "verification_cost_class",
];

static SUITE: FamilySpec = FamilySpec {
    owner_namespace: "evaluation-suites",
    resource_kind: "evaluation_suite_revision",
    admit_op: "event_stream.evaluation_suite_revision_admitted",
    payload_schema: "ioi.hypervisor.evaluation-suite-revision-admission.v1",
    contract_id: "schema://ioi/components/hypervisor/evaluation-suite-revision/v1",
    schema_version: "ioi.evaluation-suite-revision.v1",
    record_key: "evaluation_suite_revision_record",
    code_prefix: "evaluation_suite_revision",
    commitment_domain: SUITE_DOMAIN,
    material_fields: SUITE_MATERIAL,
    identity_field: "revision_ref",
    ref_scheme: "evaluation-suite://",
    stamp_field: "admitted_at",
};

const EVALUATOR_FROZEN: &[&str] = &[
    "schema_version",
    "evaluator_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "owner_ref",
    "evaluator_kind",
    "implementation_ref",
    "affiliation_ref",
    "custodian_ref",
];
const EVALUATOR_MATERIAL: &[&str] = &[
    "schema_version",
    "evaluator_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "owner_ref",
    "evaluator_kind",
    "implementation_ref",
    "affiliation_ref",
    "custodian_ref",
    "evaluator_root",
    "validity_status",
    "validity_decision_ref",
    "challenge_refs",
    "impact_disposition_ref",
];

static EVALUATOR: FamilySpec = FamilySpec {
    owner_namespace: "evaluators",
    resource_kind: "evaluator_revision",
    admit_op: "event_stream.evaluator_revision_admitted",
    payload_schema: "ioi.hypervisor.evaluator-revision-admission.v1",
    contract_id: "schema://ioi/components/hypervisor/evaluator-revision/v1",
    schema_version: "ioi.evaluator-revision.v1",
    record_key: "evaluator_revision_record",
    code_prefix: "evaluator_revision",
    commitment_domain: EVALUATOR_DOMAIN,
    material_fields: EVALUATOR_MATERIAL,
    identity_field: "revision_ref",
    ref_scheme: "evaluator://",
    stamp_field: "admitted_at",
};

const RUN_MATERIAL: &[&str] = &[
    "schema_version",
    "evaluation_run_id",
    "owner_ref",
    "evaluation_epoch_ref",
    "epoch_frozen_root",
    "suite_revision_ref",
    "evaluator_revision_ref",
    "lane",
    "incumbent_ref",
    "incumbent_root",
    "target_base_root",
    "execution_evidence_refs",
    "policy_bound_data_view_revision_ref",
    "nondeterminism_class",
    "seed",
    "submitter_role",
    "cost_units",
    "cost_unit",
];

static RUN: FamilySpec = FamilySpec {
    owner_namespace: "evaluation-runs",
    resource_kind: "evaluation_run",
    admit_op: "event_stream.evaluation_run_admitted",
    payload_schema: "ioi.hypervisor.evaluation-run-admission.v1",
    contract_id: "schema://ioi/components/hypervisor/evaluation-run/v1",
    schema_version: "ioi.evaluation-run.v1",
    record_key: "evaluation_run_record",
    code_prefix: "evaluation_run",
    commitment_domain: RUN_DOMAIN,
    material_fields: RUN_MATERIAL,
    identity_field: "evaluation_run_id",
    ref_scheme: "evaluation-run://",
    stamp_field: "admitted_at",
};

const RESULT_MATERIAL: &[&str] = &[
    "schema_version",
    "evaluation_result_id",
    "owner_ref",
    "evaluation_run_ref",
    "evaluation_epoch_ref",
    "epoch_frozen_root",
    "suite_revision_ref",
    "evaluator_revision_ref",
    "lane",
    "observations",
    "verdict",
    "verdict_basis",
    "uncertainty",
    "guardrail_findings",
    "applicability_scope",
    "cost_units",
    "cost_unit",
    "failures",
    "evaluator_versions",
    "exposure_entry_ref",
];

static RESULT: FamilySpec = FamilySpec {
    owner_namespace: "evaluation-results",
    resource_kind: "evaluation_result",
    admit_op: "event_stream.evaluation_result_admitted",
    payload_schema: "ioi.hypervisor.evaluation-result-admission.v1",
    contract_id: "schema://ioi/components/hypervisor/evaluation-result/v1",
    schema_version: "ioi.evaluation-result.v1",
    record_key: "evaluation_result_record",
    code_prefix: "evaluation_result",
    commitment_domain: RESULT_DOMAIN,
    material_fields: RESULT_MATERIAL,
    identity_field: "evaluation_result_id",
    ref_scheme: "evaluation-result://",
    stamp_field: "admitted_at",
};

const REPORT_MATERIAL: &[&str] = &[
    "schema_version",
    "model_swap_continuity_report_id",
    "owner_ref",
    "evaluation_epoch_ref",
    "epoch_frozen_root",
    "suite_revision_ref",
    "institutional_state_root",
    "policy_bound_data_view_revision_ref",
    "learning_boundary_profile_ref",
    "incumbent_route_ref",
    "incumbent_route_record_hash",
    "incumbent_disabled_evidence",
    "candidate_route_ref",
    "candidate_route_record_hash",
    "baseline_result_refs",
    "candidate_result_refs",
    "equivalence_envelope",
    "observed_deltas",
    "unsupported_dependencies",
    "threshold_verdict",
    "canary_refs",
    "rollback_refs",
    "authority_note",
];

static REPORT: FamilySpec = FamilySpec {
    owner_namespace: "model-swap-continuity-reports",
    resource_kind: "model_swap_continuity_report",
    admit_op: "event_stream.model_swap_continuity_report_admitted",
    payload_schema: "ioi.hypervisor.model-swap-continuity-report-admission.v1",
    contract_id: "schema://ioi/components/hypervisor/model-swap-continuity-report/v1",
    schema_version: "ioi.model-swap-continuity-report.v1",
    record_key: "model_swap_continuity_report_record",
    code_prefix: "model_swap_continuity_report",
    commitment_domain: REPORT_DOMAIN,
    material_fields: REPORT_MATERIAL,
    identity_field: "model_swap_continuity_report_id",
    ref_scheme: "model-swap-continuity-report://",
    stamp_field: "admitted_at",
};

// ======================================================================================== helpers

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or_default()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn integer(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn strings(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::from(item.as_str()))
            .collect(),
    )
}

fn nullable_text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn owner_scheme_supported(owner_ref: &str) -> bool {
    ["org://", "user://", "project://", "system://"]
        .iter()
        .any(|scheme| owner_ref.starts_with(scheme))
        && owner_ref.len() <= 200
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// A closed request-field fence: a member this route does not read is refused by name rather
/// than dropped.
fn refuse_unknown_fields(body: &Value, spec: &FamilySpec, allowed: &[&str]) -> Result<(), Reply> {
    let Some(object) = body.as_object() else {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &spec.code("request_body_not_object"),
            "the request body must be a JSON object",
        ));
    };
    let permitted: BTreeSet<&str> = allowed.iter().copied().collect();
    let unknown: Vec<String> = object
        .keys()
        .filter(|key| !permitted.contains(key.as_str()))
        .cloned()
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    Err(bad(
        StatusCode::BAD_REQUEST,
        &spec.code("request_unknown_field"),
        format!(
            "this route does not admit field(s): {}; a server-resolved member is asserted through its expected_* twin, never authored",
            unknown.join(", ")
        ),
    ))
}

/// Canon: Evaluations emits evidence and decides nothing. A body that tries to make a run, a
/// result or a report decide is refused by the member's own name — before the closed fence, so the
/// caller learns WHAT it tried to author.
fn refuse_self_promotion(body: &Value, spec: &FamilySpec) -> Result<(), Reply> {
    for member in SELF_PROMOTION_MEMBERS {
        if body.get(*member).is_some() {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "self_promotion_refused",
                format!(
                    "`{member}` is not a member of any {}: Evaluations cannot nominate a candidate, issue an upgrade decision, or activate, roll back or recall production state — it emits evidence; Governance and the target owner decide",
                    spec.resource_kind
                ),
            ));
        }
    }
    Ok(())
}

struct WriteContext {
    caller: WriteCaller,
    scope: RequestResourceScope,
    resource: String,
    stream: Vec<AdmittedRecord>,
    expected_head: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn open_write(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    spec: &'static FamilySpec,
    resource: String,
    allowed: &[&str],
    authored: &[&str],
    genesis: Option<&'static str>,
    reply_key: &'static str,
) -> Result<WriteContext, Reply> {
    let caller = require_write_caller(&st.data_dir, headers, body)?;
    if !owner_scheme_supported(&caller.owner_ref) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &spec.code("owner_scheme_unsupported"),
            "this family admits an owner in org://, user://, project:// or system://",
        ));
    }
    refuse_self_promotion(body, spec)?;
    reject_authored(body, spec, authored)?;
    refuse_unknown_fields(body, spec, allowed)?;
    let scope = if genesis.is_some() {
        bind_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            spec.resource_kind,
            &resource,
            &caller.owner_ref,
            &caller.owner_ref,
            &caller.idempotency_key,
        )
        .map_err(scope_refusal_reply)?
    } else {
        authorize_request_resource_scope(
            &st.data_dir,
            &caller.identity,
            spec.resource_kind,
            &resource,
            Some(caller.owner_ref.as_str()),
        )
        .map_err(scope_refusal_reply)?
    };
    let stream = read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource)?;
    if let Some(reply) = replay_for_key(spec, st, &caller, &scope, &resource, &stream, reply_key)? {
        return Err(reply);
    }
    // A genesis route on a stream that already exists is refused by the FAMILY fact, before the
    // head compare-and-swap can answer with a bare conflict; a successor route on an empty stream
    // is refused as absent for the same reason. Replay runs first, so a retried genesis key still
    // resolves to the record it admitted.
    match genesis {
        Some(conflict) if !stream.is_empty() => {
            return Err(bad(
                StatusCode::CONFLICT,
                &spec.code(conflict),
                format!(
                    "{} {} already has admissions; a successor extends it through its own route",
                    spec.resource_kind, resource
                ),
            ));
        }
        None if stream.is_empty() => {
            return Err(bad(
                StatusCode::NOT_FOUND,
                &spec.code("absent"),
                format!(
                    "no {} answers to {resource}; create it first",
                    spec.resource_kind
                ),
            ));
        }
        _ => {}
    }
    let expected_head = head_assertion(body, spec.code_prefix)?;
    require_exact_head(&stream, &expected_head, spec.code_prefix)?;
    Ok(WriteContext {
        caller,
        scope,
        resource,
        stream,
        expected_head,
    })
}

fn read_family(
    st: &DaemonState,
    headers: &HeaderMap,
    spec: &'static FamilySpec,
    resource: &str,
) -> Result<(RequestIdentity, Vec<AdmittedRecord>), Reply> {
    let identity = resolve_request_identity(&st.data_dir, headers).map_err(scope_refusal_reply)?;
    let stream = authorized_stream(spec, &st.data_dir, &identity, resource)?;
    Ok((identity, stream))
}

/// The refs of every resource of a family that HOLDS an admission. A scope pinned by a genesis
/// whose validation then refused is not a record and is not listed.
fn inventory(st: &DaemonState, headers: &HeaderMap, spec: &'static FamilySpec, key: &str) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let refs = match authorized_request_resource_refs(&st.data_dir, &identity, spec.resource_kind) {
        Ok(refs) => refs,
        Err(error) => return scope_refusal_reply(error),
    };
    let mut held = Vec::new();
    for resource in refs {
        match authorized_stream(spec, &st.data_dir, &identity, &resource) {
            Ok(stream) if !stream.is_empty() => held.push(resource),
            Ok(_) => {}
            Err(response) => return response,
        }
    }
    (StatusCode::OK, Json(json!({ "ok": true, key: held })))
}

fn family_resource(spec: &FamilySpec, family: &str) -> Result<String, Reply> {
    if !family_token(family) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            &spec.code("family_not_canonical"),
            "the family is the lineage token this record extends: [a-z0-9][a-z0-9._-]{0,127}",
        ));
    }
    Ok(format!("{}{family}", spec.ref_scheme))
}

fn projection(spec: &FamilySpec, stream: &[AdmittedRecord], key: &str, extra: Value) -> Value {
    let head = stream.last().map(|entry| entry.head.clone());
    let mut body = json!({
        "ok": true,
        key: stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
        "head": head,
        "current": stream.last().map(|entry| entry.record.clone()),
        "family": spec.resource_kind,
    });
    if let (Some(target), Some(source)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in source {
            target.insert(k.clone(), v.clone());
        }
    }
    body
}

/// The current heads of every resource of a family the caller may see.
fn family_heads(
    st: &DaemonState,
    identity: &RequestIdentity,
    spec: &'static FamilySpec,
) -> Result<Vec<Value>, Reply> {
    let refs = authorized_request_resource_refs(&st.data_dir, identity, spec.resource_kind)
        .map_err(scope_refusal_reply)?;
    let mut heads = Vec::new();
    for resource in refs {
        let stream = authorized_stream(spec, &st.data_dir, identity, &resource)?;
        if let Some(entry) = stream.last() {
            heads.push(entry.record.clone());
        }
    }
    heads.sort_by(|a, b| text(a, spec.identity_field).cmp(&text(b, spec.identity_field)));
    Ok(heads)
}

/// A stream's revisions, ordered by ordinal, each at its CURRENT record: a lifecycle transition
/// is a successor admission of the same ordinal, so the last entry carrying an ordinal is the
/// truth about that revision and the earlier entries are its lineage.
fn revisions(stream: &[AdmittedRecord]) -> Vec<(u64, Value)> {
    let mut current: BTreeMap<u64, Value> = BTreeMap::new();
    for entry in stream {
        if let Some(n) = integer(&entry.record, "revision") {
            current.insert(n, entry.record.clone());
        }
    }
    current.into_iter().collect()
}

// ================================================================================ suite revisions

const SUITE_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "family",
    "library_suite_ref",
    "tasks",
    "scorer_revision_refs",
    "rubric_refs",
    "world_refs",
    "required_lanes",
    "nondeterminism_class",
    "declared_seed_policy_ref",
    "verification_cost_class",
];
const SUITE_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluation_suite_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "content_hash",
    "release_decision_ref",
    "registry_status",
    "admitted_at",
];
const SUITE_RELEASE_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "release_decision_ref",
];
/// What a release may not author: the server-resolved members minus the decision it names.
const SUITE_RELEASE_AUTHORED: &[&str] = &[
    "schema_version",
    "evaluation_suite_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "content_hash",
    "registry_status",
    "admitted_at",
];

/// Resolve a suite revision ref to its admitted record (any status) under the caller's identity.
fn resolve_suite_revision(
    st: &DaemonState,
    identity: &RequestIdentity,
    revision_ref: &str,
) -> Result<Value, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(SUITE.ref_scheme, revision_ref) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "mutable_latest_refused",
            "a run or epoch binds an evaluation-suite REVISION (evaluation-suite://{family}/revision/{n}); a family head is the mutable `latest` canon forbids as promotion evidence",
        ));
    };
    let resource = format!("{}{family}", SUITE.ref_scheme);
    let stream = authorized_stream(&SUITE, &st.data_dir, identity, &resource)?;
    let Some((_, record)) = revisions(&stream).into_iter().find(|(n, _)| *n == ordinal) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &SUITE.code("revision_absent"),
            format!("no evaluation-suite revision answers to {revision_ref}"),
        ));
    };
    Ok(record)
}

/// Resolve an evaluator revision ref to the CURRENT record of that revision (validity moves by
/// successor admissions of the same revision ordinal, so the latest entry with that ordinal is the
/// truth about it).
fn resolve_evaluator_revision(
    st: &DaemonState,
    identity: &RequestIdentity,
    revision_ref: &str,
) -> Result<Value, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(EVALUATOR.ref_scheme, revision_ref) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EVALUATOR.code("revision_ref_not_canonical"),
            "an evaluator is bound by REVISION (evaluator://{family}/revision/{n}), never by family head",
        ));
    };
    let resource = format!("{}{family}", EVALUATOR.ref_scheme);
    let stream = authorized_stream(&EVALUATOR, &st.data_dir, identity, &resource)?;
    let Some(record) = stream
        .iter()
        .rev()
        .map(|entry| entry.record.clone())
        .find(|record| integer(record, "revision") == Some(ordinal))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("revision_absent"),
            format!("no evaluator revision answers to {revision_ref}"),
        ));
    };
    Ok(record)
}

fn validate_suite_body(
    st: &DaemonState,
    identity: &RequestIdentity,
    body: &Value,
) -> Result<Value, Reply> {
    let library = body_str(body, "library_suite_ref");
    if !library.starts_with("eval-suite://") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("library_suite_required"),
            "a suite revision freezes one declaration-only library suite (eval-suite://…)",
        ));
    }
    let library_exists = read_record_dir(&st.data_dir, "eval-suites")
        .iter()
        .any(|record| text(record, "ref") == library);
    if !library_exists {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("library_suite_unresolvable"),
            format!("{library} is not a declared eval suite in this deployment's library"),
        ));
    }
    let Some(tasks) = body.get("tasks").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("tasks_required"),
            "a suite revision freezes at least one task, each bound to its exact source commitment",
        ));
    };
    if tasks.is_empty() || tasks.len() > MAX_TASKS {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("tasks_required"),
            format!("a suite revision freezes 1..={MAX_TASKS} tasks"),
        ));
    }
    let mut frozen_tasks = Vec::new();
    for task in tasks {
        let task_ref = text(task, "task_ref");
        let commitment = text(task, "source_commitment");
        if !(task_ref.starts_with("dataset://") || task_ref.starts_with("artifact://")) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("task_ref_not_canonical"),
                "a task is a Data-owned dataset (dataset://…) or a content-addressed artifact (artifact://…), consumed by exact ref",
            ));
        }
        if !is_sha256(&commitment) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "mutable_latest_refused",
                format!("task {task_ref} carries no source_commitment: a task without its exact source commitment is the mutable `latest` canon forbids"),
            ));
        }
        frozen_tasks.push(json!({ "task_ref": task_ref, "source_commitment": commitment }));
    }
    let scorers = list(body, "scorer_revision_refs");
    for scorer in &scorers {
        resolve_evaluator_revision(st, identity, scorer).map_err(|reply| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("scorer_unresolvable"),
                format!(
                    "scorer {scorer} does not resolve to an evaluator revision ({})",
                    reply
                        .1
                         .0
                        .pointer("/error/code")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                ),
            )
        })?;
    }
    let lanes = list(body, "required_lanes");
    if lanes.is_empty() || lanes.len() > LANES.len() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("required_lanes_required"),
            "a suite revision declares which lanes its claim requires (1..=8, from canon's portfolio)",
        ));
    }
    let mut seen = BTreeSet::new();
    for lane in &lanes {
        if !LANES.contains(&lane.as_str()) || !seen.insert(lane.clone()) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("lane_outside_vocabulary"),
                format!("required_lanes are unique members of {}", LANES.join(" | ")),
            ));
        }
    }
    let nondeterminism = body_str(body, "nondeterminism_class");
    if !NONDETERMINISM_CLASSES.contains(&nondeterminism.as_str()) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("nondeterminism_class_outside_vocabulary"),
            "nondeterminism_class is deterministic | seeded | declared_nondeterministic",
        ));
    }
    let seed_policy = nullable_text(body, "declared_seed_policy_ref");
    if nondeterminism == "seeded" && seed_policy.is_none() {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("seed_policy_required"),
            "a seeded suite declares the policy its seeds are drawn under",
        ));
    }
    if let Some(policy) = &seed_policy {
        if !policy.starts_with("policy://") {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("seed_policy_not_canonical"),
                "declared_seed_policy_ref is a policy:// ref",
            ));
        }
    }
    let cost_class = body_str(body, "verification_cost_class");
    if !COST_CLASSES.contains(&cost_class.as_str()) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("verification_cost_class_outside_vocabulary"),
            format!(
                "verification_cost_class is one of {}",
                COST_CLASSES.join(" | ")
            ),
        ));
    }
    for rubric in list(body, "rubric_refs") {
        if !rubric.starts_with("rubric://") {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("rubric_ref_not_canonical"),
                "rubric_refs are rubric:// refs",
            ));
        }
    }
    for world in list(body, "world_refs") {
        if !(world.starts_with("artifact://") || world.starts_with("environment-class://")) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &SUITE.code("world_ref_not_canonical"),
                "world_refs are artifact:// or environment-class:// refs",
            ));
        }
    }
    Ok(json!({
        "library_suite_ref": library,
        "tasks": frozen_tasks,
        "scorer_revision_refs": strings(&scorers),
        "rubric_refs": strings(&list(body, "rubric_refs")),
        "world_refs": strings(&list(body, "world_refs")),
        "required_lanes": strings(&lanes),
        "nondeterminism_class": nondeterminism,
        "declared_seed_policy_ref": seed_policy,
        "verification_cost_class": cost_class,
    }))
}

fn admit_suite_revision(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    family: String,
    genesis: bool,
) -> Reply {
    let resource = match family_resource(&SUITE, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        st,
        headers,
        body,
        &SUITE,
        resource,
        SUITE_REQUEST_FIELDS,
        SUITE_SERVER_RESOLVED,
        genesis.then_some("family_already_exists"),
        "evaluation_suite_revision",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if genesis && (ctx.expected_head.is_some() || !ctx.stream.is_empty()) {
        return bad(
            StatusCode::CONFLICT,
            &SUITE.code("family_already_exists"),
            "a suite family is created once; later revisions extend it through POST …/revisions",
        );
    }
    if !genesis && ctx.stream.is_empty() {
        return bad(
            StatusCode::NOT_FOUND,
            &SUITE.code("absent"),
            "no suite family answers to that token; create it first",
        );
    }
    let frozen = match validate_suite_body(st, &ctx.caller.identity, body) {
        Ok(frozen) => frozen,
        Err(response) => return response,
    };
    let held = revisions(&ctx.stream);
    let (revision, predecessor) = match held.last() {
        Some((n, prior)) => (n + 1, Some(text(prior, "revision_ref"))),
        None => (1, None),
    };
    if revision > MAX_REVISION {
        return bad(
            StatusCode::CONFLICT,
            &SUITE.code("revision_out_of_domain"),
            "revision ordinals are bounded 1..=1000000000",
        );
    }
    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": SUITE.schema_version,
        "evaluation_suite_id": ctx.resource,
        "revision_ref": format!("{}/revision/{revision}", ctx.resource),
        "revision": revision,
        "predecessor_revision_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "release_decision_ref": Value::Null,
        "registry_status": "draft",
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    if let (Some(target), Some(source)) = (record.as_object_mut(), frozen.as_object()) {
        for (k, v) in source {
            target.insert(k.clone(), v.clone());
        }
    }
    finish_admission(
        &SUITE,
        st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_suite_revision",
        record,
        ctx.expected_head,
        recorded_at_ms,
        body,
        json!({}),
    )
}

pub(crate) async fn handle_suite_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    admit_suite_revision(&st, &headers, &body, family, true)
}

pub(crate) async fn handle_suite_revise(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    admit_suite_revision(&st, &headers, &body, family, false)
}

pub(crate) async fn handle_suite_release(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((family, revision)): Path<(String, u64)>,
    Json(body): Json<Value>,
) -> Reply {
    let resource = match family_resource(&SUITE, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &SUITE,
        resource,
        SUITE_RELEASE_FIELDS,
        SUITE_RELEASE_AUTHORED,
        None,
        "evaluation_suite_revision",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some((_, prior)) = revisions(&ctx.stream)
        .into_iter()
        .find(|(held, _)| *held == revision)
    else {
        return bad(
            StatusCode::NOT_FOUND,
            &SUITE.code("revision_absent"),
            format!("this suite family has no revision {revision}"),
        );
    };
    if text(&prior, "registry_status") == "released" {
        return bad(
            StatusCode::CONFLICT,
            &SUITE.code("already_released"),
            "this revision is already released; a release is not repeated",
        );
    }
    let decision = body_str(&body, "release_decision_ref");
    if !decision.starts_with("decision://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &SUITE.code("release_decision_required"),
            "a release names the decision:// that released it; a status nobody decided is a projection nobody made",
        );
    }
    let recorded_at_ms = now_ms();
    let mut record = prior;
    record["release_decision_ref"] = json!(decision);
    record["registry_status"] = json!("released");
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    finish_admission(
        &SUITE,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_suite_revision",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_suite_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &SUITE, "evaluation_suites")
}

pub(crate) async fn handle_suite_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&SUITE, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    match read_family(&st, &headers, &SUITE, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &SUITE.code("absent"),
            "no suite family answers to that token",
        ),
        Ok((_, stream)) => {
            let released: Vec<Value> = revisions(&stream)
                .into_iter()
                .filter(|(_, record)| text(record, "registry_status") == "released")
                .map(|(_, record)| json!(text(&record, "revision_ref")))
                .collect();
            (
                StatusCode::OK,
                Json(projection(
                    &SUITE,
                    &stream,
                    "revisions",
                    json!({ "released_revision_refs": released }),
                )),
            )
        }
        Err(response) => response,
    }
}

// ================================================================================ evaluators

const EVALUATOR_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "family",
    "evaluator_kind",
    "implementation_ref",
    "affiliation_ref",
    "custodian_ref",
];
const EVALUATOR_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluator_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "evaluator_root",
    "content_hash",
    "validity_status",
    "validity_decision_ref",
    "challenge_refs",
    "impact_disposition_ref",
    "admitted_at",
];
const EVALUATOR_TRANSITION_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "validity_decision_ref",
    "challenge_refs",
    "impact_disposition_ref",
];
/// What a transition may not author: the frozen members, the root, the hash and the status the
/// verb itself decides; the decision, evidence and disposition it names are its own to carry.
const EVALUATOR_TRANSITION_AUTHORED: &[&str] = &[
    "schema_version",
    "evaluator_id",
    "revision_ref",
    "revision",
    "predecessor_revision_ref",
    "evaluator_root",
    "content_hash",
    "validity_status",
    "admitted_at",
];

fn validate_evaluator_body(st: &DaemonState, body: &Value) -> Result<Value, Reply> {
    let kind = body_str(body, "evaluator_kind");
    if !EVALUATOR_KINDS.contains(&kind.as_str()) {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EVALUATOR.code("kind_outside_vocabulary"),
            format!("evaluator_kind is one of {}", EVALUATOR_KINDS.join(" | ")),
        ));
    }
    let implementation = body_str(body, "implementation_ref");
    if let Some(route_id) = implementation.strip_prefix("model-route:") {
        if load_route_record(&st.data_dir, route_id).is_none() {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &EVALUATOR.code("implementation_unresolvable"),
                format!(
                    "{implementation} is not a route in this deployment's model-route registry"
                ),
            ));
        }
    } else if !implementation.starts_with("artifact://") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EVALUATOR.code("implementation_ref_not_canonical"),
            "implementation_ref is a content-addressed artifact (artifact://…) or a registered model route (model-route:…)",
        ));
    }
    for key in ["affiliation_ref", "custodian_ref"] {
        if let Some(value) = nullable_text(body, key) {
            if !owner_scheme_supported(&value) {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &EVALUATOR.code("affiliation_not_canonical"),
                    format!("{key} is an org://, user://, project:// or system:// ref, or null"),
                ));
            }
        }
    }
    Ok(json!({
        "evaluator_kind": kind,
        "implementation_ref": implementation,
        "affiliation_ref": nullable_text(body, "affiliation_ref"),
        "custodian_ref": nullable_text(body, "custodian_ref"),
    }))
}

fn admit_evaluator_revision(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    family: String,
    genesis: bool,
) -> Reply {
    let resource = match family_resource(&EVALUATOR, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        st,
        headers,
        body,
        &EVALUATOR,
        resource,
        EVALUATOR_REQUEST_FIELDS,
        EVALUATOR_SERVER_RESOLVED,
        genesis.then_some("family_already_exists"),
        "evaluator_revision",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if genesis && (ctx.expected_head.is_some() || !ctx.stream.is_empty()) {
        return bad(
            StatusCode::CONFLICT,
            &EVALUATOR.code("family_already_exists"),
            "an evaluator family is created once; later revisions extend it through POST …/revisions",
        );
    }
    if !genesis && ctx.stream.is_empty() {
        return bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("absent"),
            "no evaluator family answers to that token; create it first",
        );
    }
    let frozen = match validate_evaluator_body(st, body) {
        Ok(frozen) => frozen,
        Err(response) => return response,
    };
    let held = revisions(&ctx.stream);
    let (revision, predecessor) = match held.last() {
        Some((n, prior)) => (n + 1, Some(text(prior, "revision_ref"))),
        None => (1, None),
    };
    if revision > MAX_REVISION {
        return bad(
            StatusCode::CONFLICT,
            &EVALUATOR.code("revision_out_of_domain"),
            "revision ordinals are bounded 1..=1000000000",
        );
    }
    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": EVALUATOR.schema_version,
        "evaluator_id": ctx.resource,
        "revision_ref": format!("{}/revision/{revision}", ctx.resource),
        "revision": revision,
        "predecessor_revision_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "validity_status": "draft",
        "validity_decision_ref": Value::Null,
        "challenge_refs": [],
        "impact_disposition_ref": Value::Null,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    if let (Some(target), Some(source)) = (record.as_object_mut(), frozen.as_object()) {
        for (k, v) in source {
            target.insert(k.clone(), v.clone());
        }
    }
    let root = match digest_over(&record, EVALUATOR_ROOT_DOMAIN, EVALUATOR_FROZEN) {
        Ok(root) => root,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &EVALUATOR.code("root_failed"),
                reason,
            )
        }
    };
    record["evaluator_root"] = json!(root);
    finish_admission(
        &EVALUATOR,
        st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluator_revision",
        record,
        ctx.expected_head,
        recorded_at_ms,
        body,
        json!({}),
    )
}

pub(crate) async fn handle_evaluator_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    admit_evaluator_revision(&st, &headers, &body, family, true)
}

pub(crate) async fn handle_evaluator_revise(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    admit_evaluator_revision(&st, &headers, &body, family, false)
}

/// Canon's validity diagram (evaluations.md § Evaluator Validity And Challenges), verb by verb:
/// the statuses each verb may leave from and the status it enters.
fn validity_edge(verb: &str) -> Option<(&'static [&'static str], &'static str)> {
    Some(match verb {
        "validate" => (&["draft"], "validated"),
        "release" => (&["validated"], "released"),
        "activate" => (&["released", "reverified"], "active"),
        "challenge" => (&["released", "active"], "challenged"),
        "degrade" => (&["challenged"], "degraded"),
        "invalidate" => (&["challenged", "degraded"], "invalidated"),
        "reverify" => (&["challenged", "degraded"], "reverified"),
        "supersede" => (&["active", "reverified", "invalidated"], "superseded"),
        "retire" => (
            &[
                "draft",
                "validated",
                "released",
                "active",
                "challenged",
                "degraded",
                "invalidated",
                "reverified",
                "superseded",
            ],
            "retired",
        ),
        _ => return None,
    })
}

pub(crate) async fn handle_evaluator_transition(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((family, verb)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let Some((from, to)) = validity_edge(&verb) else {
        return bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("transition_unknown"),
            "the validity transitions are validate | release | activate | challenge | degrade | invalidate | reverify | supersede | retire",
        );
    };
    let resource = match family_resource(&EVALUATOR, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &EVALUATOR,
        resource,
        EVALUATOR_TRANSITION_FIELDS,
        EVALUATOR_TRANSITION_AUTHORED,
        None,
        "evaluator_revision",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some(prior) = ctx.stream.last().map(|entry| entry.record.clone()) else {
        return bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("absent"),
            "no evaluator family answers to that token",
        );
    };
    let status = text(&prior, "validity_status");
    if !from.contains(&status.as_str()) {
        return bad(
            StatusCode::CONFLICT,
            &EVALUATOR.code("validity_transition_invalid"),
            format!("'{verb}' leaves from one of {from:?}; this evaluator is {status}"),
        );
    }
    let decision = body_str(&body, "validity_decision_ref");
    if !decision.starts_with("decision://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EVALUATOR.code("validity_decision_required"),
            "a validity transition names the decision:// that made it",
        );
    }
    let mut challenge_refs = list(&prior, "challenge_refs");
    if matches!(verb.as_str(), "challenge" | "degrade" | "invalidate") {
        let evidence = list(&body, "challenge_refs");
        if evidence.is_empty() {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &EVALUATOR.code("challenge_evidence_required"),
                "a challenge, degradation or invalidation appends linked evidence (receipt:// or decision://); a challenge is not the deletion of inconvenient evidence",
            );
        }
        for item in &evidence {
            if !(item.starts_with("receipt://") || item.starts_with("decision://")) {
                return bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &EVALUATOR.code("challenge_evidence_not_canonical"),
                    "challenge_refs are receipt:// or decision:// refs",
                );
            }
            if !challenge_refs.contains(item) {
                challenge_refs.push(item.clone());
            }
        }
    } else if body.get("challenge_refs").is_some() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &EVALUATOR.code("challenge_evidence_not_admitted"),
            format!("'{verb}' appends no challenge evidence"),
        );
    }
    let impact = nullable_text(&body, "impact_disposition_ref");
    if let Some(impact) = &impact {
        if !impact.starts_with("decision://") {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &EVALUATOR.code("impact_disposition_not_canonical"),
                "impact_disposition_ref is a decision:// ref",
            );
        }
    }
    let recorded_at_ms = now_ms();
    let mut record = prior;
    record["validity_status"] = json!(to);
    record["validity_decision_ref"] = json!(decision);
    record["challenge_refs"] = strings(&challenge_refs);
    if impact.is_some() {
        record["impact_disposition_ref"] = json!(impact);
    }
    record["admitted_at"] = json!(admitted_stamp(recorded_at_ms));
    if let Some(object) = record.as_object_mut() {
        object.remove("content_hash");
    }
    // The frozen root MUST hash identically after the transition: validity is a projection around
    // what judges, never a change to it.
    match digest_over(&record, EVALUATOR_ROOT_DOMAIN, EVALUATOR_FROZEN) {
        Ok(root) if root == text(&record, "evaluator_root") => {}
        Ok(_) => {
            return bad(
                StatusCode::CONFLICT,
                &EVALUATOR.code("frozen_root_moved"),
                "a validity transition may not move what judges; a changed implementation is a new revision",
            )
        }
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &EVALUATOR.code("root_failed"),
                reason,
            )
        }
    }
    finish_admission(
        &EVALUATOR,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluator_revision",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({ "transition": verb }),
    )
}

pub(crate) async fn handle_evaluator_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &EVALUATOR, "evaluators")
}

pub(crate) async fn handle_evaluator_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&EVALUATOR, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    match read_family(&st, &headers, &EVALUATOR, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("absent"),
            "no evaluator family answers to that token",
        ),
        Ok((_, stream)) => (
            StatusCode::OK,
            Json(projection(&EVALUATOR, &stream, "revisions", json!({}))),
        ),
        Err(response) => response,
    }
}

/// GET …/evaluators/{family}/impact — the DERIVED dependent set of an evaluator family under its
/// CURRENT validity: every run and result bound to any of its revisions, and every epoch naming it.
/// Old evidence is never mutated: a result's standing is computed here from the evaluator's current
/// status and the result's own bytes stay what they were.
pub(crate) async fn handle_evaluator_impact(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&EVALUATOR, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let (identity, stream) = match read_family(&st, &headers, &EVALUATOR, &resource) {
        Ok(read) => read,
        Err(response) => return response,
    };
    let Some(current) = stream.last().map(|entry| entry.record.clone()) else {
        return bad(
            StatusCode::NOT_FOUND,
            &EVALUATOR.code("absent"),
            "no evaluator family answers to that token",
        );
    };
    let status = text(&current, "validity_status");
    let standing = match status.as_str() {
        "active" | "reverified" => "evaluator_active",
        "invalidated" => "evaluator_invalidated",
        "challenged" | "degraded" => "evaluator_challenged",
        _ => "evaluator_not_active",
    };
    let prefix = format!("{resource}/revision/");
    let names_family = |value: &str| value.starts_with(&prefix);
    let runs = match family_heads(&st, &identity, &RUN) {
        Ok(heads) => heads,
        Err(response) => return response,
    };
    let results = match family_heads(&st, &identity, &RESULT) {
        Ok(heads) => heads,
        Err(response) => return response,
    };
    let dependent_runs: Vec<Value> = runs
        .iter()
        .filter(|run| names_family(&text(run, "evaluator_revision_ref")))
        .map(|run| json!({ "evaluation_run_id": text(run, "evaluation_run_id"), "evaluation_epoch_ref": text(run, "evaluation_epoch_ref"), "lane": text(run, "lane") }))
        .collect();
    let dependent_results: Vec<Value> = results
        .iter()
        .filter(|result| {
            names_family(&text(result, "evaluator_revision_ref"))
                || list(result, "evaluator_versions")
                    .iter()
                    .any(|v| names_family(v))
        })
        .map(|result| {
            json!({
                "evaluation_result_id": text(result, "evaluation_result_id"),
                "evaluation_epoch_ref": text(result, "evaluation_epoch_ref"),
                "recorded_verdict": text(result, "verdict"),
                "standing": standing,
                "content_hash": text(result, "content_hash"),
            })
        })
        .collect();
    let epochs = match epochs_naming_evaluator(&st.data_dir, &identity, &resource) {
        Ok(epochs) => epochs,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "evaluator_id": resource,
            "current_revision_ref": text(&current, "revision_ref"),
            "validity_status": status,
            "standing": standing,
            "dependent_runs": dependent_runs,
            "dependent_results": dependent_results,
            "dependent_epochs": epochs,
            "note": "a projection over the evaluator's CURRENT validity; the dependent records' bytes are unchanged — invalidation appends lineage, it never rewrites old evidence into a pass or deletes the dependency",
        })),
    )
}

// ================================================================================ runs

const RUN_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "expected_epoch_frozen_root",
    "family",
    "evaluation_epoch_ref",
    "suite_revision_ref",
    "evaluator_revision_ref",
    "lane",
    "execution_evidence_refs",
    "policy_bound_data_view_revision_ref",
    "nondeterminism_class",
    "seed",
    "submitter_role",
    "cost_units",
    "cost_unit",
];
const RUN_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluation_run_id",
    "epoch_frozen_root",
    "incumbent_ref",
    "incumbent_root",
    "target_base_root",
    "content_hash",
    "admitted_at",
];

/// One resolved execution evidence ref: what kind it is, which model route (if any) produced it
/// and what it cost in latency — read from the owner's own record, never from the caller.
struct Evidence {
    reference: String,
    route_ref: Option<String>,
    latency_ms: Option<u64>,
}

fn resolve_evidence(st: &DaemonState, reference: &str) -> Result<Evidence, Reply> {
    if let Some(id) = reference.strip_prefix("model-invocation://") {
        let found = read_record_dir(&st.data_dir, "model-invocations")
            .into_iter()
            .find(|record| {
                text(record, "invocation_ref") == reference
                    || text(record, "invocation_id") == id
                    || text(record, "id") == id
            });
        let Some(record) = found else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "execution_evidence_unresolvable",
                format!("{reference} is not an admitted model invocation of this deployment"),
            ));
        };
        let receipt = record
            .get("model_invocation_receipt")
            .cloned()
            .unwrap_or(Value::Null);
        let latency = integer(&receipt, "latency_ms").or_else(|| {
            record
                .pointer("/evidence/latency/total_ms")
                .and_then(Value::as_u64)
        });
        return Ok(Evidence {
            reference: reference.to_string(),
            route_ref: nullable_text(&record, "route_ref"),
            latency_ms: latency,
        });
    }
    if reference.starts_with("session://") || reference.starts_with("session:") {
        let found = read_record_dir(&st.data_dir, "sessions")
            .into_iter()
            .any(|record| text(&record, "session_ref") == reference);
        if !found {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "execution_evidence_unresolvable",
                format!("{reference} is not a session of this deployment"),
            ));
        }
        return Ok(Evidence {
            reference: reference.to_string(),
            route_ref: None,
            latency_ms: None,
        });
    }
    Err(bad(
        StatusCode::UNPROCESSABLE_ENTITY,
        "execution_evidence_unresolvable",
        format!("{reference}: this build resolves model-invocation:// receipts and session:// records as execution evidence; receipt:// and foundry-recipe-run:// evidence stays typed unsupported here"),
    ))
}

/// The epoch a run or report binds must be FROZEN AND ACTIVE. M10.1's codes are reused so a caller
/// meets one vocabulary across the campaign spine and the evaluation plane.
fn require_active_epoch(epoch: &Value) -> Result<(), Reply> {
    match text(epoch, "lifecycle_status").as_str() {
        "draft" => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "a run binds a FROZEN epoch; freeze commits the judgment contract before any evidence",
        )),
        "frozen" => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_not_frozen",
            "a run binds the campaign's ACTIVE frozen epoch; this epoch is frozen but not active",
        )),
        "active" => Ok(()),
        other => Err(bad(
            StatusCode::CONFLICT,
            "evaluation_epoch_invalid",
            format!("this epoch is {other}; a challenged, closed or invalidated epoch admits no evidence"),
        )),
    }
}

pub(crate) async fn handle_run_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    let resource = match family_resource(&RUN, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &RUN,
        resource,
        RUN_REQUEST_FIELDS,
        RUN_SERVER_RESOLVED,
        Some("already_admitted"),
        "evaluation_run",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if ctx.expected_head.is_some() || !ctx.stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &RUN.code("already_admitted"),
            "a run is admitted once; its results are admitted under it",
        );
    }
    let role = body_str(&body, "submitter_role");
    if role == "search" || role == "optimizer" || role == "candidate" {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "role_separation_violated",
            "Search cannot submit evaluation evidence: search, evaluator/judge and activation authority are independently controlled (evaluations.md § Conformance Checks)",
        );
    }
    if !SUBMITTER_ROLES.contains(&role.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("submitter_role_outside_vocabulary"),
            "submitter_role is evaluator | target_owner | independent_reproducer",
        );
    }
    let lane = body_str(&body, "lane");
    if !LANES.contains(&lane.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("lane_outside_vocabulary"),
            format!("lane is one of {}", LANES.join(" | ")),
        );
    }
    let epoch_ref = body_str(&body, "evaluation_epoch_ref");
    let binding = match resolve_admitted_epoch_binding(
        &st,
        &ctx.caller.identity,
        &ctx.caller.owner_ref,
        &epoch_ref,
    ) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    if let Err(response) = require_active_epoch(&binding.epoch) {
        return response;
    }
    let frozen_root = text(&binding.epoch, "frozen_root");
    if let Some(asserted) = body
        .get("expected_epoch_frozen_root")
        .and_then(Value::as_str)
    {
        if asserted != frozen_root {
            return bad(
                StatusCode::CONFLICT,
                "epoch_binding_mismatch",
                "expected_epoch_frozen_root is not the root the epoch froze; a run binds the epoch as it is, never as asserted",
            );
        }
    }
    let suite_ref = body_str(&body, "suite_revision_ref");
    let suite = match resolve_suite_revision(&st, &ctx.caller.identity, &suite_ref) {
        Ok(suite) => suite,
        Err(response) => return response,
    };
    if text(&suite, "registry_status") != "released" {
        return bad(
            StatusCode::CONFLICT,
            "mutable_latest_refused",
            format!("{suite_ref} is {}; only a RELEASED suite revision supplies evidence — an unreleased revision is still mutable in the sense canon forbids", text(&suite, "registry_status")),
        );
    }
    let evaluator_ref = body_str(&body, "evaluator_revision_ref");
    let evaluator = match resolve_evaluator_revision(&st, &ctx.caller.identity, &evaluator_ref) {
        Ok(evaluator) => evaluator,
        Err(response) => return response,
    };
    if text(&evaluator, "validity_status") != "active" {
        return bad(
            StatusCode::CONFLICT,
            "evaluator_not_active",
            format!(
                "{evaluator_ref} is {}; a run is judged by an ACTIVE evaluator revision",
                text(&evaluator, "validity_status")
            ),
        );
    }
    let view_ref = body_str(&body, "policy_bound_data_view_revision_ref");
    if view_ref.is_empty() {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "view_revision_required",
            "a run binds the current policy-bound data-view REVISION (view://{family}/revision/{n}) the judgment was made under",
        );
    }
    if let Err(response) = resolve_admitted_policy_bound_data_view(
        &st.data_dir,
        &ctx.caller.identity,
        Some(ctx.caller.owner_ref.as_str()),
        &view_ref,
    ) {
        return response;
    }
    let evidence_refs = list(&body, "execution_evidence_refs");
    if evidence_refs.is_empty() || evidence_refs.len() > MAX_EVIDENCE {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("execution_evidence_required"),
            format!("a run judges 1..={MAX_EVIDENCE} execution evidence refs, each resolved through its owner"),
        );
    }
    for reference in &evidence_refs {
        if let Err(response) = resolve_evidence(&st, reference) {
            return response;
        }
    }
    let nondeterminism = body_str(&body, "nondeterminism_class");
    if !NONDETERMINISM_CLASSES.contains(&nondeterminism.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("nondeterminism_class_outside_vocabulary"),
            "nondeterminism_class is deterministic | seeded | declared_nondeterministic",
        );
    }
    let seed = body.get("seed").and_then(Value::as_u64);
    match (nondeterminism.as_str(), seed) {
        ("seeded", None) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RUN.code("seed_required"),
                "a seeded run names its seed (0..=1000000000000)",
            )
        }
        ("deterministic", Some(_)) => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RUN.code("seed_not_admitted"),
                "a deterministic run carries no seed",
            )
        }
        (_, Some(value)) if value > MAX_SEED => {
            return bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RUN.code("seed_out_of_domain"),
                "seed is bounded 0..=1000000000000",
            )
        }
        _ => {}
    }
    let Some(cost_units) = integer(&body, "cost_units") else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("cost_required"),
            "cost_units is a bounded integer 0..=1000000000 with its cost_unit",
        );
    };
    let cost_unit = body_str(&body, "cost_unit");
    if cost_units > MAX_UNITS || !COST_UNITS.contains(&cost_unit.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RUN.code("cost_out_of_domain"),
            "cost_units is 0..=1000000000 and cost_unit is tokens | usd_micros | seconds | units",
        );
    }
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": RUN.schema_version,
        "evaluation_run_id": ctx.resource,
        "owner_ref": ctx.caller.owner_ref,
        "evaluation_epoch_ref": text(&binding.epoch, "evaluation_epoch_id"),
        "epoch_frozen_root": frozen_root,
        "suite_revision_ref": suite_ref,
        "evaluator_revision_ref": evaluator_ref,
        "lane": lane,
        "incumbent_ref": text(&binding.epoch, "deployment_incumbent_ref"),
        "incumbent_root": text(&binding.epoch, "deployment_incumbent_root"),
        "target_base_root": text(&binding.campaign, "target_base_root"),
        "execution_evidence_refs": strings(&evidence_refs),
        "policy_bound_data_view_revision_ref": view_ref,
        "nondeterminism_class": nondeterminism,
        "seed": seed,
        "submitter_role": role,
        "cost_units": cost_units,
        "cost_unit": cost_unit,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &RUN,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_run",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({}),
    )
}

pub(crate) async fn handle_run_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &RUN, "evaluation_runs")
}

pub(crate) async fn handle_run_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&RUN, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    match read_family(&st, &headers, &RUN, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &RUN.code("absent"),
            "no evaluation run answers to that token",
        ),
        Ok((_, stream)) => (
            StatusCode::OK,
            Json(projection(&RUN, &stream, "admissions", json!({}))),
        ),
        Err(response) => response,
    }
}

// ================================================================================ results

const RESULT_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "family",
    "observations",
    "verdict",
    "uncertainty",
    "guardrail_findings",
    "applicability_scope",
    "cost_units",
    "cost_unit",
    "failures",
    "exposure_entry_ref",
];
const RESULT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "evaluation_result_id",
    "evaluation_run_ref",
    "evaluation_epoch_ref",
    "epoch_frozen_root",
    "suite_revision_ref",
    "evaluator_revision_ref",
    "lane",
    "verdict_basis",
    "evaluator_versions",
    "content_hash",
    "admitted_at",
];

/// Verdict floors: `pass` sits above `fail`, and the typed non-verdicts sit below both. A derived
/// floor only ever LOWERS a claimed verdict; the daemon never raises one.
fn verdict_rank(verdict: &str) -> u8 {
    match verdict {
        "pass" => 4,
        "fail" => 3,
        "inconclusive" => 2,
        "blocked" => 1,
        _ => 0,
    }
}

fn lower(verdict: &mut String, basis: &mut String, floor: &str, floor_basis: &str) {
    if verdict_rank(floor) < verdict_rank(verdict) {
        *verdict = floor.to_string();
        *basis = floor_basis.to_string();
    }
}

fn validate_observations(body: &Value, suite: &Value) -> Result<Vec<Value>, Reply> {
    let Some(observations) = body.get("observations").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("observations_required"),
            "a result carries 1..=4096 observations, each bound to a task's case commitment",
        ));
    };
    if observations.is_empty() || observations.len() > MAX_OBSERVATIONS {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("observations_required"),
            "a result carries 1..=4096 observations",
        ));
    }
    let known: BTreeSet<String> = suite
        .get("tasks")
        .and_then(Value::as_array)
        .map(|tasks| {
            tasks
                .iter()
                .map(|task| text(task, "source_commitment"))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for observation in observations {
        let id = text(observation, "observation_id");
        let case = text(observation, "case_commitment");
        let outcome = text(observation, "outcome");
        let score = integer(observation, "score_milli");
        let id_canonical = !id.is_empty()
            && id.len() <= 128
            && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        if !id_canonical {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RESULT.code("observation_id_not_canonical"),
                "observation_id is [A-Za-z0-9][A-Za-z0-9._-]{0,127}",
            ));
        }
        if !known.contains(&case) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "input_substitution_refused",
                format!("observation {id} names case commitment {case}, which is not a task of the suite revision this run bound — an observation about a case the epoch did not freeze is input substitution"),
            ));
        }
        if !OUTCOMES.contains(&outcome.as_str()) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RESULT.code("outcome_outside_vocabulary"),
                "outcome is pass | fail | error | skipped",
            ));
        }
        let Some(score) = score.filter(|s| *s <= 1000) else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RESULT.code("score_out_of_domain"),
                "score_milli is 0..=1000",
            ));
        };
        let evidence = list(observation, "evidence_refs");
        if evidence.len() > 16 {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &RESULT.code("observation_evidence_out_of_domain"),
                "an observation cites at most 16 evidence refs",
            ));
        }
        out.push(json!({
            "observation_id": id,
            "case_commitment": case,
            "outcome": outcome,
            "score_milli": score,
            "evidence_refs": strings(&evidence),
        }));
    }
    Ok(out)
}

fn validate_uncertainty(body: &Value) -> Result<Value, Reply> {
    let Some(uncertainty) = body.get("uncertainty").filter(|v| v.is_object()) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("uncertainty_required"),
            "a scorecard preserves its uncertainty: method, interval_low_milli, interval_high_milli, sample_size",
        ));
    };
    let method = text(uncertainty, "method");
    let low = integer(uncertainty, "interval_low_milli");
    let high = integer(uncertainty, "interval_high_milli");
    let n = integer(uncertainty, "sample_size");
    match (low, high, n) {
        (Some(low), Some(high), Some(n))
            if UNCERTAINTY_METHODS.contains(&method.as_str())
                && low <= 1000
                && high <= 1000
                && low <= high
                && n <= MAX_UNITS =>
        {
            Ok(json!({ "method": method, "interval_low_milli": low, "interval_high_milli": high, "sample_size": n }))
        }
        _ => Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("uncertainty_out_of_domain"),
            format!("uncertainty.method is one of {}; the interval is 0..=1000 with low <= high; sample_size is 0..=1000000000", UNCERTAINTY_METHODS.join(" | ")),
        )),
    }
}

pub(crate) async fn handle_result_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(run_family): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let run_resource = match family_resource(&RUN, &run_family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let family = body_str(&body, "family");
    let resource = match family_resource(&RESULT, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &RESULT,
        resource,
        RESULT_REQUEST_FIELDS,
        RESULT_SERVER_RESOLVED,
        Some("already_admitted"),
        "evaluation_result",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if ctx.expected_head.is_some() || !ctx.stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &RESULT.code("already_admitted"),
            "a result is immutable and admitted once; a correction is a new result under a successor epoch, never a rewrite",
        );
    }
    let run_stream =
        match authorized_stream(&RUN, &st.data_dir, &ctx.caller.identity, &run_resource) {
            Ok(stream) => stream,
            Err(response) => return response,
        };
    let Some(run) = run_stream.last().map(|entry| entry.record.clone()) else {
        return bad(
            StatusCode::NOT_FOUND,
            &RUN.code("absent"),
            "no evaluation run answers to that token",
        );
    };
    let epoch_ref = text(&run, "evaluation_epoch_ref");
    let binding = match resolve_admitted_epoch_binding(
        &st,
        &ctx.caller.identity,
        &ctx.caller.owner_ref,
        &epoch_ref,
    ) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    if let Err(response) = require_active_epoch(&binding.epoch) {
        return response;
    }
    if text(&binding.epoch, "frozen_root") != text(&run, "epoch_frozen_root") {
        return bad(
            StatusCode::CONFLICT,
            "epoch_binding_mismatch",
            "the epoch's frozen root no longer equals the root this run bound; the judgment contract moved under the run",
        );
    }
    let suite = match resolve_suite_revision(
        &st,
        &ctx.caller.identity,
        &text(&run, "suite_revision_ref"),
    ) {
        Ok(suite) => suite,
        Err(response) => return response,
    };
    let evaluator = match resolve_evaluator_revision(
        &st,
        &ctx.caller.identity,
        &text(&run, "evaluator_revision_ref"),
    ) {
        Ok(evaluator) => evaluator,
        Err(response) => return response,
    };
    let observations = match validate_observations(&body, &suite) {
        Ok(observations) => observations,
        Err(response) => return response,
    };
    let uncertainty = match validate_uncertainty(&body) {
        Ok(uncertainty) => uncertainty,
        Err(response) => return response,
    };
    let claimed = body_str(&body, "verdict");
    if !VERDICTS.contains(&claimed.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("verdict_outside_vocabulary"),
            "verdict is pass | fail | inconclusive | blocked | invalid",
        );
    }
    let scope = body_str(&body, "applicability_scope");
    if scope.is_empty() || scope.len() > 240 {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("applicability_required"),
            "a scorecard names the applicability scope its claim holds for (1..=240 characters)",
        );
    }
    let Some(cost_units) = integer(&body, "cost_units") else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("cost_required"),
            "cost_units is a bounded integer 0..=1000000000 with its cost_unit",
        );
    };
    let cost_unit = body_str(&body, "cost_unit");
    if cost_units > MAX_UNITS || !COST_UNITS.contains(&cost_unit.as_str()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("cost_out_of_domain"),
            "cost_units is 0..=1000000000 and cost_unit is tokens | usd_micros | seconds | units",
        );
    }
    let guardrails = list(&body, "guardrail_findings");
    let failures = list(&body, "failures");
    if guardrails.len() > 256
        || failures.len() > 1024
        || guardrails
            .iter()
            .chain(failures.iter())
            .any(|s| s.is_empty() || s.len() > 240)
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("findings_out_of_domain"),
            "guardrail_findings (<=256) and failures (<=1024) are non-empty strings of at most 240 characters",
        );
    }
    let lane = text(&run, "lane");
    // ---- the derived verdict floor -----------------------------------------------------------
    let mut verdict = claimed.clone();
    let mut basis = "observed".to_string();
    // An evaluator that is no longer active at judgment time invalidates the judgment.
    if text(&evaluator, "validity_status") != "active" {
        lower(&mut verdict, &mut basis, "invalid", "evaluator_not_active");
    }
    // Undeclared nondeterminism: a deterministic run whose repeated case disagrees with itself.
    if text(&run, "nondeterminism_class") == "deterministic" {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for observation in &observations {
            let case = text(observation, "case_commitment");
            let outcome = text(observation, "outcome");
            if let Some(previous) = seen.insert(case, outcome.clone()) {
                if previous != outcome {
                    lower(
                        &mut verdict,
                        &mut basis,
                        "invalid",
                        "nondeterminism_undeclared",
                    );
                    break;
                }
            }
        }
    }
    // The sealed lane: protected access appends an exposure entry through M10.1's ledger — this
    // module resolves it, never appends. Exhausted exposure with no entry is `blocked`.
    let mut exposure_entry_ref: Option<String> = None;
    if lane == "sealed" {
        match nullable_text(&body, "exposure_entry_ref") {
            Some(entry_ref) => {
                let entry =
                    match resolve_exposure_entry(&st, &ctx.caller.identity, &epoch_ref, &entry_ref)
                    {
                        Ok(entry) => entry,
                        Err(response) => return response,
                    };
                if text(&entry, "entry_kind") != "spend" {
                    return bad(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &RESULT.code("exposure_entry_not_a_spend"),
                        "a sealed result names the SPEND entry its protected access appended, not a reservation, return or rotation",
                    );
                }
                exposure_entry_ref = Some(entry_ref);
            }
            None => {
                let remaining = binding
                    .ledger
                    .as_ref()
                    .and_then(|ledger| integer(ledger, "remaining_units"))
                    .unwrap_or(0);
                if remaining == 0 {
                    // BLOCKED IS RECEIPTED. The result binds the ledger HEAD entry at which no
                    // exposure remained, so "exhausted" is a fact a reader resolves through the
                    // admitted ledger rather than a counter this record asserts.
                    exposure_entry_ref = binding
                        .ledger
                        .as_ref()
                        .and_then(|ledger| ledger.get("entries"))
                        .and_then(Value::as_array)
                        .and_then(|entries| entries.last())
                        .map(|entry| text(entry, "entry_ref"))
                        .filter(|entry_ref| !entry_ref.is_empty());
                    lower(&mut verdict, &mut basis, "blocked", "exposure_exhausted");
                } else {
                    return bad(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &RESULT.code("exposure_entry_required"),
                        "a sealed-lane result names the exposure entry its protected access appended (POST …/evaluation-epochs/{epoch}/exposure/spend first); remaining exposure is derived from the admitted ledger head, never from an unreceipted counter",
                    );
                }
            }
        }
    } else if body.get("exposure_entry_ref").is_some_and(|v| !v.is_null()) {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &RESULT.code("exposure_entry_not_admitted"),
            "only a sealed-lane result names an exposure entry",
        );
    }
    // Required lanes: a `pass` stands only when every lane the suite requires has a passing result
    // under this epoch (this one included). Otherwise the floor is `inconclusive`.
    if verdict == "pass" {
        let required = list(&suite, "required_lanes");
        let results = match family_heads(&st, &ctx.caller.identity, &RESULT) {
            Ok(heads) => heads,
            Err(response) => return response,
        };
        // A lane counts as covered by a result that OBSERVED a pass: the recorded `pass`, or an
        // earlier result whose only floor was this same lane rule (`inconclusive` with basis
        // `required_lane_missing`). Results are immutable, so the pass that completes coverage is
        // the one admitted last; the earlier ones keep the floor they were admitted with.
        let mut covered: BTreeSet<String> = results
            .iter()
            .filter(|result| {
                text(result, "evaluation_epoch_ref") == epoch_ref
                    && (text(result, "verdict") == "pass"
                        || (text(result, "verdict") == "inconclusive"
                            && text(result, "verdict_basis") == "required_lane_missing"))
            })
            .map(|result| text(result, "lane"))
            .collect();
        covered.insert(lane.clone());
        if required.iter().any(|needed| !covered.contains(needed)) {
            lower(
                &mut verdict,
                &mut basis,
                "inconclusive",
                "required_lane_missing",
            );
        }
    }
    let mut evaluator_versions = vec![text(&run, "evaluator_revision_ref")];
    for scorer in list(&suite, "scorer_revision_refs") {
        if !evaluator_versions.contains(&scorer) {
            evaluator_versions.push(scorer);
        }
    }
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": RESULT.schema_version,
        "evaluation_result_id": ctx.resource,
        "owner_ref": ctx.caller.owner_ref,
        "evaluation_run_ref": run_resource,
        "evaluation_epoch_ref": epoch_ref,
        "epoch_frozen_root": text(&run, "epoch_frozen_root"),
        "suite_revision_ref": text(&run, "suite_revision_ref"),
        "evaluator_revision_ref": text(&run, "evaluator_revision_ref"),
        "lane": lane,
        "observations": observations,
        "verdict": verdict,
        "verdict_basis": basis,
        "uncertainty": uncertainty,
        "guardrail_findings": strings(&guardrails),
        "applicability_scope": scope,
        "cost_units": cost_units,
        "cost_unit": cost_unit,
        "failures": strings(&failures),
        "evaluator_versions": strings(&evaluator_versions),
        "exposure_entry_ref": exposure_entry_ref,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &RESULT,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "evaluation_result",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({ "claimed_verdict": claimed }),
    )
}

pub(crate) async fn handle_result_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &RESULT, "evaluation_results")
}

pub(crate) async fn handle_result_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&RESULT, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    match read_family(&st, &headers, &RESULT, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &RESULT.code("absent"),
            "no evaluation result answers to that token",
        ),
        Ok((_, stream)) => (
            StatusCode::OK,
            Json(projection(&RESULT, &stream, "admissions", json!({}))),
        ),
        Err(response) => response,
    }
}

// ================================================================================ continuity

const REPORT_REQUEST_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "expected_revision_ref",
    "family",
    "evaluation_epoch_ref",
    "suite_revision_ref",
    "policy_bound_data_view_revision_ref",
    "learning_boundary_profile_ref",
    "incumbent_route_ref",
    "candidate_route_ref",
    "baseline_result_refs",
    "candidate_result_refs",
    "equivalence_envelope",
    "canary_refs",
    "rollback_refs",
];
const REPORT_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "model_swap_continuity_report_id",
    "epoch_frozen_root",
    "institutional_state_root",
    "incumbent_route_record_hash",
    "incumbent_disabled_evidence",
    "candidate_route_record_hash",
    "observed_deltas",
    "unsupported_dependencies",
    "threshold_verdict",
    "authority_note",
    "content_hash",
    "admitted_at",
];

/// One result set's derived measures for the report.
struct SetMeasures {
    per_case_score: BTreeMap<String, u64>,
    per_case_outcome: BTreeMap<String, String>,
    safety_milli: u64,
    cost_units: u64,
    latency_ms_total: u64,
    latency_samples: u64,
    failures: BTreeSet<String>,
    route_refs: BTreeSet<String>,
    evidence_refs: BTreeSet<String>,
}

fn measure_result_set(
    st: &DaemonState,
    identity: &RequestIdentity,
    refs: &[String],
    epoch_ref: &str,
) -> Result<SetMeasures, Reply> {
    let mut measures = SetMeasures {
        per_case_score: BTreeMap::new(),
        per_case_outcome: BTreeMap::new(),
        safety_milli: 1000,
        cost_units: 0,
        latency_ms_total: 0,
        latency_samples: 0,
        failures: BTreeSet::new(),
        route_refs: BTreeSet::new(),
        evidence_refs: BTreeSet::new(),
    };
    let mut observations = 0u64;
    let mut guardrail_findings = 0u64;
    for reference in refs {
        let Some((family, _)) = reference
            .strip_prefix(RESULT.ref_scheme)
            .map(|rest| (rest.to_string(), ()))
        else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &REPORT.code("result_ref_not_canonical"),
                "baseline_result_refs and candidate_result_refs are evaluation-result:// refs",
            ));
        };
        let resource = format!("{}{family}", RESULT.ref_scheme);
        let stream = authorized_stream(&RESULT, &st.data_dir, identity, &resource)?;
        let Some(result) = stream.last().map(|entry| entry.record.clone()) else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &REPORT.code("result_unresolvable"),
                format!("{reference} is not an admitted evaluation result"),
            ));
        };
        if text(&result, "evaluation_epoch_ref") != epoch_ref {
            return Err(bad(
                StatusCode::CONFLICT,
                "report_epoch_mismatch",
                format!("{reference} was judged under {}, not the epoch this report freezes; continuity compares results under ONE frozen judgment contract", text(&result, "evaluation_epoch_ref")),
            ));
        }
        let run_resource = text(&result, "evaluation_run_ref");
        let run_stream = authorized_stream(&RUN, &st.data_dir, identity, &run_resource)?;
        let Some(run) = run_stream.last().map(|entry| entry.record.clone()) else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &REPORT.code("run_unresolvable"),
                format!("{reference} names a run this deployment does not hold"),
            ));
        };
        for evidence_ref in list(&run, "execution_evidence_refs") {
            let evidence = resolve_evidence(st, &evidence_ref)?;
            measures.evidence_refs.insert(evidence.reference.clone());
            if let Some(route) = evidence.route_ref {
                measures.route_refs.insert(route);
            }
            if let Some(latency) = evidence.latency_ms {
                measures.latency_ms_total = measures.latency_ms_total.saturating_add(latency);
                measures.latency_samples += 1;
            }
        }
        measures.cost_units = measures
            .cost_units
            .saturating_add(integer(&result, "cost_units").unwrap_or(0));
        for failure in list(&result, "failures") {
            measures.failures.insert(failure);
        }
        guardrail_findings += list(&result, "guardrail_findings").len() as u64;
        for observation in result
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            observations += 1;
            let case = text(observation, "case_commitment");
            measures.per_case_score.insert(
                case.clone(),
                integer(observation, "score_milli").unwrap_or(0),
            );
            measures
                .per_case_outcome
                .insert(case, text(observation, "outcome"));
        }
    }
    if observations > 0 {
        let penalty = guardrail_findings.saturating_mul(1000) / observations;
        measures.safety_milli = 1000u64.saturating_sub(penalty.min(1000));
    }
    Ok(measures)
}

fn mean(values: impl Iterator<Item = u64>) -> Option<u64> {
    let mut total = 0u64;
    let mut count = 0u64;
    for value in values {
        total = total.saturating_add(value);
        count += 1;
    }
    (count > 0).then(|| total / count)
}

fn ratio_milli(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return if numerator == 0 { 1000 } else { 100_000 };
    }
    numerator.saturating_mul(1000) / denominator
}

pub(crate) async fn handle_continuity_run(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let family = body_str(&body, "family");
    let resource = match family_resource(&REPORT, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &REPORT,
        resource,
        REPORT_REQUEST_FIELDS,
        REPORT_SERVER_RESOLVED,
        Some("already_admitted"),
        "model_swap_continuity_report",
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if ctx.expected_head.is_some() || !ctx.stream.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            &REPORT.code("already_admitted"),
            "a continuity report is derived once for its token; a new comparison is a new report",
        );
    }
    let epoch_ref = body_str(&body, "evaluation_epoch_ref");
    let binding = match resolve_admitted_epoch_binding(
        &st,
        &ctx.caller.identity,
        &ctx.caller.owner_ref,
        &epoch_ref,
    ) {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    if let Err(response) = require_active_epoch(&binding.epoch) {
        return response;
    }
    let suite_ref = body_str(&body, "suite_revision_ref");
    let suite = match resolve_suite_revision(&st, &ctx.caller.identity, &suite_ref) {
        Ok(suite) => suite,
        Err(response) => return response,
    };
    if text(&suite, "registry_status") != "released" {
        return bad(
            StatusCode::CONFLICT,
            "mutable_latest_refused",
            "a continuity report freezes a RELEASED suite revision",
        );
    }
    let view_ref = body_str(&body, "policy_bound_data_view_revision_ref");
    if let Err(response) = resolve_admitted_policy_bound_data_view(
        &st.data_dir,
        &ctx.caller.identity,
        Some(ctx.caller.owner_ref.as_str()),
        &view_ref,
    ) {
        return response;
    }
    let boundary_ref = nullable_text(&body, "learning_boundary_profile_ref");
    if let Some(profile_ref) = &boundary_ref {
        if let Err(response) = resolve_admitted_boundary_profile(
            &st.data_dir,
            &ctx.caller.identity,
            Some(ctx.caller.owner_ref.as_str()),
            profile_ref,
        ) {
            return response;
        }
    }
    let incumbent_ref = body_str(&body, "incumbent_route_ref");
    let candidate_ref = body_str(&body, "candidate_route_ref");
    let route = |reference: &str| -> Result<Value, Reply> {
        let Some(id) = reference.strip_prefix("model-route:") else {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &REPORT.code("route_ref_not_canonical"),
                "incumbent_route_ref and candidate_route_ref are model-route:{id} refs",
            ));
        };
        load_route_record(&st.data_dir, id).ok_or_else(|| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &REPORT.code("route_unresolvable"),
                format!("{reference} is not a route in this deployment's model-route registry"),
            )
        })
    };
    let incumbent = match route(&incumbent_ref) {
        Ok(record) => record,
        Err(response) => return response,
    };
    let candidate = match route(&candidate_ref) {
        Ok(record) => record,
        Err(response) => return response,
    };
    if incumbent_ref == candidate_ref {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &REPORT.code("routes_identical"),
            "a continuity report compares two different routes",
        );
    }
    // REGISTRY TRUTH, read now: the incumbent must already be disabled. A report that compared a
    // still-live incumbent would prove nothing about surviving its removal.
    let incumbent_status = incumbent
        .pointer("/lifecycle/status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if incumbent_status != "disabled" {
        return bad(
            StatusCode::CONFLICT,
            "incumbent_route_not_disabled",
            format!("{incumbent_ref} is {incumbent_status}; the incumbent route is DISABLED in the registry before candidate evidence is admitted (foundry.md § Model-Swap Continuity: hard-disable incumbent-only state and rerun)"),
        );
    }
    let incumbent_hash = match canonical_value_hash(&incumbent) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &REPORT.code("route_hash_failed"),
                reason,
            )
        }
    };
    let candidate_hash = match canonical_value_hash(&candidate) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &REPORT.code("route_hash_failed"),
                reason,
            )
        }
    };
    let baseline_refs = list(&body, "baseline_result_refs");
    let candidate_refs = list(&body, "candidate_result_refs");
    if baseline_refs.is_empty()
        || candidate_refs.is_empty()
        || baseline_refs.len() > MAX_RESULT_REFS
        || candidate_refs.len() > MAX_RESULT_REFS
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &REPORT.code("result_refs_required"),
            "a report compares 1..=256 baseline results with 1..=256 candidate results",
        );
    }
    let baseline = match measure_result_set(&st, &ctx.caller.identity, &baseline_refs, &epoch_ref) {
        Ok(measures) => measures,
        Err(response) => return response,
    };
    let candidate_set =
        match measure_result_set(&st, &ctx.caller.identity, &candidate_refs, &epoch_ref) {
            Ok(measures) => measures,
            Err(response) => return response,
        };
    if baseline.route_refs.iter().any(|r| r != &incumbent_ref) || baseline.route_refs.is_empty() {
        return bad(
            StatusCode::CONFLICT,
            "baseline_evidence_route_mismatch",
            format!("every baseline result must judge evidence the INCUMBENT route produced; observed {:?}", baseline.route_refs),
        );
    }
    let mut unsupported: Vec<String> = Vec::new();
    if candidate_set.route_refs.is_empty()
        || candidate_set.route_refs.iter().any(|r| r != &candidate_ref)
    {
        for route in &candidate_set.route_refs {
            if route != &candidate_ref {
                unsupported.push(format!(
                    "candidate evidence produced by {route}, not the candidate route"
                ));
            }
        }
        if candidate_set.route_refs.is_empty() {
            unsupported.push("candidate evidence names no model route".to_string());
        }
    }
    if candidate_set.route_refs.contains(&incumbent_ref) {
        unsupported.push(format!("candidate evidence still names the incumbent route {incumbent_ref}: an incumbent-only dependency survived disablement"));
    }
    let envelope = body
        .get("equivalence_envelope")
        .cloned()
        .unwrap_or(Value::Null);
    let semantic_rule = text(&envelope, "semantic_rule");
    let failure_rule = text(&envelope, "failure_posture_rule");
    let floors = (
        integer(&envelope, "semantic_floor_milli"),
        integer(&envelope, "safety_floor_milli"),
        integer(&envelope, "cost_ceiling_ratio_milli"),
        integer(&envelope, "latency_ceiling_ratio_milli"),
    );
    let (Some(semantic_floor), Some(safety_floor), Some(cost_ceiling), Some(latency_ceiling)) =
        floors
    else {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &REPORT.code("equivalence_envelope_required"),
            "equivalence_envelope declares semantic_rule, semantic_floor_milli, safety_floor_milli, cost_ceiling_ratio_milli, latency_ceiling_ratio_milli and failure_posture_rule",
        );
    };
    if !SEMANTIC_RULES.contains(&semantic_rule.as_str())
        || !FAILURE_RULES.contains(&failure_rule.as_str())
        || semantic_floor > 1000
        || safety_floor > 1000
        || cost_ceiling > 100_000
        || latency_ceiling > 100_000
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &REPORT.code("equivalence_envelope_out_of_domain"),
            "semantic_rule is exact_match | rubric_scored | declared_equivalence_class; failure_posture_rule is identical | no_new_failure_classes | declared; floors are 0..=1000 and ratio ceilings 0..=100000",
        );
    }
    for key in ["canary_refs", "rollback_refs"] {
        for item in list(&body, key) {
            if !(item.starts_with("receipt://") || item.starts_with("decision://")) {
                return bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &REPORT.code("lineage_ref_not_canonical"),
                    format!("{key} are receipt:// or decision:// refs"),
                );
            }
        }
    }
    // ---- the derived deltas ------------------------------------------------------------------
    let matched: Vec<String> = baseline
        .per_case_score
        .keys()
        .filter(|case| candidate_set.per_case_score.contains_key(*case))
        .cloned()
        .collect();
    if matched.is_empty() {
        unsupported.push(
            "no case commitment is judged by both the baseline and the candidate".to_string(),
        );
    }
    let baseline_semantic = if semantic_rule == "exact_match" {
        1000
    } else {
        mean(matched.iter().map(|case| baseline.per_case_score[case])).unwrap_or(0)
    };
    let candidate_semantic = if semantic_rule == "exact_match" {
        mean(matched.iter().map(|case| {
            if baseline.per_case_outcome.get(case) == candidate_set.per_case_outcome.get(case) {
                1000
            } else {
                0
            }
        }))
        .unwrap_or(0)
    } else {
        mean(
            matched
                .iter()
                .map(|case| candidate_set.per_case_score[case]),
        )
        .unwrap_or(0)
    };
    let semantic_delta = candidate_semantic as i64 - baseline_semantic as i64;
    let safety_delta = candidate_set.safety_milli as i64 - baseline.safety_milli as i64;
    let cost_ratio = ratio_milli(candidate_set.cost_units, baseline.cost_units);
    let baseline_latency = (baseline.latency_samples > 0)
        .then(|| baseline.latency_ms_total / baseline.latency_samples);
    let candidate_latency = (candidate_set.latency_samples > 0)
        .then(|| candidate_set.latency_ms_total / candidate_set.latency_samples);
    let latency_ratio = match (baseline_latency, candidate_latency) {
        (Some(b), Some(c)) => ratio_milli(c, b),
        _ => 1000,
    };
    let new_failure_classes: Vec<String> = candidate_set
        .failures
        .difference(&baseline.failures)
        .cloned()
        .collect();
    let failure_rule_holds = match failure_rule.as_str() {
        "identical" => candidate_set.failures == baseline.failures,
        "no_new_failure_classes" => new_failure_classes.is_empty(),
        _ => true,
    };
    let proven = unsupported.is_empty()
        && candidate_semantic >= semantic_floor
        && candidate_set.safety_milli >= safety_floor
        && cost_ratio <= cost_ceiling
        && latency_ratio <= latency_ceiling
        && failure_rule_holds;
    let state_root = match engine_domain_roots(&st.data_dir) {
        Ok(roots) => match digest_over(&json!({ "domains": roots }), STATE_ROOT_DOMAIN, &["domains"]) {
            Ok(root) => root,
            Err(reason) => return bad(StatusCode::INTERNAL_SERVER_ERROR, &REPORT.code("state_root_failed"), reason),
        },
        Err(reason) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                &REPORT.code("state_root_unavailable"),
                format!("the institutional state root could not be read from the substrate engine: {reason}"),
            )
        }
    };
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": REPORT.schema_version,
        "model_swap_continuity_report_id": ctx.resource,
        "owner_ref": ctx.caller.owner_ref,
        "evaluation_epoch_ref": text(&binding.epoch, "evaluation_epoch_id"),
        "epoch_frozen_root": text(&binding.epoch, "frozen_root"),
        "suite_revision_ref": suite_ref,
        "institutional_state_root": state_root,
        "policy_bound_data_view_revision_ref": view_ref,
        "learning_boundary_profile_ref": boundary_ref,
        "incumbent_route_ref": incumbent_ref,
        "incumbent_route_record_hash": incumbent_hash.clone(),
        "incumbent_disabled_evidence": {
            "lifecycle_status": "disabled",
            "observed_at": admitted_stamp(recorded_at_ms),
            "registry_record_hash": incumbent_hash,
        },
        "candidate_route_ref": candidate_ref,
        "candidate_route_record_hash": candidate_hash,
        "baseline_result_refs": strings(&baseline_refs),
        "candidate_result_refs": strings(&candidate_refs),
        "equivalence_envelope": {
            "semantic_rule": semantic_rule,
            "semantic_floor_milli": semantic_floor,
            "safety_floor_milli": safety_floor,
            "cost_ceiling_ratio_milli": cost_ceiling,
            "latency_ceiling_ratio_milli": latency_ceiling,
            "failure_posture_rule": failure_rule,
        },
        "observed_deltas": {
            "semantic_delta_milli": semantic_delta.clamp(-1000, 1000),
            "safety_delta_milli": safety_delta.clamp(-1000, 1000),
            "cost_ratio_milli": cost_ratio.min(100_000),
            "latency_ratio_milli": latency_ratio.min(100_000),
            "new_failure_classes": strings(&new_failure_classes),
        },
        "unsupported_dependencies": strings(&unsupported),
        "threshold_verdict": if proven { "continuity_proven_for_declared_envelope" } else { "not_proven" },
        "canary_refs": strings(&list(&body, "canary_refs")),
        "rollback_refs": strings(&list(&body, "rollback_refs")),
        "authority_note": AUTHORITY_NOTE,
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &REPORT,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        "model_swap_continuity_report",
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({
            "measures": {
                "baseline_semantic_milli": baseline_semantic,
                "candidate_semantic_milli": candidate_semantic,
                "baseline_safety_milli": baseline.safety_milli,
                "candidate_safety_milli": candidate_set.safety_milli,
                "matched_cases": matched.len(),
                "baseline_evidence": baseline.evidence_refs.len(),
                "candidate_evidence": candidate_set.evidence_refs.len(),
            }
        }),
    )
}

pub(crate) async fn handle_continuity_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &REPORT, "model_swap_continuity_reports")
}

pub(crate) async fn handle_continuity_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(family): Path<String>,
) -> Reply {
    let resource = match family_resource(&REPORT, &family) {
        Ok(resource) => resource,
        Err(response) => return response,
    };
    match read_family(&st, &headers, &REPORT, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &REPORT.code("absent"),
            "no continuity report answers to that token",
        ),
        Ok((_, stream)) => (
            StatusCode::OK,
            Json(projection(&REPORT, &stream, "admissions", json!({}))),
        ),
        Err(response) => response,
    }
}

// ======================================================================================== tests
//
// The driven gate (apps/hypervisor/scripts/verify-hypervisor-governed-evaluation-plane.mjs) takes
// every branch a caller can reach. These cover the branches a caller CANNOT reach by construction —
// the frozen-root guard on a transition, the floor's ordering, the diagram's closed edge set — and
// the pure domain checks, so a later edit that opens or bends one fails here before it ships.
#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(record: Value, head: &str) -> AdmittedRecord {
        AdmittedRecord {
            record,
            admission: json!({}),
            head: head.to_string(),
            recorded_at_ms: 1,
        }
    }

    #[test]
    fn validity_diagram_is_exactly_canons_edge_set() {
        // evaluations.md § Evaluator Validity And Challenges, verb by verb.
        assert_eq!(
            validity_edge("validate"),
            Some((&["draft"][..], "validated"))
        );
        assert_eq!(
            validity_edge("release"),
            Some((&["validated"][..], "released"))
        );
        assert_eq!(
            validity_edge("activate"),
            Some((&["released", "reverified"][..], "active"))
        );
        assert_eq!(
            validity_edge("challenge"),
            Some((&["released", "active"][..], "challenged"))
        );
        assert_eq!(
            validity_edge("degrade"),
            Some((&["challenged"][..], "degraded"))
        );
        assert_eq!(
            validity_edge("invalidate"),
            Some((&["challenged", "degraded"][..], "invalidated"))
        );
        assert_eq!(
            validity_edge("reverify"),
            Some((&["challenged", "degraded"][..], "reverified"))
        );
        assert_eq!(
            validity_edge("supersede"),
            Some((&["active", "reverified", "invalidated"][..], "superseded"))
        );
        let (retire_from, retire_to) = validity_edge("retire").expect("retire is an edge");
        assert_eq!(retire_to, "retired");
        assert!(!retire_from.contains(&"retired"), "retired is terminal");
        assert_eq!(retire_from.len(), VALIDITY_STATUSES.len() - 1);
        for verb in ["bless", "promote", "activate_now", ""] {
            assert!(validity_edge(verb).is_none(), "{verb} is not a transition");
        }
        // No edge enters draft, and every target status is in the vocabulary.
        for verb in [
            "validate",
            "release",
            "activate",
            "challenge",
            "degrade",
            "invalidate",
            "reverify",
            "supersede",
            "retire",
        ] {
            let (_, to) = validity_edge(verb).unwrap();
            assert_ne!(to, "draft");
            assert!(VALIDITY_STATUSES.contains(&to));
        }
    }

    #[test]
    fn the_floor_only_ever_lowers_and_the_strictest_wins() {
        let mut verdict = "pass".to_string();
        let mut basis = "observed".to_string();
        lower(
            &mut verdict,
            &mut basis,
            "inconclusive",
            "required_lane_missing",
        );
        assert_eq!(
            (verdict.as_str(), basis.as_str()),
            ("inconclusive", "required_lane_missing")
        );
        // A stricter floor replaces a looser one …
        lower(&mut verdict, &mut basis, "invalid", "evaluator_not_active");
        assert_eq!(
            (verdict.as_str(), basis.as_str()),
            ("invalid", "evaluator_not_active")
        );
        // … and a looser floor never raises what a stricter one settled.
        lower(&mut verdict, &mut basis, "blocked", "exposure_exhausted");
        assert_eq!(
            (verdict.as_str(), basis.as_str()),
            ("invalid", "evaluator_not_active")
        );
        // `lower` is a pure order: it WOULD take a fail down to inconclusive, which is why the
        // handler applies the lane floor only to a claimed pass (a fail already says what it says).
        let mut fail = "fail".to_string();
        let mut fail_basis = "observed".to_string();
        lower(
            &mut fail,
            &mut fail_basis,
            "inconclusive",
            "required_lane_missing",
        );
        assert_eq!(
            (fail.as_str(), fail_basis.as_str()),
            ("inconclusive", "required_lane_missing")
        );
        let mut kept = "fail".to_string();
        let mut kept_basis = "observed".to_string();
        lower(&mut kept, &mut kept_basis, "pass", "observed");
        assert_eq!(
            (kept.as_str(), kept_basis.as_str()),
            ("fail", "observed"),
            "never raised"
        );
        assert!(verdict_rank("pass") > verdict_rank("fail"));
        assert!(verdict_rank("fail") > verdict_rank("inconclusive"));
        assert!(verdict_rank("inconclusive") > verdict_rank("blocked"));
        assert!(verdict_rank("blocked") > verdict_rank("invalid"));
        assert_eq!(verdict_rank("winner"), 0);
    }

    #[test]
    fn a_transition_that_moves_a_frozen_member_would_move_the_root() {
        // The guard in handle_evaluator_transition compares the re-derived root with the stored
        // one; a caller cannot reach a moved frozen member through that route, so the guard's
        // discriminating power is proven here on the digest itself.
        let record = json!({
            "schema_version": EVALUATOR.schema_version,
            "evaluator_id": "evaluator://acme.judge",
            "revision_ref": "evaluator://acme.judge/revision/1",
            "revision": 1,
            "predecessor_revision_ref": null,
            "owner_ref": "org://local",
            "evaluator_kind": "judge",
            "implementation_ref": "artifact://acme/judge/v1",
            "affiliation_ref": null,
            "custodian_ref": null,
        });
        let root = digest_over(&record, EVALUATOR_ROOT_DOMAIN, EVALUATOR_FROZEN).unwrap();
        let mut projected = record.clone();
        projected["validity_status"] = json!("active");
        projected["challenge_refs"] = json!(["receipt://acme/x"]);
        assert_eq!(
            digest_over(&projected, EVALUATOR_ROOT_DOMAIN, EVALUATOR_FROZEN).unwrap(),
            root,
            "a validity projection leaves the root where it was"
        );
        let mut moved = record;
        moved["implementation_ref"] = json!("artifact://acme/judge/v2");
        assert_ne!(
            digest_over(&moved, EVALUATOR_ROOT_DOMAIN, EVALUATOR_FROZEN).unwrap(),
            root,
            "a changed implementation is a new revision, never a transition"
        );
    }

    #[test]
    fn self_promotion_members_are_refused_by_name_before_the_fence() {
        for member in SELF_PROMOTION_MEMBERS {
            let body = json!({ "owner_ref": "org://local", (*member): true });
            let (status, reply) = refuse_self_promotion(&body, &RUN).unwrap_err();
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                reply.0.pointer("/error/code").and_then(Value::as_str),
                Some("self_promotion_refused"),
                "{member}"
            );
        }
        assert!(refuse_self_promotion(
            &json!({ "owner_ref": "org://local", "lane": "visible" }),
            &RUN
        )
        .is_ok());
    }

    #[test]
    fn the_closed_fence_names_the_unknown_member_and_refuses_non_objects() {
        let (status, reply) = refuse_unknown_fields(
            &json!({ "owner_ref": "x", "fitness": 1 }),
            &SUITE,
            &["owner_ref"],
        )
        .unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.0.pointer("/error/code").and_then(Value::as_str),
            Some("evaluation_suite_revision_request_unknown_field")
        );
        assert!(reply
            .0
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap()
            .contains("fitness"));
        let (status, reply) =
            refuse_unknown_fields(&json!([1, 2]), &SUITE, &["owner_ref"]).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            reply.0.pointer("/error/code").and_then(Value::as_str),
            Some("evaluation_suite_revision_request_body_not_object")
        );
        assert!(
            refuse_unknown_fields(&json!({ "owner_ref": "x" }), &SUITE, &["owner_ref"]).is_ok()
        );
    }

    #[test]
    fn domain_checks_hold_their_edges() {
        assert!(is_sha256(&format!("sha256:{}", "a".repeat(64))));
        assert!(
            !is_sha256(&format!("sha256:{}", "A".repeat(64))),
            "uppercase hex is not canonical"
        );
        assert!(!is_sha256(&format!("sha256:{}", "a".repeat(63))));
        assert!(!is_sha256(&"a".repeat(71)));
        for owner in [
            "org://local",
            "user://u1",
            "project://p",
            "system://hypervisor",
        ] {
            assert!(owner_scheme_supported(owner));
        }
        assert!(!owner_scheme_supported("tenant://org.local"));
        assert!(!owner_scheme_supported(&format!(
            "org://{}",
            "x".repeat(200)
        )));
        assert_eq!(ratio_milli(0, 0), 1000, "nothing over nothing is parity");
        assert_eq!(
            ratio_milli(5, 0),
            100_000,
            "something over nothing is the ceiling"
        );
        assert_eq!(ratio_milli(126, 84), 1500);
        assert_eq!(mean(std::iter::empty::<u64>()), None);
        assert_eq!(mean([1000u64, 0, 1000].into_iter()), Some(666));
    }

    #[test]
    fn uncertainty_is_a_bounded_ordered_interval_under_a_declared_method() {
        let good = json!({ "uncertainty": { "method": "fixed_test", "interval_low_milli": 900, "interval_high_milli": 1000, "sample_size": 3 } });
        assert!(validate_uncertainty(&good).is_ok());
        let code_of = |body: Value| {
            let (_, reply) = validate_uncertainty(&body).unwrap_err();
            reply
                .0
                .pointer("/error/code")
                .and_then(Value::as_str)
                .unwrap()
                .to_string()
        };
        assert_eq!(code_of(json!({})), "evaluation_result_uncertainty_required");
        assert_eq!(
            code_of(json!({ "uncertainty": null })),
            "evaluation_result_uncertainty_required"
        );
        assert_eq!(
            code_of(
                json!({ "uncertainty": { "method": "gut_feel", "interval_low_milli": 1, "interval_high_milli": 2, "sample_size": 1 } })
            ),
            "evaluation_result_uncertainty_out_of_domain"
        );
        assert_eq!(
            code_of(
                json!({ "uncertainty": { "method": "fixed_test", "interval_low_milli": 900, "interval_high_milli": 800, "sample_size": 1 } })
            ),
            "evaluation_result_uncertainty_out_of_domain"
        );
        assert_eq!(
            code_of(
                json!({ "uncertainty": { "method": "fixed_test", "interval_low_milli": 0, "interval_high_milli": 1001, "sample_size": 1 } })
            ),
            "evaluation_result_uncertainty_out_of_domain"
        );
    }

    #[test]
    fn revisions_resolve_each_ordinal_to_its_current_record() {
        let stream = vec![
            admitted(json!({ "revision": 1, "registry_status": "draft" }), "h1"),
            admitted(
                json!({ "revision": 1, "registry_status": "released" }),
                "h2",
            ),
            admitted(json!({ "revision": 2, "registry_status": "draft" }), "h3"),
            admitted(json!({ "note": "no ordinal" }), "h4"),
        ];
        let held = revisions(&stream);
        assert_eq!(held.len(), 2);
        assert_eq!(held[0].0, 1);
        assert_eq!(
            text(&held[0].1, "registry_status"),
            "released",
            "the successor is the truth about revision 1"
        );
        assert_eq!(held[1].0, 2);
        assert_eq!(text(&held[1].1, "registry_status"), "draft");
    }

    #[test]
    fn only_an_active_epoch_admits_evidence() {
        let code_of = |status: &str| {
            let (http, reply) =
                require_active_epoch(&json!({ "lifecycle_status": status })).unwrap_err();
            (
                http,
                reply
                    .0
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_string(),
            )
        };
        assert!(require_active_epoch(&json!({ "lifecycle_status": "active" })).is_ok());
        assert_eq!(
            code_of("draft"),
            (
                StatusCode::CONFLICT,
                "evaluation_epoch_not_frozen".to_string()
            )
        );
        assert_eq!(
            code_of("frozen"),
            (
                StatusCode::CONFLICT,
                "evaluation_epoch_not_frozen".to_string()
            )
        );
        for terminal in ["challenged", "closed", "invalidated", ""] {
            assert_eq!(
                code_of(terminal),
                (StatusCode::CONFLICT, "evaluation_epoch_invalid".to_string()),
                "{terminal}"
            );
        }
    }

    #[test]
    fn material_lists_exclude_the_hash_and_the_stamp_and_lifecycle_projections_where_canon_says() {
        for (spec, material) in [
            (&SUITE, SUITE_MATERIAL),
            (&EVALUATOR, EVALUATOR_MATERIAL),
            (&RUN, RUN_MATERIAL),
            (&RESULT, RESULT_MATERIAL),
            (&REPORT, REPORT_MATERIAL),
        ] {
            assert!(
                !material.contains(&"content_hash"),
                "{}",
                spec.resource_kind
            );
            assert!(!material.contains(&"admitted_at"), "{}", spec.resource_kind);
            assert!(
                material.contains(&"schema_version"),
                "{}",
                spec.resource_kind
            );
            assert!(
                material.contains(&spec.identity_field),
                "{}",
                spec.resource_kind
            );
        }
        // The suite's release decision and registry status are projections outside its body;
        // the evaluator's validity IS material (a challenge changes what the record claims).
        assert!(!SUITE_MATERIAL.contains(&"release_decision_ref"));
        assert!(!SUITE_MATERIAL.contains(&"registry_status"));
        assert!(EVALUATOR_MATERIAL.contains(&"validity_status"));
        assert!(EVALUATOR_FROZEN
            .iter()
            .all(|f| EVALUATOR_MATERIAL.contains(f)));
        assert!(!EVALUATOR_FROZEN.contains(&"validity_status"));
    }
}
