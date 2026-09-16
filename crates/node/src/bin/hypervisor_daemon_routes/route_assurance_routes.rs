//! M09.7 — custody-proven private routes and node integrity: a route's assurance class is DERIVED
//! from evidence the daemon resolves, never authored, and never rounded up.
//!
//! Canon: README § 25 ("Private/no-provider-trust claims require a custody-proven route.
//! Contractual provider privacy is useful but is not cTEE no-plaintext custody"),
//! `components/model-router/doctrine.md` § Core Doctrine, § Model-Weight Custody and § Route
//! Assurance Classes (the registered `RouteAssuranceClaimEnvelope`), and
//! `components/daemon-runtime/hypervisoros.md` § Node Enforcement Profile (the registered
//! `NodeEnforcementProfileObservationEnvelope`), § EnforcementCoverageDeclaration ("audit, passive,
//! or receipt-ingestion mechanisms can never be upgraded into mediated or preventable") and § Node
//! Measurement Doctrine ("Measurement proves what was supposed to run. cTEE limits what the node is
//! allowed to see"). Three things live here:
//!
//!   * THE OBSERVATION (`POST /v1/hypervisor/hypervisoros/node-enforcement/observations`): the
//!     physical enforcement owner's admitted observation of one NodeEnforcementProfile on one node
//!     — per mechanism the mode it was OBSERVED in, the action classes it covers, its verification
//!     evidence, receipt contracts and privilege — as a versioned family on the shared chain.
//!   * THE PRODUCER: from an admitted observation the daemon derives one
//!     `EnforcementCoverageDeclaration` per covered action class and admits it through the
//!     enforcement-coverage registry (the M01.2 hand-off: `resolve_node_profile` had consumers and
//!     no producer). `mediated`, `preventable` and `receipted` are claimed only where an ACTIVE
//!     mechanism with verification evidence covers the class (`receipted` only with a receipt
//!     contract); audit-only and passive mechanisms contribute `observable`/`attributable` at
//!     most; a measured-boot receipt contributes `discovered`/`attributable` only.
//!   * THE CLAIM (`POST /v1/hypervisor/model-routes/:id/assurance`): for one model route, the
//!     relying party names the evidence and the requested class; the daemon RESOLVES the evidence
//!     (the rights contract bound to the route, the WorkRun's admitted isolation binding, the
//!     node's verified boot receipt and its appraisal, the node's egress coverage) and derives the
//!     effective class as the strongest one the evidence supports at or below the request, naming
//!     the downgrade. Role confusion, a replayed nonce, a substituted measurement, configuration,
//!     key or egress path, and a remote-readable custody refuse the custody-proven class outright.
//!
//! What this basis does NOT hold, typed: provider revocation callbacks (revocation is observed at
//! the next appraisal); a hardware-TEE quote verifier of its own (the node-attestation plane's
//! verified receipt and its appraisal record are the evidence); an isolation binding without a
//! WorkRun (M09.8's flow instantiates bindings; the claim resolves one the caller names).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use ioi_services::agentic::runtime::enforcement_coverage::EnforcementCoverageAdmissionRequest;
use ioi_types::app::hypervisoros_node_attestation::boot_receipt_root;

use super::hypervisoros_node_routes::{load_node_attestation_source, BOOT_RECEIPT_DIR};
use super::model_route_rights_routes::{
    authorized_stream, bad, body_str, finish_admission, head_assertion, read_stream,
    reject_authored, replay_for_key, require_exact_head,
    resolve_admitted_model_route_rights_contract, AdmittedRecord, FamilySpec, Reply,
};
use super::model_routes::{canonical_value_hash, load_route_record};
use super::mutation_event_foundation::{
    admit_owner_scoped_write, admitted_stamp, require_write_caller, scope_refusal_reply,
    WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::{read_record_dir, DaemonState};

const CLAIM_DOMAIN: &str =
    "ioi.model-router.route-assurance-claim-content-commitment-jcs-sha256.v1";
const OBSERVATION_DOMAIN: &str =
    "ioi.components.daemon-runtime.node-enforcement-profile-observation-content-commitment-jcs-sha256.v1";
const NODE_PRODUCER_IMPLEMENTATION_REF: &str =
    "artifact://ioi/hypervisor-daemon/node-enforcement-coverage-producer/v1";
const NODE_VERIFIER_REF: &str = "verifier://ioi/hypervisor-daemon/node-enforcement-coverage/v1";
const NODE_VERIFICATION_METHOD_REF: &str =
    "test-profile://ioi/node-enforcement/observed-mechanism-coverage/v1";
const NODE_FRESHNESS_POLICY_REF: &str = "policy://ioi/node-enforcement/observation-validity";
const COVERAGE_OWNER_NAMESPACE: &str = "hypervisor-enforcement-coverage";
const COVERAGE_RESOURCE_KIND: &str = "enforcement-coverage-snapshot";
const COVERAGE_ADMISSION_OP: &str = "enforcement_coverage.snapshot.admit";
const COVERAGE_ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.enforcement-coverage-admission.v1";
/// An observation is current for thirty days; a class derived from a stale observation is stale.
const OBSERVATION_VALIDITY_MS: u64 = 30 * 24 * 60 * 60 * 1000;

pub(crate) const CLASSES: &[&str] = &[
    "unevidenced",
    "confidential_compute_declared",
    "contractual_privacy",
    "workload_isolation",
    "custody_proven_no_plaintext",
];
const MECHANISMS: &[&str] = &[
    "daemon_gate",
    "sandbox_profile",
    "seccomp",
    "lsm_ebpf",
    "egress_policy",
    "executable_policy",
    "hash_signature_path_policy",
    "datawall",
    "log_redaction",
    "ctee_custody_check",
    "tee_attestation",
];
const MODES: &[&str] = &[
    "active_enforcement",
    "audit_only",
    "passive_observation",
    "receipt_ingestion_only",
    "uncovered",
];
const ACTION_CLASSES: &[&str] = &[
    "egress",
    "process_launch",
    "filesystem",
    "credential_access",
    "model_mount",
    "network_listen",
    "support_bundle",
    "daemon_bypass",
];
const PRIVILEGES: &[&str] = &[
    "user",
    "elevated",
    "os_privileged",
    "kernel",
    "hardware_backed",
];
const APPRAISED_POSTURES: &[&str] = &[
    "measured_boot",
    "secure_element",
    "cpu_tee",
    "gpu_confidential_compute",
    "cpu_tee_and_gpu_confidential_compute",
];

static CLAIM: FamilySpec = FamilySpec {
    owner_namespace: "route-assurance-claims",
    resource_kind: "route_assurance_claim",
    admit_op: "event_stream.route_assurance_claim_admitted",
    payload_schema: "ioi.hypervisor.route-assurance-claim-admission.v1",
    contract_id: "schema://ioi/components/model-router/route-assurance-claim/v1",
    schema_version: "ioi.model-router.route-assurance-claim.v1",
    record_key: "route_assurance_claim_record",
    code_prefix: "route_assurance",
    commitment_domain: CLAIM_DOMAIN,
    material_fields: &[
        "schema_version",
        "claim_ref",
        "revision",
        "predecessor_ref",
        "owner_ref",
        "principal_ref",
        "route_ref",
        "route_custody_hash",
        "requested_class",
        "effective_class",
        "downgrade_reason",
        "declared_posture",
        "evidence",
        "refusals",
        "appraised_at",
        "expires_at",
        "revocation_epoch",
        "status",
        "receipt_refs",
    ],
    identity_field: "claim_ref",
    ref_scheme: "route-assurance://",
    stamp_field: "admitted_at",
};

static OBSERVATION: FamilySpec = FamilySpec {
    owner_namespace: "node-enforcement-observations",
    resource_kind: "node_enforcement_profile_observation",
    admit_op: "event_stream.node_enforcement_profile_observation_admitted",
    payload_schema: "ioi.hypervisor.node-enforcement-profile-observation-admission.v1",
    contract_id: "schema://ioi/components/daemon-runtime/node-enforcement-profile-observation/v1",
    schema_version: "ioi.components.daemon-runtime.node-enforcement-profile-observation.v1",
    record_key: "node_enforcement_profile_observation_record",
    code_prefix: "node_enforcement_observation",
    commitment_domain: OBSERVATION_DOMAIN,
    material_fields: &[
        "schema_version",
        "observation_ref",
        "revision",
        "predecessor_ref",
        "owner_ref",
        "principal_ref",
        "node_enforcement_profile_ref",
        "node_ref",
        "platform",
        "observed_at",
        "mechanisms",
        "measured_boot",
        "known_gaps",
        "status",
        "receipt_refs",
    ],
    identity_field: "observation_ref",
    ref_scheme: "node-enforcement-observation://",
    stamp_field: "admitted_at",
};

const OBSERVATION_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "node_enforcement_profile_ref",
    "node_ref",
    "platform",
    "mechanisms",
    "known_gaps",
];
const OBSERVATION_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "observation_ref",
    "revision",
    "predecessor_ref",
    "principal_ref",
    "observed_at",
    "measured_boot",
    "status",
    "receipt_refs",
    "content_hash",
    "admitted_at",
];
const CLAIM_FIELDS: &[&str] = &[
    "owner_ref",
    "idempotency_key",
    "expected_head",
    "expected_content_hash",
    "requested_class",
    "rights_contract_revision_ref",
    "isolation_workrun_ref",
    "node_ref",
    "key_owner_ref",
    "protected_data_owner_ref",
];
const CLAIM_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "claim_ref",
    "revision",
    "predecessor_ref",
    "principal_ref",
    "route_ref",
    "route_custody_hash",
    "effective_class",
    "downgrade_reason",
    "declared_posture",
    "evidence",
    "refusals",
    "appraised_at",
    "expires_at",
    "revocation_epoch",
    "status",
    "receipt_refs",
    "content_hash",
    "admitted_at",
];

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

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

fn rfc3339_ms(ms: u64) -> String {
    admitted_stamp(ms)
}

fn parse_rfc3339_ms(value: &str) -> Option<u64> {
    let ms = agentgres::parse_rfc3339_ms(value);
    (ms > 0).then_some(ms)
}

fn slug(reference: &str) -> String {
    reference
        .replacen("://", "-", 1)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '.'
            }
        })
        .collect()
}

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
            "this route does not admit field(s): {}; the class, the evidence and every coverage fact are derived, never authored",
            unknown.join(", ")
        ),
    ))
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
) -> Result<WriteContext, Reply> {
    let caller = require_write_caller(&st.data_dir, headers, body)?;
    reject_authored(body, spec, authored)?;
    refuse_unknown_fields(body, spec, allowed)?;
    let genesis = body.get("expected_head").map_or(true, Value::is_null);
    let scope = if genesis {
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
    if let Some(reply) = replay_for_key(
        spec,
        st,
        &caller,
        &scope,
        &resource,
        &stream,
        spec.record_key,
    )? {
        return Err(reply);
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

fn head_record(stream: &[AdmittedRecord]) -> Option<&Value> {
    stream.last().map(|entry| &entry.record)
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
            Ok(stream) if !stream.is_empty() => held.push(json!({
                "ref": resource,
                "current": stream.last().map(|entry| entry.record.clone()),
                "head": stream.last().map(|entry| entry.head.clone()),
            })),
            Ok(_) => {}
            Err(response) => return response,
        }
    }
    (StatusCode::OK, Json(json!({ "ok": true, key: held })))
}

fn family_view(stream: &[AdmittedRecord]) -> Value {
    json!({
        "ok": true,
        "current": stream.last().map(|entry| entry.record.clone()),
        "revisions": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
        "head": stream.last().map(|entry| entry.head.clone()),
    })
}

// ================================================================================ the observation

fn validate_mechanisms(body: &Value) -> Result<Vec<Value>, Reply> {
    let Some(items) = body.get("mechanisms").and_then(Value::as_array) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &OBSERVATION.code("mechanisms_required"),
            "an observation observes at least one mechanism: {mechanism, mode, action_classes, verification_evidence_refs, receipt_contract_refs, required_privilege}",
        ));
    };
    if items.is_empty() || items.len() > 64 {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &OBSERVATION.code("mechanisms_required"),
            "an observation observes between 1 and 64 mechanisms",
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let mechanism = text(item, "mechanism");
        let mode = text(item, "mode");
        let privilege = text(item, "required_privilege");
        let classes = list(item, "action_classes");
        if !MECHANISMS.contains(&mechanism.as_str()) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &OBSERVATION.code("mechanism_outside_vocabulary"),
                format!(
                    "'{mechanism}' is not a node enforcement mechanism; one of {}",
                    MECHANISMS.join(" | ")
                ),
            ));
        }
        if !MODES.contains(&mode.as_str()) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &OBSERVATION.code("mode_outside_vocabulary"),
                format!(
                    "'{mode}' is not an observed mode; one of {}",
                    MODES.join(" | ")
                ),
            ));
        }
        if !PRIVILEGES.contains(&privilege.as_str()) {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &OBSERVATION.code("privilege_outside_vocabulary"),
                format!(
                    "'{privilege}' is not a privilege; one of {}",
                    PRIVILEGES.join(" | ")
                ),
            ));
        }
        if classes.is_empty()
            || classes
                .iter()
                .any(|class| !ACTION_CLASSES.contains(&class.as_str()))
        {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                &OBSERVATION.code("action_class_outside_vocabulary"),
                format!(
                    "action_classes is a non-empty subset of {}",
                    ACTION_CLASSES.join(" | ")
                ),
            ));
        }
        let evidence = list(item, "verification_evidence_refs");
        if mode == "active_enforcement" && evidence.is_empty() {
            return Err(bad(StatusCode::UNPROCESSABLE_ENTITY, &OBSERVATION.code("active_mechanism_unverified"), format!("'{mechanism}' is observed as active_enforcement with no verification evidence; an unverified mechanism is observed as audit_only at most, never as active")));
        }
        let mut classes = classes;
        classes.sort();
        classes.dedup();
        out.push(json!({
            "mechanism": mechanism,
            "mode": mode,
            "action_classes": strings(&classes),
            "verification_evidence_refs": strings(&evidence),
            "receipt_contract_refs": strings(&list(item, "receipt_contract_refs")),
            "required_privilege": privilege,
        }));
    }
    Ok(out)
}

/// The node's committed measured-boot receipt, if the node-attestation plane holds a verified one.
fn committed_boot_receipt(data_dir: &str, node_ref: &str) -> Option<(Value, Value)> {
    let source = load_node_attestation_source(data_dir).ok()?;
    let record = source
        .records
        .iter()
        .find(|record| record.get("node_id").and_then(Value::as_str) == Some(node_ref))?
        .clone();
    let root = record
        .pointer("/attestation/boot_receipt_root")
        .and_then(Value::as_str)?
        .to_string();
    let receipt = read_record_dir(data_dir, BOOT_RECEIPT_DIR)
        .into_iter()
        .find(|receipt| boot_receipt_root(receipt).ok().as_deref() == Some(root.as_str()))?;
    Some((record, receipt))
}

fn measured_boot_summary(data_dir: &str, node_ref: &str) -> Value {
    match committed_boot_receipt(data_dir, node_ref) {
        Some((_, receipt)) => json!({
            "boot_receipt_root": boot_receipt_root(&receipt).ok(),
            "effective_posture": receipt.pointer("/observation/attestation_assurance/effective_posture").cloned().unwrap_or(Value::Null),
        }),
        None => json!({ "boot_receipt_root": Value::Null, "effective_posture": Value::Null }),
    }
}

/// POST /v1/hypervisor/hypervisoros/node-enforcement/observations
pub(crate) async fn handle_observation_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let profile_ref = body_str(&body, "node_enforcement_profile_ref");
    let node_ref = body_str(&body, "node_ref");
    if !profile_ref.starts_with("node-enforcement://") || !node_ref.starts_with("runtime://") {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &OBSERVATION.code("subject_required"),
            "node_enforcement_profile_ref is a node-enforcement:// ref and node_ref a runtime:// ref",
        );
    }
    let platform = body.get("platform").cloned().unwrap_or(Value::Null);
    if platform.get("os").and_then(Value::as_str).is_none()
        || platform.get("kernel").and_then(Value::as_str).is_none()
        || platform.get("arch").and_then(Value::as_str).is_none()
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &OBSERVATION.code("platform_required"),
            "platform names the observed os, kernel and arch",
        );
    }
    let mechanisms = match validate_mechanisms(&body) {
        Ok(mechanisms) => mechanisms,
        Err(response) => return response,
    };
    let resource = format!(
        "{}{}/{}",
        OBSERVATION.ref_scheme,
        slug(&profile_ref),
        slug(&node_ref)
    );
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &OBSERVATION,
        resource,
        OBSERVATION_FIELDS,
        OBSERVATION_SERVER_RESOLVED,
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let revision = ctx.stream.len() as u64 + 1;
    let predecessor = head_record(&ctx.stream)
        .map(|record| json!(format!("{}/revision/{}", ctx.resource, revision - 1)))
        .unwrap_or(Value::Null);
    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": OBSERVATION.schema_version,
        "observation_ref": ctx.resource,
        "revision": revision,
        "predecessor_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "principal_ref": ctx.caller.identity.principal_ref,
        "node_enforcement_profile_ref": profile_ref,
        "node_ref": node_ref,
        "platform": { "os": platform["os"], "kernel": platform["kernel"], "arch": platform["arch"] },
        "observed_at": rfc3339_ms(recorded_at_ms),
        "mechanisms": mechanisms,
        "measured_boot": measured_boot_summary(&st.data_dir, &node_ref),
        "known_gaps": strings(&list(&body, "known_gaps")),
        "status": "observed",
        "receipt_refs": [format!("receipt://hypervisoros/node-enforcement-observation/{}/{}/{revision}", slug(&profile_ref), slug(&node_ref))],
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    let content_hash = match OBSERVATION.content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &OBSERVATION.code("content_hash_failed"),
                reason,
            )
        }
    };
    let coverage = match produce_node_coverage(&st, &ctx.caller, &record, &content_hash) {
        Ok(coverage) => coverage,
        Err(reason) => {
            return bad(
                StatusCode::CONFLICT,
                &OBSERVATION.code("coverage_production_failed"),
                reason,
            )
        }
    };
    finish_admission(
        &OBSERVATION,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        OBSERVATION.record_key,
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({ "coverage_declarations": coverage }),
    )
}

/// GET /v1/hypervisor/hypervisoros/node-enforcement/observations
pub(crate) async fn handle_observation_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(
        &st,
        &headers,
        &OBSERVATION,
        "node_enforcement_profile_observations",
    )
}

/// GET /v1/hypervisor/hypervisoros/node-enforcement/observations/:profile/:node
pub(crate) async fn handle_observation_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path((profile, node)): Path<(String, String)>,
) -> Reply {
    // The path names the profile and node refs; the family key is their slugs, as admission wrote it.
    let resource = format!(
        "{}{}/{}",
        OBSERVATION.ref_scheme,
        slug(&profile),
        slug(&node)
    );
    match read_family(&st, &headers, &OBSERVATION, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &OBSERVATION.code("absent"),
            "no observation answers to that profile and node",
        ),
        Ok((_, stream)) => (StatusCode::OK, Json(family_view(&stream))),
        Err(response) => response,
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct CoverageQuery {
    pub(crate) profile_ref: Option<String>,
}

/// GET /v1/hypervisor/hypervisoros/node-enforcement/coverage?profile_ref=… — the produced
/// declarations exactly as the enforcement-coverage registry resolves them for the node profile.
pub(crate) async fn handle_node_coverage(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<CoverageQuery>,
) -> Reply {
    if let Err(error) = resolve_request_identity(&st.data_dir, &headers) {
        return scope_refusal_reply(error);
    }
    let Some(profile_ref) = query
        .profile_ref
        .filter(|value| value.starts_with("node-enforcement://"))
    else {
        return bad(
            StatusCode::BAD_REQUEST,
            &OBSERVATION.code("profile_ref_required"),
            "profile_ref is a node-enforcement:// ref",
        );
    };
    let registry = match st.enforcement_coverage_registry.lock() {
        Ok(registry) => registry,
        Err(_) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                &OBSERVATION.code("coverage_unavailable"),
                "the enforcement-coverage registry is unavailable",
            )
        }
    };
    match super::enforcement_coverage_routes::resolve_node_profile(&registry, &profile_ref) {
        Ok(declarations) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "profile_ref": profile_ref, "declarations": declarations })),
        ),
        Err(reason) => bad(
            StatusCode::NOT_FOUND,
            &OBSERVATION.code("coverage_absent"),
            reason,
        ),
    }
}

// ================================================================================== the producer

fn mechanism_kind(mechanism: &str) -> &'static str {
    match mechanism {
        "daemon_gate" => "daemon_gate",
        "sandbox_profile" => "sandbox",
        "seccomp" => "seccomp",
        "lsm_ebpf" => "lsm",
        "egress_policy" => "network_proxy",
        "executable_policy" | "hash_signature_path_policy" => "platform_native_privileged",
        "datawall" => "datawall",
        "log_redaction" => "platform_native_user_space",
        "ctee_custody_check" => "ctee_policy",
        "tee_attestation" => "tee_attestation",
        _ => "other_declared",
    }
}

fn mode_rank(mode: &str) -> u8 {
    match mode {
        "active_enforcement" => 4,
        "audit_only" => 3,
        "passive_observation" => 2,
        "receipt_ingestion_only" => 1,
        _ => 0,
    }
}

fn privilege_rank(privilege: &str) -> u8 {
    match privilege {
        "hardware_backed" => 4,
        "kernel" => 3,
        "os_privileged" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

/// One `EnforcementCoverageDeclaration` for one action class, derived from the observed mechanisms
/// that cover it. Facts are claimed from what was OBSERVED, never from what a profile promised:
/// only an active mechanism with verification evidence mediates or prevents; only one with a
/// receipt contract receipts; audit and passive mechanisms observe and attribute at most; the
/// measured-boot receipt discovers and attributes only.
fn node_declaration(
    observation: &Value,
    observation_hash: &str,
    action_class: &str,
    evaluated_at: &str,
    valid_until: &str,
) -> Value {
    let profile_ref = text(observation, "node_enforcement_profile_ref");
    let node_ref = text(observation, "node_ref");
    let covering: Vec<&Value> = observation["mechanisms"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|mechanism| {
            list(mechanism, "action_classes")
                .iter()
                .any(|class| class == action_class)
        })
        .collect();
    let active: Vec<&Value> = covering
        .iter()
        .copied()
        .filter(|m| {
            text(m, "mode") == "active_enforcement"
                && !list(m, "verification_evidence_refs").is_empty()
        })
        .collect();
    let observing: Vec<&Value> = covering
        .iter()
        .copied()
        .filter(|m| {
            matches!(
                text(m, "mode").as_str(),
                "audit_only" | "passive_observation"
            ) && !list(m, "verification_evidence_refs").is_empty()
        })
        .collect();
    let receipted = active
        .iter()
        .any(|m| !list(m, "receipt_contract_refs").is_empty());
    let measured = observation
        .pointer("/measured_boot/boot_receipt_root")
        .and_then(Value::as_str)
        .is_some();
    let mediated = !active.is_empty();
    let observable = mediated || !observing.is_empty();
    let attributable = observable || measured;
    let discovered = attributable;
    let operating_mode = covering
        .iter()
        .map(|m| text(m, "mode"))
        .max_by_key(|mode| mode_rank(mode))
        .unwrap_or_else(|| "uncovered".to_string());
    let privilege = covering
        .iter()
        .map(|m| text(m, "required_privilege"))
        .max_by_key(|p| privilege_rank(p))
        .unwrap_or_else(|| "user".to_string());
    let mut evidence: Vec<String> = covering
        .iter()
        .flat_map(|m| list(m, "verification_evidence_refs"))
        .collect();
    if let Some(root) = observation
        .pointer("/measured_boot/boot_receipt_root")
        .and_then(Value::as_str)
    {
        // The committed receipt, named in the daemon's own boot-receipt family by its root — a
        // receipt:// reference, the coverage contract's evidence vocabulary.
        evidence.push(format!(
            "receipt://hypervisoros/boot-receipt/{}",
            root.trim_start_matches("sha256:")
        ));
    }
    evidence.push(NODE_PRODUCER_IMPLEMENTATION_REF.to_string());
    let receipt_contracts: Vec<String> = active
        .iter()
        .flat_map(|m| list(m, "receipt_contract_refs"))
        .collect();
    let mechanisms: Vec<Value> = covering
        .iter()
        .map(|m| {
            let mode = text(m, "mode");
            let verified = !list(m, "verification_evidence_refs").is_empty();
            let mut roles = vec!["discovery", "observation", "attribution"];
            if mode == "active_enforcement" && verified {
                roles.push("mediation");
                roles.push("prevention");
                if !list(m, "receipt_contract_refs").is_empty() {
                    roles.push("receipt_emission");
                }
            }
            json!({
                "mechanism_id": format!("node-{}", text(m, "mechanism").replace('_', "-")),
                "kind": mechanism_kind(&text(m, "mechanism")),
                "implementation_ref": format!("node-enforcement://mechanism/{}", text(m, "mechanism")),
                "version": "observed",
                "roles": roles,
            })
        })
        .collect();
    let platform = &observation["platform"];
    let uncovered = covering.is_empty();
    json!({
        "schema_version": "ioi.components.daemon-runtime.enforcement-coverage-declaration.v1",
        "declaration_id": format!("enforcement-coverage://{}/{}/{action_class}", slug(&profile_ref), slug(&node_ref)),
        "subject": {
            "kind": "node_enforcement_profile",
            "profile_or_adapter_ref": profile_ref,
            "version": format!("{}.0.0", observation["revision"].as_u64().unwrap_or(1)),
            "content_hash": observation_hash,
            "implementation_ref": NODE_PRODUCER_IMPLEMENTATION_REF,
            "deployment_profile_ref": node_ref,
        },
        "scope": { "surface": "node", "action_class": action_class, "boundary": "host", "scope_ref": node_ref },
        "claims": {
            "discovered": discovered, "observable": observable, "attributable": attributable,
            "mediated": mediated, "preventable": mediated, "receipted": receipted, "uncovered": uncovered,
        },
        "mechanisms": mechanisms,
        "platform": {
            "family": match text(platform, "os").as_str() { "linux" => "linux", "macos" => "macos", "windows" => "windows", _ => "other_declared" },
            "version": text(platform, "kernel"),
            "architecture": match text(platform, "arch").as_str() { "x86_64" => "x86_64", "aarch64" => "aarch64", _ => "other_declared" },
            "execution_context": "managed_host",
            "native_security_facility_refs": [],
        },
        "required_privilege": privilege,
        "custom_os_kernel_module_required_for_claim": false,
        "bypass": {
            "resistance": if mediated { if measured { "measured_host" } else { "managed_host" } } else { "none" },
            "assumptions": ["Facts are claimed from the physical enforcement owner's admitted observation of the node, never from a profile's promise or a measured-boot receipt alone."],
            "known_bypass_refs": [],
        },
        "operating_mode": operating_mode,
        "decision_source": { "kind": if mediated { "owner_policy_service" } else { "none" }, "decision_source_ref": if mediated { json!(profile_ref) } else { Value::Null }, "policy_ref": if mediated { json!(profile_ref) } else { Value::Null }, "authority_provider_ref": Value::Null },
        "final_invoker": { "kind": if mediated { "workload_broker" } else { "none" }, "invoker_ref": if mediated { json!(node_ref) } else { Value::Null } },
        "availability": { "online_behavior": if mediated { "enforce" } else { "unknown" }, "offline_behavior": if mediated { "deny" } else { "unknown" }, "failure_posture": if mediated { "fail_closed" } else { "unknown" } },
        "receipt": { "scope": if receipted { "decision_and_effect" } else if observable { "observation" } else { "none" }, "contract_refs": receipt_contracts, "evidence_refs": if observable { evidence.clone() } else { vec![] } },
        "verification": {
            "verifier_ref": NODE_VERIFIER_REF,
            "verification_method_ref": NODE_VERIFICATION_METHOD_REF,
            "evidence_refs": evidence,
            "evaluated_at": evaluated_at,
            "freshness_status": "current",
            "valid_until": valid_until,
            "freshness_policy_ref": NODE_FRESHNESS_POLICY_REF,
        },
        "known_gaps": if uncovered { json!([{ "gap_id": format!("no-observed-mechanism-{}", action_class.replace('_', "-")), "description": format!("no observed mechanism covers {action_class} on this node"), "affected_path": format!("node.{action_class}"), "mitigation_ref": Value::Null }]) } else { json!([]) },
        "limitations": ["Coverage is bounded to what the physical enforcement owner observed on this node; a mechanism not observed is not covered."],
        "status": "verified",
    })
}

/// Produce and admit one declaration per action class named by the observation's mechanisms.
fn produce_node_coverage(
    st: &DaemonState,
    caller: &WriteCaller,
    observation: &Value,
    observation_hash: &str,
) -> Result<Vec<Value>, String> {
    let classes: BTreeSet<String> = observation["mechanisms"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|m| list(m, "action_classes"))
        .collect();
    let now = now_ms();
    let evaluated_at = rfc3339_ms(now);
    let valid_until = rfc3339_ms(now + OBSERVATION_VALIDITY_MS);
    let mut guard = st
        .enforcement_coverage_registry
        .lock()
        .map_err(|_| "enforcement-coverage registry lock is poisoned".to_string())?;
    let mut next = guard.clone();
    let mut admitted = Vec::new();
    let mut pending = Vec::new();
    for action_class in classes {
        let declaration = node_declaration(
            observation,
            observation_hash,
            &action_class,
            &evaluated_at,
            &valid_until,
        );
        let content_hash = canonical_value_hash(&declaration)?;
        let artifact_ref = format!(
            "artifact://ioi/enforcement-coverage/{}",
            content_hash.trim_start_matches("sha256:")
        );
        let declaration_id = text(&declaration, "declaration_id");
        let previous = next
            .operability_index(now as i64)
            .into_iter()
            .find(|entry| entry.declaration_id == declaration_id && entry.is_logical_head)
            .map(|entry| entry.declaration_content_hash);
        let request = EnforcementCoverageAdmissionRequest {
            declaration_artifact_ref: artifact_ref.clone(),
            declaration_content_hash: content_hash.clone(),
            declaration: declaration.clone(),
            expected_previous_hash: previous,
            evidence_receipt_ref: list(observation, "receipt_refs")
                .first()
                .cloned()
                .unwrap_or_default(),
            admitted_at: evaluated_at.clone(),
        };
        let already_durable = guard
            .operability_index(now as i64)
            .into_iter()
            .any(|entry| entry.declaration_content_hash == content_hash);
        let operability = next
            .admit(request.clone(), now as i64)
            .map_err(|error| format!("coverage admission failed for {action_class}: {error}"))?;
        let projection = json!({
            "declaration_id": operability.declaration_id,
            "action_class": action_class,
            "artifact_ref": artifact_ref,
            "content_hash": content_hash,
            "operable": operability.operable,
            "currentness": operability.currentness,
            "claims": declaration["claims"],
            "operating_mode": declaration["operating_mode"],
            "replayed": already_durable,
        });
        if already_durable {
            admitted.push(projection);
        } else {
            pending.push((request, projection));
        }
    }
    for (request, projection) in pending {
        let idempotency_key = canonical_value_hash(&json!({
            "domain": "ioi.enforcement-coverage-admission-idempotency-jcs-sha256.v1",
            "caller_key": caller.idempotency_key,
            "declaration_content_hash": request.declaration_content_hash,
        }))?;
        let admission_caller = WriteCaller {
            identity: caller.identity.clone(),
            owner_ref: caller.owner_ref.clone(),
            idempotency_key,
        };
        let payload = json!({
            "schema_version": COVERAGE_ADMISSION_PAYLOAD_SCHEMA,
            "owner_ref": caller.owner_ref,
            "resource_ref": request.declaration_artifact_ref,
            "admission_request": request,
        });
        admit_owner_scoped_write(
            &st.data_dir,
            &admission_caller,
            COVERAGE_OWNER_NAMESPACE,
            COVERAGE_RESOURCE_KIND,
            payload["resource_ref"].as_str().unwrap_or_default(),
            COVERAGE_ADMISSION_OP,
            None,
            &payload,
        )
        .map_err(|(status, Json(body))| {
            format!("coverage Agentgres admission failed ({status}): {body}")
        })?;
        admitted.push(projection);
    }
    *guard = next;
    Ok(admitted)
}

// ==================================================================================== the claim

struct Finding {
    code: &'static str,
    detail: String,
}

struct Derivation {
    evidence: Value,
    declared: Value,
    contractual: bool,
    isolation: bool,
    declared_confidential: bool,
    custody: bool,
    refusals: Vec<Finding>,
    downgrades: Vec<String>,
    expires_at: Option<String>,
}

fn class_rank(class: &str) -> u8 {
    CLASSES.iter().position(|c| *c == class).unwrap_or(0) as u8
}

/// The egress coverage declaration of a node profile and whether it claims preventable under active enforcement.
fn egress_coverage(declarations: &[Value]) -> (Value, bool) {
    declarations
        .iter()
        .find(|d| d.pointer("/scope/action_class").and_then(Value::as_str) == Some("egress"))
        .map(|egress| {
            (
                egress.get("declaration_id").cloned().unwrap_or(Value::Null),
                egress
                    .pointer("/claims/preventable")
                    .and_then(Value::as_bool)
                    == Some(true)
                    && egress.get("operating_mode").and_then(Value::as_str)
                        == Some("active_enforcement"),
            )
        })
        .unwrap_or((Value::Null, false))
}

/// The findings that are the ROUTE's and the REQUEST's alone — a custody a remote provider can read,
/// owners left unnamed — reported whether or not any receipt appraised the node.
fn route_level_findings(declared: &Value, key_owner: &str, data_owner: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let remote_readable = declared["remote_provider_can_read_weights"]
        .as_bool()
        .unwrap_or(true);
    if remote_readable
        || !matches!(
            text(declared, "mount_target").as_str(),
            "local_device" | "user_owned_node" | "tee_session" | "customer_cloud"
        )
    {
        findings.push(Finding {
            code: "route_custody_remote",
            detail: format!(
                "the route mounts {} weights on {}; a provider that can read the weights or the plaintext is not no-plaintext custody",
                text(declared, "weight_class"),
                text(declared, "mount_target")
            ),
        });
    }
    if key_owner.is_empty() || data_owner.is_empty() {
        findings.push(Finding {
            code: "owners_required",
            detail: "key_owner_ref and protected_data_owner_ref name who holds the keys and the protected data".into(),
        });
    }
    findings
}

struct AppraisalInputs<'a> {
    record: &'a Value,
    receipt: &'a Value,
    declared_boot_root: Option<&'a str>,
    profile_ref: &'a str,
    relying_party: &'a str,
    declared: &'a Value,
    key_owner: &'a str,
    data_owner: &'a str,
    egress: &'a (Value, bool),
    now: u64,
}

struct Appraised {
    evidence: Value,
    ok: bool,
    findings: Vec<Finding>,
    expires_at: Option<String>,
}

/// THE APPRAISAL RULES, pure over resolved inputs: separated roles, a single-use nonce, a passing
/// appraisal inside its expiry, current endorsements and reference values, a measured posture, the
/// receipt verified against the estate's declared boot profile, a measured node, a route custody no
/// provider can read, both owners named, and physical egress coverage that prevents. Each miss is a
/// typed finding; the custody-proven class needs all of them.
fn appraise_receipt(inputs: &AppraisalInputs<'_>) -> Appraised {
    let AppraisalInputs {
        record,
        receipt,
        declared_boot_root,
        profile_ref,
        relying_party,
        declared,
        key_owner,
        data_owner,
        egress,
        now,
    } = inputs;
    let assurance = receipt
        .pointer("/observation/attestation_assurance")
        .cloned()
        .unwrap_or(Value::Null);
    let observation = receipt.get("observation").cloned().unwrap_or(Value::Null);
    let attester = text(&assurance, "attester_ref");
    let verifier = text(&assurance, "verifier_ref");
    let appraiser = text(&assurance, "appraiser_ref");
    let relying = relying_party.to_string();
    let remote_readable = declared["remote_provider_can_read_weights"]
        .as_bool()
        .unwrap_or(true);
    let mut findings: Vec<Finding> = Vec::new();
    let mut expires_at = None;
    let mut refuse = |code: &'static str, detail: String| findings.push(Finding { code, detail });
    if attester.is_empty() || appraiser.is_empty() || verifier.is_empty() {
        refuse(
            "appraisal_roles_missing",
            "the receipt names no attester, verifier or appraiser".into(),
        );
    } else if attester == appraiser
        || appraiser == relying
        || attester == relying
        || verifier == attester
    {
        refuse("appraisal_role_confusion", format!("attester {attester}, verifier {verifier}, appraiser {appraiser} and relying party {relying} are not separated roles"));
    }
    if text(&assurance, "nonce").is_empty() {
        refuse(
            "nonce_missing",
            "the appraisal carries no nonce; freshness cannot be shown".into(),
        );
    } else if text(&assurance, "nonce_single_use_status") != "consumed_for_this_appraisal" {
        refuse(
            "nonce_replayed",
            format!(
                "the nonce is {}; only a nonce consumed for this appraisal proves freshness",
                text(&assurance, "nonce_single_use_status")
            ),
        );
    }
    match text(&assurance, "appraisal_status").as_str() {
        "pass" => {}
        "indeterminate" | "" => refuse(
            "appraisal_unavailable",
            "the appraisal is indeterminate or absent; an ambiguous appraisal never rounds up"
                .into(),
        ),
        other => refuse(
            "appraisal_failed",
            format!("the appraisal status is {other}"),
        ),
    }
    match text(&assurance, "appraisal_expires_at").as_str() {
        "" => refuse("appraisal_stale", "the appraisal declares no expiry".into()),
        when => match parse_rfc3339_ms(when) {
            Some(deadline) if deadline > *now => expires_at = Some(when.to_string()),
            _ => refuse(
                "appraisal_stale",
                format!("the appraisal expired at {when}"),
            ),
        },
    }
    if text(&assurance, "revocation_status") != "current" {
        refuse(
            "endorsement_withdrawn",
            format!(
                "the appraisal's revocation status is {}",
                text(&assurance, "revocation_status")
            ),
        );
    }
    if list(&assurance, "endorsement_refs").is_empty()
        || list(&assurance, "reference_value_refs").is_empty()
    {
        refuse(
            "endorsement_missing",
            "the appraisal names no endorsement or reference values".into(),
        );
    }
    let effective_posture = text(&assurance, "effective_posture");
    if !APPRAISED_POSTURES.contains(&effective_posture.as_str())
        || assurance
            .get("hardware_or_measured_attested")
            .and_then(Value::as_bool)
            != Some(true)
    {
        refuse(
            "posture_insufficient",
            format!(
                "effective posture {effective_posture:?} is not hardware- or measurement-attested"
            ),
        );
    }
    let verified_against = receipt
        .pointer("/verification/verified_against_boot_profile_root")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if *declared_boot_root != Some(verified_against.as_str()) {
        refuse("measurement_substituted", format!("the receipt was verified against boot profile root {verified_against:?} but the estate declares {declared_boot_root:?}"));
    }
    if !matches!(text(record, "status").as_str(), "measured" | "ready") {
        refuse(
            "node_not_measured",
            format!("the node is {}", text(record, "status")),
        );
    }
    for finding in route_level_findings(declared, key_owner, data_owner) {
        refuse(finding.code, finding.detail);
    }
    let (egress_ref, egress_preventable) = (egress.0.clone(), egress.1);
    if !egress_preventable {
        refuse("egress_not_preventable", format!("the node profile {profile_ref:?} has no active, verified egress coverage claiming preventable; audited egress is not prevented egress"));
    }
    let ok = findings.is_empty();
    let observer = if key_owner.is_empty() {
        json!([])
    } else {
        json!([key_owner])
    };
    let evidence = json!({
        "node_ref": text(record, "node_id"),
        "boot_receipt_root": boot_receipt_root(receipt).ok(),
        "boot_epoch": observation.get("boot_epoch").cloned().unwrap_or(Value::Null),
        "measurement_method": observation.get("measurement_method").cloned().unwrap_or(Value::Null),
        "effective_posture": effective_posture,
        "appraisal": {
            "attester_ref": attester, "verifier_ref": verifier, "appraiser_ref": appraiser, "relying_party_ref": relying,
            "nonce": assurance["nonce"], "nonce_single_use_status": assurance["nonce_single_use_status"],
            "appraisal_status": assurance["appraisal_status"], "appraised_at": assurance["appraised_at"], "appraisal_expires_at": assurance["appraisal_expires_at"],
            "endorsement_refs": strings(&list(&assurance, "endorsement_refs")), "reference_value_refs": strings(&list(&assurance, "reference_value_refs")),
            "revocation_status": assurance["revocation_status"],
        },
        "key_owner_ref": if key_owner.is_empty() { Value::Null } else { json!(key_owner) },
        "protected_data_owner_ref": if data_owner.is_empty() { Value::Null } else { json!(data_owner) },
        "observable_paths": {
            "storage": { "observer_refs": observer.clone(), "observes": "plaintext" },
            "model": { "observer_refs": observer.clone(), "observes": if remote_readable { "plaintext" } else { "handles" } },
            "tool": { "observer_refs": [], "observes": "nothing" },
            "egress": { "observer_refs": [], "observes": if egress_preventable { "nothing" } else { "plaintext" } },
        },
        "egress_coverage_declaration_ref": egress_ref,
        "egress_preventable": egress_preventable,
    });
    Appraised {
        evidence,
        ok,
        findings,
        expires_at,
    }
}

fn empty_custody() -> Value {
    json!({
        "node_ref": Value::Null, "boot_receipt_root": Value::Null, "boot_epoch": Value::Null, "measurement_method": Value::Null, "effective_posture": Value::Null,
        "appraisal": { "attester_ref": Value::Null, "verifier_ref": Value::Null, "appraiser_ref": Value::Null, "relying_party_ref": Value::Null, "nonce": Value::Null, "nonce_single_use_status": Value::Null, "appraisal_status": Value::Null, "appraised_at": Value::Null, "appraisal_expires_at": Value::Null, "endorsement_refs": [], "reference_value_refs": [], "revocation_status": Value::Null },
        "key_owner_ref": Value::Null, "protected_data_owner_ref": Value::Null,
        "observable_paths": { "storage": { "observer_refs": [], "observes": "nothing" }, "model": { "observer_refs": [], "observes": "nothing" }, "tool": { "observer_refs": [], "observes": "nothing" }, "egress": { "observer_refs": [], "observes": "nothing" } },
        "egress_coverage_declaration_ref": Value::Null, "egress_preventable": false,
    })
}

fn declared_posture(route: &Value) -> Value {
    let custody = &route["custody"];
    let weight_class = text(custody, "weight_class");
    let mount_target = text(custody, "mount_target");
    let remote_readable = mount_target == "provider_api"
        || mount_target == "rented_gpu"
        || matches!(
            weight_class.as_str(),
            "remote_api_private_weight"
                | "provider_trust_remote_mount"
                | "forbidden_plaintext_mount"
        );
    json!({
        "execution_privacy_posture": text(custody, "execution_privacy_posture"),
        "weight_class": weight_class,
        "mount_target": mount_target,
        "remote_provider_can_read_weights": remote_readable,
    })
}

#[allow(clippy::too_many_arguments)]
fn derive(
    st: &DaemonState,
    identity: &RequestIdentity,
    owner_ref: &str,
    route: &Value,
    body: &Value,
) -> Derivation {
    let mut refusals = Vec::new();
    let mut downgrades = Vec::new();
    let declared = declared_posture(route);
    let posture = text(&declared, "execution_privacy_posture");
    let remote_readable = declared["remote_provider_can_read_weights"]
        .as_bool()
        .unwrap_or(true);
    // The plane's custody admission groups private_native, ctee_split and confidential_compute as its
    // private postures; the label is recorded verbatim and never promoted — the class is derived from
    // the custody facts (mount target, weight class, remote readability).
    let declared_confidential = matches!(
        posture.as_str(),
        "private_native" | "ctee_split" | "confidential_compute"
    ) && !remote_readable;

    // ---- contractual: the provider's promise, resolved through the rights contract bound to this route
    let mut contractual_evidence = json!({ "rights_contract_revision_ref": Value::Null, "provider_use_terms_hash": Value::Null, "retention_posture": Value::Null });
    let mut contractual = false;
    let contract_ref = body_str(body, "rights_contract_revision_ref");
    if !contract_ref.is_empty() {
        match resolve_admitted_model_route_rights_contract(&st.data_dir, identity, Some(owner_ref), &contract_ref) {
            Err(_) => refusals.push(Finding { code: "contract_unresolvable", detail: format!("{contract_ref} is not an admitted rights contract revision this identity can read") }),
            Ok(contract) => {
                let bound = contract.record.pointer("/route_binding/route_ref").and_then(Value::as_str).unwrap_or_default().to_string();
                let route_binding = text(route, "route_ref");
                if bound.is_empty() || bound != route_binding {
                    refusals.push(Finding { code: "contract_route_mismatch", detail: format!("{contract_ref} binds route {bound:?}, not this route's {route_binding:?}") });
                } else {
                    let use_terms = contract.record.get("provider_use_of_customer_material").cloned().unwrap_or(Value::Null);
                    let prohibited = ["provider_model_training", "request_or_prompt_logging", "human_review", "cross_customer_aggregation", "publication"]
                        .iter()
                        .all(|key| use_terms.get(*key).and_then(Value::as_str) == Some("prohibited"));
                    let retention = text(&contract.record, "retention_posture");
                    let status = text(&contract.record, "status");
                    let live = status == "active" && contract.record.pointer("/revocation/revocation_state").and_then(Value::as_str) != Some("revoked");
                    if !live {
                        refusals.push(Finding { code: "contract_not_live", detail: format!("{contract_ref} is {status}; a revoked or inactive contract promises nothing") });
                    } else if !prohibited || retention != "zero_retention" {
                        refusals.push(Finding { code: "contract_terms_insufficient", detail: format!("{contract_ref} does not prohibit every provider use of customer material with zero retention; its terms are evidence of disclosure, not of privacy") });
                    } else {
                        contractual = true;
                        contractual_evidence = json!({
                            "rights_contract_revision_ref": contract.revision_ref,
                            "provider_use_terms_hash": canonical_value_hash(&json!({ "provider_use_of_customer_material": use_terms, "retention_posture": retention })).ok(),
                            "retention_posture": retention,
                        });
                    }
                }
            }
        }
    }

    // ---- isolation: an admitted immutable workload isolation binding the caller names by its WorkRun
    let mut isolation_evidence = json!({ "binding_ref": Value::Null, "binding_hash": Value::Null });
    let mut isolation = false;
    let workrun_ref = body_str(body, "isolation_workrun_ref");
    if !workrun_ref.is_empty() {
        let workrun = read_record_dir(&st.data_dir, "workruns")
            .into_iter()
            .find(|record| {
                record.get("workrun_id").and_then(Value::as_str) == Some(workrun_ref.as_str())
                    || record.get("id").and_then(Value::as_str) == Some(workrun_ref.as_str())
            });
        match workrun.and_then(|record| {
            record
                .pointer("/workload_isolation_admission/binding")
                .cloned()
        }) {
            Some(binding)
                if binding.get("binding_ref").and_then(Value::as_str).is_some()
                    && binding
                        .get("binding_hash")
                        .and_then(Value::as_str)
                        .is_some() =>
            {
                isolation = true;
                isolation_evidence = json!({ "binding_ref": binding["binding_ref"], "binding_hash": binding["binding_hash"] });
            }
            _ => refusals.push(Finding {
                code: "isolation_binding_unresolvable",
                detail: format!(
                    "{workrun_ref} is not a WorkRun with an admitted workload isolation binding"
                ),
            }),
        }
    }

    // ---- custody: the node's verified boot receipt and its appraisal, the owners, the paths, the egress coverage
    let mut custody_evidence = empty_custody();
    let mut custody = false;
    let mut expires_at = None;
    let node_ref = body_str(body, "node_ref");
    if !node_ref.is_empty() {
        let key_owner = body_str(body, "key_owner_ref");
        let data_owner = body_str(body, "protected_data_owner_ref");
        match committed_boot_receipt(&st.data_dir, &node_ref) {
            None => {
                refusals.push(Finding { code: "appraisal_unavailable", detail: format!("{node_ref} holds no verified measured-boot receipt in the node-attestation plane; nothing appraised this node") });
                refusals.extend(route_level_findings(&declared, &key_owner, &data_owner));
            }
            Some((record, receipt)) => {
                let declared_root = load_node_attestation_source(&st.data_dir)
                    .ok()
                    .and_then(|source| source.boot_profile_root);
                let profile_ref = record
                    .get("node_enforcement_profile_ref")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| {
                        record
                            .pointer("/declaration/node_enforcement_profile_ref")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                let mut egress = (Value::Null, false);
                if let Ok(registry) = st.enforcement_coverage_registry.lock() {
                    if let Ok(declarations) =
                        super::enforcement_coverage_routes::resolve_node_profile(
                            &registry,
                            &profile_ref,
                        )
                    {
                        egress = egress_coverage(&declarations);
                    }
                }
                let appraised = appraise_receipt(&AppraisalInputs {
                    record: &record,
                    receipt: &receipt,
                    declared_boot_root: declared_root.as_deref(),
                    profile_ref: &profile_ref,
                    relying_party: &identity.principal_ref,
                    declared: &declared,
                    key_owner: &key_owner,
                    data_owner: &data_owner,
                    egress: &egress,
                    now: now_ms(),
                });
                refusals.extend(appraised.findings);
                custody_evidence = appraised.evidence;
                expires_at = appraised.expires_at;
                custody = appraised.ok;
            }
        }
    }
    if !custody && !node_ref.is_empty() {
        downgrades.push("custody_proven_no_plaintext not evidenced".to_string());
    }
    Derivation {
        evidence: json!({ "contractual": contractual_evidence, "isolation": isolation_evidence, "custody": custody_evidence }),
        declared,
        contractual,
        isolation,
        declared_confidential,
        custody,
        refusals,
        downgrades,
        expires_at,
    }
}

/// POST /v1/hypervisor/model-routes/:id/assurance
pub(crate) async fn handle_route_assurance_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let Some(route) = load_route_record(&st.data_dir, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            &CLAIM.code("route_unknown"),
            format!("model route '{id}' is not registered"),
        );
    };
    // The plane's admission defaults are not the route's declaration: a route registered with no
    // custody serves null custody members, and no assurance class derives over an undeclared custody.
    if ["weight_class", "mount_target", "execution_privacy_posture"]
        .iter()
        .any(|member| {
            route
                .pointer(&format!("/custody/{member}"))
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        })
    {
        return bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            &CLAIM.code("route_custody_undeclared"),
            "the route declares no custody (weight_class, mount_target and execution_privacy_posture); an assurance class derives only over a declared custody, never over the plane's admission defaults",
        );
    }
    let requested = body_str(&body, "requested_class");
    if !CLASSES.contains(&requested.as_str()) || requested == "unevidenced" {
        return bad(StatusCode::UNPROCESSABLE_ENTITY, &CLAIM.code("class_outside_vocabulary"), format!("requested_class is one of contractual_privacy | workload_isolation | confidential_compute_declared | custody_proven_no_plaintext"));
    }
    let resource = format!("{}{id}", CLAIM.ref_scheme);
    let ctx = match open_write(
        &st,
        &headers,
        &body,
        &CLAIM,
        resource,
        CLAIM_FIELDS,
        CLAIM_SERVER_RESOLVED,
    ) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let derivation = derive(
        &st,
        &ctx.caller.identity,
        &ctx.caller.owner_ref,
        &route,
        &body,
    );
    // The effective class: the strongest class the evidence supports at or below the request.
    let supported: Vec<&str> = [
        ("custody_proven_no_plaintext", derivation.custody),
        ("workload_isolation", derivation.isolation),
        ("contractual_privacy", derivation.contractual),
        (
            "confidential_compute_declared",
            derivation.declared_confidential,
        ),
    ]
    .iter()
    .filter(|(_, ok)| *ok)
    .map(|(class, _)| *class)
    .collect();
    let effective = supported
        .iter()
        .copied()
        .filter(|class| class_rank(class) <= class_rank(&requested))
        .max_by_key(|class| class_rank(class))
        .unwrap_or("unevidenced");
    let outright = derivation.refusals.iter().any(|f| {
        matches!(
            f.code,
            "appraisal_role_confusion"
                | "nonce_replayed"
                | "measurement_substituted"
                | "route_custody_remote"
                | "contract_route_mismatch"
        )
    });
    let status = if effective == "unevidenced" || outright {
        "refused"
    } else {
        "current"
    };
    let downgrade_reason = if effective == requested {
        Value::Null
    } else {
        let first = derivation
            .refusals
            .first()
            .map(|f| format!("{}: {}", f.code, f.detail))
            .unwrap_or_else(|| "the requested class is not evidenced".to_string());
        json!(format!("{first}; effective class {effective}"))
    };
    let revision = ctx.stream.len() as u64 + 1;
    let predecessor = head_record(&ctx.stream)
        .map(|_| json!(format!("{}/revision/{}", ctx.resource, revision - 1)))
        .unwrap_or(Value::Null);
    let epoch = head_record(&ctx.stream)
        .and_then(|record| record["revocation_epoch"].as_u64())
        .unwrap_or(0);
    let recorded_at_ms = now_ms();
    let route_custody_hash = match canonical_value_hash(
        &json!({ "custody": route["custody"], "provider_ref": route["provider_ref"], "endpoint_ref": route["endpoint_ref"], "route_ref": route["route_ref"] }),
    ) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &CLAIM.code("route_hash_failed"),
                reason,
            )
        }
    };
    let record = json!({
        "schema_version": CLAIM.schema_version,
        "claim_ref": ctx.resource,
        "revision": revision,
        "predecessor_ref": predecessor,
        "owner_ref": ctx.caller.owner_ref,
        "principal_ref": ctx.caller.identity.principal_ref,
        "route_ref": format!("model-route://{id}"),
        "route_custody_hash": route_custody_hash,
        "requested_class": requested,
        "effective_class": effective,
        "downgrade_reason": downgrade_reason,
        "declared_posture": derivation.declared,
        "evidence": derivation.evidence,
        "refusals": derivation.refusals.iter().map(|f| json!({ "code": f.code, "detail": f.detail })).collect::<Vec<_>>(),
        "appraised_at": rfc3339_ms(recorded_at_ms),
        "expires_at": if effective == "custody_proven_no_plaintext" { derivation.expires_at.clone().map_or(Value::Null, Value::String) } else { Value::Null },
        "revocation_epoch": if outright { epoch + 1 } else { epoch },
        "status": status,
        "receipt_refs": [format!("receipt://model-router/route-assurance/{id}/{revision}")],
        "admitted_at": admitted_stamp(recorded_at_ms),
    });
    finish_admission(
        &CLAIM,
        &st,
        &ctx.caller,
        &ctx.scope,
        &ctx.resource,
        CLAIM.record_key,
        record,
        ctx.expected_head,
        recorded_at_ms,
        &body,
        json!({ "supported_classes": supported, "downgrades": derivation.downgrades }),
    )
}

/// GET /v1/hypervisor/model-routes/:id/assurance
pub(crate) async fn handle_route_assurance_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Reply {
    let resource = format!("{}{id}", CLAIM.ref_scheme);
    match read_family(&st, &headers, &CLAIM, &resource) {
        Ok((_, stream)) if stream.is_empty() => bad(
            StatusCode::NOT_FOUND,
            &CLAIM.code("absent"),
            "no assurance claim has been derived for that route",
        ),
        Ok((_, stream)) => (StatusCode::OK, Json(family_view(&stream))),
        Err(response) => response,
    }
}

/// GET /v1/hypervisor/route-assurance — the inventory of derived claims this identity can read.
pub(crate) async fn handle_route_assurance_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    inventory(&st, &headers, &CLAIM, "route_assurance_claims")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(mechanisms: Value) -> Value {
        json!({
            "revision": 1,
            "node_enforcement_profile_ref": "node-enforcement://acme/estate-1/default",
            "node_ref": "runtime://acme/estate-1/alpha-node-1",
            "platform": { "os": "linux", "kernel": "6.17.9", "arch": "x86_64" },
            "mechanisms": mechanisms,
            "measured_boot": { "boot_receipt_root": format!("sha256:{}", "cd".repeat(32)), "effective_posture": "measured_boot" },
            "receipt_refs": ["receipt://x/1"],
        })
    }

    #[test]
    fn an_active_verified_mechanism_mediates_and_prevents_and_an_audit_only_one_never_does() {
        let active = observation(
            json!([{ "mechanism": "egress_policy", "mode": "active_enforcement", "action_classes": ["egress"], "verification_evidence_refs": ["evidence://probe/1"], "receipt_contract_refs": ["schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1"], "required_privilege": "os_privileged" }]),
        );
        let d = node_declaration(
            &active,
            "sha256:00",
            "egress",
            "2026-09-16T12:00:00Z",
            "2026-10-16T12:00:00Z",
        );
        assert_eq!(
            d["claims"],
            json!({ "discovered": true, "observable": true, "attributable": true, "mediated": true, "preventable": true, "receipted": true, "uncovered": false })
        );
        assert_eq!(d["operating_mode"], "active_enforcement");
        assert_eq!(d["subject"]["kind"], "node_enforcement_profile");
        let audit = observation(
            json!([{ "mechanism": "lsm_ebpf", "mode": "audit_only", "action_classes": ["egress"], "verification_evidence_refs": ["evidence://audit/1"], "receipt_contract_refs": [], "required_privilege": "kernel" }]),
        );
        let d = node_declaration(
            &audit,
            "sha256:00",
            "egress",
            "2026-09-16T12:00:00Z",
            "2026-10-16T12:00:00Z",
        );
        assert_eq!(d["claims"]["mediated"], false);
        assert_eq!(d["claims"]["preventable"], false);
        assert_eq!(d["claims"]["receipted"], false);
        assert_eq!(d["claims"]["observable"], true);
        assert_eq!(d["operating_mode"], "audit_only");
    }

    #[test]
    fn a_measured_boot_receipt_alone_discovers_and_attributes_only() {
        let bare = observation(
            json!([{ "mechanism": "seccomp", "mode": "uncovered", "action_classes": ["filesystem"], "verification_evidence_refs": [], "receipt_contract_refs": [], "required_privilege": "user" }]),
        );
        let d = node_declaration(
            &bare,
            "sha256:00",
            "egress",
            "2026-09-16T12:00:00Z",
            "2026-10-16T12:00:00Z",
        );
        assert_eq!(d["claims"]["uncovered"], true);
        assert_eq!(d["claims"]["mediated"], false);
        assert_eq!(d["claims"]["preventable"], false);
        assert_eq!(d["operating_mode"], "uncovered");
        let d = node_declaration(
            &bare,
            "sha256:00",
            "filesystem",
            "2026-09-16T12:00:00Z",
            "2026-10-16T12:00:00Z",
        );
        assert_eq!(
            d["claims"]["attributable"], true,
            "the measured-boot receipt attributes"
        );
        assert_eq!(d["claims"]["mediated"], false, "and never mediates");
    }

    #[test]
    fn an_active_mechanism_without_evidence_is_refused_at_admission() {
        let body = json!({ "mechanisms": [{ "mechanism": "egress_policy", "mode": "active_enforcement", "action_classes": ["egress"], "verification_evidence_refs": [], "receipt_contract_refs": [], "required_privilege": "os_privileged" }] });
        let (status, reply) = validate_mechanisms(&body).unwrap_err();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            reply.0["error"]["code"],
            "node_enforcement_observation_active_mechanism_unverified"
        );
        let bad_mode = json!({ "mechanisms": [{ "mechanism": "egress_policy", "mode": "enforced_hard", "action_classes": ["egress"], "verification_evidence_refs": ["e"], "receipt_contract_refs": [], "required_privilege": "user" }] });
        assert_eq!(
            validate_mechanisms(&bad_mode).unwrap_err().1 .0["error"]["code"],
            "node_enforcement_observation_mode_outside_vocabulary"
        );
    }

    fn good_receipt(now: u64) -> Value {
        json!({
            "receipt_id": "receipt://acme/estate-1/boot/alpha-node-1/3", "node_id": "runtime://acme/estate-1/alpha-node-1", "node_record_ref": "hypervisoros-node://acme/estate-1/node/alpha-node-1",
            "observation": { "boot_epoch": 3, "measurement_method": "tpm_quote", "attestation_assurance": {
                "attester_ref": "runtime://acme/estate-1/alpha-node-1", "verifier_ref": "verifier://acme/estate-1/appraiser-service", "appraiser_ref": "appraiser://acme/estate-1/appraiser-service", "relying_party_ref": "runtime://acme/estate-1/daemon",
                "nonce": "9f2c", "nonce_single_use_status": "consumed_for_this_appraisal", "appraisal_status": "pass", "appraised_at": rfc3339_ms(now), "appraisal_expires_at": rfc3339_ms(now + 600_000),
                "endorsement_refs": ["endorsement://acme/tpm-vendor/root"], "reference_value_refs": ["reference://acme/estate-1/pcr-baseline"], "effective_posture": "measured_boot", "hardware_or_measured_attested": true, "revocation_status": "current" } },
            "verification": { "verified_against_boot_profile_root": "sha256:root", "verified_at": Value::Null },
        })
    }

    fn appraise(now: u64, mutate: impl FnOnce(&mut Value, &mut Value, &mut Value)) -> Appraised {
        let mut receipt = good_receipt(now);
        let mut record =
            json!({ "node_id": "runtime://acme/estate-1/alpha-node-1", "status": "ready" });
        let mut declared = json!({ "execution_privacy_posture": "private_native", "weight_class": "public_open_weight", "mount_target": "local_device", "remote_provider_can_read_weights": false });
        mutate(&mut receipt, &mut record, &mut declared);
        appraise_receipt(&AppraisalInputs {
            record: &record,
            receipt: &receipt,
            declared_boot_root: Some("sha256:root"),
            profile_ref: "node-enforcement://acme/estate-1/default",
            relying_party: "user://principal_01",
            declared: &declared,
            key_owner: "org://acme",
            data_owner: "org://acme",
            egress: &(json!("enforcement-coverage://x/egress"), true),
            now,
        })
    }

    fn codes(a: &Appraised) -> Vec<&'static str> {
        a.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn a_complete_appraisal_proves_custody_and_every_miss_is_a_typed_finding() {
        let now = 1_800_000_000_000u64;
        let good = appraise(now, |_, _, _| {});
        assert!(good.ok, "{:?}", codes(&good));
        assert_eq!(
            good.expires_at.as_deref(),
            Some(rfc3339_ms(now + 600_000).as_str())
        );
        assert_eq!(
            good.evidence["observable_paths"]["egress"]["observes"],
            "nothing"
        );
        let confused = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["appraiser_ref"] =
                json!("runtime://acme/estate-1/alpha-node-1");
        });
        assert!(codes(&confused).contains(&"appraisal_role_confusion"));
        let replayed = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["nonce_single_use_status"] =
                json!("already_consumed");
        });
        assert!(codes(&replayed).contains(&"nonce_replayed"));
        let stale = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["appraisal_expires_at"] =
                json!(rfc3339_ms(now - 1));
        });
        assert!(codes(&stale).contains(&"appraisal_stale") && stale.expires_at.is_none());
        let withdrawn = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["revocation_status"] = json!("revoked");
        });
        assert!(codes(&withdrawn).contains(&"endorsement_withdrawn"));
        let indeterminate = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["appraisal_status"] = json!("indeterminate");
        });
        assert!(codes(&indeterminate).contains(&"appraisal_unavailable"));
        let substituted = appraise(now, |r, _, _| {
            r["verification"]["verified_against_boot_profile_root"] = json!("sha256:other");
        });
        assert!(codes(&substituted).contains(&"measurement_substituted"));
        let unmeasured = appraise(now, |_, rec, _| {
            rec["status"] = json!("admitted");
        });
        assert!(codes(&unmeasured).contains(&"node_not_measured"));
        let remote = appraise(now, |_, _, d| {
            d["mount_target"] = json!("provider_api");
            d["remote_provider_can_read_weights"] = json!(true);
        });
        assert!(codes(&remote).contains(&"route_custody_remote"));
        assert_eq!(
            remote.evidence["observable_paths"]["model"]["observes"],
            "plaintext"
        );
        let software = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["effective_posture"] = json!("software_only");
        });
        assert!(codes(&software).contains(&"posture_insufficient"));
        let no_endorsement = appraise(now, |r, _, _| {
            r["observation"]["attestation_assurance"]["endorsement_refs"] = json!([]);
        });
        assert!(codes(&no_endorsement).contains(&"endorsement_missing"));
    }

    #[test]
    fn audited_egress_and_missing_owners_never_prove_custody() {
        let now = 1_800_000_000_000u64;
        let receipt = good_receipt(now);
        let record =
            json!({ "node_id": "runtime://acme/estate-1/alpha-node-1", "status": "ready" });
        let declared = json!({ "execution_privacy_posture": "private_native", "weight_class": "public_open_weight", "mount_target": "local_device", "remote_provider_can_read_weights": false });
        let audited = appraise_receipt(&AppraisalInputs {
            record: &record,
            receipt: &receipt,
            declared_boot_root: Some("sha256:root"),
            profile_ref: "p",
            relying_party: "user://principal_01",
            declared: &declared,
            key_owner: "org://acme",
            data_owner: "org://acme",
            egress: &(json!("enforcement-coverage://x/egress"), false),
            now,
        });
        assert!(!audited.ok && codes(&audited) == vec!["egress_not_preventable"]);
        assert_eq!(
            audited.evidence["observable_paths"]["egress"]["observes"],
            "plaintext"
        );
        let ownerless = appraise_receipt(&AppraisalInputs {
            record: &record,
            receipt: &receipt,
            declared_boot_root: Some("sha256:root"),
            profile_ref: "p",
            relying_party: "user://principal_01",
            declared: &declared,
            key_owner: "",
            data_owner: "",
            egress: &(json!("e"), true),
            now,
        });
        assert!(codes(&ownerless).contains(&"owners_required"));
        let egress = egress_coverage(&[
            json!({ "declaration_id": "d", "scope": { "action_class": "egress" }, "claims": { "preventable": true }, "operating_mode": "audit_only" }),
        ]);
        assert_eq!(
            egress.1, false,
            "a preventable claim under audit-only mode is not prevention"
        );
        assert_eq!(egress_coverage(&[]).1, false);
    }

    #[test]
    fn declared_posture_reads_remote_readability_from_custody() {
        let local = json!({ "custody": { "weight_class": "public_open_weight", "mount_target": "local_device", "execution_privacy_posture": "private_native" } });
        assert_eq!(
            declared_posture(&local)["remote_provider_can_read_weights"],
            false
        );
        let hosted = json!({ "custody": { "weight_class": "remote_api_private_weight", "mount_target": "provider_api", "execution_privacy_posture": "provider_trust" } });
        assert_eq!(
            declared_posture(&hosted)["remote_provider_can_read_weights"],
            true
        );
        assert!(
            class_rank("custody_proven_no_plaintext") > class_rank("workload_isolation")
                && class_rank("workload_isolation") > class_rank("contractual_privacy")
                && class_rank("contractual_privacy") > class_rank("confidential_compute_declared")
                && class_rank("confidential_compute_declared") > class_rank("unevidenced")
        );
    }
}
