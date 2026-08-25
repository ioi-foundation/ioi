//! Live producer and durable owner bridge for enforcement coverage.
//!
//! Callers never submit a `verified` declaration. The daemon derives exact
//! declarations from an admitted profile and its mounted effect boundary,
//! admits them through the services lifecycle, and durably records that
//! lifecycle in owner-scoped Agentgres history. Consumers resolve only through
//! the restored registry.

use std::sync::Mutex;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use ioi_services::agentic::runtime::enforcement_coverage::{
    EnforcementCoverageAdmissionRequest, EnforcementCoverageClaim,
    EnforcementCoverageEvidenceRequirement, EnforcementCoverageRegistry,
    EnforcementCoverageRequirement,
};
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::{admit_owner_scoped_write, stream_tail, WriteCaller};
use super::DaemonState;

const OWNER_NAMESPACE: &str = "hypervisor-enforcement-coverage";
const RESOURCE_KIND: &str = "enforcement-coverage-snapshot";
const ADMISSION_OP: &str = "enforcement_coverage.snapshot.admit";
const ADMISSION_PAYLOAD_SCHEMA: &str = "ioi.hypervisor.enforcement-coverage-admission.v1";
const PRODUCER_IMPLEMENTATION_REF: &str =
    "artifact://ioi/hypervisor-daemon/authority-gateway-coverage-producer/v1";
const VERIFIER_REF: &str = "verifier://ioi/hypervisor-daemon/enforcement-coverage/v1";
const VERIFICATION_METHOD_REF: &str =
    "test-profile://ioi/authority-gateway/pre-effect-runtime-binding/v1";
const FRESHNESS_POLICY_REF: &str = "policy://ioi/authority-gateway/profile-validity";
const GATEWAY_PEP_REF: &str = "runtime://hypervisor-daemon/authority-gateway";
const GATEWAY_AUTHORITY_PROVIDER_REF: &str = "authority-provider://wallet.network";
const GATEWAY_DECISION_RECEIPT: &str =
    "schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1";
const COVERAGE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1";

fn canonical_hash(value: &Value) -> Result<String, String> {
    serde_jcs::to_vec(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|reason| format!("canonical hashing failed: {reason}"))
}

fn durable_admission_receipt(
    data_dir: &str,
    artifact_ref: &str,
    content_hash: &str,
) -> Result<String, String> {
    let tail = stream_tail(RESOURCE_KIND, artifact_ref);
    let history =
        super::substrate_store::read_event_stream_history(data_dir, OWNER_NAMESPACE, &tail)
            .map_err(|error| format!("enforcement-coverage history is unavailable: {error}"))?;
    let entry = history
        .iter()
        .find(|entry| {
            entry.operation.op_kind == ADMISSION_OP
                && entry
                    .operation
                    .payload
                    .pointer("/admission_request/declaration_content_hash")
                    .and_then(Value::as_str)
                    == Some(content_hash)
        })
        .ok_or_else(|| {
            "an in-memory enforcement-coverage artifact has no durable Agentgres admission"
                .to_string()
        })?;
    Ok(agentgres::refs::event_stream_receipt_ref(
        OWNER_NAMESPACE,
        &tail,
        entry.admission_batch_seq,
        &entry.admission_root,
    ))
}

fn required<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("admitted gateway profile lacks {pointer}"))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

pub(crate) fn restore_registry(data_dir: &str) -> Result<EnforcementCoverageRegistry, String> {
    let tails = super::substrate_store::list_event_stream_tails(data_dir, OWNER_NAMESPACE)
        .map_err(|error| format!("enforcement-coverage inventory is unavailable: {error}"))?;
    let mut pending = Vec::new();
    for tail in tails {
        let history =
            super::substrate_store::read_event_stream_history(data_dir, OWNER_NAMESPACE, &tail)
                .map_err(|error| format!("enforcement-coverage history is unavailable: {error}"))?;
        for entry in history {
            if entry.operation.op_kind != ADMISSION_OP
                || entry
                    .operation
                    .payload
                    .get("schema_version")
                    .and_then(Value::as_str)
                    != Some(ADMISSION_PAYLOAD_SCHEMA)
            {
                return Err("enforcement-coverage history contains an unknown operation".into());
            }
            let owner_ref = required(&entry.operation.payload, "/owner_ref")?;
            let resource_ref = required(&entry.operation.payload, "/resource_ref")?;
            let scope =
                super::substrate_store::read_request_scope(data_dir, RESOURCE_KIND, resource_ref)
                    .map_err(|error| {
                        format!("enforcement-coverage scope is unavailable: {error:?}")
                    })?
                    .ok_or_else(|| {
                        "enforcement-coverage admission has no owner scope".to_string()
                    })?;
            if scope.owner_ref != owner_ref
                || scope.tenant_ref != owner_ref
                || scope.resource_kind != RESOURCE_KIND
                || scope.resource_ref != resource_ref
            {
                return Err("enforcement-coverage admission owner scope does not bind".into());
            }
            let request: EnforcementCoverageAdmissionRequest = serde_json::from_value(
                entry
                    .operation
                    .payload
                    .get("admission_request")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
            .map_err(|error| format!("enforcement-coverage admission is malformed: {error}"))?;
            if request.declaration_artifact_ref != resource_ref {
                return Err("enforcement-coverage resource does not bind its artifact ref".into());
            }
            pending.push(request);
        }
    }
    let mut registry = EnforcementCoverageRegistry::default();
    while !pending.is_empty() {
        let before = pending.len();
        let mut deferred = Vec::new();
        for request in pending {
            match registry.admit(request.clone(), now_ms()) {
                Ok(_) => {}
                Err(error) if error.code == "enforcement_coverage_stale_head" => {
                    deferred.push(request)
                }
                Err(error) => {
                    return Err(format!(
                        "enforcement-coverage admitted history is invalid: {error}"
                    ))
                }
            }
        }
        if deferred.len() == before {
            return Err("enforcement-coverage history has an unresolved predecessor cycle".into());
        }
        pending = deferred;
    }
    Ok(registry)
}

pub(crate) fn coordinate_id(
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    scope_ref: &str,
) -> Result<String, String> {
    let digest = canonical_hash(&json!({
        "domain":"ioi.enforcement-coverage-logical-coordinate-jcs-sha256.v1",
        "owner_ref":owner_ref,
        "adapter_ref":required(profile, "/declaration/adapter/adapter_ref")?,
        "surface":required(surface, "/surface")?,
        "action_class":action_class,
        "scope_ref":scope_ref,
    }))?;
    Ok(format!(
        "enforcement-coverage://ioi/authority-gateway/{}",
        digest.trim_start_matches("sha256:")
    ))
}

fn platform() -> Value {
    let family = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        _ => "other_declared",
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => "other_declared",
    };
    let version = if family == "linux" {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .unwrap_or_else(|| "runtime-version-unavailable".into())
    } else {
        "runtime-version-unavailable".into()
    };
    json!({
        "family":family,
        "version":version,
        "architecture":architecture,
        "execution_context":"managed_host",
        "native_security_facility_refs":[],
    })
}

fn declaration(
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    scope_ref: &str,
    profile_admission_receipt_ref: &str,
    observed_proof: Option<(&str, &str)>,
    evaluated_at: &str,
) -> Result<Value, String> {
    let declaration_id = coordinate_id(owner_ref, profile, surface, action_class, scope_ref)?;
    let active = observed_proof.is_some()
        && required(surface, "/mediation_mode")? == "active_pre_effect"
        && required(profile, "/declaration/failure_posture")? == "fail_closed"
        && required(profile, "/declaration/policy_enforcement_point_ref")? == GATEWAY_PEP_REF
        && required(profile, "/declaration/authority_provider_ref")?
            == GATEWAY_AUTHORITY_PROVIDER_REF
        && required(surface, "/final_invoker_ref")? == GATEWAY_PEP_REF;
    let valid_until = required(profile, "/valid_until")?;
    let final_invoker_ref = required(surface, "/final_invoker_ref")?;
    let receipt_contracts: Vec<&str> = surface
        .get("receipt_profile_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|reference| *reference == GATEWAY_DECISION_RECEIPT)
        .collect();
    let verification_evidence = match observed_proof {
        Some((decision_receipt_ref, action_admission_receipt_ref)) => {
            json!([
                decision_receipt_ref,
                action_admission_receipt_ref,
                PRODUCER_IMPLEMENTATION_REF
            ])
        }
        None => json!([profile_admission_receipt_ref, PRODUCER_IMPLEMENTATION_REF]),
    };
    let (
        claims,
        mechanisms,
        operating_mode,
        decision_source,
        final_invoker,
        availability,
        receipt,
        gaps,
        limitations,
    ) = if active {
        (
            json!({"discovered":true,"observable":true,"attributable":true,"mediated":true,"preventable":true,"receipted":true,"uncovered":false}),
            json!([{
                "mechanism_id":"authority-gateway-daemon-gate",
                "kind":"daemon_gate",
                "implementation_ref":PRODUCER_IMPLEMENTATION_REF,
                "version":env!("CARGO_PKG_VERSION"),
                "roles":["discovery","observation","attribution","mediation","prevention","receipt_emission"]
            }]),
            json!("active_enforcement"),
            json!({
                "kind":"daemon_policy_engine",
                "decision_source_ref":required(profile, "/declaration/policy_enforcement_point_ref")?,
                "policy_ref":FRESHNESS_POLICY_REF,
                "authority_provider_ref":required(profile, "/declaration/authority_provider_ref")?,
            }),
            json!({"kind":"daemon","invoker_ref":final_invoker_ref}),
            json!({"online_behavior":"enforce","offline_behavior":"deny","failure_posture":"fail_closed"}),
            json!({"scope":"decision","contract_refs":receipt_contracts,"evidence_refs":[observed_proof.expect("active coverage has observed proof").0]}),
            json!([]),
            json!(["Coverage is bounded to action requests admitted through the daemon Authority Gateway; direct adapter effects remain outside this scope."]),
        )
    } else {
        (
            json!({"discovered":false,"observable":false,"attributable":false,"mediated":false,"preventable":false,"receipted":false,"uncovered":true}),
            json!([]),
            json!("uncovered"),
            json!({"kind":"none","decision_source_ref":Value::Null,"policy_ref":Value::Null,"authority_provider_ref":Value::Null}),
            json!({"kind":"none","invoker_ref":Value::Null}),
            json!({"online_behavior":"unknown","offline_behavior":"deny","failure_posture":"unknown"}),
            json!({"scope":"none","contract_refs":[],"evidence_refs":[]}),
            json!([{
                "gap_id":"no-active-fail-closed-gateway",
                "description":"The admitted surface is not backed by the daemon's exact active fail-closed pre-effect PEP, authority provider, and final invoker.",
                "affected_path":format!("authority_gateway.{}.{}", required(surface, "/surface")?, action_class),
                "mitigation_ref":Value::Null,
            }]),
            json!(["No positive enforcement capability is claimed for this exact surface and action class."]),
        )
    };
    Ok(json!({
        "schema_version":"ioi.components.daemon-runtime.enforcement-coverage-declaration.v1",
        "declaration_id":declaration_id,
        "subject":{
            "kind":"authority_gateway_profile",
            "profile_or_adapter_ref":required(profile, "/profile_ref")?,
            "version":required(profile, "/declaration/adapter/adapter_revision")?,
            "content_hash":required(profile, "/profile_hash")?,
            "implementation_ref":required(profile, "/declaration/adapter/implementation_ref")?,
            "deployment_profile_ref":required(profile, "/declaration/adapter/deployment_profile_ref")?,
        },
        "scope":{
            "surface":required(surface, "/surface")?,
            "action_class":action_class,
            "boundary":"adapter",
            "scope_ref":scope_ref,
        },
        "claims":claims,
        "mechanisms":mechanisms,
        "platform":platform(),
        "required_privilege":"user",
        "custom_os_kernel_module_required_for_claim":false,
        "bypass":{
            "resistance":if active { "managed_host" } else { "none" },
            "assumptions":["Effects enter through the admitted daemon route and exact profile revision."],
            "known_bypass_refs":["risk://ioi/authority-gateway/direct-adapter-effect"],
        },
        "operating_mode":operating_mode,
        "decision_source":decision_source,
        "final_invoker":final_invoker,
        "availability":availability,
        "receipt":receipt,
        "verification":{
            "verifier_ref":VERIFIER_REF,
            "verification_method_ref":VERIFICATION_METHOD_REF,
            "evidence_refs":verification_evidence,
            "evaluated_at":evaluated_at,
            "freshness_status":"current",
            "valid_until":valid_until,
            "freshness_policy_ref":FRESHNESS_POLICY_REF,
        },
        "known_gaps":gaps,
        "limitations":limitations,
        "status":"verified",
    }))
}

pub(crate) fn preflight_gateway_profile(owner_ref: &str, profile: &Value) -> Result<(), String> {
    let scopes = profile
        .pointer("/declaration/required_enforcement_scope_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "gateway profile lacks required enforcement scopes".to_string())?;
    let surfaces = profile
        .pointer("/declaration/action_surfaces")
        .and_then(Value::as_array)
        .ok_or_else(|| "gateway profile lacks action surfaces".to_string())?;
    for surface in surfaces {
        let action_classes = surface
            .get("action_classes")
            .and_then(Value::as_array)
            .ok_or_else(|| "gateway surface lacks action classes".to_string())?;
        for action_class in action_classes.iter().filter_map(Value::as_str) {
            for scope_ref in scopes.iter().filter_map(Value::as_str) {
                let candidate = declaration(
                    owner_ref,
                    profile,
                    surface,
                    action_class,
                    scope_ref,
                    "receipt://ioi/authority-gateway/profile-admission/preflight",
                    None,
                    required(profile, "/created_at")?,
                )?;
                validate_architecture_contract(COVERAGE_CONTRACT, &candidate).map_err(|reason| {
                    format!(
                        "gateway profile cannot produce registered-valid coverage for {action_class}/{scope_ref}: {reason}"
                    )
                })?;
                let positive = declaration(
                    owner_ref,
                    profile,
                    surface,
                    action_class,
                    scope_ref,
                    "receipt://ioi/authority-gateway/profile-admission/preflight",
                    Some((
                        "receipt://ioi/authority-gateway/decision/preflight",
                        "receipt://ioi/authority-gateway/action-admission/preflight",
                    )),
                    required(profile, "/created_at")?,
                )?;
                validate_architecture_contract(COVERAGE_CONTRACT, &positive).map_err(|reason| {
                    format!(
                        "gateway profile cannot produce registered-valid observed coverage for {action_class}/{scope_ref}: {reason}"
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn produce_gateway_coverage(
    registry: &Mutex<EnforcementCoverageRegistry>,
    data_dir: &str,
    caller: &WriteCaller,
    profile: &Value,
    profile_admission_receipt_ref: &str,
    observed_proof: Option<(&str, &str)>,
    evaluated_at: &str,
    only_surface_and_action: Option<(&str, &str)>,
) -> Result<Vec<Value>, String> {
    let mut guard = registry
        .lock()
        .map_err(|_| "enforcement-coverage registry lock is poisoned".to_string())?;
    let mut next = guard.clone();
    let now = now_ms();
    let scopes = profile
        .pointer("/declaration/required_enforcement_scope_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "gateway profile lacks required enforcement scopes".to_string())?;
    let surfaces = profile
        .pointer("/declaration/action_surfaces")
        .and_then(Value::as_array)
        .ok_or_else(|| "gateway profile lacks action surfaces".to_string())?;
    let mut pending_admissions = Vec::new();
    let mut admitted = Vec::new();
    for surface in surfaces {
        if only_surface_and_action.is_some_and(|(surface_name, _)| {
            surface.get("surface").and_then(Value::as_str) != Some(surface_name)
        }) {
            continue;
        }
        let action_classes = surface
            .get("action_classes")
            .and_then(Value::as_array)
            .ok_or_else(|| "gateway surface lacks action classes".to_string())?;
        for action_class in action_classes.iter().filter_map(Value::as_str) {
            if only_surface_and_action
                .is_some_and(|(_, required_action)| action_class != required_action)
            {
                continue;
            }
            for scope_ref in scopes.iter().filter_map(Value::as_str) {
                let declaration_id =
                    coordinate_id(&caller.owner_ref, profile, surface, action_class, scope_ref)?;
                let source_receipt = observed_proof
                    .map(|(_, action_admission)| action_admission)
                    .unwrap_or(profile_admission_receipt_ref);
                if let Some(existing) = guard
                    .snapshot_for_evidence_receipt(source_receipt, &declaration_id, now)
                    .map_err(|error| format!("coverage replay resolution failed: {error}"))?
                {
                    let artifact_ref = existing.operability.declaration_artifact_ref;
                    let content_hash = existing.operability.declaration_content_hash;
                    admitted.push(json!({
                        "declaration_id":existing.operability.declaration_id,
                        "artifact_ref":artifact_ref,
                        "content_hash":content_hash,
                        "operable":existing.operability.operable,
                        "currentness":existing.operability.currentness,
                        "coverage_admission_receipt_ref":durable_admission_receipt(data_dir, &artifact_ref, &content_hash)?,
                        "replayed":true,
                    }));
                    continue;
                }
                let declaration = declaration(
                    &caller.owner_ref,
                    profile,
                    surface,
                    action_class,
                    scope_ref,
                    profile_admission_receipt_ref,
                    observed_proof,
                    evaluated_at,
                )?;
                let previous = next
                    .operability_index(now)
                    .into_iter()
                    .find(|entry| entry.declaration_id == declaration_id && entry.is_logical_head)
                    .map(|entry| entry.declaration_content_hash);
                let content_hash = canonical_hash(&declaration)?;
                let artifact_ref = format!(
                    "artifact://ioi/enforcement-coverage/{}",
                    content_hash.trim_start_matches("sha256:")
                );
                let request = EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: artifact_ref.clone(),
                    declaration_content_hash: content_hash.clone(),
                    declaration: declaration.clone(),
                    expected_previous_hash: previous,
                    evidence_receipt_ref: observed_proof
                        .map(|(_, action_admission)| action_admission)
                        .unwrap_or(profile_admission_receipt_ref)
                        .to_owned(),
                    admitted_at: evaluated_at.to_owned(),
                };
                let already_durable = guard
                    .operability_index(now)
                    .into_iter()
                    .any(|entry| entry.declaration_content_hash == content_hash);
                let operability = next
                    .admit(request.clone(), now)
                    .map_err(|error| format!("coverage admission failed: {error}"))?;
                let mut projection = json!({
                    "declaration_id":operability.declaration_id,
                    "artifact_ref":artifact_ref,
                    "content_hash":content_hash,
                    "operable":operability.operable,
                    "currentness":operability.currentness,
                });
                if already_durable {
                    projection["coverage_admission_receipt_ref"] = json!(
                        durable_admission_receipt(data_dir, &artifact_ref, &content_hash)?
                    );
                    projection["replayed"] = json!(true);
                    admitted.push(projection);
                } else {
                    pending_admissions.push((request, projection));
                }
            }
        }
    }
    for (request, mut projection) in pending_admissions {
        let idempotency_key = canonical_hash(&json!({
            "domain":"ioi.enforcement-coverage-admission-idempotency-jcs-sha256.v1",
            "caller_key":caller.idempotency_key,
            "declaration_content_hash":request.declaration_content_hash,
        }))?;
        let admission_caller = WriteCaller {
            identity: caller.identity.clone(),
            owner_ref: caller.owner_ref.clone(),
            idempotency_key,
        };
        let payload = json!({
            "schema_version":ADMISSION_PAYLOAD_SCHEMA,
            "owner_ref":caller.owner_ref,
            "resource_ref":request.declaration_artifact_ref,
            "admission_request":request,
        });
        let commit = admit_owner_scoped_write(
            data_dir,
            &admission_caller,
            OWNER_NAMESPACE,
            RESOURCE_KIND,
            payload["resource_ref"].as_str().unwrap_or_default(),
            ADMISSION_OP,
            None,
            &payload,
        )
        .map_err(|(status, Json(body))| {
            format!("coverage Agentgres admission failed ({}): {}", status, body)
        })?;
        projection["coverage_admission_receipt_ref"] = json!(commit.receipt_ref);
        projection["replayed"] = json!(commit.replayed);
        admitted.push(projection);
    }
    *guard = next;
    admitted.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    Ok(admitted)
}

pub(crate) fn produce_gateway_profile(
    registry: &Mutex<EnforcementCoverageRegistry>,
    data_dir: &str,
    caller: &WriteCaller,
    profile: &Value,
    profile_admission_receipt_ref: &str,
) -> Result<Vec<Value>, String> {
    produce_gateway_coverage(
        registry,
        data_dir,
        caller,
        profile,
        profile_admission_receipt_ref,
        None,
        required(profile, "/created_at")?,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn produce_gateway_action(
    registry: &Mutex<EnforcementCoverageRegistry>,
    data_dir: &str,
    caller: &WriteCaller,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    profile_admission_receipt_ref: &str,
    decision_receipt_ref: &str,
    action_admission_receipt_ref: &str,
    evaluated_at: &str,
) -> Result<Vec<Value>, String> {
    produce_gateway_coverage(
        registry,
        data_dir,
        caller,
        profile,
        profile_admission_receipt_ref,
        Some((decision_receipt_ref, action_admission_receipt_ref)),
        evaluated_at,
        Some((required(surface, "/surface")?, action_class)),
    )
}

fn resolve_gateway_profile_with_posture(
    registry: &EnforcementCoverageRegistry,
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    now: i64,
    require_positive_enforcement: bool,
) -> Result<Vec<String>, String> {
    let scopes = profile
        .pointer("/declaration/required_enforcement_scope_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| "gateway profile lacks required enforcement scopes".to_string())?;
    let index = registry.operability_index(now);
    let mut refs = Vec::new();
    for scope_ref in scopes.iter().filter_map(Value::as_str) {
        let declaration_id = coordinate_id(owner_ref, profile, surface, action_class, scope_ref)?;
        let entry = index
            .iter()
            .find(|entry| entry.declaration_id == declaration_id && entry.is_logical_head)
            .ok_or_else(|| format!("no current lifecycle head resolves for '{scope_ref}'"))?;
        let requirement = EnforcementCoverageRequirement {
            declaration_artifact_ref: entry.declaration_artifact_ref.clone(),
            declaration_content_hash: entry.declaration_content_hash.clone(),
            subject_kind: "authority_gateway_profile".into(),
            profile_or_adapter_ref: required(profile, "/profile_ref")?.into(),
            subject_version: required(profile, "/declaration/adapter/adapter_revision")?.into(),
            subject_content_hash: required(profile, "/profile_hash")?.into(),
            subject_implementation_ref: required(
                profile,
                "/declaration/adapter/implementation_ref",
            )?
            .into(),
            subject_deployment_profile_ref: required(
                profile,
                "/declaration/adapter/deployment_profile_ref",
            )?
            .into(),
            surface: required(surface, "/surface")?.into(),
            action_class: action_class.into(),
            boundary: "adapter".into(),
            scope_ref: scope_ref.into(),
            decision_source_ref: require_positive_enforcement
                .then(|| required(profile, "/declaration/policy_enforcement_point_ref"))
                .transpose()?
                .map(str::to_owned),
            authority_provider_ref: require_positive_enforcement
                .then(|| required(profile, "/declaration/authority_provider_ref"))
                .transpose()?
                .map(str::to_owned),
            final_invoker_ref: require_positive_enforcement
                .then(|| required(surface, "/final_invoker_ref"))
                .transpose()?
                .map(str::to_owned),
            required_operating_mode: require_positive_enforcement
                .then(|| "active_enforcement".into()),
            required_claims: if require_positive_enforcement {
                vec![
                    EnforcementCoverageClaim::Mediated,
                    EnforcementCoverageClaim::Preventable,
                    EnforcementCoverageClaim::Receipted,
                ]
            } else {
                Vec::new()
            },
            evidence_requirement: if require_positive_enforcement {
                EnforcementCoverageEvidenceRequirement::VerificationAndReceipt
            } else {
                EnforcementCoverageEvidenceRequirement::Verification
            },
        };
        let resolved = registry
            .resolve(&requirement, now)
            .map_err(|error| format!("'{scope_ref}' is not operable: {error}"))?;
        refs.push(resolved.operability.declaration_artifact_ref);
    }
    refs.sort();
    Ok(refs)
}

pub(crate) fn resolve_gateway_profile(
    registry: &EnforcementCoverageRegistry,
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    now: i64,
) -> Result<Vec<String>, String> {
    resolve_gateway_profile_with_posture(
        registry,
        owner_ref,
        profile,
        surface,
        action_class,
        now,
        true,
    )
}

pub(crate) fn resolve_gateway_classification(
    registry: &EnforcementCoverageRegistry,
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    action_class: &str,
    now: i64,
) -> Result<Vec<String>, String> {
    resolve_gateway_profile_with_posture(
        registry,
        owner_ref,
        profile,
        surface,
        action_class,
        now,
        false,
    )
}

pub(crate) fn resolve_node_profile(
    registry: &EnforcementCoverageRegistry,
    profile_ref: &str,
) -> Result<Vec<Value>, String> {
    registry
        .resolve_current_for_subject("node_enforcement_profile", profile_ref, now_ms())
        .map(|values| values.into_iter().map(|value| value.declaration).collect())
        .map_err(|error| format!("node enforcement coverage is not operable: {error}"))
}

pub(crate) async fn handle_operability(
    State(state): State<std::sync::Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    match state.enforcement_coverage_registry.lock() {
        Ok(registry) => (
            StatusCode::OK,
            Json(json!({
                "ok":true,
                "schema_version":"ioi.hypervisor.enforcement-coverage-operability-index.v1",
                "entries":registry.operability_index(now_ms()),
            })),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok":false,"error":{"code":"enforcement_coverage_registry_unavailable"}})),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(path: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("docs/architecture/_meta/schemas/fixtures")
            .join(path);
        serde_json::from_slice(&std::fs::read(path).expect("fixture bytes")).expect("fixture json")
    }

    #[test]
    fn observed_action_supersedes_the_gap_and_rebuilds_from_agentgres() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        super::super::substrate_store::reset_handle_for_test();
        let profile = fixture("authority-gateway-profile-v1/positive-active-pre-effect.json");
        let registry = Mutex::new(EnforcementCoverageRegistry::default());
        let caller = WriteCaller {
            identity: super::super::substrate_store::request_identity_for_test(
                "user://acme/operator",
                ["org://acme".to_string()],
            ),
            owner_ref: "org://acme".into(),
            idempotency_key: "profile-registration-1".into(),
        };
        let records = produce_gateway_profile(
            &registry,
            data_dir.path().to_str().unwrap(),
            &caller,
            &profile,
            "receipt://ioi/profile-admission/1",
        )
        .expect("coverage produced");
        assert_eq!(records.len(), 2);
        let surface = &profile["declaration"]["action_surfaces"][0];
        let gap_registry = registry.lock().unwrap().clone();
        assert!(resolve_gateway_classification(
            &gap_registry,
            "org://acme",
            &profile,
            surface,
            "git",
            1_787_587_200_000,
        )
        .is_ok());
        assert!(resolve_gateway_profile(
            &gap_registry,
            "org://acme",
            &profile,
            surface,
            "git",
            1_787_587_200_000,
        )
        .is_err());
        let observed = produce_gateway_action(
            &registry,
            data_dir.path().to_str().unwrap(),
            &caller,
            &profile,
            surface,
            "git",
            "receipt://ioi/profile-admission/1",
            "receipt://ioi/authority-gateway/decision/1",
            "receipt://ioi/authority-gateway/action-admission/1",
            "2026-08-24T15:05:00Z",
        )
        .expect("observed coverage produced");
        assert_eq!(observed.len(), 1);
        let replay = produce_gateway_action(
            &registry,
            data_dir.path().to_str().unwrap(),
            &caller,
            &profile,
            surface,
            "git",
            "receipt://ioi/profile-admission/1",
            "receipt://ioi/authority-gateway/decision/1",
            "receipt://ioi/authority-gateway/action-admission/1",
            "2026-08-24T15:05:00Z",
        )
        .expect("exact observed coverage replay");
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0]["replayed"], true);
        super::super::substrate_store::reset_handle_for_test();
        let restored = restore_registry(data_dir.path().to_str().unwrap()).expect("restored");
        assert_eq!(
            resolve_gateway_profile(
                &restored,
                "org://acme",
                &profile,
                surface,
                "git",
                1_787_587_200_000,
            )
            .expect("git coverage")
            .len(),
            1
        );
        assert!(resolve_gateway_profile(
            &restored,
            "org://acme",
            &profile,
            surface,
            "shell",
            1_787_587_200_000,
        )
        .is_err());
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn non_fail_closed_profile_emits_a_verified_uncovered_finding() {
        let mut profile = fixture("authority-gateway-profile-v1/positive-active-pre-effect.json");
        profile["declaration"]["failure_posture"] = json!("queue_without_authority");
        let surface = &profile["declaration"]["action_surfaces"][0];
        let value = declaration(
            "org://acme",
            &profile,
            surface,
            "git",
            "enforcement-scope://acme/claude-code/cli-effects",
            "receipt://ioi/profile-admission/1",
            None,
            "2026-08-24T15:00:00Z",
        )
        .expect("declaration");
        assert_eq!(value["claims"]["uncovered"], true);
        assert_eq!(value["operating_mode"], "uncovered");
        assert!(!value["known_gaps"].as_array().unwrap().is_empty());
    }
}
