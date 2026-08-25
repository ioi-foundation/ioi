//! Authority Gateway attach-lane admission and native execution bridge.
//!
//! This module owns no authority and contains no final invoker. It registers immutable adapter
//! profiles, admits exact `ActionRequestEnvelope` proposals after resolving current coverage, and
//! durably prepares execution before delegating to the selected native route. That route remains
//! the single PEP/final invoker; this bridge only binds its exact effect and seals gateway receipts.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::{
    admit_owner_scoped_write, prior_admission_for_key, require_write_caller, scope_refusal_reply,
    stream_tail, WriteCaller,
};
use super::{persist_record, read_record_dir, DaemonState};

const PROFILE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/authority-gateway-profile/v1";
const REQUEST_CONTRACT: &str = "schema://ioi/components/daemon-runtime/action-request-envelope/v1";
const DECISION_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1";
const EXECUTION_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/gateway-execution-receipt/v1";
const ARTIFACT_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/gateway-artifact-receipt/v1";
const PROFILE_SCHEMA: &str = "ioi.components.daemon-runtime.authority-gateway-profile.v1";
const PROFILE_DIR: &str = "authority-gateway-profiles";
const ACTION_DIR: &str = "authority-gateway-action-requests";
const OWNER_NAMESPACE: &str = "hypervisor-authority-gateway";
const ACTION_RESOURCE_KIND: &str = "authority-gateway-action-request";
const SCM_ADVANCE_SCOPE: &str = "scope:scm.publication.advance-target-ref";
const SCM_REVIEW_SCOPE: &str = "scope:scm.publication.open-review-request";

type Reply = (StatusCode, Json<Value>);

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({"ok":false,"error":{"code":code,"message":message.into()}})),
    )
}

fn canonical_hash(material: &Value) -> Result<String, String> {
    serde_jcs::to_vec(material)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|reason| format!("canonical hashing failed: {reason}"))
}

fn validate_profile_content_hash(profile: &Value) -> Result<(), String> {
    let expected = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-profile-hash-jcs-sha256.v1",
        "profile_ref":profile["profile_ref"],
        "profile_revision":profile["profile_revision"],
        "predecessor_profile_hash":profile["predecessor_profile_hash"],
        "declaration":profile["declaration"],
        "created_at":profile["created_at"],
        "valid_until":profile["valid_until"],
    }))?;
    if profile.get("profile_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("gateway profile_hash does not bind its exact canonical profile bytes".into());
    }
    Ok(())
}

fn resolve_run_on_adapter(data_dir: &str, owner_ref: &str, profile: &Value) -> Result<(), String> {
    let graduation = profile
        .pointer("/declaration/run_on_graduation")
        .ok_or_else(|| "gateway profile lacks run_on_graduation".to_string())?;
    match (
        graduation
            .get("agent_harness_adapter_revision_ref")
            .and_then(Value::as_str),
        graduation
            .get("agent_harness_adapter_content_hash")
            .and_then(Value::as_str),
    ) {
        (None, None) => Ok(()),
        (Some(revision_ref), Some(content_hash)) => {
            super::goal_profile_contract_routes::resolve_released_agent_harness_adapter(
                data_dir,
                owner_ref,
                revision_ref,
                content_hash,
            )
            .map(|_| ())
        }
        _ => Err(
            "gateway run-on graduation requires an exact adapter revision and content hash together"
                .to_string(),
        ),
    }
}

fn parse_time(value: &str, field: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|reason| format!("{field} is not canonical RFC3339: {reason}"))
}

fn profile_from_record(record: &Value) -> Option<&Value> {
    if record.get("schema_version").and_then(Value::as_str) == Some(PROFILE_SCHEMA) {
        Some(record)
    } else {
        record.get("profile").filter(|profile| {
            profile.get("schema_version").and_then(Value::as_str) == Some(PROFILE_SCHEMA)
        })
    }
}

fn current_profile<'a>(
    records: &'a [Value],
    requested: &Value,
    now: &str,
    owner_ref: &str,
) -> Result<&'a Value, String> {
    let requested_ref = requested
        .get("authority_gateway_profile_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "action request lacks authority_gateway_profile_ref".to_string())?;
    let requested_hash = requested
        .get("authority_gateway_profile_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "action request lacks authority_gateway_profile_hash".to_string())?;
    let adapter_ref = requested
        .pointer("/source_adapter/adapter_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "action request lacks source adapter identity".to_string())?;

    let mut family = Vec::new();
    for record in records {
        if record.get("owner_ref").and_then(Value::as_str) != Some(owner_ref) {
            continue;
        }
        let Some(profile) = profile_from_record(record) else {
            continue;
        };
        validate_architecture_contract(PROFILE_CONTRACT, profile)
            .map_err(|reason| format!("gateway profile is not registered-valid: {reason}"))?;
        if profile
            .pointer("/declaration/adapter/adapter_ref")
            .and_then(Value::as_str)
            == Some(adapter_ref)
        {
            family.push(profile);
        }
    }
    let cited: BTreeSet<&str> = family
        .iter()
        .filter_map(|profile| {
            profile
                .get("predecessor_profile_hash")
                .and_then(Value::as_str)
        })
        .collect();
    let mut leaves: Vec<&Value> = family
        .into_iter()
        .filter(|profile| {
            profile.get("status").and_then(Value::as_str) == Some("declared")
                && profile
                    .get("profile_hash")
                    .and_then(Value::as_str)
                    .is_some_and(|hash| !cited.contains(hash))
        })
        .collect();
    let profile = match leaves.len() {
        1 => leaves.pop().expect("one leaf"),
        0 => return Err("no current declared gateway profile resolves for the adapter".into()),
        _ => return Err("multiple gateway profiles claim current adapter state".into()),
    };
    if profile.get("profile_ref").and_then(Value::as_str) != Some(requested_ref)
        || profile.get("profile_hash").and_then(Value::as_str) != Some(requested_hash)
    {
        return Err("action request does not bind the current exact gateway profile".into());
    }
    let now = parse_time(now, "current time")?;
    let created_at = parse_time(
        profile
            .get("created_at")
            .and_then(Value::as_str)
            .ok_or_else(|| "gateway profile lacks created_at".to_string())?,
        "gateway profile created_at",
    )?;
    let valid_until = parse_time(
        profile
            .get("valid_until")
            .and_then(Value::as_str)
            .ok_or_else(|| "gateway profile lacks valid_until".to_string())?,
        "gateway profile valid_until",
    )?;
    if now < created_at || now > valid_until {
        return Err("the current gateway profile is outside its validity interval".into());
    }
    Ok(profile)
}

fn bound_profile<'a>(
    records: &'a [Value],
    requested: &Value,
    owner_ref: &str,
) -> Result<&'a Value, String> {
    let requested_ref = requested
        .get("authority_gateway_profile_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let requested_hash = requested
        .get("authority_gateway_profile_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut matches = Vec::new();
    for record in records {
        if record.get("owner_ref").and_then(Value::as_str) != Some(owner_ref) {
            continue;
        }
        let Some(profile) = profile_from_record(record) else {
            continue;
        };
        if profile.get("profile_ref").and_then(Value::as_str) == Some(requested_ref)
            && profile.get("profile_hash").and_then(Value::as_str) == Some(requested_hash)
        {
            validate_architecture_contract(PROFILE_CONTRACT, profile)
                .map_err(|reason| format!("bound gateway profile is invalid: {reason}"))?;
            matches.push(profile);
        }
    }
    match matches.as_slice() {
        [profile] => Ok(*profile),
        [] => Err("the action request's exact gateway profile is absent".into()),
        _ => Err("the action request's exact gateway profile resolves ambiguously".into()),
    }
}

fn profile_admission_receipt<'a>(
    records: &'a [Value],
    owner_ref: &str,
    profile: &Value,
) -> Result<&'a str, String> {
    let profile_ref = profile.get("profile_ref").and_then(Value::as_str);
    let profile_hash = profile.get("profile_hash").and_then(Value::as_str);
    let mut matches = records.iter().filter(|record| {
        record.get("owner_ref").and_then(Value::as_str) == Some(owner_ref)
            && profile_from_record(record).is_some_and(|candidate| {
                candidate.get("profile_ref").and_then(Value::as_str) == profile_ref
                    && candidate.get("profile_hash").and_then(Value::as_str) == profile_hash
            })
    });
    let record = matches
        .next()
        .ok_or_else(|| "gateway profile admission receipt is absent".to_string())?;
    if matches.next().is_some() {
        return Err("gateway profile admission receipt resolves ambiguously".into());
    }
    record
        .get("admission_receipt_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("receipt://"))
        .ok_or_else(|| "gateway profile admission receipt is invalid".to_string())
}

fn exact_adapter_binding(profile: &Value, request: &Value) -> Result<(), String> {
    if profile.pointer("/declaration/adapter") != request.get("source_adapter") {
        return Err("action request source adapter differs from the current profile".into());
    }
    Ok(())
}

fn request_subject_kinds(request: &Value) -> BTreeSet<&str> {
    let mut kinds = BTreeSet::new();
    for (field, kind) in [
        ("session_ref", "session"),
        ("goal_ref", "goal"),
        ("work_run_ref", "work_run"),
        ("work_item_ref", "work_item"),
    ] {
        if request
            .pointer(&format!("/subject_refs/{field}"))
            .is_some_and(|value| !value.is_null())
        {
            kinds.insert(kind);
        }
    }
    if kinds.is_empty() {
        kinds.insert("unattached");
    }
    kinds
}

fn supporting_surface<'a>(profile: &'a Value, request: &Value) -> Result<&'a Value, String> {
    let action_class = request
        .pointer("/proposed_action/action_class")
        .and_then(Value::as_str)
        .ok_or_else(|| "action request lacks action class".to_string())?;
    let required_primitives: BTreeSet<&str> = request
        .get("primitive_capabilities_required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let required_scopes: BTreeSet<&str> = request
        .get("authority_scopes_required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let allowed_subjects: BTreeSet<&str> = profile
        .pointer("/declaration/subject_kinds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !request_subject_kinds(request).is_subset(&allowed_subjects) {
        return Err("action request carries a subject kind outside the gateway profile".into());
    }

    let matches: Vec<&Value> = profile
        .pointer("/declaration/action_surfaces")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|surface| {
            surface.get("mediation_mode").and_then(Value::as_str) == Some("active_pre_effect")
                && surface
                    .get("action_classes")
                    .and_then(Value::as_array)
                    .is_some_and(|classes| classes.iter().any(|class| class == action_class))
                && required_primitives.is_subset(
                    &surface
                        .get("primitive_capabilities")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect(),
                )
                && required_scopes.is_subset(
                    &surface
                        .get("authority_scopes")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect(),
                )
        })
        .collect();
    match matches.as_slice() {
        [surface] => Ok(*surface),
        [] => {
            Err("no active pre-effect gateway surface admits the exact action requirements".into())
        }
        _ => Err("multiple gateway surfaces ambiguously admit the exact action".into()),
    }
}

fn verify_coverage(
    registry: &ioi_services::agentic::runtime::enforcement_coverage::EnforcementCoverageRegistry,
    owner_ref: &str,
    profile: &Value,
    surface: &Value,
    request: &Value,
    now: &str,
    require_positive_enforcement: bool,
) -> Result<Vec<String>, String> {
    let action_class = request
        .pointer("/proposed_action/action_class")
        .and_then(Value::as_str)
        .ok_or_else(|| "action request lacks action class".to_string())?;
    let now_ms = i64::try_from(parse_time(now, "current time")?.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "current time is outside the supported millisecond range".to_string())?;
    if require_positive_enforcement {
        super::enforcement_coverage_routes::resolve_gateway_profile(
            registry,
            owner_ref,
            profile,
            surface,
            action_class,
            now_ms,
        )
    } else {
        super::enforcement_coverage_routes::resolve_gateway_classification(
            registry,
            owner_ref,
            profile,
            surface,
            action_class,
            now_ms,
        )
    }
}

fn produce_observed_action_coverage(
    state: &DaemonState,
    caller: &WriteCaller,
    profiles: &[Value],
    request: &Value,
    decision_receipt: &Value,
    action_admission_receipt_ref: &str,
) -> Result<Vec<Value>, Reply> {
    let profile = bound_profile(profiles, request, &caller.owner_ref).map_err(|reason| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_profile_resolution_failed",
            reason,
        )
    })?;
    let surface = supporting_surface(profile, request).map_err(|reason| {
        error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_surface_not_admitted",
            reason,
        )
    })?;
    let profile_receipt =
        profile_admission_receipt(profiles, &caller.owner_ref, profile).map_err(|reason| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_profile_admission_evidence_unavailable",
                reason,
            )
        })?;
    let action_class = request
        .pointer("/proposed_action/action_class")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let decision_ref = decision_receipt
        .get("receipt_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let evaluated_at = decision_receipt
        .get("decided_at")
        .and_then(Value::as_str)
        .unwrap_or_default();
    super::enforcement_coverage_routes::produce_gateway_action(
        &state.enforcement_coverage_registry,
        &state.data_dir,
        caller,
        profile,
        surface,
        action_class,
        profile_receipt,
        decision_ref,
        action_admission_receipt_ref,
        evaluated_at,
    )
    .map_err(|reason| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_coverage_production_failed",
            reason,
        )
    })
}

fn validate_request_window(request: &Value, now: &str) -> Result<(), String> {
    if request
        .pointer("/policy_decision/status")
        .and_then(Value::as_str)
        != Some("pending")
    {
        return Err("a submitted action request must enter with a pending policy decision".into());
    }
    let created = parse_time(
        request
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "action request created_at",
    )?;
    let expires = parse_time(
        request
            .get("expires_at")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "action request expires_at",
    )?;
    let now = parse_time(now, "current time")?;
    if expires < created || now < created || now > expires {
        return Err("action request is outside its declared validity window".into());
    }
    Ok(())
}

fn build_decision_receipt(
    request: &Value,
    coverage_refs: Vec<String>,
    decided_at: &str,
) -> Result<Value, String> {
    let request_ref = request["action_request_ref"].as_str().unwrap_or_default();
    let request_hash = request["request_hash"].as_str().unwrap_or_default();
    let external = request
        .pointer("/proposed_action/external_effect")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scopes_empty = request
        .get("authority_scopes_required")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    let requires_authority = external || !scopes_empty;
    let request_tag = request_hash.trim_start_matches("sha256:");
    let mut receipt = json!({
        "schema_version":"ioi.components.daemon-runtime.gateway-decision-receipt.v1",
        "receipt_ref":format!("receipt://ioi/authority-gateway/decision/{request_tag}"),
        "receipt_type":"gateway_decision",
        "action_request_ref":request_ref,
        "action_request_hash":request_hash,
        "authority_gateway_profile_ref":request["authority_gateway_profile_ref"],
        "authority_gateway_profile_hash":request["authority_gateway_profile_hash"],
        "policy_enforcement_point_ref":"runtime://hypervisor-daemon/authority-gateway",
        "decision":"requires_approval",
        "policy_ref":request["policy_decision"]["policy_ref"],
        "policy_hash":request["policy_decision"]["policy_hash"],
        "authority_status":if requires_authority {"required_unresolved"} else {"not_required"},
        "authority_evidence_refs":coverage_refs,
        "approval_receipt_ref":Value::Null,
        "admitted_action_hash":Value::Null,
        "decided_at":decided_at,
        "receipt_hash":Value::Null,
    });
    receipt["receipt_hash"] = json!(canonical_hash(&json!({
        "domain":"ioi.gateway-decision-receipt-hash-jcs-sha256.v1",
        "schema_version":receipt["schema_version"], "receipt_ref":receipt["receipt_ref"],
        "receipt_type":receipt["receipt_type"], "action_request_ref":receipt["action_request_ref"],
        "action_request_hash":receipt["action_request_hash"], "authority_gateway_profile_ref":receipt["authority_gateway_profile_ref"],
        "authority_gateway_profile_hash":receipt["authority_gateway_profile_hash"], "policy_enforcement_point_ref":receipt["policy_enforcement_point_ref"],
        "decision":receipt["decision"], "policy_ref":receipt["policy_ref"], "policy_hash":receipt["policy_hash"],
        "authority_status":receipt["authority_status"], "authority_evidence_refs":receipt["authority_evidence_refs"],
        "approval_receipt_ref":receipt["approval_receipt_ref"], "admitted_action_hash":receipt["admitted_action_hash"],
        "decided_at":receipt["decided_at"],
    }))?);
    validate_architecture_contract(DECISION_RECEIPT_CONTRACT, &receipt)
        .map_err(|reason| format!("gateway decision receipt failed its contract: {reason}"))?;
    Ok(receipt)
}

fn record_id_from_hash(prefix: &str, owner_ref: &str, hash: &str) -> String {
    let scoped = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-owner-record-id-jcs-sha256.v1",
        "owner_ref":owner_ref,
        "object_hash":hash,
    }))
    .unwrap_or_default();
    let hex = scoped.trim_start_matches("sha256:");
    format!("{prefix}_{}", &hex[..hex.len().min(24)])
}

fn record_matches_id(record: &Value, id_or_ref: &str) -> bool {
    record.get("record_id").and_then(Value::as_str) == Some(id_or_ref)
        || record
            .pointer("/action_request/action_request_ref")
            .and_then(Value::as_str)
            == Some(id_or_ref)
}

fn owner_record(records: &[Value], id_or_ref: &str, owner_ref: &str) -> Option<Value> {
    records
        .iter()
        .find(|record| {
            record.get("owner_ref").and_then(Value::as_str) == Some(owner_ref)
                && record_matches_id(record, id_or_ref)
        })
        .cloned()
}

fn invocation_payload_commitment(payload: &Value) -> Result<String, String> {
    canonical_hash(&json!({
        "domain":"ioi.authority-gateway-invocation-payload-jcs-sha256.v1",
        "payload":payload,
    }))
}

fn stable_native_scm_idempotency_key(request: &Value) -> String {
    let identity = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-native-scm-idempotency-jcs-sha256.v1",
        "action_request_ref":request["action_request_ref"],
        "request_revision":request["request_revision"],
    }))
    .unwrap_or_default();
    format!(
        "gateway-scm-{}",
        identity
            .trim_start_matches("sha256:")
            .chars()
            .take(48)
            .collect::<String>()
    )
}

fn phase_caller(caller: &WriteCaller, request_hash: &str, phase: &str) -> WriteCaller {
    let key = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-execution-phase-idempotency-jcs-sha256.v1",
        "principal_ref":caller.identity.principal_ref,
        "owner_ref":caller.owner_ref,
        "request_hash":request_hash,
        "phase":phase,
        "caller_idempotency_key":caller.idempotency_key,
    }))
    .unwrap_or_else(|_| format!("gateway-{phase}-{request_hash}"));
    WriteCaller {
        identity: caller.identity.clone(),
        owner_ref: caller.owner_ref.clone(),
        idempotency_key: key,
    }
}

fn validate_scm_invocation_payload(request: &Value, payload: &Value) -> Result<String, String> {
    if request
        .pointer("/proposed_action/action_class")
        .and_then(Value::as_str)
        != Some("git")
        || request
            .pointer("/proposed_action/operation")
            .and_then(Value::as_str)
            != Some("advance_target_ref")
        || request
            .pointer("/proposed_action/external_effect")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(
            "the first gateway execution adapter admits only external git advance_target_ref actions"
                .into(),
        );
    }
    let environment_id = payload
        .get("environment_id")
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 240
                && !value.chars().any(|character| {
                    character.is_whitespace() || character.is_control() || character == '/'
                })
        })
        .ok_or_else(|| "SCM gateway invocation requires one bounded environment_id".to_string())?;
    let proposal_ref = payload
        .get("proposal_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("proposal://"))
        .ok_or_else(|| "SCM gateway invocation requires one proposal:// ref".to_string())?;
    let binding_ref = payload
        .get("destination_binding_ref")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("scm-destination-binding://"))
        .ok_or_else(|| {
            "SCM gateway invocation requires one scm-destination-binding:// ref".to_string()
        })?;
    let targets: BTreeSet<&str> = request
        .pointer("/proposed_action/target_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let environment_ref = format!("environment://{environment_id}");
    if !targets.contains(proposal_ref)
        || !targets.contains(binding_ref)
        || !targets.contains(environment_ref.as_str())
    {
        return Err(
            "action target refs do not bind the native environment, proposal, and destination"
                .into(),
        );
    }
    let mut exact_scopes = BTreeSet::from([SCM_ADVANCE_SCOPE]);
    if payload
        .get("open_review_request")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        exact_scopes.insert(SCM_REVIEW_SCOPE);
    }
    let requested_scopes: BTreeSet<&str> = request
        .get("authority_scopes_required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if requested_scopes != exact_scopes {
        return Err("action authority scopes differ from the native SCM sub-effects".into());
    }
    let requested_primitives: BTreeSet<&str> = request
        .get("primitive_capabilities_required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if requested_primitives != BTreeSet::from(["prim:net.request", "prim:sys.exec"]) {
        return Err("SCM gateway execution requires exact process and network primitives".into());
    }
    let grant_hash = payload
        .get("wallet_portable_authority_grant_hash")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 71
                && value.starts_with("sha256:")
                && value[7..]
                    .chars()
                    .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
                && value[7..].chars().any(|character| character != '0')
        })
        .ok_or_else(|| {
            "gateway SCM execution requires one nonzero portable v3 grant-hash locator".to_string()
        })?;
    if payload
        .get("wallet_approval_grant")
        .is_some_and(|value| !value.is_null())
        || payload
            .get("gateway_expected_authority_effect_ref")
            .is_some()
        || payload
            .get("gateway_expected_authority_effect_hash")
            .is_some()
        || payload.get("gateway_action_expires_at").is_some()
    {
        return Err(
            "the committed invocation payload may not select legacy authority or inject gateway-owned bindings"
                .into(),
        );
    }
    let stable_key = stable_native_scm_idempotency_key(request);
    if payload.get("idempotency_key").and_then(Value::as_str) != Some(stable_key.as_str()) {
        return Err(
            "native SCM idempotency key is not derived from the immutable request hash".into(),
        );
    }
    let commitment = invocation_payload_commitment(payload)?;
    if request
        .pointer("/proposed_action/input_commitment")
        .and_then(Value::as_str)
        != Some(commitment.as_str())
    {
        return Err("invocation payload differs from the action input commitment".into());
    }
    Ok(grant_hash.to_string())
}

fn execution_outcome(
    status: StatusCode,
    native_result: &Value,
    authority_found: bool,
) -> &'static str {
    if native_result.get("ok").and_then(Value::as_bool) == Some(true) && status.is_success() {
        return "succeeded";
    }
    let overall = native_result
        .get("overall_outcome")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if overall == "refused_before_native_prepared" {
        return "refused";
    }
    if overall == "reconciliation_required"
        || native_result
            .get("authority_usage_disposition")
            .and_then(Value::as_str)
            == Some("spent_not_refunded")
            && native_result.get("publication_effect").is_none()
    {
        return "reconciliation_required";
    }
    if !authority_found
        || native_result
            .pointer("/publication_effect/effects/publication/outcome")
            .and_then(Value::as_str)
            == Some("refused")
            && native_result
                .pointer("/publication_effect/recovery/remote_effect_invoked")
                .and_then(Value::as_bool)
                == Some(false)
    {
        return "refused";
    }
    "failed"
}

fn build_execution_receipts(
    request: &Value,
    decision: &Value,
    surface: &Value,
    native_status: StatusCode,
    native_result: &Value,
    admission: Option<&super::governed_authority::PortableAdmissionEvidence>,
    started_at: &str,
    completed_at: &str,
) -> Result<(Value, Value), String> {
    let request_hash = request["request_hash"].as_str().unwrap_or_default();
    let tag = request_hash.trim_start_matches("sha256:");
    let outcome = execution_outcome(native_status, native_result, admission.is_some());
    if matches!(
        outcome,
        "succeeded" | "failed" | "unknown" | "reconciliation_required"
    ) && admission.is_none()
    {
        return Err(
            "a non-refusal external result lacks its registered authority admission receipt".into(),
        );
    }
    let result_hash = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-native-result-jcs-sha256.v1",
        "status":native_status.as_u16(),
        "result":native_result,
    }))?;
    let native_key = stable_native_scm_idempotency_key(request);
    let idempotency_hash = canonical_hash(&json!({
        "domain":"ioi.authority-gateway-native-idempotency-jcs-sha256.v1",
        "key":native_key,
    }))?;
    let mut execution = json!({
        "schema_version":"ioi.components.daemon-runtime.gateway-execution-receipt.v1",
        "receipt_ref":format!("receipt://ioi/authority-gateway/execution/{tag}"),
        "receipt_type":"gateway_execution",
        "action_request_ref":request["action_request_ref"],
        "action_request_hash":request["request_hash"],
        "authority_gateway_profile_ref":request["authority_gateway_profile_ref"],
        "authority_gateway_profile_hash":request["authority_gateway_profile_hash"],
        "gateway_decision_receipt_ref":decision["receipt_ref"],
        "gateway_decision_receipt_hash":decision["receipt_hash"],
        "policy_enforcement_point_ref":decision["policy_enforcement_point_ref"],
        "external_effect":true,
        "authority_effect_admission_receipt_ref":admission.map(|value| json!(value.receipt_ref)).unwrap_or(Value::Null),
        "authority_effect_admission_receipt_hash":admission.map(|value| json!(value.receipt_hash)).unwrap_or(Value::Null),
        "final_invoker_ref":surface["final_invoker_ref"],
        "invocation_id":format!("gateway-scm-{}", tag.chars().take(24).collect::<String>()),
        "idempotency_key":idempotency_hash,
        "actual_effect_ref":request["proposed_action"]["proposed_effect_ref"],
        "actual_effect_hash":request["proposed_action"]["proposed_effect_hash"],
        "outcome":outcome,
        "result_hash":result_hash,
        "effect_receipt_ref":native_result.pointer("/publication_effect/effects/publication/receipt_ref").cloned().unwrap_or(Value::Null),
        "started_at":started_at,
        "completed_at":completed_at,
        "receipt_hash":Value::Null,
    });
    execution["receipt_hash"] = json!(canonical_hash(&json!({
        "domain":"ioi.gateway-execution-receipt-hash-jcs-sha256.v1",
        "schema_version":execution["schema_version"], "receipt_ref":execution["receipt_ref"],
        "receipt_type":execution["receipt_type"], "action_request_ref":execution["action_request_ref"],
        "action_request_hash":execution["action_request_hash"], "authority_gateway_profile_ref":execution["authority_gateway_profile_ref"],
        "authority_gateway_profile_hash":execution["authority_gateway_profile_hash"], "gateway_decision_receipt_ref":execution["gateway_decision_receipt_ref"],
        "gateway_decision_receipt_hash":execution["gateway_decision_receipt_hash"], "policy_enforcement_point_ref":execution["policy_enforcement_point_ref"],
        "external_effect":execution["external_effect"], "authority_effect_admission_receipt_ref":execution["authority_effect_admission_receipt_ref"],
        "authority_effect_admission_receipt_hash":execution["authority_effect_admission_receipt_hash"], "final_invoker_ref":execution["final_invoker_ref"],
        "invocation_id":execution["invocation_id"], "idempotency_key":execution["idempotency_key"], "actual_effect_ref":execution["actual_effect_ref"],
        "actual_effect_hash":execution["actual_effect_hash"], "outcome":execution["outcome"], "result_hash":execution["result_hash"],
        "effect_receipt_ref":execution["effect_receipt_ref"], "started_at":execution["started_at"], "completed_at":execution["completed_at"],
    }))?);
    validate_architecture_contract(EXECUTION_RECEIPT_CONTRACT, &execution)
        .map_err(|reason| format!("gateway execution receipt failed its contract: {reason}"))?;

    let mut artifact = json!({
        "schema_version":"ioi.components.daemon-runtime.gateway-artifact-receipt.v1",
        "receipt_ref":format!("receipt://ioi/authority-gateway/artifact/{tag}"),
        "receipt_type":"gateway_artifact",
        "action_request_ref":request["action_request_ref"],
        "action_request_hash":request["request_hash"],
        "gateway_execution_receipt_ref":execution["receipt_ref"],
        "gateway_execution_receipt_hash":execution["receipt_hash"],
        "evidence_kind":"none",
        "artifacts":[],
        "diff_artifact_ref":Value::Null,
        "diff_hash":Value::Null,
        "no_artifact_reason":"The native SCM target-ref crossing emitted effect receipts but retained no gateway-owned artifact or diff.",
        "captured_at":completed_at,
        "receipt_hash":Value::Null,
    });
    artifact["receipt_hash"] = json!(canonical_hash(&json!({
        "domain":"ioi.gateway-artifact-receipt-hash-jcs-sha256.v1",
        "schema_version":artifact["schema_version"], "receipt_ref":artifact["receipt_ref"],
        "receipt_type":artifact["receipt_type"], "action_request_ref":artifact["action_request_ref"],
        "action_request_hash":artifact["action_request_hash"], "gateway_execution_receipt_ref":artifact["gateway_execution_receipt_ref"],
        "gateway_execution_receipt_hash":artifact["gateway_execution_receipt_hash"], "evidence_kind":artifact["evidence_kind"],
        "artifacts":artifact["artifacts"], "diff_artifact_ref":artifact["diff_artifact_ref"], "diff_hash":artifact["diff_hash"],
        "no_artifact_reason":artifact["no_artifact_reason"], "captured_at":artifact["captured_at"],
    }))?);
    validate_architecture_contract(ARTIFACT_RECEIPT_CONTRACT, &artifact)
        .map_err(|reason| format!("gateway artifact receipt failed its contract: {reason}"))?;
    Ok((execution, artifact))
}

/// POST /v1/authority-gateway/profiles
pub(crate) async fn handle_profile_register(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&state.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(reply) => return reply,
    };
    let profile = body.get("profile").cloned().unwrap_or(Value::Null);
    if let Err(reason) = validate_architecture_contract(PROFILE_CONTRACT, &profile) {
        return error(StatusCode::BAD_REQUEST, "gateway_profile_invalid", reason);
    }
    if let Err(reason) = validate_profile_content_hash(&profile).and_then(|_| {
        super::enforcement_coverage_routes::preflight_gateway_profile(&caller.owner_ref, &profile)
    }) {
        return error(StatusCode::BAD_REQUEST, "gateway_profile_invalid", reason);
    }
    let profile_ref = profile["profile_ref"].as_str().unwrap_or_default();
    let profile_hash = profile["profile_hash"].as_str().unwrap_or_default();
    if let Err(reason) = resolve_run_on_adapter(&state.data_dir, &caller.owner_ref, &profile) {
        return error(
            StatusCode::CONFLICT,
            "gateway_run_on_adapter_unresolved",
            reason,
        );
    }
    let prior = match prior_admission_for_key(
        &state.data_dir,
        &caller,
        OWNER_NAMESPACE,
        "authority-gateway-profile",
        profile_ref,
    ) {
        Ok(prior) => prior,
        Err(reply) => return reply,
    };
    if let Some(prior) = prior {
        if prior.operation.op_kind != "authority_gateway.profile.register"
            || prior.operation.payload != profile
        {
            return error(
                StatusCode::CONFLICT,
                "gateway_profile_idempotency_conflict",
                "the idempotency key already admitted different gateway profile bytes",
            );
        }
        let record_id = record_id_from_hash("agp", &caller.owner_ref, profile_hash);
        let receipt_ref = agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE,
            &stream_tail("authority-gateway-profile", profile_ref),
            prior.admission_batch_seq,
            &prior.admission_root,
        );
        let coverage = match super::enforcement_coverage_routes::produce_gateway_profile(
            &state.enforcement_coverage_registry,
            &state.data_dir,
            &caller,
            &profile,
            &receipt_ref,
        ) {
            Ok(coverage) => coverage,
            Err(reason) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway_coverage_production_failed",
                    reason,
                )
            }
        };
        let record = json!({
            "record_id":record_id, "owner_ref":caller.owner_ref, "profile":profile,
            "admitted_head":prior.head, "admission_receipt_ref":receipt_ref,
            "enforcement_coverage":coverage,
        });
        if let Err(reason) = persist_record(&state.data_dir, PROFILE_DIR, &record_id, &record) {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_profile_persistence_failed",
                reason.to_string(),
            );
        }
        return (
            StatusCode::CREATED,
            Json(json!({"ok":true,"profile":record,"replayed":true})),
        );
    }
    let now = super::iso_now();
    if parse_time(
        profile["created_at"].as_str().unwrap_or_default(),
        "created_at",
    )
    .and_then(|created| parse_time(&now, "current time").map(|current| (created, current)))
    .and_then(|(created, current)| {
        let valid_until = parse_time(
            profile["valid_until"].as_str().unwrap_or_default(),
            "valid_until",
        )?;
        (created <= current && current <= valid_until)
            .then_some(())
            .ok_or_else(|| "gateway profile is not currently valid".to_string())
    })
    .is_err()
    {
        return error(
            StatusCode::CONFLICT,
            "gateway_profile_not_current",
            "gateway profile is not currently valid",
        );
    }
    let family = read_record_dir(&state.data_dir, PROFILE_DIR);
    let adapter_ref = profile
        .pointer("/declaration/adapter/adapter_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let prior: Vec<&Value> = family
        .iter()
        .filter(|record| {
            record.get("owner_ref").and_then(Value::as_str) == Some(caller.owner_ref.as_str())
        })
        .filter_map(profile_from_record)
        .filter(|candidate| {
            candidate
                .pointer("/declaration/adapter/adapter_ref")
                .and_then(Value::as_str)
                == Some(adapter_ref)
                && candidate.get("status").and_then(Value::as_str) == Some("declared")
        })
        .collect();
    if prior.is_empty() && !profile["predecessor_profile_hash"].is_null() {
        return error(
            StatusCode::CONFLICT,
            "gateway_profile_predecessor_unexpected",
            "a first profile cannot name a predecessor",
        );
    }
    if !prior.is_empty() {
        let cited: BTreeSet<&str> = prior
            .iter()
            .filter_map(|candidate| {
                candidate
                    .get("predecessor_profile_hash")
                    .and_then(Value::as_str)
            })
            .collect();
        let current: Vec<&Value> = prior
            .iter()
            .copied()
            .filter(|candidate| {
                candidate
                    .get("profile_hash")
                    .and_then(Value::as_str)
                    .is_some_and(|hash| !cited.contains(hash))
            })
            .collect();
        if current.len() != 1 {
            return error(
                StatusCode::CONFLICT,
                "gateway_profile_current_ambiguous",
                "a successor requires exactly one current declared predecessor",
            );
        }
        let predecessor = profile["predecessor_profile_hash"].as_str();
        let exact = current
            .iter()
            .filter(|candidate| {
                candidate.get("profile_hash").and_then(Value::as_str) == predecessor
            })
            .count();
        if exact != 1 {
            return error(
                StatusCode::CONFLICT,
                "gateway_profile_predecessor_not_current",
                "a successor must bind exactly one current predecessor hash",
            );
        }
    }
    let commit = match admit_owner_scoped_write(
        &state.data_dir,
        &caller,
        OWNER_NAMESPACE,
        "authority-gateway-profile",
        profile_ref,
        "authority_gateway.profile.register",
        None,
        &profile,
    ) {
        Ok(commit) => commit,
        Err(reply) => return reply,
    };
    let record_id = record_id_from_hash("agp", &caller.owner_ref, profile_hash);
    let coverage = match super::enforcement_coverage_routes::produce_gateway_profile(
        &state.enforcement_coverage_registry,
        &state.data_dir,
        &caller,
        &profile,
        &commit.receipt_ref,
    ) {
        Ok(coverage) => coverage,
        Err(reason) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_coverage_production_failed",
                reason,
            )
        }
    };
    let record = json!({
        "record_id":record_id, "owner_ref":caller.owner_ref, "profile":profile,
        "admitted_head":commit.projection.head, "admission_receipt_ref":commit.receipt_ref,
        "enforcement_coverage":coverage,
    });
    if let Err(reason) = persist_record(&state.data_dir, PROFILE_DIR, &record_id, &record) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_profile_persistence_failed",
            reason.to_string(),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({"ok":true,"profile":record,"replayed":commit.replayed})),
    )
}

/// POST /v1/action-requests
pub(crate) async fn handle_action_request_create(
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&state.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(reply) => return reply,
    };
    let request = body.get("action_request").cloned().unwrap_or(Value::Null);
    if let Err(reason) = validate_architecture_contract(REQUEST_CONTRACT, &request) {
        return error(
            StatusCode::BAD_REQUEST,
            "gateway_action_request_invalid",
            reason,
        );
    }
    let action_ref = request["action_request_ref"].as_str().unwrap_or_default();
    let request_hash = request["request_hash"].as_str().unwrap_or_default();
    let prior = match prior_admission_for_key(
        &state.data_dir,
        &caller,
        OWNER_NAMESPACE,
        "authority-gateway-action-request",
        action_ref,
    ) {
        Ok(prior) => prior,
        Err(reply) => return reply,
    };
    if let Some(prior) = prior {
        let stored = &prior.operation.payload;
        if prior.operation.op_kind != "authority_gateway.action_request.admit"
            || stored.get("action_request") != Some(&request)
        {
            return error(
                StatusCode::CONFLICT,
                "gateway_action_request_idempotency_conflict",
                "the idempotency key already admitted different action-request bytes",
            );
        }
        if validate_architecture_contract(
            DECISION_RECEIPT_CONTRACT,
            stored
                .get("gateway_decision_receipt")
                .unwrap_or(&Value::Null),
        )
        .is_err()
        {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_action_request_replay_corrupt",
                "the admitted action-request decision receipt is not registered-valid",
            );
        }
        let record_id = record_id_from_hash("gar", &caller.owner_ref, request_hash);
        let receipt_ref = agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE,
            &stream_tail("authority-gateway-action-request", action_ref),
            prior.admission_batch_seq,
            &prior.admission_root,
        );
        let profiles = read_record_dir(&state.data_dir, PROFILE_DIR);
        let coverage = match produce_observed_action_coverage(
            &state,
            &caller,
            &profiles,
            &stored["action_request"],
            &stored["gateway_decision_receipt"],
            &receipt_ref,
        ) {
            Ok(coverage) => coverage,
            Err(reply) => return reply,
        };
        let record = json!({
            "record_id":record_id, "owner_ref":caller.owner_ref,
            "action_request":stored["action_request"],
            "gateway_decision_receipt":stored["gateway_decision_receipt"],
            "execution_status":"not_invoked", "admitted_head":prior.head,
            "admission_receipt_ref":receipt_ref,
            "enforcement_coverage":coverage,
        });
        if let Err(reason) = persist_record(&state.data_dir, ACTION_DIR, &record_id, &record) {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_action_request_persistence_failed",
                reason.to_string(),
            );
        }
        return (
            StatusCode::CREATED,
            Json(json!({"ok":true,"action_request":record,"replayed":true})),
        );
    }
    let now = super::iso_now();
    if let Err(reason) = validate_request_window(&request, &now) {
        return error(
            StatusCode::CONFLICT,
            "gateway_action_request_not_current",
            reason,
        );
    }
    let profiles = read_record_dir(&state.data_dir, PROFILE_DIR);
    let profile = match current_profile(&profiles, &request, &now, &caller.owner_ref) {
        Ok(profile) => profile,
        Err(reason) => {
            return error(
                StatusCode::CONFLICT,
                "gateway_profile_resolution_failed",
                reason,
            )
        }
    };
    if let Err(reason) = exact_adapter_binding(profile, &request) {
        return error(
            StatusCode::FORBIDDEN,
            "gateway_adapter_binding_mismatch",
            reason,
        );
    }
    let surface = match supporting_surface(profile, &request) {
        Ok(surface) => surface,
        Err(reason) => {
            return error(
                StatusCode::FORBIDDEN,
                "gateway_surface_not_admitted",
                reason,
            )
        }
    };
    let coverage_guard = match state.enforcement_coverage_registry.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_coverage_registry_unavailable",
                "the enforcement-coverage lifecycle registry is unavailable",
            )
        }
    };
    let coverage_refs = match verify_coverage(
        &coverage_guard,
        &caller.owner_ref,
        profile,
        surface,
        &request,
        &now,
        false,
    ) {
        Ok(refs) => refs,
        Err(reason) => return error(StatusCode::CONFLICT, "gateway_coverage_unverified", reason),
    };
    drop(coverage_guard);
    let decision_receipt = match build_decision_receipt(&request, coverage_refs, &now) {
        Ok(receipt) => receipt,
        Err(reason) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_decision_receipt_invalid",
                reason,
            )
        }
    };
    let payload = json!({"action_request":request,"gateway_decision_receipt":decision_receipt});
    let commit = match admit_owner_scoped_write(
        &state.data_dir,
        &caller,
        OWNER_NAMESPACE,
        "authority-gateway-action-request",
        action_ref,
        "authority_gateway.action_request.admit",
        None,
        &payload,
    ) {
        Ok(commit) => commit,
        Err(reply) => return reply,
    };
    let coverage = match produce_observed_action_coverage(
        &state,
        &caller,
        &profiles,
        &payload["action_request"],
        &payload["gateway_decision_receipt"],
        &commit.receipt_ref,
    ) {
        Ok(coverage) => coverage,
        Err(reply) => return reply,
    };
    let record_id = record_id_from_hash("gar", &caller.owner_ref, request_hash);
    let record = json!({
        "record_id":record_id, "owner_ref":caller.owner_ref,
        "action_request":payload["action_request"], "gateway_decision_receipt":payload["gateway_decision_receipt"],
        "execution_status":"not_invoked", "admitted_head":commit.projection.head,
        "admission_receipt_ref":commit.receipt_ref,
        "enforcement_coverage":coverage,
    });
    if let Err(reason) = persist_record(&state.data_dir, ACTION_DIR, &record_id, &record) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_action_request_persistence_failed",
            reason.to_string(),
        );
    }
    (
        StatusCode::CREATED,
        Json(json!({"ok":true,"action_request":record,"replayed":commit.replayed})),
    )
}

/// POST /v1/action-requests/:id/execute
pub(crate) async fn handle_action_request_execute(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&state.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(reply) => return reply,
    };
    let records = read_record_dir(&state.data_dir, ACTION_DIR);
    let Some(mut record) = owner_record(&records, &id, &caller.owner_ref) else {
        if records.iter().any(|record| record_matches_id(record, &id)) {
            return error(
                StatusCode::FORBIDDEN,
                "gateway_action_request_owner_mismatch",
                "action request belongs to another owner",
            );
        }
        return error(
            StatusCode::NOT_FOUND,
            "gateway_action_request_not_found",
            "action request not found",
        );
    };
    let request = record.get("action_request").cloned().unwrap_or(Value::Null);
    let decision = record
        .get("gateway_decision_receipt")
        .cloned()
        .unwrap_or(Value::Null);
    if let Err(reason) = validate_architecture_contract(REQUEST_CONTRACT, &request) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_action_request_corrupt",
            reason,
        );
    }
    if let Err(reason) = validate_architecture_contract(DECISION_RECEIPT_CONTRACT, &decision) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_decision_receipt_corrupt",
            reason,
        );
    }
    let invocation_payload = body
        .get("invocation_payload")
        .cloned()
        .unwrap_or(Value::Null);
    let grant_hash = match validate_scm_invocation_payload(&request, &invocation_payload) {
        Ok(hash) => hash,
        Err(reason) => {
            return error(
                StatusCode::BAD_REQUEST,
                "gateway_scm_invocation_invalid",
                reason,
            )
        }
    };
    let action_ref = request["action_request_ref"].as_str().unwrap_or_default();
    let request_hash = request["request_hash"].as_str().unwrap_or_default();
    let prepare_caller = phase_caller(&caller, request_hash, "prepare");
    let final_caller = phase_caller(&caller, request_hash, "final");

    let final_prior = match prior_admission_for_key(
        &state.data_dir,
        &final_caller,
        OWNER_NAMESPACE,
        ACTION_RESOURCE_KIND,
        action_ref,
    ) {
        Ok(prior) => prior,
        Err(reply) => return reply,
    };
    if let Some(prior) = final_prior {
        let terminal = prior.operation.payload;
        if prior.operation.op_kind != "authority_gateway.action_request.execution.finalize"
            || terminal.get("request_hash").and_then(Value::as_str) != Some(request_hash)
            || terminal.get("invocation_payload") != Some(&invocation_payload)
        {
            return error(
                StatusCode::CONFLICT,
                "gateway_execution_idempotency_conflict",
                "the finalization key already admitted different gateway execution bytes",
            );
        }
        record["execution_status"] = terminal["execution_status"].clone();
        record["gateway_execution_receipt"] = terminal["gateway_execution_receipt"].clone();
        record["gateway_artifact_receipt"] = terminal["gateway_artifact_receipt"].clone();
        record["native_result"] = terminal["native_result"].clone();
        record["execution_head"] = json!(prior.head);
        let record_id = record["record_id"].as_str().unwrap_or_default();
        if let Err(reason) = persist_record(&state.data_dir, ACTION_DIR, record_id, &record) {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_execution_persistence_failed",
                reason.to_string(),
            );
        }
        let response_status = terminal
            .get("response_status")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .and_then(|value| StatusCode::from_u16(value).ok())
            .unwrap_or(StatusCode::OK);
        return (
            response_status,
            Json(terminal.get("response").cloned().unwrap_or_else(
                || json!({"ok":false,"error":{"code":"gateway_execution_replay_corrupt"}}),
            )),
        );
    }

    let intent = json!({
        "schema_version":"ioi.hypervisor.authority-gateway-execution-intent.v1",
        "state":"prepared",
        "request_ref":action_ref,
        "request_hash":request_hash,
        "decision_receipt_ref":decision["receipt_ref"],
        "decision_receipt_hash":decision["receipt_hash"],
        "invocation_payload":invocation_payload,
        "invocation_payload_hash":invocation_payload_commitment(&invocation_payload).unwrap_or_default(),
        "native_route_kind":"scm_publication",
        "native_idempotency_key":stable_native_scm_idempotency_key(&request),
        "expected_effect_ref":request["proposed_action"]["proposed_effect_ref"],
        "expected_effect_hash":request["proposed_action"]["proposed_effect_hash"],
        "portable_grant_hash":grant_hash,
    });
    let prepare_prior = match prior_admission_for_key(
        &state.data_dir,
        &prepare_caller,
        OWNER_NAMESPACE,
        ACTION_RESOURCE_KIND,
        action_ref,
    ) {
        Ok(prior) => prior,
        Err(reply) => return reply,
    };
    let (prepared_head, recovering) = if let Some(prior) = prepare_prior {
        if prior.operation.op_kind != "authority_gateway.action_request.execution.prepare"
            || prior.operation.payload != intent
        {
            return error(
                StatusCode::CONFLICT,
                "gateway_execution_idempotency_conflict",
                "the preparation key already admitted different gateway execution bytes",
            );
        }
        (prior.head, true)
    } else {
        let now = super::iso_now();
        if let Err(reason) = validate_request_window(&request, &now) {
            return error(
                StatusCode::CONFLICT,
                "gateway_action_request_not_current",
                reason,
            );
        }
        let profiles = read_record_dir(&state.data_dir, PROFILE_DIR);
        let profile = match current_profile(&profiles, &request, &now, &caller.owner_ref) {
            Ok(profile) => profile,
            Err(reason) => {
                return error(
                    StatusCode::CONFLICT,
                    "gateway_profile_resolution_failed",
                    reason,
                )
            }
        };
        if let Err(reason) = exact_adapter_binding(profile, &request) {
            return error(
                StatusCode::FORBIDDEN,
                "gateway_adapter_binding_mismatch",
                reason,
            );
        }
        let surface = match supporting_surface(profile, &request) {
            Ok(surface) => surface,
            Err(reason) => {
                return error(
                    StatusCode::FORBIDDEN,
                    "gateway_surface_not_admitted",
                    reason,
                )
            }
        };
        let coverage_guard = match state.enforcement_coverage_registry.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway_coverage_registry_unavailable",
                    "the enforcement-coverage lifecycle registry is unavailable",
                )
            }
        };
        if let Err(reason) = verify_coverage(
            &coverage_guard,
            &caller.owner_ref,
            profile,
            surface,
            &request,
            &now,
            true,
        ) {
            return error(StatusCode::CONFLICT, "gateway_coverage_unverified", reason);
        }
        drop(coverage_guard);
        let expected_head = record
            .get("admitted_head")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if expected_head.is_empty() {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_action_request_corrupt",
                "action request has no admitted Agentgres head",
            );
        }
        let commit = match admit_owner_scoped_write(
            &state.data_dir,
            &prepare_caller,
            OWNER_NAMESPACE,
            ACTION_RESOURCE_KIND,
            action_ref,
            "authority_gateway.action_request.execution.prepare",
            Some(expected_head),
            &intent,
        ) {
            Ok(commit) => commit,
            Err(reply) => return reply,
        };
        (commit.projection.head, false)
    };

    record["execution_status"] = json!("prepared");
    record["execution_intent"] = intent.clone();
    record["execution_head"] = json!(prepared_head);
    let record_id = record["record_id"].as_str().unwrap_or_default().to_string();
    if let Err(reason) = persist_record(&state.data_dir, ACTION_DIR, &record_id, &record) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_execution_persistence_failed",
            reason.to_string(),
        );
    }

    let profiles = read_record_dir(&state.data_dir, PROFILE_DIR);
    let profile = match bound_profile(&profiles, &request, &caller.owner_ref) {
        Ok(profile) => profile,
        Err(reason) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_profile_resolution_failed",
                reason,
            )
        }
    };
    let surface = match supporting_surface(profile, &request) {
        Ok(surface) => surface,
        Err(reason) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_surface_not_admitted",
                reason,
            )
        }
    };
    let mut native_body = invocation_payload.clone();
    native_body["gateway_expected_authority_effect_ref"] =
        request["proposed_action"]["proposed_effect_ref"].clone();
    native_body["gateway_expected_authority_effect_hash"] =
        request["proposed_action"]["proposed_effect_hash"].clone();
    native_body["gateway_action_expires_at"] = request["expires_at"].clone();
    let environment_id = invocation_payload["environment_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let (native_status, Json(native_result)) = super::scm_publication_routes::handle_scm_publish(
        State(state.clone()),
        AxumPath(environment_id),
        headers,
        Json(native_body),
    )
    .await;
    let locator = native_result
        .pointer("/publication_effect/authority/admission_receipt_ref")
        .and_then(Value::as_str)
        .or_else(|| {
            native_result
                .get("authority_admission_receipt_ref")
                .and_then(Value::as_str)
        });
    let expected_effect_ref = request["proposed_action"]["proposed_effect_ref"]
        .as_str()
        .unwrap_or_default();
    let expected_effect_hash = request["proposed_action"]["proposed_effect_hash"]
        .as_str()
        .unwrap_or_default();
    let admission = super::governed_authority::resolve_portable_admission_evidence(
        &state.data_dir,
        locator,
        expected_effect_ref,
        expected_effect_hash,
        &grant_hash,
    );
    let authority_must_exist = native_result.get("publication_effect").is_some()
        || native_result
            .get("authority_usage_disposition")
            .and_then(Value::as_str)
            == Some("spent_not_refunded");
    let admission = match admission {
        Ok(evidence) => Some(evidence),
        Err(reason) if !authority_must_exist => None,
        Err(reason) => {
            record["execution_status"] = json!("reconciliation_required");
            record["native_result"] = native_result;
            record["authority_evidence_error"] = json!(reason);
            if let Err(persist_reason) =
                persist_record(&state.data_dir, ACTION_DIR, &record_id, &record)
            {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway_reconciliation_state_persistence_failed",
                    format!(
                        "native SCM reached an authority-bearing disposition, but neither its authority evidence nor the reconciliation marker is durably available: {persist_reason}"
                    ),
                );
            }
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway_authority_evidence_unavailable",
                "native SCM reached an authority-bearing disposition but its exact registered v2 admission evidence is unavailable; retry converges the same native idempotency key",
            );
        }
    };
    let now = super::iso_now();
    let started_at = native_result
        .pointer("/publication_effect/preparation/prepared_persisted_at")
        .and_then(Value::as_str)
        .unwrap_or(&now);
    let completed_at = native_result
        .pointer("/publication_effect/committed_at")
        .and_then(Value::as_str)
        .unwrap_or(&now);
    let (execution_receipt, artifact_receipt) = match build_execution_receipts(
        &request,
        &decision,
        surface,
        native_status,
        &native_result,
        admission.as_ref(),
        started_at,
        completed_at,
    ) {
        Ok(receipts) => receipts,
        Err(reason) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_execution_receipt_invalid",
                reason,
            )
        }
    };
    let execution_status = execution_receipt["outcome"].as_str().unwrap_or("unknown");
    let response_status = if execution_status == "succeeded" {
        StatusCode::OK
    } else if native_status.is_server_error() {
        native_status
    } else {
        StatusCode::CONFLICT
    };
    let response = json!({
        "ok":execution_status == "succeeded",
        "replayed_preparation":recovering,
        "gateway_execution_receipt":execution_receipt,
        "gateway_artifact_receipt":artifact_receipt,
        "native_result":native_result,
    });
    let terminal = json!({
        "schema_version":"ioi.hypervisor.authority-gateway-execution-result.v1",
        "request_hash":request_hash,
        "invocation_payload":invocation_payload,
        "execution_status":execution_status,
        "gateway_execution_receipt":response["gateway_execution_receipt"],
        "gateway_artifact_receipt":response["gateway_artifact_receipt"],
        "native_result":response["native_result"],
        "response_status":response_status.as_u16(),
        "response":response,
    });
    let final_commit = match admit_owner_scoped_write(
        &state.data_dir,
        &final_caller,
        OWNER_NAMESPACE,
        ACTION_RESOURCE_KIND,
        action_ref,
        "authority_gateway.action_request.execution.finalize",
        Some(&prepared_head),
        &terminal,
    ) {
        Ok(commit) => commit,
        Err(reply) => return reply,
    };
    record["execution_status"] = terminal["execution_status"].clone();
    record["gateway_execution_receipt"] = terminal["gateway_execution_receipt"].clone();
    record["gateway_artifact_receipt"] = terminal["gateway_artifact_receipt"].clone();
    record["native_result"] = terminal["native_result"].clone();
    record["execution_head"] = json!(final_commit.projection.head);
    if let Err(reason) = persist_record(&state.data_dir, ACTION_DIR, &record_id, &record) {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "gateway_execution_persistence_failed",
            reason.to_string(),
        );
    }
    (response_status, Json(terminal["response"].clone()))
}

/// GET /v1/action-requests/:id
pub(crate) async fn handle_action_request_get(
    State(state): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&state.data_dir, &headers)
    {
        Ok(identity) => identity,
        Err(reason) => return scope_refusal_reply(reason),
    };
    let records = read_record_dir(&state.data_dir, ACTION_DIR);
    let record = records
        .iter()
        .find(|record| {
            record_matches_id(record, &id)
                && record
                    .get("owner_ref")
                    .and_then(Value::as_str)
                    .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .cloned();
    let Some(record) = record else {
        if records.iter().any(|record| record_matches_id(record, &id)) {
            return error(
                StatusCode::FORBIDDEN,
                "gateway_action_request_owner_mismatch",
                "action request belongs to another owner",
            );
        }
        return error(
            StatusCode::NOT_FOUND,
            "gateway_action_request_not_found",
            "action request not found",
        );
    };
    (
        StatusCode::OK,
        Json(json!({"ok":true,"action_request":record})),
    )
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

    fn current_records() -> (Value, Value, Value, &'static str) {
        let profile = fixture("authority-gateway-profile-v1/positive-active-pre-effect.json");
        let mut request = fixture("action-request-envelope-v1/positive-external-effect.json");
        request["authority_gateway_profile_ref"] = profile["profile_ref"].clone();
        request["authority_gateway_profile_hash"] = profile["profile_hash"].clone();
        request["request_hash"] = json!(canonical_hash(&json!({
            "domain":"ioi.action-request-envelope-hash-jcs-sha256.v1",
            "action_request_ref":request["action_request_ref"], "request_revision":request["request_revision"],
            "authority_gateway_profile_ref":request["authority_gateway_profile_ref"], "authority_gateway_profile_hash":request["authority_gateway_profile_hash"],
            "source_adapter":request["source_adapter"], "proposed_action":request["proposed_action"], "risk_class":request["risk_class"],
            "primitive_capabilities_required":request["primitive_capabilities_required"], "authority_scopes_required":request["authority_scopes_required"],
            "policy_decision":request["policy_decision"], "subject_refs":request["subject_refs"], "receipt_obligations":request["receipt_obligations"],
            "created_at":request["created_at"], "expires_at":request["expires_at"],
        })).unwrap());
        let mut coverage =
            fixture("enforcement-coverage-declaration-v1/positive-active-enforcement.json");
        coverage["subject"]["kind"] = json!("authority_gateway_profile");
        coverage["subject"]["profile_or_adapter_ref"] = profile["profile_ref"].clone();
        coverage["subject"]["version"] =
            profile["declaration"]["adapter"]["adapter_revision"].clone();
        coverage["subject"]["content_hash"] = profile["profile_hash"].clone();
        coverage["subject"]["implementation_ref"] =
            profile["declaration"]["adapter"]["implementation_ref"].clone();
        coverage["subject"]["deployment_profile_ref"] =
            profile["declaration"]["adapter"]["deployment_profile_ref"].clone();
        coverage["scope"]["surface"] = json!("cli");
        coverage["scope"]["action_class"] = json!("git");
        coverage["scope"]["boundary"] = json!("adapter");
        coverage["scope"]["scope_ref"] =
            profile["declaration"]["required_enforcement_scope_refs"][0].clone();
        coverage["decision_source"]["kind"] = json!("daemon_policy_engine");
        coverage["decision_source"]["decision_source_ref"] =
            profile["declaration"]["policy_enforcement_point_ref"].clone();
        coverage["decision_source"]["authority_provider_ref"] =
            profile["declaration"]["authority_provider_ref"].clone();
        coverage["final_invoker"]["kind"] = json!("daemon");
        coverage["final_invoker"]["invoker_ref"] =
            profile["declaration"]["action_surfaces"][0]["final_invoker_ref"].clone();
        coverage["verification"]["evaluated_at"] = json!("2026-08-24T15:00:00Z");
        coverage["verification"]["valid_until"] = json!("2026-09-24T15:00:00Z");
        (profile, request, coverage, "2026-08-24T16:05:00Z")
    }

    fn coverage_registry(
        mut coverage: Value,
        profile: &Value,
        surface: &Value,
    ) -> ioi_services::agentic::runtime::enforcement_coverage::EnforcementCoverageRegistry {
        use ioi_services::agentic::runtime::enforcement_coverage::{
            EnforcementCoverageAdmissionRequest, EnforcementCoverageRegistry,
        };
        let action_class = coverage["scope"]["action_class"]
            .as_str()
            .unwrap()
            .to_owned();
        let scope_ref = coverage["scope"]["scope_ref"].as_str().unwrap().to_owned();
        coverage["declaration_id"] =
            json!(super::super::enforcement_coverage_routes::coordinate_id(
                "org://acme",
                profile,
                surface,
                &action_class,
                &scope_ref,
            )
            .unwrap());
        let hash = canonical_hash(&coverage).expect("coverage hash");
        let mut registry = EnforcementCoverageRegistry::default();
        registry
            .admit(
                EnforcementCoverageAdmissionRequest {
                    declaration_artifact_ref: format!(
                        "artifact://ioi/enforcement-coverage/{}",
                        hash.trim_start_matches("sha256:")
                    ),
                    declaration_content_hash: hash,
                    declaration: coverage,
                    expected_previous_hash: None,
                    evidence_receipt_ref: "receipt://ioi/coverage-admission/test".into(),
                    admitted_at: "2026-08-24T15:00:00Z".into(),
                },
                1_787_587_200_000,
            )
            .expect("coverage admitted");
        registry
    }

    fn scm_execution_request() -> (Value, Value, Value) {
        let (profile, mut request, _, _) = current_records();
        let payload = json!({
            "environment_id":"env-1",
            "proposal_ref":"proposal://acme/ioi/change/1",
            "destination_binding_ref":"scm-destination-binding://acme/ioi/revision/1",
            "target_ref_name":"main",
            "open_review_request":false,
            "idempotency_key":stable_native_scm_idempotency_key(&request),
            "wallet_portable_authority_grant_hash":format!("sha256:{}", "ab".repeat(32)),
        });
        request["proposed_action"]["target_refs"] = json!([
            "environment://env-1",
            "proposal://acme/ioi/change/1",
            "scm-destination-binding://acme/ioi/revision/1"
        ]);
        request["proposed_action"]["input_commitment"] =
            json!(invocation_payload_commitment(&payload).unwrap());
        request["primitive_capabilities_required"] = json!(["prim:net.request", "prim:sys.exec"]);
        request["authority_scopes_required"] = json!([SCM_ADVANCE_SCOPE]);
        request["request_hash"] = json!(canonical_hash(&json!({
            "domain":"ioi.action-request-envelope-hash-jcs-sha256.v1",
            "action_request_ref":request["action_request_ref"], "request_revision":request["request_revision"],
            "authority_gateway_profile_ref":request["authority_gateway_profile_ref"], "authority_gateway_profile_hash":request["authority_gateway_profile_hash"],
            "source_adapter":request["source_adapter"], "proposed_action":request["proposed_action"], "risk_class":request["risk_class"],
            "primitive_capabilities_required":request["primitive_capabilities_required"], "authority_scopes_required":request["authority_scopes_required"],
            "policy_decision":request["policy_decision"], "subject_refs":request["subject_refs"], "receipt_obligations":request["receipt_obligations"],
            "created_at":request["created_at"], "expires_at":request["expires_at"],
        })).unwrap());
        let mut payload = payload;
        payload["idempotency_key"] = json!(stable_native_scm_idempotency_key(&request));
        request["proposed_action"]["input_commitment"] =
            json!(invocation_payload_commitment(&payload).unwrap());
        request["request_hash"] = json!(canonical_hash(&json!({
            "domain":"ioi.action-request-envelope-hash-jcs-sha256.v1",
            "action_request_ref":request["action_request_ref"], "request_revision":request["request_revision"],
            "authority_gateway_profile_ref":request["authority_gateway_profile_ref"], "authority_gateway_profile_hash":request["authority_gateway_profile_hash"],
            "source_adapter":request["source_adapter"], "proposed_action":request["proposed_action"], "risk_class":request["risk_class"],
            "primitive_capabilities_required":request["primitive_capabilities_required"], "authority_scopes_required":request["authority_scopes_required"],
            "policy_decision":request["policy_decision"], "subject_refs":request["subject_refs"], "receipt_obligations":request["receipt_obligations"],
            "created_at":request["created_at"], "expires_at":request["expires_at"],
        })).unwrap());
        (profile, request, payload)
    }

    #[test]
    fn exact_current_profile_surface_and_coverage_admit() {
        let (profile, request, coverage, now) = current_records();
        validate_architecture_contract(REQUEST_CONTRACT, &request).unwrap();
        validate_architecture_contract(
            "schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1",
            &coverage,
        )
        .unwrap();
        let records = vec![json!({"owner_ref":"org://acme","profile":profile})];
        let resolved = current_profile(&records, &request, now, "org://acme").unwrap();
        exact_adapter_binding(resolved, &request).unwrap();
        let surface = supporting_surface(resolved, &request).unwrap();
        let coverage = coverage_registry(coverage, resolved, surface);
        let refs = verify_coverage(
            &coverage,
            "org://acme",
            resolved,
            surface,
            &request,
            now,
            true,
        )
        .unwrap();
        assert_eq!(refs.len(), 1);
        let receipt = build_decision_receipt(&request, refs, now).unwrap();
        assert_eq!(receipt["decision"], "requires_approval");
        assert_eq!(receipt["authority_status"], "required_unresolved");
    }

    #[test]
    fn adapter_scope_and_stale_coverage_substitution_fail_closed() {
        let (profile, mut request, mut coverage, now) = current_records();
        let records = vec![json!({"owner_ref":"org://acme","profile":profile})];
        assert!(current_profile(&records, &request, now, "org://foreign").is_err());
        request["source_adapter"]["adapter_revision"] = json!("foreign");
        assert!(exact_adapter_binding(
            current_profile(&records, &request, now, "org://acme").unwrap(),
            &request
        )
        .is_err());

        let (_, request, _, _) = current_records();
        let resolved = current_profile(&records, &request, now, "org://acme").unwrap();
        let surface = supporting_surface(resolved, &request).unwrap();
        coverage["verification"]["valid_until"] = json!("2026-08-24T16:04:59Z");
        let coverage = coverage_registry(coverage, resolved, surface);
        assert!(verify_coverage(
            &coverage,
            "org://acme",
            resolved,
            surface,
            &request,
            now,
            true,
        )
        .is_err());

        let (_, request, mut coverage, _) = current_records();
        coverage["verification"]["evaluated_at"] = json!("2026-08-24T16:05:01Z");
        let coverage = coverage_registry(coverage, resolved, surface);
        assert!(verify_coverage(
            &coverage,
            "org://acme",
            resolved,
            surface,
            &request,
            now,
            true,
        )
        .is_err());
    }

    #[test]
    fn a_successor_makes_the_predecessor_noncurrent_without_editing_history() {
        let (profile, mut request, _, now) = current_records();
        let mut successor = profile.clone();
        successor["profile_ref"] = json!("authority-gateway://acme/claude-code/revision/2");
        successor["profile_revision"] = json!(2);
        successor["predecessor_profile_hash"] = profile["profile_hash"].clone();
        successor["profile_hash"] = json!(canonical_hash(&json!({
            "domain":"ioi.authority-gateway-profile-hash-jcs-sha256.v1",
            "profile_ref":successor["profile_ref"], "profile_revision":successor["profile_revision"],
            "predecessor_profile_hash":successor["predecessor_profile_hash"], "declaration":successor["declaration"],
            "created_at":successor["created_at"], "valid_until":successor["valid_until"],
        })).unwrap());
        let records = vec![
            json!({"owner_ref":"org://acme","profile":profile}),
            json!({"owner_ref":"org://acme","profile":successor.clone()}),
        ];
        assert!(current_profile(&records, &request, now, "org://acme").is_err());
        request["authority_gateway_profile_ref"] = successor["profile_ref"].clone();
        request["authority_gateway_profile_hash"] = successor["profile_hash"].clone();
        assert_eq!(
            current_profile(&records, &request, now, "org://acme").unwrap()["profile_revision"],
            2
        );
    }

    #[test]
    fn local_projection_ids_and_lookups_are_owner_scoped() {
        let object_hash = format!("sha256:{}", "ab".repeat(32));
        let first_id = record_id_from_hash("gar", "org://first", &object_hash);
        let second_id = record_id_from_hash("gar", "org://second", &object_hash);
        assert_ne!(first_id, second_id);
        let action_ref = "action-request://shared/ref";
        let records = vec![
            json!({
                "record_id":first_id,
                "owner_ref":"org://first",
                "action_request":{"action_request_ref":action_ref},
            }),
            json!({
                "record_id":second_id,
                "owner_ref":"org://second",
                "action_request":{"action_request_ref":action_ref},
            }),
        ];
        assert_eq!(
            owner_record(&records, action_ref, "org://second").unwrap()["owner_ref"],
            "org://second"
        );
    }

    #[test]
    fn scm_execution_payload_is_exactly_bound_and_cannot_widen_review_scope() {
        let (_, request, mut payload) = scm_execution_request();
        validate_architecture_contract(REQUEST_CONTRACT, &request).unwrap();
        assert!(validate_scm_invocation_payload(&request, &payload).is_ok());

        payload["open_review_request"] = json!(true);
        assert!(validate_scm_invocation_payload(&request, &payload).is_err());
        payload["open_review_request"] = json!(false);
        payload["idempotency_key"] = json!("different-native-key");
        assert!(validate_scm_invocation_payload(&request, &payload).is_err());
    }

    #[test]
    fn execution_and_explicit_no_artifact_receipts_validate_for_native_success_and_refusal() {
        let (profile, request, _) = scm_execution_request();
        let surface = &profile["declaration"]["action_surfaces"][0];
        let decision = build_decision_receipt(&request, vec![], "2026-08-24T16:05:00Z")
            .expect("decision receipt");
        let admission = super::super::governed_authority::PortableAdmissionEvidence {
            admission_intent_ref: "authority-admission-intents/pai_test".into(),
            receipt_ref: "receipt://wallet/acme/admission/1".into(),
            receipt_hash: format!("sha256:{}", "44".repeat(32)),
            effect_ref: request["proposed_action"]["proposed_effect_ref"]
                .as_str()
                .unwrap()
                .into(),
            effect_hash: request["proposed_action"]["proposed_effect_hash"]
                .as_str()
                .unwrap()
                .into(),
            final_invoker_status: "invoked".into(),
        };
        let native = json!({
            "ok":true,
            "overall_outcome":"published_review_request_not_requested",
            "publication_effect":{
                "preparation":{"prepared_persisted_at":"2026-08-24T16:05:00Z"},
                "committed_at":"2026-08-24T16:05:01Z",
                "effects":{"publication":{"receipt_ref":"receipt://ioi/scm/publication/1"}}
            }
        });
        let (execution, artifact) = build_execution_receipts(
            &request,
            &decision,
            surface,
            StatusCode::OK,
            &native,
            Some(&admission),
            "2026-08-24T16:05:00Z",
            "2026-08-24T16:05:01Z",
        )
        .unwrap();
        assert_eq!(execution["outcome"], "succeeded");
        assert_eq!(artifact["evidence_kind"], "none");

        let (refused, _) = build_execution_receipts(
            &request,
            &decision,
            surface,
            StatusCode::PRECONDITION_REQUIRED,
            &json!({"ok":false,"reason":"authority_required"}),
            None,
            "2026-08-24T16:05:00Z",
            "2026-08-24T16:05:00Z",
        )
        .unwrap();
        assert_eq!(refused["outcome"], "refused");
        assert!(refused["authority_effect_admission_receipt_ref"].is_null());

        let (pre_native_refused, _) = build_execution_receipts(
            &request,
            &decision,
            surface,
            StatusCode::CONFLICT,
            &json!({
                "ok":false,
                "overall_outcome":"refused_before_native_prepared",
                "authority_usage_disposition":"spent_not_refunded",
                "remote_effect_invoked":false,
            }),
            Some(&admission),
            "2026-08-24T16:05:00Z",
            "2026-08-24T16:05:00Z",
        )
        .unwrap();
        assert_eq!(pre_native_refused["outcome"], "refused");
        assert_eq!(
            pre_native_refused["authority_effect_admission_receipt_ref"],
            admission.receipt_ref
        );
    }
}
