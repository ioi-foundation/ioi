//! Authority Gateway attach-lane admission.
//!
//! This module owns no authority and invokes nothing. It registers immutable adapter profiles and
//! admits exact `ActionRequestEnvelope` proposals only after resolving one current profile and its
//! current verified `EnforcementCoverageDeclaration` set. The resulting decision receipt is
//! durable before any later execution route can re-enter an existing native PEP/final invoker.

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
    stream_tail,
};
use super::{persist_record, read_record_dir, DaemonState};

const PROFILE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/authority-gateway-profile/v1";
const REQUEST_CONTRACT: &str = "schema://ioi/components/daemon-runtime/action-request-envelope/v1";
const DECISION_RECEIPT_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1";
const COVERAGE_CONTRACT: &str =
    "schema://ioi/components/daemon-runtime/enforcement-coverage-declaration/v1";
const PROFILE_SCHEMA: &str = "ioi.components.daemon-runtime.authority-gateway-profile.v1";
const COVERAGE_SCHEMA: &str = "ioi.components.daemon-runtime.enforcement-coverage-declaration.v1";
const PROFILE_DIR: &str = "authority-gateway-profiles";
const ACTION_DIR: &str = "authority-gateway-action-requests";
const COVERAGE_DIR: &str = "hypervisoros-node-evidence";
const OWNER_NAMESPACE: &str = "hypervisor-authority-gateway";

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
    coverage_records: &[Value],
    profile: &Value,
    surface: &Value,
    request: &Value,
    now: &str,
) -> Result<Vec<String>, String> {
    let profile_ref = profile["profile_ref"].as_str().unwrap_or_default();
    let profile_hash = profile["profile_hash"].as_str().unwrap_or_default();
    let implementation_ref = profile
        .pointer("/declaration/adapter/implementation_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let deployment_ref = profile
        .pointer("/declaration/adapter/deployment_profile_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let pep_ref = profile
        .pointer("/declaration/policy_enforcement_point_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let provider_ref = profile
        .pointer("/declaration/authority_provider_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let final_invoker_ref = surface
        .get("final_invoker_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let action_class = request
        .pointer("/proposed_action/action_class")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let surface_name = surface
        .get("surface")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let required: BTreeSet<&str> = profile
        .pointer("/declaration/required_enforcement_scope_refs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let now = parse_time(now, "current time")?;
    let mut satisfied = BTreeSet::new();
    let mut evidence = Vec::new();

    for declaration in coverage_records {
        let declaration = declaration.get("declaration").unwrap_or(declaration);
        if declaration.get("schema_version").and_then(Value::as_str) != Some(COVERAGE_SCHEMA)
            || declaration
                .pointer("/subject/profile_or_adapter_ref")
                .and_then(Value::as_str)
                != Some(profile_ref)
        {
            continue;
        }
        validate_architecture_contract(COVERAGE_CONTRACT, declaration).map_err(|reason| {
            format!("gateway coverage evidence is not registered-valid: {reason}")
        })?;
        let scope_ref = declaration
            .pointer("/scope/scope_ref")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !required.contains(scope_ref) {
            continue;
        }
        let evaluated_at = parse_time(
            declaration
                .pointer("/verification/evaluated_at")
                .and_then(Value::as_str)
                .ok_or_else(|| "coverage evidence lacks evaluated_at".to_string())?,
            "coverage evaluated_at",
        )?;
        let valid_until = parse_time(
            declaration
                .pointer("/verification/valid_until")
                .and_then(Value::as_str)
                .ok_or_else(|| "coverage evidence lacks valid_until".to_string())?,
            "coverage valid_until",
        )?;
        let exact = declaration.pointer("/subject/kind").and_then(Value::as_str)
            == Some("authority_gateway_profile")
            && declaration
                .pointer("/subject/content_hash")
                .and_then(Value::as_str)
                == Some(profile_hash)
            && declaration
                .pointer("/subject/implementation_ref")
                .and_then(Value::as_str)
                == Some(implementation_ref)
            && declaration
                .pointer("/subject/deployment_profile_ref")
                .and_then(Value::as_str)
                == Some(deployment_ref)
            && declaration
                .pointer("/scope/surface")
                .and_then(Value::as_str)
                == Some(surface_name)
            && declaration
                .pointer("/scope/action_class")
                .and_then(Value::as_str)
                == Some(action_class)
            && declaration.get("operating_mode").and_then(Value::as_str)
                == Some("active_enforcement")
            && declaration.get("status").and_then(Value::as_str) == Some("verified")
            && declaration
                .pointer("/verification/freshness_status")
                .and_then(Value::as_str)
                == Some("current")
            && evaluated_at <= now
            && now <= valid_until
            && declaration
                .pointer("/claims/mediated")
                .and_then(Value::as_bool)
                == Some(true)
            && declaration
                .pointer("/claims/preventable")
                .and_then(Value::as_bool)
                == Some(true)
            && declaration
                .pointer("/claims/receipted")
                .and_then(Value::as_bool)
                == Some(true)
            && declaration
                .pointer("/claims/uncovered")
                .and_then(Value::as_bool)
                == Some(false)
            && declaration
                .pointer("/decision_source/kind")
                .and_then(Value::as_str)
                == Some("daemon_policy_engine")
            && declaration
                .pointer("/decision_source/decision_source_ref")
                .and_then(Value::as_str)
                == Some(pep_ref)
            && declaration
                .pointer("/decision_source/authority_provider_ref")
                .and_then(Value::as_str)
                == Some(provider_ref)
            && declaration
                .pointer("/final_invoker/kind")
                .and_then(Value::as_str)
                == Some("daemon")
            && declaration
                .pointer("/final_invoker/invoker_ref")
                .and_then(Value::as_str)
                == Some(final_invoker_ref);
        if exact {
            if !satisfied.insert(scope_ref.to_string()) {
                return Err(format!(
                    "multiple current coverage declarations claim '{scope_ref}'"
                ));
            }
            evidence.push(
                declaration
                    .get("declaration_id")
                    .and_then(Value::as_str)
                    .unwrap_or(scope_ref)
                    .to_string(),
            );
        }
    }
    let required_owned: BTreeSet<String> = required.into_iter().map(str::to_string).collect();
    if satisfied != required_owned {
        return Err(
            "current verified coverage does not satisfy every profile enforcement scope".into(),
        );
    }
    evidence.sort();
    Ok(evidence)
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

fn record_id_from_hash(prefix: &str, hash: &str) -> String {
    let hex = hash.trim_start_matches("sha256:");
    format!("{prefix}_{}", &hex[..hex.len().min(24)])
}

fn owner_record(records: &[Value], id_or_ref: &str) -> Option<Value> {
    records
        .iter()
        .find(|record| {
            record.get("record_id").and_then(Value::as_str) == Some(id_or_ref)
                || record
                    .pointer("/action_request/action_request_ref")
                    .and_then(Value::as_str)
                    == Some(id_or_ref)
        })
        .cloned()
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
    let profile_ref = profile["profile_ref"].as_str().unwrap_or_default();
    let profile_hash = profile["profile_hash"].as_str().unwrap_or_default();
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
        let record_id = record_id_from_hash("agp", profile_hash);
        let receipt_ref = agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE,
            &stream_tail("authority-gateway-profile", profile_ref),
            prior.admission_batch_seq,
            &prior.admission_root,
        );
        let record = json!({
            "record_id":record_id, "owner_ref":caller.owner_ref, "profile":profile,
            "admitted_head":prior.head, "admission_receipt_ref":receipt_ref,
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
    let record_id = record_id_from_hash("agp", profile_hash);
    let record = json!({
        "record_id":record_id, "owner_ref":caller.owner_ref, "profile":profile,
        "admitted_head":commit.projection.head, "admission_receipt_ref":commit.receipt_ref,
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
        let record_id = record_id_from_hash("gar", request_hash);
        let receipt_ref = agentgres::refs::event_stream_receipt_ref(
            OWNER_NAMESPACE,
            &stream_tail("authority-gateway-action-request", action_ref),
            prior.admission_batch_seq,
            &prior.admission_root,
        );
        let record = json!({
            "record_id":record_id, "owner_ref":caller.owner_ref,
            "action_request":stored["action_request"],
            "gateway_decision_receipt":stored["gateway_decision_receipt"],
            "execution_status":"not_invoked", "admitted_head":prior.head,
            "admission_receipt_ref":receipt_ref,
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
    let coverage = read_record_dir(&state.data_dir, COVERAGE_DIR);
    let coverage_refs = match verify_coverage(&coverage, profile, surface, &request, &now) {
        Ok(refs) => refs,
        Err(reason) => return error(StatusCode::CONFLICT, "gateway_coverage_unverified", reason),
    };
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
    let record_id = record_id_from_hash("gar", request_hash);
    let record = json!({
        "record_id":record_id, "owner_ref":caller.owner_ref,
        "action_request":payload["action_request"], "gateway_decision_receipt":payload["gateway_decision_receipt"],
        "execution_status":"not_invoked", "admitted_head":commit.projection.head,
        "admission_receipt_ref":commit.receipt_ref,
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
    let Some(record) = owner_record(&records, &id) else {
        return error(
            StatusCode::NOT_FOUND,
            "gateway_action_request_not_found",
            "action request not found",
        );
    };
    let owner = record
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !identity.authorizes_tenant(owner) {
        return error(
            StatusCode::FORBIDDEN,
            "gateway_action_request_owner_mismatch",
            "action request belongs to another owner",
        );
    }
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

    #[test]
    fn exact_current_profile_surface_and_coverage_admit() {
        let (profile, request, coverage, now) = current_records();
        validate_architecture_contract(REQUEST_CONTRACT, &request).unwrap();
        validate_architecture_contract(COVERAGE_CONTRACT, &coverage).unwrap();
        let records = vec![json!({"owner_ref":"org://acme","profile":profile})];
        let resolved = current_profile(&records, &request, now, "org://acme").unwrap();
        exact_adapter_binding(resolved, &request).unwrap();
        let surface = supporting_surface(resolved, &request).unwrap();
        let refs = verify_coverage(&[coverage], resolved, surface, &request, now).unwrap();
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
        assert!(verify_coverage(&[coverage], resolved, surface, &request, now).is_err());

        let (_, request, mut coverage, _) = current_records();
        coverage["verification"]["evaluated_at"] = json!("2026-08-24T16:05:01Z");
        assert!(verify_coverage(&[coverage], resolved, surface, &request, now).is_err());
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
}
