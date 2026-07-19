//! Governed admission of one compiled AutonomousSystemGenesis proposal.
//!
//! M1.3 admits the immutable proposal through wallet.network authority, the daemon, durable
//! evidence, and the mandatory Agentgres admission boundary. It does not activate a System, materialize
//! active profiles, create node membership, or expose a Systems product surface.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    Json,
};
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use ioi_types::app::{
    compile_system_genesis_proposal, validate_principal_authority_ref, ApprovalGrant,
    SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::governed_authority::{
    self as governed, AuthorityContract, AuthorityPolicyContext, AuthorizedDecision, Governance,
};
use super::DaemonState;

type VErr = (String, String);

const RECORD_DIR: &str = "autonomous-system-genesis-registry";
const RECEIPT_DIR: &str = "autonomous-system-genesis-receipts";
const INTENT_DIR: &str = "autonomous-system-genesis-intents";
const AGGREGATE_SCHEMA: &str = "ioi.hypervisor.autonomous-system-genesis-admission.v1";
const RECEIPT_SCHEMA: &str = "ioi.hypervisor.autonomous-system-genesis-receipt.v1";
const INTENT_SCHEMA: &str = "ioi.hypervisor.autonomous-system-genesis-intent.v1";
const GENESIS_CONTRACT: &str = "schema://ioi/foundations/autonomous-system-genesis/v1";
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

const AUTHORITY: AuthorityContract = AuthorityContract {
    scope_prefix: "system_genesis",
    policy_domain: "hypervisor.system-genesis.decision.policy.v1",
    request_domain: "hypervisor.system-genesis.decision.request.v1",
    resolution_domain: "hypervisor.system-genesis.authority-resolution.v1",
    code_prefix: "system_genesis",
    host_label: "system_owner",
    participant_label: "not_applicable",
};

pub(crate) static SYSTEM_GENESIS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct CompiledAdmission {
    release: Value,
    proposed_instantiation: Value,
    proposed_genesis: Value,
    initial_profile_bundle: Value,
    proposal_root: String,
    proposal_hash_profile: String,
    bundle_root: String,
    bundle_hash_profile: String,
}

#[derive(Debug)]
struct ReconstructedIntent {
    system_id: String,
    genesis_ref: String,
    required_authority_ref: String,
    subject_ref: String,
    effect: Value,
    receipt: Value,
    receipt_tail: String,
    final_record: Value,
    record_tail: String,
}

fn verr(code: &str, message: impl Into<String>) -> VErr {
    (code.to_string(), message.into())
}

fn classify((code, message): VErr) -> (StatusCode, Json<Value>) {
    let status = if code.ends_with("_not_found") {
        StatusCode::NOT_FOUND
    } else if code.contains("conflict")
        || code.contains("in_flight")
        || code.contains("already_admitted")
    {
        StatusCode::CONFLICT
    } else if code.contains("unavailable") {
        StatusCode::NOT_IMPLEMENTED
    } else if code.contains("unreadable")
        || code.contains("persist_failed")
        || code.contains("pending_convergence")
        || code.contains("durability")
        || code.contains("swapped")
        || code.contains("agentgres")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (
        status,
        Json(json!({
            "error": {
                "code": code,
                "message": message,
                "runtimeTruthSource": "daemon-runtime"
            }
        })),
    )
}

fn s(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn canonical_tail(tail: &str, prefix: &str) -> bool {
    tail.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    })
}

fn canonical_record_tail(tail: &str) -> bool {
    canonical_tail(tail, "asg_")
}

fn canonical_receipt_tail(tail: &str) -> bool {
    canonical_tail(tail, "asgr_")
}

fn canonical_intent_tail(tail: &str) -> bool {
    canonical_tail(tail, "asgi_")
}

fn canonical_ref(value: &str, prefix: &str) -> bool {
    value.len() <= 320
        && value.strip_prefix(prefix).is_some_and(|tail| {
            !tail.is_empty()
                && !tail.starts_with('/')
                && !tail.contains("..")
                && !tail.chars().any(char::is_whitespace)
        })
}

fn deterministic_tail(prefix: &str, material: &Value) -> String {
    let hash = super::outcome_room_routes::record_output_hash(material, &[]);
    format!("{prefix}{}", hash.strip_prefix("sha256:").unwrap_or(&hash))
}

fn record_tail(system_id: &str) -> String {
    deterministic_tail(
        "asg_",
        &json!({
            "domain": "hypervisor.autonomous-system-genesis.identity.v1",
            "system_id": system_id
        }),
    )
}

fn fresh_tail(prefix: &str, subject: &str, resolved_at_ms: u64) -> String {
    deterministic_tail(
        prefix,
        &json!({
            "domain": "hypervisor.autonomous-system-genesis.evidence-nonce.v1",
            "subject_ref": subject,
            "resolved_at_ms": resolved_at_ms,
            "nonce": uuid::Uuid::new_v4().to_string()
        }),
    )
}

fn ms_to_rfc3339(ms: u64) -> Result<String, VErr> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms).saturating_mul(1_000_000))
        .map_err(|_| {
            verr(
                "system_genesis_wallet_time_invalid",
                "wallet time is not representable",
            )
        })?
        .format(&Rfc3339)
        .map_err(|error| verr("system_genesis_wallet_time_invalid", error.to_string()))
}

fn without(value: &Value, field: &str) -> Value {
    let mut clone = value.clone();
    if let Some(object) = clone.as_object_mut() {
        object.remove(field);
    }
    clone
}

fn validate_top_level(body: &Value) -> Result<(&Value, &Value), VErr> {
    if serde_json::to_vec(body).map_or(MAX_REQUEST_BYTES + 1, |bytes| bytes.len())
        > MAX_REQUEST_BYTES
    {
        return Err(verr(
            "system_genesis_payload_too_large",
            format!("request exceeds the {MAX_REQUEST_BYTES}-byte admission ceiling"),
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "system_genesis_body_invalid",
            "request body must be an object",
        )
    })?;
    for key in object.keys() {
        if !["release", "proposed_instantiation", "wallet_approval_grant"].contains(&key.as_str()) {
            return Err(verr(
                "system_genesis_field_unknown",
                format!("unknown or plane-owned field '{key}'"),
            ));
        }
    }
    let release = object
        .get("release")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            verr(
                "system_genesis_release_required",
                "'release' must be an immutable package-release object",
            )
        })?;
    let proposed = object
        .get("proposed_instantiation")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            verr(
                "system_genesis_proposal_required",
                "'proposed_instantiation' must be a proposal-input object",
            )
        })?;
    Ok((release, proposed))
}

fn reject_sensitive_body(body: &Value) -> Result<(), VErr> {
    super::outcome_room_routes::reject_sensitive_keys(body, "").map_err(|(_, message)| {
        verr(
            "system_genesis_plaintext_secret_rejected",
            format!("genesis admission rejected sensitive request material ({message})"),
        )
    })
}

fn canonical_authority_body(body: &Value) -> Result<Value, VErr> {
    let Some(grant) = body
        .get("wallet_approval_grant")
        .filter(|value| !value.is_null())
    else {
        return Ok(body.clone());
    };
    let parsed: ApprovalGrant = serde_json::from_value(grant.clone()).map_err(|error| {
        verr(
            "system_genesis_wallet_grant_invalid",
            format!("wallet_approval_grant is not a canonical ApprovalGrant ({error})"),
        )
    })?;
    let canonical = serde_json::to_value(parsed).map_err(|error| {
        verr(
            "system_genesis_wallet_grant_invalid",
            format!("wallet_approval_grant cannot be serialized canonically ({error})"),
        )
    })?;
    if &canonical != grant {
        return Err(verr(
            "system_genesis_wallet_grant_shape_invalid",
            "wallet_approval_grant must equal its closed canonical projection exactly",
        ));
    }
    let mut authority_body = body.clone();
    authority_body["wallet_approval_grant"] = canonical;
    Ok(authority_body)
}

fn compile_inputs(release: &Value, proposed: &Value) -> Result<CompiledAdmission, Value> {
    let compilation = compile_system_genesis_proposal(release, proposed);
    let Some(compiled) = compilation.proposal else {
        return Err(
            serde_json::to_value(compilation.blocker_report).unwrap_or_else(|_| {
                json!({
                    "schema_version": "ioi.autonomous-system-genesis-blocker-report.v1",
                    "blockers": [{
                        "code": "projection_failed",
                        "path": "$",
                        "message": "blocker report projection failed"
                    }],
                    "truncated": false
                })
            }),
        );
    };
    Ok(CompiledAdmission {
        release: release.clone(),
        proposed_instantiation: proposed.clone(),
        proposed_genesis: serde_json::to_value(compiled.genesis).unwrap_or(Value::Null),
        initial_profile_bundle: serde_json::to_value(compiled.initial_profile_bundle.bundle)
            .unwrap_or(Value::Null),
        proposal_root: compiled.proposal_root,
        proposal_hash_profile: compiled.hash_profile.to_string(),
        bundle_root: compiled.initial_profile_bundle.bundle_root,
        bundle_hash_profile: compiled.initial_profile_bundle.hash_profile.to_string(),
    })
}

fn compile_or_error(release: &Value, proposed: &Value) -> Result<CompiledAdmission, VErr> {
    compile_inputs(release, proposed).map_err(|report| {
        verr(
            "system_genesis_proposal_invalid",
            serde_json::to_string(&report).unwrap_or_else(|_| "proposal rejected".to_string()),
        )
    })
}

fn admission_effect(compiled: &CompiledAdmission) -> Value {
    let genesis = &compiled.proposed_genesis;
    json!({
        "operation": "admit_genesis",
        "manifest_release_payload_hash": super::outcome_room_routes::record_output_hash(&compiled.release, &[]),
        "proposed_instantiation_payload_hash": super::outcome_room_routes::record_output_hash(&compiled.proposed_instantiation, &[]),
        "system_id": genesis.get("system_id"),
        "genesis_ref": genesis.get("genesis_id"),
        "package_id": genesis.get("package_id"),
        "manifest_ref": genesis.get("manifest_ref"),
        "admitted_manifest_root": genesis.get("admitted_manifest_root"),
        "constitution_ref": genesis.get("constitution_ref"),
        "proposal_root": compiled.proposal_root,
        "initial_profile_bundle_root": compiled.bundle_root,
        "genesis_operation_commitment": genesis.pointer("/cryptographic_origin/genesis_operation_commitment"),
        "genesis_transition_commitment_ref": genesis.pointer("/cryptographic_origin/genesis_transition_commitment_ref"),
        "initial_state_root": genesis.pointer("/cryptographic_origin/initial_state_root"),
        "initial_receipt_root": genesis.pointer("/cryptographic_origin/initial_receipt_root"),
        "target_status": "authorized",
        "active_profile_materialization_admitted": false,
        "activation_admitted": false,
        "runtime_effect_admitted": false
    })
}

fn governing_authority_ref(compiled: &CompiledAdmission) -> Result<String, VErr> {
    let owners = compiled
        .initial_profile_bundle
        .pointer("/constitution/governance/governance_owner_refs")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            verr(
                "system_genesis_governing_authority_required",
                "the compiled constitution must declare governance owners",
            )
        })?;
    if owners.len() != 1 {
        return Err(verr(
            "system_genesis_authority_aggregation_unavailable",
            "M1.3 admits only a constitution with exactly one portable governance owner; multi-owner authority aggregation is not implemented",
        ));
    }
    let authority_ref = owners[0].as_str().ok_or_else(|| {
        verr(
            "system_genesis_governing_authority_invalid",
            "the sole constitution governance owner must be a canonical string ref",
        )
    })?;
    validate_principal_authority_ref(authority_ref).map_err(|error| {
        verr(
            "system_genesis_governing_authority_invalid",
            format!(
                "the sole constitution governance owner is not a registered portable authority principal ({error})"
            ),
        )
    })?;
    Ok(authority_ref.to_string())
}

fn canonical_grant_ref(wallet_grant_ref: &str) -> String {
    format!(
        "grant://wallet.network/approval/sha256:{:x}",
        Sha256::digest(wallet_grant_ref.as_bytes())
    )
}

fn build_authorized_genesis(
    compiled: &CompiledAdmission,
    receipt_ref: &str,
    canonical_grant_ref: &str,
) -> Result<Value, VErr> {
    let mut genesis = compiled.proposed_genesis.clone();
    genesis["status"] = json!("authorized");
    genesis["instantiation"]["authority_grant_refs"] = json!([canonical_grant_ref]);
    genesis["cryptographic_origin"]["admission_proof_ref"] = json!(receipt_ref);
    genesis["status_source_receipt_refs"] = json!([receipt_ref]);
    validate_architecture_contract(GENESIS_CONTRACT, &genesis).map_err(|error| {
        verr(
            "system_genesis_authorized_projection_invalid",
            format!("authorized genesis fails its registered contract ({error})"),
        )
    })?;
    Ok(genesis)
}

fn build_record(
    compiled: &CompiledAdmission,
    receipt_ref: &str,
    authorized: &AuthorizedDecision,
    admitted_at: &str,
) -> Result<Value, VErr> {
    let proposed = &compiled.proposed_genesis;
    let system_id = proposed
        .get("system_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let genesis_ref = proposed
        .get("genesis_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let tail = record_tail(system_id);
    let grant_ref = canonical_grant_ref(&authorized.evidence.grant_ref);
    let governing_authority_ref = governing_authority_ref(compiled)?;
    let authorized_genesis = build_authorized_genesis(compiled, receipt_ref, &grant_ref)?;
    Ok(json!({
        "schema_version": AGGREGATE_SCHEMA,
        "admission_id": format!("system-genesis-admission://{tail}"),
        "system_id": system_id,
        "genesis_ref": genesis_ref,
        "package_id": proposed.get("package_id"),
        "manifest_ref": proposed.get("manifest_ref"),
        "admitted_manifest_root": proposed.get("admitted_manifest_root"),
        "manifest_release_payload_hash": super::outcome_room_routes::record_output_hash(&compiled.release, &[]),
        "proposed_instantiation_payload_hash": super::outcome_room_routes::record_output_hash(&compiled.proposed_instantiation, &[]),
        "proposal_root": compiled.proposal_root,
        "proposal_hash_profile": compiled.proposal_hash_profile,
        "initial_profile_bundle_root": compiled.bundle_root,
        "initial_profile_bundle_hash_profile": compiled.bundle_hash_profile,
        "proposal_authority_boundary": SYSTEM_GENESIS_PROPOSAL_AUTHORITY_BOUNDARY,
        "manifest_release": compiled.release,
        "proposed_genesis": compiled.proposed_genesis,
        "initial_profile_bundle": compiled.initial_profile_bundle,
        "authorized_genesis": authorized_genesis,
        "governing_decision_ref": proposed.pointer("/instantiation/decision_ref"),
        "proposed_by_ref": proposed.pointer("/instantiation/proposed_by"),
        "governing_authority_ref": governing_authority_ref,
        "canonical_authority_grant_ref": grant_ref,
        "wallet_authority_grant_ref": authorized.evidence.grant_ref,
        "admission_receipt_ref": receipt_ref,
        "admission_status": "authorized",
        "active_profile_materialization_state": "pending_m1_4",
        "activation_state": "not_started",
        "live_runtime_state_created": false,
        "admitted_at": admitted_at,
        "at": admitted_at,
        "runtimeTruthSource": "daemon-runtime"
    }))
}

fn initial_profile_boundary_refs(genesis: &Value) -> Vec<Value> {
    let mut refs = vec![
        genesis.get("system_id").cloned().unwrap_or(Value::Null),
        genesis.get("genesis_id").cloned().unwrap_or(Value::Null),
        genesis.get("package_id").cloned().unwrap_or(Value::Null),
        genesis.get("manifest_ref").cloned().unwrap_or(Value::Null),
        genesis
            .get("constitution_ref")
            .cloned()
            .unwrap_or(Value::Null),
        genesis
            .pointer("/instantiation/decision_ref")
            .cloned()
            .unwrap_or(Value::Null),
        genesis
            .pointer("/instantiation/proposed_by")
            .cloned()
            .unwrap_or(Value::Null),
    ];
    for field in [
        "deployment_profile_ref",
        "ordering_admission_finality_profile_ref",
        "lifecycle_continuity_profile_ref",
        "network_enrollment_ref",
    ] {
        if let Some(value) = genesis.pointer(&format!("/initial_profile_refs/{field}")) {
            if !value.is_null() {
                refs.push(value.clone());
            }
        }
    }
    refs.extend(
        genesis
            .pointer("/initial_profile_refs/oracle_evidence_profile_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .cloned(),
    );
    refs
}

fn build_receipt(
    receipt_tail: &str,
    record: &Value,
    authorized: &AuthorizedDecision,
    admitted_at: &str,
) -> Value {
    let receipt_ref = format!("receipt://{receipt_tail}");
    let genesis = record.get("authorized_genesis").unwrap_or(&Value::Null);
    let mut boundary_refs = initial_profile_boundary_refs(genesis);
    boundary_refs.push(
        record
            .get("governing_authority_ref")
            .cloned()
            .unwrap_or(Value::Null),
    );
    boundary_refs.push(json!(record
        .get("canonical_authority_grant_ref")
        .and_then(Value::as_str)
        .unwrap_or("")));
    let constitution_root = record
        .pointer("/initial_profile_bundle/constitution/constitution_root")
        .cloned()
        .unwrap_or(Value::Null);
    let mut receipt = json!({
        "schema_version": RECEIPT_SCHEMA,
        "receipt_id": receipt_ref,
        "receipt_ref": receipt_ref,
        "receipt_type": "AutonomousSystemGenesisReceipt",
        "receipt_profile_ref": format!("schema://{RECEIPT_SCHEMA}"),
        "actor_id": "daemon://hypervisor-runtime",
        "subject_ref": record.get("genesis_ref"),
        "op": "admitted",
        "attested_boundary_fact_refs": boundary_refs,
        "bound_facts": {
            "package_id": record.get("package_id"),
            "manifest_ref": record.get("manifest_ref"),
            "manifest_release_root": record.get("admitted_manifest_root"),
            "manifest_release_payload_hash": record.get("manifest_release_payload_hash"),
            "proposed_instantiation_payload_hash": record.get("proposed_instantiation_payload_hash"),
            "system_id": record.get("system_id"),
            "genesis_ref": record.get("genesis_ref"),
            "constitution_ref": genesis.get("constitution_ref"),
            "constitution_root": constitution_root,
            "initial_profile_refs": genesis.get("initial_profile_refs"),
            "governing_decision_ref": record.get("governing_decision_ref"),
            "proposed_by_ref": record.get("proposed_by_ref"),
            "governing_authority_ref": record.get("governing_authority_ref"),
            "canonical_authority_grant_ref": record.get("canonical_authority_grant_ref"),
            "wallet_authority_grant_ref": record.get("wallet_authority_grant_ref"),
            "sequence": genesis.pointer("/cryptographic_origin/sequence"),
            "proposal_root": record.get("proposal_root"),
            "initial_profile_bundle_root": record.get("initial_profile_bundle_root"),
            "genesis_operation_commitment": genesis.pointer("/cryptographic_origin/genesis_operation_commitment"),
            "genesis_transition_commitment_ref": genesis.pointer("/cryptographic_origin/genesis_transition_commitment_ref"),
            "initial_state_root": genesis.pointer("/cryptographic_origin/initial_state_root"),
            "initial_receipt_root": genesis.pointer("/cryptographic_origin/initial_receipt_root"),
            "genesis_status": "authorized",
            "active_profile_materialization_admitted": false,
            "activation_admitted": false,
            "runtime_effect_admitted": false
        },
        "output_hash": super::outcome_room_routes::record_output_hash(record, &[]),
        "hash_scope_excludes": [],
        "assurance_posture": "genesis_admitted_not_activated",
        "assurance_note": "governed admission of one immutable genesis and stable System identity; profile materialization, activation, node membership, optional network services, and runtime effects remain unadmitted",
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "claim_scope_ref": Value::Null,
        "run_id": Value::Null,
        "task_id": Value::Null,
        "input_hash": Value::Null,
        "policy_hash": Value::Null,
        "authority_grant_id": Value::Null,
        "primitive_capabilities": [],
        "authority_scopes": [AUTHORITY.operation_scope("admit")],
        "artifact_refs": [record.get("manifest_ref").cloned().unwrap_or(Value::Null)],
        "evidence_bundle_refs": [],
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "signature": Value::Null,
        "l1_commitment": Value::Null,
        "timestamp": admitted_at,
        "outcome": "ok",
        "at": admitted_at
    });
    governed::append_evidence(&mut receipt, authorized);
    receipt
}

fn validate_record_identity(tail: &str, record: &Value) -> Result<(), String> {
    let system_id = record
        .get("system_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "aggregate lacks system_id".to_string())?;
    let genesis = record
        .get("authorized_genesis")
        .ok_or_else(|| "aggregate lacks authorized_genesis".to_string())?;
    if !canonical_record_tail(tail)
        || tail != record_tail(system_id)
        || record.get("schema_version").and_then(Value::as_str) != Some(AGGREGATE_SCHEMA)
        || record.get("admission_id").and_then(Value::as_str)
            != Some(format!("system-genesis-admission://{tail}").as_str())
        || genesis.get("system_id").and_then(Value::as_str) != Some(system_id)
        || genesis.get("status").and_then(Value::as_str) != Some("authorized")
        || record.get("admission_status").and_then(Value::as_str) != Some("authorized")
        || record
            .get("live_runtime_state_created")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(format!(
            "canonical slot '{RECORD_DIR}/{tail}.json' fails identity/status binding"
        ));
    }
    validate_architecture_contract(GENESIS_CONTRACT, genesis)
        .map_err(|error| format!("authorized genesis contract invalid ({error})"))
}

fn load_record(data_dir: &str, tail: &str) -> Result<Option<Value>, String> {
    if !canonical_record_tail(tail) {
        return Err(format!("noncanonical autonomous-System key '{tail}'"));
    }
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECORD_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("record family cannot be pinned ({error})")),
    };
    let name = format!("{tail}.json");
    let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
        Ok(None) => return Ok(None),
        Ok(Some((_file, bytes))) => bytes,
        Err(error) => return Err(format!("record slot '{name}' is unreadable ({error})")),
    };
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("record slot '{name}' is malformed ({error})"))?;
    validate_record_identity(tail, &record)?;
    Ok(Some(record))
}

fn scan_records(data_dir: &str) -> Result<Vec<Value>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, RECORD_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("record family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("record family cannot be enumerated ({error})"))?;
    let mut records = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_record_tail(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => return Err(format!("canonical record '{name}' vanished")),
            Err(error) => return Err(format!("canonical record '{name}' is unreadable ({error})")),
        };
        let record: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("canonical record '{name}' is malformed ({error})"))?;
        validate_record_identity(tail, &record)?;
        records.push(record);
    }
    Ok(records)
}

fn map_commit_failure(failure: super::durable_fs::CommitFailure) -> VErr {
    use super::durable_fs::CommitFailure;
    match failure {
        CommitFailure::KeyInvalid(message) => verr("system_genesis_evidence_key_invalid", message),
        CommitFailure::NotCommitted(message) => verr("system_genesis_persist_failed", message),
        CommitFailure::SlotUnreadable(message) => {
            verr("system_genesis_registry_unreadable", message)
        }
        CommitFailure::Conflict(message) => verr("system_genesis_conflict", message),
        CommitFailure::DurabilityUnconfirmed(message) => {
            verr("system_genesis_pending_convergence", message)
        }
        CommitFailure::Swapped(message) => verr("system_genesis_evidence_swapped", message),
    }
}

fn persist_immutable(data_dir: &str, family: &str, tail: &str, value: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_receipt_no_clobber(data_dir, family, tail, value)
        .map_err(map_commit_failure)?;
    super::substrate_store::admit_required(data_dir, family, tail, value).map_err(|error| {
        verr(
            "system_genesis_agentgres_admission_failed",
            format!(
                "Agentgres refused required admission for '{family}/{tail}' ({error}); the durable intent remains for replay"
            ),
        )
    })
}

fn persist_intent(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    super::durable_fs::persist_record_durable(data_dir, INTENT_DIR, tail, intent).map_err(
        |failure| {
            if failure.visible() {
                verr("system_genesis_pending_convergence", failure.detail())
            } else {
                verr("system_genesis_persist_failed", failure.detail())
            }
        },
    )
}

fn consume_intent(data_dir: &str, tail: &str) -> Result<(), VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(verr("system_genesis_intent_unreadable", error.to_string())),
    };
    match super::durable_fs::unlink_at(&directory, &format!("{tail}.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(verr(
                "system_genesis_pending_convergence",
                format!("intent unlink failed ({error})"),
            ))
        }
    }
    directory.sync_all().map_err(|error| {
        verr(
            "system_genesis_pending_convergence",
            format!("intent directory sync failed ({error})"),
        )
    })
}

fn touched_refs(system_id: &str, genesis_ref: &str, proposal_root: &str) -> Vec<String> {
    BTreeSet::from([
        system_id.to_string(),
        genesis_ref.to_string(),
        proposal_root.to_string(),
    ])
    .into_iter()
    .collect()
}

fn seal_intent(mut intent: Value, tail: &str) -> Value {
    let system_id = s(&intent, "system_id");
    let genesis_ref = s(&intent, "genesis_ref");
    let proposal_root = s(&intent, "proposal_root");
    let object = intent.as_object_mut().expect("intent object");
    object.insert("schema_version".into(), json!(INTENT_SCHEMA));
    object.insert(
        "intent_id".into(),
        json!(format!("system-genesis-intent://{tail}")),
    );
    object.insert(
        "touched_refs".into(),
        json!(touched_refs(&system_id, &genesis_ref, &proposal_root)),
    );
    let hash = super::outcome_room_routes::record_output_hash(&intent, &[]);
    intent
        .as_object_mut()
        .unwrap()
        .insert("intent_hash".into(), json!(hash));
    intent
}

fn validate_intent_seal(intent: &Value, tail: &str) -> Result<(), String> {
    if !canonical_intent_tail(tail)
        || intent.get("schema_version").and_then(Value::as_str) != Some(INTENT_SCHEMA)
        || intent.get("intent_id").and_then(Value::as_str)
            != Some(format!("system-genesis-intent://{tail}").as_str())
        || intent.get("intent_hash").and_then(Value::as_str)
            != Some(
                super::outcome_room_routes::record_output_hash(
                    &without(intent, "intent_hash"),
                    &[],
                )
                .as_str(),
            )
    {
        return Err("intent storage-key/hash binding failed".to_string());
    }
    let expected = touched_refs(
        &s(intent, "system_id"),
        &s(intent, "genesis_ref"),
        &s(intent, "proposal_root"),
    );
    if intent.get("touched_refs") != Some(&json!(expected)) {
        return Err("intent touched_refs differs from the exact admission coordinates".to_string());
    }
    Ok(())
}

fn scan_intents(data_dir: &str) -> Result<Vec<(String, Value)>, String> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, INTENT_DIR) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("intent family cannot be pinned ({error})")),
    };
    let names = super::durable_fs::enumerate_pinned(&directory)
        .map_err(|error| format!("intent family cannot be enumerated ({error})"))?;
    let mut intents = Vec::new();
    for name in names {
        let Some(tail) = name.strip_suffix(".json") else {
            continue;
        };
        if !canonical_intent_tail(tail) {
            continue;
        }
        let bytes = match super::durable_fs::read_slot_strict(&directory, &name) {
            Ok(Some((_file, bytes))) => bytes,
            Ok(None) => return Err(format!("canonical intent '{name}' vanished")),
            Err(error) => return Err(format!("canonical intent '{name}' is unreadable ({error})")),
        };
        let intent: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("canonical intent '{name}' is malformed ({error})"))?;
        validate_intent_seal(&intent, tail)?;
        intents.push((tail.to_string(), intent));
    }
    Ok(intents)
}

fn refuse_pending_overlap(
    data_dir: &str,
    refs: &[String],
    ignored: Option<&str>,
) -> Result<(), VErr> {
    let wanted: BTreeSet<&str> = refs.iter().map(String::as_str).collect();
    for (tail, intent) in
        scan_intents(data_dir).map_err(|error| verr("system_genesis_intent_unreadable", error))?
    {
        if ignored == Some(tail.as_str()) {
            continue;
        }
        if intent
            .get("touched_refs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|reference| wanted.contains(reference))
        {
            return Err(verr(
                "system_genesis_mutation_in_flight",
                format!("a durable genesis intent '{tail}' owns these coordinates"),
            ));
        }
    }
    Ok(())
}

fn reconstruct_intent(intent: &Value, tail: &str) -> Result<ReconstructedIntent, String> {
    validate_intent_seal(intent, tail)?;
    let release = intent
        .get("release")
        .filter(|value| value.is_object())
        .ok_or_else(|| "intent lacks immutable release input".to_string())?;
    let proposed = intent
        .get("proposed_instantiation")
        .filter(|value| value.is_object())
        .ok_or_else(|| "intent lacks proposed instantiation input".to_string())?;
    let compiled = compile_or_error(release, proposed).map_err(|(_, message)| message)?;
    let system_id = s(&compiled.proposed_genesis, "system_id");
    let genesis_ref = s(&compiled.proposed_genesis, "genesis_id");
    let required_authority_ref =
        governing_authority_ref(&compiled).map_err(|(_, message)| message)?;
    if intent.get("system_id").and_then(Value::as_str) != Some(system_id.as_str())
        || intent.get("genesis_ref").and_then(Value::as_str) != Some(genesis_ref.as_str())
        || intent.get("proposal_root").and_then(Value::as_str)
            != Some(compiled.proposal_root.as_str())
        || intent.get("required_authority_ref").and_then(Value::as_str)
            != Some(required_authority_ref.as_str())
    {
        return Err("intent coordinates differ from the recompiled proposal".to_string());
    }
    let receipt_tail = intent
        .get("receipt_tail")
        .and_then(Value::as_str)
        .filter(|value| canonical_receipt_tail(value))
        .ok_or_else(|| "intent receipt tail is invalid".to_string())?
        .to_string();
    let receipt = intent
        .get("receipt")
        .filter(|value| value.is_object())
        .ok_or_else(|| "intent lacks receipt".to_string())?
        .clone();
    if receipt.get("receipt_ref").and_then(Value::as_str)
        != Some(format!("receipt://{receipt_tail}").as_str())
        || receipt.get("subject_ref").and_then(Value::as_str) != Some(genesis_ref.as_str())
    {
        return Err("intent receipt identity differs from the compiled genesis".to_string());
    }
    let resolved_at_ms = receipt
        .get("authority_resolved_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| "intent receipt lacks wallet authority time".to_string())?;
    let admitted_at = ms_to_rfc3339(resolved_at_ms).map_err(|(_, message)| message)?;
    let authorized = AuthorizedDecision {
        evidence: governed::sealed_evidence(&receipt),
        resolved_at_ms,
    };
    let expected_record = build_record(
        &compiled,
        &format!("receipt://{receipt_tail}"),
        &authorized,
        &admitted_at,
    )
    .map_err(|(_, message)| message)?;
    let expected_receipt =
        build_receipt(&receipt_tail, &expected_record, &authorized, &admitted_at);
    if intent.get("final_record") != Some(&expected_record) || receipt != expected_receipt {
        return Err(
            "intent successor or receipt does not reconstruct byte-exactly from canonical inputs"
                .to_string(),
        );
    }
    let expected_record_tail = record_tail(&system_id);
    if intent.get("record_tail").and_then(Value::as_str) != Some(expected_record_tail.as_str()) {
        return Err("intent record key differs from the exact system identity".to_string());
    }
    Ok(ReconstructedIntent {
        system_id,
        genesis_ref: genesis_ref.clone(),
        required_authority_ref,
        subject_ref: genesis_ref,
        effect: admission_effect(&compiled),
        receipt,
        receipt_tail,
        final_record: expected_record,
        record_tail: expected_record_tail,
    })
}

fn complete_intent_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    let reconstructed = reconstruct_intent(intent, tail)
        .map_err(|error| verr("system_genesis_intent_unreadable", error))?;
    persist_immutable(
        data_dir,
        RECEIPT_DIR,
        &reconstructed.receipt_tail,
        &reconstructed.receipt,
    )?;
    persist_immutable(
        data_dir,
        RECORD_DIR,
        &reconstructed.record_tail,
        &reconstructed.final_record,
    )?;
    // Live verifier fault point: both immutable artifacts are durable locally and admitted by
    // Agentgres, while the replay anchor still exists. Restart must replay both exact payloads
    // without advancing either Agentgres domain before it consumes the intent.
    if std::env::var("IOI_TEST_FORCE_SYSTEM_GENESIS_AFTER_AGENTGRES")
        .ok()
        .as_deref()
        == Some("1")
    {
        return Err(verr(
            "system_genesis_pending_convergence",
            "test-forced interruption after required Agentgres admission",
        ));
    }
    consume_intent(data_dir, tail)
}

fn persist_and_complete_locked(data_dir: &str, tail: &str, intent: &Value) -> Result<(), VErr> {
    persist_intent(data_dir, tail, intent)?;
    complete_intent_locked(data_dir, tail, intent)
}

pub(crate) async fn handle_admit(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if let Err(error) = reject_sensitive_body(&body) {
        return classify(error);
    }
    let (release, proposed) = match validate_top_level(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let compiled = match compile_inputs(release, proposed) {
        Ok(value) => value,
        Err(blocker_report) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": {
                        "code": "system_genesis_proposal_invalid",
                        "message": "the pure proposal compiler refused admission input",
                        "blocker_report": blocker_report,
                        "runtimeTruthSource": "daemon-runtime"
                    }
                })),
            )
        }
    };
    let system_id = s(&compiled.proposed_genesis, "system_id");
    let genesis_ref = s(&compiled.proposed_genesis, "genesis_id");
    let required_authority_ref = match governing_authority_ref(&compiled) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if !canonical_ref(&system_id, "system://") || !canonical_ref(&genesis_ref, "genesis://") {
        return classify(verr(
            "system_genesis_authority_coordinate_invalid",
            "compiled genesis lacks canonical System or genesis coordinates",
        ));
    }
    let effect = admission_effect(&compiled);
    let authority_body = match canonical_authority_body(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &authority_body,
        Governance::Host,
        AuthorityPolicyContext::SystemGenesis {
            system_id: &system_id,
            genesis_id: &genesis_ref,
        },
        &required_authority_ref,
        &genesis_ref,
        "admit",
        0,
        &effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let admitted_at = match ms_to_rfc3339(authorized.resolved_at_ms) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let record_tail = record_tail(&system_id);
    let receipt_tail = fresh_tail("asgr_", &genesis_ref, authorized.resolved_at_ms);
    let receipt_ref = format!("receipt://{receipt_tail}");
    let final_record = match build_record(&compiled, &receipt_ref, &authorized, &admitted_at) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let receipt = build_receipt(&receipt_tail, &final_record, &authorized, &admitted_at);
    let intent_tail = fresh_tail("asgi_", &genesis_ref, authorized.resolved_at_ms);
    let intent = seal_intent(
        json!({
            "kind": "admit_genesis",
            "op": "admit",
            "system_id": system_id,
            "genesis_ref": genesis_ref,
            "proposal_root": compiled.proposal_root,
            "required_authority_ref": required_authority_ref,
            "record_tail": record_tail,
            "receipt_tail": receipt_tail,
            "release": compiled.release,
            "proposed_instantiation": compiled.proposed_instantiation,
            "receipt": receipt,
            "final_record": final_record
        }),
        &intent_tail,
    );

    let _plane = SYSTEM_GENESIS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let refs = touched_refs(&system_id, &genesis_ref, &compiled.proposal_root);
    if let Err(error) = refuse_pending_overlap(&state.data_dir, &refs, None) {
        return classify(error);
    }
    match load_record(&state.data_dir, &record_tail) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return classify(verr(
                "system_genesis_already_admitted",
                format!("System '{system_id}' already has an admitted genesis"),
            ))
        }
        Err(message) => return classify(verr("system_genesis_registry_unreadable", message)),
    }
    let existing = match scan_records(&state.data_dir) {
        Ok(value) => value,
        Err(message) => return classify(verr("system_genesis_registry_unreadable", message)),
    };
    if existing.iter().any(|record| {
        record.get("genesis_ref").and_then(Value::as_str) == Some(genesis_ref.as_str())
            || record.get("proposal_root").and_then(Value::as_str)
                == Some(compiled.proposal_root.as_str())
    }) {
        return classify(verr(
            "system_genesis_coordinate_conflict",
            "genesis identity or proposal root is already admitted",
        ));
    }
    match persist_and_complete_locked(&state.data_dir, &intent_tail, &intent) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "autonomous_system_genesis_admission": final_record,
                "autonomous_system_genesis_receipt": receipt,
                "nonclaims": {
                    "active_profile_materialization": false,
                    "activation": false,
                    "node_membership": false,
                    "network_enrollment_effect": false,
                    "runtime_effect": false,
                    "systems_product_surface": false
                }
            })),
        ),
        Err(error) => classify(error),
    }
}

pub(crate) async fn handle_get(
    State(state): State<Arc<DaemonState>>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let Some(system_id) = query.get("system_id") else {
        return classify(verr(
            "system_genesis_system_id_required",
            "GET requires the exact canonical 'system_id' query parameter",
        ));
    };
    if !canonical_ref(system_id, "system://") {
        return classify(verr(
            "system_genesis_system_id_invalid",
            "system_id must be a canonical system:// ref",
        ));
    }
    let tail = record_tail(system_id);
    handle_get_tail(&state.data_dir, &tail)
}

pub(crate) async fn handle_get_by_key(
    State(state): State<Arc<DaemonState>>,
    AxumPath(tail): AxumPath<String>,
) -> (StatusCode, Json<Value>) {
    if !canonical_record_tail(&tail) {
        return classify(verr(
            "system_genesis_key_invalid",
            "record key must be the exact canonical asg_<64 lowercase hex> storage identity",
        ));
    }
    handle_get_tail(&state.data_dir, &tail)
}

fn handle_get_tail(data_dir: &str, tail: &str) -> (StatusCode, Json<Value>) {
    let _plane = SYSTEM_GENESIS_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let pending = match scan_intents(data_dir) {
        Ok(intents) => intents
            .iter()
            .any(|(_, intent)| intent.get("record_tail").and_then(Value::as_str) == Some(tail)),
        Err(message) => {
            return classify(verr(
                "system_genesis_intent_unreadable",
                format!("cannot establish admission convergence state ({message})"),
            ))
        }
    };
    if pending {
        return classify(verr(
            "system_genesis_pending_convergence",
            format!("genesis admission at key '{tail}' has not crossed every durable boundary"),
        ));
    }
    match load_record(data_dir, tail) {
        Ok(Some(record)) => (
            StatusCode::OK,
            Json(json!({
                "autonomous_system_genesis_admission": record,
                "authority": governed::decision_authority_posture(AUTHORITY),
                "nonclaims": {
                    "active_profile_materialization": false,
                    "activation": false,
                    "node_membership": false,
                    "network_enrollment_effect": false,
                    "runtime_effect": false,
                    "systems_product_surface": false
                }
            })),
        ),
        Ok(None) => classify(verr(
            "system_genesis_not_found",
            format!("no admitted genesis exists at key '{tail}'"),
        )),
        Err(message) => classify(verr("system_genesis_registry_unreadable", message)),
    }
}

pub(crate) async fn complete_governed_system_genesis_intents(data_dir: &str, max_intents: usize) {
    let intents = match scan_intents(data_dir) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("SystemGenesis completer: scan failed ({message})");
            return;
        }
    };
    for (tail, intent) in intents.into_iter().take(max_intents) {
        let reconstructed = match reconstruct_intent(&intent, &tail) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("SystemGenesis completer: '{tail}' invalid ({message}); retained");
                continue;
            }
        };
        if let Err(message) = governed::reauthorize_sealed_receipt_with_context(
            AUTHORITY,
            &reconstructed.receipt,
            Governance::Host,
            AuthorityPolicyContext::SystemGenesis {
                system_id: &reconstructed.system_id,
                genesis_id: &reconstructed.genesis_ref,
            },
            &reconstructed.required_authority_ref,
            &reconstructed.subject_ref,
            "admit",
            0,
            &reconstructed.effect,
        )
        .await
        {
            eprintln!("SystemGenesis completer: '{tail}' authority refused ({message}); retained");
            continue;
        }
        let _plane = SYSTEM_GENESIS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err((_, message)) = complete_intent_locked(data_dir, &tail, &intent) {
            eprintln!("SystemGenesis completer: '{tail}' convergence failed ({message}); retained");
        }
    }
}

#[cfg(test)]
mod system_genesis_tests {
    use super::*;

    fn fixture(relative: &str) -> Value {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        serde_json::from_slice(
            &std::fs::read(
                root.join("docs/architecture/_meta/schemas/fixtures")
                    .join(relative),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn valid_inputs() -> (Value, Value) {
        let mut release = fixture("autonomous-system-manifest-v1/positive-reusable-release.json");
        release["typed_components"]["component_set_hash"] =
            json!(ioi_types::app::compute_system_component_set_hash(&release).unwrap());
        release["release_root"] =
            json!(ioi_types::app::compute_system_release_root(&release).unwrap());
        let mut candidate = fixture("autonomous-system-genesis-v1/positive-proposed.json");
        candidate
            .as_object_mut()
            .unwrap()
            .remove("admitted_manifest_root");
        candidate
            .as_object_mut()
            .unwrap()
            .remove("initial_profile_bundle_root");
        candidate["cryptographic_origin"]
            .as_object_mut()
            .unwrap()
            .remove("genesis_operation_commitment");
        candidate["cryptographic_origin"]
            .as_object_mut()
            .unwrap()
            .remove("genesis_transition_commitment_ref");
        candidate["initial_component_bindings"]["admitted_component_set_hash"] =
            release["typed_components"]["component_set_hash"].clone();
        let proposed = json!({
            "schema_version": "ioi.autonomous-system-genesis-proposal-input.v1",
            "candidate": candidate,
            "template_bindings": {
                "constitution_template_ref": release["constitution_template_ref"],
                "deployment_template_ref": release["required_profile_templates"]["deployment_template_ref"],
                "ordering_admission_finality_template_ref": release["required_profile_templates"]["ordering_admission_finality_template_ref"],
                "oracle_evidence_template_refs": release["required_profile_templates"]["oracle_evidence_template_refs"],
                "lifecycle_continuity_template_ref": release["required_profile_templates"]["lifecycle_continuity_template_ref"],
                "network_enrollment_constraint_ref": release["required_profile_templates"]["network_enrollment_constraint_ref"]
            },
            "constitution": fixture("autonomous-system-constitution-v1/positive-draft.json"),
            "ordering_profile": fixture("ordering-admission-finality-profile-v1/positive-single-authority.json"),
            "oracle_profiles": [fixture("oracle-evidence-profile-v1/positive-fail-closed.json")],
            "lifecycle_profile": fixture("lifecycle-continuity-profile-v1/positive-successor-governed.json"),
            "network_enrollment": Value::Null
        });
        (release, proposed)
    }

    fn fake_authorized() -> AuthorizedDecision {
        AuthorizedDecision {
            evidence: governed::DecisionEvidence {
                acting_authority_id: json!([1, 2, 3]),
                grant_ref: "wallet.network://grant/approval/test".to_string(),
                policy_hash: "sha256:policy".to_string(),
                request_hash: "sha256:request".to_string(),
                effect_hash: "sha256:effect".to_string(),
                authorized_effect: Value::Null,
                wallet_approval_grant: Value::Null,
                authority_binding: Value::Null,
            },
            resolved_at_ms: 1_784_395_200_000,
        }
    }

    #[test]
    fn room_policy_hash_is_byte_stable_and_system_context_is_explicit() {
        let contract = AuthorityContract {
            scope_prefix: "verifier_challenge",
            policy_domain: "hypervisor.verifier-challenge.decision.policy.v1",
            request_domain: "hypervisor.verifier-challenge.decision.request.v1",
            resolution_domain: "hypervisor.verifier-challenge.authority-resolution.v1",
            code_prefix: "verifier_challenge",
            host_label: "room_host",
            participant_label: "participant_challenger",
        };
        assert_eq!(
            governed::decision_policy_hash(
                contract,
                Governance::Host,
                "outcome-room://or_test",
                "domain://host",
                "create",
            ),
            "sha256:19277f17f3285d360be9cdb0a25f754b8bfd7099d7ddbfe6fc892841a9e6f095"
        );
        assert_eq!(
            governed::decision_policy_hash_for_context(
                contract,
                Governance::Host,
                AuthorityPolicyContext::OutcomeRoom {
                    outcome_room_ref: "outcome-room://or_test",
                },
                "domain://host",
                "create",
            ),
            governed::decision_policy_hash(
                contract,
                Governance::Host,
                "outcome-room://or_test",
                "domain://host",
                "create",
            ),
        );
        let genesis_policy = |system_id, genesis_id| {
            governed::decision_policy_hash_for_context(
                contract,
                Governance::Host,
                AuthorityPolicyContext::SystemGenesis {
                    system_id,
                    genesis_id,
                },
                "domain://host",
                "create",
            )
        };
        let baseline = genesis_policy("system://acme/test", "genesis://acme/test/zero");
        assert_ne!(
            baseline,
            genesis_policy("system://acme/other", "genesis://acme/test/zero")
        );
        assert_ne!(
            baseline,
            genesis_policy("system://acme/test", "genesis://acme/test/other")
        );
    }

    #[test]
    fn authority_effect_binds_release_projection_fields_excluded_from_release_root() {
        let (release, proposed) = valid_inputs();
        let compiled = compile_or_error(&release, &proposed).unwrap();
        let original_effect = admission_effect(&compiled);

        let mut changed_release = release.clone();
        changed_release["registry_status"] = json!("deprecated");
        assert_eq!(
            ioi_types::app::compute_system_release_root(&changed_release).unwrap(),
            release["release_root"]
        );
        let changed = compile_or_error(&changed_release, &proposed).unwrap();
        let changed_effect = admission_effect(&changed);

        assert_eq!(
            original_effect["proposal_root"],
            changed_effect["proposal_root"]
        );
        assert_ne!(
            original_effect["manifest_release_payload_hash"],
            changed_effect["manifest_release_payload_hash"]
        );
        assert_ne!(
            governed::decision_effect_hash(AUTHORITY, &original_effect),
            governed::decision_effect_hash(AUTHORITY, &changed_effect)
        );
    }

    #[test]
    fn authorized_projection_is_valid_but_activation_remains_absent() {
        let (release, proposed) = valid_inputs();
        let compiled = compile_or_error(&release, &proposed).unwrap();
        let receipt_ref = format!("receipt://asgr_{}", "a".repeat(64));
        let record = build_record(
            &compiled,
            &receipt_ref,
            &fake_authorized(),
            "2026-07-18T12:00:00Z",
        )
        .unwrap();
        let genesis = &record["authorized_genesis"];
        assert_eq!(genesis["status"], "authorized");
        assert_eq!(genesis["activation_receipt_ref"], Value::Null);
        assert_eq!(genesis["lifecycle_transition_refs"], json!([]));
        assert_eq!(record["proposed_by_ref"], "project://acme/outcome-operator");
        assert_eq!(record["governing_authority_ref"], "org://acme/research");
        assert_eq!(
            record["active_profile_materialization_state"],
            "pending_m1_4"
        );
        assert_eq!(record["live_runtime_state_created"], false);
        validate_architecture_contract(GENESIS_CONTRACT, genesis).unwrap();
    }

    #[test]
    fn admission_authority_is_constitution_owned_and_multi_owner_is_unavailable() {
        let (release, proposed) = valid_inputs();
        let mut compiled = compile_or_error(&release, &proposed).unwrap();
        compiled.initial_profile_bundle["constitution"]["governance"]["governance_owner_refs"] =
            json!(["org://acme/research", "domain://acme-host"]);
        let error = governing_authority_ref(&compiled).unwrap_err();
        assert_eq!(error.0, "system_genesis_authority_aggregation_unavailable");
        assert_eq!(
            compiled.proposed_genesis["instantiation"]["proposed_by"],
            "project://acme/outcome-operator"
        );
    }

    #[test]
    fn admission_intake_rejects_recursive_secrets_and_noncanonical_keys() {
        let error = reject_sensitive_body(&json!({
            "release": {},
            "proposed_instantiation": {
                "uncertainty": {
                    "Client-Secret": "never-persist-this"
                }
            }
        }))
        .unwrap_err();
        assert_eq!(error.0, "system_genesis_plaintext_secret_rejected");
        assert!(canonical_record_tail(&format!("asg_{}", "a".repeat(64))));
        assert!(!canonical_record_tail("../goal-runs/gr_path"));
        assert!(!canonical_record_tail(&format!("asg_{}", "A".repeat(64))));
    }

    #[test]
    fn genesis_receipt_pins_the_portable_base_and_governed_evidence_fields() {
        let (release, proposed) = valid_inputs();
        let compiled = compile_or_error(&release, &proposed).unwrap();
        let authorized = fake_authorized();
        let receipt_tail = format!("asgr_{}", "d".repeat(64));
        let receipt_ref = format!("receipt://{receipt_tail}");
        let record =
            build_record(&compiled, &receipt_ref, &authorized, "2026-07-18T12:00:00Z").unwrap();
        let receipt = build_receipt(&receipt_tail, &record, &authorized, "2026-07-18T12:00:00Z");
        let expected: BTreeSet<&str> = [
            "schema_version",
            "receipt_id",
            "receipt_ref",
            "receipt_type",
            "receipt_profile_ref",
            "actor_id",
            "subject_ref",
            "op",
            "attested_boundary_fact_refs",
            "bound_facts",
            "output_hash",
            "hash_scope_excludes",
            "assurance_posture",
            "assurance_note",
            "verification_ref",
            "acceptance_ref",
            "claim_scope_ref",
            "run_id",
            "task_id",
            "input_hash",
            "policy_hash",
            "authority_grant_id",
            "primitive_capabilities",
            "authority_scopes",
            "artifact_refs",
            "evidence_bundle_refs",
            "adjudication_ref",
            "settlement_ref",
            "signature",
            "l1_commitment",
            "timestamp",
            "outcome",
            "at",
            "effect_hash",
            "authorized_effect",
            "wallet_approval_grant",
            "principal_authority_binding",
            "authority_resolved_at_ms",
        ]
        .into_iter()
        .collect();
        let actual: BTreeSet<&str> = receipt
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn intent_reconstruction_rejects_a_forged_successor() {
        let (release, proposed) = valid_inputs();
        let compiled = compile_or_error(&release, &proposed).unwrap();
        let authorized = fake_authorized();
        let admitted_at = "2026-07-18T12:00:00Z";
        let receipt_tail = format!("asgr_{}", "b".repeat(64));
        let receipt_ref = format!("receipt://{receipt_tail}");
        let final_record = build_record(&compiled, &receipt_ref, &authorized, admitted_at).unwrap();
        let receipt = build_receipt(&receipt_tail, &final_record, &authorized, admitted_at);
        let intent_tail = format!("asgi_{}", "c".repeat(64));
        let mut intent = seal_intent(
            json!({
                "kind": "admit_genesis",
                "op": "admit",
                "system_id": compiled.proposed_genesis["system_id"],
                "genesis_ref": compiled.proposed_genesis["genesis_id"],
                "proposal_root": compiled.proposal_root,
                "required_authority_ref": governing_authority_ref(&compiled).unwrap(),
                "record_tail": record_tail(compiled.proposed_genesis["system_id"].as_str().unwrap()),
                "receipt_tail": receipt_tail,
                "release": release,
                "proposed_instantiation": proposed,
                "receipt": receipt,
                "final_record": final_record
            }),
            &intent_tail,
        );
        intent["final_record"]["activation_state"] = json!("activated");
        let hash = super::super::outcome_room_routes::record_output_hash(
            &without(&intent, "intent_hash"),
            &[],
        );
        intent["intent_hash"] = json!(hash);
        assert!(reconstruct_intent(&intent, &intent_tail)
            .unwrap_err()
            .contains("reconstruct byte-exactly"));
    }
}
