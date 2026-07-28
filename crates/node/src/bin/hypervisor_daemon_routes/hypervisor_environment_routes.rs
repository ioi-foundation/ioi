//! M2 environment lifecycle plane: governed routes over owner-bound route
//! bindings, manifest-complete backups, staged restore/activation plans, and
//! durable cleanup obligations.
//!
//! The plane is estate-scoped. Declared records (bindings, plans, opened
//! obligations) are owner-authored declared truth whose commitments recompute
//! under registered invariants; observed truth (artifact digest censuses,
//! source state roots, route observations, stage evidence) is resolved from
//! durable daemon records, never asserted by the caller (`INV-37`). The whole
//! plane is rebuilt from committed transitions and record revisions only, so
//! a restart loses no projection it cannot reconstruct byte-exactly.

use ioi_types::app::hypervisor_environment_lifecycle::{
    compile_backup_record, compile_change_plan_declaration, compile_cleanup_escalate,
    compile_cleanup_open, compile_cleanup_satisfy, compile_route_binding_declaration,
    compile_stage_advance, environment_artifact_root, environment_plane_root,
    evaluate_route_binding_observation, obligation_revision_root, replay_environment_lifecycle,
    route_binding_head, route_identity, BackupDeclaration, EnvironmentEstateBinding,
    EnvironmentLifecycleLogHead, EnvironmentLifecycleOp, EnvironmentPlaneState, StageEvidence,
    CHANGE_PLAN_CONTRACT, CLEANUP_OBLIGATION_CONTRACT, ENVIRONMENT_BACKUP_CONTRACT,
    ENVIRONMENT_OPERATION_PROFILE, ROUTE_BINDING_CONTRACT,
};
use serde_json::{json, Value};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::Json;

use super::governed_authority::{self as governed, AuthorityPolicyContext, Governance};
use super::system_activation_routes::{
    classify, contains_sensitive_key, evidence_intent_value, forced_fault, intent_seal, jcs_hash,
    load_local, load_required_exact, ms_to_timestamp, persist_local, prepare_node_evidence_for,
    remove_intent, required_string, tail, validate_contract, validate_wallet_receipt,
    verify_intent_seal, verr, with_source_locks, AUTHORITY, AUTHORITY_CONSUMPTION_DIR,
    AUTHORITY_EVIDENCE_DIR, MAX_REQUEST_BYTES, SYSTEM_ACTIVATION_GATE,
};
use super::system_protected_transition_routes::{
    decision_tuple, preflight_chain_writer_grant, DecisionAuthorityTuple,
};
use super::DaemonState;

type VErr = (String, String);

/// Immutable owner-bound route-binding revisions.
pub(crate) const ROUTE_BINDING_DIR: &str = "hypervisor-environment-route-bindings";
/// Manifest-complete backup records.
pub(crate) const BACKUP_DIR: &str = "hypervisor-environment-backups";
/// Immutable staged restore/activation plans.
pub(crate) const CHANGE_PLAN_DIR: &str = "hypervisor-change-plans";
/// Committed forward-only stage advancement records.
pub(crate) const STAGE_ADVANCE_DIR: &str = "hypervisor-change-plan-stage-advances";
/// Durable cleanup obligation revisions.
pub(crate) const CLEANUP_DIR: &str = "hypervisor-resource-cleanup-obligations";
/// Committed environment-lifecycle compare-and-swap transitions.
pub(crate) const ENVIRONMENT_TRANSITION_DIR: &str = "hypervisor-environment-lifecycle-transitions";
/// Environment-lifecycle plane receipts.
pub(crate) const ENVIRONMENT_RECEIPT_DIR: &str = "hypervisor-environment-lifecycle-receipts";
/// One-successor-per-predecessor plane CAS claims.
pub(crate) const ENVIRONMENT_CLAIM_DIR: &str = "hypervisor-environment-lifecycle-successor-claims";
/// Sealed environment-lifecycle transition intents (local replay registry).
pub(crate) const ENVIRONMENT_INTENT_DIR: &str = "hypervisor-environment-lifecycle-intents";
/// Daemon-resolved environment evidence (artifact digest census, source state
/// roots, stage evidence, route observations). The loader is live; the
/// capture/observation runtime producer is a later M2 leg.
pub(crate) const ENVIRONMENT_EVIDENCE_DIR: &str = "hypervisor-environment-evidence";

const RECEIPT_CONTRACT: &str = "schema://ioi/foundations/receipt-envelope/v1";
const TRANSITION_ARTIFACT_DOMAIN: &str =
    "ioi.hypervisor-environment-lifecycle-transition-jcs-sha256.v1";
const RECEIPT_ARTIFACT_DOMAIN: &str = "ioi.hypervisor-environment-lifecycle-receipt-jcs-sha256.v1";

/// The estate's governing principal for records that carry no per-record
/// owner (the same local-estate posture as the HypervisorOS profile plane).
const ESTATE_OWNER_REF: &str = "wallet://hypervisor/local-estate-owner";

fn required(value: &Value, pointer: &str) -> Result<String, VErr> {
    required_string(value, pointer).map(str::to_owned)
}

fn artifact_root(domain: &str, artifact: &Value) -> Result<String, VErr> {
    jcs_hash(&json!({"domain":domain,"artifact":artifact}))
}

fn plan_err(error: String) -> VErr {
    verr("hypervisor_environment_plan_invalid", error)
}

/// The one local estate this daemon governs environments for.
pub(crate) fn local_environment_estate_binding() -> EnvironmentEstateBinding {
    EnvironmentEstateBinding {
        estate_namespace: "local".into(),
        daemon_ref: "runtime://local/daemon".into(),
    }
}

/// Enumerate one local-only family without requiring Agentgres admission.
fn scan_local_family(data_dir: &str, family: &str) -> Result<Vec<(String, Value)>, VErr> {
    let directory = match super::durable_fs::open_family_dir_pinned(data_dir, family) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(verr(
                "hypervisor_environment_artifact_unreadable",
                format!("family '{family}' cannot be pinned ({error})"),
            ))
        }
    };
    let mut names = super::durable_fs::enumerate_pinned(&directory).map_err(|error| {
        verr(
            "hypervisor_environment_artifact_unreadable",
            format!("family '{family}' cannot be enumerated ({error})"),
        )
    })?;
    names.sort();
    let mut values = Vec::new();
    for name in names {
        let record_tail = name
            .strip_suffix(".json")
            .ok_or_else(|| {
                verr(
                    "hypervisor_environment_artifact_unreadable",
                    format!("unexpected entry '{family}/{name}'"),
                )
            })?
            .to_owned();
        let value = load_local(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "hypervisor_environment_artifact_unreadable",
                format!("'{family}/{name}' vanished"),
            )
        })?;
        values.push((record_tail, value));
    }
    Ok(values)
}

/// Enumerate one required-admission family with the local-versus-Agentgres
/// census equality proof; a mismatch is source incompleteness and the read
/// fails closed instead of projecting partial truth.
fn enumerate_required_censused(data_dir: &str, family: &str) -> Result<Vec<Value>, VErr> {
    let local = super::system_activation_routes::enumerate_family(data_dir, family)?;
    let mut local_values: Vec<Value> = local.into_iter().map(|(_, value)| value).collect();
    let mut substrate =
        super::substrate_store::read_required_all(data_dir, family).map_err(|error| {
            verr(
                "hypervisor_environment_source_incomplete",
                format!("Agentgres census for '{family}' failed ({error})"),
            )
        })?;
    let sort_key = |value: &Value| serde_json::to_string(value).unwrap_or_default();
    local_values.sort_by_key(sort_key);
    substrate.sort_by_key(sort_key);
    if local_values != substrate {
        return Err(verr(
            "hypervisor_environment_source_incomplete",
            format!("local and Agentgres censuses for '{family}' differ"),
        ));
    }
    Ok(local_values)
}

fn family_prefix(family: &str) -> Result<&'static str, VErr> {
    Ok(match family {
        ROUTE_BINDING_DIR => "hverb_",
        BACKUP_DIR => "hveb_",
        CHANGE_PLAN_DIR => "hvcp_",
        STAGE_ADVANCE_DIR => "hvcpsa_",
        CLEANUP_DIR => "hvrco_",
        ENVIRONMENT_TRANSITION_DIR => "hvet_",
        ENVIRONMENT_RECEIPT_DIR => "hvelr_",
        ENVIRONMENT_CLAIM_DIR => "hvelsc_",
        _ => {
            return Err(verr(
                "hypervisor_environment_artifact_invalid",
                format!("'{family}' is not an environment-lifecycle family"),
            ))
        }
    })
}

/// The exact durable truth one environment-lifecycle operation compiles
/// against.
pub(crate) struct EnvironmentLifecycleSource {
    pub binding: EnvironmentEstateBinding,
    pub state: EnvironmentPlaneState,
    pub head: EnvironmentLifecycleLogHead,
    pub transitions: Vec<Value>,
}

pub(crate) fn load_environment_lifecycle_source(
    data_dir: &str,
) -> Result<EnvironmentLifecycleSource, VErr> {
    let binding = local_environment_estate_binding();
    let transitions = enumerate_required_censused(data_dir, ENVIRONMENT_TRANSITION_DIR)?;
    let owned_dir = data_dir.to_owned();
    let loader = move |family: &str, record_root: &str| -> Result<Option<Value>, String> {
        let prefix = family_prefix(family).map_err(|(_, message)| message)?;
        load_required_exact(
            &owned_dir,
            family,
            &tail(prefix, record_root).map_err(|(_, message)| message)?,
        )
        .map_err(|(code, message)| format!("{code}: {message}"))
    };
    let (state, head) =
        replay_environment_lifecycle(&binding.estate_namespace, &transitions, &loader)
            .map_err(plan_err)?;
    Ok(EnvironmentLifecycleSource {
        binding,
        state,
        head,
        transitions,
    })
}

/// Closed caller declaration. Fields irrelevant to the named operation are
/// rejected rather than silently ignored.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnvironmentLifecycleDeclaration {
    /// Caller's compare-and-swap view of the current plane root.
    pub expected_plane_root: String,
    /// Declared immutable route-binding revision (declare only).
    #[serde(default)]
    pub route_binding: Option<Value>,
    /// Owner-allocated backup tail (record_backup only).
    #[serde(default)]
    pub backup_tail: Option<String>,
    /// Declared backup trigger (record_backup only).
    #[serde(default)]
    pub backup_trigger: Option<String>,
    /// Backup target environment (record_backup only).
    #[serde(default)]
    pub environment_ref: Option<String>,
    /// Optional originating schedule/plan ref (record_backup only).
    #[serde(default)]
    pub schedule_or_change_plan_ref: Option<String>,
    /// Declared immutable change plan (declare_change_plan only).
    #[serde(default)]
    pub change_plan: Option<Value>,
    /// Exact plan ref (advance_change_plan_stage only).
    #[serde(default)]
    pub plan_ref: Option<String>,
    /// Requested stage index (advance_change_plan_stage only).
    #[serde(default)]
    pub stage_index: Option<u64>,
    /// Declared opening obligation revision (open_cleanup_obligation only).
    #[serde(default)]
    pub cleanup_obligation: Option<Value>,
    /// Exact obligation ref (satisfy/escalate only).
    #[serde(default)]
    pub cleanup_obligation_ref: Option<String>,
    /// Closing disposition status (satisfy only).
    #[serde(default)]
    pub closing_status: Option<String>,
    /// Receipted disposition (satisfy only).
    #[serde(default)]
    pub disposition_receipt_ref: Option<String>,
    /// Escalation reason (escalate only).
    #[serde(default)]
    pub escalation_reason: Option<String>,
    /// The exact lost parent or provider (escalate only).
    #[serde(default)]
    pub lost_parent_ref: Option<String>,
    /// Loss or disposition evidence refs.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

const DECLARATION_FIELDS: &[&str] = &[
    "expected_plane_root",
    "route_binding",
    "backup_tail",
    "backup_trigger",
    "environment_ref",
    "schedule_or_change_plan_ref",
    "change_plan",
    "plan_ref",
    "stage_index",
    "cleanup_obligation",
    "cleanup_obligation_ref",
    "closing_status",
    "disposition_receipt_ref",
    "escalation_reason",
    "lost_parent_ref",
    "evidence_refs",
];

fn declaration_from_body(body: &Value) -> Result<EnvironmentLifecycleDeclaration, VErr> {
    let mut value = serde_json::Map::new();
    for key in DECLARATION_FIELDS {
        if let Some(field) = body.get(*key) {
            value.insert((*key).to_owned(), field.clone());
        }
    }
    serde_json::from_value(Value::Object(value))
        .map_err(|error| verr("hypervisor_environment_request_invalid", error.to_string()))
}

fn validate_request(body: &Value) -> Result<(), VErr> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| verr("hypervisor_environment_request_invalid", error.to_string()))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(verr(
            "hypervisor_environment_request_oversize",
            "request exceeds 512 KiB",
        ));
    }
    if contains_sensitive_key(body) {
        return Err(verr(
            "hypervisor_environment_sensitive_field_rejected",
            "secret-bearing keys are forbidden recursively",
        ));
    }
    let object = body.as_object().ok_or_else(|| {
        verr(
            "hypervisor_environment_request_invalid",
            "request must be an object",
        )
    })?;
    if let Some(key) = object.keys().find(|key| {
        !DECLARATION_FIELDS.contains(&key.as_str()) && key.as_str() != "wallet_approval_grant"
    }) {
        return Err(verr(
            "hypervisor_environment_request_field_unknown",
            format!("undeclared request field '{key}' is forbidden"),
        ));
    }
    Ok(())
}

fn validate_declaration(
    op: EnvironmentLifecycleOp,
    declaration: &EnvironmentLifecycleDeclaration,
) -> Result<(), VErr> {
    let present = [
        ("route_binding", declaration.route_binding.is_some()),
        ("backup_tail", declaration.backup_tail.is_some()),
        ("backup_trigger", declaration.backup_trigger.is_some()),
        ("environment_ref", declaration.environment_ref.is_some()),
        (
            "schedule_or_change_plan_ref",
            declaration.schedule_or_change_plan_ref.is_some(),
        ),
        ("change_plan", declaration.change_plan.is_some()),
        ("plan_ref", declaration.plan_ref.is_some()),
        ("stage_index", declaration.stage_index.is_some()),
        (
            "cleanup_obligation",
            declaration.cleanup_obligation.is_some(),
        ),
        (
            "cleanup_obligation_ref",
            declaration.cleanup_obligation_ref.is_some(),
        ),
        ("closing_status", declaration.closing_status.is_some()),
        (
            "disposition_receipt_ref",
            declaration.disposition_receipt_ref.is_some(),
        ),
        ("escalation_reason", declaration.escalation_reason.is_some()),
        ("lost_parent_ref", declaration.lost_parent_ref.is_some()),
        ("evidence_refs", !declaration.evidence_refs.is_empty()),
    ];
    let allowed: &[&str] = match op {
        EnvironmentLifecycleOp::DeclareRouteBinding => &["route_binding"],
        EnvironmentLifecycleOp::RecordBackup => &[
            "backup_tail",
            "backup_trigger",
            "environment_ref",
            "schedule_or_change_plan_ref",
        ],
        EnvironmentLifecycleOp::DeclareChangePlan => &["change_plan"],
        EnvironmentLifecycleOp::AdvanceChangePlanStage => &["plan_ref", "stage_index"],
        EnvironmentLifecycleOp::OpenCleanupObligation => &["cleanup_obligation"],
        EnvironmentLifecycleOp::SatisfyCleanupObligation => &[
            "cleanup_obligation_ref",
            "closing_status",
            "disposition_receipt_ref",
            "evidence_refs",
        ],
        EnvironmentLifecycleOp::EscalateCleanupObligation => &[
            "cleanup_obligation_ref",
            "escalation_reason",
            "lost_parent_ref",
            "evidence_refs",
        ],
    };
    if let Some((field, _)) = present
        .into_iter()
        .find(|(name, set)| *set && !allowed.contains(name))
    {
        return Err(verr(
            "hypervisor_environment_request_invalid",
            format!("{field} is not admitted for {}", op.as_str()),
        ));
    }
    Ok(())
}

/// Server-resolved trusted inputs for one operation (INV-37): the artifact
/// digest census, the daemon-admitted source state root, and stage evidence
/// are read from durable evidence records only.
pub(crate) struct ResolvedEnvironmentEvidence {
    pub source_state_root: Option<String>,
    pub artifact_digest_rows: Vec<Value>,
    pub stage_evidence_refs: Vec<String>,
}

fn resolve_trusted_inputs(
    data_dir: &str,
    op: EnvironmentLifecycleOp,
) -> Result<ResolvedEnvironmentEvidence, VErr> {
    let mut source_state_root = None;
    let mut artifact_digest_rows = Vec::new();
    let mut stage_evidence_refs = Vec::new();
    if matches!(
        op,
        EnvironmentLifecycleOp::RecordBackup | EnvironmentLifecycleOp::AdvanceChangePlanStage
    ) {
        for (_tail, record) in scan_local_family(data_dir, ENVIRONMENT_EVIDENCE_DIR)? {
            match record.get("evidence_kind").and_then(Value::as_str) {
                Some("artifact_digest") => artifact_digest_rows.push(record),
                Some("source_state_root") => {
                    if source_state_root.is_some() {
                        return Err(verr(
                            "hypervisor_environment_artifact_mismatch",
                            "two durable source state roots both claim currency",
                        ));
                    }
                    source_state_root = Some(required(&record, "/state_root")?);
                }
                Some("stage_evidence") => {
                    stage_evidence_refs.push(required(&record, "/evidence_ref")?)
                }
                _ => {}
            }
        }
    }
    Ok(ResolvedEnvironmentEvidence {
        source_state_root,
        artifact_digest_rows,
        stage_evidence_refs,
    })
}

/// Resolve the current route observations (drift evidence) for projections.
fn resolve_route_observations(data_dir: &str) -> Result<Vec<Value>, VErr> {
    Ok(scan_local_family(data_dir, ENVIRONMENT_EVIDENCE_DIR)?
        .into_iter()
        .filter_map(|(_tail, record)| {
            (record.get("evidence_kind").and_then(Value::as_str) == Some("route_observation"))
                .then_some(record)
        })
        .collect())
}

/// One compiled environment-lifecycle operation over exact durable truth.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CompiledEnvironmentLifecyclePlan {
    pub op: EnvironmentLifecycleOp,
    pub sequence: u64,
    pub subject_ref: String,
    pub record_family: &'static str,
    pub record: Value,
    pub record_root: String,
    pub predecessor_plane_root: String,
    pub resulting_plane_root: String,
    pub activation_outcome: Option<String>,
    pub governing_owner_ref: String,
    pub authority_effect: Value,
}

pub(crate) fn compile_from_source(
    op: EnvironmentLifecycleOp,
    source: &EnvironmentLifecycleSource,
    declaration: &EnvironmentLifecycleDeclaration,
    evidence: &ResolvedEnvironmentEvidence,
) -> Result<CompiledEnvironmentLifecyclePlan, VErr> {
    validate_declaration(op, declaration)?;
    // Strict CAS over the exact derived durable plane root.
    let derived = environment_plane_root(
        &source.binding.estate_namespace,
        &source.state.bindings,
        &source.state.backups,
        &source.state.plans,
        &source.state.obligations,
    )
    .map_err(plan_err)?;
    if derived != source.head.plane_root {
        return Err(verr(
            "hypervisor_environment_artifact_mismatch",
            "durable plane truth does not recompute to its committed root",
        ));
    }
    if declaration.expected_plane_root != derived {
        return Err(verr(
            "hypervisor_environment_head_conflict",
            "stale predecessor plane root",
        ));
    }

    let mut state = source.state.clone();
    let mut activation_outcome = None;
    let mut governing_owner_ref = ESTATE_OWNER_REF.to_owned();
    let (subject_ref, record_family, record): (String, &'static str, Value) = match op {
        EnvironmentLifecycleOp::DeclareRouteBinding => {
            let declared = declaration
                .route_binding
                .as_ref()
                .ok_or_else(|| plan_err("route_binding declaration is absent".into()))?;
            let record =
                compile_route_binding_declaration(&source.binding, &state.bindings, declared)
                    .map_err(plan_err)?;
            governing_owner_ref = required(&record, "/owner_principal_ref")?;
            let subject = required(&record, "/route_binding_ref")?;
            state.bindings.push(record.clone());
            (subject, ROUTE_BINDING_DIR, record)
        }
        EnvironmentLifecycleOp::RecordBackup => {
            let backup_declaration = BackupDeclaration {
                backup_tail: declaration
                    .backup_tail
                    .clone()
                    .ok_or_else(|| plan_err("backup_tail is absent".into()))?,
                trigger: declaration
                    .backup_trigger
                    .clone()
                    .ok_or_else(|| plan_err("backup_trigger is absent".into()))?,
                environment_ref: declaration
                    .environment_ref
                    .clone()
                    .ok_or_else(|| plan_err("environment_ref is absent".into()))?,
                schedule_or_change_plan_ref: declaration.schedule_or_change_plan_ref.clone(),
            };
            let source_state_root = evidence.source_state_root.as_deref().ok_or_else(|| {
                verr(
                    "hypervisor_environment_evidence_not_found",
                    "no daemon-admitted source state root is resolvable from durable evidence",
                )
            })?;
            let receipt_ref = format!(
                "receipt://{}/environment-lifecycle/sequence/{}",
                source.binding.estate_namespace,
                source.head.sequence + 1
            );
            let record = compile_backup_record(
                &source.binding,
                &backup_declaration,
                source_state_root,
                &evidence.artifact_digest_rows,
                None,
                &receipt_ref,
            )
            .map_err(plan_err)?;
            let subject = required(&record, "/backup_ref")?;
            state.backups.push(record.clone());
            (subject, BACKUP_DIR, record)
        }
        EnvironmentLifecycleOp::DeclareChangePlan => {
            let declared = declaration
                .change_plan
                .as_ref()
                .ok_or_else(|| plan_err("change_plan declaration is absent".into()))?;
            let record = compile_change_plan_declaration(
                &source.binding,
                declared,
                &state.backups,
                &state.bindings,
                &state.plans,
            )
            .map_err(plan_err)?;
            let subject = required(&record, "/plan_ref")?;
            state.committed_stages.push((subject.clone(), Vec::new()));
            state.plans.push(record.clone());
            (subject, CHANGE_PLAN_DIR, record)
        }
        EnvironmentLifecycleOp::AdvanceChangePlanStage => {
            let plan_ref = declaration
                .plan_ref
                .as_deref()
                .ok_or_else(|| plan_err("plan_ref is absent".into()))?;
            let stage_index = declaration
                .stage_index
                .ok_or_else(|| plan_err("stage_index is absent".into()))?;
            let plan = state
                .plans
                .iter()
                .find(|plan| plan.get("plan_ref").and_then(Value::as_str) == Some(plan_ref))
                .cloned()
                .ok_or_else(|| {
                    verr(
                        "hypervisor_environment_not_found",
                        format!("'{plan_ref}' is not a durable change plan"),
                    )
                })?;
            let committed = state.stages_for(plan_ref);
            let advance = compile_stage_advance(
                &plan,
                &committed,
                stage_index,
                &StageEvidence {
                    resolved_artifact_digests: evidence.artifact_digest_rows.clone(),
                    resolved_evidence_refs: evidence.stage_evidence_refs.clone(),
                },
                &state.backups,
                &state.bindings,
            )
            .map_err(plan_err)?;
            activation_outcome = Some(advance.activation_outcome.clone());
            let record =
                serde_json::to_value(&advance).map_err(|error| plan_err(error.to_string()))?;
            let stages = state
                .committed_stages
                .iter_mut()
                .find(|(held, _)| held == plan_ref)
                .ok_or_else(|| plan_err("plan stages vanished".into()))?;
            stages.1.push(stage_index);
            (
                format!("{plan_ref}/stage/{stage_index}"),
                STAGE_ADVANCE_DIR,
                record,
            )
        }
        EnvironmentLifecycleOp::OpenCleanupObligation => {
            let declared = declaration
                .cleanup_obligation
                .as_ref()
                .ok_or_else(|| plan_err("cleanup_obligation declaration is absent".into()))?;
            let record = compile_cleanup_open(declared).map_err(plan_err)?;
            let subject = required(&record, "/cleanup_obligation_ref")?;
            if state.obligations.iter().any(|held| {
                held.get("cleanup_obligation_ref") == record.get("cleanup_obligation_ref")
            }) {
                return Err(verr(
                    "hypervisor_environment_head_conflict",
                    "the cleanup obligation already exists",
                ));
            }
            state.obligations.push(record.clone());
            (subject, CLEANUP_DIR, record)
        }
        EnvironmentLifecycleOp::SatisfyCleanupObligation
        | EnvironmentLifecycleOp::EscalateCleanupObligation => {
            let obligation_ref = declaration
                .cleanup_obligation_ref
                .as_deref()
                .ok_or_else(|| plan_err("cleanup_obligation_ref is absent".into()))?;
            let current = state
                .obligations
                .iter()
                .find(|held| {
                    held.get("cleanup_obligation_ref").and_then(Value::as_str)
                        == Some(obligation_ref)
                })
                .cloned()
                .ok_or_else(|| {
                    verr(
                        "hypervisor_environment_not_found",
                        format!("'{obligation_ref}' is not a durable cleanup obligation"),
                    )
                })?;
            let successor = if op == EnvironmentLifecycleOp::SatisfyCleanupObligation {
                compile_cleanup_satisfy(
                    &current,
                    declaration
                        .closing_status
                        .as_deref()
                        .ok_or_else(|| plan_err("closing_status is absent".into()))?,
                    declaration.disposition_receipt_ref.as_deref(),
                    &declaration.evidence_refs,
                )
                .map_err(plan_err)?
            } else {
                compile_cleanup_escalate(
                    &current,
                    declaration
                        .escalation_reason
                        .as_deref()
                        .ok_or_else(|| plan_err("escalation_reason is absent".into()))?,
                    declaration
                        .lost_parent_ref
                        .as_deref()
                        .ok_or_else(|| plan_err("lost_parent_ref is absent".into()))?,
                    &declaration.evidence_refs,
                )
                .map_err(plan_err)?
            };
            let held = state
                .obligations
                .iter_mut()
                .find(|held| {
                    held.get("cleanup_obligation_ref").and_then(Value::as_str)
                        == Some(obligation_ref)
                })
                .ok_or_else(|| plan_err("obligation vanished".into()))?;
            *held = successor.clone();
            (obligation_ref.to_owned(), CLEANUP_DIR, successor)
        }
    };

    let record_root = if record_family == CLEANUP_DIR {
        obligation_revision_root(&record).map_err(plan_err)?
    } else {
        environment_artifact_root(&record).map_err(plan_err)?
    };
    let resulting_plane_root = environment_plane_root(
        &source.binding.estate_namespace,
        &state.bindings,
        &state.backups,
        &state.plans,
        &state.obligations,
    )
    .map_err(plan_err)?;
    let sequence = source
        .head
        .sequence
        .checked_add(1)
        .ok_or_else(|| plan_err("sequence overflow".into()))?;

    let mut authority_effect = json!({
        "schema_version": "ioi.hypervisor-environment-lifecycle-authority-effect.v1",
        "op": op.as_str(),
        "required_scope": op.required_scope(),
        "entry_kind": op.entry_kind(),
        "sequence": sequence,
        "estate_namespace": source.binding.estate_namespace,
        "daemon_ref": source.binding.daemon_ref,
        "subject_ref": subject_ref,
        "record_family": record_family,
        "record_root": record_root,
        "predecessor_plane_root": derived,
        "resulting_plane_root": resulting_plane_root,
        "activation_outcome": activation_outcome,
        "governing_owner_ref": governing_owner_ref,
        "evidence_refs": declaration.evidence_refs,
        "asserts_observed_route_truth": false,
        "operation_commitment": Value::Null,
    });
    let operation_commitment = jcs_hash(&json!({
        "domain": ENVIRONMENT_OPERATION_PROFILE,
        "effect": authority_effect,
    }))?;
    authority_effect["operation_commitment"] = json!(operation_commitment);

    Ok(CompiledEnvironmentLifecyclePlan {
        op,
        sequence,
        subject_ref: required(&authority_effect, "/subject_ref")?,
        record_family,
        record,
        record_root,
        predecessor_plane_root: derived,
        resulting_plane_root,
        activation_outcome,
        governing_owner_ref,
        authority_effect,
    })
}

/// One fully built environment-lifecycle step, every registered envelope
/// contract-validated inside the build itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EnvironmentStepArtifacts {
    pub record: Value,
    pub transition: Value,
    pub transition_root: String,
    pub receipt: Value,
    pub receipt_root: String,
    pub claim: Value,
    pub claim_tail: String,
}

/// Build the committed step graph without performing I/O.
pub(crate) fn build_environment_artifacts(
    plan: &CompiledEnvironmentLifecyclePlan,
    authority: &DecisionAuthorityTuple,
    timestamp: &str,
) -> Result<EnvironmentStepArtifacts, VErr> {
    let ns = required(&plan.authority_effect, "/estate_namespace")?;
    // The plane records carry no volatile stamping: the committed record is
    // the exact compiled record, so its content root never drifts.
    let record = plan.record.clone();
    let contract = match plan.record_family {
        ROUTE_BINDING_DIR => Some(ROUTE_BINDING_CONTRACT),
        BACKUP_DIR => Some(ENVIRONMENT_BACKUP_CONTRACT),
        CHANGE_PLAN_DIR => Some(CHANGE_PLAN_CONTRACT),
        CLEANUP_DIR => Some(CLEANUP_OBLIGATION_CONTRACT),
        _ => None,
    };
    if let Some(contract) = contract {
        validate_contract(contract, &record, "environment record")?;
    }

    let transition_ref = format!(
        "environment-lifecycle-transition://{ns}/sequence/{}",
        plan.sequence
    );
    let receipt_ref = format!(
        "receipt://{ns}/environment-lifecycle/sequence/{}",
        plan.sequence
    );
    let mut authority_effect_material = plan.authority_effect.clone();
    authority_effect_material["operation_commitment"] = Value::Null;
    let transition = json!({
        "schema_version": "ioi.hypervisor-environment-lifecycle-transition.v1",
        "transition_id": transition_ref,
        "estate_namespace": ns,
        "op": plan.op.as_str(),
        "entry_kind": plan.op.entry_kind(),
        "sequence": plan.sequence,
        "subject_ref": plan.subject_ref,
        "record_family": plan.record_family,
        "record_root": plan.record_root,
        "predecessor_plane_root": plan.predecessor_plane_root,
        "resulting_plane_root": plan.resulting_plane_root,
        "activation_outcome": plan.activation_outcome,
        "operation_commitment": plan.authority_effect["operation_commitment"],
        "authority_effect_material": authority_effect_material,
        "evidence_refs": plan.authority_effect["evidence_refs"],
        "authority_grant_refs": [authority.authority_grant_ref],
        "receipt_refs": [receipt_ref],
        "status": "committed",
    });
    let transition_root = artifact_root(TRANSITION_ARTIFACT_DOMAIN, &transition)?;

    let receipt = json!({
        "receipt_id": receipt_ref,
        "receipt_type": "environment_lifecycle_transition",
        "receipt_profile_ref": RECEIPT_CONTRACT,
        "attested_boundary_fact_refs": [
            plan.subject_ref,
            transition_ref,
            authority.authority_evidence_ref,
        ],
        "claim_scope_ref": "policy://hypervisor/environment-lifecycle",
        "run_id": Value::Null,
        "task_id": Value::Null,
        "actor_id": "runtime://hypervisor-runtime",
        "authority_grant_id": authority.authority_grant_ref,
        "primitive_capabilities": [],
        "authority_scopes": [plan.op.required_scope()],
        "artifact_refs": [
            format!("artifact://environment-lifecycle-transition/{transition_root}"),
            format!("artifact://{}/{}", plan.record_family, plan.record_root),
        ],
        "evidence_bundle_refs": [],
        "verification_ref": Value::Null,
        "acceptance_ref": Value::Null,
        "adjudication_ref": Value::Null,
        "settlement_ref": Value::Null,
        "timestamp": timestamp,
        "signature": Value::Null,
        "public_commitment_ref": Value::Null,
        "input_hash": authority.input_hash,
        "output_hash": plan.resulting_plane_root,
        "policy_hash": authority.policy_hash,
    });
    validate_contract(RECEIPT_CONTRACT, &receipt, "environment-lifecycle receipt")?;
    let receipt_root = artifact_root(RECEIPT_ARTIFACT_DOMAIN, &receipt)?;

    let claim_tail = tail("hvelsc_", &plan.predecessor_plane_root)?;
    let claim = json!({
        "schema_version": "ioi.hypervisor.environment-lifecycle-successor-claim.v1",
        "claim_ref": format!(
            "environment-lifecycle-successor-claim://{}",
            plan.predecessor_plane_root
        ),
        "estate_namespace": ns,
        "sequence": plan.sequence,
        "predecessor_plane_root": plan.predecessor_plane_root,
        "resulting_plane_root": plan.resulting_plane_root,
        "transition_ref": transition_ref,
        "op": plan.op.as_str(),
        "committed_at": timestamp,
    });
    Ok(EnvironmentStepArtifacts {
        record,
        transition,
        transition_root,
        receipt,
        receipt_root,
        claim,
        claim_tail,
    })
}

fn persist_environment_graph(
    data_dir: &str,
    plan: &CompiledEnvironmentLifecyclePlan,
    artifacts: &EnvironmentStepArtifacts,
    evidence: &super::system_activation_routes::NodeAdmissionEvidence,
    wallet_consumption: &Value,
) -> Result<(), VErr> {
    // One successor per predecessor plane root: the expected-absent Agentgres
    // admission is the cross-process CAS boundary.
    persist_local(
        data_dir,
        ENVIRONMENT_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|(code, message)| {
        if code == "system_lifecycle_conflict" {
            verr("hypervisor_environment_head_conflict", message)
        } else {
            (code, message)
        }
    })?;
    super::substrate_store::admit_required(
        data_dir,
        ENVIRONMENT_CLAIM_DIR,
        &artifacts.claim_tail,
        &artifacts.claim,
    )
    .map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "hypervisor_environment_head_conflict"
        } else {
            "hypervisor_environment_agentgres_admission_failed"
        };
        verr(code, format!("durable plane claim failed ({error})"))
    })?;
    if load_required_exact(data_dir, ENVIRONMENT_CLAIM_DIR, &artifacts.claim_tail)?.as_ref()
        != Some(&artifacts.claim)
    {
        return Err(verr(
            "hypervisor_environment_head_conflict",
            "durable plane predecessor claim belongs to a different successor",
        ));
    }
    let consumption: ioi_services::wallet_network::ApprovalGrantConsumptionReceipt =
        serde_json::from_value(wallet_consumption.clone()).map_err(|error| {
            verr(
                "system_lifecycle_wallet_consumption_invalid",
                error.to_string(),
            )
        })?;
    let record_prefix = family_prefix(plan.record_family)?;
    let records: Vec<(&str, String, &Value)> = vec![
        (
            AUTHORITY_CONSUMPTION_DIR,
            format!("aslac_{}", hex::encode(consumption.consumption_id)),
            wallet_consumption,
        ),
        (
            AUTHORITY_EVIDENCE_DIR,
            tail("aslae_", &evidence.authority_evidence_root)?,
            &evidence.authority_evidence,
        ),
        (
            plan.record_family,
            tail(record_prefix, &plan.record_root)?,
            &artifacts.record,
        ),
        (
            ENVIRONMENT_TRANSITION_DIR,
            tail("hvet_", &artifacts.transition_root)?,
            &artifacts.transition,
        ),
        (
            ENVIRONMENT_RECEIPT_DIR,
            tail("hvelr_", &artifacts.receipt_root)?,
            &artifacts.receipt,
        ),
    ];
    for (family, record_tail, value) in records {
        persist_local(data_dir, family, &record_tail, value)?;
        super::substrate_store::admit_required(data_dir, family, &record_tail, value).map_err(
            |error| {
                verr(
                    "hypervisor_environment_agentgres_admission_failed",
                    format!("required admission for '{family}/{record_tail}' failed ({error})"),
                )
            },
        )?;
        let loaded = load_required_exact(data_dir, family, &record_tail)?.ok_or_else(|| {
            verr(
                "hypervisor_environment_persist_failed",
                "environment-lifecycle artifact did not converge",
            )
        })?;
        if loaded != *value {
            return Err(verr(
                "hypervisor_environment_persist_failed",
                "environment-lifecycle artifact diverged",
            ));
        }
    }
    Ok(())
}

pub(crate) fn ensure_no_pending_environment_intent(data_dir: &str) -> Result<(), VErr> {
    for (_tail, intent) in scan_local_family(data_dir, ENVIRONMENT_INTENT_DIR)? {
        verify_intent_seal(&intent)?;
        return Err(verr(
            "system_lifecycle_pending_convergence",
            "an environment-lifecycle transition is pending convergence",
        ));
    }
    Ok(())
}

/// POST /v1/hypervisor/environments/lifecycle/:op
pub(crate) async fn handle_environment_transition(
    AxumPath(op_name): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(op) = EnvironmentLifecycleOp::parse(&op_name) else {
        return classify(verr(
            "hypervisor_environment_operation_not_found",
            "unknown environment-lifecycle op",
        ));
    };
    if let Err(error) = validate_request(&body) {
        return classify(error);
    }
    let declaration = match declaration_from_body(&body) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let _gate = SYSTEM_ACTIVATION_GATE.lock().await;
    let source = match with_source_locks(|| {
        ensure_no_pending_environment_intent(&state.data_dir)?;
        load_environment_lifecycle_source(&state.data_dir)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let evidence_inputs = match resolve_trusted_inputs(&state.data_dir, op) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let plan = match compile_from_source(op, &source, &declaration, &evidence_inputs) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let estate_namespace = source.binding.estate_namespace.clone();
    let governing = plan.governing_owner_ref.clone();
    let authorized = match governed::authorize_decision_with_context(
        AUTHORITY,
        &body,
        Governance::Host,
        AuthorityPolicyContext::HypervisorEnvironment {
            estate_namespace: &estate_namespace,
            subject_ref: &plan.subject_ref,
        },
        &governing,
        &plan.subject_ref,
        op.as_str(),
        plan.sequence,
        &plan.authority_effect,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let mut evidence = match prepare_node_evidence_for(
        &plan.authority_effect,
        op.as_str(),
        plan.sequence,
        op.required_scope(),
        &governing,
        &plan.resulting_plane_root,
        authorized,
    ) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if let Err(error) = preflight_chain_writer_grant(&evidence.wallet_params).await {
        return classify(error);
    }
    let intent_tail = match tail("hveli_", &evidence.authorized.evidence.request_hash) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let intent = match with_source_locks(|| {
        let fresh = load_environment_lifecycle_source(&state.data_dir)?;
        let recompiled = compile_from_source(op, &fresh, &declaration, &evidence_inputs)?;
        if recompiled != plan {
            return Err(verr(
                "hypervisor_environment_head_conflict",
                "durable truth changed between authorization and intent sealing",
            ));
        }
        let intent = intent_seal(json!({
            "schema_version": "ioi.hypervisor.environment-lifecycle-transition-intent.v1",
            "source_record_tail": "local",
            "op": op.as_str(),
            "request_body": body,
            "compiled_subject_ref": plan.subject_ref,
            "compiled_record_root": plan.record_root,
            "compiled_resulting_plane_root": plan.resulting_plane_root,
            "governed_authority": evidence_intent_value(&evidence),
            "intent_hash": Value::Null,
        }))?;
        persist_local(
            &state.data_dir,
            ENVIRONMENT_INTENT_DIR,
            &intent_tail,
            &intent,
        )?;
        Ok::<_, VErr>(intent)
    }) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_HYPERVISOR_ENVIRONMENT_AFTER_INTENT",
        op.as_str(),
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after durable environment-lifecycle intent",
        ));
    }
    let wallet_receipt =
        match super::wallet_network_capability_client::consume_approval_grant_for_effect_v2(
            evidence.wallet_params.clone(),
        )
        .await
        {
            Ok(value) => value,
            Err(
                super::wallet_network_capability_client::ResolveError::NotConfigured(message)
                | super::wallet_network_capability_client::ResolveError::Unavailable(message),
            ) => {
                return classify(verr(
                    "system_lifecycle_wallet_consumption_unavailable",
                    message,
                ))
            }
            Err(super::wallet_network_capability_client::ResolveError::Refused(message)) => {
                let cleanup = with_source_locks(|| {
                    if load_required_exact(
                        &state.data_dir,
                        AUTHORITY_CONSUMPTION_DIR,
                        &evidence.wallet_consumption_tail,
                    )?
                    .is_some()
                    {
                        return Err(verr(
                            "system_lifecycle_pending_convergence",
                            "wallet refusal conflicts with existing consumption evidence",
                        ));
                    }
                    remove_intent(&state.data_dir, ENVIRONMENT_INTENT_DIR, &intent_tail)
                });
                if let Err(error) = cleanup {
                    return classify(error);
                }
                return classify(verr("system_lifecycle_wallet_consumption_refused", message));
            }
            Err(super::wallet_network_capability_client::ResolveError::Invalid(message)) => {
                return classify(verr("system_lifecycle_wallet_consumption_invalid", message))
            }
        };
    let wallet_value = match validate_wallet_receipt(&mut evidence, &wallet_receipt) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    if forced_fault(
        "IOI_TEST_FORCE_HYPERVISOR_ENVIRONMENT_AFTER_WALLET_CONSUMPTION",
        op.as_str(),
    ) {
        return classify(verr(
            "system_lifecycle_pending_convergence",
            "test-forced interruption after exact wallet consumption",
        ));
    }
    let timestamp = match ms_to_timestamp(wallet_receipt.consumed_at_ms) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let tuple = match decision_tuple(&evidence) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let artifacts = match build_environment_artifacts(&plan, &tuple, &timestamp) {
        Ok(value) => value,
        Err(error) => return classify(error),
    };
    let result = with_source_locks(|| {
        let stored = load_local(&state.data_dir, ENVIRONMENT_INTENT_DIR, &intent_tail)?
            .ok_or_else(|| {
                verr(
                    "system_lifecycle_pending_convergence",
                    "environment-lifecycle intent vanished",
                )
            })?;
        verify_intent_seal(&stored)?;
        if stored != intent {
            return Err(verr(
                "system_lifecycle_intent_unreadable",
                "durable environment-lifecycle intent changed",
            ));
        }
        persist_environment_graph(&state.data_dir, &plan, &artifacts, &evidence, &wallet_value)?;
        remove_intent(&state.data_dir, ENVIRONMENT_INTENT_DIR, &intent_tail)
    });
    if let Err(error) = result {
        return classify(error);
    }
    (
        StatusCode::OK,
        Json(json!({
            "op": op.as_str(),
            "sequence": plan.sequence,
            "subject_ref": plan.subject_ref,
            "record": artifacts.record,
            "transition": artifacts.transition,
            "receipt": artifacts.receipt,
            "plane_root": plan.resulting_plane_root,
            "activation_outcome": plan.activation_outcome,
            "nonclaims": {
                "observed_route_truth": false,
                "restore_truth_from_bytes": false,
                "cleanup_erased_by_parent_deletion": false,
                "system_authority": false,
                "writer": false
            }
        })),
    )
}

/// Read-only eligibility projection for one operation. This never fabricates
/// eligibility: the plane head is reported separately from declaration
/// evidence and wallet authority a future POST must still supply.
pub(crate) async fn handle_get_environment_transition(
    AxumPath(op_name): AxumPath<String>,
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    let Some(op) = EnvironmentLifecycleOp::parse(&op_name) else {
        return classify(verr(
            "hypervisor_environment_operation_not_found",
            "unknown environment-lifecycle op",
        ));
    };
    match with_source_locks(|| {
        ensure_no_pending_environment_intent(&state.data_dir)?;
        let source = load_environment_lifecycle_source(&state.data_dir)?;
        let committed: usize = source
            .transitions
            .iter()
            .filter(|value| value.get("op").and_then(Value::as_str) == Some(op.as_str()))
            .count();
        Ok::<_, VErr>(json!({
            "op": op.as_str(),
            "required_scope": op.required_scope(),
            "entry_kind": op.entry_kind(),
            "plane_head": {
                "sequence": source.head.sequence,
                "plane_root": source.head.plane_root,
            },
            "required_declaration_evidence": {
                "expected_plane_root": true,
                "declared_route_binding": op == EnvironmentLifecycleOp::DeclareRouteBinding,
                "resolved_artifact_census": op == EnvironmentLifecycleOp::RecordBackup,
                "declared_change_plan": op == EnvironmentLifecycleOp::DeclareChangePlan,
                "resolved_stage_evidence": op == EnvironmentLifecycleOp::AdvanceChangePlanStage,
                "receipted_disposition":
                    op == EnvironmentLifecycleOp::SatisfyCleanupObligation,
                "loss_evidence": op == EnvironmentLifecycleOp::EscalateCleanupObligation,
            },
            "committed_entries": committed,
            "nonclaims": {"wallet_authorized": false, "observed_route_truth": false}
        }))
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

/// Pure plane projection over durable truth only. Drift verdicts are labeled
/// refusals over resolved observations; the observed binding is never adopted
/// and absence is honest, never fabricated.
pub(crate) fn build_environment_projection(
    estate_namespace: &str,
    state: &EnvironmentPlaneState,
    head: &EnvironmentLifecycleLogHead,
    route_observations: &[Value],
) -> Result<Value, VErr> {
    let mut route_rows = Vec::new();
    let mut identities: Vec<String> = state
        .bindings
        .iter()
        .map(|binding| route_identity(binding).map_err(plan_err))
        .collect::<Result<Vec<_>, VErr>>()?;
    identities.sort();
    identities.dedup();
    for identity in identities {
        let Some(binding) = route_binding_head(&state.bindings, &identity).map_err(plan_err)?
        else {
            continue;
        };
        let observation = route_observations.iter().find(|observation| {
            observation.get("hostname_or_address") == binding.get("hostname_or_address")
                && observation.get("path_prefix") == binding.get("path_prefix")
                && observation.get("target_protocol") == binding.get("target_protocol")
        });
        let drift = match observation {
            None => json!({"state": "unobserved"}),
            Some(observation) => {
                let verdict = evaluate_route_binding_observation(binding, observation);
                json!({
                    "state": if verdict.admitted { "conformant" } else { "refused" },
                    "refusal_dimension": verdict.refusal_dimension,
                    "refusal_reason": verdict.refusal_reason,
                    "observed_binding_adopted": false,
                })
            }
        };
        route_rows.push(json!({
            "route_identity": identity,
            "head_revision": binding["route_binding_ref"],
            "owner_principal_ref": binding["owner_principal_ref"],
            "system_ref": binding["system_ref"],
            "activation_generation": binding["activation_generation"],
            "active_head": state
                .active_heads
                .iter()
                .find(|(held, _)| held == &identity)
                .map(|(_, head)| json!(head))
                .unwrap_or(Value::Null),
            "drift": drift,
        }));
    }
    let plans: Vec<Value> = state
        .plans
        .iter()
        .map(|plan| {
            let plan_ref = plan
                .get("plan_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let stages = state.stages_for(&plan_ref);
            json!({
                "plan_ref": plan_ref,
                "plan_hash": plan["plan_hash"],
                "committed_stage_indexes": stages,
                "declared_stage_count": plan
                    .get("steps")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0),
            })
        })
        .collect();
    let obligations: Vec<Value> = state
        .obligations
        .iter()
        .map(|obligation| {
            json!({
                "cleanup_obligation_ref": obligation["cleanup_obligation_ref"],
                "status": obligation["status"],
                "revision": obligation["revision"],
                "escalation": obligation["escalation"],
                "receipt_refs": obligation["receipt_refs"],
            })
        })
        .collect();
    Ok(json!({
        "schema_version": "ioi.hypervisor.environment-lifecycle-projection.v1",
        "estate_namespace": estate_namespace,
        "state": if state.bindings.is_empty()
            && state.backups.is_empty()
            && state.plans.is_empty()
            && state.obligations.is_empty()
        {
            "honest_empty"
        } else {
            "ready"
        },
        "plane_head": {
            "sequence": head.sequence,
            "plane_root": head.plane_root,
        },
        "routes": route_rows,
        "backups": state
            .backups
            .iter()
            .map(|backup| json!({
                "backup_ref": backup["backup_ref"],
                "status": backup["status"],
                "manifest_root": backup["manifest_root"],
                "manifest_artifact_count": backup["manifest_artifact_count"],
            }))
            .collect::<Vec<_>>(),
        "change_plans": plans,
        "cleanup_obligations": obligations,
        "projection_source": "durable_owner_reconstruction",
        "nonclaims": {
            "observed_route_truth": false,
            "restore_truth_from_bytes": false,
            "cleanup_erased_by_parent_deletion": false,
            "availability": false,
            "writer": false
        }
    }))
}

/// GET /v1/hypervisor/environments/lifecycle/projection
pub(crate) async fn handle_get_environment_projection(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<Value>) {
    match with_source_locks(|| {
        let source = load_environment_lifecycle_source(&state.data_dir)?;
        let observations = resolve_route_observations(&state.data_dir)?;
        build_environment_projection(
            &source.binding.estate_namespace,
            &source.state,
            &source.head,
            &observations,
        )
    }) {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => classify(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn h(marker: u8) -> String {
        format!("sha256:{}", format!("{marker:02x}").repeat(32))
    }

    fn fixture(path: &str) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../../docs/architecture/_meta/schemas/fixtures/{path}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .expect(path),
        )
        .expect(path)
    }

    fn authority() -> DecisionAuthorityTuple {
        DecisionAuthorityTuple {
            input_hash: h(0x51),
            policy_hash: h(0x52),
            effect_hash: h(0x53),
            authority_grant_ref: format!("grant://wallet.network/approval/{}", h(0x54)),
            authority_evidence_ref: format!(
                "system-lifecycle-authority-evidence://aslae_{}",
                "55".repeat(32)
            ),
            authority_evidence_root: h(0x55),
            wallet_grant_consumption_ref: format!(
                "wallet.network://approval-effect-consumption/{}/{}",
                "56".repeat(32),
                "58".repeat(32)
            ),
            wallet_grant_consumption_root: h(0x56),
            wallet_grant_consumption_evidence_ref: format!(
                "system-lifecycle-authority-consumption://aslac_{}",
                "57".repeat(32)
            ),
        }
    }

    struct LadderState {
        source: EnvironmentLifecycleSource,
        records: HashMap<(String, String), String>,
        transitions: Vec<Value>,
    }

    fn empty_source() -> EnvironmentLifecycleSource {
        let binding = local_environment_estate_binding();
        let plane_root =
            environment_plane_root(&binding.estate_namespace, &[], &[], &[], &[]).expect("root");
        EnvironmentLifecycleSource {
            binding,
            state: EnvironmentPlaneState::default(),
            head: EnvironmentLifecycleLogHead {
                sequence: 0,
                plane_root,
            },
            transitions: Vec::new(),
        }
    }

    fn base_declaration(source: &EnvironmentLifecycleSource) -> EnvironmentLifecycleDeclaration {
        EnvironmentLifecycleDeclaration {
            expected_plane_root: source.head.plane_root.clone(),
            route_binding: None,
            backup_tail: None,
            backup_trigger: None,
            environment_ref: None,
            schedule_or_change_plan_ref: None,
            change_plan: None,
            plan_ref: None,
            stage_index: None,
            cleanup_obligation: None,
            cleanup_obligation_ref: None,
            closing_status: None,
            disposition_receipt_ref: None,
            escalation_reason: None,
            lost_parent_ref: None,
            evidence_refs: Vec::new(),
        }
    }

    fn digest_census() -> ResolvedEnvironmentEvidence {
        ResolvedEnvironmentEvidence {
            source_state_root: Some(h(0x0e)),
            artifact_digest_rows: vec![
                json!({
                    "evidence_kind": "artifact_digest",
                    "artifact_ref":
                        format!("artifact://environment-backup-payload/{}", "11".repeat(8)),
                    "sha256": h(0x21),
                    "size_bytes": 4096,
                    "role": "environment_backup_payload",
                }),
                json!({
                    "evidence_kind": "artifact_digest",
                    "artifact_ref":
                        format!("artifact://environment-backup-payload/{}", "22".repeat(8)),
                    "sha256": h(0x22),
                    "size_bytes": 1024,
                    "role": "workspace_snapshot",
                }),
            ],
            stage_evidence_refs: vec![
                "evidence://acme/env-alpha/restore/preflight".into(),
                "evidence://acme/env-alpha/restore/manifest-verification".into(),
                "evidence://acme/env-alpha/restore/root-recompute".into(),
                "evidence://acme/env-alpha/restore/readiness".into(),
            ],
        }
    }

    fn no_evidence() -> ResolvedEnvironmentEvidence {
        ResolvedEnvironmentEvidence {
            source_state_root: None,
            artifact_digest_rows: Vec::new(),
            stage_evidence_refs: Vec::new(),
        }
    }

    fn apply_step(
        ladder: &mut LadderState,
        op: EnvironmentLifecycleOp,
        declaration: &EnvironmentLifecycleDeclaration,
        evidence: &ResolvedEnvironmentEvidence,
    ) -> EnvironmentStepArtifacts {
        let plan = compile_from_source(op, &ladder.source, declaration, evidence)
            .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        assert_eq!(plan.predecessor_plane_root, ladder.source.head.plane_root);
        let artifacts = build_environment_artifacts(&plan, &authority(), "2026-07-28T12:00:00Z")
            .unwrap_or_else(|(code, message)| panic!("{}: {code} {message}", op.as_str()));
        ladder.records.insert(
            (plan.record_family.to_owned(), plan.record_root.clone()),
            serde_json::to_string(&artifacts.record).expect("record bytes"),
        );
        ladder.transitions.push(artifacts.transition.clone());
        // Reload the source from durable transitions only, exactly like the
        // route handler does after a restart.
        let records = ladder.records.clone();
        let loader = move |family: &str, root: &str| -> Result<Option<Value>, String> {
            Ok(records
                .get(&(family.to_owned(), root.to_owned()))
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (state, head) = replay_environment_lifecycle(
            &ladder.source.binding.estate_namespace,
            &ladder.transitions,
            &loader,
        )
        .unwrap_or_else(|error| panic!("replay after {}: {error}", op.as_str()));
        assert_eq!(head.sequence, plan.sequence);
        assert_eq!(head.plane_root, plan.resulting_plane_root);
        ladder.source = EnvironmentLifecycleSource {
            binding: local_environment_estate_binding(),
            state,
            head,
            transitions: ladder.transitions.clone(),
        };
        artifacts
    }

    fn genesis_binding() -> Value {
        fixture("hypervisor-environment-route-binding-v1/positive-declared.json")
    }

    fn plan_body(ladder: &LadderState) -> Value {
        use ioi_types::app::hypervisor_environment_lifecycle::change_plan_commitment;
        let backup = &ladder.source.state.backups[0];
        let binding = &ladder.source.state.bindings[0];
        let mut plan = fixture("hypervisor-change-plan-v1/positive-restore-declared.json");
        plan["restore"]["source_backup_ref"] = backup["backup_ref"].clone();
        plan["restore"]["restore_manifest_root"] = backup["manifest_root"].clone();
        plan["restore"]["source_root_and_head_expectations"]["source_state_root_ref"] =
            backup["source_state_root_ref"].clone();
        plan["activation"]["candidate_ref"] = binding["route_binding_ref"].clone();
        plan["activation"]["expected_active_head_ref"] = Value::Null;
        plan["activation"]["candidate_generation"] = binding["activation_generation"].clone();
        plan["plan_hash"] = json!(change_plan_commitment(&plan).expect("plan hash"));
        plan
    }

    fn open_obligation() -> Value {
        fixture("hypervisor-resource-cleanup-obligation-v1/positive-open.json")
    }

    /// The full ladder: declare binding -> record backup -> declare plan ->
    /// advance every stage forward-only -> open obligation -> escalate on
    /// parent loss -> satisfy with a receipt.
    fn run_ladder() -> LadderState {
        let mut ladder = LadderState {
            source: empty_source(),
            records: HashMap::new(),
            transitions: Vec::new(),
        };

        let mut declare = base_declaration(&ladder.source);
        declare.route_binding = Some(genesis_binding());
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::DeclareRouteBinding,
            &declare,
            &no_evidence(),
        );

        let mut backup = base_declaration(&ladder.source);
        backup.backup_tail = Some("env-alpha/2026-07-28/0001".into());
        backup.backup_trigger = Some("pre_change".into());
        backup.environment_ref = Some("environment://local/env-alpha".into());
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::RecordBackup,
            &backup,
            &digest_census(),
        );

        let mut plan = base_declaration(&ladder.source);
        plan.change_plan = Some(plan_body(&ladder));
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::DeclareChangePlan,
            &plan,
            &no_evidence(),
        );
        let plan_ref = ladder.source.state.plans[0]["plan_ref"]
            .as_str()
            .expect("plan ref")
            .to_owned();

        for stage_index in 1..=5u64 {
            let mut advance = base_declaration(&ladder.source);
            advance.plan_ref = Some(plan_ref.clone());
            advance.stage_index = Some(stage_index);
            let artifacts = apply_step(
                &mut ladder,
                EnvironmentLifecycleOp::AdvanceChangePlanStage,
                &advance,
                &digest_census(),
            );
            if stage_index == 4 {
                assert_eq!(artifacts.transition["activation_outcome"], "advanced");
            }
        }

        let mut open = base_declaration(&ladder.source);
        open.cleanup_obligation = Some(open_obligation());
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::OpenCleanupObligation,
            &open,
            &no_evidence(),
        );
        ladder
    }

    #[test]
    fn environment_ladder_artifacts_validate_every_registered_envelope() {
        let mut ladder = run_ladder();
        assert_eq!(ladder.source.head.sequence, 9);
        assert_eq!(ladder.source.state.bindings.len(), 1);
        assert_eq!(ladder.source.state.backups.len(), 1);
        assert_eq!(ladder.source.state.plans.len(), 1);
        assert_eq!(ladder.source.state.obligations.len(), 1);
        let plan_ref = ladder.source.state.plans[0]["plan_ref"]
            .as_str()
            .expect("plan ref")
            .to_owned();
        assert_eq!(
            ladder.source.state.stages_for(&plan_ref),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(ladder.source.state.active_heads.len(), 1);

        // Parent loss escalates the open obligation; nothing is erased.
        let obligation_ref = ladder.source.state.obligations[0]["cleanup_obligation_ref"]
            .as_str()
            .expect("obligation ref")
            .to_owned();
        let mut escalate = base_declaration(&ladder.source);
        escalate.cleanup_obligation_ref = Some(obligation_ref.clone());
        escalate.escalation_reason = Some("parent_loss".into());
        escalate.lost_parent_ref = Some("environment://local/env-alpha".into());
        escalate.evidence_refs = vec!["evidence://local/env-alpha/deletion".into()];
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::EscalateCleanupObligation,
            &escalate,
            &no_evidence(),
        );
        assert_eq!(ladder.source.state.obligations.len(), 1);
        assert_eq!(ladder.source.state.obligations[0]["status"], "escalated");

        // A receipted disposition closes the escalated obligation.
        let mut satisfy = base_declaration(&ladder.source);
        satisfy.cleanup_obligation_ref = Some(obligation_ref);
        satisfy.closing_status = Some("completed".into());
        satisfy.disposition_receipt_ref = Some("receipt://local/env-alpha/cleanup/0001".into());
        satisfy.evidence_refs = vec!["evidence://local/env-alpha/cleanup/absent".into()];
        apply_step(
            &mut ladder,
            EnvironmentLifecycleOp::SatisfyCleanupObligation,
            &satisfy,
            &no_evidence(),
        );
        assert_eq!(ladder.source.state.obligations[0]["status"], "completed");
        assert_eq!(ladder.source.head.sequence, 11);

        // Every registered envelope validates from the durable records.
        for ((family, _root), bytes) in &ladder.records {
            let record: Value = serde_json::from_str(bytes).expect("record");
            let contract = match family.as_str() {
                ROUTE_BINDING_DIR => Some(ROUTE_BINDING_CONTRACT),
                BACKUP_DIR => Some(ENVIRONMENT_BACKUP_CONTRACT),
                CHANGE_PLAN_DIR => Some(CHANGE_PLAN_CONTRACT),
                CLEANUP_DIR => Some(CLEANUP_OBLIGATION_CONTRACT),
                _ => None,
            };
            if let Some(contract) = contract {
                validate_contract(contract, &record, "ladder record").expect("envelope");
            }
        }
    }

    #[test]
    fn restart_rebuilds_the_projection_from_durable_records_byte_exactly() {
        let ladder = run_ladder();
        let before =
            build_environment_projection("local", &ladder.source.state, &ladder.source.head, &[])
                .expect("projection before restart");

        // Restart: every in-memory structure is gone; only durable transition
        // and record bytes remain.
        let transition_bytes: Vec<String> = ladder
            .transitions
            .iter()
            .map(|value| serde_json::to_string(value).expect("transition bytes"))
            .collect();
        let record_bytes = ladder.records.clone();
        drop(ladder);
        let transitions: Vec<Value> = transition_bytes
            .iter()
            .map(|bytes| serde_json::from_str(bytes).expect("stored transition"))
            .collect();
        let loader = move |family: &str, root: &str| -> Result<Option<Value>, String> {
            Ok(record_bytes
                .get(&(family.to_owned(), root.to_owned()))
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (state, head) =
            replay_environment_lifecycle("local", &transitions, &loader).expect("replay");
        let after = build_environment_projection("local", &state, &head, &[]).expect("projection");
        assert_eq!(before, after);
        assert_eq!(
            serde_json::to_string(&before).expect("bytes"),
            serde_json::to_string(&after).expect("bytes")
        );
    }

    #[test]
    fn stale_plane_root_and_reentered_stage_are_refused_at_the_route_compile() {
        let mut ladder = run_ladder();
        let plan_ref = ladder.source.state.plans[0]["plan_ref"]
            .as_str()
            .expect("plan ref")
            .to_owned();

        // Stale plane root: strict CAS refuses.
        let mut stale = base_declaration(&ladder.source);
        stale.plan_ref = Some(plan_ref.clone());
        stale.stage_index = Some(5);
        stale.expected_plane_root = h(0x99);
        let (code, _message) = compile_from_source(
            EnvironmentLifecycleOp::AdvanceChangePlanStage,
            &ladder.source,
            &stale,
            &digest_census(),
        )
        .unwrap_err();
        assert_eq!(code, "hypervisor_environment_head_conflict");

        // Re-entering a completed stage is a named backward_stage refusal.
        let mut reenter = base_declaration(&ladder.source);
        reenter.plan_ref = Some(plan_ref);
        reenter.stage_index = Some(4);
        let (code, message) = compile_from_source(
            EnvironmentLifecycleOp::AdvanceChangePlanStage,
            &ladder.source,
            &reenter,
            &digest_census(),
        )
        .unwrap_err();
        assert_eq!(code, "hypervisor_environment_plan_invalid");
        assert!(message.starts_with("backward_stage"), "{message}");

        // The refusals advanced nothing: the durable head is unchanged.
        let head_before = ladder.source.head.clone();
        let refreshed = apply_step_noop_probe(&mut ladder);
        assert_eq!(refreshed, head_before);
    }

    fn apply_step_noop_probe(ladder: &mut LadderState) -> EnvironmentLifecycleLogHead {
        let records = ladder.records.clone();
        let loader = move |family: &str, root: &str| -> Result<Option<Value>, String> {
            Ok(records
                .get(&(family.to_owned(), root.to_owned()))
                .map(|bytes| serde_json::from_str(bytes).expect("stored record")))
        };
        let (_state, head) =
            replay_environment_lifecycle("local", &ladder.transitions, &loader).expect("replay");
        head
    }

    #[test]
    fn drift_projection_labels_refusals_and_never_adopts_the_observed_binding() {
        let ladder = run_ladder();
        let binding = &ladder.source.state.bindings[0];
        let mut observation = json!({
            "evidence_kind": "route_observation",
            "observation_ref": "evidence://local/routes/api.acme.example/observation/1",
            "hostname_or_address": binding["hostname_or_address"],
            "path_prefix": binding["path_prefix"],
            "target_protocol": binding["target_protocol"],
            "observed_target_endpoint_ref": "endpoint://mallory/hijack",
            "observed_owner_principal_ref": binding["owner_principal_ref"],
            "observed_system_ref": binding["system_ref"],
            "observed_tls_at_or_above_floor": true,
            "observed_certificate_matches_binding": true,
            "observed_provider_records_match": true,
            "observed_endpoint_reachable": true,
        });
        let projection = build_environment_projection(
            "local",
            &ladder.source.state,
            &ladder.source.head,
            std::slice::from_ref(&observation),
        )
        .expect("projection");
        let route = &projection["routes"][0];
        assert_eq!(route["drift"]["state"], "refused");
        assert_eq!(route["drift"]["refusal_dimension"], "route_drift");
        assert_eq!(route["drift"]["observed_binding_adopted"], false);
        // The declared head revision survives byte-identically.
        assert_eq!(route["head_revision"], binding["route_binding_ref"]);

        observation["observed_owner_principal_ref"] = json!("org://mallory/takeover");
        observation["observed_target_endpoint_ref"] = binding["target_endpoint_ref"].clone();
        let projection = build_environment_projection(
            "local",
            &ladder.source.state,
            &ladder.source.head,
            std::slice::from_ref(&observation),
        )
        .expect("projection");
        assert_eq!(
            projection["routes"][0]["drift"]["refusal_dimension"],
            "owner_drift"
        );
    }

    #[test]
    fn environment_ops_have_owner_scopes_and_never_parse_as_other_families() {
        for op in EnvironmentLifecycleOp::ALL {
            assert_eq!(AUTHORITY.operation_scope(op.as_str()), op.required_scope());
            assert!(
                ioi_types::app::system_membership_transitions::MembershipTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_lifecycle_transitions::ProtectedTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_continuity_transitions::ContinuityTransitionOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::hypervisoros_node_attestation::NodeAttestationOp::parse(
                    op.as_str()
                )
                .is_none()
            );
            assert!(
                ioi_types::app::system_writer_fence::WriterEpochTransitionKind::parse(op.as_str())
                    .is_none()
            );
        }
    }

    #[test]
    fn projection_without_any_environment_truth_is_honest() {
        let source = empty_source();
        let projection = build_environment_projection("local", &source.state, &source.head, &[])
            .expect("empty projection");
        assert_eq!(projection["state"], "honest_empty");
        assert_eq!(projection["routes"], json!([]));
        assert_eq!(projection["cleanup_obligations"], json!([]));
        assert_eq!(projection["nonclaims"]["observed_route_truth"], false);
    }
}
