//! Shared append-only mechanics for bounded work lifecycles.
//!
//! This module deliberately does not invent one universal business lifecycle.
//! GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation,
//! ContextCell, and external handles keep kind-specific phases and transition
//! authorities. The shared kernel owns only record integrity, exact-head CAS,
//! idempotent replay/conflict, append-only child-reference facts, rebuildable
//! projections, cancellation fanout planning, and snapshot/archive replay.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WORK_LIFECYCLE_RECORD_SCHEMA: &str = "ioi.work-lifecycle-record.v1";
pub const WORK_LIFECYCLE_PROJECTION_SCHEMA: &str = "ioi.work-lifecycle-projection.v1";
pub const WORK_LIFECYCLE_ARCHIVE_SCHEMA: &str = "ioi.work-lifecycle-archive-segment.v1";
pub const WORK_LIFECYCLE_SNAPSHOT_SCHEMA: &str = "ioi.work-lifecycle-snapshot.v1";
pub const CANCELLATION_FANOUT_PLAN_SCHEMA: &str = "ioi.cancellation-fanout-plan.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLifecycleObjectKind {
    GoalRun,
    GoalGroundingLoop,
    WorkRun,
    AutomationRun,
    HarnessInvocation,
    ContextCell,
    ExternalHandle,
}

impl WorkLifecycleObjectKind {
    pub const ALL: [Self; 7] = [
        Self::GoalRun,
        Self::GoalGroundingLoop,
        Self::WorkRun,
        Self::AutomationRun,
        Self::HarnessInvocation,
        Self::ContextCell,
        Self::ExternalHandle,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GoalRun => "goal_run",
            Self::GoalGroundingLoop => "goal_grounding_loop",
            Self::WorkRun => "work_run",
            Self::AutomationRun => "automation_run",
            Self::HarnessInvocation => "harness_invocation",
            Self::ContextCell => "context_cell",
            Self::ExternalHandle => "external_handle",
        }
    }

    fn expected_ref_prefix(self) -> Option<&'static str> {
        match self {
            Self::GoalRun => Some("goal://"),
            Self::GoalGroundingLoop => Some("goal_loop://"),
            Self::WorkRun => Some("work_run://"),
            Self::AutomationRun => Some("automation-run://"),
            Self::HarnessInvocation => Some("harness_invocation://"),
            Self::ContextCell => Some("context_cell://"),
            Self::ExternalHandle => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLifecycleAuthorityClass {
    Owner,
    GoalKernel,
    Conductor,
    Verifier,
    Daemon,
    Operator,
    Reviewer,
    AutomationController,
    HarnessAdapter,
    ExternalProtocolAdapter,
    Reconciler,
    Governance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkLifecycleRecordType {
    PhaseTransition,
    ChildReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildRelationKind {
    ContextCell,
    ContextLease,
    RuntimeAssignment,
    HarnessInvocation,
    ExternalHandle,
    ChildGoalRun,
    WorkRun,
    AutomationRun,
    WorkResult,
    Receipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildReferenceOperation {
    Attach,
    Detach,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRecoveryClass {
    None,
    Reversible,
    Compensatable,
    Irreversible,
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationIntent {
    pub requested_by_ref: String,
    pub reason: String,
    pub drain_deadline_ms: i64,
    pub compensation_policy_ref: Option<String>,
    pub ambiguous_effect_policy_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTransitionBody {
    pub from_phase: Option<String>,
    pub to_phase: String,
    pub cancellation_intent: Option<CancellationIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildReferenceBody {
    pub operation: ChildReferenceOperation,
    pub relation_kind: ChildRelationKind,
    pub child_ref: String,
    pub effect_recovery_class: EffectRecoveryClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLifecycleRecord {
    pub schema_version: String,
    pub record_id: String,
    pub record_hash: String,
    pub record_type: WorkLifecycleRecordType,
    pub object_kind: WorkLifecycleObjectKind,
    pub object_ref: String,
    pub owner_ref: String,
    pub expected_head: Option<String>,
    pub resulting_head: String,
    pub idempotency_key: String,
    pub authority_class: WorkLifecycleAuthorityClass,
    pub authority_ref: String,
    pub authority_grant_refs: Vec<String>,
    pub decision_receipt_ref: Option<String>,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    #[serde(rename = "phase_transition")]
    pub transition: Option<PhaseTransitionBody>,
    pub child_reference: Option<ChildReferenceBody>,
    pub occurred_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildReferenceProjection {
    pub relation_kind: ChildRelationKind,
    pub child_ref: String,
    pub effect_recovery_class: EffectRecoveryClass,
    pub attached_by_record_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLifecycleProjection {
    pub schema_version: String,
    pub object_kind: WorkLifecycleObjectKind,
    pub object_ref: String,
    pub owner_ref: String,
    pub active_phase: String,
    pub head: String,
    pub last_record_ref: String,
    pub last_occurred_at_ms: i64,
    pub record_count: u64,
    pub active_children: BTreeMap<ChildRelationKind, BTreeMap<String, ChildReferenceProjection>>,
    pub cancellation_intent: Option<CancellationIntent>,
    pub receipt_lineage_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WorkLifecycleState {
    pub projection: Option<WorkLifecycleProjection>,
    pub idempotency_record_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkLifecycleAdmissionOutcome {
    Applied,
    Replay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLifecycleError {
    pub code: &'static str,
    pub message: String,
}

impl WorkLifecycleError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WorkLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WorkLifecycleTransitionRule {
    pub from_phase: Option<&'static str>,
    pub to_phase: &'static str,
    pub authority_classes: &'static [WorkLifecycleAuthorityClass],
}

use WorkLifecycleAuthorityClass as Authority;

const GOAL_RUN_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(None, "draft", &[Authority::Owner, Authority::GoalKernel]),
    rule(Some("draft"), "active", &[Authority::GoalKernel]),
    rule(
        Some("draft"),
        "revoked",
        &[Authority::Owner, Authority::Governance],
    ),
    rule(
        Some("active"),
        "paused",
        &[
            Authority::GoalKernel,
            Authority::Owner,
            Authority::Governance,
        ],
    ),
    rule(Some("active"), "complete", &[Authority::GoalKernel]),
    rule(
        Some("active"),
        "superseded",
        &[Authority::GoalKernel, Authority::Governance],
    ),
    rule(
        Some("active"),
        "revoked",
        &[Authority::Owner, Authority::Governance],
    ),
    rule(
        Some("paused"),
        "active",
        &[Authority::GoalKernel, Authority::Owner],
    ),
    rule(Some("paused"), "complete", &[Authority::GoalKernel]),
    rule(
        Some("paused"),
        "superseded",
        &[Authority::GoalKernel, Authority::Governance],
    ),
    rule(
        Some("paused"),
        "revoked",
        &[Authority::Owner, Authority::Governance],
    ),
    rule(
        Some("complete"),
        "superseded",
        &[Authority::GoalKernel, Authority::Governance],
    ),
];

const GOAL_LOOP_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(None, "receive_intent", &[Authority::GoalKernel]),
    loop_rule("receive_intent", "classify_goal"),
    loop_rule("classify_goal", "gather_grounding"),
    loop_rule("gather_grounding", "inspect_state"),
    loop_rule("inspect_state", "derive_constraints"),
    loop_rule("derive_constraints", "observe_frontier"),
    loop_rule("observe_frontier", "form_hypotheses"),
    loop_rule("form_hypotheses", "select_or_adapt_topology"),
    loop_rule("select_or_adapt_topology", "claim_allocate_or_delegate"),
    loop_rule("claim_allocate_or_delegate", "lease_context"),
    loop_rule("lease_context", "open_context_cells"),
    loop_rule("open_context_cells", "execute_attempt"),
    loop_rule("execute_attempt", "monitor_progress"),
    loop_rule("monitor_progress", "execute_attempt"),
    loop_rule("monitor_progress", "publish_result"),
    loop_rule("publish_result", "verify_compare_or_challenge"),
    rule(
        Some("verify_compare_or_challenge"),
        "repair_or_escalate",
        &[
            Authority::GoalKernel,
            Authority::Conductor,
            Authority::Verifier,
        ],
    ),
    rule(
        Some("verify_compare_or_challenge"),
        "reconcile",
        &[
            Authority::GoalKernel,
            Authority::Conductor,
            Authority::Verifier,
        ],
    ),
    loop_rule("repair_or_escalate", "inspect_state"),
    loop_rule("repair_or_escalate", "select_or_adapt_topology"),
    loop_rule("repair_or_escalate", "execute_attempt"),
    loop_rule("reconcile", "update_frontier_and_memory"),
    loop_rule("update_frontier_and_memory", "continue_or_close"),
    loop_rule("continue_or_close", "observe_frontier"),
    loop_rule("continue_or_close", "form_hypotheses"),
];

const WORK_RUN_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(None, "pending", &[Authority::Daemon]),
    run_rule("pending", "running"),
    cancel_rule("pending", "canceled"),
    run_rule("running", "waiting_for_input"),
    run_rule("running", "ready_for_review"),
    run_rule("running", "stopped"),
    run_rule("running", "completed"),
    run_rule("running", "failed"),
    cancel_rule("running", "canceled"),
    run_rule("waiting_for_input", "running"),
    run_rule("waiting_for_input", "failed"),
    cancel_rule("waiting_for_input", "canceled"),
    rule(
        Some("ready_for_review"),
        "running",
        &[Authority::Reviewer, Authority::Daemon],
    ),
    rule(
        Some("ready_for_review"),
        "completed",
        &[Authority::Reviewer, Authority::Daemon],
    ),
    rule(
        Some("ready_for_review"),
        "failed",
        &[Authority::Reviewer, Authority::Daemon],
    ),
    cancel_rule("ready_for_review", "canceled"),
    run_rule("stopped", "running"),
    run_rule("stopped", "completed"),
    run_rule("stopped", "failed"),
    cancel_rule("stopped", "canceled"),
];

const AUTOMATION_RUN_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(
        None,
        "queued",
        &[Authority::AutomationController, Authority::Daemon],
    ),
    automation_rule("queued", "running"),
    automation_rule("queued", "failed"),
    automation_cancel_rule("queued", "canceled"),
    automation_rule("running", "waiting_for_approval"),
    automation_rule("running", "blocked"),
    automation_rule("running", "succeeded"),
    automation_rule("running", "failed"),
    automation_cancel_rule("running", "canceled"),
    automation_rule("waiting_for_approval", "running"),
    automation_rule("waiting_for_approval", "blocked"),
    automation_cancel_rule("waiting_for_approval", "canceled"),
    automation_rule("blocked", "running"),
    automation_rule("blocked", "failed"),
    automation_cancel_rule("blocked", "canceled"),
    automation_rule("succeeded", "archived"),
    automation_rule("failed", "archived"),
    automation_rule("canceled", "archived"),
];

const HARNESS_INVOCATION_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(None, "queued", &[Authority::Daemon, Authority::Conductor]),
    harness_rule("queued", "running"),
    harness_rule("queued", "failed"),
    harness_cancel_rule("queued", "cancelled"),
    harness_rule("running", "waiting_on_harness"),
    harness_rule("running", "waiting_on_conductor"),
    harness_rule("running", "completed"),
    harness_rule("running", "failed"),
    harness_cancel_rule("running", "cancelled"),
    harness_rule("running", "superseded"),
    harness_rule("waiting_on_harness", "running"),
    harness_rule("waiting_on_harness", "completed"),
    harness_rule("waiting_on_harness", "failed"),
    harness_cancel_rule("waiting_on_harness", "cancelled"),
    harness_rule("waiting_on_conductor", "running"),
    harness_rule("waiting_on_conductor", "completed"),
    harness_rule("waiting_on_conductor", "failed"),
    harness_cancel_rule("waiting_on_conductor", "cancelled"),
    harness_rule("completed", "superseded"),
];

const CONTEXT_CELL_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(None, "open", &[Authority::Conductor, Authority::Daemon]),
    cell_rule("open", "active"),
    cell_rule("open", "sleeping"),
    cell_rule("open", "waiting"),
    cell_rule("open", "handed_off"),
    cell_rule("open", "summarized"),
    cell_rule("open", "quarantined"),
    cell_rule("open", "closed"),
    cell_revoke_rule("open"),
    cell_rule("active", "sleeping"),
    cell_rule("active", "waiting"),
    cell_rule("active", "handed_off"),
    cell_rule("active", "summarized"),
    cell_rule("active", "quarantined"),
    cell_rule("active", "closed"),
    cell_revoke_rule("active"),
    cell_rule("sleeping", "active"),
    cell_rule("sleeping", "waiting"),
    cell_rule("sleeping", "quarantined"),
    cell_rule("sleeping", "closed"),
    cell_revoke_rule("sleeping"),
    cell_rule("waiting", "active"),
    cell_rule("waiting", "handed_off"),
    cell_rule("waiting", "quarantined"),
    cell_rule("waiting", "closed"),
    cell_revoke_rule("waiting"),
    cell_rule("handed_off", "summarized"),
    cell_rule("handed_off", "closed"),
    cell_revoke_rule("handed_off"),
    cell_rule("summarized", "closed"),
    cell_revoke_rule("summarized"),
    cell_rule("quarantined", "active"),
    cell_rule("quarantined", "closed"),
    cell_revoke_rule("quarantined"),
];

const EXTERNAL_HANDLE_RULES: &[WorkLifecycleTransitionRule] = &[
    rule(
        None,
        "requested",
        &[Authority::Daemon, Authority::ExternalProtocolAdapter],
    ),
    external_rule("requested", "acknowledged"),
    external_rule("requested", "running"),
    external_rule("requested", "failed"),
    external_rule("requested", "cancelled"),
    external_rule("requested", "expired"),
    external_rule("requested", "ambiguous"),
    external_rule("acknowledged", "running"),
    external_rule("acknowledged", "waiting"),
    external_rule("acknowledged", "succeeded"),
    external_rule("acknowledged", "failed"),
    external_rule("acknowledged", "cancelled"),
    external_rule("acknowledged", "expired"),
    external_rule("acknowledged", "ambiguous"),
    external_rule("running", "waiting"),
    external_rule("running", "succeeded"),
    external_rule("running", "failed"),
    external_rule("running", "cancelled"),
    external_rule("running", "expired"),
    external_rule("running", "ambiguous"),
    external_rule("waiting", "running"),
    external_rule("waiting", "succeeded"),
    external_rule("waiting", "failed"),
    external_rule("waiting", "cancelled"),
    external_rule("waiting", "expired"),
    external_rule("waiting", "ambiguous"),
    rule(
        Some("ambiguous"),
        "reconciled",
        &[Authority::Reconciler, Authority::Daemon],
    ),
];

const fn rule(
    from_phase: Option<&'static str>,
    to_phase: &'static str,
    authority_classes: &'static [WorkLifecycleAuthorityClass],
) -> WorkLifecycleTransitionRule {
    WorkLifecycleTransitionRule {
        from_phase,
        to_phase,
        authority_classes,
    }
}

const fn loop_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[Authority::GoalKernel, Authority::Conductor],
    )
}

const fn run_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(Some(from), to, &[Authority::Daemon, Authority::Operator])
}

const fn cancel_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[
            Authority::Daemon,
            Authority::Operator,
            Authority::Governance,
        ],
    )
}

const fn automation_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[Authority::AutomationController, Authority::Daemon],
    )
}

const fn automation_cancel_rule(
    from: &'static str,
    to: &'static str,
) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[
            Authority::AutomationController,
            Authority::Daemon,
            Authority::Governance,
        ],
    )
}

const fn harness_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[
            Authority::Daemon,
            Authority::HarnessAdapter,
            Authority::Conductor,
        ],
    )
}

const fn harness_cancel_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[
            Authority::Daemon,
            Authority::Conductor,
            Authority::Governance,
        ],
    )
}

const fn cell_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(Some(from), to, &[Authority::Conductor, Authority::Daemon])
}

const fn cell_revoke_rule(from: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        "revoked",
        &[
            Authority::Daemon,
            Authority::Conductor,
            Authority::Governance,
        ],
    )
}

const fn external_rule(from: &'static str, to: &'static str) -> WorkLifecycleTransitionRule {
    rule(
        Some(from),
        to,
        &[Authority::ExternalProtocolAdapter, Authority::Daemon],
    )
}

pub fn legal_transition_table(
    kind: WorkLifecycleObjectKind,
) -> &'static [WorkLifecycleTransitionRule] {
    match kind {
        WorkLifecycleObjectKind::GoalRun => GOAL_RUN_RULES,
        WorkLifecycleObjectKind::GoalGroundingLoop => GOAL_LOOP_RULES,
        WorkLifecycleObjectKind::WorkRun => WORK_RUN_RULES,
        WorkLifecycleObjectKind::AutomationRun => AUTOMATION_RUN_RULES,
        WorkLifecycleObjectKind::HarnessInvocation => HARNESS_INVOCATION_RULES,
        WorkLifecycleObjectKind::ContextCell => CONTEXT_CELL_RULES,
        WorkLifecycleObjectKind::ExternalHandle => EXTERNAL_HANDLE_RULES,
    }
}

pub fn legal_phases(kind: WorkLifecycleObjectKind) -> BTreeSet<&'static str> {
    legal_transition_table(kind)
        .iter()
        .flat_map(|rule| rule.from_phase.into_iter().chain([rule.to_phase]))
        .collect()
}

pub fn record_content_hash(record: &WorkLifecycleRecord) -> Result<String, WorkLifecycleError> {
    let mut value = serde_json::to_value(record).map_err(|error| {
        WorkLifecycleError::new(
            "work_lifecycle_record_encoding_failed",
            format!("record could not be encoded: {error}"),
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        WorkLifecycleError::new(
            "work_lifecycle_record_encoding_failed",
            "record did not encode as an object",
        )
    })?;
    object.remove("record_hash");
    object.remove("resulting_head");
    sha256_value(&value)
}

pub fn seal_record(record: &mut WorkLifecycleRecord) -> Result<(), WorkLifecycleError> {
    record.record_hash.clear();
    record.resulting_head.clear();
    let hash = record_content_hash(record)?;
    record.record_hash = hash.clone();
    record.resulting_head = hash;
    Ok(())
}

fn sha256_value(value: &Value) -> Result<String, WorkLifecycleError> {
    let bytes = serde_jcs::to_vec(value).map_err(|error| {
        WorkLifecycleError::new(
            "work_lifecycle_canonicalization_failed",
            format!("value could not be canonically encoded: {error}"),
        )
    })?;
    let mut hash = Sha256::new();
    hash.update(bytes);
    Ok(format!("sha256:{:x}", hash.finalize()))
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn validate_record_integrity(record: &WorkLifecycleRecord) -> Result<(), WorkLifecycleError> {
    if record.schema_version != WORK_LIFECYCLE_RECORD_SCHEMA {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_schema_invalid",
            "work lifecycle record schema is missing or unsupported",
        ));
    }
    for (field, value) in [
        ("record_id", record.record_id.as_str()),
        ("object_ref", record.object_ref.as_str()),
        ("owner_ref", record.owner_ref.as_str()),
        ("idempotency_key", record.idempotency_key.as_str()),
        ("authority_ref", record.authority_ref.as_str()),
    ] {
        if !nonempty(value) {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_required_field_missing",
                format!("{field} is empty"),
            ));
        }
    }
    if !record.record_id.starts_with("work-lifecycle://") {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_record_ref_invalid",
            "record_id must use the work-lifecycle:// canonical identity scheme",
        ));
    }
    if record.occurred_at_ms <= 0 {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_time_invalid",
            "occurred_at_ms must be positive",
        ));
    }
    if let Some(prefix) = record.object_kind.expected_ref_prefix() {
        if !record.object_ref.starts_with(prefix) {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_object_ref_kind_mismatch",
                format!(
                    "{:?} object ref must start with {prefix}",
                    record.object_kind
                ),
            ));
        }
    }
    let computed = record_content_hash(record)?;
    if record.record_hash != computed || record.resulting_head != computed {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_record_hash_mismatch",
            "record hash and resulting head must equal the exact content commitment",
        ));
    }
    let mut grants = BTreeSet::new();
    if record.authority_grant_refs.is_empty()
        || record
            .authority_grant_refs
            .iter()
            .any(|grant| !nonempty(grant) || !grants.insert(grant.as_str()))
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_authority_grants_invalid",
            "authority grant refs must be nonempty and unique",
        ));
    }
    let mut evidence = BTreeSet::new();
    if record
        .evidence_refs
        .iter()
        .any(|evidence_ref| !nonempty(evidence_ref) || !evidence.insert(evidence_ref.as_str()))
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_evidence_invalid",
            "evidence refs must be nonempty and unique when present",
        ));
    }
    if record
        .decision_receipt_ref
        .as_deref()
        .is_some_and(|receipt| !nonempty(receipt))
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_decision_receipt_invalid",
            "decision receipt ref cannot be empty",
        ));
    }
    let mut receipts = BTreeSet::new();
    if record.receipt_refs.is_empty()
        || record
            .receipt_refs
            .iter()
            .any(|receipt| !nonempty(receipt) || !receipts.insert(receipt.as_str()))
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_receipts_invalid",
            "every lifecycle fact requires nonempty unique receipt refs",
        ));
    }
    match record.record_type {
        WorkLifecycleRecordType::PhaseTransition
            if record.transition.is_some() && record.child_reference.is_none() => {}
        WorkLifecycleRecordType::ChildReference
            if record.transition.is_none() && record.child_reference.is_some() => {}
        _ => {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_record_body_invalid",
                "record type must have exactly its matching transition or child-reference body",
            ));
        }
    }
    Ok(())
}

fn reference_authority_allowed(
    kind: WorkLifecycleObjectKind,
    authority: WorkLifecycleAuthorityClass,
) -> bool {
    match kind {
        WorkLifecycleObjectKind::GoalRun => matches!(
            authority,
            Authority::GoalKernel | Authority::Conductor | Authority::Governance
        ),
        WorkLifecycleObjectKind::GoalGroundingLoop => {
            matches!(authority, Authority::GoalKernel | Authority::Conductor)
        }
        WorkLifecycleObjectKind::WorkRun => {
            matches!(authority, Authority::Daemon | Authority::Operator)
        }
        WorkLifecycleObjectKind::AutomationRun => matches!(
            authority,
            Authority::AutomationController | Authority::Daemon
        ),
        WorkLifecycleObjectKind::HarnessInvocation => matches!(
            authority,
            Authority::Daemon | Authority::HarnessAdapter | Authority::Conductor
        ),
        WorkLifecycleObjectKind::ContextCell => {
            matches!(authority, Authority::Conductor | Authority::Daemon)
        }
        WorkLifecycleObjectKind::ExternalHandle => matches!(
            authority,
            Authority::ExternalProtocolAdapter | Authority::Daemon | Authority::Reconciler
        ),
    }
}

fn cancellation_required(kind: WorkLifecycleObjectKind, to_phase: &str) -> bool {
    matches!(
        (kind, to_phase),
        (WorkLifecycleObjectKind::GoalRun, "revoked")
            | (WorkLifecycleObjectKind::WorkRun, "canceled")
            | (WorkLifecycleObjectKind::AutomationRun, "canceled")
            | (WorkLifecycleObjectKind::HarnessInvocation, "cancelled")
            | (WorkLifecycleObjectKind::ContextCell, "revoked")
            | (WorkLifecycleObjectKind::ExternalHandle, "cancelled")
    )
}

fn validate_cancellation_intent(
    intent: &CancellationIntent,
    occurred_at_ms: i64,
) -> Result<(), WorkLifecycleError> {
    if !nonempty(&intent.requested_by_ref)
        || !nonempty(&intent.reason)
        || intent.drain_deadline_ms <= occurred_at_ms
        || intent
            .compensation_policy_ref
            .as_deref()
            .is_some_and(|value| !nonempty(value))
        || intent
            .ambiguous_effect_policy_ref
            .as_deref()
            .is_some_and(|value| !nonempty(value))
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_cancellation_intent_invalid",
            "cancellation intent requires requester, reason, a future drain deadline, and nonempty policy refs when present",
        ));
    }
    Ok(())
}

fn validate_cancellation_recovery_policies(
    projection: Option<&WorkLifecycleProjection>,
    intent: &CancellationIntent,
) -> Result<(), WorkLifecycleError> {
    let recovery_classes = projection
        .into_iter()
        .flat_map(|projection| projection.active_children.values())
        .flat_map(|children| children.values())
        .map(|child| child.effect_recovery_class)
        .collect::<BTreeSet<_>>();
    if recovery_classes.contains(&EffectRecoveryClass::Compensatable)
        && intent.compensation_policy_ref.is_none()
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_compensation_policy_required",
            "canceling an owner with compensatable active effects requires a compensation policy ref",
        ));
    }
    if (recovery_classes.contains(&EffectRecoveryClass::Ambiguous)
        || recovery_classes.contains(&EffectRecoveryClass::Irreversible))
        && intent.ambiguous_effect_policy_ref.is_none()
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_effect_reconciliation_policy_required",
            "canceling an owner with ambiguous or irreversible active effects requires an effect-reconciliation policy ref",
        ));
    }
    Ok(())
}

fn expected_child_ref_prefix(relation: ChildRelationKind) -> Option<&'static str> {
    match relation {
        ChildRelationKind::ContextCell => Some("context_cell://"),
        ChildRelationKind::ContextLease => Some("context_lease://"),
        ChildRelationKind::RuntimeAssignment => Some("runtime-assignment://"),
        ChildRelationKind::HarnessInvocation => Some("harness_invocation://"),
        ChildRelationKind::ExternalHandle => None,
        ChildRelationKind::ChildGoalRun => Some("goal://"),
        ChildRelationKind::WorkRun => Some("work_run://"),
        ChildRelationKind::AutomationRun => Some("automation-run://"),
        ChildRelationKind::WorkResult => Some("work-result://"),
        ChildRelationKind::Receipt => Some("receipt://"),
    }
}

pub fn admit_work_lifecycle_record(
    state: &mut WorkLifecycleState,
    record: &WorkLifecycleRecord,
) -> Result<WorkLifecycleAdmissionOutcome, WorkLifecycleError> {
    validate_record_integrity(record)?;
    if let Some(existing_hash) = state.idempotency_record_hashes.get(&record.idempotency_key) {
        if existing_hash == &record.record_hash {
            return Ok(WorkLifecycleAdmissionOutcome::Replay);
        }
        return Err(WorkLifecycleError::new(
            "work_lifecycle_idempotency_conflict",
            "same object-scoped idempotency key was already used for different record bytes",
        ));
    }

    let current = state.projection.as_ref();
    if let Some(current) = current {
        if current.object_kind != record.object_kind
            || current.object_ref != record.object_ref
            || current.owner_ref != record.owner_ref
        {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_owner_binding_mismatch",
                "record object kind/ref/owner does not equal durable projection truth",
            ));
        }
        if record.expected_head.as_deref() != Some(current.head.as_str()) {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_expected_head_conflict",
                "record expected head does not equal the durable object head",
            ));
        }
        if record.occurred_at_ms < current.last_occurred_at_ms {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_time_regression",
                "successor occurred_at_ms precedes the current durable record time",
            ));
        }
    } else if record.expected_head.is_some() {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_genesis_head_invalid",
            "first lifecycle record must not claim an expected head",
        ));
    }

    let mut next = current.cloned().unwrap_or_else(|| WorkLifecycleProjection {
        schema_version: WORK_LIFECYCLE_PROJECTION_SCHEMA.into(),
        object_kind: record.object_kind,
        object_ref: record.object_ref.clone(),
        owner_ref: record.owner_ref.clone(),
        active_phase: String::new(),
        head: String::new(),
        last_record_ref: String::new(),
        last_occurred_at_ms: 0,
        record_count: 0,
        active_children: BTreeMap::new(),
        cancellation_intent: None,
        receipt_lineage_refs: BTreeSet::new(),
    });

    match record.record_type {
        WorkLifecycleRecordType::PhaseTransition => {
            let transition = record.transition.as_ref().expect("integrity checked");
            if transition.to_phase.trim().is_empty()
                || transition.from_phase.as_deref()
                    != current.map(|projection| projection.active_phase.as_str())
            {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_from_phase_conflict",
                    "transition from phase does not equal the active phase",
                ));
            }
            let rule = legal_transition_table(record.object_kind)
                .iter()
                .find(|rule| {
                    rule.from_phase == transition.from_phase.as_deref()
                        && rule.to_phase == transition.to_phase
                })
                .ok_or_else(|| {
                    WorkLifecycleError::new(
                        "work_lifecycle_transition_illegal",
                        format!(
                            "{:?} transition {:?} -> {} is not legal",
                            record.object_kind, transition.from_phase, transition.to_phase
                        ),
                    )
                })?;
            if !rule.authority_classes.contains(&record.authority_class) {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_transition_authority_denied",
                    "authority class is not permitted for this owner-specific transition",
                ));
            }
            if cancellation_required(record.object_kind, &transition.to_phase) {
                let intent = transition.cancellation_intent.as_ref().ok_or_else(|| {
                    WorkLifecycleError::new(
                        "work_lifecycle_cancellation_intent_required",
                        "cancel/revoke transition requires a bounded cancellation intent",
                    )
                })?;
                validate_cancellation_intent(intent, record.occurred_at_ms)?;
                validate_cancellation_recovery_policies(current, intent)?;
            } else if transition.cancellation_intent.is_some() {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_cancellation_intent_unexpected",
                    "cancellation intent is valid only on a declared cancel or revoke transition",
                ));
            }
            next.active_phase.clone_from(&transition.to_phase);
            if transition.cancellation_intent.is_some() {
                next.cancellation_intent = transition.cancellation_intent.clone();
            }
        }
        WorkLifecycleRecordType::ChildReference => {
            if current.is_none() {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_reference_before_genesis",
                    "child references require an existing owner object lifecycle",
                ));
            }
            if !reference_authority_allowed(record.object_kind, record.authority_class) {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_reference_authority_denied",
                    "authority class cannot mutate this owner's reference index",
                ));
            }
            let reference = record.child_reference.as_ref().expect("integrity checked");
            if !nonempty(&reference.child_ref) {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_child_ref_invalid",
                    "child ref is empty",
                ));
            }
            if expected_child_ref_prefix(reference.relation_kind)
                .is_some_and(|prefix| !reference.child_ref.starts_with(prefix))
            {
                return Err(WorkLifecycleError::new(
                    "work_lifecycle_child_ref_kind_mismatch",
                    "child ref does not use the canonical identity scheme for its declared relation kind",
                ));
            }
            let children = next
                .active_children
                .entry(reference.relation_kind)
                .or_default();
            match reference.operation {
                ChildReferenceOperation::Attach => {
                    if children.contains_key(&reference.child_ref) {
                        return Err(WorkLifecycleError::new(
                            "work_lifecycle_child_already_attached",
                            "child is already active; exact replay must use the original idempotency key",
                        ));
                    }
                    children.insert(
                        reference.child_ref.clone(),
                        ChildReferenceProjection {
                            relation_kind: reference.relation_kind,
                            child_ref: reference.child_ref.clone(),
                            effect_recovery_class: reference.effect_recovery_class,
                            attached_by_record_ref: record.record_id.clone(),
                        },
                    );
                }
                ChildReferenceOperation::Detach => {
                    if children.remove(&reference.child_ref).is_none() {
                        return Err(WorkLifecycleError::new(
                            "work_lifecycle_child_not_attached",
                            "detach requires an active child reference",
                        ));
                    }
                }
            }
        }
    }

    next.head.clone_from(&record.resulting_head);
    next.last_record_ref.clone_from(&record.record_id);
    next.last_occurred_at_ms = record.occurred_at_ms;
    next.record_count = next.record_count.saturating_add(1);
    next.receipt_lineage_refs
        .extend(record.receipt_refs.iter().cloned());
    if let Some(decision) = record.decision_receipt_ref.as_ref() {
        next.receipt_lineage_refs.insert(decision.clone());
    }
    state
        .idempotency_record_hashes
        .insert(record.idempotency_key.clone(), record.record_hash.clone());
    state.projection = Some(next);
    Ok(WorkLifecycleAdmissionOutcome::Applied)
}

pub fn replay_work_lifecycle_records(
    records: &[WorkLifecycleRecord],
) -> Result<WorkLifecycleState, WorkLifecycleError> {
    let mut state = WorkLifecycleState::default();
    for record in records {
        let outcome = admit_work_lifecycle_record(&mut state, record)?;
        if outcome != WorkLifecycleAdmissionOutcome::Applied {
            return Err(WorkLifecycleError::new(
                "work_lifecycle_duplicate_record_in_log",
                "append-only log contains an idempotent duplicate instead of one canonical fact",
            ));
        }
    }
    Ok(state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationActionKind {
    RequestCancel,
    Drain,
    Fence,
    RevokeLease,
    CloseContext,
    WaitUntilTimeout,
    Rollback,
    Compensate,
    ReconcileAmbiguousEffect,
    ReconcileIrreversibleEffect,
    PreserveReceiptLineage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationTargetPlan {
    pub relation_kind: ChildRelationKind,
    pub target_ref: String,
    pub actions: Vec<CancellationActionKind>,
    pub timeout_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationFanoutPlan {
    pub schema_version: String,
    pub object_ref: String,
    pub source_head: String,
    pub requested_by_ref: String,
    pub reason: String,
    pub compensation_policy_ref: Option<String>,
    pub effect_reconciliation_policy_ref: Option<String>,
    pub targets: Vec<CancellationTargetPlan>,
    pub requires_completion_receipt: bool,
}

pub fn plan_cancellation_fanout(
    state: &WorkLifecycleState,
) -> Result<CancellationFanoutPlan, WorkLifecycleError> {
    let projection = state.projection.as_ref().ok_or_else(|| {
        WorkLifecycleError::new(
            "work_lifecycle_projection_missing",
            "cancellation fanout requires an admitted owner projection",
        )
    })?;
    let intent = projection.cancellation_intent.as_ref().ok_or_else(|| {
        WorkLifecycleError::new(
            "work_lifecycle_cancellation_intent_missing",
            "owner projection has no admitted cancellation intent",
        )
    })?;
    let mut targets = Vec::new();
    for children in projection.active_children.values() {
        for child in children.values() {
            let mut actions = match child.relation_kind {
                ChildRelationKind::ContextCell => vec![
                    CancellationActionKind::Drain,
                    CancellationActionKind::CloseContext,
                ],
                ChildRelationKind::ContextLease => vec![
                    CancellationActionKind::RevokeLease,
                    CancellationActionKind::Fence,
                ],
                ChildRelationKind::RuntimeAssignment => vec![
                    CancellationActionKind::Drain,
                    CancellationActionKind::Fence,
                    CancellationActionKind::WaitUntilTimeout,
                ],
                ChildRelationKind::HarnessInvocation
                | ChildRelationKind::ExternalHandle
                | ChildRelationKind::ChildGoalRun
                | ChildRelationKind::WorkRun
                | ChildRelationKind::AutomationRun => vec![
                    CancellationActionKind::RequestCancel,
                    CancellationActionKind::Drain,
                    CancellationActionKind::Fence,
                    CancellationActionKind::WaitUntilTimeout,
                ],
                ChildRelationKind::WorkResult | ChildRelationKind::Receipt => {
                    vec![CancellationActionKind::PreserveReceiptLineage]
                }
            };
            match child.effect_recovery_class {
                EffectRecoveryClass::None => {}
                EffectRecoveryClass::Reversible => actions.push(CancellationActionKind::Rollback),
                EffectRecoveryClass::Compensatable => {
                    actions.push(CancellationActionKind::Compensate)
                }
                EffectRecoveryClass::Irreversible => {
                    actions.push(CancellationActionKind::ReconcileIrreversibleEffect)
                }
                EffectRecoveryClass::Ambiguous => {
                    actions.push(CancellationActionKind::ReconcileAmbiguousEffect)
                }
            }
            actions.sort_by_key(|action| *action as u8);
            actions.dedup();
            let timeout_at_ms = actions
                .contains(&CancellationActionKind::WaitUntilTimeout)
                .then_some(intent.drain_deadline_ms);
            targets.push(CancellationTargetPlan {
                relation_kind: child.relation_kind,
                target_ref: child.child_ref.clone(),
                actions,
                timeout_at_ms,
            });
        }
    }
    targets.sort_by(|left, right| {
        (left.relation_kind, left.target_ref.as_str())
            .cmp(&(right.relation_kind, right.target_ref.as_str()))
    });
    Ok(CancellationFanoutPlan {
        schema_version: CANCELLATION_FANOUT_PLAN_SCHEMA.into(),
        object_ref: projection.object_ref.clone(),
        source_head: projection.head.clone(),
        requested_by_ref: intent.requested_by_ref.clone(),
        reason: intent.reason.clone(),
        compensation_policy_ref: intent.compensation_policy_ref.clone(),
        effect_reconciliation_policy_ref: intent.ambiguous_effect_policy_ref.clone(),
        targets,
        requires_completion_receipt: true,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLifecycleArchiveSegment {
    pub schema_version: String,
    pub archive_ref: String,
    pub object_kind: WorkLifecycleObjectKind,
    pub object_ref: String,
    pub through_head: String,
    pub archive_root: String,
    pub records: Vec<WorkLifecycleRecord>,
    pub receipt_lineage_refs: BTreeSet<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLifecycleSnapshot {
    pub schema_version: String,
    pub snapshot_ref: String,
    pub archive_ref: String,
    pub archive_root: String,
    pub through_head: String,
    pub resume_state: WorkLifecycleState,
    pub receipt_lineage_refs: BTreeSet<String>,
    pub created_at_ms: i64,
}

pub fn build_snapshot_and_archive(
    records: &[WorkLifecycleRecord],
    archive_ref: &str,
    snapshot_ref: &str,
    created_at_ms: i64,
) -> Result<(WorkLifecycleArchiveSegment, WorkLifecycleSnapshot), WorkLifecycleError> {
    if records.is_empty()
        || !archive_ref.starts_with("work-lifecycle-archive://")
        || !snapshot_ref.starts_with("work-lifecycle-snapshot://")
        || created_at_ms <= 0
    {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_compaction_input_invalid",
            "snapshot/archive requires records, canonical refs, and a positive creation time",
        ));
    }
    let state = replay_work_lifecycle_records(records)?;
    let projection = state.projection.as_ref().expect("nonempty replay");
    if created_at_ms < projection.last_occurred_at_ms {
        return Err(WorkLifecycleError::new(
            "work_lifecycle_compaction_time_regression",
            "snapshot/archive creation time precedes the compacted durable head",
        ));
    }
    let through_head = projection.head.clone();
    let receipt_lineage_refs = projection.receipt_lineage_refs.clone();
    let archive_root = sha256_value(&serde_json::to_value(records).map_err(|error| {
        WorkLifecycleError::new(
            "work_lifecycle_archive_encoding_failed",
            format!("archive records could not be encoded: {error}"),
        )
    })?)?;
    let archive = WorkLifecycleArchiveSegment {
        schema_version: WORK_LIFECYCLE_ARCHIVE_SCHEMA.into(),
        archive_ref: archive_ref.into(),
        object_kind: projection.object_kind,
        object_ref: projection.object_ref.clone(),
        through_head: through_head.clone(),
        archive_root: archive_root.clone(),
        records: records.to_vec(),
        receipt_lineage_refs: receipt_lineage_refs.clone(),
        created_at_ms,
    };
    let snapshot = WorkLifecycleSnapshot {
        schema_version: WORK_LIFECYCLE_SNAPSHOT_SCHEMA.into(),
        snapshot_ref: snapshot_ref.into(),
        archive_ref: archive_ref.into(),
        archive_root,
        through_head,
        resume_state: state,
        receipt_lineage_refs,
        created_at_ms,
    };
    Ok((archive, snapshot))
}

/// Independent matcher used by tests/conformance to catch drift in the table
/// implementation. It intentionally does not read the table above.
pub fn reference_transition_is_legal(
    kind: WorkLifecycleObjectKind,
    from: Option<&str>,
    to: &str,
) -> bool {
    match kind {
        WorkLifecycleObjectKind::GoalRun => matches!(
            (from, to),
            (None, "draft")
                | (Some("draft"), "active" | "revoked")
                | (
                    Some("active"),
                    "paused" | "complete" | "superseded" | "revoked"
                )
                | (
                    Some("paused"),
                    "active" | "complete" | "superseded" | "revoked"
                )
                | (Some("complete"), "superseded")
        ),
        WorkLifecycleObjectKind::GoalGroundingLoop => matches!(
            (from, to),
            (None, "receive_intent")
                | (Some("receive_intent"), "classify_goal")
                | (Some("classify_goal"), "gather_grounding")
                | (Some("gather_grounding"), "inspect_state")
                | (Some("inspect_state"), "derive_constraints")
                | (Some("derive_constraints"), "observe_frontier")
                | (Some("observe_frontier"), "form_hypotheses")
                | (Some("form_hypotheses"), "select_or_adapt_topology")
                | (
                    Some("select_or_adapt_topology"),
                    "claim_allocate_or_delegate"
                )
                | (Some("claim_allocate_or_delegate"), "lease_context")
                | (Some("lease_context"), "open_context_cells")
                | (Some("open_context_cells"), "execute_attempt")
                | (Some("execute_attempt"), "monitor_progress")
                | (
                    Some("monitor_progress"),
                    "execute_attempt" | "publish_result"
                )
                | (Some("publish_result"), "verify_compare_or_challenge")
                | (
                    Some("verify_compare_or_challenge"),
                    "repair_or_escalate" | "reconcile"
                )
                | (
                    Some("repair_or_escalate"),
                    "inspect_state" | "select_or_adapt_topology" | "execute_attempt"
                )
                | (Some("reconcile"), "update_frontier_and_memory")
                | (Some("update_frontier_and_memory"), "continue_or_close")
                | (
                    Some("continue_or_close"),
                    "observe_frontier" | "form_hypotheses"
                )
        ),
        WorkLifecycleObjectKind::WorkRun => matches!(
            (from, to),
            (None, "pending")
                | (Some("pending"), "running" | "canceled")
                | (
                    Some("running"),
                    "waiting_for_input"
                        | "ready_for_review"
                        | "stopped"
                        | "completed"
                        | "failed"
                        | "canceled"
                )
                | (Some("waiting_for_input"), "running" | "failed" | "canceled")
                | (
                    Some("ready_for_review"),
                    "running" | "completed" | "failed" | "canceled"
                )
                | (
                    Some("stopped"),
                    "running" | "completed" | "failed" | "canceled"
                )
        ),
        WorkLifecycleObjectKind::AutomationRun => matches!(
            (from, to),
            (None, "queued")
                | (Some("queued"), "running" | "failed" | "canceled")
                | (
                    Some("running"),
                    "waiting_for_approval" | "blocked" | "succeeded" | "failed" | "canceled"
                )
                | (
                    Some("waiting_for_approval"),
                    "running" | "blocked" | "canceled"
                )
                | (Some("blocked"), "running" | "failed" | "canceled")
                | (Some("succeeded" | "failed" | "canceled"), "archived")
        ),
        WorkLifecycleObjectKind::HarnessInvocation => matches!(
            (from, to),
            (None, "queued")
                | (Some("queued"), "running" | "failed" | "cancelled")
                | (
                    Some("running"),
                    "waiting_on_harness"
                        | "waiting_on_conductor"
                        | "completed"
                        | "failed"
                        | "cancelled"
                        | "superseded"
                )
                | (
                    Some("waiting_on_harness" | "waiting_on_conductor"),
                    "running" | "completed" | "failed" | "cancelled"
                )
                | (Some("completed"), "superseded")
        ),
        WorkLifecycleObjectKind::ContextCell => matches!(
            (from, to),
            (None, "open")
                | (
                    Some("open"),
                    "active"
                        | "sleeping"
                        | "waiting"
                        | "handed_off"
                        | "summarized"
                        | "quarantined"
                        | "closed"
                        | "revoked"
                )
                | (
                    Some("active"),
                    "sleeping"
                        | "waiting"
                        | "handed_off"
                        | "summarized"
                        | "quarantined"
                        | "closed"
                        | "revoked"
                )
                | (
                    Some("sleeping"),
                    "active" | "waiting" | "quarantined" | "closed" | "revoked"
                )
                | (
                    Some("waiting"),
                    "active" | "handed_off" | "quarantined" | "closed" | "revoked"
                )
                | (Some("handed_off"), "summarized" | "closed" | "revoked")
                | (Some("summarized"), "closed" | "revoked")
                | (Some("quarantined"), "active" | "closed" | "revoked")
        ),
        WorkLifecycleObjectKind::ExternalHandle => matches!(
            (from, to),
            (None, "requested")
                | (
                    Some("requested"),
                    "acknowledged" | "running" | "failed" | "cancelled" | "expired" | "ambiguous"
                )
                | (
                    Some("acknowledged"),
                    "running"
                        | "waiting"
                        | "succeeded"
                        | "failed"
                        | "cancelled"
                        | "expired"
                        | "ambiguous"
                )
                | (
                    Some("running"),
                    "waiting" | "succeeded" | "failed" | "cancelled" | "expired" | "ambiguous"
                )
                | (
                    Some("waiting"),
                    "running" | "succeeded" | "failed" | "cancelled" | "expired" | "ambiguous"
                )
                | (Some("ambiguous"), "reconciled")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ref_for(kind: WorkLifecycleObjectKind) -> &'static str {
        match kind {
            WorkLifecycleObjectKind::GoalRun => "goal://one",
            WorkLifecycleObjectKind::GoalGroundingLoop => "goal_loop://one",
            WorkLifecycleObjectKind::WorkRun => "work_run://one",
            WorkLifecycleObjectKind::AutomationRun => "automation-run://one",
            WorkLifecycleObjectKind::HarnessInvocation => "harness_invocation://one",
            WorkLifecycleObjectKind::ContextCell => "context_cell://one",
            WorkLifecycleObjectKind::ExternalHandle => "mcp-task://opaque/one",
        }
    }

    fn authority_for(kind: WorkLifecycleObjectKind) -> WorkLifecycleAuthorityClass {
        match kind {
            WorkLifecycleObjectKind::GoalRun | WorkLifecycleObjectKind::GoalGroundingLoop => {
                Authority::GoalKernel
            }
            WorkLifecycleObjectKind::WorkRun => Authority::Daemon,
            WorkLifecycleObjectKind::AutomationRun => Authority::AutomationController,
            WorkLifecycleObjectKind::HarnessInvocation => Authority::Daemon,
            WorkLifecycleObjectKind::ContextCell => Authority::Conductor,
            WorkLifecycleObjectKind::ExternalHandle => Authority::ExternalProtocolAdapter,
        }
    }

    fn transition_record(
        kind: WorkLifecycleObjectKind,
        record_id: &str,
        from: Option<&str>,
        to: &str,
        expected_head: Option<String>,
        idempotency_key: &str,
    ) -> WorkLifecycleRecord {
        let occurred_at_ms = if expected_head.is_some() {
            1_200
        } else {
            1_000
        };
        let mut record = WorkLifecycleRecord {
            schema_version: WORK_LIFECYCLE_RECORD_SCHEMA.into(),
            record_id: record_id.into(),
            record_hash: String::new(),
            record_type: WorkLifecycleRecordType::PhaseTransition,
            object_kind: kind,
            object_ref: ref_for(kind).into(),
            owner_ref: "system://owner".into(),
            expected_head,
            resulting_head: String::new(),
            idempotency_key: idempotency_key.into(),
            authority_class: authority_for(kind),
            authority_ref: "authority://one".into(),
            authority_grant_refs: vec!["grant://one".into()],
            decision_receipt_ref: None,
            evidence_refs: vec!["evidence://one".into()],
            receipt_refs: vec![format!("receipt://{record_id}")],
            transition: Some(PhaseTransitionBody {
                from_phase: from.map(str::to_string),
                to_phase: to.into(),
                cancellation_intent: None,
            }),
            child_reference: None,
            occurred_at_ms,
        };
        seal_record(&mut record).unwrap();
        record
    }

    fn child_record(
        state: &WorkLifecycleState,
        record_id: &str,
        operation: ChildReferenceOperation,
        relation_kind: ChildRelationKind,
        child_ref: &str,
        recovery: EffectRecoveryClass,
    ) -> WorkLifecycleRecord {
        let projection = state.projection.as_ref().unwrap();
        let mut record = WorkLifecycleRecord {
            schema_version: WORK_LIFECYCLE_RECORD_SCHEMA.into(),
            record_id: record_id.into(),
            record_hash: String::new(),
            record_type: WorkLifecycleRecordType::ChildReference,
            object_kind: projection.object_kind,
            object_ref: projection.object_ref.clone(),
            owner_ref: projection.owner_ref.clone(),
            expected_head: Some(projection.head.clone()),
            resulting_head: String::new(),
            idempotency_key: record_id.into(),
            authority_class: authority_for(projection.object_kind),
            authority_ref: "authority://one".into(),
            authority_grant_refs: vec!["grant://one".into()],
            decision_receipt_ref: None,
            evidence_refs: vec![],
            receipt_refs: vec![format!("receipt://{record_id}")],
            transition: None,
            child_reference: Some(ChildReferenceBody {
                operation,
                relation_kind,
                child_ref: child_ref.into(),
                effect_recovery_class: recovery,
            }),
            occurred_at_ms: 1_100,
        };
        seal_record(&mut record).unwrap();
        record
    }

    #[test]
    fn independent_reference_and_table_legality_match_exhaustively() {
        for kind in WorkLifecycleObjectKind::ALL {
            let mut phases: Vec<&str> = legal_phases(kind).into_iter().collect();
            phases.push("__unknown__");
            let mut froms = vec![None];
            froms.extend(phases.iter().copied().map(Some));
            for from in froms {
                for to in &phases {
                    let table = legal_transition_table(kind)
                        .iter()
                        .any(|rule| rule.from_phase == from && rule.to_phase == *to);
                    assert_eq!(
                        table,
                        reference_transition_is_legal(kind, from, to),
                        "legality drift for {kind:?} {from:?}->{to}"
                    );
                }
            }
        }
    }

    #[test]
    fn exact_head_and_idempotency_replay_or_conflict() {
        let mut state = WorkLifecycleState::default();
        let genesis = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://one/1",
            None,
            "pending",
            None,
            "idem-1",
        );
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &genesis).unwrap(),
            WorkLifecycleAdmissionOutcome::Applied
        );
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &genesis).unwrap(),
            WorkLifecycleAdmissionOutcome::Replay
        );
        let mut conflict = genesis.clone();
        conflict.record_id = "work-lifecycle://one/conflict".into();
        conflict.receipt_refs = vec!["receipt://conflict".into()];
        seal_record(&mut conflict).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &conflict)
                .unwrap_err()
                .code,
            "work_lifecycle_idempotency_conflict"
        );

        let head = state.projection.as_ref().unwrap().head.clone();
        let running = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://one/2",
            Some("pending"),
            "running",
            Some(head.clone()),
            "idem-2",
        );
        admit_work_lifecycle_record(&mut state, &running).unwrap();
        let stale = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://one/3",
            Some("running"),
            "failed",
            Some(head),
            "idem-3",
        );
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &stale)
                .unwrap_err()
                .code,
            "work_lifecycle_expected_head_conflict"
        );
    }

    #[test]
    fn canonical_refs_and_monotonic_time_fail_closed() {
        let mut invalid_id = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://validation/invalid-id",
            None,
            "pending",
            None,
            "validation-invalid-id",
        );
        invalid_id.record_id = "raw-record-id".into();
        seal_record(&mut invalid_id).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut WorkLifecycleState::default(), &invalid_id)
                .unwrap_err()
                .code,
            "work_lifecycle_record_ref_invalid"
        );

        let mut state = WorkLifecycleState::default();
        let genesis = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://validation/1",
            None,
            "pending",
            None,
            "validation-1",
        );
        admit_work_lifecycle_record(&mut state, &genesis).unwrap();
        let wrong_child = child_record(
            &state,
            "work-lifecycle://validation/2",
            ChildReferenceOperation::Attach,
            ChildRelationKind::HarnessInvocation,
            "work_run://wrong-kind",
            EffectRecoveryClass::None,
        );
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &wrong_child)
                .unwrap_err()
                .code,
            "work_lifecycle_child_ref_kind_mismatch"
        );

        let mut regressed = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://validation/3",
            Some("pending"),
            "running",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "validation-3",
        );
        regressed.occurred_at_ms = 999;
        seal_record(&mut regressed).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &regressed)
                .unwrap_err()
                .code,
            "work_lifecycle_time_regression"
        );
    }

    #[test]
    fn kind_specific_legality_and_authority_do_not_flatten() {
        let mut state = WorkLifecycleState::default();
        let genesis = transition_record(
            WorkLifecycleObjectKind::GoalRun,
            "work-lifecycle://goal/1",
            None,
            "draft",
            None,
            "goal-1",
        );
        admit_work_lifecycle_record(&mut state, &genesis).unwrap();
        let mut illegal = transition_record(
            WorkLifecycleObjectKind::GoalRun,
            "work-lifecycle://goal/2",
            Some("draft"),
            "running",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "goal-2",
        );
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &illegal)
                .unwrap_err()
                .code,
            "work_lifecycle_transition_illegal"
        );
        illegal.transition.as_mut().unwrap().to_phase = "active".into();
        illegal.authority_class = Authority::HarnessAdapter;
        seal_record(&mut illegal).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &illegal)
                .unwrap_err()
                .code,
            "work_lifecycle_transition_authority_denied"
        );
    }

    #[test]
    fn cancellation_fanout_includes_drain_fence_timeout_compensation_and_reconciliation() {
        let mut state = WorkLifecycleState::default();
        let genesis = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://cancel/1",
            None,
            "pending",
            None,
            "cancel-1",
        );
        admit_work_lifecycle_record(&mut state, &genesis).unwrap();
        for (id, relation, child, recovery) in [
            (
                "work-lifecycle://cancel/child-1",
                ChildRelationKind::HarnessInvocation,
                "harness_invocation://one",
                EffectRecoveryClass::Compensatable,
            ),
            (
                "work-lifecycle://cancel/child-2",
                ChildRelationKind::ExternalHandle,
                "mcp-task://opaque/one",
                EffectRecoveryClass::Ambiguous,
            ),
            (
                "work-lifecycle://cancel/child-3",
                ChildRelationKind::ContextLease,
                "context_lease://one",
                EffectRecoveryClass::None,
            ),
        ] {
            let record = child_record(
                &state,
                id,
                ChildReferenceOperation::Attach,
                relation,
                child,
                recovery,
            );
            admit_work_lifecycle_record(&mut state, &record).unwrap();
        }
        let mut cancel = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://cancel/2",
            Some("pending"),
            "canceled",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "cancel-2",
        );
        cancel.transition.as_mut().unwrap().cancellation_intent = Some(CancellationIntent {
            requested_by_ref: "user://operator".into(),
            reason: "operator_stop".into(),
            drain_deadline_ms: 20_000,
            compensation_policy_ref: Some("policy://compensate".into()),
            ambiguous_effect_policy_ref: Some("policy://reconcile".into()),
        });
        seal_record(&mut cancel).unwrap();
        admit_work_lifecycle_record(&mut state, &cancel).unwrap();
        let plan = plan_cancellation_fanout(&state).unwrap();
        assert_eq!(plan.targets.len(), 3);
        assert!(plan
            .targets
            .iter()
            .any(|target| { target.actions.contains(&CancellationActionKind::Compensate) }));
        assert!(plan.targets.iter().any(|target| {
            target
                .actions
                .contains(&CancellationActionKind::ReconcileAmbiguousEffect)
        }));
        assert!(plan.targets.iter().any(|target| {
            target.actions.contains(&CancellationActionKind::Drain)
                && target.actions.contains(&CancellationActionKind::Fence)
                && target
                    .actions
                    .contains(&CancellationActionKind::WaitUntilTimeout)
        }));
        assert!(plan.targets.iter().any(|target| {
            target
                .actions
                .contains(&CancellationActionKind::RevokeLease)
        }));
        assert_eq!(
            plan.compensation_policy_ref.as_deref(),
            Some("policy://compensate")
        );
        assert_eq!(
            plan.effect_reconciliation_policy_ref.as_deref(),
            Some("policy://reconcile")
        );
    }

    #[test]
    fn cancellation_intent_and_recovery_policies_are_admission_bounded() {
        let mut state = WorkLifecycleState::default();
        let genesis = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://bounded-cancel/1",
            None,
            "pending",
            None,
            "bounded-cancel-1",
        );
        admit_work_lifecycle_record(&mut state, &genesis).unwrap();
        let child = child_record(
            &state,
            "work-lifecycle://bounded-cancel/child",
            ChildReferenceOperation::Attach,
            ChildRelationKind::HarnessInvocation,
            "harness_invocation://bounded-cancel",
            EffectRecoveryClass::Compensatable,
        );
        admit_work_lifecycle_record(&mut state, &child).unwrap();

        let mut cancel = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://bounded-cancel/2",
            Some("pending"),
            "canceled",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "bounded-cancel-2",
        );
        cancel.transition.as_mut().unwrap().cancellation_intent = Some(CancellationIntent {
            requested_by_ref: "user://operator".into(),
            reason: "operator_stop".into(),
            drain_deadline_ms: 20_000,
            compensation_policy_ref: None,
            ambiguous_effect_policy_ref: None,
        });
        seal_record(&mut cancel).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &cancel)
                .unwrap_err()
                .code,
            "work_lifecycle_compensation_policy_required"
        );

        let mut running = transition_record(
            WorkLifecycleObjectKind::WorkRun,
            "work-lifecycle://bounded-cancel/3",
            Some("pending"),
            "running",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "bounded-cancel-3",
        );
        running.transition.as_mut().unwrap().cancellation_intent = Some(CancellationIntent {
            requested_by_ref: "user://operator".into(),
            reason: "not_a_cancel_edge".into(),
            drain_deadline_ms: 20_000,
            compensation_policy_ref: Some("policy://compensate".into()),
            ambiguous_effect_policy_ref: None,
        });
        seal_record(&mut running).unwrap();
        assert_eq!(
            admit_work_lifecycle_record(&mut state, &running)
                .unwrap_err()
                .code,
            "work_lifecycle_cancellation_intent_unexpected"
        );
    }

    #[test]
    fn append_only_references_snapshot_and_crash_replay_preserve_phase_head_and_receipts() {
        let mut records = Vec::new();
        let genesis = transition_record(
            WorkLifecycleObjectKind::AutomationRun,
            "work-lifecycle://archive/1",
            None,
            "queued",
            None,
            "archive-1",
        );
        records.push(genesis.clone());
        let mut state = replay_work_lifecycle_records(&records).unwrap();
        let child = child_record(
            &state,
            "work-lifecycle://archive/child",
            ChildReferenceOperation::Attach,
            ChildRelationKind::WorkRun,
            "work_run://child",
            EffectRecoveryClass::Reversible,
        );
        records.push(child.clone());
        admit_work_lifecycle_record(&mut state, &child).unwrap();
        let running = transition_record(
            WorkLifecycleObjectKind::AutomationRun,
            "work-lifecycle://archive/2",
            Some("queued"),
            "running",
            Some(state.projection.as_ref().unwrap().head.clone()),
            "archive-2",
        );
        records.push(running.clone());
        admit_work_lifecycle_record(&mut state, &running).unwrap();

        let (archive, snapshot) = build_snapshot_and_archive(
            &records,
            "work-lifecycle-archive://one",
            "work-lifecycle-snapshot://one",
            2_000,
        )
        .unwrap();
        assert_eq!(archive.through_head, snapshot.through_head);
        assert_eq!(snapshot.resume_state, state);
        assert_eq!(archive.receipt_lineage_refs.len(), 3);

        let blocked = transition_record(
            WorkLifecycleObjectKind::AutomationRun,
            "work-lifecycle://archive/3",
            Some("running"),
            "blocked",
            Some(snapshot.through_head.clone()),
            "archive-3",
        );
        let mut resumed = snapshot.resume_state.clone();
        admit_work_lifecycle_record(&mut resumed, &blocked).unwrap();
        records.push(blocked);
        let replayed = replay_work_lifecycle_records(&records).unwrap();
        assert_eq!(resumed, replayed);
        assert_eq!(
            replayed.projection.as_ref().unwrap().active_phase,
            "blocked"
        );
    }
}
