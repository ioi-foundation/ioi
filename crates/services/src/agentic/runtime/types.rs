// Path: crates/services/src/agentic/runtime/types.rs

use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
use ioi_types::app::agentic::{ResolvedIntentState, WebRetrievalContract};
use ioi_types::app::ActionRequest;
use ioi_types::app::{
    ArtifactGenerationSummary, ArtifactQualityScorecard, ArtifactRepairSummary,
    CodingVerificationScorecard, ComputerUsePerceptionSummary, ComputerUseRecoverySummary,
    ComputerUseVerificationScorecard, PatchSynthesisSummary, ResearchVerificationScorecard,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::VecDeque;

pub const MAX_COMMAND_HISTORY: usize = 20;
pub const MAX_PROMPT_HISTORY: usize = 5;
pub const COMMAND_HISTORY_SANITIZED_PLACEHOLDER: &str = "[REDACTED_PII]";
pub const MESSAGE_SANITIZED_PLACEHOLDER: &str = "[REDACTED_PII]";
pub const DEFAULT_MESSAGE_REDACTION_VERSION: &str = "v1";
pub const DEFAULT_MESSAGE_PRIVACY_POLICY_ID: &str = "desktop-agent/default";
pub const DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION: &str = "1";
pub const PLANNER_SCHEMA_VERSION_V1: &str = "planner.v1";

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct InteractionTarget {
    pub app_hint: Option<String>,
    pub title_pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum ToolCallStatus {
    Pending,
    Approved,
    Executed(String),
    Failed(String),
}

pub const EXECUTION_LEDGER_SCHEMA_VERSION: &str = "cec.ledger.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    #[default]
    ContractLoaded,
    Discovery,
    ProviderSelection,
    PayloadSynthesis,
    Execution,
    Verification,
    CompletionGate,
    Terminal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAttemptStatus {
    #[default]
    Active,
    Blocked,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct ExecutionAttempt {
    pub attempt_id: u64,
    pub intent_id: Option<String>,
    pub stage: ExecutionStage,
    pub status: ExecutionAttemptStatus,
    pub evidence: BTreeMap<String, String>,
    pub success_conditions: BTreeMap<String, String>,
    pub verification_evidence: BTreeMap<String, String>,
    pub completion_gate_missing: Vec<String>,
    pub error_class: Option<String>,
}

impl ExecutionAttempt {
    pub fn new(attempt_id: u64, intent_id: Option<String>) -> Self {
        Self {
            attempt_id,
            intent_id,
            stage: ExecutionStage::ContractLoaded,
            status: ExecutionAttemptStatus::Active,
            evidence: BTreeMap::new(),
            success_conditions: BTreeMap::new(),
            verification_evidence: BTreeMap::new(),
            completion_gate_missing: vec![],
            error_class: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct ExecutionLedger {
    pub schema_version: String,
    pub next_attempt_id: u64,
    pub attempts: Vec<ExecutionAttempt>,
}

impl Default for ExecutionLedger {
    fn default() -> Self {
        Self {
            schema_version: EXECUTION_LEDGER_SCHEMA_VERSION.to_string(),
            next_attempt_id: 1,
            attempts: vec![],
        }
    }
}

impl ExecutionLedger {
    fn ensure_active_attempt(&mut self, intent_id: Option<String>) -> &mut ExecutionAttempt {
        let reuse_last = self.attempts.last().is_some_and(|attempt| {
            attempt.status == ExecutionAttemptStatus::Active && attempt.intent_id == intent_id
        });
        if !reuse_last {
            let attempt_id = self.next_attempt_id;
            self.next_attempt_id = self.next_attempt_id.saturating_add(1);
            self.attempts
                .push(ExecutionAttempt::new(attempt_id, intent_id));
        }
        self.attempts
            .last_mut()
            .expect("execution ledger must contain an active attempt")
    }

    fn stage_for_evidence(evidence_key: &str) -> ExecutionStage {
        match evidence_key {
            "host_discovery" => ExecutionStage::Discovery,
            "provider_selection" | "provider_selection_commit" | "grounding" => {
                ExecutionStage::ProviderSelection
            }
            "execution" => ExecutionStage::Execution,
            "verification" | "verification_commit" => ExecutionStage::Verification,
            _ if evidence_key.ends_with("_commit") => ExecutionStage::Verification,
            _ => ExecutionStage::Execution,
        }
    }

    pub fn evidence_value(&self, evidence_key: &str) -> Option<&str> {
        self.attempts
            .iter()
            .rev()
            .find_map(|attempt| attempt.evidence.get(evidence_key).map(String::as_str))
    }

    pub fn has_evidence(&self, evidence_key: &str) -> bool {
        self.evidence_value(evidence_key)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn success_condition_value(&self, success_condition: &str) -> Option<&str> {
        self.attempts.iter().rev().find_map(|attempt| {
            attempt
                .success_conditions
                .get(success_condition)
                .map(String::as_str)
        })
    }

    pub fn has_success_condition(&self, success_condition: &str) -> bool {
        self.success_condition_value(success_condition)
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    }

    pub fn has_verification_evidence(&self) -> bool {
        self.attempts.iter().rev().any(|attempt| {
            attempt
                .verification_evidence
                .iter()
                .any(|(key, value)| !key.trim().is_empty() && !value.trim().is_empty())
        })
    }

    pub fn record_evidence(
        &mut self,
        intent_id: Option<String>,
        evidence_key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let evidence_key = evidence_key.into();
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = Self::stage_for_evidence(&evidence_key);
        attempt.evidence.insert(evidence_key, value.into());
    }

    pub fn record_success_condition(
        &mut self,
        intent_id: Option<String>,
        success_condition: impl Into<String>,
        value: impl Into<String>,
    ) {
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = ExecutionStage::Verification;
        attempt
            .success_conditions
            .insert(success_condition.into(), value.into());
    }

    pub fn record_verification_evidence(
        &mut self,
        intent_id: Option<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = ExecutionStage::Verification;
        attempt
            .verification_evidence
            .insert(key.into(), value.into());
    }

    pub fn record_completion_gate(&mut self, intent_id: Option<String>, missing: &[String]) {
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = ExecutionStage::CompletionGate;
        attempt.completion_gate_missing = missing.to_vec();
        if missing.is_empty() {
            attempt.error_class = None;
        } else {
            attempt.status = ExecutionAttemptStatus::Blocked;
            attempt.error_class = Some("ExecutionContractViolation".to_string());
        }
    }

    pub fn record_execution_failure(
        &mut self,
        intent_id: Option<String>,
        stage: ExecutionStage,
        error_class: impl Into<String>,
    ) {
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = stage;
        attempt.status = ExecutionAttemptStatus::Failed;
        attempt.error_class = Some(error_class.into());
    }

    pub fn record_terminal_success(&mut self, intent_id: Option<String>) {
        let attempt = self.ensure_active_attempt(intent_id);
        attempt.stage = ExecutionStage::Terminal;
        attempt.status = ExecutionAttemptStatus::Succeeded;
        attempt.error_class = None;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed(Option<String>),
    Failed(String),
    Paused(String),
    Terminated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
pub enum AgentMode {
    #[default]
    Agent,
    Chat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub enum ExecutionTier {
    #[default]
    DomHeadless,
    VisualBackground,
    VisualForeground,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct WorkGraphContext {
    #[serde(alias = "swarm_id")]
    pub work_graph_id: [u8; 32],
    pub role: String,
    pub allowed_delegates: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub enum SessionRole {
    Planner,
    Worker,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkerMergeMode {
    #[default]
    AppendSummaryToParent,
    AppendAsEvidence,
    ReplaceParentDraft,
    CompletionMessage,
}

impl WorkerMergeMode {
    pub fn as_label(&self) -> &'static str {
        match self {
            WorkerMergeMode::AppendSummaryToParent => "append_summary_to_parent",
            WorkerMergeMode::AppendAsEvidence => "append_as_evidence",
            WorkerMergeMode::ReplaceParentDraft => "replace_parent_draft",
            WorkerMergeMode::CompletionMessage => "completion_message",
        }
    }

    pub fn parse_label(raw: Option<&str>) -> Option<Self> {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            Some("append_summary_to_parent") | Some("append-summary-to-parent") => {
                Some(WorkerMergeMode::AppendSummaryToParent)
            }
            Some("append_as_evidence") | Some("append-as-evidence") => {
                Some(WorkerMergeMode::AppendAsEvidence)
            }
            Some("replace_parent_draft") | Some("replace-parent-draft") => {
                Some(WorkerMergeMode::ReplaceParentDraft)
            }
            Some("completion_message") | Some("completion-message") => {
                Some(WorkerMergeMode::CompletionMessage)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct WorkerCompletionContract {
    pub success_criteria: String,
    pub expected_output: String,
    pub merge_mode: WorkerMergeMode,
    pub verification_hint: Option<String>,
}

impl Default for WorkerCompletionContract {
    fn default() -> Self {
        Self {
            success_criteria: String::new(),
            expected_output: String::new(),
            merge_mode: WorkerMergeMode::AppendSummaryToParent,
            verification_hint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct WorkerTemplateWorkflowDefinition {
    pub workflow_id: String,
    pub label: String,
    pub summary: String,
    pub goal_template: String,
    pub trigger_intents: Vec<String>,
    #[serde(default)]
    pub default_budget: Option<u64>,
    #[serde(default)]
    pub max_retries: Option<u8>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub completion_contract: Option<WorkerCompletionContract>,
}

impl Default for WorkerTemplateWorkflowDefinition {
    fn default() -> Self {
        Self {
            workflow_id: String::new(),
            label: String::new(),
            summary: String::new(),
            goal_template: String::new(),
            trigger_intents: Vec::new(),
            default_budget: None,
            max_retries: None,
            allowed_tools: Vec::new(),
            completion_contract: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkerTemplateDefinition {
    pub template_id: String,
    pub label: String,
    pub role: String,
    pub summary: String,
    pub default_budget: u64,
    pub max_retries: u8,
    pub allowed_tools: Vec<String>,
    pub completion_contract: WorkerCompletionContract,
    #[serde(default)]
    pub workflows: Vec<WorkerTemplateWorkflowDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct AgentPlaybookStepDefinition {
    pub step_id: String,
    pub label: String,
    pub summary: String,
    pub worker_template_id: String,
    pub worker_workflow_id: String,
    pub goal_template: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct AgentPlaybookDefinition {
    pub playbook_id: String,
    pub label: String,
    pub summary: String,
    pub goal_template: String,
    #[serde(default)]
    pub trigger_intents: Vec<String>,
    #[serde(default)]
    pub recommended_for: Vec<String>,
    pub default_budget: u64,
    pub completion_contract: WorkerCompletionContract,
    #[serde(default)]
    pub steps: Vec<AgentPlaybookStepDefinition>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ParentPlaybookStatus {
    #[default]
    Running,
    Completed,
    Blocked,
    Failed,
}

impl ParentPlaybookStatus {
    pub fn as_label(&self) -> &'static str {
        match self {
            ParentPlaybookStatus::Running => "running",
            ParentPlaybookStatus::Completed => "completed",
            ParentPlaybookStatus::Blocked => "blocked",
            ParentPlaybookStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ParentPlaybookStepStatus {
    #[default]
    Pending,
    Running,
    Completed,
    Blocked,
    Failed,
}

impl ParentPlaybookStepStatus {
    pub fn as_label(&self) -> &'static str {
        match self {
            ParentPlaybookStepStatus::Pending => "pending",
            ParentPlaybookStepStatus::Running => "running",
            ParentPlaybookStepStatus::Completed => "completed",
            ParentPlaybookStepStatus::Blocked => "blocked",
            ParentPlaybookStepStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ParentPlaybookStepRun {
    pub step_id: String,
    pub label: String,
    pub summary: String,
    pub status: ParentPlaybookStepStatus,
    #[serde(default)]
    pub child_session_id: Option<[u8; 32]>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub goal: Option<String>,
    #[serde(default)]
    pub selected_skills: Vec<String>,
    #[serde(default)]
    pub prep_summary: Option<String>,
    #[serde(default)]
    pub artifact_generation: Option<ArtifactGenerationSummary>,
    #[serde(default)]
    pub computer_use_perception: Option<ComputerUsePerceptionSummary>,
    #[serde(default)]
    pub research_scorecard: Option<ResearchVerificationScorecard>,
    #[serde(default)]
    pub artifact_quality: Option<ArtifactQualityScorecard>,
    #[serde(default)]
    pub computer_use_verification: Option<ComputerUseVerificationScorecard>,
    #[serde(default)]
    pub coding_scorecard: Option<CodingVerificationScorecard>,
    #[serde(default)]
    pub patch_synthesis: Option<PatchSynthesisSummary>,
    #[serde(default)]
    pub artifact_repair: Option<ArtifactRepairSummary>,
    #[serde(default)]
    pub computer_use_recovery: Option<ComputerUseRecoverySummary>,
    #[serde(default)]
    pub output_preview: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub spawned_at_ms: Option<u64>,
    #[serde(default)]
    pub completed_at_ms: Option<u64>,
    #[serde(default)]
    pub merged_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct ParentPlaybookRun {
    pub parent_session_id: [u8; 32],
    pub playbook_id: String,
    pub playbook_label: String,
    pub topic: String,
    pub status: ParentPlaybookStatus,
    pub current_step_index: u32,
    #[serde(default)]
    pub active_child_session_id: Option<[u8; 32]>,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default)]
    pub completed_at_ms: Option<u64>,
    #[serde(default)]
    pub steps: Vec<ParentPlaybookStepRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkerAssignment {
    pub step_key: String,
    pub budget: u64,
    pub goal: String,
    pub success_criteria: String,
    pub max_retries: u8,
    pub retries_used: u8,
    pub assigned_session_id: Option<[u8; 32]>,
    pub status: String,
    #[serde(default)]
    pub playbook_id: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub completion_contract: WorkerCompletionContract,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct WorkerSessionResult {
    pub child_session_id: [u8; 32],
    pub parent_session_id: [u8; 32],
    pub budget: u64,
    #[serde(default)]
    pub playbook_id: Option<String>,
    #[serde(default)]
    pub template_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    pub role: String,
    pub goal: String,
    pub status: String,
    pub success: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub raw_output: Option<String>,
    pub merged_output: String,
    pub completion_contract: WorkerCompletionContract,
    pub completed_at_ms: u64,
    #[serde(default)]
    pub merged_at_ms: Option<u64>,
    #[serde(default)]
    pub merged_step_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct ExecutionPlanState {
    pub plan_id: String,
    pub plan_hash: [u8; 32],
    pub selected_route: String,
    pub status: String,
    pub worker_assignments: Vec<WorkerAssignment>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlannerStepKind {
    #[default]
    ToolCallIntent,
    Clarification,
    Wait,
    Completion,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlannerStepStatus {
    #[default]
    Pending,
    Dispatched,
    Succeeded,
    Blocked,
    RetryableFailed,
    TerminalFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PlanStepConstraint {
    pub max_retries: u8,
    pub retry_eligible: bool,
    pub requires_approval: bool,
    pub timeout_ms: Option<u64>,
}

impl Default for PlanStepConstraint {
    fn default() -> Self {
        Self {
            max_retries: 1,
            retry_eligible: false,
            requires_approval: false,
            timeout_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PlanStep {
    pub step_id: String,
    pub kind: PlannerStepKind,
    pub tool_name: Option<String>,
    pub arguments_json: Option<String>,
    pub constraints: PlanStepConstraint,
    pub depends_on: Vec<String>,
    pub status: PlannerStepStatus,
    pub evidence: Vec<String>,
}

impl Default for PlanStep {
    fn default() -> Self {
        Self {
            step_id: String::new(),
            kind: PlannerStepKind::ToolCallIntent,
            tool_name: None,
            arguments_json: None,
            constraints: PlanStepConstraint::default(),
            depends_on: Vec::new(),
            status: PlannerStepStatus::Pending,
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PlannerStatus {
    #[default]
    Draft,
    Ready,
    Running,
    Completed,
    Failed,
    Blocked,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum PlannerDiscoveryRequirement {
    ResolvedIntent,
    InteractionTarget,
    VisualContext,
    PendingSearchContext,
    ActiveLens,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PlannerState {
    pub plan_id: String,
    pub plan_schema_version: String,
    pub goal_hash: [u8; 32],
    pub intent_receipt_hash: [u8; 32],
    pub plan_hash: [u8; 32],
    pub discovery_requirements: Vec<PlannerDiscoveryRequirement>,
    pub steps: Vec<PlanStep>,
    pub cursor: u32,
    pub replan_count: u32,
    pub status: PlannerStatus,
    pub last_replan_reason: Option<String>,
    pub last_batch: Vec<String>,
}

impl Default for PlannerState {
    fn default() -> Self {
        Self {
            plan_id: String::new(),
            plan_schema_version: PLANNER_SCHEMA_VERSION_V1.to_string(),
            goal_hash: [0u8; 32],
            intent_receipt_hash: [0u8; 32],
            plan_hash: [0u8; 32],
            discovery_requirements: Vec::new(),
            steps: Vec::new(),
            cursor: 0,
            replan_count: 0,
            status: PlannerStatus::Draft,
            last_replan_reason: None,
            last_batch: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PendingSearchReadSummary {
    pub url: String,
    pub title: Option<String>,
    pub excerpt: String,
}

fn default_pending_search_min_sources() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
#[serde(default)]
pub struct PendingSearchCompletion {
    pub query: String,
    #[serde(default)]
    pub query_contract: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_contract: Option<WebRetrievalContract>,
    pub url: String,
    pub started_step: u32,
    pub started_at_ms: u64,
    pub deadline_ms: u64,
    pub candidate_urls: Vec<String>,
    #[serde(default)]
    pub candidate_source_hints: Vec<PendingSearchReadSummary>,
    pub attempted_urls: Vec<String>,
    pub blocked_urls: Vec<String>,
    pub successful_reads: Vec<PendingSearchReadSummary>,
    #[serde(default = "default_pending_search_min_sources")]
    pub min_sources: u32,
}

impl Default for PendingSearchReadSummary {
    fn default() -> Self {
        Self {
            url: String::new(),
            title: None,
            excerpt: String::new(),
        }
    }
}

impl Default for PendingSearchCompletion {
    fn default() -> Self {
        Self {
            query: String::new(),
            query_contract: String::new(),
            retrieval_contract: None,
            url: String::new(),
            started_step: 0,
            started_at_ms: 0,
            deadline_ms: 0,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: Vec::new(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources: default_pending_search_min_sources(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct CommandExecution {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timestamp_ms: u64,
    pub step_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct MessagePrivacyMetadata {
    #[serde(default)]
    pub redaction_version: String,
    #[serde(default)]
    pub sensitive_fields_mask: Vec<String>,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub scrubbed_for_model_hash: Option<String>,
}

impl Default for MessagePrivacyMetadata {
    fn default() -> Self {
        Self {
            redaction_version: String::new(),
            sensitive_fields_mask: Vec::new(),
            policy_id: String::new(),
            policy_version: String::new(),
            scrubbed_for_model_hash: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RecordedMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub trace_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub raw_content: String,
    #[serde(default)]
    pub scrubbed_for_model: String,
    #[serde(default)]
    pub scrubbed_for_scs: String,

    #[serde(default)]
    pub raw_reference: Option<String>,

    #[serde(default)]
    pub privacy_metadata: MessagePrivacyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Default)]
#[serde(default)]
pub struct PendingActionState {
    pub approval: Option<ApprovalGrant>,
    pub tool_call: Option<String>,
    pub tool_jcs: Option<Vec<u8>>,
    pub tool_hash: Option<[u8; 32]>,
    pub request_nonce: Option<u64>,
    pub visual_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPauseReason {
    WaitingForApproval,
    WaitingForHumanApproval,
    WaitingForSudoPassword,
    WaitingForIntentClarification,
    WaitingForTargetClarification,
    ApprovalLoopDetected,
    RetryBlocked(String),
    ModelRefusal(String),
    Other(String),
}

impl AgentPauseReason {
    pub fn message(&self) -> String {
        match self {
            Self::WaitingForApproval => "Waiting for approval".to_string(),
            Self::WaitingForHumanApproval => "Waiting for human approval".to_string(),
            Self::WaitingForSudoPassword => "Waiting for sudo password".to_string(),
            Self::WaitingForIntentClarification => "Waiting for intent clarification".to_string(),
            Self::WaitingForTargetClarification => {
                "Waiting for clarification on target identity.".to_string()
            }
            Self::ApprovalLoopDetected => {
                "Approval loop detected for the same incident/action. Automatic retries paused."
                    .to_string()
            }
            Self::RetryBlocked(detail) => format!("Retry blocked: {}", detail.trim()),
            Self::ModelRefusal(detail) => format!("Model Refusal: {}", detail.trim()),
            Self::Other(detail) => detail.clone(),
        }
    }

    pub fn from_message(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("Waiting for approval") {
            Self::WaitingForApproval
        } else if trimmed.eq_ignore_ascii_case("Waiting for human approval") {
            Self::WaitingForHumanApproval
        } else if trimmed.eq_ignore_ascii_case("Waiting for sudo password") {
            Self::WaitingForSudoPassword
        } else if trimmed.eq_ignore_ascii_case("Waiting for intent clarification") {
            Self::WaitingForIntentClarification
        } else if trimmed.eq_ignore_ascii_case("Waiting for clarification on target identity.") {
            Self::WaitingForTargetClarification
        } else if trimmed.eq_ignore_ascii_case(
            "Approval loop detected for the same incident/action. Automatic retries paused.",
        ) {
            Self::ApprovalLoopDetected
        } else if let Some(detail) = trimmed.strip_prefix("Retry blocked:") {
            Self::RetryBlocked(detail.trim().to_string())
        } else if let Some(detail) = trimmed.strip_prefix("Model Refusal:") {
            Self::ModelRefusal(detail.trim().to_string())
        } else {
            Self::Other(trimmed.to_string())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct AgentState {
    pub session_id: [u8; 32],
    pub goal: String,

    // [REMOVED] pub history: Vec<ChatMessage>,
    pub transcript_root: [u8; 32],

    pub status: AgentStatus,
    pub step_count: u32,
    pub max_steps: u32,
    pub last_action_type: Option<String>,
    pub parent_session_id: Option<[u8; 32]>,
    pub child_session_ids: Vec<[u8; 32]>,
    pub budget: u64,
    pub tokens_used: u64,
    pub consecutive_failures: u8,
    pub pending_approval: Option<ApprovalGrant>,
    pub pending_tool_call: Option<String>,

    // [NEW] Canonical Resume State
    // Stores the exact JCS bytes of the AgentTool that was intercepted.
    #[serde(default)]
    pub pending_tool_jcs: Option<Vec<u8>>,

    // The hash of the tool JCS, which must match the ApprovalGrant.
    #[serde(default)]
    pub pending_tool_hash: Option<[u8; 32]>,

    // The original ActionRequest nonce for the canonical pending action.
    #[serde(default)]
    pub pending_request_nonce: Option<u64>,

    // The visual context hash active when the action was intercepted.
    #[serde(default)]
    pub pending_visual_hash: Option<[u8; 32]>,

    #[serde(default)]
    pub recent_actions: Vec<String>,
    #[serde(default)]
    pub mode: AgentMode,
    #[serde(default)]
    pub current_tier: ExecutionTier,
    #[serde(default)]
    pub last_screen_phash: Option<[u8; 32]>,
    #[serde(default)]
    pub execution_queue: Vec<ActionRequest>,

    #[serde(default)]
    pub pending_search_completion: Option<PendingSearchCompletion>,

    #[serde(default)]
    pub planner_state: Option<PlannerState>,

    #[serde(default)]
    pub active_skill_hash: Option<[u8; 32]>,

    #[serde(default)]
    pub tool_execution_log: BTreeMap<String, ToolCallStatus>,

    #[serde(default)]
    pub execution_ledger: ExecutionLedger,

    #[serde(default)]
    pub visual_som_map: Option<BTreeMap<u32, (i32, i32, i32, i32)>>,

    // [NEW] Map SoM ID -> Semantic Element ID (e.g. 7 -> "btn_calculator_7")
    // This allows upgrading ephemeral numeric IDs to robust semantic lookups on resume.
    #[serde(default)]
    pub visual_semantic_map: Option<BTreeMap<u32, String>>,

    #[serde(default, alias = "swarm_context")]
    pub work_graph_context: Option<WorkGraphContext>,

    #[serde(default)]
    pub target: Option<InteractionTarget>,

    /// Global resolver output used by decision-loop/tool/recovery routing.
    #[serde(default)]
    pub resolved_intent: Option<ResolvedIntentState>,

    /// True when the session is paused waiting for intent clarification.
    #[serde(default)]
    pub awaiting_intent_clarification: bool,

    /// Persistent working directory used by `shell__run`.
    #[serde(default = "default_working_directory")]
    pub working_directory: String,

    #[serde(default)]
    pub command_history: VecDeque<CommandExecution>,

    // [NEW] The name of the Application Lens used during the last perception step.
    // Required to re-resolve element IDs (e.g. "btn_submit") to coordinates during execution.
    #[serde(default)]
    pub active_lens: Option<String>,
}

fn default_working_directory() -> String {
    ".".to_string()
}

#[derive(Encode, Decode)]
pub struct StartAgentParams {
    pub session_id: [u8; 32],
    pub goal: String,
    pub max_steps: u32,
    pub parent_session_id: Option<[u8; 32]>,
    pub initial_budget: u64,
    pub mode: AgentMode,
}

#[derive(Encode, Decode)]
pub struct StepAgentParams {
    pub session_id: [u8; 32],
}

#[derive(Encode, Decode)]
pub struct PostMessageParams {
    pub session_id: [u8; 32],
    pub role: String,
    pub content: String,
}

#[derive(Encode, Decode)]
pub struct PauseAgentParams {
    pub session_id: [u8; 32],
    pub reason: String,
}

#[derive(Encode, Decode)]
pub struct CancelAgentParams {
    pub session_id: [u8; 32],
    pub reason: String,
}

#[derive(Encode, Decode)]
pub struct DenyAgentParams {
    pub session_id: [u8; 32],
    pub request_hash: Option<[u8; 32]>,
    pub reason: String,
}

#[derive(Encode, Decode)]
pub struct ResumeAgentParams {
    pub session_id: [u8; 32],
    pub approval_grant: Option<ApprovalGrant>,
}

#[derive(Encode, Decode)]
pub struct RegisterApprovalAuthorityParams {
    pub authority: ApprovalAuthority,
}

#[derive(Encode, Decode)]
pub struct RevokeApprovalAuthorityParams {
    pub authority_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SessionSummary {
    pub session_id: [u8; 32],
    pub title: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct SessionResult {
    pub session_id: [u8; 32],
    pub result: String,
    pub cost_incurred: u64,
    pub success: bool,
    pub timestamp: u64,
}

impl AgentState {
    pub fn pending_action_state(&self) -> PendingActionState {
        PendingActionState {
            approval: self.pending_approval.clone(),
            tool_call: self.pending_tool_call.clone(),
            tool_jcs: self.pending_tool_jcs.clone(),
            tool_hash: self.pending_tool_hash,
            request_nonce: self.pending_request_nonce,
            visual_hash: self.pending_visual_hash,
        }
    }

    pub fn replace_pending_action_state(&mut self, pending: PendingActionState) {
        self.pending_approval = pending.approval;
        self.pending_tool_call = pending.tool_call;
        self.pending_tool_jcs = pending.tool_jcs;
        self.pending_tool_hash = pending.tool_hash;
        self.pending_request_nonce = pending.request_nonce;
        self.pending_visual_hash = pending.visual_hash;
    }

    pub fn clear_pending_action_state(&mut self) {
        self.replace_pending_action_state(PendingActionState::default());
    }

    pub fn has_canonical_pending_action(&self) -> bool {
        self.pending_tool_jcs.is_some()
    }

    pub fn pause_reason(&self) -> Option<AgentPauseReason> {
        match &self.status {
            AgentStatus::Paused(reason) => Some(AgentPauseReason::from_message(reason)),
            _ => None,
        }
    }

    pub fn set_pause_reason(&mut self, reason: AgentPauseReason) {
        self.status = AgentStatus::Paused(reason.message());
    }

    pub fn set_running(&mut self) {
        self.status = AgentStatus::Running;
    }

    pub fn is_waiting_for_approval(&self) -> bool {
        matches!(
            self.pause_reason(),
            Some(AgentPauseReason::WaitingForApproval | AgentPauseReason::WaitingForHumanApproval)
        )
    }

    pub fn is_waiting_for_sudo_password(&self) -> bool {
        matches!(
            self.pause_reason(),
            Some(AgentPauseReason::WaitingForSudoPassword)
        )
    }

    pub fn is_waiting_for_intent_clarification(&self) -> bool {
        matches!(
            self.pause_reason(),
            Some(AgentPauseReason::WaitingForIntentClarification)
        )
    }

    pub fn is_waiting_for_target_clarification(&self) -> bool {
        matches!(
            self.pause_reason(),
            Some(AgentPauseReason::WaitingForTargetClarification)
        )
    }
}
