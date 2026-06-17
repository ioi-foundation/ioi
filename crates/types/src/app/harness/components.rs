use super::*;

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub enum HarnessComponentKind {
    Planner,
    PromptAssembler,
    TaskState,
    UncertaintyGate,
    ProbeRunner,
    BudgetGate,
    CapabilitySequencer,
    ModelRouter,
    ModelCall,
    ToolRouter,
    ToolCall,
    DryRunSimulator,
    McpProvider,
    McpToolCall,
    ConnectorCall,
    GithubPrCreate,
    PolicyGate,
    ApprovalGate,
    WalletCapability,
    MemoryRead,
    MemorySearch,
    MemoryList,
    MemoryWrite,
    MemorySubagentInheritance,
    RuntimeDoctor,
    RuntimeTask,
    RuntimeJob,
    RuntimeChecklist,
    RuntimeThreadFork,
    RuntimeOperatorInterrupt,
    RuntimeOperatorSteer,
    RuntimeThreadMode,
    RuntimeWorkspaceTrustGate,
    RuntimeContextCompact,
    RuntimeApprovalRequest,
    RuntimeUsageMeter,
    RuntimeContextBudget,
    RuntimeCompactionPolicy,
    RuntimeRollbackSnapshot,
    RuntimeRestoreGate,
    RuntimeDiagnosticsRepair,
    RuntimeCodingToolBudgetRecovery,
    WorkflowPackageExport,
    WorkflowPackageImport,
    RepositoryContext,
    BranchPolicy,
    GithubContext,
    IssueContext,
    PrAttempt,
    ReviewGate,
    SkillRegistry,
    HookRegistry,
    HookPolicy,
    SemanticImpactAnalyzer,
    PostconditionSynthesizer,
    Verifier,
    DriftDetector,
    OutputWriter,
    ReceiptWriter,
    QualityLedger,
    RetryPolicy,
    RepairLoop,
    MergeJudge,
    HandoffBridge,
    CompletionGate,
    GuiHarnessValidator,
}

impl HarnessComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::PromptAssembler => "prompt_assembler",
            Self::TaskState => "task_state",
            Self::UncertaintyGate => "uncertainty_gate",
            Self::ProbeRunner => "probe_runner",
            Self::BudgetGate => "budget_gate",
            Self::CapabilitySequencer => "capability_sequencer",
            Self::ModelRouter => "model_router",
            Self::ModelCall => "model_call",
            Self::ToolRouter => "tool_router",
            Self::ToolCall => "tool_call",
            Self::DryRunSimulator => "dry_run_simulator",
            Self::McpProvider => "mcp_provider",
            Self::McpToolCall => "mcp_tool_call",
            Self::ConnectorCall => "connector_call",
            Self::GithubPrCreate => "github_pr_create",
            Self::PolicyGate => "policy_gate",
            Self::ApprovalGate => "approval_gate",
            Self::WalletCapability => "wallet_capability",
            Self::MemoryRead => "memory_read",
            Self::MemorySearch => "memory_search",
            Self::MemoryList => "memory_list",
            Self::MemoryWrite => "memory_write",
            Self::MemorySubagentInheritance => "memory_subagent_inheritance",
            Self::RuntimeDoctor => "runtime_doctor",
            Self::RuntimeTask => "runtime_task",
            Self::RuntimeJob => "runtime_job",
            Self::RuntimeChecklist => "runtime_checklist",
            Self::RuntimeThreadFork => "runtime_thread_fork",
            Self::RuntimeOperatorInterrupt => "runtime_operator_interrupt",
            Self::RuntimeOperatorSteer => "runtime_operator_steer",
            Self::RuntimeThreadMode => "runtime_thread_mode",
            Self::RuntimeWorkspaceTrustGate => "runtime_workspace_trust_gate",
            Self::RuntimeContextCompact => "runtime_context_compact",
            Self::RuntimeApprovalRequest => "runtime_approval_request",
            Self::RuntimeUsageMeter => "runtime_usage_meter",
            Self::RuntimeContextBudget => "runtime_context_budget",
            Self::RuntimeCompactionPolicy => "runtime_compaction_policy",
            Self::RuntimeRollbackSnapshot => "runtime_rollback_snapshot",
            Self::RuntimeRestoreGate => "runtime_restore_gate",
            Self::RuntimeDiagnosticsRepair => "runtime_diagnostics_repair",
            Self::RuntimeCodingToolBudgetRecovery => "runtime_coding_tool_budget_recovery",
            Self::WorkflowPackageExport => "workflow_package_export",
            Self::WorkflowPackageImport => "workflow_package_import",
            Self::RepositoryContext => "repository_context",
            Self::BranchPolicy => "branch_policy",
            Self::GithubContext => "github_context",
            Self::IssueContext => "issue_context",
            Self::PrAttempt => "pr_attempt",
            Self::ReviewGate => "review_gate",
            Self::SkillRegistry => "skill_registry",
            Self::HookRegistry => "hook_registry",
            Self::HookPolicy => "hook_policy",
            Self::SemanticImpactAnalyzer => "semantic_impact_analyzer",
            Self::PostconditionSynthesizer => "postcondition_synthesizer",
            Self::Verifier => "verifier",
            Self::DriftDetector => "drift_detector",
            Self::OutputWriter => "output_writer",
            Self::ReceiptWriter => "receipt_writer",
            Self::QualityLedger => "quality_ledger",
            Self::RetryPolicy => "retry_policy",
            Self::RepairLoop => "repair_loop",
            Self::MergeJudge => "merge_judge",
            Self::HandoffBridge => "handoff_bridge",
            Self::CompletionGate => "completion_gate",
            Self::GuiHarnessValidator => "gui_harness_validator",
        }
    }

    pub fn component_id(self) -> String {
        format!("ioi.agent-harness.{}.v1", self.as_str())
    }

    pub fn workflow_node_id(self) -> String {
        format!("harness.{}", self.as_str())
    }

    pub fn kernel_ref(self) -> &'static str {
        match self {
            Self::Planner => "crates/services/src/agentic/runtime/service/planning/planner",
            Self::PromptAssembler => {
                "crates/types/src/app/runtime_contracts.rs::PromptAssemblyContract"
            }
            Self::TaskState => "crates/types/src/app/runtime_contracts.rs::TaskStateModel",
            Self::UncertaintyGate => {
                "crates/types/src/app/runtime_contracts.rs::UncertaintyAssessment"
            }
            Self::ProbeRunner => "crates/types/src/app/runtime_contracts.rs::Probe",
            Self::BudgetGate => "crates/types/src/app/runtime_contracts.rs::CognitiveBudget",
            Self::CapabilitySequencer => {
                "crates/types/src/app/runtime_contracts.rs::CapabilitySequence"
            }
            Self::ModelRouter => "crates/services/src/agentic/runtime/service/decision_loop/cognition/router.rs",
            Self::ModelCall => "crates/services/src/agentic/runtime/service/handler/execution/handlers/model.rs",
            Self::ToolRouter => "crates/services/src/agentic/runtime/service/handler/execution/execution/action_execution.rs",
            Self::ToolCall => "crates/services/src/agentic/runtime/service/handler/execution",
            Self::DryRunSimulator => {
                "crates/types/src/app/runtime_contracts.rs::DryRunCapability"
            }
            Self::McpProvider => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::McpToolCall => "crates/services/src/agentic/runtime/tools/mcp.rs",
            Self::ConnectorCall => "crates/services/src/agentic/runtime/connectors",
            Self::GithubPrCreate => {
                "packages/runtime-daemon/src/index.mjs::buildGithubPrCreatePlan"
            }
            Self::PolicyGate => "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
            Self::ApprovalGate => "crates/services/src/agentic/runtime/service/handler/approvals.rs",
            Self::WalletCapability => "crates/services/src/agentic/runtime/kernel/capability.rs",
            Self::MemoryRead | Self::MemorySearch | Self::MemoryList | Self::MemoryWrite | Self::MemorySubagentInheritance => "crates/services/src/agentic/runtime/service/memory",
            Self::RuntimeDoctor
            | Self::RuntimeTask
            | Self::RuntimeJob
            | Self::RuntimeChecklist
            | Self::RuntimeThreadFork
            | Self::RuntimeOperatorInterrupt
            | Self::RuntimeOperatorSteer
            | Self::RuntimeThreadMode
            | Self::RuntimeWorkspaceTrustGate
            | Self::RuntimeContextCompact
            | Self::RuntimeApprovalRequest
            | Self::RuntimeUsageMeter
            | Self::RuntimeContextBudget
            | Self::RuntimeCompactionPolicy
            | Self::RuntimeRollbackSnapshot
            | Self::RuntimeRestoreGate
            | Self::RuntimeDiagnosticsRepair
            | Self::RuntimeCodingToolBudgetRecovery => {
                "packages/runtime-daemon/src/index.mjs"
            }
            Self::WorkflowPackageExport | Self::WorkflowPackageImport => {
                "internal-docs/legacy/autopilot-tauri-src/src/project/commands.rs"
            }
            Self::RepositoryContext
            | Self::BranchPolicy
            | Self::GithubContext
            | Self::IssueContext
            | Self::PrAttempt
            | Self::ReviewGate => "packages/runtime-daemon/src/index.mjs",
            Self::SkillRegistry | Self::HookRegistry | Self::HookPolicy => {
                "packages/runtime-daemon/src/index.mjs"
            }
            Self::SemanticImpactAnalyzer => {
                "crates/types/src/app/runtime_contracts.rs::SemanticImpactAnalysis"
            }
            Self::PostconditionSynthesizer => {
                "crates/types/src/app/runtime_contracts.rs::PostconditionSynthesis"
            }
            Self::Verifier => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::DriftDetector => "crates/types/src/app/runtime_contracts.rs::DriftSignal",
            Self::OutputWriter => "crates/services/src/agentic/runtime/service/queue/processing/completion_receipts.rs",
            Self::ReceiptWriter => "crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs",
            Self::QualityLedger => "crates/types/src/app/runtime_contracts.rs::AgentQualityLedger",
            Self::RetryPolicy => "crates/services/src/agentic/runtime/service/recovery/anti_loop",
            Self::RepairLoop => "crates/services/src/agentic/runtime/service/tool_execution/processing/repair",
            Self::MergeJudge => "crates/services/src/agentic/runtime/service/lifecycle/worker_results/merge.rs",
            Self::HandoffBridge => "crates/types/src/app/runtime_contracts.rs::HandoffQuality",
            Self::CompletionGate => "crates/services/src/agentic/runtime/service/visual_loop/browser_completion.rs",
            Self::GuiHarnessValidator => {
                "crates/types/src/app/runtime_contracts.rs::AutopilotGuiHarnessValidationContract"
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Planner => "Planner",
            Self::PromptAssembler => "Prompt assembler",
            Self::TaskState => "Task state model",
            Self::UncertaintyGate => "Uncertainty gate",
            Self::ProbeRunner => "Probe runner",
            Self::BudgetGate => "Cognitive budget gate",
            Self::CapabilitySequencer => "Capability sequencer",
            Self::ModelRouter => "Model router",
            Self::ModelCall => "Model call",
            Self::ToolRouter => "Tool router",
            Self::ToolCall => "Tool call",
            Self::DryRunSimulator => "Dry-run simulator",
            Self::McpProvider => "MCP provider",
            Self::McpToolCall => "MCP tool invocation",
            Self::ConnectorCall => "Connector call",
            Self::GithubPrCreate => "GitHub PR create",
            Self::PolicyGate => "Policy and firewall gate",
            Self::ApprovalGate => "Approval gate",
            Self::WalletCapability => "Wallet capability request",
            Self::MemoryRead => "Memory read",
            Self::MemorySearch => "Memory search",
            Self::MemoryList => "Memory list",
            Self::MemoryWrite => "Memory write",
            Self::MemorySubagentInheritance => "Memory subagent inheritance",
            Self::RuntimeDoctor => "Runtime doctor",
            Self::RuntimeTask => "Runtime task",
            Self::RuntimeJob => "Runtime job",
            Self::RuntimeChecklist => "Runtime checklist",
            Self::RuntimeThreadFork => "Runtime thread fork",
            Self::RuntimeOperatorInterrupt => "Runtime operator interrupt",
            Self::RuntimeOperatorSteer => "Runtime operator steer",
            Self::RuntimeThreadMode => "Runtime thread mode",
            Self::RuntimeWorkspaceTrustGate => "Runtime workspace trust gate",
            Self::RuntimeContextCompact => "Runtime context compaction",
            Self::RuntimeApprovalRequest => "Runtime approval request",
            Self::RuntimeUsageMeter => "Runtime usage meter",
            Self::RuntimeContextBudget => "Runtime context budget",
            Self::RuntimeCompactionPolicy => "Runtime compaction policy",
            Self::RuntimeRollbackSnapshot => "Runtime rollback snapshot",
            Self::RuntimeRestoreGate => "Runtime restore gate",
            Self::RuntimeDiagnosticsRepair => "Runtime diagnostics repair",
            Self::RuntimeCodingToolBudgetRecovery => "Runtime coding tool budget recovery",
            Self::WorkflowPackageExport => "Workflow package export",
            Self::WorkflowPackageImport => "Workflow package import",
            Self::RepositoryContext => "Repository context",
            Self::BranchPolicy => "Branch policy",
            Self::GithubContext => "GitHub context",
            Self::IssueContext => "Issue context",
            Self::PrAttempt => "PR attempt",
            Self::ReviewGate => "Review gate",
            Self::SkillRegistry => "Skill registry",
            Self::HookRegistry => "Hook registry",
            Self::HookPolicy => "Hook policy",
            Self::SemanticImpactAnalyzer => "Semantic impact analyzer",
            Self::PostconditionSynthesizer => "Postcondition synthesizer",
            Self::Verifier => "Verifier",
            Self::DriftDetector => "Drift detector",
            Self::OutputWriter => "Output writer",
            Self::ReceiptWriter => "Receipt writer",
            Self::QualityLedger => "Quality ledger",
            Self::RetryPolicy => "Retry policy",
            Self::RepairLoop => "Repair loop",
            Self::MergeJudge => "Merge and judge",
            Self::HandoffBridge => "Handoff bridge",
            Self::CompletionGate => "Completion gate",
            Self::GuiHarnessValidator => "Hypervisor App harness validator",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessSlotKind {
    StatePolicy,
    ModelPolicy,
    ToolGrantPolicy,
    BudgetPolicy,
    DryRunPolicy,
    VerifierPolicy,
    ApprovalPolicy,
    OutputPolicy,
    MemoryPolicy,
    QualityLedgerPolicy,
    RetryRepairPolicy,
    HandoffPolicy,
}

impl HarnessSlotKind {
    pub fn slot_id(self) -> &'static str {
        match self {
            Self::StatePolicy => "slot.state-policy",
            Self::ModelPolicy => "slot.model-policy",
            Self::ToolGrantPolicy => "slot.tool-grants",
            Self::BudgetPolicy => "slot.budget",
            Self::DryRunPolicy => "slot.dry-run",
            Self::VerifierPolicy => "slot.verifier",
            Self::ApprovalPolicy => "slot.approval",
            Self::OutputPolicy => "slot.output-policy",
            Self::MemoryPolicy => "slot.memory-policy",
            Self::QualityLedgerPolicy => "slot.quality-ledger",
            Self::RetryRepairPolicy => "slot.retry-repair",
            Self::HandoffPolicy => "slot.handoff",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessTimeoutBehavior {
    pub timeout_ms: u64,
    pub cancellation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessRetryBehavior {
    pub max_attempts: u32,
    pub backoff_ms: u64,
    pub retryable_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessApprovalSemantics {
    pub required: bool,
    pub mode: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentSpec {
    pub component_id: String,
    pub version: String,
    pub kind: HarnessComponentKind,
    pub readiness: HarnessComponentReadiness,
    pub label: String,
    pub kernel_ref: String,
    pub input_schema: String,
    pub output_schema: String,
    pub error_schema: String,
    pub timeout: HarnessTimeoutBehavior,
    pub retry: HarnessRetryBehavior,
    pub required_capability_scope: Vec<String>,
    pub approval: HarnessApprovalSemantics,
    pub emitted_events: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessSlotSpec {
    pub slot_id: String,
    pub kind: HarnessSlotKind,
    pub label: String,
    pub required: bool,
    pub allowed_component_kinds: Vec<HarnessComponentKind>,
    pub default_component_id: String,
    pub blocks_activation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessActionFrame {
    pub workflow_id: String,
    pub workflow_version: String,
    pub workflow_hash: String,
    pub execution_mode: HarnessExecutionMode,
    pub node_id: String,
    pub component_id: String,
    pub component_version: String,
    pub component_kind: HarnessComponentKind,
    pub readiness: HarnessComponentReadiness,
    pub kernel_ref: String,
    pub slot_ids: Vec<String>,
    pub deterministic_envelope: bool,
    pub replay: HarnessReplayEnvelope,
    pub event_kinds: Vec<String>,
    pub evidence_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentInvocation {
    pub invocation_id: String,
    pub component_kind: HarnessComponentKind,
    pub execution_mode: HarnessExecutionMode,
    pub attempt_index: u32,
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub policy_decision: Option<String>,
    pub receipt_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay_fixture_ref: Option<String>,
    pub started_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessComponentAdapterResult {
    pub schema_version: String,
    pub invocation_id: String,
    pub action_frame: HarnessActionFrame,
    pub node_attempt: HarnessNodeAttemptRecord,
    pub slot_ids: Vec<String>,
    pub result_hash: Option<String>,
    pub error_class: Option<String>,
    pub readiness: HarnessComponentReadiness,
    pub receipt_ids: Vec<String>,
    pub replay: HarnessReplayEnvelope,
}

pub(super) const DEFAULT_HARNESS_FLOW: &[HarnessComponentKind] = &[
    HarnessComponentKind::Planner,
    HarnessComponentKind::PromptAssembler,
    HarnessComponentKind::TaskState,
    HarnessComponentKind::UncertaintyGate,
    HarnessComponentKind::ProbeRunner,
    HarnessComponentKind::BudgetGate,
    HarnessComponentKind::CapabilitySequencer,
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
    HarnessComponentKind::DryRunSimulator,
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::WalletCapability,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::GithubPrCreate,
    HarnessComponentKind::MemoryRead,
    HarnessComponentKind::MemoryWrite,
    HarnessComponentKind::SemanticImpactAnalyzer,
    HarnessComponentKind::PostconditionSynthesizer,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::DriftDetector,
    HarnessComponentKind::RetryPolicy,
    HarnessComponentKind::RepairLoop,
    HarnessComponentKind::MergeJudge,
    HarnessComponentKind::HandoffBridge,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::QualityLedger,
    HarnessComponentKind::OutputWriter,
    HarnessComponentKind::GuiHarnessValidator,
];

const COGNITION_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::Planner,
    HarnessComponentKind::PromptAssembler,
    HarnessComponentKind::TaskState,
    HarnessComponentKind::UncertaintyGate,
    HarnessComponentKind::BudgetGate,
    HarnessComponentKind::CapabilitySequencer,
];

const ROUTING_MODEL_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
];

const VERIFICATION_OUTPUT_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::PostconditionSynthesizer,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::QualityLedger,
    HarnessComponentKind::OutputWriter,
];

const AUTHORITY_TOOLING_CLUSTER_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::DryRunSimulator,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::GithubPrCreate,
    HarnessComponentKind::WalletCapability,
];

const LIVE_SHADOW_COMPARISON_GATE_COMPONENTS: &[HarnessComponentKind] = &[
    HarnessComponentKind::Planner,
    HarnessComponentKind::PromptAssembler,
    HarnessComponentKind::TaskState,
    HarnessComponentKind::ModelRouter,
    HarnessComponentKind::ModelCall,
    HarnessComponentKind::ToolRouter,
    HarnessComponentKind::PostconditionSynthesizer,
    HarnessComponentKind::Verifier,
    HarnessComponentKind::CompletionGate,
    HarnessComponentKind::ReceiptWriter,
    HarnessComponentKind::QualityLedger,
    HarnessComponentKind::OutputWriter,
    HarnessComponentKind::PolicyGate,
    HarnessComponentKind::ApprovalGate,
    HarnessComponentKind::DryRunSimulator,
    HarnessComponentKind::McpProvider,
    HarnessComponentKind::McpToolCall,
    HarnessComponentKind::ToolCall,
    HarnessComponentKind::ConnectorCall,
    HarnessComponentKind::GithubPrCreate,
    HarnessComponentKind::WalletCapability,
];

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

pub(super) fn promotion_cluster_components(
    cluster_id: HarnessPromotionClusterId,
) -> Vec<HarnessComponentKind> {
    match cluster_id {
        HarnessPromotionClusterId::Cognition => COGNITION_CLUSTER_COMPONENTS.to_vec(),
        HarnessPromotionClusterId::RoutingModel => ROUTING_MODEL_CLUSTER_COMPONENTS.to_vec(),
        HarnessPromotionClusterId::VerificationOutput => {
            VERIFICATION_OUTPUT_CLUSTER_COMPONENTS.to_vec()
        }
        HarnessPromotionClusterId::AuthorityTooling => {
            AUTHORITY_TOOLING_CLUSTER_COMPONENTS.to_vec()
        }
    }
}

pub fn harness_promotion_cluster_components(
    cluster_id: HarnessPromotionClusterId,
) -> Vec<HarnessComponentKind> {
    promotion_cluster_components(cluster_id)
}

pub fn default_harness_live_shadow_comparison_gate_component_kinds() -> Vec<HarnessComponentKind> {
    LIVE_SHADOW_COMPARISON_GATE_COMPONENTS.to_vec()
}

fn component_scope(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["reasoning.read", "session.state.read"]),
        HarnessComponentKind::PromptAssembler => {
            strings(&["prompt.assemble", "session.state.read", "evidence.read"])
        }
        HarnessComponentKind::TaskState => {
            strings(&["session.state.read", "session.state.write", "evidence.read"])
        }
        HarnessComponentKind::UncertaintyGate => {
            strings(&["uncertainty.assess", "session.state.read"])
        }
        HarnessComponentKind::ProbeRunner => strings(&["probe.plan", "probe.run"]),
        HarnessComponentKind::BudgetGate => strings(&["budget.evaluate"]),
        HarnessComponentKind::CapabilitySequencer => {
            strings(&["capability.read", "tool.route", "quality.read"])
        }
        HarnessComponentKind::ModelRouter => strings(&["model.route"]),
        HarnessComponentKind::ModelCall => strings(&["model.invoke"]),
        HarnessComponentKind::ToolRouter => strings(&["tool.route", "capability.read"]),
        HarnessComponentKind::ToolCall => strings(&["tool.invoke"]),
        HarnessComponentKind::DryRunSimulator => strings(&["dry_run.preview"]),
        HarnessComponentKind::McpProvider => strings(&["mcp.provider.read", "mcp.catalog.read"]),
        HarnessComponentKind::McpToolCall => strings(&["mcp.tool.invoke"]),
        HarnessComponentKind::ConnectorCall => strings(&["connector.invoke"]),
        HarnessComponentKind::GithubPrCreate => strings(&["github.pr.create", "github.pr.dry_run"]),
        HarnessComponentKind::PolicyGate => strings(&["policy.evaluate", "capability.lease"]),
        HarnessComponentKind::ApprovalGate => strings(&["approval.request"]),
        HarnessComponentKind::WalletCapability => strings(&["wallet.request", "capability.grant"]),
        HarnessComponentKind::MemoryRead => strings(&["memory.read"]),
        HarnessComponentKind::MemoryWrite => strings(&["memory.write"]),
        HarnessComponentKind::SemanticImpactAnalyzer => {
            strings(&["impact.analyze", "workspace.read"])
        }
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["postcondition.synthesize", "evidence.read"])
        }
        HarnessComponentKind::Verifier => strings(&["verification.run"]),
        HarnessComponentKind::DriftDetector => strings(&["drift.detect", "session.state.read"]),
        HarnessComponentKind::OutputWriter => strings(&["output.write"]),
        HarnessComponentKind::ReceiptWriter => strings(&["receipt.write"]),
        HarnessComponentKind::QualityLedger => strings(&["quality.write", "scorecard.read"]),
        HarnessComponentKind::RetryPolicy => strings(&["retry.evaluate"]),
        HarnessComponentKind::RepairLoop => strings(&["repair.propose"]),
        HarnessComponentKind::MergeJudge => strings(&["judgement.run"]),
        HarnessComponentKind::HandoffBridge => strings(&["handoff.write", "session.state.read"]),
        HarnessComponentKind::CompletionGate => strings(&["completion.evaluate"]),
        HarnessComponentKind::GuiHarnessValidator => strings(&["gui.validate", "trace.read"]),
        _ => strings(&["workflow.context.read", "receipt.read"]),
    }
}

fn component_events(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => strings(&["PlanReceipt", "KernelEvent::PlanReceipt"]),
        HarnessComponentKind::PromptAssembler => {
            strings(&["PromptAssemblyContract", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::TaskState => strings(&["TaskStateModel", "AgentRuntimeEvent"]),
        HarnessComponentKind::UncertaintyGate => {
            strings(&["UncertaintyAssessment", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::ProbeRunner => strings(&["Probe", "AgentRuntimeEvent"]),
        HarnessComponentKind::BudgetGate => strings(&["CognitiveBudget", "AgentRuntimeEvent"]),
        HarnessComponentKind::CapabilitySequencer => {
            strings(&["CapabilitySequence", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::ModelRouter => {
            strings(&["RoutingReceipt", "KernelEvent::RoutingReceipt"])
        }
        HarnessComponentKind::ModelCall => {
            strings(&["WorkloadReceipt", "WorkloadReceipt::Inference"])
        }
        HarnessComponentKind::ToolRouter => strings(&["RoutingReceipt", "ActionDispatchPrepared"]),
        HarnessComponentKind::ToolCall => strings(&["AgentActionResult", "WorkloadReceipt"]),
        HarnessComponentKind::DryRunSimulator => {
            strings(&["DryRunCapability", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::McpProvider => strings(&["McpServerCatalogued", "CapabilityLease"]),
        HarnessComponentKind::McpToolCall => {
            strings(&["AgentActionResult", "ExecutionContractReceipt"])
        }
        HarnessComponentKind::ConnectorCall => strings(&["ConnectorInvocation", "WorkloadReceipt"]),
        HarnessComponentKind::GithubPrCreate => {
            strings(&["GithubPrCreatePlan", "ExecutionContractReceipt"])
        }
        HarnessComponentKind::PolicyGate => strings(&["FirewallInterception", "RoutingReceipt"]),
        HarnessComponentKind::ApprovalGate => strings(&["ApprovalRequested", "ApprovalSatisfied"]),
        HarnessComponentKind::WalletCapability => {
            strings(&["CapabilityLease", "WalletRequestReceipt"])
        }
        HarnessComponentKind::MemoryRead => strings(&["WorkloadReceipt::MemoryRetrieve"]),
        HarnessComponentKind::MemoryWrite => strings(&["StateUpdate", "WorkloadReceipt"]),
        HarnessComponentKind::SemanticImpactAnalyzer => {
            strings(&["SemanticImpactAnalysis", "AgentRuntimeEvent"])
        }
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["PostconditionSynthesis", "ExecutionContractReceipt"])
        }
        HarnessComponentKind::Verifier => {
            strings(&["ExecutionContractReceipt", "VerificationReceipt"])
        }
        HarnessComponentKind::DriftDetector => strings(&["DriftSignal", "AgentRuntimeEvent"]),
        HarnessComponentKind::OutputWriter => strings(&["OutputWritten", "AgentActionResult"]),
        HarnessComponentKind::ReceiptWriter => {
            strings(&["ExecutionContractReceipt", "PlanReceipt", "WorkloadReceipt"])
        }
        HarnessComponentKind::QualityLedger => strings(&["AgentQualityLedger", "Scorecard"]),
        HarnessComponentKind::RetryPolicy => strings(&["RetryScheduled", "RetryExhausted"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["RepairAttemptStarted", "RepairAttemptCompleted"])
        }
        HarnessComponentKind::MergeJudge => strings(&["MergeReceipt", "JudgementReceipt"]),
        HarnessComponentKind::HandoffBridge => strings(&["HandoffQuality", "AgentRuntimeEvent"]),
        HarnessComponentKind::CompletionGate => strings(&["CompletionGateReceipt", "PlanReceipt"]),
        HarnessComponentKind::GuiHarnessValidator => {
            strings(&["AutopilotGuiHarnessValidationContract", "Scorecard"])
        }
        _ => strings(&["AgentRuntimeEvent", "ExecutionContractReceipt"]),
    }
}

fn component_evidence(kind: HarnessComponentKind) -> Vec<String> {
    match kind {
        HarnessComponentKind::Planner => {
            strings(&["plan_id", "planner_policy_hash", "chosen_step_reason"])
        }
        HarnessComponentKind::PromptAssembler => strings(&[
            "sections",
            "final_prompt_hash",
            "conflict_resolutions",
            "truncation_diagnostics",
        ]),
        HarnessComponentKind::TaskState => strings(&[
            "objective",
            "known_facts",
            "uncertain_facts",
            "evidence_refs",
        ]),
        HarnessComponentKind::UncertaintyGate => strings(&[
            "ambiguity_level",
            "value_of_information",
            "selected_action",
            "rationale",
        ]),
        HarnessComponentKind::ProbeRunner => strings(&[
            "hypothesis",
            "expected_observation",
            "result",
            "confidence_update",
        ]),
        HarnessComponentKind::BudgetGate => strings(&[
            "max_tool_calls",
            "max_retries",
            "max_wall_time_ms",
            "stop_threshold",
        ]),
        HarnessComponentKind::CapabilitySequencer => strings(&[
            "discovered",
            "selected",
            "ordered_steps",
            "retired_or_deprioritized",
        ]),
        HarnessComponentKind::ModelRouter => {
            strings(&["model_policy_slot", "candidate_models", "routing_reason"])
        }
        HarnessComponentKind::ModelCall => {
            strings(&["request_hash", "response_hash", "model_binding"])
        }
        HarnessComponentKind::ToolRouter => {
            strings(&["tool_grant_slot", "candidate_tools", "routing_reason"])
        }
        HarnessComponentKind::ToolCall => {
            strings(&["action_request_id", "tool_ref", "result_hash"])
        }
        HarnessComponentKind::DryRunSimulator => strings(&[
            "capability_id",
            "supported_tool_classes",
            "side_effect_preview",
        ]),
        HarnessComponentKind::McpProvider => strings(&["server_id", "catalog_hash", "grant_scope"]),
        HarnessComponentKind::McpToolCall => {
            strings(&["server_id", "tool_name", "argument_hash", "result_hash"])
        }
        HarnessComponentKind::ConnectorCall => {
            strings(&["connector_id", "operation", "request_hash", "result_hash"])
        }
        HarnessComponentKind::GithubPrCreate => {
            strings(&["plan_id", "request_hash", "authority_scope", "dry_run"])
        }
        HarnessComponentKind::PolicyGate => {
            strings(&["policy_hash", "decision", "lease_id", "determinism_commit"])
        }
        HarnessComponentKind::ApprovalGate => {
            strings(&["approval_id", "approval_scope", "approver"])
        }
        HarnessComponentKind::WalletCapability => {
            strings(&["capability_scope", "lease_id", "budget"])
        }
        HarnessComponentKind::MemoryRead => strings(&["memory_key", "state_hash"]),
        HarnessComponentKind::MemoryWrite => strings(&["memory_key", "previous_hash", "next_hash"]),
        HarnessComponentKind::SemanticImpactAnalyzer => strings(&[
            "changed_symbols",
            "affected_tests",
            "risk_class",
            "unknowns",
        ]),
        HarnessComponentKind::PostconditionSynthesizer => {
            strings(&["objective", "checks", "minimum_evidence", "unknowns"])
        }
        HarnessComponentKind::Verifier => {
            strings(&["schema_hash", "contract_key", "verification_result"])
        }
        HarnessComponentKind::DriftDetector => strings(&[
            "plan_drift",
            "file_drift",
            "policy_drift",
            "projection_state_drift",
        ]),
        HarnessComponentKind::OutputWriter => {
            strings(&["output_hash", "delivery_target", "output_policy_slot"])
        }
        HarnessComponentKind::ReceiptWriter => {
            strings(&["receipt_id", "node_id", "evidence_commit_hash"])
        }
        HarnessComponentKind::QualityLedger => strings(&[
            "ledger_id",
            "task_family",
            "scorecard_metrics",
            "stop_condition",
        ]),
        HarnessComponentKind::RetryPolicy => strings(&["attempt", "max_attempts", "retry_reason"]),
        HarnessComponentKind::RepairLoop => {
            strings(&["failure_ref", "repair_strategy", "bounded_targets"])
        }
        HarnessComponentKind::MergeJudge => {
            strings(&["candidate_hashes", "winner_reason", "judge_policy_hash"])
        }
        HarnessComponentKind::HandoffBridge => strings(&[
            "objective_preserved",
            "blockers_included",
            "evidence_refs_included",
        ]),
        HarnessComponentKind::CompletionGate => {
            strings(&["completion_contract", "pending_actions", "final_decision"])
        }
        HarnessComponentKind::GuiHarnessValidator => strings(&[
            "launch_command",
            "retained_queries",
            "screenshots",
            "scorecard",
        ]),
        _ => strings(&["runtime_binding", "workflow_node_id", "receipt_refs"]),
    }
}

fn component_readiness(kind: HarnessComponentKind) -> HarnessComponentReadiness {
    match kind {
        HarnessComponentKind::Planner
        | HarnessComponentKind::PromptAssembler
        | HarnessComponentKind::TaskState => HarnessComponentReadiness::LiveReady,
        HarnessComponentKind::UncertaintyGate
        | HarnessComponentKind::BudgetGate
        | HarnessComponentKind::CapabilitySequencer
        | HarnessComponentKind::ModelRouter
        | HarnessComponentKind::ModelCall
        | HarnessComponentKind::ToolRouter
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpProvider
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall
        | HarnessComponentKind::GithubPrCreate
        | HarnessComponentKind::PolicyGate
        | HarnessComponentKind::ApprovalGate
        | HarnessComponentKind::WalletCapability
        | HarnessComponentKind::PostconditionSynthesizer
        | HarnessComponentKind::Verifier
        | HarnessComponentKind::CompletionGate
        | HarnessComponentKind::ReceiptWriter
        | HarnessComponentKind::QualityLedger
        | HarnessComponentKind::OutputWriter => HarnessComponentReadiness::ShadowReady,
        _ => HarnessComponentReadiness::ProjectionOnly,
    }
}

fn replay_captures_policy_decision(kind: HarnessComponentKind) -> bool {
    matches!(
        kind,
        HarnessComponentKind::UncertaintyGate
            | HarnessComponentKind::BudgetGate
            | HarnessComponentKind::DryRunSimulator
            | HarnessComponentKind::PolicyGate
            | HarnessComponentKind::ApprovalGate
            | HarnessComponentKind::GithubPrCreate
            | HarnessComponentKind::WalletCapability
            | HarnessComponentKind::RetryPolicy
            | HarnessComponentKind::CompletionGate
            | HarnessComponentKind::HandoffBridge
    )
}

fn replay_is_intrinsically_nondeterministic(kind: HarnessComponentKind) -> bool {
    matches!(
        kind,
        HarnessComponentKind::ModelCall
            | HarnessComponentKind::ToolCall
            | HarnessComponentKind::McpToolCall
            | HarnessComponentKind::ConnectorCall
            | HarnessComponentKind::GithubPrCreate
            | HarnessComponentKind::WalletCapability
    )
}

pub(super) fn default_harness_replay_envelope(kind: HarnessComponentKind) -> HarnessReplayEnvelope {
    let nondeterministic = replay_is_intrinsically_nondeterministic(kind);
    HarnessReplayEnvelope {
        deterministic_envelope: !nondeterministic,
        captures_input: true,
        captures_output: true,
        captures_policy_decision: replay_captures_policy_decision(kind),
        fixture_ref: None,
        determinism: if nondeterministic {
            HarnessReplayDeterminism::Nondeterministic
        } else {
            HarnessReplayDeterminism::Deterministic
        },
        nondeterminism_reason: nondeterministic.then(|| {
            "External model, tool, connector, or wallet boundary requires retained fixture evidence"
                .to_string()
        }),
        redaction_policy: "runtime_redacted".to_string(),
    }
}

fn approval_for(kind: HarnessComponentKind) -> HarnessApprovalSemantics {
    let required = matches!(
        kind,
        HarnessComponentKind::ToolCall
            | HarnessComponentKind::DryRunSimulator
            | HarnessComponentKind::McpToolCall
            | HarnessComponentKind::ConnectorCall
            | HarnessComponentKind::GithubPrCreate
            | HarnessComponentKind::ApprovalGate
            | HarnessComponentKind::WalletCapability
            | HarnessComponentKind::MemoryWrite
            | HarnessComponentKind::OutputWriter
    );
    let mode = match kind {
        HarnessComponentKind::ApprovalGate => "human_gate",
        HarnessComponentKind::WalletCapability => "wallet_capability",
        _ if required => "policy_gate",
        _ => "none",
    };
    HarnessApprovalSemantics {
        required,
        mode: mode.to_string(),
        reason: if required {
            "Component may cross a privileged runtime boundary.".to_string()
        } else {
            "Component is governed by workflow and node policy.".to_string()
        },
    }
}

pub fn default_harness_component_spec(kind: HarnessComponentKind) -> HarnessComponentSpec {
    let max_attempts = match kind {
        HarnessComponentKind::RetryPolicy => 3,
        HarnessComponentKind::RepairLoop
        | HarnessComponentKind::ProbeRunner
        | HarnessComponentKind::ModelCall
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall
        | HarnessComponentKind::GithubPrCreate => 2,
        _ => 1,
    };
    let timeout_ms = match kind {
        HarnessComponentKind::ModelCall => 120_000,
        HarnessComponentKind::GuiHarnessValidator => 600_000,
        HarnessComponentKind::ToolCall
        | HarnessComponentKind::DryRunSimulator
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall
        | HarnessComponentKind::GithubPrCreate => 60_000,
        _ => 30_000,
    };
    HarnessComponentSpec {
        component_id: kind.component_id(),
        version: HARNESS_COMPONENT_VERSION_V1.to_string(),
        kind,
        readiness: component_readiness(kind),
        label: kind.label().to_string(),
        kernel_ref: kind.kernel_ref().to_string(),
        input_schema: HARNESS_INPUT_SCHEMA_ID.to_string(),
        output_schema: HARNESS_OUTPUT_SCHEMA_ID.to_string(),
        error_schema: HARNESS_ERROR_SCHEMA_ID.to_string(),
        timeout: HarnessTimeoutBehavior {
            timeout_ms,
            cancellation: "cooperative".to_string(),
        },
        retry: HarnessRetryBehavior {
            max_attempts,
            backoff_ms: if max_attempts > 1 { 250 } else { 0 },
            retryable_errors: strings(&["timeout", "rate_limit", "transient_provider_error"]),
        },
        required_capability_scope: component_scope(kind),
        approval: approval_for(kind),
        emitted_events: component_events(kind),
        evidence: component_evidence(kind),
    }
}

pub fn default_agent_harness_components() -> Vec<HarnessComponentSpec> {
    DEFAULT_HARNESS_FLOW
        .iter()
        .copied()
        .map(default_harness_component_spec)
        .collect()
}

pub fn default_harness_promotion_clusters() -> Vec<HarnessPromotionCluster> {
    [
        HarnessPromotionClusterId::Cognition,
        HarnessPromotionClusterId::RoutingModel,
        HarnessPromotionClusterId::VerificationOutput,
        HarnessPromotionClusterId::AuthorityTooling,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, cluster_id)| HarnessPromotionCluster {
        cluster_id,
        label: cluster_id.label().to_string(),
        activation_order: (index + 1) as u32,
        component_kinds: promotion_cluster_components(cluster_id),
        required_execution_mode: HarnessExecutionMode::Gated,
        minimum_readiness: HarnessComponentReadiness::ShadowReady,
        promotion_rule: "zero blocking or unclassified divergence, receipt coverage, replay fixture coverage, and rollback target required".to_string(),
        rollback_target: "shadow".to_string(),
        blocks_live_activation: true,
        promotion_status: HarnessClusterPromotionStatus::ShadowReady,
        replay_gate_proof: None,
    })
    .collect()
}

fn slot_kinds_for_component(kind: HarnessComponentKind) -> Vec<HarnessSlotKind> {
    match kind {
        HarnessComponentKind::Planner
        | HarnessComponentKind::PromptAssembler
        | HarnessComponentKind::TaskState
        | HarnessComponentKind::UncertaintyGate
        | HarnessComponentKind::CapabilitySequencer
        | HarnessComponentKind::DriftDetector => vec![HarnessSlotKind::StatePolicy],
        HarnessComponentKind::ModelRouter | HarnessComponentKind::ModelCall => {
            vec![HarnessSlotKind::ModelPolicy]
        }
        HarnessComponentKind::ToolRouter
        | HarnessComponentKind::ToolCall
        | HarnessComponentKind::McpProvider
        | HarnessComponentKind::McpToolCall
        | HarnessComponentKind::ConnectorCall
        | HarnessComponentKind::GithubPrCreate => vec![HarnessSlotKind::ToolGrantPolicy],
        HarnessComponentKind::BudgetGate => vec![HarnessSlotKind::BudgetPolicy],
        HarnessComponentKind::DryRunSimulator => vec![HarnessSlotKind::DryRunPolicy],
        HarnessComponentKind::PolicyGate
        | HarnessComponentKind::ApprovalGate
        | HarnessComponentKind::WalletCapability => vec![HarnessSlotKind::ApprovalPolicy],
        HarnessComponentKind::MemoryRead
        | HarnessComponentKind::MemorySearch
        | HarnessComponentKind::MemoryList
        | HarnessComponentKind::MemoryWrite
        | HarnessComponentKind::MemorySubagentInheritance => {
            vec![HarnessSlotKind::MemoryPolicy]
        }
        HarnessComponentKind::SemanticImpactAnalyzer
        | HarnessComponentKind::PostconditionSynthesizer
        | HarnessComponentKind::Verifier
        | HarnessComponentKind::CompletionGate => {
            vec![HarnessSlotKind::VerifierPolicy]
        }
        HarnessComponentKind::OutputWriter
        | HarnessComponentKind::ReceiptWriter
        | HarnessComponentKind::GuiHarnessValidator => {
            vec![HarnessSlotKind::OutputPolicy]
        }
        HarnessComponentKind::QualityLedger => vec![HarnessSlotKind::QualityLedgerPolicy],
        HarnessComponentKind::RetryPolicy | HarnessComponentKind::RepairLoop => {
            vec![HarnessSlotKind::RetryRepairPolicy]
        }
        HarnessComponentKind::MergeJudge => {
            vec![
                HarnessSlotKind::RetryRepairPolicy,
                HarnessSlotKind::VerifierPolicy,
            ]
        }
        HarnessComponentKind::ProbeRunner => vec![
            HarnessSlotKind::StatePolicy,
            HarnessSlotKind::ToolGrantPolicy,
            HarnessSlotKind::BudgetPolicy,
        ],
        HarnessComponentKind::HandoffBridge => vec![HarnessSlotKind::HandoffPolicy],
        _ => vec![HarnessSlotKind::StatePolicy],
    }
}

pub fn default_agent_harness_slots() -> Vec<HarnessSlotSpec> {
    vec![
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::StatePolicy.slot_id().to_string(),
            kind: HarnessSlotKind::StatePolicy,
            label: "Task state and strategy policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::Planner,
                HarnessComponentKind::PromptAssembler,
                HarnessComponentKind::TaskState,
                HarnessComponentKind::UncertaintyGate,
                HarnessComponentKind::ProbeRunner,
                HarnessComponentKind::CapabilitySequencer,
                HarnessComponentKind::DriftDetector,
            ],
            default_component_id: HarnessComponentKind::TaskState.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ModelPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ModelPolicy,
            label: "Model policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ModelRouter,
                HarnessComponentKind::ModelCall,
            ],
            default_component_id: HarnessComponentKind::ModelRouter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ToolGrantPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ToolGrantPolicy,
            label: "Tool grant policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ToolRouter,
                HarnessComponentKind::ToolCall,
                HarnessComponentKind::McpProvider,
                HarnessComponentKind::McpToolCall,
                HarnessComponentKind::ConnectorCall,
                HarnessComponentKind::GithubPrCreate,
            ],
            default_component_id: HarnessComponentKind::ToolRouter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::BudgetPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::BudgetPolicy,
            label: "Cognitive budget policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::BudgetGate,
                HarnessComponentKind::ProbeRunner,
            ],
            default_component_id: HarnessComponentKind::BudgetGate.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::DryRunPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::DryRunPolicy,
            label: "Dry-run policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::DryRunSimulator],
            default_component_id: HarnessComponentKind::DryRunSimulator.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::VerifierPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::VerifierPolicy,
            label: "Verifier policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::SemanticImpactAnalyzer,
                HarnessComponentKind::PostconditionSynthesizer,
                HarnessComponentKind::Verifier,
                HarnessComponentKind::MergeJudge,
                HarnessComponentKind::CompletionGate,
            ],
            default_component_id: HarnessComponentKind::Verifier.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::ApprovalPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::ApprovalPolicy,
            label: "Approval policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::ApprovalGate,
                HarnessComponentKind::PolicyGate,
                HarnessComponentKind::WalletCapability,
            ],
            default_component_id: HarnessComponentKind::ApprovalGate.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::OutputPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::OutputPolicy,
            label: "Output policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::OutputWriter,
                HarnessComponentKind::ReceiptWriter,
                HarnessComponentKind::GuiHarnessValidator,
            ],
            default_component_id: HarnessComponentKind::OutputWriter.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::MemoryPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::MemoryPolicy,
            label: "Memory policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::MemoryRead,
                HarnessComponentKind::MemoryWrite,
            ],
            default_component_id: HarnessComponentKind::MemoryRead.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::QualityLedgerPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::QualityLedgerPolicy,
            label: "Quality ledger policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::QualityLedger],
            default_component_id: HarnessComponentKind::QualityLedger.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::RetryRepairPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::RetryRepairPolicy,
            label: "Retry and repair policy".to_string(),
            required: true,
            allowed_component_kinds: vec![
                HarnessComponentKind::RetryPolicy,
                HarnessComponentKind::RepairLoop,
                HarnessComponentKind::MergeJudge,
            ],
            default_component_id: HarnessComponentKind::RetryPolicy.component_id(),
            blocks_activation: true,
        },
        HarnessSlotSpec {
            slot_id: HarnessSlotKind::HandoffPolicy.slot_id().to_string(),
            kind: HarnessSlotKind::HandoffPolicy,
            label: "Handoff policy".to_string(),
            required: true,
            allowed_component_kinds: vec![HarnessComponentKind::HandoffBridge],
            default_component_id: HarnessComponentKind::HandoffBridge.component_id(),
            blocks_activation: true,
        },
    ]
}

pub fn default_agent_harness_action_frames() -> Vec<HarnessActionFrame> {
    default_agent_harness_components()
        .into_iter()
        .map(|component| {
            default_harness_action_frame_for_component(
                component.kind,
                HarnessExecutionMode::Projection,
            )
        })
        .collect()
}

pub fn default_harness_action_frame_for_component(
    component_kind: HarnessComponentKind,
    execution_mode: HarnessExecutionMode,
) -> HarnessActionFrame {
    let component = default_harness_component_spec(component_kind);
    HarnessActionFrame {
        workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        workflow_version: DEFAULT_AGENT_HARNESS_VERSION.to_string(),
        workflow_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        execution_mode,
        node_id: component.kind.workflow_node_id(),
        component_id: component.component_id,
        component_version: component.version,
        component_kind: component.kind,
        readiness: component.readiness,
        kernel_ref: component.kernel_ref,
        slot_ids: slot_kinds_for_component(component.kind)
            .into_iter()
            .map(HarnessSlotKind::slot_id)
            .map(str::to_string)
            .collect(),
        deterministic_envelope: default_harness_replay_envelope(component.kind)
            .deterministic_envelope,
        replay: default_harness_replay_envelope(component.kind),
        event_kinds: component.emitted_events,
        evidence_keys: component.evidence,
    }
}
