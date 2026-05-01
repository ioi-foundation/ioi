import type {
  Node,
  WorkflowEdge,
  WorkflowHarnessComponentKind,
  WorkflowHarnessComponentSpec,
  WorkflowHarnessMetadata,
  WorkflowHarnessNodeBinding,
  WorkflowHarnessSlotKind,
  WorkflowHarnessSlotSpec,
  WorkflowHarnessWorkerBinding,
  WorkflowNode,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
} from "../types/graph";
import { normalizeGlobalConfig, slugify } from "./workflow-defaults";

export const DEFAULT_AGENT_HARNESS_WORKFLOW_ID = "default-agent-harness";
export const DEFAULT_AGENT_HARNESS_VERSION = "2026.04.default-harness.v1";
export const DEFAULT_AGENT_HARNESS_HASH =
  "sha256:default-agent-harness-component-projection-v1";
export const DEFAULT_AGENT_HARNESS_ACTIVATION_ID =
  "activation:default-agent-harness:blessed-readonly";

const HARNESS_INPUT_SCHEMA = {
  type: "object",
  required: ["sessionId", "turnId"],
  properties: {
    sessionId: { type: "string" },
    turnId: { type: "string" },
    input: {},
    state: { type: "object" },
    policyContext: { type: "object" },
  },
};

const HARNESS_OUTPUT_SCHEMA = {
  type: "object",
  required: ["status"],
  properties: {
    status: { type: "string" },
    value: {},
    evidence: { type: "array", items: { type: "string" } },
    receipts: { type: "array", items: { type: "string" } },
  },
};

const HARNESS_ERROR_SCHEMA = {
  type: "object",
  required: ["code", "message", "retryable"],
  properties: {
    code: { type: "string" },
    message: { type: "string" },
    retryable: { type: "boolean" },
    evidenceRef: { type: "string" },
  },
};

type ComponentSeed = {
  kind: WorkflowHarnessComponentKind;
  label: string;
  description: string;
  kernelRef: string;
  capabilityScope: string[];
  approvalMode?: WorkflowHarnessComponentSpec["approval"]["mode"];
  approvalRequired?: boolean;
  eventKinds: string[];
  evidence: string[];
  group: string;
  icon: string;
  timeoutMs?: number;
  maxAttempts?: number;
};

function componentId(kind: WorkflowHarnessComponentKind): string {
  return `ioi.agent-harness.${kind}.v1`;
}

function makeComponent(seed: ComponentSeed): WorkflowHarnessComponentSpec {
  const approvalRequired = seed.approvalRequired ?? false;
  return {
    componentId: componentId(seed.kind),
    version: "1.0.0",
    kind: seed.kind,
    label: seed.label,
    description: seed.description,
    kernelRef: seed.kernelRef,
    inputSchema: HARNESS_INPUT_SCHEMA,
    outputSchema: HARNESS_OUTPUT_SCHEMA,
    errorSchema: HARNESS_ERROR_SCHEMA,
    timeout: {
      timeoutMs: seed.timeoutMs ?? 30000,
      cancellation: "cooperative",
    },
    retry: {
      maxAttempts: seed.maxAttempts ?? 1,
      backoffMs: seed.maxAttempts && seed.maxAttempts > 1 ? 250 : 0,
      retryableErrors: ["timeout", "rate_limit", "transient_provider_error"],
    },
    requiredCapabilityScope: seed.capabilityScope,
    approval: {
      required: approvalRequired,
      mode: seed.approvalMode ?? (approvalRequired ? "policy_gate" : "none"),
      reason: approvalRequired
        ? "Component may cross a privileged runtime boundary."
        : "Component is governed by workflow and node policy.",
    },
    emittedEvents: seed.eventKinds,
    evidence: seed.evidence,
    ui: {
      icon: seed.icon,
      group: seed.group,
      summary: seed.description,
    },
  };
}

export const DEFAULT_AGENT_HARNESS_COMPONENTS: WorkflowHarnessComponentSpec[] = [
  makeComponent({
    kind: "planner",
    label: "Planner",
    description: "Produces the next plan step from session state, user input, and available capabilities.",
    kernelRef: "crates/services/src/agentic/runtime/service/planning/planner",
    capabilityScope: ["reasoning.read", "session.state.read"],
    eventKinds: ["PlanReceipt", "KernelEvent::PlanReceipt"],
    evidence: ["plan_id", "planner_policy_hash", "chosen_step_reason"],
    group: "Planning",
    icon: "list-checks",
  }),
  makeComponent({
    kind: "task_state",
    label: "Task state",
    description: "Projects the current objective, known facts, uncertainty, blockers, stale facts, and evidence references.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["session.state.read", "evidence.read"],
    eventKinds: ["AgentRuntimeEvent", "TaskStateModel"],
    evidence: ["task_state_id", "evidence_refs", "stale_fact_refs"],
    group: "Cognition",
    icon: "map",
  }),
  makeComponent({
    kind: "uncertainty_gate",
    label: "Uncertainty gate",
    description: "Chooses whether to ask, retrieve, probe, dry-run, execute, verify, escalate, or stop.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["reasoning.route", "session.state.read"],
    eventKinds: ["UncertaintyAssessment", "RuntimeStrategyDecision"],
    evidence: ["ambiguity_level", "value_of_information", "selected_action"],
    group: "Cognition",
    icon: "circle-help",
  }),
  makeComponent({
    kind: "probe_runner",
    label: "Probe runner",
    description: "Runs the cheapest bounded validation action for a stated hypothesis.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/probe.rs",
    capabilityScope: ["probe.run", "verification.read"],
    eventKinds: ["ProbeStarted", "ProbeCompleted"],
    evidence: ["hypothesis", "expected_observation", "probe_result"],
    group: "Cognition",
    icon: "radar",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "budget_gate",
    label: "Cognitive budget",
    description: "Bounds reasoning tokens, tool calls, retries, verification spend, and wall time.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["budget.evaluate", "session.state.read"],
    eventKinds: ["CognitiveBudget", "RuntimeStrategyDecision"],
    evidence: ["remaining_tokens", "remaining_tool_calls", "stop_threshold"],
    group: "Cognition",
    icon: "gauge",
  }),
  makeComponent({
    kind: "capability_sequencer",
    label: "Capability sequencer",
    description: "Separates capability discovery, selection, sequencing, and retirement decisions.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["capability.read", "tool.route"],
    eventKinds: ["CapabilitySequence", "RoutingReceipt"],
    evidence: ["discovered_capabilities", "selected_sequence", "retired_capabilities"],
    group: "Routing",
    icon: "waypoints",
  }),
  makeComponent({
    kind: "model_router",
    label: "Model router",
    description: "Selects a model binding under workflow-level model policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/model_router",
    capabilityScope: ["model.route"],
    eventKinds: ["RoutingReceipt", "KernelEvent::RoutingReceipt"],
    evidence: ["model_policy_slot", "candidate_models", "routing_reason"],
    group: "Routing",
    icon: "brain",
  }),
  makeComponent({
    kind: "model_call",
    label: "Model call",
    description: "Invokes the selected model with deterministic request and response capture.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/model_call",
    capabilityScope: ["model.invoke"],
    eventKinds: ["ModelInvocationStarted", "ModelInvocationCompleted"],
    evidence: ["request_hash", "response_hash", "model_binding"],
    group: "Execution",
    icon: "message-square",
    timeoutMs: 120000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "tool_router",
    label: "Tool router",
    description: "Chooses native, workflow, MCP, or connector tools under grant policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/action_execution.rs",
    capabilityScope: ["tool.route", "capability.read"],
    eventKinds: ["RoutingReceipt", "ActionDispatchPrepared"],
    evidence: ["tool_grant_slot", "candidate_tools", "routing_reason"],
    group: "Routing",
    icon: "route",
  }),
  makeComponent({
    kind: "tool_call",
    label: "Tool call",
    description: "Executes a native or workflow tool through the action execution envelope.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution",
    capabilityScope: ["tool.invoke"],
    approvalRequired: true,
    eventKinds: ["AgentActionResult", "WorkloadReceipt"],
    evidence: ["action_request_id", "tool_ref", "result_hash"],
    group: "Execution",
    icon: "wrench",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "dry_run_simulator",
    label: "Dry-run simulator",
    description: "Previews side effects and policy outcomes before file, shell, connector, or commerce actions execute.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["dry_run.preview", "policy.evaluate"],
    eventKinds: ["DryRunPreview", "PolicyPreview"],
    evidence: ["side_effect_preview", "policy_preview", "preview_artifact"],
    group: "Governance",
    icon: "scan-search",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "mcp_provider",
    label: "MCP provider",
    description: "Represents an MCP server as a capability provider with reviewed grants.",
    kernelRef: "crates/services/src/mcp",
    capabilityScope: ["mcp.provider.read", "mcp.catalog.read"],
    eventKinds: ["McpServerCatalogued", "CapabilityLease"],
    evidence: ["server_id", "catalog_hash", "grant_scope"],
    group: "MCP",
    icon: "server",
  }),
  makeComponent({
    kind: "mcp_tool_call",
    label: "MCP tool invocation",
    description: "Invokes an MCP tool as a componentized callable unit with receipts.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/dynamic_native_tool.rs",
    capabilityScope: ["mcp.tool.invoke"],
    approvalRequired: true,
    eventKinds: ["AgentActionResult", "ExecutionContractReceipt"],
    evidence: ["server_id", "tool_name", "argument_hash", "result_hash"],
    group: "MCP",
    icon: "plug",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "connector_call",
    label: "Connector call",
    description: "Calls a connector operation through policy and capability grants.",
    kernelRef: "crates/services/src/connectors",
    capabilityScope: ["connector.invoke"],
    approvalRequired: true,
    eventKinds: ["ConnectorInvocation", "WorkloadReceipt"],
    evidence: ["connector_id", "operation", "request_hash", "result_hash"],
    group: "Connectors",
    icon: "cable",
    timeoutMs: 60000,
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "policy_gate",
    label: "Policy and firewall gate",
    description: "Evaluates firewall policy, deterministic commitments, and capability leases.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs",
    capabilityScope: ["policy.evaluate", "capability.lease"],
    eventKinds: ["FirewallDecisionReceipt", "DeterminismCommit"],
    evidence: ["policy_hash", "decision", "lease_id", "determinism_commit"],
    group: "Governance",
    icon: "shield",
  }),
  makeComponent({
    kind: "approval_gate",
    label: "Approval gate",
    description: "Pauses privileged actions until approval semantics are satisfied.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/approval",
    capabilityScope: ["approval.request"],
    approvalRequired: true,
    approvalMode: "human_gate",
    eventKinds: ["ApprovalRequested", "ApprovalSatisfied"],
    evidence: ["approval_id", "approval_scope", "approver"],
    group: "Governance",
    icon: "badge-check",
  }),
  makeComponent({
    kind: "wallet_capability",
    label: "Wallet capability request",
    description: "Requests runtime capability scope before spend, connector write, or external effect.",
    kernelRef: "crates/services/src/capabilities/wallet",
    capabilityScope: ["wallet.request", "capability.grant"],
    approvalRequired: true,
    approvalMode: "wallet_capability",
    eventKinds: ["CapabilityLease", "WalletRequestReceipt"],
    evidence: ["capability_scope", "lease_id", "budget"],
    group: "Governance",
    icon: "wallet",
  }),
  makeComponent({
    kind: "memory_read",
    label: "Memory read",
    description: "Reads session or worker memory through scoped state access.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/memory",
    capabilityScope: ["memory.read"],
    eventKinds: ["MemoryRead"],
    evidence: ["memory_key", "state_hash"],
    group: "State",
    icon: "database",
  }),
  makeComponent({
    kind: "memory_write",
    label: "Memory write",
    description: "Writes memory through state reducers and receipt-backed updates.",
    kernelRef: "crates/services/src/agentic/runtime/service/handler/execution/memory",
    capabilityScope: ["memory.write"],
    approvalRequired: true,
    eventKinds: ["MemoryWrite", "StateUpdate"],
    evidence: ["memory_key", "previous_hash", "next_hash"],
    group: "State",
    icon: "database",
  }),
  makeComponent({
    kind: "verifier",
    label: "Verifier",
    description: "Checks component outputs, schemas, contract receipts, and completion claims.",
    kernelRef: "crates/services/src/agentic/runtime/service/verifier",
    capabilityScope: ["verification.run"],
    eventKinds: ["ExecutionContractReceipt", "VerificationReceipt"],
    evidence: ["schema_hash", "contract_key", "verification_result"],
    group: "Verification",
    icon: "check-circle",
  }),
  makeComponent({
    kind: "semantic_impact_analyzer",
    label: "Semantic impact",
    description: "Classifies changed symbols, APIs, schemas, policies, call sites, tests, docs, and migration implications.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["impact.analyze", "evidence.read"],
    eventKinds: ["SemanticImpactAnalysis"],
    evidence: ["changed_symbols", "affected_tests", "risk_class"],
    group: "Verification",
    icon: "git-branch-plus",
  }),
  makeComponent({
    kind: "postcondition_synthesizer",
    label: "Postcondition synthesizer",
    description: "Derives success criteria, required receipts, and minimum verification evidence from the objective.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["verification.plan", "evidence.read"],
    eventKinds: ["PostconditionSynthesis"],
    evidence: ["postcondition_checks", "minimum_evidence", "unknowns"],
    group: "Verification",
    icon: "list-checks",
  }),
  makeComponent({
    kind: "drift_detector",
    label: "Drift detector",
    description: "Detects plan, file, branch, connector, requirement, policy, model, and projection drift.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["drift.detect", "session.state.read"],
    eventKinds: ["DriftSignal"],
    evidence: ["drift_flags", "drift_evidence_refs"],
    group: "Verification",
    icon: "activity",
  }),
  makeComponent({
    kind: "quality_ledger",
    label: "Quality ledger",
    description: "Records strategy, tool sequence, costs, failures, stop reason, scorecards, and promotion decisions.",
    kernelRef: "crates/services/src/agentic/runtime/substrate.rs",
    capabilityScope: ["quality.write", "scorecard.read"],
    eventKinds: ["AgentQualityLedger", "BenchmarkScorecard"],
    evidence: ["quality_ledger_id", "scorecard_metrics", "stop_condition"],
    group: "Verification",
    icon: "badge-check",
  }),
  makeComponent({
    kind: "handoff_bridge",
    label: "Handoff bridge",
    description: "Preserves objective, current state, blockers, evidence refs, and receiving-agent outcome across delegation.",
    kernelRef: "crates/services/src/agentic/runtime/service/lifecycle/worker_results",
    capabilityScope: ["handoff.write", "delegation.merge"],
    eventKinds: ["HandoffQuality", "WorkerResultMerged"],
    evidence: ["objective_preserved", "blockers_included", "receiver_succeeded"],
    group: "Delegation",
    icon: "split",
  }),
  makeComponent({
    kind: "gui_harness_validator",
    label: "GUI harness validator",
    description: "Validates retained Autopilot chat queries, screenshots, transcripts, traces, receipts, source chips, scorecards, and clean chat UX.",
    kernelRef: "scripts/run-autopilot-gui-harness-validation.mjs",
    capabilityScope: ["gui.validate", "harness.validate"],
    eventKinds: ["AutopilotGuiHarnessValidation", "CleanChatUxValidation"],
    evidence: ["screenshots", "transcripts", "trace_refs", "quality_ledger"],
    group: "Validation",
    icon: "monitor-check",
    timeoutMs: 600000,
  }),
  makeComponent({
    kind: "output_writer",
    label: "Output writer",
    description: "Materializes final user-visible output under output policy.",
    kernelRef: "crates/services/src/agentic/runtime/service/output",
    capabilityScope: ["output.write"],
    approvalRequired: true,
    eventKinds: ["OutputWritten", "AgentActionResult"],
    evidence: ["output_hash", "delivery_target", "output_policy_slot"],
    group: "Output",
    icon: "file-output",
  }),
  makeComponent({
    kind: "receipt_writer",
    label: "Receipt writer",
    description: "Emits durable receipts that link runtime events to workflow node ids.",
    kernelRef: "crates/services/src/agentic/runtime/service/receipts",
    capabilityScope: ["receipt.write"],
    eventKinds: ["ExecutionContractReceipt", "PlanReceipt", "WorkloadReceipt"],
    evidence: ["receipt_id", "node_id", "evidence_commit_hash"],
    group: "Receipts",
    icon: "receipt",
  }),
  makeComponent({
    kind: "retry_policy",
    label: "Retry policy",
    description: "Classifies retryable failures and chooses bounded retry behavior.",
    kernelRef: "crates/services/src/agentic/runtime/service/tool_execution/processing/retry",
    capabilityScope: ["retry.evaluate"],
    eventKinds: ["RetryScheduled", "RetryExhausted"],
    evidence: ["attempt", "max_attempts", "retry_reason"],
    group: "Recovery",
    icon: "rotate-ccw",
    maxAttempts: 3,
  }),
  makeComponent({
    kind: "repair_loop",
    label: "Repair loop",
    description: "Creates bounded repair attempts after verifier or tool failures.",
    kernelRef: "crates/services/src/agentic/runtime/service/repair",
    capabilityScope: ["repair.propose"],
    eventKinds: ["RepairAttemptStarted", "RepairAttemptCompleted"],
    evidence: ["failure_ref", "repair_strategy", "bounded_targets"],
    group: "Recovery",
    icon: "git-pull-request",
    maxAttempts: 2,
  }),
  makeComponent({
    kind: "merge_judge",
    label: "Merge and judge",
    description: "Merges branch outputs and judges competing repair or tool results.",
    kernelRef: "crates/services/src/agentic/runtime/service/judge",
    capabilityScope: ["judgement.run"],
    eventKinds: ["MergeReceipt", "JudgementReceipt"],
    evidence: ["candidate_hashes", "winner_reason", "judge_policy_hash"],
    group: "Verification",
    icon: "git-compare",
  }),
  makeComponent({
    kind: "completion_gate",
    label: "Completion gate",
    description: "Determines whether the turn is complete and safe to finalize.",
    kernelRef: "crates/services/src/agentic/runtime/service/decision_loop/completion",
    capabilityScope: ["completion.evaluate"],
    eventKinds: ["CompletionGateReceipt", "PlanReceipt"],
    evidence: ["completion_contract", "pending_actions", "final_decision"],
    group: "Completion",
    icon: "flag",
  }),
];

const REQUIRED_HARNESS_SLOTS: WorkflowHarnessSlotSpec[] = [
  {
    slotId: "slot.model-policy",
    kind: "model_policy",
    label: "Model policy",
    description: "Workflow-level model selection, budget, and fallback policy.",
    required: true,
    allowedComponentKinds: ["model_router", "model_call"],
    defaultComponentId: componentId("model_router"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must bind model routing to an explicit policy slot.",
    },
  },
  {
    slotId: "slot.tool-grants",
    kind: "tool_grant_policy",
    label: "Tool grant policy",
    description: "Workflow-level grants for native, workflow, connector, and MCP tools.",
    required: true,
    allowedComponentKinds: ["tool_router", "tool_call", "mcp_provider", "mcp_tool_call", "connector_call"],
    defaultComponentId: componentId("tool_router"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must make tool grants inspectable.",
    },
  },
  {
    slotId: "slot.state-policy",
    kind: "state_policy",
    label: "State policy",
    description: "Task state, drift, memory, and projection-state access rules.",
    required: true,
    allowedComponentKinds: ["task_state", "drift_detector", "memory_read", "memory_write"],
    defaultComponentId: componentId("task_state"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses must project task/world state through the shared substrate.",
    },
  },
  {
    slotId: "slot.budget-policy",
    kind: "budget_policy",
    label: "Budget policy",
    description: "Cognitive budget, escalation threshold, stop threshold, and retry bounds.",
    required: true,
    allowedComponentKinds: ["budget_gate", "model_router", "retry_policy"],
    defaultComponentId: componentId("budget_gate"),
    validation: {
      blocksActivation: true,
      reason: "Autonomous harnesses must expose their cognitive budget before activation.",
    },
  },
  {
    slotId: "slot.dry-run-policy",
    kind: "dry_run_policy",
    label: "Dry-run policy",
    description: "Preview rules for file, shell, connector, commerce, and policy side effects.",
    required: true,
    allowedComponentKinds: ["dry_run_simulator", "policy_gate", "tool_call", "connector_call"],
    defaultComponentId: componentId("dry_run_simulator"),
    validation: {
      blocksActivation: true,
      reason: "Effectful harness paths need a dry-run or preview policy.",
    },
  },
  {
    slotId: "slot.verifier",
    kind: "verifier_policy",
    label: "Verifier policy",
    description: "Schema, receipt, and completion verification policy.",
    required: true,
    allowedComponentKinds: [
      "verifier",
      "semantic_impact_analyzer",
      "postcondition_synthesizer",
      "merge_judge",
      "completion_gate",
      "gui_harness_validator",
    ],
    defaultComponentId: componentId("verifier"),
    validation: {
      blocksActivation: true,
      reason: "Activated harnesses require a verifier policy slot.",
    },
  },
  {
    slotId: "slot.approval",
    kind: "approval_policy",
    label: "Approval policy",
    description: "Approval gate and wallet capability semantics for privileged work.",
    required: true,
    allowedComponentKinds: ["approval_gate", "policy_gate", "wallet_capability"],
    defaultComponentId: componentId("approval_gate"),
    validation: {
      blocksActivation: true,
      reason: "Privileged harness forks require explicit approval semantics.",
    },
  },
  {
    slotId: "slot.output-policy",
    kind: "output_policy",
    label: "Output policy",
    description: "Rules for output writing, materialization, and receipt emission.",
    required: true,
    allowedComponentKinds: ["output_writer", "receipt_writer"],
    defaultComponentId: componentId("output_writer"),
    validation: {
      blocksActivation: true,
      reason: "Outputs must be governed before a harness fork can activate.",
    },
  },
  {
    slotId: "slot.memory-policy",
    kind: "memory_policy",
    label: "Memory policy",
    description: "Memory read/write scope and reducer behavior.",
    required: true,
    allowedComponentKinds: ["memory_read", "memory_write"],
    defaultComponentId: componentId("memory_read"),
    validation: {
      blocksActivation: true,
      reason: "Memory access must declare scope before activation.",
    },
  },
  {
    slotId: "slot.quality-ledger",
    kind: "quality_ledger_policy",
    label: "Quality ledger policy",
    description: "Scorecard, ledger writeback, stop reason, and bounded self-improvement evidence.",
    required: true,
    allowedComponentKinds: ["quality_ledger", "verifier", "completion_gate"],
    defaultComponentId: componentId("quality_ledger"),
    validation: {
      blocksActivation: true,
      reason: "Harness runs must emit quality ledger evidence before activation.",
    },
  },
  {
    slotId: "slot.handoff-policy",
    kind: "handoff_policy",
    label: "Handoff policy",
    description: "Delegation handoff, worker merge, blocker preservation, and receiver outcome quality.",
    required: true,
    allowedComponentKinds: ["handoff_bridge", "merge_judge", "receipt_writer"],
    defaultComponentId: componentId("handoff_bridge"),
    validation: {
      blocksActivation: true,
      reason: "Delegation-capable harnesses must preserve handoff quality evidence.",
    },
  },
  {
    slotId: "slot.retry-repair",
    kind: "retry_repair_policy",
    label: "Retry and repair policy",
    description: "Retry bounds, repair loops, and merge/judge behavior.",
    required: true,
    allowedComponentKinds: ["retry_policy", "repair_loop", "merge_judge"],
    defaultComponentId: componentId("retry_policy"),
    validation: {
      blocksActivation: true,
      reason: "Recovery behavior must be bounded before activation.",
    },
  },
];

export const DEFAULT_AGENT_HARNESS_SLOTS = REQUIRED_HARNESS_SLOTS;

const HARNESS_FLOW: WorkflowHarnessComponentKind[] = [
  "planner",
  "task_state",
  "uncertainty_gate",
  "budget_gate",
  "capability_sequencer",
  "model_router",
  "model_call",
  "tool_router",
  "dry_run_simulator",
  "policy_gate",
  "approval_gate",
  "wallet_capability",
  "mcp_provider",
  "mcp_tool_call",
  "tool_call",
  "connector_call",
  "probe_runner",
  "memory_read",
  "memory_write",
  "semantic_impact_analyzer",
  "postcondition_synthesizer",
  "verifier",
  "drift_detector",
  "retry_policy",
  "repair_loop",
  "merge_judge",
  "quality_ledger",
  "handoff_bridge",
  "gui_harness_validator",
  "completion_gate",
  "receipt_writer",
  "output_writer",
];

const SLOT_BY_KIND: Partial<Record<WorkflowHarnessComponentKind, WorkflowHarnessSlotKind[]>> = {
  task_state: ["state_policy"],
  uncertainty_gate: ["state_policy", "budget_policy"],
  probe_runner: ["verifier_policy", "budget_policy"],
  budget_gate: ["budget_policy"],
  capability_sequencer: ["tool_grant_policy"],
  model_router: ["model_policy"],
  model_call: ["model_policy"],
  tool_router: ["tool_grant_policy"],
  tool_call: ["tool_grant_policy"],
  dry_run_simulator: ["dry_run_policy"],
  mcp_provider: ["tool_grant_policy"],
  mcp_tool_call: ["tool_grant_policy"],
  connector_call: ["tool_grant_policy"],
  policy_gate: ["approval_policy"],
  approval_gate: ["approval_policy"],
  wallet_capability: ["approval_policy"],
  memory_read: ["memory_policy"],
  memory_write: ["memory_policy"],
  semantic_impact_analyzer: ["verifier_policy"],
  postcondition_synthesizer: ["verifier_policy"],
  verifier: ["verifier_policy"],
  drift_detector: ["state_policy", "verifier_policy"],
  retry_policy: ["retry_repair_policy"],
  repair_loop: ["retry_repair_policy"],
  merge_judge: ["retry_repair_policy", "verifier_policy"],
  quality_ledger: ["quality_ledger_policy"],
  handoff_bridge: ["handoff_policy"],
  gui_harness_validator: ["verifier_policy", "quality_ledger_policy"],
  output_writer: ["output_policy"],
  receipt_writer: ["output_policy"],
  completion_gate: ["verifier_policy", "quality_ledger_policy"],
};

function componentFor(kind: WorkflowHarnessComponentKind): WorkflowHarnessComponentSpec {
  const component = DEFAULT_AGENT_HARNESS_COMPONENTS.find((item) => item.kind === kind);
  if (!component) {
    throw new Error(`Missing harness component spec for ${kind}`);
  }
  return component;
}

function slotIdsFor(kind: WorkflowHarnessComponentKind): string[] {
  return (SLOT_BY_KIND[kind] ?? [])
    .map((slotKind) => REQUIRED_HARNESS_SLOTS.find((slot) => slot.kind === slotKind)?.slotId)
    .filter((slotId): slotId is string => Boolean(slotId));
}

function runtimeBindingFor(component: WorkflowHarnessComponentSpec): WorkflowHarnessNodeBinding {
  return {
    componentId: component.componentId,
    componentVersion: component.version,
    componentKind: component.kind,
    kernelRef: component.kernelRef,
    slotIds: slotIdsFor(component.kind),
    evidenceEventKinds: component.emittedEvents,
    receiptKinds: component.evidence,
    replay: {
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: [
        "uncertainty_gate",
        "budget_gate",
        "dry_run_simulator",
        "policy_gate",
        "approval_gate",
        "wallet_capability",
      ].includes(component.kind),
    },
  };
}

function nodeTypeFor(kind: WorkflowHarnessComponentKind): WorkflowNode["type"] {
  switch (kind) {
    case "task_state":
      return "task_state";
    case "uncertainty_gate":
      return "uncertainty_gate";
    case "probe_runner":
      return "probe";
    case "budget_gate":
      return "budget_gate";
    case "capability_sequencer":
      return "capability_sequence";
    case "model_call":
      return "model_call";
    case "tool_call":
    case "mcp_tool_call":
      return "plugin_tool";
    case "mcp_provider":
    case "connector_call":
      return "adapter";
    case "approval_gate":
    case "wallet_capability":
      return "human_gate";
    case "memory_read":
    case "memory_write":
      return "state";
    case "dry_run_simulator":
      return "dry_run";
    case "semantic_impact_analyzer":
      return "semantic_impact";
    case "postcondition_synthesizer":
      return "postcondition_synthesis";
    case "drift_detector":
      return "drift_detector";
    case "quality_ledger":
      return "quality_ledger";
    case "handoff_bridge":
      return "handoff";
    case "gui_harness_validator":
      return "gui_harness_validation";
    case "tool_router":
    case "model_router":
    case "policy_gate":
    case "merge_judge":
    case "completion_gate":
      return "decision";
    case "retry_policy":
    case "repair_loop":
      return "loop";
    case "receipt_writer":
      return "output";
    default:
      return "function";
  }
}

function nodeLogicFor(component: WorkflowHarnessComponentSpec): Record<string, unknown> {
  const base = {
    harnessComponent: component,
    harnessSlots: slotIdsFor(component.kind),
    inputSchema: component.inputSchema,
    outputSchema: component.outputSchema,
    errorSchema: component.errorSchema,
  };
  switch (component.kind) {
    case "model_call":
      return {
        ...base,
        modelRef: "reasoning",
        prompt: "Default agent harness model invocation envelope.",
        validateStructuredOutput: true,
        outputSchema: component.outputSchema,
      };
    case "tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "native_tool",
          toolRef: "agent.runtime.tool.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      };
    case "mcp_tool_call":
      return {
        ...base,
        toolBinding: {
          bindingKind: "mcp_tool",
          toolRef: "mcp.tool.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      };
    case "mcp_provider":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "mcp.capability-provider",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "read",
          requiresApproval: false,
        },
      };
    case "connector_call":
      return {
        ...base,
        connectorBinding: {
          connectorRef: "agent.connector.invoke",
          mockBinding: false,
          credentialReady: true,
          capabilityScope: component.requiredCapabilityScope,
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      };
    case "memory_read":
    case "memory_write":
      return {
        ...base,
        stateKey: component.kind,
        stateOperation: {
          key: component.kind,
          operation: component.kind === "memory_read" ? "read" : "write",
          reducer: "merge",
        },
      };
    case "retry_policy":
    case "repair_loop":
      return {
        ...base,
        loopKind: component.kind,
        maxIterations: component.retry.maxAttempts,
      };
    case "receipt_writer":
      return {
        ...base,
        format: "receipt",
        materialization: { enabled: false, assetPath: "receipts/harness/{{run.id}}.json" },
        deliveryTarget: { targetKind: "none" },
      };
    default:
      return {
        ...base,
        language: "javascript",
        code: "return { status: 'success', evidence: [], receipts: [] };",
        functionBinding: {
          language: "javascript",
          code: "return { status: 'success', evidence: [], receipts: [] };",
          outputSchema: component.outputSchema,
          sandboxPolicy: {
            timeoutMs: component.timeout.timeoutMs,
            memoryMb: 64,
            outputLimitBytes: 32768,
            permissions: [],
          },
          testInput: { sessionId: "test", turnId: "test" },
        },
      };
  }
}

function makeHarnessNode(
  kind: WorkflowHarnessComponentKind,
  index: number,
): WorkflowNode {
  const component = componentFor(kind);
  const type = nodeTypeFor(kind);
  const runtimeBinding = runtimeBindingFor(component);
  return {
    id: `harness.${kind}`,
    type,
    name: component.label,
    x: 90 + (index % 5) * 260,
    y: 110 + Math.floor(index / 5) * 190,
    metricLabel: component.ui.group,
    metricValue: component.kind,
    ioTypes: { in: "payload", out: "payload" },
    inputs: ["input"],
    outputs: ["output", "error", "retry"],
    runtimeBinding,
    config: {
      logic: nodeLogicFor(component),
      law: {
        requireHumanGate: component.approval.required,
        privilegedActions: component.approval.required ? component.requiredCapabilityScope : [],
        sandboxPolicy: {
          timeoutMs: component.timeout.timeoutMs,
          memoryMb: 64,
          outputLimitBytes: 65536,
          permissions: [],
        },
      },
    },
  };
}

function makeHarnessEdges(nodes: WorkflowNode[]): WorkflowEdge[] {
  return nodes.slice(0, -1).map((node, index) => ({
    id: `harness.edge.${node.id}.${nodes[index + 1].id}`,
    from: node.id,
    to: nodes[index + 1].id,
    fromPort: "output",
    toPort: "input",
    type: "data",
    connectionClass: "data",
    label: "deterministic envelope",
    data: {
      connectionClass: "data",
      receiptCorrelation: true,
    },
  }));
}

function harnessMetadata(options: {
  blessed: boolean;
  forkedFrom?: WorkflowHarnessMetadata["forkedFrom"];
  packageName?: string;
  activationId?: string;
  activationState: WorkflowHarnessMetadata["activationState"];
}): WorkflowHarnessMetadata {
  return {
    schemaVersion: "workflow.harness.v1",
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    templateName: "Default Agent Harness",
    blessed: options.blessed,
    forkable: options.blessed,
    forkedFrom: options.forkedFrom,
    packageName: options.packageName,
    activationId: options.activationId,
    activationState: options.activationState,
    validationGates: [
      "component_contracts_present",
      "required_slots_bound",
      "proposal_only_self_mutation",
      "receipts_mapped_to_nodes",
      "tests_and_replay_present",
      "activation_review_complete",
    ],
    aiMutationMode: "proposal_only",
    componentIds: DEFAULT_AGENT_HARNESS_COMPONENTS.map((component) => component.componentId),
    slotIds: REQUIRED_HARNESS_SLOTS.map((slot) => slot.slotId),
  };
}

export function makeDefaultAgentHarnessWorkflow(nowMs = Date.now()): WorkflowProject {
  const nodes = HARNESS_FLOW.map(makeHarnessNode);
  return {
    version: "workflow.v1",
    metadata: {
      id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      name: "Default Agent Harness",
      slug: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
      workflowKind: "agent_workflow",
      executionMode: "hybrid",
      gitLocation: `.agents/workflows/${DEFAULT_AGENT_HARNESS_WORKFLOW_ID}.workflow.json`,
      readOnly: true,
      dirty: false,
      harness: harnessMetadata({
        blessed: true,
        activationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        activationState: "read_only",
      }),
      workerHarnessBinding: {
        harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
        harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
        harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        source: "default",
      },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    nodes,
    edges: makeHarnessEdges(nodes),
    global_config: normalizeGlobalConfig({
      environmentProfile: {
        target: "local",
        credentialScope: "runtime-default",
        mockBindingPolicy: "warn",
      },
      modelBindings: {
        reasoning: { modelId: "default-agent-model-policy", required: true },
        vision: { modelId: "", required: false },
        embedding: { modelId: "", required: false },
        image: { modelId: "", required: false },
      },
      policy: {
        maxBudget: 10,
        maxSteps: 80,
        timeoutMs: 180000,
      },
      contract: {
        developerBond: 0,
        adjudicationRubric:
          "Default harness projection is inspectable and read-only; forks must pass activation gates before use.",
      },
      meta: {
        name: "Default Agent Harness",
        description:
          "Read-only projection of the blessed agent runtime harness as workflow-addressable components.",
      },
      production: {
        errorWorkflowPath: ".agents/workflows/default-agent-harness-error.workflow.json",
        evaluationSetPath: ".agents/workflows/default-agent-harness.tests.json",
        expectedTimeSavedMinutes: 0,
        mcpAccessReviewed: true,
        requireReplayFixtures: false,
      },
    }),
  };
}

export function defaultAgentHarnessTests(
  workflow: WorkflowProject = makeDefaultAgentHarnessWorkflow(0),
): WorkflowTestCase[] {
  const componentNodeIds = workflow.nodes.map((node) => node.id);
  return [
    {
      id: "test-default-harness-components-present",
      name: "Default harness components are projected",
      targetNodeIds: componentNodeIds.slice(0, 8),
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-governance-present",
      name: "Default harness governance components are projected",
      targetNodeIds: ["harness.policy_gate", "harness.approval_gate", "harness.receipt_writer"],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
    {
      id: "test-default-harness-recovery-present",
      name: "Default harness retry and repair components are projected",
      targetNodeIds: ["harness.retry_policy", "harness.repair_loop", "harness.merge_judge"],
      assertion: { kind: "node_exists" },
      status: "idle",
    },
  ];
}

export function forkDefaultAgentHarnessWorkflow(
  name = "Default Agent Harness Fork",
  nowMs = Date.now(),
): {
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
} {
  const base = makeDefaultAgentHarnessWorkflow(nowMs);
  const slug = slugify(name);
  const workflow: WorkflowProject = {
    ...base,
    metadata: {
      ...base.metadata,
      id: slug,
      name,
      slug,
      gitLocation: `.agents/workflows/${slug}.workflow.json`,
      readOnly: false,
      dirty: true,
      harness: harnessMetadata({
        blessed: false,
        forkedFrom: {
          harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
          harnessVersion: DEFAULT_AGENT_HARNESS_VERSION,
          harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        },
        packageName: slug,
        activationState: "blocked",
      }),
      workerHarnessBinding: {
        harnessWorkflowId: slug,
        harnessHash: DEFAULT_AGENT_HARNESS_HASH,
        source: "fork",
      },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    },
    global_config: normalizeGlobalConfig({
      ...base.global_config,
      environmentProfile: {
        target: "sandbox",
        credentialScope: "harness-fork",
        mockBindingPolicy: "block",
      },
      meta: {
        name,
        description:
          "Editable fork of the Default Agent Harness. Activation remains blocked until validation gates pass.",
      },
      production: {
        ...(base.global_config.production ?? {}),
        mcpAccessReviewed: false,
        requireReplayFixtures: true,
      },
    }),
  };
  return {
    workflow,
    tests: defaultAgentHarnessTests(workflow),
    proposals: [
      {
        id: `proposal-${slug}-activation-gates`,
        title: "Review harness fork activation gates",
        summary:
          "Forked harness packages stay inactive until component slots, MCP access, replay evidence, and proposal-only mutation gates are validated.",
        status: "open",
        createdAtMs: nowMs,
        boundedTargets: [
          "workflow-metadata",
          "workflow-config",
          "harness.slot.model-policy",
          "harness.slot.tool-grants",
          "harness.slot.approval",
          "harness.slot.output-policy",
        ],
        configDiff: {
          changedGlobalKeys: ["environmentProfile", "production"],
          changedMetadataKeys: ["harness", "workerHarnessBinding"],
        },
        sidecarDiff: {
          testsChanged: true,
          fixturesChanged: true,
          bindingsChanged: true,
          proposalsChanged: true,
          changedRoles: ["tests", "fixtures", "bindings", "activation"],
        },
      },
    ],
  };
}

export function workflowIsHarness(workflow: WorkflowProject): boolean {
  return Boolean(workflow.metadata.harness);
}

export function workflowIsBlessedHarness(workflow: WorkflowProject): boolean {
  return workflow.metadata.harness?.blessed === true;
}

export function workflowIsHarnessFork(workflow: WorkflowProject): boolean {
  return workflowIsHarness(workflow) && workflow.metadata.harness?.blessed !== true;
}

export function harnessComponentForNode(node: Node): WorkflowHarnessComponentSpec | null {
  const logic = node.config?.logic ?? {};
  const value = (logic as Record<string, unknown>).harnessComponent;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const component = value as WorkflowHarnessComponentSpec;
  if (!component.componentId || !component.kind) return null;
  return component;
}

export function harnessSlotsForWorkflow(workflow: WorkflowProject): WorkflowHarnessSlotSpec[] {
  if (!workflowIsHarness(workflow)) return [];
  return REQUIRED_HARNESS_SLOTS;
}

export function workflowHarnessWorkerBinding(
  workflow: WorkflowProject,
): WorkflowHarnessWorkerBinding {
  if (workflow.metadata.workerHarnessBinding) return workflow.metadata.workerHarnessBinding;
  const harness = workflow.metadata.harness;
  if (harness) {
    return {
      harnessWorkflowId: workflow.metadata.id,
      harnessActivationId: harness.activationId,
      harnessHash: harness.harnessHash,
      source: harness.blessed ? "default" : "fork",
    };
  }
  return {
    harnessWorkflowId: DEFAULT_AGENT_HARNESS_WORKFLOW_ID,
    harnessActivationId: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
    harnessHash: DEFAULT_AGENT_HARNESS_HASH,
    source: "legacy",
  };
}

export function harnessNodeEvidenceSummary(node: Node): Array<{ label: string; value: string }> {
  const component = harnessComponentForNode(node);
  if (!component) return [];
  return [
    { label: "Component", value: component.componentId },
    { label: "Version", value: component.version },
    { label: "Kernel", value: component.kernelRef },
    { label: "Capability", value: component.requiredCapabilityScope.join(", ") || "none" },
    { label: "Approval", value: component.approval.required ? component.approval.mode : "none" },
    { label: "Events", value: component.emittedEvents.join(", ") },
    { label: "Evidence", value: component.evidence.join(", ") },
  ];
}
