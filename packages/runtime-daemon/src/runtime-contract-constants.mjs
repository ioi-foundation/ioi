export const TERMINAL_EVENT_TYPES = new Set(["completed", "canceled", "failed", "error"]);
export const JOB_TERMINAL_EVENT_TYPES = new Set(["job_completed", "job_failed", "job_canceled"]);
export const RUNTIME_THREAD_SCHEMA_VERSION = "ioi.runtime.thread.v1";
export const RUNTIME_TURN_SCHEMA_VERSION = "ioi.runtime.turn.v1";
export const RUNTIME_EVENT_ENVELOPE_SCHEMA_VERSION = "ioi.runtime.event.v1";
export const RUNTIME_THREAD_CONTROLS_SCHEMA_VERSION = "ioi.runtime.thread-controls.v1";
export const RUNTIME_THREAD_MODE_CONTROL_SCHEMA_VERSION = "ioi.runtime.thread-mode-control.v1";
export const RUNTIME_MODEL_ROUTE_CONTROL_SCHEMA_VERSION = "ioi.runtime.model-route-control.v1";
export const WORKSPACE_TRUST_WARNING_SCHEMA_VERSION = "ioi.runtime.workspace-trust-warning.v1";
export const WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION = "ioi.runtime.workspace-trust-acknowledgement.v1";
export const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_SCHEMA_VERSION =
  "ioi.workflow.coding-tool-budget-recovery.v1";
export const WORKFLOW_CODING_TOOL_BUDGET_RECOVERY_POLICY_SCHEMA_VERSION =
  "ioi.workflow.coding-tool-budget-recovery-policy.v1";
export const WORKFLOW_RUN_CODING_TOOL_BUDGET_PREFLIGHT_BLOCKED_REASON =
  "coding_tool_budget_preflight_blocked";
export const CODING_TOOL_ARTIFACT_SCHEMA_VERSION = "ioi.runtime.coding-tool-artifact.v1";
export const COMPUTER_USE_VISUAL_ARTIFACT_MAX_BYTES = 5 * 1024 * 1024;
export const RUNTIME_MCP_SERVE_SCHEMA_VERSION = "ioi.runtime.mcp-serve.v1";
export const RUNTIME_MCP_SERVE_PROTOCOL_VERSION = "2024-11-05";
export const RUNTIME_MCP_SERVE_DEFAULT_ALLOWED_TOOL_IDS = [
  "workspace.status",
  "git.diff",
  "file.inspect",
];
export const RUNTIME_MCP_MANAGER_VALIDATION_SCHEMA_VERSION =
  "ioi.runtime.mcp-manager-validation.v1";
export const RUNTIME_MCP_TOOL_SEARCH_SCHEMA_VERSION = "ioi.runtime.mcp-tool-search.v1";
export const RUNTIME_USAGE_DELTA_SCHEMA_VERSION = "ioi.runtime.usage-delta.v1";
export const RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION = "ioi.runtime.context-pressure-delta.v1";
export const RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION = "ioi.runtime.context-pressure-alert.v1";
export const RUNTIME_CONTEXT_BUDGET_SCHEMA_VERSION = "ioi.runtime.context-budget-policy.v1";
export const RUNTIME_COMPACTION_POLICY_SCHEMA_VERSION = "ioi.runtime.compaction-policy.v1";
export const MCP_LIVE_CATALOG_DEFAULT_PREVIEW_LIMIT = 50;
export const MCP_LIVE_CATALOG_MAX_PREVIEW_LIMIT = 200;
export const WORKSPACE_SNAPSHOT_SCHEMA_VERSION = "ioi.runtime.workspace-snapshot.v1";
export const WORKSPACE_SNAPSHOT_NODE_ID = "runtime.workspace-snapshot";
export const WORKSPACE_RESTORE_PREVIEW_SCHEMA_VERSION = "ioi.runtime.workspace-restore-preview.v1";
export const WORKSPACE_RESTORE_APPLY_SCHEMA_VERSION = "ioi.runtime.workspace-restore-apply.v1";
export const WORKSPACE_RESTORE_PREVIEW_NODE_ID = "runtime.restore-gate";
export const LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION = "ioi.runtime.lsp-diagnostics-injection.v1";
export const LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION = "ioi.runtime.lsp-diagnostics-blocking-gate.v1";
export const DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION = "ioi.runtime.diagnostics-rollback-repair-context.v1";
export const DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION = "ioi.runtime.diagnostics-rollback-repair-policy.v1";
export const DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION = "ioi.runtime.diagnostics-repair-decision-execution.v1";
export const LSP_DIAGNOSTICS_AUTO_NODE_ID = "runtime.coding-tool.lsp-diagnostics.auto";
export const LSP_DIAGNOSTICS_INJECTION_NODE_ID = "runtime.lsp-diagnostics.injected";
export const LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID = "runtime.lsp-diagnostics.blocking-gate";
export const LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID = "runtime.lsp-diagnostics.repair.retry";
export const LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID = "runtime.lsp-diagnostics.repair.operator-override";
export const LSP_DIAGNOSTICS_REPAIR_RESTORE_PREVIEW_NODE_ID = "runtime.lsp-diagnostics.repair.restore-preview";
export const LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID = "runtime.lsp-diagnostics.repair.restore-apply";
export const LSP_DIAGNOSTICS_MAX_INJECTED_FINDINGS = 10;
export const LSP_DIAGNOSTICS_MAX_INJECTED_MESSAGE_CHARS = 240;
export const DAEMON_FIXTURE_PROFILE = "local_daemon_agentgres_projection";
export const RUN_EVENT_TO_TTI_EVENT = {
  run_started: "turn.started",
  runtime_task: "item.completed",
  job_queued: "item.created",
  job_started: "item.started",
  runtime_checklist: "item.completed",
  job_completed: "item.completed",
  job_failed: "item.failed",
  job_canceled: "item.canceled",
  repository_context: "item.completed",
  branch_policy: "item.completed",
  github_context: "item.completed",
  issue_context: "item.completed",
  pr_attempt: "item.completed",
  review_gate: "item.completed",
  github_pr_create_plan: "item.completed",
  model_route_decision: "item.completed",
  computer_use_environment_selected: "computer_use.environment_selected",
  computer_use_environment_unavailable: "computer_use.environment_unavailable",
  computer_use_lease_acquired: "computer_use.lease_acquired",
  computer_use_run_state: "computer_use.run_state",
  computer_use_observation: "computer_use.observation",
  computer_use_affordance_graph: "computer_use.affordance_graph",
  computer_use_browser_discovery: "computer_use.browser_discovery",
  computer_use_action_proposed: "computer_use.action_proposed",
  computer_use_action_executed: "computer_use.action_executed",
  computer_use_verification: "computer_use.verification",
  computer_use_commit_gate: "computer_use.commit_gate",
  computer_use_trajectory_written: "computer_use.trajectory_written",
  computer_use_cleanup: "computer_use.cleanup",
  computer_use_control: "computer_use.control",
  skill_hook_manifest: "item.completed",
  hook_dry_run_plan: "item.completed",
  hook_invocation_ledger: "item.completed",
  memory_update: "item.completed",
  lsp_diagnostics_injected: "lsp.diagnostics.injected",
  policy_blocked: "policy.blocked",
  task_state: "item.completed",
  uncertainty: "item.completed",
  probe: "item.completed",
  postcondition_synthesized: "item.completed",
  semantic_impact: "item.completed",
  delta: "item.delta",
  usage_delta: "usage.delta",
  context_pressure_delta: "context.pressure_delta",
  context_pressure_alert: "context.pressure_alert",
  usage_final: "item.completed",
  stop_condition: "item.completed",
  quality_ledger: "item.completed",
  artifact: "item.completed",
  completed: "turn.completed",
  canceled: "turn.canceled",
  failed: "turn.failed",
  error: "turn.failed",
};
export const COMPUTER_USE_BROWSER_DISCOVERY_TOOL_IDS = new Set([
  "ioi.computer_use.browser_discovery",
  "computer_use.browser_discovery",
]);
export const COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS = new Set([
  "ioi.computer_use.native_browser",
  "computer_use.native_browser",
]);
export const COMPUTER_USE_VISUAL_GUI_TOOL_IDS = new Set([
  "ioi.computer_use.visual_gui",
  "computer_use.visual_gui",
]);
export const COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS = new Set([
  "ioi.computer_use.sandboxed_hosted",
  "computer_use.sandboxed_hosted",
  "ioi.computer_use.sandboxed",
  "computer_use.sandboxed",
]);
export const COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS = new Set([
  "ioi.computer_use.visual_gui.observe",
  "computer_use.visual_gui.observe",
  "ioi.computer_use.visual_gui_observe",
  "computer_use.visual_gui_observe",
]);
export const COMPUTER_USE_CONTROL_TOOL_IDS = new Set([
  "ioi.computer_use.control",
  "computer_use.control",
]);
export const HOOK_INVOCATION_RUNTIME_EVENTS = [
  {
    eventKind: "workflow_activation",
    runtimeEventType: "run_started",
    phase: "activation",
    workflowNodeId: "runtime.runtime-thread",
  },
  {
    eventKind: "pre_model",
    runtimeEventType: "model_route_decision",
    phase: "before_model",
    workflowNodeId: "runtime.model-router",
  },
  {
    eventKind: "post_model",
    runtimeEventType: "delta",
    phase: "after_model",
    workflowNodeId: "runtime.output-writer",
  },
];
