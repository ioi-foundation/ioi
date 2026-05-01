export const AGENT_ACTION_KINDS = [
  "source_input",
  "trigger",
  "task_state",
  "uncertainty_gate",
  "probe",
  "budget_gate",
  "capability_sequence",
  "function",
  "model_binding",
  "model_call",
  "parser",
  "adapter_connector",
  "plugin_tool",
  "dry_run",
  "state",
  "decision",
  "loop",
  "barrier",
  "subgraph",
  "human_gate",
  "semantic_impact",
  "postcondition_synthesis",
  "verifier",
  "drift_detector",
  "quality_ledger",
  "handoff",
  "gui_harness_validation",
  "output",
  "test_assertion",
  "proposal",
  "unknown",
] as const;

export const AGENT_ACTION_SCHEMA_VERSION = "ioi.runtime-action-schema.v1" as const;

export const AGENT_ACTION_ENTRY_KINDS = [
  "source_input",
  "trigger",
] as const;

export const AGENT_ACTION_TERMINAL_KINDS = [
  "output",
] as const;

export const AGENT_ACTION_COMPLETION_VERIFICATION_KINDS = [
  "function",
  "model_binding",
  "model_call",
  "parser",
  "adapter_connector",
  "plugin_tool",
  "subgraph",
  "proposal",
  "probe",
  "dry_run",
  "semantic_impact",
  "postcondition_synthesis",
  "verifier",
  "gui_harness_validation",
] as const;
