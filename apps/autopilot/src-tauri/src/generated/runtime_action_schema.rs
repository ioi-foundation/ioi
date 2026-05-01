pub const RUNTIME_ACTION_SCHEMA_VERSION: &str = "ioi.runtime-action-schema.v1";

pub const RUNTIME_ACTION_KINDS: &[&str] = &[
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
];

pub const RUNTIME_ACTION_ENTRY_KINDS: &[&str] = &[
    "source_input",
    "trigger",
];

pub const RUNTIME_ACTION_TERMINAL_KINDS: &[&str] = &[
    "output",
];

pub const RUNTIME_ACTION_COMPLETION_VERIFICATION_KINDS: &[&str] = &[
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
];
