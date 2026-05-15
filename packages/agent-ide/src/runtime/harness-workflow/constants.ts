export const DEFAULT_AGENT_HARNESS_WORKFLOW_ID = "default-agent-harness";
export const DEFAULT_AGENT_HARNESS_VERSION = "2026.04.default-harness.v1";
export const DEFAULT_AGENT_HARNESS_HASH =
  "sha256:default-agent-harness-component-projection-v1";
export const DEFAULT_AGENT_HARNESS_ACTIVATION_ID =
  "activation:default-agent-harness:blessed-readonly";
export const DEFAULT_AGENT_HARNESS_LIVE_SHADOW_COMPARISON_GATE_ID =
  "p0-live-shadow-comparison-gate";
export const DEFAULT_AGENT_HARNESS_FORK_ROLLBACK_TARGET =
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID;
export const DEFAULT_AGENT_HARNESS_FORK_ACTIVATION_BLOCKERS = Object.freeze([
  "harness_activation_not_validated",
  "required_slots_unbound",
  "replay_fixtures_missing",
  "canary_not_run",
  "activation_review_incomplete",
]);
export const DEFAULT_AGENT_HARNESS_FORK_MUTATION_TARGET_PATH =
  "global_config.policy.maxSteps";
export const DEFAULT_AGENT_HARNESS_FORK_MUTATION_BEFORE_VALUE = "80";
export const DEFAULT_AGENT_HARNESS_FORK_MUTATION_AFTER_VALUE = "64";
export const DEFAULT_AGENT_HARNESS_ACTIVATION_ID_GATE_PROOF_MAX_AGE_MS =
  5 * 60 * 1000;
export const DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_INVARIANT =
  "reviewed_import_activation_apply";
export const DEFAULT_AGENT_HARNESS_REVIEWED_IMPORT_ACTIVATION_APPLY_PROOF_MAX_AGE_MS =
  5 * 60 * 1000;

export const HARNESS_INPUT_SCHEMA = {
  type: "object",
  required: ["sessionId", "turnId"],
  properties: {
    sessionId: { type: "string" },
    turnId: { type: "string" },
    input: {},
    state: { type: "object" },
    policyContext: { type: "object" },
  },
} as const;

export const HARNESS_OUTPUT_SCHEMA = {
  type: "object",
  required: ["status"],
  properties: {
    status: { type: "string" },
    value: {},
    evidence: { type: "array", items: { type: "string" } },
    receipts: { type: "array", items: { type: "string" } },
  },
} as const;

export const HARNESS_ERROR_SCHEMA = {
  type: "object",
  required: ["code", "message", "retryable"],
  properties: {
    code: { type: "string" },
    message: { type: "string" },
    retryable: { type: "boolean" },
    evidenceRef: { type: "string" },
  },
} as const;
