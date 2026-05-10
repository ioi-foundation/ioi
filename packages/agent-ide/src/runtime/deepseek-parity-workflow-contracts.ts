export const DEEPSEEK_PARITY_WORKFLOW_SCHEMA_VERSION =
  "ioi.agent-runtime.deepseek-parity.workflow.v1";

export type DeepSeekParityNodeCategory =
  | "runtime"
  | "model"
  | "tool"
  | "safety"
  | "subagent"
  | "memory"
  | "skill"
  | "hook"
  | "recovery"
  | "verification"
  | "repository";

export type DeepSeekParityRuntimeOwner =
  | "runtime_service"
  | "daemon_api"
  | "agent_sdk"
  | "cli_tui"
  | "workflow_projection"
  | "agentgres_projection";

export interface DeepSeekParityWorkflowNodeContract {
  schemaVersion: typeof DEEPSEEK_PARITY_WORKFLOW_SCHEMA_VERSION;
  nodeType: string;
  category: DeepSeekParityNodeCategory;
  componentKind: string;
  runtimeOwner: DeepSeekParityRuntimeOwner;
  inputPorts: string[];
  outputPorts: string[];
  configSchemaRef: string;
  capabilityRequirements: string[];
  authorityScopeRequirements: string[];
  approvalProfile: string;
  eventKindsEmitted: string[];
  receiptKindsEmitted: string[];
  artifactKindsEmitted: string[];
  replayBehavior: "replayable" | "projection_only" | "non_replayable";
  rollbackBehavior: "none" | "snapshot" | "restore_gate";
  validationRules: string[];
  defaultVisualStatus: "idle" | "ready" | "blocked" | "running";
}

export interface DeepSeekParityWorkflowEdgeContract {
  schemaVersion: typeof DEEPSEEK_PARITY_WORKFLOW_SCHEMA_VERSION;
  edgeType: string;
  sourcePort: string;
  targetPort: string;
  payloadType: string;
  ordering: "ordered" | "unordered" | "barrier";
  backpressure: "drop" | "buffer" | "block";
  cancellationPropagation: "none" | "downstream" | "bidirectional";
  failurePropagation: "none" | "downstream" | "graph";
  replaySemantics: "event_cursor" | "artifact_ref" | "projection";
}

export interface DeepSeekParityWorkflowManifest {
  schemaVersion: typeof DEEPSEEK_PARITY_WORKFLOW_SCHEMA_VERSION;
  graphId: string;
  runtimeComponentManifestRef: string;
  toolRegistryManifestRef: string;
  modelRoutingManifestRef: string;
  approvalPolicyManifestRef: string;
  memorySkillsHooksManifestRef: string;
  subagentManifestRef: string;
  artifactRetentionManifestRef: string;
  testFixtureManifestRef: string;
  schemaHash: string;
  activationReceiptRef: string;
  nodeContracts: DeepSeekParityWorkflowNodeContract[];
  edgeContracts: DeepSeekParityWorkflowEdgeContract[];
}

export const DEEPSEEK_PARITY_REQUIRED_NODE_TYPES = [
  "runtime.thread",
  "runtime.turn",
  "runtime.event_stream",
  "runtime.doctor",
  "runtime.agentgres_projection",
  "model.router",
  "model.reasoning_effort",
  "model.context_budget",
  "model.compaction_policy",
  "tool.pack",
  "tool.filesystem",
  "tool.patch",
  "tool.git",
  "tool.shell_job",
  "tool.web",
  "tool.browser",
  "tool.gui",
  "tool.mcp",
  "tool.lsp_diagnostics",
  "tool.test_runner",
  "tool.artifact_store",
  "safety.approval_gate",
  "safety.policy_decision",
  "safety.authority_scope",
  "safety.pii_redaction",
  "safety.sandbox_profile",
  "safety.trust_profile",
  "subagent.pool",
  "subagent.role",
  "subagent.spawn",
  "subagent.join",
  "worker.template",
  "worker.handoff_quality",
  "memory.scope",
  "memory.injection",
  "memory.remember",
  "skill.pack",
  "skill.instruction",
  "hook.runtime",
  "recovery.rollback_snapshot",
  "recovery.restore_gate",
  "recovery.retry_policy",
  "recovery.incident",
  "verification.checklist",
  "verification.gate",
  "verification.diagnostics",
  "verification.scorecard",
  "verification.quality_ledger",
  "repository.context",
  "repository.branch_policy",
  "repository.issue",
  "repository.pr_attempt",
  "repository.review_gate",
] as const;

export type DeepSeekParityRequiredNodeType =
  (typeof DEEPSEEK_PARITY_REQUIRED_NODE_TYPES)[number];

export function isDeepSeekParityRequiredNodeType(
  nodeType: string,
): nodeType is DeepSeekParityRequiredNodeType {
  return DEEPSEEK_PARITY_REQUIRED_NODE_TYPES.includes(
    nodeType as DeepSeekParityRequiredNodeType,
  );
}

export function missingDeepSeekParityNodeTypes(
  nodeTypes: readonly string[],
): DeepSeekParityRequiredNodeType[] {
  const present = new Set(nodeTypes);
  return DEEPSEEK_PARITY_REQUIRED_NODE_TYPES.filter(
    (nodeType) => !present.has(nodeType),
  );
}
