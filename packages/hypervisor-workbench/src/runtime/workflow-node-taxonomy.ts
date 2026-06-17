import type {
  WorkflowEvidenceProfile,
  WorkflowNodeExecutor,
  WorkflowNodeFamily,
  WorkflowNodeKind,
  WorkflowPolicyProfile,
  WorkflowPortDefinition,
} from "../types/graph";

export type WorkflowCanonicalPrimitive =
  | "trigger"
  | "input"
  | "context"
  | "agent_step"
  | "tool_pack"
  | "connector"
  | "memory"
  | "skills"
  | "hook"
  | "policy_gate"
  | "worker"
  | "state"
  | "control_flow"
  | "verification"
  | "recovery"
  | "pull_request"
  | "output"
  | "harness_runtime";

export type WorkflowPaletteVisibility =
  | "default"
  | "template"
  | "advanced"
  | "hidden";

export interface WorkflowNodeRuntimeMapping {
  componentKind: string;
  executorId: string;
  contract: string;
  eventKinds: string[];
  receiptKinds: string[];
}

export interface WorkflowNodeShapeProfile {
  executionBoundary: WorkflowCanonicalPrimitive;
  authorityBoundary: string;
  statusTextEquivalent: string;
}

export interface WorkflowNodeTaxonomyMetadata {
  canonicalPrimitive: WorkflowCanonicalPrimitive;
  paletteVisibility: WorkflowPaletteVisibility;
  collapseTarget: string;
  displayLabel: string;
  advancedLabel: string;
  searchAliases: string[];
  configSections: string[];
  runtimeMapping: WorkflowNodeRuntimeMapping;
  shapeProfile: WorkflowNodeShapeProfile;
  migrationCompatibility: "native" | "projected" | "legacy_compatible";
}

export interface WorkflowNodeTaxonomyInput {
  type: WorkflowNodeKind;
  label: string;
  family: WorkflowNodeFamily;
  familyLabel: string;
  group?: string;
  creatorId?: string;
  baseType?: WorkflowNodeKind;
  metricLabel?: string;
  metricValue?: string;
  portDefinitions?: WorkflowPortDefinition[];
  ports?: WorkflowPortDefinition[];
  policyProfile: WorkflowPolicyProfile;
  evidenceProfile: WorkflowEvidenceProfile;
  executor: WorkflowNodeExecutor;
}

const TYPE_PRIMITIVE: Partial<Record<WorkflowNodeKind, WorkflowCanonicalPrimitive>> = {
  source: "input",
  trigger: "trigger",
  runtime_doctor: "verification",
  runtime_task: "harness_runtime",
  runtime_job: "harness_runtime",
  runtime_checklist: "harness_runtime",
  runtime_thread_fork: "harness_runtime",
  runtime_operator_interrupt: "harness_runtime",
  runtime_operator_steer: "harness_runtime",
  runtime_thread_mode: "policy_gate",
  runtime_workspace_trust_gate: "policy_gate",
  runtime_context_compact: "recovery",
  runtime_approval_request: "policy_gate",
  runtime_usage_meter: "harness_runtime",
  runtime_context_budget: "policy_gate",
  runtime_compaction_policy: "policy_gate",
  runtime_rollback_snapshot: "recovery",
  runtime_restore_gate: "recovery",
  runtime_diagnostics_repair: "recovery",
  runtime_coding_tool_budget_recovery: "recovery",
  workflow_package_export: "harness_runtime",
  workflow_package_import: "harness_runtime",
  repository_context: "context",
  branch_policy: "policy_gate",
  github_context: "context",
  issue_context: "context",
  pr_attempt: "pull_request",
  review_gate: "policy_gate",
  github_pr_create: "pull_request",
  function: "control_flow",
  model_binding: "agent_step",
  model_call: "agent_step",
  skill_context: "skills",
  skill: "skills",
  skill_pack: "skills",
  hook: "hook",
  hook_policy: "hook",
  parser: "agent_step",
  adapter: "connector",
  plugin_tool: "tool_pack",
  dry_run: "verification",
  state: "state",
  decision: "control_flow",
  loop: "control_flow",
  barrier: "control_flow",
  subgraph: "control_flow",
  human_gate: "policy_gate",
  semantic_impact: "verification",
  postcondition_synthesis: "verification",
  verifier: "verification",
  drift_detector: "verification",
  quality_ledger: "verification",
  handoff: "output",
  gui_harness_validation: "verification",
  output: "output",
  test_assertion: "verification",
  proposal: "pull_request",
  task_state: "state",
  uncertainty_gate: "policy_gate",
  probe: "verification",
  budget_gate: "policy_gate",
  capability_sequence: "control_flow",
};

const RAW_RUNTIME_TYPES = new Set<WorkflowNodeKind>([
  "runtime_task",
  "runtime_job",
  "runtime_checklist",
  "runtime_thread_fork",
  "runtime_operator_interrupt",
  "runtime_operator_steer",
  "runtime_usage_meter",
  "workflow_package_export",
  "workflow_package_import",
]);

const SUBFACET_TYPES = new Set<WorkflowNodeKind>([
  "model_binding",
  "parser",
  "skill_context",
  "skill_pack",
  "hook_policy",
]);

export const WORKFLOW_PRIMITIVE_CONFIG_SECTIONS: Record<
  WorkflowCanonicalPrimitive,
  string[]
> = {
  trigger: ["start", "schedule", "event", "runtime"],
  input: ["source", "schema", "sanitization", "sample"],
  context: ["source", "scope", "binding", "receipts"],
  agent_step: ["model", "reasoning", "tools", "memory", "skills", "output"],
  tool_pack: ["tools", "authority", "approval", "result"],
  connector: ["provider", "credentials", "authority", "readiness"],
  memory: ["operation", "scope", "retention", "approval"],
  skills: ["discovery", "selection", "injection", "trust", "audit"],
  hook: ["event", "contract", "authority", "failure"],
  policy_gate: ["policy", "approval", "authority", "blockers"],
  worker: ["role", "pool", "lifecycle", "merge", "cancellation"],
  state: ["operation", "key", "reducer", "checkpoint"],
  control_flow: ["routing", "conditions", "retry", "subgraph"],
  verification: ["check", "assertion", "diagnostics", "evidence"],
  recovery: ["snapshot", "restore", "repair", "approval"],
  pull_request: ["repository", "branch", "review", "artifact", "authority"],
  output: ["format", "artifact", "delivery", "schema"],
  harness_runtime: ["runtime", "replay", "receipts", "debug"],
};

function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => value?.trim().toLowerCase())
        .filter((value): value is string => Boolean(value)),
    ),
  );
}

function creatorPrimitive(
  input: WorkflowNodeTaxonomyInput,
): WorkflowCanonicalPrimitive | null {
  const creatorId = input.creatorId ?? "";
  if (!creatorId) return null;
  if (creatorId.startsWith("trigger.")) return "trigger";
  if (creatorId.startsWith("source.")) return "input";
  if (creatorId.startsWith("model.") || creatorId === "model_call") {
    return "agent_step";
  }
  if (creatorId.startsWith("skill.") || creatorId.startsWith("skill_context.")) {
    return "skills";
  }
  if (creatorId.startsWith("hook.")) return "hook";
  if (creatorId.startsWith("memory.")) return "memory";
  if (creatorId.startsWith("subagent.")) return "worker";
  if (creatorId.startsWith("computer_use.")) return "harness_runtime";
  if (creatorId.startsWith("mcp.invoke") || creatorId.includes(".invoke")) {
    return "tool_pack";
  }
  if (creatorId.startsWith("mcp.")) return "connector";
  if (creatorId.startsWith("tool.") || creatorId.includes("tool")) {
    return "tool_pack";
  }
  if (
    creatorId.startsWith("github.") ||
    creatorId.startsWith("pr.") ||
    creatorId.includes("pull_request")
  ) {
    return creatorId.includes("context") ? "context" : "pull_request";
  }
  if (creatorId.startsWith("repository.")) return "context";
  if (creatorId.startsWith("branch.")) return "policy_gate";
  if (creatorId.startsWith("output.")) return "output";
  if (creatorId.startsWith("state.")) return "state";
  return null;
}

function canonicalPrimitive(
  input: WorkflowNodeTaxonomyInput,
): WorkflowCanonicalPrimitive {
  return creatorPrimitive(input) ?? TYPE_PRIMITIVE[input.type] ?? "harness_runtime";
}

function paletteVisibility(
  input: WorkflowNodeTaxonomyInput,
  primitive: WorkflowCanonicalPrimitive,
): WorkflowPaletteVisibility {
  if (input.creatorId && input.creatorId !== input.type) {
    return primitive === "harness_runtime" ? "advanced" : "template";
  }
  if (RAW_RUNTIME_TYPES.has(input.type)) return "advanced";
  if (SUBFACET_TYPES.has(input.type)) return "advanced";
  return "default";
}

function collapseTarget(
  input: WorkflowNodeTaxonomyInput,
  primitive: WorkflowCanonicalPrimitive,
): string {
  if (input.creatorId && input.creatorId !== input.type) {
    return `${primitive}.${input.creatorId}`;
  }
  switch (input.type) {
    case "model_binding":
      return "agent_step.model_route";
    case "parser":
      return "agent_step.structured_output";
    case "skill_context":
      return "skills.discovery";
    case "skill_pack":
      return "skills.pack";
    case "hook_policy":
      return "hook.policy";
    default:
      return primitive;
  }
}

function displayLabel(
  input: WorkflowNodeTaxonomyInput,
  primitive: WorkflowCanonicalPrimitive,
): string {
  const creatorDisplayLabel: Record<string, string> = {
    "plugin_tool.browser_use": "Browser tool",
    "plugin_tool.browser": "Browser/computer tool",
    "plugin_tool.computer_use.visual_gui": "Computer tool",
    "plugin_tool.computer_use.sandboxed": "Sandboxed computer",
    "plugin_tool.coding_pack": "Coding tool pack",
    "plugin_tool.git_diff": "Repository tool",
    "plugin_tool.file_inspect": "Repository tool",
    "plugin_tool.file_apply_patch": "Repository tool",
    "plugin_tool.test_run": "Repository tool",
    "plugin_tool.lsp_diagnostics": "Repository tool",
    "plugin_tool.artifact_read": "Repository tool",
    "plugin_tool.tool_retrieve_result": "Repository tool",
    "plugin_tool.mcp": "MCP tool",
    "plugin_tool.workflow_tool": "Workflow tool",
    "plugin_tool.plugin": "Tool",
  };
  if (input.creatorId && creatorDisplayLabel[input.creatorId]) {
    return creatorDisplayLabel[input.creatorId];
  }
  if (input.creatorId && input.creatorId !== input.type) {
    switch (primitive) {
      case "agent_step":
        return "Agent Step";
      case "tool_pack":
        return "Tool Pack";
      case "memory":
        return "Memory";
      case "skills":
        return "Skills";
      case "worker":
        return "Worker";
      case "hook":
        return "Hook";
      case "pull_request":
        return "Pull Request";
      case "connector":
        return "Connector";
      default:
        return input.label;
    }
  }
  switch (primitive) {
    case "agent_step":
      return input.type === "model_call" ? "Agent Step" : input.label;
    case "skills":
      return input.type === "skill" ? "Skills" : input.label;
    case "tool_pack":
      return input.type === "plugin_tool" ? "Tool Pack" : input.label;
    case "worker":
      return "Worker";
    case "pull_request":
      return input.type === "github_pr_create" ? "Pull Request" : input.label;
    default:
      return input.label;
  }
}

function statusText(input: WorkflowNodeTaxonomyInput): string {
  if (input.policyProfile.requiresApproval) return "Approval required";
  if (input.executor.sandboxed) return "Sandboxed";
  if (RAW_RUNTIME_TYPES.has(input.type)) return "Advanced runtime";
  return "Ready";
}

export function workflowNodeTaxonomyMetadata(
  input: WorkflowNodeTaxonomyInput,
): WorkflowNodeTaxonomyMetadata {
  const primitive = canonicalPrimitive(input);
  const ports = input.portDefinitions ?? input.ports ?? [];
  const visibility = paletteVisibility(input, primitive);
  const label = displayLabel(input, primitive);
  const receiptKinds = uniqueStrings([
    ...input.evidenceProfile.requiredEvidence,
    ...input.evidenceProfile.completionRequirements,
  ]);
  const aliases = uniqueStrings([
    input.label,
    label,
    input.familyLabel,
    input.group,
    input.metricLabel,
    input.metricValue,
    input.creatorId,
    input.baseType,
    primitive.replace(/_/g, " "),
    input.executor.executorId,
    ...ports.map((port) => port.label),
    ...ports.map((port) => port.connectionClass),
  ]);
  return {
    canonicalPrimitive: primitive,
    paletteVisibility: visibility,
    collapseTarget: collapseTarget(input, primitive),
    displayLabel: label,
    advancedLabel: `${input.label} (${input.type})`,
    searchAliases: aliases,
    configSections: WORKFLOW_PRIMITIVE_CONFIG_SECTIONS[primitive],
    runtimeMapping: {
      componentKind: input.executor.nodeType,
      executorId: input.executor.executorId,
      contract: `workflow.node.${input.type}`,
      eventKinds: ["workflow_activation"],
      receiptKinds,
    },
    shapeProfile: {
      executionBoundary: primitive,
      authorityBoundary: input.policyProfile.sideEffectClass,
      statusTextEquivalent: statusText(input),
    },
    migrationCompatibility:
      visibility === "advanced" || visibility === "hidden"
        ? "projected"
        : "native",
  };
}

export function applyWorkflowNodeTaxonomy<T extends WorkflowNodeTaxonomyInput>(
  input: T,
): T & WorkflowNodeTaxonomyMetadata {
  return {
    ...input,
    ...workflowNodeTaxonomyMetadata(input),
  };
}
