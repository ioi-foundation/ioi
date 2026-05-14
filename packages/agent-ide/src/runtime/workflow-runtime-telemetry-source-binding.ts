import type { Node, NodeLogic, WorkflowProject, WorkflowValidationIssue } from "../types/graph";
import {
  RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID,
  RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID,
} from "./workflow-runtime-compaction-policy-control-nodes";
import { RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID } from "./workflow-runtime-context-budget-control-nodes";
import {
  workflowRuntimeTelemetrySummaryToUsageTelemetry,
  type WorkflowRuntimeTelemetrySummary,
} from "./workflow-runtime-telemetry-summary";
import { RUNTIME_USAGE_METER_WORKFLOW_NODE_ID } from "./workflow-runtime-usage-control-nodes";

export const WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION =
  "ioi.workflow.runtime-telemetry-source-binding.v1" as const;

const TELEMETRY_BINDABLE_NODE_TYPES = new Set([
  "runtime_usage_meter",
  "runtime_context_budget",
  "runtime_compaction_policy",
  "plugin_tool",
]);

export interface WorkflowRuntimeTelemetrySourceEvidenceBinding {
  schemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION;
  source: "react_flow_quick_fix";
  fieldMappingSource: string;
  telemetrySummary: WorkflowRuntimeTelemetrySummary;
  usageTelemetry: unknown | null;
  status: WorkflowRuntimeTelemetrySummary["status"];
  sourceKinds: string[];
  threadId: string | null;
  turnId: string | null;
  workflowGraphId: string | null;
  latestEventId: string | null;
  eventIds: string[];
  receiptRefs: string[];
  policyDecisionRefs: string[];
}

export interface WorkflowRuntimeTelemetrySourceBindingResult {
  workflow: WorkflowProject;
  nodes: Node[];
  boundNodeIds: string[];
  evidenceBinding: WorkflowRuntimeTelemetrySourceEvidenceBinding | null;
  status: "bound" | "blocked";
  blockers: string[];
}

export type WorkflowRuntimeTelemetrySourceNodeBindingResult = Omit<
  WorkflowRuntimeTelemetrySourceBindingResult,
  "workflow"
>;

export interface WorkflowRuntimeTelemetrySourceBindingOptions {
  issue?: WorkflowValidationIssue | null;
  targetNodeIds?: readonly string[] | null;
}

export function workflowRuntimeTelemetrySourceBindingIssue(
  issue: WorkflowValidationIssue | null | undefined,
): boolean {
  return Boolean(
    issue?.code.startsWith("missing_runtime_telemetry_source_") ||
      issue?.repairActionId === "bind-runtime-telemetry-source" ||
      issue?.repairLabel === "Bind telemetry source",
  );
}

export function workflowRuntimeTelemetrySourceEvidenceBinding(
  summary: WorkflowRuntimeTelemetrySummary | null | undefined,
): WorkflowRuntimeTelemetrySourceEvidenceBinding | null {
  if (!summary || summary.sourceKinds.length === 0) return null;
  const latestEventId = summary.latestEventId ?? summary.eventIds[0] ?? null;
  const sourceId = safeId(latestEventId ?? summary.latestCursor ?? "summary");
  return {
    schemaVersion: WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION,
    source: "react_flow_quick_fix",
    fieldMappingSource: `{{runtime.telemetrySource.${sourceId}}}`,
    telemetrySummary: summary,
    usageTelemetry: workflowRuntimeTelemetrySummaryToUsageTelemetry(summary),
    status: summary.status,
    sourceKinds: uniqueStrings(summary.sourceKinds),
    threadId: summary.threadIds[0] ?? null,
    turnId: summary.turnIds[0] ?? null,
    workflowGraphId: summary.workflowGraphIds[0] ?? null,
    latestEventId,
    eventIds: uniqueStrings(summary.eventIds),
    receiptRefs: uniqueStrings(summary.receiptRefs),
    policyDecisionRefs: uniqueStrings(summary.policyDecisionRefs),
  };
}

export function bindWorkflowRuntimeTelemetrySourceToWorkflow(
  workflow: WorkflowProject,
  summary: WorkflowRuntimeTelemetrySummary | null | undefined,
  options: WorkflowRuntimeTelemetrySourceBindingOptions = {},
): WorkflowRuntimeTelemetrySourceBindingResult {
  const result = bindWorkflowRuntimeTelemetrySourceToNodes(
    workflow.nodes,
    summary,
    options,
  );
  return {
    ...result,
    workflow: {
      ...workflow,
      metadata: {
        ...workflow.metadata,
        dirty: workflow.metadata.readOnly ? false : true,
        updatedAtMs: Date.now(),
      },
      nodes: result.nodes,
    },
  };
}

export function bindWorkflowRuntimeTelemetrySourceToNodes(
  nodes: readonly Node[],
  summary: WorkflowRuntimeTelemetrySummary | null | undefined,
  options: WorkflowRuntimeTelemetrySourceBindingOptions = {},
): WorkflowRuntimeTelemetrySourceNodeBindingResult {
  const evidenceBinding = workflowRuntimeTelemetrySourceEvidenceBinding(summary);
  const targetNodeIds = telemetrySourceTargetNodeIds(nodes, options);
  const blockers = [
    ...(evidenceBinding ? [] : ["runtime_telemetry_source_evidence_missing"]),
    ...(targetNodeIds.length > 0 ? [] : ["runtime_telemetry_source_target_node_missing"]),
  ];

  if (!evidenceBinding || targetNodeIds.length === 0) {
    return {
      nodes: [...nodes],
      boundNodeIds: [],
      evidenceBinding,
      status: "blocked",
      blockers,
    };
  }

  const targetSet = new Set(targetNodeIds);
  const boundNodeIds: string[] = [];
  const boundNodes = nodes.map((node) => {
    if (!targetSet.has(node.id)) return node;
    const bound = bindTelemetryNodeToEvidence(node, evidenceBinding);
    if (bound !== node) boundNodeIds.push(node.id);
    return bound;
  });

  return {
    nodes: boundNodes,
    boundNodeIds,
    evidenceBinding,
    status: boundNodeIds.length > 0 ? "bound" : "blocked",
    blockers: boundNodeIds.length > 0 ? [] : ["runtime_telemetry_source_target_node_missing"],
  };
}

function bindTelemetryNodeToEvidence(
  node: Node,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Node {
  switch (node.type) {
    case "runtime_usage_meter":
      return bindUsageMeterNode(node, evidence);
    case "runtime_context_budget":
      return bindContextBudgetNode(node, evidence);
    case "runtime_compaction_policy":
      return evidence.threadId ? bindCompactionPolicyNode(node, evidence) : node;
    case "plugin_tool":
      return bindCodingToolBudgetGateNode(node, evidence);
    default:
      return node;
  }
}

function bindUsageMeterNode(
  node: Node,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Node {
  const logic = node.config?.logic ?? {};
  const scope = evidence.threadId ? "thread" : "workflow";
  return withTelemetryLogic(node, {
    ...logic,
    runtimeTelemetrySummary: evidence.telemetrySummary,
    runtimeTelemetrySourceBinding: evidence,
    runtimeUsageMeterThreadId: evidence.threadId ?? undefined,
    runtimeUsageMeterScope: scope,
    runtimeUsageMeterEndpoint: evidence.threadId
      ? "/v1/threads/{threadId}/usage"
      : "/v1/usage",
    runtimeUsageMeterWorkflowNodeId: boundWorkflowNodeId(
      node,
      logic.runtimeUsageMeterWorkflowNodeId,
      RUNTIME_USAGE_METER_WORKFLOW_NODE_ID,
    ),
    runtimeUsageMeterField: "runtimeUsageMeter",
    runtimeUsageMeterStatusField: "runtimeUsageMeter.contextPressureStatus",
    inputMapping: {
      ...(logic.inputMapping ?? {}),
      ...telemetrySourceInputMapping(evidence, ["threadId", "turnId", "runtimeTelemetrySummary"]),
    },
    testInput: telemetrySourceTestInput(logic, evidence),
  });
}

function bindContextBudgetNode(
  node: Node,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Node {
  const logic = node.config?.logic ?? {};
  const scope = evidence.threadId ? "thread" : "workflow";
  return withTelemetryLogic(node, {
    ...logic,
    runtimeTelemetrySummary: evidence.telemetrySummary,
    runtimeTelemetrySourceBinding: evidence,
    runtimeContextBudget: evidence.telemetrySummary,
    runtimeContextBudgetThreadId: evidence.threadId ?? undefined,
    runtimeContextBudgetScope: scope,
    runtimeContextBudgetEndpoint: evidence.threadId
      ? "/v1/threads/{threadId}/context-budget"
      : "/v1/context-budget",
    runtimeContextBudgetWorkflowNodeId: boundWorkflowNodeId(
      node,
      logic.runtimeContextBudgetWorkflowNodeId,
      RUNTIME_CONTEXT_BUDGET_WORKFLOW_NODE_ID,
    ),
    runtimeContextBudgetUsageField: "runtimeUsageMeter",
    runtimeContextBudgetStatusField: "runtimeContextBudget.status",
    inputMapping: {
      ...(logic.inputMapping ?? {}),
      ...telemetrySourceInputMapping(evidence, [
        "threadId",
        "turnId",
        "runtimeTelemetrySummary",
        "runtimeUsageMeter",
      ]),
    },
    testInput: telemetrySourceTestInput(logic, evidence),
  });
}

function bindCompactionPolicyNode(
  node: Node,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Node {
  const logic = node.config?.logic ?? {};
  const contextBudget = telemetrySourceContextBudget(evidence);
  return withTelemetryLogic(node, {
    ...logic,
    runtimeTelemetrySummary: evidence.telemetrySummary,
    runtimeTelemetrySourceBinding: evidence,
    runtimeCompactionPolicyThreadId: evidence.threadId ?? undefined,
    runtimeCompactionPolicyTurnId: evidence.turnId ?? undefined,
    runtimeCompactionPolicyContextBudget: contextBudget,
    runtimeCompactionPolicyContextBudgetStatus: contextBudget.status,
    runtimeCompactionPolicyWorkflowNodeId: boundWorkflowNodeId(
      node,
      logic.runtimeCompactionPolicyWorkflowNodeId,
      RUNTIME_COMPACTION_POLICY_WORKFLOW_NODE_ID,
    ),
    runtimeCompactionPolicyCompactWorkflowNodeId: boundCompactWorkflowNodeId(
      node,
      logic.runtimeCompactionPolicyCompactWorkflowNodeId,
    ),
    runtimeCompactionPolicyContextBudgetField: "runtimeContextBudget",
    runtimeCompactionPolicyContextBudgetStatusField: "runtimeContextBudget.status",
    inputMapping: {
      ...(logic.inputMapping ?? {}),
      ...telemetrySourceInputMapping(evidence, [
        "threadId",
        "turnId",
        "runtimeContextBudget",
        "runtimeTelemetrySummary",
      ]),
    },
    testInput: {
      ...telemetrySourceTestInput(logic, evidence),
      runtimeContextBudget: contextBudget,
    },
  });
}

function bindCodingToolBudgetGateNode(
  node: Node,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Node {
  const logic = node.config?.logic ?? {};
  const binding = logic.toolBinding;
  if (!binding || !codingToolPackIsBudgetBindable(binding)) return node;
  const toolPack = {
    ...(binding.toolPack ?? { pack: "coding" }),
    budgetUsageField: "runtimeTelemetrySummary",
    budgetUsageTelemetry: evidence.telemetrySummary,
    telemetrySourceBinding: evidence,
  };
  return withTelemetryLogic(node, {
    ...logic,
    workflowNodeId: boundWorkflowNodeId(node, logic.workflowNodeId, null),
    runtimeTelemetrySummary: evidence.telemetrySummary,
    runtimeTelemetrySourceBinding: evidence,
    toolBinding: {
      ...binding,
      toolPack,
    },
    inputMapping: {
      ...(logic.inputMapping ?? {}),
      ...telemetrySourceInputMapping(evidence, ["threadId", "runtimeTelemetrySummary"]),
    },
    testInput: telemetrySourceTestInput(logic, evidence),
  });
}

function withTelemetryLogic(node: Node, logic: NodeLogic): Node {
  return {
    ...node,
    config: {
      kind: node.type as any,
      ...(node.config ?? {}),
      law: node.config?.law ?? {},
      logic,
    } as NonNullable<Node["config"]>,
  };
}

function telemetrySourceTargetNodeIds(
  nodes: readonly Node[],
  options: WorkflowRuntimeTelemetrySourceBindingOptions,
): string[] {
  const candidates = nodes.filter(telemetrySourceBindableNode);
  const explicitNodeIds = uniqueStrings(options.targetNodeIds ?? []);
  if (explicitNodeIds.length > 0) {
    const candidateIds = new Set(candidates.map((node) => node.id));
    return explicitNodeIds.filter((nodeId) => candidateIds.has(nodeId));
  }
  const issue = options.issue;
  if (issue?.nodeId) {
    return candidates.some((node) => node.id === issue.nodeId)
      ? [issue.nodeId]
      : [];
  }
  return candidates.map((node) => node.id);
}

function telemetrySourceBindableNode(node: Node): boolean {
  if (!TELEMETRY_BINDABLE_NODE_TYPES.has(node.type)) return false;
  if (node.type !== "plugin_tool") return true;
  return codingToolPackIsBudgetBindable(node.config?.logic?.toolBinding);
}

function codingToolPackIsBudgetBindable(binding: unknown): binding is NonNullable<NodeLogic["toolBinding"]> {
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) return false;
  const record = binding as NonNullable<NodeLogic["toolBinding"]>;
  return record.bindingKind === "coding_tool_pack" || record.toolPack?.pack === "coding";
}

function boundWorkflowNodeId(
  node: Node,
  current: unknown,
  defaultNodeId: string | null,
): string {
  const existing = cleanString(current);
  if (existing && existing !== defaultNodeId) return existing;
  return node.id;
}

function boundCompactWorkflowNodeId(node: Node, current: unknown): string {
  const existing = cleanString(current);
  if (
    existing &&
    existing !== RUNTIME_COMPACTION_POLICY_CONTEXT_COMPACT_WORKFLOW_NODE_ID
  ) {
    return existing;
  }
  return `${node.id}.compact`;
}

function telemetrySourceInputMapping(
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
  fields: readonly string[],
): Record<string, string> {
  const source = evidence.fieldMappingSource.replace(/\}\}$/, "");
  return Object.fromEntries(fields.map((field) => [field, `${source}.${field}}}`]));
}

function telemetrySourceTestInput(
  logic: NodeLogic,
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Record<string, unknown> {
  return {
    ...(objectValue(logic.testInput) ?? {}),
    threadId: evidence.threadId,
    turnId: evidence.turnId,
    runtimeTelemetrySummary: evidence.telemetrySummary,
    runtimeUsageMeter: evidence.usageTelemetry,
  };
}

function telemetrySourceContextBudget(
  evidence: WorkflowRuntimeTelemetrySourceEvidenceBinding,
): Record<string, unknown> & { status: "ok" | "warn" | "blocked" } {
  const status = contextBudgetStatusForTelemetry(evidence.status);
  return {
    schemaVersion: "ioi.workflow.runtime-context-budget-binding-snapshot.v1",
    status,
    policyDecision: {
      status,
      source: "react_flow_quick_fix",
      sourceKinds: evidence.sourceKinds,
    },
    usageTelemetry: evidence.usageTelemetry,
    runtimeTelemetrySummary: evidence.telemetrySummary,
    receiptRefs: evidence.receiptRefs,
    policyDecisionRefs: evidence.policyDecisionRefs,
  };
}

function contextBudgetStatusForTelemetry(
  status: WorkflowRuntimeTelemetrySummary["status"],
): "ok" | "warn" | "blocked" {
  if (status === "blocked") return "blocked";
  if (status === "high" || status === "elevated") return "warn";
  return "ok";
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean ? clean : null;
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return [
    ...new Set(
      values
        .flat()
        .map((value) => (typeof value === "string" ? value.trim() : ""))
        .filter(Boolean),
    ),
  ];
}

function safeId(value: unknown): string {
  return String(value ?? "runtime")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
}
