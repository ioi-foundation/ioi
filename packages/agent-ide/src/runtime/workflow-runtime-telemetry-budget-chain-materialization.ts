import type { Edge, Node, WorkflowProject } from "../types/graph";
import {
  createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow,
  type WorkflowRuntimeTelemetryBudgetChainSubflow,
} from "./workflow-runtime-telemetry-budget-chain-subflow";
import {
  bindWorkflowRuntimeTelemetrySourceToWorkflow,
  workflowRuntimeTelemetrySourceEvidenceBinding,
  type WorkflowRuntimeTelemetrySourceEvidenceBinding,
} from "./workflow-runtime-telemetry-source-binding";
import type { WorkflowRuntimeTelemetrySummary } from "./workflow-runtime-telemetry-summary";

export const WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION =
  "ioi.workflow.runtime-telemetry-budget-chain-materialization.v1" as const;

export type WorkflowRuntimeTelemetryBudgetChainMaterializationMode =
  | "materialized"
  | "hydrated";

export interface WorkflowRuntimeTelemetryBudgetChainMaterializationOptions {
  idPrefix?: string;
  origin?: { x: number; y: number };
  maxTotalTokens?: number;
  contextWarningRatio?: number;
  contextBlockRatio?: number;
  executeCompaction?: boolean;
}

export interface WorkflowRuntimeTelemetryBudgetChainMaterializationResult {
  schemaVersion: typeof WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION;
  workflow: WorkflowProject;
  status: "bound" | "blocked";
  mode: WorkflowRuntimeTelemetryBudgetChainMaterializationMode | null;
  blockers: string[];
  evidenceBinding: WorkflowRuntimeTelemetrySourceEvidenceBinding | null;
  chainNodeIds: string[];
  boundNodeIds: string[];
  insertedNodeIds: string[];
  insertedEdgeIds: string[];
  insertedNodes: Node[];
  insertedEdges: Edge[];
}

interface WorkflowRuntimeTelemetryBudgetChainIds {
  usageMeterNodeId: string;
  contextBudgetNodeId: string;
  compactionPolicyNodeId: string;
  budgetGateNodeId: string;
}

export function materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
  workflow: WorkflowProject,
  summary: WorkflowRuntimeTelemetrySummary | null | undefined,
  options: WorkflowRuntimeTelemetryBudgetChainMaterializationOptions = {},
): WorkflowRuntimeTelemetryBudgetChainMaterializationResult {
  const evidenceBinding = workflowRuntimeTelemetrySourceEvidenceBinding(summary);
  if (!summary || !evidenceBinding) {
    return blockedResult(workflow, null, [
      "runtime_telemetry_source_evidence_missing",
    ]);
  }

  const existingChain = workflowRuntimeTelemetryBudgetChainIdsFromWorkflow(workflow);
  if (existingChain) {
    return hydrateExistingTelemetryBudgetChain(
      workflow,
      summary,
      evidenceBinding,
      existingChain,
    );
  }

  return materializeTelemetryBudgetChain(
    workflow,
    summary,
    evidenceBinding,
    options,
  );
}

export function workflowRuntimeTelemetryBudgetChainIdsFromWorkflow(
  workflow: Pick<WorkflowProject, "nodes" | "edges">,
): WorkflowRuntimeTelemetryBudgetChainIds | null {
  const nodesById = new Map(workflow.nodes.map((node) => [node.id, node]));
  const usageMeters = workflow.nodes.filter(
    (node) => node.type === "runtime_usage_meter",
  );

  for (const usageMeter of usageMeters) {
    const contextEdge = workflow.edges.find((edge) => {
      const target = nodesById.get(edge.to);
      return (
        edge.from === usageMeter.id &&
        edge.fromPort === "usage_telemetry" &&
        edge.toPort === "usage_telemetry" &&
        target?.type === "runtime_context_budget"
      );
    });
    if (!contextEdge) continue;

    const contextBudget = nodesById.get(contextEdge.to);
    if (!contextBudget) continue;
    const compactionEdge = workflow.edges.find((edge) => {
      const target = nodesById.get(edge.to);
      return (
        edge.from === contextBudget.id &&
        edge.fromPort === "runtimeContextBudget" &&
        edge.toPort === "runtimeContextBudget" &&
        target?.type === "runtime_compaction_policy"
      );
    });
    if (!compactionEdge) continue;

    const compactionPolicy = nodesById.get(compactionEdge.to);
    if (!compactionPolicy) continue;
    const budgetGateEdge = workflow.edges.find((edge) => {
      const target = nodesById.get(edge.to);
      return (
        edge.from === compactionPolicy.id &&
        edge.fromPort === "runtimeCompactionPolicy" &&
        edge.toPort === "runtimeTelemetrySummary" &&
        target?.type === "plugin_tool" &&
        codingToolPackIsBudgetBindable(target)
      );
    });
    if (!budgetGateEdge) continue;

    return {
      usageMeterNodeId: usageMeter.id,
      contextBudgetNodeId: contextBudget.id,
      compactionPolicyNodeId: compactionPolicy.id,
      budgetGateNodeId: budgetGateEdge.to,
    };
  }

  return null;
}

function hydrateExistingTelemetryBudgetChain(
  workflow: WorkflowProject,
  summary: WorkflowRuntimeTelemetrySummary,
  evidenceBinding: WorkflowRuntimeTelemetrySourceEvidenceBinding,
  chain: WorkflowRuntimeTelemetryBudgetChainIds,
): WorkflowRuntimeTelemetryBudgetChainMaterializationResult {
  const chainNodeIds = chainIds(chain);
  const binding = bindWorkflowRuntimeTelemetrySourceToWorkflow(workflow, summary, {
    targetNodeIds: chainNodeIds,
  });
  if (binding.status !== "bound") {
    return blockedResult(workflow, evidenceBinding, binding.blockers);
  }
  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION,
    workflow: binding.workflow,
    status: "bound",
    mode: "hydrated",
    blockers: [],
    evidenceBinding: binding.evidenceBinding,
    chainNodeIds,
    boundNodeIds: binding.boundNodeIds,
    insertedNodeIds: [],
    insertedEdgeIds: [],
    insertedNodes: [],
    insertedEdges: [],
  };
}

function materializeTelemetryBudgetChain(
  workflow: WorkflowProject,
  summary: WorkflowRuntimeTelemetrySummary,
  evidenceBinding: WorkflowRuntimeTelemetrySourceEvidenceBinding,
  options: WorkflowRuntimeTelemetryBudgetChainMaterializationOptions,
): WorkflowRuntimeTelemetryBudgetChainMaterializationResult {
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix:
      options.idPrefix ??
      `runtime-telemetry-budget-chain-${safeId(evidenceBinding.latestEventId ?? Date.now())}`,
    workflowGraphId: workflow.metadata.id,
    origin: options.origin,
    maxTotalTokens: options.maxTotalTokens,
    contextWarningRatio: options.contextWarningRatio,
    contextBlockRatio: options.contextBlockRatio,
    executeCompaction: options.executeCompaction,
  });
  const workflowWithSubflow = workflowWithTelemetryBudgetChainSubflow(
    workflow,
    subflow,
  );
  const chainNodeIds = [
    subflow.usageMeterNodeId,
    subflow.contextBudgetNodeId,
    subflow.compactionPolicyNodeId,
    subflow.budgetGateNodeId,
  ];
  const binding = bindWorkflowRuntimeTelemetrySourceToWorkflow(
    workflowWithSubflow,
    summary,
    { targetNodeIds: chainNodeIds },
  );
  if (binding.status !== "bound") {
    return blockedResult(workflow, evidenceBinding, binding.blockers);
  }
  const nodesById = new Map(binding.workflow.nodes.map((node) => [node.id, node]));
  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION,
    workflow: binding.workflow,
    status: "bound",
    mode: "materialized",
    blockers: [],
    evidenceBinding: binding.evidenceBinding,
    chainNodeIds,
    boundNodeIds: binding.boundNodeIds,
    insertedNodeIds: chainNodeIds,
    insertedEdgeIds: subflow.edges.map((edge) => edge.id),
    insertedNodes: chainNodeIds
      .map((nodeId) => nodesById.get(nodeId))
      .filter((node): node is Node => Boolean(node)),
    insertedEdges: subflow.edges,
  };
}

function workflowWithTelemetryBudgetChainSubflow(
  workflow: WorkflowProject,
  subflow: WorkflowRuntimeTelemetryBudgetChainSubflow,
): WorkflowProject {
  return {
    ...workflow,
    nodes: [...workflow.nodes, ...subflow.nodes],
    edges: [...workflow.edges, ...subflow.edges],
  };
}

function blockedResult(
  workflow: WorkflowProject,
  evidenceBinding: WorkflowRuntimeTelemetrySourceEvidenceBinding | null,
  blockers: string[],
): WorkflowRuntimeTelemetryBudgetChainMaterializationResult {
  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TELEMETRY_BUDGET_CHAIN_MATERIALIZATION_SCHEMA_VERSION,
    workflow,
    status: "blocked",
    mode: null,
    blockers,
    evidenceBinding,
    chainNodeIds: [],
    boundNodeIds: [],
    insertedNodeIds: [],
    insertedEdgeIds: [],
    insertedNodes: [],
    insertedEdges: [],
  };
}

function chainIds(chain: WorkflowRuntimeTelemetryBudgetChainIds): string[] {
  return [
    chain.usageMeterNodeId,
    chain.contextBudgetNodeId,
    chain.compactionPolicyNodeId,
    chain.budgetGateNodeId,
  ];
}

function codingToolPackIsBudgetBindable(node: Node): boolean {
  const binding = node.config?.logic?.toolBinding;
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) {
    return false;
  }
  return (
    binding.bindingKind === "coding_tool_pack" ||
    binding.toolPack?.pack === "coding"
  );
}

function safeId(value: unknown): string {
  return String(value ?? "runtime")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
}
