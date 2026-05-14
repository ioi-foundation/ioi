import type { Edge, Node, WorkflowProject } from "../types/graph";
import type { WorkflowRuntimeTuiControlStateRow } from "./workflow-runtime-event-projection";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
  type WorkflowRuntimeTerminalCodingLoopStepId,
  type WorkflowRuntimeTerminalCodingLoopSubflow,
} from "./workflow-runtime-terminal-coding-loop-subflow";

export const WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION =
  "ioi.workflow.runtime-terminal-coding-loop-materialization.v1" as const;

export type WorkflowRuntimeTerminalCodingLoopMaterializationMode =
  | "materialized"
  | "hydrated";

export interface WorkflowRuntimeTerminalCodingLoopEvidenceBinding {
  schemaVersion: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION;
  rowId: string;
  rowKind: "coding_tool";
  status: string;
  threadId: string;
  turnId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string;
  toolName: string | null;
  toolCallId: string | null;
  eventId: string | null;
  cursor: string | null;
  sequence: number | null;
  receiptRefs: string[];
  artifactRefs: string[];
  policyDecisionRefs: string[];
  rollbackRefs: string[];
}

export interface WorkflowRuntimeTerminalCodingLoopMaterializationOptions {
  idPrefix?: string;
  origin?: { x: number; y: number };
  allowedPaths?: string[];
  maxTotalTokens?: number;
  contextWarningRatio?: number;
  contextBlockRatio?: number;
}

export interface WorkflowRuntimeTerminalCodingLoopMaterializationResult {
  schemaVersion: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION;
  workflow: WorkflowProject;
  status: "bound" | "blocked";
  mode: WorkflowRuntimeTerminalCodingLoopMaterializationMode | null;
  blockers: string[];
  evidenceBinding: WorkflowRuntimeTerminalCodingLoopEvidenceBinding | null;
  loopNodeIds: string[];
  boundNodeIds: string[];
  insertedNodeIds: string[];
  insertedEdgeIds: string[];
  insertedNodes: Node[];
  insertedEdges: Edge[];
}

export function materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
  workflow: WorkflowProject,
  row: WorkflowRuntimeTuiControlStateRow | null | undefined,
  options: WorkflowRuntimeTerminalCodingLoopMaterializationOptions = {},
): WorkflowRuntimeTerminalCodingLoopMaterializationResult {
  const evidenceBinding = workflowRuntimeTerminalCodingLoopEvidenceBinding(row);
  if (!row || !evidenceBinding) {
    return blockedResult(workflow, null, [
      "runtime_terminal_coding_loop_evidence_missing",
    ]);
  }

  const existingLoop = workflowRuntimeTerminalCodingLoopIdsFromWorkflow(workflow);
  if (existingLoop.length > 0) {
    const hydratedWorkflow = workflowWithTerminalCodingLoopEvidence(
      workflow,
      existingLoop,
      evidenceBinding,
    );
    return {
      schemaVersion:
        WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
      workflow: hydratedWorkflow,
      status: "bound",
      mode: "hydrated",
      blockers: [],
      evidenceBinding,
      loopNodeIds: existingLoop,
      boundNodeIds: existingLoop,
      insertedNodeIds: [],
      insertedEdgeIds: [],
      insertedNodes: [],
      insertedEdges: [],
    };
  }

  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix:
      options.idPrefix ??
      `runtime-terminal-coding-loop-${safeId(
        evidenceBinding.eventId ??
          evidenceBinding.toolCallId ??
          evidenceBinding.rowId ??
          Date.now(),
      )}`,
    workflowGraphId: workflow.metadata.id,
    origin: options.origin,
    allowedPaths: options.allowedPaths,
    maxTotalTokens: options.maxTotalTokens,
    contextWarningRatio: options.contextWarningRatio,
    contextBlockRatio: options.contextBlockRatio,
  });
  const workflowWithSubflow = workflowWithTerminalCodingLoopSubflow(
    workflow,
    subflow,
  );
  const boundWorkflow = workflowWithTerminalCodingLoopEvidence(
    workflowWithSubflow,
    subflow.nodeIds,
    evidenceBinding,
  );
  const nodesById = new Map(boundWorkflow.nodes.map((node) => [node.id, node]));

  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
    workflow: boundWorkflow,
    status: "bound",
    mode: "materialized",
    blockers: [],
    evidenceBinding,
    loopNodeIds: subflow.nodeIds,
    boundNodeIds: subflow.nodeIds,
    insertedNodeIds: subflow.nodeIds,
    insertedEdgeIds: subflow.edges.map((edge) => edge.id),
    insertedNodes: subflow.nodeIds
      .map((nodeId) => nodesById.get(nodeId))
      .filter((node): node is Node => Boolean(node)),
    insertedEdges: subflow.edges,
  };
}

export function workflowRuntimeTerminalCodingLoopIdsFromWorkflow(
  workflow: Pick<WorkflowProject, "nodes">,
): string[] {
  const stepOrder = new Map(
    WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map((step, index) => [
      step.stepId,
      index,
    ]),
  );
  return workflow.nodes
    .filter((node) => {
      const logic = node.config?.logic;
      return (
        node.type === "plugin_tool" &&
        logic?.runtimeTerminalCodingLoopSchemaVersion ===
          "ioi.workflow.runtime-terminal-coding-loop-subflow.v1" &&
        typeof logic.runtimeTerminalCodingLoopStepId === "string"
      );
    })
    .sort((left, right) => {
      const leftStep = left.config?.logic
        ?.runtimeTerminalCodingLoopStepId as WorkflowRuntimeTerminalCodingLoopStepId;
      const rightStep = right.config?.logic
        ?.runtimeTerminalCodingLoopStepId as WorkflowRuntimeTerminalCodingLoopStepId;
      return (stepOrder.get(leftStep) ?? 0) - (stepOrder.get(rightStep) ?? 0);
    })
    .map((node) => node.id);
}

export function workflowRuntimeTerminalCodingLoopEvidenceBinding(
  row: WorkflowRuntimeTuiControlStateRow | null | undefined,
): WorkflowRuntimeTerminalCodingLoopEvidenceBinding | null {
  if (!row || row.rowKind !== "coding_tool" || !row.threadId) return null;
  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
    rowId: row.id,
    rowKind: "coding_tool",
    status: row.status,
    threadId: row.threadId,
    turnId: row.turnId,
    workflowGraphId: row.workflowGraphId ?? null,
    workflowNodeId: row.reactFlowNodeId,
    toolName: row.toolName ?? null,
    toolCallId: row.toolCallId ?? null,
    eventId: row.eventId,
    cursor: row.cursor,
    sequence: row.sequence,
    receiptRefs: row.receiptRefs,
    artifactRefs: row.artifactRefs ?? [],
    policyDecisionRefs: row.policyDecisionRefs,
    rollbackRefs: row.rollbackRefs ?? [],
  };
}

function workflowWithTerminalCodingLoopSubflow(
  workflow: WorkflowProject,
  subflow: WorkflowRuntimeTerminalCodingLoopSubflow,
): WorkflowProject {
  return {
    ...workflow,
    nodes: [...workflow.nodes, ...subflow.nodes],
    edges: [...workflow.edges, ...subflow.edges],
  };
}

function workflowWithTerminalCodingLoopEvidence(
  workflow: WorkflowProject,
  nodeIds: string[],
  evidenceBinding: WorkflowRuntimeTerminalCodingLoopEvidenceBinding,
): WorkflowProject {
  const nodeIdSet = new Set(nodeIds);
  return {
    ...workflow,
    nodes: workflow.nodes.map((node) => {
      if (!nodeIdSet.has(node.id) || !node.config) return node;
      const logic = node.config.logic ?? {};
      const reopen = runtimeTerminalCodingLoopTuiReopenForNode(
        node,
        evidenceBinding,
      );
      return {
        ...node,
        config: {
          ...node.config,
          logic: {
            ...logic,
            runtimeTerminalCodingLoopEvidence: evidenceBinding,
            runtimeTerminalCodingLoopTuiReopen: reopen,
            testInput: terminalCodingLoopTestInput(evidenceBinding),
          },
        },
      };
    }),
  };
}

function runtimeTerminalCodingLoopTuiReopenForNode(
  node: Node,
  evidenceBinding: WorkflowRuntimeTerminalCodingLoopEvidenceBinding,
) {
  const sinceSeq = Math.max((evidenceBinding.sequence ?? 1) - 1, 0);
  const args = [
    "agent",
    "tui",
    "--thread-id",
    evidenceBinding.threadId,
    "--interactive",
    "--since-seq",
    String(sinceSeq),
  ];
  return {
    schemaVersion: "ioi.workflow.runtime-terminal-coding-loop-tui-reopen.v1",
    command: "ioi agent tui",
    args,
    reopenCommand: `ioi ${args.join(" ")}`,
    threadId: evidenceBinding.threadId,
    turnId: evidenceBinding.turnId,
    workflowGraphId: evidenceBinding.workflowGraphId,
    workflowNodeId: node.id,
    eventId: evidenceBinding.eventId,
    eventKind: "tool.completed",
    componentKind: "coding_tool",
    toolName: evidenceBinding.toolName,
    toolCallId: evidenceBinding.toolCallId,
    seq: evidenceBinding.sequence,
    cursor: evidenceBinding.cursor,
    sinceSeq,
    lastEventId: evidenceBinding.eventId,
    rowId: evidenceBinding.rowId,
  };
}

function terminalCodingLoopTestInput(
  evidenceBinding: WorkflowRuntimeTerminalCodingLoopEvidenceBinding,
): Record<string, unknown> {
  return {
    threadId: evidenceBinding.threadId,
    turnId: evidenceBinding.turnId,
    workflowGraphId: evidenceBinding.workflowGraphId,
    cursor: evidenceBinding.cursor,
    lastEventId: evidenceBinding.eventId,
    sequence: evidenceBinding.sequence,
    toolName: evidenceBinding.toolName,
    toolCallId: evidenceBinding.toolCallId,
    artifactId: evidenceBinding.artifactRefs[0] ?? "{artifactId}",
    receiptRefs: evidenceBinding.receiptRefs,
    artifactRefs: evidenceBinding.artifactRefs,
    policyDecisionRefs: evidenceBinding.policyDecisionRefs,
    rollbackRefs: evidenceBinding.rollbackRefs,
  };
}

function blockedResult(
  workflow: WorkflowProject,
  evidenceBinding: WorkflowRuntimeTerminalCodingLoopEvidenceBinding | null,
  blockers: string[],
): WorkflowRuntimeTerminalCodingLoopMaterializationResult {
  return {
    schemaVersion:
      WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
    workflow,
    status: "blocked",
    mode: null,
    blockers,
    evidenceBinding,
    loopNodeIds: [],
    boundNodeIds: [],
    insertedNodeIds: [],
    insertedEdgeIds: [],
    insertedNodes: [],
    insertedEdges: [],
  };
}

function safeId(value: unknown): string {
  return String(value ?? "runtime")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 96);
}
