import type { WorkflowProject } from "../types/graph";
import type { WorkflowRuntimeControlRequest } from "../runtime/graph-runtime-types";
import type { RuntimeCodingToolControlRequest } from "../runtime/workflow-runtime-coding-tool-control-nodes";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
} from "../runtime/workflow-runtime-terminal-coding-loop-subflow";
import {
  createRuntimeTerminalCodingLoopRunLaunchPlan,
  runRuntimeTerminalCodingLoopWorkflowLaunch,
  type WorkflowRuntimeTerminalCodingLoopRunLaunchResult,
} from "../runtime/workflow-runtime-terminal-coding-loop-run-launch";

export const WORKFLOW_COMPOSER_TERMINAL_CODING_LOOP_RUN_ACTIVATION_SCHEMA_VERSION =
  "ioi.workflow.composer-terminal-coding-loop-run-activation.v1" as const;

export interface WorkflowComposerTerminalCodingLoopApprovalDecisionRequest {
  schemaVersion: typeof WORKFLOW_COMPOSER_TERMINAL_CODING_LOOP_RUN_ACTIVATION_SCHEMA_VERSION;
  nodeType: "runtime_approval_decision";
  nodeId: string | null;
  threadId: string;
  endpoint: string;
  method: "POST";
  body: {
    source: "react_flow";
    actor: string;
    approvalId: string;
    approval_id: string;
    workflowGraphId: string | null;
    workflow_graph_id: string | null;
    workflowNodeId: string;
    workflow_node_id: string;
    decision: "approve";
    reason: string;
  };
}

export type WorkflowComposerTerminalCodingLoopControlRequest =
  | RuntimeCodingToolControlRequest
  | WorkflowComposerTerminalCodingLoopApprovalDecisionRequest;

export interface WorkflowComposerTerminalCodingLoopRunActivationOptions {
  workflow: WorkflowProject;
  workflowPath: string;
  threadId: string;
  actor?: string | null;
  startedAtMs?: number;
  executeRuntimeControlRequest: (
    request: WorkflowComposerTerminalCodingLoopControlRequest,
  ) => Promise<unknown>;
}

export function workflowComposerTerminalCodingLoopRunLaunchEligible(
  workflow: WorkflowProject,
): boolean {
  const plan = createRuntimeTerminalCodingLoopRunLaunchPlan(workflow, {
    threadId: "eligibility-check",
  });
  return (
    plan.status === "ready" &&
    plan.nodeIds.length === workflow.nodes.length &&
    plan.stepIds.length === WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length
  );
}

export async function runWorkflowComposerTerminalCodingLoopActivation({
  workflow,
  workflowPath,
  threadId,
  actor,
  startedAtMs = Date.now(),
  executeRuntimeControlRequest,
}: WorkflowComposerTerminalCodingLoopRunActivationOptions): Promise<WorkflowRuntimeTerminalCodingLoopRunLaunchResult> {
  const resolvedActor = cleanString(actor) ?? "workflow-author";
  const runId = `workflow-terminal-coding-loop-composer-${safeId(threadId)}-${startedAtMs}`;
  return runRuntimeTerminalCodingLoopWorkflowLaunch(
    workflow,
    { threadId },
    {
      workflowPath,
      runId,
      startedAtMs,
      actor: resolvedActor,
      source: "workflow-composer-run",
      toolCallIdForStep: (stepId) =>
        `terminal_loop_${safeId(threadId)}_${stepId}`,
      invoke: async (request, body) =>
        executeRuntimeControlRequest({
          ...request,
          body,
        }),
      approve: async ({ node, approvalId }) => {
        if (!approvalId) {
          return null;
        }
        await executeRuntimeControlRequest(
          createTerminalCodingLoopApprovalDecisionRequest({
            threadId,
            workflowGraphId: cleanString(workflow.metadata?.id),
            workflowNodeId: node.id,
            approvalId,
            actor: resolvedActor,
          }),
        );
        return { approvalId };
      },
    },
  );
}

export function createTerminalCodingLoopApprovalDecisionRequest({
  threadId,
  workflowGraphId,
  workflowNodeId,
  approvalId,
  actor,
}: {
  threadId: string;
  workflowGraphId: string | null;
  workflowNodeId: string;
  approvalId: string;
  actor: string;
}): WorkflowComposerTerminalCodingLoopApprovalDecisionRequest {
  return {
    schemaVersion:
      WORKFLOW_COMPOSER_TERMINAL_CODING_LOOP_RUN_ACTIVATION_SCHEMA_VERSION,
    nodeType: "runtime_approval_decision",
    nodeId: workflowNodeId,
    threadId,
    endpoint: `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(
      approvalId,
    )}/decision`,
    method: "POST",
    body: {
      source: "react_flow",
      actor,
      approvalId,
      approval_id: approvalId,
      workflowGraphId,
      workflow_graph_id: workflowGraphId,
      workflowNodeId,
      workflow_node_id: workflowNodeId,
      decision: "approve",
      reason:
        "Approve terminal coding-loop apply step from React Flow workflow Run.",
    },
  };
}

export function workflowComposerTerminalCodingLoopControlRequestForRuntime(
  request: WorkflowComposerTerminalCodingLoopControlRequest,
): WorkflowRuntimeControlRequest {
  return request as WorkflowRuntimeControlRequest;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "thread"
  );
}
