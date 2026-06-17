import type {
  Node,
  WorkflowCheckpoint,
  WorkflowProject,
  WorkflowRunResult,
  WorkflowRunStatus,
  WorkflowStreamEvent,
} from "../types/graph";
import type {
  RuntimeCodingToolControlRequest,
  RuntimeCodingToolControlRequestBody,
} from "./workflow-runtime-coding-tool-control-nodes";
import {
  createRuntimeTerminalCodingLoopStepRequest,
  updateRuntimeTerminalCodingLoopExecutionContextFromToolResult,
  type WorkflowRuntimeTerminalCodingLoopExecutionContext,
} from "./workflow-runtime-terminal-coding-loop-execution";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  type WorkflowRuntimeTerminalCodingLoopStepId,
} from "./workflow-runtime-terminal-coding-loop-subflow";
import { workflowRuntimeTerminalCodingLoopNodesInExecutionOrder } from "./workflow-runtime-terminal-coding-loop-execution";

export const WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION =
  "ioi.workflow.runtime-terminal-coding-loop-run-launch.v1" as const;

export interface WorkflowRuntimeTerminalCodingLoopRunLaunchPlan {
  schemaVersion: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION;
  workflowGraphId: string | null;
  workflowPath: string | null;
  threadId: string;
  nodeIds: string[];
  stepIds: WorkflowRuntimeTerminalCodingLoopStepId[];
  status: "ready" | "blocked";
  blockedReason: string | null;
}

export type WorkflowRuntimeTerminalCodingLoopRunLaunchBody =
  RuntimeCodingToolControlRequestBody & Record<string, unknown>;

export interface WorkflowRuntimeTerminalCodingLoopRunLaunchInvokeContext {
  workflow: WorkflowProject;
  plan: WorkflowRuntimeTerminalCodingLoopRunLaunchPlan;
  node: Pick<Node, "id" | "type" | "config">;
  stepId: WorkflowRuntimeTerminalCodingLoopStepId;
  stepIndex: number;
  request: RuntimeCodingToolControlRequest;
  body: WorkflowRuntimeTerminalCodingLoopRunLaunchBody;
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext;
  approvedRetry: boolean;
}

export interface WorkflowRuntimeTerminalCodingLoopApprovalContext
  extends Omit<
    WorkflowRuntimeTerminalCodingLoopRunLaunchInvokeContext,
    "approvedRetry"
  > {
  blockedResult: unknown;
  approvalId: string | null;
}

export interface WorkflowRuntimeTerminalCodingLoopApprovalResult {
  approvalId?: string | null;
  result?: unknown;
}

export interface WorkflowRuntimeTerminalCodingLoopRunLaunchOptions {
  workflowPath?: string | null;
  runId?: string | null;
  startedAtMs?: number;
  actor?: string | null;
  source?: string | null;
  toolCallIdForStep?: (
    stepId: WorkflowRuntimeTerminalCodingLoopStepId,
    node: Pick<Node, "id" | "type" | "config">,
    stepIndex: number,
  ) => string | null | undefined;
  invoke: (
    request: RuntimeCodingToolControlRequest,
    body: WorkflowRuntimeTerminalCodingLoopRunLaunchBody,
    context: WorkflowRuntimeTerminalCodingLoopRunLaunchInvokeContext,
  ) => Promise<unknown>;
  approve?: (
    context: WorkflowRuntimeTerminalCodingLoopApprovalContext,
  ) => Promise<WorkflowRuntimeTerminalCodingLoopApprovalResult | null | undefined>;
}

export interface WorkflowRuntimeTerminalCodingLoopRunLaunchResult {
  schemaVersion: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION;
  plan: WorkflowRuntimeTerminalCodingLoopRunLaunchPlan;
  runResult: WorkflowRunResult;
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext;
  requests: RuntimeCodingToolControlRequest[];
  resultsByStepId: Partial<Record<WorkflowRuntimeTerminalCodingLoopStepId, unknown>>;
}

const STEP_ID_SET = new Set(
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map((step) => step.stepId),
);

export function createRuntimeTerminalCodingLoopRunLaunchPlan(
  workflow: WorkflowProject,
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext,
  options: Pick<WorkflowRuntimeTerminalCodingLoopRunLaunchOptions, "workflowPath"> = {},
): WorkflowRuntimeTerminalCodingLoopRunLaunchPlan {
  const nodes = workflowRuntimeTerminalCodingLoopNodesInExecutionOrder(
    workflow.nodes,
  );
  const stepIds = nodes
    .map((node) => terminalCodingLoopStepId(node))
    .filter(
      (stepId): stepId is WorkflowRuntimeTerminalCodingLoopStepId =>
        stepId !== null,
    );
  return {
    schemaVersion: WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION,
    workflowGraphId: cleanString(workflow.metadata?.id),
    workflowPath: cleanString(options.workflowPath),
    threadId: context.threadId,
    nodeIds: nodes.map((node) => node.id),
    stepIds,
    status: nodes.length > 0 ? "ready" : "blocked",
    blockedReason:
      nodes.length > 0
        ? null
        : "Saved workflow does not contain a terminal coding-loop subflow.",
  };
}

export async function runRuntimeTerminalCodingLoopWorkflowLaunch(
  workflow: WorkflowProject,
  initialContext: WorkflowRuntimeTerminalCodingLoopExecutionContext,
  options: WorkflowRuntimeTerminalCodingLoopRunLaunchOptions,
): Promise<WorkflowRuntimeTerminalCodingLoopRunLaunchResult> {
  const startedAtMs = options.startedAtMs ?? Date.now();
  const workflowPath =
    cleanString(options.workflowPath) ??
    cleanString(workflow.metadata?.gitLocation) ??
    "workflow.json";
  const runId =
    cleanString(options.runId) ??
    `workflow-terminal-coding-loop-run-${safeId(initialContext.threadId)}-${startedAtMs}`;
  const workflowGraphId = cleanString(workflow.metadata?.id);
  const plan = createRuntimeTerminalCodingLoopRunLaunchPlan(
    workflow,
    initialContext,
    { workflowPath },
  );
  const nodes = workflowRuntimeTerminalCodingLoopNodesInExecutionOrder(
    workflow.nodes,
  );
  const requests: RuntimeCodingToolControlRequest[] = [];
  const resultsByStepId: Partial<
    Record<WorkflowRuntimeTerminalCodingLoopStepId, unknown>
  > = {};
  const nodeOutputs: Record<string, unknown> = {};
  const completedNodeIds: string[] = [];
  const blockedNodeIds: string[] = [];
  const events: WorkflowStreamEvent[] = [];
  const nodeRuns: WorkflowRunResult["nodeRuns"] = [];
  const runtimeThreadEvents: WorkflowRuntimeThreadEventLike[] = [];
  const checkpoints: WorkflowCheckpoint[] = [];
  let context: WorkflowRuntimeTerminalCodingLoopExecutionContext = {
    ...initialContext,
  };
  let status: WorkflowRunStatus = plan.status === "ready" ? "passed" : "blocked";
  let sequence = 0;

  const pushEvent = (
    kind: WorkflowStreamEvent["kind"],
    nodeId: string | undefined,
    eventStatus: string,
    message: string,
  ) => {
    sequence += 1;
    events.push({
      id: `${runId}-event-${sequence}`,
      runId,
      threadId: initialContext.threadId,
      sequence,
      kind,
      createdAtMs: startedAtMs + sequence,
      nodeId,
      status: eventStatus,
      message,
    });
  };

  pushEvent("run_started", undefined, "running", "Terminal coding-loop run launched.");

  if (plan.status === "blocked") {
    pushEvent(
      "policy_blocked",
      undefined,
      "blocked",
      plan.blockedReason ?? "Terminal coding-loop run launch blocked.",
    );
  }

  for (const [stepIndex, node] of nodes.entries()) {
    const stepId = terminalCodingLoopStepId(node);
    if (!stepId) continue;
    const nodeStartedAtMs = startedAtMs + sequence + 1;
    pushEvent("node_started", node.id, "running", `${node.name ?? node.id} started.`);
    const request = createRuntimeTerminalCodingLoopStepRequest(
      node,
      context,
      {
        workflowGraphId,
        actor: cleanString(options.actor) ?? "operator",
      },
    );
    const toolCallId = cleanString(
      options.toolCallIdForStep?.(stepId, node, stepIndex),
    );
    const body: WorkflowRuntimeTerminalCodingLoopRunLaunchBody = {
      ...request.body,
      ...(toolCallId
        ? {
            toolCallId,
            tool_call_id: toolCallId,
          }
        : {}),
    };
    requests.push(request);

    let result = await options.invoke(request, body, {
      workflow,
      plan,
      node,
      stepId,
      stepIndex,
      request,
      body,
      context,
      approvedRetry: false,
    });

    if (isApprovalRequiredResult(result)) {
      pushEvent(
        "approval_required",
        node.id,
        "blocked",
        `${node.name ?? node.id} requires approval.`,
      );
      const approvalId = approvalIdFromResult(result);
      const approval = await options.approve?.({
        workflow,
        plan,
        node,
        stepId,
        stepIndex,
        request,
        body,
        context,
        blockedResult: result,
        approvalId,
      });
      const approvedId =
        cleanString(approval?.approvalId) ?? approvalId ?? null;
      if (approval?.result !== undefined) {
        result = approval.result;
      } else if (approvedId) {
        result = await options.invoke(
          request,
          {
            ...body,
            approvalId: approvedId,
            approval_id: approvedId,
          },
          {
            workflow,
            plan,
            node,
            stepId,
            stepIndex,
            request,
            body: {
              ...body,
              approvalId: approvedId,
              approval_id: approvedId,
            },
            context,
            approvedRetry: true,
          },
        );
      }
    }

    const resultStatus = statusFromToolResult(result);
    resultsByStepId[stepId] = result;
    nodeOutputs[node.id] = result;
    const runtimeEvent = workflowRuntimeThreadEventFromToolResult(result);
    if (runtimeEvent) runtimeThreadEvents.push(runtimeEvent);

    if (resultStatus === "completed") {
      context = updateRuntimeTerminalCodingLoopExecutionContextFromToolResult(
        context,
        result,
      );
      completedNodeIds.push(node.id);
      pushEvent("node_succeeded", node.id, "success", `${node.name ?? node.id} completed.`);
      checkpoints.push({
        id: `${runId}-checkpoint-${checkpoints.length + 1}`,
        threadId: initialContext.threadId,
        runId,
        createdAtMs: startedAtMs + sequence,
        stepIndex: checkpoints.length + 1,
        nodeId: node.id,
        status: "passed",
        summary: `${node.name ?? node.id} completed.`,
      });
    } else {
      status = resultStatus === "blocked" ? "blocked" : "failed";
      blockedNodeIds.push(node.id);
      pushEvent(
        resultStatus === "blocked" ? "node_blocked" : "node_failed",
        node.id,
        status,
        `${node.name ?? node.id} ${status}.`,
      );
    }

    const nodeFinishedAtMs = startedAtMs + sequence;
    const nodeRunStatus =
      resultStatus === "completed"
        ? "success"
        : resultStatus === "blocked"
          ? "blocked"
          : "error";
    const nodeRun = {
      nodeId: node.id,
      nodeType: node.type,
      status: nodeRunStatus,
      startedAtMs: nodeStartedAtMs,
      finishedAtMs: nodeFinishedAtMs,
      attempt: 1,
      input: body,
      output: result,
      ...(nodeRunStatus === "error"
        ? { error: errorMessageFromToolResult(result) }
        : {}),
      checkpointId:
        nodeRunStatus === "success"
          ? checkpoints[checkpoints.length - 1]?.id
          : undefined,
    } satisfies WorkflowRunResult["nodeRuns"][number];
    if (nodeRun.checkpointId === undefined) {
      delete (nodeRun as { checkpointId?: string }).checkpointId;
    }
    nodeRuns.push(nodeRun);
    if (status !== "passed") break;
  }

  pushEvent(
    "run_completed",
    undefined,
    status,
    status === "passed"
      ? "Terminal coding-loop run completed."
      : "Terminal coding-loop run stopped before completion.",
  );
  const finishedAtMs = startedAtMs + sequence + 1;
  const summary = {
    id: runId,
    threadId: initialContext.threadId,
    status,
    startedAtMs,
    finishedAtMs,
    nodeCount: nodes.length,
    checkpointCount: checkpoints.length,
    summary:
      status === "passed"
        ? "Terminal coding-loop workflow run completed."
        : "Terminal coding-loop workflow run blocked.",
  };
  const latestCheckpoint = checkpoints[checkpoints.length - 1];
  const runResult: WorkflowRunResult = {
    summary,
    thread: {
      id: initialContext.threadId,
      workflowPath,
      status,
      createdAtMs: startedAtMs,
      latestCheckpointId: latestCheckpoint?.id,
    },
    finalState: {
      threadId: initialContext.threadId,
      checkpointId: latestCheckpoint?.id ?? `${runId}-start`,
      runId,
      stepIndex: completedNodeIds.length,
      values: {
        terminalCodingLoop: {
          schemaVersion:
            WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION,
          workflowGraphId,
          threadId: initialContext.threadId,
          nodeIds: plan.nodeIds,
          stepIds: plan.stepIds,
          receiptRefs: context.receiptRefs ?? [],
          artifactRefs: context.artifactRefs ?? [],
          rollbackRefs: context.rollbackRefs ?? [],
          policyDecisionRefs: context.policyDecisionRefs ?? [],
          artifactId: context.artifactId ?? null,
          toolCallId: context.toolCallId ?? null,
          resultToolCallId: context.resultToolCallId ?? null,
        },
      },
      nodeOutputs,
      completedNodeIds,
      blockedNodeIds,
      interruptedNodeIds: [],
      activeNodeIds:
        status === "passed"
          ? []
          : nodes
              .map((node) => node.id)
              .filter(
                (nodeId) =>
                  !completedNodeIds.includes(nodeId) &&
                  !blockedNodeIds.includes(nodeId),
              ),
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns,
    checkpoints,
    events,
    runtimeThreadEvents,
    verificationEvidence: [],
    completionRequirements: [],
  };

  return {
    schemaVersion: WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_RUN_LAUNCH_SCHEMA_VERSION,
    plan,
    runResult,
    context,
    requests,
    resultsByStepId,
  };

}

function terminalCodingLoopStepId(
  node: Pick<Node, "config">,
): WorkflowRuntimeTerminalCodingLoopStepId | null {
  const stepId = cleanString(node.config?.logic?.runtimeTerminalCodingLoopStepId);
  return stepId && STEP_ID_SET.has(stepId as WorkflowRuntimeTerminalCodingLoopStepId)
    ? (stepId as WorkflowRuntimeTerminalCodingLoopStepId)
    : null;
}

function isApprovalRequiredResult(result: unknown): boolean {
  const candidate = objectRecord(result);
  return (
    candidate?.status === "blocked" &&
    (candidate.approval_required === true ||
      candidate.approvalRequired === true ||
      Boolean(cleanString(candidate.approval_id)) ||
      Boolean(cleanString(candidate.approvalId)))
  );
}

function approvalIdFromResult(result: unknown): string | null {
  const candidate = objectRecord(result);
  return (
    cleanString(candidate?.approval_id) ??
    cleanString(candidate?.approvalId) ??
    null
  );
}

function statusFromToolResult(result: unknown): "completed" | "blocked" | "failed" {
  const candidate = objectRecord(result);
  const status = cleanString(candidate?.status);
  if (status === "completed") return "completed";
  if (status === "blocked") return "blocked";
  return "failed";
}

function workflowRuntimeThreadEventFromToolResult(
  result: unknown,
): WorkflowRuntimeThreadEventLike | null {
  const resultObject = objectRecord(result);
  const event = objectRecord(resultObject?.event);
  if (!event) return null;
  const seq = finiteNumber(event.seq) ?? finiteNumber(resultObject?.sequence) ?? 0;
  const threadId =
    cleanString(event.thread_id) ??
    cleanString(event.threadId) ??
    cleanString(resultObject?.thread_id) ??
    cleanString(resultObject?.threadId);
  const eventId =
    cleanString(event.event_id) ??
    cleanString(resultObject?.event_id);
  const eventKind =
    cleanString(event.event_kind) ??
    cleanString(event.eventKind) ??
    cleanString(resultObject?.event_kind) ??
    cleanString(resultObject?.eventKind) ??
    "runtime.step";
  if (!threadId || !eventId) return null;
  const streamId =
    cleanString(event.event_stream_id) ??
    cleanString(event.eventStreamId) ??
    `events_${threadId}`;
  return {
    id: eventId,
    cursor:
      cleanString(event.cursor) ??
      cleanString(resultObject?.cursor) ??
      `${streamId}:${seq}`,
    seq,
    threadId,
    turnId:
      cleanString(event.turn_id) ??
      cleanString(event.turnId) ??
      cleanString(resultObject?.turn_id) ??
      cleanString(resultObject?.turnId) ??
      null,
    type: runtimeThreadEventType(eventKind),
    eventKind,
    sourceEventKind:
      cleanString(event.source_event_kind) ??
      cleanString(event.sourceEventKind) ??
      "CodingTool.Invoke",
    status:
      cleanString(event.status) ??
      cleanString(resultObject?.status) ??
      "completed",
    createdAt: cleanString(event.created_at) ?? cleanString(event.createdAt) ?? undefined,
    componentKind:
      cleanString(event.component_kind) ??
      cleanString(event.componentKind) ??
      "coding_tool",
    workflowNodeId:
      cleanString(event.workflow_node_id) ??
      cleanString(event.workflowNodeId) ??
      cleanString(resultObject?.workflow_node_id) ??
      cleanString(resultObject?.workflowNodeId),
    workflowGraphId:
      cleanString(event.workflow_graph_id) ??
      cleanString(event.workflowGraphId) ??
      cleanString(resultObject?.workflow_graph_id) ??
      cleanString(resultObject?.workflowGraphId),
    toolCallId:
      cleanString(event.tool_call_id) ??
      cleanString(event.toolCallId) ??
      cleanString(resultObject?.tool_call_id) ??
      cleanString(resultObject?.toolCallId),
    toolName:
      cleanString(event.tool_name) ??
      cleanString(event.toolName) ??
      cleanString(resultObject?.tool_name) ??
      cleanString(resultObject?.toolName),
    approvalId:
      cleanString(event.approval_id) ??
      cleanString(event.approvalId) ??
      cleanString(resultObject?.approval_id) ??
      cleanString(resultObject?.approvalId),
    payloadSchemaVersion:
      cleanString(event.payload_schema_version) ??
      cleanString(event.payloadSchemaVersion) ??
      "ioi.agent-sdk.thread-event.v1",
    receiptRefs: stringArray(event.receipt_refs ?? event.receiptRefs),
    artifactRefs: stringArray(event.artifact_refs ?? event.artifactRefs),
    policyDecisionRefs: stringArray(
      event.policy_decision_refs ?? event.policyDecisionRefs,
    ),
    rollbackRefs: stringArray(event.rollback_refs ?? event.rollbackRefs),
    payload: objectRecord(event.payload_summary) ??
      objectRecord(event.payload) ??
      undefined,
  };
}

function runtimeThreadEventType(eventKind: string): string {
  switch (eventKind) {
    case "tool.completed":
      return "tool_completed";
    case "tool.failed":
      return "tool_failed";
    case "approval.required":
      return "approval_required";
    case "approval.approved":
    case "approval.rejected":
      return "approval_decision";
    case "policy.blocked":
      return "policy_blocked";
    default:
      return "runtime_step";
  }
}

function errorMessageFromToolResult(result: unknown): string {
  const candidate = objectRecord(result);
  return (
    cleanString(candidate?.error) ??
    cleanString(objectRecord(candidate?.error)?.message) ??
    "Terminal coding-loop step failed."
  );
}

function objectRecord(source: unknown): Record<string, unknown> | null {
  return source && typeof source === "object" && !Array.isArray(source)
    ? (source as Record<string, unknown>)
    : null;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function finiteNumber(value: unknown): number | null {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim()
        ? Number(value)
        : null;
  return typeof parsed === "number" && Number.isFinite(parsed) ? parsed : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .map((entry) => cleanString(entry))
        .filter((entry): entry is string => Boolean(entry))
    : [];
}

function safeId(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "thread";
}
