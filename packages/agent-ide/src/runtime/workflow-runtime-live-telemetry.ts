import type {
  WorkflowProject,
  WorkflowRunResult,
  WorkflowStreamEvent,
  WorkflowThread,
} from "../types/graph";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

export const WORKFLOW_RUNTIME_TELEMETRY_POLL_INTERVAL_MS = 350;

export function mergeWorkflowRuntimeThreadEvents(
  current: readonly WorkflowRuntimeThreadEventLike[],
  incoming: readonly WorkflowRuntimeThreadEventLike[],
): WorkflowRuntimeThreadEventLike[] {
  if (incoming.length === 0) return current as WorkflowRuntimeThreadEventLike[];
  const byKey = new Map<string, WorkflowRuntimeThreadEventLike>();
  for (const event of current) {
    byKey.set(runtimeThreadEventKey(event), event);
  }
  let changed = false;
  for (const event of incoming) {
    const key = runtimeThreadEventKey(event);
    if (byKey.has(key)) continue;
    byKey.set(key, event);
    changed = true;
  }
  if (!changed) return current as WorkflowRuntimeThreadEventLike[];
  return Array.from(byKey.values()).sort(compareRuntimeThreadEvents);
}

export function createLiveWorkflowRunTelemetryHydration({
  workflow,
  thread,
  startedAtMs = Date.now(),
}: {
  workflow: WorkflowProject;
  thread: WorkflowThread;
  startedAtMs?: number;
}): WorkflowRunResult {
  const runId = `workflow-live-run-${thread.id}`;
  const startEvent: WorkflowStreamEvent = {
    id: `workflow-live-event-${thread.id}`,
    runId,
    threadId: thread.id,
    sequence: 0,
    kind: "run_started",
    createdAtMs: startedAtMs,
    status: "running",
    message: "Workflow run started; runtime telemetry is streaming.",
  };

  return {
    summary: {
      id: runId,
      threadId: thread.id,
      status: "running",
      startedAtMs,
      nodeCount: workflow.nodes.length,
      testCount: 0,
      checkpointCount: 0,
      summary: "Workflow run streaming runtime telemetry.",
    },
    thread: {
      ...thread,
      status: "running",
    },
    finalState: {
      threadId: thread.id,
      checkpointId: thread.latestCheckpointId ?? "start",
      runId,
      stepIndex: 0,
      values: thread.input === undefined ? {} : { input: thread.input },
      nodeOutputs: {},
      completedNodeIds: [],
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: workflow.nodes.map((node) => node.id),
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [],
    checkpoints: [],
    events: [startEvent],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

function runtimeThreadEventKey(event: WorkflowRuntimeThreadEventLike): string {
  return (
    event.id || event.cursor || `${event.threadId}:${event.seq}:${event.type}`
  );
}

function compareRuntimeThreadEvents(
  left: WorkflowRuntimeThreadEventLike,
  right: WorkflowRuntimeThreadEventLike,
): number {
  if (left.seq !== right.seq) return left.seq - right.seq;
  return runtimeThreadEventKey(left).localeCompare(runtimeThreadEventKey(right));
}
