import assert from "node:assert/strict";
import test from "node:test";
import type {
  WorkflowProject,
  WorkflowRunResult,
  WorkflowRunStatus,
  WorkflowRunSummary,
  WorkflowStreamEvent,
} from "../types/graph";
import { workflowRunHistoryModel } from "./workflow-run-history-model";
import {
  createLiveWorkflowRunTelemetryHydration,
  mergeWorkflowRuntimeThreadEvents,
} from "./workflow-runtime-live-telemetry";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";

const workflow = {
  version: "1",
  nodes: [
    {
      id: "model",
      type: "model_call",
      name: "Model",
      x: 0,
      y: 0,
    },
    {
      id: "output",
      type: "output",
      name: "Output",
      x: 0,
      y: 0,
    },
  ],
  edges: [],
  global_config: {
    env: "test",
    modelBindings: {},
    requiredCapabilities: {},
    policy: {
      maxBudget: 1,
      maxSteps: 4,
      timeoutMs: 1_000,
    },
    contract: {
      developerBond: 1,
      adjudicationRubric: "test",
    },
    meta: {
      name: "Test workflow",
      description: "Test workflow",
    },
  },
  metadata: {
    id: "workflow",
    name: "Workflow",
    slug: "workflow",
    workflowKind: "agent_workflow",
    executionMode: "mock",
  },
} as unknown as WorkflowProject;

function runSummary(
  id: string,
  status: WorkflowRunStatus,
  summary: string,
  startedAtMs = 1_000,
): WorkflowRunSummary {
  return {
    id,
    status,
    startedAtMs,
    finishedAtMs: startedAtMs + 100,
    nodeCount: 2,
    checkpointCount: id === "run-a" ? 1 : 2,
    summary,
  };
}

function event(id: string, runId = "run-a"): WorkflowStreamEvent {
  return {
    id,
    runId,
    threadId: "thread",
    sequence: Number(id.replace(/\D/g, "")) || 1,
    kind: "node_succeeded",
    createdAtMs: 1_100,
    nodeId: "model",
    status: "success",
    message: `event ${id}`,
  };
}

function runtimeThreadEvent(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:${seq}`,
    seq,
    threadId: "thread",
    turnId: "turn-a",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-12T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

function runResult(
  id: string,
  status: WorkflowRunStatus,
  output: unknown,
): WorkflowRunResult {
  return {
    summary: runSummary(id, status, `${id} summary`),
    thread: {
      id: "thread",
      workflowPath: "workflow.json",
      status,
      createdAtMs: 900,
    },
    finalState: {
      threadId: "thread",
      checkpointId: `${id}-checkpoint`,
      runId: id,
      stepIndex: 1,
      values: { result: output },
      nodeOutputs: { model: output },
      completedNodeIds: ["model"],
      blockedNodeIds: [],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [
      {
        nodeId: "model",
        nodeType: "model_call",
        status: status === "failed" ? "error" : "success",
        startedAtMs: 1_000,
        finishedAtMs: 1_100,
        attempt: 1,
        input: { prompt: "hello" },
        output,
      },
    ],
    checkpoints: [
      {
        id: `${id}-checkpoint`,
        threadId: "thread",
        runId: id,
        createdAtMs: 1_100,
        stepIndex: 1,
        status,
        summary: `${id} checkpoint`,
      },
    ],
    events: [event(`${id}-event`, id)],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

const runs = [
  runSummary("run-a", "passed", "Generate final answer"),
  runSummary("run-b", "failed", "Tool call failed", 2_000),
  runSummary("run-c", "blocked", "Policy blocked", 3_000),
];

test("workflow run history model filters runs by status and search", () => {
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: null,
    compareRunResult: null,
    selectedRunId: "run-b",
    compareRunId: "run-a",
    runEvents: [],
    searchQuery: " tool ",
    statusFilter: "failed",
  });

  assert.equal(model.normalizedSearch, "tool");
  assert.deepEqual(model.runStatuses, ["blocked", "failed", "passed"]);
  assert.equal(model.statusCounts.failed, 1);
  assert.deepEqual(
    model.visibleRows.map((row) => [row.run.id, row.selected, row.compare]),
    [["run-b", true, false]],
  );
});

test("workflow run history model binds selected run, timeline, and comparison", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const baseline = runResult("run-b", "failed", { answer: "old" });
  const fallbackEvents = [event("fallback")];
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: baseline,
    selectedRunId: "run-a",
    compareRunId: "run-b",
    runEvents: fallbackEvents,
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun?.summary.id, "run-a");
  assert.equal(model.defaultCompareRun?.id, "run-b");
  assert.equal(model.timelineEvents[0]?.runId, "run-a");
  assert.equal(model.comparison?.baselineRunId, "run-b");
  assert.equal(model.comparison?.targetRunId, "run-a");
  assert.equal(model.comparison?.changedNodes[0]?.nodeId, "model");
});

test("workflow run history model projects canonical runtime thread events", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("event-1", 1, {
        type: "reasoning_delta",
        eventKind: "reasoning.delta",
        sourceEventKind: "KernelEvent::AgentThought",
        workflowNodeId: "runtime.reasoning",
        componentKind: "reasoning_delta",
        status: "running",
      }),
      runtimeThreadEvent("event-2", 2, {
        type: "tool_completed",
        eventKind: "tool.completed",
        sourceEventKind: "KernelEvent::AgentActionResult",
        workflowNodeId: "runtime.tool-result",
        componentKind: "tool_result",
        toolName: "shell",
        receiptRefs: ["receipt-tool"],
        artifactRefs: ["artifact-tool"],
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimeEventProjection.eventCount, 2);
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => node.id),
    ["runtime.reasoning", "runtime.tool-result"],
  );
  assert.equal(
    model.runtimeEventProjection.reactFlowNodes[1]?.data.latestCursor,
    "events_thread:2",
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes[1]?.data.receiptRefs,
    ["receipt-tool"],
  );
  assert.equal(
    model.runtimeEventProjection.reactFlowEdges[0]?.source,
    "runtime.reasoning",
  );
  assert.equal(model.timelineEvents[0]?.runId, "run-a");
});

test("workflow run history model projects the replayable runtime policy stack", () => {
  const target = runResult("run-a", "passed", { answer: "new" });
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: [
      runtimeThreadEvent("trust-warning", 1, {
        type: "workspace_trust_warning",
        eventKind: "workspace.trust_warning",
        sourceEventKind: "WorkspaceTrust.Warning",
        workflowNodeId: "runtime.thread-mode.workspace-trust",
        componentKind: "workspace_trust",
        status: "warning",
        receiptRefs: ["receipt-trust"],
        payload: { warning_id: "warning-1" },
      }),
      runtimeThreadEvent("trust-ack", 2, {
        type: "workspace_trust_acknowledged",
        eventKind: "workspace.trust_acknowledged",
        sourceEventKind: "WorkspaceTrust.Acknowledged",
        workflowNodeId: "runtime.thread-mode.workspace-trust",
        componentKind: "workspace_trust",
        receiptRefs: ["receipt-trust-ack"],
        payload: { warning_id: "warning-1" },
      }),
      runtimeThreadEvent("approval-required", 3, {
        type: "approval_required",
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "approval_gate",
        approvalId: "approval-1",
        receiptRefs: ["receipt-approval"],
        payload: { approval_id: "approval-1" },
      }),
      runtimeThreadEvent("approval-approved", 4, {
        type: "approval_decision",
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "approval_gate",
        approvalId: "approval-1",
        status: "approved",
        receiptRefs: ["receipt-approval-approved"],
        payload: { approval_id: "approval-1", decision: "approve" },
      }),
      runtimeThreadEvent("tool-completed", 5, {
        type: "tool_completed",
        eventKind: "tool.completed",
        sourceEventKind: "CodingTool.FileApplyPatch",
        workflowNodeId: "workflow.coding.file.apply_patch",
        componentKind: "coding_tool",
        toolCallId: "tool-call-1",
        receiptRefs: ["receipt-tool"],
        payload: {
          approval_id: "approval-1",
          approval_satisfied: true,
          approval_decision_event_id: "approval-approved",
        },
      }),
    ],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.runtimePolicyStack.status, "completed");
  assert.deepEqual(
    model.runtimePolicyStack.stages.map((stage) => [stage.kind, stage.status]),
    [
      ["workspace_trust_warning", "completed"],
      ["workspace_trust_acknowledgement", "completed"],
      ["approval_requirement", "completed"],
      ["approval_decision", "completed"],
      ["approved_retry", "completed"],
    ],
  );
  assert.deepEqual(model.runtimePolicyStack.receiptRefs, [
    "receipt-trust",
    "receipt-trust-ack",
    "receipt-approval",
    "receipt-approval-approved",
    "receipt-tool",
  ]);
});

test("workflow run history model hydrates live telemetry for an in-flight run", () => {
  const liveRun = createLiveWorkflowRunTelemetryHydration({
    workflow,
    thread: {
      id: "thread-live",
      workflowPath: "workflow.json",
      status: "queued",
      createdAtMs: 950,
      input: { prompt: "stream tokens" },
    },
    startedAtMs: 1_000,
  });
  const events = mergeWorkflowRuntimeThreadEvents(
    [
      runtimeThreadEvent("usage-1", 1, {
        threadId: "thread-live",
        type: "usage_delta",
        eventKind: "usage.delta",
        sourceEventKind: "RuntimeUsageTelemetry.Delta",
        workflowNodeId: "runtime.usage-telemetry",
        componentKind: "usage_telemetry",
        status: "running",
      }),
    ],
    [
      runtimeThreadEvent("usage-1", 1, {
        threadId: "thread-live",
        type: "usage_delta",
        eventKind: "usage.delta",
        sourceEventKind: "RuntimeUsageTelemetry.Delta",
        workflowNodeId: "runtime.usage-telemetry",
        componentKind: "usage_telemetry",
        status: "running",
      }),
      runtimeThreadEvent("context-2", 2, {
        threadId: "thread-live",
        type: "context_pressure_delta",
        eventKind: "context.pressure_delta",
        sourceEventKind: "RuntimeContextPressure.Delta",
        workflowNodeId: "runtime.context-budget",
        componentKind: "context_pressure",
        status: "running",
      }),
      runtimeThreadEvent("context-alert-3", 3, {
        threadId: "thread-live",
        type: "context_pressure_alert",
        eventKind: "context.pressure_alert",
        sourceEventKind: "RuntimeContextPressure.Alert",
        workflowNodeId: "runtime.context-pressure-alert",
        componentKind: "context_pressure_alert",
        status: "warning",
        payload: {
          alert_level: "warn",
          scope: "turn",
          pressure: 0.74,
          pressure_status: "elevated",
          actions: [
            {
              action: "delegate_summary",
              label: "Delegate summary",
              executable: true,
              workflowNodeId: "runtime.subagent.delegate-summary",
            },
            {
              action: "compact",
              label: "Compact context",
              executable: true,
              workflowNodeId: "runtime.context-compact",
            },
          ],
        },
      }),
    ],
  );

  const model = workflowRunHistoryModel({
    workflow,
    runs: [liveRun.summary],
    lastRunResult: liveRun,
    compareRunResult: null,
    selectedRunId: liveRun.summary.id,
    compareRunId: null,
    runEvents: [],
    runtimeThreadEvents: events,
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun?.summary.status, "running");
  assert.equal(model.timelineEvents[0]?.threadId, "thread-live");
  assert.equal(model.runtimeEventProjection.eventCount, 3);
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes.map((node) => [
      node.id,
      node.data.nodeKind,
      node.data.status,
    ]),
    [
      ["runtime.usage-telemetry", "runtime_usage_meter", "running"],
      ["runtime.context-budget", "runtime_context_budget", "running"],
      ["runtime.context-pressure-alert", "hook_policy", "warning"],
    ],
  );
  assert.deepEqual(
    model.runtimeEventProjection.reactFlowNodes[2]?.data.contextPressureActions.map(
      (action) => [action.action, action.workflowNodeId, action.executable],
    ),
    [
      ["delegate_summary", "runtime.subagent.delegate-summary", true],
      ["compact", "runtime.context-compact", true],
    ],
  );
});

test("workflow run history model projects TUI control state for run inspector", () => {
  const target = {
    ...runResult("run-a", "passed", { answer: "new" }),
    tuiControlState: {
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: "thread",
      current_turn_id: "turn-a",
      last_cursor: "events_thread:9",
      mode_status: {
        mode: "agent",
        approval_mode: "suggest",
        trust_profile: "local_private",
      },
      approval_rows: [
        {
          approval_id: "approval-a",
          status: "pending",
          workflow_node_id: "runtime.approval.approval-a",
        },
      ],
      approval_decisions: [
        {
          approval_id: "approval-a",
          decision: "reject",
          status: "rejected",
          receipt_refs: ["receipt-approval-rejected"],
          policy_decision_refs: ["policy-approval-allow"],
        },
      ],
      command_history: [
        {
          id: "command-events",
          command: "events",
          raw_input: "/events 0",
          status: "applied",
          sequence: 1,
        },
      ],
      validation_errors: [
        {
          id: "error-steer",
          command: "steer",
          raw_input: "/steer",
          message: "/steer requires guidance text",
          sequence: 2,
        },
      ],
    },
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: target,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.tuiControlStateProjection.threadId, "thread");
  assert.equal(model.tuiControlStateProjection.currentTurnId, "turn-a");
  assert.equal(model.tuiControlStateProjection.commandCount, 1);
  assert.equal(model.tuiControlStateProjection.validationErrorCount, 1);
  assert.equal(model.tuiControlStateProjection.approvalCount, 1);
  assert.equal(model.tuiControlStateProjection.approvalDecisionCount, 1);
  assert.deepEqual(
    model.tuiControlStateProjection.rows.map((row) => [
      row.rowKind,
      row.command,
      row.status,
    ]),
    [
      ["summary", null, "current"],
      ["mode_status", null, "current"],
      ["approval", null, "pending"],
      ["approval_decision", "reject", "rejected"],
      ["command", "events", "applied"],
      ["validation_error", "steer", "validation_error"],
    ],
  );
  assert.deepEqual(
    model.tuiControlStateProjection.rows[3]?.receiptRefs,
    ["receipt-approval-rejected"],
  );
});

test("workflow run history model falls back to ambient events without selected run", () => {
  const fallbackEvents = [event("fallback")];
  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: runResult("run-a", "passed", "new"),
    compareRunResult: null,
    selectedRunId: "missing",
    compareRunId: null,
    runEvents: fallbackEvents,
    searchQuery: "zzz",
    statusFilter: "all",
  });

  assert.equal(model.selectedRun, null);
  assert.equal(model.comparison, null);
  assert.equal(model.timelineEvents, fallbackEvents);
  assert.equal(model.filteredRuns.length, 0);
});

test("workflow run history model projects interrupts and harness attempts", () => {
  const selected = {
    ...runResult("run-a", "interrupted", "needs input"),
    interrupt: {
      id: "interrupt",
      runId: "run-a",
      threadId: "thread",
      nodeId: "model",
      status: "pending",
      createdAtMs: 1_200,
      prompt: "Approve?",
      allowedOutcomes: ["approve"],
      response: {
        binding: {
          bindingKind: "tool",
          ref: "tool:write",
          sideEffectClass: "write",
        },
      },
    },
    harnessAttempts: [
      {
        attemptId: "attempt",
        harnessWorkflowId: "harness",
        harnessActivationId: "activation",
        harnessHash: "hash",
        workflowNodeId: "model",
        componentId: "component",
        componentKind: "planner",
        executionMode: "live",
        readiness: "live_ready",
        attemptIndex: 1,
        status: "succeeded",
        startedAtMs: 1_000,
        durationMs: 100,
        receiptIds: ["receipt"],
        evidenceRefs: ["evidence"],
        replay: {
          deterministicEnvelope: true,
          capturesInput: true,
          capturesOutput: true,
          capturesPolicyDecision: true,
          fixtureRef: "fixture",
          determinism: "deterministic",
          redactionPolicy: "none",
        },
      },
    ],
    harnessShadowComparisons: [
      {
        liveAttemptId: "live",
        shadowAttemptId: "shadow",
        workflowNodeId: "model",
        componentKind: "planner",
        divergence: "matched",
        blocking: false,
        summary: "matched",
        evidenceRefs: ["evidence"],
      },
    ],
  } as unknown as WorkflowRunResult;

  const model = workflowRunHistoryModel({
    workflow,
    runs,
    lastRunResult: selected,
    compareRunResult: null,
    selectedRunId: "run-a",
    compareRunId: null,
    runEvents: [],
    searchQuery: "",
    statusFilter: "all",
  });

  assert.equal(model.interrupt?.prompt, "Approve?");
  assert.equal(model.interruptPreview?.binding?.ref, "tool:write");
  assert.equal(model.harnessAttempts[0]?.attemptId, "attempt");
  assert.equal(model.harnessComparisons[0]?.divergence, "matched");
});
