import assert from "node:assert/strict";
import test from "node:test";
import {
  WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
  WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
  projectRuntimeTuiControlStateToWorkflowProjection,
  projectRuntimeThreadEventsToWorkflowNodes,
  projectRuntimeThreadEventsToWorkflowProjection,
  workflowNodeIdForRuntimeThreadEvent,
  type WorkflowRuntimeThreadEventLike,
} from "./workflow-runtime-event-projection";

function event(
  id: string,
  seq: number,
  overrides: Partial<WorkflowRuntimeThreadEventLike> = {},
): WorkflowRuntimeThreadEventLike {
  return {
    id,
    cursor: `events_thread:test:${seq}`,
    seq,
    threadId: "thread-test",
    turnId: "turn-test",
    type: "runtime_step",
    eventKind: "runtime.step",
    sourceEventKind: "KernelEvent::RuntimeStep",
    status: "completed",
    createdAt: `2026-05-12T00:00:0${seq}.000Z`,
    componentKind: null,
    workflowNodeId: null,
    workflowGraphId: "workflow-test",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}

test("projects Thread.events runtime events into stable React Flow nodes and edges", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-3", 3, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "KernelEvent::ToolCompleted",
      workflowNodeId: "runtime.tool-result",
      componentKind: "tool_result",
      toolName: "shell",
      receiptRefs: ["receipt-tool"],
    }),
    event("event-1", 1, {
      type: "reasoning_delta",
      eventKind: "reasoning.delta",
      sourceEventKind: "KernelEvent::ReasoningDelta",
      workflowNodeId: "runtime.reasoning",
      componentKind: "reasoning_delta",
      status: "running",
      payload: { summary: "Thinking through the patch." },
    }),
    event("event-2", 2, {
      type: "model_route_decision",
      eventKind: "model.route_decision",
      sourceEventKind: "KernelEvent::ModelRouteDecision",
    }),
  ]);

  assert.equal(
    projection.schemaVersion,
    WORKFLOW_RUNTIME_EVENT_PROJECTION_SCHEMA_VERSION,
  );
  assert.deepEqual(
    projection.reactFlowNodes.map((node) => node.id),
    ["runtime.reasoning", "runtime.model-router", "runtime.tool-result"],
  );
  assert.equal(projection.reactFlowNodes[0]?.data.nodeKind, "task_state");
  assert.equal(projection.reactFlowNodes[0]?.data.status, "running");
  assert.equal(projection.reactFlowNodes[0]?.data.summary, "Thinking through the patch.");
  assert.equal(projection.reactFlowNodes[1]?.data.nodeKind, "model_binding");
  assert.equal(projection.reactFlowNodes[1]?.data.componentKind, "model_router");
  assert.equal(projection.reactFlowNodes[2]?.data.nodeKind, "plugin_tool");
  assert.deepEqual(projection.reactFlowNodes[2]?.data.receiptRefs, ["receipt-tool"]);
  assert.deepEqual(
    projection.reactFlowEdges.map((edge) => [edge.source, edge.target]),
    [
      ["runtime.reasoning", "runtime.model-router"],
      ["runtime.model-router", "runtime.tool-result"],
    ],
  );
  assert.equal(projection.latestEventId, "event-3");
  assert.equal(projection.latestCursor, "events_thread:test:3");
});

test("projects coding tool events as receipt-backed React Flow rows", () => {
  const projection = projectRuntimeThreadEventsToWorkflowProjection([
    event("event-coding-status", 1, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.WorkspaceStatus",
      workflowNodeId: "runtime.coding-tool.workspace.status",
      componentKind: "coding_tool",
      toolName: "workspace.status",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-status"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Workspace status inspected 1 changed file(s).",
      },
    }),
  ]);

  const node = projection.nodes[0];
  assert.equal(node?.workflowNodeId, "runtime.coding-tool.workspace.status");
  assert.equal(node?.nodeKind, "plugin_tool");
  assert.equal(node?.componentKind, "coding_tool");
  assert.equal(node?.label, "Coding tool: workspace.status");
  assert.equal(node?.toolName, "workspace.status");
  assert.equal(node?.latestPayloadSchemaVersion, "ioi.runtime.coding-tool-result.v1");
  assert.deepEqual(node?.receiptRefs, ["receipt-coding-status"]);
  assert.equal(node?.summary, "Workspace status inspected 1 changed file(s).");
});

test("projects approval and policy events without workflow node ids", () => {
  const approval = event("event-approval", 1, {
    type: "approval_required",
    eventKind: "approval.required",
    sourceEventKind: "KernelEvent::ApprovalRequired",
    approvalId: "approval-123",
    status: "waiting_for_input",
  });
  const policy = event("event-policy", 2, {
    type: "policy_blocked",
    eventKind: "policy.blocked",
    sourceEventKind: "KernelEvent::PolicyBlocked",
    status: "blocked",
    policyDecisionRefs: ["policy-deny"],
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([approval, policy]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(approval), "runtime.approval.approval-123");
  assert.equal(nodes[0]?.nodeKind, "human_gate");
  assert.equal(nodes[0]?.status, "waiting");
  assert.equal(nodes[1]?.workflowNodeId, "runtime.policy");
  assert.equal(nodes[1]?.nodeKind, "hook_policy");
  assert.equal(nodes[1]?.status, "blocked");
  assert.deepEqual(nodes[1]?.policyDecisionRefs, ["policy-deny"]);
});

test("projects operator interrupt events into the runtime control node", () => {
  const interrupt = event("event-interrupt", 4, {
    type: "turn_interrupted",
    eventKind: "turn.interrupted",
    sourceEventKind: "OperatorControl.Interrupt",
    status: "interrupted",
    componentKind: "operator_control",
    workflowNodeId: "runtime.operator-interrupt",
    receiptRefs: ["receipt-interrupt"],
    policyDecisionRefs: ["policy-interrupt-allow"],
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
    payload: { reason: "operator paused live validation" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([interrupt]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(interrupt), "runtime.operator-interrupt");
  assert.equal(nodes[0]?.nodeKind, "runtime_operator_interrupt");
  assert.equal(nodes[0]?.componentKind, "operator_control");
  assert.equal(nodes[0]?.label, "Turn interrupted");
  assert.equal(nodes[0]?.status, "interrupted");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-interrupt"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-interrupt-allow"]);
  assert.deepEqual(nodes[0]?.tuiDeepLink, {
    schemaVersion: WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    command: "ioi agent tui",
    args: [
      "agent",
      "tui",
      "--thread-id",
      "thread-test",
      "--since-seq",
      "4",
    ],
    reopenCommand: "ioi agent tui --thread-id thread-test --since-seq 4",
    threadId: "thread-test",
    turnId: "turn-test",
    workflowGraphId: "workflow-test",
    workflowNodeId: "runtime.operator-interrupt",
    eventId: "event-interrupt",
    eventKind: "turn.interrupted",
    componentKind: "operator_control",
    seq: 4,
    cursor: "events_thread:test:4",
    sinceSeq: 4,
    lastEventId: "event-interrupt",
  });
  assert.equal(
    nodes[0]?.reactFlowNode.data.tuiDeepLink.eventId,
    "event-interrupt",
  );
});

test("projects thread fork events into the runtime fork node", () => {
  const fork = event("event-fork", 4, {
    type: "thread_forked",
    eventKind: "thread.forked",
    sourceEventKind: "OperatorControl.Fork",
    status: "completed",
    componentKind: "thread_fork",
    workflowNodeId: "runtime.thread-fork",
    receiptRefs: ["receipt-fork"],
    policyDecisionRefs: ["policy-fork-allow"],
    payloadSchemaVersion: "ioi.runtime.thread-fork.v1",
    payload: { fork_thread_id: "thread-fork" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([fork]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(fork), "runtime.thread-fork");
  assert.equal(nodes[0]?.nodeKind, "runtime_thread_fork");
  assert.equal(nodes[0]?.componentKind, "thread_fork");
  assert.equal(nodes[0]?.label, "Thread forked");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-fork"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-fork-allow"]);
});

test("projects operator steer events into the runtime control node", () => {
  const steer = event("event-steer", 5, {
    type: "turn_steered",
    eventKind: "turn.steered",
    sourceEventKind: "OperatorControl.Steer",
    status: "completed",
    componentKind: "operator_control",
    workflowNodeId: "runtime.operator-steer",
    receiptRefs: ["receipt-steer"],
    policyDecisionRefs: ["policy-steer-allow"],
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
    payload: { guidance: "focus on the failing assertion" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([steer]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(steer), "runtime.operator-steer");
  assert.equal(nodes[0]?.nodeKind, "runtime_operator_steer");
  assert.equal(nodes[0]?.componentKind, "operator_control");
  assert.equal(nodes[0]?.label, "Turn steered");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-steer"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-steer-allow"]);
});

test("projects context compact events into the runtime compaction node", () => {
  const compact = event("event-compact", 6, {
    type: "context_compacted",
    eventKind: "context.compacted",
    sourceEventKind: "OperatorControl.Compact",
    status: "completed",
    componentKind: "context_compaction",
    workflowNodeId: "runtime.context-compact",
    receiptRefs: ["receipt-compact"],
    policyDecisionRefs: ["policy-compact-allow"],
    payloadSchemaVersion: "ioi.runtime.context-compaction.v1",
    payload: { reason: "reduce stale context" },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([compact]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(compact), "runtime.context-compact");
  assert.equal(nodes[0]?.nodeKind, "runtime_context_compact");
  assert.equal(nodes[0]?.componentKind, "context_compaction");
  assert.equal(nodes[0]?.label, "Context compacted");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-compact"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, ["policy-compact-allow"]);
});

test("projects TUI control state into React Flow run-inspector rows", () => {
  const projection = projectRuntimeTuiControlStateToWorkflowProjection({
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: "thread-test",
    current_turn_id: "turn-test",
    last_cursor: "events_thread:test:8",
    last_event_id: "event-steer",
    mode_status: {
      mode: "agent",
      approval_mode: "suggest",
      trust_profile: "local_private",
      thread_status: "active",
      current_turn_status: "waiting_for_approval",
    },
    approval_rows: [
      {
        id: "approval-row",
        approval_id: "approval-123",
        status: "pending",
        message: "Confirm shell execution",
        workflow_node_id: "runtime.approval.approval-123",
        receipt_refs: ["receipt-approval-request"],
        policy_decision_refs: ["policy-approval-required"],
        sequence: 5,
      },
    ],
    approval_decisions: [
      {
        id: "approval-decision",
        approval_id: "approval-123",
        decision: "approve",
        status: "approved",
        event_id: "event-approval-approved",
        workflow_node_id: "runtime.approval.approval-123",
        receipt_refs: ["receipt-approval-approved"],
        policy_decision_refs: ["policy-approval-allow"],
        sequence: 6,
      },
    ],
    command_history: [
      {
        id: "tui-command-1",
        command: "events",
        raw_input: "/events 0",
        status: "applied",
        sequence: 1,
        cursor: "events_thread:test:4",
      },
      {
        id: "tui-command-2",
        command: "steer",
        raw_input: "/steer keep it focused",
        status: "applied",
        sequence: 2,
        turn_id: "turn-test",
        event_id: "event-steer",
      },
    ],
    validation_errors: [
      {
        id: "tui-error-1",
        command: "steer",
        raw_input: "/steer",
        message: "/steer requires guidance text",
        sequence: 3,
      },
    ],
  });

  assert.equal(
    projection.schemaVersion,
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
  );
  assert.equal(projection.sourceSchemaVersion, "ioi.agent-cli.tui-control-state.v1");
  assert.equal(projection.threadId, "thread-test");
  assert.equal(projection.currentTurnId, "turn-test");
  assert.equal(projection.lastCursor, "events_thread:test:8");
  assert.equal(projection.commandCount, 2);
  assert.equal(projection.validationErrorCount, 1);
  assert.equal(projection.approvalCount, 1);
  assert.equal(projection.approvalDecisionCount, 1);
  assert.equal(projection.rowCount, 7);
  assert.deepEqual(
    projection.rows.map((row) => [row.rowKind, row.command, row.status]),
    [
      ["summary", null, "current"],
      ["mode_status", null, "current"],
      ["approval", null, "pending"],
      ["approval_decision", "approve", "approved"],
      ["command", "events", "applied"],
      ["command", "steer", "applied"],
      ["validation_error", "steer", "validation_error"],
    ],
  );
  assert.equal(
    projection.rows[3]?.receiptRefs[0],
    "receipt-approval-approved",
  );
  assert.equal(
    projection.rows[5]?.reactFlowNodeId,
    "runtime.tui-control-state.command.steer",
  );
  assert.equal(projection.rows[6]?.message, "/steer requires guidance text");
});
