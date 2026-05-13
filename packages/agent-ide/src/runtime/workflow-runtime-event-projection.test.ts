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
    event("event-coding-patch", 2, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.FileApplyPatch",
      workflowNodeId: "runtime.coding-tool.file.apply-patch",
      componentKind: "coding_tool",
      toolName: "file.apply_patch",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-patch"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Patch applied to README.md.",
      },
    }),
    event("event-workspace-snapshot", 3, {
      type: "runtime_step",
      eventKind: "workspace.snapshot.created",
      sourceEventKind: "WorkspaceSnapshot.Created",
      workflowNodeId: "runtime.workspace-snapshot",
      componentKind: "workspace_snapshot",
      payloadSchemaVersion: "ioi.runtime.workspace-snapshot.v1",
      receiptRefs: ["receipt-workspace-snapshot"],
      artifactRefs: ["artifact-workspace-snapshot"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Workspace snapshot recorded 1 changed file(s) for coding_tool_123.",
      },
    }),
    event("event-restore-preview", 4, {
      type: "runtime_step",
      eventKind: "workspace.restore.previewed",
      sourceEventKind: "WorkspaceRestore.Previewed",
      workflowNodeId: "runtime.restore-gate",
      componentKind: "restore_gate",
      payloadSchemaVersion: "ioi.runtime.workspace-restore-preview.v1",
      receiptRefs: ["receipt-restore-preview"],
      artifactRefs: ["artifact-restore-preview"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Restore preview ready for 1 file(s) from workspace_snapshot_123.",
      },
    }),
    event("event-restore-apply", 5, {
      type: "runtime_step",
      eventKind: "workspace.restore.applied",
      sourceEventKind: "WorkspaceRestore.Applied",
      workflowNodeId: "runtime.restore-apply",
      componentKind: "restore_gate",
      payloadSchemaVersion: "ioi.runtime.workspace-restore-apply.v1",
      receiptRefs: ["receipt-restore-apply"],
      artifactRefs: ["artifact-restore-apply"],
      rollbackRefs: ["workspace_snapshot_123"],
      payload: {
        summary: "Restore apply restored 1 file(s) from workspace_snapshot_123.",
      },
    }),
    event("event-coding-test", 6, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.TestRun",
      workflowNodeId: "runtime.coding-tool.test.run",
      componentKind: "coding_tool",
      toolName: "test.run",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-test"],
      artifactRefs: ["artifact-coding-test-output"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Test run passed with exit code 0.",
      },
    }),
    event("event-coding-diagnostics", 7, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.LspDiagnostics",
      workflowNodeId: "runtime.coding-tool.lsp.diagnostics",
      componentKind: "coding_tool",
      toolName: "lsp.diagnostics",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-diagnostics"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Diagnostics findings with 1 finding(s).",
      },
    }),
    event("event-diagnostics-injected", 8, {
      type: "runtime_step",
      eventKind: "lsp.diagnostics.injected",
      sourceEventKind: "LspDiagnostics.Injected",
      workflowNodeId: "runtime.lsp-diagnostics.injected",
      componentKind: "lsp_diagnostics",
      payloadSchemaVersion: "ioi.runtime.lsp-diagnostics-injection.v1",
      receiptRefs: ["receipt-lsp-diagnostics-injected"],
      payload: {
        summary: "Injected 1 post-edit diagnostic finding(s).",
      },
    }),
    event("event-coding-retrieve", 9, {
      type: "tool_completed",
      eventKind: "tool.completed",
      sourceEventKind: "CodingTool.ToolRetrieveResult",
      workflowNodeId: "runtime.coding-tool.tool.retrieve-result",
      componentKind: "coding_tool",
      toolName: "tool.retrieve_result",
      payloadSchemaVersion: "ioi.runtime.coding-tool-result.v1",
      receiptRefs: ["receipt-coding-retrieve"],
      artifactRefs: ["artifact-coding-test-output"],
      payload: {
        tool_pack: "coding",
        shell_fallback_used: false,
        summary: "Retrieved tool result coding_tool_123.",
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
  const patchNode = projection.nodes[1];
  assert.equal(patchNode?.workflowNodeId, "runtime.coding-tool.file.apply-patch");
  assert.equal(patchNode?.label, "Coding tool: file.apply_patch");
  assert.equal(patchNode?.toolName, "file.apply_patch");
  assert.deepEqual(patchNode?.receiptRefs, ["receipt-coding-patch"]);
  assert.equal(patchNode?.summary, "Patch applied to README.md.");
  const snapshotNode = projection.nodes[2];
  assert.equal(snapshotNode?.workflowNodeId, "runtime.workspace-snapshot");
  assert.equal(snapshotNode?.nodeKind, "quality_ledger");
  assert.equal(snapshotNode?.componentKind, "workspace_snapshot");
  assert.equal(snapshotNode?.label, "Workspace snapshot");
  assert.deepEqual(snapshotNode?.receiptRefs, ["receipt-workspace-snapshot"]);
  assert.deepEqual(snapshotNode?.artifactRefs, ["artifact-workspace-snapshot"]);
  assert.deepEqual(snapshotNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    snapshotNode?.summary,
    "Workspace snapshot recorded 1 changed file(s) for coding_tool_123.",
  );
  const restoreNode = projection.nodes[3];
  assert.equal(restoreNode?.workflowNodeId, "runtime.restore-gate");
  assert.equal(restoreNode?.nodeKind, "hook_policy");
  assert.equal(restoreNode?.componentKind, "restore_gate");
  assert.equal(restoreNode?.label, "Restore preview");
  assert.deepEqual(restoreNode?.receiptRefs, ["receipt-restore-preview"]);
  assert.deepEqual(restoreNode?.artifactRefs, ["artifact-restore-preview"]);
  assert.deepEqual(restoreNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    restoreNode?.summary,
    "Restore preview ready for 1 file(s) from workspace_snapshot_123.",
  );
  const restoreApplyNode = projection.nodes[4];
  assert.equal(restoreApplyNode?.workflowNodeId, "runtime.restore-apply");
  assert.equal(restoreApplyNode?.nodeKind, "hook_policy");
  assert.equal(restoreApplyNode?.componentKind, "restore_gate");
  assert.equal(restoreApplyNode?.label, "Restore apply");
  assert.deepEqual(restoreApplyNode?.receiptRefs, ["receipt-restore-apply"]);
  assert.deepEqual(restoreApplyNode?.artifactRefs, ["artifact-restore-apply"]);
  assert.deepEqual(restoreApplyNode?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(
    restoreApplyNode?.summary,
    "Restore apply restored 1 file(s) from workspace_snapshot_123.",
  );
  const testNode = projection.nodes[5];
  assert.equal(testNode?.workflowNodeId, "runtime.coding-tool.test.run");
  assert.equal(testNode?.label, "Coding tool: test.run");
  assert.equal(testNode?.toolName, "test.run");
  assert.deepEqual(testNode?.receiptRefs, ["receipt-coding-test"]);
  assert.deepEqual(testNode?.artifactRefs, ["artifact-coding-test-output"]);
  assert.equal(testNode?.summary, "Test run passed with exit code 0.");
  const diagnosticsNode = projection.nodes[6];
  assert.equal(diagnosticsNode?.workflowNodeId, "runtime.coding-tool.lsp.diagnostics");
  assert.equal(diagnosticsNode?.label, "Coding tool: lsp.diagnostics");
  assert.deepEqual(diagnosticsNode?.receiptRefs, ["receipt-coding-diagnostics"]);
  const injectedNode = projection.nodes[7];
  assert.equal(injectedNode?.workflowNodeId, "runtime.lsp-diagnostics.injected");
  assert.equal(injectedNode?.label, "Diagnostics injected");
  assert.deepEqual(injectedNode?.receiptRefs, ["receipt-lsp-diagnostics-injected"]);
  assert.equal(injectedNode?.summary, "Injected 1 post-edit diagnostic finding(s).");
  const retrieveNode = projection.nodes[8];
  assert.equal(retrieveNode?.workflowNodeId, "runtime.coding-tool.tool.retrieve-result");
  assert.equal(retrieveNode?.label, "Coding tool: tool.retrieve_result");
  assert.deepEqual(retrieveNode?.artifactRefs, ["artifact-coding-test-output"]);
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

test("projects diagnostics blocking gates as workflow-addressable policy nodes", () => {
  const gate = event("event-diagnostics-gate", 6, {
    type: "policy_blocked",
    eventKind: "policy.blocked",
    sourceEventKind: "LspDiagnostics.BlockingGate",
    status: "blocked",
    workflowNodeId: "runtime.lsp-diagnostics.blocking-gate",
    componentKind: "lsp_diagnostics_gate",
    payloadSchemaVersion: "ioi.runtime.lsp-diagnostics-blocking-gate.v1",
    receiptRefs: ["receipt-lsp-diagnostics-gate"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-repair-retry",
      "policy-lsp-diagnostics-gate-decision-restore-preview",
      "policy-lsp-diagnostics-gate-decision-restore-apply",
      "policy-lsp-diagnostics-gate-decision-operator-override",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Blocking diagnostics gate paused model continuation after 1 finding(s).",
      reason: "post_edit_diagnostics_findings",
      repair_policy: {
        decisions: [
          { action: "repair_retry" },
          { action: "restore_preview" },
          { action: "restore_apply" },
          { action: "operator_override" },
        ],
      },
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([gate]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(gate), "runtime.lsp-diagnostics.blocking-gate");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_gate");
  assert.equal(nodes[0]?.label, "Diagnostics blocking gate");
  assert.equal(nodes[0]?.status, "blocked");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-gate"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-repair-retry",
    "policy-lsp-diagnostics-gate-decision-restore-preview",
    "policy-lsp-diagnostics-gate-decision-restore-apply",
    "policy-lsp-diagnostics-gate-decision-operator-override",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.lsp-diagnostics-blocking-gate.v1");
});

test("projects diagnostics repair decisions as workflow-addressable policy nodes", () => {
  const repairDecision = event("event-diagnostics-repair-decision", 7, {
    type: "runtime_step",
    eventKind: "diagnostics.repair_decision.executed",
    sourceEventKind: "LspDiagnostics.RepairDecisionExecuted",
    status: "completed",
    workflowNodeId: "workflow.diagnostics.repair.restore-preview.decision",
    componentKind: "lsp_diagnostics_repair",
    payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
    receiptRefs: ["receipt-lsp-diagnostics-repair"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-restore-preview",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Diagnostics repair decision restore_preview executed for workspace_snapshot_123.",
      action: "restore_preview",
      snapshot_id: "workspace_snapshot_123",
      restore_preview_event_id: "event-restore-preview",
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([repairDecision]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(repairDecision), "workflow.diagnostics.repair.restore-preview.decision");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_repair");
  assert.equal(nodes[0]?.label, "Diagnostics repair decision");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-repair"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-restore-preview",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
});

test("projects diagnostics repair retry executions as workflow-addressable policy nodes", () => {
  const repairRetry = event("event-diagnostics-repair-retry", 8, {
    type: "runtime_step",
    eventKind: "diagnostics.repair_retry.created",
    sourceEventKind: "LspDiagnostics.RepairRetryTurnCreated",
    status: "completed",
    workflowNodeId: "workflow.diagnostics.repair.retry",
    componentKind: "lsp_diagnostics_repair_retry",
    payloadSchemaVersion: "ioi.runtime.diagnostics-repair-decision-execution.v1",
    receiptRefs: ["receipt-lsp-diagnostics-repair-retry"],
    policyDecisionRefs: [
      "policy-lsp-diagnostics-gate",
      "policy-lsp-diagnostics-gate-decision-repair-retry",
    ],
    rollbackRefs: ["workspace_snapshot_123"],
    payload: {
      summary: "Diagnostics repair retry created turn turn_123.",
      action: "repair_retry",
      retry_turn_id: "turn_123",
      repair_prompt_injected: true,
    },
  });
  const nodes = projectRuntimeThreadEventsToWorkflowNodes([repairRetry]);

  assert.equal(workflowNodeIdForRuntimeThreadEvent(repairRetry), "workflow.diagnostics.repair.retry");
  assert.equal(nodes[0]?.nodeKind, "hook_policy");
  assert.equal(nodes[0]?.componentKind, "lsp_diagnostics_repair_retry");
  assert.equal(nodes[0]?.label, "Diagnostics repair retry");
  assert.equal(nodes[0]?.status, "completed");
  assert.deepEqual(nodes[0]?.receiptRefs, ["receipt-lsp-diagnostics-repair-retry"]);
  assert.deepEqual(nodes[0]?.policyDecisionRefs, [
    "policy-lsp-diagnostics-gate",
    "policy-lsp-diagnostics-gate-decision-repair-retry",
  ]);
  assert.deepEqual(nodes[0]?.rollbackRefs, ["workspace_snapshot_123"]);
  assert.equal(nodes[0]?.latestPayloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
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
