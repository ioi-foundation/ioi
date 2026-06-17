import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-control-nodes";
import type { WorkflowRuntimeTuiControlStateRow } from "./workflow-runtime-event-projection";
import {
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "./workflow-runtime-terminal-coding-loop-subflow";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
  materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow,
  workflowRuntimeTerminalCodingLoopEvidenceBinding,
  workflowRuntimeTerminalCodingLoopIdsFromWorkflow,
} from "./workflow-runtime-terminal-coding-loop-materialization";

function workflowBase(): WorkflowProject {
  const workflow = makeDefaultWorkflow("Terminal coding loop run inspector");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.terminal-coding-loop-run-inspector",
    },
  };
}

function codingToolRow(
  overrides: Partial<WorkflowRuntimeTuiControlStateRow> = {},
): WorkflowRuntimeTuiControlStateRow {
  return {
    id: "tui-coding-tool:test-run",
    rowKind: "coding_tool",
    status: "completed",
    label: "Coding tool: test.run",
    command: "test",
    rawInput: "/test sample.test.mjs",
    message: "test.run completed",
    approvalId: null,
    jobId: null,
    runId: "run-terminal-loop",
    modelId: null,
    toolName: "test.run",
    toolCallId: "coding_tool_test_run_123",
    routeId: null,
    reasoningEffort: null,
    codingToolMutationBlocked: false,
    codingToolShellFallbackUsed: false,
    codingToolDryRun: false,
    threadId: "thread-terminal-loop",
    turnId: "turn-terminal-loop",
    workflowGraphId: "workflow.terminal-coding-loop-run-inspector",
    cursor: "events_thread-terminal-loop:9",
    eventId: "event-terminal-loop-test",
    sequence: 9,
    receiptRefs: ["receipt_coding_tool_test_run_123"],
    artifactRefs: ["artifact_test_run_123_stdout"],
    policyDecisionRefs: ["policy_test_run_123"],
    rollbackRefs: ["workspace_snapshot_before_test"],
    reactFlowNodeId: "runtime.coding-tool.test.run",
    ...overrides,
  };
}

test("run-inspector coding-tool evidence materializes a terminal coding loop", () => {
  const row = codingToolRow();
  const result = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
    workflowBase(),
    row,
    {
      idPrefix: "run-inspector-terminal-loop",
      origin: { x: 180, y: 220 },
    },
  );

  assert.equal(
    result.schemaVersion,
    WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_MATERIALIZATION_SCHEMA_VERSION,
  );
  assert.equal(result.status, "bound");
  assert.equal(result.mode, "materialized");
  assert.equal(result.insertedNodeIds.length, 9);
  assert.equal(result.insertedEdgeIds.length, 8);
  assert.deepEqual(result.boundNodeIds, result.insertedNodeIds);
  assert.equal(result.evidenceBinding?.threadId, "thread-terminal-loop");
  assert.equal(result.evidenceBinding?.toolCallId, "coding_tool_test_run_123");

  const loopIds = workflowRuntimeTerminalCodingLoopIdsFromWorkflow(
    result.workflow,
  );
  assert.deepEqual(loopIds, result.insertedNodeIds);

  const testNode = result.workflow.nodes.find(
    (node) =>
      node.config?.logic.runtimeTerminalCodingLoopStepId === "test_run",
  )!;
  assert.equal(
    (testNode.config?.logic.runtimeTerminalCodingLoopEvidence as any).rowId,
    "tui-coding-tool:test-run",
  );
  assert.match(
    (testNode.config?.logic.runtimeTerminalCodingLoopTuiReopen as any)
      .reopenCommand,
    /ioi agent tui --thread-id thread-terminal-loop --interactive --since-seq 8/,
  );

  const request = createRuntimeCodingToolControlRequestFromWorkflowNode(
    testNode,
    testNode.config?.logic.testInput ?? {},
    { workflowGraphId: result.workflow.metadata.id },
  );
  assert.equal(request.threadId, "thread-terminal-loop");
  assert.equal(request.toolId, "test.run");
  assert.equal(request.body.workflowNodeId, testNode.id);
});

test("run-inspector coding-tool evidence hydrates an existing terminal loop", () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "existing-terminal-loop",
    workflowGraphId: "workflow.terminal-coding-loop-run-inspector",
  });
  const base = workflowBase();
  const workflow = {
    ...base,
    nodes: [...base.nodes, ...subflow.nodes],
    edges: [...base.edges, ...subflow.edges],
  };
  const result = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
    workflow,
    codingToolRow({ toolName: "file.inspect", command: "inspect" }),
  );

  assert.equal(result.status, "bound");
  assert.equal(result.mode, "hydrated");
  assert.deepEqual(result.insertedNodeIds, []);
  assert.deepEqual(result.insertedEdgeIds, []);
  assert.deepEqual(result.boundNodeIds, subflow.nodeIds);
  assert.equal(result.workflow.nodes.length, workflow.nodes.length);
  assert.equal(
    (result.workflow.nodes.find((node) => node.id === subflow.stepNodeIds.file_inspect)
      ?.config?.logic.runtimeTerminalCodingLoopEvidence as any).toolName,
    "file.inspect",
  );
});

test("run-inspector terminal loop materialization blocks without coding-tool row evidence", () => {
  const missing = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
    workflowBase(),
    null,
  );
  assert.equal(missing.status, "blocked");
  assert(missing.blockers.includes("runtime_terminal_coding_loop_evidence_missing"));

  const nonCodingTool = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
    workflowBase(),
    codingToolRow({ rowKind: "usage_status", threadId: "thread-terminal-loop" }),
  );
  assert.equal(nonCodingTool.status, "blocked");
});

test("terminal coding loop evidence binding requires a coding-tool row and thread", () => {
  assert.equal(
    workflowRuntimeTerminalCodingLoopEvidenceBinding(codingToolRow())?.rowKind,
    "coding_tool",
  );
  assert.equal(
    workflowRuntimeTerminalCodingLoopEvidenceBinding(
      codingToolRow({ threadId: null }),
    ),
    null,
  );
});
