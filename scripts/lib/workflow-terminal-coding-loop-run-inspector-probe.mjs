#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { makeDefaultWorkflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-defaults.ts";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-coding-tool-control-nodes.ts";
import { createWorkflowRuntimeTerminalCodingLoopTemplateSubflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts";
import {
  materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow,
  workflowRuntimeTerminalCodingLoopIdsFromWorkflow,
} from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-terminal-coding-loop-materialization.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-terminal-coding-loop-run-inspector-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function workflowBase(name = "Terminal coding loop run inspector proof") {
  const workflow = makeDefaultWorkflow(name);
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.terminal-coding-loop-run-inspector",
    },
  };
}

function codingToolRow(overrides = {}) {
  return {
    id: "tui-coding-tool:test-run-proof",
    rowKind: "coding_tool",
    status: "completed",
    label: "Coding tool: test.run",
    command: "test",
    rawInput: "/test sample.test.mjs",
    message: "test.run completed",
    approvalId: null,
    jobId: null,
    runId: "run-terminal-loop-proof",
    modelId: null,
    toolName: "test.run",
    toolCallId: "coding_tool_test_run_proof",
    routeId: null,
    reasoningEffort: null,
    codingToolMutationBlocked: false,
    codingToolShellFallbackUsed: false,
    codingToolDryRun: false,
    threadId: "thread-terminal-loop-proof",
    turnId: "turn-terminal-loop-proof",
    workflowGraphId: "workflow.terminal-coding-loop-run-inspector",
    cursor: "events_thread-terminal-loop-proof:12",
    eventId: "event-terminal-loop-test-proof",
    sequence: 12,
    receiptRefs: ["receipt_coding_tool_test_run_proof"],
    artifactRefs: ["artifact_test_run_proof_stdout"],
    policyDecisionRefs: ["policy_test_run_proof"],
    rollbackRefs: ["workspace_snapshot_before_test_proof"],
    reactFlowNodeId: "runtime.coding-tool.test.run",
    ...overrides,
  };
}

function workflowWithExistingLoop() {
  const base = workflowBase("Existing terminal coding loop");
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "existing-terminal-loop-proof",
    workflowGraphId: base.metadata.id,
    origin: { x: 100, y: 140 },
  });
  return {
    workflow: {
      ...base,
      nodes: [...base.nodes, ...subflow.nodes],
      edges: [...base.edges, ...subflow.edges],
    },
    subflow,
  };
}

const controller = read("packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx");
const view = read("packages/hypervisor-workbench/src/WorkflowComposer/view.tsx");
const runsPanel = read(
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
);
const railPanel = read(
  "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/core.tsx",
);
const materialization = read(
  "packages/hypervisor-workbench/src/runtime/workflow-runtime-terminal-coding-loop-materialization.ts",
);

const row = codingToolRow();
const materialized = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
  workflowBase(),
  row,
  {
    idPrefix: "run-inspector-terminal-loop-proof",
    origin: { x: 120, y: 160 },
  },
);
const existing = workflowWithExistingLoop();
const hydrated = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
  existing.workflow,
  codingToolRow({ toolName: "file.inspect", command: "inspect" }),
);
const blocked = materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow(
  workflowBase("Missing terminal coding row"),
  { ...row, rowKind: "usage_status" },
);
const materializedLoopIds = workflowRuntimeTerminalCodingLoopIdsFromWorkflow(
  materialized.workflow,
);
const testNode = materialized.workflow.nodes.find(
  (node) => node.config?.logic.runtimeTerminalCodingLoopStepId === "test_run",
);
const request = testNode
  ? createRuntimeCodingToolControlRequestFromWorkflowNode(
      testNode,
      testNode.config?.logic.testInput ?? {},
      { workflowGraphId: materialized.workflow.metadata.id },
    )
  : null;

const checks = {
  runInspectorButtonRendered:
    /workflow-run-terminal-coding-loop-materialize-/.test(runsPanel),
  runInspectorButtonCallsHandler:
    /onMaterializeRuntimeTerminalCodingLoop\?\.\(row\)/.test(runsPanel),
  railPanelPropWired: /onMaterializeRuntimeTerminalCodingLoop/.test(railPanel),
  viewPassesHandler:
    /handleMaterializeRuntimeTerminalCodingLoop\(row\)/.test(view),
  controllerUsesMaterializationHelper:
    /handleMaterializeRuntimeTerminalCodingLoop/.test(controller) &&
    /materializeWorkflowRuntimeTerminalCodingLoopFromTuiRow/.test(controller),
  materializationHelperDetectsExistingLoop:
    /workflowRuntimeTerminalCodingLoopIdsFromWorkflow/.test(materialization) &&
    /mode: "hydrated"/.test(materialization),
  materializesNineNodes:
    materialized.status === "bound" &&
    materialized.mode === "materialized" &&
    materialized.insertedNodeIds.length === 9,
  materializesEightEdges:
    materialized.status === "bound" && materialized.insertedEdgeIds.length === 8,
  materializedLoopDetected:
    JSON.stringify(materializedLoopIds) ===
    JSON.stringify(materialized.insertedNodeIds),
  bindsTuiReopen:
    testNode?.config?.logic.runtimeTerminalCodingLoopTuiReopen?.threadId ===
      "thread-terminal-loop-proof" &&
    /--since-seq 11/.test(
      testNode?.config?.logic.runtimeTerminalCodingLoopTuiReopen
        ?.reopenCommand ?? "",
    ),
  boundNodeCompilesToDaemonRequest:
    request?.threadId === "thread-terminal-loop-proof" &&
    request?.toolId === "test.run" &&
    request?.body.workflowNodeId === testNode?.id,
  hydratesExistingLoop:
    hydrated.status === "bound" &&
    hydrated.mode === "hydrated" &&
    hydrated.insertedNodeIds.length === 0 &&
    hydrated.boundNodeIds.length === 9 &&
    hydrated.workflow.nodes.length === existing.workflow.nodes.length,
  blocksMissingCodingToolRow:
    blocked.status === "blocked" &&
    blocked.blockers.includes("runtime_terminal_coding_loop_evidence_missing"),
};

const proof = {
  schemaVersion: "workflow.terminal-coding-loop.run-inspector-proof.v1",
  scenario: "workflow_terminal_coding_loop_run_inspector_materialize",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-terminal-coding-loop-materialize-*",
  materialized: {
    mode: materialized.mode,
    insertedNodeIds: materialized.insertedNodeIds,
    insertedEdgeIds: materialized.insertedEdgeIds,
    boundNodeIds: materialized.boundNodeIds,
    evidenceToolCallId: materialized.evidenceBinding?.toolCallId ?? null,
  },
  hydrated: {
    mode: hydrated.mode,
    insertedNodeIds: hydrated.insertedNodeIds,
    boundNodeIds: hydrated.boundNodeIds,
  },
  checks,
  sourceRefs: [
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/core.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-terminal-coding-loop-materialization.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-terminal-coding-loop-materialization.test.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
