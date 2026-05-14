#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  runWorkflowComposerTerminalCodingLoopActivation,
  workflowComposerTerminalCodingLoopRunLaunchEligible,
} from "../../packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.ts";
import { makeDefaultWorkflow } from "../../packages/agent-ide/src/runtime/workflow-defaults.ts";
import { workflowRunHistoryModel } from "../../packages/agent-ide/src/runtime/workflow-run-history-model.ts";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "../../packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-terminal-coding-loop-run-button-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);
const workflowGraphId = "workflow.terminal-coding-loop-run-button";
const threadId = "thread-terminal-loop-run-button";
const runStartedAtMs = 1_800_000;

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function workflowWithSubflow(subflow) {
  const workflow = makeDefaultWorkflow("Terminal coding loop Run button proof");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: workflowGraphId,
      name: "Terminal coding loop Run button proof",
      slug: "terminal-coding-loop-run-button-proof",
      gitLocation:
        ".agents/workflows/terminal-coding-loop-run-button-proof.workflow.json",
      readOnly: false,
    },
    nodes: subflow.nodes,
    edges: subflow.edges,
    global_config: {},
  };
}

function slug(value) {
  return (
    String(value)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 80) || "value"
  );
}

function safeId(value) {
  return slug(value);
}

function runtimeThreadEventFromDaemonEvent(event) {
  return {
    id: event.event_id,
    cursor: `${event.event_stream_id}:${event.seq}`,
    seq: event.seq,
    threadId: event.thread_id,
    turnId: event.turn_id ?? null,
    type: runtimeThreadEventType(event.event_kind),
    eventKind: event.event_kind,
    sourceEventKind: event.source_event_kind,
    status: event.status,
    componentKind: event.component_kind,
    workflowNodeId: event.workflow_node_id ?? null,
    workflowGraphId: event.workflow_graph_id ?? null,
    toolCallId: event.tool_call_id ?? null,
    toolName: event.tool_name ?? null,
    approvalId: event.approval_id ?? null,
    payloadSchemaVersion: event.payload_schema_version,
    receiptRefs: event.receipt_refs ?? [],
    artifactRefs: event.artifact_refs ?? [],
    policyDecisionRefs: event.policy_decision_refs ?? [],
    rollbackRefs: event.rollback_refs ?? [],
    payload: event.payload_summary ?? {},
  };
}

function runtimeThreadEventType(eventKind) {
  switch (eventKind) {
    case "tool.completed":
      return "tool_completed";
    case "approval.required":
      return "approval_required";
    case "approval.approved":
    case "approval.rejected":
      return "approval_decision";
    default:
      return "runtime_step";
  }
}

function tuiControlStateFromDaemonEvents(events, runId) {
  const codingToolRows = events
    .filter((event) => event.component_kind === "coding_tool")
    .map((event) => ({
      id: `tui-coding-tool:${event.tool_call_id}`,
      row_kind: "coding_tool",
      status: event.status,
      label: `Coding tool: ${event.tool_name}`,
      command: event.payload_summary?.terminal_command ?? null,
      raw_input: event.payload_summary?.terminal_command
        ? `/${event.payload_summary.terminal_command}`
        : "/tool",
      message: `${event.tool_name} completed`,
      run_id: runId,
      thread_id: event.thread_id,
      turn_id: event.turn_id,
      workflow_graph_id: event.workflow_graph_id,
      workflow_node_id: event.workflow_node_id,
      tool_name: event.tool_name,
      tool_call_id: event.tool_call_id,
      event_id: event.event_id,
      cursor: `${event.event_stream_id}:${event.seq}`,
      sequence: event.seq,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      policy_decision_refs: event.policy_decision_refs,
      rollback_refs: event.rollback_refs,
      dry_run: event.payload_summary?.dry_run === true,
      shell_fallback_used: false,
      mutation_blocked: false,
    }));
  const approvalRequired = events.find(
    (event) => event.event_kind === "approval.required",
  );
  const approvalDecision = events.find(
    (event) => event.event_kind === "approval.approved",
  );
  return {
    schema_version: "ioi.agent-cli.tui-control-state.v1",
    surface: "tui",
    thread_id: threadId,
    workflow_graph_id: workflowGraphId,
    current_turn_id: "turn-terminal-loop-run-button",
    last_cursor: events.length
      ? `${events.at(-1).event_stream_id}:${events.at(-1).seq}`
      : null,
    last_event_id: events.at(-1)?.event_id ?? null,
    mode_status: {
      mode: "agent",
      approval_mode: "human_required",
      trust_profile: "local_private",
    },
    approval_rows: approvalRequired
      ? [
          {
            id: "approval-row-terminal-loop-run-button",
            approval_id: approvalRequired.approval_id,
            status: "pending",
            message: "Terminal coding-loop patch approval required",
            thread_id: threadId,
            workflow_graph_id: workflowGraphId,
            workflow_node_id: approvalRequired.workflow_node_id,
            event_id: approvalRequired.event_id,
            sequence: approvalRequired.seq,
            receipt_refs: approvalRequired.receipt_refs,
            policy_decision_refs: approvalRequired.policy_decision_refs,
          },
        ]
      : [],
    approval_decisions: approvalDecision
      ? [
          {
            id: "approval-decision-terminal-loop-run-button",
            approval_id: approvalDecision.approval_id,
            decision: "approve",
            status: "approved",
            message: "Approved terminal coding-loop apply step",
            thread_id: threadId,
            workflow_graph_id: workflowGraphId,
            workflow_node_id: approvalDecision.workflow_node_id,
            event_id: approvalDecision.event_id,
            sequence: approvalDecision.seq,
            receipt_refs: approvalDecision.receipt_refs,
            policy_decision_refs: approvalDecision.policy_decision_refs,
          },
        ]
      : [],
    coding_tool_rows: codingToolRows,
  };
}

function expectedCommandOrder() {
  return WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map(
    (step) => step.command,
  );
}

const controller = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
const view = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
const runHistoryModelSource = read(
  "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
);

const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
  idPrefix: "terminal-coding-loop-run-button",
  workflowGraphId,
  origin: { x: 120, y: 160 },
});
const workflow = workflowWithSubflow(subflow);
const workflowPath =
  workflow.metadata.gitLocation ??
  ".agents/workflows/terminal-coding-loop-run-button-proof.workflow.json";
const stepIdByNodeId = new Map(
  Object.entries(subflow.stepNodeIds).map(([stepId, nodeId]) => [
    nodeId,
    stepId,
  ]),
);
const commandByStepId = new Map(
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map((step) => [
    step.stepId,
    step.command,
  ]),
);
const daemonEvents = [];
const controlRequests = [];
const approvalDecisionRequests = [];
let seq = 0;
let testArtifactId = null;
let testToolCallId = null;

function daemonEvent({
  eventKind,
  sourceEventKind,
  componentKind,
  workflowNodeId,
  toolName = null,
  toolCallId = null,
  approvalId = null,
  status = "completed",
  receiptRefs = [],
  artifactRefs = [],
  policyDecisionRefs = [],
  rollbackRefs = [],
  payloadSummary = {},
}) {
  seq += 1;
  const event = {
    event_id: `event-terminal-loop-run-button-${seq}`,
    event_stream_id: `events_${threadId}`,
    seq,
    event_kind: eventKind,
    source_event_kind: sourceEventKind,
    status,
    thread_id: threadId,
    turn_id: "turn-terminal-loop-run-button",
    workflow_graph_id: workflowGraphId,
    workflow_node_id: workflowNodeId,
    component_kind: componentKind,
    tool_name: toolName,
    tool_call_id: toolCallId,
    approval_id: approvalId,
    payload_schema_version: "ioi.agent-sdk.thread-event.v1",
    receipt_refs: receiptRefs,
    artifact_refs: artifactRefs,
    policy_decision_refs: policyDecisionRefs,
    rollback_refs: rollbackRefs,
    payload_summary: payloadSummary,
  };
  daemonEvents.push(event);
  return event;
}

function completedResult(stepId, nodeId, toolId, body) {
  const command = commandByStepId.get(stepId);
  const toolCallId =
    body.toolCallId ?? `terminal_loop_${safeId(threadId)}_${stepId}`;
  const receiptRefs = [`receipt-terminal-loop-run-button-${stepId}`];
  const policyDecisionRefs = [`policy-terminal-loop-run-button-${stepId}`];
  const artifactRefs =
    stepId === "test_run" || stepId === "artifact_read"
      ? ["artifact-terminal-loop-run-button-output"]
      : [];
  const rollbackRefs =
    stepId === "file_apply_patch"
      ? ["snapshot-terminal-loop-run-button"]
      : [];
  const result = {
    status: "completed",
    tool_name: toolId,
    tool_call_id: toolCallId,
    workflow_graph_id: workflowGraphId,
    workflow_node_id: nodeId,
    receipt_refs: receiptRefs,
    artifact_refs: artifactRefs,
    policy_decision_refs: policyDecisionRefs,
    rollback_refs: rollbackRefs,
    result: resultForStep(stepId, body),
    ...(stepId === "file_apply_patch"
      ? {
          workspace_snapshot: {
            schemaVersion: "ioi.runtime.workspace-snapshot.v1",
            snapshotId: "snapshot-terminal-loop-run-button",
          },
        }
      : {}),
  };
  const event = daemonEvent({
    eventKind: "tool.completed",
    sourceEventKind: "CodingTool.Invoke",
    componentKind: "coding_tool",
    workflowNodeId: nodeId,
    toolName: toolId,
    toolCallId,
    receiptRefs,
    artifactRefs,
    policyDecisionRefs,
    rollbackRefs,
    payloadSummary: {
      tool_name: toolId,
      tool_call_id: toolCallId,
      terminal_command: command,
      dry_run: stepId === "file_apply_patch_dry_run",
      approval_satisfied:
        stepId === "file_apply_patch" && Boolean(body.approvalId),
      result_summary: result.result,
    },
  });
  result.event = event;
  if (stepId === "test_run") {
    testToolCallId = toolCallId;
    testArtifactId = "artifact-terminal-loop-run-button-output";
  }
  return result;
}

function resultForStep(stepId, body) {
  switch (stepId) {
    case "workspace_status":
      return { branch: "master", dirty: true };
    case "git_diff":
      return { diff: "diff -- README.md\n+Pending terminal loop line\n" };
    case "file_inspect":
      return { path: "README.md", preview: "# Terminal loop\nreplace me\n" };
    case "file_apply_patch_dry_run":
      return { applied: false, dryRun: true, preview: "preview replacement" };
    case "file_apply_patch":
      return {
        applied: true,
        dryRun: false,
        approvalId: body.approvalId,
        changedFiles: ["README.md"],
      };
    case "test_run":
      return {
        testStatus: "passed",
        artifacts: [
          {
            artifactId: "artifact-terminal-loop-run-button-output",
            channel: "output",
          },
        ],
      };
    case "lsp_diagnostics":
      return { diagnosticStatus: "clean" };
    case "artifact_read":
      return {
        artifactId: body.arguments?.artifactId,
        content: "TERMINAL_LOOP_ARTIFACT_END",
      };
    case "tool_retrieve_result":
      return {
        toolCallId: body.arguments?.toolCallId,
        content: "TERMINAL_LOOP_ARTIFACT_END",
      };
    default:
      return {};
  }
}

const launch = await runWorkflowComposerTerminalCodingLoopActivation({
  workflow,
  workflowPath,
  threadId,
  actor: "workflow-author",
  startedAtMs: runStartedAtMs,
  executeRuntimeControlRequest: async (request) => {
    controlRequests.push(request);
    if (request.nodeType === "runtime_approval_decision") {
      approvalDecisionRequests.push(request);
      const approvalId = request.body.approvalId;
      daemonEvent({
        eventKind: "approval.approved",
        sourceEventKind: "OperatorApproval.Approve",
        componentKind: "approval_gate",
        workflowNodeId: request.body.workflowNodeId,
        approvalId,
        status: "approved",
        receiptRefs: [`receipt-terminal-loop-run-button-${approvalId}-approved`],
        policyDecisionRefs: [
          `policy-terminal-loop-run-button-${approvalId}-approved`,
        ],
        payloadSummary: {
          decision: "approve",
          approval_id: approvalId,
          workflow_graph_id: workflowGraphId,
          workflow_node_id: request.body.workflowNodeId,
        },
      });
      return { decision: "approve" };
    }

    const body = request.body;
    const stepId = stepIdByNodeId.get(body.workflowNodeId);
    if (!stepId) {
      throw new Error(`missing terminal coding-loop step for ${body.workflowNodeId}`);
    }
    if (stepId === "artifact_read" && body.arguments.artifactId !== testArtifactId) {
      throw new Error("artifact_read did not receive the prior test artifact id");
    }
    if (
      stepId === "tool_retrieve_result" &&
      body.arguments.toolCallId !== testToolCallId
    ) {
      throw new Error("tool_retrieve_result did not receive the prior test tool call id");
    }
    if (stepId === "file_apply_patch" && !body.approvalId) {
      const approvalId = "approval-terminal-loop-run-button";
      daemonEvent({
        eventKind: "approval.required",
        sourceEventKind: "OperatorApproval.Request",
        componentKind: "approval_gate",
        workflowNodeId: body.workflowNodeId,
        approvalId,
        status: "waiting_for_approval",
        receiptRefs: [`receipt-terminal-loop-run-button-${approvalId}`],
        policyDecisionRefs: [
          `policy-terminal-loop-run-button-${approvalId}-required`,
        ],
        payloadSummary: {
          action: "coding_tool.invoke",
          effect_class: "local_write",
          approval_id: approvalId,
          workflow_graph_id: workflowGraphId,
          workflow_node_id: body.workflowNodeId,
        },
      });
      return {
        status: "blocked",
        approval_required: true,
        approval_id: approvalId,
        approval_manifest: {
          schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
          workflow_policy: { source: "react_flow", requiresApproval: true },
          node_approval_override: "require_approval",
        },
      };
    }
    return completedResult(stepId, body.workflowNodeId, request.toolId, body);
  },
});

const runResult = launch.runResult;
const tuiControlState = tuiControlStateFromDaemonEvents(
  daemonEvents,
  runResult.summary.id,
);
const canonicalRuntimeEvents = daemonEvents.map(runtimeThreadEventFromDaemonEvent);
const runHistory = workflowRunHistoryModel({
  workflow,
  runs: [runResult.summary],
  lastRunResult: {
    ...runResult,
    tuiControlState,
  },
  compareRunResult: null,
  selectedRunId: runResult.summary.id,
  compareRunId: null,
  runEvents: [],
  runtimeThreadEvents: canonicalRuntimeEvents,
  searchQuery: "",
  statusFilter: "all",
  sourceFilter: "all",
});

const daemonCodingToolEvents = daemonEvents.filter(
  (event) => event.component_kind === "coding_tool",
);
const approvalDecisionEvents = daemonEvents.filter(
  (event) => event.event_kind === "approval.approved",
);
const terminalTuiRows = runHistory.visibleTuiControlStateRows.filter(
  (row) =>
    row.rowKind === "coding_tool" &&
    row.workflowGraphId === workflowGraphId &&
    subflow.nodeIds.includes(row.reactFlowNodeId),
);
const approvalDecisionRows = runHistory.visibleTuiControlStateRows.filter(
  (row) =>
    row.rowKind === "approval_decision" &&
    row.approvalId === "approval-terminal-loop-run-button",
);

const checks = {
  realRunButtonRendered:
    /testId="workflow-run-button"/.test(view) &&
    /label="Run"/.test(view) &&
    /icon=\{Play\}/.test(view),
  realRunButtonClickWired:
    /testId="workflow-run-button"[\s\S]*onClick=\{handleRun\}/.test(view),
  executionTabRunButtonClickWired:
    /onClick=\{handleRun\}[\s\S]*data-testid="workflow-executions-run-now"/.test(
      view,
    ) ||
    /data-testid="workflow-executions-run-now"[\s\S]*onClick=\{handleRun\}/.test(
      view,
    ),
  controllerRoutesEligibleTerminalLoop:
    /workflowComposerTerminalCodingLoopRunLaunchEligible\(currentProjectFile\)/.test(
      controller,
    ) &&
    /runWorkflowComposerTerminalCodingLoopActivation/.test(controller) &&
    /workflowComposerTerminalCodingLoopControlRequestForRuntime/.test(
      controller,
    ) &&
    /runtime\.executeWorkflowRuntimeControlRequest/.test(controller),
  runButtonUsesDaemonBridge:
    /executeRuntimeControlRequest: async \(request\)/.test(controller) &&
    /workflowComposerTerminalCodingLoopControlRequestForRuntime/.test(
      controller,
    ),
  workflowEligible: workflowComposerTerminalCodingLoopRunLaunchEligible(workflow),
  templateCreated:
    workflow.nodes.length === WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length &&
    workflow.edges.length === workflow.nodes.length - 1,
  noCanvasLocalRuntimeTruth:
    !/from "@xyflow\/react"/.test(
      read(
        "packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.ts",
      ),
    ) && /runtimeThreadEventsForRunResult/.test(runHistoryModelSource),
  composerActivationRun:
    runResult.summary.status === "passed" &&
    /^workflow-terminal-coding-loop-composer-/.test(runResult.summary.id) &&
    runResult.summary.threadId === threadId,
  runHistoryContainsComposerRun:
    runHistory.visibleRows.some(
      (row) => row.run.id === runResult.summary.id && row.selected === true,
    ),
  daemonCodingToolRows:
    daemonCodingToolEvents.length === WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length &&
    JSON.stringify(daemonCodingToolEvents.map((event) => event.workflow_node_id)) ===
      JSON.stringify(subflow.nodeIds),
  tuiRows:
    terminalTuiRows.length === WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length &&
    JSON.stringify(terminalTuiRows.map((row) => row.command)) ===
      JSON.stringify(expectedCommandOrder()),
  approvalDecisionEvidence:
    approvalDecisionRequests.length === 1 &&
    approvalDecisionEvents.length === 1 &&
    approvalDecisionRows.length === 1 &&
    runHistory.tuiControlStateProjection.approvalDecisionCount === 1 &&
    runHistory.runtimePolicyStack.stages.some(
      (stage) =>
        stage.kind === "approval_decision" && stage.status === "completed",
    ),
  graphNodeIdentityPreserved:
    runResult.finalState.completedNodeIds.length === subflow.nodeIds.length &&
    JSON.stringify(runResult.finalState.completedNodeIds) ===
      JSON.stringify(subflow.nodeIds) &&
    runHistory.runtimeEventProjection.nodes
      .filter((node) => node.componentKind === "coding_tool")
      .every((node) => subflow.nodeIds.includes(node.workflowNodeId)),
  artifactAndRetrievalEvidence:
    launch.context.artifactId === "artifact-terminal-loop-run-button-output" &&
    launch.context.resultToolCallId === testToolCallId &&
    runResult.finalState.values.terminalCodingLoop.rollbackRefs.includes(
      "snapshot-terminal-loop-run-button",
    ),
};

const proof = {
  schemaVersion: "workflow.terminal-coding-loop.run-button-proof.v1",
  scenario: "workflow_terminal_coding_loop_run_button_activation",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-button",
  workflowGraphId,
  runId: runResult.summary.id,
  threadId,
  insertedNodeIds: subflow.nodeIds,
  requestSummary: {
    controlRequestCount: controlRequests.length,
    approvalDecisionRequestCount: approvalDecisionRequests.length,
    daemonCodingToolEventCount: daemonCodingToolEvents.length,
    tuiCodingToolRowCount: terminalTuiRows.length,
    approvalDecisionRowCount: approvalDecisionRows.length,
  },
  checks,
  sourceRefs: [
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
    "packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.ts",
    "packages/agent-ide/src/runtime/workflow-run-history-model.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts",
    "scripts/lib/live-runtime-daemon-contract.test.mjs",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
