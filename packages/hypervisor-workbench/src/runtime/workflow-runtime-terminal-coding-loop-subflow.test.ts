import assert from "node:assert/strict";
import test from "node:test";

import { workflowRuntimeSubflowReactFlowElements } from "../WorkflowComposer/runtimeSubflowInsertion";
import type { WorkflowProject } from "../types/graph";
import { makeDefaultWorkflow } from "./workflow-defaults";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "./workflow-runtime-coding-tool-control-nodes";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION,
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "./workflow-runtime-terminal-coding-loop-subflow";

function workflowWithSubflow(): WorkflowProject {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-coding-loop-readiness",
    workflowGraphId: "workflow.terminal-coding-loop",
  });
  const workflow = makeDefaultWorkflow("Terminal coding loop template");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.terminal-coding-loop",
    },
    nodes: [...workflow.nodes, ...subflow.nodes],
    edges: [...workflow.edges, ...subflow.edges],
  };
}

test("creates a reusable terminal coding loop template", () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-coding-loop-proof",
    workflowGraphId: "workflow.terminal-coding-loop",
    origin: { x: 100, y: 120 },
  });

  assert.equal(
    subflow.schemaVersion,
    WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION,
  );
  assert.equal(subflow.workflowGraphId, "workflow.terminal-coding-loop");
  assert.equal(subflow.nodes.length, WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length);
  assert.equal(subflow.edges.length, subflow.nodes.length - 1);
  assert.deepEqual(
    subflow.nodes.map((node) => node.config?.logic.toolBinding?.toolRef),
    [
      "workspace.status",
      "git.diff",
      "file.inspect",
      "file.apply_patch",
      "file.apply_patch",
      "test.run",
      "lsp.diagnostics",
      "artifact.read",
      "tool.retrieve_result",
    ],
  );
  assert.deepEqual(
    subflow.nodes.map((node) => node.config?.logic.runtimeTerminalCodingLoopCommand),
    [
      "status",
      "diff",
      "inspect",
      "patch-dry-run",
      "patch",
      "test",
      "diagnostics",
      "artifact",
      "retrieve",
    ],
  );
  assert.deepEqual(
    subflow.edges.map((edge) => [
      edge.fromPort,
      edge.toPort,
      edge.connectionClass,
      edge.data?.createdBy,
    ]),
    Array.from({ length: 8 }, () => [
      "output",
      "input",
      "state",
      "runtime_terminal_coding_loop_template",
    ]),
  );
});

test("generated terminal coding loop nodes compile into daemon coding-tool requests", () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-coding-loop-executable",
    workflowGraphId: "workflow.terminal-coding-loop",
    maxTotalTokens: 3000,
    contextWarningRatio: 0.7,
    contextBlockRatio: 0.88,
  });
  const requests = subflow.nodes.map((node) =>
    createRuntimeCodingToolControlRequestFromWorkflowNode(
      node,
      { threadId: "thread-terminal-loop" },
      { workflowGraphId: subflow.workflowGraphId },
    ),
  );

  assert.deepEqual(
    requests.map((request) => request.toolId),
    [
      "workspace.status",
      "git.diff",
      "file.inspect",
      "file.apply_patch",
      "file.apply_patch",
      "test.run",
      "lsp.diagnostics",
      "artifact.read",
      "tool.retrieve_result",
    ],
  );
  assert(
    requests.every(
      (request) =>
        request.threadId === "thread-terminal-loop" &&
        request.body.source === "react_flow" &&
        request.body.toolPack.coding.pack === "coding" &&
        request.body.budgetMode === "block" &&
        request.body.thresholds.maxTotalTokens === 3000 &&
        request.body.thresholds.maxContextPressure === 0.88 &&
        request.body.thresholds.warnAtRatio === 0.7,
    ),
  );

  const dryRunRequest = requests[3]!;
  assert.equal(dryRunRequest.body.requiresApproval, false);
  assert.equal(dryRunRequest.body.arguments.dryRun, true);
  assert.equal(dryRunRequest.body.toolPack.coding.dryRun, true);

  const applyRequest = requests[4]!;
  assert.equal(applyRequest.body.requiresApproval, true);
  assert.equal(applyRequest.body.approvalMode, "human_required");
  assert.equal(applyRequest.body.nodeApprovalOverride, "require_approval");
  assert.equal(applyRequest.body.arguments.dryRun, false);
});

test("terminal coding loop template materializes to React Flow elements and validates", () => {
  const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
    idPrefix: "terminal-coding-loop-react-flow",
    workflowGraphId: "workflow.terminal-coding-loop",
    origin: { x: 120, y: 160 },
  });
  const elements = workflowRuntimeSubflowReactFlowElements(subflow);
  const workflow = workflowWithSubflow();
  const validation = validateWorkflowProject(workflow, []);
  const readiness = evaluateWorkflowActivationReadiness(
    workflow,
    [],
    validation,
  );

  assert.equal(elements.nodes.length, subflow.nodes.length);
  assert.equal(elements.edges.length, subflow.edges.length);
  assert(
    elements.nodes.every(
      (node, index) =>
        node.id === subflow.nodes[index]?.id &&
        node.type === "plugin_tool" &&
        node.position.x === subflow.nodes[index]?.x &&
        node.position.y === subflow.nodes[index]?.y,
    ),
  );
  assert(
    elements.edges.every(
      (edge, index) =>
        edge.source === subflow.edges[index]?.from &&
        edge.target === subflow.edges[index]?.to &&
        edge.sourceHandle === "output" &&
        edge.targetHandle === "input" &&
        edge.data?.connectionClass === "state",
    ),
  );
  assert.equal(validation.errors.length, 0);
  assert.equal(
    (readiness.executionReadinessIssues ?? []).some((issue) =>
      issue.code.includes("terminal_coding_loop"),
    ),
    false,
  );
});
