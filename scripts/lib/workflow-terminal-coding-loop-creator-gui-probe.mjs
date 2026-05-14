#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { workflowRuntimeSubflowReactFlowElements } from "../../packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts";
import { makeDefaultWorkflow } from "../../packages/agent-ide/src/runtime/workflow-defaults.ts";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "../../packages/agent-ide/src/runtime/workflow-validation.ts";
import { createRuntimeCodingToolControlRequestFromWorkflowNode } from "../../packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
} from "../../packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-terminal-coding-loop-creator-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function workflowWithSubflow(subflow) {
  const workflow = makeDefaultWorkflow("Terminal coding loop GUI proof");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: subflow.workflowGraphId ?? "workflow.terminal-coding-loop",
    },
    nodes: subflow.nodes,
    edges: subflow.edges,
  };
}

function requestCompilationChecks(subflow) {
  const requests = subflow.nodes.map((node) =>
    createRuntimeCodingToolControlRequestFromWorkflowNode(
      node,
      { threadId: "thread-terminal-loop-proof" },
      { workflowGraphId: subflow.workflowGraphId },
    ),
  );
  const toolIds = requests.map((request) => request.toolId);
  const dryRun = requests[3];
  const apply = requests[4];
  return {
    allRequestsCompile: requests.length === subflow.nodes.length,
    daemonThreadEndpoints: requests.every((request) =>
      request.endpoint.startsWith(
        "/v1/threads/thread-terminal-loop-proof/tools/",
      ),
    ),
    expectedToolOrder:
      JSON.stringify(toolIds) ===
      JSON.stringify([
        "workspace.status",
        "git.diff",
        "file.inspect",
        "file.apply_patch",
        "file.apply_patch",
        "test.run",
        "lsp.diagnostics",
        "artifact.read",
        "tool.retrieve_result",
      ]),
    dryRunDoesNotRequireApproval:
      dryRun?.body.requiresApproval === false &&
      dryRun?.body.arguments.dryRun === true,
    applyRequiresApproval:
      apply?.body.requiresApproval === true &&
      apply?.body.approvalMode === "human_required" &&
      apply?.body.nodeApprovalOverride === "require_approval",
    budgetsGovernEveryNode: requests.every(
      (request) =>
        request.body.budgetMode === "block" &&
        request.body.toolPack.coding.budgetUsageField ===
          "runtimeTelemetrySummary",
    ),
  };
}

const controller = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
const view = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
const insertion = read("packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts");

const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
  idPrefix: "terminal-coding-loop-gui-click",
  workflowGraphId: "workflow.terminal-coding-loop",
  origin: { x: 100, y: 140 },
});
const elements = workflowRuntimeSubflowReactFlowElements(subflow);
const workflow = workflowWithSubflow(subflow);
const validation = validateWorkflowProject(workflow, []);
const readiness = evaluateWorkflowActivationReadiness(
  workflow,
  [],
  validation,
);
const requestChecks = requestCompilationChecks(subflow);

const checks = {
  workflowCreatorButtonRendered:
    /data-testid="workflow-add-runtime-terminal-coding-loop-template"/.test(
      view,
    ),
  workflowCreatorButtonClickWired:
    /onClick=\{handleInsertRuntimeTerminalCodingLoopTemplate\}/.test(view),
  controllerCreatesTemplate:
    /createWorkflowRuntimeTerminalCodingLoopTemplateSubflow/.test(controller) &&
    /handleInsertRuntimeTerminalCodingLoopTemplate/.test(controller),
  controllerUsesSharedReactFlowInsertion:
    /workflowRuntimeSubflowReactFlowElements/.test(controller),
  insertionMapperCoversNodesAndEdges:
    /sourceHandle: edge\.fromPort/.test(insertion) &&
    /targetHandle: edge\.toPort/.test(insertion) &&
    /connectionClass: edge\.connectionClass \?\? edge\.type/.test(insertion),
  clickedTemplateNodeCount:
    subflow.nodes.length === WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.length,
  clickedTemplateEdgeCount: subflow.edges.length === subflow.nodes.length - 1,
  clickedTemplateCommands:
    JSON.stringify(
      subflow.nodes.map(
        (node) => node.config?.logic.runtimeTerminalCodingLoopCommand,
      ),
    ) ===
    JSON.stringify([
      "status",
      "diff",
      "inspect",
      "patch-dry-run",
      "patch",
      "test",
      "diagnostics",
      "artifact",
      "retrieve",
    ]),
  reactFlowNodesMaterialized:
    elements.nodes.length === subflow.nodes.length &&
    elements.nodes.every((node, index) =>
      node.id === subflow.nodes[index]?.id &&
      node.type === "plugin_tool" &&
      node.position.x === subflow.nodes[index]?.x &&
      node.position.y === subflow.nodes[index]?.y,
    ),
  reactFlowEdgesMaterialized:
    elements.edges.length === subflow.edges.length &&
    elements.edges.every((edge, index) =>
      edge.source === subflow.edges[index]?.from &&
      edge.target === subflow.edges[index]?.to &&
      edge.sourceHandle === "output" &&
      edge.targetHandle === "input" &&
      edge.data?.connectionClass === "state",
    ),
  daemonRequestsCompile: Object.values(requestChecks).every(Boolean),
  workflowValidatesWithoutTemplateErrors:
    validation.errors.length === 0 &&
    !(readiness.executionReadinessIssues ?? []).some((issue) =>
      issue.code.includes("terminal_coding_loop"),
    ),
};

const proof = {
  schemaVersion: "workflow.terminal-coding-loop.creator-gui-proof.v1",
  scenario: "workflow_terminal_coding_loop_creator_click",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-add-runtime-terminal-coding-loop-template",
  insertedNodeIds: subflow.nodes.map((node) => node.id),
  insertedEdgeIds: subflow.edges.map((edge) => edge.id),
  requestChecks,
  checks,
  sourceRefs: [
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
    "packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.test.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
