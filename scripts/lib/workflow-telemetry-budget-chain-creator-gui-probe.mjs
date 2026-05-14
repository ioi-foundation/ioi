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
import { createRuntimeCompactionPolicyControlRequestFromWorkflowNode } from "../../packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.ts";
import { createRuntimeContextBudgetControlRequestFromWorkflowNode } from "../../packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts";
import {
  createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow,
} from "../../packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts";
import {
  bindWorkflowRuntimeTelemetrySourceToWorkflow,
  workflowRuntimeTelemetrySourceBindingIssue,
} from "../../packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts";
import { createRuntimeUsageMeterControlRequestFromWorkflowNode } from "../../packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-telemetry-budget-chain-creator-gui-probe.mjs <output-path>",
  );
}

const repoRoot = resolve(new URL("../..", import.meta.url).pathname);

function read(relativePath) {
  return readFileSync(resolve(repoRoot, relativePath), "utf8");
}

function telemetrySummary() {
  return {
    schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
    status: "blocked",
    sourceKinds: ["runtime_usage_events", "tui_context_rows"],
    threadIds: ["thread-template"],
    turnIds: ["turn-template"],
    workflowGraphIds: ["workflow.telemetry-budget-chain"],
    workflowNodeIds: ["runtime.usage-meter", "runtime.context-budget"],
    eventIds: ["event-usage-template", "event-context-template"],
    latestSeq: 2,
    latestCursor: "events_thread:2",
    latestEventId: "event-context-template",
    runtimeEventCount: 2,
    usageEventCount: 1,
    contextPressureEventCount: 1,
    contextPressureAlertCount: 1,
    tuiRowCount: 1,
    usageRowCount: 1,
    costRowCount: 1,
    contextRowCount: 1,
    subagentRowCount: 0,
    codingToolBudgetRowCount: 0,
    inputTokens: 1600,
    outputTokens: 900,
    totalTokens: 2500,
    costEstimateUsd: 0.0125,
    contextPressure: 0.91,
    contextPressureStatus: "blocked",
    runCount: 1,
    subagentCount: 0,
    receiptRefs: ["receipt-usage-template"],
    policyDecisionRefs: ["policy-context-template"],
  };
}

function workflowWithSubflow(subflow, nodes = subflow.nodes) {
  const workflow = makeDefaultWorkflow("Telemetry budget chain GUI proof");
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: subflow.workflowGraphId ?? "workflow.telemetry-budget-chain",
    },
    nodes,
    edges: subflow.edges,
  };
}

function telemetryReadinessIssues(readiness) {
  return (readiness.executionReadinessIssues ?? []).filter((issue) =>
    workflowRuntimeTelemetrySourceBindingIssue(issue),
  );
}

function nodeById(subflow, nodeId) {
  const node = subflow.nodes.find((candidate) => candidate.id === nodeId);
  if (!node) throw new Error(`missing generated node: ${nodeId}`);
  return node;
}

function requestCompilationChecks(subflow) {
  const summary = telemetrySummary();
  const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
    nodeById(subflow, subflow.usageMeterNodeId),
    { threadId: "thread-template" },
    { workflowGraphId: subflow.workflowGraphId },
  );
  const contextRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
    nodeById(subflow, subflow.contextBudgetNodeId),
    {
      threadId: "thread-template",
      runtimeUsageMeter: {
        total_tokens: summary.totalTokens,
        estimated_cost_usd: summary.costEstimateUsd,
        context_pressure: summary.contextPressure,
      },
    },
    { workflowGraphId: subflow.workflowGraphId },
  );
  const compactionRequest =
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      nodeById(subflow, subflow.compactionPolicyNodeId),
      {
        threadId: "thread-template",
        turnId: "turn-template",
        runtimeContextBudget: {
          status: "blocked",
          receiptRefs: summary.receiptRefs,
          policyDecisionRefs: summary.policyDecisionRefs,
        },
      },
      { workflowGraphId: subflow.workflowGraphId },
    );
  const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
    nodeById(subflow, subflow.budgetGateNodeId),
    {
      threadId: "thread-template",
      runtimeTelemetrySummary: summary,
    },
    { workflowGraphId: subflow.workflowGraphId },
  );

  return {
    usageRequest: usageRequest.threadId === "thread-template" &&
      usageRequest.metadata.workflowNodeId === subflow.usageMeterNodeId,
    contextRequest: contextRequest.body.workflowNodeId ===
      subflow.contextBudgetNodeId &&
      contextRequest.body.mode === "block",
    compactionRequest: compactionRequest.body.workflowNodeId ===
      subflow.compactionPolicyNodeId &&
      compactionRequest.body.contextBudgetStatus === "blocked" &&
      compactionRequest.body.policy.blockedAction === "compact",
    codingRequest: codingRequest.body.workflowNodeId ===
      subflow.budgetGateNodeId &&
      codingRequest.body.budgetMode === "block" &&
      codingRequest.body.toolPack.coding.budgetUsageField ===
        "runtimeTelemetrySummary" &&
      codingRequest.body.budgetUsageTelemetry?.total_tokens === 2500,
  };
}

const controller = read("packages/agent-ide/src/WorkflowComposer/controller.tsx");
const view = read("packages/agent-ide/src/WorkflowComposer/view.tsx");
const insertion = read("packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts");

const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
  idPrefix: "telemetry-budget-chain-gui-click",
  workflowGraphId: "workflow.telemetry-budget-chain",
  origin: { x: 100, y: 140 },
});
const elements = workflowRuntimeSubflowReactFlowElements(subflow);
const workflow = workflowWithSubflow(subflow);
const readiness = evaluateWorkflowActivationReadiness(
  workflow,
  [],
  validateWorkflowProject(workflow, []),
);
const missingUsageNodes = subflow.nodes.map((node) => {
  if (node.id !== subflow.contextBudgetNodeId || !node.config) return node;
  return {
    ...node,
    config: {
      ...node.config,
      logic: {
        ...node.config.logic,
        inputMapping: {
          threadId: "runtime.threadId",
        },
      },
    },
  };
});
const missingUsageWorkflow = workflowWithSubflow(subflow, missingUsageNodes);
const missingUsageReadiness = evaluateWorkflowActivationReadiness(
  missingUsageWorkflow,
  [],
  validateWorkflowProject(missingUsageWorkflow, []),
);
const bindingResult = bindWorkflowRuntimeTelemetrySourceToWorkflow(
  workflow,
  telemetrySummary(),
);
const requestChecks = requestCompilationChecks(subflow);

const expectedNodeTypes = [
  "runtime_usage_meter",
  "runtime_context_budget",
  "runtime_compaction_policy",
  "plugin_tool",
];
const expectedEdgeTriples = [
  [
    subflow.usageMeterNodeId,
    subflow.contextBudgetNodeId,
    "runtimeUsageMeter",
    "runtimeUsageMeter",
    "data",
  ],
  [
    subflow.contextBudgetNodeId,
    subflow.compactionPolicyNodeId,
    "runtimeContextBudget",
    "runtimeContextBudget",
    "data",
  ],
  [
    subflow.compactionPolicyNodeId,
    subflow.budgetGateNodeId,
    "runtimeCompactionPolicy",
    "runtimeTelemetrySummary",
    "state",
  ],
];

const checks = {
  workflowCreatorButtonRendered:
    /data-testid="workflow-add-runtime-telemetry-budget-chain-template"/.test(
      view,
    ),
  workflowCreatorButtonClickWired:
    /onClick=\{handleInsertRuntimeTelemetryBudgetChainTemplate\}/.test(view),
  controllerCreatesTemplate:
    /createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow/.test(
      controller,
    ) &&
    /handleInsertRuntimeTelemetryBudgetChainTemplate/.test(controller),
  controllerUsesSharedReactFlowInsertion:
    /workflowRuntimeSubflowReactFlowElements/.test(controller),
  insertionMapperCoversNodesAndEdges:
    /sourceHandle: edge\.fromPort/.test(insertion) &&
    /targetHandle: edge\.toPort/.test(insertion) &&
    /connectionClass: edge\.connectionClass \?\? edge\.type/.test(insertion),
  clickedTemplateNodeCount: subflow.nodes.length === 4,
  clickedTemplateEdgeCount: subflow.edges.length === 3,
  clickedTemplateNodeTypes:
    JSON.stringify(subflow.nodes.map((node) => node.type)) ===
    JSON.stringify(expectedNodeTypes),
  clickedTemplateEdges:
    JSON.stringify(
      subflow.edges.map((edge) => [
        edge.from,
        edge.to,
        edge.fromPort,
        edge.toPort,
        edge.connectionClass,
      ]),
    ) === JSON.stringify(expectedEdgeTriples),
  reactFlowNodesMaterialized:
    elements.nodes.length === 4 &&
    elements.nodes.every((node, index) =>
      node.id === subflow.nodes[index]?.id &&
      node.type === subflow.nodes[index]?.type &&
      node.position.x === subflow.nodes[index]?.x &&
      node.position.y === subflow.nodes[index]?.y,
    ),
  reactFlowEdgesMaterialized:
    elements.edges.length === 3 &&
    elements.edges.every((edge, index) =>
      edge.source === subflow.edges[index]?.from &&
      edge.target === subflow.edges[index]?.to &&
      edge.sourceHandle === subflow.edges[index]?.fromPort &&
      edge.targetHandle === subflow.edges[index]?.toPort &&
      edge.data?.connectionClass === subflow.edges[index]?.connectionClass,
    ),
  daemonRequestsCompile: Object.values(requestChecks).every(Boolean),
  readinessPassesWithLiveMappings:
    telemetryReadinessIssues(readiness).length === 0,
  readinessFailsWhenUpstreamBindingRemoved:
    telemetryReadinessIssues(missingUsageReadiness).some(
      (issue) =>
        issue.nodeId === subflow.contextBudgetNodeId &&
        issue.code === "missing_runtime_telemetry_source_usage_binding",
    ),
  telemetrySourceQuickBindingCompatible:
    bindingResult.status === "bound" &&
    JSON.stringify(bindingResult.boundNodeIds) ===
      JSON.stringify([
        subflow.usageMeterNodeId,
        subflow.contextBudgetNodeId,
        subflow.compactionPolicyNodeId,
        subflow.budgetGateNodeId,
      ]),
};

const proof = {
  schemaVersion: "workflow.telemetry-budget-chain.creator-gui-proof.v1",
  scenario: "workflow_telemetry_budget_chain_creator_click",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-add-runtime-telemetry-budget-chain-template",
  insertedNodeIds: subflow.nodes.map((node) => node.id),
  insertedEdgeIds: subflow.edges.map((edge) => edge.id),
  requestChecks,
  checks,
  validation: {
    readinessTelemetryIssueCount: telemetryReadinessIssues(readiness).length,
    missingUsageTelemetryIssues: telemetryReadinessIssues(
      missingUsageReadiness,
    ).map((issue) => ({
      nodeId: issue.nodeId,
      code: issue.code,
      fieldPath: issue.fieldPath,
    })),
  },
  sourceRefs: [
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
    "packages/agent-ide/src/WorkflowComposer/runtimeSubflowInsertion.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.test.ts",
    "packages/agent-ide/src/runtime/workflow-validation.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
