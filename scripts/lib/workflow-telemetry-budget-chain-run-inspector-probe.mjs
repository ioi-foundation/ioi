#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { makeDefaultWorkflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-defaults.ts";
import {
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "../../packages/hypervisor-workbench/src/runtime/workflow-validation.ts";
import { createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow } from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts";
import {
  materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry,
  workflowRuntimeTelemetryBudgetChainIdsFromWorkflow,
} from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts";
import { workflowRuntimeTelemetrySourceBindingIssue } from "../../packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-source-binding.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-telemetry-budget-chain-run-inspector-probe.mjs <output-path>",
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
    threadIds: ["thread-run-inspector-proof"],
    turnIds: ["turn-run-inspector-proof"],
    workflowGraphIds: ["workflow.telemetry-budget-chain-run-inspector"],
    workflowNodeIds: ["runtime.usage-meter", "runtime.context-budget"],
    eventIds: ["event-run-inspector-usage", "event-run-inspector-context"],
    latestSeq: 7,
    latestCursor: "events_thread-run-inspector-proof:7",
    latestEventId: "event-run-inspector-context",
    runtimeEventCount: 7,
    usageEventCount: 1,
    contextPressureEventCount: 1,
    contextPressureAlertCount: 1,
    tuiRowCount: 1,
    usageRowCount: 1,
    costRowCount: 1,
    contextRowCount: 1,
    subagentRowCount: 0,
    codingToolBudgetRowCount: 0,
    inputTokens: 2000,
    outputTokens: 1600,
    totalTokens: 3600,
    costEstimateUsd: 0.082,
    contextPressure: 0.93,
    contextPressureStatus: "blocked",
    runCount: 1,
    subagentCount: 0,
    receiptRefs: ["receipt-run-inspector-proof"],
    policyDecisionRefs: ["policy-run-inspector-proof"],
  };
}

function workflowBase(name = "Telemetry budget chain run inspector proof") {
  const workflow = makeDefaultWorkflow(name);
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      id: "workflow.telemetry-budget-chain-run-inspector",
    },
  };
}

function telemetryIssues(workflow) {
  return (evaluateWorkflowActivationReadiness(
    workflow,
    [],
    validateWorkflowProject(workflow, []),
  ).executionReadinessIssues ?? []).filter((issue) =>
    workflowRuntimeTelemetrySourceBindingIssue(issue),
  );
}

function workflowWithExistingChain() {
  const base = workflowBase("Existing telemetry budget chain");
  const subflow = createWorkflowRuntimeTelemetryBudgetChainTemplateSubflow({
    idPrefix: "existing-run-inspector-chain",
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
  "packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
);

const summary = telemetrySummary();
const materialized = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
  workflowBase(),
  summary,
  {
    idPrefix: "run-inspector-proof-chain",
    origin: { x: 120, y: 160 },
  },
);
const existing = workflowWithExistingChain();
const hydrated = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
  existing.workflow,
  summary,
);
const blocked = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
  workflowBase("Missing telemetry proof"),
  { ...summary, sourceKinds: [] },
);
const brokenNodes = materialized.workflow.nodes.map((node) => {
  if (node.id !== "run-inspector-proof-chain-context-budget" || !node.config) {
    return node;
  }
  return {
    ...node,
    config: {
      ...node.config,
      logic: {
        ...node.config.logic,
        runtimeContextBudget: undefined,
        runtimeTelemetrySummary: undefined,
        inputMapping: {
          threadId: "runtime.threadId",
        },
      },
    },
  };
});
const brokenWorkflow = { ...materialized.workflow, nodes: brokenNodes };
const materializedChainIds = workflowRuntimeTelemetryBudgetChainIdsFromWorkflow(
  materialized.workflow,
);

const checks = {
  runInspectorButtonRendered:
    /data-testid="workflow-run-telemetry-budget-chain-materialize"/.test(
      runsPanel,
    ),
  runInspectorButtonCallsHandler:
    /onMaterializeRuntimeTelemetryBudgetChain\?\./.test(runsPanel),
  railPanelPropWired: /onMaterializeRuntimeTelemetryBudgetChain/.test(railPanel),
  viewPassesHandler:
    /handleMaterializeRuntimeTelemetryBudgetChain\(summary\)/.test(view),
  controllerUsesMaterializationHelper:
    /handleMaterializeRuntimeTelemetryBudgetChain/.test(controller) &&
    /materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry/.test(
      controller,
    ),
  materializationHelperDetectsExistingChain:
    /workflowRuntimeTelemetryBudgetChainIdsFromWorkflow/.test(
      materialization,
    ) && /mode: "hydrated"/.test(materialization),
  materializesFourNodes:
    materialized.status === "bound" &&
    materialized.mode === "materialized" &&
    materialized.insertedNodeIds.length === 4,
  materializesThreeEdges:
    materialized.status === "bound" && materialized.insertedEdgeIds.length === 3,
  materializedChainDetected:
    materializedChainIds?.usageMeterNodeId ===
      "run-inspector-proof-chain-usage-meter" &&
    materializedChainIds?.budgetGateNodeId ===
      "run-inspector-proof-chain-coding-budget-gate",
  materializedReadinessPasses: telemetryIssues(materialized.workflow).length === 0,
  hydratesExistingChain:
    hydrated.status === "bound" &&
    hydrated.mode === "hydrated" &&
    hydrated.insertedNodeIds.length === 0 &&
    hydrated.boundNodeIds.length === 4 &&
    hydrated.workflow.nodes.length === existing.workflow.nodes.length,
  blocksMissingTelemetry:
    blocked.status === "blocked" &&
    blocked.blockers.includes("runtime_telemetry_source_evidence_missing"),
  readinessFailsWhenUpstreamBindingRemoved: telemetryIssues(brokenWorkflow).some(
    (issue) =>
      issue.nodeId === "run-inspector-proof-chain-context-budget" &&
      issue.code === "missing_runtime_telemetry_source_usage_binding",
  ),
};

const proof = {
  schemaVersion:
    "workflow.telemetry-budget-chain.run-inspector-proof.v1",
  scenario: "workflow_telemetry_budget_chain_run_inspector_materialize",
  passed: Object.values(checks).every(Boolean),
  clickedControlTestId: "workflow-run-telemetry-budget-chain-materialize",
  materialized: {
    mode: materialized.mode,
    insertedNodeIds: materialized.insertedNodeIds,
    insertedEdgeIds: materialized.insertedEdgeIds,
    boundNodeIds: materialized.boundNodeIds,
    evidenceLatestEventId: materialized.evidenceBinding?.latestEventId ?? null,
  },
  hydrated: {
    mode: hydrated.mode,
    insertedNodeIds: hydrated.insertedNodeIds,
    boundNodeIds: hydrated.boundNodeIds,
  },
  validation: {
    materializedTelemetryIssueCount: telemetryIssues(materialized.workflow).length,
    brokenTelemetryIssues: telemetryIssues(brokenWorkflow).map((issue) => ({
      nodeId: issue.nodeId,
      code: issue.code,
      fieldPath: issue.fieldPath,
    })),
  },
  checks,
  sourceRefs: [
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowRailPanel/core.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
    "packages/hypervisor-workbench/src/WorkflowComposer/controller.tsx",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.test.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
