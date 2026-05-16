#!/usr/bin/env node
import React from "react";
import { writeFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";

import { WorkflowRunsPanel } from "../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx";
import { workflowRunHistoryModel } from "../../packages/agent-ide/src/runtime/workflow-run-history-model.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-run-capability-receipts-gui-probe.mjs <output-path>",
  );
}

const workflow = {
  version: "1",
  nodes: [
    boundModelNode(),
    boundToolNode(),
    boundConnectorNode(),
    blockedToolNode(),
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
      adjudicationRubric: "capability receipts",
    },
    meta: {
      name: "Capability receipt projection proof",
      description: "Capability receipt projection proof",
    },
  },
  metadata: {
    id: "workflow.capability-receipt-projection-proof",
    name: "Capability receipt projection proof",
    slug: "capability-receipt-projection-proof",
    workflowKind: "agent_workflow",
    executionMode: "live",
  },
};

const runs = [
  runSummary("run-a", "blocked", "Capability receipt projection"),
];
const selectedRun = runResult("run-a", "blocked", { answer: "blocked" });
const runtimeThreadEvents = [
  runtimeThreadEvent("model-receipt", 1, {
    workflowNodeId: "model",
    type: "model_route_decision",
    eventKind: "model.route_decision",
    receiptRefs: ["receipt:model-route"],
    policyDecisionRefs: ["policy:model-route"],
  }),
  runtimeThreadEvent("tool-receipt", 2, {
    workflowNodeId: "tool",
    type: "tool_route_decision",
    eventKind: "tool.route_decision",
    receiptRefs: ["receipt:tool"],
    policyDecisionRefs: ["policy:tool"],
  }),
  runtimeThreadEvent("connector-receipt", 3, {
    workflowNodeId: "connector",
    type: "connector_completed",
    eventKind: "connector.completed",
    receiptRefs: ["receipt:connector"],
    policyDecisionRefs: ["policy:connector"],
  }),
];

const model = workflowRunHistoryModel({
  workflow,
  runs,
  lastRunResult: selectedRun,
  compareRunResult: null,
  selectedRunId: "run-a",
  compareRunId: null,
  runEvents: [],
  runtimeThreadEvents,
  searchQuery: "",
  statusFilter: "all",
});

const inspectedNodes = [];
const markup = renderToStaticMarkup(
  React.createElement(WorkflowRunsPanel, {
    workflow,
    model,
    runSearchQuery: "",
    runStatusFilter: "all",
    runSourceFilter: "all",
    checkpoints: [],
    dogfoodRun: null,
    accessibleStatusLabel: (status) => String(status),
    onRunSearchQueryChange: () => {},
    onRunStatusFilterChange: () => {},
    onRunSourceFilterChange: () => {},
    onSelectRun: () => {},
    onCompareRun: () => {},
    onInspectNode: (nodeId) => inspectedNodes.push(nodeId),
  }),
);

const projection = model.capabilityReceiptProjection;
const rowsByNode = Object.fromEntries(
  projection.rows.map((row) => [row.nodeId, row]),
);
const htmlChecks = {
  sectionVisible: markup.includes('data-testid="workflow-run-capability-receipts"'),
  schemaProjected: markup.includes(
    'data-schema-version="workflow.run-capability-receipts.v1"',
  ),
  modelRowVisible: markup.includes(
    'data-testid="workflow-run-capability-receipt-model"',
  ),
  toolRowVisible: markup.includes(
    'data-testid="workflow-run-capability-receipt-tool"',
  ),
  connectorRowVisible: markup.includes(
    'data-testid="workflow-run-capability-receipt-connector"',
  ),
  blockedRowVisible: markup.includes(
    'data-testid="workflow-run-capability-receipt-blocked-tool"',
  ),
  canonicalRefsVisible:
    markup.includes("model-capability:route.local-first") &&
    markup.includes("tool-capability:file.apply_patch") &&
    markup.includes("connector-capability:agent.connector.catalog"),
  receiptRefsVisible:
    markup.includes("receipt:model-route") &&
    markup.includes("receipt:tool") &&
    markup.includes("receipt:connector"),
  grantPolicyReceiptAttrs:
    markup.includes('data-grant-status="ready"') &&
    markup.includes('data-policy-status="allowed"') &&
    markup.includes('data-receipt-required="true"'),
  failClosedAttrs:
    markup.includes('data-fail-closed="true"') &&
    markup.includes("missing_credential_readiness") &&
    markup.includes("missing_receipt_behavior"),
  inspectButtonsVisible:
    markup.includes(
      'data-testid="workflow-run-capability-receipt-inspect-model"',
    ) &&
    markup.includes(
      'data-testid="workflow-run-capability-receipt-inspect-blocked-tool"',
    ),
};

const projectionChecks = {
  schemaVersion:
    projection.schemaVersion === "workflow.run-capability-receipts.v1",
  aggregateBlocked: projection.status === "blocked",
  rowCount: projection.rows.length === 4,
  readyRows:
    projection.readyCount === 3 &&
    rowsByNode.model?.status === "ready" &&
    rowsByNode.tool?.status === "ready" &&
    rowsByNode.connector?.status === "ready",
  blockedRow:
    rowsByNode["blocked-tool"]?.status === "blocked" &&
    rowsByNode["blocked-tool"]?.failClosed === true,
  canonicalCapabilityRefs:
    projection.capabilityRefs.includes("model-capability:route.local-first") &&
    projection.capabilityRefs.includes("tool-capability:file.apply_patch") &&
    projection.capabilityRefs.includes(
      "connector-capability:agent.connector.catalog",
    ),
  runtimeEvidenceRefs:
    projection.receiptRefs.includes("receipt:model-route") &&
    projection.receiptRefs.includes("receipt:tool") &&
    projection.receiptRefs.includes("receipt:connector") &&
    projection.policyDecisionRefs.includes("policy:model-route") &&
    projection.policyDecisionRefs.includes("policy:tool") &&
    projection.policyDecisionRefs.includes("policy:connector"),
  failClosedBlockers:
    rowsByNode["blocked-tool"]?.blockerReasons.includes(
      "missing_credential_readiness",
    ) &&
    rowsByNode["blocked-tool"]?.blockerReasons.includes(
      "missing_grant_readiness",
    ) &&
    rowsByNode["blocked-tool"]?.blockerReasons.includes(
      "missing_policy_posture",
    ) &&
    rowsByNode["blocked-tool"]?.blockerReasons.includes(
      "missing_receipt_behavior",
    ),
};

const checks = {
  ...projectionChecks,
  ...htmlChecks,
};
const proof = {
  schemaVersion: "workflow.run-capability-receipts.gui-proof.v1",
  scenario: "workflow_run_capability_receipts_projection",
  method:
    "project model/tool/connector capability receipt readiness through workflowRunHistoryModel and render the primary Runs rail section",
  checks,
  projection: {
    schemaVersion: projection.schemaVersion,
    status: projection.status,
    capabilityRefs: projection.capabilityRefs,
    receiptRefs: projection.receiptRefs,
    policyDecisionRefs: projection.policyDecisionRefs,
    readyCount: projection.readyCount,
    blockedCount: projection.blockedCount,
    failClosedCount: projection.failClosedCount,
    receiptRequiredCount: projection.receiptRequiredCount,
    rows: projection.rows.map((row) => ({
      nodeId: row.nodeId,
      bindingKind: row.bindingKind,
      capabilityRef: row.capabilityRef,
      mode: row.mode,
      status: row.status,
      ready: row.ready,
      failClosed: row.failClosed,
      grantStatus: row.grantStatus,
      policyStatus: row.policyStatus,
      receiptRequired: row.receiptRequired,
      receiptTypes: row.receiptTypes,
      authorityScopes: row.authorityScopes,
      receiptRefs: row.receiptRefs,
      policyDecisionRefs: row.policyDecisionRefs,
      blockerReasons: row.blockerReasons,
    })),
  },
  html: {
    length: markup.length,
    sectionIndex: markup.indexOf("workflow-run-capability-receipts"),
    inspectedNodes,
  },
  passed: Object.values(checks).every(Boolean),
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
if (!proof.passed) {
  console.error(JSON.stringify(proof, null, 2));
  process.exit(1);
}

function boundModelNode() {
  return {
    id: "model",
    type: "model_call",
    name: "Model",
    x: 0,
    y: 0,
    config: {
      kind: "model_call",
      logic: {
        modelBinding: {
          modelRef: "reasoning",
          modelId: "qwen-local",
          modelCapabilityRef: "model-capability:route.local-first",
          routeId: "route.local-first",
          mockBinding: false,
          credentialReady: true,
          credentialReadiness: { status: "ready" },
          grantReadiness: { status: "ready" },
          policyPosture: { status: "allowed" },
          receiptBehavior: {
            receiptRequired: true,
            requiredReceiptTypes: [
              "model_route_selection",
              "model_invocation",
            ],
          },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          authorityScopes: ["route.use:route.local-first", "model.chat:*"],
          authorityScopeRequirements: [
            "route.use:route.local-first",
            "model.chat:*",
          ],
          capabilityScope: ["chat"],
          sideEffectClass: "none",
          requiresApproval: false,
        },
      },
      law: {},
    },
  };
}

function boundToolNode() {
  return {
    id: "tool",
    type: "plugin_tool",
    name: "Tool",
    x: 260,
    y: 0,
    config: {
      kind: "plugin_tool",
      logic: {
        toolBinding: {
          toolRef: "file.apply_patch",
          toolCapabilityRef: "tool-capability:file.apply_patch",
          bindingKind: "coding_tool_pack",
          mockBinding: false,
          credentialReady: true,
          credentialReadiness: { status: "ready" },
          grantReadiness: { status: "ready" },
          policyPosture: { status: "allowed" },
          receiptBehavior: {
            receiptRequired: true,
            requiredReceiptTypes: ["tool_invocation", "tool_verification"],
          },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          authorityScopes: ["scope:workspace.write"],
          authorityScopeRequirements: ["scope:workspace.write"],
          capabilityScope: ["file.apply_patch"],
          sideEffectClass: "write",
          requiresApproval: true,
        },
      },
      law: {},
    },
  };
}

function boundConnectorNode() {
  return {
    id: "connector",
    type: "adapter",
    name: "Connector",
    x: 520,
    y: 0,
    config: {
      kind: "adapter",
      logic: {
        connectorBinding: {
          connectorRef: "agent.connector.catalog",
          connectorCapabilityRef: "connector-capability:agent.connector.catalog",
          mockBinding: false,
          credentialReady: true,
          credentialReadiness: { status: "ready" },
          grantReadiness: { status: "ready" },
          policyPosture: { status: "allowed" },
          receiptBehavior: {
            receiptRequired: true,
            requiredReceiptTypes: [
              "connector_invocation",
              "connector_verification",
            ],
          },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          authorityScopes: ["connector.catalog.read"],
          authorityScopeRequirements: ["connector.catalog.read"],
          capabilityScope: ["connector.catalog.read"],
          sideEffectClass: "read",
          requiresApproval: false,
          operation: "describe",
        },
      },
      law: {},
    },
  };
}

function blockedToolNode() {
  return {
    id: "blocked-tool",
    type: "plugin_tool",
    name: "Blocked tool",
    x: 780,
    y: 0,
    config: {
      kind: "plugin_tool",
      logic: {
        toolBinding: {
          toolRef: "external.crm.write",
          toolCapabilityRef: "tool-capability:external.crm.write",
          bindingKind: "plugin_tool",
          mockBinding: false,
          credentialReady: false,
          credentialReadiness: { status: "unknown" },
          grantReadiness: { status: "unknown" },
          policyPosture: { status: "unknown" },
          workflowAvailability: { available: false },
          agentAvailability: { available: false },
          receiptBehavior: {
            receiptRequired: false,
            requiredReceiptTypes: [],
          },
          authorityScopes: [],
          authorityScopeRequirements: [],
          capabilityScope: ["write"],
          sideEffectClass: "external_write",
          requiresApproval: true,
        },
      },
      law: {},
    },
  };
}

function runSummary(id, status, summary, startedAtMs = 1_000) {
  return {
    id,
    status,
    startedAtMs,
    finishedAtMs: startedAtMs + 100,
    nodeCount: 4,
    checkpointCount: 1,
    summary,
  };
}

function runResult(id, status, output) {
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
      completedNodeIds: ["model", "tool", "connector"],
      blockedNodeIds: ["blocked-tool"],
      interruptedNodeIds: [],
      activeNodeIds: [],
      branchDecisions: {},
      pendingWrites: [],
    },
    nodeRuns: [
      {
        nodeId: "model",
        nodeType: "model_call",
        status: "success",
        startedAtMs: 1_000,
        finishedAtMs: 1_100,
        attempt: 1,
        input: { prompt: "hello" },
        output: {
          ...output,
          receiptRefs: ["receipt:model-route"],
          policyDecisionRefs: ["policy:model-route"],
        },
      },
      {
        nodeId: "tool",
        nodeType: "plugin_tool",
        status: "success",
        startedAtMs: 1_110,
        finishedAtMs: 1_120,
        attempt: 1,
        input: { patch: "noop" },
        output: {
          receiptRefs: ["receipt:tool"],
          policyDecisionRefs: ["policy:tool"],
        },
      },
      {
        nodeId: "connector",
        nodeType: "adapter",
        status: "success",
        startedAtMs: 1_130,
        finishedAtMs: 1_140,
        attempt: 1,
        input: { operation: "describe" },
        output: {
          receiptRefs: ["receipt:connector"],
          policyDecisionRefs: ["policy:connector"],
        },
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
    events: [
      {
        id: `${id}-event`,
        runId: id,
        threadId: "thread",
        sequence: 1,
        kind: "node_blocked",
        createdAtMs: 1_100,
        nodeId: "blocked-tool",
        status: "blocked",
        message: "blocked",
      },
    ],
    verificationEvidence: [],
    completionRequirements: [],
  };
}

function runtimeThreadEvent(id, seq, overrides = {}) {
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
    workflowGraphId: "workflow.capability-receipt-projection-proof",
    payloadSchemaVersion: "ioi.agent-sdk.thread-event.v1",
    receiptRefs: [],
    artifactRefs: [],
    policyDecisionRefs: [],
    rollbackRefs: [],
    payload: {},
    ...overrides,
  };
}
