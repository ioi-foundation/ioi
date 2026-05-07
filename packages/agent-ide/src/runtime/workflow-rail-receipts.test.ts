import assert from "node:assert/strict";
import {
  resolveWorkflowHarnessReceiptInspection,
  workflowHarnessReceiptKind,
  workflowUniqueReceiptRefs,
} from "./workflow-rail-model";
import type {
  WorkflowHarnessGroupView,
  WorkflowProject,
  WorkflowRunResult,
} from "../types/graph";

const nodeAttempt = {
  attemptId: "attempt-node",
  harnessWorkflowId: "default-agent-harness",
  harnessActivationId: "activation-1",
  harnessHash: "hash-1",
  workflowNodeId: "node-planner",
  componentId: "ioi.agent-harness.planner.v1",
  componentKind: "planner",
  executionMode: "live",
  readiness: "live_ready",
  attemptIndex: 1,
  status: "succeeded",
  inputHash: "input-node",
  outputHash: "output-node",
  policyDecision: "allow_node_attempt",
  startedAtMs: 1778190000000,
  durationMs: 12,
  receiptIds: ["receipt-node"],
  evidenceRefs: ["evidence-node"],
  replay: {
    deterministicEnvelope: true,
    capturesInput: true,
    capturesOutput: true,
    capturesPolicyDecision: true,
    fixtureRef: "fixture-node",
    determinism: "deterministic",
    redactionPolicy: "runtime_redacted",
  },
};

const workflow = {
  nodes: [
    {
      id: "node-planner",
      type: "task",
      name: "Planner",
      x: 0,
      y: 0,
    },
  ],
  edges: [],
  global_config: {},
  metadata: {
    harness: {
      activationRecord: {
        rollbackRestoreCanary: {
          schemaVersion: "workflow.harness.rollback-restore-canary.v1",
          canaryId: "canary-restore",
          status: "passed",
          revisionSource: "git",
          restoreStrategy: "git_show_file_restore",
          workflowPath: "workflows/default.json",
          expectedWorkflowContentHash: "expected-canary",
          actualWorkflowContentHash: "actual-canary",
          hashVerified: true,
          receiptBindingRef: "workflow_restore_canary:receipt-canary",
          blockers: [],
          evidenceRefs: ["workflow_restore_canary:receipt-canary", "evidence-canary"],
          createdAtMs: 1778190000001,
        },
      },
      activationAudit: [
        {
          schemaVersion: "workflow.harness.activation-audit.v1",
          eventId: "audit-1",
          eventType: "activation_minted",
          status: "applied",
          workflowId: "workflow-1",
          candidateId: "candidate-1",
          nextActivationId: "activation-2",
          blockers: [],
          evidenceRefs: ["evidence-audit"],
          receiptRefs: ["receipt-audit"],
          summary: "Activation minted",
          createdAtMs: 1778190000002,
        },
      ],
      activationRollbackProof: {
        schemaVersion: "workflow.harness.activation-rollback-proof.v1",
        drillId: "drill-1",
        workflowId: "workflow-1",
        activationId: "activation-1",
        rollbackTarget: "legacy_runtime",
        rollbackAvailable: true,
        rollbackExecuted: true,
        drillStatus: "passed",
        policyDecision: "allow_rollback_drill",
        blockers: [],
        evidenceRefs: ["evidence-drill"],
        receiptRefs: ["receipt-drill"],
        createdAtMs: 1778190000003,
      },
      activationRollbackExecution: {
        schemaVersion: "workflow.harness.activation-rollback-execution.v1",
        executionId: "rollback-1",
        workflowId: "workflow-1",
        activationId: "activation-1",
        rollbackTarget: "legacy_runtime",
        rollbackAvailable: true,
        rollbackExecuted: true,
        restoreStrategy: "git_show_file_restore",
        workflowPath: "workflows/default.json",
        expectedWorkflowContentHash: "expected-rollback",
        actualWorkflowContentHash: "actual-rollback",
        hashVerified: true,
        executionStatus: "applied",
        policyDecision: "allow_rollback_execution",
        blockers: [],
        evidenceRefs: ["evidence-rollback"],
        receiptRefs: ["receipt-rollback"],
        restoreReceiptBindingRef: "workflow_restore_canary:receipt-rollback-binding",
        createdAtMs: 1778190000004,
      },
      defaultRuntimeDispatchProof: {
        schemaVersion: "workflow.harness.default-runtime-dispatch.v1",
        dispatchId: "dispatch-1",
        workflowId: "default-agent-harness",
        executionMode: "live",
        cognitionExecutionReceiptIds: ["receipt-dispatch"],
        cognitionExecutionAttemptIds: ["attempt-dispatch"],
        cognitionExecutionReplayFixtureRefs: ["fixture-dispatch"],
        cognitionExecutionProof: {
          policyDecision: "accept_dispatch",
        },
        modelExecutionReceiptIds: [],
        modelExecutionAttemptIds: [],
        modelExecutionReplayFixtureRefs: [],
        readOnlyCapabilityRoutingReceiptIds: [],
        readOnlyCapabilityRoutingAttemptIds: [],
        readOnlyCapabilityRoutingReplayFixtureRefs: [],
        authorityToolingGateLiveReceiptIds: [],
        authorityToolingGateLiveAttemptIds: [],
        authorityToolingGateLiveReplayFixtureRefs: [],
        receiptIds: ["receipt-dispatch", "evidence-dispatch"],
        promptAssemblyPromptHash: "prompt-hash",
        modelExecutionOutputHash: "output-hash",
      },
    },
  },
} as unknown as WorkflowProject;

const lastRunResult = {
  summary: { id: "run-1" },
  nodeRuns: [
    {
      nodeId: "node-planner",
      harnessAttempt: nodeAttempt,
    },
  ],
  harnessAttempts: [nodeAttempt],
  harnessGatedClusterRuns: [
    {
      schemaVersion: "workflow.harness.gated-cluster-run.v1",
      runId: "run-gated",
      clusterId: "cognition",
      clusterLabel: "Cognition",
      executionMode: "gated",
      status: "gated",
      componentKinds: ["planner"],
      receiptIds: ["receipt-gated"],
      nodeAttemptIds: ["attempt-gated"],
      replayFixtureRefs: ["fixture-gated"],
      gateDecision: "allow_gated_cluster",
      rollbackTarget: "legacy_runtime",
      canaryStatus: "passed",
      promotionBlocked: false,
      activationBlockers: [],
      evidenceRefs: ["evidence-gated"],
    },
  ],
} as unknown as WorkflowRunResult;

const group = {
  groupId: "authority_tooling",
  label: "Authority Tooling",
  collapsed: true,
  innerNodeIds: [],
  componentKinds: ["policy_gate"],
  boundaryPorts: [],
  statusRollup: {
    executionMode: "gated",
    readiness: "live_ready",
    liveReadyCount: 1,
    shadowReadyCount: 1,
    simulatedCount: 0,
    projectionOnlyCount: 0,
    blockedCount: 0,
    warningCount: 0,
    receiptKindCount: 1,
    replayFixtureCount: 1,
    divergenceCount: 0,
  },
  deepLinks: {
    groupId: "authority_tooling",
    componentIds: ["ioi.agent-harness.policy_gate.v1"],
    receiptRefs: ["receipt-group"],
    replayFixtureRefs: ["fixture-group"],
    runId: "run-group",
  },
} as unknown as WorkflowHarnessGroupView;

const cases = [
  ["receipt-node", "node_attempt", "ioi.agent-harness.planner.v1"],
  ["receipt-gated", "gated_cluster", "planner"],
  ["receipt-audit", "activation_audit", "harness_activation_audit"],
  ["receipt-rollback", "rollback_execution", "harness_rollback_execution"],
  ["receipt-drill", "rollback_drill", "harness_rollback_drill"],
  ["workflow_restore_canary:receipt-canary", "rollback_restore_canary", "harness_restore_canary"],
  ["receipt-dispatch", "default_runtime_dispatch", "cognition"],
  ["receipt-group", "harness_group", "policy_gate"],
] as const;

for (const [receiptRef, sourceKind, producerComponent] of cases) {
  const inspection = resolveWorkflowHarnessReceiptInspection({
    receiptRef,
    workflow,
    lastRunResult,
    selectedRunId: "run-selected",
    selectedHarnessGroup: group,
    readOnlyRoutingReady: true,
    authorityToolingProof: { policyDecision: "allow_authority" },
  });
  assert.equal(inspection?.sourceKind, sourceKind, `${receiptRef} source kind`);
  assert.equal(
    inspection?.producerComponent,
    producerComponent,
    `${receiptRef} producer`,
  );
  assert.equal(inspection?.payloadPreview.kind, "object", `${receiptRef} payload preview`);
}

const unresolved = resolveWorkflowHarnessReceiptInspection({
  receiptRef: "receipt-missing",
  workflow,
  lastRunResult,
});
assert.equal(unresolved?.sourceKind, "unresolved");
assert.equal(unresolved?.policyDecision, "receipt ref pinned without a matching local record");

assert.equal(
  resolveWorkflowHarnessReceiptInspection({ receiptRef: null, workflow }),
  null,
);
assert.deepEqual(workflowUniqueReceiptRefs(["a", "a", null, undefined, "b"]), ["a", "b"]);
assert.equal(
  workflowHarnessReceiptKind("harness-default-dispatch:receipt-model_router_envelope"),
  "model router envelope",
);

console.log("workflow-rail-receipts.test.ts: ok");
