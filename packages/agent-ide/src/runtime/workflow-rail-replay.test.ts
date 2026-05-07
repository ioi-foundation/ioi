import assert from "node:assert/strict";
import {
  resolveWorkflowHarnessReplayInspection,
  workflowUniqueReplayFixtureRefs,
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

const defaultRuntimeDispatchProof = {
  schemaVersion: "workflow.harness.default-runtime-dispatch.v1",
  dispatchId: "dispatch-1",
  workflowId: "default-agent-harness",
  executionMode: "live",
  drivesRuntimeDecision: true,
  cognitionExecutionReceiptIds: ["receipt-dispatch-cognition"],
  cognitionExecutionAttemptIds: ["attempt-dispatch-cognition"],
  cognitionExecutionReplayFixtureRefs: ["fixture-dispatch-cognition"],
  cognitionExecutionProof: {
    policyDecision: "accept_cognition_dispatch",
  },
  modelExecutionReceiptIds: ["receipt-dispatch-model"],
  modelExecutionAttemptIds: ["attempt-dispatch-model"],
  modelExecutionReplayFixtureRefs: ["fixture-dispatch-model"],
  modelProviderCanaryReceiptIds: [],
  modelProviderCanaryAttemptIds: [],
  modelProviderCanaryReplayFixtureRefs: [],
  modelProviderGatedVisibleOutputReceiptIds: [],
  modelProviderGatedVisibleOutputAttemptIds: [],
  modelProviderGatedVisibleOutputReplayFixtureRefs: [],
  modelProviderGatedVisibleOutputRollbackDrillReceiptIds: [],
  modelProviderGatedVisibleOutputRollbackDrillAttemptIds: [],
  modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs: [],
  readOnlyCapabilityRoutingReceiptIds: ["receipt-readonly"],
  readOnlyCapabilityRoutingAttemptIds: ["attempt-readonly"],
  readOnlyCapabilityRoutingReplayFixtureRefs: ["fixture-readonly"],
  authorityToolingReadOnlyReceiptIds: [],
  authorityToolingReadOnlyLiveAttemptIds: [],
  authorityToolingReadOnlyReplayFixtureRefs: [],
  authorityToolingProviderCatalogLiveReceiptIds: [],
  authorityToolingProviderCatalogLiveAttemptIds: [],
  authorityToolingProviderCatalogLiveReplayFixtureRefs: [],
  authorityToolingMcpToolCatalogLiveReceiptIds: [],
  authorityToolingMcpToolCatalogLiveAttemptIds: [],
  authorityToolingMcpToolCatalogLiveReplayFixtureRefs: [],
  authorityToolingNativeToolCatalogLiveReceiptIds: [],
  authorityToolingNativeToolCatalogLiveAttemptIds: [],
  authorityToolingNativeToolCatalogLiveReplayFixtureRefs: [],
  authorityToolingConnectorCatalogLiveReceiptIds: [],
  authorityToolingConnectorCatalogLiveAttemptIds: [],
  authorityToolingConnectorCatalogLiveReplayFixtureRefs: [],
  authorityToolingWalletCapabilityLiveDryRunReceiptIds: [],
  authorityToolingWalletCapabilityLiveDryRunAttemptIds: [],
  authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs: [],
  authorityToolingGateLiveReceiptIds: [],
  authorityToolingGateLiveAttemptIds: [],
  authorityToolingGateLiveReplayFixtureRefs: [],
  authorityToolingPolicyGateLiveReceiptIds: ["receipt-policy-gate"],
  authorityToolingPolicyGateLiveAttemptIds: ["attempt-policy-gate"],
  authorityToolingPolicyGateLiveReplayFixtureRefs: ["fixture-policy-gate"],
  authorityToolingDestructiveDenialLiveReceiptIds: [],
  authorityToolingDestructiveDenialLiveAttemptIds: [],
  authorityToolingDestructiveDenialLiveReplayFixtureRefs: [],
  authorityToolingApprovalGateLiveReceiptIds: [],
  authorityToolingApprovalGateLiveAttemptIds: [],
  authorityToolingApprovalGateLiveReplayFixtureRefs: [],
  receiptIds: ["receipt-dispatch-cognition", "evidence-dispatch"],
  promptAssemblyPromptHash: "prompt-hash",
  modelExecutionOutputHash: "output-hash",
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
    {
      id: "node-bound",
      type: "task",
      name: "Bound verifier",
      x: 0,
      y: 0,
      runtimeBinding: {
        componentId: "ioi.agent-harness.verifier.v1",
        componentVersion: "1.0.0",
        componentKind: "verifier",
        executionMode: "shadow",
        readiness: "shadow_ready",
        kernelRef: "agentic::runtime::harness::verifier",
        evidenceEventKinds: ["evidence-binding"],
        receiptKinds: ["receipt-verifier"],
        replayEnvelope: {
          deterministicEnvelope: false,
          capturesInput: true,
          capturesOutput: false,
          capturesPolicyDecision: true,
          fixtureRef: "fixture-runtime-binding",
          determinism: "nondeterministic",
          nondeterminismReason: "model output is not fixture-stable",
          redactionPolicy: "binding_redacted",
        },
        replay: {
          deterministicEnvelope: false,
          capturesInput: true,
          capturesOutput: false,
          capturesPolicyDecision: true,
        },
      },
    },
  ],
  edges: [],
  global_config: {},
  metadata: {
    harness: {
      defaultRuntimeDispatchProof,
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
  ["fixture-node", "node_attempt", "ioi.agent-harness.planner.v1"],
  ["fixture-gated", "gated_cluster", "planner"],
  ["fixture-runtime-binding", "runtime_binding", "ioi.agent-harness.verifier.v1"],
  ["fixture-dispatch-cognition", "default_runtime_dispatch", "cognition"],
  ["fixture-readonly", "read_only_routing_proof", "read_only_capability_routing"],
  ["fixture-policy-gate", "authority_gate_proof", "policy_gate"],
  ["fixture-group", "harness_group", "policy_gate"],
] as const;

for (const [replayFixtureRef, sourceKind, producerComponent] of cases) {
  const inspection = resolveWorkflowHarnessReplayInspection({
    replayFixtureRef,
    workflow,
    lastRunResult,
    selectedRunId: "run-selected",
    selectedHarnessGroup: group,
    readOnlyRoutingReady: true,
    authorityToolingProof: { policyGateDecision: "allow_policy_gate" },
  });
  assert.equal(inspection?.sourceKind, sourceKind, `${replayFixtureRef} source kind`);
  assert.equal(
    inspection?.producerComponent,
    producerComponent,
    `${replayFixtureRef} producer`,
  );
  assert.equal(inspection?.payloadPreview.kind, "object", `${replayFixtureRef} payload preview`);
}

const unresolved = resolveWorkflowHarnessReplayInspection({
  replayFixtureRef: "fixture-missing",
  workflow,
  lastRunResult,
});
assert.equal(unresolved?.sourceKind, "unresolved");
assert.equal(
  unresolved?.policyDecision,
  "replay fixture ref pinned without a matching local record",
);

assert.equal(
  resolveWorkflowHarnessReplayInspection({ replayFixtureRef: null, workflow }),
  null,
);
assert.deepEqual(workflowUniqueReplayFixtureRefs(["a", "a", null, undefined, "b"]), [
  "a",
  "b",
]);
