#!/usr/bin/env node
import { writeFileSync } from "node:fs";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

globalThis.React = React;

import { WorkflowRailPanel } from "../../packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx";
import {
  executeWorkflowHarnessPromotionTransition,
  executeWorkflowHarnessReplayGate,
  forkDefaultAgentHarnessWorkflow,
  makeHarnessCanaryExecutionBoundaries,
  workflowHarnessPromotionTransitionEligibility,
} from "../../packages/agent-ide/src/runtime/harness-workflow.ts";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: harness-promotion-transition-gui-probe.mjs <output-path>");
}

const noop = () => undefined;

function clusterFor(workflow, clusterId) {
  return (
    workflow.metadata.harness?.promotionClusters?.find(
      (cluster) => String(cluster.clusterId) === String(clusterId),
    ) ?? null
  );
}

function groupViewFor(workflow, clusterId) {
  const cluster = clusterFor(workflow, clusterId);
  if (!cluster) throw new Error(`missing harness promotion cluster: ${clusterId}`);
  const componentKinds = new Set(cluster.componentKinds);
  const innerNodes = workflow.nodes.filter((node) =>
    componentKinds.has(node.runtimeBinding?.componentKind),
  );
  const readinessValues = innerNodes.map(
    (node) => node.runtimeBinding?.readiness ?? "projection_only",
  );
  const firstReadiness = readinessValues[0] ?? "projection_only";
  const readiness = readinessValues.every((value) => value === firstReadiness)
    ? firstReadiness
    : "mixed";
  const canaryBoundary =
    workflow.metadata.harness?.canaryExecutionBoundaries?.find(
      (boundary) => boundary.clusterId === cluster.clusterId,
    ) ?? null;
  const receiptRefs = [
    ...(cluster.replayGateProof?.receiptRefs ?? []),
    ...(canaryBoundary?.receiptIds ?? []),
  ];
  const replayFixtureRefs = [
    ...(cluster.replayGateProof?.replayFixtureRefs ?? []),
    ...(canaryBoundary?.replayFixtureRefs ?? []),
  ];
  return {
    groupId: cluster.clusterId,
    label: cluster.label,
    collapsed: true,
    innerNodeIds: innerNodes.map((node) => node.id),
    componentKinds: cluster.componentKinds,
    boundaryPorts: [],
    statusRollup: {
      executionMode: workflow.metadata.harness?.executionMode ?? cluster.requiredExecutionMode,
      readiness,
      liveReadyCount: readinessValues.filter((value) => value === "live_ready").length,
      shadowReadyCount: readinessValues.filter((value) => value === "shadow_ready").length,
      simulatedCount: readinessValues.filter((value) => value === "simulated").length,
      projectionOnlyCount: readinessValues.filter((value) => value === "projection_only").length,
      blockedCount: 0,
      warningCount: readinessValues.filter((value) => value !== "live_ready").length,
      receiptKindCount: receiptRefs.length,
      replayFixtureCount: replayFixtureRefs.length,
      replayGateStatus: cluster.replayGateProof?.gateStatus ?? "not_run",
      replayGateImpact: cluster.replayGateProof?.activationGateImpact ?? "pending",
      replayGateTotalFixtures: cluster.replayGateProof?.totalFixtures ?? 0,
      replayGateBlockingFixtureCount: cluster.replayGateProof?.blockingReplayFixtureRefs.length ?? 0,
      replayGateId: cluster.replayGateProof?.gateId,
      divergenceCount: cluster.replayGateProof?.blockingDivergenceCount ?? 0,
      activationState: workflow.metadata.harness?.activationState,
    },
    deepLinks: {
      groupId: cluster.clusterId,
      componentIds: innerNodes
        .map((node) => node.runtimeBinding?.componentId)
        .filter((componentId) => typeof componentId === "string"),
      receiptRefs,
      replayFixtureRefs,
      runId: "promotion-probe-run",
    },
  };
}

function railHtml(workflow, clusterId) {
  return renderToStaticMarkup(
    React.createElement(WorkflowRailPanel, {
      panel: "outputs",
      selectedNode: null,
      selectedHarnessGroup: groupViewFor(workflow, clusterId),
      harnessWorkbenchDeepLink: `#harness-workbench?group=${clusterId}`,
      harnessActivationCandidate: null,
      selectedHarnessReceiptRef: null,
      selectedHarnessReplayFixtureRef: null,
      selectedHarnessRollbackTarget: null,
      tests: [],
      proposals: [],
      runs: [],
      validationResult: null,
      readinessResult: null,
      testResult: null,
      workflow,
      lastRunResult: null,
      selectedRunId: null,
      compareRunResult: null,
      compareRunId: null,
      runEvents: [],
      dogfoodRun: null,
      portablePackage: null,
      bindingManifest: null,
      selectedNodeFixtures: [],
      checkpoints: [],
      onSelectRun: noop,
      onCompareRun: noop,
      onOpenExecutions: noop,
      onInspectNode: noop,
      onInspectHarnessGroupNode: noop,
      onSelectHarnessReceiptRef: noop,
      onSelectHarnessReplayFixtureRef: noop,
      onSelectHarnessRollbackTarget: noop,
      onCopyHarnessDeepLink: noop,
      onCheckActivationReadiness: noop,
      onRunHarnessActivationDryRun: noop,
      onRunHarnessReplayDrill: noop,
      onRunHarnessReplayGate: noop,
      onRunHarnessPromotionTransition: noop,
      onApplyHarnessActivationCandidate: noop,
      onRunHarnessRollbackDrill: noop,
      onExecuteHarnessRollback: noop,
      onConfigureNode: noop,
      onSelectProposal: noop,
      onExportPackage: noop,
      onOpenImportPackage: noop,
      onGenerateBindingManifest: noop,
      onUpdateEnvironmentProfile: noop,
      onUpdateProductionProfile: noop,
      onResolveIssue: noop,
      onRunNode: noop,
      onRunUpstream: noop,
      onCaptureFixtureForNode: noop,
      onDryRunFixtureForNode: noop,
      onPinFixtureForNode: noop,
      onAddTestFromOutput: noop,
    }),
  );
}

function selectedNodeRailHtml(workflow, selectedNode, nodeRun) {
  return renderToStaticMarkup(
    React.createElement(WorkflowRailPanel, {
      panel: "outputs",
      selectedNode,
      selectedHarnessGroup: null,
      harnessWorkbenchDeepLink: `#harness-workbench?node=${selectedNode.id}`,
      harnessActivationCandidate: null,
      selectedHarnessReceiptRef: null,
      selectedHarnessReplayFixtureRef: null,
      selectedHarnessRollbackTarget: null,
      tests: [],
      proposals: [],
      runs: [],
      validationResult: null,
      readinessResult: null,
      testResult: null,
      workflow,
      lastRunResult: {
        summary: { id: "github-pr-create-node-probe-run" },
        nodeRuns: [nodeRun],
        harnessAttempts: [nodeRun.harnessAttempt],
        checkpoints: [],
        events: [],
      },
      selectedRunId: "github-pr-create-node-probe-run",
      compareRunResult: null,
      compareRunId: null,
      runEvents: [],
      dogfoodRun: null,
      portablePackage: null,
      bindingManifest: null,
      selectedNodeFixtures: [],
      checkpoints: [],
      onSelectRun: noop,
      onCompareRun: noop,
      onOpenExecutions: noop,
      onInspectNode: noop,
      onInspectHarnessGroupNode: noop,
      onSelectHarnessReceiptRef: noop,
      onSelectHarnessReplayFixtureRef: noop,
      onSelectHarnessRollbackTarget: noop,
      onCopyHarnessDeepLink: noop,
      onCheckActivationReadiness: noop,
      onRunHarnessActivationDryRun: noop,
      onRunHarnessReplayDrill: noop,
      onRunHarnessReplayGate: noop,
      onRunHarnessPromotionTransition: noop,
      onApplyHarnessActivationCandidate: noop,
      onRunHarnessRollbackDrill: noop,
      onExecuteHarnessRollback: noop,
      onConfigureNode: noop,
      onSelectProposal: noop,
      onExportPackage: noop,
      onOpenImportPackage: noop,
      onGenerateBindingManifest: noop,
      onUpdateEnvironmentProfile: noop,
      onUpdateProductionProfile: noop,
      onResolveIssue: noop,
      onRunNode: noop,
      onRunUpstream: noop,
      onCaptureFixtureForNode: noop,
      onDryRunFixtureForNode: noop,
      onPinFixtureForNode: noop,
      onAddTestFromOutput: noop,
    }),
  );
}

function tagFor(html, tagName, testId) {
  return (
    html.match(new RegExp(`<${tagName}[^>]*data-testid="${testId}"[^>]*>`))?.[0] ??
    ""
  );
}

function hasDisabled(html, testId) {
  return /\sdisabled(=|\s|>)/.test(tagFor(html, "button", testId));
}

function attrValue(html, tagName, testId, attrName) {
  return (
    tagFor(html, tagName, testId).match(
      new RegExp(`${attrName}="([^"]*)"`, "u"),
    )?.[1] ?? ""
  );
}

function withPassingCanaryBoundaries(workflow) {
  return {
    ...workflow,
    metadata: {
      ...workflow.metadata,
      harness: {
        ...workflow.metadata.harness,
        canaryExecutionBoundaries: makeHarnessCanaryExecutionBoundaries(),
      },
    },
  };
}

function withClusterReadiness(workflow, clusterId, readiness) {
  const cluster = clusterFor(workflow, clusterId);
  const componentKinds = new Set(cluster?.componentKinds ?? []);
  return {
    ...workflow,
    nodes: workflow.nodes.map((node) =>
      node.runtimeBinding?.componentKind &&
      componentKinds.has(node.runtimeBinding.componentKind)
        ? {
            ...node,
            runtimeBinding: {
              ...node.runtimeBinding,
              readiness,
            },
          }
        : node,
    ),
  };
}

function withPassingReplayGate(workflow, clusterId, nowMs) {
  return executeWorkflowHarnessReplayGate(
    workflow,
    [
      {
        replayFixtureRef: `runtime-evidence:${clusterId}:fixture:gui-probe`,
        sourceKind: "harness_group",
        sourceLabel: `${clusterId} GUI promotion probe`,
        producerComponent: `ioi.agent-harness.${clusterId}.v1`,
        policyDecision: "accept_gui_promotion_probe_replay",
        attemptId: `attempt-${clusterId}-gui-probe`,
        receiptRef: `receipt-${clusterId}-gui-probe`,
        runId: `run-${clusterId}-gui-probe`,
        executionMode: "gated",
        readiness: "live_ready",
        inputHash: `input-${clusterId}-gui-probe`,
        outputHash: `output-${clusterId}-gui-probe`,
        deterministicEnvelope: true,
        capturesInput: true,
        capturesOutput: true,
        capturesPolicyDecision: true,
        determinism: "deterministic",
        redactionPolicy: "runtime_redacted",
        evidenceRefs: [`evidence-${clusterId}-gui-probe`],
      },
    ],
    {
      scopeKind: "harness_group",
      targetId: clusterId,
      nowMs,
    },
  ).workflow;
}

function attemptSnapshot(workflow, clusterId) {
  const attempt =
    workflow.metadata.harness?.promotionTransitions
      ?.filter((candidate) => String(candidate.clusterId) === String(clusterId))
      .at(-1) ?? null;
  return attempt
    ? {
        attemptStatus: attempt.attemptStatus,
        targetExecutionMode: attempt.targetExecutionMode,
        previousStatus: attempt.previousStatus,
        nextStatus: attempt.nextStatus,
        gateDecision: attempt.gateDecision,
        blockers: attempt.blockers,
        receiptRefCount: attempt.receiptRefs.length,
        replayFixtureRefCount: attempt.replayFixtureRefs.length,
      }
    : null;
}

function clusterStatus(workflow, clusterId) {
  return clusterFor(workflow, clusterId)?.promotionStatus ?? "missing";
}

const clusterId = "cognition";

const blockedFork = forkDefaultAgentHarnessWorkflow("Promotion Probe Blocked", 5_100);
const blockedHtml = railHtml(blockedFork.workflow, clusterId);
const blockedEligibility = workflowHarnessPromotionTransitionEligibility(
  blockedFork.workflow,
  clusterId,
  "gated",
  { nowMs: 5_110 },
);
const blockedClick = executeWorkflowHarnessPromotionTransition(
  blockedFork.workflow,
  clusterId,
  "gated",
  { nowMs: 5_120 },
);
const blockedAttemptHtml = railHtml(blockedClick.workflow, clusterId);

const validFork = forkDefaultAgentHarnessWorkflow("Promotion Probe Valid", 5_200);
const validReadyWorkflow = withClusterReadiness(
  withPassingCanaryBoundaries(
    withPassingReplayGate(validFork.workflow, clusterId, 5_210),
  ),
  clusterId,
  "live_ready",
);
const validBeforeHtml = railHtml(validReadyWorkflow, clusterId);
const gatedClick = executeWorkflowHarnessPromotionTransition(
  validReadyWorkflow,
  clusterId,
  "gated",
  { nowMs: 5_220 },
);
const gatedHtml = railHtml(gatedClick.workflow, clusterId);
const liveClick = executeWorkflowHarnessPromotionTransition(
  gatedClick.workflow,
  clusterId,
  "live",
  { nowMs: 5_230 },
);
const liveHtml = railHtml(liveClick.workflow, clusterId);

const githubPrCreateNode =
  blockedFork.workflow.nodes.find((node) => node.type === "github_pr_create") ??
  null;
const githubPrCreateRequestHash =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const githubPrCreateReceiptRef = "receipt-github-pr-create-node-probe";
const githubPrCreateReplayFixtureRef = "fixture-github-pr-create-node-probe";
const githubPrCreatePlan = {
  ...(githubPrCreateNode?.config?.logic?.githubPrCreatePlan ?? {}),
  planId: "github_pr_create_plan_node_probe",
  status: "blocked",
  decision: "blocked",
  dryRun: true,
  previewOnly: true,
  toolName: "github__pr_create",
  action: "pr_create",
  repoFullName: "ioi-test/ioi",
  baseBranch: "main",
  headBranch: "deepseek-parity-plus",
  reviewGateStatus: "blocked",
  reviewSatisfied: false,
  authority: {
    requiredScopes: ["github.pr.create"],
    grantedScopes: [],
    missingScopes: ["github.pr.create"],
    scopeGranted: false,
    approvalRequired: true,
    approvalSatisfied: false,
  },
  request: {
    method: "POST",
    path: "/repos/ioi-test/ioi/pulls",
    payloadHash: githubPrCreateRequestHash,
    bodyIncluded: false,
    tokenIncluded: false,
  },
  blockers: [
    "review_gate_not_passed",
    "review_not_satisfied",
    "missing_authority_scope:github.pr.create",
    "dry_run_only",
  ],
  networkLookupPerformed: false,
  mutationAttempted: false,
  mutationExecuted: false,
  receiptId: githubPrCreateReceiptRef,
};
const githubPrCreateNodeRun = {
  nodeId: githubPrCreateNode?.id ?? "harness.github_pr_create",
  nodeType: "github_pr_create",
  status: "blocked",
  startedAtMs: 5_240,
  finishedAtMs: 5_245,
  attempt: 1,
  input: { reviewGateStatus: "blocked" },
  output: {
    githubPrCreatePlan,
    receiptId: githubPrCreateReceiptRef,
  },
  harnessAttempt: {
    attemptId: "attempt-github-pr-create-node-probe",
    harnessWorkflowId: "default-agent-harness",
    harnessActivationId: "activation:github-pr-create-node-probe",
    harnessHash: "sha256:github-pr-create-node-probe",
    workflowNodeId: githubPrCreateNode?.id ?? "harness.github_pr_create",
    componentId: "ioi.agent-harness.github_pr_create.v1",
    componentKind: "github_pr_create",
    executionMode: "gated",
    readiness: "shadow_ready",
    attemptIndex: 1,
    status: "gated",
    inputHash: "sha256:input-github-pr-create-node-probe",
    outputHash: "sha256:output-github-pr-create-node-probe",
    policyDecision: "accept_authority_tooling_github_pr_create_adapter_envelope",
    receiptIds: [githubPrCreateReceiptRef],
    evidenceRefs: ["github_pr_create_plan", "github.pr_create.request_hash"],
    replay: {
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: false,
      fixtureRef: githubPrCreateReplayFixtureRef,
      determinism: "deterministic",
      redactionPolicy: "github_pr_create_plan_safe",
    },
  },
};
const githubPrCreateHtml =
  githubPrCreateNode === null
    ? ""
    : selectedNodeRailHtml(
        blockedFork.workflow,
        githubPrCreateNode,
        githubPrCreateNodeRun,
      );

const checks = {
  blockedGatedButtonDisabled: hasDisabled(
    blockedHtml,
    "workflow-harness-promote-cluster-gated",
  ),
  blockedLiveButtonDisabled: hasDisabled(
    blockedHtml,
    "workflow-harness-promote-cluster-live",
  ),
  blockedEligibilityExposesReplayBlocker:
    attrValue(
      blockedHtml,
      "article",
      "workflow-harness-group-promotion-eligibility",
      "data-gated-blockers",
    ).includes("promotion_replay_gate_not_passed") &&
    blockedEligibility.blockers.includes("promotion_replay_gate_not_passed"),
  blockedClickRecordsAuditAttempt:
    blockedClick.promoted === false &&
    blockedClick.attempt.attemptStatus === "blocked" &&
    blockedClick.workflow.metadata.harness?.activationAudit?.at(-1)?.eventType ===
      "promotion_transition_blocked",
  blockedAttemptCardRendered:
    attrValue(
      blockedAttemptHtml,
      "article",
      "workflow-harness-group-promotion-attempt",
      "data-attempt-status",
    ) === "blocked",
  validGatedButtonEnabledBeforeClick:
    !hasDisabled(validBeforeHtml, "workflow-harness-promote-cluster-gated"),
  validLiveButtonDisabledBeforeGated: hasDisabled(
    validBeforeHtml,
    "workflow-harness-promote-cluster-live",
  ),
  gatedClickPromotesCluster:
    gatedClick.promoted === true &&
    gatedClick.attempt.nextStatus === "gated" &&
    clusterStatus(gatedClick.workflow, clusterId) === "gated",
  gatedAttemptCardRendered:
    attrValue(
      gatedHtml,
      "article",
      "workflow-harness-group-promotion-attempt",
      "data-target-execution-mode",
    ) === "gated" &&
    attrValue(
      gatedHtml,
      "article",
      "workflow-harness-group-promotion-attempt",
      "data-attempt-status",
    ) === "promoted",
  liveButtonEnabledAfterGated:
    !hasDisabled(gatedHtml, "workflow-harness-promote-cluster-live"),
  liveClickPromotesCluster:
    liveClick.promoted === true &&
    liveClick.attempt.previousStatus === "gated" &&
    liveClick.attempt.nextStatus === "live" &&
    clusterStatus(liveClick.workflow, clusterId) === "live",
  liveAttemptCardRendered:
    attrValue(
      liveHtml,
      "article",
      "workflow-harness-group-promotion-attempt",
      "data-target-execution-mode",
    ) === "live" &&
    attrValue(
      liveHtml,
      "article",
      "workflow-harness-group-promotion-attempt",
      "data-attempt-status",
    ) === "promoted",
  githubPrCreateNodeOutputInspector:
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-request-hash",
    ) === githubPrCreateRequestHash &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-dry-run",
    ) === "true" &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-mutation-executed",
    ) === "false" &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-missing-scopes",
    ) === "github.pr.create" &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-review-gate-status",
    ) === "blocked" &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-receipt-refs",
    ).includes(githubPrCreateReceiptRef) &&
    attrValue(
      githubPrCreateHtml,
      "article",
      "workflow-selected-node-github-pr-create-output-summary",
      "data-github-pr-create-replay-fixture-ref",
    ) === githubPrCreateReplayFixtureRef,
};

const proof = {
  schemaVersion: "ioi.autopilot.gui-harness.promotion-transition-behavior.v1",
  passed: Object.values(checks).every(Boolean),
  clusterId,
  method:
    "render WorkflowRailPanel markup, verify promotion controls, invoke controller-equivalent transition handler, rerender attempt cards",
  checks,
  snapshots: {
    blockedEligibility: {
      eligible: blockedEligibility.eligible,
      blockers: blockedEligibility.blockers,
      gatedButtonDisabled: hasDisabled(
        blockedHtml,
        "workflow-harness-promote-cluster-gated",
      ),
      liveButtonDisabled: hasDisabled(
        blockedHtml,
        "workflow-harness-promote-cluster-live",
      ),
    },
    blockedAttempt: attemptSnapshot(blockedClick.workflow, clusterId),
    gatedAttempt: attemptSnapshot(gatedClick.workflow, clusterId),
    liveAttempt: attemptSnapshot(liveClick.workflow, clusterId),
    githubPrCreateNodeOutput: {
      selectedNodeId: githubPrCreateNode?.id ?? null,
      requestHash: attrValue(
        githubPrCreateHtml,
        "article",
        "workflow-selected-node-github-pr-create-output-summary",
        "data-github-pr-create-request-hash",
      ),
      missingScopes: attrValue(
        githubPrCreateHtml,
        "article",
        "workflow-selected-node-github-pr-create-output-summary",
        "data-github-pr-create-missing-scopes",
      ),
      receiptRefs: attrValue(
        githubPrCreateHtml,
        "article",
        "workflow-selected-node-github-pr-create-output-summary",
        "data-github-pr-create-receipt-refs",
      ),
    },
  },
  uiSelectors: {
    groupInspector: "workflow-harness-group-inspector",
    promotionActions: "workflow-harness-group-promotion-actions",
    promoteClusterGated: "workflow-harness-promote-cluster-gated",
    promoteClusterLive: "workflow-harness-promote-cluster-live",
    promotionEligibility: "workflow-harness-group-promotion-eligibility",
    promotionAttempt: "workflow-harness-group-promotion-attempt",
    selectedNodeGithubPrCreateOutput:
      "workflow-selected-node-github-pr-create-output-summary",
  },
  sourceRefs: [
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx",
    "packages/agent-ide/src/WorkflowComposer/controller.tsx",
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "packages/agent-ide/src/runtime/harness-workflow.ts",
    "packages/agent-ide/src/types/graph.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
if (!proof.passed) {
  process.exitCode = 1;
}
