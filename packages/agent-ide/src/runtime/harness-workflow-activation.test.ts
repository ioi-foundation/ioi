import assert from "node:assert/strict";
import type {
  WorkflowHarnessActivationIdGateClickProof,
  WorkflowHarnessPackageImportActivationApplyProof,
  WorkflowHarnessWorkerBinding,
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph.ts";
import {
  applyWorkflowHarnessActivationCandidate,
  DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  executeWorkflowHarnessPromotionTransition,
  executeWorkflowHarnessRollbackDrill,
  executeWorkflowHarnessReplayDrill,
  executeWorkflowHarnessReplayGate,
  executeWorkflowHarnessRevisionRollback,
  forkDefaultAgentHarnessWorkflow,
  makeBlessedHarnessLiveHandoffProof,
  makeHarnessDefaultRuntimeDispatchProof,
  makeHarnessCanaryExecutionBoundaries,
  makeHarnessForkActivationRecord,
  makeHarnessRuntimeSelectorDecision,
  recordWorkflowHarnessActivationDryRun,
  recordWorkflowHarnessRollbackTargetSelection,
  runWorkflowHarnessRollbackRestoreCanaryProbe,
  workflowHarnessActivationIdGateClickProofBlockers,
  workflowHarnessPackageImportActivationApplyProofBlockers,
  workflowHarnessPromotionTransitionEligibility,
  workflowRevisionBindingFor,
} from "./harness-workflow.ts";
import {
  createWorkflowHarnessActivationCandidate,
  evaluateWorkflowActivationReadiness,
  validateWorkflowProject,
} from "./workflow-validation.ts";

const activationIssueCodes = (result: WorkflowValidationResult) =>
  [
    ...result.errors,
    ...result.warnings,
    ...(result.executionReadinessIssues ?? []),
  ].map((issue) => issue.code);

const activationNotValidatedIssue: WorkflowValidationIssue = {
  code: "harness_activation_not_validated",
  message: "Harness fork has not minted an activation id yet.",
};

const makeActivationIdGateClickProof = (
  overrides: Partial<WorkflowHarnessActivationIdGateClickProof> = {},
): WorkflowHarnessActivationIdGateClickProof => {
  const activationId = "activation:runtime-harness-test-fork:validated-canary";
  const proof: WorkflowHarnessActivationIdGateClickProof = {
    schemaVersion: "workflow.harness.activation-id-gate-click-proof.v1",
    method: "unit-test activation-id gate proof",
    generatedAtMs: 10_000,
    blockedDryRun: {
      gateId: "activation-id",
      action: {
        id: "activation-gate-action:activation-id:run-dry-run",
        kind: "run_activation_dry_run",
        impact: "collect_evidence",
        command: "workflow-harness-gate-action-activation-id",
        disabled: false,
      },
      beforeState: { "data-gate-status": "blocked" },
      afterState: { "data-gate-status": "blocked" },
      clicked: true,
      candidateId: "candidate:runtime-harness-test-fork:activation-dry-run:10000",
      decision: "blocked",
      activationBlockerCount: 3,
      workflowActivationId: null,
      workflowActivationState: "blocked",
      latestAuditEventType: "dry_run_blocked",
      latestAuditStatus: "blocked",
    },
    mintedActivation: {
      gateId: "activation-id",
      action: {
        id: "activation-gate-action:activation-id:mint",
        kind: "mint_activation",
        impact: "mint_activation",
        command: "workflow-harness-gate-action-activation-id",
        disabled: false,
      },
      beforeState: { "data-gate-status": "passed" },
      afterState: { "data-gate-status": "passed" },
      clicked: true,
      applied: true,
      activationId,
      workflowActivationId: activationId,
      workflowActivationState: "validated",
      workerBindingActivationId: activationId,
      activationRecordWorkerBindingActivationId: activationId,
      rollbackTarget: "activation:default-agent-harness:blessed-readonly",
      revisionBindingActivationId: activationId,
      activationRecordRevisionBindingHash: "sha256:activation-revision",
      rollbackRevisionBindingHash: "sha256:rollback-revision",
      latestAuditEventType: "activation_minted",
      latestAuditStatus: "applied",
      receiptRefs: ["workflow_activation:runtime-harness-test-fork"],
      evidenceRefs: ["canary:passed", "rollback:drill"],
      workerHandoffReceiptIds: [
        "harness-worker-handoff:receipt:runtime-harness-test-fork:launch",
      ],
      workerHandoffNodeAttemptIds: [
        "harness-worker-handoff:attempt:runtime-harness-test-fork:launch",
      ],
      workerHandoffReplayFixtureRefs: [
        "harness-worker-handoff:fixture:runtime-harness-test-fork:launch",
      ],
      workerHandoffDeepLink:
        "#harness-workbench?panel=settings&activationGateId=worker-handoff&activationGateNodeAttemptId=harness-worker-handoff%3Aattempt%3Aruntime-harness-test-fork%3Alaunch&nodeAttemptId=harness-worker-handoff%3Aattempt%3Aruntime-harness-test-fork%3Alaunch",
      workerHandoffDeepLinkState: {
        "data-selected-activation-gate-id": "worker-handoff",
        "data-selected-activation-gate-node-attempt-id":
          "harness-worker-handoff:attempt:runtime-harness-test-fork:launch",
        "data-selected-node-attempt-id":
          "harness-worker-handoff:attempt:runtime-harness-test-fork:launch",
      },
      workerHandoffTimelineVisible: true,
      workerHandoffTimelineAttemptId:
        "harness-worker-handoff:attempt:runtime-harness-test-fork:launch",
    },
    passed: true,
    blockers: [],
  };
  return { ...proof, ...overrides };
};

const makePackageImportActivationApplyProof = (
  overrides: Partial<WorkflowHarnessPackageImportActivationApplyProof> = {},
): WorkflowHarnessPackageImportActivationApplyProof => {
  const activationId =
    "activation:package-evidence-import-roundtrip-fork:validated-canary:default-agen";
  const workerHandoffAttemptId =
    "harness-worker-handoff:attempt:package-evidence-import-roundtrip-fork:launch";
  const proof: WorkflowHarnessPackageImportActivationApplyProof = {
    schemaVersion:
      "workflow.harness.package-import-activation-apply-proof.v1",
    method: "unit-test reviewed import activation apply proof",
    generatedAtMs: 10_000,
    review: null,
    clicked: true,
    beforeState: { "data-package-import-activation-enabled": "true" },
    afterState: { "data-workflow-activation-state": "validated" },
    activationAction: {
      present: true,
      disabled: false,
      evidenceReady: true,
      blockerCount: 0,
      handoffPresent: true,
      handoffDecision: "mintable",
      activationIdPreview: activationId,
      canaryStatus: "passed",
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      workerBindingId: activationId,
      mintable: true,
    },
    activationResult: {
      applied: true,
      activationId,
      blockers: [],
      workflowActivationId: activationId,
      workflowActivationState: "validated",
      workerBindingActivationId: activationId,
      activationRecordWorkerBindingActivationId: activationId,
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      revisionBindingActivationId: activationId,
      activationRecordRevisionBindingHash: "sha256:activation-revision",
      rollbackRevisionBindingHash: "sha256:rollback-revision",
      activationAuditEventCount: 1,
      latestAuditEventId: "activation-audit:reviewed-import:minted",
      latestAuditEventType: "activation_minted",
      latestAuditStatus: "applied",
      receiptRefs: ["workflow_activation:reviewed-import"],
      evidenceRefs: ["package-evidence:reviewed-import"],
      workerHandoffReceiptIds: [
        "harness-worker-handoff:receipt:package-evidence-import-roundtrip-fork:launch",
      ],
      workerHandoffNodeAttemptIds: [workerHandoffAttemptId],
      workerHandoffReplayFixtureRefs: [
        "harness-worker-handoff:fixture:package-evidence-import-roundtrip-fork:launch",
      ],
      statusMessage: "Reviewed import activation applied",
    },
    workerHandoff: {
      deepLinkHash: `#harness-workbench?activationGateId=worker-handoff&activationGateNodeAttemptId=${workerHandoffAttemptId}`,
      selectedState: {
        "data-selected-activation-gate-id": "worker-handoff",
        "data-selected-activation-gate-node-attempt-id":
          workerHandoffAttemptId,
      },
      timelineVisible: true,
      selectedAttemptId: workerHandoffAttemptId,
    },
    incompleteAction: {
      present: true,
      disabled: true,
      evidenceReady: false,
      blockerCount: 3,
      handoffPresent: true,
      handoffDecision: "blocked",
      activationIdPreview: null,
      canaryStatus: "passed",
      rollbackTarget: DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
      workerBindingId: activationId,
      mintable: false,
    },
    passed: true,
    blockers: [],
  };
  return { ...proof, ...overrides };
};

const onlyActivationMissingReadiness = (
  base: WorkflowValidationResult,
): WorkflowValidationResult => ({
  ...base,
  status: "blocked",
  errors: [],
  warnings: [activationNotValidatedIssue],
  blockedNodes: [],
  missingConfig: [],
  connectorBindingIssues: [],
  executionReadinessIssues: [activationNotValidatedIssue],
  verificationIssues: [],
});

const withPassingPromotionClusterReplayGates = (
  workflow: WorkflowProject,
  startMs: number,
): WorkflowProject =>
  (workflow.metadata.harness?.promotionClusters ?? []).reduce(
    (currentWorkflow, cluster, index) =>
      executeWorkflowHarnessReplayGate(
        currentWorkflow,
        [
          {
            replayFixtureRef: `runtime-evidence:${cluster.clusterId}:fixture:promotion-gate`,
            sourceKind: "harness_group",
            sourceLabel: `${cluster.label} replay fixture`,
            producerComponent: `ioi.agent-harness.${cluster.clusterId}.v1`,
            policyDecision: "accept_replay",
            attemptId: `attempt-${cluster.clusterId}`,
            receiptRef: `receipt-${cluster.clusterId}`,
            runId: `run-${cluster.clusterId}`,
            executionMode: "gated",
            readiness: "live_ready",
            inputHash: `input-${cluster.clusterId}`,
            outputHash: `output-${cluster.clusterId}`,
            deterministicEnvelope: true,
            capturesInput: true,
            capturesOutput: true,
            capturesPolicyDecision: true,
            determinism: "deterministic",
            redactionPolicy: "runtime_redacted",
            evidenceRefs: [`evidence-${cluster.clusterId}`],
          },
        ],
        {
          scopeKind: "harness_group",
          targetId: cluster.clusterId,
          nowMs: startMs + index,
        },
      ).workflow,
    workflow,
  );

const withPassingCanaryBoundaries = (workflow: WorkflowProject): WorkflowProject => ({
  ...workflow,
  metadata: {
    ...workflow.metadata,
    harness: {
      ...workflow.metadata.harness!,
      canaryExecutionBoundaries: makeHarnessCanaryExecutionBoundaries(),
    },
  },
});

const withClusterReadiness = (
  workflow: WorkflowProject,
  clusterId: string,
  readiness: "shadow_ready" | "live_ready",
): WorkflowProject => {
  const cluster = workflow.metadata.harness?.promotionClusters?.find(
    (candidate) => String(candidate.clusterId) === clusterId,
  );
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
};

{
  const fork = forkDefaultAgentHarnessWorkflow("Blocked Activation Fork", 1_000);
  const base = validateWorkflowProject(fork.workflow, fork.tests);
  const readiness = evaluateWorkflowActivationReadiness(
    fork.workflow,
    fork.tests,
    base,
    fork.proposals,
    [],
  );
  const candidate = createWorkflowHarnessActivationCandidate(
    fork.workflow,
    fork.tests,
    readiness,
    fork.proposals,
    1_100,
  );
  const auditedWorkflow = recordWorkflowHarnessActivationDryRun(fork.workflow, candidate, {
    nowMs: 1_150,
  });
  const result = applyWorkflowHarnessActivationCandidate(auditedWorkflow, candidate, {
    nowMs: 1_200,
  });

  assert.equal(candidate.decision, "blocked");
  assert.equal(candidate.revisionBindingPreview.revisionSource, "file_hash_only");
  assert.match(candidate.revisionBindingPreview.workflowContentHash, /^stable-fnv1a32:/);
  assert.equal(candidate.rollbackRestoreCanary.status, "not_required");
  assert.match(candidate.rollbackRestoreCanary.receiptBindingRef ?? "", /^workflow_restore_canary:/);
  const blockedReceiptRef = candidate.rollbackRestoreCanary.receiptBindingRef ?? "";
  const dryRunAudit = auditedWorkflow.metadata.harness?.activationAudit ?? [];
  assert.equal(dryRunAudit[dryRunAudit.length - 1]?.eventType, "dry_run_blocked");
  assert.ok(dryRunAudit[dryRunAudit.length - 1]?.receiptRefs.includes(blockedReceiptRef));
  assert.equal(result.applied, false);
  assert.match(result.blockers.join(","), /candidate_not_mintable/);
  assert.equal(result.workflow.metadata.harness?.activationState, "blocked");
  assert.equal(result.workflow.metadata.workerHarnessBinding?.harnessActivationId, undefined);
  const blockedMintAudit = result.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(blockedMintAudit[blockedMintAudit.length - 1]?.eventType, "activation_mint_blocked");
  assert.ok(blockedMintAudit[blockedMintAudit.length - 1]?.receiptRefs.includes(blockedReceiptRef));
  const blockedPackageManifest = result.workflow.metadata.harness?.packageManifest;
  assert.ok(blockedPackageManifest);
  assert.equal(
    blockedPackageManifest.schemaVersion,
    "workflow.harness.package-evidence-manifest.v1",
  );
  assert.equal(blockedPackageManifest.activationState, "blocked");
  assert.ok(blockedPackageManifest.receiptRefs.includes(blockedReceiptRef));
  assert.match(blockedPackageManifest.workflowContentHash, /^stable-fnv1a32:/);
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Imported Incomplete Package Fork", 1_300);
  const workflowId = fork.workflow.metadata.id;
  const activationId = "activation:imported-incomplete-package:validated";
  const incompletePackageManifest = {
    ...fork.workflow.metadata.harness!.packageManifest!,
    activationId,
    activationState: "validated" as const,
    receiptRefs: [],
    replayFixtureRefs: [],
    deepLinks: [],
    workerHandoffNodeAttemptIds: [],
    workerHandoffReceiptIds: [],
    rollbackRestoreReceiptRefs: [],
  };
  const workerBinding: WorkflowHarnessWorkerBinding = {
    ...fork.workflow.metadata.workerHarnessBinding,
    harnessWorkflowId: workflowId,
    harnessActivationId: activationId,
    harnessHash:
      fork.workflow.metadata.harness?.harnessHash ??
      "sha256:default-agent-harness-component-projection-v1",
    source: "fork" as const,
    authorityBindingReady: true,
    authorityBindingBlockers: [],
  };
  const activationRecord = {
    ...makeHarnessForkActivationRecord({
      workflowId,
      harnessWorkflowId: workflowId,
      activationId,
      activationState: "validated",
      canaryStatus: "passed",
      rollbackTarget: "legacy_runtime",
      rollbackAvailable: true,
      liveAuthorityTransferred: false,
      workerBinding,
      mintedAtMs: 1_300,
    }),
    packageManifest: incompletePackageManifest,
  };
  const workflow: WorkflowProject = {
    ...fork.workflow,
    metadata: {
      ...fork.workflow.metadata,
      harness: {
        ...fork.workflow.metadata.harness!,
        activationId,
        activationState: "validated" as const,
        activationRecord,
        packageManifest: incompletePackageManifest,
      },
      workerHarnessBinding: workerBinding,
    },
  };
  const base = validateWorkflowProject(workflow, fork.tests);
  const readiness = evaluateWorkflowActivationReadiness(
    workflow,
    fork.tests,
    base,
    fork.proposals,
    [],
  );
  assert.ok(
    activationIssueCodes(readiness).includes("harness_package_manifest_incomplete"),
  );
  const candidate = createWorkflowHarnessActivationCandidate(
    workflow,
    fork.tests,
    readiness,
    fork.proposals,
    1_350,
  );
  const packageGate = candidate.gateResults.find(
    (gate) => gate.gateId === "package-evidence",
  );
  assert.equal(packageGate?.status, "blocked");
  assert.match(packageGate?.value ?? "", /blockers/);
  assert.equal(candidate.decision, "blocked");
  assert.ok(candidate.blockerCodes.includes("package-evidence"));
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Validated Activation Fork", 2_000);
  const workflowId = fork.workflow.metadata.id;
  const workerBinding: WorkflowHarnessWorkerBinding = {
    ...fork.workflow.metadata.workerHarnessBinding,
    harnessWorkflowId: workflowId,
    harnessActivationId: undefined,
    harnessHash:
      fork.workflow.metadata.workerHarnessBinding?.harnessHash ??
      fork.workflow.metadata.harness?.harnessHash ??
      "sha256:default-agent-harness-component-projection-v1",
    source: "fork" as const,
  };
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId,
    harnessWorkflowId: workflowId,
    activationState: "blocked",
    activationBlockers: [],
    canaryStatus: "passed",
    rollbackTarget: "activation:default-agent-harness:blessed-readonly",
    rollbackAvailable: true,
    evidenceRefs: ["canary:passed", "rollback:drill"],
    workerBinding,
    mintedAtMs: 2_000,
  });
  const workflow: WorkflowProject = withPassingPromotionClusterReplayGates({
    ...fork.workflow,
    global_config: {
      ...fork.workflow.global_config,
      environmentProfile: {
        ...fork.workflow.global_config.environmentProfile,
        target: fork.workflow.global_config.environmentProfile?.target ?? "local",
        mockBindingPolicy: "block" as const,
      },
    },
    metadata: {
      ...fork.workflow.metadata,
      harness: {
        ...fork.workflow.metadata.harness!,
        activationId: undefined,
        activationState: "blocked" as const,
        activationRecord,
      },
      workerHarnessBinding: workerBinding,
    },
  }, 2_025);
  const base = validateWorkflowProject(workflow, fork.tests);
  const readiness = onlyActivationMissingReadiness(base);
  const candidate = createWorkflowHarnessActivationCandidate(
    workflow,
    fork.tests,
    readiness,
    [],
    2_100,
  );
  const dryRunWorkflow = recordWorkflowHarnessActivationDryRun(workflow, candidate, {
    nowMs: 2_150,
  });
  const rollbackSelectedWorkflow = recordWorkflowHarnessRollbackTargetSelection(
    dryRunWorkflow,
    "legacy_runtime",
    { nowMs: 2_175 },
  );
  const result = applyWorkflowHarnessActivationCandidate(rollbackSelectedWorkflow, candidate, {
    rollbackTarget: "legacy_runtime",
    nowMs: 2_200,
  });

  assert.equal(candidate.decision, "mintable", candidate.activationBlockers.join("\n"));
  assert.equal(candidate.rollbackRestoreCanary.status, "not_required");
  const mintableReceiptRef = candidate.rollbackRestoreCanary.receiptBindingRef ?? "";
  assert.match(mintableReceiptRef, /^workflow_restore_canary:/);
  assert.equal(
    candidate.gateResults.find((gate) => gate.gateId === "rollback-restore")?.status,
    "passed",
  );
  assert.equal(result.applied, true);
  assert.equal(result.activationId, candidate.activationIdPreview);
  assert.equal(result.workflow.metadata.harness?.activationState, "validated");
  assert.equal(result.workflow.metadata.harness?.activationId, candidate.activationIdPreview);
  assert.equal(
    result.workflow.metadata.workerHarnessBinding?.harnessActivationId,
    candidate.activationIdPreview,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerBinding?.harnessActivationId,
    candidate.activationIdPreview,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerBinding
      ?.authorityBindingReady,
    true,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerBindingRegistryRecord
      ?.bindingStatus,
    "bound",
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerSessionRecord
      ?.currentStatus,
    "rollback_ready",
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerLaunchEnvelopes
      ?.length,
    3,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.workerHandoffReceipts
      ?.length,
    3,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord
      ?.workerHandoffNodeAttempts?.length,
    3,
  );
  assert.ok(
    result.workflow.metadata.harness?.activationRecord?.workerHandoffNodeAttempts?.every(
      (attempt) =>
        attempt.workflowNodeId === "harness.handoff_bridge" &&
        attempt.componentKind === "handoff_bridge" &&
        attempt.executionMode === "gated" &&
        attempt.status === "gated" &&
        Boolean(attempt.replay.fixtureRef) &&
        attempt.receiptIds.some((receiptId) =>
          result.workflow.metadata.harness?.activationRecord
            ?.workerHandoffReceipts?.some(
              (receipt) => receipt.receiptId === receiptId,
            ),
        ),
    ),
  );
  assert.equal(result.workflow.metadata.harness?.activationRecord?.rollbackTarget, "legacy_runtime");
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.rollbackRestoreCanary?.status,
    "not_required",
  );
  assert.equal(candidate.revisionBindingPreview.activationId, candidate.activationIdPreview);
  assert.equal(
    result.workflow.metadata.harness?.revisionBinding?.activationId,
    candidate.activationIdPreview,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.revisionBinding?.workflowContentHash,
    candidate.revisionBindingPreview.workflowContentHash,
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.rollbackRevisionBinding
      ?.workflowContentHash,
    rollbackSelectedWorkflow.metadata.harness?.revisionBinding?.workflowContentHash,
  );
  assert.deepEqual(
    result.workflow.metadata.harness?.activationAudit?.slice(-3).map((event) => event.eventType),
    [
      "dry_run_mintable",
      "rollback_target_selected",
      "activation_minted",
    ],
  );
  const activationAudit = result.workflow.metadata.harness?.activationAudit ?? [];
  assert.ok(
    activationAudit
      .find((event) => event.eventType === "dry_run_mintable")
      ?.receiptRefs.includes(mintableReceiptRef),
  );
  assert.ok(
    activationAudit
      .find((event) => event.eventType === "activation_minted")
      ?.receiptRefs.includes(mintableReceiptRef),
  );
  const packageManifest = result.workflow.metadata.harness?.packageManifest;
  assert.ok(packageManifest);
  assert.equal(
    packageManifest.schemaVersion,
    "workflow.harness.package-evidence-manifest.v1",
  );
  assert.equal(packageManifest.activationId, candidate.activationIdPreview);
  assert.equal(packageManifest.activationState, "validated");
  assert.equal(packageManifest.rollbackTarget, "legacy_runtime");
  assert.equal(packageManifest.workerHandoffNodeAttemptIds.length, 3);
  assert.equal(packageManifest.workerHandoffReceiptIds.length, 3);
  assert.ok(packageManifest.receiptRefs.includes(mintableReceiptRef));
  assert.ok(packageManifest.rollbackRestoreReceiptRefs.includes(mintableReceiptRef));
  assert.ok(packageManifest.evidenceRefs.includes(candidate.candidateId));
  assert.ok(
    packageManifest.deepLinks.some(
      (link) =>
        link.kind === "worker_handoff" &&
        link.hash.includes("activationGateNodeAttemptId="),
    ),
  );
  assert.ok(
    packageManifest.deepLinks.some(
      (link) =>
        link.kind === "rollback_restore" &&
        link.hash.includes("activationGateId=rollback-restore"),
    ),
  );
  assert.equal(
    result.workflow.metadata.harness?.activationRecord?.packageManifest
      ?.workflowContentHash,
    packageManifest.workflowContentHash,
  );

  const rollbackDrill = executeWorkflowHarnessRollbackDrill(result.workflow, {
    rollbackTarget: "legacy_runtime",
    nowMs: 2_300,
  });
  assert.equal(rollbackDrill.executed, true);
  assert.equal(rollbackDrill.proof?.drillStatus, "passed");
  assert.equal(rollbackDrill.proof?.rollbackExecuted, true);
  assert.ok(rollbackDrill.proof?.receiptRefs.includes(mintableReceiptRef));
  assert.equal(
    rollbackDrill.proof?.restoredWorkerBinding?.harnessActivationId,
    workerBinding.harnessActivationId,
  );
  assert.equal(
    rollbackDrill.workflow.metadata.harness?.activationRollbackProof?.drillStatus,
    "passed",
  );
  assert.equal(
    rollbackDrill.proof?.activeRevisionBinding?.activationId,
    candidate.activationIdPreview,
  );
  assert.equal(
    rollbackDrill.proof?.restoredRevisionBinding?.workflowContentHash,
    rollbackSelectedWorkflow.metadata.harness?.revisionBinding?.workflowContentHash,
  );
  const rollbackDrillAudit = rollbackDrill.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(rollbackDrillAudit[rollbackDrillAudit.length - 1]?.eventType, "rollback_drill_passed");
  assert.ok(rollbackDrillAudit[rollbackDrillAudit.length - 1]?.receiptRefs.includes(mintableReceiptRef));

  const rollbackExecution = executeWorkflowHarnessRevisionRollback(result.workflow, {
    rollbackTarget: "legacy_runtime",
    restoreResult: {
      restored: true,
      blockers: [],
      workflowPath: "/repo/.agents/workflows/default-agent-harness.json",
      repoRoot: "/repo",
      relativeWorkflowPath: ".agents/workflows/default-agent-harness.json",
      revisionSource: "git",
      restoredRevision: "abc123",
      restoreStrategy: "git_show_file_restore",
      expectedWorkflowContentHash:
        rollbackSelectedWorkflow.metadata.harness?.revisionBinding
          ?.workflowContentHash,
      receiptBindingRef: "workflow_restore_canary:rollback-execution",
      fileSha256: "sha256:restored-workflow-file",
    },
    nowMs: 2_400,
  });
  assert.equal(rollbackExecution.executed, true);
  assert.equal(rollbackExecution.execution?.executionStatus, "applied");
  assert.equal(rollbackExecution.execution?.rollbackExecuted, true);
  assert.equal(rollbackExecution.execution?.hashVerified, true);
  assert.equal(
    rollbackExecution.execution?.policyDecision,
    "rollback_execution_restored_verified_workflow_revision",
  );
  assert.equal(rollbackExecution.execution?.restoreStrategy, "git_show_file_restore");
  assert.equal(rollbackExecution.execution?.restoreRepoRoot, "/repo");
  assert.equal(
    rollbackExecution.execution?.restoreRelativeWorkflowPath,
    ".agents/workflows/default-agent-harness.json",
  );
  assert.equal(rollbackExecution.execution?.restoredRevision, "abc123");
  assert.equal(
    rollbackExecution.execution?.restoredFileSha256,
    "sha256:restored-workflow-file",
  );
  assert.equal(
    rollbackExecution.execution?.restoreReceiptBindingRef,
    "workflow_restore_canary:rollback-execution",
  );
  assert.ok(
    rollbackExecution.execution?.receiptRefs.includes(
      "workflow_restore_canary:rollback-execution",
    ),
  );
  assert.ok(rollbackExecution.execution?.receiptRefs.includes(mintableReceiptRef));
  assert.deepEqual(rollbackExecution.execution?.restoreBlockers, []);
  assert.equal(
    rollbackExecution.workflow.metadata.harness?.activationRollbackExecution
      ?.executionStatus,
    "applied",
  );
  assert.equal(
    rollbackExecution.workflow.metadata.harness?.revisionBinding?.workflowContentHash,
    rollbackSelectedWorkflow.metadata.harness?.revisionBinding?.workflowContentHash,
  );
  assert.equal(
    rollbackExecution.workflow.metadata.harness?.activationRecord?.rollbackRevisionBinding
      ?.workflowContentHash,
    result.workflow.metadata.harness?.revisionBinding?.workflowContentHash,
  );
  assert.equal(
    rollbackExecution.workflow.metadata.workerHarnessBinding?.harnessActivationId,
    workerBinding.harnessActivationId,
  );
  const rollbackExecutionAudit =
    rollbackExecution.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(
    rollbackExecutionAudit[rollbackExecutionAudit.length - 1]?.eventType,
    "rollback_executed",
  );
  assert.ok(
    rollbackExecutionAudit[rollbackExecutionAudit.length - 1]?.receiptRefs.includes(
      "workflow_restore_canary:rollback-execution",
    ),
  );

  const postValidation = validateWorkflowProject(result.workflow, fork.tests);
  const postReadiness = evaluateWorkflowActivationReadiness(
    result.workflow,
    fork.tests,
    postValidation,
    [],
    null,
  );
  assert.equal(
    activationIssueCodes(postReadiness).includes("harness_activation_not_validated"),
    false,
  );
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Replay Drill Fork", 2_600);
  const passedReplay = executeWorkflowHarnessReplayDrill(
    fork.workflow,
    {
      replayFixtureRef: "runtime-evidence:default:fixture:planner",
      sourceKind: "node_attempt",
      sourceLabel: "Planner replay fixture",
      producerComponent: "ioi.agent-harness.planner.v1",
      policyDecision: "accept_replay",
      attemptId: "attempt-planner",
      receiptRef: "receipt-planner",
      runId: "run-planner",
      executionMode: "gated",
      readiness: "live_ready",
      inputHash: "input-planner",
      outputHash: "output-planner",
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: true,
      determinism: "deterministic",
      redactionPolicy: "runtime_redacted",
      evidenceRefs: ["evidence-planner"],
    },
    { nowMs: 2_610 },
  );
  assert.equal(passedReplay.executed, true);
  assert.equal(passedReplay.drill?.drillStatus, "passed");
  assert.equal(passedReplay.drill?.divergenceClass, "none");
  assert.equal(passedReplay.drill?.actualOutputHash, "output-planner");
  assert.ok(passedReplay.drill?.receiptRefs.includes("receipt-planner"));
  assert.equal(
    passedReplay.workflow.metadata.harness?.replayDrills?.[0]?.replayFixtureRef,
    "runtime-evidence:default:fixture:planner",
  );
  const replayAudit = passedReplay.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(replayAudit[replayAudit.length - 1]?.eventType, "replay_drill_passed");
  assert.ok(replayAudit[replayAudit.length - 1]?.receiptRefs.includes("receipt-planner"));

  const blockedReplay = executeWorkflowHarnessReplayDrill(
    passedReplay.workflow,
    {
      replayFixtureRef: "runtime-evidence:default:fixture:policy",
      sourceKind: "authority_gate_proof",
      sourceLabel: "Policy gate replay fixture",
      producerComponent: "policy_gate",
      policyDecision: "policy pending",
      attemptId: "attempt-policy",
      receiptRef: "receipt pending",
      runId: "run-policy",
      executionMode: "gated",
      readiness: "shadow_ready",
      inputHash: "input-policy",
      outputHash: "output-policy",
      deterministicEnvelope: true,
      capturesInput: true,
      capturesOutput: true,
      capturesPolicyDecision: false,
      determinism: "deterministic",
      redactionPolicy: "runtime_redacted",
      evidenceRefs: ["evidence-policy"],
    },
    { nowMs: 2_620 },
  );
  assert.equal(blockedReplay.executed, false);
  assert.equal(blockedReplay.drill?.drillStatus, "blocked");
  assert.equal(blockedReplay.drill?.divergenceClass, "missing_receipt");
  const blockedAudit = blockedReplay.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(blockedAudit[blockedAudit.length - 1]?.eventType, "replay_drill_blocked");
  const base = validateWorkflowProject(blockedReplay.workflow, fork.tests);
  const readiness = onlyActivationMissingReadiness(base);
  const candidate = createWorkflowHarnessActivationCandidate(
    blockedReplay.workflow,
    fork.tests,
    readiness,
    [],
    2_630,
  );
  assert.equal(
    candidate.gateResults.find((gate) => gate.gateId === "replay-fixtures")?.status,
    "blocked",
  );
  assert.match(
    candidate.gateResults.find((gate) => gate.gateId === "replay-fixtures")?.value ?? "",
    /drill blockers/,
  );

  const gatePassed = executeWorkflowHarnessReplayGate(
    fork.workflow,
    [
      {
        replayFixtureRef: "runtime-evidence:default:fixture:planner",
        sourceKind: "node_attempt",
        sourceLabel: "Planner replay fixture",
        producerComponent: "ioi.agent-harness.planner.v1",
        policyDecision: "accept_replay",
        attemptId: "attempt-planner",
        receiptRef: "receipt-planner",
        runId: "run-planner",
        executionMode: "gated",
        readiness: "live_ready",
        inputHash: "input-planner",
        outputHash: "output-planner",
        deterministicEnvelope: true,
        capturesInput: true,
        capturesOutput: true,
        capturesPolicyDecision: true,
        determinism: "deterministic",
        redactionPolicy: "runtime_redacted",
        evidenceRefs: ["evidence-planner"],
      },
    ],
    {
      scopeKind: "harness_group",
      targetId: "cognition",
      nowMs: 2_640,
    },
  );
  assert.equal(gatePassed.executed, true);
  assert.equal(gatePassed.gate.gateStatus, "passed");
  assert.equal(gatePassed.gate.totalFixtures, 1);
  assert.equal(gatePassed.gate.activationGateImpact, "passed");
  assert.deepEqual(gatePassed.gate.divergenceCounts, { none: 1 });
  assert.ok(gatePassed.gate.receiptRefs.includes("receipt-planner"));
  assert.equal(gatePassed.workflow.metadata.harness?.replayGates?.[0]?.targetId, "cognition");
  assert.equal(
    gatePassed.workflow.metadata.harness?.promotionClusters?.find(
      (cluster) => cluster.clusterId === "cognition",
    )?.replayGateProof?.gateStatus,
    "passed",
  );
  const gatePassedAudit = gatePassed.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(gatePassedAudit[gatePassedAudit.length - 1]?.eventType, "replay_gate_passed");

  const gateBlocked = executeWorkflowHarnessReplayGate(
    fork.workflow,
    [],
    {
      scopeKind: "activation_candidate",
      targetId: "activation-preview",
      nowMs: 2_650,
    },
  );
  assert.equal(gateBlocked.executed, false);
  assert.equal(gateBlocked.gate.gateStatus, "blocked");
  assert.equal(gateBlocked.gate.blockers[0], "replay_gate_no_fixtures");
  assert.equal(gateBlocked.gate.activationGateImpact, "blocked");
  const gateBlockedAudit = gateBlocked.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(gateBlockedAudit[gateBlockedAudit.length - 1]?.eventType, "replay_gate_blocked");
  const gateBlockedBase = validateWorkflowProject(gateBlocked.workflow, fork.tests);
  const gateBlockedReadiness = onlyActivationMissingReadiness(gateBlockedBase);
  const gateBlockedCandidate = createWorkflowHarnessActivationCandidate(
    gateBlocked.workflow,
    fork.tests,
    gateBlockedReadiness,
    [],
    2_660,
  );
  assert.equal(
    gateBlockedCandidate.gateResults.find((gate) => gate.gateId === "replay-fixtures")?.status,
    "blocked",
  );
  assert.match(
    gateBlockedCandidate.gateResults.find((gate) => gate.gateId === "replay-fixtures")?.value ?? "",
    /gate blockers/,
  );
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Promotion Transition Fork", 2_700);
  const blockedEligibility = workflowHarnessPromotionTransitionEligibility(
    fork.workflow,
    "cognition",
    "gated",
    { nowMs: 2_710 },
  );
  assert.equal(blockedEligibility.eligible, false);
  assert.ok(blockedEligibility.blockers.includes("promotion_replay_gate_not_passed"));
  assert.ok(blockedEligibility.blockers.includes("promotion_canary_not_passed"));
  const blocked = executeWorkflowHarnessPromotionTransition(
    fork.workflow,
    "cognition",
    "gated",
    { nowMs: 2_720 },
  );
  assert.equal(blocked.promoted, false);
  assert.equal(blocked.attempt.attemptStatus, "blocked");
  assert.equal(blocked.attempt.gateDecision, "block_promotion_transition");
  assert.equal(blocked.attempt.nextStatus, "shadow_ready");
  assert.equal(
    blocked.workflow.metadata.harness?.promotionTransitions?.[0]?.attemptStatus,
    "blocked",
  );
  assert.equal(
    blocked.workflow.metadata.harness?.activationAudit?.slice(-1)[0]?.eventType,
    "promotion_transition_blocked",
  );

  const promotableWorkflow = withClusterReadiness(
    withPassingCanaryBoundaries(
      withPassingPromotionClusterReplayGates(fork.workflow, 2_730),
    ),
    "cognition",
    "live_ready",
  );
  const gatedEligibility = workflowHarnessPromotionTransitionEligibility(
    promotableWorkflow,
    "cognition",
    "gated",
    { nowMs: 2_740 },
  );
  assert.equal(gatedEligibility.eligible, true, gatedEligibility.blockers.join("\n"));
  assert.equal(gatedEligibility.replayGateReady, true);
  assert.equal(gatedEligibility.canaryReady, true);
  assert.equal(gatedEligibility.rollbackReady, true);
  const gated = executeWorkflowHarnessPromotionTransition(
    promotableWorkflow,
    "cognition",
    "gated",
    { nowMs: 2_750 },
  );
  assert.equal(gated.promoted, true);
  assert.equal(gated.attempt.attemptStatus, "promoted");
  assert.equal(gated.attempt.nextStatus, "gated");
  assert.equal(
    gated.workflow.metadata.harness?.promotionClusters?.find(
      (cluster) => cluster.clusterId === "cognition",
    )?.promotionStatus,
    "gated",
  );

  const liveEligibility = workflowHarnessPromotionTransitionEligibility(
    gated.workflow,
    "cognition",
    "live",
    { nowMs: 2_760 },
  );
  assert.equal(liveEligibility.eligible, true, liveEligibility.blockers.join("\n"));
  const live = executeWorkflowHarnessPromotionTransition(
    gated.workflow,
    "cognition",
    "live",
    { nowMs: 2_770 },
  );
  assert.equal(live.promoted, true);
  assert.equal(live.attempt.previousStatus, "gated");
  assert.equal(live.attempt.nextStatus, "live");
  assert.deepEqual(
    live.workflow.metadata.harness?.activationAudit?.slice(-2).map((event) => event.eventType),
    ["promotion_transition_promoted", "promotion_transition_promoted"],
  );
}

{
  const activationIdGateClickProof = makeActivationIdGateClickProof();
  const packageImportActivationApplyProof =
    makePackageImportActivationApplyProof();
  const selectorDecisionId = "harness-selector:default-agent-harness:live-default-test";
  const nodeTimelineAttemptIds = ["attempt-planner", "attempt-model-router"];
  const receiptIds = ["receipt-planner", "receipt-model-router"];
  const replayFixtureRefs = ["fixture-planner", "fixture-model-router"];
  const dispatch = makeHarnessDefaultRuntimeDispatchProof({
    selectorDecisionId,
    acceptedClusterIds: [
      "cognition",
      "routing_model",
      "verification_output",
      "authority_tooling",
    ],
    acceptedNodeAttemptIds: nodeTimelineAttemptIds,
    receiptIds,
    replayFixtureRefs,
    activationIdGateClickProof,
    activationIdGateProofNowMs: 10_100,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: 10_100,
  });
  const livePromotionReadinessProof = dispatch.livePromotionReadinessProof;
  const selector = makeHarnessRuntimeSelectorDecision({
    decisionId: selectorDecisionId,
    selectedSelector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    canaryEligible: true,
    canaryBlockers: [],
    executionMode: "live",
    actualRuntimeAuthority: "blessed_workflow_activation_default",
    defaultPromotionGateEnabled: true,
    defaultPromotionGateEligible: true,
    defaultPromotionGateAuthorityTransferred: true,
    defaultPromotionGateActivationBlockers: [],
    livePromotionReadinessProof,
    activationIdGateClickProof,
    activationIdGateProofNowMs: 10_100,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: 10_100,
  });
  const handoff = makeBlessedHarnessLiveHandoffProof({
    selector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    defaultAuthorityTransferred: true,
    runtimeAuthority: "blessed_workflow_activation_default",
    defaultPromotionGateEnabled: true,
    defaultPromotionGateEligible: true,
    defaultPromotionGateActivationBlockers: [],
    livePromotionReadinessProof,
    activationIdGateClickProof,
    activationIdGateProofNowMs: 10_100,
    packageImportActivationApplyProof,
    packageImportActivationApplyProofNowMs: 10_100,
    nodeTimelineAttemptIds,
    receiptIds,
    replayFixtureRefs,
  });

  assert.equal(selector.selectedSelector, "blessed_workflow_live_default");
  assert.equal(selector.productionDefaultSelector, "blessed_workflow_live_default");
  assert.equal(selector.executionMode, "live");
  assert.equal(selector.actualRuntimeAuthority, "blessed_workflow_activation_default");
  assert.equal(selector.defaultPromotionGate?.enabled, true);
  assert.equal(selector.defaultPromotionGate?.eligible, true);
  assert.equal(selector.defaultPromotionGate?.defaultAuthorityTransferred, true);
  assert.deepEqual(selector.defaultPromotionGate?.activationBlockers, []);
  assert.equal(selector.livePromotionReadinessReady, true);
  assert.deepEqual(selector.livePromotionReadinessBlockers, []);
  assert.deepEqual(selector.defaultLivePromotionInvariantBlockers, []);
  assert.equal(selector.reviewedImportActivationApplyProofPresent, true);
  assert.equal(selector.reviewedImportActivationApplyProofPassed, true);
  assert.deepEqual(selector.reviewedImportActivationApplyProofBlockers, []);
  assert.equal(
    selector.reviewedImportActivationApplyActivationId,
    packageImportActivationApplyProof.activationResult?.activationId,
  );
  assert.equal(
    selector.livePromotionReadinessProof?.proofId,
    dispatch.livePromotionReadinessProof.proofId,
  );
  assert.equal(handoff.selector, "blessed_workflow_live_default");
  assert.equal(handoff.productionDefaultSelector, "blessed_workflow_live_default");
  assert.equal(handoff.defaultAuthorityTransferred, true);
  assert.equal(handoff.runtimeAuthority, "blessed_workflow_activation_default");
  assert.equal(handoff.defaultPromotionGate?.eligible, true);
  assert.deepEqual(handoff.defaultPromotionGate?.activationBlockers, []);
  assert.equal(handoff.livePromotionReadinessReady, true);
  assert.deepEqual(handoff.livePromotionReadinessBlockers, []);
  assert.deepEqual(handoff.defaultLivePromotionInvariantBlockers, []);
  assert.equal(handoff.reviewedImportActivationApplyProofPresent, true);
  assert.equal(handoff.reviewedImportActivationApplyProofPassed, true);
  assert.deepEqual(handoff.reviewedImportActivationApplyProofBlockers, []);
  assert.equal(dispatch.selectorDecisionId, selector.decisionId);
  assert.equal(dispatch.selectedSelector, "blessed_workflow_live_default");
  assert.equal(dispatch.productionDefaultSelector, "blessed_workflow_live_default");
  assert.equal(dispatch.executionMode, "live");
  assert.equal(dispatch.runtimeAuthority, "blessed_workflow_activation_default");
  assert.equal(dispatch.drivesRuntimeDecision, true);
  assert.equal(dispatch.activationIdGateClickProofPresent, true);
  assert.equal(dispatch.activationIdGateClickProofPassed, true);
  assert.deepEqual(dispatch.activationIdGateClickProofBlockers, []);
  assert.deepEqual(dispatch.defaultDispatchActivationBlockers, []);
  assert.equal(dispatch.activationIdGate?.gateId, "activation-id");
  assert.equal(dispatch.activationIdGate?.proofPresent, true);
  assert.equal(dispatch.activationIdGate?.proofPassed, true);
  assert.deepEqual(dispatch.activationIdGate?.proofBlockers, []);
  assert.equal(
    dispatch.activationIdGate?.workerBindingActivationId,
    DEFAULT_AGENT_HARNESS_ACTIVATION_ID,
  );
  assert.deepEqual(
    dispatch.activationIdGate?.defaultDispatchActivationBlockers,
    [],
  );
  assert.deepEqual(dispatch.defaultLivePromotionInvariantBlockers, []);
  assert.equal(dispatch.reviewedImportActivationApplyProofPresent, true);
  assert.equal(dispatch.reviewedImportActivationApplyProofPassed, true);
  assert.deepEqual(dispatch.reviewedImportActivationApplyProofBlockers, []);
  assert.equal(
    dispatch.reviewedImportActivationApplyActivationId,
    packageImportActivationApplyProof.activationResult?.activationId,
  );
  assert.equal(dispatch.reviewedImportActivationApplyGate?.proofPassed, true);
  assert.equal(
    dispatch.reviewedImportActivationApplyGate?.invariantId,
    "reviewed_import_activation_apply",
  );
  assert.deepEqual(dispatch.activationBlockers, []);
  assert.equal(
    dispatch.livePromotionReadinessProof.schemaVersion,
    "workflow.harness.live-promotion-readiness.v1",
  );
  assert.equal(dispatch.livePromotionReadinessProof.targetExecutionMode, "live");
  assert.equal(dispatch.livePromotionReadinessProof.allClustersReady, true);
  assert.equal(dispatch.livePromotionReadinessProof.promotionEligible, true);
  assert.equal(
    dispatch.livePromotionReadinessProof.defaultLiveActivationReady,
    true,
  );
  assert.equal(
    dispatch.livePromotionReadinessProof.invalidForkLiveActivationBlocked,
    true,
  );
  assert.equal(dispatch.livePromotionReadinessProof.clusterReadiness.length, 4);
  assert.ok(
    dispatch.livePromotionReadinessProof.clusterReadiness.every(
      (cluster) =>
        cluster.targetExecutionMode === "live" &&
        cluster.blockers.length === 0 &&
        cluster.receiptRefs.length > 0 &&
        cluster.replayFixtureRefs.length > 0,
    ),
  );
  assert.equal(dispatch.acceptedClusterIds.length, 4);
  assert.equal(dispatch.workerHandoffNodeAttempts.length, 3);
  assert.equal(dispatch.workerHandoffNodeAttemptIds.length, 3);
  assert.equal(dispatch.workerHandoffReplayFixtureRefs.length, 3);
  assert.ok(
    dispatch.workerHandoffNodeAttempts.every(
      (attempt) =>
        attempt.workflowNodeId === "harness.handoff_bridge" &&
        attempt.componentKind === "handoff_bridge" &&
        attempt.status === "live" &&
        attempt.replay.fixtureRef?.startsWith(
          "harness-worker-handoff:fixture:",
        ) &&
        attempt.receiptIds.some((receiptId) =>
          dispatch.workerHandoffReceiptIds.includes(receiptId),
        ),
    ),
  );
  assert.ok(
    dispatch.workerHandoffNodeAttemptIds.every((attemptId) =>
      dispatch.dispatchNodeAttemptIds.includes(attemptId),
    ),
  );
  assert.ok(
    dispatch.workerHandoffNodeAttemptIds.every((attemptId) =>
      dispatch.nodeAttemptIds.includes(attemptId),
    ),
  );
  assert.ok(
    dispatch.workerHandoffReplayFixtureRefs.every((fixtureRef) =>
      dispatch.replayFixtureRefs.includes(fixtureRef),
    ),
  );
}

{
  const validProof = makeActivationIdGateClickProof();
  const validPackageApplyProof = makePackageImportActivationApplyProof();
  assert.deepEqual(
    workflowHarnessActivationIdGateClickProofBlockers(validProof, { nowMs: 10_100 }),
    [],
  );
  assert.deepEqual(
    workflowHarnessPackageImportActivationApplyProofBlockers(
      validPackageApplyProof,
      { nowMs: 10_100 },
    ),
    [],
  );

  const selector = makeHarnessRuntimeSelectorDecision({
    selectedSelector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    defaultPromotionGateEligible: true,
    defaultPromotionGateAuthorityTransferred: true,
  });
  assert.equal(selector.selectedSelector, "blessed_workflow_live_canary");
  assert.equal(selector.productionDefaultSelector, "legacy_runtime");
  assert.equal(selector.livePromotionReadinessReady, false);
  assert.deepEqual(selector.defaultPromotionGate?.activationBlockers, [
    "activation_id_gate_click_proof_missing",
    "live_promotion_readiness_proof_missing",
    "package_import_activation_apply_proof_missing",
  ]);
  assert.deepEqual(selector.defaultLivePromotionInvariantBlockers, [
    "package_import_activation_apply_proof_missing",
  ]);
  assert.equal(selector.reviewedImportActivationApplyProofPresent, false);
  assert.equal(selector.reviewedImportActivationApplyProofPassed, false);

  const handoff = makeBlessedHarnessLiveHandoffProof({
    selector: "blessed_workflow_live_default",
    productionDefaultSelector: "blessed_workflow_live_default",
    defaultAuthorityTransferred: true,
  });
  assert.equal(handoff.selector, "blessed_workflow_live_canary");
  assert.equal(handoff.defaultAuthorityTransferred, false);
  assert.equal(handoff.productionDefaultSelector, "legacy_runtime");
  assert.equal(handoff.livePromotionReadinessReady, false);
  assert.deepEqual(handoff.defaultPromotionGate?.activationBlockers, [
    "activation_id_gate_click_proof_missing",
    "live_promotion_readiness_proof_missing",
    "package_import_activation_apply_proof_missing",
  ]);
  assert.deepEqual(handoff.activationBlockers, [
    "activation_id_gate_click_proof_missing",
    "live_promotion_readiness_proof_missing",
    "package_import_activation_apply_proof_missing",
  ]);
  assert.deepEqual(handoff.defaultLivePromotionInvariantBlockers, [
    "package_import_activation_apply_proof_missing",
  ]);

  const missingProofDispatch = makeHarnessDefaultRuntimeDispatchProof();
  assert.deepEqual(missingProofDispatch.activationBlockers, [
    "activation_id_gate_click_proof_missing",
    "package_import_activation_apply_proof_missing",
  ]);
  assert.equal(missingProofDispatch.activationIdGateClickProofPresent, false);
  assert.equal(missingProofDispatch.activationIdGateClickProofPassed, false);
  assert.deepEqual(missingProofDispatch.activationIdGateClickProofBlockers, [
    "activation_id_gate_click_proof_missing",
  ]);
  assert.equal(missingProofDispatch.activationIdGate?.proofPresent, false);
  assert.equal(missingProofDispatch.activationIdGate?.proofPassed, false);
  assert.deepEqual(missingProofDispatch.activationIdGate?.proofBlockers, [
    "activation_id_gate_click_proof_missing",
  ]);
  assert.equal(missingProofDispatch.activationIdGate?.workerBindingActivationId, "");
  assert.equal(missingProofDispatch.drivesRuntimeDecision, false);
  assert.equal(missingProofDispatch.executionMode, "gated");
  assert.equal(missingProofDispatch.runtimeAuthority, "existing_runtime_service");
  assert.equal(
    missingProofDispatch.livePromotionReadinessProof.allClustersReady,
    true,
  );
  assert.equal(
    missingProofDispatch.livePromotionReadinessProof.promotionEligible,
    false,
  );
  assert.deepEqual(
    missingProofDispatch.livePromotionReadinessProof.activationBlockers,
    [
      "activation_id_gate_click_proof_missing",
      "package_import_activation_apply_proof_missing",
    ],
  );
  assert.equal(missingProofDispatch.reviewedImportActivationApplyProofPresent, false);
  assert.equal(missingProofDispatch.reviewedImportActivationApplyProofPassed, false);
  assert.deepEqual(missingProofDispatch.reviewedImportActivationApplyProofBlockers, [
    "package_import_activation_apply_proof_missing",
  ]);

  const dryRunOnlyProof = makeActivationIdGateClickProof({
    passed: false,
    blockers: ["activation_id_gate_mint_not_applied"],
    mintedActivation: {
      ...validProof.mintedActivation,
      clicked: false,
      applied: false,
      activationId: null,
      workflowActivationId: null,
      workerBindingActivationId: null,
      activationRecordWorkerBindingActivationId: null,
      revisionBindingActivationId: null,
      receiptRefs: [],
    },
  });
  const dryRunOnlyDispatch = makeHarnessDefaultRuntimeDispatchProof({
    activationIdGateClickProof: dryRunOnlyProof,
    activationIdGateProofNowMs: 10_100,
  });
  assert.match(
    dryRunOnlyDispatch.activationBlockers.join("\n"),
    /activation_id_gate_click_proof_failed/,
  );
  assert.match(
    dryRunOnlyDispatch.activationBlockers.join("\n"),
    /activation_id_gate_mint_not_applied/,
  );
  assert.equal(dryRunOnlyDispatch.activationIdGateClickProofPresent, true);
  assert.equal(dryRunOnlyDispatch.activationIdGateClickProofPassed, false);
  assert.deepEqual(
    dryRunOnlyDispatch.defaultDispatchActivationBlockers,
    dryRunOnlyDispatch.activationBlockers,
  );
  assert.equal(dryRunOnlyDispatch.activationIdGate?.proofPresent, true);
  assert.equal(dryRunOnlyDispatch.activationIdGate?.proofPassed, false);
  assert.deepEqual(
    dryRunOnlyDispatch.activationIdGate?.proofBlockers,
    dryRunOnlyDispatch.activationIdGateClickProofBlockers,
  );
  assert.equal(dryRunOnlyDispatch.activationIdGate?.workerBindingActivationId, "");
  assert.equal(dryRunOnlyDispatch.drivesRuntimeDecision, false);

  const mismatchedProof = makeActivationIdGateClickProof({
    mintedActivation: {
      ...validProof.mintedActivation,
      workerBindingActivationId: "activation:mismatch",
    },
  });
  const mismatchDispatch = makeHarnessDefaultRuntimeDispatchProof({
    activationIdGateClickProof: mismatchedProof,
    activationIdGateProofNowMs: 10_100,
  });
  assert.match(
    mismatchDispatch.activationBlockers.join("\n"),
    /activation_id_gate_mint_worker_binding_mismatch/,
  );
  assert.equal(mismatchDispatch.activationIdGateClickProofPassed, false);
  assert.equal(mismatchDispatch.activationIdGate?.proofPassed, false);
  assert.equal(mismatchDispatch.activationIdGate?.workerBindingActivationId, "");
  assert.equal(mismatchDispatch.drivesRuntimeDecision, false);

  const staleProof = makeActivationIdGateClickProof({ generatedAtMs: 1_000 });
  assert.match(
    workflowHarnessActivationIdGateClickProofBlockers(staleProof, {
      nowMs: 10_000,
      maxAgeMs: 1_000,
    }).join("\n"),
    /activation_id_gate_click_proof_stale/,
  );
  const stalePackageApplyProof = makePackageImportActivationApplyProof({
    generatedAtMs: 1_000,
  });
  assert.match(
    workflowHarnessPackageImportActivationApplyProofBlockers(
      stalePackageApplyProof,
      {
        nowMs: 10_000,
        maxAgeMs: 1_000,
      },
    ).join("\n"),
    /package_import_activation_apply_proof_stale/,
  );
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Git Restore Canary Fork", 3_000);
  const workflowId = fork.workflow.metadata.id;
  const rollbackWorkflow = fork.workflow;
  const rollbackRevisionBinding = workflowRevisionBindingFor(rollbackWorkflow, {
    workflowPath: "/repo/.agents/workflows/git-restore-canary.workflow.json",
    repoRoot: "/repo",
    branch: "main",
    baseRevision: "base123",
    activatedRevision: "abc123",
    nowMs: 3_025,
  });
  const workerBinding: WorkflowHarnessWorkerBinding = {
    ...fork.workflow.metadata.workerHarnessBinding,
    harnessWorkflowId: workflowId,
    harnessActivationId: undefined,
    harnessHash:
      fork.workflow.metadata.workerHarnessBinding?.harnessHash ??
      fork.workflow.metadata.harness?.harnessHash ??
      "sha256:default-agent-harness-component-projection-v1",
    source: "fork" as const,
  };
  const activationRecord = makeHarnessForkActivationRecord({
    workflowId,
    harnessWorkflowId: workflowId,
    activationState: "blocked",
    activationBlockers: [],
    canaryStatus: "passed",
    rollbackTarget: "activation:default-agent-harness:blessed-readonly",
    rollbackAvailable: true,
    evidenceRefs: ["canary:passed", "rollback:drill"],
    workerBinding,
    rollbackRevisionBinding,
    mintedAtMs: 3_000,
  });
  const workflow: WorkflowProject = withPassingPromotionClusterReplayGates({
    ...fork.workflow,
    global_config: {
      ...fork.workflow.global_config,
      environmentProfile: {
        ...fork.workflow.global_config.environmentProfile,
        target: fork.workflow.global_config.environmentProfile?.target ?? "local",
        mockBindingPolicy: "block" as const,
      },
    },
    metadata: {
      ...fork.workflow.metadata,
      harness: {
        ...fork.workflow.metadata.harness!,
        activationId: undefined,
        activationState: "blocked" as const,
        activationRecord,
      },
      workerHarnessBinding: workerBinding,
    },
  }, 3_025);
  const base = validateWorkflowProject(workflow, fork.tests);
  const readiness = onlyActivationMissingReadiness(base);
  const candidate = createWorkflowHarnessActivationCandidate(
    workflow,
    fork.tests,
    readiness,
    [],
    3_100,
    {
      rollbackRestoreResult: {
        restored: true,
        dryRun: true,
        blockers: [],
        workflowPath: rollbackRevisionBinding.workflowPath,
        repoRoot: rollbackRevisionBinding.repoRoot,
        relativeWorkflowPath: ".agents/workflows/git-restore-canary.workflow.json",
        revisionSource: "git",
        restoredRevision: "abc123",
        restoreStrategy: "git_show_file_restore",
        expectedWorkflowContentHash: rollbackRevisionBinding.workflowContentHash,
        actualWorkflowContentHash: rollbackRevisionBinding.workflowContentHash,
        hashVerified: true,
        receiptBindingRef: "workflow_restore_canary:git-verified",
        fileSha256: "0123456789abcdef",
        bundle: {
          workflowPath: rollbackRevisionBinding.workflowPath,
          testsPath: "/repo/.agents/workflows/git-restore-canary.tests.json",
          proposalsDir: "/repo/.agents/workflows/git-restore-canary.proposals",
          workflow: rollbackWorkflow,
          tests: [],
          proposals: [],
          runs: [],
        },
      },
    },
  );
  assert.equal(candidate.decision, "mintable", candidate.activationBlockers.join("\n"));
  assert.equal(candidate.rollbackRestoreCanary.status, "passed");
  assert.equal(candidate.rollbackRestoreCanary.hashVerified, true);
  assert.equal(candidate.rollbackRestoreCanary.receiptBindingRef, "workflow_restore_canary:git-verified");
  assert.ok(candidate.rollbackRestoreCanary.evidenceRefs.includes("workflow_restore_canary:git-verified"));
  assert.equal(candidate.rollbackRestoreCanary.restoredRevision, "abc123");
  assert.equal(
    candidate.gateResults.find((gate) => gate.gateId === "rollback-restore")?.status,
    "passed",
  );

  const blockedCandidate = createWorkflowHarnessActivationCandidate(
    workflow,
    fork.tests,
    readiness,
    [],
    3_200,
  );
  assert.equal(blockedCandidate.decision, "blocked");
  assert.equal(blockedCandidate.rollbackRestoreCanary.status, "blocked");
  assert.equal(
    blockedCandidate.gateResults.find((gate) => gate.gateId === "rollback-restore")?.status,
    "blocked",
  );
  assert.match(
    blockedCandidate.activationBlockers.join("\n"),
    /gate_blocked:rollback-restore/,
  );
  assert.match(
    blockedCandidate.rollbackRestoreCanary.blockers.join("\n"),
    /rollback_restore_canary_not_run/,
  );

  const mismatchCandidate = createWorkflowHarnessActivationCandidate(
    workflow,
    fork.tests,
    readiness,
    [],
    3_250,
    {
      rollbackRestoreResult: {
        restored: false,
        dryRun: true,
        blockers: ["workflow_content_hash_mismatch"],
        workflowPath: rollbackRevisionBinding.workflowPath,
        repoRoot: rollbackRevisionBinding.repoRoot,
        relativeWorkflowPath: ".agents/workflows/git-restore-canary.workflow.json",
        revisionSource: "git",
        restoredRevision: "abc123",
        restoreStrategy: "git_show_file_restore",
        expectedWorkflowContentHash: rollbackRevisionBinding.workflowContentHash,
        actualWorkflowContentHash: "stable-fnv1a32:mismatch",
        hashVerified: false,
        receiptBindingRef: "workflow_restore_canary:git-mismatch",
        fileSha256: "0123456789abcdef",
        bundle: {
          workflowPath: rollbackRevisionBinding.workflowPath,
          testsPath: "/repo/.agents/workflows/git-restore-canary.tests.json",
          proposalsDir: "/repo/.agents/workflows/git-restore-canary.proposals",
          workflow: rollbackWorkflow,
          tests: [],
          proposals: [],
          runs: [],
        },
      },
    },
  );
  assert.equal(mismatchCandidate.decision, "blocked");
  assert.equal(mismatchCandidate.rollbackRestoreCanary.hashVerified, false);
  assert.equal(
    mismatchCandidate.rollbackRestoreCanary.receiptBindingRef,
    "workflow_restore_canary:git-mismatch",
  );
  assert.match(
    mismatchCandidate.rollbackRestoreCanary.blockers.join("\n"),
    /workflow_content_hash_mismatch/,
  );
  assert.match(
    mismatchCandidate.rollbackRestoreCanary.blockers.join("\n"),
    /rollback_restore_canary_hash_mismatch/,
  );
}

{
  const fork = forkDefaultAgentHarnessWorkflow("Git Restore Probe Helper Fork", 4_000);
  const rollbackRevisionBinding = workflowRevisionBindingFor(fork.workflow, {
    workflowPath: "/repo/.agents/workflows/git-restore-probe.workflow.json",
    repoRoot: "/repo",
    branch: "main",
    baseRevision: "base123",
    activatedRevision: "abc123",
    nowMs: 4_025,
  });
  let capturedDryRun = false;
  let capturedExpectedHash = "";
  const probe = await runWorkflowHarnessRollbackRestoreCanaryProbe({
    runtime: {
      async restoreWorkflowRevision(request) {
        capturedDryRun = request.dryRun === true;
        capturedExpectedHash = request.expectedWorkflowContentHash ?? "";
        return {
          restored: true,
          dryRun: request.dryRun,
          blockers: [],
          workflowPath: request.revisionBinding.workflowPath,
          repoRoot: request.revisionBinding.repoRoot,
          relativeWorkflowPath: ".agents/workflows/git-restore-probe.workflow.json",
          revisionSource: "git",
          restoredRevision: request.revisionBinding.activatedRevision,
          restoreStrategy: "git_show_file_restore",
          expectedWorkflowContentHash: request.expectedWorkflowContentHash,
          actualWorkflowContentHash: request.expectedWorkflowContentHash,
          hashVerified: true,
          receiptBindingRef: "workflow_restore_canary:probe-helper",
          fileSha256: "sha256-from-git-show",
          bundle: {
            workflowPath: request.revisionBinding.workflowPath,
            testsPath: "/repo/.agents/workflows/git-restore-probe.tests.json",
            proposalsDir: "/repo/.agents/workflows/git-restore-probe.proposals",
            workflow: fork.workflow,
            tests: [],
            proposals: [],
            runs: [],
          },
        };
      },
    },
    workflowPath: "/repo/.agents/workflows/git-restore-probe.workflow.json",
    rollbackRevisionBinding,
  });
  assert.equal(capturedDryRun, true);
  assert.equal(capturedExpectedHash, rollbackRevisionBinding.workflowContentHash);
  assert.equal(probe.rollbackRestoreBlockers.length, 0);
  assert.equal(probe.rollbackRestoreResult?.restored, true);
  assert.equal(probe.restoreRequest?.dryRun, true);

  const unavailable = await runWorkflowHarnessRollbackRestoreCanaryProbe({
    runtime: {},
    workflowPath: "/repo/.agents/workflows/git-restore-probe.workflow.json",
    rollbackRevisionBinding,
  });
  assert.deepEqual(unavailable.rollbackRestoreBlockers, [
    "rollback_restore_api_unavailable",
  ]);
  assert.equal(unavailable.restoreRequest?.dryRun, true);

  const thrown = await runWorkflowHarnessRollbackRestoreCanaryProbe({
    runtime: {
      async restoreWorkflowRevision() {
        throw new Error("git show failed");
      },
    },
    workflowPath: "/repo/.agents/workflows/git-restore-probe.workflow.json",
    rollbackRevisionBinding,
  });
  assert.deepEqual(thrown.rollbackRestoreBlockers, [
    "rollback_restore_canary_failed",
    "git show failed",
  ]);

  const metadataOnly = await runWorkflowHarnessRollbackRestoreCanaryProbe({
    runtime: {
      async restoreWorkflowRevision() {
        throw new Error("metadata-only path should not call restore");
      },
    },
    workflowPath: "/repo/.agents/workflows/git-restore-probe.workflow.json",
    rollbackRevisionBinding: workflowRevisionBindingFor(fork.workflow, {
      revisionSource: "file_hash_only",
      nowMs: 4_050,
    }),
  });
  assert.equal(metadataOnly.rollbackRestoreResult, null);
  assert.deepEqual(metadataOnly.rollbackRestoreBlockers, []);
  assert.equal(metadataOnly.restoreRequest, undefined);
}

console.log("harness workflow activation tests passed");
