import assert from "node:assert/strict";
import type {
  WorkflowHarnessWorkerBinding,
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph.ts";
import {
  applyWorkflowHarnessActivationCandidate,
  executeWorkflowHarnessPromotionTransition,
  executeWorkflowHarnessRollbackDrill,
  executeWorkflowHarnessReplayDrill,
  executeWorkflowHarnessReplayGate,
  executeWorkflowHarnessRevisionRollback,
  forkDefaultAgentHarnessWorkflow,
  makeHarnessCanaryExecutionBoundaries,
  makeHarnessForkActivationRecord,
  recordWorkflowHarnessActivationDryRun,
  recordWorkflowHarnessRollbackTargetSelection,
  runWorkflowHarnessRollbackRestoreCanaryProbe,
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
