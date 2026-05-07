import assert from "node:assert/strict";
import type {
  WorkflowHarnessWorkerBinding,
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph.ts";
import {
  applyWorkflowHarnessActivationCandidate,
  executeWorkflowHarnessRollbackDrill,
  executeWorkflowHarnessRevisionRollback,
  forkDefaultAgentHarnessWorkflow,
  makeHarnessForkActivationRecord,
  recordWorkflowHarnessActivationDryRun,
  recordWorkflowHarnessRollbackTargetSelection,
  runWorkflowHarnessRollbackRestoreCanaryProbe,
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
  const workflow: WorkflowProject = {
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
  };
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
    result.workflow.metadata.harness?.activationAudit?.map((event) => event.eventType),
    [
      "dry_run_mintable",
      "rollback_target_selected",
      "activation_minted",
    ],
  );
  const activationAudit = result.workflow.metadata.harness?.activationAudit ?? [];
  assert.ok(activationAudit[0]?.receiptRefs.includes(mintableReceiptRef));
  assert.ok(activationAudit[2]?.receiptRefs.includes(mintableReceiptRef));

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
  const workflow: WorkflowProject = {
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
  };
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
