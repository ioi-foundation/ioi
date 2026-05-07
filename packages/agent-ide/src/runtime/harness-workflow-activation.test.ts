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
  const dryRunAudit = auditedWorkflow.metadata.harness?.activationAudit ?? [];
  assert.equal(dryRunAudit[dryRunAudit.length - 1]?.eventType, "dry_run_blocked");
  assert.equal(result.applied, false);
  assert.match(result.blockers.join(","), /candidate_not_mintable/);
  assert.equal(result.workflow.metadata.harness?.activationState, "blocked");
  assert.equal(result.workflow.metadata.workerHarnessBinding?.harnessActivationId, undefined);
  const blockedMintAudit = result.workflow.metadata.harness?.activationAudit ?? [];
  assert.equal(blockedMintAudit[blockedMintAudit.length - 1]?.eventType, "activation_mint_blocked");
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

  const rollbackDrill = executeWorkflowHarnessRollbackDrill(result.workflow, {
    rollbackTarget: "legacy_runtime",
    nowMs: 2_300,
  });
  assert.equal(rollbackDrill.executed, true);
  assert.equal(rollbackDrill.proof?.drillStatus, "passed");
  assert.equal(rollbackDrill.proof?.rollbackExecuted, true);
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
}

console.log("harness workflow activation tests passed");
