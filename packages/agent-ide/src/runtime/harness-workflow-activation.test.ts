import assert from "node:assert/strict";
import type {
  WorkflowHarnessWorkerBinding,
  WorkflowProject,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph.ts";
import {
  applyWorkflowHarnessActivationCandidate,
  forkDefaultAgentHarnessWorkflow,
  makeHarnessForkActivationRecord,
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
  const result = applyWorkflowHarnessActivationCandidate(fork.workflow, candidate, {
    nowMs: 1_200,
  });

  assert.equal(candidate.decision, "blocked");
  assert.equal(result.applied, false);
  assert.match(result.blockers.join(","), /candidate_not_mintable/);
  assert.equal(result.workflow.metadata.harness?.activationState, "blocked");
  assert.equal(result.workflow.metadata.workerHarnessBinding?.harnessActivationId, undefined);
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
  const result = applyWorkflowHarnessActivationCandidate(workflow, candidate, {
    rollbackTarget: "legacy_runtime",
    nowMs: 2_200,
  });

  assert.equal(candidate.decision, "mintable", candidate.activationBlockers.join("\n"));
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

console.log("harness workflow activation tests passed");
