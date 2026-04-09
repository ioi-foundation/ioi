import assert from "node:assert/strict";
import type { SpotlightPlaybookRunRecord } from "../hooks/useSpotlightPlaybookRuns";
import {
  buildRunStepDependencyStates,
  buildTaskDelegationOverview,
} from "./artifactHubTaskGraphModel.ts";

function sampleRun(
  overrides: Partial<SpotlightPlaybookRunRecord> = {},
): SpotlightPlaybookRunRecord {
  return {
    runId: "run-1",
    parentSessionId: "session-1",
    playbookId: "evidence_audited_patch",
    playbookLabel: "Evidence-Audited Patch",
    status: "running",
    latestPhase: "step_spawned",
    summary: "Delegated implementation is in flight.",
    currentStepId: "implement",
    currentStepLabel: "Patch the workspace",
    activeChildSessionId: "worker-2",
    startedAtMs: 1,
    updatedAtMs: 2,
    completedAtMs: null,
    errorClass: null,
    playbookSummary: "Patch flow",
    mergeContract: {
      successCriteria: "Return a verified patch summary.",
      expectedOutput: "Patch handoff",
      mergeMode: "append summary",
      verificationHint: null,
    },
    steps: [
      {
        stepId: "context",
        label: "Capture repo context",
        summary: "Gather repo context.",
        status: "completed",
        childSessionId: "worker-1",
        templateId: "context_worker",
        workflowId: "repo_context_brief",
        updatedAtMs: 1,
        completedAtMs: 1,
        errorClass: null,
        dependsOnStepIds: [],
        dependsOnLabels: [],
        receipts: [
          {
            eventId: "event-1",
            timestampMs: 1,
            phase: "step_completed",
            status: "completed",
            success: true,
            summary: "Context brief captured.",
            receiptRef: "receipt-1",
            childSessionId: "worker-1",
            templateId: "context_worker",
            workflowId: "repo_context_brief",
            errorClass: null,
            artifactIds: ["artifact-1"],
          },
        ],
      },
      {
        stepId: "implement",
        label: "Patch the workspace",
        summary: "Apply the narrowest patch.",
        status: "running",
        childSessionId: "worker-2",
        templateId: "coder",
        workflowId: "patch_build_verify",
        updatedAtMs: 2,
        completedAtMs: null,
        errorClass: null,
        dependsOnStepIds: ["context"],
        dependsOnLabels: ["Capture repo context"],
        receipts: [],
      },
      {
        stepId: "verify",
        label: "Verify targeted tests",
        summary: "Run targeted verification.",
        status: "pending",
        childSessionId: null,
        templateId: "verifier",
        workflowId: "targeted_test_audit",
        updatedAtMs: null,
        completedAtMs: null,
        errorClass: null,
        dependsOnStepIds: ["implement"],
        dependsOnLabels: ["Patch the workspace"],
        receipts: [],
      },
      {
        stepId: "synthesize",
        label: "Synthesize final patch",
        summary: "Collapse verifier evidence into the parent handoff.",
        status: "pending",
        childSessionId: null,
        templateId: "patch_synthesizer",
        workflowId: "patch_synthesis_handoff",
        updatedAtMs: null,
        completedAtMs: null,
        errorClass: null,
        dependsOnStepIds: ["implement", "verify"],
        dependsOnLabels: ["Patch the workspace", "Verify targeted tests"],
        receipts: [],
      },
    ],
    ...overrides,
  };
}

{
  const dependencyStates = buildRunStepDependencyStates(
    sampleRun({
      currentStepId: "verify",
      steps: sampleRun().steps.map((step) =>
        step.stepId === "implement"
          ? {
              ...step,
              status: "completed",
              receipts: [
                {
                  eventId: "event-2",
                  timestampMs: 2,
                  phase: "step_completed",
                  status: "completed",
                  success: true,
                  summary: "Patch landed.",
                  receiptRef: "receipt-2",
                  childSessionId: "worker-2",
                  templateId: "coder",
                  workflowId: "patch_build_verify",
                  errorClass: null,
                  artifactIds: [],
                },
              ],
            }
          : step,
      ),
    }),
  );

  assert.equal(dependencyStates.get("verify")?.state, "ready");
  assert.equal(dependencyStates.get("verify")?.label, "Ready now");
  assert.equal(
    dependencyStates.get("synthesize")?.label,
    "Waiting on Verify targeted tests",
  );
}

{
  const overview = buildTaskDelegationOverview([sampleRun()]);

  assert.equal(overview.statusLabel, "Delegated work is in flight");
  assert.equal(overview.runCount, 1);
  assert.equal(overview.stepCount, 4);
  assert.equal(overview.activeWorkerCount, 1);
  assert.equal(overview.promotableStepCount, 1);
  assert.equal(overview.artifactBackedStepCount, 1);
  assert.equal(overview.dependencyEdgeCount, 4);
}

{
  const overview = buildTaskDelegationOverview([
    sampleRun({
      status: "blocked",
      steps: sampleRun().steps.map((step) =>
        step.stepId === "implement"
          ? { ...step, status: "blocked", errorClass: "approval_required" }
          : step,
      ),
    }),
  ]);

  assert.equal(overview.statusLabel, "Delegated work needs review");
  assert.equal(overview.blockedStepCount, 1);
  assert.match(overview.detail, /Patch the workspace/);
}

{
  const overview = buildTaskDelegationOverview([]);

  assert.equal(overview.statusLabel, "No delegated graph yet");
  assert.equal(overview.stepCount, 0);
}
