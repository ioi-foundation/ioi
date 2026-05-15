import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { buildWorkflowComputerUseTriLaneScorecard } from "./autopilot-gui-harness-validation/computer-use-scorecard.mjs";
import {
  collectWorkflowComputerUseTriLaneScorecard,
  collectWorkflowNativeBrowserPromptPipelineProof,
  collectWorkflowSandboxedComputerRunButtonProof,
  collectWorkflowVisualGuiPromptPipelineProof,
} from "./autopilot-gui-harness-validation/workflow-proofs.mjs";

function collectTriLaneProofs() {
  const outputRoot = mkdtempSync(
    join(tmpdir(), "ioi-computer-use-scorecard-"),
  );
  return {
    outputRoot,
    workflowSandboxedComputerRunButtonProof:
      collectWorkflowSandboxedComputerRunButtonProof(outputRoot),
    workflowNativeBrowserPromptPipelineProof:
      collectWorkflowNativeBrowserPromptPipelineProof(outputRoot),
    workflowVisualGuiPromptPipelineProof:
      collectWorkflowVisualGuiPromptPipelineProof(outputRoot),
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test("computer-use tri-lane scorecard gates retained workflow proofs", () => {
  const {
    outputRoot,
    workflowSandboxedComputerRunButtonProof,
    workflowNativeBrowserPromptPipelineProof,
    workflowVisualGuiPromptPipelineProof,
  } = collectTriLaneProofs();
  const scorecard = collectWorkflowComputerUseTriLaneScorecard(outputRoot, {
    workflowSandboxedComputerRunButtonProof,
    workflowNativeBrowserPromptPipelineProof,
    workflowVisualGuiPromptPipelineProof,
  });

  assert.equal(scorecard.proof.passed, true);
  assert.equal(
    scorecard.proof.scenario,
    "workflow_computer_use_tri_lane_scorecard",
  );
  assert.equal(scorecard.proof.promotionStatus, "passed");
  assert.equal(scorecard.proof.operatorSummary.status, "passed");
  assert.equal(scorecard.proof.operatorSummary.blockers.length, 0);
  assert.deepEqual(
    scorecard.proof.operatorSummary.summaryRows.map((row) => row.status),
    ["passed", "passed", "passed"],
  );
  assert.deepEqual(
    scorecard.proof.operatorSummary.summaryRows.map((row) => row.label),
    ["Native Browser", "Visual GUI", "Sandboxed Hosted"],
  );
  assert.equal(scorecard.proof.scorecard.laneCoverage, 3);
  assert.equal(scorecard.proof.scorecard.promptTraceLanesCovered, 2);
  assert.equal(scorecard.proof.checks.noReactFlowShadowRuntimeTruth, true);
  assert.deepEqual(
    scorecard.proof.laneReports.map((lane) => lane.lane).sort(),
    ["native_browser", "sandboxed_hosted", "visual_gui"],
  );
  const visualLane = scorecard.proof.laneReports.find(
    (lane) => lane.lane === "visual_gui",
  );
  assert.equal(
    visualLane.workbench.policyApprovalRef,
    "approval-visual-gui-run-button",
  );
  assert.equal(visualLane.workbench.executionPreflightStatus, "passed");
  const sandboxLane = scorecard.proof.laneReports.find(
    (lane) => lane.lane === "sandboxed_hosted",
  );
  assert.equal(sandboxLane.workbench.policyFailClosed, true);
  assert.ok(
    scorecard.proof.externalDeferrals.some(
      (deferral) => deferral.id === "hosted_provider_backends",
    ),
  );
});

test("computer-use tri-lane scorecard blocks missing and degraded proof evidence", () => {
  const base = collectTriLaneProofs();
  const cases = [
    {
      name: "missing native browser lane proof",
      mutate(proofs) {
        proofs.workflowNativeBrowserPromptPipelineProof = undefined;
      },
      blockedChecks: ["nativeBrowserProofPassed", "laneCoverageComplete"],
    },
    {
      name: "failed visual GUI lane proof",
      mutate(proofs) {
        proofs.workflowVisualGuiPromptPipelineProof.proof.passed = false;
      },
      blockedChecks: ["visualGuiProofPassed"],
    },
    {
      name: "missing mounted model prompt trace",
      mutate(proofs) {
        proofs.workflowNativeBrowserPromptPipelineProof.proof.requestSummary.modelTracePhases =
          ["input", "binding", "prompt", "model"];
      },
      blockedChecks: ["modelPromptTraceCoverage"],
    },
    {
      name: "missing observation and target evidence",
      mutate(proofs) {
        proofs.workflowVisualGuiPromptPipelineProof.proof.requestSummary.targetCount =
          0;
      },
      blockedChecks: ["observationAndTargetCoverage"],
    },
    {
      name: "missing affordance and proposal evidence",
      mutate(proofs) {
        const summary =
          proofs.workflowNativeBrowserPromptPipelineProof.proof.requestSummary;
        summary.affordanceCount = 0;
        summary.workbench.proposalRef = null;
      },
      blockedChecks: ["affordanceProposalPolicyCoverage"],
    },
    {
      name: "missing approval posture",
      mutate(proofs) {
        const summary =
          proofs.workflowVisualGuiPromptPipelineProof.proof.requestSummary;
        summary.workbench.policyApprovalRef = null;
        summary.workbench.commitGateStatus = null;
      },
      blockedChecks: ["approvalOrFailClosedCoverage"],
    },
    {
      name: "missing sandbox fail-closed posture",
      mutate(proofs) {
        proofs.workflowSandboxedComputerRunButtonProof.proof.requestSummary.workbench.policyFailClosed =
          false;
      },
      blockedChecks: ["approvalOrFailClosedCoverage"],
    },
    {
      name: "missing action verification and cleanup",
      mutate(proofs) {
        const summary =
          proofs.workflowSandboxedComputerRunButtonProof.proof.requestSummary;
        summary.workbench.actionRef = null;
        summary.workbench.verificationStatus = "failed";
        summary.workbench.cleanupStatus = null;
      },
      blockedChecks: ["actionVerificationCleanupCoverage"],
    },
    {
      name: "React Flow shadow runtime truth introduced",
      mutate(proofs) {
        proofs.workflowVisualGuiPromptPipelineProof.proof.checks.noCanvasLocalRuntimeTruth =
          false;
      },
      blockedChecks: ["noReactFlowShadowRuntimeTruth"],
    },
  ];

  for (const scenario of cases) {
    const proofs = {
      workflowSandboxedComputerRunButtonProof: clone(
        base.workflowSandboxedComputerRunButtonProof,
      ),
      workflowNativeBrowserPromptPipelineProof: clone(
        base.workflowNativeBrowserPromptPipelineProof,
      ),
      workflowVisualGuiPromptPipelineProof: clone(
        base.workflowVisualGuiPromptPipelineProof,
      ),
    };
    scenario.mutate(proofs);

    const scorecard = buildWorkflowComputerUseTriLaneScorecard({
      sandboxedComputerRunButtonProof:
        proofs.workflowSandboxedComputerRunButtonProof,
      nativeBrowserPromptPipelineProof:
        proofs.workflowNativeBrowserPromptPipelineProof,
      visualGuiPromptPipelineProof:
        proofs.workflowVisualGuiPromptPipelineProof,
    });

    assert.equal(scorecard.passed, false, scenario.name);
    assert.equal(scorecard.promotionStatus, "blocked", scenario.name);
    assert.equal(scorecard.operatorSummary.status, "blocked", scenario.name);
    assert.ok(scorecard.operatorSummary.blockers.length > 0, scenario.name);
    for (const check of scenario.blockedChecks) {
      assert.equal(scorecard.checks[check], false, `${scenario.name}: ${check}`);
      assert.ok(
        scorecard.operatorSummary.blockers.some(
          (blocker) => blocker.check === check,
        ),
        `${scenario.name}: operator blocker ${check}`,
      );
    }
  }
});
