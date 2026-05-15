import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  collectWorkflowComputerUseTriLaneScorecard,
  collectWorkflowNativeBrowserPromptPipelineProof,
  collectWorkflowSandboxedComputerRunButtonProof,
  collectWorkflowVisualGuiPromptPipelineProof,
} from "./autopilot-gui-harness-validation/workflow-proofs.mjs";

test("computer-use tri-lane scorecard gates retained workflow proofs", () => {
  const outputRoot = mkdtempSync(
    join(tmpdir(), "ioi-computer-use-scorecard-"),
  );
  const workflowSandboxedComputerRunButtonProof =
    collectWorkflowSandboxedComputerRunButtonProof(outputRoot);
  const workflowNativeBrowserPromptPipelineProof =
    collectWorkflowNativeBrowserPromptPipelineProof(outputRoot);
  const workflowVisualGuiPromptPipelineProof =
    collectWorkflowVisualGuiPromptPipelineProof(outputRoot);

  const scorecard = collectWorkflowComputerUseTriLaneScorecard(outputRoot, {
    workflowSandboxedComputerRunButtonProof,
    workflowNativeBrowserPromptPipelineProof,
    workflowVisualGuiPromptPipelineProof,
  });

  assert.equal(scorecard.proof.passed, true);
  assert.equal(scorecard.proof.scenario, "workflow_computer_use_tri_lane_scorecard");
  assert.equal(scorecard.proof.promotionStatus, "passed");
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
