import assert from "node:assert/strict";
import test from "node:test";

import { decisionForRun } from "./run-agent-model-matrix.mjs";

function makeScorecard(metrics) {
  return { available: true, reason: "", metrics };
}

function makePreset({
  presetId,
  label,
  shippedDefault = false,
  experimental = true,
  artifact = {},
  coding = {},
  research = {},
  computer = {},
  latency = {},
}) {
  return {
    presetId,
    label,
    shippedDefault,
    experimental,
    scorecards: {
      artifactQuality: makeScorecard({
        passRate: 0,
        averageJudgeScore: 0,
        verifierPassRate: 0,
        routeMatchRate: 0,
        averageRepairLoopIterations: 0,
        ...artifact,
      }),
      codingCompletion: makeScorecard({
        taskPassRate: 0,
        targetedTestPassRate: 0,
        verifierPassRate: 0,
        patchSynthesisReadyRate: 0,
        ...coding,
      }),
      researchQuality: makeScorecard({
        citationVerifierPassRate: 0,
        sourceIndependenceRate: 0,
        synthesisCompleteness: 0,
        freshnessPassRate: 0,
        quoteGroundingPassRate: 0,
        ...research,
      }),
      computerUseCompletion: makeScorecard({
        rewardFloorPassRate: 0,
        postconditionPassRate: 0,
        meanStepCount: 0,
        ...computer,
      }),
      latencyAndResourcePressure: makeScorecard({
        meanWallClockMs: 100,
        p95WallClockMs: 120,
        residentModelBytes: null,
        processorKind: "GPU",
        ...latency,
      }),
    },
  };
}

test("decisionForRun keeps the default when a challenger regresses latency", () => {
  const decision = decisionForRun([
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageJudgeScore: 0.1 },
      latency: { meanWallClockMs: 100, p95WallClockMs: 120 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageJudgeScore: 0.1 },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 220, p95WallClockMs: 260 },
    }),
  ]);

  assert.equal(decision.outcome, "keep_default");
  assert.equal(decision.leaderPresetId, "baseline");
  assert.match(decision.summary, /shipped default still holds/i);
});

test("decisionForRun does not promote on a single challenger win", () => {
  const decision = decisionForRun([
    makePreset({
      presetId: "baseline",
      label: "Baseline",
      shippedDefault: true,
      experimental: false,
      artifact: { averageJudgeScore: 0.1 },
      latency: { meanWallClockMs: 180, p95WallClockMs: 220 },
    }),
    makePreset({
      presetId: "challenger",
      label: "Challenger",
      artifact: { averageJudgeScore: 0.8, verifierPassRate: 1, passRate: 1 },
      coding: {
        taskPassRate: 1,
        targetedTestPassRate: 1,
        verifierPassRate: 1,
        patchSynthesisReadyRate: 1,
      },
      research: {
        citationVerifierPassRate: 1,
        sourceIndependenceRate: 1,
        synthesisCompleteness: 1,
        freshnessPassRate: 1,
        quoteGroundingPassRate: 1,
      },
      computer: { rewardFloorPassRate: 1, postconditionPassRate: 1 },
      latency: { meanWallClockMs: 90, p95WallClockMs: 110 },
    }),
  ]);

  assert.equal(decision.outcome, "keep_default");
  assert.equal(decision.leaderPresetId, "challenger");
  assert.match(decision.summary, /wins repeatedly across retained runs/i);
});
