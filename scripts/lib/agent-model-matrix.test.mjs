import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  normalizeAgentModelMatrixView,
  renderAgentModelMatrixMarkdown,
} from "./agent-model-matrix.mjs";

test("normalizeAgentModelMatrixView supplies stable defaults", () => {
  const view = normalizeAgentModelMatrixView(
    {
      status: "partial",
      decision: { summary: "keep the baseline", outcome: "keep_default" },
      presets: [
        {
          presetId: "ollama-openai",
          label: "Baseline",
          scorecards: {
            artifactQuality: {
              available: true,
              metrics: { averageJudgeScore: 0.5 },
            },
          },
        },
      ],
    },
    process.cwd(),
  );

  assert.equal(view.status, "partial");
  assert.equal(view.presets[0].presetId, "ollama-openai");
  assert.equal(
    view.presets[0].scorecards.artifactQuality.metrics.averageJudgeScore,
    0.5,
  );
  assert.equal(view.presets[0].scorecards.codingCompletion.available, false);
});

test("renderAgentModelMatrixMarkdown includes the decision and preset table", () => {
  const markdown = renderAgentModelMatrixMarkdown({
    status: "ready",
    runId: "run-1",
    generatedAt: "2026-03-31T12:00:00.000Z",
    decision: {
      outcome: "keep_default",
      summary: "Artifact-only evidence is not enough for promotion.",
      missingCoverage: ["coding_completion", "research_quality"],
    },
    presets: [
      {
        presetId: "ollama-openai",
        label: "Baseline",
        role: "baseline_local",
        availabilityStatus: "ready",
        scorecards: {
          artifactQuality: {
            available: true,
            metrics: {
              averageJudgeScore: 0.45,
              verifierPassRate: 0.33,
            },
          },
          codingCompletion: {
            available: true,
            metrics: {
              taskPassRate: 1,
            },
          },
          researchQuality: {
            available: true,
            metrics: {
              citationVerifierPassRate: 0.5,
            },
          },
          computerUseCompletion: {
            available: false,
            metrics: {},
          },
          latencyAndResourcePressure: {
            available: true,
            metrics: {
              meanWallClockMs: 1234,
            },
          },
        },
      },
    ],
  });

  assert.match(markdown, /Artifact-only evidence is not enough for promotion/);
  assert.match(markdown, /\| preset \| deployment \| role \| base model \|/);
  assert.match(
    markdown,
    /artifacts \| coding \| research \| computer use \| tool\/api \| general agent \| latency \| conformance/,
  );
  assert.match(markdown, /\| Baseline \| local_cpu_consumer \| baseline_local \|/);
});

test("normalizeAgentModelMatrixView preserves interrupted-run summary semantics", () => {
  const fixture = JSON.parse(
    fs.readFileSync(
      new URL("./fixtures/agent-model-matrix-interrupted.json", import.meta.url),
      "utf8",
    ),
  );

  const view = normalizeAgentModelMatrixView(fixture, process.cwd());

  assert.equal(view.status, "blocked");
  assert.equal(view.runAbortReason, "Run interrupted by SIGINT.");
  assert.equal(view.plannedPresetCount, 2);
  assert.equal(view.summarizedPresetCount, 2);
  assert.equal(view.fullyCompletedPresetCount, 1);
  assert.equal(view.comparedPresetCount, 2);
  assert.equal(view.executedPresetCount, 2);
  assert.equal(view.presets[0].deploymentProfile, "local_gpu_8gb_class");
  assert.equal(view.presets[1].deploymentProfile, "local_gpu_8gb_class");
  assert.equal(view.candidateLedger.length, 2);
  assert.equal(view.candidateLedger[1].status, "candidate");
  assert.equal(view.candidateLedger[1].evidenceLinks.length, 2);
  assert.equal(view.candidateLedger[1].comparisonIntent, "model_change");
  assert.equal(view.candidateLedger[1].executionScope, "fleet_shared");
});
