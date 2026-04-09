import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { normalizeAgentModelMatrixView } from "../../../scripts/lib/agent-model-matrix.mjs";
import { buildBenchmarkDataPayload } from "./generate-benchmark-data.mjs";

const repoRoot = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const fixturePath = new URL(
  "../../../scripts/lib/fixtures/agent-model-matrix-interrupted.json",
  import.meta.url,
);

function loadInterruptedMatrixFixture() {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  return normalizeAgentModelMatrixView(fixture, repoRoot);
}

test("buildBenchmarkDataPayload preserves interrupted matrix and suite counts", () => {
  const payload = buildBenchmarkDataPayload({
    generatedAt: "2026-04-05T22:50:16.168Z",
    latestCases: [
      {
        suite: "Studio Artifacts",
        result: "pass",
        caseId: "artifact-pass",
        runId: "run-pass",
        runSort: 10,
      },
      {
        suite: "Studio Artifacts",
        result: "interrupted",
        caseId: "artifact-interrupted",
        runId: "run-interrupted",
        runSort: 20,
      },
    ],
    liveRuns: [],
    studioArtifactCorpus: { benchmarkSuite: null },
    studioArtifactArena: null,
    studioArtifactReleaseGates: null,
    studioArtifactDistillation: null,
    studioArtifactParityLoop: null,
    agentModelMatrix: loadInterruptedMatrixFixture(),
  });

  assert.equal(payload.generatedAt, "2026-04-05T22:50:16.168Z");
  assert.equal(payload.agentModelMatrix.runAbortReason, "Run interrupted by SIGINT.");
  assert.equal(payload.agentModelMatrix.plannedPresetCount, 2);
  assert.equal(payload.agentModelMatrix.summarizedPresetCount, 2);
  assert.equal(payload.agentModelMatrix.fullyCompletedPresetCount, 1);
  assert.equal(payload.agentModelMatrix.candidateLedger.length, 2);
  assert.equal(payload.latestCases[0].result, "interrupted");

  const studioArtifacts = payload.suiteSummaries.find(
    (entry) => entry.suite === "Studio Artifacts",
  );
  assert.ok(studioArtifacts);
  assert.equal(studioArtifacts.counts.pass, 1);
  assert.equal(studioArtifacts.counts.interrupted, 1);
  assert.equal(studioArtifacts.focusCaseId, "artifact-interrupted");
  assert.equal(studioArtifacts.focusResult, "interrupted");
});
