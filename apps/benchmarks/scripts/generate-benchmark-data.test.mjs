import assert from "node:assert/strict";
import test from "node:test";
import { buildBenchmarkDataPayload } from "./generate-benchmark-data.mjs";

test("buildBenchmarkDataPayload sorts latest cases and focuses suite summaries on the newest run", () => {
  const agentModelMatrix = {
    status: "blocked",
    runAbortReason: "Run interrupted by SIGINT.",
  };
  const payload = buildBenchmarkDataPayload({
    generatedAt: "2026-04-05T22:50:16.168Z",
    latestCases: [
      {
        suite: "Chat Artifacts",
        result: "pass",
        caseId: "artifact-pass",
        runId: "run-pass",
        runSort: 10,
      },
      {
        suite: "Chat Artifacts",
        result: "interrupted",
        caseId: "artifact-interrupted",
        runId: "run-interrupted",
        runSort: 20,
      },
    ],
    liveRuns: [],
    studioArtifactCorpus: { benchmarkSuite: null },
    studioArtifactArena: {},
    studioArtifactReleaseGates: {},
    studioArtifactDistillation: {},
    studioArtifactParityLoop: {},
    agentModelMatrix,
  });

  assert.equal(payload.generatedAt, "2026-04-05T22:50:16.168Z");
  assert.equal(payload.agentModelMatrix, agentModelMatrix);
  assert.deepEqual(
    payload.latestCases.map((entry) => entry.caseId),
    ["artifact-interrupted", "artifact-pass"],
  );
  assert.equal(payload.latestCases[0].result, "interrupted");

  const studioArtifacts = payload.suiteSummaries.find(
    (entry) => entry.suite === "Chat Artifacts",
  );
  assert.ok(studioArtifacts);
  assert.equal(studioArtifacts.counts.pass, 1);
  assert.equal(studioArtifacts.counts.interrupted, 1);
  assert.equal(studioArtifacts.focusCaseId, "artifact-interrupted");
  assert.equal(studioArtifacts.focusResult, "interrupted");
});
