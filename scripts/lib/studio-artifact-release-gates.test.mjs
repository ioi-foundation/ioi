import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import test from "node:test";

import {
  collectStudioArtifactReleaseGates,
  collectStudioArtifactReleaseGatesView,
  writeStudioArtifactReleaseGates,
} from "./studio-artifact-release-gates.mjs";

function buildCorpusSummary(metricOverrides = {}) {
  return {
    benchmarkSuite: {
      metrics: {
        readyRate: {
          value: 0.91,
          available: true,
          method: "ready rate",
          supportingBenchmarkIds: ["html-quantum-explainer"],
        },
        averageValidationScore: {
          value: 0.87,
          available: true,
          method: "validation score",
          supportingBenchmarkIds: ["html-quantum-explainer"],
        },
        screenshotQualityScore: {
          value: null,
          available: false,
          method: "missing render evaluation",
          supportingBenchmarkIds: [],
        },
        humanPreferenceScore: {
          value: 0.58,
          available: true,
          method: "blind pairwise win rate",
          supportingBenchmarkIds: ["html-quantum-explainer"],
        },
        shimRequiredRate: {
          value: 0.08,
          available: true,
          method: "shim rate",
          supportingBenchmarkIds: ["html-quantum-explainer"],
        },
        varianceAcrossRepeatedRuns: {
          value: 0.12,
          available: true,
          method: "repeat variance",
          supportingBenchmarkIds: ["html-quantum-explainer"],
        },
        ...metricOverrides,
      },
    },
  };
}

test("release gates evaluate benchmark metrics and conformance checks into pass, fail, and pending states", () => {
  const report = collectStudioArtifactReleaseGates({
    repoRoot: "/tmp/repo",
    evidenceRoot: "/tmp/repo/docs/evidence/studio-artifact-surface",
    config: {
      version: 1,
      gates: [
        {
          id: "ready_rate",
          label: "Ready rate",
          source: { kind: "benchmark_metric", metricId: "readyRate" },
          operator: "minimum",
          shipThreshold: 0.95,
          ratchetFloor: 0.8,
          minImprovementDelta: 0.02,
          required: true,
        },
        {
          id: "screenshot_quality_score",
          label: "Screenshot quality score",
          source: { kind: "benchmark_metric", metricId: "screenshotQualityScore" },
          operator: "minimum",
          shipThreshold: 0.8,
          ratchetFloor: 0.75,
          minImprovementDelta: 0.02,
          required: true,
        },
        {
          id: "lexical_routing_regressions",
          label: "Lexical routing regressions",
          source: {
            kind: "conformance_failed_checks",
            checkIds: ["benchmark_specific_routing", "skill_name_routing"],
          },
          operator: "maximum",
          shipThreshold: 0,
          ratchetFloor: 0,
          minImprovementDelta: 0,
          required: true,
        },
      ],
    },
    corpusSummary: buildCorpusSummary(),
    conformanceReport: {
      checks: [
        { id: "benchmark_specific_routing", status: "pass" },
        { id: "skill_name_routing", status: "pass" },
      ],
    },
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(report.status, "fail");
  assert.equal(report.passing, false);
  assert.deepEqual(report.summary.blockingGateIds.sort(), [
    "ready_rate",
    "screenshot_quality_score",
  ]);

  const readyGate = report.gates.find((gate) => gate.id === "ready_rate");
  const screenshotGate = report.gates.find(
    (gate) => gate.id === "screenshot_quality_score",
  );
  const lexicalGate = report.gates.find(
    (gate) => gate.id === "lexical_routing_regressions",
  );

  assert.equal(readyGate.status, "fail");
  assert.equal(readyGate.ratchet.status, "eligible_raise_floor");
  assert.equal(readyGate.ratchet.candidateFloor, 0.91);
  assert.equal(screenshotGate.status, "pending_measurement");
  assert.equal(lexicalGate.status, "pass");
});

test("release gates writer persists a report and exposes a summarized view", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-release-gates-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    fs.mkdirSync(evidenceRoot, { recursive: true });
    fs.writeFileSync(
      path.join(evidenceRoot, "corpus-summary.json"),
      JSON.stringify(buildCorpusSummary(), null, 2),
    );
    fs.writeFileSync(
      path.join(evidenceRoot, "conformance-report.json"),
      JSON.stringify(
        {
          checks: [
            { id: "benchmark_specific_routing", status: "pass" },
            { id: "skill_name_routing", status: "pass" },
          ],
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(
      path.join(evidenceRoot, "release-gates.config.json"),
      JSON.stringify(
        {
          version: 1,
          gates: [
            {
              id: "pairwise_win_rate",
              label: "Pairwise win rate",
              source: { kind: "benchmark_metric", metricId: "humanPreferenceScore" },
              operator: "minimum",
              shipThreshold: 0.55,
              ratchetFloor: 0.5,
              minImprovementDelta: 0.02,
              required: true,
            },
          ],
        },
        null,
        2,
      ),
    );

    const { reportPath, report } = writeStudioArtifactReleaseGates({
      repoRoot: root,
      evidenceRoot,
      now: "2026-03-31T13:00:00.000Z",
    });

    assert.equal(fs.existsSync(reportPath), true);
    assert.equal(report.status, "pass");
    assert.deepEqual(report.summary.blockingGateIds, []);

    const view = collectStudioArtifactReleaseGatesView({
      repoRoot: root,
      evidenceRoot,
      reportPath,
    });

    assert.equal(view.status, "pass");
    assert.equal(view.passing, true);
    assert.equal(view.gateCount, 1);
    assert.equal(view.passCount, 1);
    assert.equal(view.failCount, 0);
    assert.equal(view.pendingCount, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
