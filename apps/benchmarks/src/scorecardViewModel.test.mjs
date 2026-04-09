import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { normalizeAgentModelMatrixView } from "../../../scripts/lib/agent-model-matrix.mjs";
import { withScorecardPreview } from "./scorecardPreview.ts";
import {
  buildCandidatesViewModel,
  buildDeploymentsViewModel,
  buildScorecardViewModel,
} from "./scorecardViewModel.ts";

const repoRoot = path.resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const fixturePath = new URL(
  "../../../scripts/lib/fixtures/agent-model-matrix-interrupted.json",
  import.meta.url,
);

function loadFixtureMatrix() {
  const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  return normalizeAgentModelMatrixView(fixture, repoRoot);
}

function loadPreviewMatrix() {
  const previewData = withScorecardPreview({
    agentModelMatrix: loadFixtureMatrix(),
  });
  return previewData.agentModelMatrix;
}

test("buildScorecardViewModel surfaces interrupted retained-run counts", () => {
  const matrix = loadFixtureMatrix();
  const viewModel = buildScorecardViewModel(matrix, "2026-04-05T22:50:16.168Z");

  assert.ok(viewModel);
  assert.equal(viewModel.statusLabel, "blocked");
  assert.equal(viewModel.summary, matrix.decision.summary);
  assert.equal(
    viewModel.interruptionLabel,
    "Run interrupted by SIGINT. 1 preset incomplete.",
  );
  assert.equal(viewModel.plannedPresetCount, 2);
  assert.equal(viewModel.summarizedPresetCount, 2);
  assert.equal(viewModel.fullyCompletedPresetCount, 1);
  assert.equal(viewModel.executedPresetCount, 2);
  assert.equal(viewModel.coverageGapCount, 3);
  assert.equal(viewModel.leaderLabel, "Planner-grade local OSS (Qwen3 8B)");
  assert.equal(viewModel.baselineLabel, "Planner-grade local OSS (Qwen3 8B)");
  assert.equal(viewModel.rows.length, 2);
  assert.deepEqual(
    viewModel.rows[0].titleBadges.map((badge) => badge.label),
    ["leader", "default"],
  );
  assert.equal(viewModel.rows[1].label, "Coding executor local OSS");
});

test("buildDeploymentsViewModel separates explicit deployment-profile winners", () => {
  const matrix = loadPreviewMatrix();
  const scorecard = buildScorecardViewModel(matrix, "2026-04-05T22:50:16.168Z");
  const deployments = buildDeploymentsViewModel(matrix, scorecard);

  assert.ok(deployments);
  assert.equal(
    deployments.assignmentNote,
    "Deployment winners, defaults, challengers, and coverage gaps are sourced from retained deployment decisions in the matrix payload.",
  );
  assert.deepEqual(
    deployments.stats.map((entry) => `${entry.label}:${entry.value}`),
    [
      "Profiles covered:3/7",
      "Local default:Planner-grade local OSS (Qwen3 8B)",
      "Overall leader:Blind cloud candidate",
    ],
  );
  const localDefault = deployments.profiles.find(
    (profile) => profile.id === "local_gpu_8gb_class",
  );
  assert.ok(localDefault);
  assert.equal(localDefault.winnerLabel, "Planner-grade local OSS (Qwen3 8B)");
  assert.equal(
    localDefault.summary,
    "Current retained default for this deployment profile.",
  );
  const workstation = deployments.profiles.find(
    (profile) => profile.id === "local_workstation",
  );
  assert.ok(workstation);
  assert.equal(workstation.winnerLabel, "Workstation local candidate");
  assert.equal(
    workstation.summary,
    "Current leading candidate for this deployment profile.",
  );
  const blindCloud = deployments.profiles.find(
    (profile) => profile.id === "blind_cloud_standard",
  );
  assert.ok(blindCloud);
  assert.equal(blindCloud.winnerLabel, "Blind cloud candidate");
  assert.equal(
    blindCloud.summary,
    "Blind-cloud leaders remain shadow-scoped and cannot silently replace local defaults.",
  );
});

test("buildDeploymentsViewModel falls back to inferred deployment assignment", () => {
  const previewMatrix = loadPreviewMatrix();
  const matrix = {
    ...previewMatrix,
    deploymentDecisions: [],
    presets: previewMatrix.presets.map((preset, index) => ({
      ...preset,
      deploymentProfile: null,
      benchmarkTier:
        index === 0 ? "" : preset.benchmarkTier,
      label:
        index === 0 ? "Consumer local baseline" : preset.label,
    })),
  };
  const scorecard = buildScorecardViewModel(matrix, "2026-04-05T22:50:16.168Z");
  const deployments = buildDeploymentsViewModel(matrix, scorecard);

  assert.ok(deployments);
  assert.equal(
    deployments.assignmentNote,
    "Deployment profile assignment is currently inferred from retained preset metadata until the benchmark payload carries an explicit deployment profile field.",
  );
  assert.equal(
    deployments.profiles.find((profile) => profile.id === "local_cpu_consumer")?.winnerLabel,
    "Consumer local baseline",
  );
  assert.equal(
    deployments.profiles.find((profile) => profile.id === "local_workstation")?.winnerLabel,
    "Workstation local candidate",
  );
  assert.equal(
    deployments.profiles.find((profile) => profile.id === "blind_cloud_standard")?.winnerLabel,
    "Blind cloud candidate",
  );
});

test("buildCandidatesViewModel renders retained lineage and validation receipts", () => {
  const matrix = loadPreviewMatrix();
  const scorecard = buildScorecardViewModel(matrix, "2026-04-05T22:50:16.168Z");
  const candidates = buildCandidatesViewModel(matrix, scorecard);

  assert.ok(candidates);
  assert.equal(
    candidates.summary,
    "Candidate review is backed by retained lineage, comparison intent, lane receipts, rollback targets, and conformance status carried in the benchmark payload.",
  );
  assert.equal(
    candidates.assignmentNote,
    "Candidate cards are sourced from the retained candidate ledger in the benchmark payload.",
  );
  assert.deepEqual(
    candidates.stats.map((entry) => `${entry.label}:${entry.value}`),
    [
      "Candidates visible:2",
      "Current baseline:Planner-grade local OSS (Qwen3 8B)",
      "Overall leader:Blind cloud candidate",
    ],
  );
  assert.equal(candidates.candidates.length, 3);

  const workstationCandidate = candidates.candidates.find(
    (candidate) => candidate.id === "candidate:local-workstation-candidate",
  );
  assert.ok(workstationCandidate);
  assert.equal(workstationCandidate.status.label, "promotable");
  assert.equal(workstationCandidate.status.tone, "good");
  assert.equal(workstationCandidate.deploymentLabel, "Workstation local");
  assert.equal(
    workstationCandidate.lineage,
    "Planner-grade local OSS (Qwen3 8B) \u2192 Workstation local candidate",
  );
  assert.deepEqual(
    workstationCandidate.validationReadings.map((entry) => `${entry.label}:${entry.value}`),
    [
      "Required ready:6/6",
      "Best on required:3/6",
      "Coverage:clear",
      "Compare intent:model change",
      "Exec scope:fleet shared",
      "Lane state:proxy retained · validation retained · challenge queued · holdout protected not run",
      "Conformance:pass",
      "Rollback:Planner-grade local OSS (Qwen3 8B)",
      "Deployment:Workstation local",
    ],
  );
  assert.ok(workstationCandidate.touchedSurfaces.includes("role-model assignment"));
  assert.ok(workstationCandidate.touchedSurfaces.includes("role:planner"));
  assert.ok(workstationCandidate.touchedSurfaces.includes("role:verifier"));

  const cloudCandidate = candidates.candidates.find(
    (candidate) => candidate.id === "candidate:blind-cloud-candidate",
  );
  assert.ok(cloudCandidate);
  assert.equal(cloudCandidate.status.label, "shadow winner");
  assert.equal(cloudCandidate.status.tone, "warn");
  assert.equal(cloudCandidate.deploymentLabel, "Blind cloud");
  assert.equal(
    cloudCandidate.lineage,
    "Planner-grade local OSS (Qwen3 8B) \u2192 Blind cloud candidate",
  );
  assert.ok(
    cloudCandidate.regressions[0].includes("Current leader on required families"),
  );
  assert.ok(cloudCandidate.runtimeTags.includes("full stack change"));
});
