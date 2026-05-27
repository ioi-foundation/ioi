#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const manifestProofPath = process.argv[3];
const cleanupPath = process.argv[4];
const elapsedSeconds = Number(process.argv[5]);
const guidePath =
  process.argv[6] ??
  ".internal/plans/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus-12h-master-guide.md";
const gapListPath =
  process.argv[7] ??
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T05-49-35-354Z-stage9-reverse-engineering-parity-plus/reverse-engineering-parity-plus-gap-list.md";

if (!outputPath || !manifestProofPath || !cleanupPath || !Number.isFinite(elapsedSeconds)) {
  throw new Error(
    "usage: workflow-12h-closeout-proof.mjs <output-path> <manifest-proof-path> <cleanup-path> <elapsed-seconds> [guide-path] [gap-list-path]",
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

const manifestProof = readJson(manifestProofPath);
const cleanup = readJson(cleanupPath);
const guide = readText(guidePath);
const gapList = readText(gapListPath);
const recentStageIds = new Set((manifestProof.recentStages ?? []).map((stage) => stage.stage));

assert.ok(elapsedSeconds >= 43_200, `12-hour floor not met: ${elapsedSeconds}s`);
assert.equal(manifestProof.passed, true);
assert.equal(manifestProof.checks?.recentStagesHavePassingProofs, true);
assert.equal(manifestProof.checks?.recentStagesHaveSuccessfulAfterCleanup, true);
assert.ok((manifestProof.totals?.passedProofCount ?? 0) >= 89);
assert.ok((manifestProof.totals?.afterCleanupOkCount ?? 0) >= 132);
assert.ok(recentStageIds.has("stage80"));
assert.ok(recentStageIds.has("stage82"));
assert.ok(recentStageIds.has("stage88"));
assert.ok(recentStageIds.has("stage90"));
assert.ok(recentStageIds.has("stage92"));
assert.ok(recentStageIds.has("stage94"));
assert.ok(recentStageIds.has("stage96"));
assert.ok(recentStageIds.has("stage98"));
assert.equal(cleanup.ok, true);
assert.equal(cleanup.after?.length ?? 0, 0);
assert.match(guide, /Stage 99: Evidence Manifest Refresh Through Stage 98/);
assert.match(guide, /Stage 100: Final 12-Hour Closeout/);
assert.match(guide, /Done Criteria/);
assert.match(gapList, /Stage 82 Post-refactor repo-aware live proof/);
assert.match(gapList, /Isolated computer provider gap proof/);
assert.match(gapList, /Computer-use SDK contract substrate/);
assert.match(gapList, /Computer-use provider registry spine/);
assert.match(gapList, /Public computer-use provider discovery/);
assert.match(gapList, /Computer-use full regression/);
assert.match(gapList, /Final 12-hour closeout/);

const proof = {
  schemaVersion: "ioi.autopilot.12h-closeout-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  elapsedSeconds,
  checks: {
    twelveHourFloorMet: elapsedSeconds >= 43_200,
    manifestPassed: manifestProof.passed === true,
    latestManifestRequiresStage80: recentStageIds.has("stage80"),
    latestManifestRequiresStage82: recentStageIds.has("stage82"),
    latestManifestRequiresStage88: recentStageIds.has("stage88"),
    latestManifestRequiresStage90: recentStageIds.has("stage90"),
    latestManifestRequiresStage92: recentStageIds.has("stage92"),
    latestManifestRequiresStage94: recentStageIds.has("stage94"),
    latestManifestRequiresStage96: recentStageIds.has("stage96"),
    latestManifestRequiresStage98: recentStageIds.has("stage98"),
    cleanupClean: cleanup.ok === true && (cleanup.after?.length ?? 0) === 0,
    guideUpdatedThroughStage99: /Stage 99: Evidence Manifest Refresh Through Stage 98/.test(guide),
    guideIncludesFinalCloseout: /Stage 100: Final 12-Hour Closeout/.test(guide),
    gapListUpdatedThroughStage98:
      /Isolated computer provider gap proof/.test(gapList) &&
      /Computer-use SDK contract substrate/.test(gapList) &&
      /Computer-use provider registry spine/.test(gapList) &&
      /Public computer-use provider discovery/.test(gapList) &&
      /Computer-use full regression/.test(gapList) &&
      /Final 12-hour closeout/.test(gapList),
  },
  metrics: {
    manifestStageDirectoryCount: manifestProof.totals?.stageDirectoryCount ?? null,
    manifestProofCount: manifestProof.totals?.proofCount ?? null,
    manifestPassedProofCount: manifestProof.totals?.passedProofCount ?? null,
    manifestAfterCleanupOkCount: manifestProof.totals?.afterCleanupOkCount ?? null,
  },
  artifacts: {
    manifestProofPath,
    cleanupPath,
    guidePath,
    gapListPath,
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
