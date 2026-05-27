#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];
const schemaVersion = outputPath?.includes("stage82")
  ? "ioi.autopilot.stage82.post-refactor-repo-aware-live-summary-proof.v1"
  : "ioi.autopilot.stage64.live-repo-aware-read-search-summary-proof.v1";

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-repo-aware-read-search-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path>",
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function includesAll(values = [], expected = []) {
  const set = new Set(values);
  return expected.every((value) => set.has(value));
}

const hardeningProof = readJson(hardeningProofPath);
const hardeningEvidenceDir = path.dirname(hardeningProofPath);
const hardeningAfterCleanupPath = path.join(hardeningEvidenceDir, "process-cleanup-after-run.json");
const daemonTracePath = path.join(hardeningEvidenceDir, "daemon-runtime-trace-summary.json");
const hardeningAfterCleanup = readJson(hardeningAfterCleanupPath);
const campaignAfterCleanup = readJson(campaignCleanupPath);
const daemonTrace = readJson(daemonTracePath);
const queries = Array.isArray(hardeningProof.queriesTested) ? hardeningProof.queriesTested : [];
const maxPromptDurationMs = Math.max(...queries.map((query) => query.durationMs ?? 0));
const observedToolNames = daemonTrace.observedToolNames ?? [];
const completedToolNames = daemonTrace.completedToolNames ?? [];
const failedToolNames = daemonTrace.failedToolNames ?? [];
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];

assert.equal(hardeningProof.scenarioId, "stage4-repo-aware-read-search");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 3);
assert.ok(queries.every((query) => query.expectedExecutionMode === "agent"));
assert.ok(queries.every((query) => query.modelBackedStreamObserved === false));
assert.ok(maxPromptDurationMs > 0 && maxPromptDurationMs <= 30_000);
assert.ok(includesAll(observedToolNames, ["file__read", "file__search", "chat__reply"]));
assert.ok(includesAll(completedToolNames, ["file__read", "file__search", "chat__reply"]));
assert.deepEqual(failedToolNames, []);
assert.match(queries[0].assistantText, /\.internal\/plans/i);
assert.match(queries[1].assistantText, /packages\/runtime-daemon\/src\/model-mounting\.mjs/);
assert.match(queries[1].assistantText, /provider\.autopilot\.local/);
assert.match(queries[2].assistantText, /apps\/autopilot\/openvscode-extension\/ioi-workbench\/extension\.js/);
assert.match(queries[2].assistantText, /chat\.agentMode\.select/);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion,
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    allQueriesAgentHarness: queries.every((query) => query.expectedExecutionMode === "agent"),
    repoFileToolsObserved: includesAll(observedToolNames, ["file__read", "file__search"]),
    repoFileToolsCompleted: includesAll(completedToolNames, ["file__read", "file__search"]),
    noTraceToolFailures: failedToolNames.length === 0,
    maxPromptUnderThirtySeconds: maxPromptDurationMs <= 30_000,
    hardeningAfterCleanupClean: hardeningAfterCleanup.ok === true && (hardeningAfterCleanup.after?.length ?? 0) === 0,
    campaignAfterCleanupClean: campaignAfterCleanup.ok === true && (campaignAfterCleanup.after?.length ?? 0) === 0,
    screenshotsCaptured: screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists),
  },
  metrics: {
    queryCount: queries.length,
    maxPromptDurationMs,
    promptDurationsMs: queries.map((query) => ({
      kind: query.kind,
      durationMs: query.durationMs,
    })),
    modelInvocationReceiptCount: hardeningProof.modelInvocationReceiptCount ?? 0,
    observedToolNames,
    completedToolNames,
    failedToolNames,
  },
  queries: queries.map((query) => ({
    kind: query.kind,
    prompt: query.prompt,
    expectedExecutionMode: query.expectedExecutionMode,
    executionMode: query.executionMode,
    durationMs: query.durationMs,
    assistantText: query.assistantText,
  })),
  artifacts: {
    daemonTracePath,
    hardeningAfterCleanupPath,
    campaignCleanupPath,
    screenshots: screenshots.map((screenshot) => screenshot.file),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
