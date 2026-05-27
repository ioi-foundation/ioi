#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-currentness-retrieval-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path>",
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
const agentQueries = queries.filter((query) => query.expectedExecutionMode === "agent");
const askQueries = queries.filter((query) => query.expectedExecutionMode === "ask");
const maxPromptDurationMs = Math.max(...queries.map((query) => query.durationMs ?? 0));
const observedToolNames = daemonTrace.observedToolNames ?? [];
const failedToolNames = daemonTrace.failedToolNames ?? [];
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];

assert.equal(hardeningProof.scenarioId, "stage3-currentness-retrieval-gate");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.targetStudioAskModeDirectModelAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 3);
assert.equal(agentQueries.length, 2);
assert.equal(askQueries.length, 1);
assert.ok(maxPromptDurationMs > 0 && maxPromptDurationMs <= 30_000);
assert.ok(agentQueries.every((query) => query.modelBackedStreamObserved === false));
assert.equal(askQueries[0].modelBackedStreamObserved, true);
assert.match(agentQueries[0].assistantText, /AKT/i);
assert.match(agentQueries[0].assistantText, /Filecoin/i);
assert.match(agentQueries[0].assistantText, /Citations?:/i);
assert.match(agentQueries[1].assistantText, /Current snapshot|retrieved current sources|Fresh evidence/i);
assert.match(askQueries[0].assistantText, /fresh retrieval/i);
assert.match(askQueries[0].assistantText, /stale model memory/i);
assert.ok(includesAll(observedToolNames, ["web__search", "web__read", "chat__reply"]));
assert.deepEqual(failedToolNames, []);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage63.live-currentness-retrieval-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    twoAgentCurrentnessQueriesRenderedDistinctAnswers: new Set(agentQueries.map((query) => query.assistantText)).size === 2,
    askModeFailedClosedWithoutTools:
      askQueries[0].executionMode === "ask" &&
      askQueries[0].modelBackedStreamObserved === true &&
      /stale model memory/i.test(askQueries[0].assistantText),
    agentRetrievalTraceObserved: includesAll(observedToolNames, ["web__search", "web__read", "chat__reply"]),
    noTraceToolFailures: failedToolNames.length === 0,
    maxPromptUnderThirtySeconds: maxPromptDurationMs <= 30_000,
    hardeningAfterCleanupClean: hardeningAfterCleanup.ok === true && (hardeningAfterCleanup.after?.length ?? 0) === 0,
    campaignAfterCleanupClean: campaignAfterCleanup.ok === true && (campaignAfterCleanup.after?.length ?? 0) === 0,
    screenshotsCaptured: screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists),
  },
  metrics: {
    queryCount: queries.length,
    askQueryCount: askQueries.length,
    agentQueryCount: agentQueries.length,
    maxPromptDurationMs,
    promptDurationsMs: queries.map((query) => ({
      kind: query.kind,
      expectedExecutionMode: query.expectedExecutionMode,
      durationMs: query.durationMs,
    })),
    modelInvocationReceiptCount: hardeningProof.modelInvocationReceiptCount ?? 0,
    observedToolNames,
    completedToolNames: daemonTrace.completedToolNames ?? [],
    failedToolNames,
  },
  queries: queries.map((query) => ({
    kind: query.kind,
    prompt: query.prompt,
    expectedExecutionMode: query.expectedExecutionMode,
    executionMode: query.executionMode,
    durationMs: query.durationMs,
    modelBackedStreamObserved: query.modelBackedStreamObserved,
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
