#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];

if (!outputPath || !hardeningProofPath) {
  throw new Error(
    "usage: workflow-live-ask-agent-submission-summary-proof.mjs <output-path> <hardening-proof-path>",
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

const hardeningProof = readJson(hardeningProofPath);
const evidenceDir = path.dirname(hardeningProofPath);
const afterCleanupPath = path.join(evidenceDir, "process-cleanup-after-run.json");
const daemonTracePath = path.join(evidenceDir, "daemon-runtime-trace-summary.json");
const afterCleanup = readJson(afterCleanupPath);
const daemonTrace = readJson(daemonTracePath);
const queries = Array.isArray(hardeningProof.queriesTested) ? hardeningProof.queriesTested : [];
const askQueries = queries.filter((query) => query.expectedExecutionMode === "ask");
const agentQueries = queries.filter((query) => query.expectedExecutionMode === "agent");
const firstPromptDurationMs = queries[0]?.durationMs ?? null;
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];

assert.equal(hardeningProof.scenarioId, "stage62-live-ask-agent-boundary");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAskModeDirectModelAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 2);
assert.equal(askQueries.length, 1);
assert.equal(agentQueries.length, 1);
assert.ok(firstPromptDurationMs > 0 && firstPromptDurationMs <= 30_000);
assert.equal(askQueries[0].modelBackedStreamObserved, true);
assert.equal(agentQueries[0].modelBackedStreamObserved, false);
assert.match(askQueries[0].assistantText, /right triangle/i);
assert.match(agentQueries[0].assistantText, /evidence/i);
assert.match(agentQueries[0].assistantText, /dismiss/i);
assert.equal(afterCleanup.ok, true);
assert.equal(afterCleanup.after?.length ?? 0, 0);
assert.ok((daemonTrace.observedToolNames ?? []).includes("chat__reply"));
assert.ok((daemonTrace.completedToolNames ?? []).includes("chat__reply"));
assert.ok(screenshots.some((screenshot) => screenshot.file === "after-prompt-submission.png" && screenshot.exists));
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage62.live-ask-agent-submission-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir: evidenceDir,
  checks: {
    liveScenarioPassed: true,
    askSubmittedAndStreamed: askQueries[0].executionMode === "ask" && askQueries[0].modelBackedStreamObserved,
    agentSubmittedAndUsedFinalReply:
      agentQueries[0].executionMode === "agent" &&
      agentQueries[0].assistantText.length > 0 &&
      agentQueries[0].modelBackedStreamObserved === false,
    firstPromptUnderThirtySeconds: firstPromptDurationMs <= 30_000,
    daemonChatReplyObserved: (daemonTrace.completedToolNames ?? []).includes("chat__reply"),
    afterCleanupClean: afterCleanup.ok === true && (afterCleanup.after?.length ?? 0) === 0,
    screenshotsCaptured: screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists),
  },
  metrics: {
    queryCount: queries.length,
    askQueryCount: askQueries.length,
    agentQueryCount: agentQueries.length,
    firstPromptDurationMs,
    maxPromptDurationMs: Math.max(...queries.map((query) => query.durationMs ?? 0)),
    modelInvocationReceiptCount: hardeningProof.modelInvocationReceiptCount ?? 0,
    observedToolNames: daemonTrace.observedToolNames ?? [],
    completedToolNames: daemonTrace.completedToolNames ?? [],
    failedToolNames: daemonTrace.failedToolNames ?? [],
  },
  queries: queries.map((query) => ({
    kind: query.kind,
    prompt: query.prompt,
    expectedExecutionMode: query.expectedExecutionMode,
    executionMode: query.executionMode,
    durationMs: query.durationMs,
    modelBackedStreamObserved: query.modelBackedStreamObserved,
    assistantText: query.assistantText,
    bridgeRequestType: query.requestType,
  })),
  artifacts: {
    screenshots: screenshots.map((screenshot) => screenshot.file),
    afterCleanupPath,
    daemonTracePath,
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
