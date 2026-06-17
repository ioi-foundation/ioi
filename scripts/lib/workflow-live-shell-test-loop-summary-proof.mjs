#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-shell-test-loop-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path>",
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
const unexpectedToolNames = observedToolNames.filter(
  (toolName) => !["shell__run", "chat__reply"].includes(toolName),
);
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];

assert.equal(hardeningProof.scenarioId, "stage6-shell-test-loop");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 3);
assert.ok(queries.every((query) => query.expectedExecutionMode === "agent"));
assert.ok(maxPromptDurationMs > 0 && maxPromptDurationMs <= 30_000);
assert.ok(includesAll(observedToolNames, ["shell__run", "chat__reply"]));
assert.ok(includesAll(completedToolNames, ["shell__run", "chat__reply"]));
assert.deepEqual(failedToolNames, []);
assert.deepEqual(unexpectedToolNames, []);
assert.match(queries[0].assistantText, /node --check scripts\/lib\/hypervisor-agent-chat-scenarios\.mjs/);
assert.match(queries[0].assistantText, /exit(?:ed)? with code 0/i);
assert.match(queries[1].assistantText, /non_browser_tool_history_is_prefixed_for_next_model_turn/);
assert.match(queries[1].assistantText, /exit(?:ed)? with code 0/i);
assert.match(queries[2].assistantText, /tool_history_prefix_is_not_duplicated/);
assert.match(queries[2].assistantText, /exit(?:ed)? with code 0/i);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage66.live-shell-test-loop-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    shellToolCompleted: completedToolNames.includes("shell__run"),
    chatReplyCompleted: completedToolNames.includes("chat__reply"),
    noTraceToolFailures: failedToolNames.length === 0,
    noUnexpectedToolsObserved: unexpectedToolNames.length === 0,
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
