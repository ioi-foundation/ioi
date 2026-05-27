#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-code-review-patch-proposal-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path>",
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function includesAll(values = [], expected = []) {
  const set = new Set(values);
  return expected.every((value) => set.has(value));
}

const mutationToolPattern = /^(file__(write|edit|multi_edit|move|copy)|shell__run|shell__start|patch__apply)$/;
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
const mutationToolsObserved = observedToolNames.filter((tool) => mutationToolPattern.test(tool));

assert.equal(hardeningProof.scenarioId, "stage5-code-review-patch-proposal");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 3);
assert.ok(queries.every((query) => query.expectedExecutionMode === "agent"));
assert.ok(maxPromptDurationMs > 0 && maxPromptDurationMs <= 30_000);
assert.ok(includesAll(observedToolNames, ["file__read", "file__search", "chat__reply"]));
assert.ok(includesAll(completedToolNames, ["file__read", "file__search", "chat__reply"]));
assert.deepEqual(failedToolNames, []);
assert.deepEqual(mutationToolsObserved, []);
assert.match(queries[0].assistantText, /Findings/i);
assert.match(queries[0].assistantText, /success_path\.rs/);
assert.match(queries[0].assistantText, /tool_history_message_content/);
assert.match(queries[1].assistantText, /Smallest patch/i);
assert.match(queries[1].assistantText, /Tool Output/);
assert.match(queries[2].assistantText, /non_browser_tool_history_is_prefixed_for_next_model_turn/);
assert.match(queries[2].assistantText, /tool_history_prefix_is_not_duplicated/);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage65.live-code-review-patch-proposal-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    groundedFileToolsCompleted: includesAll(completedToolNames, ["file__read", "file__search"]),
    noTraceToolFailures: failedToolNames.length === 0,
    noMutationToolsObserved: mutationToolsObserved.length === 0,
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
