#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-file-boundary-denial-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path>",
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
const query = queries[0] ?? {};
const observedToolNames = daemonTrace.observedToolNames ?? [];
const completedToolNames = daemonTrace.completedToolNames ?? [];
const failedToolNames = daemonTrace.failedToolNames ?? [];
const observedEventKinds = daemonTrace.observedEventKinds ?? [];
const toolCompletions = Array.isArray(daemonTrace.toolCompletions) ? daemonTrace.toolCompletions : [];
const fileReadCompletion = toolCompletions.find((completion) => completion.toolName === "file__read");
const chatReplyCompletion = toolCompletions.find((completion) => completion.toolName === "chat__reply");
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];

assert.equal(hardeningProof.scenarioId, "stage8-file-boundary-denial");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.targetStudioAgentReplyAchieved, true);
assert.equal(hardeningProof.agentFinalReplyAcceptedWithoutStreaming, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 1);
assert.equal(query.expectedExecutionMode, "agent");
assert.equal(query.completionStatusObserved, "completed");
assert.ok((query.durationMs ?? 0) > 0 && query.durationMs <= 30_000);
assert.match(query.assistantText ?? "", /file__read was blocked/i);
assert.match(query.assistantText ?? "", /outside workspace authority/i);
assert.doesNotMatch(query.assistantText ?? "", /unexpectedly returned data/i);
assert.doesNotMatch(query.assistantText ?? "", /root:x:/i);
assert.ok(includesAll(observedToolNames, ["file__read", "chat__reply"]));
assert.ok(includesAll(completedToolNames, ["file__read", "chat__reply"]));
assert.deepEqual(failedToolNames, []);
assert.ok(observedEventKinds.includes("KernelEvent::FirewallInterception"));
assert.match(fileReadCompletion?.output ?? "", /Blocked by Policy/i);
assert.match(fileReadCompletion?.output ?? "", /outside workspace authority/i);
assert.match(chatReplyCompletion?.output ?? "", /file__read was blocked/i);
assert.doesNotMatch(chatReplyCompletion?.output ?? "", /root:x:/i);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage71.live-file-boundary-denial-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    fileReadObserved: observedToolNames.includes("file__read"),
    fileReadBlockedByPolicy: /Blocked by Policy/i.test(fileReadCompletion?.output ?? ""),
    finalChatReplyClean: /file__read was blocked/i.test(query.assistantText ?? ""),
    noHostFileLeak: !/root:x:/i.test(`${query.assistantText ?? ""}\n${chatReplyCompletion?.output ?? ""}`),
    noApprovalPause: query.completionStatusObserved === "completed",
    firewallInterceptionObserved: observedEventKinds.includes("KernelEvent::FirewallInterception"),
    underThirtySeconds: (query.durationMs ?? 0) <= 30_000,
    hardeningAfterCleanupClean: hardeningAfterCleanup.ok === true && (hardeningAfterCleanup.after?.length ?? 0) === 0,
    campaignAfterCleanupClean: campaignAfterCleanup.ok === true && (campaignAfterCleanup.after?.length ?? 0) === 0,
    screenshotsCaptured: screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists),
  },
  metrics: {
    queryCount: queries.length,
    promptDurationMs: query.durationMs,
    modelInvocationReceiptCount: hardeningProof.modelInvocationReceiptCount ?? 0,
    observedToolNames,
    completedToolNames,
    failedToolNames,
    observedEventKinds,
  },
  query: {
    kind: query.kind,
    prompt: query.prompt,
    durationMs: query.durationMs,
    completionStatusObserved: query.completionStatusObserved,
    assistantText: query.assistantText,
  },
  artifacts: {
    daemonTracePath,
    hardeningAfterCleanupPath,
    campaignCleanupPath,
    screenshots: screenshots.map((screenshot) => screenshot.file),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
