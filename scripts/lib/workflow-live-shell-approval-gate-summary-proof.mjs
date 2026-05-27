#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const hardeningProofPath = process.argv[3];
const campaignCleanupPath = process.argv[4];
const deniedMarkerPath = process.argv[5] || "/tmp/ioi-stage67-policy-denied";

if (!outputPath || !hardeningProofPath || !campaignCleanupPath) {
  throw new Error(
    "usage: workflow-live-shell-approval-gate-summary-proof.mjs <output-path> <hardening-proof-path> <campaign-after-cleanup-path> [denied-marker-path]",
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
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
const screenshots = Array.isArray(hardeningProof.screenshots) ? hardeningProof.screenshots : [];
const deniedMarkerExists = fs.existsSync(deniedMarkerPath);

assert.equal(hardeningProof.scenarioId, "stage7-shell-policy-denial-recovery");
assert.equal(hardeningProof.targetStudioOperationalChatAchieved, true);
assert.equal(hardeningProof.modelInvocationReceiptObserved, true);
assert.equal(queries.length, 1);
assert.equal(query.expectedExecutionMode, "agent");
assert.equal(query.completionStatusObserved, "blocked");
assert.ok((query.durationMs ?? 0) > 0 && query.durationMs <= 30_000);
assert.match(query.assistantText, /Waiting for approval/i);
assert.match(query.assistantText, /shell__run/i);
assert.doesNotMatch(query.assistantText, /exit code 0/i);
assert.doesNotMatch(query.assistantText, /Studio could not complete the daemon turn/i);
assert.ok(observedToolNames.includes("shell__run"));
assert.deepEqual(completedToolNames, []);
assert.deepEqual(failedToolNames, []);
assert.ok(observedEventKinds.includes("KernelEvent::FirewallInterception"));
assert.equal(deniedMarkerExists, false);
assert.equal(hardeningAfterCleanup.ok, true);
assert.equal(hardeningAfterCleanup.after?.length ?? 0, 0);
assert.equal(campaignAfterCleanup.ok, true);
assert.equal(campaignAfterCleanup.after?.length ?? 0, 0);
assert.ok(screenshots.some((screenshot) => screenshot.file === "assistant-response.png" && screenshot.exists));

const proof = {
  schemaVersion: "ioi.autopilot.stage67.live-shell-approval-gate-summary-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  hardeningProofPath,
  hardeningEvidenceDir,
  checks: {
    liveScenarioPassed: true,
    approvalPauseVisible: /Waiting for approval/i.test(query.assistantText ?? ""),
    genericDaemonFailureSuppressed: !/Studio could not complete the daemon turn/i.test(query.assistantText ?? ""),
    shellRunObserved: observedToolNames.includes("shell__run"),
    firewallInterceptionObserved: observedEventKinds.includes("KernelEvent::FirewallInterception"),
    noCommandCompletionClaimed: !/exit code 0/i.test(query.assistantText ?? ""),
    deniedMarkerAbsent: !deniedMarkerExists,
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
    deniedMarkerPath,
    screenshots: screenshots.map((screenshot) => screenshot.file),
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
