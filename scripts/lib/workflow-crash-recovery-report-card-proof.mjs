#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-crash-recovery-report-card-proof.mjs <output-path> [source-proof-path]");
}

const sourceProofPath =
  process.argv[3] ||
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T06-06-18-786Z-stage12-crash-restart-resume/workflow-crash-restart-timeline-resume-proof.json";

const { buildWorkflowCrashRecoveryReportCard } = await import(
  "../../packages/agent-ide/src/runtime/workflow-crash-recovery-report-card.ts"
);

const sourceProof = JSON.parse(fs.readFileSync(sourceProofPath, "utf8"));
const reportCard = buildWorkflowCrashRecoveryReportCard({ proof: sourceProof });

assert.equal(sourceProof.passed, true);
assert.equal(reportCard.status, "ready");
assert.equal(reportCard.crashSignal, "SIGKILL");
assert.notEqual(reportCard.firstDaemonPid, reportCard.secondDaemonPid);
assert.equal(reportCard.beforeCrashEventCount, reportCard.afterRestartEventCount);
assert.equal(reportCard.replayFromLastSeqCount, 0);
assert.equal(reportCard.duplicateTerminalEvents, 0);
assert.equal(reportCard.continuationSeqStart, (reportCard.safeBoot.resumeFromSeq ?? 0) + 1);
assert.ok(reportCard.rows.every((row) => row.status === "passed"));

const proof = {
  schemaVersion: "ioi.autopilot.stage20.crash-recovery-report-card-proof.v1",
  passed: true,
  sourceProofPath,
  checks: {
    reportCardReady: reportCard.status === "ready",
    crashSignalVisible: reportCard.crashSignal === "SIGKILL",
    restartPidChanged: reportCard.firstDaemonPid !== reportCard.secondDaemonPid,
    replayCountPreserved: reportCard.beforeCrashEventCount === reportCard.afterRestartEventCount,
    noDuplicateTerminalEvents: reportCard.duplicateTerminalEvents === 0,
    continuationCursorVisible: reportCard.continuationSeqStart === (reportCard.safeBoot.resumeFromSeq ?? 0) + 1,
    allRowsPassed: reportCard.rows.every((row) => row.status === "passed"),
  },
  reportCard,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
