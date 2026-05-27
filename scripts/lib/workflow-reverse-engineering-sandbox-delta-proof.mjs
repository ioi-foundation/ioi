#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const markdownPath = process.argv[3];

if (!outputPath || !markdownPath) {
  throw new Error("usage: workflow-reverse-engineering-sandbox-delta-proof.mjs <output-json> <output-markdown>");
}

const sandboxReportPath = "internal-docs/reverse-engineering/antigravity-sandbox-boundary-report.md";
const toolCataloguePath = "internal-docs/reverse-engineering/antigravity-tool-catalogue.md";
const stage45ProofPath =
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T11-30-00-000Z-stage45-sandbox-resource-limits/workflow-sandbox-resource-limits-proof.json";
const stage68ProofPath =
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T11-35-00-000Z-stage68-live-approval-gate-ux/workflow-live-approval-gate-ux-summary-proof.json";
const stage69ProofPath =
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T11-45-00-000Z-stage69-evidence-manifest-refresh/workflow-evidence-manifest-refresh-proof.json";

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function readJson(filePath) {
  return JSON.parse(readText(filePath));
}

function textHasAll(text, terms) {
  return terms.every((term) => text.includes(term));
}

const sandboxReport = readText(sandboxReportPath);
const toolCatalogue = readText(toolCataloguePath);
const stage45 = readJson(stage45ProofPath);
const stage68 = readJson(stage68ProofPath);
const stage69 = readJson(stage69ProofPath);

const requiredReverseEngineeringSignals = [
  "Workspace Write Isolation",
  "Workspace Read Isolation",
  "Ignored-File Protection",
  "Symlink Escape Protection",
  "Network Default Deny",
  "Env Var Filtering",
  "Timeout Enforcement",
  "Background Process Cleanup",
  "Output Limit",
  "Resource Controls",
];

assert.ok(textHasAll(sandboxReport, requiredReverseEngineeringSignals));
assert.ok(toolCatalogue.includes("BattleModePermissionManager"));
assert.equal(stage45.passed, true);
assert.equal(stage45.checks.defaultNetworkDeny, true);
assert.equal(stage45.checks.networkCommandBlocked, true);
assert.equal(stage45.checks.memoryExceededBlocked, true);
assert.equal(stage45.checks.timeoutExceededBlocked, true);
assert.equal(stage45.checks.arbitraryShellNeedsNamespaceReview, true);
assert.equal(stage68.passed, true);
assert.equal(stage68.checks.firewallInterceptionObserved, true);
assert.equal(stage68.checks.approvalPauseVisible, true);
assert.equal(stage68.checks.genericDaemonFailureSuppressed, true);
assert.equal(stage69.passed, true);
assert.equal(stage69.checks.recentStagesHavePassingProofs, true);

const deltas = [
  {
    boundary: "Network default deny",
    reverseEngineeringSignal: "Antigravity blocks outbound network by default.",
    autopilotStatus: "covered",
    evidence: [stage45ProofPath],
    note: "Stage45 proves default network deny and network command blocking in the sandbox resource panel.",
  },
  {
    boundary: "Approval prompt for risky shell",
    reverseEngineeringSignal: "Battle Mode pauses high-risk command execution.",
    autopilotStatus: "covered-plus",
    evidence: [stage68ProofPath],
    note: "Stage68 proves live Agent Studio approval-pending UX, FirewallInterception, no fake success, and no marker mutation.",
  },
  {
    boundary: "Timeout and memory limits",
    reverseEngineeringSignal: "Antigravity enforces command timeout and tracks resource controls.",
    autopilotStatus: "covered-plan-gate",
    evidence: [stage45ProofPath],
    note: "Stage45 blocks over-limit timeout and memory requests before execution; live runner-level cgroup/namespace enforcement remains a plus delta.",
  },
  {
    boundary: "Output limit",
    reverseEngineeringSignal: "Antigravity truncates massive stdout/stderr to protect trajectory storage.",
    autopilotStatus: "covered-plan-gate",
    evidence: [stage45ProofPath],
    note: "Stage45 records outputKb limits in resource rows; add a live oversized-output command probe when daemon runner exposes bounded execution output caps.",
  },
  {
    boundary: "Linux namespace/container isolation",
    reverseEngineeringSignal: "Antigravity notes Linux host-shell gaps and recommends namespace/container isolation.",
    autopilotStatus: "open-plus-delta",
    evidence: [sandboxReportPath, stage45ProofPath],
    note: "Autopilot currently marks arbitrary shell as needs_review when containerNamespaceRequired is true. True bubblewrap/nsjail-style execution remains a future parity-plus item.",
  },
  {
    boundary: "Env var filtering",
    reverseEngineeringSignal: "Antigravity scrubs subprocess environments.",
    autopilotStatus: "open-live-proof",
    evidence: [sandboxReportPath],
    note: "No Stage62-68 live GUI probe prints a sanitized env. Add an allowlisted env probe with secret canaries once shell env projection is safely redacted.",
  },
  {
    boundary: "Ignored-file and symlink escapes",
    reverseEngineeringSignal: "Antigravity blocks ignored-file reads and resolved symlink escapes.",
    autopilotStatus: "covered-elsewhere-not-live-gui",
    evidence: [sandboxReportPath],
    note: "Prior file boundary work exists in the campaign, but this refresh keeps a live GUI read/search follow-up open for ignored-file and symlink-specific prompts.",
  },
  {
    boundary: "Corpus auditability",
    reverseEngineeringSignal: "Trajectory evidence should preserve tool outcomes and failed attempts.",
    autopilotStatus: "covered-plus",
    evidence: [stage69ProofPath],
    note: "Stage69 proves recent-stage manifest coverage through Stage68 and hardens proof-directory selection when failed attempts are intentionally retained.",
  },
];

const openDeltas = deltas.filter((delta) => /open|plus-delta|not-live/.test(delta.autopilotStatus));

const proof = {
  schemaVersion: "ioi.autopilot.stage70.reverse-engineering-sandbox-delta-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    reverseEngineeringSandboxSignalsPresent: true,
    battleModePermissionSignalPresent: true,
    stage45ResourceGatesPassed: true,
    stage68ApprovalUxPassed: true,
    stage69ManifestRefreshPassed: true,
    openDeltasTracked: openDeltas.length > 0,
  },
  metrics: {
    deltaCount: deltas.length,
    openDeltaCount: openDeltas.length,
  },
  deltas,
  artifacts: {
    sandboxReportPath,
    toolCataloguePath,
    stage45ProofPath,
    stage68ProofPath,
    stage69ProofPath,
    markdownPath,
  },
};

const markdown = [
  "# Reverse-Engineering Sandbox Delta Proof",
  "",
  `Generated: ${proof.generatedAt}`,
  "",
  "| Boundary | Status | Evidence | Note |",
  "| --- | --- | --- | --- |",
  ...deltas.map((delta) => (
    `| ${delta.boundary} | ${delta.autopilotStatus} | ${delta.evidence.map((item) => `\`${item}\``).join("<br>")} | ${delta.note} |`
  )),
  "",
  "## Open Parity-Plus Deltas",
  "",
  ...openDeltas.map((delta) => `- ${delta.boundary}: ${delta.note}`),
  "",
].join("\n");

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
fs.writeFileSync(markdownPath, markdown);
