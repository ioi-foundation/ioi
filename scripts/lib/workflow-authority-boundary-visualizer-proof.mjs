#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-authority-boundary-visualizer-proof.mjs <output-path>");
}

const sourceProofPath =
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus/2026-05-25T06-01-08-320Z-stage11-sandbox-boundary/workflow-sandbox-boundary-proof.json";

const { buildWorkflowAuthorityBoundaryVisualizer } = await import(
  "../../packages/agent-ide/src/runtime/workflow-authority-boundary-visualizer.ts"
);

const sandboxProof = JSON.parse(fs.readFileSync(sourceProofPath, "utf8"));
const visualizer = buildWorkflowAuthorityBoundaryVisualizer({ sandboxProof });

assert.equal(sandboxProof.passed, true);
assert.equal(visualizer.status, "ready");
assert.ok(visualizer.workspaceRoot);
assert.ok(visualizer.outsideRoot);
assert.ok(visualizer.deniedZoneCount >= 4);
assert.ok(visualizer.approvalRequiredCount >= 1);
assert.ok(visualizer.scrubbedZoneCount >= 1);
assert.ok(visualizer.zones.some((zone) => zone.zoneKind === "network" && zone.status === "denied"));
assert.ok(visualizer.zones.some((zone) => zone.authorityScope === "computer_use.native_browser.act"));
assert.ok(visualizer.zones.some((zone) => zone.evidence.includes("outside_content_preserved")));

const proof = {
  schemaVersion: "ioi.autopilot.stage21.authority-boundary-visualizer-proof.v1",
  passed: true,
  sourceProofPath,
  checks: {
    visualizerReady: visualizer.status === "ready",
    workspaceRootVisible: Boolean(visualizer.workspaceRoot),
    outsideRootVisible: Boolean(visualizer.outsideRoot),
    deniedZonesVisible: visualizer.deniedZoneCount >= 4,
    networkDefaultDeniedVisible: visualizer.zones.some((zone) => zone.zoneKind === "network" && zone.status === "denied"),
    envSecretScrubVisible: visualizer.scrubbedZoneCount >= 1,
    computerUseApprovalScopeVisible: visualizer.zones.some((zone) => zone.authorityScope === "computer_use.native_browser.act"),
  },
  visualizer,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
