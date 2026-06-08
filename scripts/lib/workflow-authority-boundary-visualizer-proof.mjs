#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
const sourceProofPath = process.argv[3];
if (!outputPath || !sourceProofPath) {
  throw new Error("usage: workflow-authority-boundary-visualizer-proof.mjs <output-path> <source-proof-path>");
}

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
  schema_version: "ioi.autopilot.stage21.authority-boundary-visualizer-proof.v1",
  passed: true,
  source_proof_path: sourceProofPath,
  checks: {
    visualizer_ready: visualizer.status === "ready",
    workspace_root_visible: Boolean(visualizer.workspaceRoot),
    outside_root_visible: Boolean(visualizer.outsideRoot),
    denied_zones_visible: visualizer.deniedZoneCount >= 4,
    network_default_denied_visible: visualizer.zones.some((zone) => zone.zoneKind === "network" && zone.status === "denied"),
    env_secret_scrub_visible: visualizer.scrubbedZoneCount >= 1,
    computer_use_approval_scope_visible: visualizer.zones.some((zone) => zone.authorityScope === "computer_use.native_browser.act"),
  },
  visualizer,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
