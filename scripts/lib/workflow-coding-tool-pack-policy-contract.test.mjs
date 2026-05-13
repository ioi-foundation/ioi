import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

test("React Flow coding tool pack exposes restore and diagnostics repair policy controls", () => {
  const sections = read(
    "packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
  );
  const graphTypes = read("packages/agent-ide/src/types/graph.ts");
  const nodeRegistry = read(
    "packages/agent-ide/src/runtime/workflow-node-registry.ts",
  );
  const codingTools = read("packages/runtime-daemon/src/coding-tools.mjs");
  const runtimeDaemon = read("packages/runtime-daemon/src/index.mjs");
  const agentSdk = read("packages/agent-sdk/src/substrate-client.ts");
  const runtimeProjection = read("packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts");

  for (const field of [
    "restorePolicy",
    "restoreConflictPolicy",
    "diagnosticsRepairDefault",
    "operatorOverrideRequiresApproval",
  ]) {
    assert.match(graphTypes, new RegExp(`${field}\\?`));
    assert.match(sections, new RegExp(field));
    assert.match(nodeRegistry, new RegExp(field));
    assert.match(codingTools, new RegExp(`toolPack\\.coding\\.${field}`));
    assert.match(runtimeDaemon, new RegExp(field));
  }

  for (const testId of [
    "workflow-coding-tool-pack-restore-policy",
    "workflow-coding-tool-pack-restore-conflict-policy",
    "workflow-coding-tool-pack-diagnostics-repair-default",
    "workflow-coding-tool-pack-operator-override-requires-approval",
  ]) {
    assert.match(sections, new RegExp(`data-testid="${testId}"`));
  }

  assert.match(runtimeDaemon, /diagnosticsRepairPolicyConfig/);
  assert.match(runtimeDaemon, /diagnosticsRepairContextForToolPack/);
  assert.match(runtimeDaemon, /diagnosticsRepairDefaultForDecisions/);
  assert.match(runtimeDaemon, /DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION/);
  assert.match(runtimeDaemon, /executeDiagnosticsRepairDecision/);
  assert.match(runtimeDaemon, /repair-decisions/);
  assert.match(runtimeDaemon, /diagnostics\.repair_decision\.executed/);
  assert.match(agentSdk, /executeThreadDiagnosticsRepairDecision/);
  assert.match(runtimeProjection, /lsp_diagnostics_repair/);
  assert.match(runtimeProjection, /Diagnostics repair decision/);
});
