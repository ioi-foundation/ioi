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
    "packages/hypervisor-workbench/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
  );
  const graphTypes = read("packages/hypervisor-workbench/src/types/graph.ts");
  const nodeRegistry = read(
    "packages/hypervisor-workbench/src/runtime/workflow-node-registry.ts",
  );
  const codingTools = read("packages/runtime-daemon/src/coding-tools.mjs");
  const runtimeDaemon = read("packages/runtime-daemon/src/index.mjs");
  const agentSdk = read("packages/agent-sdk/src/substrate-client.ts");
  const runtimeProjection = read("packages/hypervisor-workbench/src/runtime/workflow-runtime-event-projection.ts");
  const codingToolControlNodes = read(
    "packages/hypervisor-workbench/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
  );

  for (const field of [
    "approvalMode",
    "trustProfile",
    "nodeApprovalOverride",
    "requiresApproval",
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
    "workflow-coding-tool-pack-requires-approval",
    "workflow-coding-tool-pack-approval-mode",
    "workflow-coding-tool-pack-trust-profile",
    "workflow-coding-tool-pack-node-approval-override",
    "workflow-coding-tool-pack-restore-policy",
    "workflow-coding-tool-pack-restore-conflict-policy",
    "workflow-coding-tool-pack-diagnostics-repair-default",
    "workflow-coding-tool-pack-operator-override-requires-approval",
  ]) {
    assert.match(sections, new RegExp(`data-testid="${testId}"`));
  }

  assert.match(runtimeDaemon, /diagnosticsRepairPolicyConfig/);
  assert.match(runtimeDaemon, /codingToolWorkflowApprovalPolicy/);
  assert.match(runtimeDaemon, /codingToolApprovalSatisfaction/);
  assert.match(runtimeDaemon, /workflow_node_requires_approval/);
  assert.match(runtimeDaemon, /workflow_trust_profile_requires_approval/);
  assert.match(codingToolControlNodes, /createRuntimeCodingToolControlRequestFromWorkflowNode/);
  assert.match(codingToolControlNodes, /nodeApprovalOverride/);
  assert.match(codingToolControlNodes, /trustProfile/);
  assert.match(runtimeDaemon, /diagnosticsRepairContextForToolPack/);
  assert.match(runtimeDaemon, /diagnosticsRepairDefaultForDecisions/);
  assert.match(runtimeDaemon, /DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION/);
  assert.match(runtimeDaemon, /executeDiagnosticsRepairDecision/);
  assert.match(runtimeDaemon, /repair-decisions/);
  assert.match(runtimeDaemon, /diagnostics\.repair_decision\.executed/);
  assert.match(runtimeDaemon, /diagnostics\.repair_retry\.created/);
  assert.match(runtimeDaemon, /diagnostics\.operator_override\.executed/);
  assert.match(runtimeDaemon, /LSP_DIAGNOSTICS_REPAIR_RETRY_NODE_ID/);
  assert.match(runtimeDaemon, /LSP_DIAGNOSTICS_OPERATOR_OVERRIDE_NODE_ID/);
  assert.match(runtimeDaemon, /restore_apply/);
  assert.match(runtimeDaemon, /restore_apply_event_id/);
  assert.match(runtimeDaemon, /LSP_DIAGNOSTICS_REPAIR_RESTORE_APPLY_NODE_ID/);
  assert.match(agentSdk, /executeThreadDiagnosticsRepairDecision/);
  assert.match(agentSdk, /repairRetry/);
  assert.match(agentSdk, /operatorOverride/);
  assert.match(agentSdk, /restoreApply/);
  assert.match(runtimeProjection, /lsp_diagnostics_repair/);
  assert.match(runtimeProjection, /lsp_diagnostics_repair_retry/);
  assert.match(runtimeProjection, /lsp_diagnostics_operator_override/);
  assert.match(runtimeProjection, /Diagnostics repair decision/);
  assert.match(runtimeProjection, /Diagnostics repair retry/);
  assert.match(runtimeProjection, /Diagnostics operator override/);
});
