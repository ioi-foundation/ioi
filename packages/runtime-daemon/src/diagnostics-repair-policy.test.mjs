import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { createDiagnosticsRepairPolicyHelpers } from "./diagnostics-repair-policy.mjs";

function helpers() {
  return createDiagnosticsRepairPolicyHelpers({
    doctorHash: (value) => crypto.createHash("sha256").update(String(value)).digest("hex"),
    normalizeArray: (value) => (Array.isArray(value) ? value.filter(Boolean) : []),
    normalizeBooleanOption: (value, fallback) => {
      if (value === true || value === "true" || value === "1" || value === 1) return true;
      if (value === false || value === "false" || value === "0" || value === 0) return false;
      return fallback;
    },
    optionalString: (value) => {
      if (value === undefined || value === null) return undefined;
      const text = String(value).trim();
      return text ? text : undefined;
    },
    uniqueStrings: (values) => [...new Set((Array.isArray(values) ? values : []).filter(Boolean).map(String))],
  });
}

test("diagnostics repair policy config normalizes canonical request, input, and tool-pack fields", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.diagnosticsRepairPolicyConfig({
    tool_pack: {
      coding: {
        restore_policy: "preview",
        conflict_policy: "approval",
        default_repair_decision: "apply",
        operator_override_requires_approval: "false",
      },
    },
  }), {
    restorePolicy: "preview_only",
    restore_policy: "preview_only",
    restoreConflictPolicy: "require_approval",
    restore_conflict_policy: "require_approval",
    diagnosticsRepairDefault: "restore_apply",
    diagnostics_repair_default: "restore_apply",
    operatorOverrideRequiresApproval: false,
    operator_override_requires_approval: false,
  });

  assert.equal(runtime.normalizeDiagnosticsMode("fail"), "blocking");
  assert.equal(runtime.normalizeDiagnosticsMode("off"), "skip");
  assert.equal(runtime.normalizeRestorePolicy("blocked"), "disabled");
  assert.equal(runtime.normalizeRestoreConflictPolicy("force"), "allow_override");
  assert.equal(runtime.normalizeDiagnosticsRepairDefault("continue"), "operator_override");
});

test("diagnostics repair policy config ignores retired request, input, and tool-pack aliases", () => {
  const runtime = helpers();

  assert.deepEqual(runtime.diagnosticsRepairPolicyConfig({
    restorePolicy: "preview",
    restoreConflictPolicy: "approval",
    diagnosticsRepairDefault: "restore_apply",
    defaultRepairDecision: "operator_override",
    operatorOverrideRequiresApproval: "false",
    toolPack: {
      coding: {
        restorePolicy: "preview",
        restoreConflictPolicy: "approval",
        conflictPolicy: "force",
        diagnosticsRepairDefault: "restore_apply",
        defaultRepairDecision: "operator_override",
        operatorOverrideRequiresApproval: "false",
      },
    },
    options: {
      toolPack: {
        restorePolicy: "preview",
        defaultRepairDecision: "restore_apply",
      },
    },
  }, {
    restorePolicy: "preview",
    restoreConflictPolicy: "approval",
    diagnosticsRepairDefault: "restore_apply",
    defaultRepairDecision: "operator_override",
    operatorOverrideRequiresApproval: "false",
  }), {
    restorePolicy: "apply_with_approval",
    restore_policy: "apply_with_approval",
    restoreConflictPolicy: "block",
    restore_conflict_policy: "block",
    diagnosticsRepairDefault: "repair_retry",
    diagnostics_repair_default: "repair_retry",
    operatorOverrideRequiresApproval: true,
    operator_override_requires_approval: true,
  });

  assert.equal(runtime.hasDiagnosticsRepairPolicyConfig({ restorePolicy: "preview" }, {}), false);
  assert.equal(runtime.hasDiagnosticsRepairPolicyConfig({ restore_policy: "preview" }, {}), true);
});

test("diagnostics repair contexts emit canonical fields and rollback refs", () => {
  const runtime = helpers();

  const context = runtime.diagnosticsRepairContextRecord({
    source_tool_name: "lsp.diagnostics",
    source_tool_call_id: "tool-call-one",
    workspace_snapshot_id: "snapshot-one",
    rollback_refs: ["rollback-one", "snapshot-one"],
    restore_policy: "preview_only",
    restore_conflict_policy: "allow_override",
    default_repair_decision: "restore_preview",
    operator_override_requires_approval: "false",
  });

  assert.equal(context.object, "ioi.runtime_diagnostics_rollback_repair_context");
  assert.equal(context.source_tool_name, "lsp.diagnostics");
  assert.equal(context.source_tool_call_id, "tool-call-one");
  assert.equal(context.workspace_snapshot_id, "snapshot-one");
  assert.equal(context.restore_policy, "preview_only");
  assert.equal(context.restore_conflict_policy, "allow_override");
  assert.equal(context.diagnostics_repair_default, "restore_preview");
  assert.equal(context.operator_override_requires_approval, false);
  assert.deepEqual(context.rollback_refs, ["rollback-one", "snapshot-one"]);
  for (const field of [
    "schemaVersion",
    "sourceToolName",
    "sourceToolCallId",
    "sourceWorkflowGraphId",
    "sourceWorkflowNodeId",
    "workspaceSnapshotId",
    "restorePolicy",
    "restoreConflictPolicy",
    "diagnosticsRepairDefault",
    "operatorOverrideRequiresApproval",
    "rollbackRefs",
  ]) {
    assert.equal(Object.hasOwn(context, field), false);
  }

  assert.equal(runtime.diagnosticsRepairContextForRequest({ repair_context: context }).source_tool_name, "lsp.diagnostics");
  assert.equal(
    runtime.diagnosticsRepairContextForPayload({ result: { diagnostics_repair_context: context } }).source_tool_name,
    "lsp.diagnostics",
  );
  assert.equal(runtime.diagnosticsRepairContextForToolPack({}, {}, "file.read"), null);
  assert.equal(runtime.hasDiagnosticsRepairPolicyConfig({ restore_policy: "preview" }, {}), true);
});

test("diagnostics repair contexts ignore retired context aliases", () => {
  const runtime = helpers();

  assert.equal(
    runtime.diagnosticsRepairContextForRequest({
      diagnosticsRepairContext: { source_tool_name: "alias" },
      repairContext: { source_tool_name: "alias" },
    }),
    null,
  );
  assert.equal(
    runtime.diagnosticsRepairContextForPayload({
      diagnosticsRepairContext: { source_tool_name: "alias" },
      result: { diagnosticsRepairContext: { source_tool_name: "alias" } },
    }),
    null,
  );

  const context = runtime.diagnosticsRepairContextRecord({
    schemaVersion: "alias-schema",
    sourceToolName: "alias-tool",
    sourceToolCallId: "alias-call",
    sourceWorkflowGraphId: "alias-graph",
    sourceWorkflowNodeId: "alias-node",
    workspaceSnapshotId: "alias-snapshot",
    restorePolicy: "preview",
    restoreConflictPolicy: "force",
    diagnosticsRepairDefault: "continue",
    operatorOverrideRequiresApproval: "false",
    rollbackRefs: ["alias-rollback"],
  });

  assert.equal(context.schema_version, "ioi.runtime.diagnostics-rollback-repair-context.v1");
  assert.equal(context.source_tool_name, null);
  assert.equal(context.source_tool_call_id, null);
  assert.equal(context.source_workflow_graph_id, null);
  assert.equal(context.source_workflow_node_id, null);
  assert.equal(context.workspace_snapshot_id, null);
  assert.equal(context.restore_policy, "apply_with_approval");
  assert.equal(context.restore_conflict_policy, "block");
  assert.equal(context.diagnostics_repair_default, "repair_retry");
  assert.equal(context.operator_override_requires_approval, true);
  assert.deepEqual(context.rollback_refs, []);
});

test("diagnostics rollback repair policy preserves decision defaults and refs", () => {
  const runtime = helpers();
  const policy = runtime.diagnosticsRollbackRepairPolicy({
    threadId: "thread-one",
    injectionId: "injection-one",
    mode: "blocking",
    diagnosticStatus: "findings",
    diagnosticCount: 2,
    workspaceSnapshotRefs: ["snapshot-one"],
    rollbackRefs: ["snapshot-one"],
    sourceToolCallIds: ["tool-call-one"],
    restorePolicy: "apply_with_approval",
    restoreConflictPolicy: "allow_override",
    diagnosticsRepairDefault: "restore_apply",
    operatorOverrideRequiresApproval: false,
  });

  assert.equal(policy.object, "ioi.runtime_diagnostics_rollback_repair_policy");
  assert.equal(policy.threadId, "thread-one");
  assert.equal(policy.restorePolicy, "apply_with_approval");
  assert.equal(policy.restoreConflictPolicy, "allow_override");
  assert.equal(policy.diagnosticsRepairDefault, "restore_apply");
  assert.equal(policy.operatorOverrideRequiresApproval, false);
  assert.deepEqual(policy.decisionRefs, policy.decisions.map((decision) => decision.decisionId));
  assert.equal(policy.decisions.find((decision) => decision.action === "restore_apply").status, "requires_approval");
  assert.equal(runtime.diagnosticsRepairDefaultForDecisions(policy.decisions, "operator_override"), "operator_override");
  assert.equal(runtime.diagnosticsRepairDefaultForDecisions([], "restore_apply"), "repair_retry");
});
