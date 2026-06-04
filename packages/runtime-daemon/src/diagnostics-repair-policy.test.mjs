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

test("diagnostics repair policy config normalizes request, input, and tool-pack aliases", () => {
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

test("diagnostics repair contexts preserve public aliases and rollback refs", () => {
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
  assert.equal(context.sourceToolName, "lsp.diagnostics");
  assert.equal(context.source_tool_call_id, "tool-call-one");
  assert.equal(context.workspaceSnapshotId, "snapshot-one");
  assert.equal(context.restorePolicy, "preview_only");
  assert.equal(context.restoreConflictPolicy, "allow_override");
  assert.equal(context.diagnosticsRepairDefault, "restore_preview");
  assert.equal(context.operatorOverrideRequiresApproval, false);
  assert.deepEqual(context.rollbackRefs, ["rollback-one", "snapshot-one"]);

  assert.equal(runtime.diagnosticsRepairContextForRequest({ repair_context: context }).sourceToolName, "lsp.diagnostics");
  assert.equal(runtime.diagnosticsRepairContextForPayload({ result: { diagnostics_repair_context: context } }).sourceToolName, "lsp.diagnostics");
  assert.equal(runtime.diagnosticsRepairContextForToolPack({}, {}, "file.read"), null);
  assert.equal(runtime.hasDiagnosticsRepairPolicyConfig({ restorePolicy: "preview" }, {}), true);
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
