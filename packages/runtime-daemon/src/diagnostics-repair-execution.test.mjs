import assert from "node:assert/strict";
import test from "node:test";

import { createDiagnosticsRepairExecutionHelpers } from "./diagnostics-repair-execution.mjs";

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeId(value) {
  return String(value ?? "unknown").replace(/[^a-z0-9_.:-]+/gi, "_").replace(/^_+|_+$/g, "") || "unknown";
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter((value) => typeof value === "string" && value.length > 0))];
}

function helpers() {
  return createDiagnosticsRepairExecutionHelpers({
    optionalString,
    safeId,
    uniqueStrings,
  });
}

test("workspace restore apply helpers enforce approval and conflict policy", () => {
  const runtime = helpers();

  const missingApproval = runtime.workspaceRestoreApplyApprovalForRequest({});
  assert.equal(missingApproval.required, true);
  assert.equal(missingApproval.satisfied, false);

  const approved = runtime.workspaceRestoreApplyApprovalForRequest({
    approval_decision: "approved",
    restore_conflict_policy: "allow_override",
  });
  assert.equal(approved.satisfied, true);
  assert.equal(approved.source, "approved");
  assert.equal(runtime.workspaceRestoreApplyAllowsConflicts({ restore_conflict_policy: "allow_override" }), true);
  assert.equal(
    runtime.workspaceRestoreApplyApprovalForRequest({ approvalDecision: "approved" }).satisfied,
    false,
  );
  assert.equal(runtime.workspaceRestoreApplyAllowsConflicts({ restoreConflictPolicy: "allow_override" }), false);

  const refs = runtime.workspaceRestoreApplyPolicyDecisionRefs({
    snapshotId: "snapshot:one",
    approval: approved,
    allowConflicts: true,
    applyStatus: "failed",
  });
  assert.deepEqual(refs, [
    "policy_workspace_restore_apply_snapshot:one_approval_satisfied",
    "policy_workspace_restore_apply_snapshot:one_conflict_override",
    "policy_workspace_restore_apply_snapshot:one_write_failed",
  ]);
});

test("diagnostics repair public result helpers are retired from JS helpers", () => {
  const runtime = helpers();

  assert.equal(Object.hasOwn(runtime, "diagnosticsRepairRetryResultFromEvent"), false);
  assert.equal(Object.hasOwn(runtime, "diagnosticsOperatorOverrideResultFromEvent"), false);
  assert.equal(Object.hasOwn(runtime, "diagnosticsRepairApplyApprovalKey"), false);
  assert.equal(Object.hasOwn(runtime, "diagnosticsRepairExecutionStatus"), false);
});

test("operator override approval derivation is retired from JS helpers", () => {
  const runtime = helpers();

  assert.equal(Object.hasOwn(runtime, "diagnosticsOperatorOverrideApprovalForRequest"), false);
  assert.equal(Object.hasOwn(runtime, "diagnosticsOperatorOverrideApprovalKey"), false);
});
