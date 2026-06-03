import assert from "node:assert/strict";
import test from "node:test";

import { createDiagnosticsRepairExecutionHelpers } from "./diagnostics-repair-execution.mjs";

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeBooleanOption(value, fallback) {
  if (value === true || value === "true" || value === "1" || value === 1) return true;
  if (value === false || value === "false" || value === "0" || value === 0) return false;
  return fallback;
}

function safeId(value) {
  return String(value ?? "unknown").replace(/[^a-z0-9_.:-]+/gi, "_").replace(/^_+|_+$/g, "") || "unknown";
}

function uniqueStrings(values) {
  return [...new Set(normalizeArray(values).filter((value) => typeof value === "string" && value.length > 0))];
}

function helpers() {
  return createDiagnosticsRepairExecutionHelpers({
    normalizeArray,
    normalizeBooleanOption,
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
  assert.equal(runtime.diagnosticsRepairApplyApprovalKey({}), "approval_required");

  const approved = runtime.workspaceRestoreApplyApprovalForRequest({
    approvalDecision: "approved",
    restoreConflictPolicy: "allow_override",
  });
  assert.equal(approved.satisfied, true);
  assert.equal(approved.source, "approved");
  assert.equal(runtime.workspaceRestoreApplyAllowsConflicts({ restoreConflictPolicy: "allow_override" }), true);

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

test("diagnostics repair execution projections preserve public envelopes", () => {
  const runtime = helpers();
  const event = {
    event_id: "evt-repair",
    status: "completed",
    receipt_refs: ["receipt-one"],
    artifact_refs: ["artifact-one"],
    policy_decision_refs: ["policy-one"],
    rollback_refs: ["snapshot-one"],
    payload_summary: {
      retry_turn_id: "turn-retry",
      retry_request_id: "request-retry",
      summary: "Repair retry queued.",
    },
  };

  const retry = runtime.diagnosticsRepairRetryResultFromEvent({
    threadId: "thread-one",
    event,
  });
  assert.equal(retry.object, "ioi.runtime_diagnostics_repair_retry");
  assert.equal(retry.thread_id, "thread-one");
  assert.equal(retry.turnId, "turn-retry");
  assert.deepEqual(retry.receiptRefs, ["receipt-one"]);

  const override = runtime.diagnosticsOperatorOverrideResultFromEvent({
    threadId: "thread-one",
    event: {
      ...event,
      payload_summary: {
        approval_required: true,
        approval_satisfied: true,
        continuation_allowed: true,
      },
    },
  });
  assert.equal(override.object, "ioi.runtime_diagnostics_operator_override");
  assert.equal(override.approvalRequired, true);
  assert.equal(override.approval_satisfied, true);
  assert.equal(override.continuationAllowed, true);
});
