"use strict";

const fs = require("fs");
const path = require("path");

function createStudioPolicyLeaseLifecycle({
  normalizeReceiptRefs,
  processId = process.pid,
  now = Date.now,
  cwd = process.cwd,
} = {}) {
  const receipts = typeof normalizeReceiptRefs === "function" ? normalizeReceiptRefs : () => [];

  function studioPolicyLeaseLifecycleFixture(workspaceSummary = {}) {
    const workspacePath = workspaceSummary.path || cwd();
    const fixtureId = `run-${now().toString(36)}-${processId || "studio"}`;
    const fixtureRoot = path.join(workspacePath, ".tmp", "agent-studio-policy-lease-lifecycle", fixtureId);
    const absolutePath = path.join(fixtureRoot, "lease.txt");
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
    fs.mkdirSync(fixtureRoot, { recursive: true });
    fs.writeFileSync(absolutePath, "lease before\n", "utf8");
    return {
      fixtureId,
      fixtureRoot,
      absolutePath,
      relativePath: path.relative(workspacePath, absolutePath).replace(/\\/g, "/"),
    };
  }

  function studioPolicyLeaseToolBody({
    toolCallId,
    ttlMs,
    policyHash,
    expectedReceiptRef,
    relativePath,
    idempotencyKey,
    approvalId = "",
  } = {}) {
    return {
      source: "agent_studio_runtime_cockpit",
      workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
      workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
      toolCallId,
      ttlMs,
      policyHash,
      expectedReceiptRefs: [expectedReceiptRef],
      requiresApproval: true,
      approvalMode: "human_required",
      nodeApprovalOverride: "require_approval",
      trustProfile: "review_required",
      toolPack: {
        coding: {
          requiresApproval: true,
          approvalMode: "human_required",
          nodeApprovalOverride: "require_approval",
          trustProfile: "review_required",
        },
      },
      idempotencyKey,
      ...(approvalId ? { approvalId } : {}),
      input: {
        path: relativePath,
        oldText: "lease before",
        newText: "lease after",
        dryRun: true,
      },
    };
  }

  function studioPolicyLeaseLifecycleRows({
    blocked,
    approved,
    executed,
    revoked,
    blockedAfterRevoke,
    expiryBlocked,
    expiryApproved,
    expiryExecutedBefore,
    expiryBlockedAfterExpiry,
    ttlMs,
    expiryTtlMs,
  } = {}) {
    const action = "file.apply_patch dry run";
    return [
      {
        id: "studio-policy-lease-pending",
        title: "Permission required",
        status: "pending",
        action,
        reason: "Agent requested a workspace write preview; operator approval is required before execution.",
        decision: "waiting_for_approval",
        decisionLabel: "Waiting for approval",
        outcome: "Action paused before execution.",
        ttlLabel: `${ttlMs}ms allow-once lease`,
        didExecute: false,
        lifecycle: "allow_once_revoke",
        receiptRefs: receipts(blocked),
      },
      {
        id: "studio-policy-lease-allow-once",
        title: "Allowed once",
        status: "active",
        action,
        reason: "Operator allowed one dry-run execution; the daemon satisfied the lease before any file change ran.",
        decision: "allow_once",
        decisionLabel: "Allow once",
        outcome: "One approved dry-run execution completed.",
        ttlLabel: `${ttlMs}ms allow-once lease`,
        didExecute: executed?.status === "completed",
        lifecycle: "allow_once_revoke",
        receiptRefs: receipts(approved, executed),
      },
      {
        id: "studio-policy-lease-revoked",
        title: "Lease revoked",
        status: "revoked",
        action,
        reason: "Operator revoked the approval after one execution; the retry was blocked by the daemon.",
        decision: "revoke",
        decisionLabel: "Revoke",
        outcome: "Retry after revoke was blocked.",
        ttlLabel: `${ttlMs}ms allow-once lease`,
        didExecute: false,
        afterRevokeBlocked: blockedAfterRevoke?.status === "blocked",
        lifecycle: "allow_once_revoke",
        receiptRefs: receipts(revoked, blockedAfterRevoke),
      },
      {
        id: "studio-policy-lease-expired",
        title: "Lease expired",
        status: "expired",
        action,
        reason: "A short-lived allow-once lease expired; the retry after expiry was blocked by the daemon.",
        decision: "expired",
        decisionLabel: "Expired",
        outcome: "Retry after expiry was blocked.",
        ttlLabel: `${expiryTtlMs}ms short-lived lease`,
        didExecute: false,
        executedBeforeExpiry: expiryExecutedBefore?.status === "completed",
        afterExpiryBlocked: expiryBlockedAfterExpiry?.status === "blocked",
        lifecycle: "allow_once_expiry",
        receiptRefs: receipts(expiryBlocked, expiryApproved, expiryExecutedBefore, expiryBlockedAfterExpiry),
      },
    ];
  }

  return {
    studioPolicyLeaseLifecycleFixture,
    studioPolicyLeaseLifecycleRows,
    studioPolicyLeaseToolBody,
  };
}

module.exports = {
  createStudioPolicyLeaseLifecycle,
};
