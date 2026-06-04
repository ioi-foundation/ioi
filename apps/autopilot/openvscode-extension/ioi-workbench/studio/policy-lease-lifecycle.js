"use strict";

const fs = require("fs");
const path = require("path");

function createStudioPolicyLeaseLifecycle({
  STUDIO_POLICY_LEASE_ID = "approval_agent_studio_policy_lease_destructive_action",
  appendStudioReceiptsFromResponse,
  appendStudioTimeline,
  daemonEndpoint,
  daemonRequestToken,
  getStudioRuntimeProjection,
  ensureStudioDaemonThread,
  normalizeReceiptRefs,
  processId = process.pid,
  recomputeStudioRuntimeCockpitAchieved,
  requestJson,
  studioApprovalTurnPayload,
  workspaceSummary = () => ({ path: cwd() }),
  STUDIO_MODE_AGENT = "agent",
  STUDIO_PERMISSION_MODE_DEFAULT = "default",
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

  async function requestAndDenyStudioPolicyLease(threadId, output) {
    const endpoint = daemonEndpoint();
    const token = daemonRequestToken();
    const approvalTurnPayload = studioApprovalTurnPayload();
    const approval = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/approvals`, {
      method: "POST",
      token,
      payload: {
        approval_id: STUDIO_POLICY_LEASE_ID,
        reason: "Runtime cockpit validation: destructive shell/file action must receive a policy lease before execution.",
        action: "shell.exec.destructive",
        tool_id: "execute",
        effect_class: "destructive",
        risk_domain: "workspace",
        source: "agent_studio_runtime_cockpit",
        ...approvalTurnPayload,
      },
    });
    const decision = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(STUDIO_POLICY_LEASE_ID)}/decision`,
      {
        method: "POST",
        token,
        payload: {
          decision: "reject",
          source: "agent_studio_runtime_cockpit",
          reason: "Validation denied the destructive action; execution must not occur.",
          ...approvalTurnPayload,
        },
      },
    );
    const refs = receipts(approval, decision);
    const studioRuntimeProjection = getStudioRuntimeProjection();
    studioRuntimeProjection.policyLeases.push({
      id: STUDIO_POLICY_LEASE_ID,
      title: "Permission denied",
      status: "denied",
      action: "shell.exec.destructive",
      reason: "Agent asked to run an elevated action; permission was denied and the action did not run.",
      didExecute: false,
      receiptRefs: refs,
    });
    studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
    studioRuntimeProjection.runtimeCockpit.policyDeniedActionDidNotExecute = true;
    appendStudioReceiptsFromResponse(approval, "policy_lease_required", "Daemon requested policy lease for elevated action.");
    appendStudioReceiptsFromResponse(decision, "policy_lease_denied", "Daemon denied policy lease; action did not execute.");
    appendStudioTimeline("Policy lease denied", STUDIO_POLICY_LEASE_ID, "blocked");
    output?.appendLine?.("[ioi-studio] policy lease denied; destructive action was not executed.");
  }

  async function exerciseStudioPolicyLeaseLifecycle(output) {
    const studioRuntimeProjection = getStudioRuntimeProjection();
    await ensureStudioDaemonThread({
      model: studioRuntimeProjection.modelRoute || "route.local-first",
      selectedModelId: studioRuntimeProjection.selectedModel || "auto",
      executionMode: STUDIO_MODE_AGENT,
      approvalMode: STUDIO_PERMISSION_MODE_DEFAULT,
    }, output);
    const threadId = studioRuntimeProjection.threadId;
    if (!threadId) {
      throw new Error("Policy lease lifecycle proof requires a daemon Studio thread.");
    }
    const endpoint = daemonEndpoint();
    const token = daemonRequestToken();
    const fixture = studioPolicyLeaseLifecycleFixture(workspaceSummary());
    const toolEndpoint = `/v1/threads/${encodeURIComponent(threadId)}/tools/file.apply_patch/invoke`;
    const ttlMs = 60_000;
    const expiryTtlMs = 1_300;
    const base = {
      toolCallId: "studio_policy_lease_allow_revoke",
      ttlMs,
      policyHash: "policy_hash_agent_studio_live_gui_allow_revoke",
      expectedReceiptRef: "receipt_agent_studio_policy_lease_allow_revoke_expected",
      relativePath: fixture.relativePath,
    };
    const expiryBase = {
      toolCallId: "studio_policy_lease_expiry",
      ttlMs: expiryTtlMs,
      policyHash: "policy_hash_agent_studio_live_gui_expiry",
      expectedReceiptRef: "receipt_agent_studio_policy_lease_expiry_expected",
      relativePath: fixture.relativePath,
    };

    let fixtureContentAfterLifecycle = "";
    let fixtureExistsAfterCleanup = null;
    try {
      const blocked = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...base,
          idempotencyKey: "studio-policy-lease-blocked",
        }),
      });
      const approved = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/approve`,
        {
          method: "POST",
          token,
          payload: {
            source: "agent_studio_runtime_cockpit",
            workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
            workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
            reason: "Operator allowed one Studio policy lease dry-run execution.",
            ...studioApprovalTurnPayload(),
          },
        },
      );
      const executed = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...base,
          idempotencyKey: "studio-policy-lease-allow-once-execute",
          approvalId: blocked.approval_id || blocked.approvalId,
        }),
      });
      const revoked = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/revoke`,
        {
          method: "POST",
          token,
          payload: {
            source: "agent_studio_runtime_cockpit",
            workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
            workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
            reason: "Operator revoked the Studio policy lease after one dry-run execution.",
            ...studioApprovalTurnPayload(),
          },
        },
      );
      const blockedAfterRevoke = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...base,
          idempotencyKey: "studio-policy-lease-after-revoke",
          approvalId: blocked.approval_id || blocked.approvalId,
        }),
      });

      const expiryBlocked = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...expiryBase,
          idempotencyKey: "studio-policy-lease-expiry-blocked",
        }),
      });
      const expiryApproved = await requestJson(
        endpoint,
        `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(expiryBlocked.approval_id || expiryBlocked.approvalId)}/approve`,
        {
          method: "POST",
          token,
          payload: {
            source: "agent_studio_runtime_cockpit",
            workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
            workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
            reason: "Operator allowed one short-lived Studio policy lease dry-run execution.",
            ...studioApprovalTurnPayload(),
          },
        },
      );
      const expiryExecutedBefore = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...expiryBase,
          idempotencyKey: "studio-policy-lease-before-expiry",
          approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
        }),
      });
      const expiresAtMs = Date.parse(
        expiryApproved?.approval_lease?.expires_at ||
          expiryApproved?.approvalLease?.expiresAt ||
          expiryApproved?.expires_at ||
          expiryApproved?.expiresAt ||
          "",
      );
      if (Number.isFinite(expiresAtMs)) {
        await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAtMs - now()) + 90));
      } else {
        await new Promise((resolve) => setTimeout(resolve, expiryTtlMs + 120));
      }
      const expiryBlockedAfterExpiry = await requestJson(endpoint, toolEndpoint, {
        method: "POST",
        token,
        payload: studioPolicyLeaseToolBody({
          ...expiryBase,
          idempotencyKey: "studio-policy-lease-after-expiry",
          approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
        }),
      });

      fixtureContentAfterLifecycle = fs.readFileSync(fixture.absolutePath, "utf8");
      const checks = {
        pendingVisible: blocked?.status === "blocked" && Boolean(blocked.approval_required ?? blocked.approvalRequired),
        allowOnceExecutes: executed?.status === "completed" && Boolean(executed?.event?.payload_summary?.approval_satisfied ?? executed?.event?.payloadSummary?.approvalSatisfied),
        revokeInvalidatesRetry:
          blockedAfterRevoke?.status === "blocked" &&
          (blockedAfterRevoke?.error?.code === "coding_tool_approval_required" || Boolean(blockedAfterRevoke?.approval_required ?? blockedAfterRevoke?.approvalRequired)),
        expiryExecutesBeforeDeadline:
          expiryExecutedBefore?.status === "completed" &&
          Boolean(expiryExecutedBefore?.event?.payload_summary?.approval_satisfied ?? expiryExecutedBefore?.event?.payloadSummary?.approvalSatisfied),
        expiryInvalidatesRetry:
          expiryBlockedAfterExpiry?.status === "blocked" &&
          (expiryBlockedAfterExpiry?.error?.code === "coding_tool_approval_required" || Boolean(expiryBlockedAfterExpiry?.approval_required ?? expiryBlockedAfterExpiry?.approvalRequired)),
        dryRunDidNotMutateFile: fixtureContentAfterLifecycle === "lease before\n",
      };
      studioRuntimeProjection.policyLeases.push(
        ...studioPolicyLeaseLifecycleRows({
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
        }),
      );
      studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
      studioRuntimeProjection.runtimeCockpit.policyLeaseAllowOnceObserved = checks.allowOnceExecutes;
      studioRuntimeProjection.runtimeCockpit.policyLeaseRevokeObserved = revoked?.lease_status === "revoked" || revoked?.leaseStatus === "revoked";
      studioRuntimeProjection.runtimeCockpit.policyLeaseExpiryObserved = checks.expiryInvalidatesRetry;
      studioRuntimeProjection.runtimeCockpit.policyLeaseRevokedActionDidNotExecute = checks.revokeInvalidatesRetry;
      studioRuntimeProjection.runtimeCockpit.policyLeaseExpiredActionDidNotExecute = checks.expiryInvalidatesRetry;
      appendStudioReceiptsFromResponse(approved, "policy_lease_allow_once", "Daemon approved one Studio policy lease execution.");
      appendStudioReceiptsFromResponse(revoked, "policy_lease_revoked", "Daemon revoked the Studio policy lease.");
      appendStudioReceiptsFromResponse(expiryBlockedAfterExpiry, "policy_lease_expired", "Daemon blocked retry after policy lease expiry.");
      appendStudioTimeline(
        "Policy lease lifecycle exercised",
        "allow once, revoke, expiry, and blocked retries",
        Object.values(checks).every(Boolean) ? "completed" : "blocked",
      );
      studioRuntimeProjection.status = Object.values(checks).every(Boolean) ? "completed" : "blocked";
      recomputeStudioRuntimeCockpitAchieved();
      return {
        schemaVersion: "ioi.agent-studio.policy-lease-lifecycle.v1",
        passed: Object.values(checks).every(Boolean),
        threadId,
        approvalIds: {
          allowRevoke: blocked.approval_id || blocked.approvalId || null,
          expiry: expiryBlocked.approval_id || expiryBlocked.approvalId || null,
        },
        checks,
        fixture: {
          relativePath: fixture.relativePath,
          dryRunContentPreserved: fixtureContentAfterLifecycle === "lease before\n",
        },
        receipts: receipts(
          blocked,
          approved,
          executed,
          revoked,
          blockedAfterRevoke,
          expiryBlocked,
          expiryApproved,
          expiryExecutedBefore,
          expiryBlockedAfterExpiry,
        ),
      };
    } finally {
      fs.rmSync(fixture.fixtureRoot, { recursive: true, force: true });
      fixtureExistsAfterCleanup = fs.existsSync(fixture.fixtureRoot);
      output?.appendLine?.(`[ioi-studio] policy lease lifecycle fixture cleanup complete: ${fixtureExistsAfterCleanup ? "still present" : "removed"}.`);
    }
  }

  return {
    exerciseStudioPolicyLeaseLifecycle,
    requestAndDenyStudioPolicyLease,
    studioPolicyLeaseLifecycleFixture,
    studioPolicyLeaseLifecycleRows,
    studioPolicyLeaseToolBody,
  };
}

module.exports = {
  createStudioPolicyLeaseLifecycle,
};
