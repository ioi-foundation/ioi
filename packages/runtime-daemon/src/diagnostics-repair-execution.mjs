export function createDiagnosticsRepairExecutionHelpers({
  optionalString,
  safeId,
  uniqueStrings,
} = {}) {
  function workspaceRestoreApplyApprovalForRequest(request = {}) {
    const text = optionalString(
      request.approval ??
        request.approval_decision ??
        request.policy_decision ??
        request.decision ??
        request.status,
    )?.toLowerCase();
    const approvedText = ["approve", "approved", "allow", "allowed", "accept", "accepted", "confirm", "confirmed"];
    const approvedBoolean = [
      request.confirm,
      request.confirmed,
      request.confirm_restore_apply,
      request.apply_confirmed,
      request.approval_granted,
      request.approved,
    ].some((value) => value === true || value === "true");
    return {
      required: true,
      satisfied: approvedBoolean || approvedText.includes(text),
      source: approvedBoolean ? "boolean_confirmation" : approvedText.includes(text) ? text : "missing",
    };
  }

  function workspaceRestoreApplyAllowsConflicts(request = {}) {
    const policy = optionalString(
      request.restore_conflict_policy ??
        request.conflict_policy ??
        request.restore_policy,
    )?.toLowerCase();
    return Boolean(
      request.allow_conflicts ??
        request.override_conflicts,
    ) ||
      ["allow_override", "override", "override_conflicts", "force", "force_apply", "apply_with_conflicts"].includes(
        policy,
      );
  }

  function workspaceRestoreApplyBlockedReason(operation = {}, options = {}) {
    if (!options.approvalSatisfied) return "workspace_restore_apply_requires_approval";
    if (operation.status === "blocked") {
      return operation.blockedReason ?? operation.blocked_reason ?? "workspace_restore_preview_blocked";
    }
    if (operation.status === "conflict" && !options.allowConflicts) {
      return "workspace_restore_conflict_requires_override";
    }
    if (options.hardBlocked) return "workspace_restore_apply_blocked_by_file";
    if (options.conflictBlocked) return "workspace_restore_apply_blocked_by_conflict";
    return "workspace_restore_apply_blocked_by_policy";
  }

  function workspaceRestoreApplyStatus(counts = {}) {
    if (counts.applyBlockedCount > 0) return "blocked";
    if (counts.failedCount > 0) return "failed";
    if (counts.appliedCount === 0 && counts.applyNoopCount === counts.fileCount) return "noop";
    return "applied";
  }

  function workspaceRestoreApplyPolicyDecisionRefs({
    snapshotId,
    approval,
    allowConflicts,
    hardBlocked,
    conflictBlocked,
    applyStatus,
  } = {}) {
    return uniqueStrings([
      `policy_workspace_restore_apply_${safeId(snapshotId)}_${approval?.satisfied ? "approval_satisfied" : "approval_required"}`,
      allowConflicts ? `policy_workspace_restore_apply_${safeId(snapshotId)}_conflict_override` : null,
      hardBlocked ? `policy_workspace_restore_apply_${safeId(snapshotId)}_blocked_file` : null,
      conflictBlocked ? `policy_workspace_restore_apply_${safeId(snapshotId)}_conflict_blocked` : null,
      applyStatus === "failed" ? `policy_workspace_restore_apply_${safeId(snapshotId)}_write_failed` : null,
    ].filter(Boolean));
  }

  function workspaceRestoreApplySummary({ snapshotId, applyStatus, counts = {}, approval, allowConflicts }) {
    if (!approval?.satisfied) {
      return `Restore apply blocked for ${snapshotId}: operator approval is required.`;
    }
    if (applyStatus === "blocked") {
      return `Restore apply blocked for ${snapshotId}: ${counts.conflictCount} conflict(s), ${counts.blockedCount} blocked file(s).`;
    }
    if (applyStatus === "failed") {
      return `Restore apply failed for ${snapshotId}: ${counts.failedCount} file write(s) failed.`;
    }
    if (applyStatus === "noop") {
      return `Restore apply found ${counts.fileCount} file(s) already restored for ${snapshotId}.`;
    }
    return `Restore apply restored ${counts.appliedCount} file(s) from ${snapshotId}${allowConflicts ? " with conflict override" : ""}.`;
  }

  return {
    workspaceRestoreApplyAllowsConflicts,
    workspaceRestoreApplyApprovalForRequest,
    workspaceRestoreApplyBlockedReason,
    workspaceRestoreApplyPolicyDecisionRefs,
    workspaceRestoreApplyStatus,
    workspaceRestoreApplySummary,
  };
}
