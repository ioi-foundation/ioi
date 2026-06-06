import {
  DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";

export function createDiagnosticsRepairExecutionHelpers({
  normalizeArray,
  normalizeBooleanOption,
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

  function diagnosticsOperatorOverrideApprovalForRequest(request = {}, { decision = {}, repairPolicy = {} } = {}) {
    const required = normalizeBooleanOption(
      request.operatorOverrideRequiresApproval ??
        request.operator_override_requires_approval ??
        decision.requiresApproval ??
        decision.requires_approval ??
        repairPolicy.operatorOverrideRequiresApproval ??
        repairPolicy.operator_override_requires_approval,
      true,
    );
    const text = optionalString(
      request.operatorOverrideApproval ??
        request.operator_override_approval ??
        request.approval ??
        request.approvalDecision ??
        request.approval_decision ??
        request.policyDecision ??
        request.policy_decision ??
        request.decision ??
        request.status,
    )?.toLowerCase();
    const approvedText = [
      "approve",
      "approved",
      "allow",
      "allowed",
      "accept",
      "accepted",
      "confirm",
      "confirmed",
      "override",
    ];
    const approvedBoolean = [
      request.operatorOverrideApproved,
      request.operator_override_approved,
      request.overrideApproved,
      request.override_approved,
      request.confirm,
      request.confirmed,
      request.approvalGranted,
      request.approval_granted,
      request.approved,
    ].some((value) => value === true || value === "true");
    const satisfied = !required || approvedBoolean || approvedText.includes(text);
    return {
      required,
      satisfied,
      source: !required
        ? "workflow_policy"
        : approvedBoolean
          ? "boolean_confirmation"
          : approvedText.includes(text)
            ? text
            : "missing",
    };
  }

  function diagnosticsOperatorOverrideApprovalKey(approval = {}) {
    if (!approval.required) return "approval_not_required";
    return approval.satisfied ? `approval_${safeId(approval.source)}` : "approval_required";
  }

  function diagnosticsRepairApplyApprovalKey(request = {}) {
    const approval = workspaceRestoreApplyApprovalForRequest(request);
    return approval.satisfied ? `approval_${safeId(approval.source)}` : "approval_required";
  }

  function diagnosticsRepairExecutionStatus(result = {}) {
    const status = optionalString(result.status);
    if (["blocked", "failed", "completed"].includes(status)) return status;
    const applyStatus = optionalString(result.apply_status ?? result.applyStatus);
    if (applyStatus === "blocked") return "blocked";
    if (applyStatus === "failed") return "failed";
    const previewStatus = optionalString(result.preview_status ?? result.previewStatus);
    if (previewStatus === "blocked") return "blocked";
    return "completed";
  }

  function diagnosticsRepairRetryResultFromEvent({ threadId, event, turn = null, run = null } = {}) {
    const payload = event?.payload_summary ?? event?.payload ?? {};
    const repairTurn = turn ?? null;
    return {
      schemaVersion: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_repair_retry",
      threadId,
      thread_id: threadId,
      status: event?.status ?? "completed",
      turnId: repairTurn?.turn_id ?? payload.retry_turn_id ?? null,
      turn_id: repairTurn?.turn_id ?? payload.retry_turn_id ?? null,
      requestId: repairTurn?.request_id ?? run?.id ?? payload.retry_request_id ?? null,
      request_id: repairTurn?.request_id ?? run?.id ?? payload.retry_request_id ?? null,
      repairTurn,
      repair_turn: repairTurn,
      event,
      repair_retry_event: event,
      receiptRefs: normalizeArray(event?.receipt_refs),
      receipt_refs: normalizeArray(event?.receipt_refs),
      artifactRefs: normalizeArray(event?.artifact_refs),
      artifact_refs: normalizeArray(event?.artifact_refs),
      policyDecisionRefs: normalizeArray(event?.policy_decision_refs),
      policy_decision_refs: normalizeArray(event?.policy_decision_refs),
      rollbackRefs: normalizeArray(event?.rollback_refs),
      rollback_refs: normalizeArray(event?.rollback_refs),
      summary: optionalString(payload.summary) ?? "Diagnostics repair retry turn created.",
    };
  }

  function diagnosticsOperatorOverrideResultFromEvent({ threadId, event, turn = null } = {}) {
    const payload = event?.payload_summary ?? event?.payload ?? {};
    const status = optionalString(event?.status ?? payload.status) ?? "completed";
    return {
      schemaVersion: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      schema_version: DIAGNOSTICS_REPAIR_DECISION_EXECUTION_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_operator_override",
      threadId,
      thread_id: threadId,
      status,
      overrideStatus: status,
      override_status: status,
      gateEventId: payload.gate_event_id ?? payload.gateEventId ?? null,
      gate_event_id: payload.gate_event_id ?? payload.gateEventId ?? null,
      gateId: payload.gate_id ?? payload.gateId ?? null,
      gate_id: payload.gate_id ?? payload.gateId ?? null,
      targetTurnId: payload.target_turn_id ?? payload.targetTurnId ?? null,
      target_turn_id: payload.target_turn_id ?? payload.targetTurnId ?? null,
      targetRunId: payload.target_run_id ?? payload.targetRunId ?? null,
      target_run_id: payload.target_run_id ?? payload.targetRunId ?? null,
      approvalRequired: Boolean(payload.approval_required ?? payload.approvalRequired),
      approval_required: Boolean(payload.approval_required ?? payload.approvalRequired),
      approvalSatisfied: Boolean(payload.approval_satisfied ?? payload.approvalSatisfied),
      approval_satisfied: Boolean(payload.approval_satisfied ?? payload.approvalSatisfied),
      approvalSource: payload.approval_source ?? payload.approvalSource ?? null,
      approval_source: payload.approval_source ?? payload.approvalSource ?? null,
      continuationAllowed: Boolean(payload.continuation_allowed ?? payload.continuationAllowed),
      continuation_allowed: Boolean(payload.continuation_allowed ?? payload.continuationAllowed),
      turn,
      event,
      operator_override_event: event,
      receiptRefs: normalizeArray(event?.receipt_refs),
      receipt_refs: normalizeArray(event?.receipt_refs),
      artifactRefs: normalizeArray(event?.artifact_refs),
      artifact_refs: normalizeArray(event?.artifact_refs),
      policyDecisionRefs: normalizeArray(event?.policy_decision_refs),
      policy_decision_refs: normalizeArray(event?.policy_decision_refs),
      rollbackRefs: normalizeArray(event?.rollback_refs),
      rollback_refs: normalizeArray(event?.rollback_refs),
      summary: optionalString(payload.summary) ?? "Diagnostics operator override executed.",
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
    diagnosticsOperatorOverrideApprovalForRequest,
    diagnosticsOperatorOverrideApprovalKey,
    diagnosticsOperatorOverrideResultFromEvent,
    diagnosticsRepairApplyApprovalKey,
    diagnosticsRepairExecutionStatus,
    diagnosticsRepairRetryResultFromEvent,
    workspaceRestoreApplyAllowsConflicts,
    workspaceRestoreApplyApprovalForRequest,
    workspaceRestoreApplyBlockedReason,
    workspaceRestoreApplyPolicyDecisionRefs,
    workspaceRestoreApplyStatus,
    workspaceRestoreApplySummary,
  };
}
