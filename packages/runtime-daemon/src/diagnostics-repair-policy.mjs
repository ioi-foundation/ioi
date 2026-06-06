import {
  DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
  DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";

export function createDiagnosticsRepairPolicyHelpers({
  doctorHash,
  normalizeArray,
  normalizeBooleanOption,
  optionalString,
  uniqueStrings,
} = {}) {
  function diagnosticsRepairPolicyConfig(request = {}, input = {}) {
    const packRoot = request.tool_pack ?? request.options?.tool_pack ?? {};
    const pack = packRoot?.coding ?? packRoot;
    const restorePolicy = normalizeRestorePolicy(
      request.restore_policy ??
        input.restore_policy ??
        pack.restore_policy,
    );
    const restoreConflictPolicy = normalizeRestoreConflictPolicy(
      request.restore_conflict_policy ??
        input.restore_conflict_policy ??
        pack.restore_conflict_policy ??
        pack.conflict_policy,
    );
    const diagnosticsRepairDefault = normalizeDiagnosticsRepairDefault(
      request.diagnostics_repair_default ??
        request.default_repair_decision ??
        input.diagnostics_repair_default ??
        input.default_repair_decision ??
        pack.diagnostics_repair_default ??
        pack.default_repair_decision,
    );
    const operatorOverrideRequiresApproval = normalizeBooleanOption(
      request.operator_override_requires_approval ??
        input.operator_override_requires_approval ??
        pack.operator_override_requires_approval,
      true,
    );
    return {
      restorePolicy,
      restore_policy: restorePolicy,
      restoreConflictPolicy,
      restore_conflict_policy: restoreConflictPolicy,
      diagnosticsRepairDefault,
      diagnostics_repair_default: diagnosticsRepairDefault,
      operatorOverrideRequiresApproval,
      operator_override_requires_approval: operatorOverrideRequiresApproval,
    };
  }

  function diagnosticsRepairPolicyConfigForContexts(contexts = []) {
    const firstValue = (...keys) => {
      for (const context of normalizeArray(contexts)) {
        for (const key of keys) {
          if (context?.[key] !== undefined && context?.[key] !== null) return context[key];
        }
      }
      return undefined;
    };
    return diagnosticsRepairPolicyConfig({
      restore_policy: firstValue("restore_policy"),
      restore_conflict_policy: firstValue("restore_conflict_policy"),
      diagnostics_repair_default: firstValue("diagnostics_repair_default"),
      operator_override_requires_approval: firstValue("operator_override_requires_approval"),
    });
  }

  function diagnosticsRepairContextForToolPack(request = {}, input = {}, toolName = null) {
    if (toolName !== "lsp.diagnostics") return null;
    if (!hasDiagnosticsRepairPolicyConfig(request, input)) return null;
    const policyConfig = diagnosticsRepairPolicyConfig(request, input);
    return diagnosticsRepairContextRecord({
      source_tool_name: toolName,
      ...policyConfig,
    });
  }

  function hasDiagnosticsRepairPolicyConfig(request = {}, input = {}) {
    const packRoot = request.tool_pack ?? request.options?.tool_pack ?? {};
    const pack = packRoot?.coding ?? packRoot;
    return [
      request.restore_policy,
      request.restore_conflict_policy,
      request.diagnostics_repair_default,
      request.default_repair_decision,
      request.operator_override_requires_approval,
      input.restore_policy,
      input.restore_conflict_policy,
      input.diagnostics_repair_default,
      input.default_repair_decision,
      input.operator_override_requires_approval,
      pack.restore_policy,
      pack.restore_conflict_policy,
      pack.diagnostics_repair_default,
      pack.default_repair_decision,
      pack.operator_override_requires_approval,
    ].some((value) => value !== undefined && value !== null);
  }

  function normalizeDiagnosticsMode(value) {
    const mode = optionalString(value)?.toLowerCase() ?? "advisory";
    if (["skip", "off", "disabled", "none"].includes(mode)) return "skip";
    if (["block", "blocking", "required", "fail"].includes(mode)) return "blocking";
    return "advisory";
  }

  function normalizeRestorePolicy(value) {
    const policy = optionalString(value)?.toLowerCase() ?? "apply_with_approval";
    if (["disabled", "disable", "off", "none", "blocked"].includes(policy)) return "disabled";
    if (["preview", "preview_only", "restore_preview", "preview-only"].includes(policy)) return "preview_only";
    return "apply_with_approval";
  }

  function normalizeRestoreConflictPolicy(value) {
    const policy = optionalString(value)?.toLowerCase() ?? "block";
    if (["allow_override", "override", "override_conflicts", "force", "apply_with_conflicts"].includes(policy)) {
      return "allow_override";
    }
    if (["require_approval", "approval", "approval_required"].includes(policy)) return "require_approval";
    return "block";
  }

  function normalizeDiagnosticsRepairDefault(value) {
    const action = optionalString(value)?.toLowerCase() ?? "repair_retry";
    if (["restore_preview", "preview", "preview_restore"].includes(action)) return "restore_preview";
    if (["restore_apply", "apply", "apply_restore", "restore_apply_with_approval"].includes(action)) return "restore_apply";
    if (["operator_override", "override", "continue"].includes(action)) return "operator_override";
    return "repair_retry";
  }

  function diagnosticsRepairContextForRequest(request = {}) {
    return diagnosticsRepairContextRecord(
      request.diagnostics_repair_context ?? request.repair_context,
    );
  }

  function diagnosticsRepairContextForPayload(payload = {}) {
    return diagnosticsRepairContextRecord(
      payload.diagnostics_repair_context ?? payload.result?.diagnostics_repair_context,
    );
  }

  function diagnosticsRepairContextRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const rollbackRefs = uniqueStrings([
      ...normalizeArray(value.rollback_refs),
      optionalString(value.workspace_snapshot_id),
    ]);
    const restorePolicy = normalizeRestorePolicy(value.restore_policy);
    const restoreConflictPolicy = normalizeRestoreConflictPolicy(
      value.restore_conflict_policy,
    );
    const diagnosticsRepairDefault = normalizeDiagnosticsRepairDefault(
      value.diagnostics_repair_default ?? value.default_repair_decision,
    );
    const operatorOverrideRequiresApproval = normalizeBooleanOption(
      value.operator_override_requires_approval,
      true,
    );
    return {
      schema_version:
        optionalString(value.schema_version) ??
        DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
      object: optionalString(value.object) ?? "ioi.runtime_diagnostics_rollback_repair_context",
      source_tool_name: optionalString(value.source_tool_name) ?? null,
      source_tool_call_id: optionalString(value.source_tool_call_id) ?? null,
      source_workflow_graph_id: optionalString(value.source_workflow_graph_id) ?? null,
      source_workflow_node_id: optionalString(value.source_workflow_node_id) ?? null,
      workspace_snapshot_id: optionalString(value.workspace_snapshot_id) ?? null,
      restore_policy: restorePolicy,
      restore_conflict_policy: restoreConflictPolicy,
      diagnostics_repair_default: diagnosticsRepairDefault,
      operator_override_requires_approval: operatorOverrideRequiresApproval,
      rollback_refs: rollbackRefs,
    };
  }

  function diagnosticsRollbackRepairPolicy({
    threadId,
    injectionId,
    mode,
    diagnosticStatus,
    diagnosticCount,
    workspaceSnapshotRefs,
    rollbackRefs,
    sourceToolCallIds,
    restorePolicy,
    restoreConflictPolicy,
    diagnosticsRepairDefault,
    operatorOverrideRequiresApproval,
  } = {}) {
    const policyId = `policy_lsp_diagnostics_rollback_repair_${doctorHash(
      `${threadId}:${injectionId}:${workspaceSnapshotRefs.join(",")}`,
    ).slice(0, 16)}`;
    const hasSnapshot = workspaceSnapshotRefs.length > 0;
    const normalizedRestorePolicy = normalizeRestorePolicy(restorePolicy);
    const normalizedRestoreConflictPolicy = normalizeRestoreConflictPolicy(restoreConflictPolicy);
    const normalizedRepairDefault = normalizeDiagnosticsRepairDefault(diagnosticsRepairDefault);
    const overrideRequiresApproval = normalizeBooleanOption(operatorOverrideRequiresApproval, true);
    const restorePreviewStatus =
      normalizedRestorePolicy === "disabled"
        ? "unavailable"
        : hasSnapshot
          ? "available"
          : "unavailable";
    const restoreApplyStatus =
      normalizedRestorePolicy === "apply_with_approval" && hasSnapshot
        ? "requires_approval"
        : "unavailable";
    const decisionBase = `${policyId}_decision`;
    const decisions = [
      {
        decisionId: `${decisionBase}_repair_retry`,
        decision_id: `${decisionBase}_repair_retry`,
        action: "repair_retry",
        status: "available",
        requiresApproval: false,
        requires_approval: false,
        summary: "Retry with diagnostics context and repair the reported findings.",
      },
      {
        decisionId: `${decisionBase}_restore_preview`,
        decision_id: `${decisionBase}_restore_preview`,
        action: "restore_preview",
        status: restorePreviewStatus,
        requiresApproval: false,
        requires_approval: false,
        rollbackRefs,
        rollback_refs: rollbackRefs,
        workspaceSnapshotRefs,
        workspace_snapshot_refs: workspaceSnapshotRefs,
        summary:
          normalizedRestorePolicy === "disabled"
            ? "Workflow restore policy disables snapshot restore preview."
            : hasSnapshot
              ? "Preview restoring the snapshot captured before the patch."
              : "No content-backed workspace snapshot is available for restore preview.",
      },
      {
        decisionId: `${decisionBase}_restore_apply`,
        decision_id: `${decisionBase}_restore_apply`,
        action: "restore_apply",
        status: restoreApplyStatus,
        requiresApproval: normalizedRestorePolicy === "apply_with_approval",
        requires_approval: normalizedRestorePolicy === "apply_with_approval",
        rollbackRefs,
        rollback_refs: rollbackRefs,
        workspaceSnapshotRefs,
        workspace_snapshot_refs: workspaceSnapshotRefs,
        restoreConflictPolicy: normalizedRestoreConflictPolicy,
        restore_conflict_policy: normalizedRestoreConflictPolicy,
        summary:
          normalizedRestorePolicy === "disabled"
            ? "Workflow restore policy disables snapshot restore apply."
            : normalizedRestorePolicy === "preview_only"
              ? "Workflow restore policy allows preview only; apply is unavailable."
              : hasSnapshot
                ? "Apply snapshot restore after explicit operator approval."
                : "No content-backed workspace snapshot is available for restore apply.",
      },
      {
        decisionId: `${decisionBase}_operator_override`,
        decision_id: `${decisionBase}_operator_override`,
        action: "operator_override",
        status: overrideRequiresApproval ? "requires_approval" : "available",
        requiresApproval: overrideRequiresApproval,
        requires_approval: overrideRequiresApproval,
        summary: overrideRequiresApproval
          ? "Continue despite blocking diagnostics after explicit operator override."
          : "Continue despite blocking diagnostics under workflow-configured operator override policy.",
      },
    ];
    const defaultDecision = diagnosticsRepairDefaultForDecisions(decisions, normalizedRepairDefault);
    return {
      schemaVersion: DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION,
      schema_version: DIAGNOSTICS_ROLLBACK_REPAIR_POLICY_SCHEMA_VERSION,
      object: "ioi.runtime_diagnostics_rollback_repair_policy",
      policyId,
      policy_id: policyId,
      threadId,
      thread_id: threadId,
      injectionId,
      injection_id: injectionId,
      mode,
      diagnosticStatus,
      diagnostic_status: diagnosticStatus,
      diagnosticCount,
      diagnostic_count: diagnosticCount,
      workspaceSnapshotRefs,
      workspace_snapshot_refs: workspaceSnapshotRefs,
      rollbackRefs,
      rollback_refs: rollbackRefs,
      sourceToolCallIds,
      source_tool_call_ids: sourceToolCallIds,
      restorePolicy: normalizedRestorePolicy,
      restore_policy: normalizedRestorePolicy,
      restoreConflictPolicy: normalizedRestoreConflictPolicy,
      restore_conflict_policy: normalizedRestoreConflictPolicy,
      diagnosticsRepairDefault: defaultDecision,
      diagnostics_repair_default: defaultDecision,
      operatorOverrideRequiresApproval: overrideRequiresApproval,
      operator_override_requires_approval: overrideRequiresApproval,
      defaultDecision,
      default_decision: defaultDecision,
      decisions,
      decisionRefs: decisions.map((decision) => decision.decisionId),
      decision_refs: decisions.map((decision) => decision.decision_id),
    };
  }

  function diagnosticsRepairDefaultForDecisions(decisions = [], preferredAction = "repair_retry") {
    const preferred = normalizeDiagnosticsRepairDefault(preferredAction);
    const decision = normalizeArray(decisions).find((item) => item?.action === preferred);
    if (decision && ["available", "requires_approval"].includes(decision.status)) {
      return preferred;
    }
    return "repair_retry";
  }

  return {
    diagnosticsRepairContextForPayload,
    diagnosticsRepairContextForRequest,
    diagnosticsRepairContextForToolPack,
    diagnosticsRepairContextRecord,
    diagnosticsRepairDefaultForDecisions,
    diagnosticsRepairPolicyConfig,
    diagnosticsRepairPolicyConfigForContexts,
    diagnosticsRollbackRepairPolicy,
    hasDiagnosticsRepairPolicyConfig,
    normalizeDiagnosticsMode,
    normalizeDiagnosticsRepairDefault,
    normalizeRestoreConflictPolicy,
    normalizeRestorePolicy,
  };
}
