import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import {
  DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_AUTO_NODE_ID,
} from "./runtime-contract-constants.mjs";
import { doctorHash, normalizeArray, optionalString, uniqueStrings } from "./runtime-value-helpers.mjs";

export function createRuntimeDiagnosticsFeedbackSurface(deps = {}) {
  const {
    compactDiagnosticsFeedback,
    diagnosticsRepairPolicyConfig,
    normalizeDiagnosticsMode,
    postEditDiagnosticsConfig,
  } = deps;

  function maybeRunPostEditDiagnostics(
    store,
    {
      threadId,
      turnId,
      patchToolCallId,
      patchResult,
      request = {},
      input = {},
      workflowGraphId = null,
    } = {},
  ) {
    const config = postEditDiagnosticsConfig(request, input);
    if (config.mode === "skip") return null;
    const paths = normalizeArray(patchResult?.changedFiles)
      .filter((entry) => entry?.diagnosticsRecommended !== false)
      .map((entry) => optionalString(entry?.path))
      .filter(Boolean);
    if (!paths.length) return null;
    const workspaceSnapshot =
      patchResult?.workspaceSnapshot ??
      patchResult?.workspace_snapshot ??
      null;
    const workspaceSnapshotId =
      optionalString(patchResult?.workspaceSnapshotId ?? patchResult?.workspace_snapshot_id) ??
      optionalString(workspaceSnapshot?.snapshotId ?? workspaceSnapshot?.snapshot_id);
    const rollbackRefs = uniqueStrings([
      workspaceSnapshotId,
      ...normalizeArray(patchResult?.rollbackRefs ?? patchResult?.rollback_refs),
    ]);
    const repairPolicyConfig = config.repairPolicyConfig ?? diagnosticsRepairPolicyConfig(request, input);
    return store.invokeThreadTool(threadId, "lsp.diagnostics", {
      source: "runtime_auto",
      turn_id: turnId || null,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: LSP_DIAGNOSTICS_AUTO_NODE_ID,
      tool_call_id: `coding_tool_lsp_diagnostics_auto_${doctorHash(`${patchToolCallId}:${paths.join(",")}`).slice(0, 16)}`,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: {
        schemaVersion: DIAGNOSTICS_ROLLBACK_REPAIR_CONTEXT_SCHEMA_VERSION,
        object: "ioi.runtime_diagnostics_rollback_repair_context",
        sourceToolName: "file.apply_patch",
        source_tool_name: "file.apply_patch",
        sourceToolCallId: patchToolCallId,
        source_tool_call_id: patchToolCallId,
        sourceWorkflowGraphId: workflowGraphId,
        source_workflow_graph_id: workflowGraphId,
        sourceWorkflowNodeId: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
        source_workflow_node_id: optionalString(request.workflow_node_id ?? request.workflowNodeId) ?? null,
        workspaceSnapshotId: workspaceSnapshotId ?? null,
        workspace_snapshot_id: workspaceSnapshotId ?? null,
        restorePolicy: repairPolicyConfig.restorePolicy,
        restore_policy: repairPolicyConfig.restorePolicy,
        restoreConflictPolicy: repairPolicyConfig.restoreConflictPolicy,
        restore_conflict_policy: repairPolicyConfig.restoreConflictPolicy,
        diagnosticsRepairDefault: repairPolicyConfig.diagnosticsRepairDefault,
        diagnostics_repair_default: repairPolicyConfig.diagnosticsRepairDefault,
        operatorOverrideRequiresApproval: repairPolicyConfig.operatorOverrideRequiresApproval,
        operator_override_requires_approval: repairPolicyConfig.operatorOverrideRequiresApproval,
        rollbackRefs,
        rollback_refs: rollbackRefs,
        restore: workspaceSnapshot?.restore ?? null,
        changedFiles: normalizeArray(patchResult?.changedFiles).map((entry) => ({
          path: optionalString(entry?.path) ?? null,
          beforeHash: optionalString(entry?.beforeHash ?? entry?.before_hash) ?? null,
          before_hash: optionalString(entry?.beforeHash ?? entry?.before_hash) ?? null,
          afterHash: optionalString(entry?.afterHash ?? entry?.after_hash) ?? null,
          after_hash: optionalString(entry?.afterHash ?? entry?.after_hash) ?? null,
          diagnosticsRecommended: entry?.diagnosticsRecommended !== false,
          diagnostics_recommended: entry?.diagnosticsRecommended !== false,
        })),
      },
      input: {
        commandId: config.commandId,
        paths,
        cwd: config.cwd,
        timeoutMs: config.timeoutMs,
        maxOutputBytes: config.maxOutputBytes,
      },
    });
  }

  function pendingDiagnosticsFeedbackForNextTurn(store, threadId, request = {}) {
    const injectionMode = normalizeDiagnosticsMode(
      request.diagnosticsMode ??
        request.diagnostics_mode ??
        request.options?.diagnosticsMode ??
        request.options?.diagnostics_mode ??
        "advisory",
    );
    if (injectionMode === "skip") return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const lastInjectedSeq = Math.max(
      0,
      ...stream.events
        .filter((event) => event.event_kind === "lsp.diagnostics.injected")
        .map((event) => Number(event.seq) || 0),
    );
    const diagnosticEvents = stream.events.filter((event) => {
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.seq > lastInjectedSeq &&
        event.event_kind === "tool.completed" &&
        event.source === "runtime_auto" &&
        payload.tool_name === "lsp.diagnostics"
      );
    });
    if (!diagnosticEvents.length) return null;
    return compactDiagnosticsFeedback({ threadId, mode: injectionMode, diagnosticEvents });
  }

  return {
    maybeRunPostEditDiagnostics,
    pendingDiagnosticsFeedbackForNextTurn,
  };
}
