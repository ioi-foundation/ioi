import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { notFound, policyError } from "./runtime-http-utils.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import {
  COMPUTER_USE_BROWSER_DISCOVERY_TOOL_IDS,
  COMPUTER_USE_CONTROL_TOOL_IDS,
  COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS,
  COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS,
  COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS,
  COMPUTER_USE_VISUAL_GUI_TOOL_IDS,
} from "./runtime-contract-constants.mjs";
import {
  CODING_TOOL_IDS,
  CODING_TOOL_PACK_ID,
  CODING_TOOL_RESULT_SCHEMA_VERSION,
  codingToolContracts,
  codingToolInputForRequest,
  codingToolInputSummary,
  codingToolResultSummary,
  codingToolSourceEventKind,
  codingToolSummary,
  executeCodingTool as defaultExecuteCodingTool,
} from "./coding-tools.mjs";

export function createRuntimeCodingToolInvocationSurface(deps = {}) {
  const {
    codingToolApprovalManifestForThread,
    codingToolBudgetPolicyForRequest,
    codingToolInvocationResultFromEvent,
    codingToolResultWithoutDrafts,
    diagnosticsRepairContextForRequest,
    diagnosticsRepairContextForToolPack,
    executeCodingTool = defaultExecuteCodingTool,
  } = deps;

  function invokeThreadTool(store, threadId, toolId, request = {}) {
    const agent = store.agentForThread(threadId);
    const normalizedToolId = optionalString(toolId);
    if (COMPUTER_USE_BROWSER_DISCOVERY_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseBrowserDiscoveryTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_CONTROL_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseControlTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_NATIVE_BROWSER_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseNativeBrowserTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseVisualGuiTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_SANDBOXED_HOSTED_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseSandboxedHostedTool(threadId, normalizedToolId, request);
    }
    if (COMPUTER_USE_VISUAL_GUI_OBSERVE_TOOL_IDS.has(normalizedToolId)) {
      return store.invokeComputerUseVisualGuiObserveTool(threadId, normalizedToolId, request);
    }
    if (!normalizedToolId || !CODING_TOOL_IDS.has(normalizedToolId)) {
      throw notFound(`Coding tool not found: ${toolId}`, {
        threadId,
        toolId,
        pack: CODING_TOOL_PACK_ID,
      });
    }
    const input = codingToolInputForRequest(request);
    const turnId =
      optionalString(request.turn_id ?? request.turnId) ??
      optionalString(store.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id ?? request.workflowNodeId) ??
      `runtime.coding-tool.${safeId(normalizedToolId)}`;
    const workflowGraphId = optionalString(request.workflow_graph_id ?? request.workflowGraphId) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `coding_tool_${doctorHash(`${threadId}:${normalizedToolId}:${JSON.stringify(input)}:${Date.now()}`).slice(0, 16)}`;
    const codingToolIdempotencyKey =
      optionalString(request.idempotency_key ?? request.idempotencyKey) ??
      `thread:${threadId}:coding-tool:${toolCallId}`;
    const duplicateToolEvent = store.runtimeEventStream(eventStreamIdForThread(threadId)).idempotency.get(
      codingToolIdempotencyKey,
    );
    if (duplicateToolEvent) {
      return codingToolInvocationResultFromEvent(duplicateToolEvent, {
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
        toolCallId,
        workflowGraphId,
        workflowNodeId,
      });
    }
    const receiptId = `receipt_coding_tool_${safeId(normalizedToolId)}_${doctorHash(
      `${threadId}:${normalizedToolId}:${toolCallId}`,
    ).slice(0, 12)}`;
    const requestRollbackRefs = uniqueStrings(normalizeArray(request.rollbackRefs ?? request.rollback_refs));
    const diagnosticsRepairContext =
      diagnosticsRepairContextForRequest(request) ??
      diagnosticsRepairContextForToolPack(request, input, normalizedToolId);
    const toolContract = codingToolContracts().find((tool) => tool.stableToolId === normalizedToolId);
    const budgetPolicy = codingToolBudgetPolicyForRequest({
      request,
      threadId,
      toolId: normalizedToolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
    });
    if (budgetPolicy?.status === "blocked") {
      const blocked = store.blockCodingToolForBudget({
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
        toolCallId,
        receiptId,
        input,
        request,
        workflowGraphId,
        workflowNodeId,
        requestRollbackRefs,
        diagnosticsRepairContext,
        budgetPolicy,
        toolContract,
        codingToolIdempotencyKey,
      });
      throw policyError("Coding tool budget limit exceeded.", {
        threadId,
        toolId: normalizedToolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_budget_exceeded",
        budget_status: "exceeded",
        context_budget_status: budgetPolicy.status,
        contextBudgetStatus: budgetPolicy.status,
        context_budget: budgetPolicy,
        contextBudget: budgetPolicy,
        budget_usage_telemetry: budgetPolicy.usage_telemetry,
        budgetUsageTelemetry: budgetPolicy.usageTelemetry,
        eventId: blocked.event?.event_id ?? null,
        event_id: blocked.event?.event_id ?? null,
        receiptRefs: blocked.receipt_refs,
        receipt_refs: blocked.receipt_refs,
        policyDecisionRefs: blocked.policy_decision_refs,
        policy_decision_refs: blocked.policy_decision_refs,
      });
    }
    const approvalManifest = codingToolApprovalManifestForThread({
      agent,
      threadId,
      turnId,
      toolId: normalizedToolId,
      toolCallId,
      toolContract,
      input,
      request,
      workflowGraphId,
      workflowNodeId,
    });
    const approvalSatisfaction = approvalManifest
      ? store.codingToolApprovalSatisfaction({ threadId, approvalManifest, request })
      : null;
    if (approvalManifest && !approvalSatisfaction?.satisfied) {
      return store.blockCodingToolForApproval({
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
        toolCallId,
        receiptId,
        input,
        request,
        workflowGraphId,
        workflowNodeId,
        requestRollbackRefs,
        diagnosticsRepairContext,
        approvalManifest,
        toolContract,
      });
    }
    const artifactRefs = [];
    const receiptRefs = [receiptId];
    let status = "completed";
    let result = null;
    let error = null;
    let workspaceSnapshot = null;
    let workspaceSnapshotEvent = null;
    try {
      result = executeCodingTool(normalizedToolId, agent.cwd, input, {
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        readArtifact: (artifactId, range) => store.readCodingToolArtifact(threadId, artifactId, range),
        retrieveToolResult: (query) => store.retrieveCodingToolResult(threadId, query),
      });
      const materializedArtifacts = store.materializeCodingToolArtifactDrafts({
        threadId,
        toolId: normalizedToolId,
        toolCallId,
        workspaceRoot: agent.cwd,
        result,
        receiptId,
      });
      if (normalizedToolId === "file.apply_patch") {
        workspaceSnapshot = store.prepareWorkspaceSnapshotForPatch({
          threadId,
          turnId,
          workspaceRoot: agent.cwd,
          toolCallId,
          workflowGraphId,
          workflowNodeId,
          result,
        });
      }
      result = codingToolResultWithoutDrafts(result, materializedArtifacts);
      artifactRefs.push(...normalizeArray(result.artifactRefs));
      receiptRefs.push(...normalizeArray(result.receiptRefs));
      if (workspaceSnapshot) {
        result = {
          ...result,
          workspaceSnapshot: workspaceSnapshot.record,
          workspace_snapshot: workspaceSnapshot.record,
          workspaceSnapshotId: workspaceSnapshot.record.snapshotId,
          workspace_snapshot_id: workspaceSnapshot.record.snapshotId,
        };
        artifactRefs.push(...workspaceSnapshot.record.artifactRefs);
        receiptRefs.push(...workspaceSnapshot.record.receiptRefs);
      }
    } catch (caught) {
      status = "failed";
      error = {
        code: caught?.code ?? "coding_tool_failed",
        message: String(caught?.message ?? caught),
        details: caught?.details ?? null,
      };
      result = {
        schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
        toolName: normalizedToolId,
        status,
        error,
      };
    }
    const summary = codingToolSummary(normalizedToolId, result, status);
    const rollbackRefs = uniqueStrings([
      ...(workspaceSnapshot ? [workspaceSnapshot.record.snapshotId] : []),
      ...requestRollbackRefs,
    ]);
    const payloadSummary = {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      event_kind: "CodingToolResult",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      status,
      summary,
      shell_fallback_used: false,
      input_summary: codingToolInputSummary(normalizedToolId, input),
      result_summary: codingToolResultSummary(normalizedToolId, result),
      result,
      error,
      rollback_refs: rollbackRefs,
      diagnostics_repair_context: diagnosticsRepairContext,
      diagnosticsRepairContext,
      approval_required: Boolean(approvalManifest),
      approvalRequired: Boolean(approvalManifest),
      approval_satisfied: Boolean(approvalSatisfaction?.satisfied),
      approvalSatisfied: Boolean(approvalSatisfaction?.satisfied),
      approval_id: approvalSatisfaction?.approvalId ?? null,
      approvalId: approvalSatisfaction?.approvalId ?? null,
      approval_manifest: approvalManifest ?? null,
      approvalManifest: approvalManifest ?? null,
      approval_decision_event_id: approvalSatisfaction?.decisionEventId ?? null,
      approvalDecisionEventId: approvalSatisfaction?.decisionEventId ?? null,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: artifactRefs.length,
    };
    const commandStreamEvents = store.appendCodingToolCommandStreamEvents({
      agent,
      threadId,
      turnId,
      toolId: normalizedToolId,
      toolCallId,
      workflowGraphId,
      workflowNodeId,
      request,
      result,
      status,
      receiptRefs,
      artifactRefs,
    });
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:coding-tool:${safeId(normalizedToolId)}:${doctorHash(toolCallId).slice(0, 12)}`,
      idempotency_key: codingToolIdempotencyKey,
      source: operatorControlSource(request.source),
      source_event_kind: codingToolSourceEventKind(normalizedToolId),
      event_kind: status === "failed" ? "tool.failed" : "tool.completed",
      status,
      actor: "runtime",
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      tool_call_id: toolCallId,
      artifact_refs: artifactRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      rollback_refs: rollbackRefs,
      payload_schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      payload_summary: payloadSummary,
    });
    if (workspaceSnapshot) {
      workspaceSnapshotEvent = store.appendWorkspaceSnapshotEvent({
        threadId,
        turnId,
        workspaceRoot: agent.cwd,
        workflowGraphId,
        snapshot: workspaceSnapshot.record,
        sourceToolEvent: event,
      });
    }
    const autoDiagnostics =
      status === "completed" && normalizedToolId === "file.apply_patch"
        ? store.maybeRunPostEditDiagnostics({
            threadId,
            turnId,
            patchToolCallId: toolCallId,
            patchResult: result,
            request,
            input,
            workflowGraphId,
          })
        : null;
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: normalizedToolId,
      tool_call_id: toolCallId,
      thread_id: threadId,
      turn_id: turnId || null,
      status,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      rollback_refs: event.rollback_refs,
      event,
      workspace_snapshot: workspaceSnapshot?.record ?? null,
      workspaceSnapshot: workspaceSnapshot?.record ?? null,
      workspace_snapshot_event: workspaceSnapshotEvent,
      workspaceSnapshotEvent,
      auto_diagnostics: autoDiagnostics,
      autoDiagnostics,
      command_stream_events: commandStreamEvents,
      commandStreamEvents,
      result,
      error,
    };
  }

  return {
    invokeThreadTool,
  };
}
