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
  artifactReadRange,
  codingToolContracts,
  codingToolInputForRequest,
  codingToolInputSummary,
  codingToolResultSummary,
  codingToolSourceEventKind,
  codingToolSummary,
  retiredArtifactReadRangeAliases,
} from "./coding-tools.mjs";
import { createStepModuleRunnerFromEnv } from "./step-module-runner.mjs";

const RUST_WORKLOAD_LIVE_TOOL_IDS = new Set([
  "workspace.status",
  "git.diff",
  "file.inspect",
  "file.apply_patch",
  "test.run",
  "lsp.diagnostics",
  "artifact.read",
  "tool.retrieve_result",
  "computer_use.request_lease",
]);

export function createRuntimeCodingToolInvocationSurface(deps = {}) {
  const {
    codingToolApprovalManifestForThread,
    codingToolBudgetPolicyForRequest,
    codingToolInvocationResultFromEvent,
    codingToolResultWithoutDrafts,
    diagnosticsRepairContextForRequest,
    diagnosticsRepairContextForToolPack,
    stepModuleRunner = createStepModuleRunnerFromEnv(),
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
      optionalString(request.turn_id) ??
      optionalString(store.threadForAgent(agent).latest_turn_id) ??
      "";
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      `runtime.coding-tool.${safeId(normalizedToolId)}`;
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const toolCallId =
      optionalString(request.tool_call_id ?? request.toolCallId) ??
      `coding_tool_${doctorHash(`${threadId}:${normalizedToolId}:${JSON.stringify(input)}:${Date.now()}`).slice(0, 16)}`;
    const codingToolIdempotencyKey =
      optionalString(request.idempotency_key) ??
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
    const toolContract = codingToolContracts().find((tool) => tool.stable_tool_id === normalizedToolId);
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
        context_budget: budgetPolicy,
        budget_usage_telemetry: budgetPolicy.usage_telemetry,
        event_id: blocked.event?.event_id ?? null,
        receipt_refs: blocked.receipt_refs,
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
    const rustLiveCodingTool =
      stepModuleRunner.backend === "rust_workload_live" &&
      RUST_WORKLOAD_LIVE_TOOL_IDS.has(normalizedToolId);
    if (!rustLiveCodingTool) {
      throw policyError("Coding tool execution requires the Rust workload live backend.", {
        threadId,
        toolId: normalizedToolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_rust_workload_live_required",
        backend: stepModuleRunner.backend,
        rust_workload_live_supported: RUST_WORKLOAD_LIVE_TOOL_IDS.has(normalizedToolId),
      });
    }
    const artifactRefs = [];
    const receiptRefs = [receiptId];
    let status = "completed";
    let result = null;
    let error = null;
    let workspaceSnapshot = null;
    let workspaceSnapshotEvent = null;
    let stepModuleProjection = null;
    let stepModuleError = null;
    const stepModuleContext = ({ status, receiptRefs, artifactRefs, workflowProjectionStatus }) => ({
      runId: `run:${threadId}`,
      taskId: `task:${turnId || threadId}`,
      threadId,
      workflowGraphId,
      workflowNodeId,
      actionProposalRef: `action:coding-tool:${toolCallId}`,
      gateResultRef: approvalSatisfaction?.approvalId
        ? `gate:${approvalSatisfaction.approvalId}`
        : `gate:coding-tool:${toolCallId}`,
      approvalRef: approvalSatisfaction?.approvalId ?? null,
      idempotencyKey: codingToolIdempotencyKey,
      status: status === "failed" ? "failure" : "success",
      workflowProjectionStatus,
      receiptRefs,
      artifactRefs,
      workspaceRoot: agent.cwd,
    });
    try {
      const rustLiveInput = rustLiveInputForCodingTool(store, threadId, normalizedToolId, input);
      stepModuleProjection = stepModuleRunner.runCodingTool({
        contract: toolContract,
        toolId: normalizedToolId,
        input: rustLiveInput,
        result: {},
        context: stepModuleContext({
          status,
          receiptRefs,
          artifactRefs,
          workflowProjectionStatus: "live",
        }),
      });
      receiptRefs.push(
        ...normalizeArray(stepModuleProjection?.result?.receipt_refs),
        ...normalizeArray(stepModuleProjection?.bridge_result?.receipt_refs),
      );
      result = codingToolResultForRustLiveStepModule(normalizedToolId, stepModuleProjection);
      receiptRefs.push(...normalizeArray(result.receipt_refs));
      artifactRefs.push(...normalizeArray(result.artifact_refs));
      const liveArtifactDrafts = [
        ...normalizeArray(result?.artifactDrafts),
        ...normalizeArray(result?.artifact_drafts),
      ];
      if (liveArtifactDrafts.length) {
        const materializedArtifacts = store.materializeCodingToolArtifactDrafts({
          threadId,
          toolId: normalizedToolId,
          toolCallId,
          workspaceRoot: agent.cwd,
          result,
          receiptId,
        });
        result = codingToolResultWithoutDrafts(result, materializedArtifacts);
        artifactRefs.push(...normalizeArray(result.artifact_refs));
      }
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
        if (workspaceSnapshot) {
          result = {
            ...codingToolResultWithoutDrafts(result, []),
            workspaceSnapshot: workspaceSnapshot.record,
            workspace_snapshot: workspaceSnapshot.record,
            workspaceSnapshotId: workspaceSnapshot.record.snapshot_id,
            workspace_snapshot_id: workspaceSnapshot.record.snapshot_id,
          };
          artifactRefs.push(...workspaceSnapshot.record.artifact_refs);
          receiptRefs.push(...workspaceSnapshot.record.receipt_refs);
        }
      }
    } catch (caught) {
      status = "failed";
      stepModuleError = {
        code: caught?.code ?? "step_module_runner_failed",
        message: String(caught?.message ?? caught),
        details: caught?.details ?? null,
      };
      error = stepModuleError;
      result = {
        schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
        toolName: normalizedToolId,
        status,
        error,
      };
    }
    const summary = codingToolSummary(normalizedToolId, result, status);
    const rollbackRefs = uniqueStrings([
      ...(workspaceSnapshot ? [workspaceSnapshot.record.snapshot_id] : []),
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
      approval_required: Boolean(approvalManifest),
      approval_satisfied: Boolean(approvalSatisfaction?.satisfied),
      approval_id: approvalSatisfaction?.approvalId ?? null,
      approval_manifest: approvalManifest ?? null,
      approval_decision_event_id: approvalSatisfaction?.decisionEventId ?? null,
      receipt_id: receiptId,
      receipt_count: receiptRefs.length,
      artifact_count: artifactRefs.length,
      step_module_backend: stepModuleProjection?.backend ?? stepModuleRunner.backend,
      step_module_invocation: stepModuleProjection?.invocation ?? null,
      step_module_result: stepModuleProjection?.result ?? null,
      step_module_error: stepModuleError,
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
      step_module: stepModuleProjection,
      stepModule: stepModuleProjection,
      step_module_error: stepModuleError,
      stepModuleError,
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

function rustLiveInputForCodingTool(store, threadId, toolId, input = {}) {
  if (toolId === "artifact.read") {
    if (typeof store.readCodingToolArtifact !== "function") {
      throw toolInputError(
        "artifact_read_unavailable",
        "artifact.read requires a daemon artifact store.",
        { threadId, toolId },
      );
    }
    const artifactId = optionalString(input.artifact_id ?? input.artifact_ref);
    if (!artifactId) {
      throw toolInputError(
        "artifact_read_id_required",
        "artifact.read requires artifact_id or artifact_ref.",
        { threadId, toolId },
      );
    }
    assertNoRetiredArtifactReadRangeAliases(input, { threadId, toolId, artifact_id: artifactId });
    const range = artifactReadRange(input);
    return {
      ...input,
      rustWorkloadDataPlane: {
        schemaVersion: "ioi.runtime.coding-tool-data-plane.v1",
        source: "daemon_artifact_store",
        operation: toolId,
        artifact_id: artifactId,
        artifact_ref: artifactId,
        range,
        result: store.readCodingToolArtifact(threadId, artifactId, range),
      },
    };
  }
  if (toolId === "tool.retrieve_result") {
    if (typeof store.retrieveCodingToolResult !== "function") {
      throw toolInputError(
        "tool_retrieve_result_unavailable",
        "tool.retrieve_result requires a daemon artifact store.",
        { threadId, toolId },
      );
    }
    const toolCallId = optionalString(input.tool_call_id);
    const artifactId = optionalString(input.artifact_id ?? input.artifact_ref);
    if (!toolCallId && !artifactId) {
      throw toolInputError(
        "tool_retrieve_result_target_required",
        "tool.retrieve_result requires tool_call_id or artifact_id.",
        { threadId, toolId },
      );
    }
    assertNoRetiredArtifactReadRangeAliases(input, {
      threadId,
      toolId,
      tool_call_id: toolCallId,
      artifact_id: artifactId,
    });
    const range = artifactReadRange(input);
    const query = {
      tool_call_id: toolCallId,
      artifact_id: artifactId,
      channel: optionalString(input.channel),
      range,
    };
    return {
      ...input,
      rustWorkloadDataPlane: {
        schemaVersion: "ioi.runtime.coding-tool-data-plane.v1",
        source: "daemon_artifact_store",
        operation: toolId,
        query,
        result: store.retrieveCodingToolResult(threadId, query),
      },
    };
  }
  return input;
}

function assertNoRetiredArtifactReadRangeAliases(input = {}, details = {}) {
  const retiredAliases = retiredArtifactReadRangeAliases(input);
  if (retiredAliases.length === 0) return;
  throw toolInputError(
    "artifact_read_range_aliases_retired",
    "Artifact read range aliases are retired; use canonical offset_bytes, length_bytes, or max_bytes.",
    {
      ...details,
      retired_aliases: retiredAliases,
    },
  );
}

function toolInputError(code, message, details = {}) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function codingToolResultForRustLiveStepModule(toolId, stepModuleProjection = {}) {
  const stepResult = stepModuleProjection?.result ?? {};
  const observedResult = stepModuleProjection?.bridge_result?.shadow_observation?.result;
  const toolResult =
    observedResult && typeof observedResult === "object" && !Array.isArray(observedResult)
      ? observedResult
      : {};
  const {
    executionResultRef,
    normalizedObservationRef,
    receiptRefs,
    rustWorkload,
    schemaVersion,
    stepModuleBackend,
    toolName,
    artifactRefs,
    ...canonicalToolResult
  } = toolResult;
  return {
    ...canonicalToolResult,
    schema_version: toolResult.schema_version ?? schemaVersion ?? CODING_TOOL_RESULT_SCHEMA_VERSION,
    tool_name: toolResult.tool_name ?? toolName ?? toolId,
    status: "completed",
    rust_workload: true,
    backend: toolResult.backend ?? stepModuleProjection?.backend ?? "rust_workload_live",
    step_module_backend: stepModuleProjection?.backend ?? "rust_workload_live",
    execution_result_ref: stepResult.execution_result_ref ?? null,
    normalized_observation_ref: stepResult.normalized_observation_ref ?? null,
    router_admission: stepModuleProjection?.bridge_result?.router_admission ?? null,
    receipt_refs: normalizeArray(stepResult.receipt_refs),
    observation: stepModuleProjection?.bridge_result?.shadow_observation ?? null,
  };
}
