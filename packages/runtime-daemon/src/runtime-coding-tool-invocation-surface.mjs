import { eventStreamIdForThread } from "./runtime-identifiers.mjs";
import { notFound, policyError, runtimeError } from "./runtime-http-utils.mjs";
import {
  doctorHash,
  normalizeArray,
  objectRecord,
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
  codingToolSummary,
  retiredArtifactReadRangeAliases,
} from "./coding-tools.mjs";

const WORKLOAD_STEP_MODULE_API_METHOD = "runCodingToolStepModule";
const CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-step-module-request.v1";

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
    codingToolApprovalBlockForThread = requireRustCoreCodingToolApprovalBlock,
    codingToolApprovalManifestForThread,
    codingToolApprovalSatisfactionForThread = () => null,
    codingToolBudgetPolicyForRequest,
    codingToolResultWithoutDrafts,
    diagnosticsRepairContextForRequest,
    diagnosticsRepairContextForToolPack,
    codingToolResultEnvelopeForThread = requireRustCoreCodingToolResultEnvelopePlanning,
    codingToolResultEventAdmissionForThread = requireRustCoreCodingToolResultEventAdmission,
    daemonCoreWorkloadApi = null,
    workloadGrpcAddr = null,
    workloadShmemId = null,
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
        thread_id: threadId,
        tool_id: toolId,
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
      optionalString(request.tool_call_id) ??
      `coding_tool_${doctorHash(`${threadId}:${normalizedToolId}:${JSON.stringify(input)}:${Date.now()}`).slice(0, 16)}`;
    const codingToolIdempotencyKey =
      optionalString(request.idempotency_key) ??
      `thread:${threadId}:coding-tool:${toolCallId}`;
    const receiptId = `receipt_coding_tool_${safeId(normalizedToolId)}_${doctorHash(
      `${threadId}:${normalizedToolId}:${toolCallId}`,
    ).slice(0, 12)}`;
    const requestRollbackRefs = uniqueStrings(normalizeArray(request.rollback_refs));
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
      const blocked = store.codingToolGovernanceSurface.blockCodingToolForBudget(store, {
        agent,
        threadId,
        turnId,
        toolId: normalizedToolId,
        toolCallId,
        workspaceRoot: agent.cwd,
        receiptId,
        inputSummary: codingToolInputSummary(normalizedToolId, input),
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
      const admittedBlockEvent = codingToolResultEventAdmissionForThread(store, {
        event: blocked.event,
        budget_block: blocked.record ?? blocked,
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
        event_id: admittedBlockEvent?.event_id ?? blocked.event?.event_id ?? null,
        receipt_refs: uniqueStrings([
          ...normalizeArray(blocked.receipt_refs),
          ...normalizeArray(admittedBlockEvent?.receipt_refs),
        ]),
        policy_decision_refs: uniqueStrings(blocked.policy_decision_refs),
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
    let approvalGate = null;
    if (approvalManifest) {
      approvalGate = codingToolApprovalSatisfactionForThread({
        store,
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
        approval_manifest: approvalManifest,
        toolContract,
      });
      if (!approvalGate?.satisfied) {
        const blocked = codingToolApprovalBlockForThread({
          store,
          agent,
          threadId,
          turnId,
          toolId: normalizedToolId,
          toolCallId,
          workspaceRoot: agent.cwd,
          receiptId,
          input,
          request,
          workflowGraphId,
          workflowNodeId,
          rollbackRefs: requestRollbackRefs,
          diagnosticsRepairContext,
          approval_manifest: approvalManifest,
          approval_gate: approvalGate,
          toolContract,
          idempotencyKey: codingToolIdempotencyKey,
          receiptRefs: uniqueStrings([
            receiptId,
            ...normalizeArray(approvalGate?.receipt_refs),
          ]),
          policyDecisionRefs: uniqueStrings(normalizeArray(approvalGate?.policy_decision_refs)),
        });
        const blockedEvent = codingToolResultEventAdmissionForThread(store, {
          event: blocked.event,
          approval_block: blocked.record ?? blocked,
        });
        return {
          schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
          object: "ioi.runtime_coding_tool_result",
          tool_pack: CODING_TOOL_PACK_ID,
          tool_name: normalizedToolId,
          tool_call_id: toolCallId,
          thread_id: threadId,
          turn_id: turnId || null,
          status: blocked.status ?? "blocked",
          workspace_root: agent.cwd,
          workflow_graph_id: workflowGraphId,
          workflow_node_id: workflowNodeId,
          shell_fallback_used: false,
          approval_required: true,
          approval_satisfied: false,
          approval_id: blocked.approval_id ?? approvalGate?.approval_id ?? null,
          approval_manifest: approvalManifest,
          receipt_refs: uniqueStrings(blockedEvent.receipt_refs),
          artifact_refs: uniqueStrings(blockedEvent.artifact_refs),
          rollback_refs: uniqueStrings(blockedEvent.rollback_refs),
          event: blockedEvent,
          workspace_snapshot: null,
          workspace_snapshot_event: null,
          auto_diagnostics: null,
          step_module: null,
          step_module_error: null,
          command_stream_events: [],
          result: blocked.result,
          error: blocked.result?.error ?? blocked.event?.payload_summary?.error ?? null,
          approval_block: blocked.record ?? blocked,
        };
      }
    }
    const rustLiveCodingTool = RUST_WORKLOAD_LIVE_TOOL_IDS.has(normalizedToolId);
    if (!rustLiveCodingTool) {
      throw policyError("Coding tool execution requires the Rust workload live backend.", {
        threadId,
        toolId: normalizedToolId,
        tool_call_id: toolCallId,
        reason: "coding_tool_rust_workload_live_required",
        backend: "rust_workload_live",
        rust_workload_live_supported: RUST_WORKLOAD_LIVE_TOOL_IDS.has(normalizedToolId),
      });
    }
    const artifactRefs = [];
    const receiptRefs = uniqueStrings([
      receiptId,
      ...normalizeArray(approvalGate?.receipt_refs),
    ]);
    const policyDecisionRefs = uniqueStrings(normalizeArray(approvalGate?.policy_decision_refs));
    const resultEnvelopeBase = () => ({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId || null,
      tool_id: normalizedToolId,
      tool_call_id: toolCallId,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      idempotency_key: codingToolIdempotencyKey,
      source: operatorControlSource(request.source),
      receipt_id: receiptId,
      diagnostics_repair_context: diagnosticsRepairContext ?? null,
      approval_required: Boolean(approvalManifest),
      approval_satisfied: Boolean(approvalGate?.satisfied),
      approval_id: approvalGate?.approval_id ?? null,
      approval_manifest: approvalManifest ?? null,
      approval_decision_event_id: approvalGate?.decision_event_id ?? null,
      approval_receipt_refs: normalizeArray(approvalGate?.receipt_refs),
      approval_policy_decision_refs: policyDecisionRefs,
    });
    const stepModuleEnvelope = codingToolResultEnvelopeForThread(store, {
      ...resultEnvelopeBase(),
      phase: "step_module_context",
      status: "completed",
      receipt_refs: receiptRefs,
      artifact_refs: artifactRefs,
      rollback_refs: requestRollbackRefs,
    });
    const stepModuleContext = requireRustPlannedStepModuleContext(stepModuleEnvelope, {
      thread_id: threadId,
      tool_id: normalizedToolId,
      tool_call_id: toolCallId,
      phase: "step_module_context",
    });
    const runCodingToolStepModule = requireRustWorkloadStepModuleApi(daemonCoreWorkloadApi, {
      thread_id: threadId,
      tool_id: normalizedToolId,
      tool_call_id: toolCallId,
    });
    let status = "completed";
    let result = null;
    let error = null;
    let workspaceSnapshot = null;
    let workspaceSnapshotEvent = null;
    let stepModuleProjection = null;
    let stepModuleError = null;
    try {
      const rustLiveInput = rustLiveInputForCodingTool(store, threadId, normalizedToolId, input);
      stepModuleProjection = runCodingToolStepModuleViaDaemonCore({
        runCodingToolStepModule,
        workloadGrpcAddr,
        workloadShmemId,
        toolId: normalizedToolId,
        input: rustLiveInput,
        context: stepModuleContext,
      });
      receiptRefs.push(
        ...normalizeArray(stepModuleProjection?.result?.receipt_refs),
        ...normalizeArray(stepModuleProjection?.workload_result?.receipt_refs),
      );
      result = codingToolResultForRustLiveStepModule(normalizedToolId, stepModuleProjection);
      receiptRefs.push(...normalizeArray(result.receipt_refs));
      artifactRefs.push(...normalizeArray(result.artifact_refs));
      const liveArtifactDrafts = normalizeArray(result?.artifact_drafts);
      if (liveArtifactDrafts.length) {
        const materializedArtifacts = store.codingToolArtifactSurface.materializeCodingToolArtifactDrafts(store, {
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
        workspaceSnapshot = store.workspaceSnapshotSurface.prepareWorkspaceSnapshotForPatch(store, {
          threadId,
          turnId,
          workspaceRoot: agent.cwd,
          toolCallId,
          workflowGraphId,
          workflowNodeId,
          result,
        });
        if (workspaceSnapshot) {
          workspaceSnapshotEvent = workspaceSnapshot.event ?? null;
          result = {
            ...codingToolResultWithoutDrafts(result, []),
            workspace_snapshot: workspaceSnapshot.record,
            workspace_snapshot_id: workspaceSnapshot.record.snapshot_id,
          };
          artifactRefs.push(...workspaceSnapshot.record.artifact_refs);
          receiptRefs.push(...workspaceSnapshot.record.receipt_refs);
        }
      }
    } catch (caught) {
      status = "failed";
      stepModuleError = {
        code: caught?.code ?? "step_module_execution_failed",
        message: String(caught?.message ?? caught),
        details: caught?.details ?? null,
      };
      error = stepModuleError;
      result = {
        schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
        tool_name: normalizedToolId,
        status,
        error,
      };
    }
    const summary = codingToolSummary(normalizedToolId, result, status);
    const rollbackRefs = uniqueStrings([
      ...(workspaceSnapshot ? [workspaceSnapshot.record.snapshot_id] : []),
      ...requestRollbackRefs,
    ]);
    const resultEnvelope = codingToolResultEnvelopeForThread(store, {
      ...resultEnvelopeBase(),
      phase: "result_event",
      status,
      summary,
      input_summary: codingToolInputSummary(normalizedToolId, input),
      result_summary: codingToolResultSummary(normalizedToolId, result),
      result,
      error,
      rollback_refs: rollbackRefs,
      receipt_refs: uniqueStrings(receiptRefs),
      artifact_refs: uniqueStrings(artifactRefs),
      step_module_backend: stepModuleProjection?.backend ?? "rust_workload_live",
      step_module: stepModuleProjection,
      step_module_error: stepModuleError,
    });
    const resultEvent = requireRustPlannedResultEvent(resultEnvelope, {
      thread_id: threadId,
      tool_id: normalizedToolId,
      tool_call_id: toolCallId,
      phase: "result_event",
    });
    const commandStreamEvents = store.codingToolArtifactSurface.admitCodingToolCommandStreamEvents(store, {
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
    const event = codingToolResultEventAdmissionForThread(store, {
      event: resultEvent,
      result_envelope: resultEnvelope.record ?? resultEnvelope,
    });
    const autoDiagnostics =
      status === "completed" && normalizedToolId === "file.apply_patch"
        ? store.diagnosticsFeedbackSurface.maybeRunPostEditDiagnostics(store, {
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
      workspace_snapshot_event: workspaceSnapshotEvent,
      auto_diagnostics: autoDiagnostics,
      step_module: stepModuleProjection,
      step_module_error: stepModuleError,
      command_stream_events: commandStreamEvents,
      result,
      error,
    };
  }

  return {
    invokeThreadTool,
  };
}

function requireRustWorkloadStepModuleApi(daemonCoreWorkloadApi, details = {}) {
  const invoke =
    daemonCoreWorkloadApi && typeof daemonCoreWorkloadApi === "object"
      ? daemonCoreWorkloadApi[WORKLOAD_STEP_MODULE_API_METHOD]
      : null;
  if (typeof invoke === "function") return invoke.bind(daemonCoreWorkloadApi);
  throw runtimeError({
    status: 501,
    code: "runtime_coding_tool_workload_rust_core_required",
    message: "Coding-tool StepModule execution requires daemonCoreWorkloadApi.runCodingToolStepModule.",
    details: {
      rust_core_boundary: "runtime.coding_tool_invocation",
      operation: "coding_tool_step_module_execution",
      operation_kind: "runtime.coding_tool.step_module",
      ...details,
      evidence_refs: [
        "step_module_runner_js_facade_retired",
        "rust_daemon_core_workload_api_required",
        "step_module_router_dispatch_required",
      ],
    },
  });
}

function runCodingToolStepModuleViaDaemonCore({
  runCodingToolStepModule,
  workloadGrpcAddr,
  workloadShmemId,
  toolId,
  input,
  context,
}) {
  const request = {
    schema_version: CODING_TOOL_STEP_MODULE_REQUEST_SCHEMA_VERSION,
    workload_grpc_addr: optionalString(workloadGrpcAddr),
    shmem_id: optionalString(workloadShmemId),
    tool_id: optionalString(toolId),
    workspace_root: context.workspace_root ?? null,
    run_id: context.run_id ?? null,
    task_id: context.task_id ?? null,
    thread_id: context.thread_id ?? null,
    workflow_graph_id: context.workflow_graph_id ?? null,
    workflow_node_id: context.workflow_node_id ?? null,
    context_chamber_ref: context.context_chamber_ref ?? null,
    action_proposal_ref: context.action_proposal_ref ?? null,
    gate_result_ref: context.gate_result_ref ?? null,
    authority_grant_refs: uniqueStrings(normalizeArray(context.authority_grant_refs)),
    approval_ref: context.approval_ref ?? null,
    state_root_before: context.state_root_before ?? null,
    projection_watermark: context.projection_watermark ?? null,
    artifact_refs: uniqueStrings(normalizeArray(context.artifact_refs)),
    payload_refs: uniqueStrings(normalizeArray(context.payload_refs)),
    data_plane_handle: context.data_plane_handle ?? null,
    idempotency_key: context.idempotency_key ?? null,
    deadline_ms: context.deadline_ms ?? null,
    manifest_ref: context.manifest_ref ?? null,
    input,
  };
  const response = runCodingToolStepModule(request);
  const responseError = objectRecord(response?.error);
  if (response?.ok === false && responseError) {
    const error = new Error(
      responseError.message ?? "Rust workload StepModule core rejected the invocation.",
    );
    error.status = responseError.status ?? 502;
    error.code = responseError.code ?? "rust_workload_api_rejected";
    error.details = { error: responseError };
    throw error;
  }
  const workloadApiResult = normalizeWorkloadApiResult(
    response?.ok === true ? response.result : response,
    { source: "rust_workload_api" },
  );
  return {
    backend: "rust_workload_live",
    mode: "live",
    blocking: true,
    source: workloadApiResult.source,
    workload_result: workloadApiResult,
    invocation: workloadApiResult.invocation ?? null,
    result: workloadApiResult.result ?? null,
  };
}

function normalizeWorkloadApiResult(value, defaults = {}) {
  const result = objectRecord(value) ?? {};
  return {
    ...result,
    source: result.source ?? defaults.source ?? "rust_workload",
    invocation: result.invocation ?? defaults.invocation ?? null,
    result: result.result ?? null,
    evidence_refs: Array.isArray(result.evidence_refs) ? result.evidence_refs : [],
    receipt_refs: Array.isArray(result.receipt_refs) ? result.receipt_refs : [],
  };
}

function requireRustCoreCodingToolResultEventAdmission(_store, input = {}) {
  const event = input?.event && typeof input.event === "object" ? input.event : input;
  throw runtimeError({
    status: 501,
    code: "runtime_coding_tool_invocation_rust_core_required",
    message: "Runtime coding-tool result event admission requires direct Rust daemon-core admission and persistence.",
    details: {
      rust_core_boundary: "runtime.coding_tool_invocation",
      operation: "coding_tool_result_event_admission",
      operation_kind: "runtime.coding_tool_result_event",
      thread_id: event.thread_id ?? null,
      turn_id: event.turn_id ?? null,
      tool_name: event.payload_summary?.tool_name ?? null,
      tool_call_id: event.tool_call_id ?? null,
      workflow_graph_id: event.workflow_graph_id ?? null,
      workflow_node_id: event.workflow_node_id ?? null,
      status: event.status ?? null,
      receipt_refs: uniqueStrings(event.receipt_refs),
      artifact_refs: uniqueStrings(event.artifact_refs),
      evidence_refs: [
        "coding_tool_result_event_js_append_retired",
        "rust_daemon_core_coding_tool_result_event_admission_required",
        "agentgres_coding_tool_expected_head_required",
      ],
    },
  });
}

function requireRustCoreCodingToolResultEnvelopePlanning(_store, input = {}) {
  throw runtimeError({
    status: 501,
    code: "runtime_coding_tool_result_envelope_rust_core_required",
    message: "Runtime coding-tool result envelope planning requires direct Rust daemon-core context and event authorship.",
    details: {
      rust_core_boundary: "runtime.coding_tool_invocation",
      operation: "coding_tool_result_envelope_planning",
      operation_kind: "runtime.coding_tool.result_envelope",
      phase: input.phase ?? null,
      thread_id: input.thread_id ?? null,
      turn_id: input.turn_id ?? null,
      tool_name: input.tool_id ?? null,
      tool_call_id: input.tool_call_id ?? null,
      workflow_graph_id: input.workflow_graph_id ?? null,
      workflow_node_id: input.workflow_node_id ?? null,
      evidence_refs: [
        "coding_tool_result_envelope_js_authoring_retired",
        "rust_daemon_core_coding_tool_result_envelope_required",
        "agentgres_coding_tool_result_event_admission_required",
      ],
    },
  });
}

function requireRustPlannedStepModuleContext(plan = {}, details = {}) {
  const context = objectRecord(plan.step_module_context);
  if (
    plan.operation_kind !== "runtime.coding_tool.result_envelope" ||
    plan.phase !== "step_module_context" ||
    !context ||
    context.workflow_projection_status !== "live" ||
    context.thread_id !== details.thread_id ||
    context.workflow_node_id == null
  ) {
    throw runtimeError({
      status: 502,
      code: "runtime_coding_tool_result_envelope_invalid",
      message: "Rust daemon-core coding-tool result envelope plan did not include a valid StepModule context.",
      details: {
        ...details,
        operation: "coding_tool_result_envelope_planning",
        operation_kind: plan.operation_kind ?? null,
        planned_phase: plan.phase ?? null,
        envelope_hash: plan.envelope_hash ?? null,
      },
    });
  }
  return context;
}

function requireRustPlannedResultEvent(plan = {}, details = {}) {
  const event = objectRecord(plan.event);
  const payloadSummary = objectRecord(event?.payload_summary);
  if (
    plan.operation_kind !== "runtime.coding_tool.result_envelope" ||
    plan.phase !== "result_event" ||
    !event ||
    !payloadSummary ||
    event.thread_id !== details.thread_id ||
    event.tool_call_id !== details.tool_call_id ||
    payloadSummary.tool_name !== details.tool_id ||
    event.payload_schema_version !== CODING_TOOL_RESULT_SCHEMA_VERSION
  ) {
    throw runtimeError({
      status: 502,
      code: "runtime_coding_tool_result_envelope_invalid",
      message: "Rust daemon-core coding-tool result envelope plan did not include a valid result event.",
      details: {
        ...details,
        operation: "coding_tool_result_envelope_planning",
        operation_kind: plan.operation_kind ?? null,
        planned_phase: plan.phase ?? null,
        envelope_hash: plan.envelope_hash ?? null,
      },
    });
  }
  return event;
}

function requireRustCoreCodingToolApprovalBlock(input = {}) {
  const threadId = input.thread_id ?? input.threadId ?? null;
  const turnId = input.turn_id ?? input.turnId ?? null;
  const toolName = input.tool_id ?? input.toolId ?? null;
  const toolCallId = input.tool_call_id ?? input["toolCallId"] ?? null;
  const workflowGraphId = input.workflow_graph_id ?? input.workflowGraphId ?? null;
  const workflowNodeId = input.workflow_node_id ?? input.workflowNodeId ?? null;
  throw runtimeError({
    status: 501,
    code: "runtime_coding_tool_approval_block_rust_core_required",
    message: "Runtime coding-tool approval blocking requires direct Rust daemon-core admission and projection.",
    details: {
      rust_core_boundary: "runtime.coding_tool_approval_block",
      operation: "coding_tool_approval_block",
      operation_kind: "coding_tool.approval.block",
      thread_id: threadId,
      turn_id: turnId,
      tool_name: toolName,
      tool_call_id: toolCallId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      approval_id: input.approval_gate?.approval_id ?? null,
      reason: input.approval_gate?.reason ?? "approval_not_satisfied",
      evidence_refs: [
        "coding_tool_approval_block_js_facade_retired",
        "rust_daemon_core_coding_tool_approval_block_required",
        "agentgres_coding_tool_approval_block_truth_required",
      ],
    },
  });
}

function rustLiveInputForCodingTool(store, threadId, toolId, input = {}) {
  if (toolId === "artifact.read") {
    if (typeof store.codingToolArtifactSurface?.readCodingToolArtifact !== "function") {
      throw toolInputError(
        "artifact_read_unavailable",
        "artifact.read requires a daemon artifact store.",
        { thread_id: threadId, tool_id: toolId },
      );
    }
    const artifactId = optionalString(input.artifact_id ?? input.artifact_ref);
    if (!artifactId) {
      throw toolInputError(
        "artifact_read_id_required",
        "artifact.read requires artifact_id or artifact_ref.",
        { thread_id: threadId, tool_id: toolId },
      );
    }
    assertNoRetiredArtifactReadRangeAliases(input, { thread_id: threadId, tool_id: toolId, artifact_id: artifactId });
    const range = artifactReadRange(input);
    return {
      ...input,
      rust_workload_data_plane: {
        schema_version: "ioi.runtime.coding-tool-data-plane.v1",
        source: "daemon_artifact_store",
        operation: toolId,
        artifact_id: artifactId,
        artifact_ref: artifactId,
        range,
        result: store.codingToolArtifactSurface.readCodingToolArtifact(store, threadId, artifactId, range),
      },
    };
  }
  if (toolId === "tool.retrieve_result") {
    if (typeof store.codingToolArtifactSurface?.retrieveCodingToolResult !== "function") {
      throw toolInputError(
        "tool_retrieve_result_unavailable",
        "tool.retrieve_result requires a daemon artifact store.",
        { thread_id: threadId, tool_id: toolId },
      );
    }
    const toolCallId = optionalString(input.tool_call_id);
    const artifactId = optionalString(input.artifact_id ?? input.artifact_ref);
    if (!toolCallId && !artifactId) {
      throw toolInputError(
        "tool_retrieve_result_target_required",
        "tool.retrieve_result requires tool_call_id or artifact_id.",
        { thread_id: threadId, tool_id: toolId },
      );
    }
    assertNoRetiredArtifactReadRangeAliases(input, {
      thread_id: threadId,
      tool_id: toolId,
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
      rust_workload_data_plane: {
        schema_version: "ioi.runtime.coding-tool-data-plane.v1",
        source: "daemon_artifact_store",
        operation: toolId,
        query,
        result: store.codingToolArtifactSurface.retrieveCodingToolResult(store, threadId, query),
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

const RETIRED_RUST_LIVE_TOOL_RESULT_FIELDS = [
  "artifactDrafts",
  "artifactRefs",
  "allowedCommandIds",
  "afterContent",
  "afterExists",
  "afterHash",
  "afterMtimeMs",
  "afterSizeBytes",
  "backendReason",
  "backendStatus",
  "beforeContent",
  "beforeExists",
  "beforeHash",
  "beforeMtimeMs",
  "beforeSizeBytes",
  "bytesAdded",
  "changedFiles",
  "commandId",
  "diagnosticCount",
  "diagnosticStatus",
  "diagnosticsRecommended",
  "diffBytes",
  "diffHash",
  "dryRun",
  "durationMs",
  "editCount",
  "entryCount",
  "executionResultRef",
  "exitCode",
  "fallbackFrom",
  "fallbackUsed",
  "normalizedObservationRef",
  "newHash",
  "oldHash",
  "outputBytes",
  "outputHash",
  "packageManager",
  "packageRoot",
  "pathCount",
  "payloadRefs",
  "porcelainHash",
  "previewBytes",
  "previewHash",
  "previewLineCount",
  "projectContext",
  "projectRoot",
  "receiptRefs",
  "requestedCommandId",
  "resolvedCommandId",
  "rustWorkload",
  "schemaVersion",
  "shellFallbackUsed",
  "sizeBytes",
  "spilloverRecommended",
  "stepModuleBackend",
  "stderrBytes",
  "stdoutBytes",
  "testStatus",
  "timedOut",
  "timeoutMs",
  "toolName",
  "tscAvailable",
  "tsconfigPath",
  "tsconfigPaths",
  "workspaceRoot",
  "workspaceSnapshotDrafts",
];
const RETIRED_RUST_LIVE_TOOL_RESULT_FIELD_SET = new Set(RETIRED_RUST_LIVE_TOOL_RESULT_FIELDS);

function canonicalRustLiveToolResult(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalRustLiveToolResult(entry));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const result = {};
  for (const [key, child] of Object.entries(value)) {
    if (RETIRED_RUST_LIVE_TOOL_RESULT_FIELD_SET.has(key)) {
      continue;
    }
    result[key] = canonicalRustLiveToolResult(child);
  }
  return result;
}

function codingToolResultForRustLiveStepModule(toolId, stepModuleProjection = {}) {
  const stepResult = stepModuleProjection?.result ?? {};
  const workloadObservation = stepModuleProjection?.workload_result?.workload_observation ?? null;
  const observedResult = workloadObservation?.result;
  const toolResult =
    observedResult && typeof observedResult === "object" && !Array.isArray(observedResult)
      ? observedResult
      : {};
  const canonicalToolResult = canonicalRustLiveToolResult(toolResult);
  return {
    ...canonicalToolResult,
    schema_version: toolResult.schema_version ?? CODING_TOOL_RESULT_SCHEMA_VERSION,
    tool_name: toolResult.tool_name ?? toolId,
    status: "completed",
    rust_workload: true,
    backend: toolResult.backend ?? stepModuleProjection?.backend ?? "rust_workload_live",
    step_module_backend: stepModuleProjection?.backend ?? "rust_workload_live",
    execution_result_ref: stepResult.execution_result_ref ?? null,
    normalized_observation_ref: stepResult.normalized_observation_ref ?? null,
    router_admission: stepModuleProjection?.workload_result?.router_admission ?? null,
    receipt_refs: normalizeArray(stepResult.receipt_refs),
    observation: workloadObservation,
  };
}
