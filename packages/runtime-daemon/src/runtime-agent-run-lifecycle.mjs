import crypto from "node:crypto";
import path from "node:path";

import {
  isRuntimeServiceProfile,
  runtimeProfileForRequest,
} from "./runtime-profile.mjs";
import { RUNTIME_THREAD_SCHEMA_VERSION } from "./runtime-contract-constants.mjs";
import {
  eventStreamIdForThread as defaultEventStreamIdForThread,
  isRuntimeBackedAgent,
  threadIdForAgent as defaultThreadIdForAgent,
  threadStatusForAgent as defaultThreadStatusForAgent,
} from "./runtime-identifiers.mjs";
import {
  objectRecord,
  optionalString,
} from "./runtime-value-helpers.mjs";

export function createThread(store, request = {}, deps = {}) {
  const options = request.options ?? request;
  const runtimeProfile = runtimeProfileForRequest(request, options);
  if (isRuntimeServiceProfile(runtimeProfile)) {
    return createRuntimeBridgeThread(store, request, {
      ...deps,
      options,
      runtimeProfile,
    });
  }
  const threadCreateStateUpdateRunner = deps.lifecycleAdmissionRunner ?? null;
  if (typeof threadCreateStateUpdateRunner?.planThreadCreateStateUpdate !== "function") {
    throwRuntimeLifecycleRustCoreRequired({
      lifecycleAdmissionRunner: threadCreateStateUpdateRunner,
      code: "runtime_thread_create_rust_core_required",
      message: "Thread creation requires direct Rust daemon-core state admission and persistence.",
      boundary: "runtime.thread_create",
      operation: "thread_create",
      operation_kind: "thread.create",
      requested_cwd: options.local?.cwd ?? store.defaultCwd ?? null,
      requested_runtime: runtimeForOptions(options, deps.runtimeModeForOptions),
      evidence_refs: threadCreateEvidenceRefs(),
    });
  }
  const agent = buildAgentCreateCandidate(store, options, deps);
  const thread = buildThreadCreateCandidate(agent, deps);
  const planned = threadCreateStateUpdateRunner.planThreadCreateStateUpdate({ agent, thread });
  const plannedAgent = objectRecord(planned?.agent);
  const plannedThread = objectRecord(planned?.thread);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedAgent) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_state_update_agent_missing",
      message: "Rust daemon-core thread creation did not return an agent projection.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
      },
    });
  }
  if (!plannedThread) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_state_update_thread_missing",
      message: "Rust daemon-core thread creation did not return a thread projection.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        agent_id: optionalString(plannedAgent.id),
      },
    });
  }
  if (plannedOperationKind !== "thread.create") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_state_update_operation_kind_mismatch",
      message: "Rust daemon-core thread creation returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        expected_operation_kind: "thread.create",
        actual_operation_kind: plannedOperationKind,
        agent_id: optionalString(plannedAgent.id),
      },
    });
  }
  if (
    optionalString(planned?.status) !== "planned" ||
    !optionalString(plannedAgent.id) ||
    !optionalString(plannedAgent.createdAt) ||
    !optionalString(plannedAgent.updatedAt) ||
    !optionalString(plannedThread.thread_id) ||
    !optionalString(plannedThread.agent_id) ||
    !optionalString(plannedThread.event_stream_id)
  ) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_state_update_projection_incomplete",
      message: "Rust daemon-core thread creation did not return a complete planned projection.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        expected_operation_kind: "thread.create",
        agent_id: optionalString(plannedAgent.id),
        thread_id: optionalString(plannedThread.thread_id),
      },
    });
  }
  if (optionalString(plannedThread.agent_id) !== optionalString(plannedAgent.id)) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_state_update_agent_mismatch",
      message: "Rust daemon-core thread creation returned a thread for a different agent.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        agent_id: optionalString(plannedAgent.id),
        thread_agent_id: optionalString(plannedThread.agent_id),
        thread_id: optionalString(plannedThread.thread_id),
      },
    });
  }
  store.writeAgent(plannedAgent, plannedOperationKind);
  if (typeof store.ensureThreadStartedEvent === "function") {
    store.ensureThreadStartedEvent(plannedAgent);
  }
  if (typeof store.threadForAgent !== "function") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 501,
      code: "runtime_thread_create_projection_unavailable",
      message: "Thread creation requires Rust daemon-core thread projection.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        agent_id: optionalString(plannedAgent.id),
        thread_id: optionalString(plannedThread.thread_id),
      },
    });
  }
  const threadProjection = objectRecord(store.threadForAgent(plannedAgent));
  if (!threadProjection || optionalString(threadProjection.thread_id) !== optionalString(plannedThread.thread_id)) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "thread_create_projection_mismatch",
      message: "Rust daemon-core thread creation returned a mismatched thread projection.",
      details: {
        rust_core_boundary: "runtime.thread_create",
        operation: "thread_create",
        operation_kind: "thread.create",
        agent_id: optionalString(plannedAgent.id),
        expected_thread_id: optionalString(plannedThread.thread_id),
        actual_thread_id: optionalString(threadProjection?.thread_id),
      },
    });
  }
  return threadProjection;
}

function createRuntimeBridgeThread(store, request = {}, deps = {}) {
  const options = deps.options ?? request.options ?? request;
  const runtimeProfile = deps.runtime_profile ?? runtimeProfileForRequest(request, options);
  const threadStartStateUpdateRunner = deps.lifecycleAdmissionRunner ?? null;
  if (typeof threadStartStateUpdateRunner?.planRuntimeBridgeThreadStartAgentStateUpdate !== "function") {
    throwRuntimeBridgeThreadRustCoreRequired({
      runtimeError: deps.runtimeError,
      operation: "runtime_bridge_thread_start",
      operationKind: "thread.runtime_bridge.start",
      details: {
        runtime_profile: runtimeProfile,
        evidence_refs: runtimeBridgeThreadStartEvidenceRefs(),
      },
    });
  }
  const agent = buildAgentCreateCandidate(store, options, deps);
  const thread = buildThreadCreateCandidate(agent, deps);
  const sessionId =
    optionalString(options.runtime_session_id ?? request.runtime_session_id) ??
    `session_${thread.thread_id}`;
  const bridgeId =
    optionalString(options.runtime_bridge_id ?? request.runtime_bridge_id) ??
    `bridge_${thread.thread_id}`;
  const source =
    optionalString(options.runtime_bridge_source ?? request.runtime_bridge_source) ??
    "rust_daemon_core";
  const updatedAt = optionalString(agent.updatedAt) ?? new Date().toISOString();
  const planned = threadStartStateUpdateRunner.planRuntimeBridgeThreadStartAgentStateUpdate({
    thread_id: thread.thread_id,
    agent,
    runtime_profile: runtimeProfile,
    session_id: sessionId,
    bridge_id: bridgeId,
    status: "active",
    source,
    updated_at: updatedAt,
  });
  const plannedAgent = objectRecord(planned?.agent);
  const bridgeStart = objectRecord(planned?.bridge_start);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedAgent) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "runtime_bridge_thread_start_agent_missing",
      message: "Rust daemon-core runtime bridge thread start did not return an agent projection.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation: "runtime_bridge_thread_start",
        operation_kind: "thread.runtime_bridge.start",
        thread_id: thread.thread_id,
      },
    });
  }
  if (plannedOperationKind !== "thread.runtime_bridge.start") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "runtime_bridge_thread_start_operation_kind_mismatch",
      message: "Rust daemon-core runtime bridge thread start returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation: "runtime_bridge_thread_start",
        operation_kind: "thread.runtime_bridge.start",
        expected_operation_kind: "thread.runtime_bridge.start",
        actual_operation_kind: plannedOperationKind,
        thread_id: thread.thread_id,
        agent_id: optionalString(plannedAgent.id),
      },
    });
  }
  if (
    optionalString(planned?.status) !== "planned" ||
    optionalString(plannedAgent.id) !== optionalString(agent.id) ||
    optionalString(plannedAgent.runtime_profile) !== runtimeProfile ||
    optionalString(plannedAgent.runtime_session_id) !== sessionId ||
    optionalString(plannedAgent.runtime_bridge_id) !== bridgeId ||
    optionalString(plannedAgent.runtime_bridge_source) !== source ||
    optionalString(bridgeStart?.runtime_profile) !== runtimeProfile ||
    optionalString(bridgeStart?.session_id) !== sessionId ||
    optionalString(bridgeStart?.bridge_id) !== bridgeId ||
    optionalString(bridgeStart?.source) !== source
  ) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "runtime_bridge_thread_start_projection_incomplete",
      message: "Rust daemon-core runtime bridge thread start did not return canonical bridge identity.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation: "runtime_bridge_thread_start",
        operation_kind: "thread.runtime_bridge.start",
        thread_id: thread.thread_id,
        agent_id: optionalString(plannedAgent.id),
        runtime_profile: optionalString(plannedAgent.runtime_profile),
        runtime_session_id: optionalString(plannedAgent.runtime_session_id),
        runtime_bridge_id: optionalString(plannedAgent.runtime_bridge_id),
        runtime_bridge_source: optionalString(plannedAgent.runtime_bridge_source),
      },
    });
  }
  store.writeAgent(plannedAgent, plannedOperationKind);
  if (typeof store.ensureThreadStartedEvent === "function") {
    store.ensureThreadStartedEvent(plannedAgent);
  }
  if (typeof store.threadForAgent !== "function") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 501,
      code: "runtime_bridge_thread_start_projection_unavailable",
      message: "Runtime bridge thread start requires Rust daemon-core thread projection.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation: "runtime_bridge_thread_start",
        operation_kind: "thread.runtime_bridge.start",
        agent_id: optionalString(plannedAgent.id),
        thread_id: thread.thread_id,
      },
    });
  }
  const threadProjection = objectRecord(store.threadForAgent(plannedAgent));
  if (!threadProjection || optionalString(threadProjection.thread_id) !== thread.thread_id) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "runtime_bridge_thread_start_projection_mismatch",
      message: "Rust daemon-core runtime bridge thread start returned a mismatched thread projection.",
      details: {
        rust_core_boundary: "runtime.bridge_thread",
        operation: "runtime_bridge_thread_start",
        operation_kind: "thread.runtime_bridge.start",
        agent_id: optionalString(plannedAgent.id),
        expected_thread_id: thread.thread_id,
        actual_thread_id: optionalString(threadProjection?.thread_id),
      },
    });
  }
  return threadProjection;
}

export function createAgent(store, options = {}, deps = {}) {
  const agentCreateStateUpdateRunner = deps.lifecycleAdmissionRunner ?? null;
  if (typeof agentCreateStateUpdateRunner?.planAgentCreateStateUpdate !== "function") {
    throwRuntimeLifecycleRustCoreRequired({
      lifecycleAdmissionRunner: agentCreateStateUpdateRunner,
      code: "runtime_agent_create_rust_core_required",
      message: "Agent creation requires direct Rust daemon-core state admission and persistence.",
      boundary: "runtime.agent_create",
      operation: "agent_create",
      operation_kind: "agent.create",
      requested_cwd: options.local?.cwd ?? store.defaultCwd ?? null,
      requested_runtime: runtimeForOptions(options, deps.runtimeModeForOptions),
      evidence_refs: agentCreateEvidenceRefs(),
    });
  }
  const agent = buildAgentCreateCandidate(store, options, deps);
  const planned = agentCreateStateUpdateRunner.planAgentCreateStateUpdate({ agent });
  const plannedAgent = objectRecord(planned?.agent);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedAgent) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "agent_create_state_update_agent_missing",
      message: "Rust daemon-core agent creation did not return an agent projection.",
      details: {
        rust_core_boundary: "runtime.agent_create",
        operation: "agent_create",
        operation_kind: "agent.create",
      },
    });
  }
  if (plannedOperationKind !== "agent.create") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "agent_create_state_update_operation_kind_mismatch",
      message: "Rust daemon-core agent creation returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.agent_create",
        operation: "agent_create",
        operation_kind: "agent.create",
        expected_operation_kind: "agent.create",
        actual_operation_kind: plannedOperationKind,
      },
    });
  }
  if (
    optionalString(planned?.status) !== "planned" ||
    !optionalString(plannedAgent.id) ||
    !optionalString(plannedAgent.createdAt) ||
    !optionalString(plannedAgent.updatedAt)
  ) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "agent_create_state_update_projection_incomplete",
      message: "Rust daemon-core agent creation did not return a complete planned projection.",
      details: {
        rust_core_boundary: "runtime.agent_create",
        operation: "agent_create",
        operation_kind: "agent.create",
        expected_operation_kind: "agent.create",
        agent_id: optionalString(plannedAgent.id),
      },
    });
  }
  store.writeAgent(plannedAgent, plannedOperationKind);
  return plannedAgent;
}

function buildAgentCreateCandidate(store, options = {}, deps = {}) {
  const randomUUID = typeof deps.randomUUID === "function"
    ? deps.randomUUID
    : () => crypto.randomUUID();
  const runtimeModeForOptions = typeof deps.runtimeModeForOptions === "function"
    ? deps.runtimeModeForOptions
    : defaultRuntimeModeForOptions;
  const ensureProviderAvailable = typeof deps.ensureProviderAvailable === "function"
    ? deps.ensureProviderAvailable
    : () => {};
  const initialThreadRuntimeControls = typeof deps.initialThreadRuntimeControls === "function"
    ? deps.initialThreadRuntimeControls
    : defaultInitialThreadRuntimeControls;
  const mcpRegistryForWorkspace = typeof deps.mcpRegistryForWorkspace === "function"
    ? deps.mcpRegistryForWorkspace
    : () => null;
  const summarizeAgentOptions = typeof deps.summarizeAgentOptions === "function"
    ? deps.summarizeAgentOptions
    : () => ({});
  const now = new Date().toISOString();
  const cwd = path.resolve(options.local?.cwd ?? store.defaultCwd);
  const runtime = runtimeModeForOptions(options);
  ensureProviderAvailable(runtime, options);
  const modelRoute = store.resolveModelRoute(options, {
    evidenceRefs: ["runtime_agent_model_route"],
    workflowNodeId: "runtime.model-router",
    workflowNodeType: "Model Router",
  });
  return {
    id: `agent_${randomUUID()}`,
    status: "active",
    runtime,
    cwd,
    modelId: modelRoute.selectedModel,
    requestedModelId: modelRoute.requestedModelId,
    modelRouteId: modelRoute.routeId,
    modelRouteEndpointId: modelRoute.endpointId,
    modelRouteProviderId: modelRoute.providerId,
    modelRouteReceiptId: modelRoute.receiptId,
    modelRouteDecision: modelRoute.decision,
    runtimeControls: initialThreadRuntimeControls(options, modelRoute, now),
    mcpRegistry: mcpRegistryForWorkspace(cwd, {
      ...options,
      homeDir: store.homeDir,
    }),
    createdAt: now,
    updatedAt: now,
    options: summarizeAgentOptions(cwd, options),
  };
}

function buildThreadCreateCandidate(agent, deps = {}) {
  const threadIdForAgent = typeof deps.threadIdForAgent === "function"
    ? deps.threadIdForAgent
    : defaultThreadIdForAgent;
  const eventStreamIdForThread = typeof deps.eventStreamIdForThread === "function"
    ? deps.eventStreamIdForThread
    : defaultEventStreamIdForThread;
  const threadStatusForAgent = typeof deps.threadStatusForAgent === "function"
    ? deps.threadStatusForAgent
    : defaultThreadStatusForAgent;
  const threadId = threadIdForAgent(agent.id);
  return {
    schema_version: deps.runtimeThreadSchemaVersion ?? RUNTIME_THREAD_SCHEMA_VERSION,
    thread_id: threadId,
    agent_id: agent.id,
    event_stream_id: eventStreamIdForThread(threadId),
    status: threadStatusForAgent(agent.status),
    created_at: agent.createdAt,
    updated_at: agent.updatedAt,
  };
}

export function createRun(store, agentId, request = {}, deps = {}) {
  const runCreateStateUpdateRunner = deps.lifecycleAdmissionRunner ?? null;
  if (typeof runCreateStateUpdateRunner?.planRunCreateStateUpdate !== "function") {
    throwRuntimeLifecycleRustCoreRequired({
      lifecycleAdmissionRunner: runCreateStateUpdateRunner,
      code: "runtime_run_create_rust_core_required",
      message: "Run creation requires direct Rust daemon-core state admission and persistence.",
      boundary: "runtime.run_create",
      operation: "run_create",
      operation_kind: "run.create",
      agent_id: agentId ?? null,
      requested_mode: optionalString(request.mode) ?? "send",
      evidence_refs: runCreateEvidenceRefs(),
    });
  }
  const buildRun = deps.buildRun;
  if (typeof buildRun !== "function") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 501,
      code: "runtime_run_create_builder_unavailable",
      message: "Run creation requires mounted run candidate construction before Rust state planning.",
      details: {
        rust_core_boundary: "runtime.run_create",
        operation: "run_create",
        operation_kind: "run.create",
        agent_id: agentId ?? null,
        evidence_refs: runCreateEvidenceRefs(),
      },
    });
  }
  const ensureProviderAvailable = typeof deps.ensureProviderAvailable === "function"
    ? deps.ensureProviderAvailable
    : () => {};
  const threadModeForRunMode = typeof deps.threadModeForRunMode === "function"
    ? deps.threadModeForRunMode
    : (_mode, fallback = "agent") => fallback ?? "agent";
  const approvalModeForThreadMode = typeof deps.approvalModeForThreadMode === "function"
    ? deps.approvalModeForThreadMode
    : () => "suggest";
  const agent = store.getAgent(agentId);
  const agentRecord = objectRecord(agent);
  if (!agentRecord) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 404,
      code: "runtime_run_create_agent_not_found",
      message: `Agent not found: ${agentId}`,
      details: {
        rust_core_boundary: "runtime.run_create",
        operation: "run_create",
        operation_kind: "run.create",
        agent_id: agentId ?? null,
      },
    });
  }
  const candidateRun = buildRunCandidateForAgent(store, agentRecord, request, {
    approvalModeForThreadMode,
    buildRun,
    ensureProviderAvailable,
    repositoryWorkflowProjector: deps.repositoryWorkflowProjector,
    runtimeError: deps.runtimeError,
    threadModeForRunMode,
    operation: "run_create",
    operationKind: "run.create",
    boundary: "runtime.run_create",
    builderUnavailableCode: "runtime_run_create_builder_unavailable",
    builderUnavailableMessage:
      "Run creation requires mounted run candidate construction before Rust state planning.",
    evidenceRefs: runCreateEvidenceRefs(),
  });
  const planned = runCreateStateUpdateRunner.planRunCreateStateUpdate({ run: candidateRun });
  const plannedRun = objectRecord(planned?.run);
  const plannedOperationKind = optionalString(planned?.operation_kind);
  if (!plannedRun) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "run_create_state_update_run_missing",
      message: "Rust daemon-core run creation did not return a run projection.",
      details: {
        rust_core_boundary: "runtime.run_create",
        operation: "run_create",
        operation_kind: "run.create",
        agent_id: agentId ?? null,
      },
    });
  }
  if (plannedOperationKind !== "run.create") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "run_create_state_update_operation_kind_mismatch",
      message: "Rust daemon-core run creation returned the wrong operation kind.",
      details: {
        rust_core_boundary: "runtime.run_create",
        operation: "run_create",
        operation_kind: "run.create",
        expected_operation_kind: "run.create",
        actual_operation_kind: plannedOperationKind,
        agent_id: agentId ?? null,
      },
    });
  }
  if (
    optionalString(planned?.status) !== "planned" ||
    !optionalString(plannedRun.id) ||
    !optionalString(plannedRun.agentId) ||
    !optionalString(plannedRun.createdAt) ||
    !optionalString(plannedRun.updatedAt)
  ) {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError: deps.runtimeError,
      status: 502,
      code: "run_create_state_update_projection_incomplete",
      message: "Rust daemon-core run creation did not return a complete planned projection.",
      details: {
        rust_core_boundary: "runtime.run_create",
        operation: "run_create",
        operation_kind: "run.create",
        expected_operation_kind: "run.create",
        agent_id: agentId ?? null,
        run_id: optionalString(plannedRun.id),
      },
    });
  }
  store.writeRun(plannedRun, plannedOperationKind);
  return plannedRun;
}

function buildRunCandidateForAgent(store, agentRecord, request = {}, {
  approvalModeForThreadMode,
  buildRun,
  ensureProviderAvailable,
  repositoryWorkflowProjector,
  runtimeError,
  threadModeForRunMode,
  operation,
  operationKind,
  boundary,
  builderUnavailableCode,
  builderUnavailableMessage,
  evidenceRefs,
} = {}) {
  if (typeof buildRun !== "function") {
    throwRuntimeLifecycleStateUpdateError({
      runtimeError,
      status: 501,
      code: builderUnavailableCode,
      message: builderUnavailableMessage,
      details: {
        rust_core_boundary: boundary,
        operation,
        operation_kind: operationKind,
        agent_id: optionalString(agentRecord?.id) ?? null,
        evidence_refs: evidenceRefs,
      },
    });
  }
  const ensureProvider = typeof ensureProviderAvailable === "function"
    ? ensureProviderAvailable
    : () => {};
  const modeForThread = typeof threadModeForRunMode === "function"
    ? threadModeForRunMode
    : (_mode, fallback = "agent") => fallback ?? "agent";
  const approvalModeForThread = typeof approvalModeForThreadMode === "function"
    ? approvalModeForThreadMode
    : () => "suggest";
  ensureProvider(agentRecord.runtime, agentRecord.options);
  const mode = optionalString(request.mode) ?? "send";
  const threadMode =
    optionalString(request.thread_mode) ??
    modeForThread(mode, agentRecord.runtimeControls?.mode);
  const approvalMode =
    optionalString(request.approval_mode) ??
    optionalString(agentRecord.runtimeControls?.approval_mode) ??
    approvalModeForThread(threadMode);
  const prompt =
    optionalString(request.prompt) ??
    (mode === "learn"
      ? `Learn governed task-family updates for ${request.options?.taskFamily ?? "runtime"}`
      : "");
  const modelRoute = store.resolveRunModelRoute(agentRecord, request);
  const memory = store.resolveRunMemory(agentRecord, request, prompt);
  return {
    ...buildRun({
      agent: agentRecord,
      mode,
      prompt,
      request,
      source: "local_daemon_agentgres",
      modelRoute,
      memory,
      repositoryWorkflowProjector,
      skillHookCatalog: null,
      diagnosticsFeedback: request.diagnostics_feedback ?? null,
    }),
    thread_mode: threadMode,
    approval_mode: approvalMode,
  };
}

function throwRuntimeLifecycleRustCoreRequired({
  lifecycleAdmissionRunner,
  code,
  message,
  boundary,
  operation,
  operation_kind,
  evidence_refs,
  ...details
}) {
  if (lifecycleAdmissionRunner?.planLifecycleAdmissionRequired) {
    const record = lifecycleAdmissionRunner.planLifecycleAdmissionRequired({
      operation,
      operation_kind,
      agent_id: details.agent_id,
      requested_cwd: details.requested_cwd,
      requested_runtime: details.requested_runtime,
      requested_mode: details.requested_mode,
      evidence_refs,
    });
    const planned = record?.record ?? record;
    const error = new Error(planned?.message ?? record?.message ?? message);
    error.status = Number(planned?.status_code ?? record?.status_code ?? 501);
    error.code = planned?.code ?? record?.code ?? code;
    error.details = planned?.details ?? record?.details ?? {
      rust_core_boundary: boundary,
      operation,
      operation_kind,
      ...details,
      evidence_refs,
    };
    throw error;
  }
  const error = new Error(message);
  error.status = 501;
  error.code = code;
  error.details = {
    rust_core_boundary: boundary,
    operation,
    operation_kind,
    ...details,
    evidence_refs,
  };
  throw error;
}

function throwRuntimeBridgeThreadRustCoreRequired({ runtimeError, operation, operationKind, details = {} }) {
  const input = {
    status: 501,
    code: "runtime_bridge_thread_rust_core_required",
    message:
      "Runtime bridge thread start and turn submission require direct Rust daemon-core admission and persistence.",
    details: {
      rust_core_boundary: "runtime.bridge_thread",
      operation,
      operation_kind: operationKind,
      ...details,
    },
  };
  if (runtimeError) {
    throw runtimeError(input);
  }
  const error = new Error(input.message);
  error.status = input.status;
  error.code = input.code;
  error.details = input.details;
  throw error;
}

function throwRuntimeLifecycleStateUpdateError({ runtimeError, status, code, message, details }) {
  if (typeof runtimeError === "function") {
    throw runtimeError({ status, code, message, details });
  }
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  throw error;
}

function runtimeForOptions(options = {}, runtimeModeForOptions = null) {
  if (typeof runtimeModeForOptions === "function") {
    return runtimeModeForOptions(options);
  }
  return defaultRuntimeModeForOptions(options);
}

function defaultRuntimeModeForOptions(options = {}) {
  if (options.cloud) return "cloud";
  if (options.hosted) return "hosted";
  if (options.selfHosted) return "selfHosted";
  return options.runtime ?? "local";
}

function defaultInitialThreadRuntimeControls(options = {}, modelRoute = {}, now = new Date().toISOString()) {
  const approvalMode = options.approval_mode ?? "suggest";
  return {
    mode: options.interaction_mode ?? "agent",
    approval_mode: approvalMode,
    model: {
      id: modelRoute.requestedModelId ?? options.model?.id ?? options.model?.model ?? "auto",
      route_id: modelRoute.routeId ?? options.model?.route_id ?? options.route_id ?? "route.local-first",
      selected_model: modelRoute.selectedModel ?? null,
      endpoint_id: modelRoute.endpointId ?? null,
      provider_id: modelRoute.providerId ?? null,
      receipt_id: modelRoute.receiptId ?? null,
      updated_at: now,
    },
  };
}

function agentCreateEvidenceRefs() {
  return [
    "runtime_agent_create_js_facade_retired",
    "rust_daemon_core_agent_create_required",
    "agentgres_agent_create_state_truth_required",
  ];
}

function threadCreateEvidenceRefs() {
  return [
    "runtime_thread_create_js_facade_retired",
    "rust_daemon_core_thread_create_required",
    "agentgres_thread_create_state_truth_required",
  ];
}

function runtimeBridgeThreadStartEvidenceRefs() {
  return [
    "runtime_bridge_thread_start_rust_owned",
    "runtime_bridge_thread_start_js_facade_retired",
    "rust_daemon_core_runtime_bridge_thread_start_required",
    "agentgres_runtime_bridge_thread_start_truth_required",
  ];
}

function runCreateEvidenceRefs() {
  return [
    "runtime_run_create_js_facade_retired",
    "rust_daemon_core_run_create_required",
    "agentgres_run_create_state_truth_required",
  ];
}
