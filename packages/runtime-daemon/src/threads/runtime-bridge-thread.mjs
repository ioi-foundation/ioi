export async function createRuntimeBridgeThread(store, { request, options, runtimeProfile }, deps = {}) {
  void store;
  void request;
  void options;
  throwRuntimeBridgeThreadRustCoreRequired({
    runtimeError: deps.runtimeError,
    operation: "runtime_bridge_thread_start",
    operationKind: "thread.runtime_bridge.start",
    details: {
      runtime_profile: runtimeProfile,
      evidence_refs: [
        "runtime_bridge_thread_start_js_facade_retired",
        "rust_daemon_core_runtime_bridge_thread_start_required",
        "agentgres_runtime_bridge_thread_start_truth_required",
      ],
    },
  });
}

export async function createRuntimeBridgeTurn(store, { agent, threadId, request, diagnosticsFeedback = null }, deps = {}) {
  void store;
  void request;
  void diagnosticsFeedback;
  throwRuntimeBridgeThreadRustCoreRequired({
    runtimeError: deps.runtimeError,
    operation: "runtime_bridge_turn_submit",
    operationKind: "turn.runtime_bridge.submit",
    details: {
      thread_id: threadId,
      agent_id: agent?.id ?? null,
      runtime_profile: agent?.runtimeProfile ?? null,
      evidence_refs: [
        "runtime_bridge_turn_submit_js_facade_retired",
        "rust_daemon_core_runtime_bridge_turn_required",
        "agentgres_runtime_bridge_turn_truth_required",
      ],
    },
  });
}

function throwRuntimeBridgeThreadRustCoreRequired({ runtimeError, operation, operationKind, details = {} }) {
  throw runtimeError({
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
  });
}

export async function controlRuntimeBridgeThread(store, { agent, threadId, action, reason }, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    runtimeSessionIdForAgent,
  } = deps;
  store.assertRuntimeBridgeAvailable({
    runtimeProfile: agent.runtimeProfile,
    operation: "control_thread",
  });
  try {
    return await store.runtimeBridge.controlThread({
      sessionId: runtimeSessionIdForAgent(agent),
      threadId,
      workspaceRoot: agent.cwd,
      action,
      reason,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    if (RuntimeApiBridgeUnavailableError && error instanceof RuntimeApiBridgeUnavailableError) {
      throw store.runtimeBridgeUnavailable({
        runtimeProfile: agent.runtimeProfile,
        operation: "control_thread",
        details: error.details,
      });
    }
    throw error;
  }
}

export function normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile }, deps = {}) {
  const {
    bridgeId,
    eventStreamIdForThread,
    normalizeArray,
    runtimeError,
  } = deps;
  const sessionId = String(bridgeResult?.session_id ?? "").trim();
  if (!sessionId) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge startThread result must include session_id.",
      details: { runtime_profile: runtimeProfile, operation: "start_thread" },
    });
  }
  const events = normalizeArray(bridgeResult?.events);
  const hasThreadStarted = events.some((event) => event?.event_kind === "thread.started");
  if (!hasThreadStarted) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge startThread result must include a thread.started event.",
      details: { runtime_profile: runtimeProfile, session_id: sessionId, operation: "start_thread" },
    });
  }
  const now = new Date().toISOString();
  return {
    sessionId,
    bridgeId: bridgeResult?.bridge_id ?? bridgeId,
    status: bridgeResult?.status ?? "active",
    source: bridgeResult?.source ?? "runtime_service",
    updatedAt: bridgeResult?.updated_at ?? now,
    events: events.map((event) => ({
      ...event,
      event_stream_id: event.event_stream_id ?? eventStreamIdForThread(threadId),
      thread_id: event.thread_id ?? threadId,
      workspace_root: event.workspace_root ?? agent.cwd,
      source: event.source ?? "runtime_service",
      source_event_kind: event.source_event_kind ?? "RuntimeAgentService",
      fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : null,
      payload: {
        agent_id: agent.id,
        session_id: sessionId,
        ...(event.payload ?? event.payload_summary ?? {}),
      },
    })),
  };
}

export function normalizeRuntimeBridgeTurnSubmit({ bridgeResult, agent, threadId, request }, deps = {}) {
  const {
    eventStreamIdForThread,
    normalizeArray,
    runIdForTurn,
    runtimeError,
    runtimeSessionIdForAgent,
  } = deps;
  const turnId = String(bridgeResult?.turn_id ?? "").trim();
  if (!turnId || !turnId.startsWith("turn_")) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge submitTurn result must include turn_id.",
      details: { runtime_profile: agent.runtimeProfile, operation: "submit_turn" },
    });
  }
  const runId = String(bridgeResult?.run_id ?? runIdForTurn(turnId)).trim();
  const events = normalizeArray(bridgeResult?.events);
  const hasTurnStarted = events.some((event) => event?.event_kind === "turn.started");
  if (!hasTurnStarted) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge submitTurn result must include a turn.started event.",
      details: { runtime_profile: agent.runtimeProfile, operation: "submit_turn", turn_id: turnId },
    });
  }
  const now = new Date().toISOString();
  return {
    runId,
    turnId,
    status: bridgeResult?.status ?? "completed",
    result: bridgeResult?.result ?? "",
    createdAt: bridgeResult?.created_at ?? now,
    updatedAt: bridgeResult?.updated_at ?? now,
    mode: request.mode ?? "send",
    prompt: request.prompt ?? request.message ?? request.input ?? "",
    stopReason: bridgeResult?.stop_reason ?? "runtime_bridge_completed",
    usage:
      bridgeResult?.usage_telemetry ??
      bridgeResult?.usage ??
      null,
    events: events.map((event) => ({
      ...event,
      event_stream_id: event.event_stream_id ?? eventStreamIdForThread(threadId),
      thread_id: event.thread_id ?? threadId,
      turn_id: event.turn_id ?? turnId,
      workspace_root: event.workspace_root ?? agent.cwd,
      source: event.source ?? "runtime_service",
      source_event_kind: event.source_event_kind ?? "RuntimeAgentService",
      fixture_profile: Object.hasOwn(event, "fixture_profile") ? event.fixture_profile : null,
      payload: {
        agent_id: agent.id,
        run_id: runId,
        session_id: runtimeSessionIdForAgent(agent),
        ...canonicalRuntimeBridgeEventPayload(event),
      },
    })),
  };
}

export function normalizeRuntimeBridgeLiveEvent({ event, agent, threadId }, deps = {}) {
  const {
    eventStreamIdForThread,
    optionalString,
    runIdForTurn,
    runtimeSessionIdForAgent,
  } = deps;
  const {
    turnId: _retiredTurnId,
    runId: _retiredRunId,
    ...eventRecord
  } = event ?? {};
  const turnId = optionalString(eventRecord.turn_id) ?? "";
  const runId = optionalString(eventRecord.run_id) ?? (turnId ? runIdForTurn(turnId) : null);
  return {
    ...eventRecord,
    event_stream_id: eventRecord.event_stream_id ?? eventStreamIdForThread(threadId),
    thread_id: eventRecord.thread_id ?? threadId,
    turn_id: turnId || (eventRecord.turn_id ?? ""),
    workspace_root: eventRecord.workspace_root ?? agent.cwd,
    source: eventRecord.source ?? "runtime_service",
    source_event_kind: eventRecord.source_event_kind ?? "RuntimeAgentService",
    fixture_profile: Object.hasOwn(eventRecord, "fixture_profile") ? eventRecord.fixture_profile : null,
    payload: {
      agent_id: agent.id,
      ...(runId ? { run_id: runId } : {}),
      session_id: runtimeSessionIdForAgent(agent),
      ...canonicalRuntimeBridgeEventPayload(eventRecord),
    },
  };
}

function canonicalRuntimeBridgeEventPayload(event = {}) {
  const payload = objectRecord(event.payload ?? event.payload_summary);
  return withoutKeys(payload, [
    "runId",
    "turnId",
    "threadId",
    "agentId",
    "eventKind",
    "workflowGraphId",
    "workflowNodeId",
    "componentKind",
    "payloadSchemaVersion",
    "runtimeEventId",
    "runtimeEventKind",
    "sourceEventKind",
    "receiptRefs",
    "artifactRefs",
    "policyDecisionRefs",
  ]);
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function withoutKeys(record, keys) {
  const output = { ...record };
  for (const key of keys) delete output[key];
  return output;
}
