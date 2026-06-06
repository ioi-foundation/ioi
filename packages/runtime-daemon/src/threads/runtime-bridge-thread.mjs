export async function createRuntimeBridgeThread(store, { request, options, runtimeProfile }, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    threadIdForAgent,
  } = deps;
  store.assertRuntimeBridgeAvailable({ runtimeProfile, operation: "start_thread" });
  const agent = store.createAgent(options);
  const threadId = threadIdForAgent(agent.id);
  const input = {
    request,
    options,
    runtimeProfile,
    agentId: agent.id,
    threadId,
    workspaceRoot: agent.cwd,
    modelRouteDecision: agent.modelRouteDecision ?? null,
    createdAt: agent.createdAt,
  };
  let bridgeResult;
  try {
    bridgeResult = await store.runtimeBridge.startThread(input);
  } catch (error) {
    if (RuntimeApiBridgeUnavailableError && error instanceof RuntimeApiBridgeUnavailableError) {
      throw store.runtimeBridgeUnavailable({ runtimeProfile, operation: "start_thread", details: error.details });
    }
    throw error;
  }
  const projection = normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile }, {
    bridgeId: store.runtimeBridge?.bridgeId,
    eventStreamIdForThread: deps.eventStreamIdForThread,
    normalizeArray: deps.normalizeArray,
    runtimeError: deps.runtimeError,
  });
  const contextPolicyRunner = store.contextPolicyRunner;
  if (typeof contextPolicyRunner?.planRuntimeBridgeThreadStartAgentStateUpdate !== "function") {
    throw deps.runtimeError({
      status: 500,
      code: "runtime_bridge_thread_start_state_update_planner_unavailable",
      message: "Runtime bridge thread start updates require Rust policy state-update planning.",
      details: { threadId, runtimeProfile },
    });
  }
  const stateUpdate = contextPolicyRunner.planRuntimeBridgeThreadStartAgentStateUpdate({
    thread_id: threadId,
    agent,
    runtime_profile: runtimeProfile,
    session_id: projection.sessionId,
    bridge_id: projection.bridgeId,
    status: projection.status,
    source: projection.source,
    updated_at: projection.updatedAt,
  });
  const updated = stateUpdate.agent;
  if (!updated?.id) {
    throw deps.runtimeError({
      status: 502,
      code: "runtime_bridge_thread_start_state_update_planner_invalid",
      message: "Rust runtime bridge thread start planning did not return an agent record.",
      details: { threadId, runtimeProfile },
    });
  }
  store.agents.set(updated.id, updated);
  store.writeAgent(updated, stateUpdate.operation_kind ?? "thread.runtime_bridge.start");
  for (const event of projection.events) store.appendRuntimeEvent(event);
  return store.threadForAgent(updated);
}

export async function createRuntimeBridgeTurn(store, { agent, threadId, request, diagnosticsFeedback = null }, deps = {}) {
  const {
    RuntimeApiBridgeUnavailableError,
    RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS,
    insertRuntimeBridgeComputerUseDerivedEvents,
    insertRuntimeBridgeDiagnosticsInjectionEvent,
    insertRuntimeBridgeUsageDeltaEvents,
    normalizeRuntimeBridgeLiveEvent: liveEventNormalizer = normalizeRuntimeBridgeLiveEvent,
    normalizeRuntimeBridgeTurnSubmit: turnSubmitNormalizer = normalizeRuntimeBridgeTurnSubmit,
    optionalPositiveInteger,
    optionalString,
    runtimeBridgeRunRecord,
    runtimeSessionIdForAgent,
  } = deps;
  store.assertRuntimeBridgeAvailable({ runtimeProfile: agent.runtimeProfile, operation: "submit_turn" });
  const submitOptions = request?.options && typeof request.options === "object"
    ? request.options
    : {};
  const requestMaxSteps = optionalPositiveInteger(request?.max_steps ?? request?.maxSteps);
  const optionsMaxSteps = optionalPositiveInteger(submitOptions.max_steps ?? submitOptions.maxSteps);
  const explicitStepBudgets = [requestMaxSteps, optionsMaxSteps].filter((value) => Number.isFinite(value));
  const requestedMaxSteps = explicitStepBudgets.length ? Math.max(...explicitStepBudgets) : null;
  const normalizedMaxSteps = requestedMaxSteps
    ? Math.max(RUNTIME_BRIDGE_AGENT_TURN_MIN_STEPS, requestedMaxSteps)
    : null;
  const bridgeRequest = normalizedMaxSteps
    ? {
        ...request,
        max_steps: normalizedMaxSteps,
        maxSteps: normalizedMaxSteps,
      }
    : request;
  const bridgeOptions = normalizedMaxSteps
    ? {
        ...submitOptions,
        max_steps: normalizedMaxSteps,
        maxSteps: normalizedMaxSteps,
      }
    : submitOptions;
  const input = {
    request: bridgeRequest,
    options: bridgeOptions,
    agentId: agent.id,
    threadId,
    sessionId: runtimeSessionIdForAgent(agent),
    workspaceRoot: agent.cwd,
    createdAt: new Date().toISOString(),
    streamedEventsOnly: true,
  };
  const inFlightTurnIds = new Set();
  let bridgeResult;
  try {
    bridgeResult = await store.runtimeBridge.submitTurn(input, {
      onRuntimeEvent: (event) => {
        const normalized = liveEventNormalizer({ event, agent, threadId }, deps);
        const liveTurnId = optionalString(normalized.turn_id ?? normalized.turnId);
        if (liveTurnId) {
          inFlightTurnIds.add(liveTurnId);
          store.registerInFlightRuntimeTurn({
            agent,
            threadId,
            turnId: liveTurnId,
            runId: optionalString(event?.run_id ?? event?.runId ?? normalized.payload?.run_id),
            request,
          });
        }
        store.appendRuntimeEvent(normalized);
      },
    });
  } catch (error) {
    for (const turnId of inFlightTurnIds) {
      store.unregisterInFlightRuntimeTurn(threadId, turnId);
    }
    if (RuntimeApiBridgeUnavailableError && error instanceof RuntimeApiBridgeUnavailableError) {
      throw store.runtimeBridgeUnavailable({
        runtimeProfile: agent.runtimeProfile,
        operation: "submit_turn",
        details: error.details,
      });
    }
    throw error;
  }
  const projection = turnSubmitNormalizer({ bridgeResult, agent, threadId, request }, deps);
  if (diagnosticsFeedback) {
    projection.events = insertRuntimeBridgeDiagnosticsInjectionEvent({
      projection,
      agent,
      threadId,
      diagnosticsFeedback,
    });
  }
  projection.events = insertRuntimeBridgeComputerUseDerivedEvents({
    projection,
    agent,
    threadId,
  });
  projection.events = insertRuntimeBridgeUsageDeltaEvents({
    projection,
    agent,
    threadId,
  });
  for (const event of projection.events) store.appendRuntimeEvent(event);
  const run = runtimeBridgeRunRecord({ agent, request, projection });
  store.runs.set(run.id, run);
  store.writeRun(run, "turn.runtime_bridge.submit");
  for (const turnId of inFlightTurnIds) {
    store.unregisterInFlightRuntimeTurn(threadId, turnId);
  }
  return store.turnForRun(run);
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
  const sessionId = String(bridgeResult?.session_id ?? bridgeResult?.sessionId ?? "").trim();
  if (!sessionId) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge startThread result must include session_id.",
      details: { runtimeProfile, operation: "start_thread" },
    });
  }
  const events = normalizeArray(bridgeResult?.events);
  const hasThreadStarted = events.some((event) => event?.event_kind === "thread.started");
  if (!hasThreadStarted) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge startThread result must include a thread.started event.",
      details: { runtimeProfile, sessionId, operation: "start_thread" },
    });
  }
  const now = new Date().toISOString();
  return {
    sessionId,
    bridgeId: bridgeResult?.bridge_id ?? bridgeResult?.bridgeId ?? bridgeId,
    status: bridgeResult?.status ?? "active",
    source: bridgeResult?.source ?? "runtime_service",
    updatedAt: bridgeResult?.updated_at ?? bridgeResult?.updatedAt ?? now,
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
  const turnId = String(bridgeResult?.turn_id ?? bridgeResult?.turnId ?? "").trim();
  if (!turnId || !turnId.startsWith("turn_")) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge submitTurn result must include turn_id.",
      details: { runtimeProfile: agent.runtimeProfile, operation: "submit_turn" },
    });
  }
  const runId = String(bridgeResult?.run_id ?? bridgeResult?.runId ?? runIdForTurn(turnId)).trim();
  const events = normalizeArray(bridgeResult?.events);
  const hasTurnStarted = events.some((event) => event?.event_kind === "turn.started");
  if (!hasTurnStarted) {
    throw runtimeError({
      status: 502,
      code: "runtime_bridge_contract",
      message: "RuntimeApiBridge submitTurn result must include a turn.started event.",
      details: { runtimeProfile: agent.runtimeProfile, operation: "submit_turn", turnId },
    });
  }
  const now = new Date().toISOString();
  return {
    runId,
    turnId,
    status: bridgeResult?.status ?? "completed",
    result: bridgeResult?.result ?? "",
    createdAt: bridgeResult?.created_at ?? bridgeResult?.createdAt ?? now,
    updatedAt: bridgeResult?.updated_at ?? bridgeResult?.updatedAt ?? now,
    mode: request.mode ?? "send",
    prompt: request.prompt ?? request.message ?? request.input ?? "",
    stopReason: bridgeResult?.stop_reason ?? bridgeResult?.stopReason ?? "runtime_bridge_completed",
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
        ...(event.payload ?? event.payload_summary ?? {}),
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
  const turnId = optionalString(event?.turn_id ?? event?.turnId) ?? "";
  const runId = optionalString(event?.run_id ?? event?.runId) ?? (turnId ? runIdForTurn(turnId) : null);
  return {
    ...event,
    event_stream_id: event?.event_stream_id ?? eventStreamIdForThread(threadId),
    thread_id: event?.thread_id ?? threadId,
    turn_id: turnId || (event?.turn_id ?? event?.turnId ?? ""),
    workspace_root: event?.workspace_root ?? agent.cwd,
    source: event?.source ?? "runtime_service",
    source_event_kind: event?.source_event_kind ?? "RuntimeAgentService",
    fixture_profile: Object.hasOwn(event ?? {}, "fixture_profile") ? event.fixture_profile : null,
    payload: {
      agent_id: agent.id,
      ...(runId ? { run_id: runId } : {}),
      session_id: runtimeSessionIdForAgent(agent),
      ...(event?.payload ?? event?.payload_summary ?? {}),
    },
  };
}
