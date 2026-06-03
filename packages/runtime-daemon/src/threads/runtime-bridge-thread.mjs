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
  const updated = {
    ...agent,
    runtimeProfile,
    runtimeSessionId: projection.sessionId,
    runtimeBridgeId: projection.bridgeId,
    runtimeBridgeStatus: projection.status,
    runtimeBridgeSource: projection.source,
    fixtureProfile: null,
    updatedAt: projection.updatedAt,
  };
  store.agents.set(agent.id, updated);
  store.writeAgent(updated, "thread.runtime_bridge.start");
  for (const event of projection.events) store.appendRuntimeEvent(event);
  return store.threadForAgent(updated);
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
