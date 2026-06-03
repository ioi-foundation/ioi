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
  const projection = store.normalizeRuntimeBridgeThreadStart({ bridgeResult, agent, threadId, runtimeProfile });
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
