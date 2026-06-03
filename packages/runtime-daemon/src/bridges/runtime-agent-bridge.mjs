export function assertRuntimeBridgeAvailable(runtimeBridge, { runtimeProfile, operation }, deps = {}) {
  if (operation === "start_thread" && runtimeBridge?.canStartThread) return;
  if (operation === "submit_turn" && runtimeBridge?.canSubmitTurn) return;
  if (operation === "inspect_thread" && runtimeBridge?.canInspectThread) return;
  if (operation === "control_thread" && runtimeBridge?.canControlThread) return;
  throw runtimeBridgeUnavailable({ runtimeProfile, operation }, deps);
}

export function runtimeBridgeUnavailable({ runtimeProfile, operation, details = {} }, deps = {}) {
  const { externalBlocker } = deps;
  return externalBlocker("RuntimeAgentService bridge is required for runtime_service profile.", {
    runtimeProfile,
    operation,
    requiredBridge: "RuntimeApiBridge",
    fixtureProfile: "fixture",
    syntheticFallbackAllowed: false,
    ...details,
  });
}
