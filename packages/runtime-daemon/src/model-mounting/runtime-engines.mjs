const DEFAULT_RUNTIME_ENGINE_ID = "backend.autopilot.native-local.fixture";

function defaultRuntimePreference(state, receiptId = "none", source = "default_native_local_runtime") {
  return {
    id: "default",
    selectedEngineId: DEFAULT_RUNTIME_ENGINE_ID,
    selectedAt: receiptId === "none" ? null : state.nowIso(),
    receiptId,
    source,
    ...(receiptId === "none"
      ? {}
      : {
          engineKind: "native_local",
          engineLabel: "Autopilot native-local fixture",
          modelFormat: "gguf,fixture",
        }),
    defaultLoadOptions: runtimeDefaultLoadOptions(state, DEFAULT_RUNTIME_ENGINE_ID),
  };
}

export function runtimePreference(state) {
  const preference = state.runtimeSelections.get("default") ?? defaultRuntimePreference(state);
  return {
    ...preference,
    defaultLoadOptions: runtimeDefaultLoadOptions(state, preference.selectedEngineId),
  };
}

export function runtimePreferenceForEndpoint(state, endpoint = {}) {
  const preference = runtimePreference(state);
  const endpointBackendId = endpoint.backendId ?? null;
  if (!endpointBackendId || endpointBackendId === preference.selectedEngineId) return preference;
  if (!state.backendRegistry().some((backend) => backend.id === endpointBackendId)) return preference;
  return {
    ...preference,
    selectedEngineId: endpointBackendId,
    source: "endpoint_backend_runtime",
    endpointBackendId,
    defaultLoadOptions: runtimeDefaultLoadOptions(state, endpointBackendId),
  };
}

export function runtimeEngineProfile(state, engineId) {
  return state.runtimeEngineProfiles.get(engineId) ?? null;
}

export function listRuntimeEngineProfiles(state) {
  return [...state.runtimeEngineProfiles.values()].sort((left, right) => left.id.localeCompare(right.id));
}

export function runtimeDefaultLoadOptions(state, engineId) {
  const profile = runtimeEngineProfile(state, engineId);
  return profile?.defaultLoadOptions ?? {};
}

export function runtimeEngine(state, engineId, deps = {}) {
  const { notFound } = deps;
  const engine = listRuntimeEngines(state).find((item) => item.id === engineId);
  if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engine_id: engineId });
  const preference = runtimePreference(state);
  return {
    ...engine,
    profile: runtimeEngineProfile(state, engineId),
    preference: preference.selectedEngineId === engineId ? preference : null,
    loadedInstances: state.listInstances().filter((instance) => instance.runtimeEngineId === engineId || instance.backendId === engineId),
    latestReceipts: state.listReceipts()
      .filter((receipt) =>
        receipt.details?.runtime_engine_id === engineId ||
        receipt.details?.engine_id === engineId ||
        receipt.details?.backend_id === engineId
      )
      .slice(-8),
  };
}

export function selectRuntimeEngine(state, body = {}, deps = {}) {
  const { requiredString } = deps;
  const engineId = requiredString(body.engine_id, "engine_id");
  throwRuntimeEngineRustCoreRequired("model_mount.runtime_preference.write", { engine_id: engineId }, deps);
}

export function updateRuntimeEngine(state, engineId, body = {}, deps = {}) {
  void body;
  throwRuntimeEngineRustCoreRequired("model_mount.runtime_engine_profile.write", { engine_id: engineId }, deps);
}

export function removeRuntimeEngineOverride(state, engineId, deps = {}) {
  throwRuntimeEngineRustCoreRequired("model_mount.runtime_engine_profile.delete", { engine_id: engineId }, deps);
}

function throwRuntimeEngineRustCoreRequired(operation_kind, details = {}, deps = {}) {
  const errorFactory = deps.runtimeError ?? (({ code, message, details: errorDetails, status }) =>
    Object.assign(new Error(message), { code, details: errorDetails, status }));
  throw errorFactory({
    status: 501,
    code: "model_mount_runtime_engine_rust_core_required",
    message: "Runtime-engine mutation facade requires Rust daemon-core model_mount runtime-engine ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.runtime_engine",
      evidence_refs: [
        "public_runtime_engine_js_facade_retired",
        "rust_daemon_core_runtime_engine_required",
      ],
      ...details,
    },
  });
}

export function listRuntimeEngines(state) {
  const checkedAt = state.nowIso();
  const activeBackendIds = new Set(state.listInstances().map((instance) => instance.backendId).filter(Boolean));
  const preference = runtimePreference(state);
  const hasExplicitPreference = preference.receiptId !== "none";
  const backendEngines = state.backendRegistry().map((backend) => ({
    id: backend.id,
    kind: backend.kind,
    label: backend.label,
    status: backend.status,
    selected:
      preference.selectedEngineId === backend.id ||
      (!hasExplicitPreference &&
        (activeBackendIds.has(backend.id) ||
          (activeBackendIds.size === 0 && backend.id === DEFAULT_RUNTIME_ENGINE_ID))),
    modelFormat: (backend.supportedFormats ?? []).join(",") || "unknown",
    source: "autopilot_backend_registry",
    processStatus: backend.processStatus ?? "unknown",
    checkedAt,
    evidenceRefs: backend.evidenceRefs ?? [],
  })).map((engine) => applyRuntimeEngineProfile(state, engine));
  return backendEngines.sort((left, right) => {
    const leftPriority = left.operatorProfile?.priority ?? 1000;
    const rightPriority = right.operatorProfile?.priority ?? 1000;
    if (leftPriority !== rightPriority) return leftPriority - rightPriority;
    return left.id.localeCompare(right.id);
  });
}

export function applyRuntimeEngineProfile(state, engine) {
  const profile = runtimeEngineProfile(state, engine.id);
  if (!profile) {
    return {
      ...engine,
      operatorProfile: {
        configured: false,
        disabled: false,
        priority: null,
        defaultLoadOptions: {},
        receiptId: null,
      },
    };
  }
  const disabled = Boolean(profile.disabled);
  return {
    ...engine,
    label: profile.label || engine.label,
    status: disabled ? "disabled" : engine.status,
    selected: disabled ? false : engine.selected,
    operatorProfile: {
      configured: true,
      disabled,
      priority: profile.priority ?? null,
      defaultLoadOptions: profile.defaultLoadOptions ?? {},
      updatedAt: profile.updatedAt ?? null,
      receiptId: profile.receiptId ?? null,
      source: profile.source ?? "operator_runtime_engine_profile",
    },
  };
}
