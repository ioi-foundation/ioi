import fs from "node:fs";
import path from "node:path";

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
  if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engineId });
  const preference = runtimePreference(state);
  return {
    ...engine,
    profile: runtimeEngineProfile(state, engineId),
    preference: preference.selectedEngineId === engineId ? preference : null,
    loadedInstances: state.listInstances().filter((instance) => instance.runtimeEngineId === engineId || instance.backendId === engineId),
    latestReceipts: state.listReceipts()
      .filter((receipt) => receipt.details?.runtimeEngineId === engineId || receipt.details?.engineId === engineId || receipt.details?.backendId === engineId)
      .slice(-8),
  };
}

export function selectRuntimeEngine(state, body = {}, deps = {}) {
  const { requiredString, runtimeError, schemaVersion } = deps;
  const engineId = requiredString(body.engine_id ?? body.engineId ?? body.id, "engine_id");
  const checkedAt = state.nowIso();
  const engines = listRuntimeEngines(state);
  const engine = engines.find((item) => item.id === engineId);
  if (!engine) throw deps.notFound(`Runtime engine not found: ${engineId}`, { engineId });
  if (engine.operatorProfile?.disabled) {
    throw runtimeError({
      status: 409,
      code: "runtime_engine_disabled",
      message: "Runtime engine is disabled by its operator profile.",
      details: { engineId, receiptId: engine.operatorProfile.receiptId ?? null },
    });
  }
  const receipt = state.lifecycleReceipt("runtime_engine_select", {
    engineId,
    engineKind: engine.kind,
    engineStatus: engine.status,
    source: engine.source,
    modelFormat: engine.modelFormat,
    defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
    checkedAt,
  });
  const preference = {
    id: "default",
    selectedEngineId: engineId,
    selectedAt: checkedAt,
    receiptId: receipt.id,
    source: "operator_runtime_select",
    engineKind: engine.kind,
    engineLabel: engine.label,
    modelFormat: engine.modelFormat,
    defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
  };
  state.runtimeSelections.set(preference.id, preference);
  state.writeMap("runtime-preferences", state.runtimeSelections);
  state.writeProjection();
  return {
    schemaVersion,
    ...preference,
  };
}

export function updateRuntimeEngine(state, engineId, body = {}, deps = {}) {
  const {
    normalizeRuntimeEngineDefaultLoadOptions,
    schemaVersion,
    stableHash,
  } = deps;
  const engine = runtimeEngine(state, engineId, deps);
  const now = state.nowIso();
  const existing = runtimeEngineProfile(state, engineId) ?? {};
  const disabledValue = body.disabled ?? body.disable ?? existing.disabled ?? false;
  const defaultLoadOptions = normalizeRuntimeEngineDefaultLoadOptions(
    body.default_load_options ?? body.defaultLoadOptions ?? body.load_options ?? body.loadOptions ?? existing.defaultLoadOptions ?? {},
  );
  const receipt = state.lifecycleReceipt("runtime_engine_update", {
    engineId,
    engineKind: engine.kind,
    previousProfileHash: stableHash(existing),
    disabled: Boolean(disabledValue),
    priority: body.priority ?? existing.priority ?? null,
    defaultLoadOptions,
    evidenceRefs: ["operator_runtime_engine_profile", "runtime_engine_default_load_options"],
  });
  const profile = {
    id: engineId,
    engineId,
    label: body.label ?? body.operator_label ?? body.operatorLabel ?? existing.label ?? null,
    disabled: Boolean(disabledValue),
    priority: body.priority === undefined || body.priority === null || body.priority === ""
      ? existing.priority ?? null
      : Number(body.priority),
    defaultLoadOptions,
    updatedAt: now,
    receiptId: receipt.id,
    source: "operator_runtime_engine_profile",
  };
  state.runtimeEngineProfiles.set(engineId, profile);
  state.writeMap("runtime-engine-profiles", state.runtimeEngineProfiles);
  if (profile.disabled && runtimePreference(state).selectedEngineId === engineId) {
    state.runtimeSelections.set("default", defaultRuntimePreference(state, receipt.id, "operator_runtime_disable_reset"));
    state.writeMap("runtime-preferences", state.runtimeSelections);
  }
  state.writeProjection();
  return {
    schemaVersion,
    profile,
    engine: runtimeEngine(state, engineId, deps),
    receiptId: receipt.id,
  };
}

export function removeRuntimeEngineOverride(state, engineId, deps = {}) {
  const { safeFileName, schemaVersion, stableHash } = deps;
  runtimeEngine(state, engineId, deps);
  const existing = runtimeEngineProfile(state, engineId);
  const receipt = state.lifecycleReceipt("runtime_engine_profile_remove", {
    engineId,
    hadProfile: Boolean(existing),
    previousProfileHash: stableHash(existing ?? {}),
    evidenceRefs: ["operator_runtime_engine_profile_remove"],
  });
  state.runtimeEngineProfiles.delete(engineId);
  fs.rmSync(path.join(state.stateDir, "runtime-engine-profiles", `${safeFileName(engineId)}.json`), { force: true });
  state.writeMap("runtime-engine-profiles", state.runtimeEngineProfiles);
  if (runtimePreference(state).selectedEngineId === engineId && existing?.disabled) {
    state.runtimeSelections.set("default", defaultRuntimePreference(state, receipt.id, "operator_runtime_profile_remove_reset"));
    state.writeMap("runtime-preferences", state.runtimeSelections);
  }
  state.writeProjection();
  return {
    schemaVersion,
    engineId,
    removed: Boolean(existing),
    engine: runtimeEngine(state, engineId, deps),
    receiptId: receipt.id,
  };
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
  const lmStudioEngines = state.lmStudioRuntimeEngines(checkedAt).map((engine) => ({
    ...engine,
    selected: preference.selectedEngineId === engine.id || (!hasExplicitPreference && engine.selected),
  })).map((engine) => applyRuntimeEngineProfile(state, engine));
  return [...backendEngines, ...lmStudioEngines].sort((left, right) => {
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
