const SERVER_CONTROL_RECORD_ID = "server-control.default";

export function serverStatus(state, baseUrl, { schema_version } = {}) {
  const schemaVersion = schema_version;
  state.evictExpiredInstances();
  state.coalesceLoadedInstances();
  const runningInstances = [...state.instances.values()].filter((instance) => instance.status === "loaded");
  const degradedProviders = [...state.providers.values()].filter((provider) =>
    ["blocked", "absent", "stopped"].includes(provider.status),
  );
  const backends = state.listBackends();
  const controlState = serverControlState(state, { schema_version });
  return {
    schemaVersion,
    status: runningInstances.length > 0 ? "running" : "stopped",
    gatewayStatus: "running",
    controlStatus: controlState.status,
    lastServerOperation: controlState.operation,
    lastServerOperationAt: controlState.updatedAt,
    lastServerReceiptId: controlState.receiptId,
    nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
    openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
    loadedInstances: runningInstances.length,
    mountedEndpoints: state.endpoints.size,
    providerStates: {
      available: [...state.providers.values()].filter((provider) =>
        ["available", "configured", "running"].includes(provider.status),
      ).length,
      degraded: degradedProviders.length,
    },
    backendStates: {
      available: backends.filter((backend) => ["available", "configured", "running"].includes(backend.status)).length,
      degraded: backends.filter((backend) => ["blocked", "absent", "stopped", "degraded"].includes(backend.status)).length,
    },
    idleTtlSeconds: 900,
    autoEvict: true,
    checkedAt: state.nowIso(),
  };
}

export function serverControlState(state, { schema_version } = {}) {
  void state;
  return {
    id: SERVER_CONTROL_RECORD_ID,
    schemaVersion: schema_version,
    status: "running",
    gatewayStatus: "running",
    operation: "server_status",
    updatedAt: null,
    receiptId: null,
    evidenceRefs: ["ioi_daemon_public_runtime_api"],
  };
}

export function writeServerControlState(state, controlState) {
  const record = {
    id: SERVER_CONTROL_RECORD_ID,
    ...controlState,
  };
  void state;
  throwServerControlRustCoreRequired("model_mount.server_control.write", {
    server_control_id: record.id,
    receipt_id: record.receiptId ?? null,
  });
}

export function serverStart(state, baseUrl, options) {
  void state;
  void baseUrl;
  void options;
  throwServerControlRustCoreRequired("model_mount.server_control.start");
}

export function serverStop(state, baseUrl, options) {
  void state;
  void baseUrl;
  void options;
  throwServerControlRustCoreRequired("model_mount.server_control.stop");
}

export function serverRestart(state, baseUrl, options) {
  void state;
  void baseUrl;
  void options;
  throwServerControlRustCoreRequired("model_mount.server_control.restart");
}

export function serverLogs(state, query = {}, { schema_version } = {}) {
  void state;
  void query;
  void schema_version;
  throwServerControlRustCoreRequired("model_mount.server_control.logs_read");
}

export function serverEvents(state, query = {}, { schema_version } = {}) {
  void state;
  void query;
  void schema_version;
  throwServerControlRustCoreRequired("model_mount.server_control.events_read");
}

export function serverLogRecords(state, { limit = 80 } = {}) {
  void state;
  void limit;
  throwServerControlRustCoreRequired("model_mount.server_control.log_projection");
}

export function writeServerLog(state, event) {
  void state;
  void event;
  throwServerControlRustCoreRequired("model_mount.server_control.log_append");
}

function throwServerControlRustCoreRequired(operation_kind, details = {}) {
  const error = new Error("Server-control facade requires Rust daemon-core model_mount server-control ownership.");
  error.status = 501;
  error.code = "model_mount_server_control_rust_core_required";
  error.details = {
    operation_kind,
    rust_core_boundary: "model_mount.server_control",
    evidence_refs: [
      "public_server_control_js_facade_retired",
      "rust_daemon_core_server_control_required",
    ],
    ...details,
  };
  throw error;
}
