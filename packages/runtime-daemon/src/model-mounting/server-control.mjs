import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { readLines } from "./local-system-probes.mjs";
import { normalizeLimit, parseJsonMaybe } from "./provider-protocol.mjs";
import { readJson, redact, writeJson } from "./io.mjs";

export function serverStatus(state, baseUrl, { schemaVersion }) {
  state.evictExpiredInstances();
  state.coalesceLoadedInstances();
  const runningInstances = [...state.instances.values()].filter((instance) => instance.status === "loaded");
  const degradedProviders = [...state.providers.values()].filter((provider) =>
    ["blocked", "absent", "stopped"].includes(provider.status),
  );
  const backends = state.listBackends();
  const controlState = serverControlState(state, { schemaVersion });
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

export function serverControlState(state, { schemaVersion }) {
  const statePath = path.join(state.stateDir, "server-state.json");
  if (fs.existsSync(statePath)) {
    return readJson(statePath);
  }
  return {
    schemaVersion,
    status: "running",
    gatewayStatus: "running",
    operation: "server_status",
    updatedAt: null,
    receiptId: null,
    evidenceRefs: ["ioi_daemon_public_runtime_api"],
  };
}

export function writeServerControlState(state, controlState) {
  writeJson(path.join(state.stateDir, "server-state.json"), controlState);
  return controlState;
}

export function serverStart(state, baseUrl, options) {
  return recordServerOperation(state, "server_start", "running", baseUrl, {
    requestedAction: "start",
    compatibilitySurface: "lms server start",
  }, options);
}

export function serverStop(state, baseUrl, options) {
  return recordServerOperation(state, "server_stop", "stopped", baseUrl, {
    requestedAction: "stop",
    compatibilitySurface: "lms server stop",
    note: "The daemon process remains reachable so governed clients can restart the model gateway.",
  }, options);
}

export function serverRestart(state, baseUrl, options) {
  const previousState = serverControlState(state, options);
  return recordServerOperation(state, "server_restart", "running", baseUrl, {
    requestedAction: "restart",
    compatibilitySurface: "lms server start|stop",
    previousControlStatus: previousState.status,
    previousReceiptId: previousState.receiptId,
  }, options);
}

export function recordServerOperation(state, operation, status, baseUrl, details = {}, options) {
  const occurredAt = state.nowIso();
  const receipt = state.lifecycleReceipt(operation, {
    modelId: "ioi-local-server",
    state: status,
    gatewayStatus: "running",
    nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
    openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
    evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", operation],
    ...details,
  });
  const controlState = writeServerControlState(state, {
    schemaVersion: options.schemaVersion,
    status,
    gatewayStatus: "running",
    operation,
    updatedAt: occurredAt,
    receiptId: receipt.id,
    evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", operation],
  });
  const log = writeServerLog(state, {
    event: operation,
    status,
    gatewayStatus: "running",
    receiptId: receipt.id,
    details,
  });
  return {
    ...serverStatus(state, baseUrl, options),
    controlStatus: controlState.status,
    lastServerOperation: operation,
    lastServerOperationAt: occurredAt,
    lastServerReceiptId: receipt.id,
    receiptId: receipt.id,
    logId: log.id,
  };
}

export function serverLogs(state, query = {}, { schemaVersion }) {
  const limit = normalizeLimit(query.limit, 80, 200);
  const receipt = state.lifecycleReceipt("server_logs_read", {
    modelId: "ioi-local-server",
    state: "read",
    limit,
    evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", "redacted_log_access"],
  });
  writeServerLog(state, {
    event: "server_logs_read",
    status: "read",
    receiptId: receipt.id,
    limit,
  });
  return {
    schemaVersion,
    kind: "server_logs",
    redaction: "redacted",
    receiptId: receipt.id,
    records: serverLogRecords(state, { limit }),
  };
}

export function serverEvents(state, query = {}, { schemaVersion }) {
  const limit = normalizeLimit(query.limit, 80, 200);
  const receipt = state.lifecycleReceipt("server_events_read", {
    modelId: "ioi-local-server",
    state: "read",
    limit,
    evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", "event_tail"],
  });
  writeServerLog(state, {
    event: "server_events_read",
    status: "read",
    receiptId: receipt.id,
    limit,
  });
  return {
    schemaVersion,
    kind: "server_events",
    redaction: "redacted",
    receiptId: receipt.id,
    events: serverLogRecords(state, { limit }),
  };
}

export function serverLogRecords(state, { limit = 80 } = {}) {
  const filePath = path.join(state.stateDir, "server-logs", "server.jsonl");
  return readLines(filePath)
    .map((line) => parseJsonMaybe(line))
    .filter(Boolean)
    .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")))
    .slice(-normalizeLimit(limit, 80, 200));
}

export function writeServerLog(state, event) {
  const record = {
    id: `server_log_${crypto.randomUUID()}`,
    createdAt: state.nowIso(),
    source: "ioi-local-server",
    ...redact(event),
  };
  const filePath = path.join(state.stateDir, "server-logs", "server.jsonl");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
  return record;
}
