import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function backendHealth(state, backendId) {
  return ModelMountingState.prototype.backendHealth.call(state, backendId);
}

function backendLogs(state, backendId, query = {}) {
  return ModelMountingState.prototype.backendLogs.call(state, backendId, query);
}

function backendRegistry(state) {
  return ModelMountingState.prototype.backendRegistry.call(state);
}

function listBackends(state) {
  return ModelMountingState.prototype.listBackends.call(state);
}

function ensureBackendProcess(state, backendId, details = {}) {
  return ModelMountingState.prototype.ensureBackendProcess.call(state, backendId, details);
}

function spawnBackendChildProcess(state, backend, details = {}) {
  return ModelMountingState.prototype.spawnBackendChildProcess.call(state, backend, details);
}

function startBackend(state, backendId, body = {}) {
  return ModelMountingState.prototype.startBackend.call(state, backendId, body);
}

function startBackendProcess(state, backend, details = {}) {
  return ModelMountingState.prototype.startBackendProcess.call(state, backend, details);
}

function stopBackend(state, backendId) {
  return ModelMountingState.prototype.stopBackend.call(state, backendId);
}

function stopBackendProcess(state, backend, details = {}) {
  return ModelMountingState.prototype.stopBackendProcess.call(state, backend, details);
}

function touchBackendProcess(state, processRecord, details = {}) {
  return ModelMountingState.prototype.touchBackendProcess.call(state, processRecord, details);
}

function fakeState() {
  const backends = new Map([
    ["backend.native", { id: "backend.native", kind: "native_local", label: "Native", status: "configured", evidenceRefs: ["native_backend"] }],
    ["backend.blocked", { id: "backend.blocked", kind: "llama_cpp", label: "Blocked", status: "blocked", evidenceRefs: ["binary_missing"] }],
    ["backend.llama", { id: "backend.llama", kind: "llama_cpp", label: "llama.cpp", status: "configured", binaryPath: "/bin/llama-server", baseUrl: "http://127.0.0.1:8091/v1" }],
  ]);
  const state = {
    bootId: "boot-a",
    cwd: "/workspace",
    stateDir: "/state",
    backendProcesses: new Map(),
    backendChildProcesses: new Map(),
    backends,
    logs: [],
    receipts: [],
    writes: [],
    now: "2026-06-03T20:00:00.000Z",
    backendLifecyclePlans: [],
    backendLogProjectionRequests: [],
    recordStateCommits: [],
    backend(backendId) {
      return this.backends.get(backendId);
    },
    backendProcessForBackend(backendId) {
      return [...this.backendProcesses.values()].filter((record) => record.backendId === backendId).at(-1) ?? null;
    },
    backendSupportsSupervision(backend) {
      return ["native_local", "llama_cpp", "ollama", "vllm"].includes(backend.kind);
    },
    ensureBackendProcess(backendId, details) {
      return ensureBackendProcess(this, backendId, details);
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    nowIso() {
      return this.now;
    },
    planBackendLifecycle(request) {
      return ModelMountingState.prototype.planBackendLifecycle.call(this, request);
    },
    reconciledBackendProcess(record) {
      return { stale: false, ...record };
    },
    spawnBackendChildProcess(backend, details) {
      return spawnBackendChildProcess(this, backend, details, deps);
    },
    startBackendProcess(backend, details) {
      return startBackendProcess(this, backend, details, deps);
    },
    stopBackendProcess(backend, details) {
      return stopBackendProcess(this, backend, details, deps);
    },
    touchBackendProcess(record, details) {
      return touchBackendProcess(this, record, details, deps);
    },
    writeBackendLog(backendId, event) {
      this.logs.push({ backendId, ...event });
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `model_mount://${request.record_dir}/${request.record_id}`,
        content_hash: "sha256:backend-lifecycle-content",
        admission_hash: "sha256:backend-lifecycle-admission",
        commit_hash: "sha256:backend-lifecycle-commit",
        written_record: request.record,
        storage_record: {
          object_ref: `model_mount://${request.record_dir}/${request.record_id}`,
        },
      };
    },
  };
  state.modelMountCore = {
    planReadProjection(request) {
      if (request.projection_kind === "backends") {
        return { projection: state.projectedBackends ?? [] };
      }
      if (request.projection_kind !== "backend_logs") {
        throw new Error(`unexpected read projection: ${request.projection_kind}`);
      }
      const backendId = request.state.backend_log_query?.backend_id;
      const query = request.state.backend_log_query ?? {};
      state.backendLogProjectionRequests.push({ projectionState: state, backendId, query });
      const record = {
        event: "backend_start",
        backend_id: backendId,
        rust_core_boundary: "model_mount.backend_lifecycle_log_projection",
      };
      return {
        projection: {
          object: "ioi.model_mount_backend_logs",
          status: "projected",
          projectionKind: "backend_logs",
          backend_id: backendId,
          redaction: "redacted",
          records: [record],
          logs: [record],
          count: 1,
          rustCoreBoundary: "model_mount.backend_lifecycle_log_projection",
          evidenceRefs: [
            "rust_daemon_core_backend_lifecycle_log_projection",
            "agentgres_backend_lifecycle_log_replay_required",
            "model_mount_backend_log_read_js_control_path_retired",
          ],
        },
      };
    },
    planBackendLifecycle(request) {
      state.backendLifecyclePlans.push(request);
      const suffix = request.operation_kind.replace(/[^a-z0-9]+/gi, "-");
      const recordId = `backend-lifecycle-control:${suffix}`;
      const receiptRefs = Array.isArray(request.receipt_refs) ? request.receipt_refs : [];
      const evidenceRefs = [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
      ];
      const publicResponse = {
        object: "ioi.model_mount_backend_lifecycle",
        status: "planned",
        backend_id: request.backend_id,
        backend_kind: request.backend_kind ?? null,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.backend_lifecycle",
        js_backend_registry_read: false,
        js_process_control: false,
        js_log_read: false,
        js_log_write: false,
      };
      if (request.operation_kind === "model_mount.backend.start") {
        publicResponse.backend_status = "start_planned";
        if (request.body?.load_options) publicResponse.load_options = request.body.load_options;
      } else if (request.operation_kind === "model_mount.backend.health") {
        publicResponse.backend_status = "health_planned";
      } else if (request.operation_kind === "model_mount.backend.stop") {
        publicResponse.backend_status = "stop_planned";
      }
      return {
        source: "rust_daemon_core.model_mount.backend_lifecycle",
        status: "planned",
        rust_core_boundary: "model_mount.backend_lifecycle",
        record_dir: "model-backend-lifecycle-controls",
        record_id: recordId,
        record: {
          id: recordId,
          object: "ioi.model_mount_backend_lifecycle_record",
          backend_id: request.backend_id,
          backend_kind: request.backend_kind ?? null,
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.backend_lifecycle",
          receipt_refs: [...receiptRefs, "sha256:backend-lifecycle-control"],
          evidence_refs: evidenceRefs,
        },
        public_response: publicResponse,
        operation_kind: request.operation_kind,
        receipt_refs: receiptRefs,
        evidence_refs: evidenceRefs,
        control_hash: "sha256:backend-lifecycle-control",
      };
    },
  };
  return state;
}

const deps = {
  hardwareSnapshot: () => ({ cpu: "test-cpu" }),
  llamaCppLibraryPathEnv: (binaryPath, existing) => `${binaryPath}:lib:${existing ?? ""}`,
  normalizeLoadOptions: (value) => ({ ...value, normalized: true }),
  normalizeScopes: (value, fallback = []) => (Array.isArray(value) ? value : fallback),
  processEnv: {
    IOI_MODEL_BACKEND_STARTUP_TIMEOUT_MS: "1234",
    LD_LIBRARY_PATH: "/system/lib",
  },
  redact: (value) => ({ ...value, redacted: true }),
  runtimeError({ status, code, message, details }) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    error.details = details;
    return error;
  },
  safeId: (value) => String(value).replace(/[^a-z0-9]+/gi, "_"),
  stableHash: (value) => `hash_${String(value).replace(/[^a-z0-9]+/gi, "_")}`,
};

function assertBackendProcessSupervisorRetired(error, operationKind) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_backend_process_supervisor_retired");
  assert.equal(error.details.backend_id, "backend.native");
  assert.equal(error.details.backend_kind, "native_local");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.backend_lifecycle");
  assert.deepEqual(error.details.evidence_refs, [
    "js_backend_process_supervisor_retired",
    "rust_daemon_core_backend_process_required",
    "agentgres_backend_process_truth_required",
  ]);
  assert.equal(Object.hasOwn(error.details, "backendId"), false);
  assert.equal(Object.hasOwn(error.details, "backendKind"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
  return true;
}

test("backend process supervisor entrypoints fail closed before JS process authority", () => {
  const state = fakeState();
  state.backendProcesses.set("process-a", {
    id: "process-a",
    backendId: "backend.native",
    backendKind: "native_local",
    status: "started",
    stale: true,
    evidenceRefs: ["existing"],
  });

  assert.throws(
    () => ensureBackendProcess(state, "backend.native", { reason: "health_probe" }),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.ensure"),
  );
  assert.throws(
    () => touchBackendProcess(state, state.backendProcesses.get("process-a"), { reason: "health_probe" }, deps),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.touch"),
  );
  assert.throws(
    () => startBackendProcess(state, state.backend("backend.native"), { loadOptions: { startupTimeoutMs: 10 } }, deps),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.start"),
  );
  assert.throws(
    () => spawnBackendChildProcess(state, state.backend("backend.native"), { processRef: "supervised://native/process" }, deps),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.spawn"),
  );
  assert.throws(
    () => stopBackendProcess(state, state.backend("backend.native"), { reason: "operator_stop" }, deps),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.stop"),
  );

  assert.equal(state.backendProcesses.get("process-a").status, "started");
  assert.deepEqual(state.logs, []);
  assert.deepEqual(state.writes, []);
});

test("backend process supervisor retired error uses canonical Rust-boundary metadata", () => {
  const state = fakeState();

  assert.throws(
    () => startBackendProcess(state, state.backend("backend.native")),
    (error) => assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.start"),
  );
});

test("public backend lifecycle facades commit Rust-authored records", () => {
  const state = fakeState();
  state.backendRegistry = () => {
    throw new Error("public backend lifecycle must not read JS backend registry");
  };

  const health = backendHealth(state, "backend.native");
  const started = startBackend(state, "backend.native", { loadOptions: { contextLength: 1024 } });
  const stopped = stopBackend(state, "backend.native");

  assert.deepEqual(state.backendLifecyclePlans.map((request) => request.operation_kind), [
    "model_mount.backend.health",
    "model_mount.backend.start",
    "model_mount.backend.stop",
  ]);
  assert.deepEqual(state.recordStateCommits.map((request) => request.operation_kind), [
    "model_mount.backend.health",
    "model_mount.backend.start",
    "model_mount.backend.stop",
  ]);
  assert.equal(state.backendLifecyclePlans[0].schema_version, "ioi.model_mount.backend_lifecycle.v1");
  assert.equal(state.backendLifecyclePlans[0].backend_id, "backend.native");
  assert.equal(state.backendLifecyclePlans[0].source, "runtime-daemon.model_mounting.backend_lifecycle");
  assert.equal(state.backendLifecyclePlans[1].body.backend_id, "backend.native");
  assert.deepEqual(state.backendLifecyclePlans[1].body.load_options, { contextLength: 1024 });
  assert.equal(Object.hasOwn(state.backendLifecyclePlans[1].body, "loadOptions"), false);

  for (const response of [health, started, stopped]) {
    assert.equal(response.status, "planned");
    assert.equal(response.rust_core_boundary, "model_mount.backend_lifecycle");
    assert.equal(response.js_backend_registry_read, false);
    assert.equal(response.js_process_control, false);
    assert.equal(response.commit.commit_hash, "sha256:backend-lifecycle-commit");
    assert.ok(response.evidence_refs.includes("rust_daemon_core_backend_lifecycle"));
    assert.ok(response.evidence_refs.includes("agentgres_backend_lifecycle_truth_required"));
  }
  assert.equal(health.backend_status, "health_planned");
  assert.equal(started.backend_status, "start_planned");
  assert.deepEqual(started.load_options, { contextLength: 1024 });
  assert.equal(stopped.backend_status, "stop_planned");

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.logs, []);
  assert.deepEqual(state.writes, []);
});

test("public backend lifecycle fails closed only when Rust positive planner is unavailable", () => {
  const state = fakeState();
  state.modelMountCore = {};

  assert.throws(
    () => backendHealth(state, "backend.native"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.backend.health");
      assert.equal(error.details.rust_core_boundary, "model_mount.backend_lifecycle");
      assert.deepEqual(error.details.evidence_refs, [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_backend_lifecycle",
        "agentgres_backend_lifecycle_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
  assert.deepEqual(state.backendLifecyclePlans, []);
  assert.deepEqual(state.recordStateCommits, []);
});

test("public backend list delegates to Rust projection without JS backend registry input", () => {
  const state = fakeState();
  state.projectedBackends = [];
  state.backendRegistry = () => {
    throw new Error("Rust backend list projection must not read JS backend registry");
  };

  assert.deepEqual(listBackends(state), []);
});

test("mounted backend registry delegates to Rust projection without JS registry derivation", () => {
  const state = fakeState();
  const rustBackends = [
    {
      id: "backend.native",
      kind: "native_local",
      status: "start_planned",
      rust_core_boundary: "model_mount.backend_lifecycle_projection",
    },
  ];
  state.projectedBackends = rustBackends;
  assert.equal(Object.hasOwn(ModelMountingState.prototype, "seedBackends"), false);
  assert.equal(Object.hasOwn(ModelMountingState.prototype, "deriveBackendRegistry"), false);
  state.deriveBackendRegistry = () => {
    throw new Error("backendRegistry must not derive JS backend truth");
  };
  state.backendProcessForBackend = () => {
    throw new Error("backendRegistry must not join JS process snapshots");
  };
  state.backends.set("backend.js-only", {
    id: "backend.js-only",
    status: "configured",
  });

  assert.deepEqual(backendRegistry(state), rustBackends);
});

test("blocked backend public lifecycle start still commits through Rust boundary before JS control", () => {
  const state = fakeState();
  state.backendRegistry = () => {
    throw new Error("public backend lifecycle must not read JS backend registry");
  };

  const response = startBackend(state, "backend.blocked", {});

  assert.equal(response.status, "planned");
  assert.equal(response.backend_id, "backend.blocked");
  assert.equal(response.rust_core_boundary, "model_mount.backend_lifecycle");
  assert.equal(state.backendLifecyclePlans.length, 1);
  assert.equal(state.backendLifecyclePlans[0].backend_id, "backend.blocked");
  assert.equal(state.backendLifecyclePlans[0].backend_kind, null);
  assert.equal(state.recordStateCommits.length, 1);
});

test("public backend logs delegate to Rust projection without lifecycle control or local log reads", () => {
  const state = fakeState();
  let listFilesCalled = false;
  state.planBackendLifecycle = () => {
    throw new Error("backend logs must not plan lifecycle control");
  };

  const response = backendLogs(state, "backend.native", {
    limit: "1",
    authorization: "Bearer secret-token",
    listFiles() {
      listFilesCalled = true;
      return ["/state/backend-logs/backend.native.jsonl"];
    },
    parseJsonMaybe(line) {
      return JSON.parse(line);
    },
    readLines(filePath) {
      if (filePath.endsWith("other.jsonl")) {
        return [JSON.stringify({ backendId: "other", createdAt: "2026-06-03T20:00:03.000Z" })];
      }
      return [
        JSON.stringify({ backendId: "backend.native", createdAt: "2026-06-03T20:00:02.000Z", event: "second" }),
        JSON.stringify({ backend: "backend.native", createdAt: "2026-06-03T20:00:01.000Z", event: "first" }),
      ];
    },
    safeFileName: (value) => value,
  });

  assert.equal(response.projectionKind, "backend_logs");
  assert.deepEqual(response.logs.map((record) => record.event), ["backend_start"]);
  assert.equal(listFilesCalled, false);
  assert.equal(state.backendLifecyclePlans.length, 0);
  assert.equal(state.recordStateCommits.length, 0);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.backendLogProjectionRequests.length, 1);
  assert.equal(state.backendLogProjectionRequests[0].backendId, "backend.native");
  assert.equal(state.backendLogProjectionRequests[0].query.limit, 1);
  assert.equal(Object.hasOwn(state.backendLogProjectionRequests[0].query, "authorization"), false);
});
