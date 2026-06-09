import assert from "node:assert/strict";
import test from "node:test";

import {
  backendHealth,
  backendLogs,
  backendProcessSupervisorRetiredError,
  ensureBackendProcess,
  spawnBackendChildProcess,
  startBackend,
  startBackendProcess,
  stopBackend,
  stopBackendProcess,
  touchBackendProcess,
} from "./backend-lifecycle.mjs";

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
  const error = backendProcessSupervisorRetiredError("model_mount.backend_process.start", {
    id: "backend.native",
    kind: "native_local",
  });

  assertBackendProcessSupervisorRetired(error, "model_mount.backend_process.start");
});

test("public backend lifecycle facade fails closed until Rust core owns lifecycle control", () => {
  const state = fakeState();

  assert.throws(
    () => backendHealth(state, "backend.native", deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.backend_id, "backend.native");
      assert.equal(error.details.backend_kind, "native_local");
      assert.equal(error.details.operation_kind, "model_mount.backend.health");
      assert.equal(error.details.rust_core_boundary, "model_mount.backend_lifecycle");
      assert.deepEqual(error.details.evidence_refs, [
        "public_backend_lifecycle_js_facade_retired",
        "rust_daemon_core_lifecycle_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "backendId"), false);
      assert.equal(Object.hasOwn(error.details, "backendKind"), false);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );

  assert.throws(
    () => startBackend(state, "backend.native", { loadOptions: { contextLength: 1024 } }, deps),
    (error) => {
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.backend.start");
      return true;
    },
  );

  assert.throws(
    () => stopBackend(state, "backend.native"),
    (error) => {
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.backend.stop");
      return true;
    },
  );

  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.logs, []);
  assert.deepEqual(state.writes, []);
});

test("blocked backend public lifecycle start still fails at Rust-core boundary before JS control", () => {
  const state = fakeState();

  assert.throws(
    () => startBackend(state, "backend.blocked", {}, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.backend_id, "backend.blocked");
      assert.equal(error.details.backend_kind, "llama_cpp");
      assert.equal(error.details.operation_kind, "model_mount.backend.start");
      assert.equal(Object.hasOwn(error.details, "backendId"), false);
      assert.equal(Object.hasOwn(error.details, "backendKind"), false);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    },
  );
});

test("public backend logs facade fails closed before reading local logs or writing a receipt", () => {
  const state = fakeState();
  let listFilesCalled = false;

  assert.throws(
    () =>
      backendLogs(state, "backend.native", {
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
      }),
    (error) => {
      assert.equal(error.code, "model_mount_backend_lifecycle_rust_core_required");
      assert.equal(error.details.operation_kind, "model_mount.backend.logs_read");
      return true;
    },
  );

  assert.equal(listFilesCalled, false);
  assert.deepEqual(state.receipts, []);
});
