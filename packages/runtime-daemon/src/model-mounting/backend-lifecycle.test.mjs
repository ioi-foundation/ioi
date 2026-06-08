import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  backendHealth,
  backendLogs,
  ensureBackendProcess,
  spawnBackendChildProcess,
  startBackend,
  startBackendProcess,
  stopBackend,
  stopBackendProcess,
  touchBackendProcess,
} from "./backend-lifecycle.mjs";
import { backendProcessSnapshot } from "./backend-processes.mjs";

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
    recordStateCommits: [],
    writes: [],
    now: "2026-06-03T20:00:00.000Z",
    backend(backendId) {
      return this.backends.get(backendId);
    },
    backendProcessArgs(backend) {
      return [backend.kind, "--model", "fixture"];
    },
    backendProcessForBackend(backendId) {
      return [...this.backendProcesses.values()].filter((record) => record.backendId === backendId).at(-1) ?? null;
    },
    backendProcessSnapshot(record) {
      return backendProcessSnapshot(record);
    },
    backendProcessSpawnArgs() {
      return ["--serve"];
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
    runtimeDefaultLoadOptions() {
      return { contextLength: 4096 };
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
    writeMap(dir, map) {
      this.writes.push([dir, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
        admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
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

test("ensure backend process touches an existing started record", () => {
  const state = fakeState();
  state.backendProcesses.set("process-a", {
    id: "process-a",
    backendId: "backend.native",
    backendKind: "native_local",
    status: "started",
    stale: true,
    evidenceRefs: ["existing"],
  });

  const result = ensureBackendProcess(state, "backend.native", { reason: "health_probe" });

  assert.equal(result.status, "stale_recovered");
  assert.equal(result.reason, "health_probe");
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits[0].record_dir, "backend-processes");
  assert.equal(state.recordStateCommits[0].record_id, "process-a");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.backend_process.touch");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
});

test("start backend process records deterministic fixture process metadata", () => {
  const state = fakeState();

  const result = startBackendProcess(state, state.backend("backend.native"), { loadOptions: { startupTimeoutMs: 10 } }, deps);

  assert.equal(result.backendId, "backend.native");
  assert.equal(result.supervisorKind, "deterministic_fixture_process");
  assert.equal(result.spawned, false);
  assert.equal(result.spawnStatus, "not_required");
  assert.equal(result.startupTimeoutMs, 10);
  assert.equal(result.loadOptions.redacted, true);
  assert.equal(state.recordStateCommits[0].record_dir, "backend-processes");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.backend_process.start");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.equal(state.logs.at(-1).event, "backend_process_start");
});

test("backend process persistence fails closed without Rust Agentgres record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () => startBackendProcess(state, state.backend("backend.native"), { loadOptions: { startupTimeoutMs: 10 } }, deps),
    (error) => {
      assert.equal(error.code, "model_mount_backend_process_state_commit_unconfigured");
      assert.equal(error.details.backend_id, "backend.native");
      assert.equal(error.details.record_dir, "backend-processes");
      return true;
    },
  );

  assert.equal(state.backendProcesses.size, 0);
  assert.deepEqual(state.writes, []);
});

test("spawn backend child process records output and exit without leaking raw output", () => {
  const state = fakeState();
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.pid = 42;

  const result = spawnBackendChildProcess(
    state,
    state.backend("backend.llama"),
    {
      endpoint: { artifactPath: "/models/model.gguf" },
      processRef: "supervised://backend.llama/process",
      argsRedacted: ["llama-server", "--model", "artifact:hash"],
    },
    {
      ...deps,
      spawn(binaryPath, args, options) {
        assert.equal(binaryPath, "/bin/llama-server");
        assert.deepEqual(args, ["--serve"]);
        assert.equal(options.env.IOI_MODEL_BACKEND_BASE_URL, "http://127.0.0.1:8091/v1");
        assert.match(options.env.LD_LIBRARY_PATH, /^\/bin\/llama-server:lib:/);
        return child;
      },
    },
  );

  assert.equal(result.spawned, true);
  state.backendProcesses.set("process-llama", {
    id: "process-llama",
    backendId: "backend.llama",
    backendKind: "llama_cpp",
    status: "started",
    pidHash: result.pidHash,
    evidenceRefs: ["started"],
  });
  child.stdout.emit("data", "secret stdout");
  child.emit("exit", 1, null);

  assert.equal(state.logs.some((record) => record.event === "backend_process_stdout" && record.outputHash), true);
  assert.equal(state.logs.some((record) => record.event === "backend_process_exit" && record.exitCode === 1), true);
  assert.equal(state.backendProcesses.get("process-llama").status, "degraded");
  assert.equal(state.recordStateCommits[0].record_dir, "backend-processes");
  assert.equal(state.recordStateCommits[0].record_id, "process-llama");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.backend_process.exit");
});

test("stop backend process kills tracked children and appends clean stop evidence", () => {
  const state = fakeState();
  let killedWith = null;
  state.backendProcesses.set("process-a", {
    id: "process-a",
    backendId: "backend.llama",
    backendKind: "llama_cpp",
    status: "started",
    childProcessKey: "child-a",
    evidenceRefs: ["started"],
  });
  state.backendChildProcesses.set("child-a", {
    killed: false,
    kill(signal) {
      killedWith = signal;
    },
  });

  const result = stopBackendProcess(state, state.backend("backend.llama"), { reason: "operator_stop" }, deps);

  assert.equal(killedWith, "SIGTERM");
  assert.equal(result.status, "stopped");
  assert.deepEqual(result.evidenceRefs, ["started", "clean_backend_stop"]);
  assert.equal(state.recordStateCommits[0].record_dir, "backend-processes");
  assert.equal(state.recordStateCommits[0].record_id, "process-a");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.backend_process.stop");
  assert.equal(state.logs.at(-1).event, "backend_process_stop");
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
  assert.deepEqual(state.recordStateCommits, []);
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
