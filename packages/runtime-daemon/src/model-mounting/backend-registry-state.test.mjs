import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  backendProcessForBackend,
  backendRegistry,
  deriveBackendRegistry,
  listBackendProcesses,
  reconciledBackendProcess,
  seedBackends,
  writeBackendLog,
} from "./backend-registry-state.mjs";

function fakeState() {
  return {
    backendProcesses: new Map(),
    backends: new Map(),
    bootId: "boot.current",
    homeDir: "/home/test",
    providers: {
      get() {
        throw new Error("deriveBackendRegistry must not read JS provider inventory");
      },
      size: 1,
    },
    stateDir: fs.mkdtempSync(path.join(os.tmpdir(), "ioi-backend-registry-")),
    nowIso() {
      return "2026-06-04T05:00:00.000Z";
    },
    backendProcessForBackend(backendId) {
      return backendProcessForBackend(this, backendId);
    },
    deriveBackendRegistry(checkedAt) {
      return deriveBackendRegistry(this, checkedAt, deps);
    },
    listBackendProcesses() {
      return listBackendProcesses(this);
    },
    reconciledBackendProcess(processRecord) {
      return reconciledBackendProcess(this, processRecord, deps);
    },
  };
}

const deps = {
  backendRegistryRecords(request) {
    assert.equal(Object.hasOwn(request, "providers"), false);
    const { checkedAt, hardware, llamaBinary, ollamaBinary, vllmBinary } = request;
    return [
      {
        id: "backend.llama_cpp",
        checkedAt,
        hardware,
        binary: llamaBinary,
        evidenceRefs: ["derived"],
      },
      {
        id: "backend.ollama",
        checkedAt,
        binary: ollamaBinary,
      },
      {
        id: "backend.vllm",
        checkedAt,
        binary: vllmBinary,
      },
    ];
  },
  discoverAutopilotLlamaServer(homeDir) {
    return `${homeDir}/bin/llama-server`;
  },
  findExecutable(name) {
    return `/usr/bin/${name}`;
  },
  hardwareSnapshot() {
    return { gpu: "fixture" };
  },
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
  processEnv: {},
  randomUUID() {
    return "uuid-1";
  },
  redact(event) {
    return { ...event, secret: event.secret ? "[REDACTED]" : undefined };
  },
  safeFileName(value) {
    return String(value).replace(/[^a-z0-9._-]+/gi, "_");
  },
};

test("deriveBackendRegistry uses environment override, discovery, executables, and hardware without provider inventory", () => {
  const state = fakeState();

  const derived = deriveBackendRegistry(state, "2026-06-04T05:00:00.000Z", {
    ...deps,
    processEnv: { IOI_LLAMA_CPP_SERVER_PATH: "/custom/llama-server" },
  });

  assert.equal(derived[0].binary, "/custom/llama-server");
  assert.deepEqual(derived[0].hardware, { gpu: "fixture" });
  assert.equal(derived[1].binary, "/usr/bin/ollama");
  assert.equal(derived[2].binary, "/usr/bin/vllm");
});

test("seedBackends fails closed before JS backend map mutation", () => {
  const state = fakeState();
  state.backends.set("backend.llama_cpp", { id: "backend.llama_cpp", status: "custom" });

  assert.throws(
    () => seedBackends(state, "2026-06-04T05:00:00.000Z"),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_backend_projection_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.backend_projection");
      assert.equal(error.details.operation_kind, "model_mount.backend.seed");
      assert.equal(error.details.checked_at, "2026-06-04T05:00:00.000Z");
      assert.deepEqual(error.details.evidence_refs, [
        "model_mount_backend_seed_js_map_write_retired",
        "rust_daemon_core_backend_projection_required",
        "agentgres_backend_projection_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "checkedAt"), false);
      return true;
    },
  );
  assert.deepEqual([...state.backends.entries()], [
    ["backend.llama_cpp", { id: "backend.llama_cpp", status: "custom" }],
  ]);
});

test("backendRegistry overlays stored records, process snapshots, and sorted output", () => {
  const state = fakeState();
  state.backends.set("backend.llama_cpp", {
    id: "backend.llama_cpp",
    processStatus: "configured",
    evidenceRefs: ["stored"],
  });
  state.backendProcesses.set("process.1", {
    id: "process.1",
    backendId: "backend.llama_cpp",
    status: "started",
    processStatus: "started",
    pidHash: "pid.hash",
    argsRedacted: ["llama-server"],
    startedAt: "2026-06-04T05:00:00.000Z",
    lastReceiptId: "receipt.backend",
  });

  const registry = backendRegistry(state);

  assert.deepEqual(registry.map((backend) => backend.id), ["backend.llama_cpp", "backend.ollama", "backend.vllm"]);
  const llama = registry[0];
  assert.equal(llama.processStatus, "started");
  assert.equal(llama.process.pidHash, "pid.hash");
  assert.deepEqual(llama.evidenceRefs, ["stored"]);
});

test("listBackendProcesses reconciles stale boot records and backendProcessForBackend returns newest", () => {
  const state = fakeState();
  state.backendProcesses.set("old", {
    id: "old",
    backendId: "backend.llama_cpp",
    status: "started",
    bootId: "boot.old",
    startedAt: "2026-06-04T05:00:00.000Z",
    evidenceRefs: ["existing"],
  });
  state.backendProcesses.set("new", {
    id: "new",
    backendId: "backend.llama_cpp",
    status: "started",
    bootId: "boot.current",
    startedAt: "2026-06-04T05:00:01.000Z",
  });

  const processes = listBackendProcesses(state);

  assert.equal(processes[0].status, "stale_recovered");
  assert.equal(processes[0].staleReason, "daemon_boot_mismatch");
  assert.deepEqual(processes[0].evidenceRefs, ["existing", "supervisor_stale_process_detection", "agentgres_process_projection_replay"]);
  assert.equal(backendProcessForBackend(state, "backend.llama_cpp").id, "new");
  assert.equal(reconciledBackendProcess(state, null, deps), null);
});

test("writeBackendLog returns redacted telemetry without local backend log files", () => {
  const state = fakeState();

  const record = writeBackendLog(state, "endpoint.local", { backendId: "backend.llama_cpp", secret: "token", status: "started" }, deps);

  assert.equal(record.id, "backend_log_uuid-1");
  assert.equal(record.secret, "[REDACTED]");
  assert.equal(record.persistenceStatus, "not_persisted");
  assert.deepEqual(record.evidenceRefs, [
    "model_mount_backend_log_js_writer_retired",
    "rust_daemon_core_backend_lifecycle",
    "agentgres_backend_lifecycle_truth_required",
  ]);
  const endpointLog = path.join(state.stateDir, "backend-logs", "endpoint.local.jsonl");
  const backendLog = path.join(state.stateDir, "backend-logs", "backend.llama_cpp.jsonl");
  assert.equal(fs.existsSync(endpointLog), false);
  assert.equal(fs.existsSync(backendLog), false);
});
