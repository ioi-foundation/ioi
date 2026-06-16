import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as backendRegistryState from "./backend-registry-state.mjs";

const {
  writeBackendLog,
} = backendRegistryState;

function fakeState() {
  return {
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
  };
}

const deps = {
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
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

test("backend registry JS derivation and seeding exports stay retired", () => {
  assert.equal(Object.hasOwn(backendRegistryState, "deriveBackendRegistry"), false);
  assert.equal(Object.hasOwn(backendRegistryState, "seedBackends"), false);
  assert.equal(Object.hasOwn(backendRegistryState, "listBackendProcesses"), false);
  assert.equal(Object.hasOwn(backendRegistryState, "backendProcessForBackend"), false);
  assert.equal(Object.hasOwn(backendRegistryState, "reconciledBackendProcess"), false);
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
