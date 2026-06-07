import assert from "node:assert/strict";
import test from "node:test";

import {
  backend,
  backendProcessSnapshot,
} from "./backend-processes.mjs";

function fakeState() {
  return {
    backendRegistry() {
      return [
        { id: "backend.llama", kind: "llama_cpp", baseUrl: "http://127.0.0.1:8091/v1" },
        { id: "backend.vllm", kind: "vllm", baseUrl: "http://0.0.0.0:8092/v1" },
        { id: "backend.ollama", kind: "ollama", baseUrl: "http://127.0.0.1:11434" },
        { id: "backend.native", kind: "native_local" },
        { id: "backend.custom", kind: "custom_backend" },
      ];
    },
    runtimeDefaultLoadOptions(backendId) {
      return {
        "backend.llama": { contextLength: 4096, parallel: 2, gpu: "auto", identifier: "llama profile" },
        "backend.native": { contextLength: 2048, parallel: 1, gpu: "off" },
        "backend.vllm": { contextLength: 8192, parallel: 4 },
      }[backendId] ?? {};
    },
  };
}

const deps = {
  notFound(message, details) {
    const error = new Error(message);
    error.status = 404;
    error.details = details;
    return error;
  },
};

test("backend lookup returns registry records and maps missing ids through notFound", () => {
  const state = fakeState();

  assert.equal(backend(state, "backend.llama", deps).kind, "llama_cpp");
  assert.throws(
    () => backend(state, "backend.missing", deps),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.backend_id, "backend.missing");
      assert.equal(Object.hasOwn(error.details, "backendId"), false);
      return true;
    },
  );
});

test("backend process snapshot defaults not-started state and normalizes optional fields", () => {
  assert.deepEqual(backendProcessSnapshot(null), {
    status: "not_started",
    processStatus: "not_started",
    evidenceRefs: ["supervisor_process_not_started"],
  });

  const snapshot = backendProcessSnapshot({
    id: "process_a",
    backendId: "backend.llama",
    backendKind: "llama_cpp",
    status: "started",
    spawned: true,
    stale: true,
    evidenceRefs: ["started"],
  });

  assert.equal(snapshot.processStatus, "started");
  assert.equal(snapshot.pidTracked, "process_ref_hash");
  assert.equal(snapshot.spawned, true);
  assert.equal(snapshot.stale, true);
  assert.deepEqual(snapshot.argsRedacted, []);
  assert.deepEqual(snapshot.evidenceRefs, ["started"]);
});
