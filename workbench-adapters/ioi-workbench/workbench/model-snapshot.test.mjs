import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { formatBytes, modelSnapshotFromState } = require("./model-snapshot.js");

test("formatBytes preserves compact product labels", () => {
  assert.equal(formatBytes(0), "unknown");
  assert.equal(formatBytes(null), "unknown");
  assert.equal(formatBytes(Number.NaN), "unknown");
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1024), "1.0 KB");
  assert.equal(formatBytes(10 * 1024), "10 KB");
  assert.equal(formatBytes(1.5 * 1024 * 1024), "1.5 MB");
});

test("modelSnapshotFromState normalizes missing and malformed collections", () => {
  const snapshot = modelSnapshotFromState({
    modelMounting: {
      artifacts: [{ id: "artifact-1" }],
      endpoints: "not-array",
      instances: [{ id: "instance-1" }],
      routes: null,
      backends: [{ id: "backend-1" }],
      runtimeEngines: [{ id: "engine-1" }],
      receipts: [{ id: "receipt-1" }],
      downloads: [{ id: "download-1" }],
      providers: [{ id: "provider-1" }],
      catalog: { status: "ready" },
      catalogProviderConfigs: "not-array",
      server: { generatedAt: "server-time" },
      runtimePreference: { engineId: "engine-1" },
    },
  });

  assert.deepEqual(snapshot.artifacts, [{ id: "artifact-1" }]);
  assert.deepEqual(snapshot.endpoints, []);
  assert.deepEqual(snapshot.instances, [{ id: "instance-1" }]);
  assert.deepEqual(snapshot.routes, []);
  assert.deepEqual(snapshot.backends, [{ id: "backend-1" }]);
  assert.deepEqual(snapshot.runtimeEngines, [{ id: "engine-1" }]);
  assert.deepEqual(snapshot.receipts, [{ id: "receipt-1" }]);
  assert.deepEqual(snapshot.downloads, [{ id: "download-1" }]);
  assert.deepEqual(snapshot.providers, [{ id: "provider-1" }]);
  assert.deepEqual(snapshot.catalog, { status: "ready" });
  assert.deepEqual(snapshot.catalogProviderConfigs, []);
  assert.deepEqual(snapshot.server, { generatedAt: "server-time" });
  assert.deepEqual(snapshot.runtimePreference, { engineId: "engine-1" });
  assert.equal(snapshot.generatedAt, "server-time");
});

test("modelSnapshotFromState prefers explicit generatedAt and defaults empty state", () => {
  assert.deepEqual(modelSnapshotFromState({}), {
    artifacts: [],
    endpoints: [],
    instances: [],
    routes: [],
    backends: [],
    runtimeEngines: [],
    receipts: [],
    downloads: [],
    providers: [],
    catalog: {},
    catalogProviderConfigs: [],
    server: {},
    runtimePreference: {},
    generatedAt: null,
  });

  assert.equal(modelSnapshotFromState({
    modelMounting: {
      generatedAt: "explicit-time",
      server: { generatedAt: "server-time" },
    },
  }).generatedAt, "explicit-time");
});
