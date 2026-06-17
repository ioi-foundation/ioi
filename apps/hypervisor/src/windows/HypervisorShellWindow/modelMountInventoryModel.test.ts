import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT,
  HYPERVISOR_MODEL_MOUNT_SNAPSHOT_PATH,
  loadHypervisorModelMountInventorySnapshot,
  normalizeHypervisorModelMountInventorySnapshot,
  readHypervisorModelMountDaemonEndpoint,
} from "./modelMountInventoryModel.ts";

test("model mount inventory normalizer accepts raw daemon snapshot fields", () => {
  const snapshot = normalizeHypervisorModelMountInventorySnapshot(
    {
      routes: [
        {
          id: "model-route:hypervisor/default-local",
          role: "default-local",
          status: "active",
          privacy: "local_only",
        },
      ],
      endpoints: [
        {
          id: "endpoint.local.auto",
          providerId: "provider.local",
          modelId: "local:auto",
          status: "mounted",
          privacyClass: "local_private",
        },
      ],
      instances: [
        {
          id: "instance.endpoint.local.auto",
          endpointId: "endpoint.local.auto",
          providerId: "provider.local",
          modelId: "local:auto",
          status: "loaded",
        },
      ],
    },
    { checkedAt: "2026-06-17T00:00:00.000Z" },
  );

  assert.equal(
    snapshot.schema_version,
    "ioi.hypervisor.model_mount_inventory_snapshot.v1",
  );
  assert.equal(snapshot.source, "daemon-model-mount-inventory");
  assert.equal(snapshot.checked_at, "2026-06-17T00:00:00.000Z");
  assert.deepEqual(snapshot.routes, [
    {
      id: "model-route:hypervisor/default-local",
      role: "default-local",
      status: "active",
      privacy: "local_only",
    },
  ]);
  assert.deepEqual(snapshot.endpoints, [
    {
      id: "endpoint.local.auto",
      providerId: "provider.local",
      modelId: "local:auto",
      status: "mounted",
      privacyClass: "local_private",
    },
  ]);
  assert.deepEqual(snapshot.loadedInstances, [
    {
      id: "instance.endpoint.local.auto",
      endpointId: "endpoint.local.auto",
      providerId: "provider.local",
      modelId: "local:auto",
      status: "loaded",
    },
  ]);
});

test("model mount inventory normalizer accepts UI-normalized endpoint aliases", () => {
  const snapshot = normalizeHypervisorModelMountInventorySnapshot(
    {
      routes: [{ id: "route.native-local", role: "default", status: "ready" }],
      endpoints: [
        {
          id: "endpoint.autopilot.native-fixture",
          provider: "provider.autopilot.local",
          modelId: "autopilot:native-fixture",
          status: "degraded",
          privacy: "local_private",
        },
      ],
      instances: [{ id: "instance.fixture", status: "evicted" }],
    },
    { source: "fixture", checkedAt: "2026-06-17T00:00:00.000Z" },
  );

  assert.equal(snapshot.source, "fixture");
  assert.equal(snapshot.routes[0]?.status, "active");
  assert.deepEqual(snapshot.endpoints[0], {
    id: "endpoint.autopilot.native-fixture",
    providerId: "provider.autopilot.local",
    modelId: "autopilot:native-fixture",
    status: "degraded",
    privacyClass: "local_private",
  });
  assert.equal(snapshot.loadedInstances[0]?.status, "evicted");
});

test("model mount inventory loader fetches daemon snapshot endpoint", async () => {
  const requested: string[] = [];
  const snapshot = await loadHypervisorModelMountInventorySnapshot({
    endpoint: "http://127.0.0.1:9999/",
    checkedAt: "2026-06-17T00:00:00.000Z",
    fetchImpl: async (url) => {
      requested.push(url);
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            routes: [{ id: "model-route:hypervisor/default-local", status: "active" }],
            endpoints: [{ id: "endpoint.local.auto", status: "mounted" }],
            instances: [{ id: "instance.local.auto", status: "loaded" }],
          });
        },
      };
    },
  });

  assert.deepEqual(requested, [
    `http://127.0.0.1:9999${HYPERVISOR_MODEL_MOUNT_SNAPSHOT_PATH}`,
  ]);
  assert.equal(snapshot.checked_at, "2026-06-17T00:00:00.000Z");
  assert.equal(snapshot.routes[0]?.id, "model-route:hypervisor/default-local");
});

test("model mount inventory loader reports daemon errors", async () => {
  await assert.rejects(
    loadHypervisorModelMountInventorySnapshot({
      endpoint: "http://127.0.0.1:9999",
      fetchImpl: async () => ({
        ok: false,
        status: 503,
        async text() {
          return JSON.stringify({ error: "offline" });
        },
      }),
    }),
    /503/,
  );
});

test("model mount inventory endpoint defaults to local daemon outside browser", () => {
  assert.equal(
    readHypervisorModelMountDaemonEndpoint(),
    HYPERVISOR_MODEL_MOUNT_DEFAULT_DAEMON_ENDPOINT,
  );
});
