import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createRustRouteControlClient,
  RUST_ROUTE_CONTROL_EVIDENCE_REFS,
} from "./rust-route-control-client.mjs";

test("resolves a route via the Rust daemon route-test endpoint", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          selection: {
            route: { id: "route.native-local" },
            endpoint: { id: "endpoint.e2e.native-local", modelId: "native:e2e" },
            provider: { id: "provider.hypervisor.local" },
            backend: { id: "backend.hypervisor.native-local.fixture" },
          },
        };
      },
    };
  };
  const client = createRustRouteControlClient({
    daemonEndpoint: "http://127.0.0.1:8765/",
    token: "tok-123",
    fetchImpl,
  });

  const selection = await client.selectRoute({
    modelId: "native:e2e",
    routeId: "route.native-local",
    capability: "chat",
    body: { extra: true },
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0].url,
    "http://127.0.0.1:8765/v1/model-mount/routes/route.native-local/test",
  );
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.authorization, "Bearer tok-123");
  const sentBody = JSON.parse(calls[0].init.body);
  assert.equal(sentBody.model, "native:e2e");
  assert.equal(sentBody.route_id, "route.native-local");
  assert.equal(sentBody.extra, true);

  assert.equal(selection.route.id, "route.native-local");
  assert.equal(selection.endpoint.id, "endpoint.e2e.native-local");
  assert.equal(selection.endpoint.model_id, "native:e2e");
  assert.equal(selection.provider.id, "provider.hypervisor.local");
  assert.equal(selection.rust_core_boundary, "model_mount.route_control");
  assert.deepEqual(selection.evidence_refs, RUST_ROUTE_CONTROL_EVIDENCE_REFS);
});

test("defaults the route id when none is supplied", async () => {
  let capturedUrl = null;
  const client = createRustRouteControlClient({
    daemonEndpoint: "http://127.0.0.1:8765",
    fetchImpl: async (url) => {
      capturedUrl = url;
      return { ok: true, status: 200, async json() { return { selection: {} }; } };
    },
  });
  const selection = await client.selectRoute({ modelId: "auto" });
  assert.equal(
    capturedUrl,
    "http://127.0.0.1:8765/v1/model-mount/routes/route.local-first/test",
  );
  assert.equal(selection.route.id, "route.local-first");
  assert.equal(selection.endpoint.model_id, "auto");
});

test("fails closed on a non-2xx daemon response", async () => {
  const client = createRustRouteControlClient({
    daemonEndpoint: "http://127.0.0.1:8765",
    fetchImpl: async () => ({
      ok: false,
      status: 409,
      async text() { return "no route"; },
    }),
  });
  await assert.rejects(
    () => client.selectRoute({ modelId: "native:e2e", routeId: "route.native-local" }),
    (error) => {
      assert.equal(error.status, 409);
      assert.equal(error.code, "runtime_model_route_selection_rust_core_failed");
      return true;
    },
  );
});

test("fails closed when no fetch implementation is available", async () => {
  const client = createRustRouteControlClient({ daemonEndpoint: "http://x", fetchImpl: null });
  await assert.rejects(
    () => client.selectRoute({ modelId: "native:e2e" }),
    (error) => {
      assert.equal(error.code, "runtime_model_route_selection_rust_core_unavailable");
      return true;
    },
  );
});
