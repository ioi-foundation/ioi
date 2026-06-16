import assert from "node:assert/strict";
import test from "node:test";
import {
  MODEL_MOUNT_IDE_CONTROL_ROUTES,
  WORKFLOW_MODEL_MOUNT_IDE_CONTROL_SCHEMA_VERSION,
  createModelMountIdeControlRequest,
  modelMountIdeControlRouteIdsByFamily,
  renderModelMountIdeControlEndpoint,
  type ModelMountIdeControlRouteId,
} from "./workflow-model-mount-control-nodes";

interface ExpectedModelMountIdeControlRequest {
  routeId: ModelMountIdeControlRouteId;
  expected: string;
  pathParams?: Record<string, unknown>;
  input?: Record<string, unknown>;
}

const EXPECTED_MODEL_MOUNT_IDE_CONTROL_REQUESTS: ExpectedModelMountIdeControlRequest[] = [
  { routeId: "route.upsert", expected: "POST /v1/model-mount/routes" },
  {
    routeId: "route.test",
    expected: "POST /v1/model-mount/routes/route.ide/test",
    pathParams: { route_id: "route.ide" },
  },
  { routeId: "server.start", expected: "POST /v1/model-mount/server/start" },
  { routeId: "server.stop", expected: "POST /v1/model-mount/server/stop" },
  { routeId: "server.restart", expected: "POST /v1/model-mount/server/restart" },
  { routeId: "backend.list", expected: "GET /v1/model-mount/backends" },
  {
    routeId: "backend.logs",
    expected: "GET /v1/model-mount/backends/backend.ide/logs",
    pathParams: { backend_id: "backend.ide" },
  },
  {
    routeId: "backend.health",
    expected: "POST /v1/model-mount/backends/backend.ide/health",
    pathParams: { backend_id: "backend.ide" },
  },
  {
    routeId: "backend.start",
    expected: "POST /v1/model-mount/backends/backend.ide/start",
    pathParams: { backend_id: "backend.ide" },
  },
  {
    routeId: "backend.stop",
    expected: "POST /v1/model-mount/backends/backend.ide/stop",
    pathParams: { backend_id: "backend.ide" },
  },
  { routeId: "runtime.survey", expected: "POST /v1/model-mount/runtime/survey" },
  {
    routeId: "runtime.engines.list",
    expected: "GET /v1/model-mount/runtime/engines",
  },
  {
    routeId: "runtime.engine.get",
    expected: "GET /v1/model-mount/runtime/engines/engine.ide",
    pathParams: { engine_id: "engine.ide" },
  },
  { routeId: "runtime.select", expected: "POST /v1/model-mount/runtime/select" },
  {
    routeId: "runtime.engine.select",
    expected: "POST /v1/model-mount/runtime/engines/engine.ide/select",
    pathParams: { engine_id: "engine.ide" },
  },
  {
    routeId: "runtime.engine.update",
    expected: "PATCH /v1/model-mount/runtime/engines/engine.ide",
    pathParams: { engine_id: "engine.ide" },
  },
  {
    routeId: "runtime.engine.delete",
    expected: "DELETE /v1/model-mount/runtime/engines/engine.ide",
    pathParams: { engine_id: "engine.ide" },
  },
  {
    routeId: "lifecycle.instances.list",
    expected: "GET /v1/model-mount/instances",
  },
  {
    routeId: "lifecycle.instances.loaded",
    expected: "GET /v1/model-mount/instances/loaded",
  },
  {
    routeId: "storage.catalog.import_url",
    expected: "POST /v1/model-mount/catalog/import-url",
  },
  {
    routeId: "lifecycle.artifact.import",
    expected: "POST /v1/model-mount/artifacts/import",
  },
  {
    routeId: "lifecycle.artifact.delete",
    expected: "DELETE /v1/model-mount/artifacts/artifact.ide",
    pathParams: { artifact_id: "artifact.ide" },
  },
  {
    routeId: "lifecycle.endpoint.mount",
    expected: "POST /v1/model-mount/endpoints",
  },
  {
    routeId: "lifecycle.endpoint.unmount",
    expected: "DELETE /v1/model-mount/endpoints/endpoint.ide",
    pathParams: { endpoint_id: "endpoint.ide" },
  },
  {
    routeId: "lifecycle.endpoint.load",
    expected: "POST /v1/model-mount/endpoints/endpoint.ide/load",
    pathParams: { endpoint_id: "endpoint.ide" },
  },
  {
    routeId: "lifecycle.endpoint.unload",
    expected: "POST /v1/model-mount/endpoints/endpoint.ide/unload",
    pathParams: { endpoint_id: "endpoint.ide" },
  },
  {
    routeId: "lifecycle.instance.load",
    expected: "POST /v1/model-mount/instances/load",
  },
  {
    routeId: "lifecycle.instance.unload",
    expected: "POST /v1/model-mount/instances/unload",
  },
  {
    routeId: "lifecycle.instance.unload_by_id",
    expected: "POST /v1/model-mount/instances/instance.ide/unload",
    pathParams: { instance_id: "instance.ide" },
  },
  {
    routeId: "storage.download.create",
    expected: "POST /v1/model-mount/downloads",
  },
  {
    routeId: "storage.download.status",
    expected: "GET /v1/model-mount/downloads/download.ide/status",
    pathParams: { download_id: "download.ide" },
  },
  {
    routeId: "storage.download.cancel",
    expected: "POST /v1/model-mount/downloads/download.ide/cancel",
    pathParams: { download_id: "download.ide" },
  },
  { routeId: "storage.cleanup", expected: "POST /v1/model-mount/storage/cleanup" },
  {
    routeId: "catalog_provider.get",
    expected: "GET /v1/model-mount/catalog/providers/catalog.ide",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.configure",
    expected: "PATCH /v1/model-mount/catalog/providers/catalog.ide",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.oauth.start",
    expected: "POST /v1/model-mount/catalog/providers/catalog.ide/oauth/start",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.oauth.callback",
    expected: "POST /v1/model-mount/catalog/providers/catalog.ide/oauth/callback",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.oauth.exchange",
    expected: "POST /v1/model-mount/catalog/providers/catalog.ide/oauth/exchange",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.oauth.refresh",
    expected: "POST /v1/model-mount/catalog/providers/catalog.ide/oauth/refresh",
    pathParams: { provider_id: "catalog.ide" },
  },
  {
    routeId: "catalog_provider.oauth.revoke",
    expected: "POST /v1/model-mount/catalog/providers/catalog.ide/oauth/revoke",
    pathParams: { provider_id: "catalog.ide" },
  },
  { routeId: "token.list", expected: "GET /v1/model-mount/tokens" },
  { routeId: "token.create", expected: "POST /v1/model-mount/tokens" },
  { routeId: "token.count", expected: "POST /v1/model-mount/tokens/count" },
  {
    routeId: "token.revoke",
    expected: "DELETE /v1/model-mount/tokens/token.ide",
    pathParams: { token_id: "token.ide" },
  },
  { routeId: "vault.refs.list", expected: "GET /v1/model-mount/vault/refs" },
  { routeId: "vault.ref.bind", expected: "POST /v1/model-mount/vault/refs" },
  { routeId: "vault.ref.remove", expected: "DELETE /v1/model-mount/vault/refs" },
  { routeId: "vault.ref.meta", expected: "POST /v1/model-mount/vault/refs/meta" },
  { routeId: "vault.status", expected: "GET /v1/model-mount/vault/status" },
  { routeId: "vault.health", expected: "POST /v1/model-mount/vault/health" },
  {
    routeId: "vault.health.latest",
    expected: "GET /v1/model-mount/vault/health/latest",
  },
  { routeId: "provider.upsert", expected: "POST /v1/model-mount/providers" },
  {
    routeId: "provider.update",
    expected: "PATCH /v1/model-mount/providers/provider.ide",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.health.latest",
    expected: "GET /v1/model-mount/providers/provider.ide/health/latest",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.health",
    expected: "POST /v1/model-mount/providers/provider.ide/health",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.models",
    expected: "GET /v1/model-mount/providers/provider.ide/models",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.loaded",
    expected: "GET /v1/model-mount/providers/provider.ide/loaded",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.start",
    expected: "POST /v1/model-mount/providers/provider.ide/start",
    pathParams: { provider_id: "provider.ide" },
  },
  {
    routeId: "provider.stop",
    expected: "POST /v1/model-mount/providers/provider.ide/stop",
    pathParams: { provider_id: "provider.ide" },
  },
];

test("IDE controls model_mount through stable daemon protocol routes", () => {
  const requests = EXPECTED_MODEL_MOUNT_IDE_CONTROL_REQUESTS.map((entry) =>
    createModelMountIdeControlRequest({
      routeId: entry.routeId,
      pathParams: entry.pathParams,
      input: entry.input ?? {},
      workflowGraphId: "workflow.model-mount.ide-control",
    }),
  );
  const requestLines = requests.map((request) => `${request.method} ${request.endpoint}`);

  assert.deepEqual(
    requestLines,
    EXPECTED_MODEL_MOUNT_IDE_CONTROL_REQUESTS.map((entry) => entry.expected),
  );
  assert.equal(MODEL_MOUNT_IDE_CONTROL_ROUTES.length, requestLines.length);
  assert.equal(new Set(requestLines).size, requestLines.length);
  assert.equal(requests.some((entry) => entry.endpoint.includes("/api/v1/")), false);
  assert.equal(requestLines.some((entry) => entry.includes("/api/v1/")), false);
});

test("model_mount IDE control requests are protocol clients, not compatibility shims", () => {
  const request = createModelMountIdeControlRequest({
    routeId: "lifecycle.instance.load",
    nodeId: "load-model",
    input: {
      endpoint_id: "endpoint.ide",
      load_options: {
        estimate_only: false,
        context_length: 4096,
        ttl_seconds: 60,
      },
    },
    workflowGraphId: "workflow.model-mount.load",
    actor: "workflow-author",
  });

  assert.equal(request.schemaVersion, WORKFLOW_MODEL_MOUNT_IDE_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "model_mount_control");
  assert.equal(request.endpoint, "/v1/model-mount/instances/load");
  assert.ok(request.body);
  const body = request.body;
  assert.equal(body.schema_version, WORKFLOW_MODEL_MOUNT_IDE_CONTROL_SCHEMA_VERSION);
  assert.equal(body.source, "react_flow");
  assert.equal(body.actor, "workflow-author");
  assert.equal(body.workflow_graph_id, "workflow.model-mount.load");
  assert.equal(body.workflow_node_id, "model-mount.lifecycle.instance.load");
  assert.equal(body.control_route_id, "lifecycle.instance.load");
  assert.equal(body.control_family, "lifecycle");
  assert.deepEqual(body.authority_scopes, ["model.instance.load"]);
  assert.equal(Object.prototype.hasOwnProperty.call(body, "workflowGraphId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(body, "workflowNodeId"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(body, "endpoint"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(body.input, "endpointId"), false);
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      (body.input as Record<string, unknown>).load_options as Record<string, unknown>,
      "estimateOnly",
    ),
    false,
  );
});

test("model_mount IDE control path params encode and retired body aliases fail closed", () => {
  assert.equal(
    renderModelMountIdeControlEndpoint("lifecycle.endpoint.load", {
      endpoint_id: "endpoint/local model",
    }),
    "/v1/model-mount/endpoints/endpoint%2Flocal%20model/load",
  );
  assert.deepEqual(modelMountIdeControlRouteIdsByFamily("vault"), [
    "vault.refs.list",
    "vault.ref.bind",
    "vault.ref.remove",
    "vault.ref.meta",
    "vault.status",
    "vault.health",
    "vault.health.latest",
  ]);
  assert.throws(
    () =>
      createModelMountIdeControlRequest({
        routeId: "lifecycle.instance.load",
        input: {
          endpointId: "retired",
          load_options: { estimateOnly: true },
        },
      }),
    /Retired model_mount IDE control input alias 'endpointId'/,
  );
  assert.throws(
    () =>
      createModelMountIdeControlRequest({
        routeId: "provider.start",
        pathParams: { provider_id: "provider.ide", extra: "unused" },
      }),
    /Unused model_mount IDE control path param 'extra'/,
  );
});
