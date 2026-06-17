import assert from "node:assert/strict";
import test from "node:test";
import {
  MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES,
  WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION,
  createModelMountWorkbenchControlRequest,
  modelMountWorkbenchControlRouteIdsByFamily,
  renderModelMountWorkbenchControlEndpoint,
  type ModelMountWorkbenchControlRouteId,
} from "./workflow-model-mount-control-nodes";

interface ExpectedModelMountWorkbenchControlRequest {
  routeId: ModelMountWorkbenchControlRouteId;
  expected: string;
  pathParams?: Record<string, unknown>;
  input?: Record<string, unknown>;
}

const EXPECTED_MODEL_MOUNT_WORKBENCH_CONTROL_REQUESTS: ExpectedModelMountWorkbenchControlRequest[] = [
  { routeId: "route.upsert", expected: "POST /v1/model-mount/routes" },
  {
    routeId: "route.test",
    expected: "POST /v1/model-mount/routes/route.workbench/test",
    pathParams: { route_id: "route.workbench" },
  },
  { routeId: "server.start", expected: "POST /v1/model-mount/server/start" },
  { routeId: "server.stop", expected: "POST /v1/model-mount/server/stop" },
  { routeId: "server.restart", expected: "POST /v1/model-mount/server/restart" },
  { routeId: "backend.list", expected: "GET /v1/model-mount/backends" },
  {
    routeId: "backend.logs",
    expected: "GET /v1/model-mount/backends/backend.workbench/logs",
    pathParams: { backend_id: "backend.workbench" },
  },
  {
    routeId: "backend.health",
    expected: "POST /v1/model-mount/backends/backend.workbench/health",
    pathParams: { backend_id: "backend.workbench" },
  },
  {
    routeId: "backend.start",
    expected: "POST /v1/model-mount/backends/backend.workbench/start",
    pathParams: { backend_id: "backend.workbench" },
  },
  {
    routeId: "backend.stop",
    expected: "POST /v1/model-mount/backends/backend.workbench/stop",
    pathParams: { backend_id: "backend.workbench" },
  },
  { routeId: "runtime.survey", expected: "POST /v1/model-mount/runtime/survey" },
  {
    routeId: "runtime.engines.list",
    expected: "GET /v1/model-mount/runtime/engines",
  },
  {
    routeId: "runtime.engine.get",
    expected: "GET /v1/model-mount/runtime/engines/engine.workbench",
    pathParams: { engine_id: "engine.workbench" },
  },
  { routeId: "runtime.select", expected: "POST /v1/model-mount/runtime/select" },
  {
    routeId: "runtime.engine.select",
    expected: "POST /v1/model-mount/runtime/engines/engine.workbench/select",
    pathParams: { engine_id: "engine.workbench" },
  },
  {
    routeId: "runtime.engine.update",
    expected: "PATCH /v1/model-mount/runtime/engines/engine.workbench",
    pathParams: { engine_id: "engine.workbench" },
  },
  {
    routeId: "runtime.engine.delete",
    expected: "DELETE /v1/model-mount/runtime/engines/engine.workbench",
    pathParams: { engine_id: "engine.workbench" },
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
    expected: "DELETE /v1/model-mount/artifacts/artifact.workbench",
    pathParams: { artifact_id: "artifact.workbench" },
  },
  {
    routeId: "lifecycle.endpoint.mount",
    expected: "POST /v1/model-mount/endpoints",
  },
  {
    routeId: "lifecycle.endpoint.unmount",
    expected: "DELETE /v1/model-mount/endpoints/endpoint.workbench",
    pathParams: { endpoint_id: "endpoint.workbench" },
  },
  {
    routeId: "lifecycle.endpoint.load",
    expected: "POST /v1/model-mount/endpoints/endpoint.workbench/load",
    pathParams: { endpoint_id: "endpoint.workbench" },
  },
  {
    routeId: "lifecycle.endpoint.unload",
    expected: "POST /v1/model-mount/endpoints/endpoint.workbench/unload",
    pathParams: { endpoint_id: "endpoint.workbench" },
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
    expected: "POST /v1/model-mount/instances/instance.workbench/unload",
    pathParams: { instance_id: "instance.workbench" },
  },
  {
    routeId: "storage.download.create",
    expected: "POST /v1/model-mount/downloads",
  },
  {
    routeId: "storage.download.status",
    expected: "GET /v1/model-mount/downloads/download.workbench/status",
    pathParams: { download_id: "download.workbench" },
  },
  {
    routeId: "storage.download.cancel",
    expected: "POST /v1/model-mount/downloads/download.workbench/cancel",
    pathParams: { download_id: "download.workbench" },
  },
  { routeId: "storage.cleanup", expected: "POST /v1/model-mount/storage/cleanup" },
  {
    routeId: "catalog_provider.get",
    expected: "GET /v1/model-mount/catalog/providers/catalog.workbench",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.configure",
    expected: "PATCH /v1/model-mount/catalog/providers/catalog.workbench",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.oauth.start",
    expected: "POST /v1/model-mount/catalog/providers/catalog.workbench/oauth/start",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.oauth.callback",
    expected: "POST /v1/model-mount/catalog/providers/catalog.workbench/oauth/callback",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.oauth.exchange",
    expected: "POST /v1/model-mount/catalog/providers/catalog.workbench/oauth/exchange",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.oauth.refresh",
    expected: "POST /v1/model-mount/catalog/providers/catalog.workbench/oauth/refresh",
    pathParams: { provider_id: "catalog.workbench" },
  },
  {
    routeId: "catalog_provider.oauth.revoke",
    expected: "POST /v1/model-mount/catalog/providers/catalog.workbench/oauth/revoke",
    pathParams: { provider_id: "catalog.workbench" },
  },
  { routeId: "token.list", expected: "GET /v1/model-mount/tokens" },
  { routeId: "token.create", expected: "POST /v1/model-mount/tokens" },
  { routeId: "token.count", expected: "POST /v1/model-mount/tokens/count" },
  {
    routeId: "token.revoke",
    expected: "DELETE /v1/model-mount/tokens/token.workbench",
    pathParams: { token_id: "token.workbench" },
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
    expected: "PATCH /v1/model-mount/providers/provider.workbench",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.health.latest",
    expected: "GET /v1/model-mount/providers/provider.workbench/health/latest",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.health",
    expected: "POST /v1/model-mount/providers/provider.workbench/health",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.models",
    expected: "GET /v1/model-mount/providers/provider.workbench/models",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.loaded",
    expected: "GET /v1/model-mount/providers/provider.workbench/loaded",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.start",
    expected: "POST /v1/model-mount/providers/provider.workbench/start",
    pathParams: { provider_id: "provider.workbench" },
  },
  {
    routeId: "provider.stop",
    expected: "POST /v1/model-mount/providers/provider.workbench/stop",
    pathParams: { provider_id: "provider.workbench" },
  },
];

test("Workbench controls model_mount through stable daemon protocol routes", () => {
  const requests = EXPECTED_MODEL_MOUNT_WORKBENCH_CONTROL_REQUESTS.map((entry) =>
    createModelMountWorkbenchControlRequest({
      routeId: entry.routeId,
      pathParams: entry.pathParams,
      input: entry.input ?? {},
      workflowGraphId: "workflow.model-mount.workbench-control",
    }),
  );
  const requestLines = requests.map((request) => `${request.method} ${request.endpoint}`);

  assert.deepEqual(
    requestLines,
    EXPECTED_MODEL_MOUNT_WORKBENCH_CONTROL_REQUESTS.map((entry) => entry.expected),
  );
  assert.equal(MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES.length, requestLines.length);
  assert.equal(new Set(requestLines).size, requestLines.length);
  assert.equal(requests.some((entry) => entry.endpoint.includes("/api/v1/")), false);
  assert.equal(requestLines.some((entry) => entry.includes("/api/v1/")), false);
});

test("model_mount Workbench control requests are protocol clients, not compatibility shims", () => {
  const request = createModelMountWorkbenchControlRequest({
    routeId: "lifecycle.instance.load",
    nodeId: "load-model",
    input: {
      endpoint_id: "endpoint.workbench",
      load_options: {
        estimate_only: false,
        context_length: 4096,
        ttl_seconds: 60,
      },
    },
    workflowGraphId: "workflow.model-mount.load",
    actor: "workflow-author",
  });

  assert.equal(request.schemaVersion, WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION);
  assert.equal(request.nodeType, "model_mount_control");
  assert.equal(request.endpoint, "/v1/model-mount/instances/load");
  assert.ok(request.body);
  const body = request.body;
  assert.equal(body.schema_version, WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION);
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

test("model_mount Workbench control path params encode and retired body aliases fail closed", () => {
  assert.equal(
    renderModelMountWorkbenchControlEndpoint("lifecycle.endpoint.load", {
      endpoint_id: "endpoint/local model",
    }),
    "/v1/model-mount/endpoints/endpoint%2Flocal%20model/load",
  );
  assert.deepEqual(modelMountWorkbenchControlRouteIdsByFamily("vault"), [
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
      createModelMountWorkbenchControlRequest({
        routeId: "lifecycle.instance.load",
        input: {
          endpointId: "retired",
          load_options: { estimateOnly: true },
        },
      }),
    /Retired model_mount Workbench control input alias 'endpointId'/,
  );
  assert.throws(
    () =>
      createModelMountWorkbenchControlRequest({
        routeId: "provider.start",
        pathParams: { provider_id: "provider.workbench", extra: "unused" },
      }),
    /Unused model_mount Workbench control path param 'extra'/,
  );
});
