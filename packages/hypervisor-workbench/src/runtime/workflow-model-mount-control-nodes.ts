export const WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION =
  "ioi.workflow.model-mount-control.v1" as const;
export const MODEL_MOUNT_WORKBENCH_CONTROL_SOURCE = "react_flow" as const;
export const MODEL_MOUNT_WORKBENCH_CONTROL_COMPONENT_KIND =
  "model_mount_control" as const;
export const MODEL_MOUNT_WORKBENCH_CONTROL_PAYLOAD_SCHEMA_VERSION =
  "ioi.model-mount.control-client.v1" as const;

export type ModelMountWorkbenchControlMethod = "GET" | "POST" | "PATCH" | "DELETE";
export type ModelMountWorkbenchControlFamily =
  | "route"
  | "server"
  | "backend"
  | "runtime"
  | "lifecycle"
  | "storage"
  | "catalog_provider"
  | "token"
  | "vault"
  | "provider";

export interface ModelMountWorkbenchControlRoute {
  readonly id: string;
  readonly family: ModelMountWorkbenchControlFamily;
  readonly method: ModelMountWorkbenchControlMethod;
  readonly path: string;
  readonly authorityScopes: readonly string[];
}

const controlRoute = <const Id extends string>(
  id: Id,
  family: ModelMountWorkbenchControlFamily,
  method: ModelMountWorkbenchControlMethod,
  path: string,
  authorityScopes: readonly string[],
) =>
  ({
    id,
    family,
    method,
    path,
    authorityScopes,
  }) as const;

export const MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES = [
  controlRoute("route.upsert", "route", "POST", "/v1/model-mount/routes", [
    "route.write:*",
  ]),
  controlRoute("route.test", "route", "POST", "/v1/model-mount/routes/{route_id}/test", [
    "route.use:{route_id}",
  ]),
  controlRoute("server.start", "server", "POST", "/v1/model-mount/server/start", [
    "server.control:start",
  ]),
  controlRoute("server.stop", "server", "POST", "/v1/model-mount/server/stop", [
    "server.control:stop",
  ]),
  controlRoute(
    "server.restart",
    "server",
    "POST",
    "/v1/model-mount/server/restart",
    ["server.control:restart"],
  ),
  controlRoute("backend.list", "backend", "GET", "/v1/model-mount/backends", [
    "backend.read:*",
  ]),
  controlRoute("backend.logs", "backend", "GET", "/v1/model-mount/backends/{backend_id}/logs", [
    "backend.read:{backend_id}",
  ]),
  controlRoute("backend.health", "backend", "POST", "/v1/model-mount/backends/{backend_id}/health", [
    "backend.control:{backend_id}:health",
  ]),
  controlRoute("backend.start", "backend", "POST", "/v1/model-mount/backends/{backend_id}/start", [
    "backend.control:{backend_id}:start",
  ]),
  controlRoute("backend.stop", "backend", "POST", "/v1/model-mount/backends/{backend_id}/stop", [
    "backend.control:{backend_id}:stop",
  ]),
  controlRoute("runtime.survey", "runtime", "POST", "/v1/model-mount/runtime/survey", [
    "runtime.control:survey",
  ]),
  controlRoute("runtime.engines.list", "runtime", "GET", "/v1/model-mount/runtime/engines", [
    "runtime.read:engines",
  ]),
  controlRoute("runtime.engine.get", "runtime", "GET", "/v1/model-mount/runtime/engines/{engine_id}", [
    "runtime.read:{engine_id}",
  ]),
  controlRoute("runtime.select", "runtime", "POST", "/v1/model-mount/runtime/select", [
    "runtime.control:select",
  ]),
  controlRoute(
    "runtime.engine.select",
    "runtime",
    "POST",
    "/v1/model-mount/runtime/engines/{engine_id}/select",
    ["runtime.control:{engine_id}:select"],
  ),
  controlRoute("runtime.engine.update", "runtime", "PATCH", "/v1/model-mount/runtime/engines/{engine_id}", [
    "runtime.control:{engine_id}:update",
  ]),
  controlRoute("runtime.engine.delete", "runtime", "DELETE", "/v1/model-mount/runtime/engines/{engine_id}", [
    "runtime.control:{engine_id}:delete",
  ]),
  controlRoute("lifecycle.instances.list", "lifecycle", "GET", "/v1/model-mount/instances", [
    "model.instance.read:*",
  ]),
  controlRoute("lifecycle.instances.loaded", "lifecycle", "GET", "/v1/model-mount/instances/loaded", [
    "model.instance.read:loaded",
  ]),
  controlRoute("storage.catalog.import_url", "storage", "POST", "/v1/model-mount/catalog/import-url", [
    "model.catalog.import",
  ]),
  controlRoute("lifecycle.artifact.import", "lifecycle", "POST", "/v1/model-mount/artifacts/import", [
    "model.artifact.import",
  ]),
  controlRoute("lifecycle.artifact.delete", "lifecycle", "DELETE", "/v1/model-mount/artifacts/{artifact_id}", [
    "model.artifact.delete:{artifact_id}",
  ]),
  controlRoute("lifecycle.endpoint.mount", "lifecycle", "POST", "/v1/model-mount/endpoints", [
    "model.endpoint.mount",
  ]),
  controlRoute("lifecycle.endpoint.unmount", "lifecycle", "DELETE", "/v1/model-mount/endpoints/{endpoint_id}", [
    "model.endpoint.unmount:{endpoint_id}",
  ]),
  controlRoute("lifecycle.endpoint.load", "lifecycle", "POST", "/v1/model-mount/endpoints/{endpoint_id}/load", [
    "model.endpoint.load:{endpoint_id}",
  ]),
  controlRoute("lifecycle.endpoint.unload", "lifecycle", "POST", "/v1/model-mount/endpoints/{endpoint_id}/unload", [
    "model.endpoint.unload:{endpoint_id}",
  ]),
  controlRoute("lifecycle.instance.load", "lifecycle", "POST", "/v1/model-mount/instances/load", [
    "model.instance.load",
  ]),
  controlRoute("lifecycle.instance.unload", "lifecycle", "POST", "/v1/model-mount/instances/unload", [
    "model.instance.unload",
  ]),
  controlRoute("lifecycle.instance.unload_by_id", "lifecycle", "POST", "/v1/model-mount/instances/{instance_id}/unload", [
    "model.instance.unload:{instance_id}",
  ]),
  controlRoute("storage.download.create", "storage", "POST", "/v1/model-mount/downloads", [
    "model.download.create",
  ]),
  controlRoute("storage.download.status", "storage", "GET", "/v1/model-mount/downloads/{download_id}/status", [
    "model.download.read:{download_id}",
  ]),
  controlRoute("storage.download.cancel", "storage", "POST", "/v1/model-mount/downloads/{download_id}/cancel", [
    "model.download.cancel:{download_id}",
  ]),
  controlRoute("storage.cleanup", "storage", "POST", "/v1/model-mount/storage/cleanup", [
    "model.storage.cleanup",
  ]),
  controlRoute("catalog_provider.get", "catalog_provider", "GET", "/v1/model-mount/catalog/providers/{provider_id}", [
    "catalog_provider.read:{provider_id}",
  ]),
  controlRoute("catalog_provider.configure", "catalog_provider", "PATCH", "/v1/model-mount/catalog/providers/{provider_id}", [
    "catalog_provider.control:{provider_id}",
  ]),
  controlRoute(
    "catalog_provider.oauth.start",
    "catalog_provider",
    "POST",
    "/v1/model-mount/catalog/providers/{provider_id}/oauth/start",
    ["catalog_provider.oauth:{provider_id}:start"],
  ),
  controlRoute(
    "catalog_provider.oauth.callback",
    "catalog_provider",
    "POST",
    "/v1/model-mount/catalog/providers/{provider_id}/oauth/callback",
    ["catalog_provider.oauth:{provider_id}:callback"],
  ),
  controlRoute(
    "catalog_provider.oauth.exchange",
    "catalog_provider",
    "POST",
    "/v1/model-mount/catalog/providers/{provider_id}/oauth/exchange",
    ["catalog_provider.oauth:{provider_id}:exchange"],
  ),
  controlRoute(
    "catalog_provider.oauth.refresh",
    "catalog_provider",
    "POST",
    "/v1/model-mount/catalog/providers/{provider_id}/oauth/refresh",
    ["catalog_provider.oauth:{provider_id}:refresh"],
  ),
  controlRoute(
    "catalog_provider.oauth.revoke",
    "catalog_provider",
    "POST",
    "/v1/model-mount/catalog/providers/{provider_id}/oauth/revoke",
    ["catalog_provider.oauth:{provider_id}:revoke"],
  ),
  controlRoute("token.list", "token", "GET", "/v1/model-mount/tokens", [
    "token.read:*",
  ]),
  controlRoute("token.create", "token", "POST", "/v1/model-mount/tokens", [
    "token.create",
  ]),
  controlRoute("token.count", "token", "POST", "/v1/model-mount/tokens/count", [
    "token.count",
  ]),
  controlRoute("token.revoke", "token", "DELETE", "/v1/model-mount/tokens/{token_id}", [
    "token.revoke:{token_id}",
  ]),
  controlRoute("vault.refs.list", "vault", "GET", "/v1/model-mount/vault/refs", [
    "vault.read:refs",
  ]),
  controlRoute("vault.ref.bind", "vault", "POST", "/v1/model-mount/vault/refs", [
    "vault.ref.bind",
  ]),
  controlRoute("vault.ref.remove", "vault", "DELETE", "/v1/model-mount/vault/refs", [
    "vault.ref.remove",
  ]),
  controlRoute("vault.ref.meta", "vault", "POST", "/v1/model-mount/vault/refs/meta", [
    "vault.ref.meta",
  ]),
  controlRoute("vault.status", "vault", "GET", "/v1/model-mount/vault/status", [
    "vault.read:status",
  ]),
  controlRoute("vault.health", "vault", "POST", "/v1/model-mount/vault/health", [
    "vault.health",
  ]),
  controlRoute("vault.health.latest", "vault", "GET", "/v1/model-mount/vault/health/latest", [
    "vault.read:health",
  ]),
  controlRoute("provider.upsert", "provider", "POST", "/v1/model-mount/providers", [
    "provider.write:*",
  ]),
  controlRoute("provider.update", "provider", "PATCH", "/v1/model-mount/providers/{provider_id}", [
    "provider.write:{provider_id}",
  ]),
  controlRoute("provider.health.latest", "provider", "GET", "/v1/model-mount/providers/{provider_id}/health/latest", [
    "provider.read:{provider_id}:health",
  ]),
  controlRoute("provider.health", "provider", "POST", "/v1/model-mount/providers/{provider_id}/health", [
    "provider.control:{provider_id}:health",
  ]),
  controlRoute("provider.models", "provider", "GET", "/v1/model-mount/providers/{provider_id}/models", [
    "provider.read:{provider_id}:models",
  ]),
  controlRoute("provider.loaded", "provider", "GET", "/v1/model-mount/providers/{provider_id}/loaded", [
    "provider.read:{provider_id}:loaded",
  ]),
  controlRoute("provider.start", "provider", "POST", "/v1/model-mount/providers/{provider_id}/start", [
    "provider.control:{provider_id}:start",
  ]),
  controlRoute("provider.stop", "provider", "POST", "/v1/model-mount/providers/{provider_id}/stop", [
    "provider.control:{provider_id}:stop",
  ]),
] as const satisfies readonly ModelMountWorkbenchControlRoute[];

export type ModelMountWorkbenchControlRouteId =
  (typeof MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES)[number]["id"];

export interface ModelMountWorkbenchControlRequestBody {
  schema_version: typeof WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION;
  source: typeof MODEL_MOUNT_WORKBENCH_CONTROL_SOURCE;
  actor: string;
  workflow_graph_id: string | null;
  workflow_node_id: string;
  component_kind: typeof MODEL_MOUNT_WORKBENCH_CONTROL_COMPONENT_KIND;
  payload_schema_version: typeof MODEL_MOUNT_WORKBENCH_CONTROL_PAYLOAD_SCHEMA_VERSION;
  control_route_id: ModelMountWorkbenchControlRouteId;
  control_family: ModelMountWorkbenchControlFamily;
  authority_scopes: string[];
  input: Record<string, unknown>;
}

export interface ModelMountWorkbenchControlRequest {
  schemaVersion: typeof WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION;
  nodeType: "model_mount_control";
  nodeId: string | null;
  routeId: ModelMountWorkbenchControlRouteId;
  family: ModelMountWorkbenchControlFamily;
  method: ModelMountWorkbenchControlMethod;
  endpoint: string;
  body: ModelMountWorkbenchControlRequestBody | null;
}

export interface ModelMountWorkbenchControlRequestInput {
  routeId: ModelMountWorkbenchControlRouteId;
  nodeId?: string | null;
  pathParams?: Record<string, unknown> | null;
  input?: Record<string, unknown> | null;
  workflowGraphId?: string | null;
  workflowNodeId?: string | null;
  actor?: string | null;
}

const MODEL_MOUNT_WORKBENCH_CONTROL_ROUTE_BY_ID = new Map<
  string,
  ModelMountWorkbenchControlRoute
>(MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES.map((route) => [route.id, route]));

export function modelMountWorkbenchControlRoute(
  routeId: ModelMountWorkbenchControlRouteId,
): ModelMountWorkbenchControlRoute {
  const route = MODEL_MOUNT_WORKBENCH_CONTROL_ROUTE_BY_ID.get(routeId);
  if (!route) {
    throw new Error(`Unknown model_mount Workbench control route: ${routeId}`);
  }
  return route;
}

export function modelMountWorkbenchControlRouteIdsByFamily(
  family: ModelMountWorkbenchControlFamily,
): ModelMountWorkbenchControlRouteId[] {
  return MODEL_MOUNT_WORKBENCH_CONTROL_ROUTES.filter((route) => route.family === family).map(
    (route) => route.id,
  );
}

export function createModelMountWorkbenchControlRequest(
  params: ModelMountWorkbenchControlRequestInput,
): ModelMountWorkbenchControlRequest {
  const route = modelMountWorkbenchControlRoute(params.routeId);
  const endpoint = renderModelMountWorkbenchControlEndpoint(
    params.routeId,
    params.pathParams ?? {},
  );
  const input = params.input ?? {};
  assertNoRetiredModelMountControlInputAliases(input);

  return {
    schemaVersion: WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION,
    nodeType: "model_mount_control",
    nodeId: params.nodeId ?? null,
    routeId: params.routeId,
    family: route.family,
    method: route.method,
    endpoint,
    body:
      route.method === "GET"
        ? null
        : {
            schema_version: WORKFLOW_MODEL_MOUNT_WORKBENCH_CONTROL_SCHEMA_VERSION,
            source: MODEL_MOUNT_WORKBENCH_CONTROL_SOURCE,
            actor: cleanString(params.actor) ?? "operator",
            workflow_graph_id: cleanString(params.workflowGraphId),
            workflow_node_id:
              cleanString(params.workflowNodeId) ??
              `model-mount.${params.routeId}`,
            component_kind: MODEL_MOUNT_WORKBENCH_CONTROL_COMPONENT_KIND,
            payload_schema_version: MODEL_MOUNT_WORKBENCH_CONTROL_PAYLOAD_SCHEMA_VERSION,
            control_route_id: params.routeId,
            control_family: route.family,
            authority_scopes: route.authorityScopes.map((scope) =>
              renderAuthorityScope(scope, params.pathParams ?? {}),
            ),
            input,
          },
  };
}

export function renderModelMountWorkbenchControlEndpoint(
  routeId: ModelMountWorkbenchControlRouteId,
  pathParams: Record<string, unknown> = {},
): string {
  const route = modelMountWorkbenchControlRoute(routeId);
  const usedParams = new Set<string>();
  const endpoint = route.path.replace(/\{([a-zA-Z0-9_]+)\}/g, (_match, key: string) => {
    usedParams.add(key);
    return encodeURIComponent(requiredPathParam(pathParams, key, routeId));
  });
  for (const key of Object.keys(pathParams)) {
    if (!usedParams.has(key)) {
      throw new Error(`Unused model_mount Workbench control path param '${key}' for ${routeId}.`);
    }
  }
  assertStableModelMountWorkbenchControlEndpoint(endpoint);
  return endpoint;
}

export function assertStableModelMountWorkbenchControlEndpoint(endpoint: string): void {
  if (!endpoint.startsWith("/v1/model-mount/")) {
    throw new Error(
      `Model_mount Workbench control routes must use stable /v1/model-mount protocol paths, received ${endpoint}.`,
    );
  }
  if (endpoint.includes("/api/v1/")) {
    throw new Error(
      `Model_mount Workbench control routes must not use retired /api/v1 paths, received ${endpoint}.`,
    );
  }
}

const RETIRED_MODEL_MOUNT_CONTROL_INPUT_ALIASES = new Set([
  "apiKey",
  "artifactId",
  "authHeaderName",
  "autoEvict",
  "backendId",
  "baseUrl",
  "contextLength",
  "downloadId",
  "endpointId",
  "engineId",
  "estimateOnly",
  "idleTtlSeconds",
  "instanceId",
  "loadOptions",
  "loadPolicy",
  "maxCostUsd",
  "modelId",
  "providerId",
  "routeId",
  "secretRef",
  "tokenId",
  "ttlSeconds",
  "vaultRef",
  "workflowGraphId",
  "workflowNodeId",
]);

function assertNoRetiredModelMountControlInputAliases(
  value: unknown,
  path = "input",
): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoRetiredModelMountControlInputAliases(entry, `${path}[${index}]`),
    );
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (RETIRED_MODEL_MOUNT_CONTROL_INPUT_ALIASES.has(key)) {
      throw new Error(
        `Retired model_mount Workbench control input alias '${key}' at ${path}.${key}; use canonical snake_case protocol fields.`,
      );
    }
    assertNoRetiredModelMountControlInputAliases(nested, `${path}.${key}`);
  }
}

function renderAuthorityScope(scope: string, pathParams: Record<string, unknown>): string {
  return scope.replace(/\{([a-zA-Z0-9_]+)\}/g, (_match, key: string) =>
    requiredPathParam(pathParams, key, scope),
  );
}

function requiredPathParam(
  pathParams: Record<string, unknown>,
  key: string,
  routeId: string,
): string {
  const value = pathParams[key];
  if (value === undefined || value === null || value === "") {
    throw new Error(`Model_mount Workbench control route '${routeId}' needs path param '${key}'.`);
  }
  return String(value);
}

function cleanString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim();
  return clean || null;
}
