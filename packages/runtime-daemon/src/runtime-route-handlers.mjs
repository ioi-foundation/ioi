import {
  createRun as createLifecycleRun,
} from "./runtime-agent-run-lifecycle.mjs";
import {
  deleteAgent as deleteLifecycleAgent,
  updateAgent as updateLifecycleAgent,
} from "./threads/thread-store.mjs";

export function createRuntimeRouteHandlers(deps) {
  const {
    approvalModeForThreadMode = null,
    baseUrlForRequest,
    buildRun = null,
    createLifecycleRun: createLifecycleRunDep = createLifecycleRun,
    deleteLifecycleAgent: deleteLifecycleAgentDep = deleteLifecycleAgent,
    ensureProviderAvailable = null,
    nativeEmbeddingResponse,
    nativeInvocationResponse,
    notFound,
    readBody,
    runtimeError = null,
    threadModeForRunMode = null,
    updateLifecycleAgent: updateLifecycleAgentDep = updateLifecycleAgent,
    writeJsonResponse,
    writeMcpJsonRpcResponse,
    writeSse,
  } = deps;
  const lifecycleRuntimeError = typeof runtimeError === "function" ? runtimeError : undefined;

  async function handleModelMountingNativeRoute({ request, response, store, url, segments }) {
    const mounts = store.modelMounting;
    const authorization = request.headers.authorization;
    const baseUrl = baseUrlForRequest(request);
    if (request.method === "GET" && url.pathname === "/api/v1/server/status") {
      writeJsonResponse(response, mounts.serverStatus(baseUrl));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/server/start") {
      mounts.authorize(authorization, "server.control:*");
      writeJsonResponse(response, mounts.serverStart(baseUrl));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/server/stop") {
      mounts.authorize(authorization, "server.control:*");
      writeJsonResponse(response, mounts.serverStop(baseUrl));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/server/restart") {
      mounts.authorize(authorization, "server.control:*");
      writeJsonResponse(response, mounts.serverRestart(baseUrl));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/server/logs") {
      mounts.authorize(authorization, "server.logs:*");
      writeJsonResponse(response, mounts.serverLogs(Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/server/events") {
      mounts.authorize(authorization, "server.logs:*");
      writeJsonResponse(response, mounts.serverEvents(Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/server") {
      writeJsonResponse(response, mounts.serverStatus(baseUrl));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/server/start") {
      mounts.authorize(authorization, "server.control:*");
      writeJsonResponse(response, mounts.serverStart(baseUrl));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/server/stop") {
      mounts.authorize(authorization, "server.control:*");
      writeJsonResponse(response, mounts.serverStop(baseUrl));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/backends") {
      writeJsonResponse(response, mounts.listBackends());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/backends") {
      writeJsonResponse(response, mounts.listBackends());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/runtime/engines") {
      writeJsonResponse(response, mounts.listRuntimeEngines());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/runtime-engines") {
      writeJsonResponse(response, mounts.listRuntimeEngines());
      return;
    }
    if (request.method === "GET" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
      writeJsonResponse(response, mounts.runtimeEngine(decodeURIComponent(segments[4])));
      return;
    }
    if (request.method === "POST" && segments[2] === "runtime" && segments[3] === "engines" && segments[4] && segments[5] === "select") {
      writeJsonResponse(response, mounts.selectRuntimeEngine({ engine_id: decodeURIComponent(segments[4]), ...(await readBody(request)) }));
      return;
    }
    if (request.method === "PATCH" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
      writeJsonResponse(response, mounts.updateRuntimeEngine(decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && segments[2] === "runtime" && segments[3] === "engines" && segments[4]) {
      writeJsonResponse(response, mounts.removeRuntimeEngineOverride(decodeURIComponent(segments[4])));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/runtime/survey") {
      writeJsonResponse(response, mounts.runtimeSurvey());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/runtime/select") {
      writeJsonResponse(response, mounts.selectRuntimeEngine(await readBody(request)));
      return;
    }
    if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "health") {
      writeJsonResponse(response, mounts.backendHealth(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "start") {
      mounts.authorize(authorization, `backend.control:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, mounts.startBackend(decodeURIComponent(segments[3]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && segments[2] === "backends" && segments[3] && segments[4] === "stop") {
      mounts.authorize(authorization, `backend.control:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, mounts.stopBackend(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && segments[2] === "backends" && segments[3] && segments[4] === "logs") {
      writeJsonResponse(response, mounts.backendLogs(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models") {
      writeJsonResponse(response, mounts.snapshot(baseUrl));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/authority") {
      writeJsonResponse(response, mounts.authoritySnapshot(baseUrl));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/model-capabilities") {
      writeJsonResponse(response, mounts.listModelCapabilities());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/catalog/search") {
      writeJsonResponse(response, await mounts.catalogSearch(Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/catalog/import-url") {
      mounts.authorize(authorization, "model.download:*");
      mounts.authorize(authorization, "model.import:*");
      writeJsonResponse(response, await mounts.catalogImportUrl(await readBody(request)), 202);
      return;
    }
    if (request.method === "GET" && segments[2] === "models" && segments[3] === "catalog" && segments[4] === "providers" && segments[5]) {
      writeJsonResponse(response, mounts.getCatalogProviderConfig(decodeURIComponent(segments[5])));
      return;
    }
    if (request.method === "PATCH" && segments[2] === "models" && segments[3] === "catalog" && segments[4] === "providers" && segments[5]) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      writeJsonResponse(response, mounts.configureCatalogProvider(providerId, await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "catalog" &&
      segments[4] === "providers" &&
      segments[5] &&
      segments[6] === "oauth" &&
      segments[7] === "start"
    ) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      mounts.authorize(authorization, "vault.write:*");
      writeJsonResponse(response, mounts.startCatalogProviderOAuth(providerId, await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "catalog" &&
      segments[4] === "providers" &&
      segments[5] &&
      segments[6] === "oauth" &&
      segments[7] === "callback"
    ) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      mounts.authorize(authorization, "vault.write:*");
      writeJsonResponse(response, await mounts.completeCatalogProviderOAuth(providerId, await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "catalog" &&
      segments[4] === "providers" &&
      segments[5] &&
      segments[6] === "oauth" &&
      segments[7] === "exchange"
    ) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      mounts.authorize(authorization, "vault.write:*");
      writeJsonResponse(response, await mounts.exchangeCatalogProviderOAuth(providerId, await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "catalog" &&
      segments[4] === "providers" &&
      segments[5] &&
      segments[6] === "oauth" &&
      segments[7] === "refresh"
    ) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      mounts.authorize(authorization, "vault.write:*");
      writeJsonResponse(response, await mounts.refreshCatalogProviderOAuth(providerId));
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "catalog" &&
      segments[4] === "providers" &&
      segments[5] &&
      segments[6] === "oauth" &&
      segments[7] === "revoke"
    ) {
      const providerId = decodeURIComponent(segments[5]);
      mounts.authorize(authorization, `provider.write:${providerId}`);
      mounts.authorize(authorization, "vault.delete:*");
      writeJsonResponse(response, mounts.revokeCatalogProviderOAuth(providerId));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/storage/cleanup") {
      mounts.authorize(authorization, "model.delete:*");
      writeJsonResponse(response, mounts.cleanupModelStorage(await readBody(request)));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/artifacts") {
      writeJsonResponse(response, mounts.listArtifacts());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/instances") {
      writeJsonResponse(response, mounts.listInstances());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/routes") {
      writeJsonResponse(response, mounts.listRoutes());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/events") {
      writeJsonResponse(response, mounts.projection().lifecycleEvents);
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/mounts") {
      mounts.authorize(authorization, "model.mount:*");
      writeJsonResponse(response, mounts.mountEndpoint(await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "mounts" &&
      segments[4] &&
      segments[5] === "load"
    ) {
      mounts.authorize(authorization, "model.load:*");
      writeJsonResponse(response, await mounts.loadModel({ ...(await readBody(request)), endpoint_id: decodeURIComponent(segments[4]) }), 201);
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "mounts" &&
      segments[4] &&
      segments[5] === "unload"
    ) {
      mounts.authorize(authorization, "model.unload:*");
      writeJsonResponse(response, await mounts.unloadModel({ ...(await readBody(request)), endpoint_id: decodeURIComponent(segments[4]) }));
      return;
    }
    if (
      request.method === "DELETE" &&
      segments[2] === "models" &&
      segments[3] === "mounts" &&
      segments[4] &&
      !segments[5]
    ) {
      mounts.authorize(authorization, "model.unmount:*");
      writeJsonResponse(response, mounts.unmountEndpoint({ endpoint_id: decodeURIComponent(segments[4]) }));
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "instances" &&
      segments[4] &&
      segments[5] === "unload"
    ) {
      mounts.authorize(authorization, "model.unload:*");
      writeJsonResponse(response, await mounts.unloadModel({ instance_id: decodeURIComponent(segments[4]), ...(await readBody(request)) }));
      return;
    }
    if (
      request.method === "GET" &&
      segments[2] === "models" &&
      segments[3] &&
      !["download", "loaded"].includes(segments[3])
    ) {
      writeJsonResponse(response, mounts.getModel(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "DELETE" && segments[2] === "models" && segments[3]) {
      mounts.authorize(authorization, "model.delete:*");
      writeJsonResponse(response, mounts.deleteModelArtifact(decodeURIComponent(segments[3]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/download") {
      mounts.authorize(authorization, "model.download:*");
      writeJsonResponse(response, await mounts.downloadModel(await readBody(request)), 202);
      return;
    }
    if (
      request.method === "GET" &&
      segments[2] === "models" &&
      segments[3] === "download" &&
      segments[4] === "status" &&
      segments[5]
    ) {
      writeJsonResponse(response, mounts.downloadStatus(decodeURIComponent(segments[5])));
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "download" &&
      segments[4] === "cancel" &&
      segments[5]
    ) {
      mounts.authorize(authorization, "model.download:*");
      writeJsonResponse(response, mounts.cancelDownload(decodeURIComponent(segments[5]), await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      segments[2] === "models" &&
      segments[3] === "download" &&
      segments[4] &&
      segments[5] === "cancel"
    ) {
      mounts.authorize(authorization, "model.download:*");
      writeJsonResponse(response, mounts.cancelDownload(decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/import") {
      mounts.authorize(authorization, "model.import:*");
      writeJsonResponse(response, mounts.importModel(await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/mount") {
      mounts.authorize(authorization, "model.mount:*");
      writeJsonResponse(response, mounts.mountEndpoint(await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/unmount") {
      mounts.authorize(authorization, "model.unmount:*");
      writeJsonResponse(response, mounts.unmountEndpoint(await readBody(request)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/load") {
      mounts.authorize(authorization, "model.load:*");
      writeJsonResponse(response, await mounts.loadModel(await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/models/unload") {
      mounts.authorize(authorization, "model.unload:*");
      writeJsonResponse(response, await mounts.unloadModel(await readBody(request)));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/models/loaded") {
      writeJsonResponse(response, mounts.listInstances().filter((instance) => instance.status === "loaded"));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/providers") {
      writeJsonResponse(response, mounts.listProviders());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/vault/refs") {
      mounts.authorize(authorization, "vault.read:*");
      writeJsonResponse(response, mounts.listVaultRefs());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/vault/status") {
      mounts.authorize(authorization, "vault.read:*");
      writeJsonResponse(response, mounts.vaultStatus());
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/vault/health/latest") {
      mounts.authorize(authorization, "vault.read:*");
      writeJsonResponse(response, mounts.latestVaultHealth());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/vault/health") {
      mounts.authorize(authorization, "vault.read:*");
      writeJsonResponse(response, mounts.vaultHealth());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/vault/refs") {
      mounts.authorize(authorization, "vault.write:*");
      writeJsonResponse(response, mounts.bindVaultRef(await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/vault/refs/meta") {
      mounts.authorize(authorization, "vault.read:*");
      writeJsonResponse(response, mounts.vaultRefMetadata(await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && url.pathname === "/api/v1/vault/refs") {
      mounts.authorize(authorization, "vault.delete:*");
      writeJsonResponse(response, mounts.removeVaultRef(await readBody(request)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/providers") {
      mounts.authorize(authorization, "provider.write:*");
      writeJsonResponse(response, mounts.upsertProvider(await readBody(request)), 201);
      return;
    }
    if (request.method === "PATCH" && segments[2] === "providers" && segments[3]) {
      mounts.authorize(authorization, `provider.write:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, mounts.upsertProvider({ ...(await readBody(request)), id: decodeURIComponent(segments[3]) }));
      return;
    }
    if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "health" && segments[5] === "latest") {
      writeJsonResponse(response, mounts.latestProviderHealth(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "health") {
      writeJsonResponse(response, await mounts.providerHealth(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "models") {
      writeJsonResponse(response, await mounts.listProviderModels(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && segments[2] === "providers" && segments[3] && segments[4] === "loaded") {
      writeJsonResponse(response, await mounts.listProviderLoaded(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "start") {
      mounts.authorize(authorization, `provider.control:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, await mounts.startProvider(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "POST" && segments[2] === "providers" && segments[3] && segments[4] === "stop") {
      mounts.authorize(authorization, `provider.control:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, await mounts.stopProvider(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/routes") {
      writeJsonResponse(response, mounts.listRoutes());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/routes") {
      mounts.authorize(authorization, "route.write:*");
      writeJsonResponse(response, mounts.upsertRoute(await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && segments[2] === "routes" && segments[3] && segments[4] === "test") {
      mounts.authorize(authorization, `route.use:${decodeURIComponent(segments[3])}`);
      writeJsonResponse(response, mounts.testRoute(decodeURIComponent(segments[3]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/chat") {
      const invocation = await mounts.invokeModel({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat",
        body: await readBody(request),
      });
      writeJsonResponse(response, nativeInvocationResponse(invocation));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/responses") {
      const invocation = await mounts.invokeModel({
        authorization,
        requiredScope: "model.responses:*",
        kind: "responses",
        body: await readBody(request),
      });
      writeJsonResponse(response, nativeInvocationResponse(invocation));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/embeddings") {
      const body = await readBody(request);
      const invocation = await mounts.invokeModel({
        authorization,
        requiredScope: "model.embeddings:*",
        kind: "embeddings",
        body,
      });
      writeJsonResponse(response, nativeEmbeddingResponse(invocation, body));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/rerank") {
      const invocation = await mounts.invokeModel({
        authorization,
        requiredScope: "model.rerank:*",
        kind: "rerank",
        body: await readBody(request),
      });
      writeJsonResponse(response, nativeInvocationResponse(invocation));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/tokenize") {
      writeJsonResponse(
        response,
        mounts.tokenizeModel({
          authorization,
          requiredScope: "model.tokenize:*",
          body: await readBody(request),
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/tokens/count") {
      writeJsonResponse(
        response,
        mounts.countModelTokens({
          authorization,
          requiredScope: "model.tokenize:*",
          body: await readBody(request),
        }),
      );
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/context/fit") {
      writeJsonResponse(
        response,
        mounts.fitModelContext({
          authorization,
          requiredScope: "model.context:*",
          body: await readBody(request),
        }),
      );
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/tokens") {
      writeJsonResponse(response, mounts.listTokens());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/tokens") {
      writeJsonResponse(response, mounts.createToken(await readBody(request)), 201);
      return;
    }
    if (request.method === "DELETE" && segments[2] === "tokens" && segments[3]) {
      writeJsonResponse(response, mounts.revokeToken(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/receipts") {
      writeJsonResponse(response, mounts.listReceipts());
      return;
    }
    if (request.method === "GET" && segments[2] === "receipts" && segments[3] && segments[4] === "replay") {
      writeJsonResponse(response, mounts.receiptReplay(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && segments[2] === "receipts" && segments[3]) {
      writeJsonResponse(response, mounts.getReceipt(decodeURIComponent(segments[3])));
      return;
    }
    if (request.method === "GET" && url.pathname === "/api/v1/projections/model-mounting") {
      writeJsonResponse(response, mounts.projection());
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/workflows/nodes/execute") {
      writeJsonResponse(response, await mounts.executeWorkflowNode({ authorization, body: await readBody(request) }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/api/v1/workflows/receipt-gate") {
      writeJsonResponse(response, mounts.validateReceiptGate(await readBody(request)));
      return;
    }
    throw notFound("Model mounting route not found.", {
      method: request.method,
      path: url.pathname,
    });
  }

  async function handleAgentRoute({ request, response, store, url, segments }) {
    const agentId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getAgent(store, agentId));
      return;
    }
    if (request.method === "DELETE" && !action) {
      writeJsonResponse(response, deleteLifecycleAgentDep(store, agentId, {
        deleteStateUpdateRunner: store.contextPolicyCore,
        runtimeError: lifecycleRuntimeError,
      }), 204);
      return;
    }
    if (request.method === "POST" && action === "archive") {
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "archived", "agent.archive", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: store.contextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "unarchive") {
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "active", "agent.unarchive", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: store.contextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "resume") {
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "active", "agent.resume", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: store.contextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "close") {
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, "closed", "agent.close", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: store.contextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "reload") {
      writeJsonResponse(response, updateLifecycleAgentDep(store, agentId, null, "agent.reload", {
        runtimeError: lifecycleRuntimeError,
        statusStateUpdateRunner: store.contextPolicyCore,
      }));
      return;
    }
    if (request.method === "POST" && action === "runs") {
      writeJsonResponse(response, createLifecycleRunDep(store, agentId, await readBody(request), {
        approvalModeForThreadMode,
        buildRun,
        ensureProviderAvailable,
        lifecycleAdmissionRunner: store.contextPolicyCore,
        runtimeError: lifecycleRuntimeError,
        threadModeForRunMode,
      }));
      return;
    }
    if (request.method === "GET" && action === "runs") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listRuns(store, agentId));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPolicyForAgent(store, agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.setMemoryPolicyForAgent(store, agentId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPathForAgent(store, agentId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.updateMemoryForAgentId(store, agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.deleteMemoryForAgentId(store, agentId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.publicListMemoryForAgent(store, agentId, Object.fromEntries(new URL(request.url ?? "/", "http://127.0.0.1").searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.rememberForAgentId(store, agentId, await readBody(request)));
      return;
    }
    throw notFound("Agent route not found.", { agentId, action, method: request.method });
  }

  async function handleThreadRoute({ request, response, store, url, segments }) {
    const threadId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getThread(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getThreadUsage(store, threadId));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateContextBudget(store, { threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.conversationArtifactSurface.listConversationArtifacts(store, { thread_id: threadId }));
      return;
    }
    if (request.method === "POST" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(
        response,
        store.conversationArtifactSurface.createConversationArtifact(store, threadId, await readBody(request)),
        201,
      );
      return;
    }
    if (request.method === "POST" && action === "compaction-policy" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateCompactionPolicy(store, { threadId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "resume") {
      writeJsonResponse(response, await store.threadTurnSurface.resumeThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "fork") {
      writeJsonResponse(response, await store.threadAuxiliarySurface.forkThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "compact") {
      writeJsonResponse(response, store.contextPolicySurface.compactThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mode" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadMode(store, threadId, await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      action === "workspace-trust" &&
      segments[4] &&
      segments[5] === "acknowledge" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        store.threadControlSurface.acknowledgeWorkspaceTrustWarning(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "model" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadModel(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "thinking" && !segments[4]) {
      writeJsonResponse(response, store.threadControlSurface.updateThreadThinking(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "managed-sessions" && !segments[4]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.inspectManagedSessionsForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "GET" && action === "workspace-change-reviews" && !segments[4]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.inspectWorkspaceChangeReviewsForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "managed-sessions" && segments[4] === "control" && !segments[5]) {
      writeJsonResponse(response, await store.threadAuxiliarySurface.controlManagedSessionForThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.subagentSurface.listSubagents(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "subagents" && !segments[4]) {
      writeJsonResponse(response, store.subagentSurface.spawnSubagent(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] === "cancel" && !segments[5]) {
      writeJsonResponse(response, store.subagentSurface.propagateSubagentCancellation(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "wait" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.waitSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "input" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.sendSubagentInput(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "cancel" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.cancelSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "resume" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.resumeSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "subagents" && segments[4] && segments[5] === "assign" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.assignSubagent(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "subagents" && segments[4] && segments[5] === "result" && !segments[6]) {
      writeJsonResponse(response, store.subagentSurface.getSubagentResult(store, threadId, decodeURIComponent(segments[4])));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "import" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.importThreadMcp(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "servers" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.addThreadMcpServer(store, threadId, await readBody(request)), 201);
      return;
    }
    if (
      (request.method === "DELETE" || request.method === "POST") &&
      action === "mcp" &&
      segments[4] === "servers" &&
      segments[5] &&
      (request.method === "DELETE" ? !segments[6] : segments[6] === "remove" && !segments[7])
    ) {
      writeJsonResponse(
        response,
        store.mcpControlSurface.removeThreadMcpServer(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (
      request.method === "POST" &&
      action === "mcp" &&
      segments[4] === "servers" &&
      segments[5] &&
      (segments[6] === "enable" || segments[6] === "disable") &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        store.mcpControlSurface.setThreadMcpServerEnabled(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          segments[6] === "enable",
          await readBody(request),
        ),
      );
      return;
    }
    if (
      request.method === "GET" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] === "search" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        await store.mcpCatalogSurface.searchThreadMcpTools(store, threadId, {
          ...Object.fromEntries(url.searchParams.entries()),
          source: "sdk_client",
        }),
      );
      return;
    }
    if (
      request.method === "GET" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        await store.mcpCatalogSurface.getThreadMcpTool(store, threadId, decodeURIComponent(segments[5]), {
          ...Object.fromEntries(url.searchParams.entries()),
          source: "sdk_client",
        }),
      );
      return;
    }
    if (
      request.method === "POST" &&
      action === "mcp" &&
      segments[4] === "tools" &&
      segments[5] &&
      segments[6] === "invoke" &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        await store.mcpControlSurface.invokeThreadMcpTool(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "invoke" && !segments[5]) {
      writeJsonResponse(response, await store.mcpControlSurface.invokeThreadMcpTool(store, threadId, null, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      writeJsonResponse(response, store.mcpServeSurface.mcpServeStatus(store, {
        ...Object.fromEntries(url.searchParams.entries()),
        thread_id: threadId,
      }));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "serve" && !segments[5]) {
      writeMcpJsonRpcResponse(
        response,
        await store.mcpServeSurface.handleMcpServeJsonRpc(store, threadId, await readBody(request), {
          ...Object.fromEntries(url.searchParams.entries()),
          thread_id: threadId,
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "mcp" && (!segments[4] || segments[4] === "status") && !segments[5]) {
      writeJsonResponse(response, await store.mcpControlSurface.recordThreadMcpStatus(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "mcp" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.mcpControlSurface.validateThreadMcp(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "status" && !segments[5]) {
      writeJsonResponse(response, store.threadMemorySurface.recordThreadMemoryStatus(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "memory" && segments[4] === "validate" && !segments[5]) {
      writeJsonResponse(response, store.threadMemorySurface.validateThreadMemory(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, await store.threadTurnSurface.createTurn(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "interrupt" && !segments[6]) {
      writeJsonResponse(response, await store.threadTurnSurface.interruptTurn(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "turns" && segments[4] && segments[5] === "steer" && !segments[6]) {
      writeJsonResponse(response, store.threadTurnSurface.steerTurn(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.approvalSurface.listThreadApprovals(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "approvals" && !segments[4]) {
      writeJsonResponse(response, store.approvalSurface.requestThreadApproval(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "decision" && !segments[6]) {
      writeJsonResponse(
        response,
        store.approvalSurface.decideThreadApproval(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && ["approve", "reject"].includes(segments[5]) && !segments[6]) {
      const body = await readBody(request);
      writeJsonResponse(
        response,
        store.approvalSurface.decideThreadApproval(store, threadId, decodeURIComponent(segments[4]), {
          ...body,
          decision: segments[5],
        }),
      );
      return;
    }
    if (request.method === "POST" && action === "approvals" && segments[4] && segments[5] === "revoke" && !segments[6]) {
      writeJsonResponse(
        response,
        store.approvalSurface.revokeThreadApproval(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "workflow-edit-proposals" && !segments[4]) {
      writeJsonResponse(response, store.workflowEditSurface.proposeWorkflowEdit(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "POST" && action === "governed-improvement-proposals" && !segments[4]) {
      writeJsonResponse(response, store.governedImprovementSurface.admitGovernedImprovementProposal(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "external-capability-exits" && !segments[4]) {
      writeJsonResponse(response, store.externalCapabilityAuthoritySurface.authorizeExternalCapabilityExit(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "worker-service-package-invocations" && !segments[4]) {
      writeJsonResponse(response, store.workerServicePackageSurface.admitWorkerServicePackageInvocation(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "ctee-private-workspace-actions" && !segments[4]) {
      writeJsonResponse(response, store.cteePrivateWorkspaceSurface.executeCteePrivateWorkspaceAction(store, threadId, await readBody(request)), 201);
      return;
    }
    if (request.method === "POST" && action === "l1-settlement-attempts" && !segments[4]) {
      writeJsonResponse(response, store.l1SettlementSurface.admitL1SettlementAttempt(store, threadId, await readBody(request)), 201);
      return;
    }
    if (
      request.method === "POST" &&
      action === "workflow-edit-proposals" &&
      segments[4] &&
      segments[5] === "apply" &&
      !segments[6]
    ) {
      writeJsonResponse(
        response,
        store.workflowEditSurface.applyWorkflowEditProposal(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "tools" && segments[4] && segments[5] === "invoke" && !segments[6]) {
      writeJsonResponse(response, await store.codingToolInvocationSurface.invokeThreadTool(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (
      request.method === "POST" &&
      action === "diagnostics" &&
      segments[4] === "repair-decisions" &&
      segments[5] &&
      segments[6] === "execute" &&
      !segments[7]
    ) {
      writeJsonResponse(
        response,
        store.diagnosticsRepairSurface.executeDiagnosticsRepairDecision(
          store,
          threadId,
          decodeURIComponent(segments[5]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "GET" && action === "snapshots" && !segments[4]) {
      writeJsonResponse(response, store.workspaceSnapshotSurface.listWorkspaceSnapshots(store, threadId));
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-preview" && !segments[6]) {
      writeJsonResponse(
        response,
        store.workspaceSnapshotSurface.previewWorkspaceSnapshotRestore(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "POST" && action === "snapshots" && segments[4] && segments[5] === "restore-apply" && !segments[6]) {
      writeJsonResponse(
        response,
        store.workspaceSnapshotSurface.applyWorkspaceSnapshotRestore(
          store,
          threadId,
          decodeURIComponent(segments[4]),
          await readBody(request),
        ),
      );
      return;
    }
    if (request.method === "GET" && action === "turns" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listThreadTurns(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "turns" && segments[4] && !segments[5]) {
      writeJsonResponse(
        response,
        store.lifecycleProjectionSurface.getThreadTurn(store, threadId, decodeURIComponent(segments[4])),
      );
      return;
    }
    if (request.method === "GET" && action === "events" && (!segments[4] || segments[4] === "stream")) {
      writeSse(response, store.lifecycleProjectionSurface.listThreadEvents(store, threadId));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPolicyForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PUT" || request.method === "PATCH") && action === "memory" && segments[4] === "policy") {
      writeJsonResponse(response, store.threadMemorySurface.setMemoryPolicyForThread(store, threadId, await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory" && segments[4] === "path") {
      writeJsonResponse(response, store.threadMemorySurface.publicMemoryPathForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if ((request.method === "PATCH" || request.method === "PUT") && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.updateMemoryForThread(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "DELETE" && action === "memory" && segments[4]) {
      writeJsonResponse(response, store.threadMemorySurface.deleteMemoryForThread(store, threadId, decodeURIComponent(segments[4]), await readBody(request)));
      return;
    }
    if (request.method === "GET" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.publicListMemoryForThread(store, threadId, Object.fromEntries(url.searchParams.entries())));
      return;
    }
    if (request.method === "POST" && action === "memory") {
      writeJsonResponse(response, store.threadMemorySurface.rememberForThread(store, threadId, await readBody(request)));
      return;
    }
    throw notFound("Thread route not found.", { threadId, action, method: request.method });
  }

  async function handleRunRoute({ request, response, store, url, segments }) {
    const runId = decodeURIComponent(segments[2]);
    const action = segments[3];
    if (request.method === "GET" && !action) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "usage" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunUsage(store, runId));
      return;
    }
    if (request.method === "POST" && action === "context-budget" && !segments[4]) {
      writeJsonResponse(
        response,
        store.contextPolicySurface.evaluateContextBudget(store, { runId, request: await readBody(request) }),
      );
      return;
    }
    if (request.method === "POST" && action === "coding-tool-budget-recovery" && !segments[4]) {
      writeJsonResponse(
        response,
        store.codingToolBudgetRecoverySurface.codingToolBudgetRecoveryForRun(store, runId, await readBody(request)),
      );
      return;
    }
    if (request.method === "POST" && action === "cancel") {
      writeJsonResponse(response, store.threadAuxiliarySurface.cancelRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "wait") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.waitRun(store, runId));
      return;
    }
    if (request.method === "GET" && action === "conversation") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunConversation(store, runId));
      return;
    }
    if (request.method === "GET" && action === "events") {
      writeSse(
        response,
        store.lifecycleProjectionSurface.listRunEvents(store, runId),
      );
      return;
    }
    if (request.method === "GET" && action === "replay") {
      writeSse(
        response,
        store.lifecycleProjectionSurface.replayRun(store, runId),
      );
      return;
    }
    if (request.method === "GET" && (action === "trace" || action === "inspect")) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunTrace(store, runId));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trace" && !segments[5]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunComputerUseTrace(store, runId));
      return;
    }
    if (request.method === "GET" && action === "computer-use" && segments[4] === "trajectory" && !segments[5]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunComputerUseTrajectory(store, runId));
      return;
    }
    if (request.method === "GET" && action === "scorecard") {
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunScorecard(store, runId));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && !segments[4]) {
      writeJsonResponse(response, store.lifecycleProjectionSurface.listRunArtifacts(store, runId));
      return;
    }
    if (request.method === "GET" && action === "artifacts" && segments[4]) {
      const artifactRef = decodeURIComponent(segments[4]);
      writeJsonResponse(response, store.lifecycleProjectionSurface.getRunArtifact(store, runId, artifactRef));
      return;
    }
    throw notFound("Run route not found.", { runId, action, method: request.method });
  }

  return {
    handleAgentRoute,
    handleModelMountingNativeRoute,
    handleRunRoute,
    handleThreadRoute,
  };
}
