import crypto from "node:crypto";

import {
  createAgent as createLifecycleAgent,
  createThread as createLifecycleThread,
} from "../runtime-agent-run-lifecycle.mjs";

export function createPublicRuntimeRequestHandler(deps) {
  const {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    baseUrlForRequest,
    createLifecycleAgent: createLifecycleAgentDep = createLifecycleAgent,
    createLifecycleThread: createLifecycleThreadDep = createLifecycleThread,
    ensureProviderAvailable = null,
    eventStreamIdForThread = null,
    handleAgentRoute,
    handleModelMountingNativeRoute,
    handleOpenAiCompatibilityRoute,
    handleRunRoute,
    handleThreadRoute,
    initialThreadRuntimeControls = null,
    isOpenAiCompatibilityRoute,
    mcpRegistryForWorkspace = null,
    normalizeBooleanOption,
    notFound,
    optionalString,
    readBody,
    runtimeError = null,
    runtimeModeForOptions = null,
    runtimeThreadSchemaVersion = null,
    summarizeAgentOptions = null,
    threadIdForAgent = null,
    threadStatusForAgent = null,
    usageRequestMetadataFromUrl,
    usageTelemetryWithRequestMetadata,
    writeError,
    writeJsonResponse,
    writeMcpJsonRpcResponse,
  } = deps;
  const lifecycleRuntimeError = typeof runtimeError === "function" ? runtimeError : undefined;
  function requiredPublicRuntimeContextPolicyCore(contextPolicyCore, rustCoreBoundary) {
    if (contextPolicyCore) {
      return contextPolicyCore;
    }
    const error = {
      status: 501,
      code: "runtime_route_context_policy_core_required",
      message: "Public runtime routes require the explicit Rust daemon-core policy boundary.",
      details: {
        rust_core_boundary: rustCoreBoundary,
        retired_store_fallback: "context_policy_core_store_mount",
      },
    };
    throw lifecycleRuntimeError ? lifecycleRuntimeError(error) : Object.assign(new Error(error.message), error);
  }

  return async function handleRequest({ request, response, store, contextPolicyCore = null }) {
    const requestId = `req_${crypto.randomUUID()}`;
    response.setHeader("x-request-id", requestId);
    response.setHeader("access-control-allow-origin", "*");
    response.setHeader("access-control-allow-headers", "authorization,content-type,last-event-id,x-api-key");
    response.setHeader("access-control-allow-methods", "GET,POST,PATCH,DELETE,OPTIONS");
    if (request.method === "OPTIONS") {
      response.statusCode = 204;
      response.end();
      return;
    }

    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const segments = url.pathname.split("/").filter(Boolean);
    try {
      if (segments[0] === "api" && segments[1] === "v1") {
        await handleModelMountingNativeRoute({ request, response, store, url, segments });
        return;
      }
      if (segments[0] === "v1" && isOpenAiCompatibilityRoute(request, url)) {
        await handleOpenAiCompatibilityRoute({ request, response, store, url });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/doctor") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.doctor_report.projection",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectRuntimeDoctorReport({
            operation: "runtime_doctor_report_projection",
            operation_kind: "runtime.doctor_report.projection",
            base_url: baseUrlForRequest(request),
            workspace_root: store.defaultCwd,
            state_dir: store.stateDir,
            home_dir: store.homeDir,
            runtime_schema_version: store.schemaVersion,
            source: "public_runtime_routes./v1/doctor",
          }).report,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/browser-discovery") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.computer_use.projection.browser_discovery",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectRuntimeComputerUse({
            operation: "runtime_computer_use_projection",
            operation_kind: "runtime.computer_use.projection.browser_discovery",
            projection_kind: "browser_discovery",
            workspace_root: store.defaultCwd,
            state_dir: store.stateDir,
            include_cdp_probe: normalizeBooleanOption(url.searchParams.get("probe"), true),
            include_tab_metadata: normalizeBooleanOption(url.searchParams.get("include_tabs"), false),
            reveal_tab_titles: normalizeBooleanOption(url.searchParams.get("reveal_tab_titles"), false),
            source: "public_runtime_routes./v1/computer-use/browser-discovery",
          }).browser_discovery,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/providers") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.computer_use.projection.provider_registry",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectRuntimeComputerUse({
            operation: "runtime_computer_use_projection",
            operation_kind: "runtime.computer_use.projection.provider_registry",
            projection_kind: "provider_registry",
            workspace_root: store.defaultCwd,
            state_dir: store.stateDir,
            source: "public_runtime_routes./v1/computer-use/providers",
          }).provider_registry,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/skills") {
        writeJsonResponse(response, store.skillHookSurface.listSkills({ cwd: store.defaultCwd }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hooks") {
        writeJsonResponse(response, store.skillHookSurface.listHooks({ cwd: store.defaultCwd }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/repository-context") {
        writeJsonResponse(response, store.repositorySurface.repositoryContext(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/branch-policy") {
        writeJsonResponse(response, store.repositorySurface.branchPolicy(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/github-context") {
        writeJsonResponse(response, store.repositorySurface.githubContext(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/pr-attempts") {
        writeJsonResponse(response, store.repositorySurface.prAttempts(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/issue-context") {
        writeJsonResponse(response, store.repositorySurface.issueContext(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/review-gate") {
        writeJsonResponse(response, store.repositorySurface.reviewGate(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/github/pr-create-plan") {
        writeJsonResponse(response, store.repositorySurface.githubPrCreatePlan(store));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/agents") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.agent_create",
        );
        writeJsonResponse(response, createLifecycleAgentDep(store, (await readBody(request)).options ?? {}, {
          ensureProviderAvailable,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: routeContextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForContextPolicyCore(routeContextPolicyCore),
          runtimeError: lifecycleRuntimeError,
          runtimeModeForOptions,
          summarizeAgentOptions,
        }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/agents") {
        writeJsonResponse(response, store.lifecycleProjectionSurface.listAgents(store));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/threads") {
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "runtime.thread_create",
        );
        writeJsonResponse(response, await createLifecycleThreadDep(store, await readBody(request), {
          ensureProviderAvailable,
          eventStreamIdForThread,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: routeContextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForContextPolicyCore(routeContextPolicyCore),
          runtimeError: lifecycleRuntimeError,
          runtimeThreadSchemaVersion,
          runtimeModeForOptions,
          summarizeAgentOptions,
          threadIdForAgent,
          threadStatusForAgent,
        }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/threads") {
        writeJsonResponse(response, store.lifecycleProjectionSurface.listThreads(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/usage") {
        writeJsonResponse(
          response,
          usageTelemetryWithRequestMetadata(
            store.lifecycleProjectionSurface.listUsage(store, Object.fromEntries(url.searchParams.entries())),
            usageRequestMetadataFromUrl(url, {
              runtimeUsageTelemetrySchemaVersion: RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
            }),
          ),
        );
        return;
      }
      if (
        request.method === "GET" &&
        (url.pathname === "/v1/authority-evidence" ||
          url.pathname === "/v1/workflow-capability-preflights")
      ) {
        writeJsonResponse(
          response,
          store.lifecycleProjectionSurface.authorityEvidenceSummary(store, Object.fromEntries(url.searchParams.entries())),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/context-budget") {
        writeJsonResponse(
          response,
          store.contextPolicySurface.evaluateContextBudget(store, { request: await readBody(request) }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/studio/intent-frame") {
        const body = await readBody(request);
        const routeContextPolicyCore = requiredPublicRuntimeContextPolicyCore(
          contextPolicyCore,
          "studio.intent_frame.projection",
        );
        writeJsonResponse(
          response,
          routeContextPolicyCore.projectStudioIntentFrame({
            operation: "studio_intent_frame_projection",
            operation_kind: "studio.intent_frame.projection",
            prompt: body.prompt,
            input: body.input,
            query: body.query,
            execution_mode: body.execution_mode,
            source: "public_runtime_routes./v1/studio/intent-frame",
          }).frame,
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/conversation-artifacts") {
        writeJsonResponse(
          response,
          store.conversationArtifactSurface.listConversationArtifacts(store, Object.fromEntries(url.searchParams.entries())),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/conversation-artifacts") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          store.conversationArtifactSurface.createConversationArtifact(
            store,
            optionalString(body.thread_id) ?? "thread_standalone",
            body,
          ),
          201,
        );
        return;
      }
      if (segments[0] === "v1" && segments[1] === "conversation-artifacts" && segments[2]) {
        const artifactId = decodeURIComponent(segments[2]);
        if (request.method === "GET" && !segments[3]) {
          writeJsonResponse(response, store.conversationArtifactSurface.getConversationArtifact(store, artifactId));
          return;
        }
        if (request.method === "GET" && segments[3] === "revisions" && !segments[4]) {
          writeJsonResponse(
            response,
            store.conversationArtifactSurface.listConversationArtifactRevisions(store, artifactId),
          );
          return;
        }
        if (request.method === "POST" && segments[3] === "actions" && !segments[4]) {
          writeJsonResponse(
            response,
            store.conversationArtifactSurface.performConversationArtifactAction(store, artifactId, await readBody(request)),
          );
          return;
        }
        if (request.method === "POST" && segments[3] === "export" && !segments[4]) {
          writeJsonResponse(
            response,
            store.conversationArtifactSurface.exportConversationArtifact(store, artifactId, await readBody(request)),
          );
          return;
        }
        if (request.method === "POST" && segments[3] === "promote" && !segments[4]) {
          writeJsonResponse(
            response,
            store.conversationArtifactSurface.promoteConversationArtifact(store, artifactId, await readBody(request)),
          );
          return;
        }
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "threads" &&
        segments[2] &&
        segments[3] === "mcp" &&
        segments[4] === "serve" &&
        !segments[5]
      ) {
        const threadId = decodeURIComponent(segments[2]);
        assertNoMcpServeQueryContext(url);
        if (request.method === "GET") {
          writeJsonResponse(response, store.mcpServeSurface.mcpServeStatus(store, { thread_id: threadId }));
          return;
        }
        if (request.method === "POST") {
          const { message, context } = mcpServeProtocolParts(await readBody(request));
          writeMcpJsonRpcResponse(
            response,
            await store.mcpServeSurface.handleMcpServeJsonRpc(store, threadId, message, { ...context, thread_id: threadId }),
          );
          return;
        }
      }
      if (segments[0] === "v1" && segments[1] === "threads" && segments[2]) {
        await handleThreadRoute({ request, response, store, url, segments });
        return;
      }
      if (segments[0] === "v1" && segments[1] === "agents" && segments[2]) {
        await handleAgentRoute({ request, response, store, url, segments, contextPolicyCore });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/runs") {
        writeJsonResponse(response, store.lifecycleProjectionSurface.listRuns(store, url.searchParams.get("agent_id") ?? undefined));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, store.taskJobSurface.createTask(store, await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, store.taskJobSurface.listTasks(store, Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.taskJobSurface.cancelTask(store, decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && !segments[3] && request.method === "GET") {
        writeJsonResponse(response, store.taskJobSurface.getTask(store, decodeURIComponent(segments[2])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/jobs") {
        writeJsonResponse(response, store.taskJobSurface.listJobs(store, Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.taskJobSurface.cancelJob(store, decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2]) {
        writeJsonResponse(response, store.taskJobSurface.getJob(store, decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "runs" && segments[2]) {
        await handleRunRoute({ request, response, store, url, segments });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models") {
        writeJsonResponse(response, store.modelMounting.runtimeModelCatalogList());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/artifacts") {
        writeJsonResponse(response, store.modelMounting.listArtifacts());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/endpoints") {
        writeJsonResponse(response, store.modelMounting.listEndpoints());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/providers") {
        writeJsonResponse(response, store.modelMounting.listProviders());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/routes") {
        writeJsonResponse(response, store.modelMounting.listRoutes());
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "models" &&
        segments[2] &&
        !segments[3] &&
        !["artifacts", "catalog", "endpoints", "providers", "routes"].includes(segments[2])
      ) {
        writeJsonResponse(response, store.modelMounting.getModel(decodeURIComponent(segments[2])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/snapshot") {
        writeJsonResponse(response, store.modelMounting.snapshot(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/projection") {
        writeJsonResponse(response, store.modelMounting.projection());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/mcp") {
        writeJsonResponse(response, store.modelMounting.listMcpServers());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/mcp/import") {
        writeJsonResponse(response, await store.modelMounting.importMcpJson(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/mcp/invoke") {
        writeJsonResponse(
          response,
          await store.modelMounting.invokeMcpTool({
            authorization: request.headers.authorization,
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/workflows/nodes/execute") {
        writeJsonResponse(
          response,
          await store.modelMounting.executeWorkflowNode({
            authorization: request.headers.authorization,
            body: await readBody(request),
          }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/workflows/receipt-gate") {
        writeJsonResponse(response, store.modelMounting.validateReceiptGate(await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/routes") {
        store.modelMounting.authorize(request.headers.authorization, "route.write:*");
        writeJsonResponse(response, store.modelMounting.upsertRoute(await readBody(request)), 201);
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "routes" &&
        segments[3] &&
        segments[4] === "test"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `route.use:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.testRoute(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models/catalog/search") {
        writeJsonResponse(response, await store.modelMounting.catalogSearch(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "catalog" &&
        segments[3] === "providers" &&
        segments[4]
      ) {
        const providerId = decodeURIComponent(segments[4]);
        if (request.method === "GET" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.getCatalogProviderConfig(providerId));
          return;
        }
        if (request.method === "PATCH" && !segments[5]) {
          store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
          writeJsonResponse(response, store.modelMounting.configureCatalogProvider(providerId, await readBody(request)));
          return;
        }
        if (segments[5] === "oauth" && segments[6]) {
          if (request.method === "POST" && segments[6] === "start") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, store.modelMounting.startCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "callback") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.completeCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "exchange") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.exchangeCatalogProviderOAuth(providerId, await readBody(request)), 201);
            return;
          }
          if (request.method === "POST" && segments[6] === "refresh") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
            writeJsonResponse(response, await store.modelMounting.refreshCatalogProviderOAuth(providerId));
            return;
          }
          if (request.method === "POST" && segments[6] === "revoke") {
            store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
            store.modelMounting.authorize(request.headers.authorization, "vault.delete:*");
            writeJsonResponse(response, store.modelMounting.revokeCatalogProviderOAuth(providerId));
            return;
          }
        }
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/catalog/import-url") {
        store.modelMounting.authorize(request.headers.authorization, "model.download:*");
        store.modelMounting.authorize(request.headers.authorization, "model.import:*");
        writeJsonResponse(response, await store.modelMounting.catalogImportUrl(await readBody(request)), 202);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/artifacts/import") {
        store.modelMounting.authorize(request.headers.authorization, "model.import:*");
        writeJsonResponse(response, store.modelMounting.importModel(await readBody(request)), 201);
        return;
      }
      if (
        request.method === "DELETE" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "artifacts" &&
        segments[3] &&
        !segments[4]
      ) {
        store.modelMounting.authorize(request.headers.authorization, "model.delete:*");
        writeJsonResponse(response, store.modelMounting.deleteModelArtifact(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/endpoints") {
        store.modelMounting.authorize(request.headers.authorization, "model.mount:*");
        writeJsonResponse(response, store.modelMounting.mountEndpoint(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/downloads") {
        store.modelMounting.authorize(request.headers.authorization, "model.download:*");
        writeJsonResponse(response, await store.modelMounting.downloadModel(await readBody(request)), 202);
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "downloads" &&
        segments[3]
      ) {
        if (request.method === "GET" && segments[4] === "status") {
          writeJsonResponse(response, store.modelMounting.downloadStatus(decodeURIComponent(segments[3])));
          return;
        }
        if (request.method === "POST" && segments[4] === "cancel") {
          store.modelMounting.authorize(request.headers.authorization, "model.download:*");
          writeJsonResponse(response, store.modelMounting.cancelDownload(decodeURIComponent(segments[3]), await readBody(request)));
          return;
        }
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/storage/cleanup") {
        store.modelMounting.authorize(request.headers.authorization, "model.delete:*");
        writeJsonResponse(response, store.modelMounting.cleanupModelStorage(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/tokens") {
        writeJsonResponse(response, store.modelMounting.listTokens());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/tokens") {
        writeJsonResponse(response, store.modelMounting.createToken(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/tokens/count") {
        writeJsonResponse(
          response,
          store.modelMounting.countModelTokens({
            authorization: request.headers.authorization,
            requiredScope: "model.tokenize:*",
            body: await readBody(request),
          }),
        );
        return;
      }
      if (
        request.method === "DELETE" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "tokens" &&
        segments[3] &&
        !segments[4]
      ) {
        writeJsonResponse(response, store.modelMounting.revokeToken(decodeURIComponent(segments[3])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.listVaultRefs());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.write:*");
        writeJsonResponse(response, store.modelMounting.bindVaultRef(await readBody(request)), 201);
        return;
      }
      if (request.method === "DELETE" && url.pathname === "/v1/model-mount/vault/refs") {
        store.modelMounting.authorize(request.headers.authorization, "vault.delete:*");
        writeJsonResponse(response, store.modelMounting.removeVaultRef(await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/refs/meta") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultRefMetadata(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/status") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultStatus());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/vault/health") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.vaultHealth());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/vault/health/latest") {
        store.modelMounting.authorize(request.headers.authorization, "vault.read:*");
        writeJsonResponse(response, store.modelMounting.latestVaultHealth());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/providers") {
        writeJsonResponse(response, store.modelMounting.listProviders());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/providers") {
        store.modelMounting.authorize(request.headers.authorization, "provider.write:*");
        writeJsonResponse(response, store.modelMounting.upsertProvider(await readBody(request)), 201);
        return;
      }
      if (
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "providers" &&
        segments[3]
      ) {
        const providerId = decodeURIComponent(segments[3]);
        if (request.method === "PATCH" && !segments[4]) {
          store.modelMounting.authorize(request.headers.authorization, `provider.write:${providerId}`);
          writeJsonResponse(response, store.modelMounting.upsertProvider({ ...(await readBody(request)), id: providerId }));
          return;
        }
        if (request.method === "GET" && segments[4] === "health" && segments[5] === "latest") {
          writeJsonResponse(response, store.modelMounting.latestProviderHealth(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "health") {
          writeJsonResponse(response, await store.modelMounting.providerHealth(providerId));
          return;
        }
        if (request.method === "GET" && segments[4] === "models") {
          writeJsonResponse(response, await store.modelMounting.listProviderModels(providerId));
          return;
        }
        if (request.method === "GET" && segments[4] === "loaded") {
          writeJsonResponse(response, await store.modelMounting.listProviderLoaded(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "start") {
          store.modelMounting.authorize(request.headers.authorization, `provider.control:${providerId}`);
          writeJsonResponse(response, await store.modelMounting.startProvider(providerId));
          return;
        }
        if (request.method === "POST" && segments[4] === "stop") {
          store.modelMounting.authorize(request.headers.authorization, `provider.control:${providerId}`);
          writeJsonResponse(response, await store.modelMounting.stopProvider(providerId));
          return;
        }
      }
      if (
        (request.method === "POST" || request.method === "DELETE") &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "endpoints" &&
        segments[3]
      ) {
        const endpointId = decodeURIComponent(segments[3]);
        if (request.method === "POST" && segments[4] === "load") {
          store.modelMounting.authorize(request.headers.authorization, "model.load:*");
          writeJsonResponse(response, await store.modelMounting.loadModel({ ...(await readBody(request)), endpoint_id: endpointId }), 201);
          return;
        }
        if (request.method === "POST" && segments[4] === "unload") {
          store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
          writeJsonResponse(response, await store.modelMounting.unloadModel({ ...(await readBody(request)), endpoint_id: endpointId }));
          return;
        }
        if (request.method === "DELETE" && !segments[4]) {
          store.modelMounting.authorize(request.headers.authorization, "model.unmount:*");
          writeJsonResponse(response, store.modelMounting.unmountEndpoint({ ...(await readBody(request)), endpoint_id: endpointId }));
          return;
        }
      }
      if (request.method === "GET" && url.pathname === "/v1/model-capabilities") {
        writeJsonResponse(response, store.modelMounting.listModelCapabilities());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/status") {
        writeJsonResponse(response, store.modelMounting.serverStatus(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/start") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverStart(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/stop") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverStop(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/server/restart") {
        store.modelMounting.authorize(request.headers.authorization, "server.control:*");
        writeJsonResponse(response, store.modelMounting.serverRestart(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/logs") {
        store.modelMounting.authorize(request.headers.authorization, "server.logs:*");
        writeJsonResponse(response, store.modelMounting.serverLogs(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/server/events") {
        store.modelMounting.authorize(request.headers.authorization, "server.logs:*");
        writeJsonResponse(response, store.modelMounting.serverEvents(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/backends") {
        writeJsonResponse(response, store.modelMounting.listBackends());
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "health"
      ) {
        writeJsonResponse(response, store.modelMounting.backendHealth(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "start"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `backend.control:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.startBackend(decodeURIComponent(segments[3]), await readBody(request)));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "stop"
      ) {
        store.modelMounting.authorize(request.headers.authorization, `backend.control:${decodeURIComponent(segments[3])}`);
        writeJsonResponse(response, store.modelMounting.stopBackend(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "backends" &&
        segments[3] &&
        segments[4] === "logs"
      ) {
        writeJsonResponse(response, store.modelMounting.backendLogs(decodeURIComponent(segments[3])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/runtime/engines") {
        writeJsonResponse(response, store.modelMounting.listRuntimeEngines());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/runtime/survey") {
        writeJsonResponse(response, store.modelMounting.runtimeSurvey());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/runtime/select") {
        writeJsonResponse(response, store.modelMounting.selectRuntimeEngine(await readBody(request)));
        return;
      }
      if (
        (request.method === "GET" || request.method === "PATCH" || request.method === "DELETE" || request.method === "POST") &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "runtime" &&
        segments[3] === "engines" &&
        segments[4]
      ) {
        if (request.method === "POST" && segments[5] === "select") {
          writeJsonResponse(
            response,
            store.modelMounting.selectRuntimeEngine({
              ...(await readBody(request)),
              engine_id: decodeURIComponent(segments[4]),
            }),
          );
          return;
        }
        if (request.method === "PATCH" && !segments[5]) {
          writeJsonResponse(
            response,
            store.modelMounting.updateRuntimeEngine(decodeURIComponent(segments[4]), await readBody(request)),
          );
          return;
        }
        if (request.method === "DELETE" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.removeRuntimeEngineOverride(decodeURIComponent(segments[4])));
          return;
        }
        if (request.method === "GET" && !segments[5]) {
          writeJsonResponse(response, store.modelMounting.runtimeEngine(decodeURIComponent(segments[4])));
          return;
        }
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/instances") {
        writeJsonResponse(response, store.modelMounting.listInstances());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/instances/loaded") {
        writeJsonResponse(
          response,
          store.modelMounting.listInstances().filter((instance) => instance.status === "loaded"),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/instances/load") {
        store.modelMounting.authorize(request.headers.authorization, "model.load:*");
        writeJsonResponse(response, await store.modelMounting.loadModel(await readBody(request)), 201);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/model-mount/instances/unload") {
        store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
        writeJsonResponse(response, await store.modelMounting.unloadModel(await readBody(request)));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "instances" &&
        segments[3] &&
        segments[4] === "unload"
      ) {
        store.modelMounting.authorize(request.headers.authorization, "model.unload:*");
        writeJsonResponse(
          response,
          await store.modelMounting.unloadModel({ instance_id: decodeURIComponent(segments[3]), ...(await readBody(request)) }),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/authority") {
        writeJsonResponse(response, store.modelMounting.authoritySnapshot(baseUrlForRequest(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-mount/receipts") {
        writeJsonResponse(response, store.modelMounting.listReceipts());
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "receipts" &&
        segments[3] &&
        segments[4] === "replay"
      ) {
        writeJsonResponse(response, store.modelMounting.receiptReplay(decodeURIComponent(segments[3])));
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "receipts" &&
        segments[3] &&
        !segments[4]
      ) {
        writeJsonResponse(response, store.modelMounting.getReceipt(decodeURIComponent(segments[3])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/repositories") {
        writeJsonResponse(response, store.repositorySurface.listRepositories(store));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/account") {
        writeJsonResponse(response, store.toolSurface.getAccount());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/runtime/nodes") {
        writeJsonResponse(response, store.toolSurface.listRuntimeNodes());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tools") {
        writeJsonResponse(response, store.toolSurface.listTools(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      throw notFound("Public daemon route not found.", {
        method: request.method,
        path: url.pathname,
      });
    } catch (error) {
      writeError(response, error);
    }
  };

  function lifecycleMcpRegistryForContextPolicyCore(contextPolicyCore) {
    if (typeof mcpRegistryForWorkspace !== "function") {
      return null;
    }
    return (cwd, options = {}) =>
      mcpRegistryForWorkspace(cwd, {
        ...options,
        contextPolicyCore,
      });
  }
}

function assertNoMcpServeQueryContext(url) {
  if (url.searchParams.size === 0) return;
  const error = new Error("MCP serve query-string context is retired; send the stable protocol admission body.");
  error.status = 400;
  error.code = "runtime_mcp_serve_query_context_retired";
  error.details = {
    retired_query_fields: [...url.searchParams.keys()],
    canonical_transport: "ioi.runtime.mcp-serve-client.v1 body",
  };
  throw error;
}

function mcpServeProtocolParts(body) {
  const record = body && typeof body === "object" && !Array.isArray(body) ? body : null;
  if (record && Object.hasOwn(record, "message")) {
    const { message, ...context } = record;
    return { message, context };
  }
  const error = new Error("MCP serve requires the stable protocol admission envelope.");
  error.status = 400;
  error.code = "runtime_mcp_serve_protocol_envelope_required";
  error.details = {
    schema_version: "ioi.runtime.mcp-serve-client.v1",
    required_fields: ["schema_version", "message"],
  };
  throw error;
}
