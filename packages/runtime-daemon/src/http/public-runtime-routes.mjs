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

  return async function handleRequest({ request, response, store }) {
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
        writeJsonResponse(
          response,
          store.contextPolicyCore.projectRuntimeDoctorReport({
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
        writeJsonResponse(
          response,
          store.contextPolicyCore.projectRuntimeComputerUse({
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
        writeJsonResponse(
          response,
          store.contextPolicyCore.projectRuntimeComputerUse({
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
        writeJsonResponse(response, createLifecycleAgentDep(store, (await readBody(request)).options ?? {}, {
          ensureProviderAvailable,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: store.contextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForStore(store),
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
        writeJsonResponse(response, await createLifecycleThreadDep(store, await readBody(request), {
          ensureProviderAvailable,
          eventStreamIdForThread,
          initialThreadRuntimeControls,
          lifecycleAdmissionRunner: store.contextPolicyCore,
          mcpRegistryForWorkspace: lifecycleMcpRegistryForStore(store),
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
        writeJsonResponse(
          response,
          store.contextPolicyCore.projectStudioIntentFrame({
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
        await handleAgentRoute({ request, response, store, url, segments });
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
      if (request.method === "GET" && url.pathname === "/v1/models/catalog/search") {
        writeJsonResponse(response, await store.modelMounting.catalogSearch(Object.fromEntries(url.searchParams.entries())));
        return;
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
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "model-mount" &&
        segments[2] === "runtime" &&
        segments[3] === "engines" &&
        segments[4]
      ) {
        writeJsonResponse(response, store.modelMounting.runtimeEngine(decodeURIComponent(segments[4])));
        return;
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

  function lifecycleMcpRegistryForStore(store) {
    if (typeof mcpRegistryForWorkspace !== "function") {
      return null;
    }
    return (cwd, options = {}) =>
      mcpRegistryForWorkspace(cwd, {
        ...options,
        contextPolicyCore: store?.contextPolicyCore,
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
