import crypto from "node:crypto";

export function createPublicRuntimeRequestHandler(deps) {
  const {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
    baseUrlForRequest,
    computerUseProviderRegistryReport,
    discoverComputerUseBrowsers,
    handleAgentRoute,
    handleModelMountingNativeRoute,
    handleOpenAiCompatibilityRoute,
    handleRunRoute,
    handleThreadRoute,
    isOpenAiCompatibilityRoute,
    normalizeBooleanOption,
    notFound,
    optionalString,
    readBody,
    runtimeError,
    usageRequestMetadataFromUrl,
    usageTelemetryWithRequestMetadata,
    writeError,
    writeJsonResponse,
    writeMcpJsonRpcResponse,
  } = deps;

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
        writeJsonResponse(response, store.doctorReport({ baseUrl: baseUrlForRequest(request) }));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/browser-discovery") {
        writeJsonResponse(
          response,
          await discoverComputerUseBrowsers({
            includeCdpProbe: normalizeBooleanOption(url.searchParams.get("probe"), true),
            includeTabMetadata: normalizeBooleanOption(url.searchParams.get("include_tabs"), false),
            revealTabTitles: normalizeBooleanOption(url.searchParams.get("reveal_tab_titles"), false),
          }),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/computer-use/providers") {
        writeJsonResponse(response, computerUseProviderRegistryReport());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/skills") {
        writeJsonResponse(response, store.listSkills());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hooks") {
        writeJsonResponse(response, store.listHooks());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/repository-context") {
        writeJsonResponse(response, store.repositoryContext());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/branch-policy") {
        writeJsonResponse(response, store.branchPolicy());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/github-context") {
        writeJsonResponse(response, store.githubContext());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/pr-attempts") {
        writeJsonResponse(response, store.prAttempts());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/issue-context") {
        writeJsonResponse(response, store.issueContext());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/review-gate") {
        writeJsonResponse(response, store.reviewGate());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/github/pr-create-plan") {
        writeJsonResponse(response, store.githubPrCreatePlan());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/agents") {
        writeJsonResponse(response, store.createAgent((await readBody(request)).options ?? {}));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/agents") {
        writeJsonResponse(response, store.listAgents());
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/threads") {
        writeJsonResponse(response, await store.createThread(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/threads") {
        writeJsonResponse(response, store.listThreads());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/usage") {
        writeJsonResponse(
          response,
          usageTelemetryWithRequestMetadata(
            store.listUsage(Object.fromEntries(url.searchParams.entries())),
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
          store.authorityEvidenceSummary(Object.fromEntries(url.searchParams.entries())),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/context-budget") {
        writeJsonResponse(
          response,
          store.evaluateContextBudget({ request: await readBody(request) }),
        );
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/studio/intent-frame") {
        writeJsonResponse(response, store.resolveStudioIntentFrame(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/conversation-artifacts") {
        writeJsonResponse(response, store.listConversationArtifacts(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/conversation-artifacts") {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          store.createConversationArtifact(optionalString(body.thread_id) ?? "thread_standalone", body),
          201,
        );
        return;
      }
      if (segments[0] === "v1" && segments[1] === "conversation-artifacts" && segments[2]) {
        const artifactId = decodeURIComponent(segments[2]);
        if (request.method === "GET" && !segments[3]) {
          writeJsonResponse(response, store.getConversationArtifact(artifactId));
          return;
        }
        if (request.method === "GET" && segments[3] === "revisions" && !segments[4]) {
          writeJsonResponse(response, store.listConversationArtifactRevisions(artifactId));
          return;
        }
        if (request.method === "POST" && segments[3] === "actions" && !segments[4]) {
          writeJsonResponse(response, store.performConversationArtifactAction(artifactId, await readBody(request)));
          return;
        }
        if (request.method === "POST" && segments[3] === "export" && !segments[4]) {
          writeJsonResponse(response, store.exportConversationArtifact(artifactId, await readBody(request)));
          return;
        }
        if (request.method === "POST" && segments[3] === "promote" && !segments[4]) {
          writeJsonResponse(response, store.promoteConversationArtifact(artifactId, await readBody(request)));
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
      if (request.method === "GET" && url.pathname === "/v1/memory") {
        writeJsonResponse(response, store.memoryStatus(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/runs") {
        writeJsonResponse(response, store.listRuns(url.searchParams.get("agent_id") ?? undefined));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, store.createTask(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tasks") {
        writeJsonResponse(response, store.listTasks(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.cancelTask(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "tasks" && segments[2] && !segments[3] && request.method === "GET") {
        writeJsonResponse(response, store.getTask(decodeURIComponent(segments[2])));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/jobs") {
        writeJsonResponse(response, store.listJobs(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2] && request.method === "POST" && segments[3] === "cancel") {
        writeJsonResponse(response, store.cancelJob(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "jobs" && segments[2]) {
        writeJsonResponse(response, store.getJob(decodeURIComponent(segments[2])));
        return;
      }
      if (segments[0] === "v1" && segments[1] === "runs" && segments[2]) {
        await handleRunRoute({ request, response, store, url, segments });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/models") {
        writeJsonResponse(response, store.listModels());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/model-capabilities") {
        writeJsonResponse(response, store.listModelCapabilities());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/repositories") {
        writeJsonResponse(response, store.listRepositories());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/account") {
        writeJsonResponse(response, store.getAccount());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/runtime/nodes") {
        writeJsonResponse(response, store.listRuntimeNodes());
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/tools") {
        writeJsonResponse(response, store.listTools(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/memory") {
        writeJsonResponse(response, store.memoryStatus(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/memory/records") {
        writeJsonResponse(response, store.memoryProjectionForContext(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/memory/policy") {
        writeJsonResponse(response, store.memoryStatus(Object.fromEntries(url.searchParams.entries())).policy);
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/memory/path") {
        writeJsonResponse(response, store.memoryStatus(Object.fromEntries(url.searchParams.entries())).paths);
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/memory/validate") {
        writeJsonResponse(response, store.validateMemory(await readBody(request)));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp") {
        writeJsonResponse(response, store.mcpStatus(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/serve") {
        writeJsonResponse(response, store.mcpServeStatus(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/mcp/serve") {
        const query = Object.fromEntries(url.searchParams.entries());
        const threadId = optionalString(query.thread_id);
        if (!threadId) {
          throw runtimeError({
            status: 400,
            code: "mcp_thread_required",
            message: "MCP serve JSON-RPC requires a thread_id so served tool calls can emit governed runtime receipts.",
            details: { route: "/v1/mcp/serve" },
          });
        }
        writeMcpJsonRpcResponse(
          response,
          await store.handleMcpServeJsonRpc(threadId, await readBody(request), query),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/servers") {
        writeJsonResponse(response, store.listMcpServers(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/tools") {
        writeJsonResponse(response, store.listMcpTools(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/tools/search") {
        writeJsonResponse(response, await store.searchMcpTools(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (
        request.method === "GET" &&
        segments[0] === "v1" &&
        segments[1] === "mcp" &&
        segments[2] === "tools" &&
        segments[3] &&
        !segments[4]
      ) {
        writeJsonResponse(
          response,
          await store.getMcpTool(decodeURIComponent(segments[3]), Object.fromEntries(url.searchParams.entries())),
        );
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/resources") {
        writeJsonResponse(response, store.listMcpResources(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/mcp/prompts") {
        writeJsonResponse(response, store.listMcpPrompts(Object.fromEntries(url.searchParams.entries())));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/mcp/validate") {
        writeJsonResponse(response, store.validateMcp(await readBody(request)));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/mcp/import") {
        writeJsonResponse(response, store.importMcp({
          ...Object.fromEntries(url.searchParams.entries()),
          ...(await readBody(request)),
        }));
        return;
      }
      if (request.method === "POST" && url.pathname === "/v1/mcp/servers") {
        writeJsonResponse(response, store.addMcpServer({
          ...Object.fromEntries(url.searchParams.entries()),
          ...(await readBody(request)),
        }), 201);
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "mcp" &&
        segments[2] === "servers" &&
        segments[3] &&
        (segments[4] === "enable" || segments[4] === "disable") &&
        !segments[5]
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          store.setMcpServerEnabled(decodeURIComponent(segments[3]), segments[4] === "enable", {
            ...Object.fromEntries(url.searchParams.entries()),
            ...body,
          }),
        );
        return;
      }
      if (
        (request.method === "DELETE" || request.method === "POST") &&
        segments[0] === "v1" &&
        segments[1] === "mcp" &&
        segments[2] === "servers" &&
        segments[3] &&
        (request.method === "DELETE" ? !segments[4] : segments[4] === "remove" && !segments[5])
      ) {
        writeJsonResponse(response, store.removeMcpServer(decodeURIComponent(segments[3]), {
          ...Object.fromEntries(url.searchParams.entries()),
          ...(await readBody(request)),
        }));
        return;
      }
      if (
        request.method === "POST" &&
        segments[0] === "v1" &&
        segments[1] === "mcp" &&
        segments[2] === "tools" &&
        segments[3] &&
        segments[4] === "invoke" &&
        !segments[5]
      ) {
        const body = await readBody(request);
        writeJsonResponse(
          response,
          await store.invokeMcpTool({
            ...Object.fromEntries(url.searchParams.entries()),
            ...body,
            tool_id: decodeURIComponent(segments[3]),
          }),
        );
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
}
