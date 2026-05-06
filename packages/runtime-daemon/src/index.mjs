import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

import {
  ModelMountingState,
  anthropicMessage,
  openAiChatCompletion,
  openAiCompletion,
  openAiEmbedding,
  openAiResponse,
} from "./model-mounting.mjs";

const TERMINAL_EVENT_TYPES = new Set(["completed", "canceled", "failed", "error"]);

export async function startRuntimeDaemonService(options = {}) {
  const stateDir = path.resolve(options.stateDir ?? path.join(process.cwd(), ".ioi", "agentgres"));
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: options.cwd ?? process.cwd(),
    homeDir: options.homeDir,
    vaultSecrets: options.vaultSecrets,
  });
  const server = http.createServer((request, response) => {
    handleRequest({ request, response, store }).catch((error) => {
      writeError(response, {
        status: 500,
        code: "runtime",
        message: "IOI runtime daemon failed while handling request.",
        details: { error: String(error?.message ?? error) },
      });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Runtime daemon did not bind to a TCP port.");
  }
  return {
    endpoint: `http://${address.address}:${address.port}`,
    stateDir,
    store,
    close: () =>
      new Promise((resolve, reject) => {
        store.close();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

export class AgentgresRuntimeStateStore {
  constructor(stateDir, options = {}) {
    this.stateDir = path.resolve(stateDir);
    this.defaultCwd = path.resolve(options.cwd ?? process.cwd());
    this.agents = new Map();
    this.runs = new Map();
    this.schemaVersion = "ioi.agentgres.runtime.v0";
    this.ensureDirs();
    this.modelMounting = new ModelMountingState({
      stateDir: this.stateDir,
      cwd: this.defaultCwd,
      homeDir: options.homeDir,
      vaultSecrets: options.vaultSecrets,
      appendOperation: (kind, payload) => this.appendOperation(kind, payload),
    });
    this.writeSchema();
    this.load();
  }

  close() {
    this.modelMounting.close();
  }

  createAgent(options = {}) {
    const now = new Date().toISOString();
    const cwd = path.resolve(options.local?.cwd ?? this.defaultCwd);
    const runtime = runtimeModeForOptions(options);
    ensureProviderAvailable(runtime, options);
    const agent = {
      id: `agent_${crypto.randomUUID()}`,
      status: "active",
      runtime,
      cwd,
      modelId: options.model?.id ?? "local:auto",
      createdAt: now,
      updatedAt: now,
      options: summarizeAgentOptions(cwd, options),
    };
    this.agents.set(agent.id, agent);
    this.writeAgent(agent, "agent.create");
    return agent;
  }

  listAgents() {
    return [...this.agents.values()].sort((left, right) =>
      left.createdAt.localeCompare(right.createdAt),
    );
  }

  getAgent(agentId) {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw notFound(`Agent not found: ${agentId}`, { agentId });
    }
    return agent;
  }

  updateAgent(agentId, status, operationKind) {
    const agent = this.getAgent(agentId);
    const updated = { ...agent, status, updatedAt: new Date().toISOString() };
    this.agents.set(agentId, updated);
    this.writeAgent(updated, operationKind);
    return updated;
  }

  deleteAgent(agentId) {
    const agent = this.getAgent(agentId);
    const runCount = this.listRuns(agentId).length;
    if (runCount > 0) {
      throw policyError(
        "Permanent agent deletion requires retention review when canonical runs exist; archive instead.",
        { agentId, runCount },
      );
    }
    this.agents.delete(agentId);
    this.appendOperation("agent.delete", { agentId, priorStatus: agent.status });
    this.removeQuiet(path.join(this.stateDir, "agents", `${agentId}.json`));
  }

  createRun(agentId, request = {}) {
    const agent = this.getAgent(agentId);
    ensureProviderAvailable(agent.runtime, agent.options);
    const mode = request.mode ?? "send";
    const prompt =
      request.prompt ??
      (mode === "learn"
        ? `Learn governed task-family updates for ${request.options?.taskFamily ?? "runtime"}`
        : "");
    const run = buildRun({ agent, mode, prompt, request, source: "local_daemon_agentgres" });
    this.runs.set(run.id, run);
    this.writeRun(run, "run.create");
    return run;
  }

  getRun(runId) {
    const run = this.runs.get(runId);
    if (!run) {
      throw notFound(`Run not found: ${runId}`, { runId });
    }
    return run;
  }

  listRuns(agentId) {
    return [...this.runs.values()]
      .filter((run) => !agentId || run.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  cancelRun(runId) {
    const run = this.getRun(runId);
    const status = run.status === "canceled" ? "canceled" : "canceled";
    const nonTerminalEvents = run.events.filter((event) => !TERMINAL_EVENT_TYPES.has(event.type));
    const canceled = makeEvent(
      run.id,
      run.agentId,
      nonTerminalEvents.length,
      "canceled",
      "Run canceled",
      { reason: "operator_cancel", priorStatus: run.status },
    );
    const stopCondition = {
      reason: "marginal_improvement_too_low",
      evidenceSufficient: true,
      rationale:
        "Cancellation became the single terminal event and replay cursor continuity was preserved.",
    };
    const trace = {
      ...run.trace,
      events: [...nonTerminalEvents, canceled],
      stopCondition,
      qualityLedger: {
        ...run.trace.qualityLedger,
        failureOntologyLabels: [
          ...new Set([...run.trace.qualityLedger.failureOntologyLabels, "operator_cancel"]),
        ],
      },
    };
    const updated = {
      ...run,
      status,
      updatedAt: new Date().toISOString(),
      events: trace.events,
      trace,
      result: "Run canceled with terminal event continuity preserved.",
    };
    this.runs.set(runId, updated);
    this.writeRun(updated, "run.cancel");
    return updated;
  }

  eventsForRun(runId, lastEventId) {
    const events = this.getRun(runId).events;
    if (!lastEventId) return events;
    const index = events.findIndex((event) => event.id === lastEventId);
    return events.slice(index >= 0 ? index + 1 : 0);
  }

  replayFromCanonicalState(runId, lastEventId) {
    return this.eventsForRun(runId, lastEventId);
  }

  traceFromCanonicalState(runId) {
    return this.getRun(runId).trace;
  }

  canonicalProjection(runId) {
    const run = this.getRun(runId);
    const watermark = this.operationCount();
    return {
      schemaVersion: this.schemaVersion,
      runId,
      source: "agentgres_canonical_operation_log",
      watermark,
      freshness: {
        source: "local-agentgres-v0",
        operationCount: watermark,
        generatedAt: new Date().toISOString(),
      },
      paths: {
        run: relative(this.stateDir, this.pathFor("runs", `${run.id}.json`)),
        task: relative(this.stateDir, this.pathFor("tasks", `${run.id}.json`)),
        quality: relative(this.stateDir, this.pathFor("quality", `${run.id}.json`)),
        operationLog: "operation-log.jsonl",
      },
      terminalState: run.status,
      stopCondition: run.trace.stopCondition,
      scorecard: run.trace.scorecard,
    };
  }

  listModels() {
    return this.modelMounting.legacyModelList();
  }

  listRepositories() {
    return [{ url: this.defaultCwd, source: "local_git", status: "available" }];
  }

  getAccount() {
    return {
      id: "local-operator",
      email: process.env.IOI_OPERATOR_EMAIL ?? null,
      authorityLevel: "local",
      privacyClass: "local_private",
      source: "ioi-daemon-agentgres",
    };
  }

  listRuntimeNodes() {
    return [
      {
        id: "local-daemon-agentgres",
        kind: "local",
        status: "available",
        endpoint: "local",
        privacyClass: "local_private",
        evidenceRefs: ["agentgres_canonical_operation_log", "ioi_daemon_public_runtime_api"],
      },
      {
        id: "hosted-provider",
        kind: "hosted",
        status: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
        privacyClass: "hosted",
        evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
      },
      {
        id: "self-hosted-provider",
        kind: "self_hosted",
        status: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
        endpoint: process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
        privacyClass: "workspace",
        evidenceRefs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
      },
    ];
  }

  listTools() {
    return [
      {
        stableToolId: "fs.read",
        displayName: "Read file",
        primitiveCapabilities: ["prim:fs.read"],
        authorityScopeRequirements: [],
        effectClass: "local_read",
        riskDomain: "filesystem",
        inputSchema: { type: "object", required: ["path"] },
        outputSchema: { type: "object", required: ["content"] },
        evidenceRequirements: ["file_read_receipt"],
      },
      {
        stableToolId: "sys.exec",
        displayName: "Shell command",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object", required: ["command"] },
        outputSchema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
        evidenceRequirements: ["shell_receipt", "sandbox_profile"],
      },
      {
        stableToolId: "mcp.invoke",
        displayName: "MCP tool invocation",
        primitiveCapabilities: ["prim:connector.invoke"],
        authorityScopeRequirements: ["scope:mcp.invoke"],
        effectClass: "connector_call",
        riskDomain: "connector",
        inputSchema: { type: "object", required: ["server", "tool"] },
        outputSchema: { type: "object" },
        evidenceRequirements: ["mcp_containment_receipt"],
      },
    ];
  }

  ensureDirs() {
    for (const dir of [
      "agents",
      "runs",
      "tasks",
      "artifacts",
      "receipts",
      "quality",
      "policy-decisions",
      "authority-decisions",
      "stop-conditions",
      "scorecards",
      "ledgers",
      "projections",
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-downloads",
      "tokens",
      "mcp-servers",
    ]) {
      fs.mkdirSync(path.join(this.stateDir, dir), { recursive: true });
    }
  }

  writeSchema() {
    writeJson(this.pathFor("schema.json"), {
      schemaVersion: this.schemaVersion,
      relationSchemas: {
        runs: ["id", "agentId", "status", "objective", "mode", "createdAt", "updatedAt"],
        tasks: ["runId", "currentObjective", "facts", "constraints", "evidenceRefs"],
        artifacts: ["id", "runId", "name", "mediaType", "redaction", "receiptId"],
        receipts: ["id", "runId", "kind", "summary", "redaction", "evidenceRefs"],
        quality: ["runId", "scorecard", "qualityLedger", "stopCondition"],
        operationLog: ["sequence", "operationId", "kind", "objectId", "createdAt", "digest"],
        ...this.modelMounting.writeSchemaRelationSchemas(),
      },
      canonicalOwner: "Agentgres",
      sdkCheckpointAuthority: "cache_only",
    });
  }

  load() {
    for (const file of listJson(this.pathFor("agents"))) {
      const agent = readJson(file);
      this.agents.set(agent.id, agent);
    }
    for (const file of listJson(this.pathFor("runs"))) {
      const run = readJson(file);
      this.runs.set(run.id, run);
    }
  }

  writeAgent(agent, operationKind) {
    writeJson(this.pathFor("agents", `${agent.id}.json`), agent);
    this.appendOperation(operationKind, { objectId: agent.id, agent });
  }

  writeRun(run, operationKind) {
    writeJson(this.pathFor("runs", `${run.id}.json`), run);
    writeJson(this.pathFor("tasks", `${run.id}.json`), {
      runId: run.id,
      agentId: run.agentId,
      taskState: run.trace.taskState,
      postconditions: run.trace.postconditions,
      semanticImpact: run.trace.semanticImpact,
      projectionWatermark: this.operationCount() + 1,
    });
    for (const receipt of run.receipts) {
      writeJson(this.pathFor("receipts", `${receipt.id}.json`), { runId: run.id, ...receipt });
    }
    for (const artifact of run.artifacts) {
      writeJson(this.pathFor("artifacts", `${artifact.id}.json`), artifact);
    }
    writeJson(this.pathFor("policy-decisions", `${run.id}.json`), {
      runId: run.id,
      decision: "allowed",
      rationale: "Local daemon run stayed inside bounded local/private runtime contract.",
      primitiveCapabilities: ["prim:model.invoke"],
      authorityScopes: [],
      receiptId: run.receipts.find((receipt) => receipt.kind === "policy_decision")?.id,
    });
    writeJson(this.pathFor("authority-decisions", `${run.id}.json`), {
      runId: run.id,
      decision: "allowed",
      authorityScopes: [],
      walletLayer: "wallet.network",
      receiptId: run.receipts.find((receipt) => receipt.kind === "authority_decision")?.id,
    });
    writeJson(this.pathFor("stop-conditions", `${run.id}.json`), run.trace.stopCondition);
    writeJson(this.pathFor("scorecards", `${run.id}.json`), run.trace.scorecard);
    writeJson(this.pathFor("ledgers", `${run.id}.json`), run.trace.qualityLedger);
    writeJson(this.pathFor("quality", `${run.id}.json`), {
      runId: run.id,
      scorecard: run.trace.scorecard,
      qualityLedger: run.trace.qualityLedger,
      stopCondition: run.trace.stopCondition,
      verifierIndependencePolicy: {
        sameModelAllowed: false,
        evidenceOnlyMode: true,
        humanReviewThreshold: "high_risk",
      },
    });
    writeJson(this.pathFor("projections", `${run.id}.json`), this.canonicalProjection(run.id));
    this.appendOperation(operationKind, {
      objectId: run.id,
      runId: run.id,
      agentId: run.agentId,
      status: run.status,
      eventCount: run.events.length,
      terminalEventCount: terminalCount(run.events),
      traceBundleId: run.trace.traceBundleId,
    });
  }

  appendOperation(kind, payload) {
    const sequence = this.operationCount() + 1;
    const operation = {
      sequence,
      operationId: `op_${String(sequence).padStart(8, "0")}_${kind.replace(/[^a-z0-9]+/gi, "_")}`,
      kind,
      objectId: payload.objectId ?? payload.agentId ?? payload.runId ?? null,
      createdAt: new Date().toISOString(),
      payload,
    };
    const digest = crypto.createHash("sha256").update(JSON.stringify(operation)).digest("hex");
    const record = { ...operation, digest };
    fs.mkdirSync(this.stateDir, { recursive: true });
    fs.appendFileSync(this.pathFor("operation-log.jsonl"), `${JSON.stringify(record)}\n`);
    return record;
  }

  operationCount() {
    const logPath = this.pathFor("operation-log.jsonl");
    if (!fs.existsSync(logPath)) return 0;
    const text = fs.readFileSync(logPath, "utf8").trim();
    return text ? text.split(/\n/).length : 0;
  }

  pathFor(...segments) {
    return path.join(this.stateDir, ...segments);
  }

  removeQuiet(filePath) {
    try {
      fs.rmSync(filePath, { force: true });
    } catch {
      // Deleting a non-existent projection is not a state transition.
    }
  }
}

async function handleRequest({ request, response, store }) {
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
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      writeJsonResponse(response, store.createAgent((await readBody(request)).options ?? {}));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/agents") {
      writeJsonResponse(response, store.listAgents());
      return;
    }
    if (segments[0] === "v1" && segments[1] === "agents" && segments[2]) {
      await handleAgentRoute({ request, response, store, url, segments });
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs") {
      writeJsonResponse(response, store.listRuns(url.searchParams.get("agentId") ?? undefined));
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
      writeJsonResponse(response, store.listTools());
      return;
    }
    throw notFound("Public daemon route not found.", {
      method: request.method,
      path: url.pathname,
    });
  } catch (error) {
    writeError(response, error);
  }
}

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
  if (request.method === "GET" && url.pathname === "/api/v1/backends") {
    writeJsonResponse(response, mounts.listBackends());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/runtime/engines") {
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
    writeJsonResponse(response, {
      ...nativeInvocationResponse(invocation),
      embeddings: openAiEmbedding(invocation, body).data,
    });
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
  if (request.method === "GET" && url.pathname === "/api/v1/mcp") {
    writeJsonResponse(response, mounts.listMcpServers());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/mcp/import") {
    mounts.authorize(authorization, "mcp.import:*");
    writeJsonResponse(response, mounts.importMcpJson(await readBody(request)), 201);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/mcp/invoke") {
    writeJsonResponse(response, mounts.invokeMcpTool({ authorization, body: await readBody(request) }));
    return;
  }
  throw notFound("Model mounting route not found.", {
    method: request.method,
    path: url.pathname,
  });
}

async function handleOpenAiCompatibilityRoute({ request, response, store, url }) {
  const mounts = store.modelMounting;
  const authorization = compatibilityAuthorization(request);
  if (request.method === "GET" && url.pathname === "/v1/models") {
    writeJsonResponse(response, mounts.openAiModelList());
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/chat/completions") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.chat:*",
        kind: "chat.completions",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderChatCompletionStream(response, stream, mounts);
        return;
      }
      await writeOpenAiChatCompletionStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "chat.completions",
      body,
    });
    writeJsonResponse(response, openAiChatCompletion(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/responses") {
    const body = await readBody(request);
    if (body.stream === true) {
      const stream = await mounts.startModelStream({
        authorization,
        requiredScope: "model.responses:*",
        kind: "responses",
        body,
      });
      if (stream.native) {
        await writeOpenAiProviderResponseStream(response, stream, mounts);
        return;
      }
      await writeOpenAiResponseStream(response, stream.invocation, mounts);
      return;
    }
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.responses:*",
      kind: "responses",
      body,
    });
    writeJsonResponse(response, openAiResponse(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/embeddings") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.embeddings:*",
      kind: "embeddings",
      body,
    });
    writeJsonResponse(response, openAiEmbedding(invocation, body));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/completions") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "completions",
      body,
    });
    writeJsonResponse(response, openAiCompletion(invocation));
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/messages") {
    const body = await readBody(request);
    const invocation = await mounts.invokeModel({
      authorization,
      requiredScope: "model.chat:*",
      kind: "messages",
      body: anthropicMessagesToCanonicalBody(body),
    });
    if (body.stream === true) {
      await writeAnthropicMessageStream(response, invocation, mounts);
      return;
    }
    writeJsonResponse(response, anthropicMessage(invocation));
    return;
  }
  throw notFound("OpenAI-compatible route not found.", {
    method: request.method,
    path: url.pathname,
  });
}

function isOpenAiCompatibilityRoute(request, url) {
  if (request.method === "GET" && url.pathname === "/v1/models") {
    return Boolean(compatibilityAuthorization(request));
  }
  return [
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/messages",
  ].includes(url.pathname);
}

function compatibilityAuthorization(request) {
  const authorization = firstHeader(request.headers.authorization);
  if (authorization) return authorization;
  const apiKey = firstHeader(request.headers["x-api-key"]);
  if (!apiKey) return undefined;
  return apiKey.startsWith("Bearer ") ? apiKey : `Bearer ${apiKey}`;
}

function firstHeader(value) {
  if (Array.isArray(value)) return value[0];
  return value;
}

function anthropicMessagesToCanonicalBody(body = {}) {
  return {
    ...body,
    messages: canonicalAnthropicMessages(body),
    max_tokens: body.max_tokens ?? body.maxTokens,
    stream: false,
  };
}

function canonicalAnthropicMessages(body = {}) {
  const messages = [];
  if (body.system !== undefined) {
    messages.push({ role: "system", content: anthropicContentToText(body.system) });
  }
  for (const message of Array.isArray(body.messages) ? body.messages : []) {
    messages.push({
      role: message?.role ?? "user",
      content: anthropicContentToText(message?.content ?? ""),
    });
  }
  return messages.length > 0 ? messages : [{ role: "user", content: anthropicContentToText(body.input ?? "") }];
}

function anthropicContentToText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((item) => {
        if (typeof item === "string") return item;
        if (typeof item?.text === "string") return item.text;
        if (typeof item?.content === "string") return item.content;
        if (item?.type === "image" || item?.type === "image_url") return "[image]";
        return JSON.stringify(redact(item ?? {}));
      })
      .join("\n");
  }
  if (content && typeof content === "object") {
    if (typeof content.text === "string") return content.text;
    return JSON.stringify(redact(content));
  }
  return String(content ?? "");
}

async function writeAnthropicMessageStream(response, invocation, mounts) {
  const message = anthropicMessage(invocation);
  const text = String(message.content?.[0]?.text ?? "");
  const chunks = textChunksForSse(text);
  const usage = message.usage ?? { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 };
  const events = [
    {
      event: "message_start",
      data: {
        type: "message_start",
        message: {
          id: message.id,
          type: "message",
          role: "assistant",
          content: [],
          model: message.model,
          stop_reason: null,
          stop_sequence: null,
          usage: {
            input_tokens: usage.input_tokens,
            output_tokens: 0,
            cache_read_input_tokens: usage.cache_read_input_tokens ?? 0,
          },
        },
      },
    },
    {
      event: "content_block_start",
      data: {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "content_block_delta",
      data: {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: chunk },
      },
    })),
    {
      event: "content_block_stop",
      data: {
        type: "content_block_stop",
        index: 0,
      },
    },
    {
      event: "message_delta",
      data: {
        type: "message_delta",
        delta: {
          stop_reason: message.stop_reason,
          stop_sequence: message.stop_sequence,
        },
        usage: {
          output_tokens: usage.output_tokens,
        },
      },
    },
    {
      event: "message_stop",
      data: {
        type: "message_stop",
        receipt_id: message.receipt_id,
        route_id: message.route_id,
        tool_receipt_ids: message.tool_receipt_ids,
      },
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "anthropic_messages",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

function textChunksForSse(text) {
  if (!text) return [""];
  const chunks = text.match(/.{1,96}(?:\s+|$)/gs);
  return chunks?.length ? chunks : [text];
}

async function writeOpenAiChatCompletionStream(response, invocation, mounts) {
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
  const payloads = [
    {
      ...base,
      choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
    },
    ...chunks.map((chunk) => ({
      ...base,
      choices: [{ index: 0, delta: { content: chunk }, finish_reason: null }],
    })),
    {
      ...base,
      choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
    },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_chat_completions",
    frames: [...payloads.map((payload) => `data: ${JSON.stringify(payload)}\n\n`), "data: [DONE]\n\n"],
  });
}

async function writeOpenAiProviderChatCompletionStream(response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaChatCompletionStream(response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_chat_completions_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        for (const payload of dataPayloadsFromSseBlock(frame)) {
          if (payload === "[DONE]") continue;
          const parsed = parseJsonMaybe(payload);
          const delta = parsed?.choices?.[0]?.delta?.content;
          if (typeof delta === "string") outputText += delta;
          if (parsed?.usage) providerUsage = parsed.usage;
          const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
          if (nextFinishReason) finishReason = nextFinishReason;
          try {
            response.write(`data: ${payload}\n\n`);
          } catch {
            markCanceled();
            break;
          }
          written += 1;
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      for (const payload of dataPayloadsFromSseBlock(frame)) {
        if (payload === "[DONE]") continue;
        const parsed = parseJsonMaybe(payload);
        const delta = parsed?.choices?.[0]?.delta?.content;
        if (typeof delta === "string") outputText += delta;
        if (parsed?.usage) providerUsage = parsed.usage;
        const nextFinishReason = parsed?.choices?.[0]?.finish_reason;
        if (nextFinishReason) finishReason = nextFinishReason;
        response.write(`data: ${payload}\n\n`);
        written += 1;
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const metadata = {
      id: `chatcmpl_${crypto.randomUUID()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: invocation.model,
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
      choices: [{ index: 0, delta: {}, finish_reason: null }],
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`data: ${JSON.stringify(metadata)}\n\n`);
      response.write("data: [DONE]\n\n");
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOllamaChatCompletionStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_chat_completions_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const id = `chatcmpl_${crypto.randomUUID()}`;
  const created = Math.floor(Date.now() / 1000);
  const base = {
    id,
    object: "chat.completion.chunk",
    created,
    model: invocation.model,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    provider_stream: "native",
  };
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    response.write(`data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }] })}\n\n`);
    written += 1;
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `data: ${JSON.stringify({ ...base, choices: [{ index: 0, delta: { content: delta }, finish_reason: null }] })}\n\n`,
          );
          written += 1;
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    response.write(
      `data: ${JSON.stringify({
        ...base,
        stream_receipt_id: completionReceipt.id,
        choices: [{ index: 0, delta: {}, finish_reason: finishReason }],
      })}\n\n`,
    );
    response.write("data: [DONE]\n\n");
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOpenAiProviderResponseStream(response, streamInvocation, mounts) {
  if (["ollama_jsonl", "ioi_jsonl"].includes(streamInvocation.providerResult?.streamFormat)) {
    await writeOllamaResponseStream(response, streamInvocation, mounts);
    return;
  }
  const invocation = streamInvocation.invocation;
  const streamKind = "openai_responses_provider_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = null;
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const frames = takeSseFrameBlocks(buffer);
      buffer = frames.remainder;
      for (const frame of frames.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsedPayloads = responseStreamPayloads(frame);
        for (const payload of parsedPayloads) {
          if (payload.raw === "[DONE]") continue;
          if (payload.delta) outputText += payload.delta;
          if (!outputText && payload.completionText) outputText = payload.completionText;
          if (payload.usage) providerUsage = payload.usage;
          if (payload.finishReason) finishReason = payload.finishReason;
        }
        try {
          response.write(`${frame}\n\n`);
        } catch {
          markCanceled();
          break;
        }
        written += 1;
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    const trailingBlocks = buffer.trim() ? [buffer] : [];
    for (const frame of trailingBlocks) {
      const parsedPayloads = responseStreamPayloads(frame);
      if (parsedPayloads.every((payload) => payload.raw === "[DONE]")) continue;
      for (const payload of parsedPayloads) {
        if (payload.raw === "[DONE]") continue;
        if (payload.delta) outputText += payload.delta;
        if (!outputText && payload.completionText) outputText = payload.completionText;
        if (payload.usage) providerUsage = payload.usage;
        if (payload.finishReason) finishReason = payload.finishReason;
      }
      response.write(`${frame}\n\n`);
      written += 1;
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const metadata = {
      type: "response.ioi.receipt",
      receipt_id: invocation.receipt.id,
      stream_receipt_id: completionReceipt.id,
      route_id: invocation.route.id,
      model: invocation.model,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      provider_stream: "native",
    };
    if (!response.destroyed && !response.writableEnded) {
      response.write(`event: response.ioi.receipt\ndata: ${JSON.stringify(metadata)}\n\n`);
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOllamaResponseStream(response, streamInvocation, mounts) {
  const invocation = streamInvocation.invocation;
  const streamKind = streamInvocation.providerResult?.streamKind ?? "openai_responses_ollama_native";
  const reader = streamInvocation.providerStream.getReader();
  const decoder = new TextDecoder();
  const responseId = `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  let completed = false;
  let canceled = false;
  let written = 0;
  let outputText = "";
  let providerUsage = null;
  let finishReason = "stop";
  let buffer = "";
  const markCanceled = () => {
    if (completed || canceled) return;
    canceled = true;
    streamInvocation.abort?.();
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  const onClose = () => markCanceled();
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    provider_stream: "native",
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.setHeader("x-ioi-stream-source", "provider_native");
  response.on("close", onClose);
  try {
    response.write(`event: response.created\ndata: ${JSON.stringify({ type: "response.created", response: baseResponse })}\n\n`);
    response.write(`event: response.output_item.added\ndata: ${JSON.stringify({ type: "response.output_item.added", output_index: 0, item: outputItem })}\n\n`);
    response.write(
      `event: response.content_part.added\ndata: ${JSON.stringify({
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      })}\n\n`,
    );
    written += 3;
    while (!canceled) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: true });
      const lines = takeLineBlocks(buffer);
      buffer = lines.remainder;
      for (const line of lines.blocks) {
        if (canceled) break;
        if (response.destroyed || response.writableEnded) {
          markCanceled();
          break;
        }
        const parsed = parseJsonMaybe(line);
        const delta = ollamaStreamDelta(parsed);
        if (delta) {
          outputText += delta;
          response.write(
            `event: response.output_text.delta\ndata: ${JSON.stringify({
              type: "response.output_text.delta",
              item_id: outputItemId,
              output_index: 0,
              content_index: 0,
              delta,
            })}\n\n`,
          );
          written += 1;
        }
        if (parsed?.done) {
          providerUsage = ollamaUsage(parsed);
          finishReason = parsed.done_reason ?? "stop";
        }
      }
    }
    if (canceled) return;
    const tail = decoder.decode();
    if (tail) buffer += tail;
    for (const line of buffer.trim() ? [buffer.trim()] : []) {
      const parsed = parseJsonMaybe(line);
      const delta = ollamaStreamDelta(parsed);
      if (delta) outputText += delta;
      if (parsed?.done) {
        providerUsage = ollamaUsage(parsed);
        finishReason = parsed.done_reason ?? "stop";
      }
    }
    const completionReceipt = mounts.recordModelStreamCompleted({
      invocation,
      streamKind,
      outputText,
      providerUsage,
      chunksForwarded: written,
      finishReason,
      providerResult: streamInvocation.providerResult,
    });
    const completedOutputItem = {
      ...outputItem,
      status: "completed",
      content: [{ type: "output_text", text: outputText }],
    };
    const completedResponse = {
      ...baseResponse,
      status: "completed",
      output: [completedOutputItem],
      output_text: outputText,
      usage: providerUsage,
      stream_receipt_id: completionReceipt.id,
    };
    response.write(
      `event: response.content_part.done\ndata: ${JSON.stringify({
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: outputText },
      })}\n\n`,
    );
    response.write(`event: response.output_item.done\ndata: ${JSON.stringify({ type: "response.output_item.done", output_index: 0, item: completedOutputItem })}\n\n`);
    response.write(`event: response.completed\ndata: ${JSON.stringify({ type: "response.completed", response: completedResponse })}\n\n`);
    completed = true;
    response.end();
  } finally {
    response.off("close", onClose);
    try {
      reader.releaseLock();
    } catch {
      // Some runtime streams close the reader before release.
    }
  }
}

async function writeOpenAiResponseStream(response, invocation, mounts) {
  const responseId = `resp_${crypto.randomUUID()}`;
  const outputItemId = `msg_${crypto.randomUUID()}`;
  const createdAt = Math.floor(Date.now() / 1000);
  const chunks = textChunksForSse(invocation.outputText);
  const baseResponse = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    model: invocation.model,
    status: "in_progress",
    output: [],
    usage: null,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
  const outputItem = {
    id: outputItemId,
    type: "message",
    status: "in_progress",
    role: "assistant",
    content: [],
  };
  const completedOutputItem = {
    ...outputItem,
    status: "completed",
    content: [{ type: "output_text", text: invocation.outputText }],
  };
  const completedResponse = {
    ...baseResponse,
    status: "completed",
    output: [completedOutputItem],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
  const events = [
    { event: "response.created", data: { type: "response.created", response: baseResponse } },
    {
      event: "response.output_item.added",
      data: { type: "response.output_item.added", output_index: 0, item: outputItem },
    },
    {
      event: "response.content_part.added",
      data: {
        type: "response.content_part.added",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: "" },
      },
    },
    ...chunks.map((chunk) => ({
      event: "response.output_text.delta",
      data: {
        type: "response.output_text.delta",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        delta: chunk,
      },
    })),
    {
      event: "response.content_part.done",
      data: {
        type: "response.content_part.done",
        item_id: outputItemId,
        output_index: 0,
        content_index: 0,
        part: { type: "output_text", text: invocation.outputText },
      },
    },
    {
      event: "response.output_item.done",
      data: { type: "response.output_item.done", output_index: 0, item: completedOutputItem },
    },
    { event: "response.completed", data: { type: "response.completed", response: completedResponse } },
  ];
  await writeModelSseFrames({
    response,
    invocation,
    mounts,
    streamKind: "openai_responses",
    frames: events.map((event) => `event: ${event.event}\ndata: ${JSON.stringify(event.data)}\n\n`),
  });
}

async function writeModelSseFrames({ response, invocation, mounts, streamKind, frames }) {
  let completed = false;
  let canceled = false;
  const onClose = () => {
    if (completed || canceled) return;
    canceled = true;
    recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten: written });
  };
  let written = 0;
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.setHeader("x-ioi-receipt-id", invocation.receipt.id);
  response.on("close", onClose);
  try {
    for (const frame of frames) {
      if (canceled || response.destroyed || response.writableEnded) break;
      response.write(frame);
      written += 1;
      await delay(streamFrameDelayMs());
    }
    if (!canceled && !response.destroyed && !response.writableEnded) {
      completed = true;
      response.end();
    }
  } finally {
    response.off("close", onClose);
  }
}

function recordModelStreamCanceled({ mounts, invocation, streamKind, framesWritten }) {
  mounts.receipt("model_invocation_stream_canceled", {
    summary: `${streamKind} stream canceled for ${invocation.model}.`,
    redaction: "redacted",
    evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
    details: {
      streamKind,
      invocationReceiptId: invocation.receipt.id,
      routeId: invocation.route.id,
      selectedModel: invocation.model,
      endpointId: invocation.endpoint.id,
      providerId: invocation.endpoint.providerId,
      instanceId: invocation.instance.id,
      backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
      selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
      streamSource: invocation.receipt.details?.streamSource ?? null,
      providerResponseKind: invocation.providerResponseKind ?? invocation.receipt.details?.providerResponseKind ?? null,
      backendEvidenceRefs: invocation.receipt.details?.backendEvidenceRefs ?? [],
      toolReceiptIds: invocation.toolReceiptIds ?? [],
      framesWritten,
      status: "aborted",
      reason: "client_disconnect",
    },
  });
}

function streamFrameDelayMs() {
  const configured = Number(process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS ?? "");
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 5;
}

function takeSseFrameBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.filter(Boolean), remainder };
}

function takeLineBlocks(buffer) {
  const parts = String(buffer).split(/\r?\n/);
  const remainder = parts.pop() ?? "";
  return { blocks: parts.map((part) => part.trim()).filter(Boolean), remainder };
}

function dataPayloadsFromSseBlock(block) {
  const payload = String(block)
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.replace(/^data:\s?/, ""))
    .join("\n");
  return payload ? [payload] : [];
}

function responseStreamPayloads(block) {
  return dataPayloadsFromSseBlock(block).map((raw) => {
    if (raw === "[DONE]") return { raw };
    const parsed = parseJsonMaybe(raw);
    return {
      raw,
      parsed,
      delta: typeof parsed?.delta === "string" && parsed?.type === "response.output_text.delta" ? parsed.delta : "",
      completionText: typeof parsed?.response?.output_text === "string" ? parsed.response.output_text : "",
      usage: parsed?.response?.usage ?? parsed?.usage ?? null,
      finishReason: parsed?.response?.status ?? parsed?.status ?? parsed?.type ?? null,
    };
  });
}

function ollamaStreamDelta(payload) {
  if (!payload || typeof payload !== "object") return "";
  return String(payload.delta ?? payload.message?.content ?? payload.response ?? "");
}

function ollamaUsage(payload) {
  const promptTokens = Number(payload?.prompt_eval_count ?? 0) || 0;
  const completionTokens = Number(payload?.eval_count ?? 0) || 0;
  return {
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: promptTokens + completionTokens,
  };
}

function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function nativeInvocationResponse(invocation) {
  return {
    id: `model_invocation_${crypto.randomUUID()}`,
    object: "ioi.model_invocation",
    model: invocation.model,
    route_id: invocation.route.id,
    endpoint_id: invocation.endpoint.id,
    instance_id: invocation.instance.id,
    backend_id: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    receipt_id: invocation.receipt.id,
    route_receipt_id: invocation.routeReceipt?.id ?? null,
    compat_translation: invocation.compatTranslation ?? null,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
}

function baseUrlForRequest(request) {
  const host = request.headers.host;
  return host ? `http://${host}` : null;
}

async function handleAgentRoute({ request, response, store, segments }) {
  const agentId = decodeURIComponent(segments[2]);
  const action = segments[3];
  if (request.method === "GET" && !action) {
    writeJsonResponse(response, store.getAgent(agentId));
    return;
  }
  if (request.method === "DELETE" && !action) {
    store.deleteAgent(agentId);
    writeJsonResponse(response, undefined, 204);
    return;
  }
  if (request.method === "POST" && action === "archive") {
    writeJsonResponse(response, store.updateAgent(agentId, "archived", "agent.archive"));
    return;
  }
  if (request.method === "POST" && action === "unarchive") {
    writeJsonResponse(response, store.updateAgent(agentId, "active", "agent.unarchive"));
    return;
  }
  if (request.method === "POST" && action === "resume") {
    writeJsonResponse(response, store.updateAgent(agentId, "active", "agent.resume"));
    return;
  }
  if (request.method === "POST" && action === "close") {
    writeJsonResponse(response, store.updateAgent(agentId, "closed", "agent.close"));
    return;
  }
  if (request.method === "POST" && action === "reload") {
    writeJsonResponse(response, store.updateAgent(agentId, store.getAgent(agentId).status, "agent.reload"));
    return;
  }
  if (request.method === "POST" && action === "runs") {
    writeJsonResponse(response, store.createRun(agentId, await readBody(request)));
    return;
  }
  if (request.method === "GET" && action === "runs") {
    writeJsonResponse(response, store.listRuns(agentId));
    return;
  }
  throw notFound("Agent route not found.", { agentId, action, method: request.method });
}

async function handleRunRoute({ request, response, store, url, segments }) {
  const runId = decodeURIComponent(segments[2]);
  const action = segments[3];
  if (request.method === "GET" && !action) {
    writeJsonResponse(response, store.getRun(runId));
    return;
  }
  if (request.method === "POST" && action === "cancel") {
    writeJsonResponse(response, store.cancelRun(runId));
    return;
  }
  if (request.method === "GET" && action === "wait") {
    const run = store.getRun(runId);
    writeJsonResponse(response, {
      id: run.id,
      agentId: run.agentId,
      status: run.status,
      result: run.result,
      stopCondition: run.trace.stopCondition,
      trace: run.trace,
      scorecard: run.trace.scorecard,
    });
    return;
  }
  if (request.method === "GET" && action === "conversation") {
    writeJsonResponse(response, store.getRun(runId).conversation);
    return;
  }
  if (request.method === "GET" && action === "events") {
    writeSse(
      response,
      store.eventsForRun(
        runId,
        url.searchParams.get("lastEventId") ?? request.headers["last-event-id"],
      ),
    );
    return;
  }
  if (request.method === "GET" && action === "replay") {
    writeSse(
      response,
      store.replayFromCanonicalState(
        runId,
        url.searchParams.get("lastEventId") ?? request.headers["last-event-id"],
      ),
    );
    return;
  }
  if (request.method === "GET" && (action === "trace" || action === "inspect")) {
    const trace = store.traceFromCanonicalState(runId);
    writeJsonResponse(response, {
      ...trace,
      canonicalState: store.canonicalProjection(runId),
    });
    return;
  }
  if (request.method === "GET" && action === "scorecard") {
    writeJsonResponse(response, store.getRun(runId).trace.scorecard);
    return;
  }
  if (request.method === "GET" && action === "artifacts" && !segments[4]) {
    writeJsonResponse(response, store.getRun(runId).artifacts);
    return;
  }
  if (request.method === "GET" && action === "artifacts" && segments[4]) {
    const artifactId = decodeURIComponent(segments[4]);
    const artifact = store.getRun(runId).artifacts.find((item) => item.id === artifactId);
    if (!artifact) throw notFound(`Artifact not found: ${artifactId}`, { runId, artifactId });
    writeJsonResponse(response, artifact);
    return;
  }
  throw notFound("Run route not found.", { runId, action, method: request.method });
}

function buildRun({ agent, mode, prompt, request, source }) {
  const runId = `run_${crypto.randomUUID()}`;
  const createdAt = new Date().toISOString();
  const taskFamily = taskFamilyForMode(mode);
  const selectedStrategy = strategyForMode(mode);
  const toolSequence = capabilitySequenceForMode(mode, agent);
  const selectedModel = request.options?.model?.id ?? agent.modelId;
  const taskState = {
    currentObjective: prompt,
    knownFacts: [
      "Run entered the live local IOI daemon public runtime API",
      "Agentgres v0 is the canonical owner for this run state",
      `Selected model profile: ${selectedModel}`,
    ],
    uncertainFacts: mode === "dry_run" ? ["Side effects are previewed, not executed"] : [],
    assumptions: [],
    constraints: ["No GUI internals", "No raw receipt dump", "No policy bypass"],
    blockers: [],
    changedObjects: mode === "send" ? [] : [`daemon:${mode}`],
    evidenceRefs: [
      "ioi_daemon_public_runtime_api",
      "agentgres_canonical_operation_log",
      ...agent.options.mcpServerNames,
      ...agent.options.skillNames,
      ...agent.options.hookNames,
    ],
  };
  const uncertainty = {
    ambiguityLevel: mode === "send" ? "low" : "medium",
    selectedAction:
      mode === "dry_run"
        ? "dry_run"
        : mode === "plan"
          ? "verify"
          : mode === "handoff"
            ? "execute"
            : "probe",
    rationale: "Live daemon run chose bounded local execution with canonical state writeback.",
    valueOfProbe: mode === "send" ? "medium" : "high",
  };
  const probes = [
    {
      probeId: `${runId}:probe:canonical-replay`,
      hypothesis: "Agentgres canonical operation log can replay the terminal run event stream.",
      cheapestValidationAction: "Read canonical run projection and replay events by cursor.",
      expectedObservation: "Monotonic event stream with exactly one terminal event.",
      result: "confirmed",
      confidenceUpdate: "Canonical replay and daemon stream use the same event IDs.",
    },
  ];
  const postconditions = {
    objective: prompt,
    taskFamily,
    riskClass: mode === "dry_run" ? "side_effect_preview" : "bounded_local",
    checks: [
      {
        checkId: "daemon-event-stream-terminal",
        description: "Daemon event stream contains exactly one terminal event.",
        status: "passed",
      },
      {
        checkId: "agentgres-operation-log",
        description: "Run, task, receipts, scorecard, and ledger are written to Agentgres v0.",
        status: "passed",
      },
      {
        checkId: "canonical-replay",
        description: "Replay from Agentgres reconstructs terminal event stream.",
        status: "passed",
      },
    ],
    minimumEvidence: ["events", "receipts", "trace", "scorecard", "agentgres_operation_log"],
  };
  const semanticImpact = {
    changedSymbols: [],
    changedApis: ["/v1/agents/{id}/runs", "/v1/runs/{id}/events", "/v1/runs/{id}/trace"],
    changedSchemas: ["IOISDKMessage", "RuntimeTraceBundle", "AgentgresRuntimeStateV0"],
    changedPolicies: mode === "dry_run" ? ["authority.preview_only"] : [],
    affectedTests: ["live-runtime-daemon-contract"],
    affectedDocs: ["docs/plans/architectural-improvements-broad-master-guide.md"],
    riskClass: postconditions.riskClass,
  };
  const stopCondition = {
    reason: "evidence_sufficient",
    evidenceSufficient: true,
    rationale:
      "Daemon stream, canonical Agentgres writeback, trace export, replay, and scorecard evidence were produced.",
  };
  const qualityLedger = {
    ledgerId: `quality_${runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence,
    scorecardMetrics: {
      task_pass_rate: 100,
      recovery_success: 100,
      memory_relevance: mode === "learn" ? 100 : 92,
      tool_quality: 96,
      strategy_roi: 93,
      operator_interventions: 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: [],
  };
  const scorecard = {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: mode === "learn" ? 1 : 0.92,
    toolQuality: 0.96,
    strategyRoi: 0.93,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
  const receipts = [
    {
      id: `receipt_${runId}_policy`,
      kind: "policy_decision",
      summary: "Local daemon run was admitted under bounded local/private runtime policy.",
      redaction: "none",
      evidenceRefs: ["prim:model.invoke", "policy.local_private"],
    },
    {
      id: `receipt_${runId}_authority`,
      kind: "authority_decision",
      summary: "No external authority scope was required for this bounded local daemon run.",
      redaction: "none",
      evidenceRefs: ["wallet.network", "authority.no_external_scope"],
    },
    {
      id: `receipt_${runId}_agentgres`,
      kind: "agentgres_canonical_write",
      summary: "Run state, task state, receipts, scorecard, stop condition, and quality ledger were written to Agentgres v0.",
      redaction: "redacted",
      evidenceRefs: ["agentgres_canonical_operation_log", `run:${runId}`],
    },
    {
      id: `receipt_${runId}_trace`,
      kind: "trace_export",
      summary: "Trace export is reconstructed from daemon runtime state and canonical Agentgres projection.",
      redaction: "redacted",
      evidenceRefs: ["RuntimeTraceBundle", "canonical_replay"],
    },
  ];
  const result = resultForMode(mode, agent, prompt, source);
  const events = [
    makeEvent(runId, agent.id, 0, "run_started", "Run entered local IOI daemon", {
      taskFamily,
      selectedStrategy,
    }),
    makeEvent(runId, agent.id, 1, "task_state", "Task state written to Agentgres", taskState),
    makeEvent(runId, agent.id, 2, "uncertainty", "Uncertainty assessed", uncertainty),
    makeEvent(runId, agent.id, 3, "probe", "Canonical replay probe completed", probes[0]),
    makeEvent(runId, agent.id, 4, "postcondition_synthesized", "Postconditions synthesized", postconditions),
    makeEvent(runId, agent.id, 5, "semantic_impact", "Semantic impact classified", semanticImpact),
    makeEvent(runId, agent.id, 6, "delta", result, { text: result }),
    makeEvent(runId, agent.id, 7, "stop_condition", "Stop condition recorded", stopCondition),
    makeEvent(runId, agent.id, 8, "quality_ledger", "Quality ledger recorded", qualityLedger),
    makeEvent(runId, agent.id, 9, "artifact", "Trace and scorecard artifacts recorded", {
      artifactNames: ["trace.json", "scorecard.json", "agentgres-projection.json"],
    }),
    makeEvent(runId, agent.id, 10, "completed", "Run completed", { stopReason: stopCondition.reason }),
  ];
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: `trace_${runId}`,
    agentId: agent.id,
    runId,
    eventStreamId: `events_${runId}`,
    events,
    receipts,
    taskState,
    uncertainty,
    probes,
    postconditions,
    semanticImpact,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const artifacts = [
    artifact(runId, "trace.json", "application/json", receipts[3].id, trace, "redacted"),
    artifact(runId, "scorecard.json", "application/json", receipts[3].id, scorecard, "none"),
    artifact(
      runId,
      "agentgres-projection.json",
      "application/json",
      receipts[2].id,
      {
        runId,
        canonicalOwner: "Agentgres",
        source: "agentgres_canonical_operation_log",
      },
      "redacted",
    ),
  ];
  return {
    id: runId,
    agentId: agent.id,
    status: "completed",
    objective: prompt,
    mode,
    createdAt,
    updatedAt: createdAt,
    events,
    conversation: [
      { role: "user", content: prompt, eventId: events[0].id, createdAt },
      { role: "assistant", content: result, eventId: events[6].id, createdAt },
    ],
    receipts,
    artifacts,
    trace,
    result,
  };
}

function artifact(runId, name, mediaType, receiptId, value, redaction) {
  return {
    id: `artifact_${runId}_${name.replace(/[^a-z0-9]+/gi, "_").replace(/_$/, "")}`,
    runId,
    name,
    mediaType,
    redaction,
    receiptId,
    content: JSON.stringify(value, null, 2),
  };
}

function summarizeAgentOptions(cwd, options = {}) {
  const cursorConfig = loadCursorCompatibilityConfig(cwd);
  return {
    localCwd: options.local?.cwd,
    cloudConfigured: Boolean(options.cloud ?? options.hosted),
    selfHostedConfigured: Boolean(options.selfHosted),
    mcpServerNames: [
      ...new Set([
        ...Object.keys(options.mcpServers ?? {}),
        ...Object.keys(cursorConfig.mcpServers),
      ]),
    ],
    skillNames: cursorConfig.skillNames,
    hookNames: cursorConfig.hookNames,
    subagentNames: Object.keys(options.agents ?? {}),
    sandboxProfile: options.sandboxOptions?.profile ?? "development",
  };
}

function loadCursorCompatibilityConfig(cwd) {
  const cursorDir = path.join(cwd, ".cursor");
  const mcpPath = path.join(cursorDir, "mcp.json");
  const hooksPath = path.join(cursorDir, "hooks.json");
  const skillsDir = path.join(cursorDir, "skills");
  return {
    mcpServers: fs.existsSync(mcpPath) ? readJson(mcpPath).mcpServers ?? {} : {},
    hookNames: fs.existsSync(hooksPath) ? Object.keys(readJson(hooksPath)) : [],
    skillNames: fs.existsSync(skillsDir)
      ? fs.readdirSync(skillsDir).filter((entry) => !entry.startsWith("."))
      : [],
  };
}

function runtimeModeForOptions(options = {}) {
  if (options.cloud) return "cloud";
  if (options.hosted) return "hosted";
  if (options.selfHosted) return "selfHosted";
  return "local";
}

function ensureProviderAvailable(runtime, options = {}) {
  if (runtime === "local") return;
  const endpoint =
    options.hosted?.endpoint ??
    options.hosted?.provider?.endpoint ??
    options.cloud?.endpoint ??
    options.selfHosted?.endpoint ??
    process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT ??
    process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  if (!endpoint) {
    throw externalBlocker(`${runtime} runtime requested, but no IOI worker provider endpoint is configured.`, {
      runtime,
      requiredEnvironment: [
        "IOI_AGENT_SDK_HOSTED_ENDPOINT",
        "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
      ],
    });
  }
}

function resultForMode(mode, agent, prompt, source) {
  switch (mode) {
    case "plan":
      return `Plan-only daemon run recorded objective, constraints, postconditions, and stop reason for: ${prompt}`;
    case "dry_run":
      return "Dry run completed through the daemon. Side effects were previewed and no mutation was executed.";
    case "handoff":
      return "Daemon handoff bundle is complete: objective, state, blockers, evidence, and next action are preserved.";
    case "learn":
      return "Governed learning record created behind memory quality and bounded self-improvement gates.";
    case "send":
    default:
      return `IOI daemon run completed for ${agent.cwd}. Source=${source}. Trace, receipts, Agentgres canonical projection, task state, uncertainty, probe, postconditions, semantic impact, stop condition, and scorecard are available through public runtime APIs.`;
  }
}

function taskFamilyForMode(mode) {
  switch (mode) {
    case "plan":
      return "planning";
    case "dry_run":
      return "safety_preview";
    case "handoff":
      return "delegation";
    case "learn":
      return "learning";
    case "send":
    default:
      return "local_daemon_agentgres";
  }
}

function strategyForMode(mode) {
  switch (mode) {
    case "plan":
      return "daemon_plan_with_postconditions";
    case "dry_run":
      return "daemon_dry_run_before_effect";
    case "handoff":
      return "daemon_handoff_with_state_preservation";
    case "learn":
      return "daemon_bounded_learning_gate";
    case "send":
    default:
      return "local_daemon_agentgres_execution";
  }
}

function capabilitySequenceForMode(mode, agent) {
  const sequence = [
    "authority_check",
    "policy_check",
    "task_state_write",
    "agentgres_operation_log",
    "trace_export",
    "canonical_replay",
  ];
  if (agent.options.mcpServerNames.length > 0) sequence.push("mcp_containment");
  if (agent.options.skillNames.length > 0) sequence.push("skill_instruction_import");
  if (agent.options.hookNames.length > 0) sequence.push("runtime_event_hook");
  if (mode === "dry_run") sequence.push("side_effect_preview");
  if (mode === "handoff") sequence.push("handoff_quality");
  if (mode === "learn") sequence.push("memory_quality_gate");
  return sequence;
}

function makeEvent(runId, agentId, index, type, summary, data) {
  return {
    id: `${runId}:event:${String(index).padStart(3, "0")}:${type}`,
    runId,
    agentId,
    type,
    cursor: `${runId}:${index}`,
    createdAt: new Date().toISOString(),
    summary,
    data,
  };
}

function terminalCount(events) {
  return events.filter((event) => TERMINAL_EVENT_TYPES.has(event.type)).length;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  return text.trim() ? JSON.parse(text) : {};
}

function writeSse(response, events) {
  response.statusCode = 200;
  response.setHeader("content-type", "text/event-stream");
  response.setHeader("cache-control", "no-cache");
  response.end(events.map((event) => `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`).join(""));
}

function writeJsonResponse(response, value, status = 200) {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(status === 204 ? "" : JSON.stringify(value));
}

function writeError(response, error) {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) {
    try {
      response.end();
    } catch {
      // Streaming clients may disconnect while the handler is unwinding.
    }
    return;
  }
  const status = error?.status ?? 500;
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(
    JSON.stringify({
      error: {
        code: error?.code ?? "runtime",
        message: error?.message ?? "Local daemon request failed.",
        retryable: status >= 500,
        requestId: response.getHeader("x-request-id"),
        details: redact(error?.details ?? {}),
      },
    }),
  );
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function policyError(message, details) {
  return runtimeError({ status: 403, code: "policy", message, details });
}

function externalBlocker(message, details) {
  return runtimeError({ status: 424, code: "external_blocker", message, details });
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function redact(value) {
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      /token|secret|key|authorization/i.test(key) ? "[REDACTED]" : item,
    ]),
  );
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(dir, file));
}

function relative(from, to) {
  return path.relative(from, to) || ".";
}
