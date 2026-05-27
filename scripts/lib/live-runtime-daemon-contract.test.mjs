import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { promisify } from "node:util";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const execFileAsync = promisify(execFile);
const mcpStdioFixture = path.join(root, "scripts/fixtures/mcp-stdio-echo-server.mjs");
const mcpFixtureTools = [
  {
    name: "query",
    description: "Echo a query argument through a deterministic MCP remote tool.",
    inputSchema: {
      type: "object",
      properties: { q: { type: "string" } },
      required: ["q"],
    },
  },
  {
    name: "fetch",
    description: "Echo a fetch id through a deterministic MCP remote tool.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
    },
  },
];
const mcpFixtureResources = [
  {
    uri: "ioi://fixture/remote-context",
    name: "remote-context",
    description: "Deterministic read-only context exposed by the MCP remote fixture.",
    mimeType: "application/json",
  },
];
const mcpFixturePrompts = [
  {
    name: "remote-brief",
    description: "Build a concise brief for the deterministic MCP remote fixture.",
    arguments: [{ name: "topic", required: true }],
  },
];

function largeMcpFixtureTools(count = 80) {
  return Array.from({ length: count }, (_, index) => {
    const suffix = String(index).padStart(3, "0");
    return {
      name: `large_tool_${suffix}`,
      description: `Large catalog fixture tool ${suffix}.`,
      inputSchema: {
        type: "object",
        properties: {
          value: { type: "string" },
          index: { type: "integer", const: index },
        },
      },
    };
  });
}

async function execFileWithInput(file, args, input, options = {}) {
  const mergedOptions = { maxBuffer: 10 * 1024 * 1024, ...options };
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, mergedOptions, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

async function startMcpRemoteFixtureServer(options = {}) {
  const requiredHeaders = options.requiredHeaders ?? {};
  const fixtureTools = Array.isArray(options.tools) ? options.tools : mcpFixtureTools;
  const observedHeaders = [];
  const sseClients = new Map();
  const recordHeaders = (request, pathLabel) => {
    observedHeaders.push({
      path: pathLabel,
      headers: Object.fromEntries(
        Object.entries(request.headers).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(",") : String(value ?? ""),
        ]),
      ),
    });
  };
  const enforceRequiredHeaders = (request, response, pathLabel) => {
    recordHeaders(request, pathLabel);
    for (const [key, expectedValue] of Object.entries(requiredHeaders)) {
      if (String(request.headers[key.toLowerCase()] ?? "") !== String(expectedValue)) {
        response.writeHead(401, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "missing_required_header", header: key }));
        return false;
      }
    }
    return true;
  };
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method === "GET" && ["/sse", "/secure-sse"].includes(url.pathname)) {
      if (url.pathname === "/secure-sse" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const sessionId = `session_${cryptoRandomSuffix()}`;
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      const messagesPath = url.pathname === "/secure-sse" ? "/secure-messages" : "/messages";
      response.write(`event: endpoint\ndata: ${messagesPath}?sessionId=${sessionId}\n\n`);
      sseClients.set(sessionId, response);
      request.on("close", () => sseClients.delete(sessionId));
      return;
    }
    if (request.method === "POST" && ["/messages", "/secure-messages"].includes(url.pathname)) {
      if (url.pathname === "/secure-messages" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const sessionId = url.searchParams.get("sessionId") ?? "";
      const client = sseClients.get(sessionId);
      const message = JSON.parse(await readRequestBody(request));
      const rpc = mcpFixtureJsonRpcResponse(message, "ioi-fixture-mcp-sse", { tools: fixtureTools });
      response.writeHead(202).end();
      if (client && rpc) {
        client.write(`event: message\ndata: ${JSON.stringify(rpc)}\n\n`);
      }
      return;
    }
    if (request.method === "POST" && ["/mcp", "/secure-mcp"].includes(url.pathname)) {
      if (url.pathname === "/secure-mcp" && !enforceRequiredHeaders(request, response, url.pathname)) {
        return;
      }
      const message = JSON.parse(await readRequestBody(request));
      const rpc = mcpFixtureJsonRpcResponse(message, "ioi-fixture-mcp-http", { tools: fixtureTools });
      if (!rpc) {
        response.writeHead(202).end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify(rpc));
      return;
    }
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found" }));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  return {
    url: `http://${address.address}:${address.port}`,
    observedHeaders: () => observedHeaders.map((entry) => ({ ...entry, headers: { ...entry.headers } })),
    close: () =>
      new Promise((resolve, reject) => {
        for (const client of sseClients.values()) client.end();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

function mcpFixtureJsonRpcResponse(message, serverName, options = {}) {
  const tools = Array.isArray(options.tools) ? options.tools : mcpFixtureTools;
  if (message.method === "notifications/initialized") return null;
  if (message.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {}, resources: {}, prompts: {} },
        serverInfo: { name: serverName, version: "0.1.0" },
      },
    };
  }
  if (message.method === "tools/list") {
    return { jsonrpc: "2.0", id: message.id, result: { tools } };
  }
  if (message.method === "resources/list") {
    return { jsonrpc: "2.0", id: message.id, result: { resources: mcpFixtureResources } };
  }
  if (message.method === "prompts/list") {
    return { jsonrpc: "2.0", id: message.id, result: { prompts: mcpFixturePrompts } };
  }
  if (message.method === "tools/call") {
    const name = message.params?.name ?? "query";
    const args = message.params?.arguments ?? {};
    return {
      jsonrpc: "2.0",
      id: message.id,
      result: {
        content: [{ type: "text", text: `${name}:${args.q ?? args.id ?? args.value ?? ""}` }],
        structuredContent: {
          ok: true,
          server: serverName,
          tool: name,
          arguments: args,
        },
      },
    };
  }
  return {
    jsonrpc: "2.0",
    id: message.id,
    error: { code: -32601, message: `Unsupported method: ${message.method}` },
  };
}

function cryptoRandomSuffix() {
  return Math.random().toString(36).slice(2, 10);
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

async function importSdk() {
  const bundle = path.join(root, "packages/agent-sdk/dist/index.js");
  const sources = [
    "packages/agent-sdk/src/index.ts",
    "packages/agent-sdk/src/messages.ts",
    "packages/agent-sdk/src/runtime-events.ts",
    "packages/agent-sdk/src/substrate-client.ts",
  ].map((file) => path.join(root, file));
  const bundleMtime = fs.existsSync(bundle) ? fs.statSync(bundle).mtimeMs : 0;
  const sourceIsNewer = sources.some(
    (source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > bundleMtime,
  );
  if (!fs.existsSync(bundle) || sourceIsNewer) {
    execFileSync("npm", ["run", "build", "--workspace=@ioi/agent-sdk"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return import("../../packages/agent-sdk/dist/index.js");
}

async function importAgentIde() {
  const bundle = path.join(root, "packages/agent-ide/dist/index.es.js");
  const sources = [
    "packages/agent-ide/src/index.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-policy-stack.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-edit-proposal-policy.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-subflow.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-telemetry-budget-chain-materialization.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-subflow.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-materialization.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-execution.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-terminal-coding-loop-run-launch.ts",
    "packages/agent-ide/src/WorkflowComposer/terminalCodingLoopRunActivation.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-edit-proposal-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-mcp-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-diagnostics-repair-actions.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-subflow.ts",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  ].map((file) => path.join(root, file));
  const bundleMtime = fs.existsSync(bundle) ? fs.statSync(bundle).mtimeMs : 0;
  const sourceIsNewer = sources.some(
    (source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > bundleMtime,
  );
  if (!fs.existsSync(bundle) || sourceIsNewer) {
    execFileSync("npm", ["run", "build", "--workspace=@ioi/agent-ide"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return import(pathToFileURL(bundle).href);
}

async function collect(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

function terminalCount(events) {
  return events.filter((event) => ["completed", "canceled", "failed", "error"].includes(event.type))
    .length;
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}`);
  return response.json();
}

async function fetchSseEvents(url, options = {}) {
  const text = await fetch(url, options).then(async (response) => {
    assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}`);
    return response.text();
  });
  return text
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.replace(/^data:\s?/, ""))
        .join("\n");
      return JSON.parse(data);
    });
}

function workflowProjectionEventsFromDaemonEvents(daemonEvents) {
  return daemonEvents.map((event) => ({
    id: event.event_id,
    seq: event.seq,
    type: event.event_kind === "approval.required"
      ? "approval_required"
      : event.event_kind === "approval.approved" || event.event_kind === "approval.rejected"
        ? "approval_decision"
        : event.event_kind === "workflow.run.retry_completed"
          ? "tool_completed"
          : event.event_kind === "policy.blocked"
            ? "policy_blocked"
            : event.event_kind,
    eventKind: event.event_kind,
    sourceEventKind: event.source_event_kind,
    status: event.status,
    componentKind: event.component_kind,
    workflowNodeId: event.workflow_node_id,
    workflowGraphId: event.workflow_graph_id,
    threadId: event.thread_id,
    turnId: event.turn_id,
    approvalId: event.approval_id,
    payloadSchemaVersion: event.payload_schema_version,
    payload: event.payload_summary ?? event.payload ?? {},
    receiptRefs: event.receipt_refs ?? [],
    policyDecisionRefs: event.policy_decision_refs ?? [],
    artifactRefs: event.artifact_refs ?? [],
    rollbackRefs: event.rollback_refs ?? [],
  }));
}

function canonicalRuntimeEventCursor(event) {
  return `${event.event_stream_id}:${event.seq}`;
}

function operatorControlContractShape(event) {
  return {
    eventKind: event.event_kind,
    sourceEventKind: event.source_event_kind,
    status: event.status,
    componentKind: event.component_kind,
    workflowNodeId: event.workflow_node_id,
    payloadSchemaVersion: event.payload_schema_version,
  };
}

async function fetchTuiJsonEventRow(cli, endpoint, threadId, eventId) {
  const result = await execFileAsync(
    cli,
    [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--since-seq",
      "0",
      "--endpoint",
      endpoint,
      "--json",
    ],
    { cwd: root },
  );
  const payload = JSON.parse(result.stdout);
  const row = payload.event_rows.find((candidate) => candidate.event_id === eventId);
  assert.ok(row, `expected TUI JSON event row for ${eventId}`);
  return row;
}

function assertOperatorControlCrossSurfaceIdentity({
  daemonEvent,
  sdkEvent,
  reactFlowNode,
  tuiRow,
  expected,
}) {
  const cursor = canonicalRuntimeEventCursor(daemonEvent);
  assert.equal(sdkEvent.id, daemonEvent.event_id);
  assert.equal(sdkEvent.cursor, cursor);
  assert.equal(sdkEvent.eventKind, expected.eventKind);
  assert.equal(sdkEvent.sourceEventKind, expected.sourceEventKind);
  assert.equal(sdkEvent.componentKind, expected.componentKind);
  assert.equal(sdkEvent.workflowGraphId, expected.workflowGraphId);
  assert.equal(sdkEvent.workflowNodeId, expected.workflowNodeId);
  assert.equal(sdkEvent.payloadSchemaVersion, expected.payloadSchemaVersion);
  assert.deepEqual(sdkEvent.receiptRefs, daemonEvent.receipt_refs);
  assert.deepEqual(sdkEvent.policyDecisionRefs, daemonEvent.policy_decision_refs);

  assert.equal(reactFlowNode.latestEventId, daemonEvent.event_id);
  assert.equal(reactFlowNode.latestCursor, cursor);
  assert.equal(reactFlowNode.workflowGraphId, expected.workflowGraphId);
  assert.equal(reactFlowNode.workflowNodeId, expected.workflowNodeId);
  assert.equal(reactFlowNode.componentKind, expected.componentKind);
  assert.equal(reactFlowNode.tuiDeepLink.eventId, daemonEvent.event_id);
  assert.equal(reactFlowNode.tuiDeepLink.cursor, cursor);
  assert.equal(reactFlowNode.tuiDeepLink.workflowGraphId, expected.workflowGraphId);
  assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, expected.workflowNodeId);

  assert.equal(tuiRow.event_id, daemonEvent.event_id);
  assert.equal(tuiRow.cursor, cursor);
  assert.equal(tuiRow.thread_id, daemonEvent.thread_id);
  assert.equal(tuiRow.turn_id, daemonEvent.turn_id);
  assert.equal(tuiRow.workflow_graph_id, expected.workflowGraphId);
  assert.equal(tuiRow.workflow_node_id, expected.workflowNodeId);
  assert.equal(tuiRow.event_kind, expected.eventKind);
  assert.equal(tuiRow.source_event_kind, expected.sourceEventKind);
  assert.equal(tuiRow.component_kind, expected.componentKind);
  assert.deepEqual(tuiRow.tui_reopen.args, [
    "agent",
    "tui",
    "--thread-id",
    daemonEvent.thread_id,
    "--since-seq",
    String(daemonEvent.seq),
  ]);
  assert.equal(tuiRow.tui_reopen.last_event_id, daemonEvent.event_id);
}

async function fetchJsonStatus(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
  };
}

function restoreEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function git(cwd, args) {
  return execFileSync("git", ["-C", cwd, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

let cachedRustRuntimeBridgeBinary;
let cachedCliBinary;

function rustRuntimeBridgeBinary() {
  if (cachedRustRuntimeBridgeBinary) return cachedRustRuntimeBridgeBinary;
  if (process.env.IOI_RUNTIME_BRIDGE_RUST_BIN) {
    const configured = process.env.IOI_RUNTIME_BRIDGE_RUST_BIN;
    const binary = path.isAbsolute(configured) ? configured : path.resolve(root, configured);
    assert.ok(fs.existsSync(binary), `IOI_RUNTIME_BRIDGE_RUST_BIN does not exist: ${binary}`);
    cachedRustRuntimeBridgeBinary = binary;
    return binary;
  }

  execFileSync(
    "cargo",
    ["build", "-p", "ioi-node", "--bin", "ioi-runtime-bridge", "--features", "local-mode"],
    {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const binaryName = process.platform === "win32" ? "ioi-runtime-bridge.exe" : "ioi-runtime-bridge";
  const binary = path.join(root, "target", "debug", binaryName);
  assert.ok(fs.existsSync(binary), `expected Rust runtime bridge binary at ${binary}`);
  cachedRustRuntimeBridgeBinary = binary;
  return binary;
}

function cliBinary() {
  if (cachedCliBinary) return cachedCliBinary;
  if (process.env.IOI_CLI_BIN) {
    const configured = process.env.IOI_CLI_BIN;
    const binary = path.isAbsolute(configured) ? configured : path.resolve(root, configured);
    assert.ok(fs.existsSync(binary), `IOI_CLI_BIN does not exist: ${binary}`);
    cachedCliBinary = binary;
    return binary;
  }

  execFileSync("cargo", ["build", "-p", "ioi-cli", "--bin", "cli"], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const binaryName = process.platform === "win32" ? "cli.exe" : "cli";
  const binary = path.join(root, "target", "debug", binaryName);
  assert.ok(fs.existsSync(binary), `expected CLI binary at ${binary}`);
  cachedCliBinary = binary;
  return binary;
}

test("local daemon public API persists canonical Agentgres state and replays without terminal duplication", async () => {
  const { Agent, Cursor, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    const run = await agent.send(
      "Create a local SDK run, cancel it, reconnect, and prove no terminal event was duplicated.",
    );
    const firstBatch = [];
    for await (const event of run.stream()) {
      firstBatch.push(event);
      if (firstBatch.length === 4) break;
    }
    const resumed = await collect(run.stream({ lastEventId: firstBatch.at(-1).id }));
    assert.equal(terminalCount([...firstBatch, ...resumed]), 1);

    const canceled = await run.cancel();
    const canceledReplay = await collect(canceled.replay());
    assert.equal(await canceled.status(), "canceled");
    assert.equal(terminalCount(canceledReplay), 1);
    assert.equal(canceledReplay.at(-1)?.type, "canceled");

    const trace = await canceled.trace();
    assert.equal(trace.canonicalState.source, "agentgres_canonical_operation_log");
    assert.equal(trace.runtimeTask.schemaVersion, "ioi.agent-runtime.task-record.v1");
    assert.equal(trace.runtimeTask.object, "ioi.runtime_task");
    assert.equal(trace.runtimeTask.runId, run.id);
    assert.equal(trace.runtimeTask.status, "canceled");
    assert.equal(trace.runtimeTask.promptIncluded, false);
    assert.equal(trace.runtimeTask.durable, true);
    assert.equal(trace.runtimeTask.replayable, true);
    assert.equal(trace.runtimeJob.schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(trace.runtimeJob.object, "ioi.runtime_job");
    assert.equal(trace.runtimeJob.runId, run.id);
    assert.equal(trace.runtimeJob.taskId, trace.runtimeTask.taskId);
    assert.equal(trace.runtimeJob.status, "canceled");
    assert.deepEqual(trace.runtimeJob.lifecycle, ["queued", "started", "canceled"]);
    assert.equal(trace.runtimeJob.queueName, "local-agentgres");
    assert.equal(trace.runtimeJob.durable, true);
    assert.equal(trace.runtimeJob.replayable, true);
    assert.equal(trace.runtimeChecklist.schemaVersion, "ioi.agent-runtime.checklist-record.v1");
    assert.equal(trace.runtimeChecklist.object, "ioi.runtime_checklist");
    assert.equal(trace.runtimeChecklist.runId, run.id);
    assert.equal(trace.runtimeChecklist.taskId, trace.runtimeTask.taskId);
    assert.equal(trace.runtimeChecklist.jobId, trace.runtimeJob.jobId);
    assert.equal(trace.runtimeChecklist.status, "canceled");
    assert.ok(trace.runtimeChecklist.itemCount >= 6);
    assert.ok(trace.runtimeChecklist.items.some((item) => item.itemId.endsWith(":job_terminal") && item.status === "canceled"));
    assert.equal(trace.runtimeChecklist.durable, true);
    assert.equal(trace.runtimeChecklist.replayable, true);
    assert.equal(trace.runtimeChecklist.readOnly, true);
    assert.equal(trace.runtimeJob.checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(trace.runtimeJob.checklistStatus, "canceled");
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "agentgres_canonical_write"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_task"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_job"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_checklist"));
    assert.equal((await canceled.scorecard()).verifierIndependence, 1);
    const canceledArtifacts = await canceled.artifacts();
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-task.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-job.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-checklist.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "agentgres-projection.json"));

    const operationLog = path.join(stateDir, "operation-log.jsonl");
    assert.ok(fs.existsSync(operationLog));
    assert.ok(fs.readFileSync(operationLog, "utf8").includes("run.cancel"));
    for (const relative of [
      ["runs", `${run.id}.json`],
      ["tasks", `${run.id}.json`],
      ["jobs", trace.runtimeJob.jobId + ".json"],
      ["checklists", trace.runtimeChecklist.checklistId + ".json"],
      ["scorecards", `${run.id}.json`],
      ["ledgers", `${run.id}.json`],
      ["projections", `${run.id}.json`],
    ]) {
      assert.ok(fs.existsSync(path.join(stateDir, ...relative)), relative.join("/"));
    }

    const models = await Cursor.models.list({ substrateClient: client });
    assert.equal(models.at(0)?.provider, "ioi-daemon-local");
    const account = await Cursor.account.get({ substrateClient: client });
    assert.equal(account.source, "ioi-daemon-agentgres");
    const nodes = await Cursor.runtimeNodes.list({ substrateClient: client });
    assert.ok(nodes.some((node) => node.id === "local-daemon-agentgres"));

    const jobs = await fetchJson(`${daemon.endpoint}/v1/jobs`);
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(jobs[0].jobId, trace.runtimeJob.jobId);
    assert.equal(jobs[0].taskId, trace.runtimeTask.taskId);
    assert.equal(jobs[0].status, "canceled");
    assert.equal(jobs[0].checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(jobs[0].checklistStatus, "canceled");
    assert.equal(jobs[0].endpoints.self, `/v1/jobs/${jobs[0].jobId}`);
    assert.equal(jobs[0].endpoints.cancel, `/v1/jobs/${jobs[0].jobId}/cancel`);
    const job = await fetchJson(`${daemon.endpoint}/v1/jobs/${jobs[0].jobId}`);
    assert.equal(job.jobId, jobs[0].jobId);
    assert.equal(job.runId, run.id);
    const sdkJobs = await client.listJobs({ agentId: run.agentId });
    assert.equal(sdkJobs.length, 1);
    assert.equal(sdkJobs[0].jobId, jobs[0].jobId);
    assert.equal(sdkJobs[0].runId, run.id);
    assert.equal((await client.getJob(jobs[0].jobId)).jobId, jobs[0].jobId);
    const tasks = await fetchJson(`${daemon.endpoint}/v1/tasks`);
    assert.equal(tasks.length, 1);
    assert.equal(tasks[0].schemaVersion, "ioi.agent-runtime.task-record.v1");
    assert.equal(tasks[0].object, "ioi.runtime_task");
    assert.equal(tasks[0].taskId, trace.runtimeTask.taskId);
    assert.equal(tasks[0].runId, run.id);
    assert.equal(tasks[0].status, "canceled");
    assert.equal(tasks[0].promptIncluded, false);
    assert.equal(tasks[0].endpoints.self, `/v1/tasks/${tasks[0].taskId}`);
    assert.equal(tasks[0].endpoints.cancel, `/v1/tasks/${tasks[0].taskId}/cancel`);
    assert.equal(tasks[0].endpoints.job, `/v1/jobs/${jobs[0].jobId}`);
    const task = await fetchJson(`${daemon.endpoint}/v1/tasks/${tasks[0].taskId}`);
    assert.equal(task.taskId, tasks[0].taskId);
    assert.equal(task.runId, run.id);
    const sdkTasks = await client.listTasks({ agentId: run.agentId });
    assert.equal(sdkTasks.length, 1);
    assert.equal(sdkTasks[0].taskId, tasks[0].taskId);
    assert.equal(sdkTasks[0].runId, run.id);
    assert.equal((await client.getTask(tasks[0].taskId)).taskId, tasks[0].taskId);
    const jobCancel = await fetchJson(`${daemon.endpoint}/v1/jobs/${jobs[0].jobId}/cancel`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(jobCancel.jobId, jobs[0].jobId);
    assert.equal(jobCancel.status, "canceled");
    assert.deepEqual(jobCancel.lifecycle, ["queued", "started", "canceled"]);
    assert.equal(jobCancel.cancellation.reason, "operator_cancel");
    const sdkJobCancel = await client.cancelJob(jobs[0].jobId);
    assert.equal(sdkJobCancel.jobId, jobs[0].jobId);
    assert.equal(sdkJobCancel.status, "canceled");
    const taskCancel = await fetchJson(`${daemon.endpoint}/v1/tasks/${tasks[0].taskId}/cancel`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(taskCancel.taskId, tasks[0].taskId);
    assert.equal(taskCancel.status, "canceled");
    const sdkTaskCancel = await client.cancelTask(tasks[0].taskId);
    assert.equal(sdkTaskCancel.taskId, tasks[0].taskId);
    assert.equal(sdkTaskCancel.status, "canceled");
    assert.equal(jobCancel.checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(jobCancel.checklistStatus, "canceled");
    const traceAfterJobCancel = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/trace`);
    assert.equal(terminalCount(traceAfterJobCancel.events), 1);
    assert.equal(traceAfterJobCancel.events.at(-1)?.type, "canceled");
    const threadId = `thread_${agent.id.slice("agent_".length)}`;
    const threadEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`);
    const runtimeTaskEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "RuntimeTaskRecord");
    assert.ok(runtimeTaskEvent);
    assert.equal(runtimeTaskEvent.component_kind, "runtime_task");
    assert.equal(runtimeTaskEvent.workflow_node_id, "runtime.runtime-task");
    assert.equal(runtimeTaskEvent.payload_summary.prompt_included, false);
    assert.ok(runtimeTaskEvent.artifact_refs.includes("runtime-task.json"));
    const runtimeChecklistEvent = threadEvents
      .filter((event) => event.payload_summary?.event_kind === "RuntimeChecklistRecord")
      .at(-1);
    assert.ok(runtimeChecklistEvent);
    assert.equal(runtimeChecklistEvent.component_kind, "runtime_checklist");
    assert.equal(runtimeChecklistEvent.workflow_node_id, "runtime.runtime-checklist");
    assert.ok(["completed", "canceled"].includes(runtimeChecklistEvent.payload_summary.status));
    assert.ok(runtimeChecklistEvent.artifact_refs.includes("runtime-checklist.json"));
    const jobQueuedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobQueued");
    const jobStartedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobStarted");
    const jobCompletedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobCompleted");
    const jobCanceledEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobCanceled");
    assert.ok(jobQueuedEvent);
    assert.ok(jobStartedEvent);
    assert.ok(jobCanceledEvent);
    if (jobCompletedEvent) assert.ok(jobCompletedEvent.seq < jobCanceledEvent.seq);
    assert.equal(jobQueuedEvent.component_kind, "runtime_job");
    assert.equal(jobStartedEvent.workflow_node_id, "runtime.runtime-job");
    assert.equal(jobCanceledEvent.payload_summary.lifecycle_status, "canceled");
    assert.ok(jobCanceledEvent.artifact_refs.includes("runtime-job.json"));

    const cliView = await fetch(`${daemon.endpoint}/v1/runs/${run.id}/trace`).then((response) =>
      response.json(),
    );
    assert.equal(cliView.canonicalState.runId, run.id);
    assert.equal(cliView.canonicalState.terminalState, "canceled");
  } finally {
    await daemon.close();
  }
});

test("local daemon doctor reports redacted runtime readiness for CLI and workflow activation", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-doctor-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-doctor-agentgres-state-"));
  const savedOpenAi = process.env.OPENAI_API_KEY;
  const savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  process.env.OPENAI_API_KEY = "sk-doctor-secret-do-not-print";
  process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = "https://doctor-secret.example";
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const report = await fetchJson(`${daemon.endpoint}/v1/doctor`);
    assert.equal(report.schemaVersion, "ioi.agent-runtime.doctor.v1");
    assert.equal(report.object, "ioi.agent_runtime_doctor_report");
    assert.equal(report.readiness, "ready");
    assert.ok(["pass", "degraded"].includes(report.status));
    assert.deepEqual(report.blockers, []);
    assert.equal(report.redaction.secretValuesIncluded, false);
    assert.equal(report.redaction.endpointValuesHashed, true);
    assert.equal(report.workflow.doctorNodeType, "runtime_doctor");
    assert.equal(report.workflow.activationConsumesDoctorReport, true);
    assert.ok(report.checks.some((check) => check.id === "daemon.public_api" && check.status === "pass"));
    assert.ok(report.checks.every((check) => !check.required || check.status === "pass"));
    const openAiKey = report.providerKeys.find((key) => key.name === "OPENAI_API_KEY");
    assert.equal(openAiKey.configured, true);
    assert.equal(openAiKey.valueRedacted, true);
    assert.match(openAiKey.valueHash, /^[a-f0-9]{64}$/);
    const hostedNode = report.runtimeNodes.find((node) => node.id === "hosted-provider");
    assert.equal(hostedNode.endpointConfigured, true);
    assert.match(hostedNode.endpointHash, /^[a-f0-9]{64}$/);
    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes("sk-doctor-secret-do-not-print"));
    assert.ok(!serialized.includes("https://doctor-secret.example"));
  } finally {
    await daemon.close();
    if (savedOpenAi === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = savedOpenAi;
    if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
  }
});

test("local daemon exposes compact authority evidence summaries without trace payload leakage", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-authority-evidence-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-authority-evidence-state-"));
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Record a blocked workflow capability preflight.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.local-first" } },
      }),
    });
    daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: "",
      item_id: `${thread.thread_id}:item:authority-evidence-preflight`,
      idempotency_key: `${thread.thread_id}:authority-evidence-preflight`,
      source: "daemon_bridge",
      source_event_kind: "WorkflowRunCapabilityPreflightBlocked",
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: cwd,
      workflow_graph_id: "workflow.authority-evidence-proof",
      workflow_node_id: "runtime.workflow-capability-preflight",
      component_kind: "capability_preflight",
      payload_schema_version: "ioi.workflow.capability-preflight.v1",
      payload: {
        eventKind: "WorkflowRunCapabilityPreflightBlocked",
        reason: "workflow_capability_preflight_blocked",
        runId: "workflow-run-policy-authority-proof",
        summary: "Workflow run blocked by capability readiness preflight.",
        rows: [
          {
            nodeId: "model-node",
            nodeType: "agent_step",
            bindingKind: "model_capability",
            capabilityRef: "model-capability:route.local-first",
            routeId: "route.local-first",
            authorityScopeRequirements: ["model.chat:*"],
            receiptRefs: ["receipt_model_capability_row"],
            policyDecisionRefs: ["policy_model_capability_row"],
          },
          {
            nodeId: "tool-node",
            nodeType: "tool_pack",
            bindingKind: "tool_capability",
            capabilityRef: "tool-capability:filesystem.write",
            authorityScopeRequirements: ["filesystem.write"],
            receiptRefs: ["receipt_tool_capability_row"],
          },
        ],
        rawPayload: "sk-authorityevidenceshouldnotescape123456",
        runtimeThreadEvents: [
          {
            receiptRefs: ["receipt_trace_surface_must_not_escape"],
            payload: "ghp_tracepayloadshouldnotescape123456",
          },
        ],
      },
      receipt_refs: ["receipt_workflow_run_capability_preflight_authority_proof"],
      policy_decision_refs: ["policy_workflow_run_capability_preflight_blocked_authority_proof"],
      artifact_refs: [],
      rollback_refs: [],
    });

    const evidence = await fetchJson(`${daemon.endpoint}/api/v1/authority-evidence`);
    assert.equal(evidence.schemaVersion, "ioi.authority-evidence-summary-list.v1");
    assert.equal(evidence.rowCount, 2);
    assert.deepEqual(
      evidence.items.map((row) => row.capabilityRef).sort(),
      [
        "model-capability:route.local-first",
        "tool-capability:filesystem.write",
      ],
    );
    const modelRow = evidence.items.find(
      (row) => row.capabilityRef === "model-capability:route.local-first",
    );
    assert.equal(modelRow.routeId, "route.local-first");
    assert.deepEqual(modelRow.authorityScopeRequirements, ["model.chat:*"]);
    assert.ok(
      modelRow.receiptRefs.includes(
        "receipt_workflow_run_capability_preflight_authority_proof",
      ),
    );
    assert.ok(modelRow.receiptRefs.includes("receipt_model_capability_row"));
    assert.ok(
      modelRow.policyDecisionRefs.includes(
        "policy_workflow_run_capability_preflight_blocked_authority_proof",
      ),
    );
    assert.ok(modelRow.policyDecisionRefs.includes("policy_model_capability_row"));
    assert.equal(JSON.stringify(evidence).includes("sk-authorityevidence"), false);
    assert.equal(JSON.stringify(evidence).includes("tracepayloadshouldnotescape"), false);
    assert.equal(
      JSON.stringify(evidence).includes("receipt_trace_surface_must_not_escape"),
      false,
    );

    const filtered = await fetchJson(
      `${daemon.endpoint}/api/v1/authority-evidence?capability_ref=${encodeURIComponent(
        "tool-capability:filesystem.write",
      )}`,
    );
    assert.equal(filtered.rowCount, 1);
    assert.equal(filtered.items[0].capabilityRef, "tool-capability:filesystem.write");
  } finally {
    if (daemon) await daemon.close();
  }
});

test("local daemon emits read-only repository context for Git workspaces", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-repository-context-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-repository-context-state-"));
  const savedGithubToken = process.env.GITHUB_TOKEN;
  const savedGhToken = process.env.GH_TOKEN;
  process.env.GITHUB_TOKEN = "ghp-secret-do-not-print";
  delete process.env.GH_TOKEN;
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "ioi-test@example.invalid"]);
  git(cwd, ["config", "user.name", "IOI Test"]);
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "one\n");
  git(cwd, ["add", "tracked.txt"]);
  git(cwd, ["commit", "-m", "initial"]);
  const branch = git(cwd, ["branch", "--show-current"]);
  git(cwd, ["remote", "add", "origin", "https://user:secret@github.com/ioi-test/ioi.git"]);
  git(cwd, ["update-ref", `refs/remotes/origin/${branch}`, "HEAD"]);
  git(cwd, ["symbolic-ref", "refs/remotes/origin/HEAD", `refs/remotes/origin/${branch}`]);
  git(cwd, ["branch", "--set-upstream-to", `origin/${branch}`]);
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "two\n");
  fs.writeFileSync(path.join(cwd, "staged.txt"), "staged\n");
  git(cwd, ["add", "staged.txt"]);
  fs.writeFileSync(path.join(cwd, "untracked.txt"), "new\n");

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const repositoryContext = await fetchJson(`${daemon.endpoint}/v1/repository-context`);
    assert.equal(repositoryContext.schemaVersion, "ioi.agent-runtime.repository-context.v1");
    assert.equal(repositoryContext.object, "ioi.repository_context");
    assert.equal(repositoryContext.isGitRepository, true);
    assert.equal(repositoryContext.repoRoot, cwd);
    assert.equal(repositoryContext.branch, branch);
    assert.equal(repositoryContext.defaultBranch, branch);
    assert.match(repositoryContext.headSha, /^[a-f0-9]{40}$/);
    assert.equal(repositoryContext.upstream, `origin/${branch}`);
    assert.equal(repositoryContext.remoteCount, 1);
    assert.equal(repositoryContext.remotes[0].fetchUrl, "https://github.com/ioi-test/ioi.git");
    assert.match(repositoryContext.remotes[0].fetchUrlHash, /^[a-f0-9]{64}$/);
    assert.equal(repositoryContext.remotes[0].provider, "github");
    assert.equal(repositoryContext.remotes[0].host, "github.com");
    assert.equal(repositoryContext.remotes[0].owner, "ioi-test");
    assert.equal(repositoryContext.remotes[0].repo, "ioi");
    assert.equal(repositoryContext.remotes[0].repoFullName, "ioi-test/ioi");
    assert.equal(repositoryContext.status.isDirty, true);
    assert.equal(repositoryContext.status.counts.staged, 1);
    assert.equal(repositoryContext.status.counts.unstaged, 1);
    assert.equal(repositoryContext.status.counts.untracked, 1);
    assert.equal(repositoryContext.readOnly, true);
    assert.equal(repositoryContext.mutationExecuted, false);
    assert.equal(repositoryContext.redaction.remoteCredentialsIncluded, false);

    const repositories = await fetchJson(`${daemon.endpoint}/v1/repositories`);
    assert.equal(repositories[0].contextId, repositoryContext.contextId);
    assert.equal(repositories[0].branch, branch);
    assert.equal(repositories[0].isDirty, true);

    const branchPolicy = await fetchJson(`${daemon.endpoint}/v1/branch-policy`);
    assert.equal(branchPolicy.schemaVersion, "ioi.agent-runtime.branch-policy.v1");
    assert.equal(branchPolicy.object, "ioi.branch_policy_decision");
    assert.equal(branchPolicy.repositoryContextId, repositoryContext.contextId);
    assert.equal(branchPolicy.status, "blocked");
    assert.equal(branchPolicy.branch, branch);
    assert.equal(branchPolicy.defaultBranch, branch);
    assert.equal(branchPolicy.protectedBranch, true);
    assert.equal(branchPolicy.dirty, true);
    assert.equal(branchPolicy.readOnly, true);
    assert.equal(branchPolicy.mutationExecuted, false);
    assert.equal(branchPolicy.mutationAllowed, false);
    assert.equal(branchPolicy.prCreationAllowed, false);
    assert.ok(branchPolicy.blockers.includes("protected_branch"));
    assert.ok(branchPolicy.warnings.includes("dirty_worktree"));
    assert.ok(branchPolicy.warnings.includes("untracked_files"));

    const githubContext = await fetchJson(`${daemon.endpoint}/v1/github-context`);
    assert.equal(githubContext.schemaVersion, "ioi.agent-runtime.github-context.v1");
    assert.equal(githubContext.object, "ioi.github_context");
    assert.equal(githubContext.repositoryContextId, repositoryContext.contextId);
    assert.equal(githubContext.branchPolicyId, branchPolicy.policyId);
    assert.equal(githubContext.status, "blocked");
    assert.equal(githubContext.githubRemotePresent, true);
    assert.equal(githubContext.defaultRemoteName, "origin");
    assert.equal(githubContext.owner, "ioi-test");
    assert.equal(githubContext.repo, "ioi");
    assert.equal(githubContext.repoFullName, "ioi-test/ioi");
    assert.equal(githubContext.htmlUrl, "https://github.com/ioi-test/ioi");
    assert.equal(githubContext.branchPolicyStatus, "blocked");
    assert.equal(githubContext.prCreationEligible, false);
    assert.equal(githubContext.prCreationPreconditions.githubRemotePresent, true);
    assert.equal(githubContext.prCreationPreconditions.branchPolicyAllowsPr, false);
    assert.equal(githubContext.prCreationPreconditions.tokenAvailable, true);
    assert.equal(githubContext.prCreationPreconditions.networkLookupPerformed, false);
    assert.equal(githubContext.prCreationPreconditions.mutationExecuted, false);
    assert.equal(githubContext.credentials.tokenAvailable, true);
    assert.deepEqual(githubContext.credentials.tokenSources, ["GITHUB_TOKEN"]);
    assert.equal(githubContext.credentials.tokenValueIncluded, false);
    assert.equal(githubContext.networkLookupPerformed, false);
    assert.equal(githubContext.mutationExecuted, false);

    const issueContext = await fetchJson(`${daemon.endpoint}/v1/issue-context`);
    assert.equal(issueContext.schemaVersion, "ioi.agent-runtime.issue-context.v1");
    assert.equal(issueContext.object, "ioi.issue_context");
    assert.equal(issueContext.repositoryContextId, repositoryContext.contextId);
    assert.equal(issueContext.githubContextId, githubContext.contextId);
    assert.equal(issueContext.status, "unbound");
    assert.equal(issueContext.repoFullName, "ioi-test/ioi");
    assert.equal(issueContext.bound, false);
    assert.equal(issueContext.issueProvided, false);
    assert.equal(issueContext.issueNumber, null);
    assert.equal(issueContext.title, null);
    assert.equal(issueContext.sourceUrl, null);
    assert.equal(issueContext.sourceKind, "unbound");
    assert.ok(issueContext.warnings.includes("issue_context_unbound"));
    assert.equal(issueContext.noIssuePolicy.allowed, true);
    assert.equal(issueContext.networkLookupPerformed, false);
    assert.equal(issueContext.mutationExecuted, false);
    assert.equal(issueContext.redaction.bodyIncluded, false);

    const prAttempts = await fetchJson(`${daemon.endpoint}/v1/pr-attempts`);
    assert.equal(prAttempts.length, 1);
    const prAttempt = prAttempts[0];
    assert.equal(prAttempt.schemaVersion, "ioi.agent-runtime.pr-attempt.v1");
    assert.equal(prAttempt.object, "ioi.pr_attempt");
    assert.equal(issueContext.prAttemptId, prAttempt.attemptId);
    assert.equal(prAttempt.repositoryContextId, repositoryContext.contextId);
    assert.equal(prAttempt.branchPolicyId, branchPolicy.policyId);
    assert.equal(prAttempt.githubContextId, githubContext.contextId);
    assert.equal(prAttempt.status, "blocked");
    assert.equal(prAttempt.outcome, "failed_precondition");
    assert.equal(prAttempt.repoFullName, "ioi-test/ioi");
    assert.equal(prAttempt.branch, branch);
    assert.equal(prAttempt.defaultBranch, branch);
    assert.match(prAttempt.headSha, /^[a-f0-9]{40}$/);
    assert.deepEqual(prAttempt.authority.requiredScopes, ["github.pr.create"]);
    assert.deepEqual(prAttempt.authority.missingScopes, ["github.pr.create"]);
    assert.equal(prAttempt.authority.scopeGranted, false);
    assert.equal(prAttempt.preconditions.githubRemotePresent, true);
    assert.equal(prAttempt.preconditions.branchPolicyAllowsPr, false);
    assert.equal(prAttempt.preconditions.tokenAvailable, true);
    assert.equal(prAttempt.preconditions.branchArtifactAttached, true);
    assert.equal(prAttempt.preconditions.diffArtifactAttached, true);
    assert.equal(prAttempt.preconditions.networkLookupPerformed, false);
    assert.equal(prAttempt.preconditions.mutationExecuted, false);
    assert.ok(prAttempt.blockers.includes("protected_branch"));
    assert.ok(prAttempt.blockers.includes("branch_policy_not_passed"));
    assert.ok(prAttempt.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(prAttempt.previewOnly, true);
    assert.equal(prAttempt.mutationAttempted, false);
    assert.equal(prAttempt.mutationExecuted, false);
    assert.equal(prAttempt.networkLookupPerformed, false);
    assert.equal(prAttempt.branchArtifact.artifactName, "pr-branch.json");
    assert.equal(prAttempt.diffArtifact.artifactName, "pr-diff.patch");
    assert.equal(prAttempt.diffArtifact.hasDiff, true);
    assert.ok(prAttempt.diffArtifact.fileCount >= 1);
    assert.equal(prAttempt.redaction.diffContentInProjection, false);

    const reviewGate = await fetchJson(`${daemon.endpoint}/v1/review-gate`);
    assert.equal(reviewGate.schemaVersion, "ioi.agent-runtime.review-gate.v1");
    assert.equal(reviewGate.object, "ioi.review_gate_decision");
    assert.equal(issueContext.reviewGateId, reviewGate.gateId);
    assert.equal(reviewGate.repositoryContextId, repositoryContext.contextId);
    assert.equal(reviewGate.branchPolicyId, branchPolicy.policyId);
    assert.equal(reviewGate.githubContextId, githubContext.contextId);
    assert.equal(reviewGate.prAttemptId, prAttempt.attemptId);
    assert.equal(reviewGate.status, "blocked");
    assert.equal(reviewGate.decision, "blocked");
    assert.equal(reviewGate.repoFullName, "ioi-test/ioi");
    assert.equal(reviewGate.branch, branch);
    assert.equal(reviewGate.defaultBranch, branch);
    assert.equal(reviewGate.reviewRequired, true);
    assert.equal(reviewGate.reviewSatisfied, false);
    assert.equal(reviewGate.approvalRequired, true);
    assert.equal(reviewGate.approvalSatisfied, false);
    assert.deepEqual(reviewGate.requiredReviewers, ["code-owner"]);
    assert.ok(reviewGate.requiredChecks.includes("human_review_satisfied"));
    assert.ok(reviewGate.blockers.includes("review_not_satisfied"));
    assert.ok(reviewGate.blockers.includes("pr_attempt_not_ready"));
    assert.ok(reviewGate.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(reviewGate.preconditions.prAttemptReady, false);
    assert.equal(reviewGate.preconditions.diffArtifactAttached, true);
    assert.equal(reviewGate.preconditions.reviewPolicySatisfied, false);
    assert.equal(reviewGate.preconditions.networkLookupPerformed, false);
    assert.equal(reviewGate.preconditions.mutationExecuted, false);
    assert.equal(reviewGate.mutationAllowed, false);
    assert.equal(reviewGate.prCreationAllowed, false);
    assert.equal(reviewGate.mutationExecuted, false);
    assert.equal(reviewGate.networkLookupPerformed, false);

    const githubPrCreatePlan = await fetchJson(`${daemon.endpoint}/v1/github/pr-create-plan`);
    assert.equal(githubPrCreatePlan.schemaVersion, "ioi.agent-runtime.github-pr-create-plan.v1");
    assert.equal(githubPrCreatePlan.object, "ioi.github_pr_create_plan");
    assert.equal(githubPrCreatePlan.repositoryContextId, repositoryContext.contextId);
    assert.equal(githubPrCreatePlan.branchPolicyId, branchPolicy.policyId);
    assert.equal(githubPrCreatePlan.githubContextId, githubContext.contextId);
    assert.equal(githubPrCreatePlan.issueContextId, issueContext.contextId);
    assert.equal(githubPrCreatePlan.prAttemptId, prAttempt.attemptId);
    assert.equal(githubPrCreatePlan.reviewGateId, reviewGate.gateId);
    assert.equal(githubPrCreatePlan.status, "blocked");
    assert.equal(githubPrCreatePlan.decision, "blocked");
    assert.equal(githubPrCreatePlan.dryRun, true);
    assert.equal(githubPrCreatePlan.previewOnly, true);
    assert.equal(githubPrCreatePlan.toolName, "github__pr_create");
    assert.equal(githubPrCreatePlan.action, "pr_create");
    assert.equal(githubPrCreatePlan.repoFullName, "ioi-test/ioi");
    assert.equal(githubPrCreatePlan.baseBranch, branch);
    assert.equal(githubPrCreatePlan.headBranch, branch);
    assert.equal(githubPrCreatePlan.issueNumber, null);
    assert.equal(githubPrCreatePlan.reviewGateStatus, "blocked");
    assert.equal(githubPrCreatePlan.reviewSatisfied, false);
    assert.equal(githubPrCreatePlan.bodyPlan.included, false);
    assert.equal(githubPrCreatePlan.request.method, "POST");
    assert.equal(githubPrCreatePlan.request.path, "/repos/ioi-test/ioi/pulls");
    assert.match(githubPrCreatePlan.request.payloadHash, /^[a-f0-9]{64}$/);
    assert.equal(githubPrCreatePlan.request.bodyIncluded, false);
    assert.equal(githubPrCreatePlan.request.tokenIncluded, false);
    assert.deepEqual(githubPrCreatePlan.authority.requiredScopes, ["github.pr.create"]);
    assert.deepEqual(githubPrCreatePlan.authority.missingScopes, ["github.pr.create"]);
    assert.equal(githubPrCreatePlan.authority.scopeGranted, false);
    assert.ok(githubPrCreatePlan.blockers.includes("review_gate_not_passed"));
    assert.ok(githubPrCreatePlan.blockers.includes("review_not_satisfied"));
    assert.ok(githubPrCreatePlan.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.ok(githubPrCreatePlan.blockers.includes("dry_run_only"));
    assert.equal(githubPrCreatePlan.networkLookupPerformed, false);
    assert.equal(githubPrCreatePlan.mutationAttempted, false);
    assert.equal(githubPrCreatePlan.mutationExecuted, false);
    assert.equal(githubPrCreatePlan.redaction.tokenValueIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.authorizationHeaderIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.requestBodyIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.networkResponseIncluded, false);

    const { Agent, createRuntimeSubstrateClient } = await importSdk();
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    const run = await agent.send("Record repository context for branch policy.");
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/trace`);
    assert.equal(trace.repositoryContext.schemaVersion, "ioi.agent-runtime.repository-context.v1");
    assert.equal(trace.repositoryContext.branch, branch);
    assert.equal(trace.repositoryContext.status.counts.staged, 1);
    assert.equal(trace.repositoryContext.status.counts.unstaged, 1);
    assert.equal(trace.repositoryContext.status.counts.untracked, 1);
    assert.equal(trace.repositoryContext.mutationExecuted, false);
    assert.equal(trace.branchPolicy.schemaVersion, "ioi.agent-runtime.branch-policy.v1");
    assert.equal(trace.branchPolicy.repositoryContextId, trace.repositoryContext.contextId);
    assert.equal(trace.branchPolicy.status, "blocked");
    assert.equal(trace.branchPolicy.protectedBranch, true);
    assert.equal(trace.branchPolicy.mutationAllowed, false);
    assert.ok(trace.branchPolicy.blockers.includes("protected_branch"));
    assert.ok(trace.branchPolicy.warnings.includes("dirty_worktree"));
    assert.equal(trace.githubContext.schemaVersion, "ioi.agent-runtime.github-context.v1");
    assert.equal(trace.githubContext.repoFullName, "ioi-test/ioi");
    assert.equal(trace.githubContext.status, "blocked");
    assert.equal(trace.githubContext.prCreationEligible, false);
    assert.equal(trace.issueContext.schemaVersion, "ioi.agent-runtime.issue-context.v1");
    assert.equal(trace.issueContext.status, "unbound");
    assert.equal(trace.issueContext.repoFullName, "ioi-test/ioi");
    assert.equal(trace.issueContext.bound, false);
    assert.equal(trace.issueContext.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.issueContext.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.prAttempt.schemaVersion, "ioi.agent-runtime.pr-attempt.v1");
    assert.equal(trace.prAttempt.repoFullName, "ioi-test/ioi");
    assert.equal(trace.prAttempt.status, "blocked");
    assert.equal(trace.prAttempt.outcome, "failed_precondition");
    assert.equal(trace.prAttempt.mutationExecuted, false);
    assert.equal(trace.prAttempt.branchArtifact.artifactName, "pr-branch.json");
    assert.equal(trace.prAttempt.diffArtifact.artifactName, "pr-diff.patch");
    assert.ok(trace.prAttempt.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(trace.reviewGate.schemaVersion, "ioi.agent-runtime.review-gate.v1");
    assert.equal(trace.reviewGate.status, "blocked");
    assert.equal(trace.reviewGate.decision, "blocked");
    assert.equal(trace.reviewGate.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.reviewGate.reviewRequired, true);
    assert.equal(trace.reviewGate.reviewSatisfied, false);
    assert.ok(trace.reviewGate.blockers.includes("review_not_satisfied"));
    assert.equal(trace.githubPrCreatePlan.schemaVersion, "ioi.agent-runtime.github-pr-create-plan.v1");
    assert.equal(trace.githubPrCreatePlan.status, "blocked");
    assert.equal(trace.githubPrCreatePlan.dryRun, true);
    assert.equal(trace.githubPrCreatePlan.toolName, "github__pr_create");
    assert.equal(trace.githubPrCreatePlan.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.githubPrCreatePlan.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.githubPrCreatePlan.issueContextId, trace.issueContext.contextId);
    assert.match(trace.githubPrCreatePlan.request.payloadHash, /^[a-f0-9]{64}$/);
    assert.equal(trace.githubPrCreatePlan.request.bodyIncluded, false);
    assert.equal(trace.githubPrCreatePlan.request.tokenIncluded, false);
    assert.equal(trace.githubPrCreatePlan.mutationExecuted, false);
    assert.equal(trace.githubPrCreatePlan.networkLookupPerformed, false);
    assert.equal(trace.promptAudit.repositoryContextId, trace.repositoryContext.contextId);
    assert.equal(trace.promptAudit.branchPolicyId, trace.branchPolicy.policyId);
    assert.equal(trace.promptAudit.githubContextId, trace.githubContext.contextId);
    assert.equal(trace.promptAudit.issueContextId, trace.issueContext.contextId);
    assert.equal(trace.promptAudit.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.promptAudit.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.promptAudit.githubPrCreatePlanId, trace.githubPrCreatePlan.planId);
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "repository_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "branch_policy"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "github_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "issue_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "pr_attempt"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "review_gate"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "github_pr_create_plan"));
    const artifacts = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/artifacts`);
    assert.ok(artifacts.some((artifact) => artifact.name === "repository-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "branch-policy.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "github-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "issue-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "pr-attempt.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "pr-branch.json"));
    const prDiffArtifact = artifacts.find((artifact) => artifact.name === "pr-diff.patch");
    assert.ok(prDiffArtifact);
    assert.equal(prDiffArtifact.mediaType, "text/x-diff");
    assert.match(prDiffArtifact.content, /diff --git/);
    assert.ok(artifacts.some((artifact) => artifact.name === "review-gate.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "github-pr-create-plan.json"));

    const threadId = `thread_${agent.id.slice("agent_".length)}`;
    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`);
    const repoEvent = events.find((event) => event.payload_summary?.event_kind === "RepositoryContext");
    assert.ok(repoEvent);
    assert.equal(repoEvent.component_kind, "repository_context");
    assert.equal(repoEvent.workflow_node_id, "runtime.repository-context");
    assert.equal(repoEvent.payload_summary.branch, branch);
    assert.equal(repoEvent.payload_summary.is_git_repository, true);
    assert.equal(repoEvent.payload_summary.is_dirty, true);
    assert.equal(repoEvent.payload_summary.staged_count, 1);
    assert.equal(repoEvent.payload_summary.unstaged_count, 1);
    assert.equal(repoEvent.payload_summary.untracked_count, 1);
    assert.equal(repoEvent.payload_summary.mutation_executed, false);
    assert.ok(repoEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_repository_context")));
    assert.ok(repoEvent.artifact_refs.includes("repository-context.json"));
    const branchPolicyEvent = events.find(
      (event) => event.payload_summary?.event_kind === "BranchPolicyDecision",
    );
    assert.ok(branchPolicyEvent);
    assert.equal(branchPolicyEvent.component_kind, "branch_policy");
    assert.equal(branchPolicyEvent.workflow_node_id, "runtime.branch-policy");
    assert.equal(branchPolicyEvent.payload_summary.status, "blocked");
    assert.equal(branchPolicyEvent.payload_summary.branch, branch);
    assert.equal(branchPolicyEvent.payload_summary.default_branch, branch);
    assert.equal(branchPolicyEvent.payload_summary.protected_branch, true);
    assert.equal(branchPolicyEvent.payload_summary.dirty, true);
    assert.equal(branchPolicyEvent.payload_summary.mutation_allowed, false);
    assert.equal(branchPolicyEvent.payload_summary.pr_creation_allowed, false);
    assert.equal(branchPolicyEvent.payload_summary.review_required, true);
    assert.ok(branchPolicyEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_branch_policy")));
    assert.ok(branchPolicyEvent.artifact_refs.includes("branch-policy.json"));
    const githubContextEvent = events.find(
      (event) => event.payload_summary?.event_kind === "GitHubContext",
    );
    assert.ok(githubContextEvent);
    assert.equal(githubContextEvent.component_kind, "github_context");
    assert.equal(githubContextEvent.workflow_node_id, "runtime.github-context");
    assert.equal(githubContextEvent.payload_summary.status, "blocked");
    assert.equal(githubContextEvent.payload_summary.github_remote_present, true);
    assert.equal(githubContextEvent.payload_summary.default_remote_name, "origin");
    assert.equal(githubContextEvent.payload_summary.owner, "ioi-test");
    assert.equal(githubContextEvent.payload_summary.repo, "ioi");
    assert.equal(githubContextEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(githubContextEvent.payload_summary.branch, branch);
    assert.equal(githubContextEvent.payload_summary.default_branch, branch);
    assert.equal(githubContextEvent.payload_summary.branch_policy_status, "blocked");
    assert.equal(githubContextEvent.payload_summary.token_available, true);
    assert.equal(githubContextEvent.payload_summary.pr_creation_eligible, false);
    assert.equal(githubContextEvent.payload_summary.network_lookup_performed, false);
    assert.equal(githubContextEvent.payload_summary.mutation_executed, false);
    assert.ok(githubContextEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_github_context")));
    assert.ok(githubContextEvent.artifact_refs.includes("github-context.json"));
    const issueContextEvent = events.find(
      (event) => event.payload_summary?.event_kind === "IssueContext",
    );
    assert.ok(issueContextEvent);
    assert.equal(issueContextEvent.component_kind, "issue_context");
    assert.equal(issueContextEvent.workflow_node_id, "runtime.issue-context");
    assert.equal(issueContextEvent.payload_summary.status, "unbound");
    assert.equal(issueContextEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(issueContextEvent.payload_summary.bound, false);
    assert.equal(issueContextEvent.payload_summary.issue_provided, false);
    assert.equal(issueContextEvent.payload_summary.issue_number, null);
    assert.equal(issueContextEvent.payload_summary.source_kind, "unbound");
    assert.equal(issueContextEvent.payload_summary.network_lookup_performed, false);
    assert.equal(issueContextEvent.payload_summary.mutation_executed, false);
    assert.ok(issueContextEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_issue_context")));
    assert.ok(issueContextEvent.artifact_refs.includes("issue-context.json"));
    const prAttemptEvent = events.find(
      (event) => event.payload_summary?.event_kind === "PrAttemptRecord",
    );
    assert.ok(prAttemptEvent);
    assert.equal(prAttemptEvent.component_kind, "pr_attempt");
    assert.equal(prAttemptEvent.workflow_node_id, "runtime.pr-attempt");
    assert.equal(prAttemptEvent.payload_summary.status, "blocked");
    assert.equal(prAttemptEvent.payload_summary.outcome, "failed_precondition");
    assert.equal(prAttemptEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(prAttemptEvent.payload_summary.branch, branch);
    assert.equal(prAttemptEvent.payload_summary.default_branch, branch);
    assert.deepEqual(prAttemptEvent.payload_summary.required_authority_scopes, ["github.pr.create"]);
    assert.deepEqual(prAttemptEvent.payload_summary.missing_authority_scopes, ["github.pr.create"]);
    assert.equal(prAttemptEvent.payload_summary.authority_scope_granted, false);
    assert.equal(prAttemptEvent.payload_summary.branch_artifact_name, "pr-branch.json");
    assert.equal(prAttemptEvent.payload_summary.diff_artifact_name, "pr-diff.patch");
    assert.ok(prAttemptEvent.payload_summary.diff_file_count >= 1);
    assert.equal(prAttemptEvent.payload_summary.mutation_attempted, false);
    assert.equal(prAttemptEvent.payload_summary.mutation_executed, false);
    assert.equal(prAttemptEvent.payload_summary.network_lookup_performed, false);
    assert.ok(prAttemptEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_pr_attempt")));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-attempt.json"));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-branch.json"));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-diff.patch"));
    const reviewGateEvent = events.find(
      (event) => event.payload_summary?.event_kind === "ReviewGateDecision",
    );
    assert.ok(reviewGateEvent);
    assert.equal(reviewGateEvent.component_kind, "review_gate");
    assert.equal(reviewGateEvent.workflow_node_id, "runtime.review-gate");
    assert.equal(reviewGateEvent.payload_summary.status, "blocked");
    assert.equal(reviewGateEvent.payload_summary.decision, "blocked");
    assert.equal(reviewGateEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(reviewGateEvent.payload_summary.branch, branch);
    assert.equal(reviewGateEvent.payload_summary.default_branch, branch);
    assert.equal(reviewGateEvent.payload_summary.review_required, true);
    assert.equal(reviewGateEvent.payload_summary.review_satisfied, false);
    assert.equal(reviewGateEvent.payload_summary.approval_required, true);
    assert.equal(reviewGateEvent.payload_summary.approval_satisfied, false);
    assert.deepEqual(reviewGateEvent.payload_summary.required_reviewers, ["code-owner"]);
    assert.ok(reviewGateEvent.payload_summary.required_checks.includes("human_review_satisfied"));
    assert.equal(reviewGateEvent.payload_summary.mutation_allowed, false);
    assert.equal(reviewGateEvent.payload_summary.pr_creation_allowed, false);
    assert.equal(reviewGateEvent.payload_summary.mutation_executed, false);
    assert.equal(reviewGateEvent.payload_summary.network_lookup_performed, false);
    assert.ok(reviewGateEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_review_gate")));
    assert.ok(reviewGateEvent.artifact_refs.includes("review-gate.json"));
    const githubPrCreatePlanEvent = events.find(
      (event) => event.payload_summary?.event_kind === "GitHubPrCreatePlan",
    );
    assert.ok(githubPrCreatePlanEvent);
    assert.equal(githubPrCreatePlanEvent.component_kind, "github_pr_create");
    assert.equal(githubPrCreatePlanEvent.workflow_node_id, "runtime.github-pr-create");
    assert.equal(githubPrCreatePlanEvent.payload_summary.status, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.decision, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.dry_run, true);
    assert.equal(githubPrCreatePlanEvent.payload_summary.tool_name, "github__pr_create");
    assert.equal(githubPrCreatePlanEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(githubPrCreatePlanEvent.payload_summary.base_branch, branch);
    assert.equal(githubPrCreatePlanEvent.payload_summary.head_branch, branch);
    assert.equal(githubPrCreatePlanEvent.payload_summary.issue_context_id, trace.issueContext.contextId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.pr_attempt_id, trace.prAttempt.attemptId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_gate_id, trace.reviewGate.gateId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_gate_status, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_satisfied, false);
    assert.match(githubPrCreatePlanEvent.payload_summary.request_payload_hash, /^[a-f0-9]{64}$/);
    assert.equal(githubPrCreatePlanEvent.payload_summary.request_body_included, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.request_token_included, false);
    assert.deepEqual(githubPrCreatePlanEvent.payload_summary.required_authority_scopes, ["github.pr.create"]);
    assert.deepEqual(githubPrCreatePlanEvent.payload_summary.missing_authority_scopes, ["github.pr.create"]);
    assert.equal(githubPrCreatePlanEvent.payload_summary.authority_scope_granted, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.mutation_attempted, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.mutation_executed, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.network_lookup_performed, false);
    assert.ok(githubPrCreatePlanEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_github_pr_create_plan")));
    assert.ok(githubPrCreatePlanEvent.artifact_refs.includes("github-pr-create-plan.json"));

    const serializedProjection = JSON.stringify({
      repositoryContext,
      repositories,
      branchPolicy,
      githubContext,
      issueContext,
      prAttempt,
      reviewGate,
      githubPrCreatePlan,
      trace,
      events,
    });
    assert.ok(!serializedProjection.includes("user:secret"));
    assert.ok(!serializedProjection.includes("https://user:secret@github.com"));
    assert.ok(!serializedProjection.includes("Authorization"));
    assert.ok(!serializedProjection.includes("ghp-secret-do-not-print"));
  } finally {
    await daemon.close();
    if (savedGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = savedGithubToken;
    if (savedGhToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = savedGhToken;
  }
});

test("local daemon discovers governed skills and hooks without leaking hook commands", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-hook-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-hook-state-"));
  const cursorSkillDir = path.join(cwd, ".cursor", "skills", "repo-cartographer");
  const agentsDir = path.join(cwd, ".agents");
  fs.mkdirSync(cursorSkillDir, { recursive: true });
  fs.mkdirSync(agentsDir, { recursive: true });
  fs.writeFileSync(
    path.join(cursorSkillDir, "SKILL.md"),
    [
      "---",
      "name: Repo Cartographer",
      "description: Maps likely repo files before edits.",
      "capabilityScopes: repo.read, evidence.read",
      "---",
      "# Repo Cartographer",
      "",
      "Use focused repo discovery before patching.",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(agentsDir, "hooks.json"),
    JSON.stringify(
      {
        "pre-model-redaction": {
          eventKinds: ["pre_model"],
          failurePolicy: "warn",
          authorityScopes: ["runtime.read"],
          command: "echo super-secret-hook",
        },
        "post-tool-ledger": {
          eventKinds: ["post_model", "post_tool"],
          failurePolicy: "block",
          authorityScopes: ["runtime.read"],
          toolContracts: ["hook.preview"],
          command: "echo allowed-hook-secret",
        },
        "workflow-activation-observer": {
          eventKinds: ["workflow_activation"],
          failurePolicy: "warn",
          authorityScopes: ["runtime.read"],
        },
      },
      null,
      2,
    ),
  );
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const skills = await fetchJson(`${daemon.endpoint}/v1/skills`);
    assert.equal(skills.schemaVersion, "ioi.agent-runtime.skills.v1");
    assert.equal(skills.status, "pass");
    assert.equal(skills.skillCount, 1);
    assert.equal(skills.skills[0].name, "Repo Cartographer");
    assert.equal(skills.skills[0].compatibility, "cursor");
    assert.equal(skills.skills[0].hasSkillMd, true);
    assert.deepEqual(skills.skills[0].capabilityScopes, ["repo.read", "evidence.read"]);

    const hooks = await fetchJson(`${daemon.endpoint}/v1/hooks`);
    assert.equal(hooks.schemaVersion, "ioi.agent-runtime.hooks.v1");
    assert.equal(hooks.status, "pass");
    assert.equal(hooks.hookCount, 3);
    const blockedHook = hooks.hooks.find((hook) => hook.name === "pre-model-redaction");
    const dryRunHook = hooks.hooks.find((hook) => hook.name === "post-tool-ledger");
    const observerHook = hooks.hooks.find((hook) => hook.name === "workflow-activation-observer");
    assert.ok(blockedHook);
    assert.ok(dryRunHook);
    assert.ok(observerHook);
    assert.equal(blockedHook.failurePolicy, "warn");
    assert.deepEqual(blockedHook.eventKinds, ["pre_model"]);
    assert.deepEqual(blockedHook.authorityScopes, ["runtime.read"]);
    assert.deepEqual(blockedHook.toolContracts, []);
    assert.equal(blockedHook.commandConfigured, true);
    assert.equal(blockedHook.commandRedacted, true);
    assert.match(blockedHook.commandHash, /^[a-f0-9]{64}$/);
    assert.equal(dryRunHook.failurePolicy, "block");
    assert.deepEqual(dryRunHook.eventKinds, ["post_model", "post_tool"]);
    assert.deepEqual(dryRunHook.authorityScopes, ["runtime.read"]);
    assert.deepEqual(dryRunHook.toolContracts, ["hook.preview"]);
    assert.equal(dryRunHook.commandConfigured, true);
    assert.equal(dryRunHook.commandRedacted, true);
    assert.match(dryRunHook.commandHash, /^[a-f0-9]{64}$/);
    assert.deepEqual(observerHook.eventKinds, ["workflow_activation"]);
    assert.equal(observerHook.commandConfigured, false);

    const doctor = await fetchJson(`${daemon.endpoint}/v1/doctor`);
    const skillHookCheck = doctor.checks.find((check) => check.id === "skills.hooks");
    assert.equal(skillHookCheck.status, "pass");
    assert.equal(doctor.skillsHooks.skillCount, 1);
    assert.equal(doctor.skillsHooks.hookCount, 3);
    assert.ok(!doctor.optionalWarnings.includes("skills.hooks"));
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({ options: { local: { cwd } } }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Use governed skill and hook provenance.", mode: "send" }),
    });
    assert.match(turn.active_skill_hook_manifest_ref, /^skill_hook_manifest_run_/);
    assert.match(turn.active_skill_set_hash, /^[a-f0-9]{64}$/);
    assert.match(turn.active_hook_set_hash, /^[a-f0-9]{64}$/);

    const runId = `run_${turn.turn_id.slice("turn_".length)}`;
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/trace`);
    assert.equal(trace.activeSkillHookManifest.schemaVersion, "ioi.agent-runtime.active-skill-hook-manifest.v1");
    assert.equal(trace.activeSkillHookManifest.selectedSkillIds.length, 1);
    assert.equal(trace.activeSkillHookManifest.selectedHookIds.length, 3);
    assert.equal(trace.activeSkillHookManifest.hookExecution.enabled, false);
    assert.equal(trace.activeSkillHookManifest.hookExecution.mutationBlockedWithoutDeclaredCapabilities, true);
    assert.equal(trace.activeSkillHookManifest.mutationBlockedHookIds.length, 1);
    assert.equal(trace.activeSkillHookManifest.hookExecution.mutationAllowedHookIds.length, 1);
    assert.equal(trace.hookDryRunPlan.schemaVersion, "ioi.agent-runtime.hook-dry-run-plan.v1");
    assert.equal(trace.hookDryRunPlan.decisionCount, 3);
    assert.equal(trace.hookDryRunPlan.wouldRunCount, 1);
    assert.equal(trace.hookDryRunPlan.blockedCount, 1);
    assert.equal(trace.hookDryRunPlan.skippedCount, 1);
    assert.equal(trace.hookDryRunPlan.hookExecutionEnabled, false);
    assert.equal(trace.hookDryRunPlan.commandExecutionEnabled, false);
    assert.equal(trace.hookDryRunPlan.policyDecision.status, "blocked");
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "blocked" &&
          decision.blockers.includes("missing_tool_contract") &&
          decision.execution.commandExecuted === false,
      ),
    );
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "would_run" &&
          decision.toolContracts.includes("hook.preview") &&
          decision.execution.previewOnly === true,
      ),
    );
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "skipped" &&
          decision.reason === "no_command_configured" &&
          decision.execution.commandExecuted === false,
      ),
    );
    assert.equal(trace.hookInvocationLedger.schemaVersion, "ioi.agent-runtime.hook-invocation-ledger.v1");
    assert.equal(trace.hookInvocationLedger.invocationCount, 3);
    assert.equal(trace.hookInvocationLedger.wouldRunCount, 1);
    assert.equal(trace.hookInvocationLedger.blockedCount, 1);
    assert.equal(trace.hookInvocationLedger.skippedCount, 1);
    assert.equal(trace.hookInvocationLedger.escalationCount, 1);
    assert.deepEqual(trace.hookInvocationLedger.emittedEventKinds, [
      "workflow_activation",
      "pre_model",
      "post_model",
    ]);
    const blockedInvocation = trace.hookInvocationLedger.records.find(
      (record) => record.eventKind === "pre_model" && record.state === "blocked",
    );
    assert.ok(blockedInvocation);
    assert.equal(blockedInvocation.escalation.required, true);
    assert.ok(blockedInvocation.escalation.receiptId.endsWith(blockedInvocation.invocationId.slice(-12)));
    assert.deepEqual(blockedInvocation.escalation.missingToolContracts, [
      "declare_at_least_one_tool_contract",
    ]);
    assert.deepEqual(blockedInvocation.escalation.missingAuthorityScopes, []);
    assert.match(blockedInvocation.escalation.recommendedNextAction, /toolContracts/);
    assert.equal(blockedInvocation.escalation.commandExecuted, false);
    assert.equal(trace.hookInvocationLedger.escalations.length, 1);
    assert.equal(
      trace.hookInvocationLedger.escalations[0].receiptId,
      blockedInvocation.escalation.receiptId,
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "pre_model" &&
          record.state === "blocked" &&
          record.blockers.includes("missing_tool_contract"),
      ),
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "post_model" &&
          record.state === "would_run" &&
          record.execution.commandExecuted === false,
      ),
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "workflow_activation" &&
          record.state === "skipped" &&
          record.commandConfigured === false,
      ),
    );
    assert.equal(trace.promptAudit.activeSkillHookManifestId, trace.activeSkillHookManifest.manifestId);
    assert.equal(trace.promptAudit.hookDryRunPlanId, trace.hookDryRunPlan.planId);
    assert.equal(trace.promptAudit.hookInvocationLedgerId, trace.hookInvocationLedger.ledgerId);
    assert.equal(trace.promptAudit.hookExecutionEnabled, false);
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "active_skill_hook_manifest"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_dry_run_plan"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_policy_decision"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_invocation_ledger"),
    );
    const escalationReceipt = trace.receipts.find((receipt) => receipt.kind === "hook_escalation");
    assert.ok(escalationReceipt);
    assert.equal(escalationReceipt.id, blockedInvocation.escalation.receiptId);
    assert.equal(escalationReceipt.details.schemaVersion, "ioi.agent-runtime.hook-escalation-receipt.v1");
    assert.equal(escalationReceipt.details.hookId, blockedInvocation.hookId);
    assert.equal(escalationReceipt.details.eventKind, "pre_model");
    assert.deepEqual(escalationReceipt.details.missingToolContracts, [
      "declare_at_least_one_tool_contract",
    ]);
    assert.equal(escalationReceipt.details.commandExecuted, false);
    assert.equal(escalationReceipt.details.approvalGrantCreated, false);
    const artifacts = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/artifacts`);
    assert.ok(
      artifacts.some((artifact) => artifact.name === "active-skill-hook-manifest.json"),
    );
    assert.ok(
      artifacts.some((artifact) => artifact.name === "hook-dry-run-plan.json"),
    );
    assert.ok(
      artifacts.some((artifact) => artifact.name === "hook-invocations.json"),
    );
    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    const manifestEvent = events.find(
      (event) => event.payload_summary?.event_kind === "ActiveSkillHookManifest",
    );
    assert.equal(manifestEvent.component_kind, "skill_registry");
    assert.equal(manifestEvent.workflow_node_id, "runtime.skill-hook-manifest");
    assert.equal(manifestEvent.payload_summary.selected_skill_count, 1);
    assert.equal(manifestEvent.payload_summary.selected_hook_count, 3);
    assert.equal(manifestEvent.payload_summary.hook_execution_enabled, false);
    assert.ok(manifestEvent.artifact_refs.includes("active-skill-hook-manifest.json"));
    const hookDryRunEvent = events.find(
      (event) => event.payload_summary?.event_kind === "HookDryRunPlan",
    );
    assert.ok(hookDryRunEvent);
    assert.equal(hookDryRunEvent.component_kind, "hook_policy");
    assert.equal(hookDryRunEvent.workflow_node_id, "runtime.hook-policy");
    assert.equal(hookDryRunEvent.payload_summary.decision_count, 3);
    assert.equal(hookDryRunEvent.payload_summary.would_run_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.blocked_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.skipped_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.policy_status, "blocked");
    assert.equal(hookDryRunEvent.payload_summary.command_execution_enabled, false);
    assert.ok(
      hookDryRunEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_dry_run_plan"),
      ),
    );
    assert.ok(
      hookDryRunEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_policy_decision"),
      ),
    );
    assert.ok(hookDryRunEvent.artifact_refs.includes("hook-dry-run-plan.json"));
    const hookInvocationEvent = events.find(
      (event) => event.payload_summary?.event_kind === "HookInvocationLedger",
    );
    assert.ok(hookInvocationEvent);
    assert.equal(hookInvocationEvent.component_kind, "hook_runtime");
    assert.equal(hookInvocationEvent.workflow_node_id, "runtime.hook-invocations");
    assert.equal(hookInvocationEvent.payload_summary.invocation_count, 3);
    assert.equal(hookInvocationEvent.payload_summary.would_run_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.blocked_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.skipped_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.escalation_count, 1);
    assert.deepEqual(hookInvocationEvent.payload_summary.emitted_event_kinds, [
      "workflow_activation",
      "pre_model",
      "post_model",
    ]);
    assert.ok(
      hookInvocationEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_invocation_ledger"),
      ),
    );
    assert.ok(hookInvocationEvent.receipt_refs.includes(escalationReceipt.id));
    assert.ok(hookInvocationEvent.artifact_refs.includes("hook-invocations.json"));
    const serializedProjection = JSON.stringify({ skills, hooks, doctor, turn, trace, events });
    assert.ok(!serializedProjection.includes("super-secret-hook"));
    assert.ok(!serializedProjection.includes("allowed-hook-secret"));
  } finally {
    await daemon.close();
  }
});

test("local daemon projects Agentgres runs through thread, turn, and monotonic event records", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-tti-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-tti-agentgres-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          model: {
            id: "auto",
            routeId: "route.native-local",
            reasoningEffort: "low",
            workflowGraphId: "tti-parity",
            workflowNodeId: "workflow.model-router",
            workflowNodeType: "Model Router",
          },
        },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.match(thread.thread_id, /^thread_/);
    assert.match(thread.session_id, /^agent_/);
    assert.equal(thread.agent_id, thread.session_id);
    assert.equal(thread.event_stream_id, `${thread.thread_id}:events`);
    assert.equal(thread.latest_seq, 1);
    assert.equal(thread.workspace_root, cwd);
    assert.equal(thread.workspace, cwd);
    assert.equal(thread.fixture_profile, "local_daemon_agentgres_projection");
    assert.equal(thread.requested_model, "auto");
    assert.equal(thread.model_route_id, "route.native-local");
    assert.equal(thread.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(thread.model_route_decision.requestedModelMode, "auto");
    assert.equal(thread.model_route_decision.selectedModel, "autopilot:native-fixture");
    assert.equal(thread.model_route_decision.neverSendAutoUpstream, true);
    assert.equal(thread.model_route_decision.workflowNodeId, "workflow.model-router");

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Exercise the public thread turn event projection.",
        mode: "send",
      }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.equal(turn.thread_id, thread.thread_id);
    assert.match(turn.turn_id, /^turn_/);
    assert.equal(turn.status, "completed");
    assert.ok(turn.seq_start > 1);
    assert.ok(turn.seq_end >= turn.seq_start);
    assert.equal(turn.stop_reason, "evidence_sufficient");
    assert.ok(turn.quality_ledger_ref);
    assert.equal(turn.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(turn.model_route_decision.selectedModel, "autopilot:native-fixture");

    const reloadedThread = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}`);
    assert.equal(reloadedThread.latest_turn_id, turn.turn_id);
    assert.equal(reloadedThread.turns.length, 1);
    assert.ok(reloadedThread.latest_seq > 0);

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.ok(events.length >= 11);
    assert.deepEqual(
      events.map((event) => event.seq),
      Array.from({ length: events.length }, (_, index) => index + 1),
    );
    assert.equal(events[0].schema_version, "ioi.runtime.event.v1");
    assert.equal(events[0].thread_id, thread.thread_id);
    assert.equal(events[0].event_stream_id, thread.event_stream_id);
    assert.equal(events[0].event_kind, "thread.started");
    assert.equal(events[0].event, "thread.started");
    const turnStartedEvent = events.find((event) => event.event_kind === "turn.started");
    assert.equal(turnStartedEvent.turn_id, turn.turn_id);
    assert.equal(turnStartedEvent.event, "turn.started");
    assert.equal(events[0].workflow_node_id, "runtime.runtime-thread");
    const routeEvent = events.find((event) => event.payload_summary?.event_kind === "ModelRouteDecision");
    assert.equal(routeEvent.event_kind, "item.completed");
    assert.equal(routeEvent.component_kind, "model_router");
    assert.equal(routeEvent.workflow_node_id, "workflow.model-router");
    assert.equal(routeEvent.payload_summary.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload_summary.reasoning_effort, "low");
    assert.ok(routeEvent.payload_summary.model_route_decision_id);
    assert.deepEqual(routeEvent.receipt_refs, [thread.model_route_receipt_id]);
    assert.equal(events.at(-1).event, "turn.completed");
    assert.ok(events.some((event) => event.workflow_node_id === "runtime.quality-ledger"));
    assert.ok(events.filter((event) => event.turn_id === turn.turn_id).every((event) => event.payload_summary?.run_id));

    const replayAfterFive = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=5`,
    );
    assert.equal(replayAfterFive[0].seq, 6);
    assert.ok(replayAfterFive.every((event) => event.seq > 5));

    const replayAfterHeaderSeq = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events`,
      { headers: { "last-event-id": "5" } },
    );
    assert.equal(replayAfterHeaderSeq[0].seq, 6);

    const cursorEvent = events[5];
    const replayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events`,
      { headers: { "last-event-id": cursorEvent.event_id } },
    );
    assert.equal(replayAfterEventId[0].seq, cursorEvent.seq + 1);

    const streamAlias = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events/stream?since_seq=0`,
    );
    assert.deepEqual(streamAlias.map((event) => event.event_id), events.map((event) => event.event_id));

    const owningTurnEvents = events.filter((event) => event.turn_id === turn.turn_id);
    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(
      runEvents.map((event) => event.event_id),
      owningTurnEvents.map((event) => event.event_id),
    );
    const runReplayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/runs/${turn.request_id}/events`,
      { headers: { "last-event-id": owningTurnEvents[0].event_id } },
    );
    assert.deepEqual(
      runReplayAfterEventId.map((event) => event.event_id),
      owningTurnEvents.slice(1).map((event) => event.event_id),
    );
    const legacyReplayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/runs/${turn.request_id}/replay`,
      { headers: { "last-event-id": owningTurnEvents[0].event_id } },
    );
    assert.deepEqual(
      legacyReplayAfterEventId.map((event) => event.event_id),
      owningTurnEvents.slice(1).map((event) => event.event_id),
    );

    const futureCursor = await fetchJsonStatus(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=${events.at(-1).seq + 100}`,
    );
    assert.equal(futureCursor.status, 409);
    assert.equal(futureCursor.body.error.code, "event_cursor_out_of_range");
    assert.equal(futureCursor.body.error.details.latestSeq, events.at(-1).seq);
  } finally {
    await daemon.close();
  }
});

test("daemon owns thread mode, model, and thinking controls for TUI and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeThreadModeControlRequestFromWorkflowNode,
    createRuntimeWorkspaceTrustAcknowledgementControlRequest,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
    workflowWorkspaceTrustGateReadiness,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-controls-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-controls-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "cli_tui",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
      method: "POST",
      body: JSON.stringify({
        mode: "yolo",
        source: "react_flow",
        workflowGraphId: "runtime-control-graph",
        workflowNodeId: "runtime.thread-mode",
      }),
    });
    assert.equal(mode.mode, "yolo");
    assert.equal(mode.approval_mode, "never_prompt");
    assert.equal(mode.control.control_kind, "mode");
    assert.equal(mode.event.source_event_kind, "OperatorControl.Mode");
    assert.equal(mode.event.workflow_graph_id, "runtime-control-graph");

    const model = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/model`, {
      method: "POST",
      body: JSON.stringify({
        model: {
          id: "auto",
          routeId: "route.native-local",
          reasoningEffort: "medium",
          workflowGraphId: "runtime-control-graph",
          workflowNodeId: "runtime.model-router",
        },
        source: "cli_tui",
      }),
    });
    assert.equal(model.requested_model, "auto");
    assert.equal(model.model_route_id, "route.native-local");
    assert.equal(model.control.control_kind, "model");
    assert.equal(model.event.event_kind, "model.route_decision");
    assert.equal(model.event.component_kind, "model_router");

    const thinkingOff = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/thinking`, {
      method: "POST",
      body: JSON.stringify({
        reasoningEffort: "none",
        source: "cli_tui",
        workflowNodeId: "runtime.model-router",
      }),
    });
    assert.equal(thinkingOff.reasoning_effort, "none");
    assert.equal(thinkingOff.runtime_controls.model.reasoningEffort, "none");

    const thinking = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/thinking`, {
      method: "POST",
      body: JSON.stringify({
        reasoningEffort: "high",
        source: "cli_tui",
        workflowNodeId: "runtime.model-router",
      }),
    });
    assert.equal(thinking.reasoning_effort, "high");
    assert.equal(thinking.runtime_controls.model.reasoningEffort, "high");
    assert.equal(thinking.control.control_kind, "thinking");
    assert.equal(thinking.event.source_event_kind, "OperatorControl.Thinking");

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Use daemon-owned controls for this turn." }),
    });
    assert.equal(turn.mode, "yolo");
    assert.equal(turn.approval_mode, "never_prompt");
    assert.equal(turn.model_route_decision.reasoningEffort, "high");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.Mode"));
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.Model"));
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.Thinking"));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    assert.equal(sdkThread.record.mode, "yolo");
    assert.equal(sdkThread.record.reasoning_effort, "high");
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    assert.ok(
      reactFlowProjection.nodes.some((node) => node.workflowNodeId === "runtime.model-router"),
    );
    const controlProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: thread.thread_id,
      current_turn_id: turn.turn_id,
      last_cursor: `${thinking.event.event_stream_id}:${thinking.event.seq}`,
      mode_status: {
        mode: thinking.mode,
        approval_mode: thinking.approval_mode,
        requested_model: thinking.requested_model,
        selected_model: thinking.selected_model,
        model_route_id: thinking.model_route_id,
        reasoning_effort: thinking.reasoning_effort,
        workflow_node_id: "runtime.model-router",
      },
      command_history: [
        { command: "mode", raw_input: "/mode yolo", status: "applied" },
        { command: "model", raw_input: "/model auto route.native-local", status: "applied" },
        { command: "thinking", raw_input: "/thinking high", status: "applied" },
      ],
    });
    assert.ok(controlProjection.rows.some((row) => row.rowKind === "model_route"));
    assert.ok(controlProjection.rows.some((row) => row.rowKind === "thinking"));
    assert.ok(
      controlProjection.rows.some(
        (row) => row.rowKind === "thinking" && row.reactFlowNodeId === "runtime.model-router.thinking",
      ),
    );
  } finally {
    await daemon.close();
  }
});

test("daemon emits workspace trust warnings for review and yolo mode controls", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeThreadModeControlRequestFromWorkflowNode,
    createRuntimeWorkspaceTrustAcknowledgementControlRequest,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
    workflowWorkspaceTrustGateReadiness,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-workspace-trust-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-workspace-trust-state-"));
  execFileSync("git", ["init"], { cwd, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "runtime-trust@example.com"], { cwd });
  execFileSync("git", ["config", "user.name", "Runtime Trust"], { cwd });
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "clean\n");
  execFileSync("git", ["add", "tracked.txt"], { cwd });
  execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "-m", "seed tracked file"], {
    cwd,
    stdio: "ignore",
  });
  execFileSync("git", ["checkout", "-b", "feature/workspace-trust"], { cwd, stdio: "ignore" });
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "dirty\n");
  fs.writeFileSync(path.join(cwd, "untracked.txt"), "untracked\n");

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.workspace-trust-proof";
    const modeNodeId = "runtime.thread-mode.yolo";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove workspace trust warnings are daemon-owned.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const yoloControl = createRuntimeThreadModeControlRequestFromWorkflowNode(
      {
        id: "mode-control",
        type: "runtime_thread_mode",
        config: {
          logic: {
            runtimeThreadModeWorkflowNodeId: modeNodeId,
            runtimeThreadModeWorkspaceTrustWorkflowNodeId: `${modeNodeId}.workspace-trust`,
            runtimeThreadModeTrustProfile: "canvas_claims_trusted",
          },
        },
      },
      {
        threadId: thread.thread_id,
        mode: "yolo",
        approvalMode: "never_prompt",
        trustProfile: "canvas_claims_trusted",
      },
      { workflowGraphId },
    );
    assert.equal(yoloControl.nodeType, "runtime_thread_mode");
    assert.equal(yoloControl.endpoint, `/v1/threads/${thread.thread_id}/mode`);
    assert.equal(yoloControl.body.workspace_trust_workflow_node_id, `${modeNodeId}.workspace-trust`);
    const yoloMode = await fetchJson(`${daemon.endpoint}${yoloControl.endpoint}`, {
      method: "POST",
      body: JSON.stringify({
        ...yoloControl.body,
        workspaceTrustStatus: "trusted",
        workspaceTrustSuppressed: true,
        workspaceTrustIdempotencyKey: "canvas-controlled-warning-key",
      }),
    });
    assert.equal(yoloMode.mode, "yolo");
    assert.equal(yoloMode.approval_mode, "never_prompt");
    assert.equal(yoloMode.workspace_trust_warning?.mode, "yolo");
    assert.equal(yoloMode.workspace_trust_warning?.severity, "high");
    assert.equal(yoloMode.workspace_trust_warning?.trust_profile, "local_private");
    assert.equal(yoloMode.workspace_trust_warning?.ui_override_ignored, true);
    assert.equal(yoloMode.workspace_trust_warning?.canvas_local_trust_state_accepted, false);
    assert.equal(yoloMode.workspace_trust_warning?.dirty, true);
    assert.equal(yoloMode.workspace_trust_warning?.counts?.unstaged, 1);
    assert.equal(yoloMode.workspace_trust_warning?.counts?.untracked, 1);
    assert.ok(
      yoloMode.workspace_trust_warning?.warning_reasons.includes(
        "thread_yolo_mode_never_prompts",
      ),
    );
    assert.ok(
      yoloMode.workspace_trust_warning?.warning_reasons.includes(
        "canvas_local_trust_override_ignored",
      ),
    );
    assert.ok(
      yoloMode.workspace_trust_warning?.ignored_ui_fields.includes(
        "workspaceTrustIdempotencyKey",
      ),
    );
    assert.equal(yoloMode.workspace_trust_warning_event?.event_kind, "workspace.trust_warning");
    assert.equal(yoloMode.workspace_trust_warning_event?.component_kind, "workspace_trust");
    assert.equal(yoloMode.workspace_trust_warning_event?.workflow_graph_id, workflowGraphId);
    assert.equal(
      yoloMode.workspace_trust_warning_event?.workflow_node_id,
      `${modeNodeId}.workspace-trust`,
    );

    const reviewMode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
      method: "POST",
      body: JSON.stringify({
        mode: "review",
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "runtime.thread-mode.review",
      }),
    });
    assert.equal(reviewMode.workspace_trust_warning?.mode, "review");
    assert.equal(reviewMode.workspace_trust_warning?.approval_mode, "human_required");
    assert.ok(
      reviewMode.workspace_trust_warning?.warning_reasons.includes(
        "thread_review_mode_requires_visible_review",
      ),
    );

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const warningEvents = daemonEvents.filter(
      (event) => event.event_kind === "workspace.trust_warning",
    );
    assert.equal(warningEvents.length, 2);
    const yoloWarningEvent = warningEvents.find((event) => event.payload_summary?.mode === "yolo");
    assert.ok(yoloWarningEvent);
    assert.equal(yoloWarningEvent.source, "react_flow");
    assert.equal(yoloWarningEvent.actor, "policy");
    assert.equal(yoloWarningEvent.payload_summary?.source_mode_event_id, yoloMode.event.event_id);
    assert.deepEqual(yoloWarningEvent.receipt_refs, yoloMode.workspace_trust_warning_event.receipt_refs);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkWarning = sdkEvents.find((event) => event.id === yoloWarningEvent.event_id);
    assert.ok(sdkWarning);
    assert.equal(sdkWarning.type, "workspace_trust_warning");
    assert.equal(sdkWarning.componentKind, "workspace_trust");
    assert.equal(sdkWarning.workflowGraphId, workflowGraphId);
    assert.equal(sdkWarning.payload.ui_override_ignored, true);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const trustNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(yoloWarningEvent.event_id),
    );
    assert.ok(trustNode);
    assert.equal(trustNode.nodeKind, "runtime_workspace_trust_gate");
    assert.equal(trustNode.componentKind, "workspace_trust");
    assert.equal(trustNode.label, "Workspace trust warning");
    assert.equal(trustNode.status, "warning");
    assert.equal(trustNode.workflowNodeId, `${modeNodeId}.workspace-trust`);
    assert.equal(trustNode.workspaceTrustActions[0]?.action, "acknowledge");
    assert.equal(trustNode.workspaceTrustActions[0]?.executable, true);
    const workflowWithTrustGate = {
      version: "1",
      metadata: {
        id: workflowGraphId,
        slug: "workspace-trust-proof",
        name: "Workspace trust proof",
        workflowKind: "agent_workflow",
        executionMode: "mock",
      },
      global_config: {
        env: "test",
        requiredCapabilities: {},
        policy: { maxBudget: 1, maxSteps: 4, timeoutMs: 1000 },
        contract: { developerBond: 0, adjudicationRubric: "test" },
        meta: { name: "Workspace trust proof", description: "Workspace trust proof" },
      },
      nodes: [
        {
          id: "mode-control",
          type: "runtime_thread_mode",
          name: "Yolo mode",
          x: 0,
          y: 0,
          config: {
            logic: {
              runtimeThreadModeMode: "yolo",
              runtimeThreadModeWorkflowNodeId: modeNodeId,
              runtimeThreadModeWorkspaceTrustWorkflowNodeId: `${modeNodeId}.workspace-trust`,
              runtimeThreadModeRequestWarningAcknowledgement: true,
            },
          },
        },
        {
          id: "trust-gate",
          type: "runtime_workspace_trust_gate",
          name: "Workspace trust gate",
          x: 240,
          y: 0,
          config: {
            logic: {
              runtimeWorkspaceTrustGateModeNodeId: "mode-control",
              runtimeWorkspaceTrustGateWarningWorkflowNodeId: `${modeNodeId}.workspace-trust`,
            },
          },
        },
      ],
      edges: [{ id: "mode-to-trust", from: "mode-control", to: "trust-gate" }],
    };
    const trustGateBeforeAck = workflowWorkspaceTrustGateReadiness(
      workflowWithTrustGate,
      sdkEvents,
    );
    assert.equal(trustGateBeforeAck.status, "blocked");
    assert.equal(
      trustGateBeforeAck.issues[0]?.code,
      "workspace_trust_acknowledgement_missing",
    );

    const acknowledgementRequest = createRuntimeWorkspaceTrustAcknowledgementControlRequest({
      nodeId: trustNode.workspaceTrustActions[0].id,
      threadId: thread.thread_id,
      warningId: yoloWarningEvent.payload_summary.warning_id,
      sourceEventId: yoloWarningEvent.event_id,
      workflowGraphId,
      workflowNodeId: trustNode.workflowNodeId,
      reason: "operator reviewed the daemon workspace trust warning",
    });
    assert.equal(
      acknowledgementRequest.endpoint,
      `/v1/threads/${thread.thread_id}/workspace-trust/${yoloWarningEvent.payload_summary.warning_id}/acknowledge`,
    );
    const acknowledgement = await fetchJson(
      `${daemon.endpoint}${acknowledgementRequest.endpoint}`,
      {
        method: "POST",
        body: JSON.stringify(acknowledgementRequest.body),
      },
    );
    assert.equal(
      acknowledgement.workspace_trust_acknowledgement?.warning_id,
      yoloWarningEvent.payload_summary.warning_id,
    );
    assert.equal(
      acknowledgement.workspace_trust_acknowledgement_event?.event_kind,
      "workspace.trust_acknowledged",
    );
    assert.equal(
      acknowledgement.workspace_trust_acknowledgement_event?.workflow_node_id,
      trustNode.workflowNodeId,
    );

    const sdkEventsAfterAck = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkAcknowledgement = sdkEventsAfterAck.find(
      (event) =>
        event.id === acknowledgement.workspace_trust_acknowledgement_event.event_id,
    );
    assert.ok(sdkAcknowledgement);
    assert.equal(sdkAcknowledgement.type, "workspace_trust_acknowledged");
    assert.equal(sdkAcknowledgement.componentKind, "workspace_trust");
    const acknowledgedProjection =
      projectRuntimeThreadEventsToWorkflowProjection(sdkEventsAfterAck);
    const acknowledgedTrustNode = acknowledgedProjection.nodes.find((node) =>
      node.eventIds.includes(acknowledgement.workspace_trust_acknowledgement_event.event_id),
    );
    assert.ok(acknowledgedTrustNode);
    assert.equal(acknowledgedTrustNode.status, "completed");
    assert.equal(acknowledgedTrustNode.label, "Workspace trust acknowledged");
    assert.equal(
      acknowledgedTrustNode.workspaceTrustActions[0]?.status,
      "acknowledged",
    );
    assert.equal(
      acknowledgedTrustNode.workspaceTrustActions[0]?.executable,
      false,
    );
    const trustGateAfterAck = workflowWorkspaceTrustGateReadiness(
      workflowWithTrustGate,
      sdkEventsAfterAck,
    );
    assert.equal(trustGateAfterAck.status, "passed");
    assert.deepEqual(trustGateAfterAck.issues, []);

    const tuiProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      last_cursor: `${yoloWarningEvent.event_stream_id}:${yoloWarningEvent.seq}`,
      last_event_id: yoloWarningEvent.event_id,
      mode_status: {
        mode: yoloMode.mode,
        approval_mode: yoloMode.approval_mode,
        trust_profile: "local_private",
        workflow_node_id: modeNodeId,
      },
      workspace_trust_rows: [
        {
          ...yoloWarningEvent.payload_summary,
          event_id: yoloWarningEvent.event_id,
          sequence: yoloWarningEvent.seq,
          cursor: `${yoloWarningEvent.event_stream_id}:${yoloWarningEvent.seq}`,
          workflow_graph_id: yoloWarningEvent.workflow_graph_id,
          workflow_node_id: yoloWarningEvent.workflow_node_id,
          receipt_refs: yoloWarningEvent.receipt_refs,
          policy_decision_refs: yoloWarningEvent.policy_decision_refs,
        },
      ],
    });
    const tuiTrustRow = tuiProjection.rows.find(
      (row) => row.rowKind === "workspace_trust_warning",
    );
    assert.ok(tuiTrustRow);
    assert.equal(tuiProjection.workspaceTrustWarningCount, 1);
    assert.equal(tuiTrustRow.workspaceTrustWarningId, yoloWarningEvent.payload_summary.warning_id);
    assert.equal(tuiTrustRow.workspaceTrustSeverity, "high");
    assert.equal(tuiTrustRow.workspaceTrustDirty, true);
    assert.equal(tuiTrustRow.reactFlowNodeId, `${modeNodeId}.workspace-trust`);
  } finally {
    await daemon.close();
  }
});

test("daemon requires approval before review-mode mutating coding tools from React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-approval-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-approval-state-"));
  const targetPath = path.join(cwd, "README.md");
  fs.writeFileSync(targetPath, "Review mode keeps this line.\n");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.coding-approval-proof";
    const workflowNodeId = "workflow.coding.file.apply_patch.review-gate";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove review mode blocks mutating coding tools until approval.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
      method: "POST",
      body: JSON.stringify({
        mode: "review",
        approvalMode: "never_prompt",
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "runtime.thread-mode.review",
      }),
    });
    assert.equal(mode.mode, "review");
    assert.equal(mode.approval_mode, "never_prompt");

    const patch = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          approvalGranted: true,
          approvalMode: "never_prompt",
          input: {
            path: "README.md",
            oldText: "Review mode keeps this line.",
            newText: "Review mode should not mutate without approval.",
          },
        }),
      },
    );
    assert.equal(patch.status, "blocked");
    assert.equal(patch.approval_required, true);
    assert.equal(patch.result?.status, "blocked");
    assert.equal(patch.error?.code, "coding_tool_approval_required");
    assert.equal(patch.approval_manifest?.schema_version, "ioi.runtime.coding-tool-approval-manifest.v1");
    assert.equal(patch.approval_manifest?.tool_id, "file.apply_patch");
    assert.equal(patch.approval_manifest?.effect_class, "local_write");
    assert.equal(patch.approval_manifest?.thread_mode, "review");
    assert.equal(patch.approval_manifest?.approval_mode, "never_prompt");
    assert.equal(patch.approval_manifest?.policy_reason, "thread_review_mode_requires_approval");
    assert.equal(patch.approval_manifest?.ui_override_ignored, true);
    assert.ok(patch.approval_manifest?.authority_scope_requirements.includes("scope:workspace.write"));
    assert.equal(fs.readFileSync(targetPath, "utf8"), "Review mode keeps this line.\n");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const approvalEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "approval.required" &&
        event.payload?.tool_id === "file.apply_patch" &&
        event.workflow_graph_id === workflowGraphId,
    );
    assert.ok(approvalEvent);
    assert.equal(approvalEvent.source, "react_flow");
    assert.equal(approvalEvent.workflow_node_id, workflowNodeId);
    assert.equal(approvalEvent.component_kind, "approval_gate");
    assert.equal(approvalEvent.payload.action, "coding_tool.invoke");
    assert.equal(approvalEvent.payload.effect_class, "local_write");
    assert.equal(approvalEvent.payload_summary?.approval_manifest?.thread_mode, "review");
    assert.equal(approvalEvent.payload_summary?.approval_manifest?.ui_override_ignored, true);
    assert.ok(approvalEvent.receipt_refs.includes(patch.receipt_refs[0]));
    assert.ok(
      approvalEvent.policy_decision_refs.some(
        (ref) => ref.includes("file.apply_patch") && ref.includes("approval_required"),
      ),
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkApprovalEvent = sdkEvents.find((event) => event.id === approvalEvent.event_id);
    assert.ok(sdkApprovalEvent);
    assert.equal(sdkApprovalEvent.type, "approval_required");
    assert.equal(sdkApprovalEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkApprovalEvent.workflowNodeId, workflowNodeId);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const approvalNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(approvalEvent.event_id),
    );
    assert.ok(approvalNode);
    assert.equal(approvalNode.nodeKind, "human_gate");
    assert.equal(approvalNode.componentKind, "approval_gate");
    assert.equal(approvalNode.workflowNodeId, workflowNodeId);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));

    const tuiProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: thread.thread_id,
      last_cursor: `${approvalEvent.event_stream_id}:${approvalEvent.seq}`,
      last_event_id: approvalEvent.event_id,
      workflow_graph_id: workflowGraphId,
      mode_status: {
        mode: mode.mode,
        approval_mode: mode.approval_mode,
        trust_profile: "local_private",
        workflow_node_id: "runtime.thread-mode.review",
      },
      approval_rows: [
        {
          approval_id: patch.approval_id,
          status: "pending",
          message: patch.error?.message,
          workflow_node_id: workflowNodeId,
          event_id: approvalEvent.event_id,
          receipt_refs: approvalEvent.receipt_refs,
          policy_decision_refs: approvalEvent.policy_decision_refs,
          sequence: approvalEvent.seq,
        },
      ],
      command_history: [
        { command: "mode", raw_input: "/mode review", status: "applied" },
        { command: "patch", raw_input: "/patch README.md ...", status: "blocked" },
      ],
    });
    assert.ok(tuiProjection.rows.some((row) => row.rowKind === "mode_status" && row.status === "current"));
    assert.ok(
      tuiProjection.rows.some(
        (row) =>
          row.rowKind === "approval" &&
          row.approvalId === patch.approval_id &&
          row.reactFlowNodeId === workflowNodeId,
      ),
    );
  } finally {
    await daemon.close();
  }
});

test("React Flow coding-tool approval manifests survive approval and retry execution", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeCodingToolControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-approval-retry-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-approval-retry-state-"));
  const targetPath = path.join(cwd, "README.md");
  fs.writeFileSync(targetPath, "React Flow policy starts here.\n");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.coding-approval-retry-proof";
    const workflowNodeId = "workflow.coding.file.apply_patch.node-policy";
    const toolCallId = "coding_tool_react_flow_policy_retry";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove React Flow approval policy cannot bypass daemon approval and retry execution.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const mode = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mode`, {
      method: "POST",
      body: JSON.stringify({
        mode: "yolo",
        approvalMode: "never_prompt",
        source: "react_flow",
        workflowGraphId,
        workflowNodeId: "runtime.thread-mode.yolo",
      }),
    });
    assert.equal(mode.mode, "yolo");
    assert.equal(mode.approval_mode, "never_prompt");

    const control = createRuntimeCodingToolControlRequestFromWorkflowNode(
      {
        id: "react-flow-coding-node-policy",
        type: "plugin_tool",
        config: {
          logic: {
            workflowNodeId,
            toolBinding: {
              toolRef: "file.apply_patch",
              bindingKind: "coding_tool_pack",
              mockBinding: false,
              credentialReady: true,
              capabilityScope: ["file.apply_patch"],
              sideEffectClass: "write",
              requiresApproval: true,
              arguments: {
                path: "README.md",
                oldText: "React Flow policy starts here.",
                newText: "React Flow policy applied after approval.",
              },
              toolPack: {
                pack: "coding",
                writeEnabled: true,
                dryRun: false,
                approvalMode: "human_required",
                trustProfile: "review_required",
                nodeApprovalOverride: "require_approval",
                requiresApproval: true,
              },
            },
          },
        },
      },
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(control.endpoint, `/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`);
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.requiresApproval, true);
    assert.equal(control.body.approvalMode, "human_required");
    assert.equal(control.body.trustProfile, "review_required");
    assert.equal(control.body.nodeApprovalOverride, "require_approval");

    const attemptBody = {
      ...control.body,
      toolCallId,
      approved: true,
      approvalGranted: true,
      approvalMode: "never_prompt",
      approval_mode: "never_prompt",
      requiresApproval: false,
      requires_approval: false,
      toolPack: {
        coding: {
          ...control.body.toolPack.coding,
          requiresApproval: false,
          requires_approval: false,
          approvalMode: "suggest",
          approval_mode: "suggest",
        },
      },
    };
    const blocked = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: control.method,
      body: JSON.stringify(attemptBody),
    });
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.approval_required, true);
    assert.equal(blocked.approval_manifest?.thread_mode, "yolo");
    assert.equal(blocked.approval_manifest?.approval_mode, "never_prompt");
    assert.equal(blocked.approval_manifest?.policy_reason, "workflow_node_requires_approval");
    assert.equal(blocked.approval_manifest?.workflow_policy?.source, "react_flow");
    assert.equal(blocked.approval_manifest?.workflow_policy?.requiresApproval, true);
    assert.equal(blocked.approval_manifest?.workflow_trust_profile, "review_required");
    assert.equal(blocked.approval_manifest?.node_requires_approval, true);
    assert.equal(blocked.approval_manifest?.node_approval_override, "require_approval");
    assert.match(blocked.approval_manifest?.input_hash, /^[a-f0-9]{64}$/);
    assert.equal(blocked.approval_manifest?.ui_override_ignored, true);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "React Flow policy starts here.\n");

    const decision = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/decision`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          decision: "approve",
          reason: "Approve the policy-gated React Flow coding tool retry.",
        }),
      },
    );
    assert.equal(decision.decision, "approve");

    const approved = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: control.method,
      body: JSON.stringify({
        ...attemptBody,
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(approved.status, "completed");
    assert.equal(approved.tool_call_id, toolCallId);
    assert.equal(approved.event.payload_summary.approval_required, true);
    assert.equal(approved.event.payload_summary.approval_satisfied, true);
    assert.equal(approved.event.payload_summary.approval_id, blocked.approval_id);
    assert.equal(approved.event.payload_summary.approval_manifest.policy_reason, "workflow_node_requires_approval");
    assert.equal(approved.event.payload_summary.approval_manifest.workflow_policy.requiresApproval, true);
    assert.equal(approved.event.payload_summary.approval_manifest.workflow_trust_profile, "review_required");
    assert.equal(fs.readFileSync(targetPath, "utf8"), "React Flow policy applied after approval.\n");

    const replay = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: control.method,
      body: JSON.stringify({
        ...attemptBody,
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(replay.status, "completed");
    assert.equal(replay.idempotent_replay, true);
    assert.equal(replay.event.event_id, approved.event.event_id);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "React Flow policy applied after approval.\n");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const approvalEvent = daemonEvents.find((event) => event.event_id === blocked.approval_event_id);
    assert.ok(approvalEvent);
    assert.equal(approvalEvent.payload_summary.approval_manifest.workflow_policy.source, "react_flow");
    assert.equal(approvalEvent.payload_summary.approval_manifest.input_hash, blocked.approval_manifest.input_hash);
    const decisionEvent = daemonEvents.find((event) => event.event_id === decision.event_id);
    assert.ok(decisionEvent);
    assert.equal(decisionEvent.event_kind, "approval.approved");
    assert.equal(decisionEvent.payload_summary.approval_request_event_id, approvalEvent.event_id);
    assert.equal(
      decisionEvent.payload_summary.approval_manifest.input_hash,
      blocked.approval_manifest.input_hash,
    );
    const toolEvent = daemonEvents.find((event) => event.event_id === approved.event.event_id);
    assert.ok(toolEvent);
    assert.equal(toolEvent.payload_summary.approval_decision_event_id, decision.event_id);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const pendingApprovalEvents = sdkEvents.filter((event) => event.seq <= approvalEvent.seq);
    const projection = projectRuntimeThreadEventsToWorkflowProjection(pendingApprovalEvents);
    const approvalNode = projection.nodes.find((node) =>
      node.eventIds.includes(approvalEvent.event_id),
    );
    assert.ok(approvalNode);
    assert.equal(approvalNode.nodeKind, "human_gate");
    assert.equal(approvalNode.componentKind, "approval_gate");
    assert.equal(approvalNode.workflowNodeId, workflowNodeId);
  } finally {
    await daemon.close();
  }
});

test("React Flow coding-tool budget gates consume runtime telemetry summary before mutation", async () => {
  const {
    createRuntimeCodingToolControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
    projectRuntimeTuiControlStateToWorkflowProjection,
    workflowRuntimeTelemetrySummaryFromProjection,
  } = await importAgentIde();
  const cli = cliBinary();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-budget-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-budget-state-"));
  const targetPath = path.join(cwd, "README.md");
  fs.writeFileSync(targetPath, "Budget gate keeps this line.\n");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.coding-tool-summary-budget";
    const workflowNodeId = "workflow.coding.file.apply_patch.summary-budget";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove runtime telemetry summary blocks coding tool mutation before execution.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const telemetrySummary = {
      schemaVersion: "ioi.workflow.runtime-telemetry-summary.v1",
      status: "elevated",
      sourceKinds: ["runtime_usage_events"],
      threadIds: [thread.thread_id],
      turnIds: ["turn_coding_tool_budget"],
      workflowGraphIds: [workflowGraphId],
      eventIds: ["evt_coding_tool_budget_usage"],
      inputTokens: 420,
      outputTokens: 300,
      totalTokens: 720,
      costEstimateUsd: 0.0042,
      contextPressure: 0.72,
      contextPressureStatus: "elevated",
      runCount: 1,
      subagentCount: 0,
      receiptRefs: ["receipt_coding_tool_budget_usage"],
      policyDecisionRefs: ["policy_context_budget_coding_tool_usage"],
    };
    const control = createRuntimeCodingToolControlRequestFromWorkflowNode(
      {
        id: "react-flow-coding-tool-summary-budget",
        type: "plugin_tool",
        config: {
          logic: {
            workflowNodeId,
            toolBinding: {
              toolRef: "file.apply_patch",
              bindingKind: "coding_tool_pack",
              mockBinding: false,
              credentialReady: true,
              capabilityScope: ["file.apply_patch"],
              sideEffectClass: "write",
              requiresApproval: false,
              arguments: {
                path: "README.md",
                oldText: "Budget gate keeps this line.",
                newText: "Budget gate should not allow mutation.",
              },
              toolPack: {
                pack: "coding",
                writeEnabled: true,
                dryRun: false,
                approvalMode: "suggest",
                trustProfile: "local_private",
                nodeApprovalOverride: "inherit",
                requiresApproval: false,
                budgetMode: "block",
                budgetUsageField: "runtimeTelemetrySummary",
                maxTotalTokens: 100,
                maxCostUsd: 1,
                maxContextPressure: 1,
              },
            },
          },
        },
      },
      { threadId: thread.thread_id, runtimeTelemetrySummary: telemetrySummary },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(control.body.budgetMode, "block");
    assert.equal(control.body.budgetUsageTelemetry.total_tokens, 720);
    assert.equal(control.body.thresholds.maxTotalTokens, 100);

    const blocked = await fetchJsonStatus(`${daemon.endpoint}${control.endpoint}`, {
      method: control.method,
      body: JSON.stringify({
        ...control.body,
        tool_call_id: "coding_tool_summary_budget_blocked",
        toolCallId: "coding_tool_summary_budget_blocked",
      }),
    });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error.code, "policy");
    assert.equal(blocked.body.error.details.reason, "coding_tool_budget_exceeded");
    assert.equal(blocked.body.error.details.budget_status, "exceeded");
    assert.equal(blocked.body.error.details.context_budget_status, "blocked");
    assert.equal(
      blocked.body.error.details.budget_usage_telemetry.total_tokens,
      telemetrySummary.totalTokens,
    );
    assert.ok(
      blocked.body.error.details.policy_decision_refs.some((ref) =>
        ref.startsWith("policy_context_budget_thread_"),
      ),
    );
    assert.equal(fs.readFileSync(targetPath, "utf8"), "Budget gate keeps this line.\n");

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    const budgetEvent = events.find(
      (event) =>
        event.event_kind === "policy.blocked" &&
        event.component_kind === "coding_tool" &&
        event.workflow_node_id === workflowNodeId,
    );
    assert.ok(budgetEvent);
    assert.equal(budgetEvent.status, "blocked");
    assert.equal(budgetEvent.source_event_kind, "CodingTool.FileApplyPatch");
    assert.equal(budgetEvent.workflow_graph_id, workflowGraphId);
    assert.equal(budgetEvent.payload_summary.error.code, "coding_tool_budget_exceeded");
    assert.equal(budgetEvent.payload_summary.budget_usage_telemetry.total_tokens, 720);
    assert.ok(budgetEvent.policy_decision_refs[0].startsWith("policy_context_budget_thread_"));
    const budgetCursor = canonicalRuntimeEventCursor(budgetEvent);

    const runtimeProjection = projectRuntimeThreadEventsToWorkflowProjection([
      {
        id: budgetEvent.event_id,
        cursor: budgetCursor,
        seq: budgetEvent.seq,
        threadId: budgetEvent.thread_id,
        turnId: budgetEvent.turn_id ?? null,
        type: "policy_blocked",
        eventKind: budgetEvent.event_kind,
        sourceEventKind: budgetEvent.source_event_kind,
        status: budgetEvent.status,
        createdAt: budgetEvent.created_at,
        componentKind: budgetEvent.component_kind,
        workflowNodeId: budgetEvent.workflow_node_id,
        workflowGraphId: budgetEvent.workflow_graph_id,
        toolCallId: budgetEvent.tool_call_id,
        toolName: budgetEvent.payload_summary.tool_name,
        payloadSchemaVersion: budgetEvent.payload_schema_version,
        receiptRefs: budgetEvent.receipt_refs ?? [],
        artifactRefs: budgetEvent.artifact_refs ?? [],
        policyDecisionRefs: budgetEvent.policy_decision_refs ?? [],
        rollbackRefs: budgetEvent.rollback_refs ?? [],
        payload: budgetEvent.payload_summary,
      },
    ]);
    const budgetNode = runtimeProjection.nodes.find((node) =>
      node.eventIds.includes(budgetEvent.event_id),
    );
    assert.ok(budgetNode);
    assert.equal(budgetNode.nodeKind, "plugin_tool");
    assert.equal(budgetNode.label, "Coding tool budget: file.apply_patch");
    assert.equal(budgetNode.status, "blocked");
    assert.equal(budgetNode.toolCallId, "coding_tool_summary_budget_blocked");
    assert.equal(budgetNode.codingToolBudgetStatus, "exceeded");
    assert.equal(budgetNode.codingToolContextBudgetStatus, "blocked");
    assert.equal(budgetNode.codingToolBudgetMode, "block");
    assert.equal(budgetNode.codingToolBudgetViolationCount, 1);
    assert.equal(budgetNode.codingToolMutationBlocked, true);

    const tuiResult = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const tuiPayload = JSON.parse(tuiResult.stdout);
    assert.equal(tuiPayload.tui_control_state.thread_id, thread.thread_id);
    assert.equal(tuiPayload.tui_control_state.last_event_id, budgetEvent.event_id);
    const emittedBudgetRow = tuiPayload.tui_control_state.coding_tool_rows.find(
      (row) => row.event_id === budgetEvent.event_id,
    );
    assert.ok(emittedBudgetRow, "expected CLI/TUI control-state coding_tool_rows to include the budget block");
    assert.equal(emittedBudgetRow.row_kind, "coding_tool_budget");
    assert.equal(emittedBudgetRow.command, "run");
    assert.match(emittedBudgetRow.raw_input, /^\/run recovery request/);
    assert.equal(emittedBudgetRow.tool_name, "file.apply_patch");
    assert.equal(emittedBudgetRow.tool_call_id, "coding_tool_summary_budget_blocked");
    assert.equal(emittedBudgetRow.budget_status, "exceeded");
    assert.equal(emittedBudgetRow.context_budget_status, "blocked");
    assert.equal(emittedBudgetRow.context_budget_mode, "block");
    assert.ok(
      emittedBudgetRow.context_budget_decision_id.startsWith("policy_context_budget_thread_"),
    );
    assert.equal(emittedBudgetRow.coding_tool_budget_violation_count, 1);
    assert.equal(emittedBudgetRow.mutation_blocked, true);
    assert.equal(emittedBudgetRow.cursor, budgetCursor);
    assert.deepEqual(emittedBudgetRow.receipt_refs, budgetEvent.receipt_refs);
    assert.deepEqual(emittedBudgetRow.policy_decision_refs, budgetEvent.policy_decision_refs);

    const tuiProjection = projectRuntimeTuiControlStateToWorkflowProjection(
      tuiPayload.tui_control_state,
    );
    const budgetRow = tuiProjection.rows.find(
      (row) => row.rowKind === "coding_tool_budget",
    );
    assert.ok(budgetRow);
    assert.equal(tuiProjection.codingToolBudgetRowCount, 1);
    assert.equal(budgetRow.reactFlowNodeId, workflowNodeId);
    assert.equal(budgetRow.toolName, "file.apply_patch");
    assert.equal(budgetRow.toolCallId, "coding_tool_summary_budget_blocked");
    assert.equal(budgetRow.codingToolBudgetStatus, "exceeded");
    assert.equal(budgetRow.codingToolContextBudgetStatus, "blocked");
    assert.equal(budgetRow.codingToolBudgetViolationCount, 1);
    assert.equal(budgetRow.codingToolMutationBlocked, true);

    const tuiTelemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: tuiProjection,
    });
    assert.equal(tuiTelemetrySummary.status, "blocked");
    assert.ok(tuiTelemetrySummary.sourceKinds.includes("tui_coding_tool_rows"));
    assert.equal(tuiTelemetrySummary.codingToolBudgetRowCount, 1);
    assert.equal(tuiTelemetrySummary.totalTokens, 720);
    assert.equal(tuiTelemetrySummary.contextPressure, 0.72);
    assert.equal(tuiTelemetrySummary.contextPressureStatus, "blocked");
    assert.ok(tuiTelemetrySummary.eventIds.includes(budgetEvent.event_id));
    const followupControl = createRuntimeCodingToolControlRequestFromWorkflowNode(
      {
        id: "react-flow-coding-tool-tui-summary-budget",
        type: "plugin_tool",
        config: {
          logic: {
            workflowNodeId: "workflow.coding.file.apply_patch.tui-summary-budget",
            toolBinding: {
              toolRef: "file.apply_patch",
              bindingKind: "coding_tool_pack",
              mockBinding: false,
              credentialReady: true,
              capabilityScope: ["file.apply_patch"],
              sideEffectClass: "write",
              requiresApproval: false,
              arguments: {
                path: "README.md",
                oldText: "Budget gate keeps this line.",
                newText: "TUI summary budget should not allow mutation.",
              },
              toolPack: {
                pack: "coding",
                writeEnabled: true,
                dryRun: false,
                approvalMode: "suggest",
                trustProfile: "local_private",
                nodeApprovalOverride: "inherit",
                requiresApproval: false,
                budgetMode: "block",
                budgetUsageField: "runtimeTelemetrySummary",
                maxTotalTokens: 100,
                maxCostUsd: 1,
                maxContextPressure: 1,
              },
            },
          },
        },
      },
      { threadId: thread.thread_id, runtimeTelemetrySummary: tuiTelemetrySummary },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(followupControl.body.budgetUsageTelemetry.total_tokens, 720);
    assert.ok(
      followupControl.body.budgetUsageTelemetry.source_refs.includes(
        budgetEvent.event_id,
      ),
    );
    const followupBlocked = await fetchJsonStatus(
      `${daemon.endpoint}${followupControl.endpoint}`,
      {
        method: followupControl.method,
        body: JSON.stringify({
          ...followupControl.body,
          tool_call_id: "coding_tool_tui_summary_budget_blocked",
          toolCallId: "coding_tool_tui_summary_budget_blocked",
        }),
      },
    );
    assert.equal(followupBlocked.status, 403);
    assert.equal(
      followupBlocked.body.error.details.budget_usage_telemetry.total_tokens,
      720,
    );
    assert.equal(fs.readFileSync(targetPath, "utf8"), "Budget gate keeps this line.\n");
  } finally {
    await daemon.close();
  }
});

test("React Flow policy stack replays workspace trust and coding approval gates in order", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeCodingToolControlRequestFromWorkflowNode,
    createRuntimeThreadModeControlRequestFromWorkflowNode,
    createRuntimeWorkspaceTrustAcknowledgementControlRequest,
    projectRuntimeThreadEventsToWorkflowProjection,
    workflowRuntimePolicyStackFromEvents,
    workflowWorkspaceTrustGateReadiness,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-policy-stack-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-policy-stack-state-"));
  execFileSync("git", ["init"], { cwd, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "runtime-policy-stack@example.com"], { cwd });
  execFileSync("git", ["config", "user.name", "Runtime Policy Stack"], { cwd });
  const targetPath = path.join(cwd, "README.md");
  fs.writeFileSync(targetPath, "Policy stack starts here.\n");
  execFileSync("git", ["add", "README.md"], { cwd });
  execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "-m", "seed policy stack"], {
    cwd,
    stdio: "ignore",
  });
  execFileSync("git", ["checkout", "-b", "feature/policy-stack"], { cwd, stdio: "ignore" });
  fs.writeFileSync(path.join(cwd, "dirty.txt"), "untracked policy evidence\n");

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.policy-stack-proof";
    const modeNodeId = "runtime.thread-mode.yolo.policy-stack";
    const trustWorkflowNodeId = `${modeNodeId}.workspace-trust`;
    const codingNodeId = "workflow.coding.file.apply_patch.policy-stack";
    const toolCallId = "coding_tool_policy_stack_retry";
    const workflowWithPolicyStack = {
      version: "1",
      metadata: {
        id: workflowGraphId,
        slug: "policy-stack-proof",
        name: "Policy stack proof",
        workflowKind: "agent_workflow",
        executionMode: "mock",
      },
      global_config: {
        env: "test",
        requiredCapabilities: {},
        policy: { maxBudget: 1, maxSteps: 6, timeoutMs: 1000 },
        contract: { developerBond: 0, adjudicationRubric: "test" },
        meta: { name: "Policy stack proof", description: "Policy stack proof" },
      },
      nodes: [
        {
          id: "mode-control",
          type: "runtime_thread_mode",
          name: "Yolo mode",
          x: 0,
          y: 0,
          config: {
            logic: {
              runtimeThreadModeMode: "yolo",
              runtimeThreadModeWorkflowNodeId: modeNodeId,
              runtimeThreadModeWorkspaceTrustWorkflowNodeId: trustWorkflowNodeId,
              runtimeThreadModeRequestWarningAcknowledgement: true,
            },
          },
        },
        {
          id: "trust-gate",
          type: "runtime_workspace_trust_gate",
          name: "Workspace trust gate",
          x: 240,
          y: 0,
          config: {
            logic: {
              runtimeWorkspaceTrustGateModeNodeId: "mode-control",
              runtimeWorkspaceTrustGateWarningWorkflowNodeId: trustWorkflowNodeId,
            },
          },
        },
        {
          id: "apply-patch",
          type: "plugin_tool",
          name: "Apply patch",
          x: 480,
          y: 0,
          config: {
            logic: {
              workflowNodeId: codingNodeId,
              toolBinding: {
                toolRef: "file.apply_patch",
                bindingKind: "coding_tool_pack",
                mockBinding: false,
                credentialReady: true,
                capabilityScope: ["file.apply_patch"],
                sideEffectClass: "write",
                requiresApproval: true,
                arguments: {
                  path: "README.md",
                  oldText: "Policy stack starts here.",
                  newText: "Policy stack applied after trust and approval.",
                },
                toolPack: {
                  pack: "coding",
                  writeEnabled: true,
                  dryRun: false,
                  approvalMode: "human_required",
                  trustProfile: "review_required",
                  nodeApprovalOverride: "require_approval",
                  requiresApproval: true,
                },
              },
            },
          },
        },
      ],
      edges: [
        { id: "mode-to-trust", from: "mode-control", to: "trust-gate" },
        { id: "trust-to-patch", from: "trust-gate", to: "apply-patch" },
      ],
    };

    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove the ordered runtime policy stack is replayable.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const modeRequest = createRuntimeThreadModeControlRequestFromWorkflowNode(
      workflowWithPolicyStack.nodes[0],
      {
        threadId: thread.thread_id,
        mode: "yolo",
        approvalMode: "never_prompt",
        trustProfile: "local_private",
      },
      { workflowGraphId },
    );
    const mode = await fetchJson(`${daemon.endpoint}${modeRequest.endpoint}`, {
      method: "POST",
      body: JSON.stringify(modeRequest.body),
    });
    assert.equal(mode.mode, "yolo");
    assert.equal(mode.workspace_trust_warning_event?.workflow_node_id, trustWorkflowNodeId);

    const eventsBeforeAck = await collect(sdkThread.events({ sinceSeq: 0 }));
    const readinessBeforeAck = workflowWorkspaceTrustGateReadiness(
      workflowWithPolicyStack,
      eventsBeforeAck,
    );
    assert.equal(readinessBeforeAck.status, "blocked");
    assert.equal(
      readinessBeforeAck.issues[0]?.code,
      "workspace_trust_acknowledgement_missing",
    );

    const warningEvent = eventsBeforeAck.find(
      (event) =>
        event.type === "workspace_trust_warning" &&
        event.workflowNodeId === trustWorkflowNodeId,
    );
    assert.ok(warningEvent);
    const acknowledgementRequest = createRuntimeWorkspaceTrustAcknowledgementControlRequest({
      nodeId: "policy-stack-trust-ack",
      threadId: thread.thread_id,
      warningId: warningEvent.payload.warning_id,
      sourceEventId: warningEvent.id,
      workflowGraphId,
      workflowNodeId: trustWorkflowNodeId,
      reason: "operator acknowledged the policy stack workspace trust warning",
    });
    const acknowledgement = await fetchJson(
      `${daemon.endpoint}${acknowledgementRequest.endpoint}`,
      {
        method: "POST",
        body: JSON.stringify(acknowledgementRequest.body),
      },
    );
    assert.equal(
      acknowledgement.workspace_trust_acknowledgement_event?.workflow_node_id,
      trustWorkflowNodeId,
    );

    const eventsAfterAck = await collect(sdkThread.events({ sinceSeq: 0 }));
    const readinessAfterAck = workflowWorkspaceTrustGateReadiness(
      workflowWithPolicyStack,
      eventsAfterAck,
    );
    assert.equal(readinessAfterAck.status, "passed");

    const codingControl = createRuntimeCodingToolControlRequestFromWorkflowNode(
      workflowWithPolicyStack.nodes[2],
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    const attemptBody = {
      ...codingControl.body,
      toolCallId,
      approved: true,
      approvalGranted: true,
      approvalMode: "never_prompt",
      approval_mode: "never_prompt",
      requiresApproval: false,
      requires_approval: false,
      toolPack: {
        coding: {
          ...codingControl.body.toolPack.coding,
          requiresApproval: false,
          requires_approval: false,
          approvalMode: "suggest",
          approval_mode: "suggest",
        },
      },
    };
    const blocked = await fetchJson(`${daemon.endpoint}${codingControl.endpoint}`, {
      method: codingControl.method,
      body: JSON.stringify(attemptBody),
    });
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.approval_required, true);
    assert.equal(blocked.approval_manifest?.policy_reason, "workflow_node_requires_approval");
    assert.equal(fs.readFileSync(targetPath, "utf8"), "Policy stack starts here.\n");

    const decision = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/decision`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId: codingNodeId,
          decision: "approve",
          reason: "Approve the full policy stack coding retry.",
        }),
      },
    );
    assert.equal(decision.decision, "approve");

    const approved = await fetchJson(`${daemon.endpoint}${codingControl.endpoint}`, {
      method: codingControl.method,
      body: JSON.stringify({
        ...attemptBody,
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(approved.status, "completed");
    assert.equal(approved.event.payload_summary.approval_satisfied, true);
    assert.equal(approved.event.payload_summary.approval_decision_event_id, decision.event_id);
    assert.equal(
      fs.readFileSync(targetPath, "utf8"),
      "Policy stack applied after trust and approval.\n",
    );

    const replay = await fetchJson(`${daemon.endpoint}${codingControl.endpoint}`, {
      method: codingControl.method,
      body: JSON.stringify({
        ...attemptBody,
        approvalId: blocked.approval_id,
      }),
    });
    assert.equal(replay.status, "completed");
    assert.equal(replay.idempotent_replay, true);
    assert.equal(replay.event.event_id, approved.event.event_id);

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const approvalDecisionEvent = sdkEvents.find((event) => event.id === decision.event_id);
    assert.ok(approvalDecisionEvent);
    assert.equal(approvalDecisionEvent.type, "approval_decision");
    assert.equal(approvalDecisionEvent.componentKind, "approval_gate");
    assert.equal(approvalDecisionEvent.workflowNodeId, codingNodeId);
    const projection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const trustNode = projection.nodes.find((node) => node.workflowNodeId === trustWorkflowNodeId);
    assert.equal(trustNode?.nodeKind, "runtime_workspace_trust_gate");
    assert.equal(trustNode?.status, "completed");
    const approvalNode = projection.nodes.find((node) => node.workflowNodeId === codingNodeId);
    assert.ok(approvalNode);
    assert.equal(approvalNode.nodeKind, "plugin_tool");
    assert.ok(approvalNode.eventIds.includes(blocked.approval_event_id));
    assert.ok(approvalNode.eventIds.includes(decision.event_id));
    assert.ok(approvalNode.eventIds.includes(approved.event.event_id));

    const policyStack = workflowRuntimePolicyStackFromEvents(sdkEvents, { workflowGraphId });
    assert.equal(policyStack.status, "completed");
    assert.equal(policyStack.approvalId, blocked.approval_id);
    assert.equal(policyStack.warningId, warningEvent.payload.warning_id);
    assert.equal(policyStack.toolCallId, toolCallId);
    assert.deepEqual(
      policyStack.stages.map((stage) => [stage.kind, stage.status, stage.eventId]),
      [
        ["workspace_trust_warning", "completed", warningEvent.id],
        [
          "workspace_trust_acknowledgement",
          "completed",
          acknowledgement.workspace_trust_acknowledgement_event.event_id,
        ],
        ["approval_requirement", "completed", blocked.approval_event_id],
        ["approval_decision", "completed", decision.event_id],
        ["approved_retry", "completed", approved.event.event_id],
      ],
    );
    assert.ok(policyStack.workflowNodeIds.includes(trustWorkflowNodeId));
    assert.ok(policyStack.workflowNodeIds.includes(codingNodeId));
    assert.ok(policyStack.receiptRefs.length >= 5);
    assert.ok(policyStack.policyDecisionRefs.length >= 5);
  } finally {
    await daemon.close();
  }
});

test("React Flow workflow edit proposals are daemon-gated and replayable", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeWorkflowEditProposalApplyControlRequest,
    createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
    workflowRuntimeEditProposalPolicyStackFromEvents,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-edit-proposal-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-edit-proposal-state-"));
  const workflowPath = path.join(cwd, "proposal-proof.workflow.json");
  const initialWorkflow = {
    version: "1",
    metadata: {
      id: "workflow.react-flow.edit-proposal-proof",
      name: "Proposal proof",
    },
    nodes: [{ id: "model", type: "model_call", name: "Model" }],
    edges: [],
  };
  const rejectedWorkflow = {
    ...initialWorkflow,
    metadata: { ...initialWorkflow.metadata, name: "Rejected edit" },
  };
  const approvedWorkflow = {
    ...initialWorkflow,
    metadata: { ...initialWorkflow.metadata, name: "Approved edit" },
  };
  fs.writeFileSync(workflowPath, `${JSON.stringify(initialWorkflow, null, 2)}\n`);

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = initialWorkflow.metadata.id;
    const workflowNodeId = "runtime.workflow-edit-proposal.model";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove workflow edit proposals are daemon gated.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const proposalNode = {
      id: "proposal-node",
      type: "proposal",
      name: "Bounded workflow edit",
      config: {
        logic: {
          workflowNodeId,
          proposalId: "proposal-rejected",
          title: "Reject unsafe metadata edit",
          summary: "Rejected proposal should never mutate the workflow file.",
          workflowPath,
          workflowPatch: rejectedWorkflow,
          proposalAction: {
            actionKind: "create",
            boundedTargets: ["model"],
            requiresApproval: true,
          },
        },
      },
    };
    const rejectedProposalControl =
      createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode(
        proposalNode,
        { threadId: thread.thread_id },
        { workflowGraphId, actor: "workflow-author" },
      );
    assert.equal(rejectedProposalControl.body.proposal_only, true);
    assert.equal(rejectedProposalControl.body.mutation_allowed, false);

    const rejectedProposal = await fetchJson(
      `${daemon.endpoint}${rejectedProposalControl.endpoint}`,
      {
        method: rejectedProposalControl.method,
        body: JSON.stringify(rejectedProposalControl.body),
      },
    );
    assert.equal(rejectedProposal.status, "waiting_for_approval");
    assert.equal(rejectedProposal.approval_required, true);
    assert.equal(rejectedProposal.mutation_executed, false);
    assert.equal(JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name, "Proposal proof");

    const directApply = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/workflow-edit-proposals/proposal-rejected/apply`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          approved: true,
          approvalGranted: true,
          approvalMode: "never_prompt",
        }),
      },
    );
    assert.equal(directApply.status, "blocked");
    assert.equal(directApply.approval_required, true);
    assert.equal(directApply.mutation_executed, false);
    assert.equal(JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name, "Proposal proof");

    const rejectedDecision = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${rejectedProposal.approval_id}/reject`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          reason: "Reject the proposal to prove no workflow mutation occurs.",
        }),
      },
    );
    assert.equal(rejectedDecision.decision, "reject");

    const rejectedApply = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/workflow-edit-proposals/proposal-rejected/apply`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          approvalId: rejectedProposal.approval_id,
        }),
      },
    );
    assert.equal(rejectedApply.status, "blocked");
    assert.equal(rejectedApply.reason, "approval_rejected");
    assert.equal(JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name, "Proposal proof");

    const approvedControl = createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode(
      {
        ...proposalNode,
        config: {
          logic: {
            ...proposalNode.config.logic,
            proposalId: "proposal-approved",
            title: "Approve metadata edit",
            summary: "Approved proposal mutates the workflow after daemon approval.",
            workflowPatch: approvedWorkflow,
          },
        },
      },
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    const approvedProposal = await fetchJson(`${daemon.endpoint}${approvedControl.endpoint}`, {
      method: approvedControl.method,
      body: JSON.stringify(approvedControl.body),
    });
    assert.equal(approvedProposal.status, "waiting_for_approval");
    const approvedDecision = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${approvedProposal.approval_id}/approve`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId,
          reason: "Approve bounded workflow metadata edit.",
        }),
      },
    );
    assert.equal(approvedDecision.decision, "approve");

    const applyControl = createRuntimeWorkflowEditProposalApplyControlRequest({
      threadId: thread.thread_id,
      proposalId: "proposal-approved",
      approvalId: approvedProposal.approval_id,
      workflowGraphId,
      workflowNodeId,
      actor: "workflow-author",
    });
    const applied = await fetchJson(`${daemon.endpoint}${applyControl.endpoint}`, {
      method: applyControl.method,
      body: JSON.stringify(applyControl.body),
    });
    assert.equal(applied.status, "completed");
    assert.equal(applied.mutation_executed, true);
    assert.equal(JSON.parse(fs.readFileSync(workflowPath, "utf8")).metadata.name, "Approved edit");

    const replay = await fetchJson(`${daemon.endpoint}${applyControl.endpoint}`, {
      method: applyControl.method,
      body: JSON.stringify(applyControl.body),
    });
    assert.equal(replay.status, "completed");
    assert.equal(replay.idempotent_replay, true);
    assert.equal(replay.event.event_id, applied.event.event_id);

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const proposedEvent = sdkEvents.find(
      (event) => event.eventKind === "workflow.edit_proposed" &&
        event.payload.proposal_id === "proposal-approved",
    );
    assert.ok(proposedEvent);
    assert.equal(proposedEvent.type, "workflow_edit_proposed");
    assert.equal(proposedEvent.componentKind, "workflow_edit_proposal");
    const appliedEvent = sdkEvents.find((event) => event.id === applied.event.event_id);
    assert.ok(appliedEvent);
    assert.equal(appliedEvent.type, "workflow_edit_applied");
    assert.equal(appliedEvent.payload.mutation_executed, true);
    const rejectedAppliedEvent = sdkEvents.find(
      (event) => event.eventKind === "workflow.edit_applied" &&
        event.payload.proposal_id === "proposal-rejected",
    );
    assert.equal(rejectedAppliedEvent, undefined);

    const projection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const proposalNodeProjection = projection.nodes.find(
      (node) => node.workflowNodeId === workflowNodeId,
    );
    assert.ok(proposalNodeProjection);
    assert.equal(proposalNodeProjection.nodeKind, "proposal");
    assert.ok(proposalNodeProjection.eventIds.includes(proposedEvent.id));
    assert.ok(proposalNodeProjection.eventIds.includes(appliedEvent.id));

    const rejectedStack = workflowRuntimeEditProposalPolicyStackFromEvents(sdkEvents, {
      workflowGraphId,
      proposalId: "proposal-rejected",
    });
    assert.equal(rejectedStack.status, "blocked");
    assert.equal(rejectedStack.mutationExecuted, false);
    assert.deepEqual(
      rejectedStack.stages.map((stage) => [stage.kind, stage.status]),
      [
        ["proposal_created", "completed"],
        ["approval_requirement", "completed"],
        ["approval_decision", "blocked"],
        ["proposal_apply", "blocked"],
      ],
    );

    const approvedStack = workflowRuntimeEditProposalPolicyStackFromEvents(sdkEvents, {
      workflowGraphId,
      proposalId: "proposal-approved",
    });
    assert.equal(approvedStack.status, "completed");
    assert.equal(approvedStack.approvalId, approvedProposal.approval_id);
    assert.equal(approvedStack.mutationExecuted, true);
    assert.deepEqual(
      approvedStack.stages.map((stage) => [stage.kind, stage.status]),
      [
        ["proposal_created", "completed"],
        ["approval_requirement", "completed"],
        ["approval_decision", "completed"],
        ["proposal_apply", "completed"],
      ],
    );
  } finally {
    await daemon.close();
  }
});

test("daemon owns MCP discovery, validation, and React Flow workflow rows", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-mcp-workspace-"));
  const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-mcp-home-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-mcp-state-"));
  const remoteAuthVaultRef = "vault://mcp/remote/header-token";
  const remoteAuthMaterial = `mcp-fixture-${cryptoRandomSuffix()}`;
  const remoteAuthHeaderName = "x-fixture-token";
  const remoteFixture = await startMcpRemoteFixtureServer({
    requiredHeaders: { [remoteAuthHeaderName]: remoteAuthMaterial },
  });
  const largeRemoteFixture = await startMcpRemoteFixtureServer({
    tools: largeMcpFixtureTools(),
  });
  fs.mkdirSync(path.join(cwd, ".cursor"), { recursive: true });
  fs.writeFileSync(
    path.join(cwd, ".cursor", "mcp.json"),
    JSON.stringify(
      {
        mcpServers: {
          search: {
            command: "node",
            args: [mcpStdioFixture],
            allowedTools: ["query", "fetch"],
            resources: [{ uri: "ioi://fixture/search-context", name: "search-context" }],
            prompts: [{ name: "search-brief", arguments: [{ name: "topic", required: true }] }],
            env: { SEARCH_TOKEN: "vault://mcp/search/token" },
            containment: { mode: "sandboxed", allowChildProcesses: true },
          },
        },
      },
      null,
      2,
    ),
  );
  fs.mkdirSync(path.join(homeDir, ".ioi"), { recursive: true });
  fs.writeFileSync(
    path.join(homeDir, ".ioi", "mcp.json"),
    JSON.stringify(
      {
        mcpServers: {
          global: {
            command: "node",
            args: [mcpStdioFixture],
            allowedTools: ["global_lookup"],
            enabled: false,
            env: { GLOBAL_TOKEN: "vault://mcp/global/token" },
            containment: { mode: "sandboxed", allowChildProcesses: true },
          },
        },
      },
      null,
      2,
    ),
  );
  const daemon = await startRuntimeDaemonService({
    cwd,
    homeDir,
    stateDir,
    vaultSecrets: { [remoteAuthVaultRef]: remoteAuthMaterial },
  });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "cli_tui",
        options: { local: { cwd }, mcpServers: {} },
      }),
    });

    const servers = await fetchJson(
      `${daemon.endpoint}/v1/mcp/servers?thread_id=${thread.thread_id}`,
    );
    assert.equal(servers.length, 2);
    const searchServer = servers.find((server) => server.id === "mcp.search");
    const globalServer = servers.find((server) => server.id === "mcp.global");
    assert.equal(searchServer.source, ".cursor/mcp.json");
    assert.equal(searchServer.sourceScope, "workspace");
    assert.equal(searchServer.configCompatibility, "cursor");
    assert.equal(searchServer.secretRefs.SEARCH_TOKEN.redacted, true);
    assert.equal(globalServer.source, "global.ioi/mcp.json");
    assert.equal(globalServer.sourceScope, "global");
    assert.equal(globalServer.configCompatibility, "ioi");
    assert.equal(globalServer.enabled, false);
    assert.equal(globalServer.secretRefs.GLOBAL_TOKEN.redacted, true);
    assert.equal(JSON.stringify(servers).includes("vault://mcp/global/token"), false);

    const workspaceOnlyServers = await fetchJson(
      `${daemon.endpoint}/v1/mcp/servers?thread_id=${thread.thread_id}&mcp_config_source_mode=workspace`,
    );
    assert.deepEqual(workspaceOnlyServers.map((server) => server.id), ["mcp.search"]);
    const globalOnlyServers = await fetchJson(
      `${daemon.endpoint}/v1/mcp/servers?thread_id=${thread.thread_id}&mcp_config_source_mode=global`,
    );
    assert.deepEqual(globalOnlyServers.map((server) => server.id), ["mcp.global"]);

    const tools = await fetchJson(
      `${daemon.endpoint}/v1/mcp/tools?thread_id=${thread.thread_id}`,
    );
    assert.deepEqual(
      tools.filter((tool) => tool.serverId === "mcp.search").map((tool) => tool.toolName).sort(),
      ["fetch", "query"],
    );
    assert.ok(tools.some((tool) => tool.serverId === "mcp.global" && tool.toolName === "global_lookup"));
    const searchQueryTool = tools.find((tool) => tool.serverId === "mcp.search" && tool.toolName === "query");
    assert.ok(
      tools
        .filter((tool) => tool.serverId === "mcp.search")
        .every((tool) => tool.workflowNodeId.startsWith("runtime.mcp-tool.search.")),
    );
    assert.ok(
      tools
        .filter((tool) => tool.serverId === "mcp.global")
        .every((tool) => tool.workflowNodeId.startsWith("runtime.mcp-tool.global.")),
    );

    const status = await fetchJson(
      `${daemon.endpoint}/v1/mcp?thread_id=${thread.thread_id}`,
    );
    assert.equal(status.status, "ready");
    assert.equal(status.server_count, 2);
    assert.equal(status.tool_count, 3);
    assert.equal(status.resource_count, 1);
    assert.equal(status.prompt_count, 1);
    assert.equal(status.validation.servers.find((server) => server.id === "mcp.global").sourceScope, "global");

    const resources = await fetchJson(
      `${daemon.endpoint}/v1/mcp/resources?thread_id=${thread.thread_id}`,
    );
    assert.equal(resources[0].uri, "ioi://fixture/search-context");
    assert.ok(resources[0].workflowNodeId.startsWith("runtime.mcp-resource.search."));

    const prompts = await fetchJson(
      `${daemon.endpoint}/v1/mcp/prompts?thread_id=${thread.thread_id}`,
    );
    assert.equal(prompts[0].name, "search-brief");
    assert.ok(prompts[0].workflowNodeId.startsWith("runtime.mcp-prompt.search."));

    const validation = await fetchJson(`${daemon.endpoint}/v1/mcp/validate`, {
      method: "POST",
      body: JSON.stringify({ mcpServers: { search: searchServer } }),
    });
    assert.equal(validation.ok, true);
    assert.equal(validation.status, "pass");

    const threadStatus = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/status`, {
      method: "POST",
      body: JSON.stringify({
        source: "cli_tui",
        workflowGraphId: "mcp-control-graph",
        live_discovery: true,
      }),
    });
    assert.equal(threadStatus.event.source_event_kind, "OperatorControl.Mcp");
    assert.equal(threadStatus.event.component_kind, "mcp_provider");
    assert.equal(threadStatus.event.workflow_node_id, "runtime.mcp-manager");
    assert.equal(threadStatus.receipt_refs.length, 1);
    assert.equal(threadStatus.resource_count, 1);
    assert.equal(threadStatus.prompt_count, 1);
    assert.equal(threadStatus.resources[0].uri, "ioi://fixture/search-context");
    assert.equal(threadStatus.prompts[0].name, "search-brief");
    assert.equal(threadStatus.live_discovery.status, "completed");

    const threadValidation = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/validate`, {
      method: "POST",
      body: JSON.stringify({ source: "react_flow" }),
    });
    assert.equal(threadValidation.event.source_event_kind, "OperatorControl.McpValidate");
    assert.equal(threadValidation.event.component_kind, "mcp_validator");
    assert.equal(threadValidation.ok, true);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    assert.equal((await sdkClient.getMcpStatus({ thread_id: thread.thread_id })).server_count, 2);
    assert.equal((await sdkClient.listMcpTools({ thread_id: thread.thread_id })).length, 3);
    assert.equal((await sdkClient.listMcpResources({ thread_id: thread.thread_id })).length, 1);
    assert.equal((await sdkClient.listMcpPrompts({ thread_id: thread.thread_id })).length, 1);
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    assert.equal((await sdkThread.mcp()).tool_count, 3);
    assert.equal((await sdkThread.validateMcp()).ok, true);

    const added = await sdkThread.addMcpServer({
      label: "scratch",
      server: {
        command: "node",
        args: [mcpStdioFixture],
        allowedTools: ["query"],
        resources: [{ uri: "ioi://fixture/scratch-context", name: "scratch-context" }],
        prompts: [{ name: "scratch-brief" }],
      },
    });
    assert.equal(added.event.source_event_kind, "OperatorControl.McpAdd");
    assert.equal(added.added[0].id, "mcp.scratch");
    assert.equal((await sdkClient.listMcpTools({ thread_id: thread.thread_id })).length, 4);

    const imported = await sdkClient.importMcp({
      threadId: thread.thread_id,
      mcpJson: {
        mcpServers: {
          imported: {
            command: "node",
            args: [mcpStdioFixture],
            allowedTools: ["fetch"],
          },
        },
      },
    });
    assert.equal(imported.event.source_event_kind, "OperatorControl.McpImport");
    assert.equal(imported.imported[0].id, "mcp.imported");
    assert.equal(imported.server_count, 4);

    const removedScratch = await sdkThread.removeMcpServer("mcp.scratch");
    assert.equal(removedScratch.event.source_event_kind, "OperatorControl.McpRemove");
    assert.equal(removedScratch.removed[0].id, "mcp.scratch");
    const removedImported = await sdkClient.removeMcpServer("mcp.imported", {
      threadId: thread.thread_id,
    });
    assert.equal(removedImported.event.source_event_kind, "OperatorControl.McpRemove");
    assert.equal(removedImported.server_count, 2);

    const disabled = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/servers/mcp.search/disable`, {
      method: "POST",
      body: JSON.stringify({ source: "cli_tui" }),
    });
    assert.equal(disabled.event.source_event_kind, "OperatorControl.McpDisable");
    assert.equal(disabled.servers.find((server) => server.id === "mcp.search").enabled, false);
    assert.equal(disabled.tools.find((tool) => tool.serverId === "mcp.search").status, "disabled");
    assert.equal(disabled.receipt_refs.length, 1);

    const blockedInvoke = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/tools/mcp.search.query/invoke`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        server_id: "mcp.search",
        tool_name: "query",
        input: { q: "parity" },
      }),
    });
    assert.equal(blockedInvoke.event.source_event_kind, "OperatorControl.McpInvoke");
    assert.equal(blockedInvoke.event.component_kind, "mcp_tool_call");
    assert.equal(blockedInvoke.status, "blocked");
    assert.ok(blockedInvoke.blockers.includes("server_disabled"));

    const enabled = await sdkThread.enableMcpServer("mcp.search");
    assert.equal(enabled.event.source_event_kind, "OperatorControl.McpEnable");
    assert.equal(enabled.servers.find((server) => server.id === "mcp.search").enabled, true);

    const invoked = await sdkThread.invokeMcpTool({
      serverId: "mcp.search",
      toolName: "query",
      input: { q: "parity" },
    });
    assert.equal(invoked.status, "completed");
    assert.equal(invoked.server_id, "mcp.search");
    assert.equal(invoked.tool_name, "query");
    assert.equal(invoked.event.source_event_kind, "OperatorControl.McpInvoke");
    assert.equal(invoked.containment.executionMode, "live_stdio");
    assert.equal(invoked.transport_execution.executionMode, "live_stdio");
    assert.equal(invoked.result.structuredContent.arguments.q, "parity");
    assert.ok(invoked.receipt_refs[0].startsWith("receipt_mcp_mcp_invoke"));

    const remoteHttpAdded = await sdkThread.addMcpServer({
      label: "remote-http",
      server: {
        transport: "http",
        url: `${remoteFixture.url}/secure-mcp`,
        headers: { [remoteAuthHeaderName]: remoteAuthVaultRef },
        allowedTools: ["query"],
      },
    });
    assert.equal(remoteHttpAdded.added[0].transport, "http");
    assert.equal(remoteHttpAdded.added[0].serverUrl, `${remoteFixture.url}/secure-mcp`);
    assert.equal(remoteHttpAdded.added[0].headerSecretRefs[remoteAuthHeaderName].redacted, true);
    assert.equal(JSON.stringify(remoteHttpAdded).includes(remoteAuthVaultRef), false);
    assert.equal(JSON.stringify(remoteHttpAdded).includes(remoteAuthMaterial), false);

    const remoteSseAdded = await sdkThread.addMcpServer({
      label: "remote-sse",
      server: {
        transport: "sse",
        url: `${remoteFixture.url}/secure-sse`,
        headers: { [remoteAuthHeaderName]: remoteAuthVaultRef },
        allowedTools: ["query"],
      },
    });
    assert.equal(remoteSseAdded.added[0].transport, "sse");
    assert.equal(remoteSseAdded.added[0].headerSecretRefs[remoteAuthHeaderName].redacted, true);
    assert.equal(JSON.stringify(remoteSseAdded).includes(remoteAuthVaultRef), false);
    assert.equal(JSON.stringify(remoteSseAdded).includes(remoteAuthMaterial), false);

    const largeHttpAdded = await sdkThread.addMcpServer({
      label: "large-http",
      server: {
        transport: "http",
        url: `${largeRemoteFixture.url}/mcp`,
        allowedTools: ["large_tool_000"],
      },
    });
    assert.equal(largeHttpAdded.added[0].transport, "http");
    assert.equal(largeHttpAdded.added[0].serverUrl, `${largeRemoteFixture.url}/mcp`);

    const rawAuthValidation = await sdkThread.validateMcp({
      mcpServers: {
        "raw-auth": {
          transport: "http",
          url: `${remoteFixture.url}/secure-mcp`,
          headers: { [remoteAuthHeaderName]: remoteAuthMaterial },
          allowedTools: ["query"],
        },
      },
    });
    assert.equal(rawAuthValidation.ok, false);
    assert.ok(rawAuthValidation.issues.some((issue) => issue.code === "mcp_secret_not_vault_ref"));
    assert.equal(JSON.stringify(rawAuthValidation).includes(remoteAuthMaterial), false);

    const remoteStatus = await sdkThread.mcp({ live_discovery: true });
    const remoteDiscoveries = remoteStatus.live_discovery.servers.filter((entry) =>
      ["mcp.remote-http", "mcp.remote-sse"].includes(entry.server_id),
    );
    assert.equal(remoteDiscoveries.length, 2);
    assert.ok(remoteDiscoveries.every((entry) => entry.status === "completed"));
    assert.ok(remoteDiscoveries.some((entry) => entry.executionMode === "live_http"));
    assert.ok(remoteDiscoveries.some((entry) => entry.executionMode === "live_sse"));
    assert.ok(remoteDiscoveries.every((entry) => entry.authBoundary.secretValuesIncluded === false));
    assert.ok(remoteDiscoveries.every((entry) => entry.authBoundary.vaultResolvedHeaderCount === 1));
    assert.ok(remoteStatus.tools.some((tool) => tool.serverId === "mcp.remote-http" && tool.toolName === "query"));
    assert.ok(remoteStatus.resources.some((resource) => resource.uri === "ioi://fixture/remote-context"));
    assert.ok(remoteStatus.prompts.some((prompt) => prompt.name === "remote-brief"));
    assert.equal(JSON.stringify(remoteStatus).includes(remoteAuthVaultRef), false);
    assert.equal(JSON.stringify(remoteStatus).includes(remoteAuthMaterial), false);
    const largeDiscovery = remoteStatus.live_discovery.servers.find((entry) => entry.server_id === "mcp.large-http");
    assert.equal(largeDiscovery.status, "completed");
    assert.equal(largeDiscovery.catalogSummary.toolCount, 80);
    assert.equal(largeDiscovery.catalogSummary.deferred, true);
    assert.equal(largeDiscovery.catalogExposure.fullCatalogIncluded, false);
    assert.ok(
      remoteStatus.tools.filter((tool) => tool.serverId === "mcp.large-http").length <=
        largeDiscovery.catalogExposure.previewLimit,
    );
    assert.equal(JSON.stringify(remoteStatus).includes("large_tool_079"), false);

    const largePreviewStatus = await sdkThread.mcp({
      live_discovery: true,
      catalog_preview_limit: 5,
    });
    const largePreviewDiscovery = largePreviewStatus.live_discovery.servers.find(
      (entry) => entry.server_id === "mcp.large-http",
    );
    assert.equal(largePreviewDiscovery.catalogSummary.toolCount, 80);
    assert.equal(largePreviewDiscovery.catalogExposure.returnedToolCount, 5);
    assert.ok(
      largePreviewStatus.tools.filter((tool) => tool.serverId === "mcp.large-http").length <= 5,
    );

    const largeSearch = await sdkClient.searchMcpTools({
      threadId: thread.thread_id,
      serverId: "mcp.large-http",
      q: "large_tool_079",
      live_discovery: true,
      limit: 3,
    });
    assert.equal(largeSearch.status, "completed");
    assert.equal(largeSearch.returnedCount, 1);
    assert.equal(largeSearch.tools[0].toolName, "large_tool_079");
    assert.equal(largeSearch.catalogSummaries[0].toolCount, 80);
    assert.equal(largeSearch.catalogSummaries[0].deferred, true);

    const largeFetched = await sdkThread.getMcpTool("mcp.large-http.large_tool_079", {
      serverId: "mcp.large-http",
      live_discovery: true,
    });
    assert.equal(largeFetched.object, "ioi.runtime_mcp_tool_fetch");
    assert.equal(largeFetched.tool.toolName, "large_tool_079");
    assert.equal(largeFetched.tools.length, 1);

    const httpInvoked = await sdkThread.invokeMcpTool({
      serverId: "mcp.remote-http",
      toolName: "query",
      input: { q: "http-parity" },
    });
    assert.equal(httpInvoked.status, "completed");
    assert.equal(httpInvoked.containment.executionMode, "live_http");
    assert.equal(httpInvoked.transport_execution.executionMode, "live_http");
    assert.equal(httpInvoked.result.structuredContent.server, "ioi-fixture-mcp-http");
    assert.equal(httpInvoked.result.structuredContent.arguments.q, "http-parity");
    assert.ok(httpInvoked.evidence_refs.includes("mcp.transport.http.live"));
    assert.equal(httpInvoked.transport_execution.authBoundary.secretValuesIncluded, false);
    assert.equal(httpInvoked.transport_execution.authBoundary.vaultResolvedHeaderCount, 1);
    assert.equal(JSON.stringify(httpInvoked).includes(remoteAuthVaultRef), false);
    assert.equal(JSON.stringify(httpInvoked).includes(remoteAuthMaterial), false);

    const sseInvoked = await sdkThread.invokeMcpTool({
      serverId: "mcp.remote-sse",
      toolName: "query",
      input: { q: "sse-parity" },
    });
    assert.equal(sseInvoked.status, "completed");
    assert.equal(sseInvoked.containment.executionMode, "live_sse");
    assert.equal(sseInvoked.transport_execution.executionMode, "live_sse");
    assert.equal(sseInvoked.result.structuredContent.server, "ioi-fixture-mcp-sse");
    assert.equal(sseInvoked.result.structuredContent.arguments.q, "sse-parity");
    assert.ok(sseInvoked.evidence_refs.includes("mcp.transport.sse.live"));
    assert.equal(sseInvoked.transport_execution.authBoundary.secretValuesIncluded, false);
    assert.equal(sseInvoked.transport_execution.authBoundary.vaultResolvedHeaderCount, 1);
    assert.equal(JSON.stringify(sseInvoked).includes(remoteAuthVaultRef), false);
    assert.equal(JSON.stringify(sseInvoked).includes(remoteAuthMaterial), false);
    const observedRemoteHeaders = remoteFixture.observedHeaders();
    assert.ok(
      observedRemoteHeaders.some(
        (entry) => entry.path === "/secure-mcp" && entry.headers[remoteAuthHeaderName] === remoteAuthMaterial,
      ),
    );
    assert.ok(
      observedRemoteHeaders.some(
        (entry) => entry.path === "/secure-sse" && entry.headers[remoteAuthHeaderName] === remoteAuthMaterial,
      ),
    );
    assert.ok(
      observedRemoteHeaders.some(
        (entry) => entry.path === "/secure-messages" && entry.headers[remoteAuthHeaderName] === remoteAuthMaterial,
      ),
    );

    const publicDisabled = await sdkClient.disableMcpServer("mcp.search", {
      threadId: thread.thread_id,
    });
    assert.equal(publicDisabled.event.source_event_kind, "OperatorControl.McpDisable");
    const publicEnabled = await sdkClient.enableMcpServer("mcp.search", {
      threadId: thread.thread_id,
    });
    assert.equal(publicEnabled.event.source_event_kind, "OperatorControl.McpEnable");

    const serveStatus = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/serve`);
    assert.equal(serveStatus.transport, "http_jsonrpc");
    assert.deepEqual(
      serveStatus.allowed_tool_ids,
      ["workspace.status", "git.diff", "file.inspect"],
    );

    const serveInitialize = await fetchJson(`${daemon.endpoint}/v1/mcp/serve?thread_id=${thread.thread_id}`, {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: "init", method: "initialize", params: {} }),
    });
    assert.equal(serveInitialize.result.serverInfo.name, "ioi-runtime");
    assert.equal(serveInitialize.result.capabilities.tools.listChanged, false);

    const serveTools = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/serve`, {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: "tools", method: "tools/list" }),
    });
    assert.deepEqual(
      serveTools.result.tools.map((tool) => tool.name).sort(),
      ["file.inspect", "git.diff", "workspace.status"],
    );
    assert.ok(serveTools.result.tools.every((tool) => tool._meta.schema_version === "ioi.runtime.mcp-serve.v1"));

    const serveCall = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/mcp/serve`, {
      method: "POST",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "call",
        method: "tools/call",
        params: { name: "workspace.status", arguments: {} },
      }),
    });
    assert.equal(serveCall.result.structuredContent.status, "completed");
    assert.equal(serveCall.result.structuredContent.tool_name, "workspace.status");
    assert.equal(serveCall.result.structuredContent.workflow_node_id, "runtime.mcp-serve.workspace.status");
    assert.ok(serveCall.result.structuredContent.receipt_refs[0].startsWith("receipt_coding_tool_workspace.status"));

    const sdkServeTools = await sdkThread.mcpServeRpc({
      jsonrpc: "2.0",
      id: "sdk-tools",
      method: "tools/list",
    });
    assert.ok(
      sdkServeTools.result.tools.some((tool) => tool.name === "workspace.status"),
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    assert.ok(
      sdkEvents.some(
        (event) =>
          event.source === "mcp_serve" &&
          event.componentKind === "coding_tool" &&
          event.workflowNodeId === "runtime.mcp-serve.workspace.status",
      ),
    );
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    assert.ok(
      reactFlowProjection.nodes.some((node) => node.workflowNodeId === "runtime.mcp-manager"),
    );
    assert.ok(
      reactFlowProjection.nodes.some((node) => node.workflowNodeId === "runtime.mcp-manager.validate"),
    );
    assert.ok(
      reactFlowProjection.nodes.some(
        (node) => node.workflowNodeId === "runtime.mcp-tool.search.query",
      ),
    );
    assert.ok(
      reactFlowProjection.nodes.some(
        (node) => node.workflowNodeId === "runtime.mcp-serve.workspace.status",
      ),
    );

    const controlProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      surface: "tui",
      thread_id: thread.thread_id,
      last_cursor: `${invoked.event.event_stream_id}:${invoked.event.seq}`,
      mcp_rows: [
        {
          row_kind: "mcp_server",
          status: "configured",
          command: "mcp",
          raw_input: "/mcp status",
          mcp_server_id: searchServer.id,
          workflow_node_id: "runtime.mcp-manager",
          receipt_refs: threadStatus.receipt_refs,
          policy_decision_refs: threadStatus.policy_decision_refs,
        },
        {
          row_kind: "mcp_tool",
          status: "configured",
          command: "mcp",
          raw_input: "/mcp tools",
          mcp_server_id: searchQueryTool.serverId,
          mcp_tool_name: searchQueryTool.toolName,
          workflow_node_id: searchQueryTool.workflowNodeId,
          receipt_refs: threadStatus.receipt_refs,
        },
        {
          row_kind: "mcp_resource",
          status: "configured",
          command: "mcp",
          raw_input: "/mcp resources",
          mcp_server_id: resources[0].serverId,
          mcp_resource_uri: resources[0].uri,
          workflow_node_id: resources[0].workflowNodeId,
          receipt_refs: threadStatus.receipt_refs,
        },
        {
          row_kind: "mcp_prompt",
          status: "configured",
          command: "mcp",
          raw_input: "/mcp prompts",
          mcp_server_id: prompts[0].serverId,
          mcp_prompt_name: prompts[0].name,
          workflow_node_id: prompts[0].workflowNodeId,
          receipt_refs: threadStatus.receipt_refs,
        },
        {
          row_kind: "mcp_tool",
          status: "completed",
          command: "mcp",
          raw_input: "/mcp invoke",
          mcp_server_id: invoked.server_id,
          mcp_tool_name: invoked.tool_name,
          mcp_tool_call_id: invoked.tool_call_id,
          mcp_operation: "invoke",
          workflow_node_id: invoked.event.workflow_node_id,
          receipt_refs: invoked.receipt_refs,
          policy_decision_refs: invoked.policy_decision_refs,
        },
      ],
    });
    assert.equal(controlProjection.mcpRowCount, 5);
    assert.ok(controlProjection.rows.some((row) => row.rowKind === "mcp_server"));
    assert.ok(controlProjection.rows.some((row) => row.rowKind === "mcp_resource"));
    assert.ok(controlProjection.rows.some((row) => row.rowKind === "mcp_prompt"));
    assert.ok(
      controlProjection.rows.some(
        (row) =>
          row.rowKind === "mcp_tool" &&
          row.mcpServerId === "mcp.search" &&
          row.reactFlowNodeId.startsWith("runtime.mcp-tool.search."),
      ),
    );
    assert.ok(
      controlProjection.rows.some(
        (row) =>
          row.rowKind === "mcp_tool" &&
          row.mcpOperation === "invoke" &&
          row.mcpToolCallId === invoked.tool_call_id,
      ),
    );
  } finally {
    await daemon.close();
    await remoteFixture.close();
    await largeRemoteFixture.close();
  }
});

test("React Flow MCP workflow authoring compiles state nodes into live daemon MCP controls", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeMcpToolControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-mcp-react-flow-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-mcp-react-flow-state-"));
  fs.mkdirSync(path.join(cwd, ".cursor"), { recursive: true });
  fs.writeFileSync(
    path.join(cwd, ".cursor", "mcp.json"),
    JSON.stringify(
      {
        mcpServers: {
          search: {
            command: "node",
            args: [mcpStdioFixture],
            allowedTools: ["query"],
            containment: { mode: "sandboxed", allowChildProcesses: true },
          },
        },
      },
      null,
      2,
    ),
  );

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, mcpServers: {} },
      }),
    });
    const workflowGraphId = "workflow.react-flow.mcp-authoring";
    const searchNode = {
      id: "react-flow-mcp-search",
      type: "state",
      config: {
        logic: {
          stateKey: "mcp",
          stateOperation: "mcp_tool_search",
          reducer: "replace",
          mcpServerId: "mcp.search",
          mcpToolSearchQuery: "query",
          mcpConfigSourceMode: "workspace",
          mcpCatalogMode: "summary",
          mcpToolCatalogPreviewLimit: 2,
        },
      },
    };
    const fetchNode = {
      id: "react-flow-mcp-fetch",
      type: "state",
      config: {
        logic: {
          stateKey: "mcp",
          stateOperation: "mcp_tool_fetch",
          reducer: "replace",
          mcpServerId: "mcp.search",
          mcpToolName: "query",
          mcpConfigSourceMode: "workspace",
          mcpCatalogMode: "summary",
        },
      },
    };
    const invokeNode = {
      id: "react-flow-mcp-invoke",
      type: "state",
      config: {
        logic: {
          stateKey: "mcp",
          stateOperation: "mcp_tool_invoke",
          reducer: "replace",
          mcpServerId: "mcp.search",
          mcpToolName: "query",
          mcpToolInputJson: "{\"q\":\"workflow-authored\"}",
          mcpConfigSourceMode: "workspace",
          mcpCatalogMode: "summary",
          mcpContainmentMode: "sandboxed",
          mcpAllowNetworkEgress: false,
          mcpVaultHeaderRefsJson: "{}",
        },
      },
    };

    const searchRequest = createRuntimeMcpToolControlRequestFromWorkflowNode(
      searchNode,
      { threadId: thread.thread_id },
      { workflowGraphId },
    );
    assert.equal(searchRequest.method, "GET");
    assert.match(searchRequest.endpoint, /\/mcp\/tools\/search\?/);
    assert.match(searchRequest.endpoint, /source=react_flow/);
    const searchResult = await fetchJson(`${daemon.endpoint}${searchRequest.endpoint}`);
    assert.equal(searchResult.object, "ioi.runtime_mcp_tool_search");
    assert.equal(searchResult.status, "completed");
    assert.equal(searchResult.tools[0].stableToolId, "mcp.search.query");

    const fetchRequest = createRuntimeMcpToolControlRequestFromWorkflowNode(
      fetchNode,
      { threadId: thread.thread_id },
      { workflowGraphId },
    );
    assert.equal(fetchRequest.method, "GET");
    assert.equal(fetchRequest.toolId, "mcp.search.query");
    const fetchResult = await fetchJson(`${daemon.endpoint}${fetchRequest.endpoint}`);
    assert.equal(fetchResult.object, "ioi.runtime_mcp_tool_fetch");
    assert.equal(fetchResult.toolName, "query");
    assert.equal(fetchResult.tool.stableToolId, "mcp.search.query");

    const invokeRequest = createRuntimeMcpToolControlRequestFromWorkflowNode(
      invokeNode,
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(invokeRequest.method, "POST");
    assert.equal(
      invokeRequest.endpoint,
      `/v1/threads/${thread.thread_id}/mcp/tools/mcp.search.query/invoke`,
    );
    assert.equal(invokeRequest.body.workflowGraphId, workflowGraphId);
    assert.equal(invokeRequest.body.workflowNodeId, "runtime.mcp-tool.mcp.search.query");
    assert.equal(invokeRequest.body.containmentMode, "sandboxed");
    assert.equal(invokeRequest.body.allowNetworkEgress, false);
    const invoked = await fetchJson(`${daemon.endpoint}${invokeRequest.endpoint}`, {
      method: invokeRequest.method,
      body: JSON.stringify(invokeRequest.body),
    });
    assert.equal(invoked.status, "completed");
    assert.equal(invoked.event.source, "react_flow");
    assert.equal(invoked.event.source_event_kind, "OperatorControl.McpInvoke");
    assert.equal(invoked.event.workflow_graph_id, workflowGraphId);
    assert.equal(invoked.event.workflow_node_id, "runtime.mcp-tool.mcp.search.query");
    assert.equal(invoked.result.structuredContent.arguments.q, "workflow-authored");
    assert.equal(invoked.containment.executionMode, "live_stdio");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.ok(
      events.some(
        (event) =>
          event.source === "react_flow" &&
          event.source_event_kind === "OperatorControl.McpInvoke" &&
          event.workflow_graph_id === workflowGraphId,
      ),
    );
    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const projection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    assert.ok(
      projection.nodes.some(
        (node) => node.workflowNodeId === "runtime.mcp-tool.mcp.search.query",
      ),
    );
  } finally {
    await daemon.close();
  }
});

test("runtime_service thread creation requires RuntimeApiBridge and preserves bridge events", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-state-"));
  const unavailable = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const blocked = await fetchJsonStatus(`${unavailable.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(blocked.status, 424);
    assert.equal(blocked.body.error.code, "external_blocker");
    assert.equal(blocked.body.error.details.requiredBridge, "RuntimeApiBridge");
    assert.equal(blocked.body.error.details.syntheticFallbackAllowed, false);
  } finally {
    await unavailable.close();
  }

  const bridgeStateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-ready-state-"));
  const runtimeSessionId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const runtimeBridge = {
    bridgeId: "test-runtime-agent-service",
    async startThread(input) {
      return {
        bridge_id: "test-runtime-agent-service",
        session_id: runtimeSessionId,
        source: "runtime_service",
        status: "active",
        events: [
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: "",
            item_id: `${input.threadId}:item:runtime-thread-started`,
            idempotency_key: `runtime-service:${runtimeSessionId}:thread.started`,
            source: "runtime_service",
            source_event_kind: "AgentState.start",
            event_kind: "thread.started",
            status: "running",
            actor: "runtime",
            created_at: "2026-05-12T00:00:00.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_thread",
            workflow_node_id: "runtime.runtime-thread",
            payload_schema_version: "ioi.runtime.thread.v1",
            payload: {
              event_kind: "AgentStateStarted",
              session_id: runtimeSessionId,
              agent_id: input.agentId,
              thread_id: input.threadId,
            },
            fixture_profile: null,
          },
        ],
      };
    },
    async submitTurn(input) {
      const turnId = "turn_runtime_bridge_001";
      return {
        run_id: "run_runtime_bridge_001",
        turn_id: turnId,
        status: "completed",
        result: "Runtime bridge turn completed.",
        stop_reason: "runtime_bridge_completed",
        created_at: "2026-05-12T00:00:01.000Z",
        updated_at: "2026-05-12T00:00:02.000Z",
        events: [
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: turnId,
            item_id: `${turnId}:item:user-request`,
            idempotency_key: `runtime-service:${runtimeSessionId}:${turnId}:started`,
            source: "runtime_service",
            source_event_kind: "KernelEvent.AgentStep",
            event_kind: "turn.started",
            status: "running",
            actor: "user",
            created_at: "2026-05-12T00:00:01.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: "ioi.runtime.event.v1",
            payload: {
              event_kind: "TurnStarted",
              prompt: input.request.prompt,
            },
            fixture_profile: null,
          },
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: turnId,
            item_id: `${turnId}:item:assistant-result`,
            idempotency_key: `runtime-service:${runtimeSessionId}:${turnId}:completed`,
            source: "runtime_service",
            source_event_kind: "KernelEvent.AgentActionResult",
            event_kind: "turn.completed",
            status: "completed",
            actor: "assistant",
            created_at: "2026-05-12T00:00:02.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: "ioi.runtime.event.v1",
            payload: {
              event_kind: "TurnCompleted",
              summary: "Runtime bridge turn completed.",
            },
            fixture_profile: null,
          },
        ],
      };
    },
  };
  const daemon = await startRuntimeDaemonService({ cwd, stateDir: bridgeStateDir, runtimeBridge });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.equal(thread.session_id, runtimeSessionId);
    assert.equal(thread.fixture_profile, null);
    assert.equal(thread.runtime_profile, "runtime_service");
    assert.equal(thread.runtime_bridge_id, "test-runtime-agent-service");
    assert.equal(thread.latest_seq, 1);

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(events.length, 1);
    assert.equal(events[0].schema_version, "ioi.runtime.event.v1");
    assert.equal(events[0].source, "runtime_service");
    assert.equal(events[0].source_event_kind, "AgentState.start");
    assert.equal(events[0].fixture_profile, null);
    assert.equal(events[0].payload.session_id, runtimeSessionId);
    assert.equal(events[0].payload.agent_id, thread.agent_id);

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "This must flow through RuntimeApiBridge." }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.equal(turn.turn_id, "turn_runtime_bridge_001");
    assert.equal(turn.request_id, "run_runtime_bridge_001");
    assert.equal(turn.fixture_profile, null);
    assert.equal(turn.status, "completed");
    assert.equal(turn.result, "Runtime bridge turn completed.");
    assert.equal(turn.output, "Runtime bridge turn completed.");
    assert.equal(turn.text, "Runtime bridge turn completed.");
    assert.equal(turn.conversation.at(-1)?.role, "assistant");
    assert.equal(turn.conversation.at(-1)?.content, "Runtime bridge turn completed.");
    const replayed = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(turn.seq_end, replayed.length);
    assert.equal(turn.stop_reason, "runtime_bridge_completed");

    assert.deepEqual(replayed.map((event) => event.seq), Array.from({ length: replayed.length }, (_, i) => i + 1));
    assert.ok(replayed.every((event) => event.source === "runtime_service" || event.source === "runtime_auto"));
    assert.ok(replayed.every((event) => event.source === "runtime_auto" || event.fixture_profile === null));
    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(runEvents.map((event) => event.event_id), replayed.slice(1).map((event) => event.event_id));
  } finally {
    await daemon.close();
  }
});

test("runtime_service profile auto-wires RuntimeAgentService command bridge from env", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-state-"));
  const bridgeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-bridge-"));
  const bridgeScript = path.join(bridgeDir, "bridge-command.mjs");
  const traceFile = path.join(bridgeDir, "bridge-trace.jsonl");
  const runtimeSessionId = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
  fs.writeFileSync(
    bridgeScript,
    `
import fs from "node:fs";

const request = JSON.parse(fs.readFileSync(0, "utf8"));
fs.appendFileSync(process.env.BRIDGE_TRACE_FILE, JSON.stringify({
  schema_version: request.schema_version,
  bridge_id: request.bridge_id,
  operation: request.operation,
  runtime_profile: request.input?.runtimeProfile,
  thread_id: request.input?.threadId,
  session_id: request.input?.sessionId ?? null,
}) + "\\n");

const input = request.input ?? {};
const sessionId = "${runtimeSessionId}";

if (request.operation === "start_thread") {
  console.log("RuntimeAgentService command bridge accepted start_thread");
  console.log(JSON.stringify({
    ok: true,
    result: {
      bridge_id: request.bridge_id,
      session_id: sessionId,
      source: "runtime_service",
      status: "active",
      events: [{
        item_id: input.threadId + ":item:runtime-command-started",
        idempotency_key: "runtime-command:" + sessionId + ":thread.started",
        source_event_kind: "RuntimeAgentService.handle_service_call.start@v1",
        event_kind: "thread.started",
        status: "running",
        actor: "runtime",
        created_at: "2026-05-12T00:00:03.000Z",
        component_kind: "runtime_thread",
        workflow_node_id: "runtime.runtime-thread",
        payload_schema_version: "ioi.runtime.thread.v1",
        payload: {
          bridge_schema_version: request.schema_version,
          session_id: sessionId,
          runtime_profile: input.runtimeProfile,
        },
        fixture_profile: null,
      }],
    },
  }));
} else if (request.operation === "submit_turn") {
  const turnId = "turn_runtime_command_001";
  console.log(JSON.stringify({
    ok: true,
    result: {
      bridge_id: request.bridge_id,
      run_id: "run_runtime_command_001",
      turn_id: turnId,
      source: "runtime_service",
      status: "completed",
      result: "RuntimeAgentService command bridge turn completed.",
      stop_reason: "runtime_bridge_completed",
      created_at: "2026-05-12T00:00:04.000Z",
      updated_at: "2026-05-12T00:00:05.000Z",
      events: [
        {
          item_id: turnId + ":item:user-message",
          idempotency_key: "runtime-command:" + sessionId + ":" + turnId + ":started",
          source_event_kind: "RuntimeAgentService.handle_service_call.post_message@v1",
          event_kind: "turn.started",
          status: "running",
          actor: "user",
          created_at: "2026-05-12T00:00:04.000Z",
          component_kind: "runtime_turn",
          workflow_node_id: "runtime.runtime-turn",
          payload_schema_version: "ioi.runtime.event.v1",
          payload: {
            prompt: input.request?.prompt,
            session_id: input.sessionId,
          },
          fixture_profile: null,
        },
        {
          item_id: turnId + ":item:assistant-message",
          idempotency_key: "runtime-command:" + sessionId + ":" + turnId + ":completed",
          source_event_kind: "RuntimeAgentService.handle_service_call.step@v1",
          event_kind: "turn.completed",
          status: "completed",
          actor: "assistant",
          created_at: "2026-05-12T00:00:05.000Z",
          component_kind: "runtime_turn",
          workflow_node_id: "runtime.runtime-turn",
          payload_schema_version: "ioi.runtime.event.v1",
          payload: {
            summary: "RuntimeAgentService command bridge turn completed.",
            session_id: input.sessionId,
          },
          fixture_profile: null,
        },
      ],
    },
  }));
} else {
  console.log(JSON.stringify({
    ok: false,
    error: {
      code: "unsupported_operation",
      message: "unsupported operation " + request.operation,
    },
  }));
}
`,
  );

  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
    trace: process.env.BRIDGE_TRACE_FILE,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = process.execPath;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify([bridgeScript]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "env-command-runtime-agent-service";
  process.env.BRIDGE_TRACE_FILE = traceFile;

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.session_id, runtimeSessionId);
    assert.equal(thread.runtime_bridge_id, "env-command-runtime-agent-service");
    assert.equal(thread.fixture_profile, null);

    const startEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(startEvents.length, 1);
    assert.equal(startEvents[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(startEvents[0].payload.bridge_schema_version, "ioi.runtime.bridge.command.v1");

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Flow through the command bridge." }),
    });
    assert.equal(turn.turn_id, "turn_runtime_command_001");
    assert.equal(turn.request_id, "run_runtime_command_001");
    assert.equal(turn.status, "completed");
    assert.equal(turn.stop_reason, "runtime_bridge_completed");
    assert.equal(turn.result, "RuntimeAgentService command bridge turn completed.");
    assert.equal(turn.output, "RuntimeAgentService command bridge turn completed.");
    assert.equal(turn.text, "RuntimeAgentService command bridge turn completed.");
    assert.equal(turn.conversation.at(-1)?.role, "assistant");
    assert.equal(turn.conversation.at(-1)?.content, "RuntimeAgentService command bridge turn completed.");
    assert.equal(turn.fixture_profile, null);
    assert.equal(turn.seq_start, 2);
    const replayed = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(turn.seq_end, replayed.length);

    const trace = fs.readFileSync(traceFile, "utf8")
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
    assert.deepEqual(trace.map((entry) => entry.operation), ["start_thread", "submit_turn"]);
    assert.ok(trace.every((entry) => entry.schema_version === "ioi.runtime.bridge.command.v1"));
    assert.ok(trace.every((entry) => entry.bridge_id === "env-command-runtime-agent-service"));
    assert.equal(trace[0].runtime_profile, "runtime_service");
    assert.equal(trace[1].session_id, runtimeSessionId);
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
    restoreEnv("BRIDGE_TRACE_FILE", previousEnv.trace);
  }
});

test("runtime_service profile auto-wires the Rust RuntimeAgentService bridge executable from env", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
    inferenceUrl: process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL,
    inferenceApiKey: process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY,
    inferenceModel: process.env.IOI_RUNTIME_AGENT_SERVICE_MODEL,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-contract";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL = `${daemon.endpoint}/v1/chat/completions`;
    process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY = "dummy-key";
    process.env.IOI_RUNTIME_AGENT_SERVICE_MODEL = "auto";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Start a durable Rust-backed runtime-service thread.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.match(thread.session_id, /^[a-f0-9]{64}$/);
    assert.equal(thread.runtime_profile, "runtime_service");
    assert.equal(thread.runtime_bridge_id, "rust-runtime-agent-service-contract");
    assert.equal(thread.fixture_profile, null);
    assert.equal(thread.latest_seq, 1);

    const startEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(startEvents.length, 1);
    assert.equal(startEvents[0].source, "runtime_service");
    assert.equal(startEvents[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(startEvents[0].event_kind, "thread.started");
    assert.equal(startEvents[0].component_kind, "runtime_thread");
    assert.equal(startEvents[0].workflow_node_id, "runtime.runtime-thread");
    assert.equal(startEvents[0].fixture_profile, null);
    assert.equal(startEvents[0].payload.bridge_schema_version, "ioi.runtime.bridge.command.v1");
    assert.equal(startEvents[0].payload.session_id, thread.session_id);
    assert.equal(startEvents[0].payload.goal, "Start a durable Rust-backed runtime-service thread.");
    assert.equal(Number(startEvents[0].payload.max_steps), 2);

    const prompt = "Exercise the Rust RuntimeAgentService bridge executable.";
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.match(turn.turn_id, /^turn_runtime_service_[a-f0-9]{16}_\d+$/);
    assert.match(turn.request_id, /^run_runtime_service_[a-f0-9]{16}_\d+$/);
    assert.equal(turn.fixture_profile, null);
    assert.ok(["completed", "blocked", "failed", "paused", "waiting_for_input"].includes(turn.status));
    assert.match(turn.stop_reason, /^runtime_bridge_/);
    assert.equal(turn.seq_start, 2);
    assert.ok(turn.seq_end === null || turn.seq_end >= 3);

    const replayed = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.ok(replayed.length >= 4);
    assert.equal(turn.seq_end ?? replayed.at(-1).seq, replayed.at(-1).seq);
    assert.equal(replayed[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(replayed[1].source_event_kind, "RuntimeAgentService.handle_service_call.post_message@v1");
    assert.equal(replayed.at(-1).source_event_kind, "RuntimeAgentService.handle_service_call.step@v1");
    assert.deepEqual(replayed.map((event) => event.event_kind).slice(0, 2), [
      "thread.started",
      "turn.started",
    ]);
    const mappedKernelEvents = replayed.slice(2, -1);
    assert.ok(mappedKernelEvents.length >= 1);
    const actionResultEvent = mappedKernelEvents.find(
      (event) => event.source_event_kind === "KernelEvent::AgentActionResult",
    );
    assert.ok(actionResultEvent);
    assert.ok(["tool.completed", "tool.failed"].includes(actionResultEvent.event_kind));
    assert.equal(actionResultEvent.component_kind, "tool_result");
    assert.equal(actionResultEvent.workflow_node_id, "runtime.tool-result");
    assert.equal(actionResultEvent.payload_schema_version, "ioi.runtime.kernel-event.v1");
    assert.equal(actionResultEvent.payload.event_kind, "KernelEvent::AgentActionResult");
    assert.equal(actionResultEvent.payload.tool_name, "system::intent_clarification");
    assert.equal(actionResultEvent.payload.agent_status, "Paused");
    assert.equal(Number(actionResultEvent.payload.step_index), 0);
    assert.ok(["turn.completed", "turn.failed"].includes(replayed.at(-1).event_kind));
    assert.ok(replayed.every((event) => event.source === "runtime_service" || event.source === "runtime_auto"));
    assert.ok(replayed.every((event) => event.source === "runtime_auto" || event.fixture_profile === null));
    assert.ok(replayed.every((event) => event.source === "runtime_auto" || event.payload.session_id === thread.session_id));
    assert.equal(replayed[1].payload.prompt, prompt);
    assert.equal(typeof replayed.at(-1).payload.agent_status, "string");
    assert.ok(Number.isFinite(Number(replayed.at(-1).payload.step_count)));
    assert.ok(fs.existsSync(path.join(bridgeData, "runtime-state.redb")));
    assert.ok(fs.existsSync(path.join(bridgeData, "desktop-memory.db")));

    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(
      runEvents.map((event) => event.event_id),
      replayed.slice(1).map((event) => event.event_id),
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkActionResult = sdkEvents.find(
      (event) => event.sourceEventKind === "KernelEvent::AgentActionResult",
    );
    assert.ok(sdkActionResult);
    assert.ok(["tool_completed", "tool_failed"].includes(sdkActionResult.type));
    assert.equal(sdkActionResult.payloadSchemaVersion, "ioi.runtime.kernel-event.v1");
    assert.equal(sdkActionResult.componentKind, "tool_result");
    assert.equal(sdkActionResult.workflowNodeId, "runtime.tool-result");
    assert.equal(sdkActionResult.toolName, "system::intent_clarification");
    assert.equal(sdkActionResult.agentStatus, "Paused");
    assert.equal(sdkActionResult.stepIndex, 0);
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    const sdkTurnEvents = await collect(sdkTurn.events());
    assert.deepEqual(
      sdkTurnEvents.map((event) => event.id),
      replayed.slice(1).map((event) => event.event_id),
    );
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL", previousEnv.inferenceUrl);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY", previousEnv.inferenceApiKey);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_MODEL", previousEnv.inferenceModel);
  }
});

test("mapped KernelEvent row keeps one canonical sequence across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
    inferenceUrl: process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL,
    inferenceApiKey: process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY,
    inferenceModel: process.env.IOI_RUNTIME_AGENT_SERVICE_MODEL,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-cross-surface";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL = `${daemon.endpoint}/v1/chat/completions`;
    process.env.IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY = "dummy-key";
    process.env.IOI_RUNTIME_AGENT_SERVICE_MODEL = "auto";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove one mapped KernelEvent has one cross-surface sequence.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Emit a mapped KernelEvent that every operator surface can inspect.",
      }),
    });

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const daemonKernelEvent = daemonEvents.find(
      (event) => event.source_event_kind === "KernelEvent::AgentActionResult",
    );
    assert.ok(daemonKernelEvent);
    assert.ok(["tool.completed", "tool.failed"].includes(daemonKernelEvent.event_kind));
    assert.equal(daemonKernelEvent.turn_id, turn.turn_id);
    assert.equal(daemonKernelEvent.component_kind, "tool_result");
    assert.equal(daemonKernelEvent.workflow_node_id, "runtime.tool-result");
    assert.equal(daemonKernelEvent.payload_schema_version, "ioi.runtime.kernel-event.v1");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkKernelEvent = sdkEvents.find((event) => event.id === daemonKernelEvent.event_id);
    assert.ok(sdkKernelEvent);

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "stream",
        "--thread-id",
        thread.thread_id,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliProjection = JSON.parse(cliResult.stdout);
    const cliKernelEvent = cliProjection.events.find(
      (event) => event.event_id === daemonKernelEvent.event_id,
    );
    assert.ok(cliKernelEvent);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(daemonKernelEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${daemonKernelEvent.event_stream_id}:${daemonKernelEvent.seq}`;
    assert.equal(sdkKernelEvent.id, daemonKernelEvent.event_id);
    assert.equal(sdkKernelEvent.seq, daemonKernelEvent.seq);
    assert.equal(sdkKernelEvent.cursor, canonicalCursor);
    assert.equal(sdkKernelEvent.eventKind, daemonKernelEvent.event_kind);
    assert.equal(sdkKernelEvent.sourceEventKind, daemonKernelEvent.source_event_kind);
    assert.equal(sdkKernelEvent.componentKind, daemonKernelEvent.component_kind);
    assert.equal(sdkKernelEvent.workflowNodeId, daemonKernelEvent.workflow_node_id);
    assert.equal(sdkKernelEvent.payloadSchemaVersion, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(sdkKernelEvent.receiptRefs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(sdkKernelEvent.policyDecisionRefs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(sdkKernelEvent.artifactRefs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(sdkKernelEvent.rollbackRefs, daemonKernelEvent.rollback_refs);

    assert.equal(cliProjection.schema_version, "ioi.agent-cli.runtime-event-stream.v1");
    assert.equal(cliKernelEvent.seq, daemonKernelEvent.seq);
    assert.equal(cliKernelEvent.event_stream_id, daemonKernelEvent.event_stream_id);
    assert.equal(cliKernelEvent.event_kind, daemonKernelEvent.event_kind);
    assert.equal(cliKernelEvent.source_event_kind, daemonKernelEvent.source_event_kind);
    assert.equal(cliKernelEvent.component_kind, daemonKernelEvent.component_kind);
    assert.equal(cliKernelEvent.workflow_node_id, daemonKernelEvent.workflow_node_id);
    assert.equal(cliKernelEvent.payload_schema_version, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(cliKernelEvent.receipt_refs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(cliKernelEvent.policy_decision_refs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(cliKernelEvent.artifact_refs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(cliKernelEvent.rollback_refs, daemonKernelEvent.rollback_refs);

    assert.equal(reactFlowNode.latestSeq, daemonKernelEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, daemonKernelEvent.event_id);
    assert.equal(reactFlowNode.componentKind, daemonKernelEvent.component_kind);
    assert.equal(reactFlowNode.workflowNodeId, daemonKernelEvent.workflow_node_id);
    assert.equal(reactFlowNode.latestPayloadSchemaVersion, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(reactFlowNode.receiptRefs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(reactFlowNode.policyDecisionRefs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(reactFlowNode.artifactRefs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(reactFlowNode.rollbackRefs, daemonKernelEvent.rollback_refs);
    assert.ok(reactFlowNode.sourceEventKinds.includes(daemonKernelEvent.source_event_kind));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL", previousEnv.inferenceUrl);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY", previousEnv.inferenceApiKey);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_MODEL", previousEnv.inferenceModel);
  }
});

test("operator interrupt keeps one canonical control event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-interrupt";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove operator interrupt control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare an interruptible turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "interrupt",
        "--thread-id",
        thread.thread_id,
        "--turn-id",
        turn.turn_id,
        "--reason",
        "operator validation interrupt",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliTurn = JSON.parse(cliResult.stdout);
    assert.equal(cliTurn.status, "interrupted");
    assert.equal(cliTurn.stop_reason, "operator_interrupt");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.event_kind, "turn.interrupted");
    assert.equal(interruptEvent.status, "interrupted");
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.actor, "user");
    assert.equal(interruptEvent.thread_id, thread.thread_id);
    assert.equal(interruptEvent.turn_id, turn.turn_id);
    assert.equal(interruptEvent.component_kind, "operator_control");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    assert.equal(interruptEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(interruptEvent.payload.reason, "operator validation interrupt");
    assert.ok(interruptEvent.receipt_refs.includes(`receipt_${turn.request_id}_operator_interrupt`));
    assert.ok(interruptEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_interrupt_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    assert.equal(sdkTurn.status, "interrupted");
    const sdkInterrupted = await sdkTurn.interrupt({ reason: "sdk idempotency probe" });
    assert.equal(sdkInterrupted.status, "interrupted");
    const afterSdkInterrupt = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkInterrupt.filter((event) => event.source_event_kind === "OperatorControl.Interrupt").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterruptEvent = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterruptEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    assert.equal(sdkInterruptEvent.type, "turn_interrupted");
    assert.equal(sdkInterruptEvent.seq, interruptEvent.seq);
    assert.equal(sdkInterruptEvent.cursor, canonicalCursor);
    assert.equal(sdkInterruptEvent.eventKind, interruptEvent.event_kind);
    assert.equal(sdkInterruptEvent.sourceEventKind, interruptEvent.source_event_kind);
    assert.equal(sdkInterruptEvent.componentKind, interruptEvent.component_kind);
    assert.equal(sdkInterruptEvent.workflowNodeId, interruptEvent.workflow_node_id);
    assert.equal(sdkInterruptEvent.payloadSchemaVersion, interruptEvent.payload_schema_version);
    assert.deepEqual(sdkInterruptEvent.receiptRefs, interruptEvent.receipt_refs);
    assert.deepEqual(sdkInterruptEvent.policyDecisionRefs, interruptEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, interruptEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, interruptEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.operator-interrupt");
    assert.equal(reactFlowNode.status, "interrupted");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Interrupt"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow operator interrupt control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "pause live turn from React Flow control";
  const workflowGraphId = "workflow.react-flow.operator-interrupt-proof";
  const workflowNodeId = "runtime.operator-interrupt";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-interrupt";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated operator interrupt keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated interrupt control validation.",
      }),
    });
    const workflowNode = {
      id: "react-flow-operator-interrupt-control",
      type: "runtime_operator_interrupt",
      config: {
        logic: {
          runtimeOperatorInterruptEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
          runtimeOperatorInterruptThreadIdField: "threadId",
          runtimeOperatorInterruptTurnIdField: "turnId",
          runtimeOperatorInterruptReasonField: "reason",
          runtimeOperatorInterruptWorkflowNodeId: workflowNodeId,
          runtimeOperatorInterruptActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.interrupt"] },
      },
    };
    const control = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, reason },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_operator_interrupt");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "operator_control");

    const interrupted = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(interrupted.turn_id, turn.turn_id);
    assert.equal(interrupted.status, "interrupted");
    assert.equal(interrupted.stop_reason, "operator_interrupt");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt" && event.source === "react_flow",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.event_kind, "turn.interrupted");
    assert.equal(interruptEvent.status, "interrupted");
    assert.equal(interruptEvent.source, "react_flow");
    assert.equal(interruptEvent.actor, "user");
    assert.equal(interruptEvent.thread_id, thread.thread_id);
    assert.equal(interruptEvent.turn_id, turn.turn_id);
    assert.equal(interruptEvent.workflow_graph_id, workflowGraphId);
    assert.equal(interruptEvent.workflow_node_id, workflowNodeId);
    assert.equal(interruptEvent.component_kind, "operator_control");
    assert.equal(interruptEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(interruptEvent.payload.reason, reason);
    assert.equal(interruptEvent.payload.requested_by, "operator");
    assert.ok(interruptEvent.receipt_refs.includes(`receipt_${turn.request_id}_operator_interrupt`));
    assert.ok(interruptEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_interrupt_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterruptEvent = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterruptEvent);
    assert.equal(sdkInterruptEvent.type, "turn_interrupted");
    assert.equal(sdkInterruptEvent.sourceEventKind, "OperatorControl.Interrupt");
    assert.equal(sdkInterruptEvent.componentKind, "operator_control");
    assert.equal(sdkInterruptEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkInterruptEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkInterruptEvent.receiptRefs, interruptEvent.receipt_refs);
    assert.deepEqual(sdkInterruptEvent.policyDecisionRefs, interruptEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_operator_interrupt");
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "interrupted");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Interrupt"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("operator steer keeps one canonical guidance event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const guidance = "focus on the current failing assertion";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-steer";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove operator steer control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a steerable turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "steer",
        "--thread-id",
        thread.thread_id,
        "--turn-id",
        turn.turn_id,
        "--guidance",
        guidance,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliTurn = JSON.parse(cliResult.stdout);
    assert.equal(cliTurn.status, turn.status);
    assert.equal(cliTurn.stop_reason, turn.stop_reason);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const steerEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Steer",
    );
    assert.ok(steerEvent);
    assert.equal(steerEvent.event_kind, "turn.steered");
    assert.equal(steerEvent.status, "completed");
    assert.equal(steerEvent.source, "cli_tui");
    assert.equal(steerEvent.actor, "user");
    assert.equal(steerEvent.thread_id, thread.thread_id);
    assert.equal(steerEvent.turn_id, turn.turn_id);
    assert.equal(steerEvent.component_kind, "operator_control");
    assert.equal(steerEvent.workflow_node_id, "runtime.operator-steer");
    assert.equal(steerEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(steerEvent.payload.guidance, guidance);
    assert.ok(steerEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${turn.request_id}_operator_steer_`)));
    assert.ok(steerEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_steer_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    assert.equal(sdkTurn.status, cliTurn.status);
    const sdkSteered = await sdkTurn.steer({ guidance });
    assert.equal(sdkSteered.status, cliTurn.status);
    const afterSdkSteer = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkSteer.filter((event) => event.source_event_kind === "OperatorControl.Steer").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkSteerEvent = sdkEvents.find((event) => event.id === steerEvent.event_id);
    assert.ok(sdkSteerEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(steerEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${steerEvent.event_stream_id}:${steerEvent.seq}`;
    assert.equal(sdkSteerEvent.type, "turn_steered");
    assert.equal(sdkSteerEvent.seq, steerEvent.seq);
    assert.equal(sdkSteerEvent.cursor, canonicalCursor);
    assert.equal(sdkSteerEvent.eventKind, steerEvent.event_kind);
    assert.equal(sdkSteerEvent.sourceEventKind, steerEvent.source_event_kind);
    assert.equal(sdkSteerEvent.componentKind, steerEvent.component_kind);
    assert.equal(sdkSteerEvent.workflowNodeId, steerEvent.workflow_node_id);
    assert.equal(sdkSteerEvent.payloadSchemaVersion, steerEvent.payload_schema_version);
    assert.deepEqual(sdkSteerEvent.receiptRefs, steerEvent.receipt_refs);
    assert.deepEqual(sdkSteerEvent.policyDecisionRefs, steerEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, steerEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, steerEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.operator-steer");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Steer"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow operator steer control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorSteerControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const guidance = "focus live turn from React Flow steer control";
  const workflowGraphId = "workflow.react-flow.operator-steer-proof";
  const workflowNodeId = "runtime.operator-steer";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-steer";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated operator steer keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated steer control validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-operator-steer-control",
      type: "runtime_operator_steer",
      config: {
        logic: {
          runtimeOperatorSteerEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
          runtimeOperatorSteerThreadIdField: "threadId",
          runtimeOperatorSteerTurnIdField: "turnId",
          runtimeOperatorSteerGuidanceField: "guidance",
          runtimeOperatorSteerWorkflowNodeId: workflowNodeId,
          runtimeOperatorSteerActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.steer"] },
      },
    };
    const control = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, guidance },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_operator_steer");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "operator_control");

    const steered = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(steered.turn_id, turn.turn_id);
    assert.equal(steered.status, turn.status);
    assert.equal(steered.stop_reason, turn.stop_reason);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const steerEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Steer" && event.source === "react_flow",
    );
    assert.ok(steerEvent);
    assert.equal(steerEvent.event_kind, "turn.steered");
    assert.equal(steerEvent.status, "completed");
    assert.equal(steerEvent.source, "react_flow");
    assert.equal(steerEvent.actor, "user");
    assert.equal(steerEvent.thread_id, thread.thread_id);
    assert.equal(steerEvent.turn_id, turn.turn_id);
    assert.equal(steerEvent.workflow_graph_id, workflowGraphId);
    assert.equal(steerEvent.workflow_node_id, workflowNodeId);
    assert.equal(steerEvent.component_kind, "operator_control");
    assert.equal(steerEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(steerEvent.payload.guidance, guidance);
    assert.equal(steerEvent.payload.requested_by, "operator");
    assert.ok(steerEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${turn.request_id}_operator_steer_`)));
    assert.ok(steerEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_steer_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkSteerEvent = sdkEvents.find((event) => event.id === steerEvent.event_id);
    assert.ok(sdkSteerEvent);
    assert.equal(sdkSteerEvent.type, "turn_steered");
    assert.equal(sdkSteerEvent.sourceEventKind, "OperatorControl.Steer");
    assert.equal(sdkSteerEvent.componentKind, "operator_control");
    assert.equal(sdkSteerEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkSteerEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkSteerEvent.receiptRefs, steerEvent.receipt_refs);
    assert.deepEqual(sdkSteerEvent.policyDecisionRefs, steerEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(steerEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_operator_steer");
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Steer"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("context compact keeps one canonical compaction event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const reason = "reduce stale context for live validation";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-compact";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove context compact control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a turn with context for compaction validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "compact",
        "--thread-id",
        thread.thread_id,
        "--reason",
        reason,
        "--scope",
        "thread",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliThread = JSON.parse(cliResult.stdout);
    assert.equal(cliThread.thread_id, thread.thread_id);
    assert.ok(cliThread.latest_seq > thread.latest_seq);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Compact",
    );
    assert.ok(compactEvent);
    assert.equal(compactEvent.event_kind, "context.compacted");
    assert.equal(compactEvent.status, "completed");
    assert.equal(compactEvent.source, "cli_tui");
    assert.equal(compactEvent.actor, "user");
    assert.equal(compactEvent.thread_id, thread.thread_id);
    assert.equal(compactEvent.turn_id, turn.turn_id);
    assert.equal(compactEvent.component_kind, "context_compaction");
    assert.equal(compactEvent.workflow_node_id, "runtime.context-compact");
    assert.equal(compactEvent.payload_schema_version, "ioi.runtime.context-compaction.v1");
    assert.equal(compactEvent.payload.reason, reason);
    assert.equal(compactEvent.payload.scope, "thread");
    assert.ok(compactEvent.receipt_refs.some((ref) =>
      ref.startsWith(`receipt_${turn.request_id}_context_compaction_`),
    ));
    assert.ok(compactEvent.policy_decision_refs.includes(`policy_${turn.request_id}_context_compaction_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkCompacted = await sdkThread.compact({ reason, scope: "thread" });
    assert.equal(sdkCompacted.id, thread.thread_id);
    const afterSdkCompact = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkCompact.filter((event) => event.source_event_kind === "OperatorControl.Compact").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkCompactEvent = sdkEvents.find((event) => event.id === compactEvent.event_id);
    assert.ok(sdkCompactEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${compactEvent.event_stream_id}:${compactEvent.seq}`;
    assert.equal(sdkCompactEvent.type, "context_compacted");
    assert.equal(sdkCompactEvent.seq, compactEvent.seq);
    assert.equal(sdkCompactEvent.cursor, canonicalCursor);
    assert.equal(sdkCompactEvent.eventKind, compactEvent.event_kind);
    assert.equal(sdkCompactEvent.sourceEventKind, compactEvent.source_event_kind);
    assert.equal(sdkCompactEvent.componentKind, compactEvent.component_kind);
    assert.equal(sdkCompactEvent.workflowNodeId, compactEvent.workflow_node_id);
    assert.equal(sdkCompactEvent.payloadSchemaVersion, compactEvent.payload_schema_version);
    assert.deepEqual(sdkCompactEvent.receiptRefs, compactEvent.receipt_refs);
    assert.deepEqual(sdkCompactEvent.policyDecisionRefs, compactEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, compactEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, compactEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "context_compaction");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.context-compact");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Compact"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow context compact control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeContextCompactControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "reduce live context from React Flow compact control";
  const scope = "thread";
  const workflowGraphId = "workflow.react-flow.context-compact-proof";
  const workflowNodeId = "runtime.context-compact";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-compact";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated context compact keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated context compact validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-context-compact-control",
      type: "runtime_context_compact",
      config: {
        logic: {
          runtimeContextCompactEndpoint: "/v1/threads/{threadId}/compact",
          runtimeContextCompactThreadIdField: "threadId",
          runtimeContextCompactTurnIdField: "turnId",
          runtimeContextCompactReasonField: "reason",
          runtimeContextCompactScopeField: "scope",
          runtimeContextCompactWorkflowNodeId: workflowNodeId,
          runtimeContextCompactActor: "operator",
        },
        law: { privilegedActions: ["runtime.context.compact"] },
      },
    };
    const control = createRuntimeContextCompactControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, reason, scope },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_context_compact");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "context_compaction");

    const compacted = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(compacted.thread_id, thread.thread_id);
    assert.ok(compacted.latest_seq > thread.latest_seq);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Compact" && event.source === "react_flow",
    );
    assert.ok(compactEvent);
    assert.equal(compactEvent.event_kind, "context.compacted");
    assert.equal(compactEvent.status, "completed");
    assert.equal(compactEvent.source, "react_flow");
    assert.equal(compactEvent.actor, "user");
    assert.equal(compactEvent.thread_id, thread.thread_id);
    assert.equal(compactEvent.turn_id, turn.turn_id);
    assert.equal(compactEvent.workflow_graph_id, workflowGraphId);
    assert.equal(compactEvent.workflow_node_id, workflowNodeId);
    assert.equal(compactEvent.component_kind, "context_compaction");
    assert.equal(compactEvent.payload_schema_version, "ioi.runtime.context-compaction.v1");
    assert.equal(compactEvent.payload.reason, reason);
    assert.equal(compactEvent.payload.scope, scope);
    assert.equal(compactEvent.payload.requested_by, "operator");
    assert.ok(compactEvent.receipt_refs.some((ref) =>
      ref.startsWith(`receipt_${turn.request_id}_context_compaction_`),
    ));
    assert.ok(compactEvent.policy_decision_refs.includes(`policy_${turn.request_id}_context_compaction_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkCompactEvent = sdkEvents.find((event) => event.id === compactEvent.event_id);
    assert.ok(sdkCompactEvent);
    assert.equal(sdkCompactEvent.type, "context_compacted");
    assert.equal(sdkCompactEvent.sourceEventKind, "OperatorControl.Compact");
    assert.equal(sdkCompactEvent.componentKind, "context_compaction");
    assert.equal(sdkCompactEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkCompactEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkCompactEvent.receiptRefs, compactEvent.receipt_refs);
    assert.deepEqual(sdkCompactEvent.policyDecisionRefs, compactEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_context_compact");
    assert.equal(reactFlowNode.componentKind, "context_compaction");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Compact"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("thread fork keeps one canonical source event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const reason = "branch live context for validation";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-fork";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove thread fork control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a forkable turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "fork",
        "--thread-id",
        thread.thread_id,
        "--reason",
        reason,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliFork = JSON.parse(cliResult.stdout);
    assert.equal(cliFork.source_thread_id, thread.thread_id);
    assert.notEqual(cliFork.thread_id, thread.thread_id);
    assert.ok(cliFork.forked_from_seq >= turn.seq_end);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const forkEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Fork",
    );
    assert.ok(forkEvent);
    assert.equal(forkEvent.event_kind, "thread.forked");
    assert.equal(forkEvent.status, "completed");
    assert.equal(forkEvent.source, "cli_tui");
    assert.equal(forkEvent.actor, "user");
    assert.equal(forkEvent.thread_id, thread.thread_id);
    assert.equal(forkEvent.turn_id, turn.turn_id);
    assert.equal(forkEvent.component_kind, "thread_fork");
    assert.equal(forkEvent.workflow_node_id, "runtime.thread-fork");
    assert.equal(forkEvent.payload_schema_version, "ioi.runtime.thread-fork.v1");
    assert.equal(forkEvent.payload.reason, reason);
    assert.equal(forkEvent.payload.source_thread_id, thread.thread_id);
    assert.equal(forkEvent.payload.fork_thread_id, cliFork.thread_id);
    assert.equal(forkEvent.payload.source_latest_turn_id, turn.turn_id);
    assert.equal(forkEvent.payload.source_latest_seq, String(cliFork.forked_from_seq));
    assert.ok(forkEvent.receipt_refs.includes(`receipt_${thread.agent_id}_thread_fork_${cliFork.agent_id}`));
    assert.ok(forkEvent.policy_decision_refs.includes(`policy_${thread.agent_id}_thread_fork_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const openedFork = await Thread.open(cliFork.thread_id, { substrateClient: sdkClient });
    assert.equal(openedFork.id, cliFork.thread_id);
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkForkEvent = sdkEvents.find((event) => event.id === forkEvent.event_id);
    assert.ok(sdkForkEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(forkEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${forkEvent.event_stream_id}:${forkEvent.seq}`;
    assert.equal(sdkForkEvent.type, "thread_forked");
    assert.equal(sdkForkEvent.seq, forkEvent.seq);
    assert.equal(sdkForkEvent.cursor, canonicalCursor);
    assert.equal(sdkForkEvent.eventKind, forkEvent.event_kind);
    assert.equal(sdkForkEvent.sourceEventKind, forkEvent.source_event_kind);
    assert.equal(sdkForkEvent.componentKind, forkEvent.component_kind);
    assert.equal(sdkForkEvent.workflowNodeId, forkEvent.workflow_node_id);
    assert.equal(sdkForkEvent.payloadSchemaVersion, forkEvent.payload_schema_version);
    assert.deepEqual(sdkForkEvent.receiptRefs, forkEvent.receipt_refs);
    assert.deepEqual(sdkForkEvent.policyDecisionRefs, forkEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, forkEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, forkEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "thread_fork");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.thread-fork");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Fork"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow thread fork control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeThreadForkControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "branch live context from React Flow control";
  const workflowGraphId = "workflow.react-flow.thread-fork-proof";
  const workflowNodeId = "runtime.thread-fork";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-fork";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated thread fork control keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated fork control validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-thread-fork-control",
      type: "runtime_thread_fork",
      config: {
        logic: {
          runtimeThreadForkEndpoint: "/v1/threads/{threadId}/fork",
          runtimeThreadForkThreadIdField: "threadId",
          runtimeThreadForkReasonField: "reason",
          runtimeThreadForkWorkflowNodeId: workflowNodeId,
          runtimeThreadForkActor: "operator",
        },
        law: { privilegedActions: ["runtime.thread.fork"] },
      },
    };
    const control = createRuntimeThreadForkControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, reason },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_thread_fork");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "thread_fork");

    const fork = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(fork.source_thread_id, thread.thread_id);
    assert.notEqual(fork.thread_id, thread.thread_id);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const forkEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Fork" && event.source === "react_flow",
    );
    assert.ok(forkEvent);
    assert.equal(forkEvent.event_kind, "thread.forked");
    assert.equal(forkEvent.status, "completed");
    assert.equal(forkEvent.source, "react_flow");
    assert.equal(forkEvent.actor, "user");
    assert.equal(forkEvent.thread_id, thread.thread_id);
    assert.equal(forkEvent.turn_id, turn.turn_id);
    assert.equal(forkEvent.workflow_graph_id, workflowGraphId);
    assert.equal(forkEvent.workflow_node_id, workflowNodeId);
    assert.equal(forkEvent.component_kind, "thread_fork");
    assert.equal(forkEvent.payload_schema_version, "ioi.runtime.thread-fork.v1");
    assert.equal(forkEvent.payload.reason, reason);
    assert.equal(forkEvent.payload.requested_by, "operator");
    assert.equal(forkEvent.payload.fork_thread_id, fork.thread_id);
    assert.ok(forkEvent.receipt_refs.includes(`receipt_${thread.agent_id}_thread_fork_${fork.agent_id}`));
    assert.ok(forkEvent.policy_decision_refs.includes(`policy_${thread.agent_id}_thread_fork_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkForkEvent = sdkEvents.find((event) => event.id === forkEvent.event_id);
    assert.ok(sdkForkEvent);
    assert.equal(sdkForkEvent.type, "thread_forked");
    assert.equal(sdkForkEvent.sourceEventKind, "OperatorControl.Fork");
    assert.equal(sdkForkEvent.componentKind, "thread_fork");
    assert.equal(sdkForkEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkForkEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkForkEvent.receiptRefs, forkEvent.receipt_refs);
    assert.deepEqual(sdkForkEvent.policyDecisionRefs, forkEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(forkEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_thread_fork");
    assert.equal(reactFlowNode.componentKind, "thread_fork");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Fork"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("daemon runtime event store is append-only and idempotent per stream", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-event-store-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-event-store-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const first = daemon.store.appendRuntimeEvent({
      event_stream_id: "event-store-contract:events",
      thread_id: "thread_event_store_contract",
      turn_id: "turn_event_store_contract",
      item_id: "item_event_store_contract",
      idempotency_key: "request:first",
      source: "daemon_bridge",
      source_event_kind: "contract.first",
      event_kind: "contract.first",
      status: "completed",
      actor: "runtime",
      created_at: "2026-05-12T00:00:00.000Z",
      workspace_root: cwd,
      payload_schema_version: "ioi.runtime.event.v1",
      payload: { value: "first" },
    });
    const duplicate = daemon.store.appendRuntimeEvent({
      ...first,
      payload: { value: "duplicate" },
    });
    const second = daemon.store.appendRuntimeEvent({
      event_stream_id: "event-store-contract:events",
      thread_id: "thread_event_store_contract",
      turn_id: "turn_event_store_contract",
      item_id: "item_event_store_contract_2",
      idempotency_key: "request:second",
      source: "daemon_bridge",
      source_event_kind: "contract.second",
      event_kind: "contract.second",
      status: "completed",
      actor: "runtime",
      created_at: "2026-05-12T00:00:01.000Z",
      workspace_root: cwd,
      payload_schema_version: "ioi.runtime.event.v1",
      payload: { value: "second" },
    });

    assert.equal(first.seq, 1);
    assert.equal(first.parent_seq, null);
    assert.equal(duplicate.seq, first.seq);
    assert.equal(duplicate.payload.value, "first");
    assert.equal(second.seq, 2);
    assert.equal(second.parent_seq, 1);
    assert.deepEqual(
      daemon.store.runtimeEventsForStream("event-store-contract:events", 0).map((event) => event.seq),
      [1, 2],
    );
    assert.deepEqual(
      daemon.store.runtimeEventsForStream("event-store-contract:events", 1).map((event) => event.seq),
      [2],
    );

    await daemon.close();
    const reloaded = await startRuntimeDaemonService({ cwd, stateDir });
    try {
      assert.deepEqual(
        reloaded.store.runtimeEventsForStream("event-store-contract:events", 0).map((event) => event.seq),
        [1, 2],
      );
      const persistedDuplicate = reloaded.store.appendRuntimeEvent({
        event_stream_id: "event-store-contract:events",
        thread_id: "thread_event_store_contract",
        turn_id: "turn_event_store_contract",
        item_id: "item_event_store_contract",
        idempotency_key: "request:first",
        source: "daemon_bridge",
        source_event_kind: "contract.first",
        event_kind: "contract.first",
        status: "completed",
        actor: "runtime",
        created_at: "2026-05-12T00:00:02.000Z",
        workspace_root: cwd,
        payload_schema_version: "ioi.runtime.event.v1",
        payload: { value: "after-reload" },
      });
      assert.equal(persistedDuplicate.seq, 1);
      assert.equal(persistedDuplicate.payload.value, "first");
    } finally {
      await reloaded.close();
    }
  } finally {
    await daemon.close().catch(() => {});
  }
});

test("local daemon emits deterministic model route fallback decisions with receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-route-fallback-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-route-fallback-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    daemon.store.modelMounting.upsertRoute({
      id: "route.unavailable-primary",
      role: "test_unavailable",
      privacy: "local_or_enterprise",
      providerEligibility: ["openai"],
      fallback: ["endpoint.local.auto"],
      deniedProviders: [],
      status: "active",
    });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          model: { id: "auto", routeId: "route.unavailable-primary", reasoningEffort: "high" },
        },
      }),
    });
    assert.equal(thread.model_route_id, "route.local-first");
    assert.equal(thread.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(thread.model_route_decision.fallbackTriggered, true);
    assert.equal(thread.model_route_decision.selectedModel, "local:auto");
    assert.equal(thread.model_route_decision.reasoningEffort, "high");
    assert.ok(
      thread.model_route_decision.rejectedCandidates.some(
        (candidate) => candidate.reason === "provider_not_eligible_for_route",
      ),
    );
    assert.ok(thread.model_route_receipt_id);
  } finally {
    await daemon.close();
  }
});

test("local daemon records explicit memory writes and injects provenance into the next turn", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-daemon-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({ options: { local: { cwd } } }),
    });
    const rememberTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "# remember The operator prefers focused runtime slices.",
        mode: "send",
      }),
    });
    assert.equal(rememberTurn.memory_write_receipt_ids.length, 1);

    const memory = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`);
    assert.equal(memory.schemaVersion, "ioi.agent-runtime.memory.v1");
    assert.equal(memory.records.length, 1);
    assert.equal(memory.records[0].fact, "The operator prefers focused runtime slices.");
    assert.equal(memory.policy.injectionEnabled, true);

    const memoryStatus = await fetchJson(
      `${daemon.endpoint}/v1/memory?thread_id=${thread.thread_id}`,
    );
    assert.equal(memoryStatus.schemaVersion, "ioi.runtime.memory-manager-status.v1");
    assert.equal(memoryStatus.status, "ready");
    assert.equal(memoryStatus.record_count, 1);
    assert.equal(memoryStatus.validation.ok, true);
    assert.equal(memoryStatus.policy.id, memory.policy.id);

    const memoryValidation = await fetchJson(`${daemon.endpoint}/v1/memory/validate`, {
      method: "POST",
      body: JSON.stringify({ thread_id: thread.thread_id }),
    });
    assert.equal(memoryValidation.schemaVersion, "ioi.runtime.memory-manager-validation.v1");
    assert.equal(memoryValidation.ok, true);
    assert.equal(memoryValidation.record_count, 1);

    const threadMemoryStatus = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/status`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId: "memory-control-graph",
          workflowNodeId: "memory-status-node",
        }),
      },
    );
    assert.equal(threadMemoryStatus.event.source_event_kind, "OperatorControl.Memory");
    assert.equal(threadMemoryStatus.event.component_kind, "memory_policy");
    assert.equal(threadMemoryStatus.event.workflow_node_id, "memory-status-node");
    assert.ok(threadMemoryStatus.rows.some((row) => row.row_kind === "memory_status"));

    const threadMemoryValidation = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/validate`,
      {
        method: "POST",
        body: JSON.stringify({ source: "react_flow" }),
      },
    );
    assert.equal(threadMemoryValidation.event.source_event_kind, "OperatorControl.MemoryValidate");
    assert.equal(threadMemoryValidation.event.workflow_node_id, "runtime.memory-manager.validate");
    assert.equal(threadMemoryValidation.ok, true);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    assert.equal((await sdkClient.getMemoryStatus({ thread_id: thread.thread_id })).record_count, 1);
    assert.equal((await sdkClient.validateMemory({ thread_id: thread.thread_id })).ok, true);
    assert.equal((await sdkThread.memory()).record_count, 1);
    assert.equal((await sdkThread.validateMemory()).ok, true);

    const sdkRemember = await sdkThread.rememberMemory({
      text: "The operator wants direct memory writes projected through React Flow.",
      memoryKey: "workflow-preferences",
      workflowGraphId: "memory-write-graph",
      workflowNodeId: "memory-write-node",
    });
    assert.equal(sdkRemember.operation, "write");
    assert.equal(sdkRemember.event.source_event_kind, "OperatorControl.MemoryWrite");
    assert.equal(sdkRemember.event.workflow_node_id, "memory-write-node");
    assert.ok(sdkRemember.rows.some((row) => row.memory_operation === "write"));

    const sdkEdit = await sdkThread.updateMemory(sdkRemember.record.id, {
      text: "The operator wants direct memory edits projected through React Flow.",
      workflowGraphId: "memory-write-graph",
      workflowNodeId: "memory-edit-node",
    });
    assert.equal(sdkEdit.operation, "edit");
    assert.equal(sdkEdit.event.source_event_kind, "OperatorControl.MemoryEdit");
    assert.equal(sdkEdit.event.workflow_node_id, "memory-edit-node");
    assert.ok(sdkEdit.rows.some((row) => row.memory_operation === "edit"));

    const sdkDelete = await sdkThread.deleteMemory(sdkRemember.record.id, {
      workflowGraphId: "memory-write-graph",
      workflowNodeId: "memory-delete-node",
    });
    assert.equal(sdkDelete.operation, "delete");
    assert.equal(sdkDelete.event.source_event_kind, "OperatorControl.MemoryDelete");
    assert.equal(sdkDelete.event.workflow_node_id, "memory-delete-node");
    assert.ok(sdkDelete.rows.some((row) => row.memory_operation === "delete"));

    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The operator wants memory filters validated through workflow nodes.",
        memoryKey: "workflow-preferences",
        scope: "thread",
      }),
    });
    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "This unrelated note should be filtered away.",
        memoryKey: "scratch",
        scope: "thread",
      }),
    });
    const filteredMemory = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory?memoryKey=workflow-preferences&q=workflow&limit=1`,
    );
    assert.equal(filteredMemory.filters.memoryKey, "workflow-preferences");
    assert.equal(filteredMemory.filters.query, "workflow");
    assert.equal(filteredMemory.filters.limit, 1);
    assert.equal(filteredMemory.records.length, 1);
    assert.equal(
      filteredMemory.records[0].fact,
      "The operator wants memory filters validated through workflow nodes.",
    );
    const redactedMemory = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory?memoryKey=workflow-preferences&redaction=redacted`,
    );
    assert.equal(redactedMemory.records[0].fact, "[REDACTED]");
    assert.equal(redactedMemory.records[0].redaction, "redacted");
    assert.match(redactedMemory.records[0].factHash, /^[a-f0-9]{64}$/);

    const memoryPath = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/path`);
    assert.match(memoryPath.recordsPath, /memory-records/);
    assert.match(memoryPath.policiesPath, /memory-policies/);

    const edit = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/${memory.records[0].id}`, {
      method: "PATCH",
      body: JSON.stringify({ text: "The operator prefers narrow, validated runtime slices." }),
    });
    assert.equal(edit.receipt.kind, "memory_edit");
    const commandEditTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: `/memory edit ${memory.records[0].id} The operator prefers narrow, command-validated runtime slices.`,
        mode: "send",
      }),
    });
    assert.equal(commandEditTurn.memory_write_receipt_ids.length, 1);
    const editedMemory = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`);
    assert.equal(editedMemory.records[0].fact, "The operator prefers narrow, command-validated runtime slices.");

    const readOnlyPolicy = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`, {
      method: "PATCH",
      body: JSON.stringify({ readOnly: true }),
    });
    assert.equal(readOnlyPolicy.policy.readOnly, true);
    const readOnlyBlockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "# remember This should not write.", mode: "send" }),
    });
    const readOnlyBlockedRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyBlockedTurn.turn_id.slice("turn_".length)}`,
    );
    assert.match(readOnlyBlockedRun.result, /memory_read_only/);

    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`, {
      method: "PATCH",
      body: JSON.stringify({ readOnly: false, writeRequiresApproval: true }),
    });
    const approvalBlockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "# remember Approval missing.", mode: "send" }),
    });
    const approvalBlockedRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${approvalBlockedTurn.turn_id.slice("turn_".length)}`,
    );
    assert.match(approvalBlockedRun.result, /memory_write_requires_approval/);
    const approvalTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "# remember Approval granted.",
        mode: "send",
        options: { memory: { writeApproved: true } },
      }),
    });
    assert.equal(approvalTurn.memory_write_receipt_ids.length, 1);

    const disableTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "/memory disable", mode: "send" }),
    });
    assert.equal(disableTurn.memory_write_receipt_ids.length, 1);
    const disabledPolicy = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`);
    assert.equal(disabledPolicy.disabled, true);
    const enableTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "/memory enable", mode: "send" }),
    });
    assert.equal(enableTurn.memory_write_receipt_ids.length, 1);

    const showTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "/memory show",
        mode: "send",
        options: { memory: { writeRequiresApproval: false } },
      }),
    });
    const runId = `run_${showTurn.turn_id.slice("turn_".length)}`;
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/trace`);
    assert.ok(
      trace.taskState.knownFacts.some((fact) =>
        fact.includes("The operator prefers narrow, command-validated runtime slices."),
      ),
    );
    assert.ok(trace.memoryRecords.some((record) => record.id === memory.records[0].id));

    const disabledTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "/memory show",
        mode: "send",
        options: { memory: { disabled: true } },
      }),
    });
    const disabledRunId = `run_${disabledTurn.turn_id.slice("turn_".length)}`;
    const disabledTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${disabledRunId}/trace`);
    assert.equal(disabledTrace.memoryRecords.length, 0);
    assert.ok(
      !disabledTrace.taskState.knownFacts.some((fact) =>
        fact.includes("The operator prefers narrow, command-validated runtime slices."),
      ),
    );

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const memoryEvent = events.find((event) => event.payload_summary?.event_kind === "MemoryWrite");
    assert.equal(memoryEvent.component_kind, "memory_write");
    assert.equal(memoryEvent.workflow_node_id, "runtime.memory");
    assert.equal(memoryEvent.payload_summary.memory_record_id, memory.records[0].id);
    assert.deepEqual(memoryEvent.receipt_refs, rememberTurn.memory_write_receipt_ids);
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.MemoryWrite"));
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.MemoryEdit"));
    assert.ok(events.some((event) => event.source_event_kind === "OperatorControl.MemoryDelete"));
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryEdit"));
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryPolicy"));
  } finally {
    await daemon.close();
  }
});

test("local daemon projects subagent memory inheritance modes with receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-memory-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-memory-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          agents: { reviewer: { prompt: "Review inherited memory." } },
        },
      }),
    });
    const targeted = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The reviewer should inherit the targeted handoff memory.",
        memoryKey: "reviewer-handoff",
        scope: "thread",
      }),
    });
    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The reviewer should not inherit scratch memory.",
        memoryKey: "scratch",
        scope: "thread",
      }),
    });

    const explicitTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with explicit inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: { subagentInheritance: "explicit", memoryKey: "reviewer-handoff" },
        },
      }),
    });
    const explicitRunId = `run_${explicitTurn.turn_id.slice("turn_".length)}`;
    const explicitTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${explicitRunId}/trace`);
    assert.equal(explicitTrace.subagentMemoryInheritance.mode, "explicit");
    assert.equal(explicitTrace.subagentMemoryInheritance.subagentName, "reviewer");
    assert.deepEqual(explicitTrace.subagentMemoryInheritance.inheritedRecordIds, [
      targeted.record.id,
    ]);
    assert.ok(explicitTrace.receipts.some((receipt) => receipt.kind === "subagent_memory_inheritance"));

    const noneTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with no inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: { subagentInheritance: "none", memoryKey: "reviewer-handoff" },
        },
      }),
    });
    const noneTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${noneTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.equal(noneTrace.subagentMemoryInheritance.mode, "none");
    assert.equal(noneTrace.subagentMemoryInheritance.records.length, 0);
    assert.equal(noneTrace.subagentMemoryInheritance.effectivePolicy.disabled, true);

    const readOnlyTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with read-only inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: {
            subagentInheritance: "read_only",
            memoryKey: "reviewer-handoff",
            remember: "Reviewer attempted a read-only daemon write.",
          },
        },
      }),
    });
    const readOnlyRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyTurn.turn_id.slice("turn_".length)}`,
    );
    const readOnlyTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.match(readOnlyRun.result, /memory_read_only/);
    assert.equal(readOnlyTrace.subagentMemoryInheritance.writeBlockReason, "memory_read_only");
    assert.equal(readOnlyTrace.memoryWrites.length, 0);

    const fullTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with full inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: {
            subagentInheritance: "full",
            memoryKey: "reviewer-handoff",
            remember: "Reviewer can persist a daemon full-inheritance note.",
          },
        },
      }),
    });
    assert.equal(fullTurn.memory_write_receipt_ids.length, 1);
    const fullTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${fullTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.equal(fullTrace.subagentMemoryInheritance.mode, "full");
    assert.equal(fullTrace.subagentMemoryInheritance.writeBlockReason, null);
    assert.equal(fullTrace.memoryWrites.length, 1);
    assert.equal(fullTrace.memoryWrites[0].memoryKey, "reviewer-handoff");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const inheritanceEvent = events.find(
      (event) => event.payload_summary?.event_kind === "SubagentMemoryInheritance",
    );
    assert.equal(inheritanceEvent.component_kind, "subagent_memory");
    assert.equal(inheritanceEvent.workflow_node_id, "runtime.subagent-memory");
    assert.equal(inheritanceEvent.payload_summary.subagent_inheritance_mode, "explicit");
    assert.equal(inheritanceEvent.payload_summary.inherited_memory_count, 1);
  } finally {
    await daemon.close();
  }
});

test("local daemon exposes SubagentManager spawn, list, input, cancel, resume, assign, wait, and result contracts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-manager-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-manager-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const spawn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        actor: "workflow-author",
        role: "explore",
        prompt: "Inspect the daemon SubagentManager slice and return contract evidence.",
        toolPack: "coding",
        modelRouteId: "route.native-local",
        forkContext: false,
        maxConcurrency: 2,
        budget: { maxTokens: 12000 },
        outputContract: ["SUMMARY", "CHANGES", "EVIDENCE", "RISKS", "BLOCKERS", "RECEIPTS"],
        mergePolicy: "evidence_only",
        cancellationInheritance: "propagate",
        workflowGraphId: "workflow.subagent.manager",
        workflowNodeId: "runtime.subagent.spawn.explore",
      }),
    });
    assert.equal(spawn.schema_version, "ioi.runtime.subagent-manager.v1");
    assert.equal(spawn.object, "ioi.runtime_subagent");
    assert.equal(spawn.parent_thread_id, thread.thread_id);
    assert.equal(spawn.role, "explore");
    assert.equal(spawn.tool_pack, "coding");
    assert.equal(spawn.model_route_id, "route.native-local");
    assert.equal(spawn.context_mode, "fresh");
    assert.equal(spawn.lifecycle_status, "completed");
    assert.equal(spawn.budget_status, "within_budget");
    assert.equal(spawn.budgetStatus.status, "within_budget");
    assert.ok(spawn.usage_telemetry.cumulative_total_tokens > 0);
    assert.ok(spawn.usage_telemetry.cumulative_cost_estimate_usd > 0);
    assert.equal(spawn.output_contract_status, "passed");
    assert.equal(spawn.outputContractStatus.status, "passed");
    assert.equal(spawn.event.source_event_kind, "OperatorControl.SubagentSpawn");
    assert.equal(spawn.event.component_kind, "subagent_lifecycle");
    assert.equal(spawn.event.workflow_graph_id, "workflow.subagent.manager");
    assert.equal(spawn.event.workflow_node_id, "runtime.subagent.spawn.explore");
    assert.ok(spawn.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_spawn_")));

    const listed = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`);
    assert.equal(listed.schema_version, "ioi.runtime.subagent-manager.v1");
    assert.equal(listed.count, 1);
    assert.equal(listed.subagents[0].subagent_id, spawn.subagent_id);
    assert.equal(listed.subagents[0].output_contract_status, "passed");

    const waited = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/wait`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId: "workflow.subagent.manager",
          workflowNodeId: "runtime.subagent.join.explore",
        }),
      },
    );
    assert.equal(waited.schema_version, "ioi.runtime.subagent-result.v1");
    assert.equal(waited.lifecycle_status, "completed");
    assert.equal(waited.output_contract_status, "passed");
    assert.deepEqual(waited.output.required_sections, [
      "SUMMARY",
      "CHANGES",
      "EVIDENCE",
      "RISKS",
      "BLOCKERS",
      "RECEIPTS",
    ]);
    assert.match(waited.output.sections.SUMMARY, /IOI daemon run completed/);
    assert.ok(waited.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_wait_")));
    assert.equal(waited.event.source_event_kind, "OperatorControl.SubagentWait");
    assert.equal(waited.event.payload_summary.output_contract_status, "passed");
    assert.equal(waited.budget_status, "within_budget");
    assert.ok(waited.usage_telemetry.cumulative_total_tokens > 0);

    const result = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/result`,
    );
    assert.equal(result.schema_version, "ioi.runtime.subagent-result.v1");
    assert.equal(result.output_contract_status, "passed");
    assert.equal(result.subagent.subagent_id, spawn.subagent_id);
    assert.ok(result.output.sections.RECEIPTS.length > 0);

    const input = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/input`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          actor: "workflow-author",
          message: "Follow up with the route evidence for the send-input contract.",
          workflowGraphId: "workflow.subagent.manager",
          workflowNodeId: "runtime.subagent.input.explore",
        }),
      },
    );
    assert.equal(input.schema_version, "ioi.runtime.subagent-manager.v1");
    assert.equal(input.lifecycle_status, "completed");
    assert.equal(input.input_count, 1);
    assert.match(input.input.input_id, /^subagent_input_/);
    assert.equal(input.input.message, "Follow up with the route evidence for the send-input contract.");
    assert.equal(input.input.previous_run_id, spawn.run_id);
    assert.notEqual(input.run_id, spawn.run_id);
    assert.equal(input.result.output_contract_status, "passed");
    assert.equal(input.event.source_event_kind, "OperatorControl.SubagentSendInput");
    assert.equal(input.event.payload_summary.input_count, 1);
    assert.ok(input.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_send_input_")));

    const canceled = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/cancel`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          actor: "workflow-author",
          reason: "workflow_cancel",
          workflowGraphId: "workflow.subagent.manager",
          workflowNodeId: "runtime.subagent.cancel.explore",
        }),
      },
    );
    assert.equal(canceled.schema_version, "ioi.runtime.subagent-result.v1");
    assert.equal(canceled.lifecycle_status, "canceled");
    assert.equal(canceled.subagent.lifecycle_status, "canceled");
    assert.equal(canceled.subagent.cancellation_reason, "workflow_cancel");
    assert.equal(canceled.cancellation.reason, "workflow_cancel");
    assert.equal(canceled.event.source_event_kind, "OperatorControl.SubagentCancel");
    assert.equal(canceled.event.payload_summary.cancellation_reason, "workflow_cancel");
    assert.ok(canceled.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_cancel_")));

    const canceledResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/result`,
    );
    assert.equal(canceledResult.lifecycle_status, "canceled");
    assert.equal(canceledResult.subagent.input_count, 1);
    assert.equal(canceledResult.subagent.cancellation_reason, "workflow_cancel");
    assert.match(canceledResult.result, /Run canceled/);

    const resumed = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/resume`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          actor: "workflow-author",
          message: "Resume the subagent after workflow cancellation and refresh the contract evidence.",
          workflowGraphId: "workflow.subagent.manager",
          workflowNodeId: "runtime.subagent.resume.explore",
        }),
      },
    );
    assert.equal(resumed.schema_version, "ioi.runtime.subagent-result.v1");
    assert.equal(resumed.lifecycle_status, "completed");
    assert.equal(resumed.subagent.lifecycle_status, "completed");
    assert.equal(resumed.subagent.restart_status, "restarted");
    assert.equal(resumed.subagent.restart_count, 1);
    assert.equal(resumed.subagent.cancellation_reason, null);
    assert.equal(resumed.resume.previous_run_id, input.run_id);
    assert.notEqual(resumed.run_id, input.run_id);
    assert.equal(resumed.event.source_event_kind, "OperatorControl.SubagentResume");
    assert.equal(resumed.event.payload_summary.restart_count, 1);
    assert.ok(resumed.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_resume_")));

    const assigned = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/assign`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          actor: "workflow-author",
          role: "implement",
          toolPack: "coding-plus",
          modelRouteId: "route.native-local",
          mergePolicy: "manual_review",
          cancellationInheritance: "propagate",
          workflowGraphId: "workflow.subagent.manager",
          workflowNodeId: "runtime.subagent.assign.implement",
        }),
      },
    );
    assert.equal(assigned.schema_version, "ioi.runtime.subagent-manager.v1");
    assert.equal(assigned.lifecycle_status, "completed");
    assert.equal(assigned.role, "implement");
    assert.equal(assigned.tool_pack, "coding-plus");
    assert.equal(assigned.model_route_id, "route.native-local");
    assert.equal(assigned.merge_policy, "manual_review");
    assert.equal(assigned.assignment_count, 1);
    assert.equal(assigned.assignment.previous_role, "explore");
    assert.equal(assigned.event.source_event_kind, "OperatorControl.SubagentAssign");
    assert.equal(assigned.event.payload_summary.assignment_count, 1);

    const assignedResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${spawn.subagent_id}/result`,
    );
    assert.equal(assignedResult.lifecycle_status, "completed");
    assert.equal(assignedResult.subagent.role, "implement");
    assert.equal(assignedResult.subagent.restart_count, 1);
    assert.equal(assignedResult.subagent.assignment_count, 1);
    assert.equal(assignedResult.output_contract_status, "passed");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const spawnEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentSpawn");
    const waitEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentWait");
    const inputEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentSendInput");
    const cancelEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentCancel");
    const resumeEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentResume");
    const assignEvent = events.find((event) => event.source_event_kind === "OperatorControl.SubagentAssign");
    assert.equal(spawnEvent.component_kind, "subagent_lifecycle");
    assert.equal(spawnEvent.payload_summary.role, "explore");
    assert.equal(spawnEvent.payload_summary.subagent_id, spawn.subagent_id);
    assert.equal(spawnEvent.payload_summary.output_contract_status, "passed");
    assert.equal(waitEvent.payload_summary.lifecycle_status, "completed");
    assert.equal(inputEvent.payload_summary.input_count, 1);
    assert.equal(cancelEvent.payload_summary.lifecycle_status, "canceled");
    assert.equal(cancelEvent.payload_summary.cancellation_reason, "workflow_cancel");
    assert.equal(resumeEvent.payload_summary.lifecycle_status, "completed");
    assert.equal(resumeEvent.payload_summary.restart_count, 1);
    assert.equal(assignEvent.payload_summary.role, "implement");
    assert.equal(assignEvent.payload_summary.assignment_count, 1);

    await daemon.close();
    const reloaded = await startRuntimeDaemonService({ cwd, stateDir });
    try {
      const reloadedList = await fetchJson(`${reloaded.endpoint}/v1/threads/${thread.thread_id}/subagents`);
      assert.equal(reloadedList.count, 1);
      assert.equal(reloadedList.subagents[0].subagent_id, spawn.subagent_id);
      assert.equal(reloadedList.subagents[0].lifecycle_status, "completed");
      assert.equal(reloadedList.subagents[0].input_count, 1);
      assert.equal(reloadedList.subagents[0].cancellation_reason, null);
      assert.equal(reloadedList.subagents[0].restart_count, 1);
      assert.equal(reloadedList.subagents[0].assignment_count, 1);
      assert.equal(reloadedList.subagents[0].role, "implement");
    } finally {
      await reloaded.close();
    }
  } finally {
    try {
      await daemon.close();
    } catch {
      // The reload branch closes the first daemon before re-opening the same state.
    }
  }
});

test("local daemon propagates parent subagent cancellation with fan-out policy evidence", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-propagation-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-propagation-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const explorer = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        role: "explore",
        prompt: "Explore the parent cancellation propagation path.",
        cancellationInheritance: "propagate",
        workflowGraphId: "workflow.subagent.propagation",
        workflowNodeId: "runtime.subagent.spawn.explore",
      }),
    });
    const implementer = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        role: "implement",
        prompt: "Implement independently and ignore inherited parent cancellation.",
        cancellationInheritance: "isolate",
        workflowGraphId: "workflow.subagent.propagation",
        workflowNodeId: "runtime.subagent.spawn.implement",
      }),
    });

    const propagation = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/cancel`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        actor: "workflow-author",
        reason: "parent_workflow_cancel",
        workflowGraphId: "workflow.subagent.propagation",
        workflowNodeId: "runtime.subagent.cancel.parent",
      }),
    });
    assert.equal(propagation.schema_version, "ioi.runtime.subagent-manager.v1");
    assert.equal(propagation.object, "ioi.runtime_subagent_cancellation_propagation");
    assert.equal(propagation.thread_id, thread.thread_id);
    assert.equal(propagation.candidate_count, 2);
    assert.equal(propagation.canceled_count, 1);
    assert.equal(propagation.skipped_count, 1);
    assert.equal(propagation.canceled_subagents[0].subagent_id, explorer.subagent_id);
    assert.equal(propagation.canceled_subagents[0].lifecycle_status, "canceled");
    assert.equal(propagation.canceled_subagents[0].cancellation_reason, "parent_workflow_cancel");
    assert.equal(propagation.canceled_subagents[0].cancellation_inherited, true);
    assert.equal(propagation.canceled_subagents[0].propagated_from_thread_id, thread.thread_id);
    assert.equal(propagation.skipped_subagents[0].subagent_id, implementer.subagent_id);
    assert.equal(propagation.skipped_subagents[0].skip_reason, "cancellation_inheritance_not_propagate");
    assert.ok(propagation.receipt_refs.some((receipt) => receipt.startsWith("receipt_subagent_cancel_")));

    const listed = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`);
    const listedExplorer = listed.subagents.find((subagent) => subagent.subagent_id === explorer.subagent_id);
    const listedImplementer = listed.subagents.find((subagent) => subagent.subagent_id === implementer.subagent_id);
    assert.equal(listedExplorer.lifecycle_status, "canceled");
    assert.equal(listedExplorer.cancellation_inherited, true);
    assert.equal(listedImplementer.lifecycle_status, "completed");
    assert.equal(listedImplementer.cancellation_inheritance, "isolate");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const propagatedCancelEvent = events.find(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentCancel" &&
        event.payload_summary.subagent_id === explorer.subagent_id,
    );
    assert.equal(propagatedCancelEvent.component_kind, "subagent_lifecycle");
    assert.equal(propagatedCancelEvent.payload_summary.lifecycle_status, "canceled");
    assert.equal(propagatedCancelEvent.payload_summary.cancellation_reason, "parent_workflow_cancel");
    assert.equal(propagatedCancelEvent.payload_summary.cancellation_inherited, true);
    assert.equal(propagatedCancelEvent.payload_summary.propagated_from_thread_id, thread.thread_id);

    await daemon.close();
    const reloaded = await startRuntimeDaemonService({ cwd, stateDir });
    try {
      const reloadedList = await fetchJson(`${reloaded.endpoint}/v1/threads/${thread.thread_id}/subagents`);
      const reloadedExplorer = reloadedList.subagents.find((subagent) => subagent.subagent_id === explorer.subagent_id);
      const reloadedImplementer = reloadedList.subagents.find((subagent) => subagent.subagent_id === implementer.subagent_id);
      assert.equal(reloadedExplorer.lifecycle_status, "canceled");
      assert.equal(reloadedExplorer.cancellation_inherited, true);
      assert.equal(reloadedExplorer.propagated_from_thread_id, thread.thread_id);
      assert.equal(reloadedImplementer.lifecycle_status, "completed");
      assert.equal(reloadedImplementer.cancellation_inheritance, "isolate");
    } finally {
      await reloaded.close();
    }
  } finally {
    try {
      await daemon.close();
    } catch {
      // The reload branch closes the first daemon before re-opening the same state.
    }
  }
});

test("SDK client and Thread wrappers drive daemon SubagentManager routes with workflow identity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sdk-subagent-manager-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sdk-subagent-manager-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const thread = await Thread.create({
      local: { cwd },
      model: { id: "auto", routeId: "route.native-local" },
      substrateClient: sdkClient,
    });

    const spawned = await sdkClient.spawnSubagent(thread.id, {
      source: "react_flow",
      actor: "workflow-author",
      role: "sdk-explore",
      prompt: "Prove the SDK SubagentManager wrapper reaches the daemon route surface.",
      toolPack: "coding",
      modelRouteId: "route.native-local",
      cancellationInheritance: "propagate",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.spawn.sdk-explore",
    });
    assert.equal(spawned.object, "ioi.runtime_subagent");
    assert.equal(spawned.parent_thread_id, thread.id);
    assert.equal(spawned.role, "sdk-explore");
    assert.equal(spawned.event.workflow_graph_id, "workflow.sdk.subagent.manager");
    assert.equal(spawned.event.workflow_node_id, "runtime.subagent.spawn.sdk-explore");

    const listed = await thread.listSubagents({ role: "sdk-explore" });
    assert.equal(listed.count, 1);
    assert.equal(listed.subagents[0].subagent_id, spawned.subagent_id);

    const waited = await thread.waitSubagent(spawned.subagent_id, {
      source: "react_flow",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.join.sdk-explore",
    });
    assert.equal(waited.object, "ioi.runtime_subagent_result");
    assert.equal(waited.lifecycle_status, "completed");
    assert.equal(waited.event.workflow_node_id, "runtime.subagent.join.sdk-explore");

    const result = await sdkClient.getSubagentResult(thread.id, spawned.subagent_id);
    assert.equal(result.subagent.subagent_id, spawned.subagent_id);
    assert.equal(result.output_contract_status, "passed");

    const input = await thread.sendSubagentInput(spawned.subagent_id, {
      source: "react_flow",
      message: "Add SDK wrapper send-input evidence.",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.input.sdk-explore",
    });
    assert.equal(input.input_count, 1);
    assert.equal(input.event.workflow_node_id, "runtime.subagent.input.sdk-explore");

    const canceled = await sdkClient.cancelSubagent(thread.id, spawned.subagent_id, {
      source: "react_flow",
      reason: "sdk_wrapper_cancel",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.cancel.sdk-explore",
    });
    assert.equal(canceled.lifecycle_status, "canceled");
    assert.equal(canceled.subagent.cancellation_reason, "sdk_wrapper_cancel");

    const resumed = await thread.resumeSubagent(spawned.subagent_id, {
      source: "react_flow",
      message: "Resume the SDK wrapper subagent.",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.resume.sdk-explore",
    });
    assert.equal(resumed.lifecycle_status, "completed");
    assert.equal(resumed.subagent.restart_count, 1);

    const assigned = await sdkClient.assignSubagent(thread.id, spawned.subagent_id, {
      source: "react_flow",
      role: "sdk-implement",
      toolPack: "coding-plus",
      mergePolicy: "manual_review",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.assign.sdk-implement",
    });
    assert.equal(assigned.role, "sdk-implement");
    assert.equal(assigned.assignment_count, 1);

    const isolated = await thread.spawnSubagent({
      source: "react_flow",
      role: "sdk-verify",
      prompt: "Remain isolated from parent cancellation propagation.",
      cancellationInheritance: "isolate",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.spawn.sdk-verify",
    });
    const propagation = await sdkClient.propagateSubagentCancellation(thread.id, {
      source: "react_flow",
      reason: "sdk_parent_cancel",
      workflowGraphId: "workflow.sdk.subagent.manager",
      workflowNodeId: "runtime.subagent.cancel.parent-sdk",
    });
    assert.equal(propagation.object, "ioi.runtime_subagent_cancellation_propagation");
    assert.equal(propagation.candidate_count, 2);
    assert.equal(propagation.canceled_count, 1);
    assert.equal(propagation.skipped_count, 1);
    assert.equal(propagation.canceled_subagents[0].subagent_id, spawned.subagent_id);
    assert.equal(propagation.skipped_subagents[0].subagent_id, isolated.subagent_id);

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.id}/events?since_seq=0`);
    const sdkSpawnEvent = events.find(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentSpawn" &&
        event.payload_summary.subagent_id === spawned.subagent_id,
    );
    const sdkAssignEvent = events.find(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentAssign" &&
        event.payload_summary.subagent_id === spawned.subagent_id,
    );
    const sdkPropagatedCancelEvent = events.find(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentCancel" &&
        event.payload_summary.subagent_id === spawned.subagent_id &&
        event.payload_summary.cancellation_inherited === true,
    );
    assert.equal(sdkSpawnEvent.workflow_graph_id, "workflow.sdk.subagent.manager");
    assert.equal(sdkSpawnEvent.workflow_node_id, "runtime.subagent.spawn.sdk-explore");
    assert.equal(sdkAssignEvent.workflow_node_id, "runtime.subagent.assign.sdk-implement");
    assert.equal(sdkPropagatedCancelEvent.workflow_node_id, "runtime.subagent.cancel.parent-sdk");
  } finally {
    await daemon.close();
  }
});

test("React Flow subagent fan-out workflow compiles nodes into live daemon controls", async () => {
  const {
    createRuntimeSubagentControlRequestFromWorkflowNode,
    projectRuntimeTuiControlStateToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-react-flow-subagent-fanout-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-react-flow-subagent-fanout-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const workflowGraphId = "workflow.react-flow.subagent-fanout";
    const stateNode = (id, label, logic) => ({
      id,
      type: "state",
      config: {
        logic: {
          stateKey: "subagents",
          reducer: "replace",
          ...logic,
        },
      },
      label,
    });
    const spawnNodes = [
      stateNode("subagent-spawn-explore", "Spawn explorer", {
        stateOperation: "subagent_spawn",
        reducer: "append",
        subagentRole: "explore",
        subagentPrompt: "Map the remaining P1-A fan-out parity evidence.",
        subagentToolPack: "coding",
        subagentModelRoute: "route.native-local",
        subagentMaxConcurrency: 2,
        subagentOutputContractJson: "[\"SUMMARY\",\"EVIDENCE\",\"RECEIPTS\"]",
        subagentMergePolicy: "evidence_only",
        subagentCancellationInheritance: "propagate",
      }),
      stateNode("subagent-spawn-implementer", "Spawn implementer", {
        stateOperation: "subagent_spawn",
        reducer: "append",
        subagentRole: "implementer",
        subagentPrompt: "Implement the selected fan-out workflow slice.",
        subagentToolPack: "coding-plus",
        subagentModelRoute: "route.native-local",
        subagentMaxConcurrency: 1,
        subagentOutputContractJson: "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RECEIPTS\"]",
        subagentMergePolicy: "manual_review",
        subagentCancellationInheritance: "propagate",
      }),
      stateNode("subagent-spawn-verifier", "Spawn verifier", {
        stateOperation: "subagent_spawn",
        reducer: "append",
        subagentRole: "verifier",
        subagentPrompt: "Verify fan-out evidence and remain isolated from parent cancellation.",
        subagentToolPack: "coding",
        subagentModelRoute: "route.native-local",
        subagentMaxConcurrency: 2,
        subagentOutputContractJson: "[\"SUMMARY\",\"EVIDENCE\",\"RISKS\",\"RECEIPTS\"]",
        subagentMergePolicy: "evidence_only",
        subagentCancellationInheritance: "isolate",
      }),
    ];

    const spawnRequests = spawnNodes.map((node) =>
      createRuntimeSubagentControlRequestFromWorkflowNode(
        node,
        { threadId: thread.thread_id },
        { workflowGraphId, actor: "workflow-author" },
      ),
    );
    assert.deepEqual(
      spawnRequests.map((request) => request.operation),
      ["spawn", "spawn", "spawn"],
    );
    assert.equal(spawnRequests[1].body?.maxConcurrency, 1);
    assert.equal(spawnRequests[1].body?.mergePolicy, "manual_review");
    assert.equal(spawnRequests[2].body?.cancellationInheritance, "isolate");

    const spawned = await Promise.all(
      spawnRequests.map((request) =>
        fetchJson(`${daemon.endpoint}${request.endpoint}`, {
          method: request.method,
          body: JSON.stringify(request.body),
        }),
      ),
    );
    const [explorer, implementer, verifier] = spawned;
    assert.deepEqual(
      spawned.map((subagent) => subagent.role),
      ["explore", "implementer", "verifier"],
    );
    assert.ok(spawned.every((subagent) => subagent.outputContractStatus.status === "passed"));
    assert.equal(explorer.event.workflow_graph_id, workflowGraphId);
    assert.equal(implementer.maxConcurrency, 1);
    assert.equal(implementer.mergePolicy, "manual_review");
    assert.equal(verifier.cancellationInheritance, "isolate");

    const poolNode = stateNode("subagent-pool-explore", "Explorer pool", {
      stateOperation: "subagent_list",
      subagentRole: "explore",
      subagentMaxConcurrency: 2,
    });
    const poolRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      poolNode,
      { threadId: thread.thread_id },
      { workflowGraphId },
    );
    assert.equal(poolRequest.method, "GET");
    assert.match(poolRequest.endpoint, /role=explore/);
    const explorerPool = await fetchJson(`${daemon.endpoint}${poolRequest.endpoint}`);
    assert.equal(explorerPool.count, 1);
    assert.equal(explorerPool.subagents[0].subagent_id, explorer.subagent_id);

    const waitRequests = spawned.map((subagent) =>
      createRuntimeSubagentControlRequestFromWorkflowNode(
        stateNode(`subagent-wait-${subagent.role}`, `Join ${subagent.role}`, {
          stateOperation: "subagent_wait",
          reducer: "merge",
          subagentId: subagent.subagent_id,
          subagentWaitTimeoutMs: 120000,
          subagentOutputContractJson: JSON.stringify(subagent.outputContract),
          subagentMergePolicy: subagent.mergePolicy,
        }),
        { threadId: thread.thread_id },
        { workflowGraphId, actor: "workflow-author" },
      ),
    );
    const waited = await Promise.all(
      waitRequests.map((request) =>
        fetchJson(`${daemon.endpoint}${request.endpoint}`, {
          method: request.method,
          body: JSON.stringify(request.body),
        }),
      ),
    );
    assert.ok(waited.every((result) => result.lifecycle_status === "completed"));
    assert.ok(waited.every((result) => result.outputContractStatus.status === "passed"));

    const activeImplementer = {
      ...daemon.store.subagents.get(implementer.subagent_id),
      lifecycle_status: "running",
      lifecycleStatus: "running",
      status: "running",
    };
    daemon.store.writeSubagent(activeImplementer, "subagent.fanout.active-fixture");
    const blockedRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      stateNode("subagent-spawn-implementer-blocked", "Blocked implementer", {
        stateOperation: "subagent_spawn",
        reducer: "append",
        subagentRole: "implementer",
        subagentPrompt: "This second implementer should be blocked by max concurrency.",
        subagentMaxConcurrency: 1,
      }),
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    const blocked = await fetchJsonStatus(`${daemon.endpoint}${blockedRequest.endpoint}`, {
      method: blockedRequest.method,
      body: JSON.stringify(blockedRequest.body),
    });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error.code, "policy");
    assert.equal(blocked.body.error.details.role, "implementer");
    assert.equal(blocked.body.error.details.maxConcurrency, 1);
    assert.equal(blocked.body.error.details.activeForRole, 1);

    const propagationRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      stateNode("subagent-cancel-parent", "Parent cancel", {
        stateOperation: "subagent_cancel_propagation",
        reducer: "replace",
        subagentInput: "react_flow_parent_cancel",
      }),
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(propagationRequest.operation, "propagate_cancel");
    assert.equal(propagationRequest.endpoint, `/v1/threads/${thread.thread_id}/subagents/cancel`);
    assert.equal(propagationRequest.body.reason, "react_flow_parent_cancel");
    const propagation = await fetchJson(`${daemon.endpoint}${propagationRequest.endpoint}`, {
      method: propagationRequest.method,
      body: JSON.stringify(propagationRequest.body),
    });
    assert.equal(propagation.object, "ioi.runtime_subagent_cancellation_propagation");
    assert.equal(propagation.candidate_count, 3);
    assert.equal(propagation.canceled_count, 2);
    assert.equal(propagation.skipped_count, 1);
    assert.deepEqual(
      propagation.canceled_subagents.map((subagent) => subagent.role).sort(),
      ["explore", "implementer"],
    );
    assert.equal(propagation.skipped_subagents[0].subagent_id, verifier.subagent_id);
    assert.equal(propagation.skipped_subagents[0].cancellation_inheritance, "isolate");

    const propagationRows = [
      ...propagation.canceled_subagents.map((subagent) => ({
        ...subagent,
        row_kind: "subagent",
        subagent_operation: "propagate_cancel",
        workflow_graph_id: workflowGraphId,
        workflowGraphId,
        workflow_node_id: propagationRequest.body.workflowNodeId,
        workflowNodeId: propagationRequest.body.workflowNodeId,
      })),
      ...propagation.skipped_subagents.map((subagent) => ({
        ...subagent,
        row_kind: "subagent",
        subagent_operation: "propagate_skip",
        workflow_graph_id: workflowGraphId,
        workflowGraphId,
        workflow_node_id: propagationRequest.body.workflowNodeId,
        workflowNodeId: propagationRequest.body.workflowNodeId,
      })),
    ];
    const projection = projectRuntimeTuiControlStateToWorkflowProjection({
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      subagent_rows: propagationRows,
    });
    assert.equal(projection.subagentRowCount, 3);
    assert.equal(projection.subagentChildSubflowCount, 3);
    assert.equal(projection.subagentChildSubflowReactFlowNodes.length, 6);
    assert.equal(projection.subagentChildSubflowReactFlowEdges.length, 6);
    assert.ok(
      projection.subagentChildSubflows.every(
        (subflow) =>
          subflow.workflowGraphId === workflowGraphId &&
          subflow.parentReactFlowNodeId === propagationRequest.body.workflowNodeId &&
          subflow.childThreadId &&
          subflow.childRunId,
      ),
    );
    assert.deepEqual(
      projection.subagentChildSubflows.map((subflow) => subflow.subagentRole).sort(),
      ["explore", "implementer", "verifier"],
    );
    assert.ok(
      projection.subagentChildSubflowReactFlowNodes.some(
        (node) =>
          node.type === "runtimeSubagentRun" &&
          node.data.subagentRole === "verifier" &&
          node.data.subagentCancellationInheritance === "isolate",
      ),
    );
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "subagent" &&
          row.subagentRole === "verifier" &&
          row.subagentCancellationInheritance === "isolate" &&
          row.subagentOperation === "propagate_skip",
      ),
    );
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "subagent" &&
          row.subagentRole === "implementer" &&
          row.subagentLifecycleStatus === "canceled" &&
          row.subagentMergePolicy === "manual_review",
      ),
    );
    assert.ok(
      projection.rows
        .filter((row) => row.rowKind === "subagent")
        .every((row) => row.reactFlowNodeId === propagationRequest.body.workflowNodeId),
    );

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    const spawnEvents = events.filter((event) => event.source_event_kind === "OperatorControl.SubagentSpawn");
    const waitEvents = events.filter((event) => event.source_event_kind === "OperatorControl.SubagentWait");
    const propagatedCancelEvents = events.filter(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentCancel" &&
        event.workflow_node_id === propagationRequest.body.workflowNodeId,
    );
    assert.equal(spawnEvents.length, 3);
    assert.equal(waitEvents.length, 3);
    assert.equal(propagatedCancelEvents.length, 2);
    assert.ok(spawnEvents.every((event) => event.workflow_graph_id === workflowGraphId));
    assert.ok(waitEvents.every((event) => event.workflow_graph_id === workflowGraphId));
    assert.ok(propagatedCancelEvents.every((event) => event.payload_summary.cancellation_inherited === true));
  } finally {
    await daemon.close();
  }
});

test("React Flow subagent budget and cost caps block delegated child runs with projection evidence", async () => {
  const {
    createRuntimeSubagentControlRequestFromWorkflowNode,
    projectRuntimeTuiControlStateToWorkflowProjection,
    workflowRuntimeTelemetrySummaryFromProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-budget-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-budget-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const workflowGraphId = "workflow.react-flow.subagent-budget";
    const stateNode = (id, logic) => ({
      id,
      type: "state",
      config: {
        logic: {
          stateKey: "subagents",
          reducer: "append",
          stateOperation: "subagent_spawn",
          subagentRole: "explore",
          subagentPrompt: "Return budget telemetry evidence for delegated child work.",
          subagentToolPack: "coding",
          subagentModelRoute: "route.native-local",
          subagentOutputContractJson: "[\"SUMMARY\",\"EVIDENCE\",\"RECEIPTS\"]",
          subagentMergePolicy: "evidence_only",
          subagentCancellationInheritance: "propagate",
          ...logic,
        },
      },
    });

    const allowedRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      stateNode("subagent-budget-allowed", {
        subagentBudgetJson: JSON.stringify({ maxTokens: 12000, maxCostUsd: 1 }),
      }),
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.deepEqual(allowedRequest.body.budget, { maxTokens: 12000, maxCostUsd: 1 });
    const allowed = await fetchJson(`${daemon.endpoint}${allowedRequest.endpoint}`, {
      method: allowedRequest.method,
      body: JSON.stringify(allowedRequest.body),
    });
    assert.equal(allowed.lifecycle_status, "completed");
    assert.equal(allowed.budget_status, "within_budget");
    assert.equal(allowed.budgetStatus.status, "within_budget");
    assert.ok(allowed.usage_telemetry.cumulative_total_tokens > 1);
    assert.ok(allowed.usage_telemetry.cumulative_cost_estimate_usd > 0);
    assert.equal(allowed.event.payload_summary.budget_status, "within_budget");

    const allowedProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      subagent_rows: [
        {
          ...allowed,
          row_kind: "subagent",
          subagent_operation: "spawn",
          workflow_graph_id: workflowGraphId,
          workflow_node_id: allowedRequest.body.workflowNodeId,
        },
      ],
    });
    const telemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: allowedProjection,
    });
    assert.ok(telemetrySummary.totalTokens > 1);
    assert.equal(telemetrySummary.subagentCount, 1);

    const summaryBlockedRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      stateNode("subagent-budget-summary-blocked", {
        subagentPrompt:
          "Continue delegated work only if the shared runtime telemetry summary budget allows it.",
        subagentBudgetJson: JSON.stringify({
          maxTokens: telemetrySummary.totalTokens,
          maxCostUsd: 1,
        }),
        subagentBudgetUsageField: "runtimeTelemetrySummary",
      }),
      { threadId: thread.thread_id, runtimeTelemetrySummary: telemetrySummary },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(
      summaryBlockedRequest.body.budgetUsageTelemetry.total_tokens,
      telemetrySummary.totalTokens,
    );
    assert.equal(
      summaryBlockedRequest.body.budgetUsageTelemetry.source_counts.subagents,
      1,
    );
    const summaryBlocked = await fetchJsonStatus(
      `${daemon.endpoint}${summaryBlockedRequest.endpoint}`,
      {
        method: summaryBlockedRequest.method,
        body: JSON.stringify(summaryBlockedRequest.body),
      },
    );
    assert.equal(summaryBlocked.status, 403);
    assert.equal(summaryBlocked.body.error.details.reason, "subagent_budget_exceeded");
    assert.equal(summaryBlocked.body.error.details.budget_status, "exceeded");
    assert.ok(
      summaryBlocked.body.error.details.budgetStatus.usage
        .cumulative_total_tokens > telemetrySummary.totalTokens,
    );
    assert.equal(
      summaryBlocked.body.error.details.subagent.budget_usage_telemetry
        .cumulative_total_tokens,
      telemetrySummary.totalTokens,
    );

    const continuationBlockedRequest =
      createRuntimeSubagentControlRequestFromWorkflowNode(
        stateNode("subagent-budget-summary-continuation-blocked", {
          stateOperation: "subagent_send_input",
          subagentId: allowed.subagent_id,
          subagentInput:
            "Continue delegated work only if the shared telemetry budget allows continuation.",
          subagentBudgetJson: JSON.stringify({
            maxTokens: telemetrySummary.totalTokens,
            maxCostUsd: 1,
          }),
          subagentBudgetUsageField: "runtimeTelemetrySummary",
        }),
        { threadId: thread.thread_id, runtimeTelemetrySummary: telemetrySummary },
        { workflowGraphId, actor: "workflow-author" },
      );
    assert.equal(
      continuationBlockedRequest.body.budgetUsageTelemetry.total_tokens,
      telemetrySummary.totalTokens,
    );
    const continuationBlocked = await fetchJsonStatus(
      `${daemon.endpoint}${continuationBlockedRequest.endpoint}`,
      {
        method: continuationBlockedRequest.method,
        body: JSON.stringify(continuationBlockedRequest.body),
      },
    );
    assert.equal(continuationBlocked.status, 403);
    assert.equal(
      continuationBlocked.body.error.details.reason,
      "subagent_budget_exceeded",
    );
    assert.equal(
      continuationBlocked.body.error.details.subagent.lifecycle_status,
      "blocked",
    );
    assert.equal(
      continuationBlocked.body.error.details.subagent.budget_usage_telemetry
        .cumulative_total_tokens,
      telemetrySummary.totalTokens,
    );

    const blockedRequest = createRuntimeSubagentControlRequestFromWorkflowNode(
      stateNode("subagent-budget-blocked", {
        subagentPrompt:
          "Return enough delegated evidence that the one token budget is exceeded.",
        subagentBudgetJson: JSON.stringify({ maxTokens: 1, maxCostUsd: 0.000001 }),
      }),
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    const blocked = await fetchJsonStatus(`${daemon.endpoint}${blockedRequest.endpoint}`, {
      method: blockedRequest.method,
      body: JSON.stringify(blockedRequest.body),
    });
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error.code, "policy");
    assert.equal(blocked.body.error.details.reason, "subagent_budget_exceeded");
    assert.equal(blocked.body.error.details.budget_status, "exceeded");
    assert.equal(blocked.body.error.details.budgetStatus.status, "exceeded");
    assert.equal(blocked.body.error.details.subagent.lifecycle_status, "blocked");
    assert.ok(
      blocked.body.error.details.policy_decision_refs.some((ref) =>
        ref.includes("policy_subagent_budget_"),
      ),
    );

    const summaryBlockedSubagentId = summaryBlocked.body.error.details.subagent.subagent_id;
    const blockedSubagentId = blocked.body.error.details.subagent.subagent_id;
    const listed = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`);
    const summaryBlockedRecord = listed.subagents.find(
      (subagent) => subagent.subagent_id === summaryBlockedSubagentId,
    );
    assert.ok(summaryBlockedRecord);
    assert.equal(summaryBlockedRecord.lifecycle_status, "blocked");
    assert.equal(summaryBlockedRecord.budget_status, "exceeded");
    assert.equal(
      summaryBlockedRecord.budget_usage_telemetry.cumulative_total_tokens,
      telemetrySummary.totalTokens,
    );
    const blockedRecord = listed.subagents.find((subagent) => subagent.subagent_id === blockedSubagentId);
    assert.ok(blockedRecord);
    assert.equal(blockedRecord.lifecycle_status, "blocked");
    assert.equal(blockedRecord.budget_status, "exceeded");
    assert.equal(blockedRecord.block_reason, "subagent_budget_exceeded");
    assert.ok(blockedRecord.usage_telemetry.cumulative_total_tokens > 1);

    const waitedBlocked = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents/${blockedSubagentId}/wait`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId,
          workflowNodeId: "subagent-budget-blocked-wait",
        }),
      },
    );
    assert.equal(waitedBlocked.lifecycle_status, "blocked");
    assert.equal(waitedBlocked.budget_status, "exceeded");
    assert.equal(waitedBlocked.event.status, "blocked");
    assert.equal(waitedBlocked.event.payload_summary.budget_status, "exceeded");

    const projection = projectRuntimeTuiControlStateToWorkflowProjection({
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      subagent_rows: [
        {
          ...allowed,
          row_kind: "subagent",
          subagent_operation: "spawn",
          workflow_graph_id: workflowGraphId,
          workflow_node_id: allowedRequest.body.workflowNodeId,
        },
        {
          ...blockedRecord,
          row_kind: "subagent",
          subagent_operation: "spawn",
          workflow_graph_id: workflowGraphId,
          workflow_node_id: blockedRequest.body.workflowNodeId,
        },
        {
          ...summaryBlockedRecord,
          row_kind: "subagent",
          subagent_operation: "spawn",
          workflow_graph_id: workflowGraphId,
          workflow_node_id: summaryBlockedRequest.body.workflowNodeId,
        },
      ],
    });
    assert.equal(projection.subagentRowCount, 3);
    assert.equal(projection.subagentChildSubflowCount, 3);
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "subagent" &&
          row.subagentBudgetStatus === "exceeded" &&
          row.subagentTokenEstimate > 1 &&
          row.subagentCostEstimateUsd > 0,
      ),
    );
    assert.ok(
      projection.subagentChildSubflows.some(
        (subflow) =>
          subflow.subagentBudgetStatus === "exceeded" &&
          subflow.subagentLifecycleStatus === "blocked" &&
          subflow.subagentTokenEstimate > 1,
      ),
    );
    assert.ok(
      projection.subagentChildSubflowReactFlowNodes.some(
        (node) =>
          node.type === "runtimeSubagentRun" &&
          node.data.subagentBudgetStatus === "exceeded" &&
          node.data.subagentTokenEstimate > 1,
      ),
    );
  } finally {
    await daemon.close();
  }
});

test("daemon aggregates usage, cost, and context telemetry across turns and delegated subagents", async () => {
  const {
    createRuntimeContextBudgetControlRequestFromWorkflowNode,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
    workflowRuntimeTelemetrySummaryFromProjection,
  } = await importAgentIde();
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-usage-telemetry-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-usage-telemetry-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce usage telemetry evidence for the parent runtime turn.",
        mode: "send",
      }),
    });
    assert.equal(turn.usage.schema_version, "ioi.runtime.usage-telemetry.v1");
    assert.equal(turn.usage.scope, "run");
    assert.ok(turn.usage.total_tokens > 0);
    assert.ok(turn.usage.estimated_cost_usd > 0);

    const runId = `run_${turn.turn_id.slice("turn_".length)}`;
    const runUsage = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/usage`);
    assert.equal(runUsage.run_id, runId);
    assert.equal(runUsage.context_pressure_status, "nominal");

    const subagent = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/subagents`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        actor: "workflow-author",
        role: "usage-auditor",
        prompt: "Inspect delegated usage telemetry and return concise evidence.",
        budget: { maxTokens: 12000, maxCostUsd: 1 },
        outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
        workflowGraphId: "workflow.runtime.usage-telemetry",
        workflowNodeId: "runtime.subagent.spawn.usage-auditor",
      }),
    });
    assert.equal(subagent.budget_status, "within_budget");
    assert.ok(subagent.usage_telemetry.cumulative_total_tokens > 0);

    const threadUsage = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/usage`);
    assert.equal(threadUsage.schema_version, "ioi.runtime.usage-telemetry.v1");
    assert.equal(threadUsage.scope, "thread");
    assert.equal(threadUsage.thread_id, thread.thread_id);
    assert.equal(threadUsage.source_counts.runs, 1);
    assert.equal(threadUsage.source_counts.subagents, 1);
    assert.ok(threadUsage.total_tokens >= runUsage.total_tokens);
    assert.ok(threadUsage.total_tokens >= subagent.usage_telemetry.cumulative_total_tokens);
    assert.ok(threadUsage.estimated_cost_usd >= runUsage.estimated_cost_usd);
    assert.match(threadUsage.context_pressure_status, /nominal|elevated|high/);

    const listedUsage = await fetchJson(`${daemon.endpoint}/v1/usage?group_by=thread`);
    assert.equal(listedUsage.schema_version, "ioi.runtime.usage-telemetry.v1");
    assert.equal(listedUsage.group_by, "thread");
    assert.ok(listedUsage.usage.some((record) => record.thread_id === thread.thread_id));

    const threadProjection = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}`);
    assert.equal(threadProjection.usage.schema_version, "ioi.runtime.usage-telemetry.v1");
    assert.equal(threadProjection.usage.total_tokens, threadUsage.total_tokens);

    const projection = projectRuntimeTuiControlStateToWorkflowProjection({
      thread_id: thread.thread_id,
      workflow_graph_id: "workflow.runtime.usage-telemetry",
      usage_status: threadUsage,
    });
    assert.equal(projection.usageRowCount, 1);
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "usage_status" &&
          row.usageTotalTokens === threadUsage.total_tokens &&
          row.usageSubagentCount === 1 &&
          row.reactFlowNodeId === "runtime.usage-telemetry",
      ),
    );

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.ok(
      events.some(
        (event) =>
          event.workflow_node_id === "runtime.usage-telemetry" &&
          event.payload_summary?.eventKind === "RuntimeUsageTelemetry",
      ),
    );
    const usageDelta = events.find(
      (event) =>
        event.event_kind === "usage.delta" &&
        event.workflow_node_id === "runtime.usage-telemetry",
    );
    assert.ok(usageDelta);
    assert.equal(usageDelta.component_kind, "usage_telemetry");
    assert.equal(usageDelta.status, "running");
    assert.ok(usageDelta.payload_summary.total_tokens > 0);

    const contextPressureDelta = events.find(
      (event) =>
        event.event_kind === "context.pressure_delta" &&
        event.workflow_node_id === "runtime.context-budget",
    );
    assert.ok(contextPressureDelta);
    assert.equal(contextPressureDelta.component_kind, "context_pressure");
    assert.match(
      contextPressureDelta.payload_summary.usage_context_pressure_status,
      /nominal|elevated|high/,
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    assert.ok(
      sdkEvents.some(
        (event) =>
          event.type === "usage_delta" &&
          event.workflowNodeId === "runtime.usage-telemetry",
      ),
    );
    assert.ok(
      sdkEvents.some(
        (event) =>
          event.type === "context_pressure_delta" &&
          event.workflowNodeId === "runtime.context-budget",
      ),
    );
    const runtimeProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    assert.ok(
      runtimeProjection.nodes.some(
        (node) =>
          node.workflowNodeId === "runtime.usage-telemetry" &&
          node.nodeKind === "runtime_usage_meter",
      ),
    );
    assert.ok(
      runtimeProjection.nodes.some(
        (node) =>
          node.workflowNodeId === "runtime.context-budget" &&
          node.nodeKind === "runtime_context_budget",
      ),
    );
    const telemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      runtimeThreadEvents: sdkEvents,
      runtimeEventProjection: runtimeProjection,
      tuiControlStateProjection: projection,
    });
    assert.equal(
      telemetrySummary.schemaVersion,
      "ioi.workflow.runtime-telemetry-summary.v1",
    );
    assert.match(telemetrySummary.status, /nominal|elevated|high|blocked/);
    assert.ok(telemetrySummary.totalTokens >= threadUsage.total_tokens);
    assert.ok(telemetrySummary.costEstimateUsd >= threadUsage.estimated_cost_usd);
    assert.equal(telemetrySummary.runCount, 1);
    assert.equal(telemetrySummary.subagentCount, 1);
    assert.equal(telemetrySummary.usageRowCount, 1);
    assert.ok(telemetrySummary.usageEventCount >= 1);
    assert.ok(telemetrySummary.contextPressureEventCount >= 1);
    assert.ok(telemetrySummary.sourceKinds.includes("runtime_usage_events"));
    assert.ok(telemetrySummary.sourceKinds.includes("tui_usage_rows"));
    assert.ok(telemetrySummary.workflowNodeIds.includes("runtime.usage-telemetry"));
    assert.ok(telemetrySummary.workflowNodeIds.includes("runtime.context-budget"));

    const summaryGateRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
      {
        id: "react-flow-summary-budget-gate",
        type: "runtime_context_budget",
        config: {
          logic: {
            runtimeContextBudgetScope: "thread",
            runtimeContextBudgetThreadIdField: "threadId",
            runtimeContextBudgetUsageField: "runtimeTelemetrySummary",
            runtimeContextBudgetMode: "block",
            runtimeContextBudgetMaxTotalTokens: Math.max(
              1,
              telemetrySummary.totalTokens - 1,
            ),
            runtimeContextBudgetMaxCostUsd: Math.max(
              0.000001,
              telemetrySummary.costEstimateUsd / 2,
            ),
            runtimeContextBudgetWorkflowNodeId:
              "runtime.context-budget.summary-gate",
            runtimeContextBudgetActor: "workflow-author",
          },
        },
      },
      {
        threadId: thread.thread_id,
        runtimeTelemetrySummary: telemetrySummary,
      },
      {
        workflowGraphId: "workflow.runtime.usage-telemetry",
        actor: "workflow-author",
      },
    );
    assert.equal(
      summaryGateRequest.body.usageTelemetry.total_tokens,
      telemetrySummary.totalTokens,
    );
    assert.equal(
      summaryGateRequest.body.usageTelemetry.estimated_cost_usd,
      telemetrySummary.costEstimateUsd,
    );
    assert.equal(
      summaryGateRequest.body.usageTelemetry.context_pressure,
      telemetrySummary.contextPressure,
    );
    assert.equal(
      summaryGateRequest.body.usageTelemetry.source_counts.subagents,
      telemetrySummary.subagentCount,
    );
    const summaryGate = await fetchJson(
      `${daemon.endpoint}${summaryGateRequest.endpoint}`,
      {
        method: summaryGateRequest.method,
        body: JSON.stringify(summaryGateRequest.body),
      },
    );
    assert.equal(summaryGate.status, "blocked");
    assert.equal(
      summaryGate.workflow_node_id,
      "runtime.context-budget.summary-gate",
    );
    assert.equal(summaryGate.usage_summary.total_tokens, telemetrySummary.totalTokens);
    assert.equal(
      summaryGate.usage_summary.estimated_cost_usd,
      telemetrySummary.costEstimateUsd,
    );
    assert.equal(
      summaryGate.usage_summary.context_pressure,
      telemetrySummary.contextPressure,
    );
    assert.ok(
      summaryGate.policy_decision_refs.some((ref) =>
        ref.startsWith("policy_context_budget_thread_"),
      ),
    );
  } finally {
    await daemon.close();
  }
});

test("React Flow usage meter workflow node reads daemon telemetry with graph identity", async () => {
  const {
    createRuntimeUsageMeterControlRequestFromWorkflowNode,
    projectRuntimeTuiControlStateToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-usage-meter-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-usage-meter-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce usage meter evidence for a workflow-authored telemetry node.",
        mode: "send",
      }),
    });
    const runId = `run_${turn.turn_id.slice("turn_".length)}`;
    const workflowGraphId = "workflow.react-flow.usage-meter";
    const usageNode = {
      id: "react-flow-usage-meter",
      type: "runtime_usage_meter",
      config: {
        logic: {
          runtimeUsageMeterScope: "thread",
          runtimeUsageMeterThreadIdField: "threadId",
          runtimeUsageMeterWorkflowNodeId: "runtime.usage-meter",
          runtimeUsageMeterSimulationMode: true,
        },
      },
    };

    const threadRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      usageNode,
      { threadId: thread.thread_id },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(threadRequest.nodeType, "runtime_usage_meter");
    assert.equal(threadRequest.method, "GET");
    assert.equal(threadRequest.body, null);
    assert.equal(threadRequest.scope, "thread");
    assert.match(threadRequest.endpoint, /\/v1\/threads\/.+\/usage\?/);
    assert.match(threadRequest.endpoint, /usage_meter_scope=thread/);
    assert.match(threadRequest.endpoint, /workflow_node_id=runtime\.usage-meter/);
    const threadUsage = await fetchJson(`${daemon.endpoint}${threadRequest.endpoint}`);
    assert.equal(threadUsage.schema_version, "ioi.runtime.usage-telemetry.v1");
    assert.equal(threadUsage.scope, "thread");
    assert.equal(threadUsage.source, "react_flow");
    assert.equal(threadUsage.actor, "workflow-author");
    assert.equal(threadUsage.workflow_graph_id, workflowGraphId);
    assert.equal(threadUsage.workflow_node_id, "runtime.usage-meter");
    assert.equal(threadUsage.usage_meter_scope, "thread");
    assert.equal(threadUsage.simulation_mode, true);
    assert.ok(threadUsage.total_tokens >= turn.usage.total_tokens);

    const projection = projectRuntimeTuiControlStateToWorkflowProjection({
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      usage_status: threadUsage,
    });
    const usageRow = projection.rows.find(
      (row) =>
        row.rowKind === "usage_status" &&
        row.reactFlowNodeId === "runtime.usage-meter",
    );
    assert.ok(usageRow);
    assert.equal(usageRow.usageTotalTokens, threadUsage.total_tokens);
    assert.equal(usageRow.usageScope, "thread");

    const runNode = {
      ...usageNode,
      config: {
        logic: {
          runtimeUsageMeterScope: "run",
          runtimeUsageMeterRunIdField: "runId",
          runtimeUsageMeterWorkflowNodeId: "runtime.usage-meter.run",
        },
      },
    };
    const runRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      runNode,
      { runId },
      { workflowGraphId },
    );
    assert.equal(runRequest.scope, "run");
    assert.equal(runRequest.runId, runId);
    assert.match(runRequest.endpoint, new RegExp(`/v1/runs/${runId}/usage\\?`));
    const runUsage = await fetchJson(`${daemon.endpoint}${runRequest.endpoint}`);
    assert.equal(runUsage.run_id, runId);
    assert.equal(runUsage.workflow_node_id, "runtime.usage-meter.run");
    assert.equal(runUsage.usage_meter_scope, "run");
  } finally {
    await daemon.close();
  }
});

test("React Flow context budget workflow node evaluates daemon telemetry policy", async () => {
  const {
    createRuntimeContextBudgetControlRequestFromWorkflowNode,
    createRuntimeUsageMeterControlRequestFromWorkflowNode,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-context-budget-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-context-budget-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce context budget evidence for a workflow-authored policy node.",
        mode: "send",
      }),
    });
    const workflowGraphId = "workflow.react-flow.context-budget";
    const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      {
        id: "react-flow-usage-meter",
        type: "runtime_usage_meter",
        config: {
          logic: {
            runtimeUsageMeterScope: "thread",
            runtimeUsageMeterThreadIdField: "threadId",
            runtimeUsageMeterWorkflowNodeId: "runtime.usage-meter",
          },
        },
      },
      { threadId: thread.thread_id },
      { workflowGraphId },
    );
    const usageTelemetry = await fetchJson(`${daemon.endpoint}${usageRequest.endpoint}`);
    assert.ok(usageTelemetry.total_tokens >= turn.usage.total_tokens);

    const budgetRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
      {
        id: "react-flow-context-budget",
        type: "runtime_context_budget",
        config: {
          logic: {
            runtimeContextBudgetScope: "thread",
            runtimeContextBudgetThreadIdField: "threadId",
            runtimeContextBudgetUsageField: "usageTelemetry",
            runtimeContextBudgetMode: "block",
            runtimeContextBudgetMaxTotalTokens: 1,
            runtimeContextBudgetMaxCostUsd: 0.000001,
            runtimeContextBudgetMaxContextPressure: 0.000001,
            runtimeContextBudgetWorkflowNodeId: "runtime.context-budget",
          },
        },
      },
      { threadId: thread.thread_id, usageTelemetry },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(budgetRequest.nodeType, "runtime_context_budget");
    assert.equal(budgetRequest.method, "POST");
    assert.equal(budgetRequest.scope, "thread");
    assert.match(budgetRequest.endpoint, /\/v1\/threads\/.+\/context-budget/);
    assert.equal(budgetRequest.body.mode, "block");
    assert.equal(budgetRequest.body.thresholds.maxTotalTokens, 1);
    assert.equal(budgetRequest.body.workflowNodeId, "runtime.context-budget");

    const budgetResult = await fetchJson(`${daemon.endpoint}${budgetRequest.endpoint}`, {
      method: budgetRequest.method,
      body: JSON.stringify(budgetRequest.body),
    });
    assert.equal(budgetResult.schema_version, "ioi.runtime.context-budget-policy.v1");
    assert.equal(budgetResult.status, "blocked");
    assert.equal(budgetResult.mode, "block");
    assert.equal(budgetResult.workflow_graph_id, workflowGraphId);
    assert.equal(budgetResult.workflow_node_id, "runtime.context-budget");
    assert.equal(budgetResult.component_kind, "context_budget");
    assert.equal(budgetResult.would_block, true);
    assert.ok(budgetResult.violations.length >= 1);
    assert.ok(budgetResult.receipt_refs[0].startsWith("receipt_context_budget_thread_"));
    assert.ok(budgetResult.policy_decision_refs[0].startsWith("policy_context_budget_thread_"));

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    const budgetEvent = events.find(
      (event) =>
        event.component_kind === "context_budget" &&
        event.workflow_node_id === "runtime.context-budget",
    );
    assert.ok(budgetEvent);
    assert.equal(budgetEvent.event_kind, "policy.blocked");
    assert.equal(budgetEvent.source_event_kind, "RuntimeContextBudget.Evaluate");
    assert.equal(budgetEvent.status, "blocked");
    assert.deepEqual(budgetEvent.receipt_refs, budgetResult.receipt_refs);
    assert.deepEqual(budgetEvent.policy_decision_refs, budgetResult.policy_decision_refs);
    assert.equal(budgetEvent.payload_summary.status, "blocked");
  } finally {
    await daemon.close();
  }
});

test("React Flow compaction policy workflow node drives approved compaction", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode,
    createRuntimeContextBudgetControlRequestFromWorkflowNode,
    createRuntimeUsageMeterControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-compaction-policy-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-compaction-policy-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce compaction policy evidence for a workflow-authored actuator node.",
        mode: "send",
      }),
    });
    const workflowGraphId = "workflow.react-flow.compaction-policy";
    const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      {
        id: "react-flow-usage-meter",
        type: "runtime_usage_meter",
        config: {
          logic: {
            runtimeUsageMeterScope: "thread",
            runtimeUsageMeterThreadIdField: "threadId",
            runtimeUsageMeterWorkflowNodeId: "runtime.usage-meter",
          },
        },
      },
      { threadId: thread.thread_id },
      { workflowGraphId },
    );
    const usageTelemetry = await fetchJson(`${daemon.endpoint}${usageRequest.endpoint}`);
    assert.ok(usageTelemetry.total_tokens >= turn.usage.total_tokens);

    const budgetRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
      {
        id: "react-flow-context-budget",
        type: "runtime_context_budget",
        config: {
          logic: {
            runtimeContextBudgetScope: "thread",
            runtimeContextBudgetThreadIdField: "threadId",
            runtimeContextBudgetUsageField: "usageTelemetry",
            runtimeContextBudgetMode: "block",
            runtimeContextBudgetMaxTotalTokens: 1,
            runtimeContextBudgetWorkflowNodeId: "runtime.context-budget",
          },
        },
      },
      { threadId: thread.thread_id, usageTelemetry },
      { workflowGraphId },
    );
    const budgetResult = await fetchJson(`${daemon.endpoint}${budgetRequest.endpoint}`, {
      method: budgetRequest.method,
      body: JSON.stringify(budgetRequest.body),
    });
    assert.equal(budgetResult.status, "blocked");

    const policyRequest = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      {
        id: "react-flow-compaction-policy",
        type: "runtime_compaction_policy",
        config: {
          logic: {
            runtimeCompactionPolicyThreadIdField: "threadId",
            runtimeCompactionPolicyTurnIdField: "turnId",
            runtimeCompactionPolicyContextBudgetField: "runtimeContextBudget",
            runtimeCompactionPolicyBlockedAction: "compact",
            runtimeCompactionPolicyApprovalRequired: true,
            runtimeCompactionPolicyApprovalGrantedField: "approvalGranted",
            runtimeCompactionPolicyExecuteCompactionField: "executeCompaction",
            runtimeCompactionPolicyCompactReason:
              "approved context-budget policy requested compaction",
            runtimeCompactionPolicyCompactWorkflowNodeId: "runtime.context-compact",
            runtimeCompactionPolicyWorkflowNodeId: "runtime.compaction-policy",
          },
        },
      },
      {
        threadId: thread.thread_id,
        turnId: turn.turn_id,
        runtimeContextBudget: budgetResult,
        approvalGranted: true,
        executeCompaction: true,
      },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(policyRequest.nodeType, "runtime_compaction_policy");
    assert.equal(policyRequest.body.policy.blockedAction, "compact");
    assert.equal(policyRequest.body.policy.approvalRequired, true);
    assert.equal(policyRequest.body.policy.approvalGranted, true);
    assert.equal(policyRequest.body.policy.executeCompaction, true);
    assert.equal(policyRequest.body.contextBudgetStatus, "blocked");

    const policyResult = await fetchJson(`${daemon.endpoint}${policyRequest.endpoint}`, {
      method: policyRequest.method,
      body: JSON.stringify(policyRequest.body),
    });
    assert.equal(policyResult.schema_version, "ioi.runtime.compaction-policy.v1");
    assert.equal(policyResult.status, "compacted");
    assert.equal(policyResult.action, "compact");
    assert.equal(policyResult.budget_status, "blocked");
    assert.equal(policyResult.approval_required, true);
    assert.equal(policyResult.approval_satisfied, true);
    assert.equal(policyResult.execute_compaction, true);
    assert.equal(policyResult.compaction_executed, true);
    assert.equal(policyResult.workflow_graph_id, workflowGraphId);
    assert.equal(policyResult.workflow_node_id, "runtime.compaction-policy");
    assert.equal(policyResult.compact_workflow_node_id, "runtime.context-compact");
    assert.ok(policyResult.compaction_event_id);
    assert.ok(policyResult.receipt_refs[0].startsWith("receipt_compaction_policy_"));
    assert.ok(policyResult.policy_decision_refs[0].startsWith("policy_compaction_"));

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const policyEvent = daemonEvents.find(
      (event) => event.event_id === policyResult.event_id,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.event_id === policyResult.compaction_event_id,
    );
    assert.ok(policyEvent);
    assert.ok(compactEvent);
    assert.equal(policyEvent.event_kind, "compaction_policy.evaluated");
    assert.equal(policyEvent.source_event_kind, "RuntimeCompactionPolicy.Evaluate");
    assert.equal(policyEvent.component_kind, "compaction_policy");
    assert.equal(policyEvent.workflow_node_id, "runtime.compaction-policy");
    assert.equal(policyEvent.payload_summary.action, "compact");
    assert.equal(policyEvent.payload_summary.compaction_executed, true);
    assert.equal(compactEvent.event_kind, "context.compacted");
    assert.equal(compactEvent.component_kind, "context_compaction");
    assert.equal(compactEvent.workflow_node_id, "runtime.context-compact");
    assert.equal(compactEvent.payload.reason, "approved context-budget policy requested compaction");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkPolicyEvent = sdkEvents.find((event) => event.id === policyEvent.event_id);
    assert.ok(sdkPolicyEvent);
    assert.equal(sdkPolicyEvent.type, "compaction_policy_evaluated");
    assert.equal(sdkPolicyEvent.componentKind, "compaction_policy");
    assert.equal(sdkPolicyEvent.workflowNodeId, "runtime.compaction-policy");
    const projection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const policyNode = projection.nodes.find((node) =>
      node.eventIds.includes(policyEvent.event_id),
    );
    const compactNode = projection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    assert.equal(policyNode?.nodeKind, "runtime_compaction_policy");
    assert.equal(policyNode?.componentKind, "compaction_policy");
    assert.equal(compactNode?.nodeKind, "runtime_context_compact");
    assert.equal(compactNode?.componentKind, "context_compaction");
  } finally {
    await daemon.close();
  }
});

test("React Flow bound telemetry-source chain executes with graph and node identity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION,
    bindWorkflowRuntimeTelemetrySourceToWorkflow,
    createRuntimeCodingToolControlRequestFromWorkflowNode,
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode,
    createRuntimeContextBudgetControlRequestFromWorkflowNode,
    createRuntimeUsageMeterControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
    projectRuntimeTuiControlStateToWorkflowProjection,
    workflowRuntimeTelemetrySummaryFromProjection,
  } = await importAgentIde();
  const cli = cliBinary();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-bound-telemetry-chain-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-bound-telemetry-chain-state-"));
  const targetPath = path.join(cwd, "README.md");
  fs.writeFileSync(targetPath, "Bound telemetry source keeps this line.\n");
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.bound-telemetry-source-chain";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove a bound runtime telemetry source drives a React Flow budget chain.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce telemetry for a bound React Flow usage, context, compaction, and coding budget chain.",
        mode: "send",
      }),
    });

    const seedUsageParams = new URLSearchParams({
      source: "react_flow",
      actor: "workflow-author",
      event_kind: "RuntimeUsageTelemetry.Read",
      component_kind: "usage_telemetry",
      payload_schema_version: "ioi.runtime.usage-telemetry.v1",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "telemetry-source-seed",
      usage_meter_scope: "thread",
      simulation_mode: "true",
    });
    const seedUsage = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/usage?${seedUsageParams}`,
    );
    assert.equal(seedUsage.workflow_graph_id, workflowGraphId);
    assert.equal(seedUsage.workflow_node_id, "telemetry-source-seed");
    assert.ok(seedUsage.total_tokens >= turn.usage.total_tokens);

    const seedProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      current_turn_id: turn.turn_id,
      last_event_id: "telemetry-source-seed",
      usage_status: {
        ...seedUsage,
        event_id: "telemetry-source-seed",
        workflow_node_id: "telemetry-source-seed",
      },
    });
    const telemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: seedProjection,
    });
    assert.ok(telemetrySummary.sourceKinds.includes("tui_usage_rows"));
    assert.equal(telemetrySummary.threadIds[0], thread.thread_id);
    assert.equal(telemetrySummary.workflowGraphIds[0], workflowGraphId);

    const workflow = {
      version: "workflow.v1",
      metadata: {
        id: workflowGraphId,
        name: "Bound telemetry source chain",
        slug: "bound-telemetry-source-chain",
        workflowKind: "agent_workflow",
        executionMode: "local",
        gitLocation: ".agents/workflows/bound-telemetry-source-chain.workflow.json",
        readOnly: false,
        dirty: false,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      },
      nodes: [
        {
          id: "bound-usage-meter",
          type: "runtime_usage_meter",
          name: "Bound usage meter",
          x: 0,
          y: 0,
          config: { kind: "runtime_usage_meter", logic: {} },
        },
        {
          id: "bound-context-budget",
          type: "runtime_context_budget",
          name: "Bound context budget",
          x: 280,
          y: 0,
          config: {
            kind: "runtime_context_budget",
            logic: {
              runtimeContextBudgetMode: "block",
              runtimeContextBudgetMaxTotalTokens: 1,
              runtimeContextBudgetMaxCostUsd: 0.000001,
              runtimeContextBudgetMaxContextPressure: 0.000001,
            },
          },
        },
        {
          id: "bound-compaction-policy",
          type: "runtime_compaction_policy",
          name: "Bound compaction policy",
          x: 560,
          y: 0,
          config: {
            kind: "runtime_compaction_policy",
            logic: {
              runtimeCompactionPolicyBlockedAction: "compact",
              runtimeCompactionPolicyApprovalRequired: false,
              runtimeCompactionPolicyExecuteCompaction: true,
              runtimeCompactionPolicyCompactReason:
                "bound telemetry-source context budget requested compaction",
            },
          },
        },
        {
          id: "bound-coding-tool-budget-gate",
          type: "plugin_tool",
          name: "Bound coding tool budget gate",
          x: 840,
          y: 0,
          config: {
            kind: "plugin_tool",
            logic: {
              toolBinding: {
                toolRef: "file.apply_patch",
                bindingKind: "coding_tool_pack",
                mockBinding: false,
                credentialReady: true,
                capabilityScope: ["file.apply_patch"],
                sideEffectClass: "write",
                requiresApproval: false,
                arguments: {
                  path: "README.md",
                  oldText: "Bound telemetry source keeps this line.",
                  newText: "Bound telemetry source should not allow mutation.",
                },
                toolPack: {
                  pack: "coding",
                  writeEnabled: true,
                  dryRun: false,
                  approvalMode: "suggest",
                  trustProfile: "local_private",
                  nodeApprovalOverride: "inherit",
                  requiresApproval: false,
                  budgetMode: "block",
                  budgetUsageField: "runtimeTelemetrySummary",
                  maxTotalTokens: 1,
                  maxCostUsd: 1,
                  maxContextPressure: 1,
                },
              },
            },
          },
        },
      ],
      edges: [
        { id: "usage-to-budget", from: "bound-usage-meter", to: "bound-context-budget", type: "data" },
        { id: "budget-to-policy", from: "bound-context-budget", to: "bound-compaction-policy", type: "data" },
        { id: "policy-to-tool", from: "bound-compaction-policy", to: "bound-coding-tool-budget-gate", type: "control" },
      ],
      global_config: {},
    };

    const binding = bindWorkflowRuntimeTelemetrySourceToWorkflow(
      workflow,
      telemetrySummary,
    );
    assert.equal(binding.status, "bound");
    assert.deepEqual(binding.boundNodeIds, [
      "bound-usage-meter",
      "bound-context-budget",
      "bound-compaction-policy",
      "bound-coding-tool-budget-gate",
    ]);
    assert.equal(
      binding.evidenceBinding.schemaVersion,
      WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION,
    );

    const boundNode = (id) => binding.workflow.nodes.find((node) => node.id === id);
    const usageNode = boundNode("bound-usage-meter");
    const contextNode = boundNode("bound-context-budget");
    const compactionNode = boundNode("bound-compaction-policy");
    const codingNode = boundNode("bound-coding-tool-budget-gate");
    assert.ok(usageNode);
    assert.ok(contextNode);
    assert.ok(compactionNode);
    assert.ok(codingNode);
    for (const node of [usageNode, contextNode, compactionNode, codingNode]) {
      assert.equal(
        node.config.logic.runtimeTelemetrySourceBinding.schemaVersion,
        WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION,
      );
    }

    const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      usageNode,
      {},
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(usageRequest.metadata.workflowNodeId, "bound-usage-meter");
    const usageResult = await fetchJson(`${daemon.endpoint}${usageRequest.endpoint}`);
    assert.equal(usageResult.workflow_graph_id, workflowGraphId);
    assert.equal(usageResult.workflow_node_id, "bound-usage-meter");
    assert.ok(usageResult.total_tokens >= turn.usage.total_tokens);

    const usageProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      current_turn_id: turn.turn_id,
      usage_status: usageResult,
    });
    assert.ok(
      usageProjection.rows.some(
        (row) =>
          row.rowKind === "usage_status" &&
          row.reactFlowNodeId === "bound-usage-meter" &&
          row.usageTotalTokens === usageResult.total_tokens,
      ),
    );

    const budgetRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
      contextNode,
      { runtimeUsageMeter: usageResult },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(budgetRequest.body.workflowNodeId, "bound-context-budget");
    assert.equal(budgetRequest.body.usageTelemetry.workflow_node_id, "bound-usage-meter");
    const budgetResult = await fetchJson(`${daemon.endpoint}${budgetRequest.endpoint}`, {
      method: budgetRequest.method,
      body: JSON.stringify(budgetRequest.body),
    });
    assert.equal(budgetResult.status, "blocked");
    assert.equal(budgetResult.workflow_graph_id, workflowGraphId);
    assert.equal(budgetResult.workflow_node_id, "bound-context-budget");

    const policyRequest = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      compactionNode,
      { runtimeContextBudget: budgetResult },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(policyRequest.body.workflowNodeId, "bound-compaction-policy");
    assert.equal(policyRequest.body.contextBudgetStatus, "blocked");
    assert.equal(policyRequest.body.policy.compactWorkflowNodeId, "bound-compaction-policy.compact");
    const policyResult = await fetchJson(`${daemon.endpoint}${policyRequest.endpoint}`, {
      method: policyRequest.method,
      body: JSON.stringify(policyRequest.body),
    });
    assert.equal(policyResult.status, "compacted");
    assert.equal(policyResult.action, "compact");
    assert.equal(policyResult.workflow_graph_id, workflowGraphId);
    assert.equal(policyResult.workflow_node_id, "bound-compaction-policy");
    assert.equal(policyResult.compact_workflow_node_id, "bound-compaction-policy.compact");
    assert.equal(policyResult.compaction_executed, true);

    const boundContextRows = [
      {
        id: "bound-context-budget-row",
        row_kind: "context_budget",
        status: budgetResult.status,
        context_budget_status: budgetResult.status,
        context_budget_mode: budgetResult.mode,
        context_budget_decision_id: budgetResult.policy_decision_id,
        usage_total_tokens: String(budgetResult.usage_summary.total_tokens),
        usage_cost_estimate_usd: String(budgetResult.usage_summary.estimated_cost_usd),
        usage_context_pressure: String(budgetResult.usage_summary.context_pressure),
        usage_context_pressure_status: budgetResult.usage_summary.context_pressure_status,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: "bound-context-budget",
        event_id: budgetResult.event_id,
        receipt_refs: budgetResult.receipt_refs,
        policy_decision_refs: budgetResult.policy_decision_refs,
        context_budget: budgetResult,
      },
      {
        id: "bound-compaction-policy-row",
        row_kind: "compaction_policy",
        status: policyResult.status,
        turn_id: turn.turn_id,
        context_budget_status: policyResult.budget_status,
        compaction_policy_status: policyResult.status,
        compaction_policy_action: policyResult.action,
        compaction_policy_decision_id: policyResult.policy_decision_id,
        compaction_executed: String(policyResult.compaction_executed),
        workflow_graph_id: workflowGraphId,
        workflow_node_id: "bound-compaction-policy",
        event_id: policyResult.event_id,
        receipt_refs: policyResult.receipt_refs,
        policy_decision_refs: policyResult.policy_decision_refs,
        context_budget: budgetResult,
      },
    ];
    const preCodingControlState = {
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      current_turn_id: turn.turn_id,
      last_event_id: policyResult.event_id,
      context_rows: boundContextRows,
    };
    const preCodingProjection = projectRuntimeTuiControlStateToWorkflowProjection(
      preCodingControlState,
    );
    assert.ok(
      preCodingProjection.rows.some(
        (row) =>
          row.rowKind === "context_budget" &&
          row.reactFlowNodeId === "bound-context-budget",
      ),
    );
    assert.ok(
      preCodingProjection.rows.some(
        (row) =>
          row.rowKind === "compaction_policy" &&
          row.reactFlowNodeId === "bound-compaction-policy",
      ),
    );
    const liveTelemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: preCodingProjection,
    });
    assert.ok(liveTelemetrySummary.sourceKinds.includes("tui_context_rows"));
    assert.ok(liveTelemetrySummary.eventIds.includes(policyResult.event_id));

    const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
      codingNode,
      {
        ...codingNode.config.logic.testInput,
        runtimeTelemetrySummary: liveTelemetrySummary,
      },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(codingRequest.body.workflowNodeId, "bound-coding-tool-budget-gate");
    assert.equal(
      codingRequest.body.toolPack.coding.telemetrySourceBinding.schemaVersion,
      WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION,
    );
    assert.ok(codingRequest.body.budgetUsageTelemetry.total_tokens >= 1);
    assert.ok(
      codingRequest.body.budgetUsageTelemetry.source_refs.includes(
        policyResult.event_id,
      ),
    );
    const blockedTool = await fetchJsonStatus(`${daemon.endpoint}${codingRequest.endpoint}`, {
      method: codingRequest.method,
      body: JSON.stringify({
        ...codingRequest.body,
        tool_call_id: "bound_telemetry_source_coding_budget_blocked",
        toolCallId: "bound_telemetry_source_coding_budget_blocked",
      }),
    });
    assert.equal(blockedTool.status, 403);
    assert.equal(blockedTool.body.error.details.reason, "coding_tool_budget_exceeded");
    assert.equal(
      blockedTool.body.error.details.budget_usage_telemetry.runtime_telemetry_summary_schema_version,
      "ioi.workflow.runtime-telemetry-summary.v1",
    );
    assert.equal(fs.readFileSync(targetPath, "utf8"), "Bound telemetry source keeps this line.\n");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const contextBudgetEvent = daemonEvents.find(
      (event) =>
        event.component_kind === "context_budget" &&
        event.workflow_node_id === "bound-context-budget",
    );
    const policyEvent = daemonEvents.find((event) => event.event_id === policyResult.event_id);
    const compactEvent = daemonEvents.find(
      (event) => event.event_id === policyResult.compaction_event_id,
    );
    const codingBudgetEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "policy.blocked" &&
        event.component_kind === "coding_tool" &&
        event.workflow_node_id === "bound-coding-tool-budget-gate",
    );
    assert.ok(contextBudgetEvent);
    assert.ok(policyEvent);
    assert.ok(compactEvent);
    assert.ok(codingBudgetEvent);
    for (const event of [contextBudgetEvent, policyEvent, compactEvent, codingBudgetEvent]) {
      assert.equal(event.workflow_graph_id, workflowGraphId);
    }
    assert.equal(contextBudgetEvent.status, "blocked");
    assert.equal(policyEvent.workflow_node_id, "bound-compaction-policy");
    assert.equal(compactEvent.workflow_node_id, "bound-compaction-policy.compact");
    assert.equal(codingBudgetEvent.status, "blocked");
    assert.equal(
      codingBudgetEvent.payload_summary.budget_usage_telemetry.runtime_telemetry_summary_schema_version,
      "ioi.workflow.runtime-telemetry-summary.v1",
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const runtimeProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const contextBudgetNode = runtimeProjection.nodes.find((node) =>
      node.eventIds.includes(contextBudgetEvent.event_id),
    );
    const policyNode = runtimeProjection.nodes.find((node) =>
      node.eventIds.includes(policyEvent.event_id),
    );
    const compactNode = runtimeProjection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    const codingBudgetNode = runtimeProjection.nodes.find((node) =>
      node.eventIds.includes(codingBudgetEvent.event_id),
    );
    assert.equal(contextBudgetNode?.nodeKind, "runtime_context_budget");
    assert.equal(contextBudgetNode?.workflowNodeId, "bound-context-budget");
    assert.equal(policyNode?.nodeKind, "runtime_compaction_policy");
    assert.equal(policyNode?.workflowNodeId, "bound-compaction-policy");
    assert.equal(compactNode?.nodeKind, "runtime_context_compact");
    assert.equal(compactNode?.workflowNodeId, "bound-compaction-policy.compact");
    assert.equal(codingBudgetNode?.nodeKind, "plugin_tool");
    assert.equal(codingBudgetNode?.workflowNodeId, "bound-coding-tool-budget-gate");

    const finalTui = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const finalControlState = JSON.parse(finalTui.stdout).tui_control_state;
    assert.ok(
      finalControlState.coding_tool_rows.some(
        (row) =>
          row.row_kind === "coding_tool_budget" &&
          row.workflow_node_id === "bound-coding-tool-budget-gate" &&
          row.event_id === codingBudgetEvent.event_id,
      ),
    );
    const finalProjection = projectRuntimeTuiControlStateToWorkflowProjection(
      {
        ...finalControlState,
        workflow_graph_id: workflowGraphId,
        context_rows: [
          ...boundContextRows,
          ...(Array.isArray(finalControlState.context_rows)
            ? finalControlState.context_rows
            : []),
        ],
      },
    );
    assert.ok(
      finalProjection.rows.some(
        (row) =>
          row.rowKind === "context_budget" &&
          row.reactFlowNodeId === "bound-context-budget",
      ),
    );
    assert.ok(
      finalProjection.rows.some(
        (row) =>
          row.rowKind === "compaction_policy" &&
          row.reactFlowNodeId === "bound-compaction-policy",
      ),
    );
    assert.ok(
      finalProjection.rows.some(
        (row) =>
          row.rowKind === "coding_tool_budget" &&
          row.reactFlowNodeId === "bound-coding-tool-budget-gate" &&
          row.eventId === codingBudgetEvent.event_id,
      ),
    );
    const finalSummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: finalProjection,
    });
    assert.ok(finalSummary.eventIds.includes(codingBudgetEvent.event_id));
    assert.ok(finalSummary.workflowNodeIds.includes("bound-context-budget"));
    assert.ok(finalSummary.workflowNodeIds.includes("bound-compaction-policy"));
    assert.ok(finalSummary.workflowNodeIds.includes("bound-coding-tool-budget-gate"));
  } finally {
    await daemon.close();
  }
});

test("React Flow run-inspector-created telemetry budget chain executes with graph and node identity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeCodingToolControlRequestFromWorkflowNode,
    createRuntimeCompactionPolicyControlRequestFromWorkflowNode,
    createRuntimeContextBudgetControlRequestFromWorkflowNode,
    createRuntimeUsageMeterControlRequestFromWorkflowNode,
    materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry,
    projectRuntimeThreadEventsToWorkflowProjection,
    projectRuntimeTuiControlStateToWorkflowProjection,
    workflowRuntimeTelemetryBudgetChainIdsFromWorkflow,
    workflowRuntimeTelemetrySummaryFromProjection,
  } = await importAgentIde();
  const cli = cliBinary();
  const cwd = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-run-inspector-telemetry-chain-workspace-"),
  );
  const stateDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "ioi-run-inspector-telemetry-chain-state-"),
  );
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const workflowGraphId = "workflow.react-flow.run-inspector-telemetry-chain";
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove a run-inspector-created telemetry budget chain executes.",
        options: {
          local: { cwd },
          model: { id: "auto", routeId: "route.native-local" },
        },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        prompt: "Produce telemetry for a run-inspector-created budget chain.",
        mode: "send",
      }),
    });

    const seedUsageParams = new URLSearchParams({
      source: "react_flow",
      actor: "workflow-author",
      event_kind: "RuntimeUsageTelemetry.Read",
      component_kind: "usage_telemetry",
      payload_schema_version: "ioi.runtime.usage-telemetry.v1",
      workflow_graph_id: workflowGraphId,
      workflow_node_id: "run-inspector-selected-telemetry",
      usage_meter_scope: "thread",
      simulation_mode: "true",
    });
    const seedUsage = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/usage?${seedUsageParams}`,
    );
    const seedProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      current_turn_id: turn.turn_id,
      last_event_id: seedUsage.event_id,
      usage_status: seedUsage,
    });
    const selectedTelemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: seedProjection,
    });
    assert.ok(selectedTelemetrySummary.sourceKinds.includes("tui_usage_rows"));
    assert.equal(selectedTelemetrySummary.threadIds[0], thread.thread_id);

    const workflow = {
      version: "workflow.v1",
      metadata: {
        id: workflowGraphId,
        name: "Run-inspector telemetry budget chain",
        slug: "run-inspector-telemetry-budget-chain",
        workflowKind: "agent_workflow",
        executionMode: "local",
        gitLocation:
          ".agents/workflows/run-inspector-telemetry-budget-chain.workflow.json",
        readOnly: false,
        dirty: false,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      },
      nodes: [],
      edges: [],
      global_config: {},
    };
    const materialized = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
      workflow,
      selectedTelemetrySummary,
      {
        idPrefix: "run-inspector-exec-chain",
        origin: { x: 120, y: 180 },
        maxTotalTokens: 1,
        contextWarningRatio: 0.000001,
        contextBlockRatio: 0.000001,
        executeCompaction: true,
      },
    );
    assert.equal(materialized.status, "bound");
    assert.equal(materialized.mode, "materialized");
    assert.equal(materialized.insertedNodeIds.length, 4);
    assert.equal(materialized.insertedEdgeIds.length, 3);
    assert.deepEqual(materialized.boundNodeIds, materialized.insertedNodeIds);

    const hydrated = materializeWorkflowRuntimeTelemetryBudgetChainFromTelemetry(
      materialized.workflow,
      selectedTelemetrySummary,
    );
    assert.equal(hydrated.status, "bound");
    assert.equal(hydrated.mode, "hydrated");
    assert.deepEqual(hydrated.insertedNodeIds, []);
    assert.deepEqual(hydrated.insertedEdgeIds, []);
    assert.deepEqual(hydrated.chainNodeIds, materialized.chainNodeIds);
    assert.equal(hydrated.workflow.nodes.length, materialized.workflow.nodes.length);
    assert.equal(hydrated.workflow.edges.length, materialized.workflow.edges.length);
    assert.equal(
      hydrated.workflow.nodes.filter((node) => node.type === "runtime_usage_meter").length,
      1,
    );

    const chainIds = workflowRuntimeTelemetryBudgetChainIdsFromWorkflow(
      hydrated.workflow,
    );
    assert.deepEqual(chainIds, {
      usageMeterNodeId: "run-inspector-exec-chain-usage-meter",
      contextBudgetNodeId: "run-inspector-exec-chain-context-budget",
      compactionPolicyNodeId: "run-inspector-exec-chain-compaction-policy",
      budgetGateNodeId: "run-inspector-exec-chain-coding-budget-gate",
    });
    const nodeById = (id) => hydrated.workflow.nodes.find((node) => node.id === id);
    const usageNode = nodeById(chainIds.usageMeterNodeId);
    const contextNode = nodeById(chainIds.contextBudgetNodeId);
    const compactionNode = nodeById(chainIds.compactionPolicyNodeId);
    const codingNode = nodeById(chainIds.budgetGateNodeId);
    assert.ok(usageNode);
    assert.ok(contextNode);
    assert.ok(compactionNode);
    assert.ok(codingNode);

    const usageRequest = createRuntimeUsageMeterControlRequestFromWorkflowNode(
      usageNode,
      {},
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(usageRequest.metadata.workflowNodeId, chainIds.usageMeterNodeId);
    const usageResult = await fetchJson(`${daemon.endpoint}${usageRequest.endpoint}`);
    assert.equal(usageResult.workflow_graph_id, workflowGraphId);
    assert.equal(usageResult.workflow_node_id, chainIds.usageMeterNodeId);
    assert.ok(usageResult.total_tokens >= turn.usage.total_tokens);

    const budgetRequest = createRuntimeContextBudgetControlRequestFromWorkflowNode(
      contextNode,
      { runtimeUsageMeter: usageResult },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(budgetRequest.body.workflowNodeId, chainIds.contextBudgetNodeId);
    assert.equal(
      budgetRequest.body.usageTelemetry.workflow_node_id,
      chainIds.usageMeterNodeId,
    );
    const budgetResult = await fetchJson(`${daemon.endpoint}${budgetRequest.endpoint}`, {
      method: budgetRequest.method,
      body: JSON.stringify(budgetRequest.body),
    });
    assert.equal(budgetResult.status, "blocked");
    assert.equal(budgetResult.workflow_graph_id, workflowGraphId);
    assert.equal(budgetResult.workflow_node_id, chainIds.contextBudgetNodeId);

    const policyRequest = createRuntimeCompactionPolicyControlRequestFromWorkflowNode(
      compactionNode,
      { runtimeContextBudget: budgetResult },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(policyRequest.body.workflowNodeId, chainIds.compactionPolicyNodeId);
    assert.equal(policyRequest.body.contextBudgetStatus, "blocked");
    assert.equal(
      policyRequest.body.policy.compactWorkflowNodeId,
      `${chainIds.compactionPolicyNodeId}.compact`,
    );
    const policyResult = await fetchJson(`${daemon.endpoint}${policyRequest.endpoint}`, {
      method: policyRequest.method,
      body: JSON.stringify(policyRequest.body),
    });
    assert.equal(policyResult.status, "compacted");
    assert.equal(policyResult.action, "compact");
    assert.equal(policyResult.workflow_graph_id, workflowGraphId);
    assert.equal(policyResult.workflow_node_id, chainIds.compactionPolicyNodeId);
    assert.equal(
      policyResult.compact_workflow_node_id,
      `${chainIds.compactionPolicyNodeId}.compact`,
    );
    assert.equal(policyResult.compaction_executed, true);

    const runInspectorRows = [
      {
        id: "run-inspector-created-context-budget-row",
        row_kind: "context_budget",
        status: budgetResult.status,
        context_budget_status: budgetResult.status,
        context_budget_mode: budgetResult.mode,
        context_budget_decision_id: budgetResult.policy_decision_id,
        usage_total_tokens: String(budgetResult.usage_summary.total_tokens),
        usage_cost_estimate_usd: String(budgetResult.usage_summary.estimated_cost_usd),
        usage_context_pressure: String(budgetResult.usage_summary.context_pressure),
        usage_context_pressure_status:
          budgetResult.usage_summary.context_pressure_status,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: chainIds.contextBudgetNodeId,
        event_id: budgetResult.event_id,
        receipt_refs: budgetResult.receipt_refs,
        policy_decision_refs: budgetResult.policy_decision_refs,
        context_budget: budgetResult,
      },
      {
        id: "run-inspector-created-compaction-policy-row",
        row_kind: "compaction_policy",
        status: policyResult.status,
        turn_id: turn.turn_id,
        context_budget_status: policyResult.budget_status,
        compaction_policy_status: policyResult.status,
        compaction_policy_action: policyResult.action,
        compaction_policy_decision_id: policyResult.policy_decision_id,
        compaction_executed: String(policyResult.compaction_executed),
        workflow_graph_id: workflowGraphId,
        workflow_node_id: chainIds.compactionPolicyNodeId,
        event_id: policyResult.event_id,
        receipt_refs: policyResult.receipt_refs,
        policy_decision_refs: policyResult.policy_decision_refs,
        context_budget: budgetResult,
      },
    ];
    const preCodingProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      schema_version: "ioi.agent-cli.tui-control-state.v1",
      thread_id: thread.thread_id,
      workflow_graph_id: workflowGraphId,
      current_turn_id: turn.turn_id,
      last_event_id: policyResult.event_id,
      usage_status: usageResult,
      context_rows: runInspectorRows,
    });
    for (const [rowKind, nodeId] of [
      ["usage_status", chainIds.usageMeterNodeId],
      ["context_budget", chainIds.contextBudgetNodeId],
      ["compaction_policy", chainIds.compactionPolicyNodeId],
    ]) {
      assert.ok(
        preCodingProjection.rows.some(
          (row) => row.rowKind === rowKind && row.reactFlowNodeId === nodeId,
        ),
      );
    }
    const liveTelemetrySummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: preCodingProjection,
    });
    assert.ok(liveTelemetrySummary.eventIds.includes(policyResult.event_id));
    assert.ok(
      liveTelemetrySummary.workflowNodeIds.includes(chainIds.compactionPolicyNodeId),
    );

    const codingRequest = createRuntimeCodingToolControlRequestFromWorkflowNode(
      codingNode,
      {
        ...codingNode.config.logic.testInput,
        runtimeTelemetrySummary: liveTelemetrySummary,
      },
      { workflowGraphId, actor: "workflow-author" },
    );
    assert.equal(codingRequest.body.workflowNodeId, chainIds.budgetGateNodeId);
    assert.ok(
      codingRequest.body.budgetUsageTelemetry.source_refs.includes(
        policyResult.event_id,
      ),
    );
    const blockedTool = await fetchJsonStatus(`${daemon.endpoint}${codingRequest.endpoint}`, {
      method: codingRequest.method,
      body: JSON.stringify({
        ...codingRequest.body,
        tool_call_id: "run_inspector_created_telemetry_chain_budget_blocked",
        toolCallId: "run_inspector_created_telemetry_chain_budget_blocked",
      }),
    });
    assert.equal(blockedTool.status, 403);
    assert.equal(blockedTool.body.error.details.reason, "coding_tool_budget_exceeded");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const contextBudgetEvent = daemonEvents.find(
      (event) =>
        event.component_kind === "context_budget" &&
        event.workflow_node_id === chainIds.contextBudgetNodeId,
    );
    const policyEvent = daemonEvents.find(
      (event) => event.event_id === policyResult.event_id,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.event_id === policyResult.compaction_event_id,
    );
    const codingBudgetEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "policy.blocked" &&
        event.component_kind === "coding_tool" &&
        event.workflow_node_id === chainIds.budgetGateNodeId,
    );
    for (const [label, event] of [
      ["context budget", contextBudgetEvent],
      ["compaction policy", policyEvent],
      ["context compact", compactEvent],
      ["coding budget", codingBudgetEvent],
    ]) {
      assert.ok(event, `${label} event missing`);
      assert.equal(event.workflow_graph_id, workflowGraphId);
    }
    assert.equal(policyEvent.workflow_node_id, chainIds.compactionPolicyNodeId);
    assert.equal(
      compactEvent.workflow_node_id,
      `${chainIds.compactionPolicyNodeId}.compact`,
    );
    assert.equal(codingBudgetEvent.status, "blocked");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, {
      substrateClient: sdkClient,
    });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const runtimeProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const projectedNode = (eventId) =>
      runtimeProjection.nodes.find((node) => node.eventIds.includes(eventId));
    assert.equal(
      projectedNode(contextBudgetEvent.event_id)?.nodeKind,
      "runtime_context_budget",
    );
    assert.equal(
      projectedNode(contextBudgetEvent.event_id)?.workflowNodeId,
      chainIds.contextBudgetNodeId,
    );
    assert.equal(
      projectedNode(policyEvent.event_id)?.nodeKind,
      "runtime_compaction_policy",
    );
    assert.equal(
      projectedNode(policyEvent.event_id)?.workflowNodeId,
      chainIds.compactionPolicyNodeId,
    );
    assert.equal(projectedNode(compactEvent.event_id)?.nodeKind, "runtime_context_compact");
    assert.equal(
      projectedNode(codingBudgetEvent.event_id)?.workflowNodeId,
      chainIds.budgetGateNodeId,
    );

    const finalTui = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const finalControlState = JSON.parse(finalTui.stdout).tui_control_state;
    assert.ok(
      finalControlState.coding_tool_rows.some(
        (row) =>
          row.row_kind === "coding_tool_budget" &&
          row.workflow_node_id === chainIds.budgetGateNodeId &&
          row.event_id === codingBudgetEvent.event_id,
      ),
    );
    const finalProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      ...finalControlState,
      workflow_graph_id: workflowGraphId,
      usage_status: usageResult,
      context_rows: [
        ...runInspectorRows,
        ...(Array.isArray(finalControlState.context_rows)
          ? finalControlState.context_rows
          : []),
      ],
    });
    for (const [rowKind, nodeId] of [
      ["usage_status", chainIds.usageMeterNodeId],
      ["context_budget", chainIds.contextBudgetNodeId],
      ["compaction_policy", chainIds.compactionPolicyNodeId],
      ["coding_tool_budget", chainIds.budgetGateNodeId],
    ]) {
      assert.ok(
        finalProjection.rows.some(
          (row) => row.rowKind === rowKind && row.reactFlowNodeId === nodeId,
        ),
      );
    }
    const finalSummary = workflowRuntimeTelemetrySummaryFromProjection({
      tuiControlStateProjection: finalProjection,
    });
    assert.ok(finalSummary.eventIds.includes(codingBudgetEvent.event_id));
    for (const nodeId of [
      chainIds.usageMeterNodeId,
      chainIds.contextBudgetNodeId,
      chainIds.compactionPolicyNodeId,
      chainIds.budgetGateNodeId,
    ]) {
      assert.ok(finalSummary.workflowNodeIds.includes(nodeId));
    }
  } finally {
    await daemon.close();
  }
});

function terminalLoopNodeWithArguments(node, argumentsOverride) {
  return {
    ...node,
    config: {
      ...node.config,
      logic: {
        ...node.config?.logic,
        toolBinding: {
          ...node.config?.logic?.toolBinding,
          arguments: {
            ...(node.config?.logic?.toolBinding?.arguments ?? {}),
            ...argumentsOverride,
          },
        },
      },
    },
  };
}

function safeId(value) {
  return String(value)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "thread";
}

test("React Flow terminal coding-loop template executes against daemon with TUI row parity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createWorkflowRuntimeTerminalCodingLoopTemplateSubflow,
    projectRuntimeThreadEventsToWorkflowProjection,
    projectRuntimeTuiControlStateToWorkflowProjection,
    runWorkflowComposerTerminalCodingLoopActivation,
    workflowComposerTerminalCodingLoopRunLaunchEligible,
    workflowRunHistoryModel,
    workflowRuntimeTerminalCodingLoopNodesInExecutionOrder,
  } = await importAgentIde();
  const cli = cliBinary();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-terminal-coding-loop-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-terminal-coding-loop-state-"));
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "runtime@example.test"]);
  git(cwd, ["config", "user.name", "Runtime Test"]);
  fs.writeFileSync(path.join(cwd, "README.md"), "# Terminal loop\n\nreplace me\n");
  fs.writeFileSync(
    path.join(cwd, "sample.test.mjs"),
    "import test from 'node:test';\nimport assert from 'node:assert/strict';\n\nconst marker = `TERMINAL_LOOP_ARTIFACT_START ${'x'.repeat(4096)} TERMINAL_LOOP_ARTIFACT_END`;\n\ntest('terminal coding loop proof', () => {\n  console.log(marker);\n  assert.equal(21 * 2, 42);\n});\n",
  );
  fs.writeFileSync(path.join(cwd, "loop-diagnostics.mjs"), "export const diagnostics = 1;\n");
  git(cwd, ["add", "README.md", "sample.test.mjs", "loop-diagnostics.mjs"]);
  git(cwd, ["commit", "-m", "seed terminal coding loop workspace"]);
  fs.appendFileSync(path.join(cwd, "README.md"), "\nPending diff line.\n");

  const workflowGraphId = "workflow.react-flow.terminal-coding-loop-live";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        source: "react_flow",
        goal: "Prove a React Flow terminal coding loop executes through daemon coding tools.",
        options: {
          local: { cwd },
          model: { id: "auto", routeId: "route.native-local" },
        },
      }),
    });
    const subflow = createWorkflowRuntimeTerminalCodingLoopTemplateSubflow({
      idPrefix: "terminal-loop-live",
      workflowGraphId,
      origin: { x: 120, y: 180 },
    });
    const nodes = workflowRuntimeTerminalCodingLoopNodesInExecutionOrder(
      subflow.nodes.map((node) => {
        const stepId = node.config?.logic.runtimeTerminalCodingLoopStepId;
        if (stepId === "test_run") {
          return terminalLoopNodeWithArguments(node, {
            commandId: "node.test",
            path: "sample.test.mjs",
            maxOutputBytes: 128,
          });
        }
        if (stepId === "lsp_diagnostics") {
          return terminalLoopNodeWithArguments(node, {
            commandId: "node.check",
            path: "loop-diagnostics.mjs",
            maxOutputBytes: 4096,
          });
        }
        if (stepId === "artifact_read") {
          return terminalLoopNodeWithArguments(node, {
            artifactId: "{artifactId}",
            lengthBytes: 8192,
          });
        }
        if (stepId === "tool_retrieve_result") {
          return terminalLoopNodeWithArguments(node, {
            toolCallId: "{toolCallId}",
            channel: "output",
            lengthBytes: 8192,
          });
        }
        return node;
      }),
    );
    assert.deepEqual(nodes.map((node) => node.id), subflow.nodeIds);

    const workflowPath = path.join(
      cwd,
      ".agents/workflows/terminal-coding-loop-live.workflow.json",
    );
    const savedWorkflow = {
      version: "workflow.v1",
      metadata: {
        id: workflowGraphId,
        name: "Terminal coding loop live",
        slug: "terminal-coding-loop-live",
        workflowKind: "agent_workflow",
        executionMode: "local",
        gitLocation: ".agents/workflows/terminal-coding-loop-live.workflow.json",
        readOnly: false,
        dirty: false,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      },
      nodes,
      edges: subflow.edges,
      global_config: {},
    };
    fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
    fs.writeFileSync(workflowPath, `${JSON.stringify(savedWorkflow, null, 2)}\n`);
    const loadedWorkflow = JSON.parse(fs.readFileSync(workflowPath, "utf8"));
    assert.equal(workflowComposerTerminalCodingLoopRunLaunchEligible(loadedWorkflow), true);
    const stepIdByNodeId = new Map(
      Object.entries(subflow.stepNodeIds).map(([stepId, nodeId]) => [
        nodeId,
        stepId,
      ]),
    );
    let testArtifactId = null;
    let testToolCallId = null;
    const composerThreadToolCallPrefix = `terminal_loop_${safeId(thread.thread_id)}_`;
    const launch = await runWorkflowComposerTerminalCodingLoopActivation({
      workflow: loadedWorkflow,
      workflowPath,
      threadId: thread.thread_id,
      actor: "workflow-author",
      executeRuntimeControlRequest: async (request) => {
        if (request.nodeType === "runtime_approval_decision") {
          assert.equal(request.threadId, thread.thread_id);
          assert.match(request.endpoint, /\/approvals\/.+\/decision$/);
          assert.equal(request.body.source, "react_flow");
          assert.equal(request.body.workflowGraphId, workflowGraphId);
          assert.equal(request.body.workflowNodeId, subflow.stepNodeIds.file_apply_patch);
          assert.equal(request.body.decision, "approve");
          const decision = await fetchJson(`${daemon.endpoint}${request.endpoint}`, {
            method: request.method,
            body: JSON.stringify(request.body),
          });
          assert.equal(decision.decision, "approve");
          return decision;
        }
        const body = request.body;
        const stepId = stepIdByNodeId.get(body.workflowNodeId);
        assert.ok(stepId, `missing step for ${body.workflowNodeId}`);
        assert.equal(request.threadId, thread.thread_id);
        assert.equal(body.workflowGraphId, workflowGraphId);
        assert.equal(body.workflowNodeId, request.nodeId);
        if (stepId === "artifact_read") {
          assert.notEqual(body.arguments.artifactId, "{artifactId}");
          assert.equal(body.arguments.artifactId, testArtifactId);
        }
        if (stepId === "tool_retrieve_result") {
          assert.notEqual(body.arguments.toolCallId, "{toolCallId}");
          assert.equal(body.arguments.toolCallId, testToolCallId);
        }
        const result = await fetchJson(`${daemon.endpoint}${request.endpoint}`, {
          method: request.method,
          body: JSON.stringify(body),
        });
        assert.equal(
          result.status,
          stepId === "file_apply_patch" && !body.approvalId
            ? "blocked"
            : "completed",
          `${stepId} failed: ${JSON.stringify(result.error ?? result.result ?? result).slice(0, 600)}`,
        );
        if (stepId === "file_apply_patch" && !body.approvalId) {
          assert.equal(result.approval_required, true);
          assert.equal(result.approval_manifest?.workflow_policy?.requiresApproval, true);
          assert.equal(result.approval_manifest?.workflow_trust_profile, "local_private");
          assert.equal(result.approval_manifest?.node_approval_override, "require_approval");
        }
        if (result.status === "completed") {
          assert.equal(result.workflow_graph_id, workflowGraphId);
          assert.equal(result.workflow_node_id, body.workflowNodeId);
          assert.equal(result.tool_call_id, `${composerThreadToolCallPrefix}${stepId}`);
        }
        if (stepId === "file_apply_patch" && body.approvalId) {
          assert.equal(result.event.payload_summary.approval_satisfied, true);
        }
        if (stepId === "test_run") {
          testToolCallId = result.tool_call_id;
          testArtifactId = result.result.artifacts.find(
            (artifact) => artifact.channel === "output",
          )?.artifactId;
        }
        return result;
      },
    });

    const context = launch.context;
    const results = new Map(Object.entries(launch.resultsByStepId));
    const runResult = launch.runResult;
    assert.equal(runResult.summary.status, "passed");
    assert.equal(runResult.summary.threadId, thread.thread_id);
    assert.match(runResult.summary.id, /^workflow-terminal-coding-loop-composer-/);
    assert.deepEqual(runResult.finalState.completedNodeIds, subflow.nodeIds);
    assert.equal(runResult.nodeRuns.length, 9);
    assert.equal(runResult.runtimeThreadEvents?.length, 9);
    assert.deepEqual(launch.plan.nodeIds, subflow.nodeIds);
    assert.equal(launch.requests.length, 9);

    assert.match(results.get("git_diff").result.diff, /Pending diff line/);
    assert.match(results.get("file_inspect").result.preview, /Terminal loop/);
    assert.equal(results.get("file_apply_patch_dry_run").result.applied, false);
    assert.equal(results.get("file_apply_patch_dry_run").result.dryRun, true);
    assert.equal(results.get("file_apply_patch").result.applied, true);
    assert.match(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /applied replacement/);
    assert.doesNotMatch(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /preview replacement/);
    assert.equal(results.get("file_apply_patch").workspace_snapshot?.schemaVersion, "ioi.runtime.workspace-snapshot.v1");
    assert.deepEqual(results.get("file_apply_patch").rollback_refs, [
      results.get("file_apply_patch").workspace_snapshot?.snapshotId,
    ]);
    assert.equal(results.get("test_run").result.testStatus, "passed");
    assert.equal(results.get("test_run").result.truncated, true);
    assert.ok(results.get("test_run").artifact_refs.length >= 1);
    assert.equal(results.get("lsp_diagnostics").result.diagnosticStatus, "clean");
    assert.match(results.get("artifact_read").result.content, /TERMINAL_LOOP_ARTIFACT_END/);
    assert.equal(
      results.get("artifact_read").result.artifactId,
      results.get("test_run").result.artifacts.find((artifact) => artifact.channel === "output")?.artifactId,
    );
    assert.equal(
      results.get("tool_retrieve_result").result.toolCallId,
      results.get("test_run").tool_call_id,
    );
    assert.match(results.get("tool_retrieve_result").result.content, /TERMINAL_LOOP_ARTIFACT_END/);
    assert.equal(context.resultToolCallId, results.get("test_run").tool_call_id);
    assert.equal(context.artifactId, results.get("artifact_read").result.artifactId);
    assert.ok(context.receiptRefs.length >= 9);
    assert.ok(context.rollbackRefs.includes(results.get("file_apply_patch").workspace_snapshot?.snapshotId));

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const loopEvents = daemonEvents.filter(
      (event) =>
        event.component_kind === "coding_tool" &&
        event.workflow_graph_id === workflowGraphId &&
        subflow.nodeIds.includes(event.workflow_node_id),
    );
    assert.equal(loopEvents.length, 9);
    assert.deepEqual(
      loopEvents.map((event) => event.workflow_node_id),
      subflow.nodeIds,
    );
    assert.ok(loopEvents.every((event) => event.event_kind === "tool.completed"));
    assert.ok(loopEvents.every((event) => event.source === "react_flow"));
    assert.ok(loopEvents.every((event) => event.receipt_refs.length >= 1));
    const applyEvent = loopEvents.find(
      (event) => event.workflow_node_id === subflow.stepNodeIds.file_apply_patch,
    );
    assert.ok(applyEvent.rollback_refs.includes(results.get("file_apply_patch").workspace_snapshot?.snapshotId));
    const approvalEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "approval.required" &&
        event.workflow_node_id === subflow.stepNodeIds.file_apply_patch,
    );
    assert.ok(approvalEvent);
    assert.equal(approvalEvent.workflow_graph_id, workflowGraphId);
    const approvalDecisionEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "approval.approved" &&
        event.workflow_node_id === subflow.stepNodeIds.file_apply_patch,
    );
    assert.ok(approvalDecisionEvent);
    const snapshotEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "workspace.snapshot.created" &&
        event.payload_summary?.snapshot_id ===
          results.get("file_apply_patch").workspace_snapshot?.snapshotId,
    );
    assert.ok(snapshotEvent);
    assert.equal(snapshotEvent.component_kind, "workspace_snapshot");
    assert.deepEqual(snapshotEvent.rollback_refs, [
      results.get("file_apply_patch").workspace_snapshot?.snapshotId,
    ]);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, {
      substrateClient: sdkClient,
    });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const projection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    for (const event of loopEvents) {
      const projected = projection.nodes.find((node) =>
        node.eventIds.includes(event.event_id),
      );
      assert.ok(projected, `missing projected node for ${event.workflow_node_id}`);
      assert.equal(projected.nodeKind, "plugin_tool");
      assert.equal(projected.componentKind, "coding_tool");
      assert.equal(projected.workflowNodeId, event.workflow_node_id);
      for (const receiptRef of event.receipt_refs) {
        assert.ok(projected.receiptRefs.includes(receiptRef));
      }
    }
    const projectedRetrieve = projection.nodes.find((node) =>
      node.eventIds.includes(results.get("tool_retrieve_result").event.event_id),
    );
    assert.equal(projectedRetrieve?.label, "Coding tool: tool.retrieve_result");

    const finalTui = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const finalControlState = JSON.parse(finalTui.stdout).tui_control_state;
    const terminalRows = finalControlState.coding_tool_rows.filter(
      (row) =>
        row.row_kind === "coding_tool" &&
        row.workflow_graph_id === workflowGraphId &&
        subflow.nodeIds.includes(row.workflow_node_id),
    );
    assert.equal(terminalRows.length, 9);
    assert.deepEqual(
      terminalRows.map((row) => row.workflow_node_id),
      subflow.nodeIds,
    );
    assert.deepEqual(
      terminalRows.map((row) => row.command),
      ["status", "diff", "inspect", "patch-dry-run", "patch", "test", "diagnostics", "artifact", "retrieve"],
    );
    assert.ok(terminalRows.every((row) => row.receipt_refs.length >= 1));
    assert.ok(terminalRows.every((row) => row.shell_fallback_used === false));
    assert.equal(
      terminalRows.find((row) => row.workflow_node_id === subflow.stepNodeIds.file_apply_patch_dry_run)?.dry_run,
      true,
    );
    assert.equal(
      terminalRows.find((row) => row.workflow_node_id === subflow.stepNodeIds.file_apply_patch)?.rollback_refs[0],
      results.get("file_apply_patch").workspace_snapshot?.snapshotId,
    );
    const tuiProjection = projectRuntimeTuiControlStateToWorkflowProjection({
      ...finalControlState,
      workflow_graph_id: workflowGraphId,
    });
    for (const nodeId of subflow.nodeIds) {
      assert.ok(
        tuiProjection.rows.some(
          (row) =>
            row.rowKind === "coding_tool" &&
            row.reactFlowNodeId === nodeId &&
            row.workflowGraphId === workflowGraphId,
        ),
        `missing TUI projected row for ${nodeId}`,
      );
    }
    const runHistory = workflowRunHistoryModel({
      workflow: loadedWorkflow,
      runs: [runResult.summary],
      lastRunResult: {
        ...runResult,
        tuiControlState: {
          ...finalControlState,
          workflow_graph_id: workflowGraphId,
        },
      },
      compareRunResult: null,
      selectedRunId: runResult.summary.id,
      compareRunId: null,
      runEvents: [],
      searchQuery: "",
      statusFilter: "all",
      sourceFilter: "all",
    });
    assert.equal(runHistory.selectedRun?.summary.id, runResult.summary.id);
    assert.ok(
      runHistory.runtimeEventProjection.nodes.some(
        (node) => node.workflowNodeId === subflow.stepNodeIds.tool_retrieve_result,
      ),
    );
    assert.equal(
      runHistory.visibleTuiControlStateRows.filter(
        (row) =>
          row.rowKind === "coding_tool" &&
          row.workflowGraphId === workflowGraphId &&
          subflow.nodeIds.includes(row.reactFlowNodeId),
      ).length,
      9,
    );
  } finally {
    if (daemon) await daemon.close();
  }
});

test("agent CLI exposes model, thinking, and stream control contracts", () => {
  const source = [
    "crates/cli/src/commands/agent.rs",
    "crates/cli/src/commands/agent_event_stream.rs",
    "crates/cli/src/commands/agent_tui.rs",
    "crates/cli/src/commands/agent_tui_loop.rs",
    "packages/runtime-daemon/src/index.mjs",
    "packages/runtime-daemon/src/mcp-manager.mjs",
  ].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  assert.match(source, /AgentCommands::Model/);
  assert.match(source, /AgentCommands::Thinking/);
  assert.match(source, /AgentCommands::Memory/);
  assert.match(source, /AgentCommands::Doctor/);
  assert.match(source, /AgentCommands::Stream/);
  assert.match(source, /AgentCommands::Tui/);
  assert.match(source, /AgentCommands::Interrupt/);
  assert.match(source, /AgentCommands::Steer/);
  assert.match(source, /AgentCommands::Compact/);
  assert.match(source, /AgentCommands::Fork/);
  assert.match(source, /AgentEventStreamArgs/);
  assert.match(source, /\/model/);
  assert.match(source, /\/thinking/);
  assert.match(source, /\/mcp/);
  assert.match(source, /# remember/);
  assert.match(source, /\/memory show/);
  assert.match(source, /\/memory remember/);
  assert.match(source, /\/memory edit/);
  assert.match(source, /\/memory delete/);
  assert.match(source, /\/memory disable/);
  assert.match(source, /\/memory path/);
  assert.match(source, /\/subagent spawn/);
  assert.match(source, /\/subagent wait/);
  assert.match(source, /\/subagent input/);
  assert.match(source, /\/subagent cancel/);
  assert.match(source, /\/subagent resume/);
  assert.match(source, /\/subagent assign/);
  assert.match(source, /propagate \[reason\]/);
  assert.match(source, /memory_policy/);
  assert.match(source, /ModelRouteDecision/);
  assert.match(source, /memory_update/);
  assert.match(source, /usage_delta/);
  assert.match(source, /context_pressure_delta/);
  assert.match(source, /\/v1\/doctor/);
  assert.match(source, /\/v1\/skills/);
  assert.match(source, /\/v1\/hooks/);
  assert.match(source, /\/v1\/threads\/\{id\}\/events/);
  assert.match(source, /\/v1\/threads\/\{id\}\/events\/stream/);
  assert.match(source, /\/v1\/runs\/\{id\}\/events/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mode/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/model/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/thinking/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/usage/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/context-budget/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/compaction-policy/);
  assert.match(source, /\/v1\/mcp\/servers/);
  assert.match(source, /\/v1\/mcp\/tools/);
  assert.match(source, /\/v1\/mcp\/tools\/search/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/tools\/search/);
  assert.match(source, /TUI_THREAD_MCP_TOOL_FETCH_ROUTE_TEMPLATE/);
  assert.match(source, /search_tui_mcp_tools/);
  assert.match(source, /fetch_tui_mcp_tool/);
  assert.match(source, /mcp_config_source_mode/);
  assert.match(source, /\/mcp search/);
  assert.match(source, /\/mcp fetch/);
  assert.match(source, /global\.ioi\/mcp\.json/);
  assert.match(source, /sourceScope/);
  assert.match(source, /configCompatibility/);
  assert.match(source, /\/v1\/mcp\/resources/);
  assert.match(source, /\/v1\/mcp\/prompts/);
  assert.match(source, /\/v1\/mcp\/validate/);
  assert.match(source, /\/v1\/mcp\/import/);
  assert.match(source, /\/v1\/mcp\/serve/);
  assert.match(source, /\/v1\/mcp\/servers/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/status/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/import/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/validate/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/servers\/\{server_id\}\/enable/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/servers\/\{server_id\}\/disable/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/tools\/\{tool_id\}\/invoke/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/mcp\/serve/);
  assert.match(source, /\/v1\/memory/);
  assert.match(source, /\/v1\/memory\/validate/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/memory\/status/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/memory\/validate/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/memory\/policy/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/memory\/\{memory_id\}/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/\{subagent_id\}\/wait/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/\{subagent_id\}\/input/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/\{subagent_id\}\/cancel/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/\{subagent_id\}\/resume/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/\{subagent_id\}\/assign/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/subagents\/cancel/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns\/\{turn_id\}\/interrupt/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns\/\{turn_id\}\/steer/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/approvals\/\{approval_id\}\/decision/);
  assert.match(source, /\/v1\/tools\?pack=coding/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/tools\/\{tool_id\}\/invoke/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/diagnostics\/repair-decisions\/\{decision_id\}\/execute/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/compact/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/fork/);
  assert.match(source, /workspace\.status/);
  assert.match(source, /git\.diff/);
  assert.match(source, /file\.inspect/);
  assert.match(source, /execute_tui_diagnostics_repair_decision/);
  assert.match(source, /DiagnosticsRepair/);
  assert.match(source, /\/diagnostics repair/);
  assert.match(source, /line_mode_command=diagnostics action=repair/);
  assert.match(source, /OperatorControl\.Mcp/);
  assert.match(source, /OperatorControl\.McpValidate/);
  assert.match(source, /OperatorControl\.McpImport/);
  assert.match(source, /OperatorControl\.McpAdd/);
  assert.match(source, /OperatorControl\.McpRemove/);
  assert.match(source, /OperatorControl\.McpEnable/);
  assert.match(source, /OperatorControl\.McpDisable/);
  assert.match(source, /OperatorControl\.McpInvoke/);
  assert.match(source, /discoverMcpStdioCatalog/);
  assert.match(source, /invokeMcpStdioTool/);
  assert.match(source, /discoverMcpHttpCatalog/);
  assert.match(source, /invokeMcpHttpTool/);
  assert.match(source, /mcp_remote_header_vault_unbound/);
  assert.match(source, /mcp_remote_header_requires_vault_ref/);
  assert.match(source, /VaultPort\.resolveVaultRef/);
  assert.match(source, /handleMcpServeJsonRpc/);
  assert.match(source, /mcp_serve/);
  assert.match(source, /live_stdio/);
  assert.match(source, /live_http/);
  assert.match(source, /live_sse/);
  assert.match(source, /mcp\.transport\.http\.live/);
  assert.match(source, /mcp\.transport\.sse\.live/);
  assert.match(source, /resources\/list/);
  assert.match(source, /prompts\/list/);
  assert.match(source, /OperatorControl\.Memory/);
  assert.match(source, /OperatorControl\.MemoryValidate/);
  assert.match(source, /OperatorControl\.MemoryWrite/);
  assert.match(source, /OperatorControl\.MemoryEdit/);
  assert.match(source, /OperatorControl\.MemoryDelete/);
  assert.match(source, /OperatorControl\.MemoryPolicy/);
  assert.match(source, /OperatorControl\.SubagentSpawn/);
  assert.match(source, /OperatorControl\.SubagentWait/);
  assert.match(source, /OperatorControl\.SubagentSendInput/);
  assert.match(source, /OperatorControl\.SubagentCancel/);
  assert.match(source, /OperatorControl\.SubagentResume/);
  assert.match(source, /OperatorControl\.SubagentAssign/);
  assert.match(source, /OperatorControl\.Interrupt/);
  assert.match(source, /OperatorControl\.Steer/);
  assert.match(source, /OperatorApproval\.Approve/);
  assert.match(source, /OperatorApproval\.Reject/);
  assert.match(source, /OperatorControl\.Compact/);
  assert.match(source, /OperatorControl\.Fork/);
  assert.match(source, /operator_control/);
  assert.match(source, /approval_gate/);
  assert.match(source, /context_compaction/);
  assert.match(source, /thread_fork/);
  assert.match(source, /since_seq/);
  assert.match(source, /Last-Event-ID/);
  assert.match(source, /parse_runtime_event_sse_blocks/);
  assert.match(source, /format_runtime_event_line/);
  assert.match(source, /TUI_PRIVATE_RUNTIME_LOOP: bool = false/);
  assert.match(source, /ioi\.agent-cli\.tui\.v1/);
  assert.match(source, /ioi\.agent-cli\.tui-control-state\.v1/);
  assert.match(source, /ioi\.workflow\.runtime-tui-deeplink\.v1/);
  assert.match(source, /tui_control_state/);
  assert.match(source, /command_history/);
  assert.match(source, /validation_errors/);
  assert.match(source, /mode_status/);
  assert.match(source, /mcp_rows/);
  assert.match(source, /memory_rows/);
  assert.match(source, /cost_rows/);
  assert.match(source, /context_rows/);
  assert.match(source, /coding_tool_rows/);
  assert.match(source, /tui_coding_tool_rows/);
  assert.match(source, /coding_tool_budget/);
  assert.match(source, /subagent_rows/);
  assert.match(source, /approval_rows/);
  assert.match(source, /approval_decisions/);
  assert.match(source, /tui_event_rows/);
  assert.match(source, /tui_reopen/);
  assert.match(source, /run_tui_interactive_loop/);
  assert.match(source, /parse_tui_line_command/);
  for (const slashCommand of ["/resume", "/events", "/mode", "/model", "/thinking", "/cost", "/context", "/mcp", "/memory", "/subagents", "/subagent", "/approvals", "/approve", "/reject", "/interrupt", "/steer", "/status", "/diff", "/inspect", "/patch", "/patch-dry-run", "/test", "/diagnostics", "/restore", "/quit"]) {
    assert.match(source, new RegExp(slashCommand));
  }
  assert.match(source, /event_kind/);
  assert.match(source, /component_kind/);
  assert.match(source, /workflow_node_id/);
  assert.match(source, /receipt_refs/);
  assert.match(source, /policy_decision_refs/);
  assert.match(source, /ioi\.agent-runtime\.doctor\.v1/);
  assert.match(source, /ioi\.agent-runtime\.skills\.v1/);
  assert.match(source, /ioi\.agent-runtime\.hooks\.v1/);
  assert.match(source, /reactflow_workflow_node/);
});

test("agent TUI thin shell is daemon-backed and avoids a private runtime loop", () => {
  const source = [
    "crates/cli/src/commands/agent_tui.rs",
    "crates/cli/src/commands/agent_tui_loop.rs",
  ].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  assert.match(source, /TUI_PRIVATE_RUNTIME_LOOP: bool = false/);
  assert.match(source, /TUI_THREAD_CREATE_ROUTE/);
  assert.match(source, /TUI_EVENT_STREAM_ROUTE_TEMPLATE/);
  assert.match(source, /fetch_runtime_event_stream/);
  assert.match(source, /daemon_request/);
  assert.match(source, /OperatorControl\.Interrupt/);
  assert.match(source, /OperatorControl\.Steer/);
  assert.match(source, /OperatorControl\.Mode/);
  assert.match(source, /OperatorControl\.Model/);
  assert.match(source, /OperatorControl\.Thinking/);
  assert.match(source, /OperatorControl\.Mcp/);
  assert.match(source, /OperatorControl\.McpEnable/);
  assert.match(source, /OperatorControl\.McpDisable/);
  assert.match(source, /OperatorControl\.McpInvoke/);
  assert.match(source, /OperatorControl\.Memory/);
  assert.match(source, /OperatorControl\.SubagentSpawn/);
  assert.match(source, /OperatorControl\.SubagentCancel/);
  assert.match(source, /TUI_THREAD_MCP_STATUS_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MCP_VALIDATE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MCP_SERVER_ENABLE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MCP_SERVER_DISABLE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MCP_TOOL_INVOKE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MEMORY_STATUS_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_MEMORY_VALIDATE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_SUBAGENT_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_SUBAGENT_CANCEL_PROPAGATE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_SNAPSHOT_LIST_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_RESTORE_PREVIEW_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_RESTORE_APPLY_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_THREAD_DIAGNOSTICS_REPAIR_DECISION_EXECUTE_ROUTE_TEMPLATE/);
  assert.match(source, /TUI_RUN_CODING_TOOL_BUDGET_RECOVERY_ROUTE_TEMPLATE/);
  assert.match(source, /execute_tui_diagnostics_repair_decision/);
  assert.match(source, /execute_tui_run_coding_tool_budget_recovery/);
  assert.match(source, /RunRecovery/);
  assert.match(source, /\/run recovery/);
  assert.match(source, /workflow_node_ids/);
  assert.match(source, /tui_event_rows/);
  assert.match(source, /tui_coding_tool_rows/);
  assert.match(source, /tui_control_state/);
  assert.match(source, /tui_reopen_args/);
  assert.match(source, /line_mode_command=interrupt/);
  assert.match(source, /line_mode_command=events/);
  assert.match(source, /line_mode_command=mcp/);
  assert.match(source, /line_mode_command=memory/);
  assert.match(source, /line_mode_command=subagent/);
  assert.match(source, /line_mode_command=run action=recovery/);
  assert.match(source, /line_mode_command=restore/);
  assert.match(source, /line_mode_command=diagnostics action=repair/);
  assert.match(source, /line_mode_error/);
  assert.doesNotMatch(source, /CliAgentRuntimeClient/);
  assert.doesNotMatch(source, /submit_runtime_call/);
  assert.doesNotMatch(source, /StartAgentParams/);
  assert.doesNotMatch(source, /StepAgentParams/);
});

test("coding tool pack invokes status, diff, inspect, apply patch, diagnostics, test run, and artifact retrieval across daemon, SDK, CLI, TUI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    projectRuntimeThreadEventsToWorkflowProjection,
    projectRuntimeTuiControlStateToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-tools-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-tools-state-"));
  const cli = cliBinary();
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "runtime@example.test"]);
  git(cwd, ["config", "user.name", "Runtime Test"]);
  fs.writeFileSync(path.join(cwd, "README.md"), "# Runtime coding tools\n\nInitial line.\n");
  fs.writeFileSync(path.join(cwd, "package.json"), JSON.stringify({ type: "module", devDependencies: { typescript: "workspace" } }, null, 2));
  fs.writeFileSync(
    path.join(cwd, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          strict: true,
          target: "ES2022",
          module: "ESNext",
          noEmit: true,
        },
        include: ["src/**/*.ts"],
      },
      null,
      2,
    ),
  );
  fs.mkdirSync(path.join(cwd, "src"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "src", "project-target.ts"), "export const typed: number = 1;\n");
  const rootTsc = path.join(root, "node_modules", ".bin", process.platform === "win32" ? "tsc.cmd" : "tsc");
  assert.ok(fs.existsSync(rootTsc), "repo-local TypeScript compiler is required for project-aware diagnostics proof");
  fs.mkdirSync(path.join(cwd, "node_modules", ".bin"), { recursive: true });
  const workspaceTsc = path.join(cwd, "node_modules", ".bin", process.platform === "win32" ? "tsc.cmd" : "tsc");
  fs.symlinkSync(rootTsc, workspaceTsc);
  fs.writeFileSync(
    path.join(cwd, "sample.test.mjs"),
    "import test from 'node:test';\nimport assert from 'node:assert/strict';\n\nconst marker = `RUNTIME_ARTIFACT_SPILLOVER_START ${'x'.repeat(4096)} RUNTIME_ARTIFACT_SPILLOVER_END`;\n\ntest('runtime coding test proof', () => {\n  console.log(marker);\n  assert.equal(2 + 2, 4);\n});\n",
  );
  fs.writeFileSync(path.join(cwd, "diagnostic-target.mjs"), "export const value = 1;\n");
  fs.writeFileSync(path.join(cwd, "restore-target.mjs"), "export const restore = 1;\n");
  fs.writeFileSync(path.join(cwd, "blocking-target.mjs"), "export const blocked = 1;\n");
  fs.writeFileSync(path.join(cwd, "apply-diagnostics.mjs"), "export const applyRepair = 1;\n");
  fs.writeFileSync(path.join(cwd, "skip-diagnostics.mjs"), "export const skip = 1;\n");
  git(cwd, [
    "add",
    "README.md",
    "package.json",
    "tsconfig.json",
    "src/project-target.ts",
    "sample.test.mjs",
    "diagnostic-target.mjs",
    "restore-target.mjs",
    "blocking-target.mjs",
    "apply-diagnostics.mjs",
    "skip-diagnostics.mjs",
  ]);
  git(cwd, ["commit", "-m", "seed workspace"]);
  fs.appendFileSync(path.join(cwd, "README.md"), "\nChanged line for diff proof.\n");

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Prove structured coding tools without shell-only fallback.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const expectedCodingToolIds = [
      "artifact.read",
      "computer_use.request_lease",
      "file.apply_patch",
      "file.inspect",
      "git.diff",
      "lsp.diagnostics",
      "test.run",
      "tool.retrieve_result",
      "workspace.status",
    ];

    const catalog = await fetchJson(`${daemon.endpoint}/v1/tools?pack=coding`);
    assert.deepEqual(
      catalog.map((tool) => tool.stableToolId).sort(),
      expectedCodingToolIds,
    );
    assert.ok(catalog.every((tool) => tool.pack === "coding"));
    assert.ok(catalog.every((tool) => tool.workflowNodeType));
    const patchContract = catalog.find((tool) => tool.stableToolId === "file.apply_patch");
    assert.ok(patchContract);
    assert.equal(patchContract.effectClass, "local_write");
    assert.ok(patchContract.authorityScopeRequirements.includes("scope:workspace.write"));
    assert.ok(patchContract.evidenceRequirements.includes("workspace_snapshot_receipt"));
    const testContract = catalog.find((tool) => tool.stableToolId === "test.run");
    assert.ok(testContract);
    assert.equal(testContract.effectClass, "local_command");
    assert.ok(testContract.authorityScopeRequirements.includes("scope:workspace.test"));
    const diagnosticsContract = catalog.find((tool) => tool.stableToolId === "lsp.diagnostics");
    assert.ok(diagnosticsContract);
    assert.equal(diagnosticsContract.effectClass, "local_read");
    assert.equal(diagnosticsContract.riskDomain, "diagnostics");
    assert.ok(diagnosticsContract.inputSchema.properties.commandId.enum.includes("auto"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.diagnosticsMode"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.defaultDiagnosticCommandId"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.restorePolicy"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.restoreConflictPolicy"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.diagnosticsRepairDefault"));
    assert.ok(patchContract.workflowConfigFields.includes("toolPack.coding.operatorOverrideRequiresApproval"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.diagnosticsMode"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.defaultDiagnosticCommandId"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.restorePolicy"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.restoreConflictPolicy"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.diagnosticsRepairDefault"));
    assert.ok(diagnosticsContract.workflowConfigFields.includes("toolPack.coding.operatorOverrideRequiresApproval"));
    const artifactContract = catalog.find((tool) => tool.stableToolId === "artifact.read");
    assert.ok(artifactContract);
    assert.equal(artifactContract.effectClass, "local_read");
    const retrieveContract = catalog.find((tool) => tool.stableToolId === "tool.retrieve_result");
    assert.ok(retrieveContract);
    assert.equal(retrieveContract.riskDomain, "artifact");

    const statusResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/workspace.status/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.workspace.status",
          input: {},
        }),
      },
    );
    const diffResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/git.diff/invoke`,
      {
        method: "POST",
        body: JSON.stringify({ input: { path: "README.md" } }),
      },
    );
    const inspectResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.inspect/invoke`,
      {
        method: "POST",
        body: JSON.stringify({ input: { path: "README.md" } }),
      },
    );
    const dryRunPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch",
          input: {
            path: "README.md",
            oldText: "Initial line.",
            newText: "Dry-run patched line.",
            dryRun: true,
          },
        }),
      },
    );
    const testResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/test.run/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.test.run",
          input: {
            commandId: "node.test",
            path: "sample.test.mjs",
            maxOutputBytes: 128,
          },
        }),
      },
    );
    const diagnosticPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.diagnostics",
          input: {
            path: "diagnostic-target.mjs",
            oldText: "export const value = 1;",
            newText: "export const value = ;",
          },
        }),
      },
    );
    const diagnosticsResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/lsp.diagnostics/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.lsp.diagnostics",
          input: {
            commandId: "node.check",
            path: "diagnostic-target.mjs",
            maxOutputBytes: 4096,
          },
        }),
      },
    );
    const leaseResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/computer_use.request_lease/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.computer_use.request_lease",
          input: {
            prompt: "TUI lease proof",
          },
        }),
      },
    );
    assert.equal(leaseResult.status, "completed");
    assert.equal(statusResult.status, "completed");
    assert.equal(statusResult.shell_fallback_used, false);
    assert.equal(diffResult.result.paths[0], "README.md");
    assert.match(diffResult.result.diff, /Changed line for diff proof/);
    assert.equal(inspectResult.result.kind, "file");
    assert.match(inspectResult.result.preview, /Runtime coding tools/);
    assert.equal(dryRunPatchResult.status, "completed");
    assert.equal(dryRunPatchResult.result.dryRun, true);
    assert.equal(dryRunPatchResult.result.applied, false);
    assert.equal(dryRunPatchResult.workspace_snapshot, null);
    assert.match(dryRunPatchResult.result.diff, /Dry-run patched line/);
    assert.match(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /Initial line\./);
    assert.equal(diagnosticPatchResult.status, "completed");
    assert.equal(diagnosticPatchResult.result.diagnosticsRecommended, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.path, "diagnostic-target.mjs");
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.beforeExists, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.afterExists, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.beforeSizeBytes > 0, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.afterSizeBytes > 0, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.beforeMtimeMs > 0, true);
    assert.equal(diagnosticPatchResult.result.changedFiles[0]?.afterMtimeMs > 0, true);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.schemaVersion, "ioi.runtime.workspace-snapshot.v1");
    assert.equal(diagnosticPatchResult.workspace_snapshot?.snapshotKind, "pre_post_touched_files");
    assert.equal(diagnosticPatchResult.workspace_snapshot?.fileCount, 1);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.files[0]?.path, "diagnostic-target.mjs");
    assert.equal(
      diagnosticPatchResult.workspace_snapshot?.files[0]?.before?.contentHash,
      diagnosticPatchResult.result.changedFiles[0]?.beforeHash,
    );
    assert.equal(
      diagnosticPatchResult.workspace_snapshot?.files[0]?.after?.contentHash,
      diagnosticPatchResult.result.changedFiles[0]?.afterHash,
    );
    assert.equal(diagnosticPatchResult.workspace_snapshot?.restore?.status, "content_captured");
    assert.equal(diagnosticPatchResult.workspace_snapshot?.restore?.previewSupported, true);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.restore?.applySupported, true);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.files[0]?.before?.contentCaptured, true);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.files[0]?.after?.contentCaptured, true);
    assert.equal(diagnosticPatchResult.workspace_snapshot?.files[0]?.before?.content, undefined);
    assert.ok(diagnosticPatchResult.workspace_snapshot?.receiptRefs[0]?.startsWith("receipt_workspace_snapshot_"));
    assert.ok(diagnosticPatchResult.workspace_snapshot?.artifactRefs[0]?.includes("workspace_snapshot"));
    assert.deepEqual(diagnosticPatchResult.rollback_refs, [diagnosticPatchResult.workspace_snapshot?.snapshotId]);
    assert.ok(diagnosticPatchResult.event.rollback_refs.includes(diagnosticPatchResult.workspace_snapshot?.snapshotId));
    assert.ok(diagnosticPatchResult.event.artifact_refs.includes(diagnosticPatchResult.workspace_snapshot?.artifactRefs[0]));
    const snapshotListResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots`,
    );
    assert.equal(snapshotListResult.snapshot_count >= 1, true);
    assert.ok(
      snapshotListResult.snapshots.some(
        (snapshot) => snapshot.snapshotId === diagnosticPatchResult.workspace_snapshot?.snapshotId,
      ),
    );
    const snapshotArtifactReadResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/artifact.read/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.workspace-snapshot-artifact.read",
          input: {
            artifactId: diagnosticPatchResult.workspace_snapshot?.artifactRefs[0],
            maxBytes: 65536,
          },
        }),
      },
    );
    const snapshotArtifactContent = JSON.parse(snapshotArtifactReadResult.result.content);
    assert.equal(snapshotArtifactContent.object, "ioi.runtime_workspace_snapshot_content");
    assert.equal(snapshotArtifactContent.files[0]?.before?.content, "export const value = 1;\n");
    assert.equal(snapshotArtifactContent.files[0]?.after?.content, "export const value = ;\n");
    const restorePreviewResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots/${diagnosticPatchResult.workspace_snapshot?.snapshotId}/restore-preview`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.restore.preview",
        }),
      },
    );
    assert.equal(restorePreviewResult.schema_version, "ioi.runtime.workspace-restore-preview.v1");
    assert.equal(restorePreviewResult.snapshot_id, diagnosticPatchResult.workspace_snapshot?.snapshotId);
    assert.equal(restorePreviewResult.preview_status, "ready");
    assert.equal(restorePreviewResult.apply_supported, true);
    assert.equal(restorePreviewResult.operations[0]?.path, "diagnostic-target.mjs");
    assert.equal(restorePreviewResult.operations[0]?.operation, "replace");
    assert.equal(restorePreviewResult.operations[0]?.status, "ready");
    assert.equal(restorePreviewResult.operations[0]?.current_hash, diagnosticPatchResult.result.changedFiles[0]?.afterHash);
    assert.equal(restorePreviewResult.operations[0]?.target_hash, diagnosticPatchResult.result.changedFiles[0]?.beforeHash);
    assert.match(restorePreviewResult.operations[0]?.diff, /export const value = 1;/);
    assert.deepEqual(restorePreviewResult.rollback_refs, [diagnosticPatchResult.workspace_snapshot?.snapshotId]);
    assert.equal(restorePreviewResult.event.event_kind, "workspace.restore.previewed");
    assert.equal(restorePreviewResult.event.component_kind, "restore_gate");
    assert.equal(restorePreviewResult.event.workflow_node_id, "workflow.restore.preview");
    const restorePatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.restore-target",
          toolPack: { coding: { diagnosticsMode: "skip" } },
          input: {
            path: "restore-target.mjs",
            oldText: "export const restore = 1;",
            newText: "export const restore = 2;",
          },
        }),
      },
    );
    assert.equal(restorePatchResult.status, "completed");
    assert.equal(restorePatchResult.result.applied, true);
    assert.equal(restorePatchResult.workspace_snapshot?.restore?.applySupported, true);
    assert.match(fs.readFileSync(path.join(cwd, "restore-target.mjs"), "utf8"), /restore = 2/);
    const restoreApplyBlockedResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots/${restorePatchResult.workspace_snapshot?.snapshotId}/restore-apply`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.restore.apply.blocked",
        }),
      },
    );
    assert.equal(restoreApplyBlockedResult.schema_version, "ioi.runtime.workspace-restore-apply.v1");
    assert.equal(restoreApplyBlockedResult.apply_status, "blocked");
    assert.equal(restoreApplyBlockedResult.approval_required, true);
    assert.equal(restoreApplyBlockedResult.approval_satisfied, false);
    assert.equal(restoreApplyBlockedResult.operations[0]?.apply_status, "blocked");
    assert.equal(restoreApplyBlockedResult.operations[0]?.apply_reason, "workspace_restore_apply_requires_approval");
    assert.match(fs.readFileSync(path.join(cwd, "restore-target.mjs"), "utf8"), /restore = 2/);
    const restoreApplyResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/snapshots/${restorePatchResult.workspace_snapshot?.snapshotId}/restore-apply`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.restore.apply",
          approval_granted: true,
        }),
      },
    );
    assert.equal(restoreApplyResult.apply_status, "applied");
    assert.equal(restoreApplyResult.apply_supported, true);
    assert.equal(restoreApplyResult.approval_satisfied, true);
    assert.equal(restoreApplyResult.applied_count, 1);
    assert.equal(restoreApplyResult.operations[0]?.path, "restore-target.mjs");
    assert.equal(restoreApplyResult.operations[0]?.apply_status, "applied");
    assert.deepEqual(restoreApplyResult.rollback_refs, [restorePatchResult.workspace_snapshot?.snapshotId]);
    assert.equal(restoreApplyResult.event.event_kind, "workspace.restore.applied");
    assert.equal(restoreApplyResult.event.component_kind, "restore_gate");
    assert.equal(restoreApplyResult.event.workflow_node_id, "workflow.restore.apply");
    assert.match(fs.readFileSync(path.join(cwd, "restore-target.mjs"), "utf8"), /restore = 1/);
    assert.equal(diagnosticPatchResult.auto_diagnostics?.status, "completed");
    assert.equal(diagnosticPatchResult.auto_diagnostics?.tool_name, "lsp.diagnostics");
    assert.equal(diagnosticPatchResult.auto_diagnostics?.event.source, "runtime_auto");
    assert.equal(diagnosticPatchResult.auto_diagnostics?.workflow_node_id, "runtime.coding-tool.lsp-diagnostics.auto");
    assert.equal(diagnosticPatchResult.auto_diagnostics?.result.diagnosticStatus, "findings");
    assert.equal(diagnosticPatchResult.auto_diagnostics?.result.diagnosticCount, 1);
    assert.deepEqual(diagnosticPatchResult.auto_diagnostics?.rollback_refs, [
      diagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(diagnosticPatchResult.auto_diagnostics?.event.rollback_refs, [
      diagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.equal(
      diagnosticPatchResult.auto_diagnostics?.event.payload_summary.diagnostics_repair_context.workspace_snapshot_id,
      diagnosticPatchResult.workspace_snapshot?.snapshotId,
    );
    const injectedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        message: "Continue after diagnostics.",
        diagnosticsMode: "advisory",
      }),
    });
    assert.equal(injectedTurn.status, "completed");
    const injectedConversation = await fetchJson(`${daemon.endpoint}/v1/runs/${injectedTurn.request_id}/conversation`);
    assert.match(injectedConversation[0]?.content ?? "", /Post-edit diagnostics \(advisory, findings\)/);
    assert.match(injectedConversation[0]?.content ?? "", /diagnostic-target\.mjs/);
    const injectedTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${injectedTurn.request_id}/trace`);
    assert.equal(injectedTrace.diagnosticsFeedback?.diagnosticStatus, "findings");
    assert.equal(injectedTrace.diagnosticsFeedback?.mode, "advisory");
    assert.equal(injectedTrace.diagnosticsFeedback?.diagnosticCount, 1);
    const blockingDiagnosticPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.diagnostics-blocking",
          toolPack: {
            coding: {
              restorePolicy: "preview_only",
              restoreConflictPolicy: "require_approval",
              diagnosticsRepairDefault: "restore_preview",
              operatorOverrideRequiresApproval: false,
            },
          },
          input: {
            path: "blocking-target.mjs",
            oldText: "export const blocked = 1;",
            newText: "export const blocked = ;",
          },
        }),
      },
    );
    assert.equal(blockingDiagnosticPatchResult.status, "completed");
    assert.equal(blockingDiagnosticPatchResult.auto_diagnostics?.result.diagnosticStatus, "findings");
    assert.equal(blockingDiagnosticPatchResult.workspace_snapshot?.restore?.previewSupported, true);
    assert.equal(blockingDiagnosticPatchResult.workspace_snapshot?.restore?.applySupported, true);
    assert.deepEqual(blockingDiagnosticPatchResult.auto_diagnostics?.rollback_refs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.equal(
      blockingDiagnosticPatchResult.auto_diagnostics?.event.payload_summary.diagnostics_repair_context.restore_policy,
      "preview_only",
    );
    assert.equal(
      blockingDiagnosticPatchResult.auto_diagnostics?.event.payload_summary.diagnostics_repair_context.restore_conflict_policy,
      "require_approval",
    );
    assert.equal(
      blockingDiagnosticPatchResult.auto_diagnostics?.event.payload_summary.diagnostics_repair_context.diagnostics_repair_default,
      "restore_preview",
    );
    assert.equal(
      blockingDiagnosticPatchResult.auto_diagnostics?.event.payload_summary.diagnostics_repair_context.operator_override_requires_approval,
      false,
    );
    const blockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        message: "Continue after blocking diagnostics.",
        diagnosticsMode: "blocking",
      }),
    });
    assert.equal(blockedTurn.status, "waiting_for_input");
    assert.equal(blockedTurn.completed_at, null);
    assert.equal(blockedTurn.stop_reason, "blocked_by_post_edit_diagnostics");
    const blockedRun = await fetchJson(`${daemon.endpoint}/v1/runs/${blockedTurn.request_id}`);
    assert.equal(blockedRun.status, "blocked");
    assert.equal(blockedRun.result.includes("Model continuation is paused"), true);
    assert.equal(blockedRun.events.some((event) => event.type === "delta"), false);
    assert.equal(blockedRun.events.some((event) => event.type === "completed"), false);
    assert.equal(blockedRun.events.some((event) => event.type === "policy_blocked"), true);
    const blockedConversation = await fetchJson(`${daemon.endpoint}/v1/runs/${blockedTurn.request_id}/conversation`);
    assert.equal(blockedConversation[1]?.role, "system");
    assert.match(blockedConversation[0]?.content ?? "", /Post-edit diagnostics \(blocking, findings\)/);
    assert.match(blockedConversation[0]?.content ?? "", /blocking-target\.mjs/);
    const blockedTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${blockedTurn.request_id}/trace`);
    assert.equal(blockedTrace.diagnosticsFeedback?.mode, "blocking");
    assert.deepEqual(blockedTrace.diagnosticsFeedback?.rollbackRefs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(blockedTrace.diagnosticsFeedback?.repairPolicy?.workspaceSnapshotRefs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(
      blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.map((decision) => decision.action),
      ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
    );
    assert.equal(blockedTrace.diagnosticsFeedback?.repairPolicy?.restorePolicy, "preview_only");
    assert.equal(blockedTrace.diagnosticsFeedback?.repairPolicy?.restoreConflictPolicy, "require_approval");
    assert.equal(blockedTrace.diagnosticsFeedback?.repairPolicy?.defaultDecision, "restore_preview");
    assert.equal(blockedTrace.diagnosticsFeedback?.repairPolicy?.operatorOverrideRequiresApproval, false);
    assert.equal(
      blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find((decision) => decision.action === "restore_apply")?.status,
      "unavailable",
    );
    assert.equal(
      blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find((decision) => decision.action === "operator_override")?.status,
      "available",
    );
    assert.equal(blockedTrace.diagnosticsBlockingGate?.status, "blocked");
    assert.equal(blockedTrace.diagnosticsBlockingGate?.workflowNodeId, "runtime.lsp-diagnostics.blocking-gate");
    assert.deepEqual(blockedTrace.diagnosticsBlockingGate?.rollbackRefs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(blockedTrace.diagnosticsBlockingGate?.workspaceSnapshotRefs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.ok(blockedTrace.diagnosticsBlockingGate?.policyDecisionRefs?.includes(
      blockedTrace.diagnosticsBlockingGate?.repairPolicy?.policyId,
    ));
    assert.equal(blockedTrace.runtimeTask?.status, "blocked");
    assert.equal(blockedTrace.runtimeJob?.status, "blocked");
    assert.equal(blockedTrace.runtimeChecklist?.blockedItemCount, 1);
    const applyDiagnosticPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.diagnostics-apply",
          toolPack: {
            coding: {
              restorePolicy: "apply_with_approval",
              restoreConflictPolicy: "require_approval",
              diagnosticsRepairDefault: "restore_apply",
              operatorOverrideRequiresApproval: true,
            },
          },
          input: {
            path: "apply-diagnostics.mjs",
            oldText: "export const applyRepair = 1;",
            newText: "export const applyRepair = ;",
          },
        }),
      },
    );
    assert.equal(applyDiagnosticPatchResult.status, "completed");
    assert.equal(applyDiagnosticPatchResult.auto_diagnostics?.result.diagnosticStatus, "findings");
    assert.deepEqual(applyDiagnosticPatchResult.auto_diagnostics?.rollback_refs, [
      applyDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    const applyBlockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        message: "Continue after apply repair diagnostics.",
        diagnosticsMode: "blocking",
      }),
    });
    assert.equal(applyBlockedTurn.status, "waiting_for_input");
    assert.equal(applyBlockedTurn.stop_reason, "blocked_by_post_edit_diagnostics");
    const applyBlockedTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${applyBlockedTurn.request_id}/trace`);
    assert.equal(applyBlockedTrace.diagnosticsFeedback?.repairPolicy?.defaultDecision, "restore_apply");
    assert.equal(
      applyBlockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find((decision) => decision.action === "restore_apply")?.status,
      "requires_approval",
    );
    assert.deepEqual(applyBlockedTrace.diagnosticsFeedback?.repairPolicy?.workspaceSnapshotRefs, [
      applyDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    const skippedDiagnosticPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.diagnostics-skip",
          toolPack: {
            coding: {
              diagnosticsMode: "skip",
              defaultDiagnosticCommandId: "node.check",
            },
          },
          input: {
            path: "skip-diagnostics.mjs",
            oldText: "export const skip = 1;",
            newText: "export const skip = ;",
          },
        }),
      },
    );
    assert.equal(skippedDiagnosticPatchResult.status, "completed");
    assert.equal(skippedDiagnosticPatchResult.result.diagnosticsRecommended, true);
    assert.equal(skippedDiagnosticPatchResult.auto_diagnostics, null);
    const projectDiagnosticPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch.project-diagnostics",
          input: {
            path: "src/project-target.ts",
            oldText: "export const typed: number = 1;",
            newText: "export const typed: number = \"not a number\";",
          },
        }),
      },
    );
    assert.equal(projectDiagnosticPatchResult.status, "completed");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.commandId, "auto");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.resolvedCommandId, "typescript.check");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.backend, "typescript.project.check");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.backendStatus, "available");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.projectContext?.tsconfigPath, "tsconfig.json");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.projectContext?.packageManager, "npm");
    assert.equal(projectDiagnosticPatchResult.auto_diagnostics?.result.diagnosticStatus, "findings");
    assert.match(projectDiagnosticPatchResult.auto_diagnostics?.result.diagnostics[0]?.code ?? "", /^TS/);
    fs.renameSync(workspaceTsc, `${workspaceTsc}.disabled`);
    const degradedProjectDiagnostics = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/lsp.diagnostics/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.lsp.diagnostics.degraded-project",
          input: {
            commandId: "auto",
            path: "src/project-target.ts",
            maxOutputBytes: 4096,
          },
        }),
      },
    );
    assert.equal(degradedProjectDiagnostics.status, "completed");
    assert.equal(degradedProjectDiagnostics.result.commandId, "auto");
    assert.equal(degradedProjectDiagnostics.result.backendStatus, "degraded");
    assert.equal(degradedProjectDiagnostics.result.backendReason, "typescript_executable_missing");
    assert.equal(degradedProjectDiagnostics.result.fallbackUsed, true);
    assert.equal(degradedProjectDiagnostics.result.diagnosticStatus, "degraded");
    assert.ok(degradedProjectDiagnostics.result.receiptRefs.some((receiptRef) => receiptRef.includes("degraded")));
    assert.ok(degradedProjectDiagnostics.result.receiptRefs.some((receiptRef) => receiptRef.includes("fallback")));
    assert.equal(diagnosticsResult.status, "completed");
    assert.equal(diagnosticsResult.tool_name, "lsp.diagnostics");
    assert.equal(diagnosticsResult.result.diagnosticStatus, "findings");
    assert.equal(diagnosticsResult.result.diagnosticCount, 1);
    assert.equal(diagnosticsResult.result.shellFallbackUsed, false);
    assert.match(diagnosticsResult.result.diagnostics[0]?.message ?? "", /SyntaxError|Unexpected/);
    assert.equal(testResult.status, "completed");
    assert.equal(testResult.tool_name, "test.run");
    assert.equal(testResult.result.testStatus, "passed");
    assert.equal(testResult.result.exitCode, 0);
    assert.equal(testResult.result.shellFallbackUsed, false);
    assert.match(`${testResult.result.stdout}\n${testResult.result.stderr}`, /RUNTIME_ARTIFACT_SPILLOVER_START/);
    assert.equal(testResult.result.truncated, true);
    assert.ok(testResult.artifact_refs.length >= 1);
    assert.ok(testResult.result.artifacts.length >= 1);
    const spilloverArtifactId = testResult.result.artifacts.find((artifact) => artifact.channel === "output")?.artifactId;
    assert.ok(spilloverArtifactId);
    const artifactReadResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/artifact.read/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.artifact.read",
          input: {
            artifactId: spilloverArtifactId,
            lengthBytes: 8192,
          },
        }),
      },
    );
    assert.equal(artifactReadResult.status, "completed");
    assert.equal(artifactReadResult.tool_name, "artifact.read");
    assert.equal(artifactReadResult.result.artifactId, spilloverArtifactId);
    assert.match(artifactReadResult.result.content, /RUNTIME_ARTIFACT_SPILLOVER_END/);
    const retrieveResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/tool.retrieve_result/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.tool.retrieve_result",
          input: {
            toolCallId: testResult.tool_call_id,
            channel: "output",
            lengthBytes: 8192,
          },
        }),
      },
    );
    assert.equal(retrieveResult.status, "completed");
    assert.equal(retrieveResult.tool_name, "tool.retrieve_result");
    assert.equal(retrieveResult.result.toolCallId, testResult.tool_call_id);
    assert.match(retrieveResult.result.content, /RUNTIME_ARTIFACT_SPILLOVER_END/);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkCatalog = await sdkClient.listTools({ pack: "coding" });
    assert.deepEqual(
      sdkCatalog.map((tool) => tool.stableToolId).sort(),
      expectedCodingToolIds,
    );
    const sdkInvoke = await sdkClient.invokeThreadTool(thread.thread_id, "file.inspect", {
      input: { path: "README.md" },
      workflowNodeId: "runtime.coding-tool.sdk-file-inspect",
    });
    assert.equal(sdkInvoke.status, "completed");
    assert.equal(sdkInvoke.tool_name, "file.inspect");
    const sdkPatch = await sdkClient.invokeThreadTool(thread.thread_id, "file.apply_patch", {
      input: {
        path: "README.md",
        oldText: "Initial line.",
        newText: "SDK patched line.",
      },
      workflowNodeId: "runtime.coding-tool.sdk-file-apply-patch",
    });
    assert.equal(sdkPatch.status, "completed");
    assert.equal(sdkPatch.tool_name, "file.apply_patch");
    assert.equal(sdkPatch.result.applied, true);
    assert.equal(sdkPatch.workspace_snapshot?.schemaVersion, "ioi.runtime.workspace-snapshot.v1");
    assert.deepEqual(sdkPatch.rollback_refs, [sdkPatch.workspace_snapshot?.snapshotId]);
    const sdkSnapshots = await sdkClient.listThreadWorkspaceSnapshots(thread.thread_id);
    assert.equal(sdkSnapshots.snapshots.length >= 1, true);
    assert.ok(
      sdkSnapshots.snapshots.some(
        (snapshot) => snapshot.snapshotId === diagnosticPatchResult.workspace_snapshot?.snapshotId,
      ),
    );
    const sdkRestorePreview = await sdkClient.previewThreadWorkspaceRestore(
      thread.thread_id,
      diagnosticPatchResult.workspace_snapshot?.snapshotId,
      { workflowNodeId: "runtime.restore-gate.sdk-preview" },
    );
    assert.equal(sdkRestorePreview.previewStatus, "ready");
    assert.equal(sdkRestorePreview.operations[0]?.status, "ready");
    assert.deepEqual(sdkRestorePreview.rollbackRefs, [diagnosticPatchResult.workspace_snapshot?.snapshotId]);
    const sdkRestoreApply = await sdkClient.applyThreadWorkspaceRestore(
      thread.thread_id,
      restorePatchResult.workspace_snapshot?.snapshotId,
      {
        workflowNodeId: "runtime.restore-gate.sdk-apply",
        approvalGranted: true,
      },
    );
    assert.equal(sdkRestoreApply.applyStatus, "noop");
    assert.equal(sdkRestoreApply.operations[0]?.applyStatus, "noop");
    assert.deepEqual(sdkRestoreApply.rollbackRefs, [restorePatchResult.workspace_snapshot?.snapshotId]);
    const repairRetryDecision = blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "repair_retry",
    );
    assert.ok(repairRetryDecision);
    const sdkRepairRetry = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      repairRetryDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.retry",
        message: "Repair retry after blocking diagnostics.",
      },
    );
    assert.equal(sdkRepairRetry.schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(sdkRepairRetry.action, "repair_retry");
    assert.equal(sdkRepairRetry.status, "completed");
    assert.equal(sdkRepairRetry.snapshotId, blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId);
    assert.equal(sdkRepairRetry.repairTurn?.status, "completed");
    assert.equal(sdkRepairRetry.repairRetryEvent?.workflow_node_id, "workflow.diagnostics.repair.retry");
    assert.equal(sdkRepairRetry.event?.workflow_node_id, "workflow.diagnostics.repair.retry.decision");
    assert.deepEqual(sdkRepairRetry.rollbackRefs, [blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId]);
    const repairRetryConversation = await fetchJson(
      `${daemon.endpoint}/v1/runs/${sdkRepairRetry.repairTurn?.request_id}/conversation`,
    );
    assert.match(repairRetryConversation[0]?.content ?? "", /Post-edit diagnostics \(repair_retry, findings\)/);
    assert.match(repairRetryConversation[0]?.content ?? "", /blocking-target\.mjs/);
    const restorePreviewDecision = blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "restore_preview",
    );
    assert.ok(restorePreviewDecision);
    const preRepairPlainPreview = await sdkClient.previewThreadWorkspaceRestore(
      thread.thread_id,
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
      { workflowNodeId: "workflow.restore.preview.pre-repair" },
    );
    assert.equal(preRepairPlainPreview.restorePreviewEvent?.workflow_node_id, "workflow.restore.preview.pre-repair");
    const sdkRepairPreview = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      restorePreviewDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.restore-preview",
      },
    );
    assert.equal(sdkRepairPreview.schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(sdkRepairPreview.action, "restore_preview");
    assert.equal(sdkRepairPreview.status, "completed");
    assert.equal(sdkRepairPreview.snapshotId, blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId);
    assert.equal(sdkRepairPreview.restorePreview?.previewStatus, "ready");
    assert.equal(sdkRepairPreview.restorePreviewEvent?.workflow_node_id, "workflow.diagnostics.repair.restore-preview");
    assert.notEqual(sdkRepairPreview.restorePreviewEvent?.event_id, preRepairPlainPreview.restorePreviewEvent?.event_id);
    assert.equal(sdkRepairPreview.event?.workflow_node_id, "workflow.diagnostics.repair.restore-preview.decision");
    assert.deepEqual(sdkRepairPreview.rollbackRefs, [blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId]);
    const restoreApplyDecision = applyBlockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "restore_apply",
    );
    assert.ok(restoreApplyDecision);
    const sdkRepairApply = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      restoreApplyDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.restore-apply",
        approvalGranted: true,
      },
    );
    assert.equal(sdkRepairApply.schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(sdkRepairApply.action, "restore_apply");
    assert.equal(sdkRepairApply.status, "completed");
    assert.equal(sdkRepairApply.snapshotId, applyDiagnosticPatchResult.workspace_snapshot?.snapshotId);
    assert.equal(sdkRepairApply.restoreApply?.applyStatus, "applied");
    assert.equal(sdkRepairApply.restoreApply?.approvalSatisfied, true);
    assert.equal(sdkRepairApply.restoreApplyEvent?.workflow_node_id, "workflow.diagnostics.repair.restore-apply");
    assert.equal(sdkRepairApply.event?.workflow_node_id, "workflow.diagnostics.repair.restore-apply.decision");
    assert.deepEqual(sdkRepairApply.rollbackRefs, [applyDiagnosticPatchResult.workspace_snapshot?.snapshotId]);
    assert.match(fs.readFileSync(path.join(cwd, "apply-diagnostics.mjs"), "utf8"), /export const applyRepair = 1;/);
    const operatorOverrideDecision = blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "operator_override",
    );
    assert.ok(operatorOverrideDecision);
    const sdkOperatorOverride = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      operatorOverrideDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.operator-override",
      },
    );
    assert.equal(sdkOperatorOverride.schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(sdkOperatorOverride.action, "operator_override");
    assert.equal(sdkOperatorOverride.status, "completed");
    assert.equal(sdkOperatorOverride.snapshotId, blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId);
    assert.equal(sdkOperatorOverride.operatorOverride?.approvalRequired, false);
    assert.equal(sdkOperatorOverride.operatorOverride?.approvalSatisfied, true);
    assert.equal(sdkOperatorOverride.operatorOverride?.continuationAllowed, true);
    assert.equal(sdkOperatorOverride.operatorOverrideEvent?.workflow_node_id, "workflow.diagnostics.repair.operator-override");
    assert.equal(sdkOperatorOverride.event?.workflow_node_id, "workflow.diagnostics.repair.operator-override.decision");
    assert.deepEqual(sdkOperatorOverride.rollbackRefs, [blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId]);
    const overriddenTurn = await sdkClient.getTurn(thread.thread_id, blockedTurn.turn_id);
    assert.equal(overriddenTurn.status, "completed");
    const requiredOperatorOverrideDecision = applyBlockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "operator_override",
    );
    assert.ok(requiredOperatorOverrideDecision);
    const sdkOperatorOverrideBlocked = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      requiredOperatorOverrideDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.operator-override.required",
      },
    );
    assert.equal(sdkOperatorOverrideBlocked.action, "operator_override");
    assert.equal(sdkOperatorOverrideBlocked.status, "blocked");
    assert.equal(sdkOperatorOverrideBlocked.operatorOverride?.approvalRequired, true);
    assert.equal(sdkOperatorOverrideBlocked.operatorOverride?.approvalSatisfied, false);
    assert.equal(sdkOperatorOverrideBlocked.operatorOverride?.continuationAllowed, false);
    const stillBlockedTurn = await sdkClient.getTurn(thread.thread_id, applyBlockedTurn.turn_id);
    assert.equal(stillBlockedTurn.status, "waiting_for_input");
    const sdkOperatorOverrideApproved = await sdkClient.executeThreadDiagnosticsRepairDecision(
      thread.thread_id,
      requiredOperatorOverrideDecision.decisionId,
      {
        source: "react_flow",
        workflowGraphId: "workflow-coding-tools",
        workflowNodeId: "workflow.diagnostics.repair.operator-override.required",
        approvalGranted: true,
      },
    );
    assert.equal(sdkOperatorOverrideApproved.action, "operator_override");
    assert.equal(sdkOperatorOverrideApproved.status, "completed");
    assert.equal(sdkOperatorOverrideApproved.operatorOverride?.approvalRequired, true);
    assert.equal(sdkOperatorOverrideApproved.operatorOverride?.approvalSatisfied, true);
    assert.equal(sdkOperatorOverrideApproved.operatorOverride?.continuationAllowed, true);
    assert.equal(sdkOperatorOverrideApproved.operatorOverrideEvent?.workflow_node_id, "workflow.diagnostics.repair.operator-override.required");
    assert.equal(sdkOperatorOverrideApproved.event?.workflow_node_id, "workflow.diagnostics.repair.operator-override.required.decision");
    const overrideApprovedTurn = await sdkClient.getTurn(thread.thread_id, applyBlockedTurn.turn_id);
    assert.equal(overrideApprovedTurn.status, "completed");
    const sdkTest = await sdkClient.invokeThreadTool(thread.thread_id, "test.run", {
      input: { commandId: "node.test", path: "sample.test.mjs" },
      workflowNodeId: "runtime.coding-tool.sdk-test-run",
    });
    assert.equal(sdkTest.status, "completed");
    assert.equal(sdkTest.tool_name, "test.run");
    assert.equal(sdkTest.result.testStatus, "passed");
    const sdkDiagnostics = await sdkClient.invokeThreadTool(thread.thread_id, "lsp.diagnostics", {
      input: { commandId: "node.check", path: "diagnostic-target.mjs" },
      workflowNodeId: "runtime.coding-tool.sdk-lsp-diagnostics",
    });
    assert.equal(sdkDiagnostics.status, "completed");
    assert.equal(sdkDiagnostics.tool_name, "lsp.diagnostics");
    assert.equal(sdkDiagnostics.result.diagnosticStatus, "findings");
    const sdkArtifactRead = await sdkClient.invokeThreadTool(thread.thread_id, "artifact.read", {
      input: { artifactId: spilloverArtifactId, lengthBytes: 8192 },
      workflowNodeId: "runtime.coding-tool.sdk-artifact-read",
    });
    assert.equal(sdkArtifactRead.status, "completed");
    assert.equal(sdkArtifactRead.tool_name, "artifact.read");
    assert.match(String(sdkArtifactRead.result.content), /RUNTIME_ARTIFACT_SPILLOVER_END/);

    const cliCatalog = JSON.parse(
      (await execFileAsync(cli, ["agent", "tools", "coding", "--endpoint", daemon.endpoint, "--json"], {
        cwd: root,
      })).stdout,
    );
    assert.equal(cliCatalog.schema_version, "ioi.agent-cli.coding-tool-pack.v1");
    assert.deepEqual(
      cliCatalog.tools.map((tool) => tool.stableToolId).sort(),
      expectedCodingToolIds,
    );
    const cliInvoke = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "file.inspect",
          "--thread-id",
          thread.thread_id,
          "--path",
          "README.md",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliInvoke.status, "completed");
    assert.equal(cliInvoke.tool_name, "file.inspect");
    const cliPatch = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "file.apply_patch",
          "--thread-id",
          thread.thread_id,
          "--path",
          "README.md",
          "--old-text",
          "Changed line for diff proof.",
          "--new-text",
          "CLI patched diff proof.",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliPatch.status, "completed");
    assert.equal(cliPatch.tool_name, "file.apply_patch");
    assert.equal(cliPatch.result.applied, true);
    assert.equal(cliPatch.workspace_snapshot?.schemaVersion, "ioi.runtime.workspace-snapshot.v1");
    assert.deepEqual(cliPatch.rollback_refs, [cliPatch.workspace_snapshot?.snapshotId]);
    const cliTest = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "test.run",
          "--thread-id",
          thread.thread_id,
          "--command-id",
          "node.test",
          "--path",
          "sample.test.mjs",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliTest.status, "completed");
    assert.equal(cliTest.tool_name, "test.run");
    assert.equal(cliTest.result.testStatus, "passed");
    const cliDiagnostics = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "lsp.diagnostics",
          "--thread-id",
          thread.thread_id,
          "--command-id",
          "node.check",
          "--path",
          "diagnostic-target.mjs",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliDiagnostics.status, "completed");
    assert.equal(cliDiagnostics.tool_name, "lsp.diagnostics");
    assert.equal(cliDiagnostics.result.diagnosticStatus, "findings");
    const cliRetrieve = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "tool.retrieve_result",
          "--thread-id",
          thread.thread_id,
          "--tool-call-id",
          testResult.tool_call_id,
          "--length-bytes",
          "8192",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliRetrieve.status, "completed");
    assert.equal(cliRetrieve.tool_name, "tool.retrieve_result");
    assert.match(cliRetrieve.result.content, /RUNTIME_ARTIFACT_SPILLOVER_END/);


    const sseResponse = await fetch(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events`);
    const sseText = await sseResponse.text();
    const parsedEvents = [];
    for (const line of sseText.split("\n")) {
      if (line.startsWith("data: ")) {
        try {
          const parsed = JSON.parse(line.slice(6));
          parsedEvents.push(parsed);
        } catch {}
      }
    }
    const leaseEvent = parsedEvents.find(e => e.seq === 11);
    console.log("LEASE EVENT seq 11:", JSON.stringify(leaseEvent, null, 2));
    if (leaseEvent) {
      console.log("seq 11 component_kind:", leaseEvent.component_kind);
      console.log("seq 11 event_kind:", leaseEvent.event_kind);
      console.log("seq 11 status:", leaseEvent.status);
    }

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      `/status\n/diff README.md\n/inspect README.md\n/patch README.md SDK patched line. => TUI patched line.\n/patch-dry-run README.md TUI patched line. => TUI dry-run line.\n/test sample.test.mjs\n/diagnostics diagnostic-target.mjs\n/artifact ${spilloverArtifactId}\n/retrieve ${testResult.tool_call_id}\n/restore\n/restore preview ${skippedDiagnosticPatchResult.workspace_snapshot?.snapshotId}\n/restore apply ${skippedDiagnosticPatchResult.workspace_snapshot?.snapshotId} --approve\n/quit\n`,
      { cwd: root, timeout: 45000 },
    );
    assert.match(tuiResult.stdout, /Line-mode commands: .*\/status .*\/diff \[path\] .*\/inspect <path> .*\/patch <path> <old> => <new> .*\/test \[path\] .*\/diagnostics <path> .*\/artifact <artifact_id> .*\/retrieve <tool_call_id_or_artifact_id> .*\/restore \[list\|preview <snapshot_id>\|apply <snapshot_id> --approve\] .*\/quit/);
    assert.match(tuiResult.stdout, /line_mode_command=status tool=workspace\.status status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=diff tool=git\.diff status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=inspect tool=file\.inspect status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=patch tool=file\.apply_patch status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=test tool=test\.run status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=diagnostics tool=lsp\.diagnostics status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=artifact tool=artifact\.read status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=retrieve tool=tool\.retrieve_result status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=restore action=list count=\d+/);
    assert.match(tuiResult.stdout, /line_mode_command=restore action=preview snapshot=workspace_snapshot_[^\s]+ status=ready/);
    assert.match(tuiResult.stdout, /line_mode_command=restore action=apply snapshot=workspace_snapshot_[^\s]+ status=applied approval_satisfied=true/);
    assert.match(tuiResult.stdout, /"command":"restore"/);
    assert.match(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /TUI patched line\./);
    assert.doesNotMatch(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /TUI dry-run line/);
    assert.match(fs.readFileSync(path.join(cwd, "skip-diagnostics.mjs"), "utf8"), /export const skip = 1;/);
    const tuiControlStateMatches = [...tuiResult.stdout.matchAll(/^tui_control_state=(.+)$/gm)];
    assert.ok(tuiControlStateMatches.length >= 1);
    const tuiControlState = JSON.parse(tuiControlStateMatches.at(-1)[1]);
    const tuiCodingRows = tuiControlState.coding_tool_rows.filter(
      (row) => row.row_kind === "coding_tool",
    );
    console.log("TUI Coding Rows:", JSON.stringify(tuiCodingRows, null, 2));
    for (const toolName of expectedCodingToolIds) {
      assert.ok(
        tuiCodingRows.some((row) => row.tool_name === toolName),
        `TUI control state should include successful coding-tool row for ${toolName}`,
      );
    }
    assert.ok(tuiCodingRows.every((row) => row.receipt_refs.length >= 1));
    assert.ok(tuiCodingRows.every((row) => row.shell_fallback_used === false));
    const tuiDryRunRow = tuiCodingRows.find(
      (row) => row.tool_name === "file.apply_patch" && row.command === "patch-dry-run",
    );
    assert.ok(tuiDryRunRow);
    assert.equal(tuiDryRunRow.dry_run, true);
    assert.equal(tuiDryRunRow.mutation_blocked, false);
    const tuiTestRow = tuiCodingRows.find(
      (row) =>
        row.tool_name === "test.run" &&
        row.command === "test" &&
        row.workflow_node_id === "runtime.coding-tool.test.run",
    );
    assert.ok(tuiTestRow);
    const tuiRetrieveRow = tuiCodingRows.find(
      (row) => row.tool_name === "tool.retrieve_result" && row.command === "retrieve",
    );
    assert.ok(tuiRetrieveRow);
    assert.match(tuiRetrieveRow.raw_input, /^\/retrieve/);
    const tuiControlProjection =
      projectRuntimeTuiControlStateToWorkflowProjection(tuiControlState);
    assert.equal(
      tuiControlProjection.codingToolBudgetRowCount,
      tuiControlState.coding_tool_rows.filter(
        (row) => row.row_kind === "coding_tool_budget",
      ).length,
    );
    assert.equal(tuiControlProjection.codingToolRowCount, tuiCodingRows.length);
    const tuiProjectedTestRow = tuiControlProjection.rows.find(
      (row) =>
        row.rowKind === "coding_tool" &&
        row.toolName === "test.run" &&
        row.command === "test" &&
        row.reactFlowNodeId === "runtime.coding-tool.test.run",
    );
    assert.ok(tuiProjectedTestRow);
    assert.equal(tuiProjectedTestRow.reactFlowNodeId, "runtime.coding-tool.test.run");
    assert.deepEqual(tuiProjectedTestRow.receiptRefs, tuiTestRow.receipt_refs);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const codingEvents = daemonEvents.filter((event) => event.component_kind === "coding_tool");
    assert.ok(codingEvents.length >= 24);
    assert.ok(codingEvents.every((event) => event.payload_schema_version === "ioi.runtime.coding-tool-result.v1"));
    assert.ok(codingEvents.every((event) => event.event_kind === "tool.completed"));
    assert.ok(codingEvents.every((event) => event.payload.shell_fallback_used === "false"));
    assert.ok(codingEvents.every((event) => event.receipt_refs.length >= 1));
    const reactFlowStatus = codingEvents.find(
      (event) =>
        event.payload.tool_name === "workspace.status" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowStatus);
    assert.equal(reactFlowStatus.workflow_graph_id, "workflow-coding-tools");
    assert.equal(reactFlowStatus.workflow_node_id, "workflow.coding.workspace.status");
    const reactFlowPatch = codingEvents.find(
      (event) =>
        event.payload.tool_name === "file.apply_patch" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowPatch);
    assert.equal(reactFlowPatch.workflow_node_id, "workflow.coding.file.apply_patch");
    const diagnosticPatchToolEvent = codingEvents.find(
      (event) => event.tool_call_id === diagnosticPatchResult.tool_call_id,
    );
    assert.ok(diagnosticPatchToolEvent);
    assert.ok(diagnosticPatchToolEvent.rollback_refs.includes(diagnosticPatchResult.workspace_snapshot.snapshotId));
    assert.ok(diagnosticPatchToolEvent.artifact_refs.includes(diagnosticPatchResult.workspace_snapshot.artifactRefs[0]));
    const reactFlowTest = codingEvents.find(
      (event) =>
        event.payload.tool_name === "test.run" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowTest);
    assert.equal(reactFlowTest.workflow_node_id, "workflow.coding.test.run");
    assert.ok(reactFlowTest.artifact_refs.includes(spilloverArtifactId));
    const reactFlowDiagnostics = codingEvents.find(
      (event) =>
        event.payload.tool_name === "lsp.diagnostics" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowDiagnostics);
    assert.equal(reactFlowDiagnostics.workflow_node_id, "workflow.coding.lsp.diagnostics");
    const autoDiagnostics = codingEvents.find(
      (event) =>
        event.payload.tool_name === "lsp.diagnostics" &&
        event.source === "runtime_auto" &&
        event.workflow_node_id === "runtime.coding-tool.lsp-diagnostics.auto",
    );
    assert.ok(autoDiagnostics);
    assert.equal(autoDiagnostics.payload_summary.result_summary.diagnosticStatus, "findings");
    const projectAutoDiagnostics = codingEvents.find(
      (event) =>
        event.payload.tool_name === "lsp.diagnostics" &&
        event.source === "runtime_auto" &&
        event.payload_summary.result_summary.backend === "typescript.project.check",
    );
    assert.ok(projectAutoDiagnostics);
    assert.equal(projectAutoDiagnostics.payload_summary.result_summary.resolvedCommandId, "typescript.check");
    assert.equal(projectAutoDiagnostics.payload_summary.result_summary.backendStatus, "available");
    const degradedProjectDiagnosticsEvent = codingEvents.find(
      (event) => event.workflow_node_id === "workflow.coding.lsp.diagnostics.degraded-project",
    );
    assert.ok(degradedProjectDiagnosticsEvent);
    assert.equal(degradedProjectDiagnosticsEvent.payload_summary.result_summary.backendStatus, "degraded");
    assert.equal(String(degradedProjectDiagnosticsEvent.payload_summary.result_summary.fallbackUsed), "true");
    assert.ok(degradedProjectDiagnosticsEvent.receipt_refs.some((receiptRef) => receiptRef.includes("degraded")));
    const workspaceSnapshotEvents = daemonEvents.filter(
      (event) =>
        event.event_kind === "workspace.snapshot.created" &&
        event.component_kind === "workspace_snapshot",
    );
    assert.ok(workspaceSnapshotEvents.length >= 5);
    const diagnosticSnapshotEvent = workspaceSnapshotEvents.find(
      (event) => event.payload_summary.snapshot_id === diagnosticPatchResult.workspace_snapshot.snapshotId,
    );
    assert.ok(diagnosticSnapshotEvent);
    assert.equal(diagnosticSnapshotEvent.source, "runtime_auto");
    assert.equal(diagnosticSnapshotEvent.source_event_kind, "WorkspaceSnapshot.Created");
    assert.equal(diagnosticSnapshotEvent.workflow_node_id, "runtime.workspace-snapshot");
    assert.equal(diagnosticSnapshotEvent.payload_schema_version, "ioi.runtime.workspace-snapshot.v1");
    assert.equal(diagnosticSnapshotEvent.tool_call_id, diagnosticPatchResult.tool_call_id);
    assert.equal(diagnosticSnapshotEvent.payload_summary.source_tool_event_id, diagnosticPatchToolEvent.event_id);
    assert.equal(diagnosticSnapshotEvent.payload_summary.changed_file_count, 1);
    assert.equal(diagnosticSnapshotEvent.payload_summary.restore_status, "content_captured");
    assert.equal(String(diagnosticSnapshotEvent.payload_summary.restore_preview_supported), "true");
    assert.equal(String(diagnosticSnapshotEvent.payload_summary.restore_apply_supported), "true");
    assert.equal(diagnosticSnapshotEvent.payload_summary.files[0]?.path, "diagnostic-target.mjs");
    assert.deepEqual(diagnosticSnapshotEvent.rollback_refs, [diagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.deepEqual(diagnosticSnapshotEvent.receipt_refs, diagnosticPatchResult.workspace_snapshot.receiptRefs);
    assert.deepEqual(diagnosticSnapshotEvent.artifact_refs, diagnosticPatchResult.workspace_snapshot.artifactRefs);
    const restorePreviewEvent = daemonEvents.find(
      (event) => event.event_id === restorePreviewResult.event.event_id,
    );
    assert.ok(restorePreviewEvent);
    assert.equal(restorePreviewEvent.source, "runtime_auto");
    assert.equal(restorePreviewEvent.source_event_kind, "WorkspaceRestore.Previewed");
    assert.equal(restorePreviewEvent.event_kind, "workspace.restore.previewed");
    assert.equal(restorePreviewEvent.component_kind, "restore_gate");
    assert.equal(restorePreviewEvent.workflow_node_id, "workflow.restore.preview");
    assert.equal(restorePreviewEvent.payload_schema_version, "ioi.runtime.workspace-restore-preview.v1");
    assert.equal(restorePreviewEvent.payload_summary.preview_status, "ready");
    assert.equal(restorePreviewEvent.payload_summary.operations[0]?.status, "ready");
    assert.deepEqual(restorePreviewEvent.rollback_refs, [diagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.deepEqual(restorePreviewEvent.receipt_refs, restorePreviewResult.receipt_refs);
    assert.deepEqual(restorePreviewEvent.artifact_refs, restorePreviewResult.artifact_refs);
    const restoreApplyBlockedEvent = daemonEvents.find(
      (event) => event.event_id === restoreApplyBlockedResult.event.event_id,
    );
    assert.ok(restoreApplyBlockedEvent);
    assert.equal(restoreApplyBlockedEvent.status, "blocked");
    assert.equal(restoreApplyBlockedEvent.event_kind, "workspace.restore.applied");
    assert.equal(restoreApplyBlockedEvent.payload_summary.apply_status, "blocked");
    assert.deepEqual(restoreApplyBlockedEvent.policy_decision_refs, restoreApplyBlockedResult.policy_decision_refs);
    const restoreApplyEvent = daemonEvents.find(
      (event) => event.event_id === restoreApplyResult.event.event_id,
    );
    assert.ok(restoreApplyEvent);
    assert.equal(restoreApplyEvent.source, "runtime_auto");
    assert.equal(restoreApplyEvent.source_event_kind, "WorkspaceRestore.Applied");
    assert.equal(restoreApplyEvent.event_kind, "workspace.restore.applied");
    assert.equal(restoreApplyEvent.component_kind, "restore_gate");
    assert.equal(restoreApplyEvent.workflow_node_id, "workflow.restore.apply");
    assert.equal(restoreApplyEvent.payload_schema_version, "ioi.runtime.workspace-restore-apply.v1");
	    assert.equal(restoreApplyEvent.payload_summary.apply_status, "applied");
	    assert.equal(restoreApplyEvent.payload_summary.operations[0]?.apply_status, "applied");
	    assert.deepEqual(restoreApplyEvent.rollback_refs, [restorePatchResult.workspace_snapshot.snapshotId]);
	    assert.deepEqual(restoreApplyEvent.receipt_refs, restoreApplyResult.receipt_refs);
	    assert.deepEqual(restoreApplyEvent.artifact_refs, restoreApplyResult.artifact_refs);
    const diagnosticsRepairRetryEvent = daemonEvents.find(
      (event) => event.event_id === sdkRepairRetry.repairRetryEvent?.event_id,
    );
    assert.ok(diagnosticsRepairRetryEvent);
    assert.equal(diagnosticsRepairRetryEvent.source, "react_flow");
    assert.equal(diagnosticsRepairRetryEvent.source_event_kind, "LspDiagnostics.RepairRetryTurnCreated");
    assert.equal(diagnosticsRepairRetryEvent.event_kind, "diagnostics.repair_retry.created");
    assert.equal(diagnosticsRepairRetryEvent.component_kind, "lsp_diagnostics_repair_retry");
    assert.equal(diagnosticsRepairRetryEvent.workflow_node_id, "workflow.diagnostics.repair.retry");
    assert.equal(diagnosticsRepairRetryEvent.payload_schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(diagnosticsRepairRetryEvent.payload_summary.action, "repair_retry");
    assert.equal(diagnosticsRepairRetryEvent.payload_summary.retry_turn_id, sdkRepairRetry.repairTurn?.turn_id);
    assert.equal(diagnosticsRepairRetryEvent.payload_summary.repair_prompt_injected, true);
    assert.deepEqual(diagnosticsRepairRetryEvent.rollback_refs, [blockingDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsRepairRetryEvent.policy_decision_refs.some((ref) => ref.includes("repair_retry")));
    const diagnosticsRepairRetryDecisionEvent = daemonEvents.find(
      (event) => event.event_id === sdkRepairRetry.event?.event_id,
    );
    assert.ok(diagnosticsRepairRetryDecisionEvent);
    assert.equal(diagnosticsRepairRetryDecisionEvent.source, "react_flow");
    assert.equal(diagnosticsRepairRetryDecisionEvent.source_event_kind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(diagnosticsRepairRetryDecisionEvent.event_kind, "diagnostics.repair_decision.executed");
    assert.equal(diagnosticsRepairRetryDecisionEvent.component_kind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairRetryDecisionEvent.workflow_node_id, "workflow.diagnostics.repair.retry.decision");
    assert.equal(diagnosticsRepairRetryDecisionEvent.payload_schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(diagnosticsRepairRetryDecisionEvent.payload_summary.action, "repair_retry");
    assert.equal(diagnosticsRepairRetryDecisionEvent.payload_summary.repair_retry_event_id, diagnosticsRepairRetryEvent.event_id);
    assert.equal(diagnosticsRepairRetryDecisionEvent.payload_summary.repair_retry_turn_id, sdkRepairRetry.repairTurn?.turn_id);
    assert.deepEqual(diagnosticsRepairRetryDecisionEvent.rollback_refs, [blockingDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsRepairRetryDecisionEvent.policy_decision_refs.some((ref) => ref.includes("repair_retry")));
	    const diagnosticsRepairRestorePreviewEvent = daemonEvents.find(
	      (event) => event.event_id === sdkRepairPreview.restorePreviewEvent?.event_id,
	    );
    assert.ok(diagnosticsRepairRestorePreviewEvent);
    assert.equal(diagnosticsRepairRestorePreviewEvent.source, "runtime_auto");
    assert.equal(diagnosticsRepairRestorePreviewEvent.event_kind, "workspace.restore.previewed");
    assert.equal(diagnosticsRepairRestorePreviewEvent.component_kind, "restore_gate");
    assert.equal(diagnosticsRepairRestorePreviewEvent.workflow_node_id, "workflow.diagnostics.repair.restore-preview");
    assert.equal(diagnosticsRepairRestorePreviewEvent.payload_summary.snapshot_id, blockingDiagnosticPatchResult.workspace_snapshot.snapshotId);
    assert.equal(diagnosticsRepairRestorePreviewEvent.payload_summary.preview_status, "ready");
    assert.deepEqual(diagnosticsRepairRestorePreviewEvent.rollback_refs, [blockingDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    const diagnosticsRepairDecisionEvent = daemonEvents.find(
      (event) => event.event_id === sdkRepairPreview.event?.event_id,
    );
    assert.ok(diagnosticsRepairDecisionEvent);
    assert.equal(diagnosticsRepairDecisionEvent.source, "react_flow");
    assert.equal(diagnosticsRepairDecisionEvent.source_event_kind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(diagnosticsRepairDecisionEvent.event_kind, "diagnostics.repair_decision.executed");
    assert.equal(diagnosticsRepairDecisionEvent.component_kind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairDecisionEvent.workflow_node_id, "workflow.diagnostics.repair.restore-preview.decision");
    assert.equal(diagnosticsRepairDecisionEvent.payload_schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(diagnosticsRepairDecisionEvent.payload_summary.action, "restore_preview");
    assert.equal(diagnosticsRepairDecisionEvent.payload_summary.restore_preview_event_id, diagnosticsRepairRestorePreviewEvent.event_id);
    assert.deepEqual(diagnosticsRepairDecisionEvent.rollback_refs, [blockingDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsRepairDecisionEvent.policy_decision_refs.some((ref) => ref.includes("restore_preview")));
    const diagnosticsRepairRestoreApplyEvent = daemonEvents.find(
      (event) => event.event_id === sdkRepairApply.restoreApplyEvent?.event_id,
    );
    assert.ok(diagnosticsRepairRestoreApplyEvent);
    assert.equal(diagnosticsRepairRestoreApplyEvent.source, "runtime_auto");
    assert.equal(diagnosticsRepairRestoreApplyEvent.event_kind, "workspace.restore.applied");
    assert.equal(diagnosticsRepairRestoreApplyEvent.component_kind, "restore_gate");
    assert.equal(diagnosticsRepairRestoreApplyEvent.workflow_node_id, "workflow.diagnostics.repair.restore-apply");
    assert.equal(diagnosticsRepairRestoreApplyEvent.payload_summary.snapshot_id, applyDiagnosticPatchResult.workspace_snapshot.snapshotId);
    assert.equal(diagnosticsRepairRestoreApplyEvent.payload_summary.apply_status, "applied");
    assert.equal(diagnosticsRepairRestoreApplyEvent.payload_summary.approval_satisfied, true);
    assert.deepEqual(diagnosticsRepairRestoreApplyEvent.rollback_refs, [applyDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsRepairRestoreApplyEvent.policy_decision_refs.some((ref) => ref.includes("approval_satisfied")));
    const diagnosticsRepairApplyDecisionEvent = daemonEvents.find(
      (event) => event.event_id === sdkRepairApply.event?.event_id,
    );
    assert.ok(diagnosticsRepairApplyDecisionEvent);
    assert.equal(diagnosticsRepairApplyDecisionEvent.source, "react_flow");
    assert.equal(diagnosticsRepairApplyDecisionEvent.source_event_kind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(diagnosticsRepairApplyDecisionEvent.event_kind, "diagnostics.repair_decision.executed");
    assert.equal(diagnosticsRepairApplyDecisionEvent.component_kind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairApplyDecisionEvent.workflow_node_id, "workflow.diagnostics.repair.restore-apply.decision");
    assert.equal(diagnosticsRepairApplyDecisionEvent.payload_schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(diagnosticsRepairApplyDecisionEvent.payload_summary.action, "restore_apply");
    assert.equal(diagnosticsRepairApplyDecisionEvent.payload_summary.restore_apply_event_id, diagnosticsRepairRestoreApplyEvent.event_id);
    assert.equal(diagnosticsRepairApplyDecisionEvent.payload_summary.restore_apply_status, "applied");
    assert.equal(diagnosticsRepairApplyDecisionEvent.payload_summary.approval_satisfied, true);
    assert.deepEqual(diagnosticsRepairApplyDecisionEvent.rollback_refs, [applyDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsRepairApplyDecisionEvent.policy_decision_refs.some((ref) => ref.includes("restore_apply")));
    const diagnosticsOperatorOverrideEvent = daemonEvents.find(
      (event) => event.event_id === sdkOperatorOverride.operatorOverrideEvent?.event_id,
    );
    assert.ok(diagnosticsOperatorOverrideEvent);
    assert.equal(diagnosticsOperatorOverrideEvent.source, "react_flow");
    assert.equal(diagnosticsOperatorOverrideEvent.source_event_kind, "LspDiagnostics.OperatorOverrideExecuted");
    assert.equal(diagnosticsOperatorOverrideEvent.event_kind, "diagnostics.operator_override.executed");
    assert.equal(diagnosticsOperatorOverrideEvent.component_kind, "lsp_diagnostics_operator_override");
    assert.equal(diagnosticsOperatorOverrideEvent.workflow_node_id, "workflow.diagnostics.repair.operator-override");
    assert.equal(diagnosticsOperatorOverrideEvent.payload_schema_version, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.equal(diagnosticsOperatorOverrideEvent.payload_summary.action, "operator_override");
    assert.equal(diagnosticsOperatorOverrideEvent.payload_summary.approval_required, false);
    assert.equal(diagnosticsOperatorOverrideEvent.payload_summary.approval_satisfied, true);
    assert.equal(diagnosticsOperatorOverrideEvent.payload_summary.continuation_allowed, true);
    assert.deepEqual(diagnosticsOperatorOverrideEvent.rollback_refs, [blockingDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    assert.ok(diagnosticsOperatorOverrideEvent.policy_decision_refs.some((ref) => ref.includes("operator_override")));
    const diagnosticsOperatorOverrideDecisionEvent = daemonEvents.find(
      (event) => event.event_id === sdkOperatorOverride.event?.event_id,
    );
    assert.ok(diagnosticsOperatorOverrideDecisionEvent);
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.source, "react_flow");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.source_event_kind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.event_kind, "diagnostics.repair_decision.executed");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.component_kind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.workflow_node_id, "workflow.diagnostics.repair.operator-override.decision");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.payload_summary.operator_override_event_id, diagnosticsOperatorOverrideEvent.event_id);
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.payload_summary.operator_override_status, "completed");
    assert.equal(diagnosticsOperatorOverrideDecisionEvent.payload_summary.operator_override_continuation_allowed, true);
    const diagnosticsOperatorOverrideBlockedEvent = daemonEvents.find(
      (event) => event.event_id === sdkOperatorOverrideBlocked.operatorOverrideEvent?.event_id,
    );
    assert.ok(diagnosticsOperatorOverrideBlockedEvent);
    assert.equal(diagnosticsOperatorOverrideBlockedEvent.status, "blocked");
    assert.equal(diagnosticsOperatorOverrideBlockedEvent.payload_summary.approval_required, true);
    assert.equal(diagnosticsOperatorOverrideBlockedEvent.payload_summary.approval_satisfied, false);
    assert.equal(diagnosticsOperatorOverrideBlockedEvent.payload_summary.continuation_allowed, false);
    const diagnosticsOperatorOverrideApprovedEvent = daemonEvents.find(
      (event) => event.event_id === sdkOperatorOverrideApproved.operatorOverrideEvent?.event_id,
    );
    assert.ok(diagnosticsOperatorOverrideApprovedEvent);
    assert.equal(diagnosticsOperatorOverrideApprovedEvent.status, "completed");
    assert.equal(diagnosticsOperatorOverrideApprovedEvent.workflow_node_id, "workflow.diagnostics.repair.operator-override.required");
    assert.equal(diagnosticsOperatorOverrideApprovedEvent.payload_summary.approval_required, true);
    assert.equal(diagnosticsOperatorOverrideApprovedEvent.payload_summary.approval_satisfied, true);
    assert.equal(diagnosticsOperatorOverrideApprovedEvent.payload_summary.continuation_allowed, true);
    const tuiRestorePreviewEvent = daemonEvents.find(
      (event) =>
        event.source === "runtime_auto" &&
        event.source_event_kind === "WorkspaceRestore.Previewed" &&
        event.workflow_node_id === "runtime.restore-gate.tui-preview" &&
        event.payload_summary.snapshot_id === skippedDiagnosticPatchResult.workspace_snapshot.snapshotId,
    );
    assert.ok(tuiRestorePreviewEvent);
    assert.equal(tuiRestorePreviewEvent.event_kind, "workspace.restore.previewed");
    assert.equal(tuiRestorePreviewEvent.component_kind, "restore_gate");
    assert.equal(tuiRestorePreviewEvent.payload_schema_version, "ioi.runtime.workspace-restore-preview.v1");
    assert.equal(tuiRestorePreviewEvent.payload_summary.preview_status, "ready");
    assert.deepEqual(tuiRestorePreviewEvent.rollback_refs, [skippedDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    const tuiRestoreApplyEvent = daemonEvents.find(
      (event) =>
        event.source === "runtime_auto" &&
        event.source_event_kind === "WorkspaceRestore.Applied" &&
        event.workflow_node_id === "runtime.restore-gate.tui-apply" &&
        event.payload_summary.snapshot_id === skippedDiagnosticPatchResult.workspace_snapshot.snapshotId,
    );
    assert.ok(tuiRestoreApplyEvent);
    assert.equal(tuiRestoreApplyEvent.event_kind, "workspace.restore.applied");
    assert.equal(tuiRestoreApplyEvent.component_kind, "restore_gate");
    assert.equal(tuiRestoreApplyEvent.payload_schema_version, "ioi.runtime.workspace-restore-apply.v1");
    assert.equal(tuiRestoreApplyEvent.payload_summary.apply_status, "applied");
    assert.equal(tuiRestoreApplyEvent.payload_summary.approval_satisfied, true);
    assert.deepEqual(tuiRestoreApplyEvent.rollback_refs, [skippedDiagnosticPatchResult.workspace_snapshot.snapshotId]);
    const reactFlowArtifactRead = codingEvents.find(
      (event) =>
        event.payload.tool_name === "artifact.read" &&
        event.source === "react_flow" &&
        event.workflow_node_id === "workflow.coding.artifact.read",
    );
    assert.ok(reactFlowArtifactRead);
    assert.equal(reactFlowArtifactRead.workflow_node_id, "workflow.coding.artifact.read");
    const reactFlowRetrieve = codingEvents.find(
      (event) =>
        event.payload.tool_name === "tool.retrieve_result" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowRetrieve);
    assert.equal(reactFlowRetrieve.workflow_node_id, "workflow.coding.tool.retrieve_result");
    const diagnosticsInjection = daemonEvents.find(
      (event) =>
        event.event_kind === "lsp.diagnostics.injected" &&
        event.component_kind === "lsp_diagnostics",
    );
    assert.ok(diagnosticsInjection);
    assert.equal(diagnosticsInjection.source, "runtime_auto");
    assert.equal(diagnosticsInjection.workflow_node_id, "runtime.lsp-diagnostics.injected");
    assert.equal(diagnosticsInjection.payload_schema_version, "ioi.runtime.lsp-diagnostics-injection.v1");
    assert.equal(diagnosticsInjection.payload.diagnostic_status, "findings");
    assert.equal(diagnosticsInjection.payload.mode, "advisory");
    assert.match(diagnosticsInjection.payload.prompt_text, /diagnostic-target\.mjs/);
    const blockingDiagnosticsInjection = daemonEvents.find(
      (event) =>
        event.event_kind === "lsp.diagnostics.injected" &&
        event.component_kind === "lsp_diagnostics" &&
        event.status === "blocked" &&
        event.payload.mode === "blocking",
    );
    assert.ok(blockingDiagnosticsInjection);
    assert.equal(blockingDiagnosticsInjection.source, "runtime_auto");
    assert.equal(blockingDiagnosticsInjection.workflow_node_id, "runtime.lsp-diagnostics.injected");
    assert.match(blockingDiagnosticsInjection.payload.prompt_text, /blocking-target\.mjs/);
    assert.deepEqual(blockingDiagnosticsInjection.rollback_refs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(blockingDiagnosticsInjection.payload_summary.workspace_snapshot_refs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(
      blockingDiagnosticsInjection.payload_summary.repair_policy.decisions.map((decision) => decision.action),
      ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
    );
    assert.equal(blockingDiagnosticsInjection.payload_summary.repair_policy.restore_policy, "preview_only");
    assert.equal(blockingDiagnosticsInjection.payload_summary.repair_policy.restore_conflict_policy, "require_approval");
    assert.equal(blockingDiagnosticsInjection.payload_summary.repair_policy.default_decision, "restore_preview");
    assert.equal(blockingDiagnosticsInjection.payload_summary.repair_policy.operator_override_requires_approval, false);
    const diagnosticsBlockingGate = daemonEvents.find(
      (event) =>
        event.event_kind === "policy.blocked" &&
        event.component_kind === "lsp_diagnostics_gate" &&
        event.workflow_node_id === "runtime.lsp-diagnostics.blocking-gate",
    );
    assert.ok(diagnosticsBlockingGate);
    assert.equal(diagnosticsBlockingGate.source, "runtime_auto");
    assert.equal(diagnosticsBlockingGate.source_event_kind, "LspDiagnostics.BlockingGate");
    assert.equal(diagnosticsBlockingGate.status, "blocked");
    assert.equal(diagnosticsBlockingGate.payload_schema_version, "ioi.runtime.lsp-diagnostics-blocking-gate.v1");
    assert.equal(diagnosticsBlockingGate.payload.reason, "post_edit_diagnostics_findings");
    assert.equal(diagnosticsBlockingGate.payload.diagnostic_status, "findings");
    assert.equal(diagnosticsBlockingGate.payload.requires_input, "true");
    assert.deepEqual(diagnosticsBlockingGate.rollback_refs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(diagnosticsBlockingGate.payload_summary.workspace_snapshot_refs, [
      blockingDiagnosticPatchResult.workspace_snapshot?.snapshotId,
    ]);
    assert.deepEqual(
      diagnosticsBlockingGate.payload_summary.repair_decisions.map((decision) => decision.action),
      ["repair_retry", "restore_preview", "restore_apply", "operator_override"],
    );
    assert.equal(diagnosticsBlockingGate.payload_summary.repair_policy.restore_policy, "preview_only");
    assert.equal(diagnosticsBlockingGate.payload_summary.repair_policy.default_decision, "restore_preview");
    assert.deepEqual(diagnosticsBlockingGate.payload_summary.recommended_next_actions, [
      "repair_retry",
      "restore_preview",
      "operator_override",
    ]);
    assert.ok(diagnosticsBlockingGate.policy_decision_refs.length >= 5);
    assert.ok(diagnosticsBlockingGate.policy_decision_refs.some((ref) => ref.includes("repair_retry")));
    assert.ok(diagnosticsBlockingGate.policy_decision_refs.some((ref) => ref.includes("restore_preview")));
    assert.ok(diagnosticsBlockingGate.policy_decision_refs.some((ref) => ref.includes("restore_apply")));
    assert.ok(diagnosticsBlockingGate.policy_decision_refs.some((ref) => ref.includes("operator_override")));
    assert.ok(diagnosticsBlockingGate.receipt_refs.length >= 1);
    assert.ok(diagnosticsBlockingGate.artifact_refs.includes("diagnostics-blocking-gate.json"));

    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkStatusEvent = sdkEvents.find((event) => event.id === reactFlowStatus.event_id);
    assert.ok(sdkStatusEvent);
    assert.equal(sdkStatusEvent.toolName, "workspace.status");
    assert.equal(sdkStatusEvent.componentKind, "coding_tool");
    assert.equal(sdkStatusEvent.payloadSchemaVersion, "ioi.runtime.coding-tool-result.v1");
    const sdkPatchEvent = sdkEvents.find((event) => event.id === reactFlowPatch.event_id);
    assert.ok(sdkPatchEvent);
    assert.equal(sdkPatchEvent.toolName, "file.apply_patch");
    assert.equal(sdkPatchEvent.sourceEventKind, "CodingTool.FileApplyPatch");
    const sdkTestEvent = sdkEvents.find((event) => event.id === reactFlowTest.event_id);
    assert.ok(sdkTestEvent);
    assert.equal(sdkTestEvent.toolName, "test.run");
    assert.equal(sdkTestEvent.sourceEventKind, "CodingTool.TestRun");
    assert.ok(sdkTestEvent.artifactRefs.includes(spilloverArtifactId));
    const sdkDiagnosticsEvent = sdkEvents.find((event) => event.id === reactFlowDiagnostics.event_id);
    assert.ok(sdkDiagnosticsEvent);
    assert.equal(sdkDiagnosticsEvent.toolName, "lsp.diagnostics");
    assert.equal(sdkDiagnosticsEvent.sourceEventKind, "CodingTool.LspDiagnostics");
    const sdkAutoDiagnosticsEvent = sdkEvents.find((event) => event.id === autoDiagnostics.event_id);
    assert.ok(sdkAutoDiagnosticsEvent);
    assert.equal(sdkAutoDiagnosticsEvent.toolName, "lsp.diagnostics");
    assert.equal(sdkAutoDiagnosticsEvent.source, "runtime_auto");
    assert.equal(sdkAutoDiagnosticsEvent.sourceEventKind, "CodingTool.LspDiagnostics");
    const sdkDiagnosticsInjectionEvent = sdkEvents.find((event) => event.id === diagnosticsInjection.event_id);
    assert.ok(sdkDiagnosticsInjectionEvent);
    assert.equal(sdkDiagnosticsInjectionEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsInjectionEvent.componentKind, "lsp_diagnostics");
    assert.equal(sdkDiagnosticsInjectionEvent.sourceEventKind, "LspDiagnostics.Injected");
    assert.deepEqual(sdkDiagnosticsInjectionEvent.receiptRefs, diagnosticsInjection.receipt_refs);
    const sdkBlockingDiagnosticsInjectionEvent = sdkEvents.find(
      (event) => event.id === blockingDiagnosticsInjection.event_id,
    );
    assert.ok(sdkBlockingDiagnosticsInjectionEvent);
    assert.deepEqual(sdkBlockingDiagnosticsInjectionEvent.rollbackRefs, blockingDiagnosticsInjection.rollback_refs);
    assert.deepEqual(
      sdkBlockingDiagnosticsInjectionEvent.payload?.workspace_snapshot_refs,
      blockingDiagnosticsInjection.payload_summary.workspace_snapshot_refs,
    );
    const sdkDiagnosticsGateEvent = sdkEvents.find((event) => event.id === diagnosticsBlockingGate.event_id);
    assert.ok(sdkDiagnosticsGateEvent);
    assert.equal(sdkDiagnosticsGateEvent.type, "policy_blocked");
    assert.equal(sdkDiagnosticsGateEvent.componentKind, "lsp_diagnostics_gate");
    assert.equal(sdkDiagnosticsGateEvent.source, "runtime_auto");
    assert.equal(sdkDiagnosticsGateEvent.sourceEventKind, "LspDiagnostics.BlockingGate");
    assert.equal(sdkDiagnosticsGateEvent.payloadSchemaVersion, "ioi.runtime.lsp-diagnostics-blocking-gate.v1");
    assert.deepEqual(sdkDiagnosticsGateEvent.policyDecisionRefs, diagnosticsBlockingGate.policy_decision_refs);
    assert.deepEqual(sdkDiagnosticsGateEvent.rollbackRefs, diagnosticsBlockingGate.rollback_refs);
    assert.deepEqual(
      sdkDiagnosticsGateEvent.payload?.workspace_snapshot_refs,
      diagnosticsBlockingGate.payload_summary.workspace_snapshot_refs,
    );
    const sdkWorkspaceSnapshotEvent = sdkEvents.find((event) => event.id === diagnosticSnapshotEvent.event_id);
    assert.ok(sdkWorkspaceSnapshotEvent);
    assert.equal(sdkWorkspaceSnapshotEvent.type, "runtime_step");
    assert.equal(sdkWorkspaceSnapshotEvent.componentKind, "workspace_snapshot");
    assert.equal(sdkWorkspaceSnapshotEvent.sourceEventKind, "WorkspaceSnapshot.Created");
    assert.deepEqual(sdkWorkspaceSnapshotEvent.rollbackRefs, diagnosticSnapshotEvent.rollback_refs);
    assert.deepEqual(sdkWorkspaceSnapshotEvent.artifactRefs, diagnosticSnapshotEvent.artifact_refs);
    const sdkRestorePreviewEvent = sdkEvents.find((event) => event.id === restorePreviewEvent.event_id);
    assert.ok(sdkRestorePreviewEvent);
    assert.equal(sdkRestorePreviewEvent.type, "runtime_step");
    assert.equal(sdkRestorePreviewEvent.componentKind, "restore_gate");
    assert.equal(sdkRestorePreviewEvent.sourceEventKind, "WorkspaceRestore.Previewed");
    assert.deepEqual(sdkRestorePreviewEvent.rollbackRefs, restorePreviewEvent.rollback_refs);
    assert.deepEqual(sdkRestorePreviewEvent.artifactRefs, restorePreviewEvent.artifact_refs);
    const sdkRestoreApplyEvent = sdkEvents.find((event) => event.id === restoreApplyEvent.event_id);
    assert.ok(sdkRestoreApplyEvent);
    assert.equal(sdkRestoreApplyEvent.type, "runtime_step");
    assert.equal(sdkRestoreApplyEvent.componentKind, "restore_gate");
	    assert.equal(sdkRestoreApplyEvent.sourceEventKind, "WorkspaceRestore.Applied");
	    assert.deepEqual(sdkRestoreApplyEvent.rollbackRefs, restoreApplyEvent.rollback_refs);
	    assert.deepEqual(sdkRestoreApplyEvent.artifactRefs, restoreApplyEvent.artifact_refs);
	    assert.deepEqual(sdkRestoreApplyEvent.policyDecisionRefs, restoreApplyEvent.policy_decision_refs);
    const sdkDiagnosticsRepairRetryEvent = sdkEvents.find(
      (event) => event.id === diagnosticsRepairRetryEvent.event_id,
    );
    assert.ok(sdkDiagnosticsRepairRetryEvent);
    assert.equal(sdkDiagnosticsRepairRetryEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsRepairRetryEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsRepairRetryEvent.componentKind, "lsp_diagnostics_repair_retry");
    assert.equal(sdkDiagnosticsRepairRetryEvent.sourceEventKind, "LspDiagnostics.RepairRetryTurnCreated");
    assert.equal(sdkDiagnosticsRepairRetryEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsRepairRetryEvent.rollbackRefs, diagnosticsRepairRetryEvent.rollback_refs);
    assert.deepEqual(sdkDiagnosticsRepairRetryEvent.policyDecisionRefs, diagnosticsRepairRetryEvent.policy_decision_refs);
    const sdkDiagnosticsRepairRetryDecisionEvent = sdkEvents.find(
      (event) => event.id === diagnosticsRepairRetryDecisionEvent.event_id,
    );
    assert.ok(sdkDiagnosticsRepairRetryDecisionEvent);
    assert.equal(sdkDiagnosticsRepairRetryDecisionEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsRepairRetryDecisionEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsRepairRetryDecisionEvent.componentKind, "lsp_diagnostics_repair");
    assert.equal(sdkDiagnosticsRepairRetryDecisionEvent.sourceEventKind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(sdkDiagnosticsRepairRetryDecisionEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsRepairRetryDecisionEvent.rollbackRefs, diagnosticsRepairRetryDecisionEvent.rollback_refs);
    const sdkDiagnosticsOperatorOverrideEvent = sdkEvents.find(
      (event) => event.id === diagnosticsOperatorOverrideEvent.event_id,
    );
    assert.ok(sdkDiagnosticsOperatorOverrideEvent);
    assert.equal(sdkDiagnosticsOperatorOverrideEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsOperatorOverrideEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsOperatorOverrideEvent.componentKind, "lsp_diagnostics_operator_override");
    assert.equal(sdkDiagnosticsOperatorOverrideEvent.sourceEventKind, "LspDiagnostics.OperatorOverrideExecuted");
    assert.equal(sdkDiagnosticsOperatorOverrideEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsOperatorOverrideEvent.rollbackRefs, diagnosticsOperatorOverrideEvent.rollback_refs);
    assert.deepEqual(sdkDiagnosticsOperatorOverrideEvent.policyDecisionRefs, diagnosticsOperatorOverrideEvent.policy_decision_refs);
    const sdkDiagnosticsOperatorOverrideDecisionEvent = sdkEvents.find(
      (event) => event.id === diagnosticsOperatorOverrideDecisionEvent.event_id,
    );
    assert.ok(sdkDiagnosticsOperatorOverrideDecisionEvent);
    assert.equal(sdkDiagnosticsOperatorOverrideDecisionEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsOperatorOverrideDecisionEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsOperatorOverrideDecisionEvent.componentKind, "lsp_diagnostics_repair");
    assert.equal(sdkDiagnosticsOperatorOverrideDecisionEvent.sourceEventKind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(sdkDiagnosticsOperatorOverrideDecisionEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsOperatorOverrideDecisionEvent.rollbackRefs, diagnosticsOperatorOverrideDecisionEvent.rollback_refs);
    const sdkDiagnosticsOperatorOverrideBlockedEvent = sdkEvents.find(
      (event) => event.id === diagnosticsOperatorOverrideBlockedEvent.event_id,
    );
    assert.ok(sdkDiagnosticsOperatorOverrideBlockedEvent);
    assert.equal(sdkDiagnosticsOperatorOverrideBlockedEvent.componentKind, "lsp_diagnostics_operator_override");
    assert.equal(sdkDiagnosticsOperatorOverrideBlockedEvent.status, "blocked");
    const sdkDiagnosticsOperatorOverrideApprovedEvent = sdkEvents.find(
      (event) => event.id === diagnosticsOperatorOverrideApprovedEvent.event_id,
    );
    assert.ok(sdkDiagnosticsOperatorOverrideApprovedEvent);
    assert.equal(sdkDiagnosticsOperatorOverrideApprovedEvent.componentKind, "lsp_diagnostics_operator_override");
    assert.equal(sdkDiagnosticsOperatorOverrideApprovedEvent.status, "completed");
	    const sdkDiagnosticsRepairRestorePreviewEvent = sdkEvents.find(
	      (event) => event.id === diagnosticsRepairRestorePreviewEvent.event_id,
	    );
    assert.ok(sdkDiagnosticsRepairRestorePreviewEvent);
    assert.equal(sdkDiagnosticsRepairRestorePreviewEvent.componentKind, "restore_gate");
    assert.equal(sdkDiagnosticsRepairRestorePreviewEvent.sourceEventKind, "WorkspaceRestore.Previewed");
    assert.deepEqual(sdkDiagnosticsRepairRestorePreviewEvent.rollbackRefs, diagnosticsRepairRestorePreviewEvent.rollback_refs);
    const sdkDiagnosticsRepairDecisionEvent = sdkEvents.find(
      (event) => event.id === diagnosticsRepairDecisionEvent.event_id,
    );
    assert.ok(sdkDiagnosticsRepairDecisionEvent);
    assert.equal(sdkDiagnosticsRepairDecisionEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsRepairDecisionEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsRepairDecisionEvent.componentKind, "lsp_diagnostics_repair");
    assert.equal(sdkDiagnosticsRepairDecisionEvent.sourceEventKind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(sdkDiagnosticsRepairDecisionEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsRepairDecisionEvent.rollbackRefs, diagnosticsRepairDecisionEvent.rollback_refs);
    const sdkDiagnosticsRepairRestoreApplyEvent = sdkEvents.find(
      (event) => event.id === diagnosticsRepairRestoreApplyEvent.event_id,
    );
    assert.ok(sdkDiagnosticsRepairRestoreApplyEvent);
    assert.equal(sdkDiagnosticsRepairRestoreApplyEvent.componentKind, "restore_gate");
    assert.equal(sdkDiagnosticsRepairRestoreApplyEvent.sourceEventKind, "WorkspaceRestore.Applied");
    assert.deepEqual(sdkDiagnosticsRepairRestoreApplyEvent.rollbackRefs, diagnosticsRepairRestoreApplyEvent.rollback_refs);
    assert.deepEqual(sdkDiagnosticsRepairRestoreApplyEvent.policyDecisionRefs, diagnosticsRepairRestoreApplyEvent.policy_decision_refs);
    const sdkDiagnosticsRepairApplyDecisionEvent = sdkEvents.find(
      (event) => event.id === diagnosticsRepairApplyDecisionEvent.event_id,
    );
    assert.ok(sdkDiagnosticsRepairApplyDecisionEvent);
    assert.equal(sdkDiagnosticsRepairApplyDecisionEvent.source, "react_flow");
    assert.equal(sdkDiagnosticsRepairApplyDecisionEvent.type, "runtime_step");
    assert.equal(sdkDiagnosticsRepairApplyDecisionEvent.componentKind, "lsp_diagnostics_repair");
    assert.equal(sdkDiagnosticsRepairApplyDecisionEvent.sourceEventKind, "LspDiagnostics.RepairDecisionExecuted");
    assert.equal(sdkDiagnosticsRepairApplyDecisionEvent.payloadSchemaVersion, "ioi.runtime.diagnostics-repair-decision-execution.v1");
    assert.deepEqual(sdkDiagnosticsRepairApplyDecisionEvent.rollbackRefs, diagnosticsRepairApplyDecisionEvent.rollback_refs);
    const sdkTuiRestorePreviewEvent = sdkEvents.find((event) => event.id === tuiRestorePreviewEvent.event_id);
    assert.ok(sdkTuiRestorePreviewEvent);
    assert.equal(sdkTuiRestorePreviewEvent.source, "runtime_auto");
    assert.equal(sdkTuiRestorePreviewEvent.componentKind, "restore_gate");
    assert.equal(sdkTuiRestorePreviewEvent.sourceEventKind, "WorkspaceRestore.Previewed");
    assert.deepEqual(sdkTuiRestorePreviewEvent.rollbackRefs, tuiRestorePreviewEvent.rollback_refs);
    const sdkTuiRestoreApplyEvent = sdkEvents.find((event) => event.id === tuiRestoreApplyEvent.event_id);
    assert.ok(sdkTuiRestoreApplyEvent);
    assert.equal(sdkTuiRestoreApplyEvent.source, "runtime_auto");
    assert.equal(sdkTuiRestoreApplyEvent.componentKind, "restore_gate");
    assert.equal(sdkTuiRestoreApplyEvent.sourceEventKind, "WorkspaceRestore.Applied");
    assert.deepEqual(sdkTuiRestoreApplyEvent.rollbackRefs, tuiRestoreApplyEvent.rollback_refs);
    const sdkArtifactReadEvent = sdkEvents.find((event) => event.id === reactFlowArtifactRead.event_id);
    assert.ok(sdkArtifactReadEvent);
    assert.equal(sdkArtifactReadEvent.toolName, "artifact.read");
    assert.equal(sdkArtifactReadEvent.sourceEventKind, "CodingTool.ArtifactRead");
    const sdkRetrieveEvent = sdkEvents.find((event) => event.id === reactFlowRetrieve.event_id);
    assert.ok(sdkRetrieveEvent);
    assert.equal(sdkRetrieveEvent.toolName, "tool.retrieve_result");
    assert.equal(sdkRetrieveEvent.sourceEventKind, "CodingTool.ToolRetrieveResult");

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const statusNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowStatus.event_id),
    );
    assert.ok(statusNode);
    assert.equal(statusNode.workflowNodeId, "workflow.coding.workspace.status");
    assert.equal(statusNode.componentKind, "coding_tool");
    assert.equal(statusNode.label, "Coding tool: workspace.status");
    assert.deepEqual(statusNode.receiptRefs, reactFlowStatus.receipt_refs);
    const patchNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowPatch.event_id),
    );
    assert.ok(patchNode);
    assert.equal(patchNode.workflowNodeId, "workflow.coding.file.apply_patch");
    assert.equal(patchNode.label, "Coding tool: file.apply_patch");
    assert.deepEqual(patchNode.receiptRefs, reactFlowPatch.receipt_refs);
    const testNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowTest.event_id),
    );
    assert.ok(testNode);
    assert.equal(testNode.workflowNodeId, "workflow.coding.test.run");
    assert.equal(testNode.label, "Coding tool: test.run");
    assert.deepEqual(testNode.receiptRefs, reactFlowTest.receipt_refs);
    assert.ok(testNode.artifactRefs.includes(spilloverArtifactId));
    const diagnosticsNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowDiagnostics.event_id),
    );
    assert.ok(diagnosticsNode);
    assert.equal(diagnosticsNode.workflowNodeId, "workflow.coding.lsp.diagnostics");
    assert.equal(diagnosticsNode.label, "Coding tool: lsp.diagnostics");
    assert.deepEqual(diagnosticsNode.receiptRefs, reactFlowDiagnostics.receipt_refs);
    const autoDiagnosticsNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(autoDiagnostics.event_id),
    );
    assert.ok(autoDiagnosticsNode);
    assert.equal(autoDiagnosticsNode.workflowNodeId, "runtime.coding-tool.lsp-diagnostics.auto");
    assert.equal(autoDiagnosticsNode.label, "Coding tool: lsp.diagnostics");
    const diagnosticsInjectionNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsInjection.event_id),
    );
    assert.ok(diagnosticsInjectionNode);
    assert.equal(diagnosticsInjectionNode.workflowNodeId, "runtime.lsp-diagnostics.injected");
    assert.equal(diagnosticsInjectionNode.componentKind, "lsp_diagnostics");
    assert.equal(diagnosticsInjectionNode.label, "Diagnostics injected");
    for (const receiptRef of diagnosticsInjection.receipt_refs) {
      assert.ok(diagnosticsInjectionNode.receiptRefs.includes(receiptRef));
    }
    const diagnosticsGateNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsBlockingGate.event_id),
    );
    assert.ok(diagnosticsGateNode);
    assert.equal(diagnosticsGateNode.workflowNodeId, "runtime.lsp-diagnostics.blocking-gate");
    assert.equal(diagnosticsGateNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsGateNode.componentKind, "lsp_diagnostics_gate");
    assert.equal(diagnosticsGateNode.label, "Diagnostics blocking gate");
    assert.equal(diagnosticsGateNode.status, "blocked");
    for (const receiptRef of diagnosticsBlockingGate.receipt_refs) {
      assert.ok(diagnosticsGateNode.receiptRefs.includes(receiptRef));
    }
    for (const policyDecisionRef of diagnosticsBlockingGate.policy_decision_refs) {
      assert.ok(diagnosticsGateNode.policyDecisionRefs.includes(policyDecisionRef));
    }
    for (const rollbackRef of diagnosticsBlockingGate.rollback_refs) {
      assert.ok(diagnosticsGateNode.rollbackRefs.includes(rollbackRef));
    }
    const workspaceSnapshotNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticSnapshotEvent.event_id),
    );
    assert.ok(workspaceSnapshotNode);
    assert.equal(workspaceSnapshotNode.workflowNodeId, "runtime.workspace-snapshot");
    assert.equal(workspaceSnapshotNode.nodeKind, "quality_ledger");
    assert.equal(workspaceSnapshotNode.componentKind, "workspace_snapshot");
    assert.equal(workspaceSnapshotNode.label, "Workspace snapshot");
    for (const rollbackRef of diagnosticSnapshotEvent.rollback_refs) {
      assert.ok(workspaceSnapshotNode.rollbackRefs.includes(rollbackRef));
    }
    for (const receiptRef of diagnosticSnapshotEvent.receipt_refs) {
      assert.ok(workspaceSnapshotNode.receiptRefs.includes(receiptRef));
    }
    for (const artifactRef of diagnosticSnapshotEvent.artifact_refs) {
      assert.ok(workspaceSnapshotNode.artifactRefs.includes(artifactRef));
    }
    const restorePreviewNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(restorePreviewEvent.event_id),
    );
    assert.ok(restorePreviewNode);
    assert.equal(restorePreviewNode.workflowNodeId, "workflow.restore.preview");
    assert.equal(restorePreviewNode.nodeKind, "hook_policy");
    assert.equal(restorePreviewNode.componentKind, "restore_gate");
    assert.equal(restorePreviewNode.label, "Restore preview");
	    assert.equal(restorePreviewNode.status, "completed");
	    assert.deepEqual(restorePreviewNode.rollbackRefs, restorePreviewEvent.rollback_refs);
	    assert.deepEqual(restorePreviewNode.receiptRefs, restorePreviewEvent.receipt_refs);
	    assert.deepEqual(restorePreviewNode.artifactRefs, restorePreviewEvent.artifact_refs);
    const diagnosticsRepairRetryNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsRepairRetryEvent.event_id),
    );
    assert.ok(diagnosticsRepairRetryNode);
    assert.equal(diagnosticsRepairRetryNode.workflowNodeId, "workflow.diagnostics.repair.retry");
    assert.equal(diagnosticsRepairRetryNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairRetryNode.componentKind, "lsp_diagnostics_repair_retry");
    assert.equal(diagnosticsRepairRetryNode.label, "Diagnostics repair retry");
    assert.equal(diagnosticsRepairRetryNode.status, "completed");
    assert.deepEqual(diagnosticsRepairRetryNode.rollbackRefs, diagnosticsRepairRetryEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairRetryNode.receiptRefs, diagnosticsRepairRetryEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairRetryNode.policyDecisionRefs, diagnosticsRepairRetryEvent.policy_decision_refs);
    const diagnosticsRepairRetryDecisionNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsRepairRetryDecisionEvent.event_id),
    );
    assert.ok(diagnosticsRepairRetryDecisionNode);
    assert.equal(diagnosticsRepairRetryDecisionNode.workflowNodeId, "workflow.diagnostics.repair.retry.decision");
    assert.equal(diagnosticsRepairRetryDecisionNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairRetryDecisionNode.componentKind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairRetryDecisionNode.label, "Diagnostics repair decision");
    assert.equal(diagnosticsRepairRetryDecisionNode.status, "completed");
    assert.deepEqual(diagnosticsRepairRetryDecisionNode.rollbackRefs, diagnosticsRepairRetryDecisionEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairRetryDecisionNode.receiptRefs, diagnosticsRepairRetryDecisionEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairRetryDecisionNode.policyDecisionRefs, diagnosticsRepairRetryDecisionEvent.policy_decision_refs);
    const diagnosticsOperatorOverrideNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsOperatorOverrideEvent.event_id),
    );
    assert.ok(diagnosticsOperatorOverrideNode);
    assert.equal(diagnosticsOperatorOverrideNode.workflowNodeId, "workflow.diagnostics.repair.operator-override");
    assert.equal(diagnosticsOperatorOverrideNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsOperatorOverrideNode.componentKind, "lsp_diagnostics_operator_override");
    assert.equal(diagnosticsOperatorOverrideNode.label, "Diagnostics operator override");
    assert.equal(diagnosticsOperatorOverrideNode.status, "completed");
    assert.deepEqual(diagnosticsOperatorOverrideNode.rollbackRefs, diagnosticsOperatorOverrideEvent.rollback_refs);
    assert.deepEqual(diagnosticsOperatorOverrideNode.receiptRefs, diagnosticsOperatorOverrideEvent.receipt_refs);
    assert.deepEqual(diagnosticsOperatorOverrideNode.policyDecisionRefs, diagnosticsOperatorOverrideEvent.policy_decision_refs);
    const diagnosticsOperatorOverrideDecisionNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsOperatorOverrideDecisionEvent.event_id),
    );
    assert.ok(diagnosticsOperatorOverrideDecisionNode);
    assert.equal(diagnosticsOperatorOverrideDecisionNode.workflowNodeId, "workflow.diagnostics.repair.operator-override.decision");
    assert.equal(diagnosticsOperatorOverrideDecisionNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsOperatorOverrideDecisionNode.componentKind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsOperatorOverrideDecisionNode.label, "Diagnostics repair decision");
    assert.equal(diagnosticsOperatorOverrideDecisionNode.status, "completed");
    assert.deepEqual(diagnosticsOperatorOverrideDecisionNode.rollbackRefs, diagnosticsOperatorOverrideDecisionEvent.rollback_refs);
    assert.deepEqual(diagnosticsOperatorOverrideDecisionNode.receiptRefs, diagnosticsOperatorOverrideDecisionEvent.receipt_refs);
    assert.deepEqual(diagnosticsOperatorOverrideDecisionNode.policyDecisionRefs, diagnosticsOperatorOverrideDecisionEvent.policy_decision_refs);
    const diagnosticsOperatorOverrideRequiredNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsOperatorOverrideApprovedEvent.event_id),
    );
    assert.ok(diagnosticsOperatorOverrideRequiredNode);
    assert.equal(diagnosticsOperatorOverrideRequiredNode.workflowNodeId, "workflow.diagnostics.repair.operator-override.required");
    assert.equal(diagnosticsOperatorOverrideRequiredNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsOperatorOverrideRequiredNode.componentKind, "lsp_diagnostics_operator_override");
    assert.equal(diagnosticsOperatorOverrideRequiredNode.label, "Diagnostics operator override");
    assert.equal(diagnosticsOperatorOverrideRequiredNode.status, "completed");
	    const diagnosticsRepairRestorePreviewNode = reactFlowProjection.nodes.find((node) =>
	      node.eventIds.includes(diagnosticsRepairRestorePreviewEvent.event_id),
	    );
    assert.ok(diagnosticsRepairRestorePreviewNode);
    assert.equal(diagnosticsRepairRestorePreviewNode.workflowNodeId, "workflow.diagnostics.repair.restore-preview");
    assert.equal(diagnosticsRepairRestorePreviewNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairRestorePreviewNode.componentKind, "restore_gate");
    assert.equal(diagnosticsRepairRestorePreviewNode.label, "Restore preview");
    assert.equal(diagnosticsRepairRestorePreviewNode.status, "completed");
    assert.deepEqual(diagnosticsRepairRestorePreviewNode.rollbackRefs, diagnosticsRepairRestorePreviewEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairRestorePreviewNode.receiptRefs, diagnosticsRepairRestorePreviewEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairRestorePreviewNode.artifactRefs, diagnosticsRepairRestorePreviewEvent.artifact_refs);
    const diagnosticsRepairDecisionNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsRepairDecisionEvent.event_id),
    );
    assert.ok(diagnosticsRepairDecisionNode);
    assert.equal(diagnosticsRepairDecisionNode.workflowNodeId, "workflow.diagnostics.repair.restore-preview.decision");
    assert.equal(diagnosticsRepairDecisionNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairDecisionNode.componentKind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairDecisionNode.label, "Diagnostics repair decision");
    assert.equal(diagnosticsRepairDecisionNode.status, "completed");
    assert.deepEqual(diagnosticsRepairDecisionNode.rollbackRefs, diagnosticsRepairDecisionEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairDecisionNode.receiptRefs, diagnosticsRepairDecisionEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairDecisionNode.policyDecisionRefs, diagnosticsRepairDecisionEvent.policy_decision_refs);
    const diagnosticsRepairRestoreApplyNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsRepairRestoreApplyEvent.event_id),
    );
    assert.ok(diagnosticsRepairRestoreApplyNode);
    assert.equal(diagnosticsRepairRestoreApplyNode.workflowNodeId, "workflow.diagnostics.repair.restore-apply");
    assert.equal(diagnosticsRepairRestoreApplyNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairRestoreApplyNode.componentKind, "restore_gate");
    assert.equal(diagnosticsRepairRestoreApplyNode.label, "Restore apply");
    assert.equal(diagnosticsRepairRestoreApplyNode.status, "completed");
    assert.deepEqual(diagnosticsRepairRestoreApplyNode.rollbackRefs, diagnosticsRepairRestoreApplyEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairRestoreApplyNode.receiptRefs, diagnosticsRepairRestoreApplyEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairRestoreApplyNode.artifactRefs, diagnosticsRepairRestoreApplyEvent.artifact_refs);
    const diagnosticsRepairApplyDecisionNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(diagnosticsRepairApplyDecisionEvent.event_id),
    );
    assert.ok(diagnosticsRepairApplyDecisionNode);
    assert.equal(diagnosticsRepairApplyDecisionNode.workflowNodeId, "workflow.diagnostics.repair.restore-apply.decision");
    assert.equal(diagnosticsRepairApplyDecisionNode.nodeKind, "hook_policy");
    assert.equal(diagnosticsRepairApplyDecisionNode.componentKind, "lsp_diagnostics_repair");
    assert.equal(diagnosticsRepairApplyDecisionNode.label, "Diagnostics repair decision");
    assert.equal(diagnosticsRepairApplyDecisionNode.status, "completed");
    assert.deepEqual(diagnosticsRepairApplyDecisionNode.rollbackRefs, diagnosticsRepairApplyDecisionEvent.rollback_refs);
    assert.deepEqual(diagnosticsRepairApplyDecisionNode.receiptRefs, diagnosticsRepairApplyDecisionEvent.receipt_refs);
    assert.deepEqual(diagnosticsRepairApplyDecisionNode.policyDecisionRefs, diagnosticsRepairApplyDecisionEvent.policy_decision_refs);
    const restoreApplyNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(restoreApplyEvent.event_id),
    );
    assert.ok(restoreApplyNode);
    assert.equal(restoreApplyNode.workflowNodeId, "workflow.restore.apply");
    assert.equal(restoreApplyNode.nodeKind, "hook_policy");
    assert.equal(restoreApplyNode.componentKind, "restore_gate");
    assert.equal(restoreApplyNode.label, "Restore apply");
    assert.equal(restoreApplyNode.status, "completed");
    assert.deepEqual(restoreApplyNode.rollbackRefs, restoreApplyEvent.rollback_refs);
    assert.deepEqual(restoreApplyNode.receiptRefs, restoreApplyEvent.receipt_refs);
    assert.deepEqual(restoreApplyNode.artifactRefs, restoreApplyEvent.artifact_refs);
    const tuiRestorePreviewNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(tuiRestorePreviewEvent.event_id),
    );
    assert.ok(tuiRestorePreviewNode);
    assert.equal(tuiRestorePreviewNode.workflowNodeId, "runtime.restore-gate.tui-preview");
    assert.equal(tuiRestorePreviewNode.nodeKind, "hook_policy");
    assert.equal(tuiRestorePreviewNode.componentKind, "restore_gate");
    assert.equal(tuiRestorePreviewNode.label, "Restore preview");
    assert.equal(tuiRestorePreviewNode.status, "completed");
    assert.deepEqual(tuiRestorePreviewNode.rollbackRefs, tuiRestorePreviewEvent.rollback_refs);
    const tuiRestoreApplyNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(tuiRestoreApplyEvent.event_id),
    );
    assert.ok(tuiRestoreApplyNode);
    assert.equal(tuiRestoreApplyNode.workflowNodeId, "runtime.restore-gate.tui-apply");
    assert.equal(tuiRestoreApplyNode.nodeKind, "hook_policy");
    assert.equal(tuiRestoreApplyNode.componentKind, "restore_gate");
    assert.equal(tuiRestoreApplyNode.label, "Restore apply");
    assert.equal(tuiRestoreApplyNode.status, "completed");
    assert.deepEqual(tuiRestoreApplyNode.rollbackRefs, tuiRestoreApplyEvent.rollback_refs);
    const retrieveNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowRetrieve.event_id),
    );
    assert.ok(retrieveNode);
    assert.equal(retrieveNode.workflowNodeId, "workflow.coding.tool.retrieve_result");
    assert.equal(retrieveNode.label, "Coding tool: tool.retrieve_result");
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow run-inspector diagnostics repair action recovers a blocked diagnostics turn through daemon and TUI replay", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeDiagnosticsRepairControlRequest,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-diagnostics-repair-row-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-diagnostics-repair-row-state-"));
  const cli = cliBinary();
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "runtime@example.test"]);
  git(cwd, ["config", "user.name", "Runtime Test"]);
  fs.writeFileSync(path.join(cwd, "run-inspector-target.mjs"), "export const runInspector = 1;\n");
  git(cwd, ["add", "run-inspector-target.mjs"]);
  git(cwd, ["commit", "-m", "seed run inspector diagnostics workspace"]);

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Prove a React Flow run-inspector diagnostics repair row can recover a blocked turn.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const diagnosticPatch = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-diagnostics-row-proof",
          workflow_node_id: "workflow.coding.file.apply_patch.run-inspector-diagnostics",
          toolPack: {
            coding: {
              restorePolicy: "preview_only",
              restoreConflictPolicy: "require_approval",
              diagnosticsRepairDefault: "operator_override",
              operatorOverrideRequiresApproval: true,
            },
          },
          input: {
            path: "run-inspector-target.mjs",
            oldText: "export const runInspector = 1;",
            newText: "export const runInspector = ;",
          },
        }),
      },
    );
    assert.equal(diagnosticPatch.status, "completed");
    assert.equal(diagnosticPatch.auto_diagnostics?.result.diagnosticStatus, "findings");
    assert.deepEqual(diagnosticPatch.auto_diagnostics?.rollback_refs, [
      diagnosticPatch.workspace_snapshot?.snapshotId,
    ]);
    const blockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        message: "Continue after run-inspector diagnostics.",
        diagnosticsMode: "blocking",
      }),
    });
    assert.equal(blockedTurn.status, "waiting_for_input");
    assert.equal(blockedTurn.stop_reason, "blocked_by_post_edit_diagnostics");
    const blockedTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${blockedTurn.request_id}/trace`);
    const traceOverrideDecision = blockedTrace.diagnosticsFeedback?.repairPolicy?.decisions.find(
      (decision) => decision.action === "operator_override",
    );
    assert.ok(traceOverrideDecision);
    assert.equal(traceOverrideDecision.status, "requires_approval");
    assert.deepEqual(blockedTrace.diagnosticsFeedback?.rollbackRefs, [
      diagnosticPatch.workspace_snapshot?.snapshotId,
    ]);

    const sdkThreadBefore = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEventsBefore = await collect(sdkThreadBefore.events({ sinceSeq: 0 }));
    const diagnosticsGateEvent = sdkEventsBefore.find(
      (event) =>
        event.type === "policy_blocked" &&
        event.componentKind === "lsp_diagnostics_gate" &&
        event.rollbackRefs.includes(diagnosticPatch.workspace_snapshot?.snapshotId),
    );
    assert.ok(diagnosticsGateEvent);
    const projectionBefore = projectRuntimeThreadEventsToWorkflowProjection(sdkEventsBefore);
    const diagnosticsGateNode = projectionBefore.nodes.find((node) =>
      node.eventIds.includes(diagnosticsGateEvent.id),
    );
    assert.ok(diagnosticsGateNode);
    assert.equal(diagnosticsGateNode.workflowNodeId, "runtime.lsp-diagnostics.blocking-gate");
    assert.equal(diagnosticsGateNode.componentKind, "lsp_diagnostics_gate");
    assert.equal(diagnosticsGateNode.status, "blocked");
    const overrideAction = diagnosticsGateNode.diagnosticsRepairActions.find(
      (action) => action.action === "operator_override",
    );
    assert.ok(overrideAction);
    assert.equal(overrideAction.executable, true);
    assert.equal(overrideAction.requiresApproval, true);
    assert.equal(overrideAction.threadId, thread.thread_id);
    assert.equal(overrideAction.eventId, diagnosticsGateEvent.id);
    assert.equal(overrideAction.decisionId, traceOverrideDecision.decisionId);
    assert.equal(
      overrideAction.workflowNodeId,
      "runtime.run-inspector.diagnostics-repair.operator-override",
    );
    assert.ok(overrideAction.rollbackRefs.includes(diagnosticPatch.workspace_snapshot?.snapshotId));

    const repairRequest = createRuntimeDiagnosticsRepairControlRequest({
      nodeId: overrideAction.id,
      threadId: overrideAction.threadId,
      decisionId: overrideAction.decisionId,
      action: overrideAction.action,
      message: overrideAction.summary ?? "Run inspector diagnostics recovery proof.",
      approvalGranted: overrideAction.approvalGranted,
      allowConflicts: overrideAction.allowConflicts,
      workflowGraphId: overrideAction.workflowGraphId ?? "workflow-diagnostics-row-proof",
      workflowNodeId: overrideAction.workflowNodeId,
      actor: "operator",
    });
    assert.equal(repairRequest.nodeType, "runtime_diagnostics_repair");
    assert.equal(repairRequest.body.source, "react_flow");
    assert.equal(repairRequest.body.action, "operator_override");
    assert.equal(repairRequest.body.approvalGranted, true);
    assert.equal(
      repairRequest.body.workflowNodeId,
      "runtime.run-inspector.diagnostics-repair.operator-override",
    );
    const repairExecution = await fetchJson(`${daemon.endpoint}${repairRequest.endpoint}`, {
      method: "POST",
      body: JSON.stringify(repairRequest.body),
    });
    assert.equal(repairExecution.action, "operator_override");
    assert.equal(repairExecution.status, "completed");
    assert.equal(repairExecution.snapshotId, diagnosticPatch.workspace_snapshot?.snapshotId);
    assert.equal(repairExecution.operatorOverride?.approvalRequired, true);
    assert.equal(repairExecution.operatorOverride?.approvalSatisfied, true);
    assert.equal(repairExecution.operatorOverride?.continuationAllowed, true);
    assert.equal(
      repairExecution.operatorOverrideEvent?.workflow_node_id,
      "runtime.run-inspector.diagnostics-repair.operator-override",
    );
    assert.equal(
      repairExecution.event?.workflow_node_id,
      "runtime.run-inspector.diagnostics-repair.operator-override.decision",
    );
    const unblockedTurn = await sdkClient.getTurn(thread.thread_id, blockedTurn.turn_id);
    assert.equal(unblockedTurn.status, "completed");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const operatorOverrideEvent = daemonEvents.find(
      (event) => event.event_id === repairExecution.operatorOverrideEvent?.event_id,
    );
    assert.ok(operatorOverrideEvent);
    assert.equal(operatorOverrideEvent.source, "react_flow");
    assert.equal(operatorOverrideEvent.event_kind, "diagnostics.operator_override.executed");
    assert.equal(operatorOverrideEvent.component_kind, "lsp_diagnostics_operator_override");
    assert.equal(
      operatorOverrideEvent.workflow_node_id,
      "runtime.run-inspector.diagnostics-repair.operator-override",
    );
    assert.equal(operatorOverrideEvent.payload_summary.approval_required, true);
    assert.equal(operatorOverrideEvent.payload_summary.approval_satisfied, true);
    assert.deepEqual(operatorOverrideEvent.rollback_refs, [diagnosticPatch.workspace_snapshot?.snapshotId]);
    const decisionEvent = daemonEvents.find((event) => event.event_id === repairExecution.event?.event_id);
    assert.ok(decisionEvent);
    assert.equal(decisionEvent.source, "react_flow");
    assert.equal(decisionEvent.event_kind, "diagnostics.repair_decision.executed");
    assert.equal(decisionEvent.component_kind, "lsp_diagnostics_repair");
    assert.equal(
      decisionEvent.workflow_node_id,
      "runtime.run-inspector.diagnostics-repair.operator-override.decision",
    );
    assert.equal(
      decisionEvent.payload_summary.operator_override_event_id,
      operatorOverrideEvent.event_id,
    );

    const sdkThreadAfter = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEventsAfter = await collect(sdkThreadAfter.events({ sinceSeq: 0 }));
    const sdkDecisionEvent = sdkEventsAfter.find((event) => event.id === decisionEvent.event_id);
    assert.ok(sdkDecisionEvent);
    assert.equal(sdkDecisionEvent.componentKind, "lsp_diagnostics_repair");
    assert.equal(sdkDecisionEvent.workflowNodeId, decisionEvent.workflow_node_id);
    const projectionAfter = projectRuntimeThreadEventsToWorkflowProjection(sdkEventsAfter);
    const decisionNode = projectionAfter.nodes.find((node) =>
      node.eventIds.includes(decisionEvent.event_id),
    );
    assert.ok(decisionNode);
    assert.equal(
      decisionNode.workflowNodeId,
      "runtime.run-inspector.diagnostics-repair.operator-override.decision",
    );
    assert.equal(decisionNode.componentKind, "lsp_diagnostics_repair");
    assert.equal(decisionNode.status, "completed");
    assert.deepEqual(decisionNode.rollbackRefs, decisionEvent.rollback_refs);
    assert.equal(decisionNode.tuiDeepLink.threadId, thread.thread_id);
    assert.equal(decisionNode.tuiDeepLink.eventId, decisionEvent.event_id);
    assert.deepEqual(decisionNode.tuiDeepLink.args, [
      "agent",
      "tui",
      "--thread-id",
      thread.thread_id,
      "--since-seq",
      String(decisionEvent.seq),
    ]);

    const tuiReplay = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        String(Math.max(0, Number(decisionEvent.seq) - 1)),
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const tuiReplayPayload = JSON.parse(tuiReplay.stdout);
    assert.equal(tuiReplayPayload.schema_version, "ioi.agent-cli.tui.v1");
    assert.equal(tuiReplayPayload.thread.thread_id, thread.thread_id);
    assert.ok(tuiReplayPayload.events.some((event) => event.event_id === decisionEvent.event_id));
    assert.ok(
      tuiReplayPayload.event_rows.some(
        (row) =>
          row.event_id === decisionEvent.event_id &&
          row.react_flow?.workflow_node_id === decisionEvent.workflow_node_id,
      ),
    );
  } finally {
    if (daemon) await daemon.close();
  }
});

test("agent TUI thin shell starts a live thread, replays by cursor, and controls through daemon endpoints", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-tui";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const result = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove the thin terminal UI uses the live daemon runtime.",
        "--message",
        "Render canonical events and then accept an operator interrupt.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--interrupt",
        "--reason",
        "tui validation interrupt",
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.schema_version, "ioi.agent-cli.tui.v1");
    assert.equal(payload.surface, "tui");
    assert.equal(payload.private_runtime_loop, false);
    assert.ok(payload.thread.thread_id);
    assert.ok(payload.submitted_turn.turn_id);
    assert.equal(payload.control.status, "interrupted");
    assert.equal(payload.control.stop_reason, "operator_interrupt");
    assert.match(payload.event_route, new RegExp(`/v1/threads/${payload.thread.thread_id}/events\\?since_seq=0`));
    assert.ok(payload.event_count >= 3);
    assert.ok(payload.job_count >= 1);
    assert.ok(payload.job_rows.some((row) => row.thread_id === payload.thread.thread_id));
    assert.ok(payload.run_lifecycle_rows.some((row) => row.run_id));
    assert.equal(payload.deep_links.job_row_count, payload.job_rows.length);
    assert.equal(payload.deep_links.run_lifecycle_row_count, payload.run_lifecycle_rows.length);
    assert.equal(payload.routes.job_list, "/v1/jobs");
    assert.equal(payload.routes.run_replay, "/v1/runs/{run_id}/replay");
    assert.ok(payload.workflow_node_ids.includes("runtime.operator-interrupt"));
    assert.equal(
      payload.tui_control_state.schema_version,
      "ioi.agent-cli.tui-control-state.v1",
    );
    assert.equal(payload.tui_control_state.thread_id, payload.thread.thread_id);
    assert.equal(payload.tui_control_state.current_turn_id, payload.submitted_turn.turn_id);
    assert.ok(payload.tui_control_state.last_cursor);
    assert.equal(payload.tui_control_state.validation_errors.length, 0);
    assert.deepEqual(
      payload.tui_control_state.command_history.map((entry) => entry.command),
      ["message", "interrupt"],
    );
    const tuiControlStateProjection =
      projectRuntimeTuiControlStateToWorkflowProjection(payload.tui_control_state);
    assert.equal(
      tuiControlStateProjection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(tuiControlStateProjection.currentTurnId, payload.submitted_turn.turn_id);
    assert.equal(tuiControlStateProjection.commandCount, 2);
    assert.equal(tuiControlStateProjection.validationErrorCount, 0);
    assert.ok(tuiControlStateProjection.jobCount >= 1);
    assert.ok(tuiControlStateProjection.runLifecycleCount >= 1);
    assert.ok(
      tuiControlStateProjection.rows.some(
        (row) =>
          row.rowKind === "command" &&
          row.command === "interrupt" &&
          row.reactFlowNodeId === "runtime.tui-control-state.command.interrupt",
      ),
    );
    assert.ok(
      tuiControlStateProjection.rows.some(
        (row) =>
          row.rowKind === "job" &&
          row.runId &&
          row.reactFlowNodeId === "runtime.runtime-job",
      ),
    );
    const interruptEvent = payload.events.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    const interruptRow = payload.event_rows.find(
      (row) => row.event_id === interruptEvent.event_id,
    );
    assert.ok(interruptRow);
    assert.equal(
      interruptRow.schema_version,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(interruptRow.thread_id, payload.thread.thread_id);
    assert.equal(interruptRow.turn_id, payload.submitted_turn.turn_id);
    assert.equal(interruptRow.workflow_node_id, "runtime.operator-interrupt");
    assert.equal(interruptRow.cursor, canonicalCursor);
    assert.deepEqual(interruptRow.tui_reopen.args, [
      "agent",
      "tui",
      "--thread-id",
      payload.thread.thread_id,
      "--since-seq",
      String(interruptEvent.seq),
    ]);
    assert.equal(interruptRow.tui_reopen.command, "ioi agent tui");
    assert.equal(interruptRow.tui_reopen.last_event_id, interruptEvent.event_id);
    assert.equal(interruptRow.react_flow.workflow_node_id, "runtime.operator-interrupt");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(payload.thread.thread_id, {
      substrateClient: sdkClient,
    });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterrupt = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterrupt);
    assert.equal(sdkInterrupt.cursor, canonicalCursor);
    assert.equal(sdkInterrupt.workflowNodeId, interruptRow.workflow_node_id);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.equal(
      reactFlowNode.tuiDeepLink.schemaVersion,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(reactFlowNode.tuiDeepLink.threadId, interruptRow.thread_id);
    assert.equal(reactFlowNode.tuiDeepLink.turnId, interruptRow.turn_id);
    assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, interruptRow.workflow_node_id);
    assert.equal(reactFlowNode.tuiDeepLink.eventId, interruptRow.event_id);
    assert.equal(reactFlowNode.tuiDeepLink.cursor, interruptRow.cursor);
    assert.deepEqual(reactFlowNode.tuiDeepLink.args, interruptRow.tui_reopen.args);

    const replay = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        payload.thread.thread_id,
        "--last-event-id",
        interruptEvent.event_id,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const replayPayload = JSON.parse(replay.stdout);
    assert.equal(replayPayload.schema_version, "ioi.agent-cli.tui.v1");
    assert.equal(replayPayload.thread.thread_id, payload.thread.thread_id);
    assert.equal(replayPayload.last_event_id, interruptEvent.event_id);
    assert.equal(replayPayload.event_count, 0);
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("agent TUI line-mode slash commands control daemon turns and keep React Flow identity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  fs.mkdirSync(path.join(cwd, ".cursor"), { recursive: true });
  fs.writeFileSync(
    path.join(cwd, ".cursor", "mcp.json"),
    JSON.stringify(
      {
        mcpServers: {
          search: {
            command: "node",
            args: [mcpStdioFixture],
            allowedTools: ["query"],
            env: { SEARCH_TOKEN: "vault://mcp/search/token" },
          },
        },
      },
      null,
      2,
    ),
  );
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-tui-line";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const scratchMcpConfig = JSON.stringify({
      command: "node",
      args: [mcpStdioFixture],
      allowedTools: ["query"],
    });
    const result = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove the line-mode terminal UI uses daemon controls.",
        "--message",
        "Render canonical events before line-mode slash commands.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      `/mode yolo\n/model auto route.native-local\n/thinking high\n/cost\n/context\n/mcp tools\n/mcp search query --server mcp.search --source-mode workspace --limit 2\n/mcp fetch mcp.search/query --source-mode workspace\n/mcp add scratch ${scratchMcpConfig}\n/mcp remove mcp.scratch\n/mcp disable mcp.search\n/mcp enable mcp.search\n/mcp invoke mcp.search query {"q":"line-mode"}\n/mcp validate\n/mcp servers --source-mode workspace\n/memory status\n/memory remember Line-mode memory write receipt.\n/memory validate\n/subagent spawn explore Inspect line-mode subagent route evidence --tool-pack coding --route route.native-local --output-contract SUMMARY,EVIDENCE,RECEIPTS --merge-policy evidence_only --cancel-inheritance propagate\n/subagents\n/subagent wait\n/subagent result\n/subagent input Add line-mode subagent input evidence.\n/subagent cancel line_mode_subagent_cancel\n/subagent resume Resume line-mode subagent evidence.\n/subagent assign implement --tool-pack coding-plus --merge-policy manual_review\n/subagent spawn verify Remain isolated from parent cancellation --cancel-inheritance isolate\n/subagent propagate line_mode_parent_cancel\n/jobs\n/job\n/run replay\n/interrupt line-mode validation interrupt\n/events 0\n/steer\n/quit\n`,
      { cwd: root, timeout: 60000 },
    );
    assert.match(result.stdout, /Line-mode commands: .*\/mode .*\/model .*\/thinking .*\/cost .*\/context .*\/mcp .*\/memory .*\/subagents .*\/subagent .*\/approvals .*\/approve \[approval_id\] \[reason\] .*\/reject \[approval_id\] \[reason\].*\/interrupt \[reason\] .*\/steer <guidance> .*\/jobs .*\/job .*\/run .*\/quit/);
    assert.match(result.stdout, /line_mode_command=mode/);
    assert.match(result.stdout, /line_mode_command=model/);
    assert.match(result.stdout, /line_mode_command=thinking/);
    assert.match(result.stdout, /line_mode_command=cost/);
    assert.match(result.stdout, /line_mode_command=context/);
    assert.match(result.stdout, /line_mode_command=mcp action=tools/);
    assert.match(result.stdout, /line_mode_command=mcp action=search source_mode=workspace/);
    assert.match(result.stdout, /line_mode_command=mcp action=fetch source_mode=workspace/);
    assert.match(result.stdout, /line_mode_command=mcp action=add/);
    assert.match(result.stdout, /line_mode_command=mcp action=remove/);
    assert.match(result.stdout, /line_mode_command=mcp action=disable/);
    assert.match(result.stdout, /line_mode_command=mcp action=enable/);
    assert.match(result.stdout, /line_mode_command=mcp action=invoke/);
    assert.match(result.stdout, /line_mode_command=mcp action=validate/);
    assert.match(result.stdout, /line_mode_command=mcp action=servers source_mode=workspace/);
    assert.match(result.stdout, /line_mode_command=memory action=status/);
    assert.match(result.stdout, /line_mode_command=memory action=remember/);
    assert.match(result.stdout, /line_mode_command=memory action=validate/);
    assert.match(result.stdout, /line_mode_command=subagent action=spawn/);
    assert.match(result.stdout, /line_mode_command=subagent action=list/);
    assert.match(result.stdout, /line_mode_command=subagent action=wait/);
    assert.match(result.stdout, /line_mode_command=subagent action=result/);
    assert.match(result.stdout, /line_mode_command=subagent action=input/);
    assert.match(result.stdout, /line_mode_command=subagent action=cancel/);
    assert.match(result.stdout, /line_mode_command=subagent action=resume/);
    assert.match(result.stdout, /line_mode_command=subagent action=assign/);
    assert.match(result.stdout, /line_mode_command=subagent action=propagate/);
    assert.match(result.stdout, /line_mode_command=jobs count=\d+/);
    assert.match(result.stdout, /line_mode_command=job action=inspect/);
    assert.match(result.stdout, /line_mode_command=run action=replay/);
    assert.match(result.stdout, /line_mode_command=interrupt/);
    assert.match(result.stdout, /line_mode_command=events/);
    assert.match(result.stdout, /line_mode_error=\/steer requires guidance text/);
    assert.match(result.stdout, /line_mode_command=quit/);
    assert.match(result.stdout, /OperatorControl\.Interrupt/);
    assert.match(result.stdout, /OperatorControl\.Thinking/);
    assert.match(result.stdout, /OperatorControl\.Mcp/);
    assert.match(result.stdout, /OperatorControl\.McpAdd/);
    assert.match(result.stdout, /OperatorControl\.McpRemove/);
    assert.match(result.stdout, /OperatorControl\.McpDisable/);
    assert.match(result.stdout, /OperatorControl\.McpEnable/);
    assert.match(result.stdout, /OperatorControl\.McpInvoke/);
    assert.match(result.stdout, /OperatorControl\.Memory/);
    assert.match(result.stdout, /OperatorControl\.MemoryWrite/);
    assert.match(result.stdout, /OperatorControl\.SubagentSpawn/);
    assert.match(result.stdout, /OperatorControl\.SubagentWait/);
    assert.match(result.stdout, /OperatorControl\.SubagentSendInput/);
    assert.match(result.stdout, /OperatorControl\.SubagentCancel/);
    assert.match(result.stdout, /OperatorControl\.SubagentResume/);
    assert.match(result.stdout, /OperatorControl\.SubagentAssign/);
    assert.match(result.stdout, /mcp_row kind=mcp_tool server=mcp\.search tool=query operation=search/);
    assert.match(result.stdout, /mcp_row kind=mcp_tool server=mcp\.search tool=query operation=fetch/);
    assert.match(result.stdout, /mcp_row kind=mcp_resource server=mcp\.search/);
    assert.match(result.stdout, /mcp_row kind=mcp_prompt server=mcp\.search/);
    assert.match(result.stdout, /cost_row kind=cost_status scope=thread/);
    assert.match(result.stdout, /context_row kind=context_budget status=/);
    assert.match(result.stdout, /context_row kind=compaction_policy status=/);
    assert.match(result.stdout, /usage_delta_row stage=completion_streamed/);
    assert.match(result.stdout, /context_pressure_row pressure=/);
    assert.match(result.stdout, /memory_row kind=memory_status/);
    assert.match(result.stdout, /memory_row kind=memory_record/);
    assert.match(result.stdout, /subagent_row subagent=agent_[^\s]+ role=explore status=completed operation=spawn/);
    assert.match(result.stdout, /subagent_row subagent=agent_[^\s]+ role=implement status=completed operation=assign/);
    assert.match(result.stdout, /subagent_row subagent=agent_[^\s]+ role=verify status=completed operation=spawn/);
    assert.match(result.stdout, /node=runtime\.operator-interrupt/);
    const threadId = result.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(threadId);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.payload?.reason === "line-mode validation interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    assert.ok(
      daemonEvents.some(
        (event) =>
          event.event_kind === "usage.delta" &&
          event.workflow_node_id === "runtime.usage-telemetry",
      ),
    );
    assert.ok(
      daemonEvents.some(
        (event) =>
          event.event_kind === "context.pressure_delta" &&
          event.workflow_node_id === "runtime.context-budget",
      ),
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(threadId, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterrupt = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterrupt);
    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    assert.equal(sdkInterrupt.cursor, canonicalCursor);
    assert.equal(sdkInterrupt.workflowNodeId, interruptEvent.workflow_node_id);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.equal(
      reactFlowNode.tuiDeepLink.schemaVersion,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(reactFlowNode.tuiDeepLink.threadId, threadId);
    assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, "runtime.operator-interrupt");
    assert.equal(reactFlowNode.tuiDeepLink.eventId, interruptEvent.event_id);
    assert.equal(reactFlowNode.tuiDeepLink.cursor, canonicalCursor);
    assert.deepEqual(reactFlowNode.tuiDeepLink.args, [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--since-seq",
      String(interruptEvent.seq),
    ]);

    const controlStates = result.stdout
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tui_control_state="))
      .map((line) => JSON.parse(line.replace(/^tui_control_state=/, "")));
    assert.ok(controlStates.length >= 4);
    const finalControlState = controlStates[controlStates.length - 1];
    assert.equal(
      finalControlState.schema_version,
      "ioi.agent-cli.tui-control-state.v1",
    );
    assert.equal(finalControlState.thread_id, threadId);
    assert.ok(finalControlState.current_turn_id);
    assert.ok(finalControlState.last_cursor);
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "mode" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "thinking" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "cost" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "context" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "mcp" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "memory" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "subagent" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "interrupt" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "events" && entry.status === "applied",
      ),
    );
    assert.ok(finalControlState.job_rows.some((row) => row.job_id));
    assert.ok(finalControlState.run_lifecycle_rows.some((row) => row.run_id));
    assert.ok(finalControlState.mcp_rows.some((row) => row.mcp_server_id === "mcp.search"));
    assert.ok(finalControlState.mcp_rows.some((row) => row.mcp_tool_name === "query"));
    assert.ok(finalControlState.mcp_rows.some((row) => row.row_kind === "mcp_resource"));
    assert.ok(finalControlState.mcp_rows.some((row) => row.row_kind === "mcp_prompt"));
    assert.ok(finalControlState.mcp_rows.some((row) => row.mcp_operation === "invoke"));
    assert.ok(finalControlState.cost_rows.some((row) => row.row_kind === "cost_status"));
    assert.ok(
      finalControlState.context_rows.some(
        (row) =>
          row.row_kind === "context_budget" &&
          row.workflow_node_id === "runtime.context-budget",
      ),
    );
    assert.ok(
      finalControlState.context_rows.some(
        (row) =>
          row.row_kind === "compaction_policy" &&
          row.workflow_node_id === "runtime.compaction-policy",
      ),
    );
    assert.ok(finalControlState.memory_rows.some((row) => row.row_kind === "memory_status"));
    assert.ok(finalControlState.memory_rows.some((row) => row.row_kind === "memory_policy"));
    assert.ok(finalControlState.memory_rows.some((row) => row.memory_operation === "write"));
    assert.ok(finalControlState.subagent_rows.some((row) => row.subagent_role === "implement"));
    assert.ok(
      finalControlState.subagent_rows.some(
        (row) =>
          row.subagent_role === "verify" &&
          row.subagent_cancellation_inheritance === "isolate",
      ),
    );
    assert.ok(
      finalControlState.validation_errors.some(
        (entry) =>
          entry.command === "steer" &&
          entry.message === "/steer requires guidance text",
      ),
    );
    const lineModeControlProjection =
      projectRuntimeTuiControlStateToWorkflowProjection(finalControlState);
    assert.equal(
      lineModeControlProjection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(lineModeControlProjection.threadId, threadId);
    assert.ok(lineModeControlProjection.jobCount >= 1);
    assert.ok(lineModeControlProjection.runLifecycleCount >= 1);
    assert.ok(lineModeControlProjection.mcpRowCount >= 2);
    assert.ok(lineModeControlProjection.memoryRowCount >= 2);
    assert.ok(lineModeControlProjection.costRowCount >= 1);
    assert.ok(lineModeControlProjection.contextRowCount >= 2);
    assert.ok(lineModeControlProjection.subagentRowCount >= 2);
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "model_route" && row.reactFlowNodeId === "runtime.model-router",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "thinking" && row.reasoningEffort === "high",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "mcp_tool" && row.mcpToolName === "query",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "cost_status" &&
          row.reactFlowNodeId === "runtime.usage-telemetry",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "context_budget" &&
          row.reactFlowNodeId === "runtime.context-budget",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "compaction_policy" &&
          row.reactFlowNodeId === "runtime.compaction-policy",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "mcp_tool" && row.mcpOperation === "invoke",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "memory_status" && row.reactFlowNodeId === "runtime.memory-manager",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) => row.rowKind === "memory_record" && row.memoryOperation === "write",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "subagent" &&
          row.subagentRole === "implement" &&
          row.subagentOutputContractStatus === "passed",
      ),
    );
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "validation_error" &&
          row.command === "steer" &&
          row.reactFlowNodeId === "runtime.tui-control-state.validation.steer",
      ),
    );
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("agent TUI approval slash commands emit receipt-backed React Flow rows", async () => {
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-approval-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-approval-state-"));
  const cli = cliBinary();
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Approve a daemon-backed TUI control.",
        source: "cli_tui",
        options: { local: { cwd } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Wait for a synthetic approval gate.",
        source: "cli_tui",
        mode: "tui",
      }),
    });
    daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: turn.turn_id,
      item_id: `${turn.turn_id}:item:approval-required`,
      idempotency_key: `${turn.turn_id}:approval.required:approval-live`,
      source: "daemon_bridge",
      source_event_kind: "KernelEvent::ApprovalRequired",
      event_kind: "approval.required",
      status: "waiting_for_approval",
      actor: "runtime",
      workspace_root: cwd,
      component_kind: "approval_gate",
      workflow_node_id: "runtime.approval.approval-live",
      approval_id: "approval-live",
      payload_schema_version: "ioi.runtime.approval-request.v1",
      payload: {
        event_kind: "KernelEvent::ApprovalRequired",
        approval_id: "approval-live",
        message: "Approve shell execution",
      },
      receipt_refs: ["receipt_approval_required"],
      policy_decision_refs: ["policy_approval_required"],
      artifact_refs: [],
      rollback_refs: [],
    });

    const result = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/approvals\n/approve approval-live proceed with validation\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    assert.match(result.stdout, /line_mode_command=approvals count=1/);
    assert.match(result.stdout, /line_mode_command=approve approval=approval-live status=/);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const decisionEvent = daemonEvents.find(
      (event) =>
        event.source_event_kind === "OperatorApproval.Approve" &&
        event.approval_id === "approval-live",
    );
    assert.ok(decisionEvent);
    assert.equal(decisionEvent.source, "cli_tui");
    assert.equal(decisionEvent.event_kind, "approval.approved");
    assert.equal(decisionEvent.component_kind, "approval_gate");
    assert.equal(decisionEvent.workflow_node_id, "runtime.approval.approval-live");
    assert.equal(decisionEvent.payload_schema_version, "ioi.runtime.approval-decision.v1");
    assert.ok(decisionEvent.receipt_refs.length > 0);
    assert.ok(decisionEvent.policy_decision_refs.length > 0);

    const controlStates = result.stdout
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tui_control_state="))
      .map((line) => JSON.parse(line.replace(/^tui_control_state=/, "")));
    const finalControlState = controlStates[controlStates.length - 1];
    assert.equal(finalControlState.mode_status.approval_mode, "suggest");
    assert.ok(
      finalControlState.approval_rows.some(
        (row) =>
          row.approval_id === "approval-live" &&
          row.workflow_node_id === "runtime.approval.approval-live",
      ),
    );
    assert.ok(
      finalControlState.approval_decisions.some(
        (row) =>
          row.approval_id === "approval-live" &&
          row.decision === "approve" &&
          row.receipt_refs.length > 0 &&
          row.policy_decision_refs.length > 0,
      ),
    );
    const projection =
      projectRuntimeTuiControlStateToWorkflowProjection(finalControlState);
    assert.equal(
      projection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(projection.approvalCount, 1);
    assert.equal(projection.approvalDecisionCount, 1);
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "approval_decision" &&
          row.status === "approved" &&
          row.reactFlowNodeId === "runtime.approval.approval-live" &&
          row.receiptRefs.length > 0,
      ),
    );
  } finally {
    if (daemon) await daemon.close();
  }
});

test("agent TUI coding-tool budget recovery slash commands use workflow recovery policy", async () => {
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-budget-recovery-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-budget-recovery-state-"));
  const cli = cliBinary();
  const workflowGraphId = "workflow.tui.coding-budget-recovery-proof";
  const workflowNodeId = "node-write";
  const approvalId = "approval-budget-recovery-live";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Recover a coding-tool budget block through TUI slash commands.",
        source: "cli_tui",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Wait for a synthetic coding-tool budget preflight block.",
        source: "cli_tui",
        mode: "tui",
      }),
    });
    const sourceEvent = daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: turn.turn_id,
      item_id: `${turn.turn_id}:item:coding-budget-preflight-blocked`,
      idempotency_key: `${turn.turn_id}:coding-budget-preflight-blocked`,
      source: "daemon_bridge",
      source_event_kind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "coding_tool",
      payload_schema_version: "ioi.workflow.coding-tool-budget-preflight.v1",
      payload: {
        eventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        reason: "coding_tool_budget_preflight_blocked",
        runId: turn.request_id,
        threadId: thread.thread_id,
        targetNodeIds: [workflowNodeId],
        budgetStatus: "exceeded",
        contextBudgetStatus: "blocked",
        mutationBlocked: true,
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          source: "cli_tui_live",
          approvalScope: "target_nodes",
          operatorRole: "budget_operator",
          retryLimit: 1,
          ttlMs: 300000,
          requiresApproval: true,
          allowOverride: true,
          targetNodeIds: [workflowNodeId],
          sourceNodeIds: [workflowNodeId],
        },
      },
      receipt_refs: ["receipt_budget_preflight_live"],
      policy_decision_refs: ["policy_budget_preflight_live"],
      artifact_refs: [],
      rollback_refs: [],
    });

    const result = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      `/run recovery request ${turn.request_id} ${approvalId}\n/run recovery approve ${turn.request_id} ${approvalId}\n/run recovery retry-approved ${turn.request_id} ${approvalId}\n/quit\n`,
      { cwd: root, timeout: 30000 },
    );
    assert.match(result.stdout, /\/run recovery \[request\|approve\|reject\|retry-approved\]/);
    assert.match(result.stdout, /line_mode_command=run action=recovery recovery_action=request_approval/);
    assert.match(result.stdout, /line_mode_command=run action=recovery recovery_action=approve_override/);
    assert.match(result.stdout, /line_mode_command=run action=recovery recovery_action=retry_approved/);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const approvalEvent = daemonEvents.find(
      (event) => event.event_kind === "approval.required" && event.approval_id === approvalId,
    );
    assert.ok(approvalEvent);
    assert.equal(approvalEvent.source, "cli_tui");
    assert.equal(
      approvalEvent.payload_summary.approval_manifest.recoveryPolicy.operatorRole,
      "budget_operator",
    );
    assert.equal(
      approvalEvent.payload_summary.approval_manifest.recoveryPolicy.retryLimit,
      1,
    );
    assert.equal(
      approvalEvent.payload_summary.approval_manifest.sourceEventId,
      sourceEvent.event_id,
    );
    const decisionEvent = daemonEvents.find(
      (event) => event.event_kind === "approval.approved" && event.approval_id === approvalId,
    );
    assert.ok(decisionEvent);
    assert.equal(decisionEvent.payload_summary.decision, "approve");
    const retryEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "workflow.run.retry_completed" &&
        event.approval_id === approvalId,
    );
    assert.ok(retryEvent);
    assert.equal(retryEvent.source_event_kind, "WorkflowRunCodingToolBudgetApprovedRetry");
    assert.equal(retryEvent.payload_summary.approvalDecisionEventId, decisionEvent.event_id);
    assert.equal(retryEvent.payload_summary.recoveryPolicy.operatorRole, "budget_operator");
    assert.equal(retryEvent.payload_summary.recoveryPolicy.retryLimit, 1);

    const finalControlState = result.stdout
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tui_control_state="))
      .map((line) => JSON.parse(line.replace(/^tui_control_state=/, "")))
      .at(-1);
    assert.ok(
      finalControlState.coding_tool_rows.some(
        (row) =>
          row.raw_input === `/run recovery request ${turn.request_id}` ||
          row.raw_input === `/run recovery request ${turn.request_id} ${approvalId}`,
      ),
    );

    const projectionEvents = daemonEvents.map((event) => ({
      id: event.event_id,
      seq: event.seq,
      type: event.event_kind === "approval.required"
        ? "approval_required"
        : event.event_kind === "approval.approved" || event.event_kind === "approval.rejected"
          ? "approval_decision"
          : event.event_kind === "workflow.run.retry_completed"
            ? "tool_completed"
            : event.event_kind === "policy.blocked"
              ? "policy_blocked"
              : event.event_kind,
      eventKind: event.event_kind,
      sourceEventKind: event.source_event_kind,
      status: event.status,
      componentKind: event.component_kind,
      workflowNodeId: event.workflow_node_id,
      workflowGraphId: event.workflow_graph_id,
      threadId: event.thread_id,
      turnId: event.turn_id,
      approvalId: event.approval_id,
      payloadSchemaVersion: event.payload_schema_version,
      payload: event.payload_summary ?? event.payload ?? {},
      receiptRefs: event.receipt_refs ?? [],
      policyDecisionRefs: event.policy_decision_refs ?? [],
    }));
    const projection = projectRuntimeThreadEventsToWorkflowProjection(projectionEvents);
    const node = [...projection.nodes].reverse().find(
      (candidate) =>
        candidate.workflowNodeId === workflowNodeId ||
        candidate.codingToolBudgetRecoveryActions?.length > 0,
    );
    assert.ok(node);
    assert.deepEqual(
      node.codingToolBudgetRecoveryActions.map((action) => [
        action.action,
        action.status,
        action.executable,
      ]),
      [
        ["review_receipt", "completed", false],
        ["request_approval", "completed", false],
        ["approve_override", "completed", false],
        ["reject_override", "blocked", false],
        ["retry_approved", "completed", false],
      ],
    );
    assert.equal(
      node.codingToolBudgetRecoveryActions[4].recoveryPolicy.operatorRole,
      "budget_operator",
    );
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow coding-tool budget recovery control node drives daemon recovery route", async () => {
  const {
    createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-budget-recovery-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-budget-recovery-state-"));
  const workflowGraphId = "workflow.react-flow.coding-budget-recovery-proof";
  const workflowNodeId = "runtime.coding-tool-budget-recovery";
  const targetNodeId = "workflow.coding.file.apply_patch";
  const approvalId = "approval-react-flow-budget-recovery-live";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Recover a coding-tool budget block from a React Flow authored control node.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Wait for a React Flow coding-tool budget recovery control proof.",
      }),
    });
    const blockedEvent = daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: turn.turn_id,
      item_id: `${turn.turn_id}:item:react-flow-budget-preflight-blocked`,
      idempotency_key: `${turn.turn_id}:react-flow-budget-preflight-blocked`,
      source: "daemon_bridge",
      source_event_kind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: targetNodeId,
      component_kind: "coding_tool",
      payload_schema_version: "ioi.workflow.coding-tool-budget-preflight.v1",
      payload: {
        eventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        reason: "coding_tool_budget_preflight_blocked",
        runId: turn.request_id,
        threadId: thread.thread_id,
        targetNodeIds: [targetNodeId],
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          source: "react_flow_live",
          approvalScope: "target_nodes",
          operatorRole: "budget_operator",
          retryLimit: 1,
          ttlMs: 300000,
          requiresApproval: true,
          allowOverride: true,
          targetNodeIds: [targetNodeId],
          sourceNodeIds: [targetNodeId],
        },
      },
      receipt_refs: ["receipt_budget_preflight_react_flow_live"],
      policy_decision_refs: ["policy_budget_preflight_react_flow_live"],
      artifact_refs: [],
      rollback_refs: [],
    });
    const workflowNode = {
      id: "react-flow-budget-recovery-control",
      type: "runtime_coding_tool_budget_recovery",
      config: {
        logic: {
          runtimeCodingToolBudgetRecoveryEndpoint:
            "/v1/runs/{runId}/coding-tool-budget-recovery",
          runtimeCodingToolBudgetRecoveryRunIdField: "runId",
          runtimeCodingToolBudgetRecoveryThreadIdField: "threadId",
          runtimeCodingToolBudgetRecoveryActionField: "action",
          runtimeCodingToolBudgetRecoveryApprovalIdField: "approvalId",
          runtimeCodingToolBudgetRecoverySourceEventIdField: "sourceEventId",
          runtimeCodingToolBudgetRecoveryTargetNodeIdsField: "targetNodeIds",
          runtimeCodingToolBudgetRecoveryPolicyInputField: "recoveryPolicy",
          runtimeCodingToolBudgetRecoveryWorkflowNodeId: workflowNodeId,
          runtimeCodingToolBudgetRecoveryActor: "operator",
        },
        law: { privilegedActions: ["runtime.coding-tool-budget.recover"] },
      },
    };
    const blockedPayload = blockedEvent.payload_summary ?? blockedEvent.payload ?? {};
    const baseInput = {
      runId: turn.request_id,
      threadId: thread.thread_id,
      approvalId,
      sourceEventId: blockedEvent.event_id,
      targetNodeIds: [targetNodeId],
      recoveryPolicy: blockedPayload.recoveryPolicy,
    };
    const requestApproval =
      createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
        workflowNode,
        { ...baseInput, action: "request_approval" },
        { workflowGraphId },
      );
    assert.equal(requestApproval.nodeType, "runtime_coding_tool_budget_recovery");
    assert.equal(requestApproval.body.workflowNodeId, workflowNodeId);
    const approvalResult = await fetchJson(`${daemon.endpoint}${requestApproval.endpoint}`, {
      method: "POST",
      body: JSON.stringify(requestApproval.body),
    });
    assert.equal(approvalResult.status, "waiting_for_approval");

    const approve = createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      workflowNode,
      { ...baseInput, action: "approve_override" },
      { workflowGraphId },
    );
    const approveResult = await fetchJson(`${daemon.endpoint}${approve.endpoint}`, {
      method: "POST",
      body: JSON.stringify(approve.body),
    });
    assert.equal(approveResult.status, "approved");

    const retry = createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      workflowNode,
      { ...baseInput, action: "retry_approved" },
      { workflowGraphId },
    );
    const retryResult = await fetchJson(`${daemon.endpoint}${retry.endpoint}`, {
      method: "POST",
      body: JSON.stringify(retry.body),
    });
    assert.equal(retryResult.status, "completed");
    assert.equal(retryResult.recoveryPolicy.operatorRole, "budget_operator");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const retryEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "workflow.run.retry_completed" &&
        event.approval_id === approvalId,
    );
    assert.ok(retryEvent);
    assert.equal(retryEvent.source, "react_flow");
    assert.equal(retryEvent.workflow_graph_id, workflowGraphId);
    assert.equal(retryEvent.workflow_node_id, workflowNodeId);
    const projection = projectRuntimeThreadEventsToWorkflowProjection(
      daemonEvents.map((event) => ({
        id: event.event_id,
        seq: event.seq,
        type: event.event_kind === "approval.required"
          ? "approval_required"
          : event.event_kind === "approval.approved"
            ? "approval_decision"
            : event.event_kind === "workflow.run.retry_completed"
              ? "tool_completed"
              : event.event_kind === "policy.blocked"
                ? "policy_blocked"
                : event.event_kind,
        eventKind: event.event_kind,
        sourceEventKind: event.source_event_kind,
        status: event.status,
        componentKind: event.component_kind,
        workflowNodeId: event.workflow_node_id,
        workflowGraphId: event.workflow_graph_id,
        threadId: event.thread_id,
        turnId: event.turn_id,
        approvalId: event.approval_id,
        payloadSchemaVersion: event.payload_schema_version,
        payload: event.payload_summary ?? event.payload ?? {},
        receiptRefs: event.receipt_refs ?? [],
        policyDecisionRefs: event.policy_decision_refs ?? [],
      })),
    );
    const node = projection.nodes.find((candidate) =>
      candidate.eventIds.includes(retryEvent.event_id),
    );
    assert.ok(node);
    assert.equal(node.workflowNodeId, workflowNodeId);
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow approval request control creates a daemon-owned approval gate", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeApprovalRequestControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-approval-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-approval-state-"));
  const workflowGraphId = "workflow.react-flow.approval-request-proof";
  const workflowNodeId = "runtime.approval.context-pressure";
  const approvalId = "approval-context-pressure-live";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Prove React Flow approval request controls create approval gates.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow approval-request validation.",
      }),
    });
    const workflowNode = {
      id: "react-flow-approval-request-control",
      type: "runtime_approval_request",
      config: {
        logic: {
          runtimeApprovalRequestEndpoint: "/v1/threads/{threadId}/approvals",
          runtimeApprovalRequestThreadIdField: "threadId",
          runtimeApprovalRequestTurnIdField: "turnId",
          runtimeApprovalRequestApprovalIdField: "approvalId",
          runtimeApprovalRequestReasonField: "reason",
          runtimeApprovalRequestScopeField: "scope",
          runtimeApprovalRequestPressureField: "pressure",
          runtimeApprovalRequestPressureStatusField: "pressureStatus",
          runtimeApprovalRequestAlertIdField: "alertId",
          runtimeApprovalRequestSourceEventIdField: "sourceEventId",
          runtimeApprovalRequestWorkflowNodeId: workflowNodeId,
          runtimeApprovalRequestActor: "operator",
        },
        law: { privilegedActions: ["runtime.approval.request"] },
      },
    };
    const control = createRuntimeApprovalRequestControlRequestFromWorkflowNode(
      workflowNode,
      {
        threadId: thread.thread_id,
        turnId: turn.turn_id,
        approvalId,
        reason: "request approval to continue at high context pressure",
        scope: "subagent_aggregate",
        pressure: 0.91,
        pressureStatus: "high",
        alertId: "event-context-pressure-alert-live",
        sourceEventId: "event-context-pressure-live",
        receiptRefs: ["receipt_context_pressure_alert_live"],
        policyDecisionRefs: ["policy_context_pressure_alert_compact_live"],
      },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_approval_request");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "approval_gate");

    const requested = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(requested.turn_id, turn.turn_id);
    assert.equal(requested.status, "waiting_for_approval");
    assert.equal(requested.approval_id, approvalId);
    assert.equal(requested.approval_required, true);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const approvalEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorApproval.Request" && event.source === "react_flow",
    );
    assert.ok(approvalEvent);
    assert.equal(approvalEvent.event_kind, "approval.required");
    assert.equal(approvalEvent.status, "waiting_for_approval");
    assert.equal(approvalEvent.actor, "user");
    assert.equal(approvalEvent.workflow_graph_id, workflowGraphId);
    assert.equal(approvalEvent.workflow_node_id, workflowNodeId);
    assert.equal(approvalEvent.component_kind, "approval_gate");
    assert.equal(approvalEvent.payload_schema_version, "ioi.runtime.approval-request.v1");
    assert.equal(approvalEvent.approval_id, approvalId);
    assert.ok(approvalEvent.payload.approval_required === true || approvalEvent.payload.approval_required === "true");
    assert.equal(approvalEvent.payload.scope, "subagent_aggregate");
    assert.equal(Number(approvalEvent.payload.pressure), 0.91);
    assert.equal(approvalEvent.payload.pressure_status, "high");
    assert.ok(approvalEvent.receipt_refs.includes("receipt_context_pressure_alert_live"));
    assert.ok(approvalEvent.policy_decision_refs.includes("policy_context_pressure_alert_compact_live"));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkApprovalEvent = sdkEvents.find((event) => event.id === approvalEvent.event_id);
    assert.ok(sdkApprovalEvent);
    assert.equal(sdkApprovalEvent.type, "approval_required");
    assert.equal(sdkApprovalEvent.sourceEventKind, "OperatorApproval.Request");
    assert.equal(sdkApprovalEvent.approvalId, approvalId);
    assert.equal(sdkApprovalEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkApprovalEvent.workflowNodeId, workflowNodeId);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const approvalNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(approvalEvent.event_id),
    );
    assert.ok(approvalNode);
    assert.equal(approvalNode.nodeKind, "human_gate");
    assert.equal(approvalNode.componentKind, "approval_gate");
    assert.equal(approvalNode.workflowNodeId, workflowNodeId);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow delegate-summary context-pressure action spawns a daemon-owned subagent", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeSubagentControlRequest,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-delegate-summary-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-delegate-summary-state-"));
  const workflowGraphId = "workflow.react-flow.delegate-summary-proof";
  const workflowNodeId = "runtime.subagent.delegate-summary";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Prove React Flow context-pressure delegate summaries spawn subagents.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow context-pressure delegate-summary validation.",
      }),
    });

    const control = createRuntimeSubagentControlRequest({
      nodeId: "react-flow-delegate-summary-action",
      operation: "spawn",
      threadId: thread.thread_id,
      parentTurnId: turn.turn_id,
      role: "review",
      prompt:
        "Summarize the current turn context under elevated pressure. Return SUMMARY, EVIDENCE, RISKS, BLOCKERS, and RECEIPTS.",
      forkContext: true,
      toolPack: "coding",
      outputContract: ["SUMMARY", "EVIDENCE", "RISKS", "BLOCKERS", "RECEIPTS"],
      mergePolicy: "evidence_only",
      cancellationInheritance: "isolate",
      contextPressureAction: "delegate_summary",
      pressure: 0.74,
      pressureStatus: "elevated",
      alertId: "event-context-pressure-alert-live",
      sourceEventId: "event-context-pressure-live",
      receiptRefs: ["receipt_context_pressure_alert_live"],
      policyDecisionRefs: ["policy_context_pressure_delegate_live"],
      workflowGraphId,
      workflowNodeId,
      actor: "operator",
    });
    assert.equal(control.nodeType, "runtime_subagent");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.contextPressureAction, "delegate_summary");
    assert.equal(control.body.cancellationInheritance, "isolate");

    const spawned = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: control.method,
      body: JSON.stringify(control.body),
    });
    assert.equal(spawned.object, "ioi.runtime_subagent");
    assert.equal(spawned.parent_thread_id, thread.thread_id);
    assert.equal(spawned.parent_turn_id, turn.turn_id);
    assert.equal(spawned.workflow_graph_id, workflowGraphId);
    assert.equal(spawned.workflow_node_id, workflowNodeId);
    assert.equal(spawned.role, "review");
    assert.equal(spawned.context_pressure_action, "delegate_summary");
    assert.equal(spawned.context_pressure, 0.74);
    assert.equal(spawned.pressure_status, "elevated");
    assert.equal(spawned.alert_id, "event-context-pressure-alert-live");
    assert.equal(spawned.source_event_id, "event-context-pressure-live");
    assert.equal(spawned.merge_policy, "evidence_only");
    assert.equal(spawned.cancellation_inheritance, "isolate");
    assert.ok(spawned.receipt_refs.includes("receipt_context_pressure_alert_live"));
    assert.ok(spawned.policy_decision_refs.includes("policy_context_pressure_delegate_live"));

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const spawnEvent = daemonEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.SubagentSpawn" &&
        event.workflow_node_id === workflowNodeId,
    );
    assert.ok(spawnEvent);
    assert.equal(spawnEvent.component_kind, "subagent_lifecycle");
    assert.equal(spawnEvent.payload_summary.context_pressure_action, "delegate_summary");
    assert.equal(spawnEvent.payload_summary.alert_id, "event-context-pressure-alert-live");
    assert.equal(spawnEvent.payload_summary.source_event_id, "event-context-pressure-live");
    assert.ok(spawnEvent.receipt_refs.includes("receipt_context_pressure_alert_live"));
    assert.ok(spawnEvent.policy_decision_refs.includes("policy_context_pressure_delegate_live"));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkSpawnEvent = sdkEvents.find((event) => event.id === spawnEvent.event_id);
    assert.ok(sdkSpawnEvent);
    assert.equal(sdkSpawnEvent.sourceEventKind, "OperatorControl.SubagentSpawn");
    assert.equal(sdkSpawnEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkSpawnEvent.workflowNodeId, workflowNodeId);
    assert.equal(sdkSpawnEvent.payload.contextPressureAction, "delegate_summary");

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const subagentNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(spawnEvent.event_id),
    );
    assert.ok(subagentNode);
    assert.equal(subagentNode.componentKind, "subagent_lifecycle");
    assert.equal(subagentNode.workflowNodeId, workflowNodeId);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow and line-mode TUI interrupt controls share the operator-control event contract", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const workflowGraphId = "workflow.react-flow.tui-control-equivalence";
  const workflowNodeId = "runtime.operator-interrupt";
  const contractShape = {
    eventKind: "turn.interrupted",
    sourceEventKind: "OperatorControl.Interrupt",
    status: "interrupted",
    componentKind: "operator_control",
    workflowNodeId,
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
  };
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-control-equivalence";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const reactFlowThread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow and TUI interrupts share the control event contract.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const reactFlowTurn = await fetchJson(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/turns`,
      {
        method: "POST",
        body: JSON.stringify({
          prompt: "Prepare the React Flow side of the control equivalence proof.",
        }),
      },
    );
    const workflowNode = {
      id: "react-flow-tui-equivalence-interrupt-control",
      type: "runtime_operator_interrupt",
      config: {
        logic: {
          runtimeOperatorInterruptEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
          runtimeOperatorInterruptThreadIdField: "threadId",
          runtimeOperatorInterruptTurnIdField: "turnId",
          runtimeOperatorInterruptReasonField: "reason",
          runtimeOperatorInterruptWorkflowNodeId: workflowNodeId,
          runtimeOperatorInterruptActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.interrupt"] },
      },
    };
    const reactFlowControl = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      workflowNode,
      {
        threadId: reactFlowThread.thread_id,
        turnId: reactFlowTurn.turn_id,
        reason: "react-flow equivalence interrupt",
      },
      { workflowGraphId },
    );
    await fetchJson(`${daemon.endpoint}${reactFlowControl.endpoint}`, {
      method: "POST",
      body: JSON.stringify(reactFlowControl.body),
    });

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove line-mode TUI shares the React Flow control event contract.",
        "--message",
        "Prepare the TUI side of the control equivalence proof.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/interrupt tui equivalence interrupt\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    const tuiThreadId = tuiResult.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(tuiThreadId);

    const reactFlowEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/events?since_seq=0`,
    );
    const tuiEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${tuiThreadId}/events?since_seq=0`,
    );
    const reactFlowEvent = reactFlowEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.source === "react_flow" &&
        event.payload?.reason === "react-flow equivalence interrupt",
    );
    const tuiEvent = tuiEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.source === "cli_tui" &&
        event.payload?.reason === "tui equivalence interrupt",
    );
    assert.ok(reactFlowEvent);
    assert.ok(tuiEvent);
    assert.deepEqual(operatorControlContractShape(reactFlowEvent), contractShape);
    assert.deepEqual(operatorControlContractShape(tuiEvent), contractShape);
    assert.equal(reactFlowEvent.workflow_graph_id, workflowGraphId);
    assert.equal(tuiEvent.workflow_graph_id, null);
    assert.ok(reactFlowEvent.receipt_refs.includes(`receipt_${reactFlowTurn.request_id}_operator_interrupt`));
    assert.ok(reactFlowEvent.policy_decision_refs.includes(`policy_${reactFlowTurn.request_id}_operator_interrupt_allow`));
    assert.ok(tuiEvent.receipt_refs.some((ref) => ref.endsWith("_operator_interrupt")));
    assert.ok(tuiEvent.policy_decision_refs.some((ref) => ref.endsWith("_operator_interrupt_allow")));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const reactFlowSdkThread = await Thread.open(reactFlowThread.thread_id, {
      substrateClient: sdkClient,
    });
    const tuiSdkThread = await Thread.open(tuiThreadId, { substrateClient: sdkClient });
    const reactFlowSdkEvents = await collect(reactFlowSdkThread.events({ sinceSeq: 0 }));
    const tuiSdkEvents = await collect(tuiSdkThread.events({ sinceSeq: 0 }));
    const reactFlowSdkEvent = reactFlowSdkEvents.find(
      (event) => event.id === reactFlowEvent.event_id,
    );
    const tuiSdkEvent = tuiSdkEvents.find((event) => event.id === tuiEvent.event_id);
    assert.ok(reactFlowSdkEvent);
    assert.ok(tuiSdkEvent);

    const reactFlowProjection =
      projectRuntimeThreadEventsToWorkflowProjection(reactFlowSdkEvents);
    const tuiProjection = projectRuntimeThreadEventsToWorkflowProjection(tuiSdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowEvent.event_id),
    );
    const tuiNode = tuiProjection.nodes.find((node) =>
      node.eventIds.includes(tuiEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(tuiNode);

    const reactFlowTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      reactFlowThread.thread_id,
      reactFlowEvent.event_id,
    );
    const lineModeTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      tuiThreadId,
      tuiEvent.event_id,
    );
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: reactFlowEvent,
      sdkEvent: reactFlowSdkEvent,
      reactFlowNode,
      tuiRow: reactFlowTuiRow,
      expected: { ...contractShape, workflowGraphId },
    });
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: tuiEvent,
      sdkEvent: tuiSdkEvent,
      reactFlowNode: tuiNode,
      tuiRow: lineModeTuiRow,
      expected: { ...contractShape, workflowGraphId: null },
    });
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow and line-mode TUI steer controls share the operator-control event contract", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorSteerControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const workflowGraphId = "workflow.react-flow.tui-steer-equivalence";
  const workflowNodeId = "runtime.operator-steer";
  const contractShape = {
    eventKind: "turn.steered",
    sourceEventKind: "OperatorControl.Steer",
    status: "completed",
    componentKind: "operator_control",
    workflowNodeId,
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
  };
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-steer-equivalence";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const reactFlowThread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow and TUI steers share the control event contract.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const reactFlowTurn = await fetchJson(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/turns`,
      {
        method: "POST",
        body: JSON.stringify({
          prompt: "Prepare the React Flow side of the steer equivalence proof.",
        }),
      },
    );
    const workflowNode = {
      id: "react-flow-tui-equivalence-steer-control",
      type: "runtime_operator_steer",
      config: {
        logic: {
          runtimeOperatorSteerEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
          runtimeOperatorSteerThreadIdField: "threadId",
          runtimeOperatorSteerTurnIdField: "turnId",
          runtimeOperatorSteerGuidanceField: "guidance",
          runtimeOperatorSteerWorkflowNodeId: workflowNodeId,
          runtimeOperatorSteerActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.steer"] },
      },
    };
    const reactFlowControl = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      workflowNode,
      {
        threadId: reactFlowThread.thread_id,
        turnId: reactFlowTurn.turn_id,
        guidance: "react-flow equivalence steer",
      },
      { workflowGraphId },
    );
    await fetchJson(`${daemon.endpoint}${reactFlowControl.endpoint}`, {
      method: "POST",
      body: JSON.stringify(reactFlowControl.body),
    });

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove line-mode TUI shares the React Flow steer event contract.",
        "--message",
        "Prepare the TUI side of the steer equivalence proof.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/steer tui equivalence steer\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    const tuiThreadId = tuiResult.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(tuiThreadId);

    const reactFlowEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/events?since_seq=0`,
    );
    const tuiEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${tuiThreadId}/events?since_seq=0`,
    );
    const reactFlowEvent = reactFlowEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Steer" &&
        event.source === "react_flow" &&
        event.payload?.guidance === "react-flow equivalence steer",
    );
    const tuiEvent = tuiEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Steer" &&
        event.source === "cli_tui" &&
        event.payload?.guidance === "tui equivalence steer",
    );
    assert.ok(reactFlowEvent);
    assert.ok(tuiEvent);
    assert.deepEqual(operatorControlContractShape(reactFlowEvent), contractShape);
    assert.deepEqual(operatorControlContractShape(tuiEvent), contractShape);
    assert.equal(reactFlowEvent.workflow_graph_id, workflowGraphId);
    assert.equal(tuiEvent.workflow_graph_id, null);
    assert.ok(reactFlowEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${reactFlowTurn.request_id}_operator_steer_`)));
    assert.ok(reactFlowEvent.policy_decision_refs.includes(`policy_${reactFlowTurn.request_id}_operator_steer_allow`));
    assert.ok(tuiEvent.receipt_refs.some((ref) => ref.includes("_operator_steer_")));
    assert.ok(tuiEvent.policy_decision_refs.some((ref) => ref.endsWith("_operator_steer_allow")));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const reactFlowSdkThread = await Thread.open(reactFlowThread.thread_id, {
      substrateClient: sdkClient,
    });
    const tuiSdkThread = await Thread.open(tuiThreadId, { substrateClient: sdkClient });
    const reactFlowSdkEvents = await collect(reactFlowSdkThread.events({ sinceSeq: 0 }));
    const tuiSdkEvents = await collect(tuiSdkThread.events({ sinceSeq: 0 }));
    const reactFlowSdkEvent = reactFlowSdkEvents.find(
      (event) => event.id === reactFlowEvent.event_id,
    );
    const tuiSdkEvent = tuiSdkEvents.find((event) => event.id === tuiEvent.event_id);
    assert.ok(reactFlowSdkEvent);
    assert.ok(tuiSdkEvent);

    const reactFlowProjection =
      projectRuntimeThreadEventsToWorkflowProjection(reactFlowSdkEvents);
    const tuiProjection = projectRuntimeThreadEventsToWorkflowProjection(tuiSdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowEvent.event_id),
    );
    const tuiNode = tuiProjection.nodes.find((node) =>
      node.eventIds.includes(tuiEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(tuiNode);

    const reactFlowTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      reactFlowThread.thread_id,
      reactFlowEvent.event_id,
    );
    const lineModeTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      tuiThreadId,
      tuiEvent.event_id,
    );
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: reactFlowEvent,
      sdkEvent: reactFlowSdkEvent,
      reactFlowNode,
      tuiRow: reactFlowTuiRow,
      expected: { ...contractShape, workflowGraphId },
    });
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: tuiEvent,
      sdkEvent: tuiSdkEvent,
      reactFlowNode: tuiNode,
      tuiRow: lineModeTuiRow,
      expected: { ...contractShape, workflowGraphId: null },
    });
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow generated coding-tool budget recovery subflow executes daemon recovery route", async () => {
  const {
    createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode,
    createWorkflowRuntimeCodingToolBudgetRecoverySubflow,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-budget-subflow-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-budget-subflow-state-"));
  const workflowGraphId = "workflow.react-flow.coding-budget-recovery-subflow-proof";
  const targetNodeId = "workflow.coding.file.apply_patch.subflow";
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Recover a coding-tool budget block from a generated React Flow subflow.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Wait for a generated React Flow coding-tool budget recovery subflow proof.",
      }),
    });
    daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: turn.turn_id,
      item_id: `${turn.turn_id}:item:react-flow-budget-subflow-preflight-blocked`,
      idempotency_key: `${turn.turn_id}:react-flow-budget-subflow-preflight-blocked`,
      source: "daemon_bridge",
      source_event_kind: "WorkflowRunCodingToolBudgetPreflightBlocked",
      event_kind: "policy.blocked",
      status: "blocked",
      actor: "runtime",
      workspace_root: cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: targetNodeId,
      component_kind: "coding_tool",
      payload_schema_version: "ioi.workflow.coding-tool-budget-preflight.v1",
      payload: {
        eventKind: "WorkflowRunCodingToolBudgetPreflightBlocked",
        reason: "coding_tool_budget_preflight_blocked",
        runId: turn.request_id,
        threadId: thread.thread_id,
        targetNodeIds: [targetNodeId],
        recoveryPolicy: {
          schemaVersion: "ioi.workflow.coding-tool-budget-recovery-policy.v1",
          source: "react_flow_generated_subflow_live",
          approvalScope: "target_nodes",
          operatorRole: "budget_operator",
          retryLimit: 1,
          ttlMs: 300000,
          requiresApproval: true,
          allowOverride: true,
          targetNodeIds: [targetNodeId],
          sourceNodeIds: [targetNodeId],
        },
      },
      receipt_refs: ["receipt_budget_preflight_generated_subflow_live"],
      policy_decision_refs: ["policy_budget_preflight_generated_subflow_live"],
      artifact_refs: [],
      rollback_refs: [],
    });

    const blockedEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const blockedProjection = projectRuntimeThreadEventsToWorkflowProjection(
      workflowProjectionEventsFromDaemonEvents(blockedEvents),
    );
    const blockedNode = blockedProjection.nodes.find(
      (node) =>
        node.workflowNodeId === targetNodeId &&
        node.codingToolBudgetRecoveryActions.length > 0,
    );
    assert.ok(blockedNode);
    const seed = blockedNode.codingToolBudgetRecoveryActions.find(
      (action) => action.action === "request_approval",
    );
    assert.ok(seed);
    const subflow = createWorkflowRuntimeCodingToolBudgetRecoverySubflow(seed, {
      idPrefix: "react-flow-generated-budget-recovery",
      origin: { x: 480, y: 160 },
    });
    const subflowNodeByAction = new Map(
      subflow.nodes.map((node) => [
        node.config?.logic.runtimeCodingToolBudgetRecoveryAction,
        node,
      ]),
    );
    const requestNode = subflowNodeByAction.get("request_approval");
    const approveNode = subflowNodeByAction.get("approve_override");
    const retryNode = subflowNodeByAction.get("retry_approved");
    assert.ok(requestNode);
    assert.ok(approveNode);
    assert.ok(retryNode);

    const requestApproval =
      createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
        requestNode,
        {},
        { workflowGraphId },
      );
    assert.equal(requestApproval.body.workflowNodeId, subflow.requestNodeId);
    const approvalResult = await fetchJson(`${daemon.endpoint}${requestApproval.endpoint}`, {
      method: "POST",
      body: JSON.stringify(requestApproval.body),
    });
    assert.equal(approvalResult.status, "waiting_for_approval");

    const approve = createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      approveNode,
      {},
      { workflowGraphId },
    );
    assert.equal(approve.body.approvalId, requestApproval.body.approvalId);
    assert.equal(approve.body.workflowNodeId, subflow.approveNodeId);
    const approveResult = await fetchJson(`${daemon.endpoint}${approve.endpoint}`, {
      method: "POST",
      body: JSON.stringify(approve.body),
    });
    assert.equal(approveResult.status, "approved");

    const retry = createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode(
      retryNode,
      {},
      { workflowGraphId },
    );
    assert.equal(retry.body.approvalId, requestApproval.body.approvalId);
    assert.equal(retry.body.workflowNodeId, subflow.retryNodeId);
    const retryResult = await fetchJson(`${daemon.endpoint}${retry.endpoint}`, {
      method: "POST",
      body: JSON.stringify(retry.body),
    });
    assert.equal(retryResult.status, "completed");
    assert.equal(retryResult.recoveryPolicy.operatorRole, "budget_operator");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const approvalEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "approval.required" &&
        event.approval_id === requestApproval.body.approvalId,
    );
    const decisionEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "approval.approved" &&
        event.approval_id === requestApproval.body.approvalId,
    );
    const retryEvent = daemonEvents.find(
      (event) =>
        event.event_kind === "workflow.run.retry_completed" &&
        event.approval_id === requestApproval.body.approvalId,
    );
    assert.ok(approvalEvent);
    assert.ok(decisionEvent);
    assert.ok(retryEvent);
    assert.equal(approvalEvent.source, "react_flow");
    assert.equal(approvalEvent.workflow_node_id, subflow.requestNodeId);
    assert.equal(decisionEvent.workflow_node_id, subflow.approveNodeId);
    assert.equal(retryEvent.workflow_node_id, subflow.retryNodeId);
    assert.equal(retryEvent.workflow_graph_id, workflowGraphId);
    assert.equal(retryEvent.payload_summary.sourceEventId, seed.sourceEventId);
    assert.equal(retryEvent.payload_summary.recoveryPolicy.operatorRole, "budget_operator");

    const projection = projectRuntimeThreadEventsToWorkflowProjection(
      workflowProjectionEventsFromDaemonEvents(daemonEvents),
    );
    const projectedNodeIds = new Set(projection.nodes.map((node) => node.workflowNodeId));
    assert.ok(projectedNodeIds.has(subflow.requestNodeId));
    assert.ok(projectedNodeIds.has(subflow.approveNodeId));
    assert.ok(projectedNodeIds.has(subflow.retryNodeId));
    const retryProjectionNode = projection.nodes.find(
      (node) => node.workflowNodeId === subflow.retryNodeId,
    );
    assert.ok(retryProjectionNode);
    const runInspectorEvidenceLink = {
      schemaVersion: "ioi.workflow.run-inspector.evidence-link.v1",
      kind: "coding_tool_budget_recovery_subflow_execution",
      runId: turn.request_id,
      threadId: thread.thread_id,
      workflowGraphId,
      workflowNodeId: subflow.retryNodeId,
      eventId: retryEvent.event_id,
      reopenCommand: retryProjectionNode.tuiDeepLink.reopenCommand,
    };
    assert.equal(runInspectorEvidenceLink.workflowNodeId, subflow.retryNodeId);
    assert.match(runInspectorEvidenceLink.reopenCommand, new RegExp(thread.thread_id));
    assert.match(runInspectorEvidenceLink.reopenCommand, /--since-seq/);
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable", () => {
  const liveRuntimeDaemonContract = fs.readFileSync(
    path.join(root, "scripts/lib/live-runtime-daemon-contract.test.mjs"),
    "utf8",
  );
  const workflowContracts = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/deepseek-parity-workflow-contracts.ts"),
    "utf8",
  );
  const graphTypes = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/types/graph.ts"),
    "utf8",
  );
  const workflowDefaults = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-defaults.ts"),
    "utf8",
  );
  const harnessWorkflow = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/harness-workflow/core.ts"),
    "utf8",
  );
  const nodeRegistry = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-node-registry.ts"),
    "utf8",
  );
  const workflowRuntimeControlNodes = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-control-nodes.ts"),
    "utf8",
  );
  const workflowRuntimeCodingToolControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeCodingToolBudgetRecoveryControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeCodingToolBudgetRecoverySubflow = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-subflow.ts",
    ),
    "utf8",
  );
  const workflowRuntimeEditProposalControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-edit-proposal-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeMcpControlNodes = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-mcp-control-nodes.ts"),
    "utf8",
  );
  const workflowRuntimeSubagentControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-subagent-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeUsageControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-usage-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeContextBudgetControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-context-budget-control-nodes.ts",
    ),
    "utf8",
  );
  const workflowRuntimeCompactionPolicyControlNodes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-compaction-policy-control-nodes.ts",
    ),
    "utf8",
  );
  const runtimeDaemon = fs.readFileSync(
    path.join(root, "packages/runtime-daemon/src/index.mjs"),
    "utf8",
  );
  const runtimeCodingTools = fs.readFileSync(
    path.join(root, "packages/runtime-daemon/src/coding-tools.mjs"),
    "utf8",
  );
  const runtimeUsageTelemetry = fs.readFileSync(
    path.join(root, "packages/runtime-daemon/src/usage-telemetry.mjs"),
    "utf8",
  );
  const workflowNodeBindingEditorSections = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/sections.tsx",
    ),
    "utf8",
  );
  const workflowNodeBindingEditorSubagentFields = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowNodeBindingEditor/subagentFields.tsx",
    ),
    "utf8",
  );
  const workflowRuntimeUiStrings = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-ui-strings.ts"),
    "utf8",
  );
  const canvasNode = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.tsx"),
    "utf8",
  );
  const graphConfigView = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Inspector/views/GraphConfigView.tsx"),
    "utf8",
  );
  const agentEditor = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/AgentEditor.tsx"),
    "utf8",
  );
  const workflowComposerView = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/view.tsx"),
    "utf8",
  );
  const workflowComposerController = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/controller.tsx"),
    "utf8",
  );
  const canvas = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Canvas.tsx"),
    "utf8",
  );
  const canvasNodeStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.css"),
    "utf8",
  );
  const inspector = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Inspector/Inspector.tsx"),
    "utf8",
  );
  const workflowRailPanel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx"),
    "utf8",
  );
  const workflowSearchPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx",
    ),
    "utf8",
  );
  const workflowRailSearchModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-rail-search-model.ts"),
    "utf8",
  );
  const workflowEntrypointsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx",
    ),
    "utf8",
  );
  const workflowEntrypointsModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts"),
    "utf8",
  );
  const workflowFilesPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx",
    ),
    "utf8",
  );
  const workflowFileBundleModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts"),
    "utf8",
  );
  const workflowSettingsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-settings-model.ts"),
    "utf8",
  );
  const workflowSettingsHarnessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessTypes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGatePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGateRefsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGateTimelinePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageEvidencePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageEvidenceRowsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageImportReviewPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessWorkerBindingPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActiveRuntimeRollbackPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActiveRuntimeBindingPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessRollbackRestoreProofPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPromotionPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPromotionReadinessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts"),
    "utf8",
  );
  const workflowReadinessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    ),
    "utf8",
  );
  const workflowReadinessModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-readiness-model.ts"),
    "utf8",
  );
  const workflowUnitTestsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
    ),
    "utf8",
  );
  const workflowTestReadinessModel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts",
    ),
    "utf8",
  );
  const workflowRunsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    ),
    "utf8",
  );
  const workflowRunHistoryModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-run-history-model.ts"),
    "utf8",
  );
  const workflowRuntimeEventProjection = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts"),
    "utf8",
  );
  const workflowRuntimePolicyStack = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-policy-stack.ts"),
    "utf8",
  );
  const workflowRuntimeEditProposalPolicy = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-edit-proposal-policy.ts",
    ),
    "utf8",
  );
  const workflowRuntimeTelemetrySummary = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-summary.ts",
    ),
    "utf8",
  );
  const workflowRuntimeTelemetrySourceBinding = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-telemetry-source-binding.ts",
    ),
    "utf8",
  );
  const workflowRuntimeDiagnosticsRepairActions = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-diagnostics-repair-actions.ts",
    ),
    "utf8",
  );
  const workflowRuntimeCodingToolBudgetRecoveryPolicy = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-policy.ts",
    ),
    "utf8",
  );
  const workflowRuntimeCodingToolBudgetRecoveryBinding = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-runtime-coding-tool-budget-recovery-binding.ts",
    ),
    "utf8",
  );
  const graphRuntimeTypes = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/graph-runtime-types.ts"),
    "utf8",
  );
  const tauriRuntime = fs.readFileSync(
    path.join(root, "apps/autopilot/src/services/TauriRuntime.ts"),
    "utf8",
  );
  const tauriArtifacts = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/kernel/artifacts/mod.rs"),
    "utf8",
  );
  const tauriLib = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/lib.rs"),
    "utf8",
  );
  const workflowRailModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-rail-model.ts"),
    "utf8",
  );
  const workflowBottomShelf = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx"),
    "utf8",
  );
  const composerPanelStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/styles/composer-panels.css"),
    "utf8",
  );
  const composerShellStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/styles/composer-shell.css"),
    "utf8",
  );
  const workflowValidation = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-validation.ts"),
    "utf8",
  );
  const workflowSchedulerLaneReadiness = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-scheduler-lane-readiness.ts",
    ),
    "utf8",
  );
  const tauriProjectTypes = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/types.rs"),
    "utf8",
  );
  const tauriProjectCommands = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/commands.rs"),
    "utf8",
  );
  const tauriProjectRuntime = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/runtime.rs"),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerFinalizationLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_finalization_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerTerminalResultLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_terminal_result_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowRunPolicyLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_run_policy_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerInterruptLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_interrupt_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeExecutionLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_node_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeOutcomeLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_node_outcome_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeFailureOutcomeLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_node_failure_outcome_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeSuccessEventLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_node_success_event_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeStateUpdateLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_node_state_update_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerValidationLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_scheduler_validation_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectPackage = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/package.rs"),
    "utf8",
  );
  const tauriProjectValidation = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/validation.rs"),
    "utf8",
  );
  const tauriProjectWorkflowAuthorityToolingLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_authority_tooling_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowApprovalInterruptLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_approval_interrupt_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowBindingLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_binding_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowCheckpointLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_checkpoint_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowStateLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_state_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeContractLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_node_contract_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeMetadataLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_node_metadata_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowRunLifecycleLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_run_lifecycle_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeExecutionLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_node_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowMemoryLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_memory_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowOutputLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_output_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowPackageLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_package_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowCodingRouteLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_coding_route_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowExecutionResultsLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_execution_results_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowGraphExecutionLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_graph_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowHarnessResultsLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_harness_results_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectRepositoryPrLane = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/repository_pr_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowValueHelpers = fs.readFileSync(
    path.join(
      root,
      "internal-docs/legacy/autopilot-tauri-src/src/project/workflow_value_helpers.rs",
    ),
    "utf8",
  );
  const tauriProjectTemplates = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/project/templates.rs"),
    "utf8",
  );
  const tauriRuntimeProjection = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/runtime_projection.rs"),
    "utf8",
  );
  const workflowHarnessTools = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-harness-tools.ts"),
    "utf8",
  );
  const runtimeProjectionAdapter = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/runtime-projection-adapter.ts"),
    "utf8",
  );
  const runtimeActionSchema = fs.readFileSync(
    path.join(root, "internal-docs/implementation/runtime-action-schema.json"),
    "utf8",
  );
  const generatedActionSchema = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/generated/action-schema.ts"),
    "utf8",
  );
  const generatedRustActionSchema = fs.readFileSync(
    path.join(root, "internal-docs/legacy/autopilot-tauri-src/src/generated/runtime_action_schema.rs"),
    "utf8",
  );
  assert.match(workflowContracts, /memory\.scope/);
  assert.match(workflowContracts, /memory\.remember/);
  assert.match(workflowContracts, /memory\.search/);
  assert.match(workflowContracts, /memory\.list/);
  assert.match(workflowContracts, /memory\.policy/);
  assert.match(workflowContracts, /memory\.path/);
  assert.match(workflowContracts, /memory\.subagentInheritance/);
  assert.match(workflowContracts, /subagent\.pool/);
  assert.match(workflowContracts, /subagent\.role/);
  assert.match(workflowContracts, /subagent\.spawn/);
  assert.match(workflowContracts, /subagent\.join/);
  assert.match(workflowContracts, /subagent\.result/);
  assert.match(workflowContracts, /subagent\.cancel_propagation/);
  assert.match(nodeRegistry, /creatorId: "mcp\.status"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.tool\.search"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.tool\.fetch"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.tool\.invoke"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.import"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.add"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.add\.http"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.add\.sse"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.serve"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.remove"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.enable"/);
  assert.match(nodeRegistry, /creatorId: "mcp\.server\.disable"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.pool"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.role"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.spawn"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.join"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.result"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.send_input"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.cancel"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.cancel_propagation"/);
  assert.match(nodeRegistry, /creatorId: "subagent\.resume"/);
  assert.match(nodeRegistry, /creatorId: "memory\.remember"/);
  assert.match(nodeRegistry, /creatorId: "memory\.edit"/);
  assert.match(nodeRegistry, /creatorId: "memory\.delete"/);
  assert.match(nodeRegistry, /creatorId: "plugin_tool\.mcp"/);
  assert.match(graphTypes, /mcp_status/);
  assert.match(graphTypes, /mcp_tool_search/);
  assert.match(graphTypes, /mcp_tool_fetch/);
  assert.match(graphTypes, /mcp_tool_invoke/);
  assert.match(graphTypes, /mcpToolInputJson/);
  assert.match(graphTypes, /mcpVaultHeaderRefsJson/);
  assert.match(graphTypes, /mcpContainmentMode/);
  assert.match(graphTypes, /mcpAllowNetworkEgress/);
  assert.match(graphTypes, /mcpConfigSourceMode/);
  assert.match(workflowRuntimeMcpControlNodes, /createRuntimeMcpToolControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeMcpControlNodes, /\/v1\/threads\/\$\{encodeSegment\(threadId\)\}\/mcp\/tools\/search/);
  assert.match(workflowRuntimeMcpControlNodes, /OperatorControl\.McpInvoke/);
  assert.match(workflowRuntimeCodingToolControlNodes, /createRuntimeCodingToolControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeCodingToolControlNodes, /\/v1\/threads\/\$\{encodeSegment\(threadId\)\}\/tools\/\$\{encodeSegment\(toolId\)\}\/invoke/);
  assert.match(workflowRuntimeCodingToolControlNodes, /nodeApprovalOverride/);
  assert.match(workflowRuntimeCodingToolControlNodes, /trustProfile/);
  assert.match(workflowRuntimeCodingToolControlNodes, /runtimeTelemetrySummary/);
  assert.match(workflowRuntimeCodingToolControlNodes, /budgetUsageTelemetry/);
  assert.match(workflowRuntimeCodingToolControlNodes, /budgetUsageTelemetryField/);
  assert.match(workflowRuntimeCodingToolControlNodes, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.ok(
    workflowRuntimeCodingToolControlNodes.indexOf(
      "valueAtPath(params.input, budgetUsageField)",
    ) < workflowRuntimeCodingToolControlNodes.indexOf("params.runtimeTelemetrySummary"),
  );
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /runtime_coding_tool_budget_recovery/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /\/v1\/runs\/\{runId\}\/coding-tool-budget-recovery/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /WorkflowRunCodingToolBudgetRecoveryControl/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /normalizeWorkflowCodingToolBudgetRecoveryPolicy/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /createWorkflowRuntimeCodingToolBudgetRecoverySubflow/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /bindRuntimeInputs/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /runtime_coding_tool_budget_recovery/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /request_approval/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /approve_override/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /reject_override/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /retry_approved/);
  assert.match(workflowRuntimeCodingToolBudgetRecoverySubflow, /ioi\.workflow\.runtime-coding-tool-budget-recovery-subflow\.v1/);
  assert.match(workflowRuntimeTelemetrySummary, /tui_coding_tool_rows/);
  assert.match(workflowRuntimeTelemetrySummary, /codingToolBudgetRowCount/);
  assert.match(workflowRuntimeTelemetrySummary, /usageSnapshotFromCodingToolBudgetRow/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /WORKFLOW_RUNTIME_TELEMETRY_SOURCE_BINDING_SCHEMA_VERSION/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /bindWorkflowRuntimeTelemetrySourceToWorkflow/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /runtime_usage_meter/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /runtime_context_budget/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /runtime_compaction_policy/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /react_flow_quick_fix/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /boundWorkflowNodeId/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /boundCompactWorkflowNodeId/);
  assert.match(workflowRuntimeTelemetrySourceBinding, /runtimeContextBudgetUsageField: "runtimeUsageMeter"/);
  assert.match(graphTypes, /workflowNodeId\?: string/);
  assert.match(graphTypes, /workflow_node_id\?: string/);
  assert.match(liveRuntimeDaemonContract, /React Flow bound telemetry-source chain executes/);
  assert.match(liveRuntimeDaemonContract, /bound-usage-meter/);
  assert.match(liveRuntimeDaemonContract, /bound-context-budget/);
  assert.match(liveRuntimeDaemonContract, /bound-compaction-policy/);
  assert.match(liveRuntimeDaemonContract, /bound-coding-tool-budget-gate/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-budget-mode/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-budget-usage-field/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-recovery-approval-scope/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-recovery-target-node-ids/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-recovery-retry-limit/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-recovery-ttl-ms/);
  assert.match(workflowNodeBindingEditorSections, /workflow-coding-tool-pack-recovery-operator-role/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryPolicy, /workflowCodingToolBudgetRecoveryPolicyFromWorkflow/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryPolicy, /ioi\.workflow\.coding-tool-budget-recovery-policy\.v1/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /\/run recovery request/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /\/run recovery retry-approved/);
  assert.match(runtimeCodingTools, /toolPack\.coding\.budgetUsageField/);
  assert.match(runtimeCodingTools, /toolPack\.coding\.maxTotalTokens/);
  assert.match(workflowRuntimeEditProposalControlNodes, /createRuntimeWorkflowEditProposalControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeEditProposalControlNodes, /workflow-edit-proposals/);
  assert.match(workflowRuntimeEditProposalControlNodes, /proposal_only/);
  assert.match(workflowRuntimeEditProposalControlNodes, /mutation_allowed: false/);
  assert.match(workflowRuntimeSubagentControlNodes, /createRuntimeSubagentControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeSubagentControlNodes, /contextPressureAction/);
  assert.match(workflowRuntimeSubagentControlNodes, /policyDecisionRefs/);
  assert.match(workflowRuntimeSubagentControlNodes, /\/v1\/threads\/\$\{encodeSegment\(threadId\)\}\/subagents/);
  assert.match(workflowRuntimeSubagentControlNodes, /OperatorControl\.SubagentSpawn/);
  assert.match(workflowRuntimeSubagentControlNodes, /OperatorControl\.SubagentSendInput/);
  assert.match(workflowRuntimeSubagentControlNodes, /OperatorControl\.SubagentCancel/);
  assert.match(workflowRuntimeSubagentControlNodes, /subagent_cancel_propagation/);
  assert.match(workflowRuntimeSubagentControlNodes, /propagate_cancel/);
  assert.match(workflowRuntimeSubagentControlNodes, /subagentBudgetJson/);
  assert.match(workflowRuntimeSubagentControlNodes, /subagentBudgetUsageField/);
  assert.match(workflowRuntimeSubagentControlNodes, /budgetUsageTelemetry/);
  assert.match(workflowRuntimeSubagentControlNodes, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(workflowRuntimeUsageControlNodes, /createRuntimeUsageMeterControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeUsageControlNodes, /runtime_usage_meter/);
  assert.match(workflowRuntimeUsageControlNodes, /RuntimeUsageTelemetry\.Read/);
  assert.match(workflowRuntimeUsageControlNodes, /usage_meter_scope/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /createRuntimeContextBudgetControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /runtime_context_budget/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /RuntimeContextBudget\.Evaluate/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /\/v1\/threads\/\{threadId\}\/context-budget/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /runtimeTelemetrySummary/);
  assert.match(workflowRuntimeContextBudgetControlNodes, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.ok(
    workflowRuntimeContextBudgetControlNodes.indexOf(
      'valueAtPath(params.input, params.usageTelemetryField ?? "runtimeUsageMeter")',
    ) < workflowRuntimeContextBudgetControlNodes.indexOf("params.usageTelemetry"),
  );
  assert.match(workflowRuntimeCompactionPolicyControlNodes, /createRuntimeCompactionPolicyControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeCompactionPolicyControlNodes, /runtime_compaction_policy/);
  assert.match(workflowRuntimeCompactionPolicyControlNodes, /RuntimeCompactionPolicy\.Evaluate/);
  assert.match(workflowRuntimeCompactionPolicyControlNodes, /\/v1\/threads\/\{threadId\}\/compaction-policy/);
  assert.ok(
    workflowRuntimeCompactionPolicyControlNodes.indexOf(
      'valueAtPath(params.input, params.contextBudgetField ?? "runtimeContextBudget")',
    ) < workflowRuntimeCompactionPolicyControlNodes.indexOf("params.contextBudget"),
  );
  assert.match(nodeRegistry, /creatorId: "usage\.meter"/);
  assert.match(nodeRegistry, /creatorId: "context\.budget"/);
  assert.match(nodeRegistry, /creatorId: "compaction\.policy"/);
  assert.match(nodeRegistry, /creatorId: "coding_budget\.recovery"/);
  assert.match(nodeRegistry, /RuntimeUsageMeterNode/);
  assert.match(nodeRegistry, /RuntimeContextBudgetNode/);
  assert.match(nodeRegistry, /RuntimeCompactionPolicyNode/);
  assert.match(nodeRegistry, /RuntimeCodingToolBudgetRecoveryNode/);
  assert.match(nodeRegistry, /runtimeUsageMeterSimulationMode/);
  assert.match(nodeRegistry, /runtimeContextBudgetMaxContextPressure/);
  assert.match(nodeRegistry, /runtimeCompactionPolicyBlockedAction/);
  assert.match(graphTypes, /runtime_usage_meter/);
  assert.match(graphTypes, /runtime_context_budget/);
  assert.match(graphTypes, /runtime_compaction_policy/);
  assert.match(graphTypes, /runtime_coding_tool_budget_recovery/);
  assert.match(graphTypes, /runtimeCodingToolBudgetRecoveryAction/);
  assert.match(workflowRuntimeUiStrings, /runtime_usage_meter/);
  assert.match(workflowRuntimeUiStrings, /runtime_context_budget/);
  assert.match(workflowRuntimeUiStrings, /runtime_compaction_policy/);
  assert.match(workflowRuntimeUiStrings, /runtime_coding_tool_budget_recovery/);
  assert.match(generatedActionSchema, /runtime_coding_tool_budget_recovery/);
  assert.match(generatedRustActionSchema, /runtime_coding_tool_budget_recovery/);
  assert.match(runtimeActionSchema, /runtime_coding_tool_budget_recovery/);
  assert.match(tauriRuntimeProjection, /RuntimeCodingToolBudgetRecovery/);
  assert.match(tauriProjectTemplates, /workflow\.runtime\.coding_tool_budget_recovery/);
  assert.match(runtimeDaemon, /subagentBudgetStatusForRun/);
  assert.match(runtimeDaemon, /subagentBudgetUsageTelemetryForRequest/);
  assert.match(runtimeDaemon, /Subagent budget limit exceeded/);
  assert.match(runtimeDaemon, /runtimeUsageTelemetryForThread/);
  assert.match(runtimeDaemon, /\/v1\/usage/);
  assert.match(runtimeDaemon, /\/v1\/context-budget/);
  assert.match(runtimeDaemon, /evaluateContextBudget/);
  assert.match(runtimeDaemon, /action === "compaction-policy"/);
  assert.match(runtimeDaemon, /evaluateCompactionPolicy/);
  assert.match(runtimeDaemon, /usage_delta/);
  assert.match(runtimeDaemon, /context_pressure_delta/);
  assert.match(runtimeDaemon, /usage_final/);
  assert.match(runtimeUsageTelemetry, /RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION/);
  assert.match(runtimeUsageTelemetry, /runtimeUsageTelemetryForRun/);
  assert.match(runtimeUsageTelemetry, /runtimeUsageTelemetryForThread/);
  assert.match(runtimeUsageTelemetry, /costEstimateUsd/);
  assert.match(workflowRuntimeEventProjection, /usage_status/);
  assert.match(workflowRuntimeEventProjection, /usageTotalTokens/);
  assert.match(workflowRuntimeEventProjection, /coding_tool_budget/);
  assert.match(workflowRuntimeEventProjection, /usage_delta/);
  assert.match(workflowRuntimeEventProjection, /context_pressure_delta/);
  assert.match(graphTypes, /mcp_import/);
  assert.match(graphTypes, /mcp_add/);
  assert.match(graphTypes, /mcp_serve/);
  assert.match(graphTypes, /mcp_remove/);
  assert.match(graphTypes, /mcpServeAllowedToolsJson/);
  assert.match(graphTypes, /mcpTransport/);
  assert.match(graphTypes, /mcpServerUrl/);
  assert.match(graphTypes, /mcpServerHeadersJson/);
  assert.match(graphTypes, /mcp_enable/);
  assert.match(graphTypes, /mcp_disable/);
  assert.match(graphTypes, /memory_remember/);
  assert.match(graphTypes, /memory_edit/);
  assert.match(graphTypes, /memory_delete/);
  assert.match(graphTypes, /subagent_spawn/);
  assert.match(graphTypes, /subagent_wait/);
  assert.match(graphTypes, /subagent_result/);
  assert.match(graphTypes, /subagent_send_input/);
  assert.match(graphTypes, /subagent_cancel_propagation/);
  assert.match(graphTypes, /subagentCancellationInheritance/);
  assert.match(graphTypes, /subagentBudgetJson/);
  assert.match(graphTypes, /subagentBudgetUsageField/);
  assert.match(graphTypes, /subagentOutputContractJson/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-server-id/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-transport/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-server-url/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-server-headers/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-server-config/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-config-source-mode/);
  assert.match(workflowNodeBindingEditorSections, /workflow-mcp-config-source-mode/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-serve-endpoint/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-serve-allowed-tools/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-import-json/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-tool-input/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-containment-mode/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-vault-header-refs/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-mcp-allow-network-egress/);
  assert.match(workflowNodeBindingEditorSections, /workflow-mcp-validate-before-invoke/);
  assert.match(workflowNodeBindingEditorSections, /WorkflowSubagentStateFields/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-role/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-id/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-prompt/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-fork-context/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-max-concurrency/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-budget-json/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-budget-usage-field/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-output-contract-json/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-merge-policy/);
  assert.match(workflowNodeBindingEditorSubagentFields, /workflow-state-subagent-cancellation-inheritance/);
  assert.match(workflowNodeBindingEditorSubagentFields, /value="isolate"/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-memory-record-id/);
  assert.match(workflowNodeBindingEditorSections, /workflow-state-memory-text/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_memory_lane/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_memory_send_options/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_memory_query_output/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_memory_mutation_output/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_search/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_list/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_remember/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_edit/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_delete/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_redacted_memory_record/);
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /workflow_authority_tooling_lane/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_mcp_provider_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_mcp_tool_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_native_tool_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_connector_catalog_describe/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_wallet_capability_dry_run/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_policy_gate/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_approval_gate/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_destructive_denial/,
  );
  assert.match(tauriProjectRuntime, /workflow_scheduler_lane/);
  assert.match(
    workflowSchedulerLaneReadiness,
    /EXPECTED_WORKFLOW_SCHEDULER_LANE_CAPABILITY_IDS/,
  );
  assert.match(workflowSchedulerLaneReadiness, /WORKFLOW_SCHEDULER_LANE_CAPABILITIES/);
  for (const capabilityId of [
    "scheduler",
    "scheduler.finalization",
    "terminalResult",
    "nodeExecution",
    "nodeOutcome",
    "nodeStateUpdate",
    "nodeSuccessEvent",
    "nodeFailureOutcome",
    "interrupt",
    "validation",
  ]) {
    assert.match(workflowSchedulerLaneReadiness, new RegExp(`"${capabilityId}"`));
  }
  for (const proofKey of [
    "workflowSchedulerRuntimeLane",
    "workflowSchedulerFinalizationRuntimeLane",
    "workflowSchedulerTerminalResultRuntimeLane",
    "workflowSchedulerNodeExecutionRuntimeLane",
    "workflowSchedulerNodeOutcomeRuntimeLane",
    "workflowSchedulerNodeStateUpdateRuntimeLane",
    "workflowSchedulerNodeSuccessEventRuntimeLane",
    "workflowSchedulerNodeFailureOutcomeRuntimeLane",
    "workflowSchedulerInterruptRuntimeLane",
    "workflowSchedulerValidationRuntimeLane",
  ]) {
    assert.match(workflowSchedulerLaneReadiness, new RegExp(proofKey));
  }
  assert.match(workflowValidation, /schedulerLaneReadiness/);
  assert.match(workflowValidation, /gateId: "scheduler-lanes"/);
  assert.match(workflowRailPanel, /WorkflowReadinessPanel/);
  assert.match(workflowRailPanel, /runtimeCodingToolBudgetEvidence/);
  assert.match(workflowReadinessPanel, /workflowReadinessModel/);
  assert.match(workflowReadinessPanel, /workflow-readiness-coding-tool-budget-preflight/);
  assert.match(workflowReadinessPanel, /data-tool-call-ids/);
  assert.match(workflowReadinessPanel, /data-policy-decision-refs/);
  assert.match(workflowReadinessModel, /workflowSchedulerLaneReadiness/);
  assert.match(workflowReadinessModel, /WorkflowCodingToolBudgetPreflight/);
  assert.match(workflowReadinessModel, /WorkflowCodingToolBudgetRunLaunchAnnotation/);
  assert.match(workflowReadinessModel, /runtimeCodingToolBudgetEvidence/);
  assert.match(workflowReadinessModel, /workflowCodingToolBudgetRunLaunchAnnotation/);
  assert.match(workflowReadinessModel, /prior_coding_tool_budget_evidence/);
  assert.match(workflowReadinessModel, /Coding budget preflight/);
  assert.match(workflowReadinessModel, /readinessItems/);
  assert.match(workflowReadinessPanel, /workflow-readiness-scheduler-lanes/);
  assert.match(workflowReadinessPanel, /data-proof-check/);
  assert.match(workflowRailPanel, /WorkflowUnitTestsPanel/);
  assert.match(workflowRailPanel, /workflowTestReadinessModel/);
  assert.match(workflowUnitTestsPanel, /workflow-unit-test-list/);
  assert.match(workflowUnitTestsPanel, /workflow-unit-test-uncovered/);
  assert.match(workflowTestReadinessModel, /coveredNodeIds/);
  assert.match(workflowTestReadinessModel, /uncoveredNodes/);
  assert.match(workflowRailPanel, /WorkflowRunsPanel/);
  assert.match(workflowRailPanel, /workflowRunHistoryModel/);
  assert.match(workflowRunsPanel, /workflow-runs-list/);
  assert.match(workflowRunsPanel, /workflow-run-inspector/);
  assert.match(workflowRunsPanel, /workflow-run-timeline/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-graph/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-node-/);
  assert.match(workflowRunsPanel, /data-event-cursor/);
  assert.match(workflowRunsPanel, /data-thread-id/);
  assert.match(workflowRunsPanel, /data-tui-reopen-command/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-tui-reopen/);
  assert.match(workflowRunsPanel, /data-receipt-refs/);
  assert.match(workflowRunsPanel, /data-policy-decision-refs/);
  assert.match(workflowRunsPanel, /workflow-run-diagnostics-repair-actions/);
  assert.match(workflowRunsPanel, /workflow-run-diagnostics-repair-action-/);
  assert.match(workflowRunsPanel, /data-diagnostics-repair-action-count/);
  assert.match(workflowRunsPanel, /onExecuteRuntimeDiagnosticsRepair/);
  assert.match(workflowRunsPanel, /workflow-run-context-pressure-actions/);
  assert.match(workflowRunsPanel, /workflow-run-context-pressure-action-/);
  assert.match(workflowRunsPanel, /data-context-pressure-action-count/);
  assert.match(workflowRunsPanel, /onExecuteRuntimeContextPressureAction/);
  assert.match(workflowRunsPanel, /workflow-run-workspace-trust-actions/);
  assert.match(workflowRunsPanel, /workflow-run-workspace-trust-action-/);
  assert.match(workflowRunsPanel, /data-workspace-trust-action-count/);
  assert.match(workflowRunsPanel, /workflow-run-policy-stack/);
  assert.match(workflowRunsPanel, /data-policy-stack-status/);
  assert.match(workflowRunsPanel, /workflow-run-telemetry-summary/);
  assert.match(workflowRunsPanel, /workflow-run-source-filter/);
  assert.match(workflowRunsPanel, /workflow-run-coding-tool-budget-evidence/);
  assert.match(workflowRunsPanel, /workflow-run-coding-tool-budget-recovery-bind-template-/);
  assert.match(workflowRunsPanel, /onBindRuntimeCodingToolBudgetRecoveryTemplate/);
  assert.match(workflowRunsPanel, /workflow-run-telemetry-source-kinds/);
  assert.match(workflowRunsPanel, /data-telemetry-status/);
  assert.match(workflowRunsPanel, /data-context-pressure-event-count/);
  assert.match(workflowRunsPanel, /data-subagent-count/);
  assert.match(workflowRunsPanel, /data-coding-tool-budget-row-count/);
  assert.match(workflowRunsPanel, /data-visible-row-count/);
  assert.match(workflowRunsPanel, /onExecuteRuntimeWorkspaceTrustAction/);
  assert.match(workflowRunsPanel, /workflow-run-subagent-subflows/);
  assert.match(workflowRunsPanel, /data-subagent-child-subflow-count/);
  assert.match(workflowRunsPanel, /data-usage-row-count/);
  assert.match(workflowRunsPanel, /data-usage-total-tokens/);
  assert.match(workflowRunsPanel, /data-usage-context-pressure-status/);
  assert.match(workflowRunsPanel, /data-child-thread-id/);
  assert.match(workflowRuntimeEventProjection, /WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRuntimeTuiDeepLinkDescriptor/);
  assert.match(workflowRuntimeEventProjection, /tuiDeepLinkForRuntimeThreadEvent/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRuntimeSubagentChildSubflowDescriptor/);
  assert.match(workflowRuntimeEventProjection, /subagentChildSubflowReactFlowNodes/);
  assert.match(workflowRuntimeEventProjection, /runtimeSubagentSubflow/);
  assert.match(workflowRuntimeEventProjection, /diagnosticsRepairActionsForEvents/);
  assert.match(workflowRuntimeEventProjection, /contextPressureActionsForEvents/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRuntimeContextPressureActionDescriptor/);
  assert.match(workflowRuntimeEventProjection, /workspaceTrustActionsForEvents/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRuntimeWorkspaceTrustActionDescriptor/);
  assert.match(workflowRuntimeEventProjection, /runtime_workspace_trust_gate/);
  assert.match(workflowRuntimePolicyStack, /WORKFLOW_RUNTIME_POLICY_STACK_SCHEMA_VERSION/);
  assert.match(workflowRuntimePolicyStack, /approved_retry/);
  assert.match(workflowRuntimeEditProposalPolicy, /WORKFLOW_RUNTIME_EDIT_PROPOSAL_POLICY_SCHEMA_VERSION/);
  assert.match(workflowRuntimeEditProposalPolicy, /proposal_apply/);
  assert.match(workflowRuntimeTelemetrySummary, /WORKFLOW_RUNTIME_TELEMETRY_SUMMARY_SCHEMA_VERSION/);
  assert.match(workflowRuntimeTelemetrySummary, /workflowRuntimeTelemetrySummaryFromProjection/);
  assert.match(workflowRuntimeTelemetrySummary, /workflowRuntimeTelemetrySummaryToUsageTelemetry/);
  assert.match(workflowRuntimeTelemetrySummary, /ioi\.workflow_runtime_telemetry_summary_usage/);
  assert.match(workflowRuntimeTelemetrySummary, /runtime_usage_events/);
  assert.match(workflowRuntimeTelemetrySummary, /tui_subagent_rows/);
  assert.match(workflowRunHistoryModel, /workflowRuntimePolicyStackFromEvents/);
  assert.match(workflowRunHistoryModel, /runtimePolicyStack/);
  assert.match(workflowRunHistoryModel, /workflowRuntimeEditProposalPolicyStackFromEvents/);
  assert.match(workflowRunHistoryModel, /runtimeEditProposalPolicyStack/);
  assert.match(workflowRunHistoryModel, /runtimeTelemetrySummary/);
  assert.match(workflowRunHistoryModel, /runtimeTelemetrySourceFilters/);
  assert.match(workflowRunHistoryModel, /runtimeCodingToolBudgetEvidence/);
  assert.match(workflowRunHistoryModel, /visibleTuiControlStateRows/);
  assert.match(workflowRunsPanel, /workflow-run-edit-proposal-policy-stack/);
  assert.match(workflowRunsPanel, /workflow-run-coding-tool-budget-recovery-action/);
  assert.match(workflowRunsPanel, /workflow-run-coding-tool-budget-recovery-subflow-/);
  assert.match(workflowRunsPanel, /workflow-run-telemetry-bind-source/);
  assert.match(workflowRunsPanel, /data-coding-tool-budget-recovery-action-count/);
  assert.match(workflowRunsPanel, /data-recovery-policy-operator-role/);
  assert.match(workflowRunsPanel, /onCreateRuntimeCodingToolBudgetRecoverySubflow/);
  assert.match(runtimeDaemon, /proposeWorkflowEdit/);
  assert.match(runtimeDaemon, /applyWorkflowEditProposal/);
  assert.match(runtimeDaemon, /action === "workflow-edit-proposals"/);
  assert.match(workflowValidation, /workflowWorkspaceTrustGateIssues/);
  assert.match(workflowValidation, /missing_workspace_trust_gate/);
  assert.match(workflowValidation, /workflowRuntimeCodingToolBudgetRecoveryBindingIssues/);
  assert.match(workflowValidation, /missing_runtime_coding_tool_budget_recovery_policy_binding/);
  assert.match(workflowValidation, /workflowRuntimeTelemetrySourceBindingIssues/);
  assert.match(workflowValidation, /missing_runtime_telemetry_source_usage_binding/);
  assert.match(tauriProjectValidation, /workflow_runtime_coding_tool_budget_recovery_binding_issues/);
  assert.match(tauriProjectValidation, /missing_runtime_coding_tool_budget_recovery_policy_binding/);
  assert.match(workflowComposerController, /workflowWorkspaceTrustGateReadiness/);
  assert.match(workflowComposerController, /createRuntimeThreadModeControlRequestFromWorkflowNode/);
  assert.match(workflowComposerController, /workspace_trust_warning_not_emitted/);
  assert.match(workflowComposerController, /workflowRunHistoryModel/);
  assert.match(workflowComposerController, /workflowRunCodingBudgetPreflight/);
  assert.match(workflowComposerController, /coding_tool_budget_preflight_blocked/);
  assert.match(workflowComposerController, /codingToolBudgetPreflight/);
  assert.match(workflowComposerController, /codingToolBudgetRecovery/);
  assert.match(workflowComposerController, /handleExecuteRuntimeCodingToolBudgetRecovery/);
  assert.match(workflowComposerController, /handleCreateRuntimeCodingToolBudgetRecoverySubflow/);
  assert.match(workflowComposerController, /handleBindRuntimeCodingToolBudgetRecoveryTemplate/);
  assert.match(workflowComposerController, /handleBindRuntimeTelemetrySource/);
  assert.match(workflowComposerController, /createWorkflowRuntimeCodingToolBudgetRecoverySubflow/);
  assert.match(workflowComposerController, /handleInsertRuntimeCodingToolBudgetRecoveryTemplate/);
  assert.match(workflowComposerController, /createWorkflowRuntimeCodingToolBudgetRecoveryTemplateSubflow/);
  assert.match(workflowComposerController, /bindWorkflowRuntimeCodingToolBudgetRecoveryTemplateToEvidence/);
  assert.match(workflowComposerController, /bindWorkflowRuntimeTelemetrySourceToWorkflow/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryBinding, /WORKFLOW_RUNTIME_CODING_TOOL_BUDGET_RECOVERY_BINDING_SCHEMA_VERSION/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryBinding, /workflowRuntimeCodingToolBudgetRecoveryEvidenceActionsFromProjection/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryBinding, /react_flow_quick_fix/);
  assert.match(workflowComposerController, /coding-tool-budget-approved-retry/);
  assert.match(workflowComposerController, /coding-tool-budget-preflight/);
  assert.match(workflowComposerController, /inspector-coding-tool-budget-preflight/);
  assert.match(workflowRuntimeDiagnosticsRepairActions, /WorkflowRuntimeDiagnosticsRepairActionDescriptor/);
  assert.match(workflowRuntimeDiagnosticsRepairActions, /repair_decisions/);
  assert.match(workflowRuntimeDiagnosticsRepairActions, /runtime\.run-inspector\.diagnostics-repair/);
  assert.match(workflowComposerController, /loadWorkflowRuntimeThreadEvents/);
  assert.match(workflowComposerController, /setRuntimeThreadEvents/);
  assert.match(workflowComposerController, /createRuntimeDiagnosticsRepairControlRequest/);
  assert.match(workflowComposerController, /handleExecuteRuntimeDiagnosticsRepair/);
  assert.match(workflowComposerController, /createRuntimeApprovalRequestControlRequest/);
  assert.match(workflowComposerController, /createRuntimeContextCompactControlRequest/);
  assert.match(workflowComposerController, /createRuntimeOperatorInterruptControlRequest/);
  assert.match(workflowComposerController, /createRuntimeThreadModeControlRequestFromWorkflowNode/);
  assert.match(workflowComposerController, /createRuntimeWorkspaceTrustAcknowledgementControlRequest/);
  assert.match(workflowComposerController, /createRuntimeSubagentControlRequest/);
  assert.match(workflowComposerController, /handleExecuteRuntimeContextPressureAction/);
  assert.match(workflowComposerController, /handleExecuteRuntimeWorkspaceTrustAction/);
  assert.match(workflowComposerController, /"request_approval"/);
  assert.match(workflowComposerController, /"delegate_summary"/);
  assert.match(workflowComposerController, /executeWorkflowRuntimeControlRequest/);
  assert.match(workflowComposerView, /runtimeThreadEvents=\{runtimeThreadEvents\}/);
  assert.match(workflowComposerView, /workflowRunLaunchBlocked/);
  assert.match(workflowComposerView, /data-workflow-run-launch-blocked/);
  assert.match(workflowComposerView, /data-coding-tool-budget-preflight-status/);
  assert.match(workflowComposerView, /data-disabled-reason/);
  assert.match(workflowComposerView, /onExecuteRuntimeDiagnosticsRepair/);
  assert.match(workflowComposerView, /onExecuteRuntimeContextPressureAction/);
  assert.match(workflowComposerView, /onExecuteRuntimeWorkspaceTrustAction/);
  assert.match(workflowComposerView, /onExecuteRuntimeCodingToolBudgetRecovery/);
  assert.match(workflowComposerView, /onCreateRuntimeCodingToolBudgetRecoverySubflow/);
  assert.match(workflowComposerView, /workflow-add-coding-budget-recovery-template/);
  assert.match(workflowComposerView, /handleInsertRuntimeCodingToolBudgetRecoveryTemplate/);
  assert.match(runtimeDaemon, /context_pressure_alert/);
  assert.match(runtimeDaemon, /context\.pressure_alert/);
  assert.match(runtimeDaemon, /requestThreadApproval/);
  assert.match(runtimeDaemon, /OperatorApproval\.Request/);
  assert.match(runtimeDaemon, /approval\.required/);
  assert.match(runtimeDaemon, /codingToolApprovalManifestForThread/);
  assert.match(runtimeDaemon, /codingToolApprovalSatisfaction/);
  assert.match(runtimeDaemon, /codingToolApprovalManifestsMatch/);
  assert.match(runtimeDaemon, /codingToolBudgetPolicyForRequest/);
  assert.match(runtimeDaemon, /coding_tool_budget_exceeded/);
  assert.match(runtimeDaemon, /codingToolBudgetRecoveryForRun/);
  assert.match(runtimeDaemon, /coding-tool-budget-recovery/);
  assert.match(runtimeDaemon, /WorkflowRunCodingToolBudgetApprovedRetry/);
  assert.match(runtimeDaemon, /ioi\.workflow\.coding-tool-budget-recovery\.v1/);
  assert.match(runtimeDaemon, /workflow_node_requires_approval/);
  assert.match(runtimeDaemon, /workflow_trust_profile_requires_approval/);
  assert.match(runtimeDaemon, /approval_decision_event_id/);
  assert.match(runtimeDaemon, /coding_tool_approval_required/);
  assert.match(runtimeDaemon, /thread_review_mode_requires_approval/);
  assert.match(runtimeDaemon, /WORKSPACE_TRUST_WARNING_SCHEMA_VERSION/);
  assert.match(runtimeDaemon, /WORKSPACE_TRUST_ACKNOWLEDGEMENT_SCHEMA_VERSION/);
  assert.match(runtimeDaemon, /workspace\.trust_warning/);
  assert.match(runtimeDaemon, /workspace\.trust_acknowledged/);
  assert.match(runtimeDaemon, /canvas_local_trust_state_accepted/);
  assert.match(workflowRuntimeEventProjection, /workspace_trust_warning/);
  assert.match(workflowRuntimeEventProjection, /workspace_trust_acknowledged/);
  assert.match(workflowRuntimeEventProjection, /approval_decision/);
  assert.match(workflowRuntimeEventProjection, /codingToolBudgetRecoveryActions/);
  assert.match(workflowRuntimeEventProjection, /recoveryPolicy/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRunCodingToolBudgetApprovedRetry/);
  assert.match(workflowRuntimeEventProjection, /ioi\.workflow\.coding-tool-budget-recovery\.v1/);
  assert.match(workflowRuntimeEventProjection, /workflowCodingToolBudgetRecoveryPolicyFromUnknown/);
  assert.match(workflowRuntimeEventProjection, /workflow\.run\.retry_completed/);
  assert.match(workflowRuntimeEventProjection, /workspaceTrustRows/);
  assert.match(graphRuntimeTypes, /executeWorkflowRuntimeControlRequest\?/);
  assert.match(graphRuntimeTypes, /WorkflowRunRequestOptions/);
  assert.match(graphRuntimeTypes, /codingToolBudgetPreflight/);
  assert.match(graphRuntimeTypes, /codingToolBudgetRecovery/);
  assert.match(tauriProjectCommands, /workflow_coding_tool_budget_preflight_blocked_from_options/);
  assert.match(tauriProjectCommands, /workflow_coding_tool_budget_preflight_blocked_result/);
  assert.match(tauriProjectCommands, /workflow_coding_tool_budget_recovery_from_options/);
  assert.match(tauriProjectCommands, /workflow_coding_tool_budget_recovery_control_result/);
  assert.match(tauriProjectCommands, /workflow_attach_coding_tool_budget_recovery_retry/);
  assert.match(tauriProjectTypes, /runtime_thread_events/);
  assert.match(tauriProjectTypes, /tui_control_state/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /ioi\.workflow\.coding-tool-budget-preflight\.v1/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /ioi\.workflow\.coding-tool-budget-recovery\.v1/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /ioi\.workflow\.coding-tool-budget-recovery-policy\.v1/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /WorkflowRunCodingToolBudgetPreflightBlocked/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /WorkflowRunCodingToolBudgetApprovedRetry/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /workflow_coding_tool_budget_recovery_retry_count/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /workflow_coding_tool_budget_recovery_from_options/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /workflow_coding_tool_budget_recovery_control_result/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /workflow_attach_coding_tool_budget_recovery_retry/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /coding_tool_budget_preflight_blocked/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /runtime_thread_events/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /tui_control_state/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /policy_blocked/);
  assert.match(tauriProjectWorkflowRunPolicyLane, /workflow_finalize_run_result/);
  assert.match(graphRuntimeTypes, /WorkflowRuntimeControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeApprovalRequestControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeCodingToolControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeContextCompactControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeOperatorInterruptControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeThreadModeControlRequest/);
  assert.match(graphRuntimeTypes, /RuntimeWorkspaceTrustAcknowledgementControlRequest/);
  assert.match(tauriRuntime, /execute_workflow_runtime_control_request/);
  assert.match(tauriArtifacts, /execute_workflow_runtime_control_request/);
  assert.match(tauriLib, /execute_workflow_runtime_control_request/);
  assert.match(workflowRunHistoryModel, /visibleRows/);
  assert.match(workflowRunHistoryModel, /timelineEvents/);
  assert.match(workflowRunHistoryModel, /comparison/);
  assert.match(workflowRunHistoryModel, /runtimeEventProjection/);
  assert.match(workflowRunHistoryModel, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.doesNotMatch(tauriProjectRuntime, /fn execute_workflow_project\(/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /fn execute_workflow_project\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_node_execution_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_finalization_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_finalized_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /fn workflow_scheduler_execute_node\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /enum WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /execute_workflow_node/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_max_attempts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_scheduler_node_outcome_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_scheduler_handle_node_outcome/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_push_event/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /node_started/);
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /retrying/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_selected_output/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_node_logic/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_next_ready_nodes/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_checkpoint_state/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /node_succeeded/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /child_run_completed/,
  );
  assert.doesNotMatch(tauriProjectWorkflowSchedulerNodeExecutionLane, /output_created/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /fn workflow_scheduler_handle_node_outcome\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_state_update_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_apply_node_state_update/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_success_event_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_emit_node_success_events/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_failure_outcome_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_handle_node_failure_outcome/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_selected_output/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_node_logic/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /pending_writes/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_push_event/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /node_succeeded/,
  );
  assert.doesNotMatch(tauriProjectWorkflowSchedulerNodeOutcomeLane, /node_failed/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /child_run_completed/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /output_created/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /fn workflow_scheduler_handle_node_failure_outcome\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_node_name/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /blocked_node_ids/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeFailureOutcomeLane, /node_failed/);
  assert.match(tauriProjectWorkflowSchedulerNodeFailureOutcomeLane, /error/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /fn workflow_scheduler_emit_node_success_events\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /WorkflowStateUpdate/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /workflow_node_name/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeSuccessEventLane, /node_succeeded/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /child_run_completed/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeSuccessEventLane, /output_created/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /fn workflow_scheduler_apply_node_state_update\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /WorkflowStateUpdate/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_selected_output/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_node_logic/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /branch_decisions/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /pending_writes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /completed_node_ids/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /interrupted_node_ids/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /node_outputs/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeStateUpdateLane, /merge/);
  assert.match(tauriProjectWorkflowSchedulerNodeStateUpdateLane, /append/);
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /fn workflow_scheduler_finalized_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_completion_has_missing/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /struct WorkflowSchedulerTerminalResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /fn workflow_scheduler_terminal_summary\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /fn workflow_scheduler_terminal_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_push_event/,
  );
  assert.match(tauriProjectWorkflowSchedulerTerminalResultLane, /run_completed/);
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /save_workflow_thread/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /WorkflowRunResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_interrupt_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /fn workflow_scheduler_interrupted_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_runtime_interrupt/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_runtime_interrupt_notice/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_interrupt_path/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_finalize_run_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_validation_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /fn workflow_scheduler_validation_blocked_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_finalize_run_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_approval_interrupt_lane/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_approval_binding\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_approval_preview\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt_prompt\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt_notice\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt\(/,
  );
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /WorkflowInterrupt/);
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /requiresApproval/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_binding_lane/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_node_schema/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_function_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_tool_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_parser_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_model_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_connector_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_sandbox_policy/);
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_sandbox_precheck/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_dependency_precheck/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_input_schema/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_output_schema/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_checkpoint_lane/,
  );
  assert.match(
    tauriProjectWorkflowCheckpointLane,
    /fn workflow_checkpoint_state\(/,
  );
  assert.match(tauriProjectWorkflowCheckpointLane, /WorkflowCheckpoint/);
  assert.match(tauriProjectWorkflowCheckpointLane, /WorkflowStateSnapshot/);
  assert.match(tauriProjectWorkflowCheckpointLane, /save_workflow_checkpoint/);
  assert.match(tauriProjectWorkflowCheckpointLane, /unique_runtime_id/);
  assert.match(tauriProjectWorkflowCheckpointLane, /active_node_ids\.sort/);
  assert.match(tauriProjectWorkflowSchedulerLane, /workflow_state_lane/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_predecessor_output\(/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_mapped_node_input\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn workflow_first_expression_source\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_selected_output\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn validate_workflow_expression_refs\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_schema_from_sample\(/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_schema_is_object_like\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn workflow_node_declared_output_schema\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /workflow_value_at_path/);
  assert.match(tauriProjectWorkflowStateLane, /workflow_edge_from_port/);
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_action_frame\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_node_port_connection_class\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_default_port_connection_class\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn validate_workflow_edge_ports\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_max_attempts\(/,
  );
  assert.match(tauriProjectWorkflowNodeContractLane, /ActionFrame/);
  assert.match(tauriProjectWorkflowNodeContractLane, /ActionBindingRef/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_edge_connection_class/);
  assert.match(tauriProjectWorkflowNodeContractLane, /validate_workflow_connection_class/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_logic_string/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_action_frame/);
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /workflow_max_attempts/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_node_metadata_lane/,
  );
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_value_string\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_id\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_type\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_name\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_logic\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_law\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_by_id/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /WorkflowProject/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /workflow_node_metadata_lane/);
  assert.doesNotMatch(tauriProjectWorkflowRunLifecycleLane, /use super::runtime::/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowStateLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectValidation, /workflow_node_metadata_lane/);
  assert.match(tauriProjectPackage, /workflow_node_metadata_lane/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_run_lifecycle_lane/,
  );
  assert.match(tauriProjectWorkflowRunLifecycleLane, /fn workflow_push_event\(/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /fn new_workflow_thread\(/);
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /fn initial_workflow_state\(/,
  );
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /fn workflow_single_node_result\(/,
  );
  assert.match(tauriProjectWorkflowRunLifecycleLane, /WorkflowStreamEvent/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /WorkflowStateSnapshot/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /execute_workflow_node/);
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_tool_binding\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_function_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_harness_canary_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_harness_live_default_node\(/,
  );
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_output_lane/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::GithubPrCreate/);
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /ActionKind::WorkflowPackageExport/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /ActionKind::WorkflowPackageImport/,
  );
  assert.match(
    tauriProjectWorkflowOutputLane,
    /workflow_output_satisfies_schema/,
  );
  assert.match(tauriProjectWorkflowOutputLane, /workflow_truncate_output/);
  assert.match(tauriProjectWorkflowOutputLane, /workflow_output_bundle/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowOutputBundle/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowMaterializedAsset/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowRendererRef/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowDeliveryTarget/);
  assert.match(tauriProjectWorkflowSchedulerLane, /workflow_coding_route_lane/);
  assert.match(tauriProjectWorkflowCodingRouteLane, /struct WorkflowSkillResolver/);
  assert.match(tauriProjectWorkflowCodingRouteLane, /resolve_skill_context/);
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_evidence_from_run/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_benchmark_results/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_promotion_decisions/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_run_summary/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_route_verification_evidence/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_execution_results_lane/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /struct WorkflowRunResultParts/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_run_result_from_parts/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_verification_evidence_from_node_runs/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_coding_route_evidence_from_run/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_graph_execution_lane/,
  );
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_edge_from/);
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_edge_to/);
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_edge_connection_class/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_has_incoming_connection_class/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_edge_is_selected/,
  );
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_node_ready/);
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_harness_results_lane/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_attempt_for_node_run/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_shadow_comparison_records_for_attempt_records/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_gated_cluster_runs_for_attempt_records/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /DEFAULT_AGENT_HARNESS_ACTIVATION_ID/,
  );
  assert.match(tauriProjectWorkflowHarnessResultsLane, /workflow_hash_value/);
  assert.match(workflowContracts, /runtime\.task/);
  assert.match(workflowContracts, /runtime\.job/);
  assert.match(workflowContracts, /runtime\.checklist/);
  assert.match(workflowContracts, /runtime\.ui_string_catalog/);
  assert.match(workflowContracts, /runtime\.accessible_status/);
  assert.match(workflowContracts, /workflow\.package_export/);
  assert.match(workflowContracts, /workflow\.package_import/);
  assert.match(graphTypes, /workflowChromeLocale\?: string/);
  assert.match(workflowDefaults, /workflowChromeLocale: "en-US"/);
  assert.match(workflowDefaults, /config\?\.workflowChromeLocale/);
  assert.match(graphTypes, /workflowChromeLocale\?: string \| null/);
  assert.match(graphTypes, /workflowPackageExportEndpoint\?: string/);
  assert.match(graphTypes, /workflowPackageImportEndpoint\?: string/);
  assert.match(graphTypes, /runtimeDiagnosticsRepairEndpoint\?: string/);
  assert.match(graphTypes, /runtimeDiagnosticsRepairDecisionIdField\?: string/);
  assert.match(graphTypes, /consumesRuntimeDiagnosticsRepair\?: boolean/);
  assert.match(graphTypes, /runtimeCodingToolBudgetRecoveryEndpoint\?: string/);
  assert.match(graphTypes, /runtimeCodingToolBudgetRecoveryRunIdField\?: string/);
  assert.match(graphTypes, /consumesRuntimeCodingToolBudgetRecovery\?: boolean/);
  assert.match(graphTypes, /consumesWorkflowPackageExport\?: boolean/);
  assert.match(graphTypes, /consumesWorkflowPackageImportReview\?: boolean/);
  assert.match(graphTypes, /\| "workflow_package_export"/);
  assert.match(graphTypes, /\| "workflow_package_import"/);
  assert.match(graphTypes, /workflowPackageImportLocalePreservedField\?: string/);
  assert.match(workflowComposerController, /sourceWorkflowChromeLocale/);
  assert.match(workflowComposerController, /portableManifest\?\.workflowChromeLocale/);
  assert.match(workflowComposerController, /workflowChromeLocalePreserved/);
  assert.match(workflowRailPanel, /data-workflow-chrome-locale/);
  assert.match(workflowRailPanel, /data-package-import-source-chrome-locale/);
  assert.match(workflowRailPanel, /data-package-import-imported-chrome-locale/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /data-package-import-chrome-locale-preserved/);
  assert.match(workflowRailModel, /manifest\.workflowChromeLocale/);
  assert.match(workflowRailModel, /workflowPackageNodeOutputSummary/);
  assert.match(workflowRailModel, /workflowPackageNodeOutputStatus/);
  assert.match(workflowRailModel, /workflow\.package\.export/);
  assert.match(workflowRailModel, /workflow\.package\.import/);
  assert.match(workflowRailModel, /workflowChromeLocalePreserved/);
  assert.match(workflowRailModel, /WorkflowGithubPrCreatePlanSummary/);
  assert.match(workflowRailModel, /workflowGithubPrCreatePlanSummary/);
  assert.match(workflowRailModel, /workflowGithubPrCreatePlanStatus/);
  assert.match(workflowRailModel, /github__pr_create/);
  assert.match(workflowRailModel, /requestPayloadHash/);
  assert.match(workflowRailModel, /missingScopes/);
  assert.match(workflowRailPanel, /workflow-selected-node-package-output-summary/);
  assert.match(workflowRailPanel, /workflowPackageNodeOutputSummary/);
  assert.match(workflowRailPanel, /data-package-node-kind/);
  assert.match(workflowRailPanel, /data-package-path/);
  assert.match(workflowRailPanel, /data-imported-workflow-path/);
  assert.match(workflowRailPanel, /data-workflow-chrome-locale-preserved/);
  assert.match(workflowRailPanel, /WorkflowGithubPrCreateOutputSummaryCard/);
  assert.match(workflowRailPanel, /workflow-selected-node-github-pr-create-output-summary/);
  assert.match(workflowRailPanel, /data-github-pr-create-request-hash/);
  assert.match(workflowRailPanel, /data-github-pr-create-dry-run/);
  assert.match(workflowRailPanel, /data-github-pr-create-mutation-executed/);
  assert.match(workflowRailPanel, /data-github-pr-create-missing-scopes/);
  assert.match(workflowRailPanel, /data-github-pr-create-review-gate-status/);
  assert.match(workflowRailPanel, /data-github-pr-create-receipt-refs/);
  assert.match(workflowRailPanel, /data-github-pr-create-replay-fixture-ref/);
  assert.match(workflowBottomShelf, /workflow-selection-package-output-summary/);
  assert.match(workflowBottomShelf, /workflowPackageNodeOutputSummary/);
  assert.match(workflowBottomShelf, /workflow-selection-github-pr-create-output-summary/);
  assert.match(workflowBottomShelf, /workflowGithubPrCreatePlanSummary/);
  assert.match(workflowBottomShelf, /workflowGithubPrCreatePlanStatus/);
  assert.match(tauriProjectTypes, /workflow_chrome_locale: Option<String>/);
  assert.match(tauriProjectCommands, /get\("workflowChromeLocale"\)/);
  assert.match(tauriProjectCommands, /manifest\.workflow_chrome_locale/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::WorkflowPackageExport/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::WorkflowPackageImport/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::GithubPrCreate/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::RuntimeThreadMode/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::RuntimeWorkspaceTrustGate/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::RuntimeRollbackSnapshot/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::RuntimeRestoreGate/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::RuntimeCodingToolBudgetRecovery/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_runtime_rollback_snapshot_output/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_runtime_restore_gate_output/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_runtime_coding_tool_budget_recovery_output/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_runtime_thread_mode_output/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_runtime_workspace_trust_gate_output/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_package_lane/);
  assert.match(tauriProjectWorkflowPackageLane, /execute_workflow_package_export_node/);
  assert.match(tauriProjectWorkflowPackageLane, /execute_workflow_package_import_node/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /repository_pr_lane/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_value_helpers/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_value_helpers/);
  assert.match(tauriProjectRepositoryPrLane, /workflow_value_helpers/);
  assert.match(tauriProjectRepositoryPrLane, /workflow_github_pr_create_output/);
  assert.match(tauriProjectWorkflowValueHelpers, /workflow_value_at_path/);
  assert.match(tauriProjectWorkflowValueHelpers, /workflow_hash_value_raw_hex/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_package_export/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_package_import/);
  assert.match(tauriProjectRepositoryPrLane, /github_pr_create/);
  assert.match(tauriProjectWorkflowPackageLane, /workflowPackageImportReview/);
  assert.match(tauriProjectTemplates, /workflow_package_export/);
  assert.match(tauriProjectTemplates, /workflow_package_import/);
  assert.match(tauriProjectTemplates, /github_pr_create/);
  assert.match(tauriProjectTemplates, /workflow_package_export_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_package_import_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_thread_fork_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_operator_interrupt_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_operator_steer_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_thread_mode_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_workspace_trust_gate_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_context_compact_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_rollback_snapshot_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_restore_gate_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_coding_tool_budget_recovery_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_github_pr_create_output_schema/);
  assert.match(tauriRuntimeProjection, /WorkflowPackageExport/);
  assert.match(tauriRuntimeProjection, /WorkflowPackageImport/);
  assert.match(tauriRuntimeProjection, /RuntimeThreadFork/);
  assert.match(tauriRuntimeProjection, /RuntimeOperatorInterrupt/);
  assert.match(tauriRuntimeProjection, /RuntimeOperatorSteer/);
  assert.match(tauriRuntimeProjection, /RuntimeThreadMode/);
  assert.match(tauriRuntimeProjection, /RuntimeWorkspaceTrustGate/);
  assert.match(tauriRuntimeProjection, /RuntimeContextCompact/);
  assert.match(tauriRuntimeProjection, /RuntimeRollbackSnapshot/);
  assert.match(tauriRuntimeProjection, /RuntimeRestoreGate/);
  assert.match(tauriRuntimeProjection, /RuntimeCodingToolBudgetRecovery/);
  assert.match(tauriRuntimeProjection, /GithubPrCreate/);
  assert.match(tauriRuntimeProjection, /output_bundle/);
  assert.match(workflowContracts, /repository\.context/);
  assert.match(workflowContracts, /repository\.branch_policy/);
  assert.match(workflowContracts, /repository\.github_context/);
  assert.match(workflowContracts, /repository\.issue/);
  assert.match(workflowContracts, /repository\.pr_attempt/);
  assert.match(workflowContracts, /repository\.review_gate/);
  assert.match(workflowContracts, /repository\.github_pr_create/);
  assert.match(workflowContracts, /runtime\.doctor/);
  assert.match(nodeRegistry, /runtime_doctor/);
  assert.match(nodeRegistry, /RuntimeDoctorNode/);
  assert.match(nodeRegistry, /\/v1\/doctor/);
  assert.match(nodeRegistry, /blockOnRequiredFailures/);
  assert.match(nodeRegistry, /runtimeUiStringCatalogRef/);
  assert.match(nodeRegistry, /workflowChromeLocale/);
  assert.match(nodeRegistry, /localeKey/);
  assert.match(nodeRegistry, /ariaLabelKey/);
  assert.match(nodeRegistry, /statusAnnouncementKey/);
  assert.match(nodeRegistry, /accessibleStatusField/);
  assert.match(nodeRegistry, /colorIndependentStatus/);
  assert.match(nodeRegistry, /runtime_task/);
  assert.match(nodeRegistry, /RuntimeTaskNode/);
  assert.match(nodeRegistry, /\/v1\/tasks/);
  assert.match(nodeRegistry, /\/v1\/tasks\/\{taskId\}\/cancel/);
  assert.match(nodeRegistry, /runtimeTaskStatusField/);
  assert.match(nodeRegistry, /runtimeTaskCancelEndpoint/);
  assert.match(nodeRegistry, /runtime_job/);
  assert.match(nodeRegistry, /RuntimeJobNode/);
  assert.match(nodeRegistry, /\/v1\/jobs/);
  assert.match(nodeRegistry, /\/v1\/jobs\/\{jobId\}\/cancel/);
  assert.match(nodeRegistry, /runtimeJobLifecycleField/);
  assert.match(nodeRegistry, /runtimeJobCancelEndpoint/);
  assert.match(nodeRegistry, /runtime_checklist/);
  assert.match(nodeRegistry, /RuntimeChecklistNode/);
  assert.match(nodeRegistry, /runtimeChecklistStatusField/);
  assert.match(nodeRegistry, /\/v1\/runs\/\{runId\}\/trace/);
  assert.match(nodeRegistry, /runtime_thread_fork/);
  assert.match(nodeRegistry, /RuntimeThreadForkNode/);
  assert.match(nodeRegistry, /runtimeThreadForkWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/fork/);
  assert.match(nodeRegistry, /runtime_operator_interrupt/);
  assert.match(nodeRegistry, /RuntimeOperatorInterruptNode/);
  assert.match(nodeRegistry, /runtimeOperatorInterruptWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/turns\/\{turnId\}\/interrupt/);
  assert.match(nodeRegistry, /runtime_operator_steer/);
  assert.match(nodeRegistry, /RuntimeOperatorSteerNode/);
  assert.match(nodeRegistry, /runtimeOperatorSteerWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/turns\/\{turnId\}\/steer/);
  assert.match(nodeRegistry, /runtime_context_compact/);
  assert.match(nodeRegistry, /RuntimeContextCompactNode/);
  assert.match(nodeRegistry, /runtimeContextCompactWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/compact/);
  assert.match(nodeRegistry, /runtime_rollback_snapshot/);
  assert.match(nodeRegistry, /RuntimeRollbackSnapshotNode/);
  assert.match(nodeRegistry, /runtimeRollbackSnapshotWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/snapshots/);
  assert.match(nodeRegistry, /runtime_restore_gate/);
  assert.match(nodeRegistry, /RuntimeRestoreGateNode/);
  assert.match(nodeRegistry, /runtimeRestoreGateSnapshotIdField/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/snapshots\/\{snapshotId\}\/restore-\{mode\}/);
  assert.match(nodeRegistry, /runtime_diagnostics_repair/);
  assert.match(nodeRegistry, /RuntimeDiagnosticsRepairNode/);
  assert.match(nodeRegistry, /runtimeDiagnosticsRepairDecisionIdField/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/diagnostics\/repair-decisions\/\{decisionId\}\/execute/);
  assert.match(nodeRegistry, /runtime_coding_tool_budget_recovery/);
  assert.match(nodeRegistry, /RuntimeCodingToolBudgetRecoveryNode/);
  assert.match(nodeRegistry, /runtimeCodingToolBudgetRecoveryRunIdField/);
  assert.match(nodeRegistry, /\/v1\/runs\/\{runId\}\/coding-tool-budget-recovery/);
  assert.match(nodeRegistry, /runtime_thread_mode/);
  assert.match(nodeRegistry, /RuntimeThreadModeNode/);
  assert.match(nodeRegistry, /runtimeThreadModeWorkspaceTrustWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/mode/);
  assert.match(nodeRegistry, /runtime_workspace_trust_gate/);
  assert.match(nodeRegistry, /WorkspaceTrustGateNode/);
  assert.match(nodeRegistry, /runtimeWorkspaceTrustGateWarningWorkflowNodeId/);
  assert.match(graphTypes, /runtimeWorkspaceTrustGateWarningWorkflowNodeId\?: string/);
  assert.match(graphTypes, /consumesRuntimeWorkspaceTrustGate\?: boolean/);
  assert.match(runtimeActionSchema, /runtime_workspace_trust_gate/);
  assert.match(generatedActionSchema, /runtime_workspace_trust_gate/);
  assert.match(generatedRustActionSchema, /runtime_workspace_trust_gate/);
  assert.match(workflowRuntimeControlNodes, /createRuntimeThreadModeControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeControlNodes, /createRuntimeWorkspaceTrustAcknowledgementControlRequest/);
  assert.match(workflowRuntimeControlNodes, /RUNTIME_THREAD_MODE_SOURCE_EVENT_KIND/);
  assert.match(workflowRuntimeControlNodes, /WorkspaceTrust\.Acknowledged/);
  assert.match(workflowRuntimeControlNodes, /createRuntimeDiagnosticsRepairControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeControlNodes, /RUNTIME_DIAGNOSTICS_REPAIR_SOURCE_EVENT_KIND/);
  assert.match(workflowRuntimeControlNodes, /operatorOverrideApproved/);
  assert.match(workflowRuntimeControlNodes, /allowConflicts/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /createRuntimeCodingToolBudgetRecoveryControlRequestFromWorkflowNode/);
  assert.match(workflowRuntimeCodingToolBudgetRecoveryControlNodes, /RUNTIME_CODING_TOOL_BUDGET_RECOVERY_SOURCE_EVENT_KIND/);
  assert.match(nodeRegistry, /workflow_package_export/);
  assert.match(nodeRegistry, /WorkflowPackageExportNode/);
  assert.match(nodeRegistry, /workflow\.package\.export/);
  assert.match(nodeRegistry, /workflowPackageExport\.manifest\.workflowChromeLocale/);
  assert.match(nodeRegistry, /workflowPackageExport\.manifest\.harnessPackageManifest/);
  assert.match(nodeRegistry, /workflow_package_import/);
  assert.match(nodeRegistry, /WorkflowPackageImportNode/);
  assert.match(nodeRegistry, /workflow\.package\.import/);
  assert.match(nodeRegistry, /workflowPackageImportReview\.evidence\.packageEvidenceReady/);
  assert.match(nodeRegistry, /workflowPackageImportReview\.evidence\.workflowChromeLocalePreserved/);
  assert.match(nodeRegistry, /repository_context/);
  assert.match(nodeRegistry, /RepositoryContextNode/);
  assert.match(nodeRegistry, /\/v1\/repository-context/);
  assert.match(nodeRegistry, /repositoryDirtyField/);
  assert.match(nodeRegistry, /branch_policy/);
  assert.match(nodeRegistry, /BranchPolicyNode/);
  assert.match(nodeRegistry, /branchPolicyStatusField/);
  assert.match(nodeRegistry, /protectedBranchNames/);
  assert.match(nodeRegistry, /github_context/);
  assert.match(nodeRegistry, /GitHubContextNode/);
  assert.match(nodeRegistry, /\/v1\/github-context/);
  assert.match(nodeRegistry, /githubPrPreconditionsField/);
  assert.match(nodeRegistry, /issue_context/);
  assert.match(nodeRegistry, /IssueContextNode/);
  assert.match(nodeRegistry, /\/v1\/issue-context/);
  assert.match(nodeRegistry, /issueContextBoundField/);
  assert.match(nodeRegistry, /pr_attempt/);
  assert.match(nodeRegistry, /PrAttemptNode/);
  assert.match(nodeRegistry, /\/v1\/pr-attempts/);
  assert.match(nodeRegistry, /prAttemptAuthorityField/);
  assert.match(nodeRegistry, /review_gate/);
  assert.match(nodeRegistry, /ReviewGateNode/);
  assert.match(nodeRegistry, /\/v1\/review-gate/);
  assert.match(nodeRegistry, /reviewGateReviewersField/);
  assert.match(nodeRegistry, /github_pr_create/);
  assert.match(nodeRegistry, /GitHubPrCreateNode/);
  assert.match(nodeRegistry, /\/v1\/github\/pr-create-plan/);
  assert.match(nodeRegistry, /githubPrCreatePlanRequestHashField/);
  assert.match(nodeRegistry, /SkillNode/);
  assert.match(nodeRegistry, /SkillPackNode/);
  assert.match(nodeRegistry, /HookNode/);
  assert.match(nodeRegistry, /HookPolicyNode/);
  assert.match(nodeRegistry, /\/v1\/skills/);
  assert.match(nodeRegistry, /\/v1\/hooks/);
  assert.match(nodeRegistry, /failurePolicy/);
  assert.match(nodeRegistry, /consumesSkillHookManifest/);
  assert.match(nodeRegistry, /hookDryRunOnly/);
  assert.match(nodeRegistry, /hookDryRunPlan/);
  assert.match(nodeRegistry, /hookPolicyPassedRoute/);
  assert.match(nodeRegistry, /hookPolicyBlockedRoute/);
  assert.match(nodeRegistry, /hookInvocationLedger/);
  assert.match(nodeRegistry, /hookInvocationStateField/);
  assert.match(nodeRegistry, /hookEscalationCountField/);
  assert.match(nodeRegistry, /hookEscalationDetailsField/);
  assert.match(nodeRegistry, /hookEscalationReceiptField/);
  assert.match(nodeRegistry, /activeSkillSetHash/);
  assert.match(nodeRegistry, /activeHookSetHash/);
  assert.match(workflowRuntimeUiStrings, /resolveWorkflowRuntimeUiString/);
  assert.match(workflowRuntimeUiStrings, /workflowRuntimeNodeChrome/);
  assert.match(workflowRuntimeUiStrings, /normalizeWorkflowRuntimeLocale/);
  assert.match(workflowRuntimeUiStrings, /workflowRuntimeAccessibleStatusLabel/);
  assert.match(workflowRuntimeUiStrings, /modelOutputLocalized: false/);
  assert.match(workflowRuntimeUiStrings, /workflow_package_export/);
  assert.match(workflowRuntimeUiStrings, /workflow_package_import/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_export\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_import\.status/);
  assert.match(canvas, /onKeyboardSelect/);
  assert.match(canvas, /nodesFocusable/);
  assert.match(canvas, /node-enter-space-selects-inspector/);
  assert.match(canvas, /workflowChromeLocale/);
  assert.match(canvas, /data-workflow-chrome-locale/);
  assert.match(canvasNode, /workflowRuntimeNodeChrome/);
  assert.match(canvasNode, /aria-label=\{chrome\.ariaLabel\}/);
  assert.match(canvasNode, /tabIndex=\{0\}/);
  assert.match(canvasNode, /aria-keyshortcuts="Enter Space"/);
  assert.match(canvasNode, /data-keyboard-selectable="true"/);
  assert.match(canvasNode, /handleNodeKeyDown/);
  assert.match(canvasNode, /event\.key !== "Enter" && event\.key !== " "/);
  assert.match(canvasNode, /locale: workflowChromeLocale/);
  assert.match(canvasNode, /data-accessible-status-text=\{chrome\.statusText\}/);
  assert.match(canvasNode, /workflow-canvas-node-accessible-status/);
  assert.match(canvasNodeStyles, /\.canvas-node:focus-visible/);
  assert.match(canvasNodeStyles, /\.react-flow__node:focus-visible \.canvas-node/);
  assert.match(graphConfigView, /workflow-global-chrome-locale/);
  assert.match(graphConfigView, /normalizeWorkflowRuntimeLocale/);
  assert.match(agentEditor, /workflowChromeLocale=\{globalConfig\.workflowChromeLocale\}/);
  assert.match(workflowComposerView, /workflowChromeLocale=\{globalConfig\.workflowChromeLocale\}/);
  assert.match(workflowComposerView, /onUpdateWorkflowChromeLocale/);
  assert.match(workflowComposerController, /handleUpdateWorkflowChromeLocale/);
  assert.match(inspector, /workflow-runtime-chrome-locale/);
  assert.match(inspector, /workflowChromeLocale/);
  assert.match(inspector, /data-model-output-localized/);
  assert.match(workflowRailPanel, /workflowRuntimeAccessibleStatusLabel/);
  assert.match(workflowRailPanel, /workflowRuntimeNodeChrome/);
  assert.match(workflowRailPanel, /WorkflowSearchPanel/);
  assert.match(workflowRailPanel, /workflowRailSearchModel/);
  assert.match(workflowSearchPanel, /workflow-rail-search-results/);
  assert.match(workflowSearchPanel, /workflow-rail-search-index-summary/);
  assert.match(workflowSearchPanel, /data-result-kind/);
  assert.match(workflowRailSearchModel, /workflowRailSearchModel/);
  assert.match(workflowRailSearchModel, /visibleResults/);
  assert.match(workflowRailSearchModel, /resultGroups/);
  assert.match(workflowRailSearchModel, /resultKindCounts/);
  assert.match(workflowRailPanel, /WorkflowEntrypointsPanel/);
  assert.match(workflowRailPanel, /workflowEntrypointsModel/);
  assert.match(workflowEntrypointsPanel, /workflow-sources-list/);
  assert.match(workflowEntrypointsPanel, /workflow-schedules-list/);
  assert.match(workflowEntrypointsPanel, /workflow-source-node-/);
  assert.match(workflowEntrypointsPanel, /workflow-schedule-node-/);
  assert.match(workflowEntrypointsModel, /workflowEntrypointsModel/);
  assert.match(workflowEntrypointsModel, /readyStartPoints/);
  assert.match(workflowEntrypointsModel, /readyTriggers/);
  assert.match(workflowEntrypointsModel, /blockedTriggers/);
  assert.match(workflowRailPanel, /WorkflowFilesPanel/);
  assert.match(workflowRailPanel, /workflowFileBundleModel/);
  assert.match(workflowFilesPanel, /workflow-files-list/);
  assert.match(workflowFilesPanel, /workflow-file-/);
  assert.match(workflowFilesPanel, /data-file-ready/);
  assert.match(workflowFileBundleModel, /workflowFileBundleModel/);
  assert.match(workflowFileBundleModel, /readyItems/);
  assert.match(workflowFileBundleModel, /pendingItems/);
  assert.match(workflowFileBundleModel, /portablePackageExported/);
  assert.match(workflowRailPanel, /WorkflowSettingsPanel/);
  assert.match(workflowRailPanel, /WorkflowSettingsHarnessPanel/);
  assert.match(workflowRailPanel, /workflowSettingsModel/);
  assert.match(workflowRailPanel, /workflowSettingsHarnessModel/);
  assert.match(workflowSettingsPanel, /workflow-settings-summary/);
  assert.match(workflowSettingsPanel, /workflow-settings-chrome-locale-select/);
  assert.match(workflowSettingsPanel, /workflow-environment-profile/);
  assert.match(workflowSettingsPanel, /workflow-settings-binding-registry/);
  assert.match(workflowSettingsPanel, /workflow-settings-production-profile/);
  assert.match(workflowSettingsModel, /workflowSettingsModel/);
  assert.match(workflowSettingsModel, /productionSummary/);
  assert.match(workflowSettingsModel, /packageReadinessStatus/);
  assert.match(workflowSettingsHarnessPanel, /workflow-settings-harness-summary/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessActivationPanel/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessWorkerBindingPanel/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessPromotionPanel/);
  assert.match(workflowSettingsHarnessPanel, /settingsHarnessTypes/);
  assert.match(workflowSettingsHarnessTypes, /WorkflowSettingsHarnessPanelProps/);
  assert.match(workflowSettingsHarnessTypes, /WorkflowSettingsHarnessActivationProps/);
  assert.match(workflowSettingsHarnessActivationPanel, /WorkflowSettingsHarnessActivationGatePanel/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /workflow-harness-activation-gate-inspector/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessActivationGateRefsPanel/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessActivationGateTimelinePanel/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-evidence-refs/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-receipt-refs/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-replay-refs/);
  assert.match(workflowSettingsHarnessActivationGateTimelinePanel, /workflow-harness-activation-gate-node-attempt-refs/);
  assert.match(workflowSettingsHarnessActivationGateTimelinePanel, /workflow-harness-activation-gate-node-timeline/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessPackageEvidencePanel/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /workflow-harness-package-evidence-review/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /WorkflowSettingsHarnessPackageEvidenceRowsPanel/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /WorkflowSettingsHarnessPackageImportReviewPanel/);
  assert.match(workflowSettingsHarnessPackageEvidenceRowsPanel, /workflow-harness-package-evidence-row-/);
  assert.match(workflowSettingsHarnessPackageEvidenceRowsPanel, /workflow-harness-package-evidence-row-ref-/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /workflow-harness-package-import-review/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /workflow-harness-package-import-handoff/);
  assert.doesNotMatch(workflowSettingsHarnessActivationPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGatePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGateRefsPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGateTimelinePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageEvidencePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageEvidenceRowsPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageImportReviewPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessWorkerBindingPanel, /WorkflowSettingsHarnessActiveRuntimeRollbackPanel/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /WorkflowSettingsHarnessActiveRuntimeBindingPanel/);
  assert.match(workflowSettingsHarnessActiveRuntimeBindingPanel, /data-worker-binding-registry-bound/);
  assert.match(workflowSettingsHarnessActiveRuntimeBindingPanel, /workflow-harness-active-runtime-binding-deep-links/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /workflow-harness-active-runtime-rollback-proof/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /WorkflowSettingsHarnessRollbackRestoreProofPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActiveRuntimeBindingPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessRollbackRestoreProofPanel, /workflow-harness-git-restore-proof/);
  assert.doesNotMatch(workflowSettingsHarnessRollbackRestoreProofPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActiveRuntimeRollbackPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessWorkerBindingPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessPromotionPanel, /WorkflowSettingsHarnessPromotionReadinessPanel/);
  assert.match(workflowSettingsHarnessPromotionPanel, /workflow-harness-promotion-clusters/);
  assert.match(workflowSettingsHarnessPromotionReadinessPanel, /workflow-harness-selector-live-promotion-readiness/);
  assert.match(workflowSettingsHarnessPromotionReadinessPanel, /workflow-harness-authority-gate-live/);
  assert.doesNotMatch(workflowSettingsHarnessPromotionReadinessPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPromotionPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessModel, /workflowSettingsHarnessModel/);
  assert.match(workflowSettingsHarnessModel, /gatedClustersLabel/);
  assert.match(workflowRailPanel, /globalWorkflowChromeLocale/);
  assert.match(workflowRailPanel, /onUpdateWorkflowChromeLocale/);
  assert.match(workflowRailPanel, /workflow-selected-node-status-announcement/);
  assert.match(workflowRailPanel, /data-accessible-status-text/);
  assert.match(workflowRunsPanel, /workflow-run-timeline/);
  assert.match(workflowRunsPanel, /tabIndex=\{0\}/);
  assert.match(workflowRailPanel, /workflow-selected-node-inspector/);
  assert.match(workflowBottomShelf, /workflow-bottom-run-timeline/);
  assert.match(workflowBottomShelf, /workflow-run-event-snapshot/);
  assert.match(workflowBottomShelf, /tabIndex=\{0\}/);
  assert.match(composerPanelStyles, /\.workflow-run-timeline li:focus-visible/);
  assert.match(composerPanelStyles, /\.workflow-run-card:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-node-inspector:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-search-result:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-harness-ref-button:focus-visible/);
  assert.match(harnessWorkflow, /memory_read/);
  assert.match(harnessWorkflow, /memory_search/);
  assert.match(harnessWorkflow, /memory_list/);
  assert.match(harnessWorkflow, /memory_write/);
  assert.match(harnessWorkflow, /memory_policy/);
  assert.match(harnessWorkflow, /memory_subagent_inheritance/);
  assert.match(harnessWorkflow, /SubagentMemoryInheritance/);
  assert.match(harnessWorkflow, /memory\.writeRequiresApproval/);
  assert.match(harnessWorkflow, /subagent inheritance/);
  assert.match(harnessWorkflow, /runtime_doctor/);
  assert.match(harnessWorkflow, /RuntimeDoctorReport/);
  assert.match(harnessWorkflow, /runtime\.doctor\.read/);
  assert.match(harnessWorkflow, /runtimeNodeChromeLogic/);
  assert.match(harnessWorkflow, /accessibleStatusField/);
  assert.match(harnessWorkflow, /colorIndependentStatus/);
  assert.match(harnessWorkflow, /runtime_task/);
  assert.match(harnessWorkflow, /RuntimeTaskRecord/);
  assert.match(harnessWorkflow, /runtime\.task\.read/);
  assert.match(harnessWorkflow, /runtime_job/);
  assert.match(harnessWorkflow, /JobQueued/);
  assert.match(harnessWorkflow, /runtime\.job\.read/);
  assert.match(harnessWorkflow, /\/v1\/jobs\/\{jobId\}\/cancel/);
  assert.match(harnessWorkflow, /runtimeJobCancelable/);
  assert.match(harnessWorkflow, /runtime_checklist/);
  assert.match(harnessWorkflow, /RuntimeChecklistRecord/);
  assert.match(harnessWorkflow, /runtime\.checklist\.read/);
  assert.match(harnessWorkflow, /runtimeChecklistStatusField/);
  assert.match(harnessWorkflow, /workflow_package_export/);
  assert.match(harnessWorkflow, /workflow_package_import/);
  assert.match(harnessWorkflow, /WorkflowPortablePackageManifest/);
  assert.match(harnessWorkflow, /WorkflowPackageImportReview/);
  assert.match(harnessWorkflow, /workflow\.package\.export/);
  assert.match(harnessWorkflow, /workflow\.package\.import/);
  assert.match(harnessWorkflow, /workflowPackageImportReview\.evidence\.workflowChromeLocalePreserved/);
  assert.match(harnessWorkflow, /repository_context/);
  assert.match(harnessWorkflow, /RepositoryContext/);
  assert.match(harnessWorkflow, /repository\.context\.read/);
  assert.match(harnessWorkflow, /branch_policy/);
  assert.match(harnessWorkflow, /BranchPolicyDecision/);
  assert.match(harnessWorkflow, /repository\.branch_policy\.read/);
  assert.match(harnessWorkflow, /github_context/);
  assert.match(harnessWorkflow, /GitHubContext/);
  assert.match(harnessWorkflow, /github\.context\.read/);
  assert.match(harnessWorkflow, /issue_context/);
  assert.match(harnessWorkflow, /IssueContext/);
  assert.match(harnessWorkflow, /github\.issue\.read/);
  assert.match(harnessWorkflow, /pr_attempt/);
  assert.match(harnessWorkflow, /PrAttemptRecord/);
  assert.match(harnessWorkflow, /github\.pr\.preview/);
  assert.match(harnessWorkflow, /review_gate/);
  assert.match(harnessWorkflow, /ReviewGateDecision/);
  assert.match(harnessWorkflow, /review\.gate\.evaluate/);
  assert.match(harnessWorkflow, /github_pr_create/);
  assert.match(harnessWorkflow, /GitHubPrCreatePlan/);
  assert.match(harnessWorkflow, /github\.pr\.create/);
  assert.match(harnessWorkflow, /githubPrCreatePlanRequestHashField/);
  assert.match(harnessWorkflow, /authority_tooling_github_pr_create_envelope/);
  assert.match(
    harnessWorkflow,
    /DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS[\s\S]*"github_pr_create"/,
  );
  assert.match(
    harnessWorkflow,
    /HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS[\s\S]*"github_pr_create"/,
  );
  assert.match(harnessWorkflow, /skill_registry/);
  assert.match(harnessWorkflow, /hook_registry/);
  assert.match(harnessWorkflow, /hook_policy/);
  assert.match(harnessWorkflow, /SkillRegistryProjection/);
  assert.match(harnessWorkflow, /HookRegistryProjection/);
  assert.match(harnessWorkflow, /HookDryRunPlan/);
  assert.match(harnessWorkflow, /active_skill_hook_manifest/);
  assert.match(harnessWorkflow, /hook_dry_run_plan/);
  assert.match(harnessWorkflow, /hook_policy_decision/);
  assert.match(harnessWorkflow, /hook_invocation_ledger/);
  assert.match(harnessWorkflow, /hook_escalation_receipt/);
  assert.match(workflowValidation, /workflowNodeIsHookPolicy/);
  assert.match(workflowValidation, /hook_policy_dry_run_blocked/);
  assert.match(workflowValidation, /hook_policy_dry_run_plan_missing/);
  assert.match(workflowValidation, /hook_policy_routes_missing/);
  assert.match(workflowRuntimeUiStrings, /ioi\.workflow\.runtime-ui-string-catalog\.v1/);
  assert.match(workflowRuntimeUiStrings, /workflow_chrome/);
  assert.match(workflowRuntimeUiStrings, /supportedLocales: \["en-US", "es-ES"\]/);
  assert.match(workflowRuntimeUiStrings, /modelOutputLocalized: false/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_task\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_job\.aria/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_checklist\.status/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_thread_fork\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_operator_interrupt\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_operator_steer\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_context_compact\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_rollback_snapshot\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_restore_gate\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_diagnostics_repair\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_coding_tool_budget_recovery\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_export\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_import\.status/);
  assert.match(workflowRuntimeUiStrings, /runtime\.status\.blocked/);
  assert.match(workflowRuntimeUiStrings, /WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT/);
  assert.match(workflowHarnessTools, /workflow\.package\.export/);
  assert.match(workflowHarnessTools, /workflow\.package\.import/);
  assert.match(workflowHarnessTools, /workflowChromeLocale/);
  assert.match(workflowHarnessTools, /packageEvidenceReady/);
  assert.match(runtimeProjectionAdapter, /case "workflow_package_export"/);
  assert.match(runtimeProjectionAdapter, /return "workflow_package_export"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_thread_fork"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_thread_fork"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_operator_interrupt"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_operator_interrupt"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_operator_steer"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_operator_steer"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_context_compact"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_context_compact"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_rollback_snapshot"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_rollback_snapshot"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_restore_gate"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_restore_gate"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_diagnostics_repair"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_diagnostics_repair"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_coding_tool_budget_recovery"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_coding_tool_budget_recovery"/);
  assert.match(runtimeProjectionAdapter, /case "workflow_package_import"/);
  assert.match(runtimeProjectionAdapter, /return "workflow_package_import"/);
  assert.match(runtimeActionSchema, /"skill_context"/);
  assert.match(runtimeActionSchema, /"workflow_package_export"/);
  assert.match(runtimeActionSchema, /"workflow_package_import"/);
  assert.match(runtimeActionSchema, /"runtime_operator_steer"/);
  assert.match(runtimeActionSchema, /"runtime_context_compact"/);
  assert.match(runtimeActionSchema, /"runtime_rollback_snapshot"/);
  assert.match(runtimeActionSchema, /"runtime_restore_gate"/);
  assert.match(runtimeActionSchema, /"runtime_diagnostics_repair"/);
  assert.match(runtimeActionSchema, /"runtime_coding_tool_budget_recovery"/);
  assert.match(generatedActionSchema, /"skill_context"/);
  assert.match(generatedActionSchema, /"workflow_package_export"/);
  assert.match(generatedActionSchema, /"workflow_package_import"/);
  assert.match(generatedActionSchema, /"runtime_operator_steer"/);
  assert.match(generatedActionSchema, /"runtime_context_compact"/);
  assert.match(generatedActionSchema, /"runtime_rollback_snapshot"/);
  assert.match(generatedActionSchema, /"runtime_restore_gate"/);
  assert.match(generatedActionSchema, /"runtime_diagnostics_repair"/);
  assert.match(generatedActionSchema, /"runtime_coding_tool_budget_recovery"/);
  assert.match(generatedRustActionSchema, /"skill_context"/);
  assert.match(generatedRustActionSchema, /"workflow_package_export"/);
  assert.match(generatedRustActionSchema, /"workflow_package_import"/);
  assert.match(generatedRustActionSchema, /"runtime_operator_steer"/);
  assert.match(generatedRustActionSchema, /"runtime_context_compact"/);
  assert.match(generatedRustActionSchema, /"runtime_rollback_snapshot"/);
  assert.match(generatedRustActionSchema, /"runtime_restore_gate"/);
  assert.match(generatedRustActionSchema, /"runtime_diagnostics_repair"/);
  assert.match(generatedRustActionSchema, /"runtime_coding_tool_budget_recovery"/);
});

test("local daemon hosted and self-hosted modes fail closed without provider endpoints", async () => {
  const { Agent, createRuntimeSubstrateClient, IoiAgentError } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-blocker-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-blocker-"));
  const savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  const savedSelfHosted = process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    await assert.rejects(
      Agent.create({
        local: { cwd },
        hosted: {
          repos: [{ url: "https://example.invalid/ioi.git" }],
          provider: { providerId: "missing-hosted-provider" },
        },
        substrateClient: client,
      }),
      (error) =>
        error instanceof IoiAgentError &&
        error.code === "external_blocker" &&
        error.status === 424,
    );
  } finally {
    await daemon.close();
    if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
    if (savedSelfHosted === undefined) delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT = savedSelfHosted;
  }
});
