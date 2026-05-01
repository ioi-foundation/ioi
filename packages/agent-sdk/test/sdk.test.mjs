import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  Agent,
  Cursor,
  IoiAgentError,
  createRuntimeSubstrateClient,
} from "../dist/index.js";
import { createMockRuntimeSubstrateClient } from "../dist/testing.js";

function tempClient() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agent-sdk-"));
  return {
    cwd,
    client: createMockRuntimeSubstrateClient({
      cwd,
      checkpointDir: path.join(cwd, ".ioi", "agent-sdk"),
    }),
  };
}

test("default SDK client is daemon-backed and fails closed without transport", async () => {
  await assert.rejects(
    Agent.create({ local: { cwd: process.cwd() } }),
    (error) =>
      error instanceof IoiAgentError &&
      error.code === "external_blocker" &&
      error.details?.explicitMockFactory ===
        "@ioi/agent-sdk/testing#createMockRuntimeSubstrateClient",
  );
  await assert.rejects(
    createRuntimeSubstrateClient().listModels(),
    (error) => error instanceof IoiAgentError && error.code === "external_blocker",
  );
});

test("explicit mock quickstart streams, waits, inspects, scores, and exports trace", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Summarize this repository");
  const events = [];
  for await (const event of run.stream()) {
    events.push(event);
  }
  assert.equal(events.at(-1)?.type, "completed");
  assert.equal(events.filter((event) => event.type === "completed").length, 1);
  const result = await run.wait();
  assert.equal(result.stopCondition.reason, "evidence_sufficient");
  const trace = await run.inspect();
  assert.equal(trace.events.length, events.length);
  assert.equal(trace.taskState.currentObjective, "Summarize this repository");
  assert.ok(trace.probes.length > 0);
  assert.ok(trace.taskState.assumptions.some((item) => item.includes("non-authoritative")));
  assert.equal(trace.qualityLedger.selectedStrategy, "explicit_mock_substrate_projection");
  assert.equal((await run.scorecard()).verifierIndependence, 1);
  assert.ok((await run.artifacts()).some((artifact) => artifact.name === "trace.json"));
});

test("stream reconnect starts after the supplied cursor without duplicating terminal events", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const run = await agent.send("Reconnect test");
  const firstBatch = [];
  for await (const event of run.stream()) {
    firstBatch.push(event);
    if (firstBatch.length === 4) break;
  }
  const secondBatch = [];
  for await (const event of run.stream({ lastEventId: firstBatch.at(-1).id })) {
    secondBatch.push(event);
  }
  assert.equal(secondBatch[0].type, "postcondition_synthesized");
  assert.equal(secondBatch.filter((event) => event.type === "completed").length, 1);
});

test("per-send onStep and onDelta callbacks receive substrate event projections", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const steps = [];
  const deltas = [];
  await agent.send("Callback test", {
    onStep: (event) => steps.push(event.type),
    onDelta: (delta) => deltas.push(delta),
  });
  assert.ok(steps.includes("task_state"));
  assert.ok(steps.includes("completed"));
  assert.equal(deltas.length, 1);
  assert.match(deltas[0], /IOI SDK mock run completed/);
});

test("plan dry-run handoff and learn expose smarter-agent records", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const plan = await agent.plan("Plan StopCondition support", { noMutation: true });
  assert.equal((await plan.inspect()).qualityLedger.selectedStrategy, "plan_only_with_postconditions");
  const preview = await agent.dryRun("Preview filesystem delete", { toolClass: "filesystem" });
  assert.equal((await preview.inspect()).uncertainty.selectedAction, "dry_run");
  const handoff = await agent.handoff("Delegate investigation", { receiver: "worker" });
  assert.ok((await handoff.inspect()).qualityLedger.toolSequence.includes("handoff_quality"));
  const learned = await agent.learn({ taskFamily: "sdk_parity", positive: ["traceable SDK run"] });
  assert.ok((await learned.inspect()).qualityLedger.toolSequence.includes("memory_quality_gate"));
});

test("cloud and self-hosted modes fail closed without configured providers", async () => {
  const { cwd, client } = tempClient();
  await assert.rejects(
    Agent.create({
      cloud: { repos: [{ url: "https://example.invalid/repo.git" }] },
      local: { cwd },
      substrateClient: client,
    }),
    (error) => error instanceof IoiAgentError && error.code === "external_blocker",
  );
});

test("Cursor facade exposes operator, model, and repository catalogs", async () => {
  const { cwd, client } = tempClient();
  const models = await Cursor.models.list({ local: { cwd }, substrateClient: client });
  assert.ok(models.some((model) => model.id === "local:auto"));
  const repositories = await Cursor.repositories.list({ local: { cwd }, substrateClient: client });
  assert.equal(repositories[0].url, cwd);
  assert.equal((await Cursor.account.get({ substrateClient: client })).privacyClass, "local_private");
  assert.ok((await Cursor.runtimeNodes.list({ substrateClient: client })).some((node) => node.kind === "local"));
  assert.equal((await Cursor.me()).source, "ioi-agent-sdk");
});

test("SDK exposes governed tool catalog and subagent map without creating a second runtime", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    local: { cwd },
    agents: {
      reviewer: {
        prompt: "Review evidence and return a handoff.",
      },
    },
    substrateClient: client,
  });
  assert.ok(agent.agents.reviewer);
  const tools = await agent.tools();
  assert.ok(tools.some((tool) => tool.primitiveCapabilities.includes("prim:sys.exec")));
  assert.ok(tools.some((tool) => tool.authorityScopeRequirements.includes("scope:host.controlled_execution")));
  const handoff = await agent.agents.reviewer.send("Investigate runtime substrate state");
  assert.ok((await handoff.inspect()).qualityLedger.toolSequence.includes("handoff_quality"));
});

test("daemon SDK client uses the public substrate HTTP endpoint", async () => {
  const now = new Date().toISOString();
  const events = [
    event("run_http:0", "run_started", "Run entered daemon substrate", now),
    event("run_http:1", "task_state", "Task state projected", now),
    event("run_http:2", "completed", "Run completed", now),
  ];
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: "trace_http",
    agentId: "agent_http",
    runId: "run_http",
    eventStreamId: "events_http",
    events,
    receipts: [],
    taskState: {
      currentObjective: "HTTP daemon test",
      knownFacts: ["daemon endpoint configured"],
      uncertainFacts: [],
      assumptions: [],
      constraints: [],
      blockers: [],
      changedObjects: [],
      evidenceRefs: ["events_http"],
    },
    uncertainty: {
      ambiguityLevel: "low",
      selectedAction: "execute",
      rationale: "endpoint supplied",
      valueOfProbe: "low",
    },
    probes: [],
    postconditions: {
      objective: "HTTP daemon test",
      taskFamily: "sdk_transport",
      riskClass: "low",
      checks: [],
      minimumEvidence: ["events_http"],
    },
    semanticImpact: {
      changedSymbols: [],
      changedApis: [],
      changedSchemas: [],
      changedPolicies: [],
      affectedTests: [],
      affectedDocs: [],
      riskClass: "low",
    },
    stopCondition: {
      reason: "evidence_sufficient",
      evidenceSufficient: true,
      rationale: "daemon completed run",
    },
    qualityLedger: {
      ledgerId: "ledger_http",
      taskFamily: "sdk_transport",
      selectedStrategy: "daemon_substrate",
      toolSequence: ["http_request", "event_replay"],
      scorecardMetrics: {},
      failureOntologyLabels: [],
    },
    scorecard: scorecard(),
  };
  const runRecord = {
    id: "run_http",
    agentId: "agent_http",
    status: "completed",
    objective: "HTTP daemon test",
    mode: "send",
    createdAt: now,
    updatedAt: now,
    events,
    conversation: [
      { role: "user", content: "HTTP daemon test", createdAt: now },
      { role: "assistant", content: "Daemon completed", createdAt: now },
    ],
    receipts: [],
    artifacts: [],
    trace,
    result: "Daemon completed",
  };
  const agentRecord = {
    id: "agent_http",
    status: "active",
    runtime: "local",
    cwd: process.cwd(),
    modelId: "local:auto",
    createdAt: now,
    updatedAt: now,
    options: {
      cloudConfigured: false,
      selfHostedConfigured: false,
      mcpServerNames: [],
      skillNames: [],
      hookNames: [],
      subagentNames: [],
      sandboxProfile: "development",
    },
  };
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}${url.search}`);
    const body = await readBody(request);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      assert.equal(body.options.local.cwd, process.cwd());
      response.end(JSON.stringify(agentRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/agents/agent_http/runs") {
      assert.equal(body.mode, "send");
      assert.equal(body.prompt, "HTTP daemon test");
      response.end(JSON.stringify(runRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/events") {
      const lastEventId = url.searchParams.get("lastEventId");
      const start = lastEventId ? events.findIndex((item) => item.id === lastEventId) + 1 : 0;
      response.setHeader("content-type", "text/event-stream");
      response.end(events.slice(start).map((item) => `id: ${item.id}\ndata: ${JSON.stringify(item)}\n\n`).join(""));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/wait") {
      response.end(JSON.stringify({
        id: runRecord.id,
        agentId: runRecord.agentId,
        status: runRecord.status,
        result: runRecord.result,
        stopCondition: trace.stopCondition,
        trace,
        scorecard: trace.scorecard,
      }));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runs/run_http/trace") {
      response.end(JSON.stringify(trace));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/models") {
      response.end(JSON.stringify([{ id: "local:auto", provider: "daemon", cost: "local", quality: "high" }]));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/account") {
      response.end(JSON.stringify({
        id: "operator_http",
        email: null,
        authorityLevel: "local",
        privacyClass: "local_private",
        source: "daemon",
      }));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/runtime/nodes") {
      response.end(JSON.stringify([{
        id: "daemon-local",
        kind: "local",
        status: "available",
        privacyClass: "local_private",
        evidenceRefs: ["daemon-runtime-api"],
      }]));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/tools") {
      response.end(JSON.stringify([{
        stableToolId: "sys.exec",
        displayName: "Shell command",
        primitiveCapabilities: ["prim:sys.exec"],
        authorityScopeRequirements: ["scope:host.controlled_execution"],
        effectClass: "local_command",
        riskDomain: "host",
        inputSchema: { type: "object" },
        outputSchema: { type: "object" },
        evidenceRequirements: ["shell_receipt"],
      }]));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const client = createRuntimeSubstrateClient({ endpoint });
    const agent = await Agent.create({ local: { cwd: process.cwd() }, substrateClient: client });
    const run = await agent.send("HTTP daemon test");
    const firstBatch = [];
    for await (const item of run.stream()) {
      firstBatch.push(item);
      if (firstBatch.length === 1) break;
    }
    const secondBatch = [];
    for await (const item of run.stream({ lastEventId: firstBatch.at(-1).id })) {
      secondBatch.push(item);
    }
    assert.deepEqual(secondBatch.map((item) => item.id), ["run_http:1", "run_http:2"]);
    assert.equal((await run.wait()).stopCondition.reason, "evidence_sufficient");
    assert.equal((await run.trace()).qualityLedger.selectedStrategy, "daemon_substrate");
    assert.equal((await Cursor.models.list({ substrateClient: client })).at(0)?.provider, "daemon");
    assert.equal((await Cursor.account.get({ substrateClient: client })).source, "daemon");
    assert.equal((await Cursor.runtimeNodes.list({ substrateClient: client })).at(0)?.id, "daemon-local");
    assert.equal((await agent.tools()).at(0)?.stableToolId, "sys.exec");
    assert.ok(requests.includes("POST /v1/agents"));
    assert.ok(requests.includes("POST /v1/agents/agent_http/runs"));
    assert.ok(requests.includes("GET /v1/runs/run_http/events?lastEventId=run_http%3A0"));
  } finally {
    await close(server);
  }
});

function event(id, type, summary, createdAt) {
  return {
    id,
    runId: "run_http",
    agentId: "agent_http",
    type,
    cursor: id,
    createdAt,
    summary,
  };
}

function scorecard() {
  return {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: 1,
    toolQuality: 1,
    strategyRoi: 1,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
