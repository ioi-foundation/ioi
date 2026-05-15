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
  Thread,
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
  assert.equal(result.routeDecision.eventKind, "ModelRouteDecision");
  assert.equal(result.routeDecision.selectedModel, "local:auto");
  const trace = await run.inspect();
  assert.equal(trace.events.length, events.length);
  assert.equal(trace.modelRouteDecision.eventKind, "ModelRouteDecision");
  assert.equal(trace.modelRouteDecision.selectedModel, "local:auto");
  assert.equal((await run.routeDecision()).decisionId, trace.modelRouteDecision.decisionId);
  assert.ok(trace.events.some((event) => event.type === "model_route_decision"));
  assert.ok(trace.receipts.some((receipt) => receipt.kind === "model_route_selection"));
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
  assert.equal(secondBatch[0].type, "probe");
  assert.equal(secondBatch.filter((event) => event.type === "completed").length, 1);
});

test("explicit mock memory helpers remember facts and inject them into later turns", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const remembered = await agent.memory.remember("Prefer focused runtime slices.");
  assert.equal(remembered.record.fact, "Prefer focused runtime slices.");
  assert.equal(remembered.receipt.kind, "memory_write");
  const memory = await agent.memory.list();
  assert.equal(memory.records.length, 1);
  assert.equal(memory.records[0].id, remembered.record.id);
  await agent.memory.remember("Prefer memory filters in workflow nodes.", {
    memoryKey: "workflow-preferences",
  });
  await agent.memory.remember("Unrelated scratch memory.", { memoryKey: "scratch" });
  const filteredMemory = await agent.memory.search("filters", {
    memoryKey: "workflow-preferences",
    limit: 1,
  });
  assert.equal(filteredMemory.filters.query, "filters");
  assert.equal(filteredMemory.records.length, 1);
  assert.equal(filteredMemory.records[0].memoryKey, "workflow-preferences");
  assert.match(filteredMemory.records[0].fact, /filters/);
  const redactedMemory = await agent.memory.list({
    memoryKey: "workflow-preferences",
    redaction: "redacted",
  });
  assert.equal(redactedMemory.records[0].fact, "[REDACTED]");
  assert.match(redactedMemory.records[0].factHash, /^[a-f0-9]{64}$/);

  const run = await agent.send("/memory show");
  const result = await run.wait();
  assert.match(result.result, /Prefer focused runtime slices/);
  const trace = await run.inspect();
  assert.ok(trace.memoryRecords.some((record) => record.id === remembered.record.id));
  assert.ok(trace.taskState.knownFacts.some((fact) => fact.includes("Prefer focused runtime slices")));

  const memoryPath = await agent.memory.path();
  assert.match(memoryPath.recordsPath, /\.ioi/);
  assert.match(memoryPath.policiesPath, /memory-policies/);

  const edited = await agent.memory.edit(remembered.record.id, "Prefer narrow, validated runtime slices.");
  assert.equal(edited.receipt.kind, "memory_edit");
  assert.equal((await agent.memory.list()).records[0].fact, "Prefer narrow, validated runtime slices.");

  const readOnly = await agent.memory.configure({ readOnly: true });
  assert.equal(readOnly.policy.readOnly, true);
  await assert.rejects(
    agent.memory.remember("This write should be blocked."),
    (error) => error instanceof IoiAgentError && error.code === "policy",
  );
  const blockedReadOnlyRun = await agent.send("# remember Policy blocks this.");
  assert.match((await blockedReadOnlyRun.wait()).result, /memory_read_only/);

  await agent.memory.configure({ readOnly: false, writeRequiresApproval: true });
  const approvalBlockedRun = await agent.send("# remember Approval is missing.");
  assert.match((await approvalBlockedRun.wait()).result, /memory_write_requires_approval/);
  const approvalRun = await agent.send("# remember Approval was granted.", {
    memory: { writeApproved: true },
  });
  assert.ok((await approvalRun.inspect()).receipts.some((receipt) => receipt.kind === "memory_write"));

  const disabledPolicyRun = await agent.send("/memory disable");
  assert.equal((await disabledPolicyRun.wait()).result, "Memory is disabled for this thread.");
  assert.equal((await agent.memory.policy()).disabled, true);
  const enablePolicyRun = await agent.send("/memory enable");
  assert.equal((await enablePolicyRun.wait()).result, "Memory is enabled for this thread.");
  assert.equal((await agent.memory.policy()).disabled, false);

  const disabledRun = await agent.send("/memory show", { memory: { disabled: true } });
  const disabledResult = await disabledRun.wait();
  assert.equal(disabledResult.result, "Memory is disabled for this run.");
  const disabledTrace = await disabledRun.inspect();
  assert.equal(disabledTrace.memoryRecords.length, 0);
  assert.ok(!disabledTrace.taskState.knownFacts.some((fact) => fact.includes("Prefer focused runtime slices")));

  await agent.memory.configure({ writeRequiresApproval: false });
  const rememberRun = await agent.send("# remember Preserve memory receipts.");
  const events = [];
  for await (const event of rememberRun.stream()) events.push(event);
  assert.ok(events.some((event) => event.type === "memory_update"));
  assert.ok((await rememberRun.inspect()).receipts.some((receipt) => receipt.kind === "memory_write"));
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
  for (const tool of tools) {
    assert.ok(tool.credentialReadiness?.status);
    assert.equal(typeof tool.credentialReady, "boolean");
    assert.equal(typeof tool.approvalRequired, "boolean");
    assert.ok(tool.rateLimitProfile?.policy);
    assert.ok(tool.idempotencyBehavior?.strategy);
    assert.equal(typeof tool.receiptBehavior?.receiptRequired, "boolean");
    assert.ok(Array.isArray(tool.receiptBehavior?.requiredReceiptTypes));
    assert.equal(typeof tool.workflowAvailability?.available, "boolean");
    assert.equal(typeof tool.agentAvailability?.available, "boolean");
    assert.equal(typeof tool.marketplaceExposure?.eligible, "boolean");
  }
  const shellTool = tools.find((tool) => tool.stableToolId === "sys.exec");
  assert.equal(shellTool?.approvalRequired, true);
  assert.equal(shellTool?.credentialReadiness.status, "not_required");
  assert.equal(shellTool?.idempotencyBehavior.required, true);
  const readTool = tools.find((tool) => tool.stableToolId === "fs.read");
  assert.equal(readTool?.approvalRequired, false);
  assert.equal(readTool?.credentialReady, true);
  const targeted = await agent.memory.remember("Reviewer should see the targeted handoff fact.", {
    memoryKey: "reviewer-handoff",
  });
  await agent.memory.remember("Reviewer should not inherit unrelated scratch memory.", {
    memoryKey: "scratch",
  });

  const handoff = await agent.agents.reviewer.send("Investigate runtime substrate state", {
    memory: { subagentInheritance: "explicit", memoryKey: "reviewer-handoff" },
  });
  const explicitTrace = await handoff.inspect();
  assert.ok(explicitTrace.qualityLedger.toolSequence.includes("handoff_quality"));
  assert.equal(explicitTrace.subagentMemoryInheritance.mode, "explicit");
  assert.equal(explicitTrace.subagentMemoryInheritance.subagentName, "reviewer");
  assert.deepEqual(explicitTrace.subagentMemoryInheritance.inheritedRecordIds, [targeted.record.id]);
  assert.ok(explicitTrace.receipts.some((receipt) => receipt.kind === "subagent_memory_inheritance"));
  assert.ok(
    explicitTrace.events.some(
      (event) => event.data?.eventKind === "SubagentMemoryInheritance",
    ),
  );

  const noInheritance = await agent.agents.reviewer.send("Investigate without inherited memory", {
    memory: { subagentInheritance: "none", memoryKey: "reviewer-handoff" },
  });
  const noneTrace = await noInheritance.inspect();
  assert.equal(noneTrace.subagentMemoryInheritance.mode, "none");
  assert.equal(noneTrace.subagentMemoryInheritance.records.length, 0);
  assert.equal(noneTrace.subagentMemoryInheritance.effectivePolicy.disabled, true);

  const readOnly = await agent.agents.reviewer.send("Try to write read-only inherited memory", {
    memory: {
      subagentInheritance: "read_only",
      memoryKey: "reviewer-handoff",
      remember: "Reviewer attempted a read-only write.",
    },
  });
  const readOnlyTrace = await readOnly.inspect();
  assert.equal(readOnlyTrace.subagentMemoryInheritance.mode, "read_only");
  assert.equal(readOnlyTrace.subagentMemoryInheritance.writeBlockReason, "memory_read_only");
  assert.equal(readOnlyTrace.memoryWrites.length, 0);

  const full = await agent.agents.reviewer.send("Write with full inherited memory", {
    memory: {
      subagentInheritance: "full",
      memoryKey: "reviewer-handoff",
      remember: "Reviewer can persist a full-inheritance handoff note.",
    },
  });
  const fullTrace = await full.inspect();
  assert.equal(fullTrace.subagentMemoryInheritance.mode, "full");
  assert.equal(fullTrace.subagentMemoryInheritance.writeBlockReason, null);
  assert.equal(fullTrace.memoryWrites.length, 1);
  assert.equal(fullTrace.memoryWrites[0].memoryKey, "reviewer-handoff");
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
    const httpTools = await agent.tools();
    assert.equal(httpTools.at(0)?.stableToolId, "sys.exec");
    assert.equal(httpTools.at(0)?.approvalRequired, true);
    assert.equal(httpTools.at(0)?.credentialReadiness.status, "not_required");
    assert.equal(httpTools.at(0)?.receiptBehavior.requiredReceiptTypes.at(0), "shell_receipt");
    assert.ok(requests.includes("POST /v1/agents"));
    assert.ok(requests.includes("POST /v1/agents/agent_http/runs"));
    assert.ok(requests.includes("GET /v1/runs/run_http/events?lastEventId=run_http%3A0"));
  } finally {
    await close(server);
  }
});

test("Thread and Turn wrappers project canonical daemon events into typed SDK runtime events", async () => {
  const now = new Date().toISOString();
  const threadRecord = {
    schema_version: "ioi.runtime.thread.v1",
    thread_id: "thread_sdk",
    session_id: "session_sdk",
    agent_id: "agent_sdk",
    workspace_root: process.cwd(),
    title: "SDK thread projection",
    mode: "agent",
    approval_mode: "suggest",
    trust_profile: "local_private",
    model_route: "local:auto",
    status: "active",
    latest_turn_id: null,
    latest_seq: 1,
    event_stream_id: "events_thread_sdk",
    workflow_graph_id: null,
    harness_binding_id: null,
    agentgres_projection_ref: "agents/agent_sdk.json",
    created_at: now,
    updated_at: now,
    archived_at: null,
    fixture_profile: null,
  };
  const turnRecord = {
    schema_version: "ioi.runtime.turn.v1",
    turn_id: "turn_sdk",
    thread_id: "thread_sdk",
    parent_turn_id: null,
    request_id: "run_sdk",
    status: "completed",
    input_item_ids: ["item_turn_started"],
    output_item_ids: ["item_tool", "item_terminal"],
    seq_start: 2,
    seq_end: 4,
    started_at: now,
    completed_at: now,
    mode: "agent",
    approval_mode: "suggest",
    model_route_decision_id: null,
    usage: null,
    stop_reason: "runtime_bridge_completed",
    error: null,
    rollback_snapshot_id: null,
    quality_ledger_ref: null,
    workflow_execution_ref: null,
    fixture_profile: null,
  };
  const interruptedTurnRecord = {
    ...turnRecord,
    status: "interrupted",
    seq_end: 8,
    completed_at: now,
    stop_reason: "operator_interrupt",
  };
  const forkedThreadRecord = {
    ...threadRecord,
    thread_id: "thread_sdk_fork",
    agent_id: "agent_sdk_fork",
    session_id: "session_sdk_fork",
    event_stream_id: "events_thread_sdk_fork",
    latest_seq: 1,
    agentgres_projection_ref: "agents/agent_sdk_fork.json",
    source_thread_id: "thread_sdk",
    forked_from_seq: 4,
  };
  const compactedThreadRecord = {
    ...threadRecord,
    latest_seq: 6,
  };
  const runtimeEvents = [
    runtimeEnvelope({
      seq: 1,
      eventKind: "thread.started",
      sourceEventKind: "RuntimeAgentService.handle_service_call.start@v1",
      turnId: "",
      itemId: "item_thread_started",
      componentKind: "runtime_thread",
      workflowNodeId: "runtime.runtime-thread",
      payload: { agent_id: "agent_sdk", thread_id: "thread_sdk" },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 2,
      eventKind: "turn.started",
      sourceEventKind: "RuntimeAgentService.handle_service_call.post_message@v1",
      itemId: "item_turn_started",
      componentKind: "runtime_turn",
      workflowNodeId: "runtime.runtime-turn",
      payload: { agent_id: "agent_sdk", run_id: "run_sdk", prompt: "Exercise typed thread events." },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 3,
      eventKind: "tool.completed",
      sourceEventKind: "KernelEvent::AgentActionResult",
      itemId: "item_tool",
      componentKind: "tool_result",
      workflowNodeId: "runtime.tool-result",
      payloadSchemaVersion: "ioi.runtime.kernel-event.v1",
      payload: {
        event_kind: "KernelEvent::AgentActionResult",
        agent_id: "agent_sdk",
        run_id: "run_sdk",
        tool_name: "system::intent_clarification",
        agent_status: "Paused",
        step_index: 0,
      },
      createdAt: now,
    }),
    runtimeEnvelope({
      seq: 4,
      eventKind: "turn.completed",
      sourceEventKind: "RuntimeAgentService.handle_service_call.step@v1",
      itemId: "item_terminal",
      componentKind: "runtime_turn",
      workflowNodeId: "runtime.runtime-turn",
      payload: { agent_id: "agent_sdk", run_id: "run_sdk", agent_status: "Paused" },
      createdAt: now,
    }),
  ];
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    requests.push(`${request.method} ${url.pathname}${url.search}`);
    response.setHeader("content-type", "application/json");
    if (request.method === "POST" && url.pathname === "/v1/threads") {
      const body = await readBody(request);
      assert.equal(body.options.local.cwd, process.cwd());
      response.end(JSON.stringify(threadRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/threads/thread_sdk") {
      response.end(JSON.stringify({ ...threadRecord, turns: [turnRecord] }));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns") {
      const body = await readBody(request);
      assert.equal(body.prompt, "Exercise typed thread events.");
      response.end(JSON.stringify(turnRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/fork") {
      const body = await readBody(request);
      assert.equal(body.reason, "branch context");
      assert.equal(body.source, "sdk_client");
      runtimeEvents.push(runtimeEnvelope({
        seq: 5,
        eventKind: "thread.forked",
        sourceEventKind: "OperatorControl.Fork",
        turnId: "turn_sdk",
        itemId: "item_thread_fork",
        componentKind: "thread_fork",
        workflowNodeId: "runtime.thread-fork",
        payloadSchemaVersion: "ioi.runtime.thread-fork.v1",
        payload: {
          event_kind: "OperatorControl.Fork",
          reason: "branch context",
          source_thread_id: "thread_sdk",
          fork_thread_id: "thread_sdk_fork",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(forkedThreadRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/compact") {
      const body = await readBody(request);
      assert.equal(body.reason, "reduce stale context");
      runtimeEvents.push(runtimeEnvelope({
        seq: 6,
        eventKind: "context.compacted",
        sourceEventKind: "OperatorControl.Compact",
        itemId: "item_context_compact",
        componentKind: "context_compaction",
        workflowNodeId: "runtime.context-compact",
        payloadSchemaVersion: "ioi.runtime.context-compaction.v1",
        payload: {
          event_kind: "OperatorControl.Compact",
          reason: "reduce stale context",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(compactedThreadRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns/turn_sdk/interrupt") {
      const body = await readBody(request);
      assert.equal(body.reason, "operator validation");
      runtimeEvents.push(runtimeEnvelope({
        seq: 8,
        eventKind: "turn.interrupted",
        sourceEventKind: "OperatorControl.Interrupt",
        itemId: "item_operator_interrupt",
        componentKind: "operator_control",
        workflowNodeId: "runtime.operator-interrupt",
        payloadSchemaVersion: "ioi.runtime.operator-control.v1",
        payload: {
          event_kind: "OperatorControl.Interrupt",
          reason: "operator validation",
        },
        status: "interrupted",
        createdAt: now,
      }));
      response.end(JSON.stringify(interruptedTurnRecord));
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/threads/thread_sdk/turns/turn_sdk/steer") {
      const body = await readBody(request);
      assert.equal(body.guidance, "focus on the failing assertion");
      runtimeEvents.push(runtimeEnvelope({
        seq: 7,
        eventKind: "turn.steered",
        sourceEventKind: "OperatorControl.Steer",
        itemId: "item_operator_steer",
        componentKind: "operator_control",
        workflowNodeId: "runtime.operator-steer",
        payloadSchemaVersion: "ioi.runtime.operator-control.v1",
        payload: {
          event_kind: "OperatorControl.Steer",
          guidance: "focus on the failing assertion",
        },
        status: "completed",
        createdAt: now,
      }));
      response.end(JSON.stringify(turnRecord));
      return;
    }
    if (request.method === "GET" && url.pathname === "/v1/threads/thread_sdk/events") {
      const sinceSeq = Number(url.searchParams.get("since_seq") ?? 0) || 0;
      response.setHeader("content-type", "text/event-stream");
      response.end(
        runtimeEvents
          .filter((item) => item.seq > sinceSeq)
          .map((item) => `id: ${item.event_id}\ndata: ${JSON.stringify(item)}\n\n`)
          .join(""),
      );
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: { code: "not_found", message: "missing route" } }));
  });
  await listen(server);
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const client = createRuntimeSubstrateClient({ endpoint: `http://127.0.0.1:${address.port}` });
    const thread = await Thread.create({ local: { cwd: process.cwd() }, substrateClient: client });
    const turn = await thread.send("Exercise typed thread events.");
    const threadEvents = [];
    for await (const item of thread.events({ sinceSeq: 0 })) threadEvents.push(item);
    const toolEvent = threadEvents.find((item) => item.sourceEventKind === "KernelEvent::AgentActionResult");
    assert.equal(toolEvent.type, "tool_completed");
    assert.equal(toolEvent.payloadSchemaVersion, "ioi.runtime.kernel-event.v1");
    assert.equal(toolEvent.componentKind, "tool_result");
    assert.equal(toolEvent.workflowNodeId, "runtime.tool-result");
    assert.equal(toolEvent.toolName, "system::intent_clarification");
    assert.equal(toolEvent.agentStatus, "Paused");
    assert.equal(toolEvent.stepIndex, 0);

    const turnEvents = [];
    for await (const item of turn.events()) turnEvents.push(item);
    assert.deepEqual(turnEvents.map((item) => item.type), [
      "turn_started",
      "tool_completed",
      "turn_completed",
    ]);
    const forked = await thread.fork({ reason: "branch context" });
    assert.equal(forked.id, "thread_sdk_fork");
    const forkedEvents = [];
    for await (const item of thread.events({ sinceSeq: 4 })) forkedEvents.push(item);
    assert.deepEqual(forkedEvents.map((item) => item.type), ["thread_forked"]);
    assert.equal(forkedEvents[0].eventKind, "thread.forked");
    assert.equal(forkedEvents[0].sourceEventKind, "OperatorControl.Fork");
    assert.equal(forkedEvents[0].componentKind, "thread_fork");
    assert.equal(forkedEvents[0].workflowNodeId, "runtime.thread-fork");
    assert.equal(forkedEvents[0].payloadSchemaVersion, "ioi.runtime.thread-fork.v1");

    const compacted = await thread.compact({ reason: "reduce stale context" });
    assert.equal(compacted.record.latest_seq, 6);
    const compactedEvents = [];
    for await (const item of thread.events({ sinceSeq: 5 })) compactedEvents.push(item);
    assert.deepEqual(compactedEvents.map((item) => item.type), ["context_compacted"]);
    assert.equal(compactedEvents[0].eventKind, "context.compacted");
    assert.equal(compactedEvents[0].sourceEventKind, "OperatorControl.Compact");
    assert.equal(compactedEvents[0].componentKind, "context_compaction");
    assert.equal(compactedEvents[0].workflowNodeId, "runtime.context-compact");
    assert.equal(compactedEvents[0].payloadSchemaVersion, "ioi.runtime.context-compaction.v1");

    const steered = await turn.steer({ guidance: "focus on the failing assertion" });
    assert.equal(steered.status, "completed");
    const steeredEvents = [];
    for await (const item of thread.events({ sinceSeq: 6 })) steeredEvents.push(item);
    assert.deepEqual(steeredEvents.map((item) => item.type), ["turn_steered"]);
    assert.equal(steeredEvents[0].eventKind, "turn.steered");
    assert.equal(steeredEvents[0].sourceEventKind, "OperatorControl.Steer");
    assert.equal(steeredEvents[0].componentKind, "operator_control");
    assert.equal(steeredEvents[0].workflowNodeId, "runtime.operator-steer");
    assert.equal(steeredEvents[0].payloadSchemaVersion, "ioi.runtime.operator-control.v1");

    const interrupted = await turn.interrupt({ reason: "operator validation" });
    assert.equal(interrupted.status, "interrupted");
    const interruptedEvents = [];
    for await (const item of thread.events({ sinceSeq: 7 })) interruptedEvents.push(item);
    assert.deepEqual(interruptedEvents.map((item) => item.type), ["turn_interrupted"]);
    assert.equal(interruptedEvents[0].eventKind, "turn.interrupted");
    assert.equal(interruptedEvents[0].sourceEventKind, "OperatorControl.Interrupt");
    assert.equal(interruptedEvents[0].componentKind, "operator_control");
    assert.equal(interruptedEvents[0].workflowNodeId, "runtime.operator-interrupt");
    assert.equal(interruptedEvents[0].payloadSchemaVersion, "ioi.runtime.operator-control.v1");
    assert.ok(requests.includes("POST /v1/threads"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/fork"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/compact"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns/turn_sdk/steer"));
    assert.ok(requests.includes("POST /v1/threads/thread_sdk/turns/turn_sdk/interrupt"));
    assert.ok(requests.includes("GET /v1/threads/thread_sdk/events?since_seq=0"));
  } finally {
    await close(server);
  }
});

test("Thread subagent wrappers cover the full manager surface on the explicit mock substrate", async () => {
  const { cwd, client } = tempClient();
  const thread = await Thread.create({
    local: { cwd },
    model: { id: "local:auto" },
    substrateClient: client,
  });

  const spawned = await thread.spawnSubagent({
    role: "explore",
    prompt: "Inspect SDK subagent wrapper coverage.",
    toolPack: "coding",
    modelRouteId: "route.local-first",
    cancellationInheritance: "propagate",
    workflowGraphId: "workflow.sdk.subagents",
    workflowNodeId: "runtime.subagent.spawn.explore",
  });
  const subagentId = spawned.subagent_id ?? spawned.subagentId;
  assert.ok(subagentId);
  assert.equal(spawned.object, "ioi.runtime_subagent");
  assert.equal(spawned.role, "explore");
  assert.equal(spawned.lifecycle_status, "completed");

  const listed = await thread.listSubagents({ role: "explore" });
  assert.equal(listed.object, "ioi.runtime_subagent_list");
  assert.equal(listed.count, 1);
  assert.equal(listed.subagents[0].subagent_id, subagentId);

  const waited = await thread.waitSubagent(subagentId, {
    workflowNodeId: "runtime.subagent.join.explore",
  });
  assert.equal(waited.object, "ioi.runtime_subagent_result");
  assert.equal(waited.status, "completed");
  assert.equal(waited.subagent.subagent_id, subagentId);
  assert.equal(waited.event.source_event_kind, "Subagent.wait");

  const input = await thread.sendSubagentInput(subagentId, {
    message: "Add SDK input route evidence.",
    workflowNodeId: "runtime.subagent.input.explore",
  });
  assert.equal(input.input_count, 1);
  assert.equal(input.last_input, "Add SDK input route evidence.");
  assert.equal(input.event.source_event_kind, "Subagent.send_input");

  const canceled = await thread.cancelSubagent(subagentId, {
    reason: "sdk_mock_cancel",
    workflowNodeId: "runtime.subagent.cancel.explore",
  });
  assert.equal(canceled.status, "canceled");
  assert.equal(canceled.subagent.cancellation_reason, "sdk_mock_cancel");
  assert.equal(canceled.event.source_event_kind, "Subagent.cancel");

  const resumed = await thread.resumeSubagent(subagentId, {
    message: "Resume SDK subagent wrapper proof.",
    workflowNodeId: "runtime.subagent.resume.explore",
  });
  assert.equal(resumed.status, "completed");
  assert.equal(resumed.subagent.restart_count, 1);
  assert.equal(resumed.event.source_event_kind, "Subagent.resume");

  const assigned = await thread.assignSubagent(subagentId, {
    role: "implement",
    toolPack: "coding-plus",
    mergePolicy: "manual_review",
    workflowNodeId: "runtime.subagent.assign.implement",
  });
  assert.equal(assigned.role, "implement");
  assert.equal(assigned.assignment_count, 1);
  assert.equal(assigned.event.source_event_kind, "Subagent.assign");

  const isolated = await thread.spawnSubagent({
    role: "verify",
    prompt: "Stay isolated from parent cancellation.",
    cancellationInheritance: "isolate",
  });
  const propagation = await thread.propagateSubagentCancellation({ reason: "parent_stop" });
  assert.equal(propagation.object, "ioi.runtime_subagent_cancellation_propagation");
  assert.equal(propagation.candidate_count, 2);
  assert.equal(propagation.canceled_count, 1);
  assert.equal(propagation.skipped_count, 1);
  assert.equal(propagation.canceled_subagents[0].subagent_id, subagentId);
  assert.equal(propagation.skipped_subagents[0].subagent_id, isolated.subagent_id);
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

function runtimeEnvelope({
  seq,
  eventKind,
  sourceEventKind,
  payload,
  createdAt,
  itemId,
  turnId = "turn_sdk",
  componentKind = null,
  workflowNodeId = null,
  payloadSchemaVersion = "ioi.runtime.event.v1",
  status,
}) {
  return {
    schema_version: "ioi.runtime.event.v1",
    event_id: `events_thread_sdk:seq:${String(seq).padStart(8, "0")}`,
    event_stream_id: "events_thread_sdk",
    thread_id: "thread_sdk",
    turn_id: turnId,
    item_id: itemId,
    seq,
    parent_seq: seq > 1 ? seq - 1 : null,
    idempotency_key: `${sourceEventKind}:${seq}`,
    source: "runtime_service",
    source_event_kind: sourceEventKind,
    event_kind: eventKind,
    status: status ?? (eventKind.endsWith(".started") ? "running" : "completed"),
    actor: "runtime",
    created_at: createdAt,
    workspace_root: process.cwd(),
    workflow_graph_id: null,
    workflow_node_id: workflowNodeId,
    component_kind: componentKind,
    tool_call_id: null,
    approval_id: null,
    artifact_refs: [],
    receipt_refs: [],
    policy_decision_refs: [],
    rollback_refs: [],
    payload_schema_version: payloadSchemaVersion,
    payload_ref: null,
    payload: Object.fromEntries(Object.entries(payload).map(([key, value]) => [key, String(value)])),
    payload_summary: payload,
    redaction_profile: "internal",
    fixture_profile: null,
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
