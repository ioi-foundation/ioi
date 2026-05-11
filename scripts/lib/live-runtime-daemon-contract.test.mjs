import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");

async function importSdk() {
  return import("../../packages/agent-sdk/dist/index.js");
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

async function fetchSseEvents(url) {
  const text = await fetch(url).then(async (response) => {
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
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "agentgres_canonical_write"));
    assert.equal((await canceled.scorecard()).verifierIndependence, 1);
    assert.ok((await canceled.artifacts()).some((artifact) => artifact.name === "agentgres-projection.json"));

    const operationLog = path.join(stateDir, "operation-log.jsonl");
    assert.ok(fs.existsSync(operationLog));
    assert.ok(fs.readFileSync(operationLog, "utf8").includes("run.cancel"));
    for (const relative of [
      ["runs", `${run.id}.json`],
      ["tasks", `${run.id}.json`],
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

    const cliView = await fetch(`${daemon.endpoint}/v1/runs/${run.id}/trace`).then((response) =>
      response.json(),
    );
    assert.equal(cliView.canonicalState.runId, run.id);
    assert.equal(cliView.canonicalState.terminalState, "canceled");
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
    assert.equal(thread.schema_version, "ioi.agent-runtime.tti.v1");
    assert.match(thread.thread_id, /^thread_/);
    assert.match(thread.session_id, /^agent_/);
    assert.equal(thread.latest_seq, 0);
    assert.equal(thread.workspace, cwd);
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
    assert.equal(turn.schema_version, "ioi.agent-runtime.tti.v1");
    assert.equal(turn.thread_id, thread.thread_id);
    assert.match(turn.turn_id, /^turn_/);
    assert.equal(turn.status, "completed");
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
    assert.equal(events[0].schema_version, "ioi.agent-runtime.event-envelope.v1");
    assert.equal(events[0].thread_id, thread.thread_id);
    assert.equal(events[0].turn_id, turn.turn_id);
    assert.equal(events[0].event, "turn.started");
    assert.equal(events[0].workflow_node_id, "runtime.runtime-thread");
    const routeEvent = events.find((event) => event.payload_summary?.event_kind === "ModelRouteDecision");
    assert.equal(routeEvent.component_kind, "model_router");
    assert.equal(routeEvent.workflow_node_id, "workflow.model-router");
    assert.equal(routeEvent.payload_summary.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload_summary.reasoning_effort, "low");
    assert.ok(routeEvent.payload_summary.model_route_decision_id);
    assert.deepEqual(routeEvent.receipt_refs, [thread.model_route_receipt_id]);
    assert.equal(events.at(-1).event, "turn.completed");
    assert.ok(events.some((event) => event.workflow_node_id === "runtime.quality-ledger"));
    assert.ok(events.every((event) => event.payload_summary?.run_id));

    const replayAfterFive = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=5`,
    );
    assert.equal(replayAfterFive[0].seq, 6);
    assert.ok(replayAfterFive.every((event) => event.seq > 5));
  } finally {
    await daemon.close();
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
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryEdit"));
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryPolicy"));
  } finally {
    await daemon.close();
  }
});

test("agent CLI exposes model and thinking control contracts", () => {
  const source = fs.readFileSync(path.join(root, "crates/cli/src/commands/agent.rs"), "utf8");
  assert.match(source, /AgentCommands::Model/);
  assert.match(source, /AgentCommands::Thinking/);
  assert.match(source, /AgentCommands::Memory/);
  assert.match(source, /\/model/);
  assert.match(source, /\/thinking/);
  assert.match(source, /# remember/);
  assert.match(source, /\/memory show/);
  assert.match(source, /\/memory disable/);
  assert.match(source, /\/memory path/);
  assert.match(source, /memory_policy/);
  assert.match(source, /ModelRouteDecision/);
  assert.match(source, /memory_update/);
  assert.match(source, /reactflow_workflow_node/);
});

test("React Flow memory node contracts remain workflow-addressable", () => {
  const workflowContracts = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/deepseek-parity-workflow-contracts.ts"),
    "utf8",
  );
  const harnessWorkflow = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/harness-workflow/core.ts"),
    "utf8",
  );
  assert.match(workflowContracts, /memory\.scope/);
  assert.match(workflowContracts, /memory\.remember/);
  assert.match(workflowContracts, /memory\.policy/);
  assert.match(workflowContracts, /memory\.path/);
  assert.match(harnessWorkflow, /memory_read/);
  assert.match(harnessWorkflow, /memory_write/);
  assert.match(harnessWorkflow, /memory_policy/);
  assert.match(harnessWorkflow, /memory\.writeRequiresApproval/);
  assert.match(harnessWorkflow, /subagent inheritance/);
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
