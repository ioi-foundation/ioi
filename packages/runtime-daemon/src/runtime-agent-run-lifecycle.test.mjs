import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgent,
  createRun,
} from "./runtime-agent-run-lifecycle.mjs";

function fakeStore() {
  return {
    agents: new Map(),
    runs: new Map(),
    defaultCwd: "/workspace/default",
    homeDir: "/home/operator",
    writes: [],
    resolveModelRoute(options, context) {
      this.resolveModelRouteCall = { options, context };
      return {
        selectedModel: "model.local",
        requestedModelId: options.model?.id ?? null,
        routeId: "route.local-first",
        endpointId: "endpoint.local",
        providerId: "provider.local",
        receiptId: "receipt.route",
        decision: { decisionId: "decision.route", selectedModel: "model.local" },
      };
    },
    getAgent(agentId) {
      return this.agents.get(agentId);
    },
    resolveRunModelRoute(agent, request) {
      this.resolveRunModelRouteCall = { agent, request };
      return { selectedModel: agent.modelId, receiptId: "receipt.run.route", decision: { decisionId: "decision.run" } };
    },
    resolveRunMemory(agent, request, prompt) {
      this.resolveRunMemoryCall = { agent, request, prompt };
      return { records: [{ id: "memory.1", fact: "Remembered fact" }] };
    },
    skillHookCatalog({ cwd }) {
      this.skillHookCatalogCwd = cwd;
      return { selectedSkillIds: [], selectedHookIds: [] };
    },
    writeAgent(agent, operationKind) {
      this.writes.push({ kind: "agent", operationKind, agent });
    },
    writeRun(run, operationKind) {
      this.writes.push({ kind: "run", operationKind, run });
    },
  };
}

function deps(overrides = {}) {
  return {
    approvalModeForThreadMode: (threadMode) => (threadMode === "agent" ? "on-request" : "read-only"),
    buildRun({ agent, mode, prompt, request, source, modelRoute, memory, skillHookCatalog, diagnosticsFeedback }) {
      return {
        id: "run.test",
        agentId: agent.id,
        mode,
        prompt,
        request,
        source,
        modelRoute,
        memory,
        skillHookCatalog,
        diagnosticsFeedback,
        status: "completed",
        trace: { taskState: { currentObjective: prompt } },
      };
    },
    ensureProviderAvailable(runtime, options) {
      if (runtime !== "local" && !options.hostedEndpoint) {
        throw Object.assign(new Error("missing provider"), { runtime });
      }
    },
    initialThreadRuntimeControls: (options, modelRoute, now) => ({
      mode: options.mode ?? "ask",
      approvalMode: options.approvalMode ?? null,
      modelRouteId: modelRoute.routeId,
      updatedAt: now,
    }),
    mcpRegistryForWorkspace: (cwd, options) => ({
      cwd,
      homeDir: options.homeDir,
      servers: Object.keys(options.mcpServers ?? {}),
    }),
    randomUUID: () => "uuid-1",
    runtimeModeForOptions: (options) => (options.hosted ? "hosted" : "local"),
    runtimeUsageTelemetryForRun({ run, agent, threadId }) {
      return {
        run_id: run.id,
        agent_id: agent.id,
        thread_id: threadId,
        total_tokens: 7,
      };
    },
    summarizeAgentOptions: (cwd, options) => ({
      localCwd: cwd,
      mcpServerNames: Object.keys(options.mcpServers ?? {}),
      skillNames: [],
      hookNames: [],
    }),
    threadIdForAgent: (agentId) => `thread.${agentId}`,
    threadModeForRunMode: (mode, fallback) => (mode === "send" ? "agent" : fallback ?? "ask"),
    ...overrides,
  };
}

test("createAgent resolves runtime, model route, controls, MCP registry, and persists agent", () => {
  const store = fakeStore();

  const agent = createAgent(
    store,
    {
      local: { cwd: "/workspace/project" },
      model: { id: "model.local" },
      mcpServers: { docs: {} },
      mode: "agent",
    },
    deps(),
  );

  assert.equal(agent.id, "agent_uuid-1");
  assert.equal(agent.runtime, "local");
  assert.equal(agent.cwd, "/workspace/project");
  assert.equal(agent.modelRouteId, "route.local-first");
  assert.equal(agent.runtimeControls.mode, "agent");
  assert.equal(agent.mcpRegistry.homeDir, "/home/operator");
  assert.deepEqual(agent.options.mcpServerNames, ["docs"]);
  assert.equal(store.agents.get(agent.id), agent);
  assert.equal(store.writes[0].operationKind, "agent.create");
  assert.deepEqual(store.resolveModelRouteCall.context.evidenceRefs, ["runtime_agent_model_route"]);
});

test("createAgent preserves hosted provider availability failures", () => {
  const store = fakeStore();

  assert.throws(
    () => createAgent(store, { hosted: true }, deps()),
    (error) => error.runtime === "hosted",
  );
});

test("createRun resolves route, memory, skill catalog, usage telemetry, and persists run", () => {
  const store = fakeStore();
  const agent = createAgent(store, { local: { cwd: "/workspace/project" } }, deps());

  const run = createRun(
    store,
    agent.id,
    {
      mode: "learn",
      options: { taskFamily: "schemas" },
      approval_mode: "manual",
      diagnostics_feedback: { diagnosticStatus: "clean" },
    },
    deps(),
  );

  assert.equal(run.id, "run.test");
  assert.equal(run.mode, "learn");
  assert.equal(run.prompt, "Learn governed task-family updates for schemas");
  assert.equal(run.threadMode, "ask");
  assert.equal(run.approvalMode, "manual");
  assert.deepEqual(run.usage, {
    run_id: "run.test",
    agent_id: agent.id,
    thread_id: `thread.${agent.id}`,
    total_tokens: 7,
  });
  assert.equal(run.trace.usageTelemetry.total_tokens, 7);
  assert.equal(store.resolveRunMemoryCall.prompt, "Learn governed task-family updates for schemas");
  assert.equal(store.skillHookCatalogCwd, "/workspace/project");
  assert.equal(store.runs.get(run.id), run);
  assert.equal(store.writes.at(-1).operationKind, "run.create");
});
