import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgent,
  createRuntimeAgentRunLifecycleSurface,
  createRun,
} from "./runtime-agent-run-lifecycle.mjs";

function fakeStore() {
  return {
    agents: new Map([["agent_existing", { id: "agent_existing", runtime: "local" }]]),
    runs: new Map(),
    defaultCwd: "/workspace/default",
    writes: [],
    plannerCalls: [],
    routeCalls: [],
    memoryCalls: [],
    getAgentCalls: [],
    resolveModelRoute(options, context) {
      this.routeCalls.push({ surface: "agent", options, context });
      return { selectedModel: "model.local" };
    },
    resolveRunModelRoute(agent, request) {
      this.routeCalls.push({ surface: "run", agent, request });
      return { selectedModel: "model.local" };
    },
    resolveRunMemory(agent, request, prompt) {
      this.memoryCalls.push({ agent, request, prompt });
      return { records: [] };
    },
    getAgent(agentId) {
      this.getAgentCalls.push(agentId);
      return this.agents.get(agentId);
    },
    writeAgent(agent, operationKind) {
      this.writes.push({ kind: "agent", operationKind, agent });
    },
    writeRun(run, operationKind) {
      this.writes.push({ kind: "run", operationKind, run });
    },
  };
}

function assertNoRetiredLifecycleDetailAliases(details) {
  for (const key of [
    "rustCoreBoundary",
    "operationKind",
    "requestedCwd",
    "requestedRuntime",
    "agentId",
    "requestedMode",
    "evidenceRefs",
  ]) {
    assert.equal(Object.hasOwn(details, key), false, `retired detail alias ${key} must be absent`);
  }
}

test("createAgent facade fails closed before Rust planning or JS persistence", () => {
  const store = fakeStore();

  assert.throws(
    () => createAgent(store, {
      local: { cwd: "/workspace/project" },
      hosted: true,
      model: { id: "model.local" },
      mcp_servers: { docs: {} },
      mcpServers: { retired: {} },
    }),
    (error) => {
      assert.equal(error.code, "runtime_agent_create_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.agent_create");
      assert.equal(error.details.operation, "agent_create");
      assert.equal(error.details.operation_kind, "agent.create");
      assert.equal(error.details.requested_cwd, "/workspace/project");
      assert.equal(error.details.requested_runtime, "hosted");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_agent_create_js_facade_retired",
        "rust_daemon_core_agent_create_required",
        "agentgres_agent_create_state_truth_required",
      ]);
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.agents.size, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.plannerCalls, []);
  assert.deepEqual(store.routeCalls, []);
});

test("createRun facade fails closed before route, memory, Rust planning, or JS persistence", () => {
  const store = fakeStore();

  assert.throws(
    () => createRun(store, "agent_existing", {
      mode: "learn",
      prompt: "Learn governed task-family updates",
      threadMode: "retired",
      approvalMode: "retired",
      diagnosticsFeedback: { diagnostic_status: "alias" },
    }),
    (error) => {
      assert.equal(error.code, "runtime_run_create_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.run_create");
      assert.equal(error.details.operation, "run_create");
      assert.equal(error.details.operation_kind, "run.create");
      assert.equal(error.details.agent_id, "agent_existing");
      assert.equal(error.details.requested_mode, "learn");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_run_create_js_facade_retired",
        "rust_daemon_core_run_create_required",
        "agentgres_run_create_state_truth_required",
      ]);
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.runs.size, 0);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
});

test("createRun missing-agent path is still Rust-core required and does not read JS agent state", () => {
  const store = fakeStore();

  assert.throws(
    () => createRun(store, "agent_missing", {}),
    (error) => {
      assert.equal(error.code, "runtime_run_create_rust_core_required");
      assert.equal(error.details.agent_id, "agent_missing");
      assert.equal(error.details.requested_mode, "send");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.writes, []);
});

test("agent/run lifecycle surface routes create and run creation to fail-closed core boundary", () => {
  const store = fakeStore();
  const surface = createRuntimeAgentRunLifecycleSurface();

  assert.throws(
    () => surface.createAgent(store, { local: { cwd: "/workspace/surface" } }),
    (error) => {
      assert.equal(error.code, "runtime_agent_create_rust_core_required");
      assert.equal(error.details.requested_cwd, "/workspace/surface");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );
  assert.throws(
    () => surface.createRun(store, "agent_existing", { mode: "review" }),
    (error) => {
      assert.equal(error.code, "runtime_run_create_rust_core_required");
      assert.equal(error.details.agent_id, "agent_existing");
      assert.equal(error.details.requested_mode, "review");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
});
