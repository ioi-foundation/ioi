import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgent,
  createRuntimeAgentRunLifecycleSurface,
  createRun,
  createThread,
} from "./runtime-agent-run-lifecycle.mjs";

function fakeStore() {
  const store = {
    agents: new Map([["agent_existing", { id: "agent_existing", runtime: "local" }]]),
    runs: new Map(),
    defaultCwd: "/workspace/default",
    writes: [],
    plannerCalls: [],
    lifecycleAdmissionRequiredCalls: [],
    routeCalls: [],
    memoryCalls: [],
    getAgentCalls: [],
    runtimeThreadCalls: [],
    startedEvents: [],
    resolveModelRoute(options, context) {
      this.routeCalls.push({ surface: "agent", options, context });
      return { selectedModel: "model.local" };
    },
    contextPolicyRunner: {
      planLifecycleAdmissionRequired(request) {
        store.lifecycleAdmissionRequiredCalls.push(request);
        return {
          source: "rust_lifecycle_admission_required_command",
          backend: "rust_policy",
          record: {
            status: "rust_core_required",
            status_code: 501,
            code: request.operation === "agent_create"
              ? "runtime_agent_create_rust_core_required"
              : "runtime_run_create_rust_core_required",
            message: request.operation === "agent_create"
              ? "Agent creation requires direct Rust daemon-core state admission and persistence."
              : "Run creation requires direct Rust daemon-core state admission and persistence.",
            details: {
              rust_core_boundary: request.operation === "agent_create"
                ? "runtime.agent_create"
                : "runtime.run_create",
              operation: request.operation,
              operation_kind: request.operation_kind,
              agent_id: request.agent_id ?? null,
              requested_cwd: request.requested_cwd ?? null,
              requested_runtime: request.requested_runtime ?? null,
              requested_mode: request.requested_mode ?? null,
              evidence_refs: request.evidence_refs,
            },
          },
        };
      },
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
    ensureThreadStartedEvent(agent) {
      this.startedEvents.push(agent.id);
    },
    threadForAgent(agent) {
      return { thread_id: `thread_${agent.id}`, agent_id: agent.id };
    },
  };
  return store;
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

function assertRuntimeBridgeThreadRustCoreRequired(error, {
  operation = "runtime_bridge_thread_start",
  operationKind = "thread.runtime_bridge.start",
  runtimeProfile = "runtime_service",
} = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "runtime_bridge_thread_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "runtime.bridge_thread");
  assert.equal(error.details.operation, operation);
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.runtime_profile, runtimeProfile);
  assert.equal(
    error.details.evidence_refs.includes("runtime_bridge_thread_start_js_facade_retired"),
    true,
  );
  assert.equal(Object.hasOwn(error.details, "runtimeProfile"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
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

  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 1);
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls[0], {
    operation: "agent_create",
    operation_kind: "agent.create",
    agent_id: undefined,
    requested_cwd: "/workspace/project",
    requested_runtime: "hosted",
    requested_mode: undefined,
    evidence_refs: [
      "runtime_agent_create_js_facade_retired",
      "rust_daemon_core_agent_create_required",
      "agentgres_agent_create_state_truth_required",
    ],
  });
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

  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 1);
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls[0], {
    operation: "run_create",
    operation_kind: "run.create",
    agent_id: "agent_existing",
    requested_cwd: undefined,
    requested_runtime: undefined,
    requested_mode: "learn",
    evidence_refs: [
      "runtime_run_create_js_facade_retired",
      "rust_daemon_core_run_create_required",
      "agentgres_run_create_state_truth_required",
    ],
  });
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

  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 1);
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].operation, "run_create");
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].agent_id, "agent_missing");
  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.writes, []);
});

test("createThread facade fails closed before JS agent persistence for default threads", () => {
  const store = fakeStore();

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }),
    (error) => {
      assert.equal(error.code, "runtime_agent_create_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "runtime.agent_create");
      assert.equal(error.details.requested_cwd, "/workspace/thread");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 1);
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].operation, "agent_create");
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].requested_cwd, "/workspace/thread");
  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.deepEqual(store.startedEvents, []);
  assert.deepEqual(store.writes, []);
});

test("createThread facade fails closed for runtime-service threads before bridge boundary dispatch", () => {
  const store = fakeStore();

  assert.throws(
    () => createThread(store, {
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: "/workspace/runtime" },
      },
    }),
    assertRuntimeBridgeThreadRustCoreRequired,
  );

  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.deepEqual(store.startedEvents, []);
  assert.deepEqual(store.writes, []);
});

test("agent/run lifecycle surface routes create, run creation, and thread creation to mounted boundary", async () => {
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
  assert.throws(
    () => surface.createThread(store, {
      options: { runtime_profile: "runtime_service" },
    }),
    assertRuntimeBridgeThreadRustCoreRequired,
  );

  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 2);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
});
