import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgent,
  createRuntimeAgentRunLifecycleSurface,
  createRun,
  createThread,
} from "./runtime-agent-run-lifecycle.mjs";

function fakeStore({
  agentCreatePlan = defaultAgentCreatePlan,
  threadCreatePlan = defaultThreadCreatePlan,
  runCreatePlan = defaultRunCreatePlan,
  runtimeBridgeThreadStartPlan = defaultRuntimeBridgeThreadStartPlan,
  runtimeBridgeThreadControlPlan = defaultRuntimeBridgeThreadControlPlan,
  runtimeBridgeTurnRunStateUpdatePlan = defaultRuntimeBridgeTurnRunStateUpdatePlan,
} = {}) {
  const store = {
    agents: new Map([[
      "agent_existing",
      {
        id: "agent_existing",
        runtime: "local",
        runtimeControls: {
          mode: "agent",
          approval_mode: "suggest",
        },
        options: {
          localCwd: "/workspace/default",
        },
      },
    ], [
      "agent_runtime",
      {
        id: "agent_runtime",
        runtime: "local",
        runtimeProfile: "runtime_service",
        runtime_profile: "runtime_service",
        runtimeSessionId: "session_runtime",
        runtime_session_id: "session_runtime",
        runtimeBridgeId: "bridge_runtime",
        runtime_bridge_id: "bridge_runtime",
        runtimeControls: {
          mode: "agent",
          approval_mode: "suggest",
        },
        options: {
          localCwd: "/workspace/runtime",
        },
      },
    ]]),
    runs: new Map(),
    defaultCwd: "/workspace/default",
    homeDir: "/home/tester",
    writes: [],
    plannerCalls: [],
    lifecycleAdmissionRequiredCalls: [],
    routeCalls: [],
    memoryCalls: [],
    getAgentCalls: [],
    providerCalls: [],
    runBuildCalls: [],
    runtimeControlCalls: [],
    threadProjectionCalls: [],
    turnProjectionCalls: [],
    mcpCalls: [],
    runtimeModeCalls: [],
    summaryCalls: [],
    runtimeThreadCalls: [],
    startedEvents: [],
    resolveModelRoute(options, context) {
      this.routeCalls.push({ surface: "agent", options, context });
      return {
        selectedModel: "model.local",
        requestedModelId: options.model?.id ?? "auto",
        routeId: "route.local-first",
        endpointId: "endpoint.local",
        providerId: "provider.local",
        receiptId: "receipt.model-route",
        decision: {
          route_id: "route.local-first",
          selected_model: "model.local",
          evidence_refs: ["runtime_agent_model_route"],
        },
      };
    },
    contextPolicyRunner: {
      planLifecycleAdmissionRequired(request) {
        store.lifecycleAdmissionRequiredCalls.push(request);
        const profile = lifecycleRequiredProfile(request);
        return {
          source: "rust_lifecycle_admission_required_command",
          backend: "rust_policy",
          record: {
            status: "rust_core_required",
            status_code: 501,
            code: profile.code,
            message: profile.message,
            details: {
              rust_core_boundary: profile.boundary,
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
      this.threadProjectionCalls.push(agent);
      const threadId = agent.id.replace(/^agent_/, "thread_");
      return {
        thread_id: threadId,
        agent_id: agent.id,
        event_stream_id: `${threadId}:events`,
        rust_projected: true,
      };
    },
    turnForRun(run) {
      this.turnProjectionCalls.push(run);
      const threadId = run.agentId.replace(/^agent_/, "thread_");
      const turnId = run.id.replace(/^run_/, "turn_");
      return {
        turn_id: turnId,
        thread_id: threadId,
        request_id: run.id,
        run_id: run.id,
        agent_id: run.agentId,
        rust_projected: true,
      };
    },
  };
  if (agentCreatePlan) {
    store.contextPolicyRunner.planAgentCreateStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return agentCreatePlan(request);
    };
  }
  if (threadCreatePlan) {
    store.contextPolicyRunner.planThreadCreateStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return threadCreatePlan(request);
    };
  }
  if (runCreatePlan) {
    store.contextPolicyRunner.planRunCreateStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return runCreatePlan(request);
    };
  }
  if (runtimeBridgeThreadStartPlan) {
    store.contextPolicyRunner.planRuntimeBridgeThreadStartAgentStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return runtimeBridgeThreadStartPlan(request);
    };
  }
  if (runtimeBridgeThreadControlPlan) {
    store.contextPolicyRunner.planRuntimeBridgeThreadControlAgentStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return runtimeBridgeThreadControlPlan(request);
    };
  }
  if (runtimeBridgeTurnRunStateUpdatePlan) {
    store.contextPolicyRunner.planRuntimeBridgeTurnRunStateUpdate = (request) => {
      store.plannerCalls.push(request);
      return runtimeBridgeTurnRunStateUpdatePlan(request);
    };
  }
  return store;
}

function defaultAgentCreatePlan(request) {
  return {
    source: "rust_agent_create_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "agent.create",
    created_at: request.agent.createdAt,
    updated_at: request.agent.updatedAt,
    agent: {
      ...request.agent,
      rust_planned: true,
    },
  };
}

function defaultThreadCreatePlan(request) {
  return {
    source: "rust_thread_create_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "thread.create",
    thread_id: request.thread.thread_id,
    agent_id: request.thread.agent_id,
    created_at: request.agent.createdAt,
    updated_at: request.agent.updatedAt,
    agent: {
      ...request.agent,
      rust_thread_planned: true,
    },
    thread: {
      ...request.thread,
      rust_planned: true,
    },
  };
}

function defaultRunCreatePlan(request) {
  return {
    source: "rust_run_create_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "run.create",
    created_at: request.run.createdAt,
    updated_at: request.run.updatedAt,
    run: {
      ...request.run,
      rust_planned: true,
    },
  };
}

function defaultRuntimeBridgeThreadStartPlan(request) {
  return {
    source: "rust_runtime_bridge_thread_start_agent_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "thread.runtime_bridge.start",
    thread_id: request.thread_id,
    agent_id: request.agent.id,
    updated_at: request.updated_at,
    bridge_start: {
      runtime_profile: request.runtime_profile,
      session_id: request.session_id,
      bridge_id: request.bridge_id,
      status: request.status,
      source: request.source,
      updated_at: request.updated_at,
    },
    agent: {
      ...request.agent,
      runtimeProfile: request.runtime_profile,
      runtime_profile: request.runtime_profile,
      runtimeSessionId: request.session_id,
      runtime_session_id: request.session_id,
      runtimeBridgeId: request.bridge_id,
      runtime_bridge_id: request.bridge_id,
      runtimeBridgeStatus: request.status,
      runtime_bridge_status: request.status,
      runtimeBridgeSource: request.source,
      runtime_bridge_source: request.source,
      fixtureProfile: null,
      updatedAt: request.updated_at,
      rust_runtime_bridge_started: true,
    },
  };
}

function defaultRuntimeBridgeThreadControlPlan(request) {
  return {
    source: "rust_runtime_bridge_thread_control_agent_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "thread.runtime_bridge.control",
    thread_id: request.thread_id,
    agent_id: request.agent.id,
    updated_at: request.updated_at,
    control: {
      action: request.action,
      reason: request.reason,
      runtime_bridge_status: "active",
      updated_at: request.updated_at,
      evidence_refs: request.evidence_refs,
    },
    agent: {
      ...request.agent,
      status: "active",
      runtimeBridgeStatus: "active",
      runtime_bridge_status: "active",
      updatedAt: request.updated_at,
      rust_runtime_bridge_controlled: true,
    },
  };
}

function defaultRuntimeBridgeTurnRunStateUpdatePlan(request) {
  return {
    source: "rust_runtime_bridge_turn_run_state_update_command",
    backend: "rust_policy",
    status: "planned",
    operation_kind: "turn.runtime_bridge.submit",
    thread_id: request.thread_id,
    run_id: request.run.id,
    agent_id: request.run.agentId,
    updated_at: request.run.updatedAt,
    run: {
      ...request.run,
      rust_runtime_bridge_submitted: true,
    },
  };
}

function lifecycleRequiredProfile(request) {
  if (request.operation === "agent_create") {
    return {
      code: "runtime_agent_create_rust_core_required",
      message: "Agent creation requires direct Rust daemon-core state admission and persistence.",
      boundary: "runtime.agent_create",
    };
  }
  if (request.operation === "thread_create") {
    return {
      code: "runtime_thread_create_rust_core_required",
      message: "Thread creation requires direct Rust daemon-core state admission and persistence.",
      boundary: "runtime.thread_create",
    };
  }
  return {
    code: "runtime_run_create_rust_core_required",
    message: "Run creation requires direct Rust daemon-core state admission and persistence.",
    boundary: "runtime.run_create",
  };
}

function agentCreateDeps(store) {
  return {
    ensureProviderAvailable(runtime, options) {
      store.providerCalls.push({ runtime, options });
    },
    initialThreadRuntimeControls(options, modelRoute, now) {
      store.runtimeControlCalls.push({ options, modelRoute, now });
      return {
        mode: "agent",
        approvalMode: "suggest",
        approval_mode: "suggest",
        model: {
          id: modelRoute.requestedModelId,
          route_id: modelRoute.routeId,
          selected_model: modelRoute.selectedModel,
          endpoint_id: modelRoute.endpointId,
          provider_id: modelRoute.providerId,
          receipt_id: modelRoute.receiptId,
          updated_at: now,
        },
        updatedAt: now,
      };
    },
    mcpRegistryForWorkspace(cwd, options) {
      store.mcpCalls.push({ cwd, options });
      return {
        schema_version: "ioi.runtime.mcp-manager-status.v1",
        workspace_root: cwd,
        server_count: 0,
        servers: [],
      };
    },
    randomUUID() {
      return "uuid-agent";
    },
    runtimeModeForOptions(options) {
      store.runtimeModeCalls.push(options);
      return options.hosted ? "hosted" : "local";
    },
    summarizeAgentOptions(cwd, options) {
      store.summaryCalls.push({ cwd, options });
      return {
        localCwd: options.local?.cwd ?? null,
        cloudConfigured: Boolean(options.cloud ?? options.hosted),
      };
    },
  };
}

function threadCreateDeps(store) {
  return {
    ...agentCreateDeps(store),
    eventStreamIdForThread(threadId) {
      return `${threadId}:events`;
    },
    runtimeThreadSchemaVersion: "ioi.runtime.thread.v1",
    threadIdForAgent(agentId) {
      return agentId.replace(/^agent_/, "thread_");
    },
    threadStatusForAgent(status) {
      return status === "active" ? "active" : "archived";
    },
  };
}

function runCreateDeps(store) {
  return {
    ensureProviderAvailable(runtime, options) {
      store.providerCalls.push({ runtime, options });
    },
    buildRun(args) {
      store.runBuildCalls.push(args);
      return {
        id: "run_uuid-run",
        agentId: args.agent.id,
        status: "completed",
        mode: args.mode,
        objective: args.prompt,
        createdAt: "2026-06-12T12:00:00.000Z",
        updatedAt: "2026-06-12T12:00:00.000Z",
        events: [],
        conversation: [],
        receipts: [],
        artifacts: [],
        trace: {
          usage_telemetry: {
            total_tokens: 7,
          },
        },
        usage: {
          total_tokens: 7,
        },
        usage_telemetry: {
          total_tokens: 7,
        },
        result: "ok",
      };
    },
    threadModeForRunMode(mode, fallback) {
      return mode === "learn" ? "agent" : fallback ?? "agent";
    },
    approvalModeForThreadMode(mode) {
      return mode === "review" ? "human_required" : "suggest";
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
  const evidenceRef = operation === "runtime_bridge_turn_submit"
    ? "runtime_bridge_turn_submit_rust_owned"
    : operation === "runtime_bridge_thread_control"
      ? "runtime_bridge_thread_control_rust_owned"
      : "runtime_bridge_thread_start_js_facade_retired";
  assert.equal(
    error.details.evidence_refs.includes(evidenceRef),
    true,
  );
  assert.equal(Object.hasOwn(error.details, "runtimeProfile"), false);
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  return true;
}

test("createAgent commits Rust-planned agent projection through Agentgres", () => {
  const store = fakeStore();
  const options = {
    local: { cwd: "/workspace/project" },
    hosted: true,
    model: { id: "model.local" },
    mcp_servers: { docs: {} },
    mcpServers: { retired: {} },
  };

  const agent = createAgent(store, options, agentCreateDeps(store));

  assert.equal(agent.id, "agent_uuid-agent");
  assert.equal(agent.status, "active");
  assert.equal(agent.runtime, "hosted");
  assert.equal(agent.cwd, "/workspace/project");
  assert.equal(agent.modelId, "model.local");
  assert.equal(agent.runtimeControls.model.route_id, "route.local-first");
  assert.equal(agent.rust_planned, true);
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].agent.id, "agent_uuid-agent");
  assert.equal(store.plannerCalls[0].agent.runtimeControls.model.selected_model, "model.local");
  assert.deepEqual(store.writes, [{ kind: "agent", operationKind: "agent.create", agent }]);
  assert.equal(store.agents.size, 2);
  assert.equal(store.routeCalls.length, 1);
  assert.equal(store.providerCalls.length, 1);
  assert.equal(store.runtimeControlCalls.length, 1);
  assert.equal(store.mcpCalls.length, 1);
  assert.equal(store.summaryCalls.length, 1);
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls, []);
  assert.equal(Object.hasOwn(agent.options, "mcpServers"), false);
});

test("createAgent fails closed before route planning when Rust planner is missing", () => {
  const store = fakeStore({ agentCreatePlan: null });

  assert.throws(
    () => createAgent(store, {
      local: { cwd: "/workspace/project" },
      hosted: true,
      model: { id: "model.local" },
      mcp_servers: { docs: {} },
      mcpServers: { retired: {} },
    }, agentCreateDeps(store)),
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
  assert.equal(store.agents.size, 2);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.plannerCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.providerCalls, []);
  assert.deepEqual(store.mcpCalls, []);
});

test("createAgent rejects missing Rust-planned agent projection", () => {
  const store = fakeStore({
    agentCreatePlan: () => ({
      status: "planned",
      operation_kind: "agent.create",
    }),
  });

  assert.throws(
    () => createAgent(store, { local: { cwd: "/workspace/project" } }, agentCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "agent_create_state_update_agent_missing");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.agent_create");
      assert.equal(error.details.operation_kind, "agent.create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.agents.size, 2);
});

test("createAgent rejects mismatched Rust operation kind", () => {
  const store = fakeStore({
    agentCreatePlan: (request) => ({
      status: "planned",
      operation_kind: "run.create",
      agent: request.agent,
    }),
  });

  assert.throws(
    () => createAgent(store, { local: { cwd: "/workspace/project" } }, agentCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "agent_create_state_update_operation_kind_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.expected_operation_kind, "agent.create");
      assert.equal(error.details.actual_operation_kind, "run.create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.agents.size, 2);
});

test("createAgent rejects incomplete Rust-planned projection", () => {
  const store = fakeStore({
    agentCreatePlan: () => ({
      status: "planned",
      operation_kind: "agent.create",
      agent: {
        id: "agent_uuid-agent",
      },
    }),
  });

  assert.throws(
    () => createAgent(store, { local: { cwd: "/workspace/project" } }, agentCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "agent_create_state_update_projection_incomplete");
      assert.equal(error.status, 502);
      assert.equal(error.details.agent_id, "agent_uuid-agent");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.agents.size, 2);
});

test("createRun commits Rust-planned run projection through Agentgres", () => {
  const store = fakeStore();

  const run = createRun(store, "agent_existing", {
    mode: "learn",
    prompt: "Learn governed task-family updates",
    threadMode: "retired",
    approvalMode: "retired",
    diagnosticsFeedback: { diagnostic_status: "alias" },
    diagnostics_feedback: { diagnostic_status: "snake" },
  }, runCreateDeps(store));

  assert.equal(run.id, "run_uuid-run");
  assert.equal(run.agentId, "agent_existing");
  assert.equal(run.rust_planned, true);
  assert.equal(run.thread_mode, "agent");
  assert.equal(run.approval_mode, "suggest");
  assert.equal(Object.hasOwn(run, "threadMode"), false);
  assert.equal(Object.hasOwn(run, "approvalMode"), false);
  assert.equal(run.usage_telemetry.total_tokens, 7);
  assert.equal(store.runs.size, 0);
  assert.deepEqual(store.getAgentCalls, ["agent_existing"]);
  assert.equal(store.providerCalls.length, 1);
  assert.equal(store.routeCalls.length, 1);
  assert.equal(store.memoryCalls.length, 1);
  assert.equal(store.runBuildCalls.length, 1);
  assert.equal(store.runBuildCalls[0].mode, "learn");
  assert.equal(store.runBuildCalls[0].diagnosticsFeedback.diagnostic_status, "snake");
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].run.id, "run_uuid-run");
  assert.equal(store.plannerCalls[0].run.thread_mode, "agent");
  assert.equal(store.plannerCalls[0].run.approval_mode, "suggest");
  assert.deepEqual(store.writes, [{ kind: "run", operationKind: "run.create", run }]);
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls, []);
});

test("createRun fails closed before lookup, route, memory, or persistence when Rust planner is missing", () => {
  const store = fakeStore({ runCreatePlan: null });

  assert.throws(
    () => createRun(store, "agent_existing", {
      mode: "learn",
      prompt: "Learn governed task-family updates",
      threadMode: "retired",
      approvalMode: "retired",
      diagnosticsFeedback: { diagnostic_status: "alias" },
    }, runCreateDeps(store)),
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
  assert.deepEqual(store.getAgentCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
  assert.deepEqual(store.writes, []);
});

test("createRun rejects missing Rust-planned run projection", () => {
  const store = fakeStore({
    runCreatePlan: () => ({
      status: "planned",
      operation_kind: "run.create",
    }),
  });

  assert.throws(
    () => createRun(store, "agent_existing", { mode: "learn" }, runCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "run_create_state_update_run_missing");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.run_create");
      assert.equal(error.details.operation_kind, "run.create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.runs.size, 0);
});

test("createRun rejects mismatched Rust operation kind", () => {
  const store = fakeStore({
    runCreatePlan: (request) => ({
      status: "planned",
      operation_kind: "agent.create",
      run: request.run,
    }),
  });

  assert.throws(
    () => createRun(store, "agent_existing", { mode: "learn" }, runCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "run_create_state_update_operation_kind_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.expected_operation_kind, "run.create");
      assert.equal(error.details.actual_operation_kind, "agent.create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.runs.size, 0);
});

test("createRun rejects incomplete Rust-planned projection", () => {
  const store = fakeStore({
    runCreatePlan: () => ({
      status: "planned",
      operation_kind: "run.create",
      run: {
        id: "run_uuid-run",
      },
    }),
  });

  assert.throws(
    () => createRun(store, "agent_existing", { mode: "learn" }, runCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "run_create_state_update_projection_incomplete");
      assert.equal(error.status, 502);
      assert.equal(error.details.run_id, "run_uuid-run");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.equal(store.runs.size, 0);
});

test("createThread commits Rust-planned thread agent and returns Rust thread projection", () => {
  const store = fakeStore();

  const thread = createThread(store, {
    goal: "Keep the public thread lifecycle Rust-owned",
    options: {
      local: { cwd: "/workspace/thread" },
      model: { id: "model.local" },
    },
  }, threadCreateDeps(store));

  assert.equal(thread.thread_id, "thread_uuid-agent");
  assert.equal(thread.agent_id, "agent_uuid-agent");
  assert.equal(thread.event_stream_id, "thread_uuid-agent:events");
  assert.equal(thread.rust_projected, true);
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].agent.id, "agent_uuid-agent");
  assert.equal(store.plannerCalls[0].thread.thread_id, "thread_uuid-agent");
  assert.equal(store.plannerCalls[0].thread.agent_id, "agent_uuid-agent");
  assert.equal(store.plannerCalls[0].thread.event_stream_id, "thread_uuid-agent:events");
  assert.equal(store.plannerCalls[0].thread.status, "active");
  assert.equal(store.writes.length, 1);
  assert.equal(store.writes[0].kind, "agent");
  assert.equal(store.writes[0].operationKind, "thread.create");
  assert.equal(store.writes[0].agent.rust_thread_planned, true);
  assert.deepEqual(store.startedEvents, ["agent_uuid-agent"]);
  assert.equal(store.threadProjectionCalls.length, 1);
  assert.equal(store.threadProjectionCalls[0].id, "agent_uuid-agent");
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls, []);
  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.equal(store.routeCalls.length, 1);
  assert.equal(store.providerCalls.length, 1);
  assert.equal(store.runtimeControlCalls.length, 1);
  assert.equal(store.mcpCalls.length, 1);
  assert.equal(store.summaryCalls.length, 1);
});

test("createThread fails closed before route planning when Rust planner is missing", () => {
  const store = fakeStore({ threadCreatePlan: null });

  assert.throws(
    () => createThread(store, {
      options: {
        local: { cwd: "/workspace/thread" },
        hosted: true,
      },
    }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "runtime_thread_create_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.rust_core_boundary, "runtime.thread_create");
      assert.equal(error.details.operation, "thread_create");
      assert.equal(error.details.operation_kind, "thread.create");
      assert.equal(error.details.requested_cwd, "/workspace/thread");
      assert.equal(error.details.requested_runtime, "hosted");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_thread_create_js_facade_retired",
        "rust_daemon_core_thread_create_required",
        "agentgres_thread_create_state_truth_required",
      ]);
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.lifecycleAdmissionRequiredCalls.length, 1);
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].operation, "thread_create");
  assert.equal(store.lifecycleAdmissionRequiredCalls[0].requested_cwd, "/workspace/thread");
  assert.deepEqual(store.plannerCalls, []);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.startedEvents, []);
  assert.deepEqual(store.threadProjectionCalls, []);
});

test("createThread rejects missing Rust-planned agent projection", () => {
  const store = fakeStore({
    threadCreatePlan: (request) => ({
      status: "planned",
      operation_kind: "thread.create",
      thread: request.thread,
    }),
  });

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "thread_create_state_update_agent_missing");
      assert.equal(error.status, 502);
      assert.equal(error.details.rust_core_boundary, "runtime.thread_create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.startedEvents, []);
});

test("createThread rejects missing Rust-planned thread projection", () => {
  const store = fakeStore({
    threadCreatePlan: (request) => ({
      status: "planned",
      operation_kind: "thread.create",
      agent: request.agent,
    }),
  });

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "thread_create_state_update_thread_missing");
      assert.equal(error.status, 502);
      assert.equal(error.details.agent_id, "agent_uuid-agent");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.startedEvents, []);
});

test("createThread rejects mismatched Rust operation kind", () => {
  const store = fakeStore({
    threadCreatePlan: (request) => ({
      status: "planned",
      operation_kind: "agent.create",
      agent: request.agent,
      thread: request.thread,
    }),
  });

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "thread_create_state_update_operation_kind_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.expected_operation_kind, "thread.create");
      assert.equal(error.details.actual_operation_kind, "agent.create");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.startedEvents, []);
});

test("createThread rejects incomplete Rust-planned projection", () => {
  const store = fakeStore({
    threadCreatePlan: () => ({
      status: "planned",
      operation_kind: "thread.create",
      agent: {
        id: "agent_uuid-agent",
      },
      thread: {
        thread_id: "thread_uuid-agent",
      },
    }),
  });

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "thread_create_state_update_projection_incomplete");
      assert.equal(error.status, 502);
      assert.equal(error.details.thread_id, "thread_uuid-agent");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.startedEvents, []);
});

test("createThread rejects Rust thread projection agent mismatch", () => {
  const store = fakeStore({
    threadCreatePlan: (request) => ({
      ...defaultThreadCreatePlan(request),
      thread: {
        ...request.thread,
        agent_id: "agent_other",
      },
    }),
  });

  assert.throws(
    () => createThread(store, { options: { local: { cwd: "/workspace/thread" } } }, threadCreateDeps(store)),
    (error) => {
      assert.equal(error.code, "thread_create_state_update_agent_mismatch");
      assert.equal(error.status, 502);
      assert.equal(error.details.agent_id, "agent_uuid-agent");
      assert.equal(error.details.thread_agent_id, "agent_other");
      assertNoRetiredLifecycleDetailAliases(error.details);
      return true;
    },
  );

  assert.equal(store.plannerCalls.length, 1);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.startedEvents, []);
});

test("createThread starts runtime-service threads through Rust bridge-start state planning", () => {
  const store = fakeStore();

  const thread = createThread(store, {
    options: {
      runtime_profile: "runtime_service",
      runtime_session_id: "session_runtime",
      runtime_bridge_id: "bridge_runtime",
      runtime_bridge_source: "rust_core",
      local: { cwd: "/workspace/runtime" },
      model: { id: "model.local" },
    },
  }, threadCreateDeps(store));

  assert.equal(thread.thread_id, "thread_uuid-agent");
  assert.equal(thread.agent_id, "agent_uuid-agent");
  assert.equal(thread.rust_projected, true);
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].thread_id, "thread_uuid-agent");
  assert.equal(store.plannerCalls[0].runtime_profile, "runtime_service");
  assert.equal(store.plannerCalls[0].session_id, "session_runtime");
  assert.equal(store.plannerCalls[0].bridge_id, "bridge_runtime");
  assert.equal(store.plannerCalls[0].source, "rust_core");
  assert.equal(store.writes.length, 1);
  assert.equal(store.writes[0].operationKind, "thread.runtime_bridge.start");
  assert.equal(store.writes[0].agent.runtime_profile, "runtime_service");
  assert.equal(store.writes[0].agent.runtime_session_id, "session_runtime");
  assert.equal(store.writes[0].agent.runtime_bridge_id, "bridge_runtime");
  assert.equal(store.writes[0].agent.runtime_bridge_source, "rust_core");
  assert.equal(store.writes[0].agent.rust_runtime_bridge_started, true);
  assert.deepEqual(store.startedEvents, ["agent_uuid-agent"]);
  assert.equal(store.threadProjectionCalls.length, 1);
  assert.equal(store.threadProjectionCalls[0].runtime_bridge_id, "bridge_runtime");
  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.equal(store.routeCalls.length, 1);
  assert.equal(store.providerCalls.length, 1);
});

test("createThread fails closed for runtime-service threads before route planning when Rust bridge-start planner is missing", () => {
  const store = fakeStore({ runtimeBridgeThreadStartPlan: null });

  assert.throws(
    () => createThread(store, {
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: "/workspace/runtime" },
      },
    }, threadCreateDeps(store)),
    assertRuntimeBridgeThreadRustCoreRequired,
  );

  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.deepEqual(store.startedEvents, []);
  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.providerCalls, []);
});

test("createRuntimeBridgeThreadControl commits Rust-planned bridge agent and returns Rust thread projection", () => {
  const store = fakeStore();
  const surface = createRuntimeAgentRunLifecycleSurface({
    lifecycleAdmissionRunner: store.contextPolicyRunner,
  });
  const agent = store.agents.get("agent_runtime");

  const thread = surface.createRuntimeBridgeThreadControl(store, "thread_runtime", agent, {
    action: "resume",
    reason: "continue",
  });

  assert.equal(thread.thread_id, "thread_runtime");
  assert.equal(thread.agent_id, "agent_runtime");
  assert.equal(thread.rust_projected, true);
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].thread_id, "thread_runtime");
  assert.equal(store.plannerCalls[0].agent.id, "agent_runtime");
  assert.equal(store.plannerCalls[0].action, "resume");
  assert.equal(store.plannerCalls[0].reason, "continue");
  assert.equal(store.plannerCalls[0].evidence_refs.includes("runtime_bridge_thread_control_rust_owned"), true);
  assert.deepEqual(store.writes, [{
    kind: "agent",
    operationKind: "thread.runtime_bridge.control",
    agent: {
      ...agent,
      status: "active",
      runtimeBridgeStatus: "active",
      runtime_bridge_status: "active",
      updatedAt: store.writes[0]?.agent?.updatedAt,
      rust_runtime_bridge_controlled: true,
    },
  }]);
  assert.equal(store.writes[0].agent.runtime_bridge_status, "active");
  assert.equal(store.writes[0].agent.rust_runtime_bridge_controlled, true);
  assert.equal(store.threadProjectionCalls.length, 1);
  assert.equal(store.threadProjectionCalls[0].id, "agent_runtime");
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
});

test("createRuntimeBridgeThreadControl fails closed before projection or persistence when Rust bridge-control planner is missing", () => {
  const store = fakeStore({ runtimeBridgeThreadControlPlan: null });
  const surface = createRuntimeAgentRunLifecycleSurface({
    lifecycleAdmissionRunner: store.contextPolicyRunner,
  });
  const agent = store.agents.get("agent_runtime");

  assert.throws(
    () => surface.createRuntimeBridgeThreadControl(store, "thread_runtime", agent, {
      action: "resume",
      reason: "continue",
    }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_thread_control",
      operationKind: "thread.runtime_bridge.control",
    }),
  );

  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.threadProjectionCalls, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
});

test("createRuntimeBridgeTurn commits Rust-planned runtime bridge run and returns Rust turn projection", () => {
  const store = fakeStore();
  const surface = createRuntimeAgentRunLifecycleSurface({
    lifecycleAdmissionRunner: store.contextPolicyRunner,
    ...runCreateDeps(store),
  });
  const agent = store.agents.get("agent_runtime");

  const turn = surface.createRuntimeBridgeTurn(store, "thread_runtime", agent, {
    mode: "send",
    prompt: "Ship the runtime turn",
    threadMode: "retired",
    approvalMode: "retired",
  });

  assert.equal(turn.thread_id, "thread_runtime");
  assert.equal(turn.request_id, "run_uuid-run");
  assert.equal(turn.run_id, "run_uuid-run");
  assert.equal(turn.rust_projected, true);
  assert.equal(store.providerCalls.length, 1);
  assert.equal(store.routeCalls.length, 1);
  assert.equal(store.memoryCalls.length, 1);
  assert.equal(store.runBuildCalls.length, 1);
  assert.equal(store.runBuildCalls[0].agent.id, "agent_runtime");
  assert.equal(store.runBuildCalls[0].request.prompt, "Ship the runtime turn");
  assert.equal(store.plannerCalls.length, 1);
  assert.equal(store.plannerCalls[0].thread_id, "thread_runtime");
  assert.equal(store.plannerCalls[0].agent.id, "agent_runtime");
  assert.equal(store.plannerCalls[0].projection.thread_id, "thread_runtime");
  assert.equal(store.plannerCalls[0].projection.run_id, "run_uuid-run");
  assert.equal(store.plannerCalls[0].run.id, "run_uuid-run");
  assert.deepEqual(store.writes, [{
    kind: "run",
    operationKind: "turn.runtime_bridge.submit",
    run: {
      id: "run_uuid-run",
      agentId: "agent_runtime",
      status: "completed",
      mode: "send",
      objective: "Ship the runtime turn",
      createdAt: "2026-06-12T12:00:00.000Z",
      updatedAt: "2026-06-12T12:00:00.000Z",
      events: [],
      conversation: [],
      receipts: [],
      artifacts: [],
      trace: {
        usage_telemetry: {
          total_tokens: 7,
        },
      },
      usage: {
        total_tokens: 7,
      },
      usage_telemetry: {
        total_tokens: 7,
      },
      result: "ok",
      thread_mode: "agent",
      approval_mode: "suggest",
      rust_runtime_bridge_submitted: true,
    },
  }]);
  assert.equal(store.turnProjectionCalls.length, 2);
  assert.equal(store.turnProjectionCalls[0].id, "run_uuid-run");
  assert.equal(store.turnProjectionCalls[1].rust_runtime_bridge_submitted, true);
});

test("createRuntimeBridgeTurn fails closed before route, memory, or persistence when Rust bridge-turn planner is missing", () => {
  const store = fakeStore({ runtimeBridgeTurnRunStateUpdatePlan: null });
  const surface = createRuntimeAgentRunLifecycleSurface({
    lifecycleAdmissionRunner: store.contextPolicyRunner,
    ...runCreateDeps(store),
  });
  const agent = store.agents.get("agent_runtime");

  assert.throws(
    () => surface.createRuntimeBridgeTurn(store, "thread_runtime", agent, {
      mode: "send",
      prompt: "Ship the runtime turn",
    }),
    (error) => assertRuntimeBridgeThreadRustCoreRequired(error, {
      operation: "runtime_bridge_turn_submit",
      operationKind: "turn.runtime_bridge.submit",
    }),
  );

  assert.deepEqual(store.writes, []);
  assert.deepEqual(store.routeCalls, []);
  assert.deepEqual(store.memoryCalls, []);
  assert.deepEqual(store.providerCalls, []);
  assert.deepEqual(store.turnProjectionCalls, []);
});

test("agent/run lifecycle surface routes create, run creation, and thread creation to mounted boundary", async () => {
  const store = fakeStore();
  const surface = createRuntimeAgentRunLifecycleSurface({
    lifecycleAdmissionRunner: store.contextPolicyRunner,
    ...runCreateDeps(store),
    ...threadCreateDeps(store),
  });

  const agent = surface.createAgent(store, { local: { cwd: "/workspace/surface" } });
  assert.equal(agent.id, "agent_uuid-agent");
  assert.equal(agent.rust_planned, true);
  const run = surface.createRun(store, "agent_existing", { mode: "review" });
  assert.equal(run.id, "run_uuid-run");
  assert.equal(run.rust_planned, true);
  assert.equal(run.thread_mode, "agent");
  assert.equal(run.approval_mode, "suggest");
  const thread = surface.createThread(store, {
    options: { local: { cwd: "/workspace/thread" } },
  });
  assert.equal(thread.thread_id, "thread_uuid-agent");
  assert.equal(thread.agent_id, "agent_uuid-agent");
  assert.equal(thread.rust_projected, true);
  const runtimeThread = surface.createThread(store, {
    options: {
      runtime_profile: "runtime_service",
      runtime_session_id: "session_runtime",
      runtime_bridge_id: "bridge_runtime",
      runtime_bridge_source: "rust_core",
    },
  });
  assert.equal(runtimeThread.thread_id, "thread_uuid-agent");
  assert.equal(runtimeThread.agent_id, "agent_uuid-agent");
  assert.equal(runtimeThread.rust_projected, true);
  const runtimeControl = surface.createRuntimeBridgeThreadControl(
    store,
    "thread_uuid-agent",
    store.writes[3].agent,
    { reason: "continue runtime thread" },
  );
  assert.equal(runtimeControl.thread_id, "thread_uuid-agent");
  assert.equal(runtimeControl.agent_id, "agent_uuid-agent");
  assert.equal(runtimeControl.rust_projected, true);
  const runtimeTurn = surface.createRuntimeBridgeTurn(store, "thread_uuid-agent", store.writes[4].agent, {
    prompt: "ship runtime turn",
  });
  assert.equal(runtimeTurn.thread_id, "thread_uuid-agent");
  assert.equal(runtimeTurn.run_id, "run_uuid-run");
  assert.equal(runtimeTurn.rust_projected, true);

  assert.deepEqual(store.runtimeThreadCalls, []);
  assert.deepEqual(store.lifecycleAdmissionRequiredCalls, []);
  assert.equal(store.writes.length, 6);
  assert.equal(store.writes[0].operationKind, "agent.create");
  assert.equal(store.writes[1].operationKind, "run.create");
  assert.equal(store.writes[2].operationKind, "thread.create");
  assert.equal(store.writes[3].operationKind, "thread.runtime_bridge.start");
  assert.equal(store.writes[3].agent.runtime_bridge_id, "bridge_runtime");
  assert.equal(store.writes[4].operationKind, "thread.runtime_bridge.control");
  assert.equal(store.writes[4].agent.runtime_bridge_status, "active");
  assert.equal(store.writes[5].operationKind, "turn.runtime_bridge.submit");
  assert.equal(store.writes[5].run.rust_runtime_bridge_submitted, true);
  assert.deepEqual(store.startedEvents, ["agent_uuid-agent", "agent_uuid-agent"]);
  assert.equal(store.threadProjectionCalls.length, 3);
  assert.equal(store.turnProjectionCalls.length, 2);
  assert.deepEqual(store.getAgentCalls, ["agent_existing"]);
  assert.equal(store.routeCalls.length, 5);
  assert.equal(store.memoryCalls.length, 2);
});
