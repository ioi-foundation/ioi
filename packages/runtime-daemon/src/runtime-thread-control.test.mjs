import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountCoreForTest(calls) {
  return {
    planReadProjection(request) {
      calls.push({ method: "planModelMountReadProjection", input: request });
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection: { source: "agentgres_model_mounting_projection" },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
    planRouteControlRequired(request) {
      calls.push({ method: "planModelMountRouteControlRequired", input: request });
      return {
        source: "rust_daemon_core.model_mount.route_control_required",
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_route_control_rust_core_required",
        message: "Model mount route control requires direct Rust daemon-core admission.",
        details: {
          rust_core_boundary: "model_mount.route_control",
          operation: request.operation,
          operation_kind: request.operation_kind,
          route_id: request.details?.route_id ?? null,
          evidence_refs: request.evidence_refs ?? [],
        },
      };
    },
    planRouteControl(request) {
      calls.push({ method: "planModelMountRouteControl", input: request });
      const record = {
        id: request.route_id ?? request.body?.id ?? "route.local-first",
        role: request.body?.role ?? "chat",
        fallback: request.body?.fallback ?? [],
        providerEligibility: request.body?.provider_eligibility ?? [],
        receiptRefs: ["receipt://runtime-thread-control/route"],
      };
      return {
        source: "rust_daemon_core.model_mount.route_control",
        plan: {
          schema_version: "ioi.model_mount.route_control_plan.v1",
          object: "ioi.model_mount_route_control_plan",
          status: "planned",
          rust_core_boundary: "model_mount.route_control",
          operation_kind: request.operation_kind,
          source: request.source,
          record_dir: "model-routes",
          record_id: record.id,
          record,
          receipt_refs: ["receipt://runtime-thread-control/route"],
          evidence_refs: ["model_mount_route_control_rust_owned"],
          control_hash: "sha256:runtime-thread-control-route",
        },
        record_dir: "model-routes",
        record_id: record.id,
        record,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.route_control",
        receipt_refs: ["receipt://runtime-thread-control/route"],
        evidence_refs: ["model_mount_route_control_rust_owned"],
        control_hash: "sha256:runtime-thread-control-route",
      };
    },
  };
}

function runtimeControlStore(stateDir, calls) {
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    daemonCoreAgentgresApi: {
      commitRuntimeAgentState(request) {
        const input = request.request ?? {};
        calls.push({ method: "commitRuntimeAgentState", input });
        const agentId = input.agent_id ?? input.agent?.id ?? "agent_runtime";
        return {
          source: "direct_agentgres_api",
          backend: "runtime-agentgres",
          record: {
            schema_version: "ioi.runtime_agent_state_commit.v1",
            agent_id: agentId,
            operation_kind: input.operation_kind,
            storage_backend_ref: input.storage_backend_ref,
            record: {
              object_ref: `agentgres://runtime-state/agents/${agentId}`,
              content_hash: `sha256:${agentId}-content`,
              payload_refs: [`payload://runtime/agents/${agentId}`],
              receipt_refs: [`receipt_agent_state_${agentId}`],
              admission: {
                admission_hash: `sha256:${agentId}-admission`,
              },
            },
            commit_hash: `sha256:${agentId}-commit`,
          },
          agent_id: agentId,
          object_ref: `agentgres://runtime-state/agents/${agentId}`,
          content_hash: `sha256:${agentId}-content`,
          admission_hash: `sha256:${agentId}-admission`,
          commit_hash: `sha256:${agentId}-commit`,
          written_record: {
            record_path: `agents/${agentId}.json`,
          },
          evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
        };
      },
      commitRuntimeModelMountRecordState(request) {
        const input = request.request ?? {};
        calls.push({ method: "commitRuntimeModelMountRecordState", input });
        return {
          source: "direct_agentgres_api",
          backend: "runtime-agentgres",
          record: {
            schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
            record_dir: input.record_dir,
            record_id: input.record_id,
            operation_kind: input.operation_kind,
            storage_backend_ref: input.storage_backend_ref,
            record: {
              object_ref: `agentgres://model-mounting/${input.record_dir}/${input.record_id}`,
              content_hash: `sha256:${input.record_id}-content`,
              payload_refs: [`payload://model-mounting/${input.record_dir}/${input.record_id}`],
              receipt_refs: input.receipt_refs,
              admission: {
                admission_hash: `sha256:${input.record_id}-admission`,
              },
            },
            commit_hash: `sha256:${input.record_id}-commit`,
          },
          record_id: input.record_id,
          object_ref: `agentgres://model-mounting/${input.record_dir}/${input.record_id}`,
          content_hash: `sha256:${input.record_id}-content`,
          admission_hash: `sha256:${input.record_id}-admission`,
          commit_hash: `sha256:${input.record_id}-commit`,
          written_record: input.record,
          evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
        };
      },
      projectRuntimeThreadEventReplay(request) {
        const input = request.request ?? {};
        calls.push({ method: "projectRuntimeThreadEventReplay", input });
        return {
          source: "direct_agentgres_api",
          backend: "runtime-agentgres",
          projected: true,
          events: [
            {
              event_id: "event_replay_1",
              event_stream_id: input.event_stream_id,
              seq: input.latest_seq ?? 0,
              agentgres_operation_ref:
                "agentgres://runtime-events/thread_1_events/operations/event_replay_1",
              receipt_refs: ["receipt_runtime_replay"],
            },
          ],
          event_count: 1,
          replay_hash: "sha256:runtime-thread-replay",
        };
      },
    },
    daemonCoreMcpApi: {
      planMcpManagerCatalogProjection(request) {
        calls.push({ method: "planMcpManagerCatalogProjection", input: request });
        return {
          source: "direct_mcp_api",
          backend: "rust_policy",
          status: "projected",
          server_count: 0,
          tool_count: 0,
          resource_count: 0,
          prompt_count: 0,
          enabled_tool_count: 0,
          servers: [],
          tools: [],
          resources: [],
          prompts: [],
          enabled_tools: [],
        };
      },
    },
    daemonCoreThreadLifecycleApi: {
      planRuntimeBridgeThreadStartAgentStateUpdate(request) {
        calls.push({ method: "planRuntimeBridgeThreadStartAgentStateUpdate", input: request });
        return {
          source: "direct_thread_lifecycle_api",
          backend: "rust_policy",
          status: "planned",
          operation_kind: "thread.runtime_bridge.start",
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
            runtime_profile: request.runtime_profile,
            runtime_session_id: request.session_id,
            runtime_bridge_id: request.bridge_id,
            runtime_bridge_status: request.status,
            runtime_bridge_source: request.source,
            fixtureProfile: null,
            updatedAt: request.updated_at,
          },
        };
      },
    },
    modelMountCore: modelMountCoreForTest(calls),
  });
  store.resolveModelRoute = (options = {}, context = {}) => {
    calls.push({ operation: "resolve_model_route", input: { options, context } });
    return {
      selectedModel: options.model?.id ?? "model.runtime-test",
      requestedModelId: options.model?.id ?? "auto",
      routeId: options.model?.route_id ?? "route.local-first",
      endpointId: "endpoint.runtime-control-test",
      providerId: "provider.local",
      receiptId: "receipt_model_route_runtime_control",
      decision: {
        route_id: options.model?.route_id ?? "route.local-first",
        selected_model: options.model?.id ?? "model.runtime-test",
        evidence_refs: context.evidenceRefs ?? [],
      },
    };
  };
  store.ensureThreadStartedEvent = (agent) => {
    calls.push({ operation: "ensure_thread_started_event", input: { agent_id: agent.id } });
  };
  store.threadForAgent = (agent) => ({
    thread_id: agent.id.replace(/^agent_/, "thread_"),
    agent_id: agent.id,
    runtime_profile: agent.runtime_profile ?? "fixture",
    runtime_bridge_id: agent.runtime_bridge_id ?? null,
    runtime_bridge_source: agent.runtime_bridge_source ?? null,
  });
  return store;
}

test("runtime thread-control integration proof seeds model routes through Rust route control", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-route-required-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    const result = store.modelMounting.upsertRoute({
      id: "route.local-first",
      role: "chat",
      fallback: ["endpoint.runtime-control-test"],
      provider_eligibility: ["local_folder"],
    });

    assert.equal(result.status, "committed");
    assert.equal(result.operation_kind, "model_mount.route.write");
    assert.equal(result.route.id, "route.local-first");
    assert.equal(result.rust_core_boundary, "model_mount.route_control");
    assert.equal(
      calls.filter((call) => call.method === "planModelMountRouteControl").length,
      1,
    );
    assert.equal(
      calls.filter((call) => call.method === "commitRuntimeModelMountRecordState").length,
      1,
    );
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime thread-event replay sends state-dir request without JS event candidates", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-event-replay-state-dir-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    store.registerRuntimeEvent({
      event_stream_id: "thread_1:events",
      event_id: "event_head_7",
      idempotency_key: "event_head_7",
      event_kind: "turn.completed",
      seq: 7,
    });

    const replay = store.projectRuntimeThreadEventReplayForThread(store, {
      replay_kind: "stream",
      event_stream_id: "thread_1:events",
      cursor: { since_seq: 6 },
    });
    const call = calls.find((candidate) => candidate.method === "projectRuntimeThreadEventReplay");

    assert.equal(replay.events[0].event_id, "event_replay_1");
    assert.equal(call.input.state_dir, stateDir);
    assert.equal(call.input.latest_seq, 7);
    assert.equal(call.input.cursor.since_seq, 6);
    assert.equal(Object.hasOwn(call.input, "events"), false);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-service thread creation uses Rust bridge-start planning before JS bridge dispatch", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-create-required-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    const thread = store.agentRunLifecycleSurface.createThread(store, {
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        runtime_session_id: "session_runtime",
        runtime_bridge_id: "bridge_runtime",
        runtime_bridge_source: "rust_core",
        local: { cwd: stateDir },
      },
    });

    assert.equal(thread.runtime_profile, "runtime_service");
    assert.equal(thread.runtime_bridge_id, "bridge_runtime");
    assert.equal(thread.runtime_bridge_source, "rust_core");
    assert.equal(calls.some((call) => call.operation === "start_thread"), false);
    assert.equal(store.agents.size, 1);
    assert.equal(store.runs.size, 0);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime thread-control compatibility store wrappers stay retired", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-wrapper-retired-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    assert.equal(typeof store.createAgent, "undefined");
    assert.equal(typeof store.createThread, "undefined");
    assert.equal(typeof store.createRun, "undefined");
    assert.equal(typeof store.resumeThread, "undefined");
    assert.equal(typeof store.createTurn, "undefined");
    assert.equal(typeof store.interruptTurn, "undefined");
    assert.equal(typeof store.steerTurn, "undefined");
    assert.equal(typeof store.spawnSubagent, "undefined");
    assert.equal(typeof store.resumeSubagent, "undefined");
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
