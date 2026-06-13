import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountAdmissionRunnerForTest(calls) {
  return {
    planReadProjection(request) {
      calls.push({ operation: "plan_model_mount_read_projection", input: request });
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
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
      calls.push({ operation: "plan_model_mount_route_control_required", input: request });
      return {
        source: "rust_model_mount_route_control_required_command",
        backend: "rust_model_mount_route_control_required",
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
      calls.push({ operation: "plan_model_mount_route_control", input: request });
      const record = {
        id: request.route_id ?? request.body?.id ?? "route.local-first",
        role: request.body?.role ?? "chat",
        fallback: request.body?.fallback ?? [],
        providerEligibility: request.body?.provider_eligibility ?? [],
        receiptRefs: ["receipt://runtime-thread-control/route"],
      };
      return {
        source: "rust_model_mount_route_control_command",
        backend: "rust_model_mount_route_control",
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

function runtimeBridgeThatMustNotDispatch(calls) {
  return {
    bridgeId: "retired-runtime-control-test-bridge",
    async startThread(input) {
      calls.push({ operation: "start_thread", input });
      throw new Error("runtime-thread-control test must fail before JS bridge start dispatch.");
    },
    async controlThread(input) {
      calls.push({ operation: "control_thread", input });
      throw new Error("runtime-thread-control test must fail before JS bridge control dispatch.");
    },
    async submitTurn(input) {
      calls.push({ operation: "submit_turn", input });
      throw new Error("runtime-thread-control test must fail before JS bridge turn dispatch.");
    },
  };
}

function runtimeControlStore(stateDir, calls) {
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    daemonCoreInvoker(request) {
      calls.push({ operation: request.operation, input: request });
      if (request.operation === "commit_runtime_agent_state") {
        const input = request.request ?? {};
        const agentId = input.agent_id ?? input.agent?.id ?? "agent_runtime";
        return {
          source: "rust_agentgres_runtime_agent_state_commit_command",
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
      }
      if (request.operation === "commit_runtime_model_mount_record_state") {
        const input = request.request ?? {};
        return {
          source: "rust_agentgres_runtime_model_mount_record_state_commit_command",
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
      }
      if (request.operation !== "plan_runtime_bridge_thread_start_agent_state_update") {
        throw new Error(`unexpected daemon-core operation ${request.operation}`);
      }
      const input = request.request ?? {};
      return {
        source: "rust_runtime_bridge_thread_start_agent_state_update_command",
        backend: "rust_policy",
        status: "planned",
        operation_kind: "thread.runtime_bridge.start",
        updated_at: input.updated_at,
        bridge_start: {
          runtime_profile: input.runtime_profile,
          session_id: input.session_id,
          bridge_id: input.bridge_id,
          status: input.status,
          source: input.source,
          updated_at: input.updated_at,
        },
        agent: {
          ...input.agent,
          runtime_profile: input.runtime_profile,
          runtime_session_id: input.session_id,
          runtime_bridge_id: input.bridge_id,
          runtime_bridge_status: input.status,
          runtime_bridge_source: input.source,
          fixtureProfile: null,
          updatedAt: input.updated_at,
        },
      };
    },
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
    runtimeBridge: runtimeBridgeThatMustNotDispatch(calls),
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
      calls.filter((call) => call.operation === "plan_model_mount_route_control").length,
      1,
    );
    assert.equal(
      calls.filter((call) => call.operation === "commit_runtime_model_mount_record_state").length,
      1,
    );
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
