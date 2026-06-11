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
  return new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
    runtimeBridge: runtimeBridgeThatMustNotDispatch(calls),
  });
}

test("runtime thread-control integration proof rejects retired model-route seeding", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-route-required-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    assert.throws(
      () =>
        store.modelMounting.upsertRoute({
          id: "route.local-first",
          role: "chat",
          fallback: ["endpoint.runtime-control-test"],
          provider_eligibility: ["local_folder"],
        }),
      (error) => {
        assert.equal(error.code, "model_mount_route_control_rust_core_required");
        assert.equal(error.details.rust_core_boundary, "model_mount.route_control");
        assert.equal(error.details.operation_kind, "model_mount.route.write");
        assert.equal(error.details.route_id, "route.local-first");
        return true;
      },
    );
    assert.equal(
      calls.filter((call) => call.operation === "plan_model_mount_route_control_required").length,
      1,
    );
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-service thread creation fails before JS runtime bridge dispatch", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-create-required-"));
  const calls = [];
  const store = runtimeControlStore(stateDir, calls);
  try {
    await assert.rejects(
      () =>
        store.agentRunLifecycleSurface.createThread(store, {
          runtime_profile: "runtime_service",
          options: {
            runtime_profile: "runtime_service",
            local: { cwd: stateDir },
          },
        }),
      (error) => {
        assert.equal(error.code, "runtime_bridge_thread_rust_core_required");
        assert.equal(error.details.rust_core_boundary, "runtime.bridge_thread");
        assert.equal(error.details.operation, "runtime_bridge_thread_start");
        assert.equal(error.details.operation_kind, "thread.runtime_bridge.start");
        assert.equal(error.details.runtime_profile, "runtime_service");
        assert.equal(Object.hasOwn(error.details, "runtimeProfile"), false);
        assert.equal(Object.hasOwn(error.details, "operationKind"), false);
        return true;
      },
    );
    assert.equal(calls.some((call) => call.operation === "start_thread"), false);
    assert.equal(store.agents.size, 0);
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
