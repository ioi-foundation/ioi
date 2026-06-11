import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeLifecycleProjectionSurface } from "./runtime-lifecycle-projection-surface.mjs";

function lifecycleRunner(calls = []) {
  return {
    planRuntimeLifecycleProjectionRequired(request) {
      calls.push(request);
      return {
        source: "rust_runtime_lifecycle_projection_required_command",
        record: {
          status_code: 501,
          code: "runtime_lifecycle_projection_rust_core_required",
          message:
            "Runtime agent, thread, and run lifecycle projections require direct Rust daemon-core projection over Agentgres-admitted lifecycle truth.",
          details: {
            rust_core_boundary: "runtime.lifecycle_projection",
            ...request,
          },
        },
      };
    },
  };
}

test("lifecycle projection surface fails public agent/thread/run list projections through Rust core", () => {
  const calls = [];
  const surface = createRuntimeLifecycleProjectionSurface({
    lifecycleRunner: lifecycleRunner(calls),
    workspaceRoot: "/workspace/project",
  });

  assert.throws(
    () => surface.listAgents({}),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "runtime_lifecycle_projection_rust_core_required");
      assert.equal(error.details.projection_kind, "agents");
      assert.equal(error.details.workspace_root, "/workspace/project");
      assert.equal(error.details.source, "runtime.lifecycle_projection_surface");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_lifecycle_js_projection_retired",
        "rust_daemon_core_runtime_lifecycle_projection_required",
        "agentgres_runtime_lifecycle_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "workspaceRoot"), false);
      return true;
    },
  );

  assert.throws(() => surface.listThreads({}));
  assert.throws(() => surface.listRuns({}, null));
  assert.deepEqual(calls.map((call) => call.projection_kind), [
    "agents",
    "threads",
    "runs",
  ]);
});

test("lifecycle projection surface keeps route identifiers in canonical snake_case details", () => {
  const calls = [];
  const surface = createRuntimeLifecycleProjectionSurface({
    lifecycleRunner: lifecycleRunner(calls),
    workspaceRoot: "/workspace/project",
  });

  assert.throws(
    () => surface.getAgent({}, "agent_123"),
    (error) => {
      assert.equal(error.details.projection_kind, "agent");
      assert.equal(error.details.agent_id, "agent_123");
      assert.equal(Object.hasOwn(error.details, "agentId"), false);
      return true;
    },
  );
  assert.throws(
    () => surface.getThread({}, "thread_123"),
    (error) => {
      assert.equal(error.details.projection_kind, "thread");
      assert.equal(error.details.thread_id, "thread_123");
      assert.equal(Object.hasOwn(error.details, "threadId"), false);
      return true;
    },
  );
  assert.throws(
    () => surface.getRun({}, "run_123"),
    (error) => {
      assert.equal(error.details.projection_kind, "run");
      assert.equal(error.details.run_id, "run_123");
      assert.equal(Object.hasOwn(error.details, "runId"), false);
      return true;
    },
  );
  assert.throws(
    () => surface.listRuns({}, "agent_123"),
    (error) => {
      assert.equal(error.details.projection_kind, "agent_runs");
      assert.equal(error.details.agent_id, "agent_123");
      assert.equal(
        error.details.operation_kind,
        "runtime.lifecycle_projection.agent_runs",
      );
      return true;
    },
  );

  assert.deepEqual(calls.map((call) => call.projection_kind), [
    "agent",
    "thread",
    "run",
    "agent_runs",
  ]);
});
