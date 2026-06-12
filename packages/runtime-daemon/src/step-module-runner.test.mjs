import assert from "node:assert/strict";
import test from "node:test";

import {
  RustWorkloadStepModuleRunner,
  StepModuleRunnerError,
  createStepModuleRunnerFromEnv,
} from "./step-module-runner.mjs";

test("default StepModuleRunner is Rust workload live and fails closed without direct invoker", () => {
  const runner = createStepModuleRunnerFromEnv({});
  assert.ok(runner instanceof RustWorkloadStepModuleRunner);
  assert.equal(runner.backend, "rust_workload_live");
  assert.equal(runner.blocksDaemonJsExecution, true);
  assert.throws(
    () =>
      runner.runCodingTool({
        toolId: "workspace.status",
        input: {},
      }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "rust_workload_direct_invoker_unconfigured",
  );
});

test("retired StepModule backend selection env fails closed", () => {
  for (const backend of ["daemon_js", "rust_workload_shadow", "rust_workload_gated", "rust_workload_live"]) {
    assert.throws(
      () => createStepModuleRunnerFromEnv({ IOI_STEP_MODULE_BACKEND: backend }),
      (error) =>
        error instanceof StepModuleRunnerError &&
        error.code === "step_module_backend_selection_retired",
    );
  }
});

test("retired StepModule backend constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ backend: "rust_workload_live" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_backend_selection_retired",
  );
});

test("retired StepModule command args env fails closed", () => {
  assert.throws(
    () => createStepModuleRunnerFromEnv({ IOI_STEP_MODULE_COMMAND_ARGS: "--legacy-flag value" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_args_retired",
  );
});

test("retired StepModule command env fails closed", () => {
  assert.throws(
    () => createStepModuleRunnerFromEnv({ IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_selection_retired",
  );
});

test("retired daemon-core command env fails closed for StepModule runner", () => {
  assert.throws(
    () => createStepModuleRunnerFromEnv({ IOI_RUNTIME_DAEMON_CORE_COMMAND: "retired-daemon-core" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_selection_retired",
  );
});

test("retired StepModule command args constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ args: ["--legacy-flag", "value"] }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_args_retired",
  );
});

test("retired daemon-core command args env fails closed for StepModule runner", () => {
  assert.throws(
    () => createStepModuleRunnerFromEnv({ IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_args_retired",
  );
});

test("retired StepModule command constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ command: "retired-daemon-core" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_selection_retired",
  );
});

test("rust workload live runner produces workload invocation with direct daemon-core result", () => {
  const runner = new RustWorkloadStepModuleRunner({
    daemonCoreInvoker(request) {
      assert.equal(request.tool_id, "workspace.status");
      assert.equal(Object.hasOwn(request, "invocation"), false);
      return {
        source: "direct_daemon_core_api",
        invocation: rustInvocation(request.tool_id),
        result: {
          schema_version: "ioi.step_module_result.v1",
          invocation_id: "invocation://direct",
          status: "success",
          execution_result_ref: "result://direct",
          normalized_observation_ref: "observation://direct",
          receipt_refs: ["receipt://direct"],
          artifact_refs: [],
          payload_refs: [],
          agentgres_operation_refs: [],
          state_root_after: null,
          resulting_head: null,
          workflow_projection: {
            workflow_graph_id: "workflow:test",
            workflow_node_id: "node:test",
            component_kind: "CodingToolNode",
            status: "live",
            attempt_id: "attempt://direct",
            evidence_refs: [],
            receipt_refs: ["receipt://direct"],
          },
          next: {
            model_reentry_required: false,
            verifier_required: false,
          },
        },
      };
    },
  });
  const projection = runner.runCodingTool({
    toolId: "workspace.status",
    input: {},
    context: {
      run_id: "run:test",
      task_id: "task:test",
      workflow_graph_id: "workflow:test",
      workflow_node_id: "node:test",
    },
  });

  assert.equal(projection.backend, "rust_workload_live");
  assert.equal(projection.invocation.module_ref.kind, "workload_job");
  assert.equal(projection.invocation.execution.backend, "workload_grpc");
  assert.equal(projection.result.workflow_projection.status, "live");
  assert.equal(projection.blocking, true);
});

test("rust workload direct daemon-core invoker sends canonical coding-tool request", () => {
  const calls = [];
  const runner = new RustWorkloadStepModuleRunner({
    daemonCoreInvoker(request) {
      calls.push({ request });
      return {
        ok: true,
        result: {
          source: "rust_workload_command",
          invocation: rustInvocation(request.tool_id),
          receipt_binding: {
            schema_version: "ioi.step_module_receipt_binding.v1",
            binding_hash: "sha256:test",
          },
          result: null,
        },
      };
    },
  });
  const projection = runner.runCodingTool({
    toolId: "workspace.status",
    input: { includeIgnored: true },
    context: {
      workspaceRoot: "/tmp/retired-workspace",
      workspace_root: "/tmp/workspace",
      workflow_node_id: "node:test",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].request.schema_version, "ioi.runtime.daemon_core.command.v1");
  assert.equal(calls[0].request.operation, "run_coding_tool_step_module");
  assert.equal(
    calls[0].request.request_schema_version,
    "ioi.runtime.coding-tool-step-module-request.v1",
  );
  assert.equal(calls[0].request.tool_id, "workspace.status");
  assert.equal(calls[0].request.workspace_root, "/tmp/workspace");
  assert.notEqual(calls[0].request.workspace_root, "/tmp/retired-workspace");
  assert.equal(calls[0].request.workflow_node_id, "node:test");
  assert.equal(Object.hasOwn(calls[0].request, "invocation"), false);
  assert.equal(projection.invocation.module_ref.kind, "workload_job");
  assert.equal(projection.invocation.execution.backend, "workload_grpc");
  assert.equal(
    projection.bridge_result.receipt_binding.schema_version,
    "ioi.step_module_receipt_binding.v1",
  );
  assert.equal(projection.result, null);
});

function rustInvocation(toolId = "workspace.status") {
  return {
    schema_version: "ioi.step_module_invocation.v1",
    invocation_id: "invocation://rust-daemon-core/test",
    module_ref: {
      kind: "workload_job",
      id: toolId,
      version: "ioi.runtime.coding-tool-pack.v1",
    },
    execution: {
      backend: "workload_grpc",
    },
  };
}
