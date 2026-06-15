import assert from "node:assert/strict";
import test from "node:test";

import {
  RustWorkloadStepModuleRunner,
  StepModuleRunnerError,
  createStepModuleRunnerFromEnv,
} from "./step-module-runner.mjs";

test("default StepModuleRunner is Rust workload live and fails closed without direct workload API", () => {
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
      error.code === "rust_workload_api_unconfigured",
  );
});

test("retired StepModule backend constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ backend: "rust_workload_live" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_backend_selection_retired",
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

test("retired StepModule command constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ command: "retired-daemon-core" }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_selection_retired",
  );
});

test("retired StepModule daemon-core invoker option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ daemonCoreInvoker() {} }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_daemon_core_invoker_retired",
  );
});

test("StepModule runner env reads only workload transport handles", () => {
  const runner = createStepModuleRunnerFromEnv({
    IOI_WORKLOAD_GRPC_ADDR: "127.0.0.1:9000",
    IOI_SHMEM_ID: "shmem-step-module",
  });

  assert.equal(runner.grpcAddr, "127.0.0.1:9000");
  assert.equal(runner.shmemId, "shmem-step-module");
});

test("rust workload live runner produces workload invocation with direct daemon-core workload API result", () => {
  const runner = new RustWorkloadStepModuleRunner({
    daemonCoreWorkloadApi: {
      runCodingToolStepModule(request) {
        assert.equal(request.tool_id, "workspace.status");
        assert.equal(Object.hasOwn(request, "invocation"), false);
        assert.equal(Object.hasOwn(request, "operation"), false);
        assert.equal(Object.hasOwn(request, "backend"), false);
        return {
          source: "direct_daemon_core_workload_api",
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

test("rust workload direct daemon-core workload API sends canonical coding-tool request", () => {
  const calls = [];
  const runner = new RustWorkloadStepModuleRunner({
    daemonCoreWorkloadApi: {
      runCodingToolStepModule(request) {
        calls.push({ request });
        return {
          ok: true,
          result: {
            source: "rust_workload_api",
            invocation: rustInvocation(request.tool_id),
            receipt_binding: {
              schema_version: "ioi.step_module_receipt_binding.v1",
              binding_hash: "sha256:test",
            },
            result: null,
          },
        };
      },
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
  assert.equal(
    calls[0].request.schema_version,
    "ioi.runtime.coding-tool-step-module-request.v1",
  );
  assert.equal(Object.hasOwn(calls[0].request, "operation"), false);
  assert.equal(Object.hasOwn(calls[0].request, "backend"), false);
  assert.equal(calls[0].request.tool_id, "workspace.status");
  assert.equal(calls[0].request.workspace_root, "/tmp/workspace");
  assert.notEqual(calls[0].request.workspace_root, "/tmp/retired-workspace");
  assert.equal(calls[0].request.workflow_node_id, "node:test");
  assert.equal(Object.hasOwn(calls[0].request, "invocation"), false);
  assert.equal(projection.invocation.module_ref.kind, "workload_job");
  assert.equal(projection.invocation.execution.backend, "workload_grpc");
  assert.equal(
    projection.workload_result.receipt_binding.schema_version,
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
