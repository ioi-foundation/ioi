import assert from "node:assert/strict";
import test from "node:test";

import { codingToolContracts } from "./coding-tools.mjs";
import {
  RustWorkloadStepModuleRunner,
  StepModuleRunnerError,
  createStepModuleRunnerFromEnv,
} from "./step-module-runner.mjs";

const workspaceStatusContract = codingToolContracts().find(
  (contract) => contract.stable_tool_id === "workspace.status",
);

test("default StepModuleRunner is Rust workload live and fails closed without command", () => {
  const runner = createStepModuleRunnerFromEnv({});
  assert.ok(runner instanceof RustWorkloadStepModuleRunner);
  assert.equal(runner.backend, "rust_workload_live");
  assert.equal(runner.blocksDaemonJsExecution, true);
  assert.throws(
    () =>
      runner.runCodingTool({
        contract: workspaceStatusContract,
        toolId: "workspace.status",
        input: {},
        result: {},
      }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "rust_workload_bridge_unconfigured",
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

test("retired StepModule command args constructor option fails closed", () => {
  assert.throws(
    () => new RustWorkloadStepModuleRunner({ args: ["--legacy-flag", "value"] }),
    (error) =>
      error instanceof StepModuleRunnerError &&
      error.code === "step_module_command_args_retired",
  );
});

test("rust workload live runner produces workload invocation with mock bridge result", () => {
  const runner = new RustWorkloadStepModuleRunner({
    mockResult: {
      source: "rust_workload_mock",
      result: {
        schema_version: "ioi.step_module_result.v1",
        invocation_id: "invocation://mock",
        status: "success",
        execution_result_ref: "result://mock",
        normalized_observation_ref: "observation://mock",
        receipt_refs: ["receipt://mock"],
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
          attempt_id: "attempt://mock",
          evidence_refs: [],
          receipt_refs: ["receipt://mock"],
        },
        next: {
          model_reentry_required: false,
          verifier_required: false,
        },
      },
    },
  });
  const projection = runner.runCodingTool({
    contract: workspaceStatusContract,
    toolId: "workspace.status",
    input: {},
    result: {},
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

test("rust workload command bridge sends StepModuleInvocation request", () => {
  const calls = [];
  const runner = new RustWorkloadStepModuleRunner({
    command: "mock-step-module-bridge",
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, request: JSON.parse(options.input) });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_workload_command",
            receipt_binding: {
              schema_version: "ioi.step_module_receipt_binding.v1",
              binding_hash: "sha256:test",
            },
            result: null,
          },
        }),
        stderr: "",
      };
    },
  });
  const projection = runner.runCodingTool({
    contract: workspaceStatusContract,
    toolId: "workspace.status",
    input: { includeIgnored: true },
    result: {},
    context: {
      workspaceRoot: "/tmp/retired-workspace",
      workspace_root: "/tmp/workspace",
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-step-module-bridge");
  assert.deepEqual(calls[0].args, []);
  assert.equal(calls[0].request.operation, "run_coding_tool_step_module");
  assert.equal(calls[0].request.workspace_root, "/tmp/workspace");
  assert.notEqual(calls[0].request.workspace_root, "/tmp/retired-workspace");
  assert.equal(calls[0].request.invocation.schema_version, "ioi.step_module_invocation.v1");
  assert.equal(calls[0].request.invocation.execution.backend, "workload_grpc");
  assert.equal(
    projection.bridge_result.receipt_binding.schema_version,
    "ioi.step_module_receipt_binding.v1",
  );
});
