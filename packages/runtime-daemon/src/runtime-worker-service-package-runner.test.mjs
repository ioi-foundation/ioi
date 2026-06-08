import assert from "node:assert/strict";
import test from "node:test";

import {
  RUST_WORKER_SERVICE_PACKAGE_BACKEND,
  RustWorkerServicePackageRunner,
  WORKER_SERVICE_PACKAGE_COMMAND_ARGS_ENV,
  WORKER_SERVICE_PACKAGE_COMMAND_ENV,
  WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION,
  WorkerServicePackageRunnerError,
  createWorkerServicePackageRunnerFromEnv,
} from "./runtime-worker-service-package-runner.mjs";

function packageInvocationRequest() {
  return {
    schema_version: "ioi.worker_service_package_invocation.v1",
    package_kind: "worker_package",
    package_ref: "worker://runtime-auditor",
    manifest_ref: "worker://runtime-auditor@1",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://worker-package/daemon-runner",
      run_id: "run:worker-package",
      task_id: "task:worker-package",
      thread_id: "thread:worker-package",
      workflow_graph_id: "workflow.worker-package",
      workflow_node_id: "node.worker-package",
      module_ref: {
        kind: "workload_job",
        id: "worker://runtime-auditor",
        version: "1",
        manifest_ref: "worker://runtime-auditor@1",
      },
      actor: {
        actor_id: "runtime:hypervisor-daemon",
        runtime_node_ref: "node://local",
      },
      authority: {
        authority_grant_refs: ["grant://wallet/worker-package"],
        policy_hash: "sha256:worker-policy",
        primitive_capabilities: ["prim:worker.invoke"],
        authority_scopes: ["scope:repo.read"],
        approval_ref: "approval://worker-package",
      },
      input: {
        input_hash: "sha256:worker-input",
        expected_schema_ref: "schema://worker-package/input",
        context_refs: ["agentgres://project/hypervisor"],
        artifact_refs: [],
        payload_refs: ["payload://worker-package/input"],
        state_root_before: "sha256:package-before",
        projection_watermark: "agentgres:worker-package:0",
      },
      custody: {
        privacy_profile: "internal",
        plaintext_policy: {
          node_plaintext_allowed: true,
          declassification_required: false,
        },
      },
      execution: {
        backend: "workload_grpc",
        idempotency_key: "idem:worker-package-daemon-runner",
        deadline_ms: 300000,
        resource_lease_ref: "lease://worker-package",
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: "invocation://worker-package/daemon-runner",
      status: "success",
      execution_result_ref: "result://worker-package/daemon-runner",
      normalized_observation_ref: "observation://worker-package/daemon-runner",
      receipt_refs: ["receipt://worker-package/daemon-runner"],
      artifact_refs: ["artifact://worker-package/report"],
      payload_refs: ["payload://worker-package/output"],
      agentgres_operation_refs: ["agentgres://worker-service-package/operations/daemon-runner"],
      state_root_after: "sha256:package-after",
      resulting_head: "agentgres://worker-service-package/head/daemon-runner",
      workflow_projection: {
        workflow_graph_id: "workflow.worker-package",
        workflow_node_id: "node.worker-package",
        component_kind: "WorkerPackageNode",
        status: "live",
        attempt_id: "attempt://worker-package/daemon-runner",
        evidence_refs: ["artifact://worker-package/report"],
        receipt_refs: ["receipt://worker-package/daemon-runner"],
      },
    },
  };
}

test("worker/service package runner sends invocation admission bridge request", () => {
  const calls = [];
  const runner = new RustWorkerServicePackageRunner({
    command: "mock-worker-service-package-bridge",
    args: ["--json"],
    spawnSyncImpl(command, args, options) {
      const bridgeRequest = JSON.parse(options.input);
      calls.push({ command, args, bridgeRequest });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_worker_service_package_invocation_command",
            backend: RUST_WORKER_SERVICE_PACKAGE_BACKEND,
            record: {
              package_kind: bridgeRequest.request.package_kind,
              package_ref: bridgeRequest.request.package_ref,
              manifest_ref: bridgeRequest.request.manifest_ref,
              invocation_id: bridgeRequest.request.invocation.invocation_id,
              authority_grant_refs:
                bridgeRequest.request.invocation.authority.authority_grant_refs,
              receipt_refs: bridgeRequest.request.result.receipt_refs,
              artifact_refs: bridgeRequest.request.result.artifact_refs,
              payload_refs: bridgeRequest.request.result.payload_refs,
            },
            router_admission: {
              backend: "workload_grpc",
              admission_ref: "admission://worker-package",
            },
            receipt_binding: {
              binding_hash: "sha256:worker-package-binding",
            },
            accepted_receipt_append: {
              receipt_ref: "receipt://worker-package/daemon-runner",
            },
            agentgres_admission: {
              operation_ref: "agentgres://worker-service-package/operations/daemon-runner",
            },
            projection_record: {
              workflow_node_id: "node.worker-package",
              status: "live",
            },
            receipt_refs: bridgeRequest.request.result.receipt_refs,
            artifact_refs: bridgeRequest.request.result.artifact_refs,
            payload_refs: bridgeRequest.request.result.payload_refs,
            authority_grant_refs:
              bridgeRequest.request.invocation.authority.authority_grant_refs,
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitInvocation(packageInvocationRequest());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-worker-service-package-bridge");
  assert.deepEqual(calls[0].args, ["--json"]);
  assert.equal(calls[0].bridgeRequest.schema_version, WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].bridgeRequest.operation, "admit_worker_service_package_invocation");
  assert.equal(calls[0].bridgeRequest.backend, RUST_WORKER_SERVICE_PACKAGE_BACKEND);
  assert.equal(calls[0].bridgeRequest.request.package_ref, "worker://runtime-auditor");
  assert.equal(result.source, "rust_worker_service_package_invocation_command");
  assert.equal(result.backend, RUST_WORKER_SERVICE_PACKAGE_BACKEND);
  assert.equal(result.package_ref, "worker://runtime-auditor");
  assert.equal(result.invocation_id, "invocation://worker-package/daemon-runner");
  assert.equal(result.router_admission.backend, "workload_grpc");
  assert.equal(result.accepted_receipt_append.receipt_ref, "receipt://worker-package/daemon-runner");
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/worker-package"]);
  assert.deepEqual(result.receipt_refs, ["receipt://worker-package/daemon-runner"]);
  assert.deepEqual(result.artifact_refs, ["artifact://worker-package/report"]);
  assert.deepEqual(result.payload_refs, ["payload://worker-package/output"]);
});

test("worker/service package runner env uses daemon-core command boundary", () => {
  const runner = createWorkerServicePackageRunnerFromEnv({
    [WORKER_SERVICE_PACKAGE_COMMAND_ENV]: "ioi-runtime-daemon-core",
    [WORKER_SERVICE_PACKAGE_COMMAND_ARGS_ENV]: "--json",
    IOI_WORKER_SERVICE_PACKAGE_COMMAND: "retired-worker-service-package-bridge",
    IOI_WORKER_SERVICE_PACKAGE_COMMAND_ARGS: "--retired-package",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  });

  assert.equal(runner.command, "ioi-runtime-daemon-core");
  assert.deepEqual(runner.args, ["--json"]);
});

test("worker/service package runner fails closed without command", () => {
  const runner = new RustWorkerServicePackageRunner();

  assert.throws(
    () => runner.admitInvocation(packageInvocationRequest()),
    (error) =>
      error instanceof WorkerServicePackageRunnerError &&
      error.code === "worker_service_package_bridge_unconfigured",
  );
});

test("worker/service package runner surfaces Rust package rejection", () => {
  const runner = new RustWorkerServicePackageRunner({
    command: "mock-worker-service-package-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "worker_service_package_invocation_invalid",
            message: "missing authority grant",
          },
        }),
        stderr: "",
      };
    },
  });

  assert.throws(
    () => runner.admitInvocation(packageInvocationRequest()),
    (error) =>
      error instanceof WorkerServicePackageRunnerError &&
      error.code === "worker_service_package_invocation_invalid" &&
      error.message === "missing authority grant",
  );
});
