import assert from "node:assert/strict";
import test from "node:test";

import {
  RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND,
  RuntimeWorkerServicePackageCore,
  RuntimeWorkerServicePackageCoreError,
  WORKER_SERVICE_PACKAGE_CORE_SCHEMA_VERSION,
  createRuntimeWorkerServicePackageCore,
} from "./runtime-worker-service-package-core.mjs";

function packageInvocationRequest() {
  return {
    schema_version: "ioi.worker_service_package_invocation.v1",
    package_kind: "worker_package",
    package_ref: "worker://runtime-auditor",
    manifest_ref: "worker://runtime-auditor@1",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://worker-package/daemon-core",
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
        idempotency_key: "idem:worker-package-daemon-core",
        deadline_ms: 300000,
        resource_lease_ref: "lease://worker-package",
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: "invocation://worker-package/daemon-core",
      status: "success",
      execution_result_ref: "result://worker-package/daemon-core",
      normalized_observation_ref: "observation://worker-package/daemon-core",
      receipt_refs: ["receipt://worker-package/daemon-core"],
      artifact_refs: ["artifact://worker-package/report"],
      payload_refs: ["payload://worker-package/output"],
      agentgres_operation_refs: ["agentgres://worker-service-package/operations/daemon-core"],
      state_root_after: "sha256:package-after",
      resulting_head: "agentgres://worker-service-package/head/daemon-core",
      workflow_projection: {
        workflow_graph_id: "workflow.worker-package",
        workflow_node_id: "node.worker-package",
        component_kind: "WorkerPackageNode",
        status: "live",
        attempt_id: "attempt://worker-package/daemon-core",
        evidence_refs: ["artifact://worker-package/report"],
        receipt_refs: ["receipt://worker-package/daemon-core"],
      },
    },
  };
}

function admittedResult(coreRequest) {
  return {
    schema_version: "ioi.runtime.worker_service_package_admission.v1",
    object: "ioi.runtime_worker_service_package_admission",
    status: "admitted",
    invocation_admitted: true,
    source: "rust_worker_service_package_invocation_command",
    backend: RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND,
    thread_id: coreRequest.thread_id,
    agent_id: coreRequest.agent_id,
    record: {
      package_kind: coreRequest.request.package_kind,
      package_ref: coreRequest.request.package_ref,
      manifest_ref: coreRequest.request.manifest_ref,
      invocation_id: coreRequest.request.invocation.invocation_id,
      authority_grant_refs:
        coreRequest.request.invocation.authority.authority_grant_refs,
      receipt_refs: coreRequest.request.result.receipt_refs,
      artifact_refs: coreRequest.request.result.artifact_refs,
      payload_refs: coreRequest.request.result.payload_refs,
    },
    package_kind: coreRequest.request.package_kind,
    package_ref: coreRequest.request.package_ref,
    manifest_ref: coreRequest.request.manifest_ref,
    invocation_id: coreRequest.request.invocation.invocation_id,
    router_admission: {
      backend: "workload_grpc",
      admission_ref: "admission://worker-package",
    },
    receipt_binding: {
      binding_hash: "sha256:worker-package-binding",
    },
    accepted_receipt_append: {
      receipt_ref: "receipt://worker-package/daemon-core",
    },
    agentgres_admission: {
      operation_ref: "agentgres://worker-service-package/operations/daemon-core",
    },
    projection_record: {
      workflow_node_id: "node.worker-package",
      status: "live",
    },
    receipt_refs: coreRequest.request.result.receipt_refs,
    artifact_refs: coreRequest.request.result.artifact_refs,
    payload_refs: coreRequest.request.result.payload_refs,
    authority_grant_refs:
      coreRequest.request.invocation.authority.authority_grant_refs,
  };
}

test("worker/service package core calls direct Rust daemon-core package API", () => {
  const calls = [];
  const core = createRuntimeWorkerServicePackageCore({
    daemonCoreInvoker(coreRequest) {
      calls.push(coreRequest);
      return admittedResult(coreRequest);
    },
  });

  const result = core.admitInvocation(packageInvocationRequest(), {
    thread_id: "thread:worker-core",
    agent_id: "agent:worker-core",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].schema_version, WORKER_SERVICE_PACKAGE_CORE_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "admit_worker_service_package_invocation");
  assert.equal(calls[0].backend, RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND);
  assert.equal(calls[0].thread_id, "thread:worker-core");
  assert.equal(calls[0].agent_id, "agent:worker-core");
  assert.equal(calls[0].request.package_ref, "worker://runtime-auditor");
  assert.equal(Object.hasOwn(calls[0].request, "expected_heads"), false);
  assert.equal(result.schema_version, "ioi.runtime.worker_service_package_admission.v1");
  assert.equal(result.object, "ioi.runtime_worker_service_package_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.invocation_admitted, true);
  assert.equal(result.thread_id, "thread:worker-core");
  assert.equal(result.agent_id, "agent:worker-core");
  assert.equal(result.source, "rust_worker_service_package_invocation_command");
  assert.equal(result.backend, RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND);
  assert.equal(result.package_ref, "worker://runtime-auditor");
  assert.equal(result.invocation_id, "invocation://worker-package/daemon-core");
  assert.equal(result.router_admission.backend, "workload_grpc");
  assert.equal(result.accepted_receipt_append.receipt_ref, "receipt://worker-package/daemon-core");
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/worker-package"]);
  assert.deepEqual(result.receipt_refs, ["receipt://worker-package/daemon-core"]);
  assert.deepEqual(result.artifact_refs, ["artifact://worker-package/report"]);
  assert.deepEqual(result.payload_refs, ["payload://worker-package/output"]);
});

test("worker/service package core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.worker_service_package_admission.v1",
    record: {},
  };
  const core = createRuntimeWorkerServicePackageCore({
    daemonCoreInvoker() {
      return rustEnvelope;
    },
  });

  const result = core.admitInvocation(packageInvocationRequest());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "artifact_refs"), false);
  assert.equal(Object.hasOwn(result, "payload_refs"), false);
  assert.equal(Object.hasOwn(result, "authority_grant_refs"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
});

test("worker/service package core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeWorkerServicePackageCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeWorkerServicePackageCoreError &&
      error.code === "worker_service_package_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeWorkerServicePackageCore({ args: ["--json"] }),
    (error) =>
      error instanceof RuntimeWorkerServicePackageCoreError &&
      error.code === "worker_service_package_core_compatibility_option_retired",
  );
});

test("worker/service package core rejects retired bridge request aliases before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeWorkerServicePackageCore({
    daemonCoreInvoker() {
      calls.push("invoked");
      return {};
    },
  });
  const request = packageInvocationRequest();

  assert.throws(
    () =>
      core.admitInvocation({
        ...request,
        packageInvocation: request,
        package_invocation: request,
        expectedHeads: ["agentgres://worker-service-package/head/client"],
        expected_heads: ["agentgres://worker-service-package/head/client"],
      }),
    (error) =>
      error.code === "worker_service_package_core_request_aliases_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("packageInvocation") &&
      error.details.retired_aliases.includes("package_invocation") &&
      error.details.retired_aliases.includes("expectedHeads") &&
      error.details.retired_aliases.includes("expected_heads") &&
      Object.hasOwn(error.details, "packageInvocation") === false &&
      Object.hasOwn(error.details, "expectedHeads") === false,
  );
  assert.deepEqual(calls, []);
});

test("worker/service package core fails closed without direct daemon-core API", () => {
  const core = createRuntimeWorkerServicePackageCore({});

  assert.throws(
    () => core.admitInvocation(packageInvocationRequest()),
    (error) => error.code === "worker_service_package_core_direct_invoker_unconfigured",
  );
});

test("worker/service package core surfaces Rust invocation rejection", () => {
  const core = createRuntimeWorkerServicePackageCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "worker_service_package_invocation_invalid",
          message: "missing authority grant",
        },
      };
    },
  });

  assert.throws(
    () => core.admitInvocation(packageInvocationRequest()),
    (error) =>
      error.code === "worker_service_package_invocation_invalid" &&
      error.message === "missing authority grant",
  );
});
