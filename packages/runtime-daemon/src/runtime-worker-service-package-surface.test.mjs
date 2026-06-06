import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION,
  createRuntimeWorkerServicePackageSurface,
} from "./runtime-worker-service-package-surface.mjs";

function packageInvocation() {
  return {
    schema_version: "ioi.worker_service_package_invocation.v1",
    package_kind: "worker_package",
    package_ref: "worker://runtime-auditor",
    manifest_ref: "worker://runtime-auditor@1",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://worker-package/surface",
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
        idempotency_key: "idem:worker-package-surface",
        deadline_ms: 300000,
        resource_lease_ref: "lease://worker-package",
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: "invocation://worker-package/surface",
      status: "success",
      receipt_refs: ["receipt://worker-package/surface"],
      artifact_refs: ["artifact://worker-package/report"],
      payload_refs: ["payload://worker-package/output"],
      agentgres_operation_refs: ["agentgres://worker-service-package/operations/surface"],
      state_root_after: "sha256:package-after",
      resulting_head: "agentgres://worker-service-package/head/surface",
    },
    expected_heads: ["agentgres://worker-service-package/head/before"],
  };
}

function store() {
  const calls = [];
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_surface" };
    },
    workerServicePackageRunner: {
      admitInvocation(input) {
        calls.push({ name: "admitInvocation", input });
        return {
          source: "rust_worker_service_package_invocation_command",
          backend: "rust_package_invocation",
          record: {
            ...input,
            router_admission: {
              accepted: true,
              backend: "workload_grpc",
            },
            receipt_binding: {
              binding_ref: "receipt-binding://worker-package/surface",
            },
            agentgres_admission: {
              operation_ref: "agentgres://worker-service-package/operations/surface",
            },
            projection: {
              projection_ref: "projection://worker-package/surface",
            },
            receipt_refs: ["receipt://worker-package/surface"],
            artifact_refs: ["artifact://worker-package/report"],
            payload_refs: ["payload://worker-package/output"],
            authority_grant_refs: ["grant://wallet/worker-package"],
          },
          package_kind: input.package_kind,
          package_ref: input.package_ref,
          manifest_ref: input.manifest_ref,
          invocation_id: input.invocation.invocation_id,
          router_admission: {
            accepted: true,
            backend: "workload_grpc",
          },
          receipt_binding: {
            binding_ref: "receipt-binding://worker-package/surface",
          },
          accepted_receipt_append: {
            issuer: "rust_receipt_core",
          },
          agentgres_admission: {
            operation_ref: "agentgres://worker-service-package/operations/surface",
          },
          projection_record: {
            projection_ref: "projection://worker-package/surface",
          },
          receipt_refs: ["receipt://worker-package/surface"],
          artifact_refs: ["artifact://worker-package/report"],
          payload_refs: ["payload://worker-package/output"],
          authority_grant_refs: ["grant://wallet/worker-package"],
        };
      },
    },
  };
}

const WORKER_SERVICE_PACKAGE_ADMISSION_CAMEL_ALIASES = [
  "schemaVersion",
  "invocationAdmitted",
  "threadId",
  "agentId",
  "packageKind",
  "packageRef",
  "manifestRef",
  "invocationId",
  "routerAdmission",
  "receiptBinding",
  "acceptedReceiptAppend",
  "agentgresAdmission",
  "projectionRecord",
  "receiptRefs",
  "artifactRefs",
  "payloadRefs",
  "authorityGrantRefs",
];

test("worker/service package surface admits nested invocation through Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeWorkerServicePackageSurface();

  const result = surface.admitWorkerServicePackageInvocation(runtimeStore, "thread_surface", {
    invocation: packageInvocation(),
  });

  assert.equal(result.schema_version, WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION);
  assert.equal(result.status, "admitted");
  assert.equal(result.invocation_admitted, true);
  assert.equal(result.thread_id, "thread_surface");
  assert.equal(result.agent_id, "agent_surface");
  assert.equal(result.package_kind, "worker_package");
  assert.equal(result.package_ref, "worker://runtime-auditor");
  assert.equal(result.manifest_ref, "worker://runtime-auditor@1");
  assert.equal(result.invocation_id, "invocation://worker-package/surface");
  assert.equal(result.router_admission.accepted, true);
  assert.equal(result.receipt_binding.binding_ref, "receipt-binding://worker-package/surface");
  assert.equal(result.accepted_receipt_append.issuer, "rust_receipt_core");
  assert.equal(
    result.agentgres_admission.operation_ref,
    "agentgres://worker-service-package/operations/surface",
  );
  assert.equal(result.projection_record.projection_ref, "projection://worker-package/surface");
  assert.deepEqual(result.receipt_refs, ["receipt://worker-package/surface"]);
  assert.deepEqual(result.artifact_refs, ["artifact://worker-package/report"]);
  assert.deepEqual(result.payload_refs, ["payload://worker-package/output"]);
  assert.deepEqual(result.authority_grant_refs, ["grant://wallet/worker-package"]);
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "admitInvocation"]);
});

test("worker/service package surface rejects retired request aliases before agent lookup or Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeWorkerServicePackageSurface();

  assert.throws(
    () =>
      surface.admitWorkerServicePackageInvocation(runtimeStore, "thread_surface", {
        package_invocation: packageInvocation(),
        packageInvocation: packageInvocation(),
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "worker_service_package_invocation_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["packageInvocation", "package_invocation"]);
      assert.deepEqual(error.details.canonical_fields, ["invocation"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("worker/service package surface exposes only canonical snake_case admission fields", () => {
  const result = createRuntimeWorkerServicePackageSurface().admitWorkerServicePackageInvocation(
    store(),
    "thread_surface",
    { invocation: packageInvocation() },
  );

  for (const key of WORKER_SERVICE_PACKAGE_ADMISSION_CAMEL_ALIASES) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be emitted`);
  }
});

test("worker/service package surface fails closed without invocation payload", () => {
  const surface = createRuntimeWorkerServicePackageSurface();

  assert.throws(
    () => surface.admitWorkerServicePackageInvocation(store(), "thread_surface", {}),
    (error) => error.code === "worker_service_package_invocation_required",
  );
});
