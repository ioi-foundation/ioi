import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION,
  createRuntimeWorkerServicePackageControlRequest,
  createRuntimeWorkerServicePackageControlRequestFromWorkflowNode,
} from "./workflow-runtime-worker-service-package-control-nodes";

function packageInvocation() {
  return {
    schema_version: "ioi.worker_service_package_invocation.v1",
    package_kind: "worker_package" as const,
    package_ref: "worker://runtime-auditor",
    manifest_ref: "worker://runtime-auditor@1",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: "invocation://worker-package/ide",
      module_ref: {
        kind: "workload_job",
        id: "worker://runtime-auditor",
        manifest_ref: "worker://runtime-auditor@1",
      },
      authority: {
        authority_grant_refs: ["grant://wallet/worker-package-ide"],
      },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      invocation_id: "invocation://worker-package/ide",
      status: "success",
      receipt_refs: ["receipt://worker-package/ide"],
      artifact_refs: ["artifact://worker-package/ide-report"],
      payload_refs: ["payload://worker-package/ide-output"],
    },
  };
}

const retiredWorkerServicePackageRequestAliases = [
  "eventKind",
  "componentKind",
  "payloadSchemaVersion",
  "workflowGraphId",
  "workflowNodeId",
  "packageKind",
  "packageRef",
  "manifestRef",
  "invocationId",
  "expected_heads",
  "expectedHeads",
  "admissionOnly",
  "directTruthWriteAllowed",
  "mutationAllowed",
  "package_invocation",
  "packageInvocation",
];

test("builds worker/service package controls for daemon admission", () => {
  const request = createRuntimeWorkerServicePackageControlRequest({
    nodeId: "node-worker-service-package",
    threadId: "thread-ide",
    packageInvocation: packageInvocation(),
    workflowGraphId: "workflow.worker-service-package",
    actor: "workflow-author",
  });

  assert.equal(request.schemaVersion, WORKFLOW_RUNTIME_WORKER_SERVICE_PACKAGE_CONTROL_SCHEMA_VERSION);
  assert.equal(request.endpoint, "/v1/threads/thread-ide/worker-service-package-invocations");
  assert.equal(request.method, "POST");
  assert.equal(request.nodeType, "worker_service_package_invocation");
  assert.equal(request.invocationId, "invocation://worker-package/ide");
  assert.equal(request.body.source, "react_flow");
  assert.equal(request.body.package_ref, "worker://runtime-auditor");
  assert.equal(request.body.manifest_ref, "worker://runtime-auditor@1");
  assert.equal(request.body.invocation.invocation.invocation_id, "invocation://worker-package/ide");
  assert.equal(request.body.admission_only, true);
  assert.equal(request.body.direct_truth_write_allowed, false);
  assert.equal(request.body.mutation_allowed, false);
  for (const key of retiredWorkerServicePackageRequestAliases) {
    assert.equal(Object.prototype.hasOwnProperty.call(request.body, key), false, `${key} must not be emitted`);
  }
  assert.equal(request.endpoint.includes("/apply"), false);
});

test("builds worker/service package controls from workflow package nodes", () => {
  const request = createRuntimeWorkerServicePackageControlRequestFromWorkflowNode(
    {
      id: "worker-service-package-node",
      type: "runtime.control.worker_service_package",
      config: {
        logic: {
          workerServicePackage: packageInvocation(),
        },
      } as any,
    },
    { threadId: "thread-node" },
    { workflowGraphId: "workflow.package-node", actor: "runtime-composer" },
  );

  assert.equal(request.nodeId, "worker-service-package-node");
  assert.equal(request.threadId, "thread-node");
  assert.equal(request.body.actor, "runtime-composer");
  assert.equal(request.body.workflow_graph_id, "workflow.package-node");
  assert.equal(
    request.body.workflow_node_id,
    "runtime.worker-service-package-invocation.worker-service-package-node",
  );
  assert.equal(request.body.invocation.package_ref, "worker://runtime-auditor");
});

test("worker/service package controls fail closed without admission result", () => {
  const invalid: Record<string, unknown> = packageInvocation();
  invalid.result = {};

  assert.throws(
    () =>
      createRuntimeWorkerServicePackageControlRequest({
        threadId: "thread-ide",
        packageInvocation: invalid,
      }),
    /result/,
  );
});

test("worker/service package controls reject retired Agentgres truth fields", () => {
  for (const key of ["expected_heads", "expectedHeads"]) {
    assert.throws(
      () =>
        createRuntimeWorkerServicePackageControlRequest({
          threadId: "thread-ide",
          packageInvocation: {
            ...packageInvocation(),
            [key]: ["agentgres://worker-service-package/head/client"],
          },
        }),
      /Rust-derived Agentgres truth fields/,
    );
  }
});
