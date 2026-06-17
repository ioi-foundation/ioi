import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

const RETIRED_WORKER_SERVICE_PACKAGE_REQUEST_ALIASES = [
  "packageInvocation",
  "package_invocation",
];

const CANONICAL_WORKER_SERVICE_PACKAGE_REQUEST_FIELDS = [
  "invocation",
];

const RETIRED_WORKER_SERVICE_PACKAGE_TRUTH_FIELDS = [
  "expected_heads",
];

export function createRuntimeWorkerServicePackageSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function invocationForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    assertCanonicalWorkerServicePackageRequestBody(body);
    const nested = objectRecord(body.invocation) ?? {};
    const invocation = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(invocation).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "worker_service_package_invocation_required",
        message: "Worker/service package admission requires an invocation payload.",
      });
    }
    assertNoClientSuppliedWorkerServicePackageTruth(invocation);
    return invocation;
  }

  function assertCanonicalWorkerServicePackageRequestBody(body = {}) {
    const retiredAliases = RETIRED_WORKER_SERVICE_PACKAGE_REQUEST_ALIASES.filter((field) =>
      Object.hasOwn(body, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "worker_service_package_invocation_request_aliases_retired",
      message: "Worker/service package invocation request aliases are retired; use invocation.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_WORKER_SERVICE_PACKAGE_REQUEST_FIELDS,
      },
    });
  }

  function assertNoClientSuppliedWorkerServicePackageTruth(invocation = {}) {
    const retiredTruthFields = RETIRED_WORKER_SERVICE_PACKAGE_TRUTH_FIELDS.filter((field) =>
      Object.hasOwn(invocation, field),
    );
    if (retiredTruthFields.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "worker_service_package_agentgres_truth_fields_retired",
      message: "Worker/service package Agentgres truth fields are Rust-derived and cannot be supplied by clients.",
      details: {
        retired_fields: retiredTruthFields,
        derived_by: "rust_worker_service_package_invocation",
      },
    });
  }

  function admitWorkerServicePackageInvocation(store, threadId, request = {}) {
    const invocation = invocationForRequest(request);
    const agent = store.agentForThread(threadId);
    return store.workerServicePackageCore.admitInvocation(invocation, {
      thread_id: threadId,
      agent_id: agent.id,
    });
  }

  return {
    admitWorkerServicePackageInvocation,
    invocationForRequest,
  };
}
