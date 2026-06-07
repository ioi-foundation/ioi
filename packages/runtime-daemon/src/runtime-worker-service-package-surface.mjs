import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.worker_service_package_admission.v1";

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
    const admission = store.workerServicePackageRunner.admitInvocation(invocation);
    const record = objectRecord(admission.record) ?? {};
    return {
      schema_version: WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_worker_service_package_admission",
      status: "admitted",
      invocation_admitted: true,
      thread_id: threadId,
      agent_id: agent.id,
      package_kind: admission.package_kind ?? record.package_kind ?? optionalString(invocation.package_kind),
      package_ref: admission.package_ref ?? record.package_ref ?? optionalString(invocation.package_ref),
      manifest_ref: admission.manifest_ref ?? record.manifest_ref ?? optionalString(invocation.manifest_ref),
      invocation_id:
        admission.invocation_id ??
        record.invocation_id ??
        optionalString(invocation.invocation?.invocation_id),
      router_admission: admission.router_admission ?? record.router_admission ?? null,
      receipt_binding: admission.receipt_binding ?? record.receipt_binding ?? null,
      accepted_receipt_append: admission.accepted_receipt_append ?? null,
      agentgres_admission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      projection_record: admission.projection_record ?? record.projection ?? null,
      receipt_refs: admission.receipt_refs ?? record.receipt_refs ?? [],
      artifact_refs: admission.artifact_refs ?? record.artifact_refs ?? [],
      payload_refs: admission.payload_refs ?? record.payload_refs ?? [],
      authority_grant_refs: admission.authority_grant_refs ?? record.authority_grant_refs ?? [],
      admission,
      record,
    };
  }

  return {
    admitWorkerServicePackageInvocation,
    invocationForRequest,
  };
}
