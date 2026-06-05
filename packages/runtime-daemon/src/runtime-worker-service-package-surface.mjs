import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.worker_service_package_admission.v1";

export function createRuntimeWorkerServicePackageSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function invocationForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    const nested =
      objectRecord(body.invocation ?? body.package_invocation ?? body.packageInvocation) ?? {};
    const invocation = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(invocation).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "worker_service_package_invocation_required",
        message: "Worker/service package admission requires an invocation payload.",
      });
    }
    return invocation;
  }

  function admitWorkerServicePackageInvocation(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const invocation = invocationForRequest(request);
    const admission = store.workerServicePackageRunner.admitInvocation(invocation);
    const record = objectRecord(admission.record) ?? {};
    return {
      schema_version: WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      schemaVersion: WORKER_SERVICE_PACKAGE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_worker_service_package_admission",
      status: "admitted",
      invocation_admitted: true,
      invocationAdmitted: true,
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      package_kind: admission.package_kind ?? record.package_kind ?? optionalString(invocation.package_kind),
      packageKind: admission.package_kind ?? record.package_kind ?? optionalString(invocation.package_kind),
      package_ref: admission.package_ref ?? record.package_ref ?? optionalString(invocation.package_ref),
      packageRef: admission.package_ref ?? record.package_ref ?? optionalString(invocation.package_ref),
      manifest_ref: admission.manifest_ref ?? record.manifest_ref ?? optionalString(invocation.manifest_ref),
      manifestRef: admission.manifest_ref ?? record.manifest_ref ?? optionalString(invocation.manifest_ref),
      invocation_id:
        admission.invocation_id ??
        record.invocation_id ??
        optionalString(invocation.invocation?.invocation_id ?? invocation.invocation?.invocationId),
      invocationId:
        admission.invocation_id ??
        record.invocation_id ??
        optionalString(invocation.invocation?.invocation_id ?? invocation.invocation?.invocationId),
      router_admission: admission.router_admission ?? record.router_admission ?? null,
      routerAdmission: admission.router_admission ?? record.router_admission ?? null,
      receipt_binding: admission.receipt_binding ?? record.receipt_binding ?? null,
      receiptBinding: admission.receipt_binding ?? record.receipt_binding ?? null,
      accepted_receipt_append: admission.accepted_receipt_append ?? null,
      acceptedReceiptAppend: admission.accepted_receipt_append ?? null,
      agentgres_admission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      agentgresAdmission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      projection_record: admission.projection_record ?? record.projection ?? null,
      projectionRecord: admission.projection_record ?? record.projection ?? null,
      receipt_refs: admission.receipt_refs ?? record.receipt_refs ?? [],
      receiptRefs: admission.receipt_refs ?? record.receipt_refs ?? [],
      artifact_refs: admission.artifact_refs ?? record.artifact_refs ?? [],
      artifactRefs: admission.artifact_refs ?? record.artifact_refs ?? [],
      payload_refs: admission.payload_refs ?? record.payload_refs ?? [],
      payloadRefs: admission.payload_refs ?? record.payload_refs ?? [],
      authority_grant_refs: admission.authority_grant_refs ?? record.authority_grant_refs ?? [],
      authorityGrantRefs: admission.authority_grant_refs ?? record.authority_grant_refs ?? [],
      admission,
      record,
    };
  }

  return {
    admitWorkerServicePackageInvocation,
    invocationForRequest,
  };
}
