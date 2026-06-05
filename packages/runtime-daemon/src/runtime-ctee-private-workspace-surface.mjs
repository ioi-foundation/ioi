import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.ctee_private_workspace_admission.v1";

export function createRuntimeCteePrivateWorkspaceSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function actionForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    const nested =
      objectRecord(body.action ?? body.ctee_action ?? body.cteeAction) ?? {};
    const action = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(action).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "ctee_private_workspace_action_required",
        message: "Private Workspace cTEE admission requires an action payload.",
      });
    }
    return action;
  }

  function executeCteePrivateWorkspaceAction(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const action = actionForRequest(request);
    const admission = store.cteePrivateWorkspaceRunner.executeAction(action);
    const record = objectRecord(admission.record) ?? {};
    const result = objectRecord(admission.result) ?? objectRecord(record.result) ?? {};
    const receipt = objectRecord(admission.receipt) ?? objectRecord(record.receipt) ?? null;
    return {
      schema_version: CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      schemaVersion: CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_ctee_private_workspace_admission",
      status: "admitted",
      action_executed: true,
      actionExecuted: true,
      thread_id: threadId,
      threadId,
      agent_id: agent.id,
      agentId: agent.id,
      invocation_id:
        result.invocation_id ??
        record.invocation_id ??
        optionalString(action.invocation?.invocation_id ?? action.invocation?.invocationId),
      invocationId:
        result.invocation_id ??
        record.invocation_id ??
        optionalString(action.invocation?.invocation_id ?? action.invocation?.invocationId),
      receipt_ref: receipt?.receipt_ref ?? result.receipt_refs?.[0] ?? null,
      receiptRef: receipt?.receipt_ref ?? result.receipt_refs?.[0] ?? null,
      receipt,
      result,
      receipt_binding: admission.receipt_binding ?? record.receipt_binding ?? null,
      receiptBinding: admission.receipt_binding ?? record.receipt_binding ?? null,
      accepted_receipt_append: admission.accepted_receipt_append ?? null,
      acceptedReceiptAppend: admission.accepted_receipt_append ?? null,
      agentgres_admission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      agentgresAdmission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      projection_record: admission.projection_record ?? record.projection ?? null,
      projectionRecord: admission.projection_record ?? record.projection ?? null,
      receipt_refs: admission.receipt_refs ?? result.receipt_refs ?? [],
      receiptRefs: admission.receipt_refs ?? result.receipt_refs ?? [],
      evidence_refs: admission.evidence_refs ?? record.projection?.evidence_refs ?? [],
      evidenceRefs: admission.evidence_refs ?? record.projection?.evidence_refs ?? [],
      admission,
      record,
    };
  }

  return {
    actionForRequest,
    executeCteePrivateWorkspaceAction,
  };
}
