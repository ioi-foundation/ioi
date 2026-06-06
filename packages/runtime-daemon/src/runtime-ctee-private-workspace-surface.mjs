import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.ctee_private_workspace_admission.v1";

const RETIRED_CTEE_PRIVATE_WORKSPACE_REQUEST_ALIASES = [
  "cteeAction",
  "ctee_action",
];

const CANONICAL_CTEE_PRIVATE_WORKSPACE_REQUEST_FIELDS = [
  "action",
];

export function createRuntimeCteePrivateWorkspaceSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function actionForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    assertCanonicalCteePrivateWorkspaceRequestBody(body);
    const nested = objectRecord(body.action) ?? {};
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

  function assertCanonicalCteePrivateWorkspaceRequestBody(body = {}) {
    const retiredAliases = RETIRED_CTEE_PRIVATE_WORKSPACE_REQUEST_ALIASES.filter((field) =>
      Object.hasOwn(body, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "ctee_private_workspace_action_request_aliases_retired",
      message: "Private Workspace cTEE action request aliases are retired; use action.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_CTEE_PRIVATE_WORKSPACE_REQUEST_FIELDS,
      },
    });
  }

  function executeCteePrivateWorkspaceAction(store, threadId, request = {}) {
    const action = actionForRequest(request);
    const agent = store.agentForThread(threadId);
    const admission = store.cteePrivateWorkspaceRunner.executeAction(action);
    const record = objectRecord(admission.record) ?? {};
    const result = objectRecord(admission.result) ?? objectRecord(record.result) ?? {};
    const receipt = objectRecord(admission.receipt) ?? objectRecord(record.receipt) ?? null;
    return {
      schema_version: CTEE_PRIVATE_WORKSPACE_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_ctee_private_workspace_admission",
      status: "admitted",
      action_executed: true,
      thread_id: threadId,
      agent_id: agent.id,
      invocation_id:
        result.invocation_id ??
        record.invocation_id ??
        optionalString(action.invocation?.invocation_id ?? action.invocation?.invocationId),
      receipt_ref: receipt?.receipt_ref ?? result.receipt_refs?.[0] ?? null,
      receipt,
      result,
      receipt_binding: admission.receipt_binding ?? record.receipt_binding ?? null,
      accepted_receipt_append: admission.accepted_receipt_append ?? null,
      agentgres_admission: admission.agentgres_admission ?? record.agentgres_admission ?? null,
      projection_record: admission.projection_record ?? record.projection ?? null,
      receipt_refs: admission.receipt_refs ?? result.receipt_refs ?? [],
      evidence_refs: admission.evidence_refs ?? record.projection?.evidence_refs ?? [],
      admission,
      record,
    };
  }

  return {
    actionForRequest,
    executeCteePrivateWorkspaceAction,
  };
}
