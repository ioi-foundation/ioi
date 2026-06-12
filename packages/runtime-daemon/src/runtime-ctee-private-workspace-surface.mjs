import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

const RETIRED_CTEE_PRIVATE_WORKSPACE_REQUEST_ALIASES = [
  "cteeAction",
  "ctee_action",
];

const CANONICAL_CTEE_PRIVATE_WORKSPACE_REQUEST_FIELDS = [
  "action",
];

const RETIRED_CTEE_PRIVATE_WORKSPACE_TRUTH_FIELDS = [
  "expected_heads",
  "expectedHeads",
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
    assertNoClientSuppliedCteePrivateWorkspaceTruth(action);
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

  function assertNoClientSuppliedCteePrivateWorkspaceTruth(action = {}) {
    const retiredFields = RETIRED_CTEE_PRIVATE_WORKSPACE_TRUTH_FIELDS.filter((field) =>
      Object.hasOwn(action, field),
    );
    if (retiredFields.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "ctee_private_workspace_agentgres_truth_fields_retired",
      message:
        "Private Workspace cTEE expected heads are derived by the Rust core and cannot be supplied by clients.",
      details: {
        retired_fields: retiredFields,
      },
    });
  }

  function executeCteePrivateWorkspaceAction(store, threadId, request = {}) {
    const action = actionForRequest(request);
    const agent = store.agentForThread(threadId);
    return store.cteePrivateWorkspaceRunner.executeAction(action, {
      thread_id: threadId,
      agent_id: agent.id,
    });
  }

  return {
    actionForRequest,
    executeCteePrivateWorkspaceAction,
  };
}
