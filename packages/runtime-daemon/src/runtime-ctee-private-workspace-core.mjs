export const CTEE_PRIVATE_WORKSPACE_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUNTIME_CTEE_PRIVATE_WORKSPACE_BACKEND = "ctee_operator";

const RETIRED_CTEE_PRIVATE_WORKSPACE_CORE_REQUEST_ALIASES = [
  "nodeTrust",
  "expectedHeads",
  "expected_heads",
];

export function createRuntimeCteePrivateWorkspaceCore(options = {}) {
  return new RuntimeCteePrivateWorkspaceCore(options);
}

export class RuntimeCteePrivateWorkspaceCore {
  constructor(options = {}) {
    assertNoRetiredCteePrivateWorkspaceCoreOption("command", options.command);
    assertNoRetiredCteePrivateWorkspaceCoreOption("args", options.args);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  executeAction(request = {}, context = {}) {
    assertCanonicalCteePrivateWorkspaceCoreRequest(request);
    const daemonCoreRequest = {
      schema_version: CTEE_PRIVATE_WORKSPACE_CORE_SCHEMA_VERSION,
      operation: "execute_private_workspace_ctee_action",
      backend: RUNTIME_CTEE_PRIVATE_WORKSPACE_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      invocation: request.invocation,
      node_trust: request.node_trust,
    };
    return this.invokeDaemonCore(daemonCoreRequest);
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeCteePrivateWorkspaceCoreError(
        "Private Workspace cTEE execution requires daemonCoreInvoker for direct Rust daemon-core cTEE custody admission.",
        "ctee_private_workspace_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeCteePrivateWorkspaceCoreError(
        error.message ?? "Rust cTEE Private Workspace core rejected the action.",
        error.code ?? "ctee_private_workspace_core_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalCteePrivateWorkspaceCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_CTEE_PRIVATE_WORKSPACE_CORE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new RuntimeCteePrivateWorkspaceCoreError(
    "Private Workspace cTEE core request aliases are retired; use canonical snake_case Rust daemon-core fields.",
    "ctee_private_workspace_core_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      canonical_fields: ["node_trust"],
    },
  );
}

function assertNoRetiredCteePrivateWorkspaceCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeCteePrivateWorkspaceCoreError(
    "Private Workspace cTEE command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core cTEE custody admission.",
    "ctee_private_workspace_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeCteePrivateWorkspaceCoreError extends Error {
  constructor(message, code = "ctee_private_workspace_core_error", details = {}) {
    super(message);
    this.name = "RuntimeCteePrivateWorkspaceCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
