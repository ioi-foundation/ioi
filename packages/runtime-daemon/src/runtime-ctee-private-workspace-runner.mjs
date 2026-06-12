export const CTEE_PRIVATE_WORKSPACE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_CTEE_PRIVATE_WORKSPACE_BACKEND = "ctee_operator";

const RETIRED_CTEE_PRIVATE_WORKSPACE_RUNNER_ALIASES = [
  "nodeTrust",
  "expectedHeads",
  "expected_heads",
];

export function createCteePrivateWorkspaceRunnerFromEnv(env = process.env, options = {}) {
  assertNoCteePrivateWorkspaceCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoCteePrivateWorkspaceCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_CTEE_PRIVATE_WORKSPACE_COMMAND,
  );
  return new RustCteePrivateWorkspaceRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
  });
}

export function assertNoCteePrivateWorkspaceCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new CteePrivateWorkspaceRunnerError(
    "Private Workspace cTEE command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "ctee_private_workspace_command_args_retired",
    { retired_args: value },
  );
}

export function assertNoCteePrivateWorkspaceCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new CteePrivateWorkspaceRunnerError(
    "Private Workspace cTEE binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core cTEE custody admission.",
    "ctee_private_workspace_command_selection_retired",
    { retired_command: value },
  );
}

export class RustCteePrivateWorkspaceRunner {
  constructor(options = {}) {
    assertNoCteePrivateWorkspaceCommandArgs(options.args);
    assertNoCteePrivateWorkspaceCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  executeAction(request = {}, context = {}) {
    assertCanonicalCteePrivateWorkspaceRunnerRequest(request);
    const bridgeRequest = {
      schema_version: CTEE_PRIVATE_WORKSPACE_COMMAND_SCHEMA_VERSION,
      operation: "execute_private_workspace_ctee_action",
      backend: RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      invocation: request.invocation,
      node_trust: request.node_trust,
    };
    return normalizeCteePrivateWorkspaceBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new CteePrivateWorkspaceRunnerError(
        "Private Workspace cTEE execution requires daemonCoreInvoker for direct Rust daemon-core cTEE custody admission.",
        "ctee_private_workspace_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new CteePrivateWorkspaceRunnerError(
        error.message ?? "Rust cTEE Private Workspace core rejected the action.",
        error.code ?? "ctee_private_workspace_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalCteePrivateWorkspaceRunnerRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_CTEE_PRIVATE_WORKSPACE_RUNNER_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new CteePrivateWorkspaceRunnerError(
    "Private Workspace cTEE runner request aliases are retired; use canonical snake_case bridge fields.",
    "ctee_private_workspace_runner_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      canonical_fields: ["node_trust"],
    },
  );
}

export class CteePrivateWorkspaceRunnerError extends Error {
  constructor(message, code = "ctee_private_workspace_runner_error", details = {}) {
    super(message);
    this.name = "CteePrivateWorkspaceRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeCteePrivateWorkspaceBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const record = objectRecord(result.record) ?? {};
  return {
    schema_version: result.schema_version ?? null,
    object: result.object ?? null,
    status: result.status ?? null,
    action_executed: result.action_executed ?? null,
    source: result.source ?? "rust_ctee_private_workspace_command",
    backend: result.backend ?? RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
    thread_id: result.thread_id ?? null,
    agent_id: result.agent_id ?? null,
    invocation_id: result.invocation_id ?? null,
    receipt_ref: result.receipt_ref ?? null,
    record,
    receipt: objectRecord(result.receipt) ?? objectRecord(record.receipt) ?? null,
    result: objectRecord(result.result) ?? objectRecord(record.result) ?? null,
    receipt_binding: objectRecord(result.receipt_binding) ?? objectRecord(record.receipt_binding) ?? null,
    accepted_receipt_append: objectRecord(result.accepted_receipt_append) ?? null,
    agentgres_admission:
      objectRecord(result.agentgres_admission) ?? objectRecord(record.agentgres_admission) ?? null,
    projection_record: objectRecord(result.projection_record) ?? objectRecord(record.projection) ?? null,
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.result?.receipt_refs) ?? null,
    evidence_refs: stringArray(result.evidence_refs) ?? stringArray(record.projection?.evidence_refs) ?? null,
  };
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function stringArray(value) {
  if (!Array.isArray(value)) return null;
  return value.filter((entry) => typeof entry === "string" && entry.trim()).map((entry) => entry.trim());
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
