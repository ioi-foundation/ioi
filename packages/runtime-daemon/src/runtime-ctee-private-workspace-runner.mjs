import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

export const CTEE_PRIVATE_WORKSPACE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const CTEE_PRIVATE_WORKSPACE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_CTEE_PRIVATE_WORKSPACE_BACKEND = "ctee_operator";

const RETIRED_CTEE_PRIVATE_WORKSPACE_RUNNER_ALIASES = [
  "nodeTrust",
  "expectedHeads",
  "expected_heads",
];

export function createCteePrivateWorkspaceRunnerFromEnv(env = process.env, options = {}) {
  assertNoCteePrivateWorkspaceCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustCteePrivateWorkspaceRunner({
    command: options.command ?? env[CTEE_PRIVATE_WORKSPACE_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
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

export class RustCteePrivateWorkspaceRunner {
  constructor(options = {}) {
    assertNoCteePrivateWorkspaceCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_ctee_private_workspace_mock",
      defaultBackend: RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
      ErrorClass: CteePrivateWorkspaceRunnerError,
      env: CTEE_PRIVATE_WORKSPACE_COMMAND_ENV,
      unconfiguredMessage:
        "Private Workspace cTEE execution requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core cTEE custody admission.",
      unconfiguredCode: "ctee_private_workspace_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust Private Workspace cTEE bridge command.",
      spawnFailedCode: "ctee_private_workspace_bridge_spawn_failed",
      commandFailedMessage: "Rust Private Workspace cTEE bridge command failed.",
      commandFailedCode: "ctee_private_workspace_bridge_failed",
      invalidJsonMessage: "Rust Private Workspace cTEE bridge command returned invalid JSON.",
      invalidJsonCode: "ctee_private_workspace_bridge_invalid_json",
      rejectedMessage: "Rust cTEE Private Workspace core rejected the action.",
      rejectedCode: "ctee_private_workspace_bridge_rejected",
    });
  }

  executeAction(request = {}) {
    assertCanonicalCteePrivateWorkspaceRunnerRequest(request);
    const bridgeRequest = {
      schema_version: CTEE_PRIVATE_WORKSPACE_COMMAND_SCHEMA_VERSION,
      operation: "execute_private_workspace_ctee_action",
      backend: RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
      invocation: request.invocation,
      node_trust: request.node_trust,
    };
    return normalizeCteePrivateWorkspaceBridgeResult(this.invokeBridge(bridgeRequest));
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
    source: result.source ?? "rust_ctee_private_workspace_command",
    backend: result.backend ?? RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
    record,
    receipt: objectRecord(result.receipt) ?? objectRecord(record.receipt) ?? null,
    result: objectRecord(result.result) ?? objectRecord(record.result) ?? null,
    receipt_binding: objectRecord(result.receipt_binding) ?? objectRecord(record.receipt_binding) ?? null,
    accepted_receipt_append: objectRecord(result.accepted_receipt_append) ?? null,
    agentgres_admission:
      objectRecord(result.agentgres_admission) ?? objectRecord(record.agentgres_admission) ?? null,
    projection_record: objectRecord(result.projection_record) ?? objectRecord(record.projection) ?? null,
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.result?.receipt_refs) ?? [],
    evidence_refs: stringArray(result.evidence_refs) ?? stringArray(record.projection?.evidence_refs) ?? [],
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
