import { spawnSync } from "node:child_process";

export const CTEE_PRIVATE_WORKSPACE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const CTEE_PRIVATE_WORKSPACE_COMMAND_ARGS_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS";
export const CTEE_PRIVATE_WORKSPACE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_CTEE_PRIVATE_WORKSPACE_BACKEND = "ctee_operator";

const RETIRED_CTEE_PRIVATE_WORKSPACE_RUNNER_ALIASES = [
  "nodeTrust",
  "expectedHeads",
  "expected_heads",
];

export function createCteePrivateWorkspaceRunnerFromEnv(env = process.env, options = {}) {
  return new RustCteePrivateWorkspaceRunner({
    command: options.command ?? env[CTEE_PRIVATE_WORKSPACE_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[CTEE_PRIVATE_WORKSPACE_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustCteePrivateWorkspaceRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
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

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_ctee_private_workspace_mock",
        backend: request.backend ?? RUST_CTEE_PRIVATE_WORKSPACE_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new CteePrivateWorkspaceRunnerError(
        "Private Workspace cTEE execution requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core cTEE custody admission.",
        "ctee_private_workspace_bridge_unconfigured",
        {
          env: CTEE_PRIVATE_WORKSPACE_COMMAND_ENV,
          argsEnv: CTEE_PRIVATE_WORKSPACE_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new CteePrivateWorkspaceRunnerError(
        "Failed to spawn Rust Private Workspace cTEE bridge command.",
        "ctee_private_workspace_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new CteePrivateWorkspaceRunnerError(
        "Rust Private Workspace cTEE bridge command failed.",
        "ctee_private_workspace_bridge_failed",
        {
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new CteePrivateWorkspaceRunnerError(
        "Rust Private Workspace cTEE bridge command returned invalid JSON.",
        "ctee_private_workspace_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new CteePrivateWorkspaceRunnerError(
        parsed.error?.message ?? "Rust cTEE Private Workspace core rejected the action.",
        parsed.error?.code ?? "ctee_private_workspace_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
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

function parseCommandArgs(value) {
  if (!value) return [];
  if (Array.isArray(value)) return normalizeArgs(value);
  return String(value)
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeArgs(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry)).filter((entry) => entry.length > 0);
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
