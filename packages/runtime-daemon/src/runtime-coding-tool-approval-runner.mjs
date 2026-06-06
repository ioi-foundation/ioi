import { spawnSync } from "node:child_process";

export const CODING_TOOL_APPROVAL_COMMAND_ENV = "IOI_STEP_MODULE_COMMAND";
export const CODING_TOOL_APPROVAL_COMMAND_ARGS_ENV = "IOI_STEP_MODULE_COMMAND_ARGS";
export const CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION = "ioi.step_module.command_bridge.v1";
export const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-request.v1";
export const RUST_CODING_TOOL_APPROVAL_BACKEND = "rust_authority";

export function createCodingToolApprovalRunnerFromEnv(env = process.env, options = {}) {
  return new RustCodingToolApprovalRunner({
    command: options.command ?? env[CODING_TOOL_APPROVAL_COMMAND_ENV] ?? null,
    args:
      options.args ??
      parseCommandArgs(env[CODING_TOOL_APPROVAL_COMMAND_ARGS_ENV]),
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export class RustCodingToolApprovalRunner {
  constructor(options = {}) {
    this.command = optionalString(options.command);
    this.args = normalizeArgs(options.args);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  planApprovalManifest(request = {}) {
    const bridgeRequest = {
      schema_version: CODING_TOOL_APPROVAL_COMMAND_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_manifest",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
      },
    };
    return normalizeCodingToolApprovalBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_coding_tool_approval_mock",
        backend: request.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new CodingToolApprovalRunnerError(
        "Coding-tool approval requires IOI_STEP_MODULE_COMMAND for Rust authority planning.",
        "coding_tool_approval_bridge_unconfigured",
        {
          env: CODING_TOOL_APPROVAL_COMMAND_ENV,
          argsEnv: CODING_TOOL_APPROVAL_COMMAND_ARGS_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, this.args, {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new CodingToolApprovalRunnerError(
        "Failed to spawn Rust coding-tool approval bridge command.",
        "coding_tool_approval_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new CodingToolApprovalRunnerError(
        "Rust coding-tool approval bridge command failed.",
        "coding_tool_approval_bridge_failed",
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
      throw new CodingToolApprovalRunnerError(
        "Rust coding-tool approval bridge command returned invalid JSON.",
        "coding_tool_approval_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new CodingToolApprovalRunnerError(
        parsed.error?.message ?? "Rust coding-tool approval core rejected the request.",
        parsed.error?.code ?? "coding_tool_approval_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class CodingToolApprovalRunnerError extends Error {
  constructor(message, code = "coding_tool_approval_runner_error", details = {}) {
    super(message);
    this.name = "CodingToolApprovalRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeCodingToolApprovalBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const plan = objectRecord(result.plan) ?? {};
  const manifest = objectRecord(result.manifest) ?? objectRecord(plan.manifest) ?? null;
  const workflowPolicy =
    objectRecord(result.workflow_policy) ??
    objectRecord(plan.workflow_policy) ??
    objectRecord(manifest?.workflow_policy) ??
    null;
  const approvalRequired = Boolean(result.approval_required ?? plan.approval_required ?? manifest);
  return {
    source: result.source ?? "rust_coding_tool_approval_command",
    backend: result.backend ?? RUST_CODING_TOOL_APPROVAL_BACKEND,
    plan,
    approval_required: approvalRequired,
    workflow_policy: workflowPolicy,
    manifest,
    input_hash: optionalString(result.input_hash ?? plan.input_hash ?? manifest?.input_hash),
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

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}
