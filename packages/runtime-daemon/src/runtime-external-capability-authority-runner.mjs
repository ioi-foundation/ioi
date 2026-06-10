import { spawnSync } from "node:child_process";

export const EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND = "rust_authority";

export function createExternalCapabilityAuthorityRunnerFromEnv(env = process.env, options = {}) {
  assertNoExternalCapabilityAuthorityCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustExternalCapabilityAuthorityRunner({
    command: options.command ?? env[EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoExternalCapabilityAuthorityCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new ExternalCapabilityAuthorityRunnerError(
    "External capability authority command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "external_capability_authority_command_args_retired",
    { retired_args: value },
  );
}

export class RustExternalCapabilityAuthorityRunner {
  constructor(options = {}) {
    assertNoExternalCapabilityAuthorityCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  authorizeExit(request) {
    const bridgeRequest = {
      schema_version: EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION,
      operation: "authorize_external_capability_exit",
      backend: RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
      request,
    };
    return normalizeExternalCapabilityAuthorityBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_external_capability_authority_mock",
        backend: request.backend ?? RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new ExternalCapabilityAuthorityRunnerError(
        "External capability exits require IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core wallet.network authority.",
        "external_capability_authority_bridge_unconfigured",
        {
          env: EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ExternalCapabilityAuthorityRunnerError(
        "Failed to spawn Rust external capability authority bridge command.",
        "external_capability_authority_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ExternalCapabilityAuthorityRunnerError(
        "Rust external capability authority bridge command failed.",
        "external_capability_authority_bridge_failed",
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
      throw new ExternalCapabilityAuthorityRunnerError(
        "Rust external capability authority bridge command returned invalid JSON.",
        "external_capability_authority_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ExternalCapabilityAuthorityRunnerError(
        parsed.error?.message ?? "Rust authority core rejected the external capability exit.",
        parsed.error?.code ?? "external_capability_authority_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class ExternalCapabilityAuthorityRunnerError extends Error {
  constructor(message, code = "external_capability_authority_runner_error", details = {}) {
    super(message);
    this.name = "ExternalCapabilityAuthorityRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeExternalCapabilityAuthorityBridgeResult(value = {}) {
  const result = objectRecord(value) ?? {};
  const authority = objectRecord(result.authority) ?? {};
  return {
    source: result.source ?? "rust_external_capability_exit_authority_command",
    backend: result.backend ?? RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
    authority,
    exit_ref: result.exit_ref ?? authority.exit_ref ?? null,
    capability_ref: result.capability_ref ?? authority.capability_ref ?? null,
    target_ref: result.target_ref ?? authority.target_ref ?? null,
    policy_hash: result.policy_hash ?? authority.policy_hash ?? null,
    idempotency_key: result.idempotency_key ?? authority.idempotency_key ?? null,
    wallet_network_grant_refs:
      stringArray(result.wallet_network_grant_refs) ??
      stringArray(authority.wallet_network_grant_refs) ??
      [],
    authority_receipt_refs:
      stringArray(result.authority_receipt_refs) ??
      stringArray(authority.authority_receipt_refs) ??
      [],
    authority_hash: result.authority_hash ?? authority.authority_hash ?? null,
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
