import { createDaemonCoreCommandInvoker } from "./runtime-daemon-core-command-runner.mjs";

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
    this.invokeBridge = createDaemonCoreCommandInvoker({
      command: this.command,
      spawnSyncImpl: options.spawnSyncImpl,
      mockResult: options.mockResult,
      mockSource: "rust_external_capability_authority_mock",
      defaultBackend: RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
      ErrorClass: ExternalCapabilityAuthorityRunnerError,
      env: EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_ENV,
      unconfiguredMessage:
        "External capability exits require IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core wallet.network authority.",
      unconfiguredCode: "external_capability_authority_bridge_unconfigured",
      spawnFailedMessage: "Failed to spawn Rust external capability authority bridge command.",
      spawnFailedCode: "external_capability_authority_bridge_spawn_failed",
      commandFailedMessage: "Rust external capability authority bridge command failed.",
      commandFailedCode: "external_capability_authority_bridge_failed",
      invalidJsonMessage: "Rust external capability authority bridge command returned invalid JSON.",
      invalidJsonCode: "external_capability_authority_bridge_invalid_json",
      rejectedMessage: "Rust authority core rejected the external capability exit.",
      rejectedCode: "external_capability_authority_bridge_rejected",
    });
  }

  authorizeExit(request, context = {}) {
    const bridgeRequest = {
      schema_version: EXTERNAL_CAPABILITY_AUTHORITY_COMMAND_SCHEMA_VERSION,
      operation: "authorize_external_capability_exit",
      backend: RUST_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      request,
    };
    return normalizeExternalCapabilityAuthorityBridgeResult(this.invokeBridge(bridgeRequest));
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
    schema_version: result.schema_version ?? null,
    object: result.object ?? null,
    status: result.status ?? null,
    exit_authorized: result.exit_authorized ?? null,
    direct_truth_write_allowed: result.direct_truth_write_allowed ?? null,
    thread_id: result.thread_id ?? null,
    agent_id: result.agent_id ?? null,
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
