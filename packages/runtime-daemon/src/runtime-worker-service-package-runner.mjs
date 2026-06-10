import { spawnSync } from "node:child_process";

export const WORKER_SERVICE_PACKAGE_COMMAND_ENV = "IOI_RUNTIME_DAEMON_CORE_COMMAND";
export const WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_WORKER_SERVICE_PACKAGE_BACKEND = "rust_package_invocation";

export function createWorkerServicePackageRunnerFromEnv(env = process.env, options = {}) {
  assertNoWorkerServicePackageCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  return new RustWorkerServicePackageRunner({
    command: options.command ?? env[WORKER_SERVICE_PACKAGE_COMMAND_ENV] ?? null,
    spawnSyncImpl: options.spawnSyncImpl,
    mockResult: options.mockResult,
  });
}

export function assertNoWorkerServicePackageCommandArgs(value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new WorkerServicePackageRunnerError(
    "Worker/service package command argument selection is retired; daemon-core command argv is fixed migration transport.",
    "worker_service_package_command_args_retired",
    { retired_args: value },
  );
}

export class RustWorkerServicePackageRunner {
  constructor(options = {}) {
    assertNoWorkerServicePackageCommandArgs(options.args);
    this.command = optionalString(options.command);
    this.spawnSyncImpl = options.spawnSyncImpl ?? spawnSync;
    this.mockResult = options.mockResult;
  }

  admitInvocation(request) {
    const bridgeRequest = {
      schema_version: WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION,
      operation: "admit_worker_service_package_invocation",
      backend: RUST_WORKER_SERVICE_PACKAGE_BACKEND,
      request,
    };
    return normalizeWorkerServicePackageBridgeResult(this.invokeBridge(bridgeRequest));
  }

  invokeBridge(request) {
    if (this.mockResult) {
      const value = typeof this.mockResult === "function" ? this.mockResult(request) : this.mockResult;
      return {
        source: "rust_worker_service_package_mock",
        backend: request.backend ?? RUST_WORKER_SERVICE_PACKAGE_BACKEND,
        ...value,
      };
    }
    if (!this.command) {
      throw new WorkerServicePackageRunnerError(
        "Worker/service package invocation admission requires IOI_RUNTIME_DAEMON_CORE_COMMAND for Rust daemon-core package admission.",
        "worker_service_package_bridge_unconfigured",
        {
          env: WORKER_SERVICE_PACKAGE_COMMAND_ENV,
        },
      );
    }
    const output = this.spawnSyncImpl(this.command, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new WorkerServicePackageRunnerError(
        "Failed to spawn Rust worker/service package admission bridge command.",
        "worker_service_package_bridge_spawn_failed",
        { error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new WorkerServicePackageRunnerError(
        "Rust worker/service package admission bridge command failed.",
        "worker_service_package_bridge_failed",
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
      throw new WorkerServicePackageRunnerError(
        "Rust worker/service package admission bridge command returned invalid JSON.",
        "worker_service_package_bridge_invalid_json",
        { error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new WorkerServicePackageRunnerError(
        parsed.error?.message ?? "Rust worker/service package core rejected the invocation.",
        parsed.error?.code ?? "worker_service_package_bridge_rejected",
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  }
}

export class WorkerServicePackageRunnerError extends Error {
  constructor(message, code = "worker_service_package_runner_error", details = {}) {
    super(message);
    this.name = "WorkerServicePackageRunnerError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

export function normalizeWorkerServicePackageBridgeResult(value = {}) {
  const result = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const record = objectRecord(result.record) ?? {};
  return {
    source: result.source ?? "rust_worker_service_package_invocation_command",
    backend: result.backend ?? RUST_WORKER_SERVICE_PACKAGE_BACKEND,
    record,
    package_kind: result.package_kind ?? record.package_kind ?? null,
    package_ref: result.package_ref ?? record.package_ref ?? null,
    manifest_ref: result.manifest_ref ?? record.manifest_ref ?? null,
    invocation_id: result.invocation_id ?? record.invocation_id ?? null,
    router_admission: objectRecord(result.router_admission) ?? objectRecord(record.router_admission) ?? null,
    receipt_binding: objectRecord(result.receipt_binding) ?? objectRecord(record.receipt_binding) ?? null,
    accepted_receipt_append: objectRecord(result.accepted_receipt_append) ?? null,
    agentgres_admission: objectRecord(result.agentgres_admission) ?? objectRecord(record.agentgres_admission) ?? null,
    projection_record: objectRecord(result.projection_record) ?? objectRecord(record.projection) ?? null,
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.receipt_refs) ?? [],
    artifact_refs: stringArray(result.artifact_refs) ?? stringArray(record.artifact_refs) ?? [],
    payload_refs: stringArray(result.payload_refs) ?? stringArray(record.payload_refs) ?? [],
    authority_grant_refs:
      stringArray(result.authority_grant_refs) ?? stringArray(record.authority_grant_refs) ?? [],
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
