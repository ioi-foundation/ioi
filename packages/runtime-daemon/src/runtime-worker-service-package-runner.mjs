export const WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUST_WORKER_SERVICE_PACKAGE_BACKEND = "rust_package_invocation";

export function createWorkerServicePackageRunnerFromEnv(env = process.env, options = {}) {
  assertNoWorkerServicePackageCommandArgs(options.args ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS);
  assertNoWorkerServicePackageCommandSelection(
    options.command ?? env.IOI_RUNTIME_DAEMON_CORE_COMMAND ?? env.IOI_WORKER_SERVICE_PACKAGE_COMMAND,
  );
  return new RustWorkerServicePackageRunner({
    daemonCoreInvoker: options.daemonCoreInvoker,
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

export function assertNoWorkerServicePackageCommandSelection(value) {
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new WorkerServicePackageRunnerError(
    "Worker/service package binary command selection is retired; use daemonCoreInvoker for direct Rust daemon-core package admission.",
    "worker_service_package_command_selection_retired",
    { retired_command: value },
  );
}

export class RustWorkerServicePackageRunner {
  constructor(options = {}) {
    assertNoWorkerServicePackageCommandArgs(options.args);
    assertNoWorkerServicePackageCommandSelection(options.command);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitInvocation(request, context = {}) {
    const bridgeRequest = {
      schema_version: WORKER_SERVICE_PACKAGE_COMMAND_SCHEMA_VERSION,
      operation: "admit_worker_service_package_invocation",
      backend: RUST_WORKER_SERVICE_PACKAGE_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      request,
    };
    return normalizeWorkerServicePackageBridgeResult(this.invokeDaemonCore(bridgeRequest));
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new WorkerServicePackageRunnerError(
        "Worker/service package invocation admission requires daemonCoreInvoker for direct Rust daemon-core package admission.",
        "worker_service_package_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new WorkerServicePackageRunnerError(
        error.message ?? "Rust worker/service package core rejected the invocation.",
        error.code ?? "worker_service_package_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
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
    schema_version: result.schema_version ?? null,
    object: result.object ?? null,
    status: result.status ?? null,
    invocation_admitted: result.invocation_admitted ?? null,
    source: result.source ?? "rust_worker_service_package_invocation_command",
    backend: result.backend ?? RUST_WORKER_SERVICE_PACKAGE_BACKEND,
    thread_id: result.thread_id ?? null,
    agent_id: result.agent_id ?? null,
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
    receipt_refs: stringArray(result.receipt_refs) ?? stringArray(record.receipt_refs) ?? null,
    artifact_refs: stringArray(result.artifact_refs) ?? stringArray(record.artifact_refs) ?? null,
    payload_refs: stringArray(result.payload_refs) ?? stringArray(record.payload_refs) ?? null,
    authority_grant_refs:
      stringArray(result.authority_grant_refs) ?? stringArray(record.authority_grant_refs) ?? null,
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
