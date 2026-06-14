export const WORKER_SERVICE_PACKAGE_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND = "rust_package_invocation";

const RETIRED_WORKER_SERVICE_PACKAGE_CORE_REQUEST_ALIASES = [
  "packageInvocation",
  "package_invocation",
  "expectedHeads",
  "expected_heads",
];

export function createRuntimeWorkerServicePackageCore(options = {}) {
  return new RuntimeWorkerServicePackageCore(options);
}

export class RuntimeWorkerServicePackageCore {
  constructor(options = {}) {
    assertNoRetiredWorkerServicePackageCoreOption("command", options.command);
    assertNoRetiredWorkerServicePackageCoreOption("args", options.args);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  admitInvocation(request, context = {}) {
    assertCanonicalWorkerServicePackageCoreRequest(request);
    const daemonCoreRequest = {
      schema_version: WORKER_SERVICE_PACKAGE_CORE_SCHEMA_VERSION,
      operation: "admit_worker_service_package_invocation",
      backend: RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      request,
    };
    return this.invokeDaemonCore(daemonCoreRequest);
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeWorkerServicePackageCoreError(
        "Worker/service package invocation admission requires daemonCoreInvoker for direct Rust daemon-core package admission.",
        "worker_service_package_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeWorkerServicePackageCoreError(
        error.message ?? "Rust worker/service package core rejected the invocation.",
        error.code ?? "worker_service_package_core_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalWorkerServicePackageCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_WORKER_SERVICE_PACKAGE_CORE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new RuntimeWorkerServicePackageCoreError(
    "Worker/service package core request aliases are retired; use canonical snake_case Rust daemon-core fields.",
    "worker_service_package_core_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      canonical_fields: ["request"],
    },
  );
}

function assertNoRetiredWorkerServicePackageCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeWorkerServicePackageCoreError(
    "Worker/service package command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core package admission.",
    "worker_service_package_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeWorkerServicePackageCoreError extends Error {
  constructor(message, code = "worker_service_package_core_error", details = {}) {
    super(message);
    this.name = "RuntimeWorkerServicePackageCoreError";
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
