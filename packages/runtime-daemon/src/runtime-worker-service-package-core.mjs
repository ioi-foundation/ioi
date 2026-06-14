export const RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND = "rust_package_invocation";
export const WORKER_SERVICE_PACKAGE_CORE_API_METHOD = "admitWorkerServicePackageInvocation";

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
    assertNoRetiredWorkerServicePackageCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    this.daemonCoreWorkerServiceApi = workerServiceApi(
      options.daemonCoreWorkerServiceApi ??
        options.daemonCoreApi?.worker_service ??
        options.daemonCoreApi?.workerService ??
        options.daemonCoreApi,
    );
  }

  admitInvocation(request, context = {}) {
    assertCanonicalWorkerServicePackageCoreRequest(request);
    const routeContext = {
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
    };
    return this.invokeRustWorkerServiceApi(request, routeContext);
  }

  invokeRustWorkerServiceApi(request, context = {}) {
    if (!this.daemonCoreWorkerServiceApi) {
      throw new RuntimeWorkerServicePackageCoreError(
        "Worker/service package invocation admission requires daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation for Rust daemon-core package admission.",
        "worker_service_package_core_direct_worker_service_api_unconfigured",
        {
          boundary: "daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation",
          backend: RUNTIME_WORKER_SERVICE_PACKAGE_BACKEND,
        },
      );
    }
    const response = this.daemonCoreWorkerServiceApi[WORKER_SERVICE_PACKAGE_CORE_API_METHOD](
      request,
      context,
    );
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeWorkerServicePackageCoreError(
        error.message ?? "Rust worker/service package core rejected the invocation.",
        error.code ?? "worker_service_package_core_direct_worker_service_api_rejected",
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
    "Worker/service package command compatibility options are retired; use daemonCoreWorkerServiceApi.admitWorkerServicePackageInvocation for Rust daemon-core package admission.",
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

function workerServiceApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return typeof value[WORKER_SERVICE_PACKAGE_CORE_API_METHOD] === "function"
    ? value
    : null;
}
