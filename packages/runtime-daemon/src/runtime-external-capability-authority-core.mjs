export const EXTERNAL_CAPABILITY_AUTHORITY_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND = "rust_authority";

const RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_CORE_REQUEST_ALIASES = [
  "request",
  "authorityRequest",
  "authority_request",
  "capabilityExit",
  "capability_exit",
  "schemaVersion",
  "exitRef",
  "capabilityRef",
  "targetRef",
  "policyHash",
  "idempotencyKey",
  "authorityGrantRefs",
  "authorityReceiptRefs",
  "walletNetworkGrantRefs",
  "authorityHash",
  "exitAuthorized",
  "directTruthWriteAllowed",
  "threadId",
  "agentId",
];

const RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_CORE_TRUTH_FIELDS = [
  "wallet_network_grant_refs",
  "authority_hash",
  "exit_authorized",
  "direct_truth_write_allowed",
  "thread_id",
  "agent_id",
  "source",
  "backend",
  "status",
  "object",
];

export function createRuntimeExternalCapabilityAuthorityCore(options = {}) {
  return new RuntimeExternalCapabilityAuthorityCore(options);
}

export class RuntimeExternalCapabilityAuthorityCore {
  constructor(options = {}) {
    assertNoRetiredExternalCapabilityAuthorityCoreOption("command", options.command);
    assertNoRetiredExternalCapabilityAuthorityCoreOption("args", options.args);
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  authorizeExit(request, context = {}) {
    assertCanonicalExternalCapabilityAuthorityCoreRequest(request);
    const daemonCoreRequest = {
      schema_version: EXTERNAL_CAPABILITY_AUTHORITY_CORE_SCHEMA_VERSION,
      operation: "authorize_external_capability_exit",
      backend: RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
      thread_id: optionalString(context.thread_id),
      agent_id: optionalString(context.agent_id),
      request,
    };
    return this.invokeDaemonCore(daemonCoreRequest);
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeExternalCapabilityAuthorityCoreError(
        "External capability exits require daemonCoreInvoker for direct Rust daemon-core wallet.network authority.",
        "external_capability_authority_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeExternalCapabilityAuthorityCoreError(
        error.message ?? "Rust authority core rejected the external capability exit.",
        error.code ?? "external_capability_authority_core_direct_invoker_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

function assertCanonicalExternalCapabilityAuthorityCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_CORE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(record, field),
  );
  const retiredTruthFields = RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_CORE_TRUTH_FIELDS.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0 && retiredTruthFields.length === 0) return;
  throw new RuntimeExternalCapabilityAuthorityCoreError(
    "External capability authority core request aliases and Rust authority truth fields are retired; use canonical snake_case request fields and Rust-derived wallet.network truth.",
    "external_capability_authority_core_request_fields_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
      retired_truth_fields: retiredTruthFields,
      canonical_fields: [
        "schema_version",
        "exit_ref",
        "capability_ref",
        "target_ref",
        "policy_hash",
        "idempotency_key",
        "authority_grant_refs",
        "authority_receipt_refs",
      ],
      derived_by: RUNTIME_EXTERNAL_CAPABILITY_AUTHORITY_BACKEND,
    },
  );
}

function assertNoRetiredExternalCapabilityAuthorityCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeExternalCapabilityAuthorityCoreError(
    "External capability authority command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core wallet.network authority.",
    "external_capability_authority_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

export class RuntimeExternalCapabilityAuthorityCoreError extends Error {
  constructor(message, code = "external_capability_authority_core_error", details = {}) {
    super(message);
    this.name = "RuntimeExternalCapabilityAuthorityCoreError";
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
