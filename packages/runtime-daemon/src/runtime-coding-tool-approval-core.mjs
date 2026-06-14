export const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-projection-request.v1";
export const CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-block-request.v1";
export const RUST_CODING_TOOL_APPROVAL_BACKEND = "rust_authority";
export const CODING_TOOL_APPROVAL_MANIFEST_API_METHOD = "planCodingToolApprovalManifest";
export const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD =
  "projectCodingToolApprovalSatisfaction";
export const CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD =
  "planCodingToolApprovalSatisfaction";
export const CODING_TOOL_APPROVAL_BLOCK_API_METHOD = "planCodingToolApprovalBlock";

const RETIRED_CODING_TOOL_APPROVAL_CORE_REQUEST_FIELDS = [
  "threadId",
  "turnId",
  "toolId",
  "toolCallId",
  "effectClass",
  "riskDomain",
  "authorityScopeRequirements",
  "primitiveCapabilities",
  "threadMode",
  "approvalMode",
  "trustProfile",
  "requestedMode",
  "normalizedRequestedMode",
  "requestedApprovalMode",
  "uiOverrideRequested",
  "approvalGranted",
  "workflowGraphId",
  "workflowNodeId",
  "workflowPolicy",
  "inputSummary",
  "approvalId",
  "approvalManifest",
  "approvalRequest",
  "latestDecision",
  "leaseState",
  "expectedHead",
  "stateRootBefore",
  "approvalGate",
  "workspaceRoot",
  "idempotencyKey",
  "receiptId",
  "rollbackRefs",
  "receiptRefs",
  "policyDecisionRefs",
  "artifactRefs",
];

export function createRuntimeCodingToolApprovalCore(options = {}) {
  return new RuntimeCodingToolApprovalCore(options);
}

export class RuntimeCodingToolApprovalCore {
  constructor(options = {}) {
    assertNoRetiredCodingToolApprovalCoreOption("command", options.command);
    assertNoRetiredCodingToolApprovalCoreOption("args", options.args);
    assertNoRetiredCodingToolApprovalCoreOption("env", options.env);
    assertNoRetiredCodingToolApprovalCoreOption("daemonCoreInvoker", options.daemonCoreInvoker);
    this.daemonCoreApprovalApi = approvalApi(
      options.daemonCoreApprovalApi ??
        options.daemonCoreApi?.approval ??
        options.daemonCoreApi?.approval_state ??
        options.daemonCoreApi?.approvalState ??
        options.daemonCoreApi,
    );
  }

  planApprovalManifest(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeRustApprovalApi(CODING_TOOL_APPROVAL_MANIFEST_API_METHOD, {
      ...(objectRecord(request) ?? {}),
      schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
    });
  }

  planApprovalSatisfaction(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeRustApprovalApi(CODING_TOOL_APPROVAL_SATISFACTION_API_METHOD, {
      ...(objectRecord(request) ?? {}),
      schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
    });
  }

  projectApprovalSatisfaction(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeRustApprovalApi(CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_API_METHOD, {
      ...(objectRecord(request) ?? {}),
      schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
    });
  }

  planApprovalBlock(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeRustApprovalApi(CODING_TOOL_APPROVAL_BLOCK_API_METHOD, {
      ...(objectRecord(request) ?? {}),
      schema_version: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
    });
  }

  invokeRustApprovalApi(method, request) {
    const invoke = this.daemonCoreApprovalApi?.[method];
    if (typeof invoke !== "function") {
      throw new RuntimeCodingToolApprovalCoreError(
        `Coding-tool approval requires daemonCoreApprovalApi.${method} for Rust daemon-core authority planning.`,
        "coding_tool_approval_core_direct_approval_api_unconfigured",
        { boundary: `daemonCoreApprovalApi.${method}`, backend: RUST_CODING_TOOL_APPROVAL_BACKEND },
      );
    }
    const response = invoke.call(this.daemonCoreApprovalApi, request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeCodingToolApprovalCoreError(
        error.message ?? "Rust coding-tool approval core rejected the request.",
        error.code ?? "coding_tool_approval_core_direct_approval_api_rejected",
        { error },
      );
    }
    return response?.ok === true ? response.result : response;
  }
}

export class RuntimeCodingToolApprovalCoreError extends Error {
  constructor(message, code = "coding_tool_approval_core_error", details = {}) {
    super(message);
    this.name = "RuntimeCodingToolApprovalCoreError";
    this.status = details.status ?? 502;
    this.code = code;
    this.details = details;
  }
}

function assertCanonicalCodingToolApprovalCoreRequest(request = {}) {
  const record = objectRecord(request) ?? {};
  const retiredAliases = RETIRED_CODING_TOOL_APPROVAL_CORE_REQUEST_FIELDS.filter((field) =>
    Object.hasOwn(record, field),
  );
  if (retiredAliases.length === 0) return;
  throw new RuntimeCodingToolApprovalCoreError(
    "Coding-tool approval core request aliases are retired; use canonical snake_case Rust daemon-core fields.",
    "coding_tool_approval_core_request_aliases_retired",
    {
      status: 400,
      retired_aliases: retiredAliases,
    },
  );
}

function assertNoRetiredCodingToolApprovalCoreOption(field, value) {
  if (Array.isArray(value) && value.length === 0) return;
  if (typeof value === "string" && value.trim().length === 0) return;
  if (value == null) return;
  throw new RuntimeCodingToolApprovalCoreError(
    "Coding-tool approval command compatibility options are retired; use daemonCoreApprovalApi for direct Rust daemon-core approval APIs.",
    "coding_tool_approval_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function approvalApi(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value;
}
