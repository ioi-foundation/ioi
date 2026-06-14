export const CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION = "ioi.runtime.daemon_core.command.v1";
export const CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-request.v1";
export const CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-satisfaction-projection-request.v1";
export const CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION =
  "ioi.runtime.coding-tool-approval-block-request.v1";
export const RUST_CODING_TOOL_APPROVAL_BACKEND = "rust_authority";

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
    this.daemonCoreInvoker = optionalFunction(options.daemonCoreInvoker);
  }

  planApprovalManifest(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeDaemonCore({
      schema_version: CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_manifest",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  planApprovalSatisfaction(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeDaemonCore({
      schema_version: CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_satisfaction",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  projectApprovalSatisfaction(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeDaemonCore({
      schema_version: CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION,
      operation: "project_coding_tool_approval_satisfaction",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_SATISFACTION_PROJECTION_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  planApprovalBlock(request = {}) {
    assertCanonicalCodingToolApprovalCoreRequest(request);
    return this.invokeDaemonCore({
      schema_version: CODING_TOOL_APPROVAL_CORE_SCHEMA_VERSION,
      operation: "plan_coding_tool_approval_block",
      backend: RUST_CODING_TOOL_APPROVAL_BACKEND,
      request: {
        ...(objectRecord(request) ?? {}),
        schema_version: CODING_TOOL_APPROVAL_BLOCK_REQUEST_SCHEMA_VERSION,
      },
    });
  }

  invokeDaemonCore(request) {
    if (!this.daemonCoreInvoker) {
      throw new RuntimeCodingToolApprovalCoreError(
        "Coding-tool approval requires daemonCoreInvoker for direct Rust daemon-core authority planning.",
        "coding_tool_approval_core_direct_invoker_unconfigured",
        { boundary: "daemonCoreInvoker" },
      );
    }
    const response = this.daemonCoreInvoker(request);
    if (response?.ok === false) {
      const error = objectRecord(response.error) ?? {};
      throw new RuntimeCodingToolApprovalCoreError(
        error.message ?? "Rust coding-tool approval core rejected the request.",
        error.code ?? "coding_tool_approval_core_direct_invoker_rejected",
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
    "Coding-tool approval command compatibility options are retired; use daemonCoreInvoker for direct Rust daemon-core approval APIs.",
    "coding_tool_approval_core_compatibility_option_retired",
    { retired_option: field, retired_value: value },
  );
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
