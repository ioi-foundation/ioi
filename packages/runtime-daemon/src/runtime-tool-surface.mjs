import { normalizeArray, objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeToolSurface({
  env = process.env,
  toolCatalogRunner = null,
  workspaceRoot = null,
} = {}) {
  const project = (projection) => {
    if (!toolCatalogRunner?.projectRuntimeToolCatalog) {
      throwRuntimeToolCatalogRustCoreRequired({
        ...projection,
        source: "runtime.tool_surface",
        workspace_root: workspaceRoot,
      });
    }
    const result = toolCatalogRunner.projectRuntimeToolCatalog({
      operation: "runtime_tool_catalog",
      source: "runtime.tool_surface",
      workspace_root: workspaceRoot,
      ...projection,
      operator_email: optionalString(env.IOI_OPERATOR_EMAIL),
      hosted_endpoint_configured: Boolean(optionalString(env.IOI_AGENT_SDK_HOSTED_ENDPOINT)),
      self_hosted_endpoint_configured: Boolean(optionalString(env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT)),
    });
    if (result.projection_kind !== projection.projection_kind) {
      throwRuntimeToolCatalogProjectionInvalid(result, projection);
    }
    return result;
  };

  return {
    getAccount() {
      const result = project({
        operation_kind: "runtime.tool_catalog.projection.account",
        projection_kind: "account",
      });
      const account = objectRecord(result.account);
      if (!account) throwRuntimeToolCatalogProjectionInvalid(result, { projection_kind: "account" });
      return account;
    },
    listRuntimeNodes() {
      const result = project({
        operation_kind: "runtime.tool_catalog.projection.runtime_nodes",
        projection_kind: "runtime_nodes",
      });
      return normalizeArray(result.runtime_nodes);
    },
    listTools(options = {}) {
      const result = project({
        operation_kind: "runtime.tool_catalog.projection.tools",
        projection_kind: "tools",
        pack: optionalString(options.pack)?.toLowerCase() ?? null,
      });
      return normalizeArray(result.tools);
    },
  };
}

function throwRuntimeToolCatalogRustCoreRequired(errorDetails = {}) {
  throw createRuntimeToolCatalogProjectionError(null, {
    ...errorDetails,
    evidence_refs: [
      "runtime_tool_catalog_js_projection_retired",
      "rust_daemon_core_runtime_tool_catalog_projection_required",
      "agentgres_runtime_tool_catalog_truth_required",
    ],
  });
}

function throwRuntimeToolCatalogProjectionInvalid(record, expected) {
  const error = new Error("Rust runtime tool catalog projection did not match the requested public projection.");
  error.status = 502;
  error.code = "runtime_tool_catalog_rust_projection_invalid";
  error.details = {
    rust_core_boundary: "runtime.tool_catalog",
    expected_projection_kind: expected.projection_kind,
    projection_kind: record?.projection_kind ?? null,
    operation_kind: record?.operation_kind ?? null,
  };
  throw error;
}

function createRuntimeToolCatalogProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Runtime account, node, and tool catalog projections require Rust daemon-core projection over Agentgres-admitted runtime catalog truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_tool_catalog_rust_core_required";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.tool_catalog",
    ...fallbackDetails,
  };
  return error;
}
