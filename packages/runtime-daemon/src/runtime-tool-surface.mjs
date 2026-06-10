import { optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeToolSurface({
  toolCatalogRunner = null,
  workspaceRoot = null,
} = {}) {
  const fail = (projection) =>
    throwRuntimeToolCatalogProjectionRustCoreRequired({
      toolCatalogRunner,
      workspace_root: workspaceRoot,
      ...projection,
    });

  return {
    getAccount() {
      fail({
        operation: "runtime_account_projection",
        operation_kind: "runtime.tool_catalog.projection.account",
        projection_kind: "account",
      });
    },
    listRuntimeNodes() {
      fail({
        operation: "runtime_nodes_projection",
        operation_kind: "runtime.tool_catalog.projection.runtime_nodes",
        projection_kind: "runtime_nodes",
      });
    },
    listTools(options = {}) {
      fail({
        operation: "runtime_tool_catalog",
        operation_kind: "runtime.tool_catalog.projection.tools",
        projection_kind: "tools",
        pack: optionalString(options.pack)?.toLowerCase() ?? null,
      });
    },
  };
}

function throwRuntimeToolCatalogProjectionRustCoreRequired(details = {}) {
  const { toolCatalogRunner = null, ...errorDetails } = details;
  const evidence_refs = [
    "runtime_tool_catalog_js_projection_retired",
    "rust_daemon_core_runtime_tool_catalog_required",
    "agentgres_runtime_tool_catalog_truth_required",
  ];

  if (toolCatalogRunner?.planRuntimeToolCatalogProjectionRequired) {
    const record = toolCatalogRunner.planRuntimeToolCatalogProjectionRequired({
      ...errorDetails,
      source: "runtime.tool_surface",
      evidence_refs,
    });
    const planned = record?.record ?? record;
    throw createRuntimeToolCatalogProjectionError(planned ?? record, {
      ...errorDetails,
      source: "runtime.tool_surface",
      evidence_refs,
    });
  }

  throw createRuntimeToolCatalogProjectionError(null, {
    ...errorDetails,
    source: "runtime.tool_surface",
    evidence_refs,
  });
}

function createRuntimeToolCatalogProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Runtime account, node, and tool catalog projections require direct Rust daemon-core projection over Agentgres-admitted runtime catalog truth.",
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
