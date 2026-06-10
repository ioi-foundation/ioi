import {
  runtimeError,
} from "./io.mjs";

export const MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS = ["catalog.local_manifest", "catalog.custom_http", "catalog.huggingface"];

export function assertConfigurableCatalogProvider(providerId) {
  if (!MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.includes(providerId)) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `Catalog provider is not configurable: ${providerId}`,
      details: { provider_id: providerId },
    });
  }
}

export function throwCatalogProviderControlRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_catalog_provider_control_rust_core_required",
    message:
      "Catalog provider configuration, OAuth, and auth-header mutation facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.catalog_provider_control",
      evidence_refs: [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}
