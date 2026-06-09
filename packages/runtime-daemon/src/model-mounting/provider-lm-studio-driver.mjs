import { retiredJsProviderInvocationError } from "./provider-invocation-retirement.mjs";

export class LmStudioModelProviderDriver {
  async health(provider) {
    throw lmStudioDriverRustCoreRequired(provider, "provider_health", {
      operation_kind: "model_mount.provider.health",
    });
  }

  async listModels({ provider }) {
    throw lmStudioDriverRustCoreRequired(provider, "provider_models_list", {
      operation_kind: "model_mount.provider.inventory.list_models",
    });
  }

  async listLoaded({ provider }) {
    throw lmStudioDriverRustCoreRequired(provider, "provider_loaded_list", {
      operation_kind: "model_mount.provider.inventory.list_loaded",
    });
  }

  async start({ provider }) {
    throw lmStudioDriverRustCoreRequired(provider, "provider_start", {
      operation_kind: "model_mount.provider.start",
    });
  }

  async stop({ provider }) {
    throw lmStudioDriverRustCoreRequired(provider, "provider_stop", {
      operation_kind: "model_mount.provider.stop",
    });
  }

  async load({ provider, endpoint, body = {} }) {
    throw lmStudioDriverRustCoreRequired(provider, "model_load", {
      operation_kind: "model_mount.instance.load",
      endpoint_id: endpoint?.id ?? null,
      model_id: endpoint?.modelId ?? null,
      backend_id: endpoint?.backendId ?? "backend.lmstudio",
    });
  }

  async unload({ provider, instance, endpoint }) {
    throw lmStudioDriverRustCoreRequired(provider, "model_unload", {
      operation_kind: "model_mount.instance.unload",
      instance_id: instance?.id ?? null,
      endpoint_id: endpoint?.id ?? instance?.endpointId ?? null,
      model_id: instance?.modelId ?? endpoint?.modelId ?? null,
      backend_id: endpoint?.backendId ?? instance?.backendId ?? "backend.lmstudio",
    });
  }

  async invoke(args) {
    throw retiredJsProviderInvocationError(args.provider, { label: "lm_studio", stream: false });
  }

  supportsStream(kind) {
    return false;
  }

  async streamInvoke(args) {
    throw retiredJsProviderInvocationError(args.provider, { label: "lm_studio", stream: true });
  }

}

function lmStudioDriverRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("LM Studio provider control and inventory require direct Rust daemon-core model_mount support.");
  error.status = 501;
  error.code = "model_mount_lm_studio_public_cli_retired";
  error.details = {
    rust_core_boundary: "model_mount.provider_lm_studio",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? "lm_studio",
    evidence_refs: [
      "lm_studio_public_cli_driver_retired",
      "rust_daemon_core_provider_control_required",
      "rust_daemon_core_provider_inventory_required",
      "agentgres_provider_projection_required",
    ],
  };
  return error;
}
