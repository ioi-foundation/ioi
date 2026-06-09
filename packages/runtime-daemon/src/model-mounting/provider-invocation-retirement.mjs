import { runtimeError } from "./io.mjs";

export function retiredJsProviderInvocationError(provider = {}, { label = "provider", stream = false } = {}) {
  return runtimeError({
    status: 501,
    code: "model_mount_provider_js_invocation_retired",
    message: "Provider invocation must execute through Rust model_mount.",
    details: {
      provider_id: provider.id ?? null,
      provider_kind: provider.kind ?? null,
      provider_driver: provider.driver ?? label,
      stream,
      rust_core_boundary: "model_mount.provider_invocation",
      evidence_refs: [
        "model_mount_provider_js_invocation_retired",
        "rust_daemon_core_provider_invocation_required",
        "agentgres_provider_execution_truth_required",
      ],
    },
  });
}
