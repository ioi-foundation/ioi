import { runtimeError } from "./io.mjs";

const RETIRED_PROVIDER_UPSERT_REQUEST_ALIASES = [
  "authScheme",
  "authHeaderName",
  "apiFormat",
  "baseUrl",
  "privacyClass",
  "evidenceRefs",
];

const CANONICAL_PROVIDER_UPSERT_REQUEST_FIELDS = [
  "auth_scheme",
  "auth_header_name",
  "api_format",
  "base_url",
  "privacy_class",
  "evidence_refs",
];

export function upsertProvider(state, body = {}, deps = {}) {
  const {
    safeId,
  } = deps;
  assertCanonicalProviderUpsertRequestBody(body);
  const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
  const existing = state.providers.get(id) ?? {};
  const kind = body.kind ?? existing.kind ?? "custom_http";
  throw providerControlRustCoreRequired({
    id,
    kind,
  }, "provider_upsert", {
    operation_kind: "model_mount.provider.write",
  });
}

function assertCanonicalProviderUpsertRequestBody(body = {}) {
  const retiredAliases = RETIRED_PROVIDER_UPSERT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "provider_upsert_request_aliases_retired",
    message: "Provider upsert request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_PROVIDER_UPSERT_REQUEST_FIELDS,
    },
  });
}

export function normalizeProviderSecretRef(state, kind, body = {}, existingSecretRef = null, deps = {}) {
  const {
    assertNoPlaintextProviderSecret,
    providerRequiresVaultSecret,
    providerSecretInput,
  } = deps;
  assertNoPlaintextProviderSecret(body);
  const secretRef = providerSecretInput(body);
  const normalized = secretRef === undefined ? existingSecretRef : secretRef || null;
  if (normalized) state.walletAuthority.resolveVaultRef(normalized);
  if (providerRequiresVaultSecret(kind) && !normalized) return null;
  return normalized;
}

export async function providerHealth(state, providerId, deps = {}) {
  const provider = state.provider(providerId);
  throwProviderHealthRustCoreRequired(provider, "provider_health", {
    operation_kind: "model_mount.provider.health",
  });
}

export async function listProviderModels(state, providerId) {
  const provider = state.provider(providerId);
  throwProviderInventoryRustCoreRequired(provider, "provider_models_list", {
    operation_kind: "model_mount.provider.inventory.list_models",
  });
}

export async function listProviderLoaded(state, providerId) {
  const provider = state.provider(providerId);
  throwProviderInventoryRustCoreRequired(provider, "provider_loaded_list", {
    operation_kind: "model_mount.provider.inventory.list_loaded",
  });
}

export async function startProvider(state, providerId, deps = {}) {
  const provider = state.provider(providerId);
  throw providerControlRustCoreRequired(provider, "provider_start");
}

export async function stopProvider(state, providerId, deps = {}) {
  const provider = state.provider(providerId);
  throw providerControlRustCoreRequired(provider, "provider_stop");
}

function providerControlRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider control requires direct Rust daemon-core support.");
  error.status = 501;
  error.code = "model_mount_provider_control_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_control",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    evidence_refs: [
      "model_mount_provider_control_js_facade_retired",
      "rust_daemon_core_provider_control_required",
      "wallet_network_vault_authority_required",
    ],
  };
  return error;
}

function throwProviderHealthRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider health requires direct Rust daemon-core support.");
  error.status = 501;
  error.code = "model_mount_provider_health_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_health",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_provider_health_js_facade_retired",
      "rust_daemon_core_provider_health_required",
      "agentgres_provider_health_record_truth_required",
    ],
  };
  throw error;
}

function throwProviderInventoryRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider inventory reads require direct Rust daemon-core projection support.");
  error.status = 501;
  error.code = "model_mount_provider_inventory_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_inventory",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
    evidence_refs: [
      "model_mount_provider_inventory_js_facade_retired",
      "rust_daemon_core_provider_inventory_required",
      "agentgres_provider_inventory_projection_required",
    ],
  };
  throw error;
}
