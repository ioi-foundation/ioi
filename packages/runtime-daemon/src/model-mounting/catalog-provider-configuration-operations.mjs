import {
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  assertConfigurableCatalogProvider,
  throwCatalogProviderControlRustCoreRequired,
} from "./catalog-provider-config.mjs";

export function listCatalogProviderConfigs(state, deps = {}) {
  void state;
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_configuration.list",
    { configurable_provider_count: MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.length },
    deps,
  );
}

export function getCatalogProviderConfig(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider: assertConfigurableCatalogProviderDep = assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProviderDep(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_configuration.get",
    { provider_id: providerId },
    deps,
  );
}

export function configureCatalogProvider(state, providerId, body = {}, deps = {}) {
  const {
    assertConfigurableCatalogProvider: assertConfigurableCatalogProviderDep = assertConfigurableCatalogProvider,
  } = deps;
  void state;
  assertConfigurableCatalogProviderDep(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_configuration.write",
    { provider_id: providerId, request_field_count: Object.keys(body ?? {}).length },
    deps,
  );
}

export function catalogProviderConfig(state, providerId) {
  return state.catalogProviderConfigs.get(providerId) ?? null;
}

export function catalogProviderRuntimeMaterial(state, providerId, deps = {}) {
  const existing = state.catalogProviderRuntimeMaterials.get(providerId) ?? null;
  const config = state.catalogProviderConfigs.get(providerId) ?? null;
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_runtime_material.resolve",
    {
      provider_id: providerId,
      material_vault_ref_hash: config?.materialVaultRefHash ?? existing?.materialVaultRefHash ?? null,
      material_configured: Boolean(
        config?.materialConfigured ||
          config?.materialVaultRefHash ||
          existing?.manifestPath ||
          existing?.baseUrl ||
          existing?.materialVaultRefHash,
      ),
      runtime_material_status: existing?.runtimeMaterialStatus ?? "rust_core_projection_required",
    },
    deps,
  );
}
