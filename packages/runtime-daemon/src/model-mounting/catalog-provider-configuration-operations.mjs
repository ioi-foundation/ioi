import {
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  assertConfigurableCatalogProvider,
  catalogProviderHasSourceMaterial,
  catalogProviderMaterialVaultRef,
  throwCatalogProviderControlRustCoreRequired,
} from "./catalog-provider-config.mjs";
import {
  stableHash,
} from "./io.mjs";

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
  const {
    catalogProviderHasSourceMaterial: catalogProviderHasSourceMaterialDep = catalogProviderHasSourceMaterial,
    catalogProviderMaterialVaultRef: catalogProviderMaterialVaultRefDep = catalogProviderMaterialVaultRef,
    stableHash: stableHashDep = stableHash,
  } = deps;
  const existing = state.catalogProviderRuntimeMaterials.get(providerId) ?? null;
  if (catalogProviderHasSourceMaterialDep(existing)) return existing;
  if (
    existing?.runtimeMaterialStatus === "missing_runtime_material" ||
    existing?.runtimeMaterialStatus === "vault_material_unavailable"
  ) {
    return existing;
  }
  const config = state.catalogProviderConfigs.get(providerId) ?? null;
  if (!config?.materialConfigured && !config?.materialVaultRefHash) return existing;
  const vaultRef = catalogProviderMaterialVaultRefDep(providerId);
  throwCatalogProviderControlRustCoreRequired(
    "model_mount.catalog_provider_runtime_material.resolve",
    {
      provider_id: providerId,
      material_vault_ref_hash: config.materialVaultRefHash ?? stableHashDep(vaultRef),
      material_configured: Boolean(config.materialConfigured || config.materialVaultRefHash),
      runtime_material_status: existing?.runtimeMaterialStatus ?? "requires_rust_core_custody",
    },
    deps,
  );
}
