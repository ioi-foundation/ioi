import {
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  assertConfigurableCatalogProvider,
  catalogProviderHasSourceMaterial,
  catalogProviderMaterialPurpose,
  catalogProviderMaterialVaultRef,
  catalogProviderRuntimeMaterialFromValue,
  throwCatalogProviderControlRustCoreRequired,
} from "./catalog-provider-config.mjs";
import { publicCatalogProviderConfig } from "./catalog-projections.mjs";
import { catalogProviderStatus } from "./catalog-registry.mjs";
import {
  normalizeScopes,
  stableHash,
} from "./io.mjs";

export function listCatalogProviderConfigs(state, deps = {}) {
  const {
    configurableProviderIds = MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
    publicCatalogProviderConfig: publicCatalogProviderConfigDep = publicCatalogProviderConfig,
  } = deps;
  return configurableProviderIds.map((providerId) =>
    publicCatalogProviderConfigDep(
      providerId,
      state.catalogProviderConfigs.get(providerId),
      state.catalogProviderRuntimeMaterial(providerId),
    ),
  );
}

export function getCatalogProviderConfig(state, providerId, deps = {}) {
  const {
    assertConfigurableCatalogProvider: assertConfigurableCatalogProviderDep = assertConfigurableCatalogProvider,
    catalogProviderStatus: catalogProviderStatusDep = catalogProviderStatus,
    publicCatalogProviderConfig: publicCatalogProviderConfigDep = publicCatalogProviderConfig,
  } = deps;
  assertConfigurableCatalogProviderDep(providerId);
  const port = state.catalogProviderPorts().find((candidate) => candidate.id === providerId) ?? null;
  return {
    ...publicCatalogProviderConfigDep(
      providerId,
      state.catalogProviderConfigs.get(providerId),
      state.catalogProviderRuntimeMaterial(providerId),
    ),
    provider: port ? catalogProviderStatusDep(port) : null,
  };
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
    catalogProviderMaterialPurpose: catalogProviderMaterialPurposeDep = catalogProviderMaterialPurpose,
    catalogProviderMaterialVaultRef: catalogProviderMaterialVaultRefDep = catalogProviderMaterialVaultRef,
    catalogProviderRuntimeMaterialFromValue: catalogProviderRuntimeMaterialFromValueDep = catalogProviderRuntimeMaterialFromValue,
    normalizeScopes: normalizeScopesDep = normalizeScopes,
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
  const purpose = catalogProviderMaterialPurposeDep(providerId);
  try {
    const resolved = state.vault.resolveVaultRef(vaultRef, purpose);
    if (!resolved.resolvedMaterial || typeof resolved.material !== "string" || !resolved.material.trim()) {
      return {
        runtimeMaterialStatus: "missing_runtime_material",
        materialSource: resolved.materialSource ?? "unbound",
        materialVaultRefHash: resolved.vaultRefHash,
        evidenceRefs: normalizeScopesDep(
          resolved.evidenceRefs,
          ["VaultPort.resolveVaultRef", "catalog_provider_source_material_unbound"],
        ),
      };
    }
    return {
      ...catalogProviderRuntimeMaterialFromValueDep(providerId, resolved.material),
      runtimeMaterialStatus: "resolved_from_vault",
      materialSource: resolved.materialSource ?? "vault_material_adapter",
      materialVaultRefHash: resolved.vaultRefHash,
      evidenceRefs: normalizeScopesDep(
        resolved.evidenceRefs,
        ["VaultPort.resolveVaultRef", "catalog_provider_source_material_resolved"],
      ),
    };
  } catch (error) {
    return {
      runtimeMaterialStatus: "vault_material_unavailable",
      materialSource: "unavailable",
      materialVaultRefHash: config.materialVaultRefHash ?? stableHashDep(vaultRef),
      errorHash: stableHashDep(error?.message ?? "catalog source vault resolution failed"),
      evidenceRefs: ["VaultPort.resolveVaultRef", "catalog_provider_source_material_fail_closed"],
    };
  }
}
