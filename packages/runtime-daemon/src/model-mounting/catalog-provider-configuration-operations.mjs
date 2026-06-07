import {
  MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS,
  assertConfigurableCatalogProvider,
  catalogProviderConfigUpdate,
  catalogProviderHasSourceMaterial,
  catalogProviderMaterialPurpose,
  catalogProviderMaterialVaultRef,
  catalogProviderRuntimeMaterialFromValue,
} from "./catalog-provider-config.mjs";
import { publicCatalogProviderConfig } from "./catalog-projections.mjs";
import { catalogProviderStatus } from "./catalog-registry.mjs";
import {
  normalizeScopes,
  stableHash,
} from "./io.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

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
    catalogProviderConfigUpdate: catalogProviderConfigUpdateDep = catalogProviderConfigUpdate,
    catalogProviderStatus: catalogProviderStatusDep = catalogProviderStatus,
    publicCatalogProviderConfig: publicCatalogProviderConfigDep = publicCatalogProviderConfig,
  } = deps;
  assertConfigurableCatalogProviderDep(providerId);
  const existing = state.catalogProviderConfigs.get(providerId);
  const update = catalogProviderConfigUpdateDep(providerId, body, existing, state.nowIso(), state);
  const { record, runtimeMaterial, evidenceRefs } = update;
  const publicRecord = publicCatalogProviderConfigDep(
    providerId,
    record,
    runtimeMaterial,
  );
  const receipt = state.receipt("model_catalog_provider_configuration", {
    summary: `${providerId} catalog configuration updated through the governed catalog provider path.`,
    redaction: "redacted",
    evidenceRefs: ["ModelCatalogProviderPort.configure", providerId, ...evidenceRefs],
    details: publicRecord,
  });
  commitModelMountRecordState(state, {
    recordDir: "model-catalog-providers",
    record: { ...record, receiptId: receipt.id },
    operation_kind: "model_mount.catalog_provider_configuration.write",
    receipt_refs: [receipt.id],
    unconfiguredCode: "model_mount_catalog_provider_configuration_state_commit_unconfigured",
    unconfiguredMessage:
      "Catalog provider configuration persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: { provider_id: providerId },
  });
  state.catalogProviderConfigs.set(providerId, { ...record, receiptId: receipt.id });
  if (runtimeMaterial) state.catalogProviderRuntimeMaterials.set(providerId, runtimeMaterial);
  else state.catalogProviderRuntimeMaterials.delete(providerId);
  state.writeProjection();
  return {
    ...publicRecord,
    receiptId: receipt.id,
    provider: catalogProviderStatusDep(state.catalogProviderPorts().find((port) => port.id === providerId)),
  };
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
    state.writeVaultRefs();
    if (!resolved.resolvedMaterial || typeof resolved.material !== "string" || !resolved.material.trim()) {
      const missing = {
        runtimeMaterialStatus: "missing_runtime_material",
        materialSource: resolved.materialSource ?? "unbound",
        materialVaultRefHash: resolved.vaultRefHash,
        evidenceRefs: normalizeScopesDep(
          resolved.evidenceRefs,
          ["VaultPort.resolveVaultRef", "catalog_provider_source_material_unbound"],
        ),
      };
      state.catalogProviderRuntimeMaterials.set(providerId, missing);
      return missing;
    }
    const material = {
      ...catalogProviderRuntimeMaterialFromValueDep(providerId, resolved.material),
      runtimeMaterialStatus: "resolved_from_vault",
      materialSource: resolved.materialSource ?? "vault_material_adapter",
      materialVaultRefHash: resolved.vaultRefHash,
      evidenceRefs: normalizeScopesDep(
        resolved.evidenceRefs,
        ["VaultPort.resolveVaultRef", "catalog_provider_source_material_resolved"],
      ),
    };
    state.catalogProviderRuntimeMaterials.set(providerId, material);
    return material;
  } catch (error) {
    const failed = {
      runtimeMaterialStatus: "vault_material_unavailable",
      materialSource: "unavailable",
      materialVaultRefHash: config.materialVaultRefHash ?? stableHashDep(vaultRef),
      errorHash: stableHashDep(error?.message ?? "catalog source vault resolution failed"),
      evidenceRefs: ["VaultPort.resolveVaultRef", "catalog_provider_source_material_fail_closed"],
    };
    state.catalogProviderRuntimeMaterials.set(providerId, failed);
    return failed;
  }
}
