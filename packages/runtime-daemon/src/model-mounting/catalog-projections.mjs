import path from "node:path";

import { normalizeScopes, stableHash } from "./io.mjs";

export function catalogAuthProviderFields(evidence = null) {
  if (!evidence) return {};
  return {
    authVaultRefHash: evidence.authVaultRefHash ?? null,
    catalogAuthConfigured: true,
    catalogAuthResolved: Boolean(evidence.resolvedMaterial ?? evidence.catalogAuthResolved),
    catalogAuthScheme: evidence.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: evidence.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: normalizeScopes(evidence.evidenceRefs, []),
    oauthBoundary: evidence.oauthBoundary ?? null,
  };
}

export function publicCatalogAuthEvidence(evidence = null) {
  if (!evidence) return null;
  return {
    authVaultRefHash: evidence.authVaultRefHash ?? null,
    resolvedMaterial: Boolean(evidence.resolvedMaterial ?? evidence.catalogAuthResolved),
    catalogAuthScheme: evidence.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: evidence.catalogAuthHeaderNameHash ?? null,
    evidenceRefs: normalizeScopes(evidence.evidenceRefs, []),
    oauthBoundary: evidence.oauthBoundary ?? null,
  };
}

export function catalogEntryWithAuth(entry, evidence = null) {
  if (!evidence) return entry;
  return {
    ...entry,
    catalogAuth: publicCatalogAuthEvidence(evidence),
  };
}

export function catalogAuthFailureStatus(error) {
  if (error?.status === 403 || error?.code === "policy") return "blocked";
  return "degraded";
}

export function catalogAuthFailureFields(error) {
  const details = error?.details && typeof error.details === "object" ? error.details : {};
  if (!details.authVaultRefHash && !details.catalogAuthHeaderNameHash && !details.catalogAuthScheme && !details.oauthSessionHash) return {};
  return {
    authVaultRefHash: details.authVaultRefHash ?? null,
    catalogAuthConfigured: true,
    catalogAuthResolved: false,
    catalogAuthScheme: details.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: details.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: normalizeScopes(details.evidenceRefs, ["catalog_auth_fail_closed"]),
    oauthSessionHash: details.oauthSessionHash ?? details.oauthBoundary?.oauthSessionHash ?? null,
    oauthBoundary: details.oauthBoundary ?? null,
  };
}

export function publicCatalogProviderConfig(providerId, record = null, material = null) {
  const materialConfigured = Boolean(record?.materialConfigured ?? material?.manifestPath ?? material?.baseUrl);
  return {
    id: providerId,
    enabled: record?.enabled ?? true,
    configHash: record?.configHash ?? null,
    manifestPathHash: record?.manifestPathHash ?? (material?.manifestPath ? stableHash(path.resolve(material.manifestPath)) : null),
    baseUrlHash: record?.baseUrlHash ?? (material?.baseUrl ? stableHash(material.baseUrl) : null),
    authVaultRefHash: record?.authVaultRefHash ?? material?.authVaultRefHash ?? null,
    catalogAuthConfigured: Boolean(record?.catalogAuthConfigured ?? record?.authVaultRefHash ?? false),
    catalogAuthScheme: record?.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: record?.catalogAuthHeaderNameHash ?? null,
    oauthSessionHash: record?.oauthSessionHash ?? (record?.oauthSessionId ? stableHash(record.oauthSessionId) : null),
    oauthBoundary: record?.oauthBoundary ?? null,
    materialVaultRefHash: record?.materialVaultRefHash ?? material?.materialVaultRefHash ?? null,
    materialConfigured,
    materialPersistence: record?.materialPersistence ?? "metadata_only",
    runtimeMaterialStatus: materialConfigured
      ? material?.runtimeMaterialStatus
        ? material.runtimeMaterialStatus
        : material?.manifestPath || material?.baseUrl
          ? "bound_runtime_session"
          : record?.runtimeMaterialStatus ?? "missing_runtime_material"
      : "unconfigured",
    vaultMaterialSource: material?.materialSource ?? record?.vaultMaterialSource ?? null,
    errorHash: material?.errorHash ?? record?.errorHash ?? null,
    updatedAt: record?.updatedAt ?? null,
    evidenceRefs: normalizeScopes(
      [...normalizeScopes(record?.evidenceRefs, ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"]), ...normalizeScopes(material?.evidenceRefs, [])],
      ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"],
    ),
  };
}

export function catalogProviderConfigHealthFields(providerId, config = null, material = null) {
  const publicConfig = publicCatalogProviderConfig(providerId, config, material);
  return {
    enabled: publicConfig.enabled,
    configHash: publicConfig.configHash,
    manifestPathHash: publicConfig.manifestPathHash,
    baseUrlHash: publicConfig.baseUrlHash,
    authVaultRefHash: publicConfig.authVaultRefHash,
    catalogAuthConfigured: publicConfig.catalogAuthConfigured,
    catalogAuthScheme: publicConfig.catalogAuthScheme,
    catalogAuthHeaderNameHash: publicConfig.catalogAuthHeaderNameHash,
    oauthSessionHash: publicConfig.oauthSessionHash,
    oauthBoundary: publicConfig.oauthBoundary,
    materialVaultRefHash: publicConfig.materialVaultRefHash,
    materialConfigured: publicConfig.materialConfigured,
    materialPersistence: publicConfig.materialPersistence,
    runtimeMaterialStatus: publicConfig.runtimeMaterialStatus,
    vaultMaterialSource: publicConfig.vaultMaterialSource,
    errorHash: publicConfig.errorHash,
  };
}
