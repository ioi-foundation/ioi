export function modelCatalogProviderPorts({
  state,
  fixtureCatalogProviderPort,
  localManifestCatalogProviderPort,
  ollamaCatalogProviderPort,
  huggingFaceCatalogProviderPort,
  customHttpCatalogProviderPort,
}) {
  return [
    fixtureCatalogProviderPort(),
    localManifestCatalogProviderPort(state),
    ollamaCatalogProviderPort(state),
    huggingFaceCatalogProviderPort(state),
    customHttpCatalogProviderPort(state),
  ];
}

export function catalogProviderStatus(port, result = null) {
  const health = typeof port.health === "function" ? port.health() : {};
  return {
    id: port.id,
    label: port.label,
    status: result?.status ?? health.status ?? port.status ?? "unknown",
    gate: port.gate ?? health.gate ?? null,
    downloadGate: port.downloadGate ?? health.downloadGate ?? null,
    liveDownloadStatus: result?.liveDownloadStatus ?? health.liveDownloadStatus ?? null,
    formats: port.formats ?? [],
    enabled: result?.enabled ?? health.enabled ?? null,
    configHash: result?.configHash ?? health.configHash ?? null,
    baseUrlHash: result?.baseUrlHash ?? health.baseUrlHash ?? null,
    manifestPathHash: result?.manifestPathHash ?? health.manifestPathHash ?? null,
    authVaultRefHash: result?.authVaultRefHash ?? health.authVaultRefHash ?? null,
    catalogAuthConfigured: result?.catalogAuthConfigured ?? health.catalogAuthConfigured ?? null,
    catalogAuthResolved: result?.catalogAuthResolved ?? health.catalogAuthResolved ?? null,
    catalogAuthScheme: result?.catalogAuthScheme ?? health.catalogAuthScheme ?? null,
    catalogAuthHeaderNameHash: result?.catalogAuthHeaderNameHash ?? health.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: result?.catalogAuthEvidenceRefs ?? health.catalogAuthEvidenceRefs ?? [],
    oauthBoundary: result?.oauthBoundary ?? health.oauthBoundary ?? null,
    oauthSessionHash: result?.oauthSessionHash ?? health.oauthSessionHash ?? result?.oauthBoundary?.oauthSessionHash ?? health.oauthBoundary?.oauthSessionHash ?? null,
    materialVaultRefHash: result?.materialVaultRefHash ?? health.materialVaultRefHash ?? null,
    materialConfigured: result?.materialConfigured ?? health.materialConfigured ?? null,
    materialPersistence: result?.materialPersistence ?? health.materialPersistence ?? null,
    runtimeMaterialStatus: result?.runtimeMaterialStatus ?? health.runtimeMaterialStatus ?? null,
    vaultMaterialSource: result?.vaultMaterialSource ?? health.vaultMaterialSource ?? null,
    providerId: port.providerId ?? null,
    errorHash: result?.errorHash ?? health.errorHash ?? null,
    adapterPort: "ModelCatalogProviderPort",
    operations: ["search", "resolveVariant", "importUrl", "download", "health"],
    evidenceRefs: result?.evidenceRefs ?? health.evidenceRefs ?? port.evidenceRefs ?? [],
  };
}
