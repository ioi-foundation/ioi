export function importModel(state, body = {}, deps = {}) {
  const {
    importTargetPath,
    inspectLocalArtifact,
    materializeImportArtifact,
    normalizeImportMode,
    normalizeScopes,
    parseLocalModelMetadata,
    requiredString,
    safeId,
    schemaVersion,
    stableHash,
  } = deps;
  const now = state.nowIso();
  const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
  const sourcePath = body.path ?? body.source_path ?? body.sourcePath ?? body.local_path ?? body.localPath ?? null;
  const sourceInfo = sourcePath ? inspectLocalArtifact(sourcePath) : null;
  const importMode = normalizeImportMode(body.import_mode ?? body.importMode ?? body.mode ?? (sourceInfo ? "reference" : "operator"));
  if (importMode === "dry_run") {
    const targetPreview = sourceInfo ? importTargetPath(state.modelRoot, modelId, sourceInfo.path) : null;
    const metadata = sourceInfo ? parseLocalModelMetadata(sourceInfo.path) : {};
    const receipt = state.lifecycleReceipt("model_import_dry_run", {
      modelId,
      providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
      sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
      targetPathHash: targetPreview ? stableHash(targetPreview) : null,
      importMode,
    });
    return {
      schemaVersion,
      status: "dry_run",
      modelId,
      importMode,
      sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
      targetPathHash: targetPreview ? stableHash(targetPreview) : null,
      metadata,
      receiptId: receipt.id,
    };
  }
  const importedPath = sourceInfo ? materializeImportArtifact(state.modelRoot, modelId, sourceInfo.path, importMode) : null;
  const inspectedPath = importedPath ?? sourceInfo?.path ?? null;
  const importedInfo = inspectedPath ? inspectLocalArtifact(inspectedPath) : sourceInfo;
  const metadata = inspectedPath ? parseLocalModelMetadata(inspectedPath) : {};
  const artifact = {
    id: body.id ?? `import.${safeId(modelId)}`,
    providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
    modelId,
    displayName: body.display_name ?? body.displayName ?? modelId,
    family: body.family ?? metadata.family ?? "imported",
    format: body.format ?? metadata.format ?? null,
    quantization: body.quantization ?? metadata.quantization ?? null,
    sizeBytes: body.size_bytes ?? body.sizeBytes ?? importedInfo?.sizeBytes ?? null,
    checksum: body.checksum ?? importedInfo?.checksum ?? null,
    contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
    capabilities: normalizeScopes(body.capabilities, ["chat"]),
    privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
    source: body.source ?? (sourceInfo ? "local_path_import" : "operator_import"),
    importMode,
    artifactPath: inspectedPath,
    metadata,
    backendRegistry: state.backendRegistry(),
    state: "installed",
    discoveredAt: now,
  };
  state.artifacts.set(artifact.id, artifact);
  state.writeMap("model-artifacts", state.artifacts);
  state.lifecycleReceipt("model_import", {
    artifactId: artifact.id,
    modelId: artifact.modelId,
    providerId: artifact.providerId,
    state: artifact.state,
    artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
    sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
    importMode,
    checksum: artifact.checksum,
  });
  state.writeProjection();
  return artifact;
}

export function mountEndpoint(state, body = {}, deps = {}) {
  const {
    defaultBackendForProvider,
    driverForProviderKind,
    normalizeLoadPolicy,
    normalizeScopes,
    runtimeError,
    safeId,
  } = deps;
  const now = state.nowIso();
  const modelId = body.model_id ?? body.modelId;
  if (!modelId) {
    throw runtimeError({
      status: 400,
      code: "model_id_required",
      message: "Mounting a model endpoint requires an explicit model id.",
    });
  }
  const explicitProviderId = body.provider_id ?? body.providerId;
  const artifact = explicitProviderId ? null : state.getModel(modelId);
  const providerId = explicitProviderId ?? artifact.providerId;
  const provider = state.provider(providerId);
  const resolvedArtifact = artifact ?? state.modelForProviderMount(modelId, provider, body, now);
  const driver = body.driver ?? provider.driver ?? driverForProviderKind(provider.kind);
  const endpoint = {
    id: body.id ?? `endpoint.${safeId(providerId)}.${safeId(resolvedArtifact.modelId)}`,
    providerId,
    modelId: resolvedArtifact.modelId,
    apiFormat: body.api_format ?? body.apiFormat ?? provider.apiFormat,
    driver,
    baseUrl:
      body.base_url ??
      body.baseUrl ??
      provider.baseUrl ??
      (driver === "fixture" ? "local://ioi-daemon/model-fixture" : null),
    capabilities: normalizeScopes(body.capabilities, resolvedArtifact.capabilities),
    privacyClass: body.privacy_class ?? body.privacyClass ?? provider.privacyClass,
    artifactId: resolvedArtifact.id,
    artifactPath: resolvedArtifact.artifactPath ?? null,
    backendId: body.backend_id ?? body.backendId ?? defaultBackendForProvider(provider),
    loadPolicy: normalizeLoadPolicy(body.load_policy ?? body.loadPolicy),
    status: "mounted",
    mountedAt: now,
  };
  state.endpoints.set(endpoint.id, endpoint);
  state.writeMap("model-endpoints", state.endpoints);
  state.lifecycleReceipt("model_mount", {
    endpointId: endpoint.id,
    modelId: endpoint.modelId,
    providerId: endpoint.providerId,
    loadPolicy: endpoint.loadPolicy,
  });
  return endpoint;
}

export function unmountEndpoint(state, body = {}, deps = {}) {
  const { requiredString } = deps;
  const endpointId = requiredString(body.endpoint_id ?? body.endpointId ?? body.id, "endpoint_id");
  const endpoint = state.endpoint(endpointId);
  const updated = {
    ...endpoint,
    status: "unmounted",
    unmountedAt: state.nowIso(),
  };
  state.endpoints.set(endpointId, updated);
  state.writeMap("model-endpoints", state.endpoints);
  state.lifecycleReceipt("model_unmount", {
    endpointId,
    modelId: endpoint.modelId,
    providerId: endpoint.providerId,
  });
  return updated;
}
