const RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "apiFormat",
  "baseUrl",
  "privacyClass",
  "backendId",
  "loadPolicy",
];

const CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "api_format",
  "base_url",
  "privacy_class",
  "backend_id",
  "load_policy",
];

const RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES = ["endpointId"];
const CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS = ["endpoint_id"];

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
      model_id: modelId,
      provider_id: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
      source_path_hash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
      target_path_hash: targetPreview ? stableHash(targetPreview) : null,
      import_mode: importMode,
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
    artifact_id: artifact.id,
    model_id: artifact.modelId,
    provider_id: artifact.providerId,
    state: artifact.state,
    artifact_path_hash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
    source_path_hash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
    import_mode: importMode,
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
  assertCanonicalEndpointMountRequestBody(body);
  const now = state.nowIso();
  const modelId = body.model_id;
  if (!modelId) {
    throw runtimeError({
      status: 400,
      code: "model_id_required",
      message: "Mounting a model endpoint requires an explicit model id.",
    });
  }
  const explicitProviderId = body.provider_id;
  const artifact = explicitProviderId ? null : state.getModel(modelId);
  const providerId = explicitProviderId ?? artifact.providerId;
  const provider = state.provider(providerId);
  const resolvedArtifact = artifact ?? state.modelForProviderMount(modelId, provider, body, now);
  const driver = body.driver ?? provider.driver ?? driverForProviderKind(provider.kind);
  const endpoint = {
    id: body.id ?? `endpoint.${safeId(providerId)}.${safeId(resolvedArtifact.modelId)}`,
    providerId,
    modelId: resolvedArtifact.modelId,
    apiFormat: body.api_format ?? provider.apiFormat,
    driver,
    baseUrl:
      body.base_url ??
      provider.baseUrl ??
      (driver === "fixture" ? "local://ioi-daemon/model-fixture" : null),
    capabilities: normalizeScopes(body.capabilities, resolvedArtifact.capabilities),
    privacyClass: body.privacy_class ?? provider.privacyClass,
    artifactId: resolvedArtifact.id,
    artifactPath: resolvedArtifact.artifactPath ?? null,
    backendId: body.backend_id ?? defaultBackendForProvider(provider),
    loadPolicy: normalizeLoadPolicy(body.load_policy),
    status: "mounted",
    mountedAt: now,
  };
  state.endpoints.set(endpoint.id, endpoint);
  state.writeMap("model-endpoints", state.endpoints);
  state.lifecycleReceipt("model_mount", {
    endpoint_id: endpoint.id,
    model_id: endpoint.modelId,
    provider_id: endpoint.providerId,
    load_policy: endpoint.loadPolicy,
  });
  return endpoint;
}

export function unmountEndpoint(state, body = {}, deps = {}) {
  const { requiredString } = deps;
  assertCanonicalEndpointUnmountRequestBody(body);
  const endpointId = requiredString(body.endpoint_id ?? body.id, "endpoint_id");
  const endpoint = state.endpoint(endpointId);
  const updated = {
    ...endpoint,
    status: "unmounted",
    unmountedAt: state.nowIso(),
  };
  state.endpoints.set(endpointId, updated);
  state.writeMap("model-endpoints", state.endpoints);
  state.lifecycleReceipt("model_unmount", {
    endpoint_id: endpointId,
    model_id: endpoint.modelId,
    provider_id: endpoint.providerId,
  });
  return updated;
}

function assertCanonicalEndpointMountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint mount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalEndpointUnmountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint unmount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_unmount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS,
  };
  throw error;
}
