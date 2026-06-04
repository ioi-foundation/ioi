import path from "node:path";

import { modelMountProviderKindRequiresRustInstanceLifecycle } from "./model-instance-lifecycle.mjs";

export function upsertProvider(state, body = {}, deps = {}) {
  const {
    driverForProviderKind,
    normalizeProviderAuthHeaderName,
    normalizeProviderAuthScheme,
    normalizeScopes,
    providerRequiresVaultSecret,
    publicProvider,
    safeId,
  } = deps;
  const checkedAt = state.nowIso();
  const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
  const existing = state.providers.get(id) ?? {};
  const kind = body.kind ?? existing.kind ?? "custom_http";
  const secretRef = state.normalizeProviderSecretRef(kind, body, existing.secretRef ?? null);
  const authScheme = normalizeProviderAuthScheme(body.auth_scheme ?? body.authScheme ?? existing.authScheme);
  const authHeaderName = normalizeProviderAuthHeaderName(
    body.auth_header_name ?? body.authHeaderName ?? existing.authHeaderName,
  );
  const requestedStatus = body.status ?? existing.status ?? "configured";
  const provider = {
    id,
    kind,
    label: body.label ?? existing.label ?? id,
    apiFormat: body.api_format ?? body.apiFormat ?? existing.apiFormat ?? "custom",
    driver: body.driver ?? existing.driver ?? driverForProviderKind(kind),
    baseUrl: body.base_url ?? body.baseUrl ?? existing.baseUrl ?? null,
    status: providerRequiresVaultSecret(kind) && !secretRef ? "blocked" : requestedStatus,
    privacyClass: body.privacy_class ?? body.privacyClass ?? existing.privacyClass ?? "workspace",
    capabilities: normalizeScopes(body.capabilities, existing.capabilities ?? ["chat"]),
    discovery: {
      ...existing.discovery,
      checkedAt,
      evidenceRefs: normalizeScopes(body.evidence_refs ?? body.evidenceRefs, existing.discovery?.evidenceRefs ?? ["operator_provider_config"]),
    },
    secretRef,
    authScheme,
    authHeaderName,
  };
  state.providers.set(provider.id, provider);
  state.writeMap("model-providers", state.providers);
  return publicProvider(provider);
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
  const {
    pathModule = path,
    providerHasVaultRef,
    providerHealthFailureStatus,
    publicProvider,
    safeFileName,
    safeId,
    writeJson,
  } = deps;
  const provider = state.provider(providerId);
  const checkedAt = state.nowIso();
  try {
    const driverResult = await state.driverForProvider(provider).health(provider, { state });
    const status = driverResult.status ?? (provider.status === "configured" ? "available" : provider.status);
    const receipt = state.receipt("provider_health", {
      summary: `Provider ${providerId} health is ${status}.`,
      redaction: "redacted",
      evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
      details: {
        providerId,
        providerKind: provider.kind,
        status,
        httpStatus: driverResult.httpStatus ?? null,
        authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
        providerAuthEvidenceRefs: driverResult.authEvidence?.evidenceRefs ?? [],
        providerAuthHeaderNames: driverResult.authEvidence?.headerNames ?? [],
        ...providerLifecycleReceiptFields(driverResult.modelMountProviderLifecycle),
      },
    });
    const updated = {
      ...provider,
      status,
      discovery: {
        ...provider.discovery,
        checkedAt,
        lastHealthCheck: {
          status,
          evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
          httpStatus: driverResult.httpStatus ?? null,
          authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
          receiptId: receipt.id,
        },
        ...(driverResult.publicCli ? { publicCli: driverResult.publicCli } : {}),
      },
    };
    state.providers.set(providerId, updated);
    state.writeMap("model-providers", state.providers);
    writeJson(pathModule.join(state.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
      id: `health.${safeId(providerId)}`,
      providerId,
      status,
      checkedAt,
      receiptId: receipt.id,
      evidenceRefs: driverResult.evidenceRefs ?? [],
    });
    state.writeProjection();
    return publicProvider(updated, providerHasVaultRef(updated) ? state.vault.vaultRefMetadata(updated.secretRef) : null);
  } catch (error) {
    return providerHealthFailure(state, provider, providerId, error, {
      pathModule,
      normalizeScopes: deps.normalizeScopes,
      providerHasVaultRef,
      providerHealthFailureStatus,
      safeFileName,
      safeId,
      writeJson,
    });
  }
}

function providerHealthFailure(state, provider, providerId, error, deps) {
  const {
    pathModule,
    normalizeScopes,
    providerHasVaultRef,
    providerHealthFailureStatus,
    safeFileName,
    safeId,
    writeJson,
  } = deps;
  const checkedAt = state.nowIso();
  const status = providerHealthFailureStatus(error);
  const failureDetails = error?.details && typeof error.details === "object" ? error.details : {};
  const evidenceRefs = normalizeScopes(failureDetails.evidenceRefs, [`provider_health_${error?.code ?? "runtime_error"}`]);
  const receipt = state.receipt("provider_health", {
    summary: `Provider ${providerId} health failed closed as ${status}.`,
    redaction: "redacted",
    evidenceRefs,
    details: {
      providerId,
      providerKind: provider.kind,
      status,
      failureCode: error?.code ?? "runtime",
      failureStatus: error?.status ?? 500,
      httpStatus: failureDetails.httpStatus ?? null,
      providerErrorHash: failureDetails.providerErrorHash ?? null,
      vaultRefConfigured: failureDetails.vaultRefConfigured ?? providerHasVaultRef(provider),
      authVaultRefHash: failureDetails.vaultRefHash ?? null,
      resolvedMaterial: failureDetails.resolvedMaterial ?? null,
    },
  });
  const updated = {
    ...provider,
    status,
    discovery: {
      ...provider.discovery,
      checkedAt,
      lastHealthCheck: {
        status,
        evidenceRefs,
        httpStatus: failureDetails.httpStatus ?? null,
        authVaultRefHash: failureDetails.vaultRefHash ?? null,
        failureCode: error?.code ?? "runtime",
        failureStatus: error?.status ?? 500,
        resolvedMaterial: failureDetails.resolvedMaterial ?? null,
        receiptId: receipt.id,
      },
    },
  };
  state.providers.set(providerId, updated);
  state.writeMap("model-providers", state.providers);
  writeJson(pathModule.join(state.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
    id: `health.${safeId(providerId)}`,
    providerId,
    status,
    checkedAt,
    receiptId: receipt.id,
    failureCode: error?.code ?? "runtime",
    failureStatus: error?.status ?? 500,
    evidenceRefs,
  });
  state.writeProjection();
  error.details = {
    ...failureDetails,
    providerHealthStatus: status,
    providerHealthReceiptId: receipt.id,
  };
  throw error;
}

function providerLifecycleReceiptFields(lifecycle) {
  if (!lifecycle) return {};
  return {
    modelMountProviderLifecycleAction: lifecycle.action,
    modelMountProviderLifecycleStatus: lifecycle.status,
    providerLifecycleHash: lifecycle.lifecycleHash,
    modelMountProviderLifecycleEvidenceRefs: lifecycle.evidenceRefs ?? [],
    modelMountProviderLifecycleExecutionBackend: lifecycle.executionBackend,
    modelMountProviderLifecycleBackendId: lifecycle.backendId,
  };
}

export async function listProviderModels(state, providerId) {
  const provider = state.provider(providerId);
  const models = await state.driverForProvider(provider).listModels({ state, provider });
  for (const artifact of models) {
    state.artifacts.set(artifact.id, artifact);
  }
  if (models.length > 0) state.writeMap("model-artifacts", state.artifacts);
  const resolved = models.length > 0
    ? models
    : state.listArtifacts().filter((artifact) => artifact.providerId === providerId);
  state.lifecycleReceipt("provider_models_list", {
    providerId,
    providerKind: provider.kind,
    modelId: provider.label,
    state: provider.status,
    modelCount: resolved.length,
    evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    ...providerInventoryReceiptFields(models.modelMountProviderInventory),
  });
  return resolved;
}

export async function listProviderLoaded(state, providerId) {
  const provider = state.provider(providerId);
  const loaded = await state.driverForProvider(provider).listLoaded({ state, provider });
  const resolved = loaded.length > 0
    ? loaded
    : state.listInstances().filter((instance) => instance.providerId === providerId && instance.status === "loaded");
  state.lifecycleReceipt("provider_loaded_list", {
    providerId,
    providerKind: provider.kind,
    modelId: provider.label,
    state: provider.status,
    loadedCount: resolved.length,
    evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    ...providerInventoryReceiptFields(loaded.modelMountProviderInventory),
  });
  return resolved;
}

function providerInventoryReceiptFields(inventory) {
  if (!inventory) return {};
  return {
    modelMountProviderInventoryAction: inventory.action,
    modelMountProviderInventoryStatus: inventory.status,
    modelMountProviderInventoryHash: inventory.inventoryHash,
    modelMountProviderInventoryEvidenceRefs: inventory.evidenceRefs ?? [],
    modelMountProviderInventoryExecutionBackend: inventory.executionBackend,
    modelMountProviderInventoryItemCount: inventory.itemCount,
  };
}

export async function startProvider(state, providerId, deps = {}) {
  const { publicProvider } = deps;
  const provider = state.provider(providerId);
  const driver = state.driverForProvider(provider);
  const result = typeof driver.start === "function"
    ? await driver.start({ state, provider })
    : { status: provider.status === "blocked" ? "blocked" : "available", evidenceRefs: ["provider_stateless_start"] };
  assertProviderControlLifecycleBound(provider, result, "provider_start");
  const updated = {
    ...provider,
    status: result.status ?? "available",
    discovery: {
      ...provider.discovery,
      checkedAt: state.nowIso(),
      lastStart: {
        status: result.status ?? "available",
        evidenceRefs: result.evidenceRefs ?? [],
      },
    },
  };
  state.providers.set(providerId, updated);
  state.writeMap("model-providers", state.providers);
  state.lifecycleReceipt("provider_start", {
    providerId,
    providerKind: provider.kind,
    modelId: provider.label,
    state: updated.status,
    evidenceRefs: result.evidenceRefs ?? [],
    ...providerLifecycleReceiptFields(result.modelMountProviderLifecycle),
  });
  return publicProvider(updated);
}

export async function stopProvider(state, providerId, deps = {}) {
  const { publicProvider } = deps;
  const provider = state.provider(providerId);
  const driver = state.driverForProvider(provider);
  const result = typeof driver.stop === "function"
    ? await driver.stop({ state, provider })
    : { status: "stopped", evidenceRefs: ["provider_stateless_stop"] };
  assertProviderControlLifecycleBound(provider, result, "provider_stop");
  const updated = {
    ...provider,
    status: result.status ?? "stopped",
    discovery: {
      ...provider.discovery,
      checkedAt: state.nowIso(),
      lastStop: {
        status: result.status ?? "stopped",
        evidenceRefs: result.evidenceRefs ?? [],
      },
    },
  };
  state.providers.set(providerId, updated);
  state.writeMap("model-providers", state.providers);
  state.lifecycleReceipt("provider_stop", {
    providerId,
    providerKind: provider.kind,
    modelId: provider.label,
    state: updated.status,
    evidenceRefs: result.evidenceRefs ?? [],
    ...providerLifecycleReceiptFields(result.modelMountProviderLifecycle),
  });
  return publicProvider(updated);
}

function assertProviderControlLifecycleBound(provider, result, operation) {
  if (!modelMountProviderKindRequiresRustInstanceLifecycle(provider?.kind)) return;
  if (result?.modelMountProviderLifecycle) return;
  const error = new Error("Provider start/stop for migrated local providers requires Rust model_mount lifecycle planning.");
  error.status = 502;
  error.code = "model_mount_provider_control_lifecycle_planning_required";
  error.details = {
    operation,
    providerId: provider?.id ?? null,
    providerKind: provider?.kind ?? null,
  };
  throw error;
}
