import { runtimeError } from "./io.mjs";
import { modelMountProviderKindRequiresRustInstanceLifecycle } from "./model-instance-lifecycle.mjs";

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

const RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_model_mount_record_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

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
  assertCanonicalProviderUpsertRequestBody(body);
  const checkedAt = state.nowIso();
  const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
  const existing = state.providers.get(id) ?? {};
  const kind = body.kind ?? existing.kind ?? "custom_http";
  const secretRef = state.normalizeProviderSecretRef(kind, body, existing.secretRef ?? null);
  const authScheme = normalizeProviderAuthScheme(body.auth_scheme ?? existing.authScheme);
  const authHeaderName = normalizeProviderAuthHeaderName(
    body.auth_header_name ?? existing.authHeaderName,
  );
  const requestedStatus = body.status ?? existing.status ?? "configured";
  const provider = {
    id,
    kind,
    label: body.label ?? existing.label ?? id,
    apiFormat: body.api_format ?? existing.apiFormat ?? "custom",
    driver: body.driver ?? existing.driver ?? driverForProviderKind(kind),
    baseUrl: body.base_url ?? existing.baseUrl ?? null,
    status: providerRequiresVaultSecret(kind) && !secretRef ? "blocked" : requestedStatus,
    privacyClass: body.privacy_class ?? existing.privacyClass ?? "workspace",
    capabilities: normalizeScopes(body.capabilities, existing.capabilities ?? ["chat"]),
    discovery: {
      ...existing.discovery,
      checkedAt,
      evidenceRefs: normalizeScopes(body.evidence_refs, existing.discovery?.evidenceRefs ?? ["operator_provider_config"]),
    },
    secretRef,
    authScheme,
    authHeaderName,
  };
  state.providers.set(provider.id, provider);
  state.writeMap("model-providers", state.providers);
  return publicProvider(provider);
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
  const {
    providerHasVaultRef,
    providerHealthFailureStatus,
    publicProvider,
    safeId,
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
        provider_id: providerId,
        provider_kind: provider.kind,
        status,
        http_status: driverResult.httpStatus ?? null,
        auth_vault_ref_hash: driverResult.authEvidence?.vaultRefHash ?? null,
        provider_auth_evidence_refs: driverResult.authEvidence?.evidenceRefs ?? [],
        provider_auth_header_names: driverResult.authEvidence?.headerNames ?? [],
        ...providerLifecycleReceiptFields(driverResult.model_mount_provider_lifecycle),
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
    commitProviderHealthStateRecord(state, {
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
    if (isModelMountRecordStateCommitError(error)) throw error;
    return providerHealthFailure(state, provider, providerId, error, {
      normalizeScopes: deps.normalizeScopes,
      providerHasVaultRef,
      providerHealthFailureStatus,
      safeId,
    });
  }
}

function isModelMountRecordStateCommitError(error) {
  return typeof error?.code === "string" && (
    error.code.startsWith("model_mount_record_state_commit") ||
    error.code.startsWith("model_mount_provider_health_state_commit")
  );
}

function providerHealthFailure(state, provider, providerId, error, deps) {
  const {
    normalizeScopes,
    providerHasVaultRef,
    providerHealthFailureStatus,
    safeId,
  } = deps;
  const checkedAt = state.nowIso();
  const status = providerHealthFailureStatus(error);
  const failureDetails = error?.details && typeof error.details === "object" ? error.details : {};
  const evidenceRefs = normalizeScopes(failureDetails.evidence_refs, [`provider_health_${error?.code ?? "runtime_error"}`]);
  const receipt = state.receipt("provider_health", {
    summary: `Provider ${providerId} health failed closed as ${status}.`,
    redaction: "redacted",
    evidenceRefs,
    details: {
      provider_id: providerId,
      provider_kind: provider.kind,
      status,
      failure_code: error?.code ?? "runtime",
      failure_status: error?.status ?? 500,
      http_status: failureDetails.http_status ?? null,
      provider_error_hash: failureDetails.provider_error_hash ?? null,
      vault_ref_configured: failureDetails.vault_ref_configured ?? providerHasVaultRef(provider),
      auth_vault_ref_hash: failureDetails.vault_ref_hash ?? null,
      resolved_material: failureDetails.resolved_material ?? null,
      adapter: failureDetails.adapter ?? null,
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
        httpStatus: failureDetails.http_status ?? null,
        authVaultRefHash: failureDetails.vault_ref_hash ?? null,
        failureCode: error?.code ?? "runtime",
        failureStatus: error?.status ?? 500,
        resolvedMaterial: failureDetails.resolved_material ?? null,
        receiptId: receipt.id,
      },
    },
  };
  state.providers.set(providerId, updated);
  state.writeMap("model-providers", state.providers);
  commitProviderHealthStateRecord(state, {
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
    provider_id: providerId,
    provider_kind: provider.kind,
    provider_health_status: status,
    provider_health_receipt_id: receipt.id,
    failure_code: error?.code ?? "runtime",
    failure_status: error?.status ?? 500,
    http_status: failureDetails.http_status ?? null,
    provider_error_hash: failureDetails.provider_error_hash ?? null,
    vault_ref_configured: failureDetails.vault_ref_configured ?? providerHasVaultRef(provider),
    auth_vault_ref_hash: failureDetails.vault_ref_hash ?? null,
    resolved_material: failureDetails.resolved_material ?? null,
    evidence_refs: evidenceRefs,
    adapter: failureDetails.adapter ?? null,
  };
  throw error;
}

function commitProviderHealthStateRecord(state, record) {
  if (typeof state.commitRuntimeModelMountRecordState !== "function") {
    const error = new Error("Model-mount provider health persistence requires Rust Agentgres record-state commit.");
    error.status = 500;
    error.code = "model_mount_provider_health_state_commit_unconfigured";
    error.details = {
      provider_id: record?.providerId ?? null,
      receipt_id: record?.receiptId ?? null,
    };
    throw error;
  }
  return normalizeModelMountRecordStateCommit(state.commitRuntimeModelMountRecordState({
    schema_version: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION,
    record_dir: "provider-health",
    record_id: record.id,
    operation_kind: "model_mount.provider_health.write",
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    record,
    receipt_refs: [record.receiptId],
  }));
}

function normalizeModelMountRecordStateCommit(value = {}) {
  const commit = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const storageRecord = commit.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : commit.record?.record ?? {};
  const required = {
    record_id: commit.record_id ?? commit.record?.record_id,
    object_ref: commit.object_ref ?? storageRecord.object_ref,
    content_hash: commit.content_hash ?? storageRecord.content_hash,
    admission_hash: commit.admission_hash ?? storageRecord.admission?.admission_hash,
    commit_hash: commit.commit_hash ?? commit.record?.commit_hash,
    written_record: commit.written_record,
  };
  for (const [field, fieldValue] of Object.entries(required)) {
    if (!fieldValue) {
      const error = new Error(`Rust model-mount record state commit returned without ${field}.`);
      error.status = 502;
      error.code = "model_mount_record_state_commit_invalid";
      error.details = { field };
      throw error;
    }
  }
  return {
    ...commit,
    storage_record: storageRecord,
    record_id: required.record_id,
    object_ref: required.object_ref,
    content_hash: required.content_hash,
    admission_hash: required.admission_hash,
    commit_hash: required.commit_hash,
    written_record: required.written_record,
  };
}

function providerLifecycleReceiptFields(lifecycle) {
  if (!lifecycle) return {};
  return {
    model_mount_provider_lifecycle_action: lifecycle.action,
    model_mount_provider_lifecycle_status: lifecycle.status,
    model_mount_provider_lifecycle_hash: lifecycle.lifecycle_hash,
    model_mount_provider_lifecycle_evidence_refs: lifecycle.evidence_refs ?? [],
    model_mount_provider_lifecycle_execution_backend: lifecycle.execution_backend,
    model_mount_provider_lifecycle_backend_id: lifecycle.backend_id,
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
    provider_id: providerId,
    provider_kind: provider.kind,
    model_id: provider.label,
    state: provider.status,
    model_count: resolved.length,
    evidence_refs: provider.discovery?.evidenceRefs ?? [],
    ...providerInventoryReceiptFields(models.model_mount_provider_inventory),
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
    provider_id: providerId,
    provider_kind: provider.kind,
    model_id: provider.label,
    state: provider.status,
    loaded_count: resolved.length,
    evidence_refs: provider.discovery?.evidenceRefs ?? [],
    ...providerInventoryReceiptFields(loaded.model_mount_provider_inventory),
  });
  return resolved;
}

function providerInventoryReceiptFields(inventory) {
  if (!inventory) return {};
  return {
    model_mount_provider_inventory_action: inventory.action,
    model_mount_provider_inventory_status: inventory.status,
    model_mount_provider_inventory_hash: inventory.inventory_hash,
    model_mount_provider_inventory_evidence_refs: inventory.evidence_refs ?? [],
    model_mount_provider_inventory_execution_backend: inventory.execution_backend,
    model_mount_provider_inventory_item_count: inventory.item_count,
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
    provider_id: providerId,
    provider_kind: provider.kind,
    model_id: provider.label,
    state: updated.status,
    evidence_refs: result.evidenceRefs ?? [],
    ...providerLifecycleReceiptFields(result.model_mount_provider_lifecycle),
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
    provider_id: providerId,
    provider_kind: provider.kind,
    model_id: provider.label,
    state: updated.status,
    evidence_refs: result.evidenceRefs ?? [],
    ...providerLifecycleReceiptFields(result.model_mount_provider_lifecycle),
  });
  return publicProvider(updated);
}

function assertProviderControlLifecycleBound(provider, result, operation) {
  if (!modelMountProviderKindRequiresRustInstanceLifecycle(provider?.kind)) return;
  if (result?.model_mount_provider_lifecycle) return;
  const error = new Error("Provider start/stop for migrated local providers requires Rust model_mount lifecycle planning.");
  error.status = 502;
  error.code = "model_mount_provider_control_lifecycle_planning_required";
  error.details = {
    operation,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
  };
  throw error;
}
