import { runtimeError } from "./io.mjs";
import { commitModelArtifactRecordState } from "./model-artifact-record-state.mjs";
import { modelMountProviderKindRequiresRustInstanceLifecycle } from "./model-instance-lifecycle.mjs";
import { commitModelMountRecordState } from "./record-state-commits.mjs";

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

export function upsertProvider(state, body = {}, deps = {}) {
  const {
    safeId,
  } = deps;
  assertCanonicalProviderUpsertRequestBody(body);
  const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
  const existing = state.providers.get(id) ?? {};
  const kind = body.kind ?? existing.kind ?? "custom_http";
  throw providerControlRustCoreRequired({
    id,
    kind,
  }, "provider_upsert", {
    operation_kind: "model_mount.provider.write",
  });
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
  assertProviderRustLifecycleBackend(provider, "provider_health");
  const checkedAt = state.nowIso();
  try {
    const driverResult = await state.driverForProvider(provider).health(provider, { state });
    assertProviderOperationLifecycleBound(provider, driverResult, "provider_health");
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
    commitProviderRecordState(state, updated, "model_mount.provider.health_update", [receipt.id]);
    commitProviderHealthStateRecord(state, {
      id: `health.${safeId(providerId)}`,
      providerId,
      status,
      checkedAt,
      receiptId: receipt.id,
      evidenceRefs: driverResult.evidenceRefs ?? [],
    });
    state.providers.set(providerId, updated);
    state.writeProjection();
    return publicProvider(updated, providerHasVaultRef(updated) ? state.vault.vaultRefMetadata(updated.secretRef) : null);
  } catch (error) {
    throw error;
  }
}

function commitProviderHealthStateRecord(state, record) {
  return commitModelMountRecordState(state, {
    recordDir: "provider-health",
    record,
    operation_kind: "model_mount.provider_health.write",
    receipt_refs: [record.receiptId],
    unconfiguredCode: "model_mount_provider_health_state_commit_unconfigured",
    unconfiguredMessage:
      "Model-mount provider health persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      provider_id: record?.providerId ?? null,
    },
  });
}

function commitProviderRecordState(state, record, operation_kind, receipt_refs) {
  return commitModelMountRecordState(state, {
    recordDir: "model-providers",
    record,
    operation_kind,
    receipt_refs,
    unconfiguredCode: "model_mount_provider_state_commit_unconfigured",
    unconfiguredMessage:
      "Model provider persistence requires Rust Agentgres record-state commit.",
    unconfiguredDetails: {
      provider_id: record?.id ?? null,
      provider_kind: record?.kind ?? null,
    },
  });
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
  assertProviderRustInventoryBackend(provider, "provider_models_list");
  const models = await state.driverForProvider(provider).listModels({ state, provider });
  assertProviderOperationInventoryBound(provider, models, "provider_models_list");
  for (const artifact of models) {
    commitModelArtifactRecordState(state, artifact, "model_mount.artifact.provider_inventory", []);
    state.artifacts.set(artifact.id, artifact);
  }
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
  assertProviderRustInventoryBackend(provider, "provider_loaded_list");
  const loaded = await state.driverForProvider(provider).listLoaded({ state, provider });
  assertProviderOperationInventoryBound(provider, loaded, "provider_loaded_list");
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
  const provider = state.provider(providerId);
  throw providerControlRustCoreRequired(provider, "provider_start");
}

export async function stopProvider(state, providerId, deps = {}) {
  const provider = state.provider(providerId);
  throw providerControlRustCoreRequired(provider, "provider_stop");
}

function assertProviderRustLifecycleBackend(provider, operation) {
  if (providerHasRustModelMountLifecycleBackend(provider)) return;
  const error = new Error("Provider lifecycle operation requires Rust model_mount lifecycle backend support.");
  error.status = 501;
  error.code = "model_mount_provider_lifecycle_backend_unmigrated";
  error.details = {
    operation,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
  };
  throw error;
}

function assertProviderRustInventoryBackend(provider, operation) {
  if (providerHasRustModelMountInventoryBackend(provider)) return;
  const error = new Error("Provider inventory operation requires Rust model_mount inventory backend support.");
  error.status = 501;
  error.code = "model_mount_provider_inventory_backend_unmigrated";
  error.details = {
    operation,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    provider_driver: provider?.driver ?? null,
    api_format: provider?.apiFormat ?? null,
  };
  throw error;
}

function assertProviderOperationLifecycleBound(provider, result, operation) {
  if (result?.model_mount_provider_lifecycle) return;
  const error = new Error("Provider lifecycle operation requires Rust model_mount lifecycle planning.");
  error.status = 502;
  error.code = "model_mount_provider_lifecycle_planning_required";
  error.details = {
    operation,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
  };
  throw error;
}

function assertProviderOperationInventoryBound(provider, result, operation) {
  if (result?.model_mount_provider_inventory) return;
  const error = new Error("Provider inventory operation requires Rust model_mount inventory planning.");
  error.status = 502;
  error.code = "model_mount_provider_inventory_planning_required";
  error.details = {
    operation,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
  };
  throw error;
}

function providerControlRustCoreRequired(provider, operation, details = {}) {
  const error = new Error("Provider control requires direct Rust daemon-core support.");
  error.status = 501;
  error.code = "model_mount_provider_control_rust_core_required";
  error.details = {
    rust_core_boundary: "model_mount.provider_control",
    operation,
    ...details,
    provider_id: provider?.id ?? null,
    provider_kind: provider?.kind ?? null,
    evidence_refs: [
      "model_mount_provider_control_js_facade_retired",
      "rust_daemon_core_provider_control_required",
      "wallet_network_vault_authority_required",
    ],
  };
  return error;
}

function providerHasRustModelMountLifecycleBackend(provider = {}) {
  return modelMountProviderKindRequiresRustInstanceLifecycle(provider.kind) ||
    provider.kind === "fixture" ||
    provider.driver === "native_local" ||
    provider.driver === "fixture" ||
    provider.apiFormat === "ioi_native" ||
    provider.apiFormat === "ioi_fixture";
}

function providerHasRustModelMountInventoryBackend(provider = {}) {
  return providerHasRustModelMountLifecycleBackend(provider);
}
