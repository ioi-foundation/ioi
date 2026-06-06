import path from "node:path";

import {
  normalizeScopes,
  runtimeError,
  safeId,
  stableHash,
  truthy,
} from "./io.mjs";
import {
  normalizeProviderAuthHeaderName,
} from "./provider-auth.mjs";
import {
  oauthBoundaryForSession,
} from "./oauth-boundary.mjs";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1";

export const MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS = ["catalog.local_manifest", "catalog.custom_http", "catalog.huggingface"];

const RETIRED_CATALOG_PROVIDER_SOURCE_REQUEST_ALIASES = [
  "manifestPath",
  "baseUrl",
];

const CANONICAL_CATALOG_PROVIDER_SOURCE_REQUEST_FIELDS = [
  "manifest_path",
  "base_url",
];

const RETIRED_CATALOG_PROVIDER_AUTH_REQUEST_ALIASES = [
  "authVaultRef",
  "vault_ref",
  "vaultRef",
  "api_key_vault_ref",
  "apiKeyVaultRef",
  "authScheme",
  "authHeaderName",
  "oauthSessionId",
];

const CANONICAL_CATALOG_PROVIDER_AUTH_REQUEST_FIELDS = [
  "auth_vault_ref",
  "auth_scheme",
  "auth_header_name",
  "oauth_session_id",
];

export function assertConfigurableCatalogProvider(providerId) {
  if (!MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.includes(providerId)) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `Catalog provider is not configurable: ${providerId}`,
      details: { provider_id: providerId },
    });
  }
}

export function catalogProviderConfigUpdate(providerId, body, existing = null, updatedAt, state) {
  assertCanonicalCatalogProviderAuthRequestBody(body);
  const enabled = body.enabled === undefined ? existing?.enabled ?? true : truthy(body.enabled);
  const materialFromBody = catalogProviderRuntimeMaterialFromBody(providerId, body);
  let runtimeMaterial = catalogProviderHasSourceMaterial(materialFromBody)
    ? materialFromBody
    : state.catalogProviderRuntimeMaterials.get(providerId) ?? null;
  let materialPersistence = existing?.materialPersistence ?? "metadata_only";
  let materialVaultRefHash = existing?.materialVaultRefHash ?? null;
  let runtimeMaterialStatus = existing?.runtimeMaterialStatus ?? (existing?.materialConfigured ? "missing_runtime_material" : "unconfigured");
  let materialSource = existing?.vaultMaterialSource ?? runtimeMaterial?.materialSource ?? null;
  const evidenceRefs = ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"];
  if (catalogProviderHasSourceMaterial(materialFromBody)) {
    const sourceValue = catalogProviderSourceValue(providerId, materialFromBody);
    const binding = state.vault.bindVaultRef({
      vaultRef: catalogProviderMaterialVaultRef(providerId),
      material: sourceValue,
      purpose: catalogProviderMaterialPurpose(providerId),
      label: catalogProviderMaterialLabel(providerId),
    });
    state.writeVaultRefs();
    runtimeMaterial = {
      ...materialFromBody,
      runtimeMaterialStatus: "bound_runtime_session",
      materialSource: binding.materialSource ?? "runtime_memory",
      materialVaultRefHash: binding.vaultRefHash,
      evidenceRefs: normalizeScopes(binding.evidenceRefs, ["VaultPort.bindVaultRef", "catalog_provider_source_material_vault_bound"]),
    };
    materialVaultRefHash = binding.vaultRefHash;
    materialSource = binding.materialSource ?? "runtime_memory";
    materialPersistence =
      binding.materialSource === "encrypted_keychain_vault_adapter"
        ? "vault_material_adapter"
        : "runtime_vault_binding";
    runtimeMaterialStatus = "bound_runtime_session";
    evidenceRefs.push("VaultPort.bindVaultRef", "catalog_provider_source_material_vault_bound");
  } else if (existing?.materialConfigured || existing?.materialVaultRefHash) {
    runtimeMaterial = state.catalogProviderRuntimeMaterial(providerId);
    materialVaultRefHash = runtimeMaterial?.materialVaultRefHash ?? existing?.materialVaultRefHash ?? stableHash(catalogProviderMaterialVaultRef(providerId));
    materialSource = runtimeMaterial?.materialSource ?? existing?.vaultMaterialSource ?? null;
    runtimeMaterialStatus =
      runtimeMaterial?.runtimeMaterialStatus ??
      (catalogProviderHasSourceMaterial(runtimeMaterial) ? "resolved_from_vault" : "missing_runtime_material");
    if (materialSource === "encrypted_keychain_vault_adapter") materialPersistence = "vault_material_adapter";
    evidenceRefs.push("VaultPort.resolveVaultRef", "catalog_provider_source_material_vault_resolve");
  }
  const material = catalogProviderHasSourceMaterial(runtimeMaterial) ? runtimeMaterial : {};
  const materialHash =
    providerId === "catalog.local_manifest"
      ? material.manifestPath
        ? stableHash(path.resolve(material.manifestPath))
        : existing?.manifestPathHash ?? null
      : (providerId === "catalog.custom_http" || providerId === "catalog.huggingface") && material.baseUrl
        ? stableHash(material.baseUrl)
        : providerId === "catalog.custom_http" || providerId === "catalog.huggingface"
          ? existing?.baseUrlHash ?? null
          : null;
  const authConfig = catalogProviderAuthConfig(providerId, body, existing, state);
  const authVaultRefHash = authConfig.authVaultRefHash;
  if (authVaultRefHash) evidenceRefs.push("wallet.network.vault_ref_boundary", "catalog_provider_auth_vault_ref");
  if (!materialVaultRefHash && (materialHash || existing?.materialConfigured)) {
    materialVaultRefHash = stableHash(catalogProviderMaterialVaultRef(providerId));
  }
  const record = {
    id: providerId,
    schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    enabled,
    configHash: stableHash({
      providerId,
      enabled,
      materialHash,
      materialVaultRefHash,
      authVaultRefHash,
      catalogAuthScheme: authConfig.catalogAuthScheme,
      catalogAuthHeaderNameHash: authConfig.catalogAuthHeaderNameHash,
      oauthSessionHash: authConfig.oauthSessionHash,
    }),
    manifestPathHash: providerId === "catalog.local_manifest" ? materialHash : null,
    baseUrlHash: providerId === "catalog.custom_http" || providerId === "catalog.huggingface" ? materialHash : null,
    authVaultRef: authConfig.authVaultRef,
    authVaultRefHash,
    catalogAuthConfigured: authConfig.catalogAuthConfigured,
    catalogAuthScheme: authConfig.catalogAuthScheme,
    catalogAuthHeaderName: authConfig.catalogAuthHeaderName,
    catalogAuthHeaderNameHash: authConfig.catalogAuthHeaderNameHash,
    oauthSessionId: authConfig.oauthSessionId,
    oauthSessionHash: authConfig.oauthSessionHash,
    oauthBoundary: authConfig.oauthBoundary,
    materialVaultRefHash,
    materialConfigured: Boolean(materialHash),
    materialPersistence: materialHash ? materialPersistence : "metadata_only",
    runtimeMaterialStatus: materialHash ? runtimeMaterialStatus : "unconfigured",
    vaultMaterialSource: materialSource,
    updatedAt,
    evidenceRefs: normalizeScopes(evidenceRefs, ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"]),
  };
  return {
    record,
    runtimeMaterial: materialHash ? runtimeMaterial : null,
    evidenceRefs: record.evidenceRefs,
  };
}

export function catalogProviderRuntimeMaterialFromBody(providerId, body = {}) {
  assertCanonicalCatalogProviderSourceRequestBody(body);
  const source =
    providerId === "catalog.local_manifest"
      ? body.manifest_path ?? body.path ?? null
      : providerId === "catalog.custom_http" || providerId === "catalog.huggingface"
        ? body.base_url ?? body.url ?? null
        : null;
  return source === null ? {} : catalogProviderRuntimeMaterialFromValue(providerId, source);
}

function assertCanonicalCatalogProviderSourceRequestBody(body = {}) {
  const retiredAliases = RETIRED_CATALOG_PROVIDER_SOURCE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "catalog_provider_source_request_aliases_retired",
    message: "Catalog provider source request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_CATALOG_PROVIDER_SOURCE_REQUEST_FIELDS,
    },
  });
}

export function catalogProviderAuthConfig(providerId, body = {}, existing = null, state) {
  assertCanonicalCatalogProviderAuthRequestBody(body);
  const authVaultInput = firstOwn(body, ["auth_vault_ref"]);
  const authVaultRef =
    authVaultInput.has
      ? typeof authVaultInput.value === "string" && authVaultInput.value.trim()
        ? authVaultInput.value.trim()
        : null
      : existing?.authVaultRef ?? null;
  const authVaultRefHash = authVaultRef
    ? state.walletAuthority.resolveVaultRef(authVaultRef).vaultRefHash
    : authVaultInput.has
      ? null
      : existing?.authVaultRefHash ?? null;
  const rawScheme = body.auth_scheme ?? existing?.catalogAuthScheme ?? "bearer";
  const catalogAuthScheme = normalizeCatalogAuthScheme(rawScheme);
  const rawHeaderName = body.auth_header_name ?? existing?.catalogAuthHeaderName ?? "authorization";
  const catalogAuthHeaderName = normalizeProviderAuthHeaderName(rawHeaderName);
  const catalogAuthHeaderNameHash = stableHash(catalogAuthHeaderName);
  const oauthSessionInput = firstOwn(body, ["oauth_session_id"]);
  const oauthSessionId =
    oauthSessionInput.has
      ? typeof oauthSessionInput.value === "string" && oauthSessionInput.value.trim()
        ? oauthSessionInput.value.trim()
        : null
      : existing?.oauthSessionId ?? null;
  const oauthSessionHash = oauthSessionId ? stableHash(oauthSessionId) : oauthSessionInput.has ? null : existing?.oauthSessionHash ?? null;
  const oauthSession = oauthSessionId ? state?.oauthSessions?.get(oauthSessionId) ?? null : null;
  const catalogAuthConfigured = Boolean(authVaultRefHash || oauthSessionHash);
  const oauthBoundary =
    catalogAuthScheme === "oauth2"
      ? oauthSession
        ? oauthBoundaryForSession(oauthSession)
        : {
            configured: catalogAuthConfigured,
            status: catalogAuthConfigured ? "vault_token_passthrough" : "requires_oauth_exchange",
            tokenExchange: catalogAuthConfigured ? "vault_token_passthrough" : "OAuthCredentialProvider.exchangeAuthorizationCode",
            oauthSessionHash,
            evidenceRefs: ["catalog_oauth_boundary", "vault_ref_oauth_token_material"],
          }
      : null;
  return {
    authVaultRef,
    authVaultRefHash,
    catalogAuthConfigured,
    catalogAuthScheme,
    catalogAuthHeaderName,
    catalogAuthHeaderNameHash,
    oauthSessionId,
    oauthSessionHash,
    oauthBoundary,
  };
}

function assertCanonicalCatalogProviderAuthRequestBody(body = {}) {
  const retiredAliases = RETIRED_CATALOG_PROVIDER_AUTH_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "catalog_provider_auth_request_aliases_retired",
    message: "Catalog provider auth request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_CATALOG_PROVIDER_AUTH_REQUEST_FIELDS,
    },
  });
}

export function firstOwn(value, keys) {
  if (!value || typeof value !== "object") return { has: false, value: undefined };
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      return { has: true, value: value[key] };
    }
  }
  return { has: false, value: undefined };
}

export function normalizeCatalogAuthScheme(value) {
  const scheme = String(value ?? "bearer").toLowerCase().replace(/[-\s]+/g, "_");
  if (["bearer", "raw", "api_key", "oauth2"].includes(scheme)) return scheme;
  throw runtimeError({
    status: 400,
    code: "validation",
    message: "Catalog auth scheme must be bearer, raw, api_key, or oauth2.",
    details: { auth_scheme: scheme },
  });
}

export function catalogProviderRuntimeMaterialFromValue(providerId, value) {
  if (providerId === "catalog.local_manifest") {
    return { manifestPath: typeof value === "string" && value.trim() ? path.resolve(value.trim()) : null };
  }
  if (providerId === "catalog.custom_http" || providerId === "catalog.huggingface") {
    return { baseUrl: typeof value === "string" && value.trim() ? value.trim().replace(/\/+$/, "") : null };
  }
  return {};
}

export function catalogProviderHasSourceMaterial(material) {
  return Boolean(material?.manifestPath || material?.baseUrl);
}

export function catalogProviderSourceValue(providerId, material) {
  return providerId === "catalog.local_manifest" ? path.resolve(material.manifestPath) : material?.baseUrl ?? "";
}

export function catalogProviderMaterialVaultRef(providerId) { return `vault://ioi/model-catalog/${safeId(providerId)}/source`; }

export function catalogProviderMaterialPurpose(providerId) { return `catalog.source:${providerId}`; }

export function catalogProviderMaterialLabel(providerId) {
  if (providerId === "catalog.local_manifest") return "Local manifest catalog source";
  return providerId === "catalog.huggingface" ? "Hugging Face-compatible catalog source" : "Custom HTTP catalog source";
}

export async function catalogProviderAuthHeaders(providerId, state) {
  const config = state?.catalogProviderConfig?.(providerId) ?? null;
  if (!config?.authVaultRef && !config?.authVaultRefHash && !config?.oauthSessionId) return { headers: {}, evidence: null };
  const headerName = normalizeProviderAuthHeaderName(config.catalogAuthHeaderName ?? "authorization");
  const authScheme = normalizeCatalogAuthScheme(config.catalogAuthScheme ?? "bearer");
  if (authScheme === "oauth2" && config.oauthSessionId) {
    const session = state?.oauthSessions?.get(config.oauthSessionId) ?? null;
    const resolved = await state.oauthCredentialProvider.resolveAccessHeader(session, { providerId, headerName });
    if (resolved.refreshed) {
      state.oauthSessions.set(resolved.session.id, resolved.session);
      state.writeMap?.("oauth-sessions", state.oauthSessions);
      if (config?.id && state.catalogProviderConfigs?.has(config.id)) {
        state.catalogProviderConfigs.set(config.id, {
          ...config,
          oauthBoundary: oauthBoundaryForSession(resolved.session, { refreshed: true }),
          updatedAt: state.nowIso?.() ?? config.updatedAt,
        });
        state.writeMap?.("model-catalog-providers", state.catalogProviderConfigs);
      }
    }
    state?.writeVaultRefs?.();
    return {
      headers: { [headerName]: resolved.headerValue },
      evidence: resolved.evidence,
    };
  }
  if (!config.authVaultRef) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Catalog auth is configured by hash only; request-time vault ref resolution requires a vault ref.",
      details: {
        catalog_provider_id: providerId,
        auth_vault_ref_hash: config.authVaultRefHash ?? null,
        resolved_material: false,
        evidence_refs: ["catalog_auth_fail_closed", "vault_ref_required"],
      },
    });
  }
  const resolved = state?.vault?.resolveVaultRef(config.authVaultRef, `catalog.auth:${providerId}`);
  state?.writeVaultRefs?.();
  if (!resolved?.material) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Catalog auth vault ref is configured, but no runtime vault material is available.",
      details: {
        catalog_provider_id: providerId,
        auth_vault_ref_hash: resolved?.vaultRefHash ?? config.authVaultRefHash ?? stableHash(config.authVaultRef),
        resolved_material: false,
        catalog_auth_scheme: authScheme,
        catalog_auth_header_name_hash: stableHash(headerName),
        evidence_refs: normalizeScopes(resolved?.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_auth_fail_closed"]),
      },
    });
  }
  return {
    headers: {
      [headerName]: catalogAuthorizationHeaderValue(authScheme, resolved.material),
    },
    evidence: {
      authVaultRefHash: resolved.vaultRefHash,
      resolvedMaterial: true,
      catalogAuthResolved: true,
      catalogAuthScheme: authScheme,
      catalogAuthHeaderNameHash: stableHash(headerName),
      headerNames: [headerName],
      oauthBoundary:
        authScheme === "oauth2"
          ? {
              configured: true,
              status: "vault_token_passthrough",
              tokenExchange: "not_local",
              evidenceRefs: ["catalog_oauth_boundary", "vault_ref_oauth_token_material"],
            }
          : null,
      evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_auth_resolved"]),
    },
  };
}

export function catalogAuthorizationHeaderValue(authScheme, material) {
  if (authScheme === "raw" || authScheme === "api_key") return material;
  return `Bearer ${material}`;
}
