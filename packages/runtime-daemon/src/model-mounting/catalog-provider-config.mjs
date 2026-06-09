import path from "node:path";

import {
  normalizeScopes,
  runtimeError,
  safeId,
  stableHash,
} from "./io.mjs";
import {
  normalizeProviderAuthHeaderName,
} from "./provider-auth.mjs";
import {
  oauthBoundaryForSession,
} from "./oauth-boundary.mjs";

export const MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS = ["catalog.local_manifest", "catalog.custom_http", "catalog.huggingface"];

const RETIRED_CATALOG_PROVIDER_SOURCE_REQUEST_ALIASES = [
  "path",
  "url",
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

export function catalogProviderRuntimeMaterialFromBody(providerId, body = {}) {
  assertCanonicalCatalogProviderSourceRequestBody(body);
  const source =
    providerId === "catalog.local_manifest"
      ? body.manifest_path ?? null
      : providerId === "catalog.custom_http" || providerId === "catalog.huggingface"
        ? body.base_url ?? null
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
            tokenExchange: catalogAuthConfigured ? "vault_token_passthrough" : "RustDaemonCore.catalogProviderOAuth",
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

export function catalogProviderMaterialVaultRef(providerId) { return `vault://ioi/model-catalog/${safeId(providerId)}/source`; }

export function catalogProviderMaterialPurpose(providerId) { return `catalog.source:${providerId}`; }

export async function catalogProviderAuthHeaders(providerId, state) {
  const config = state?.catalogProviderConfig?.(providerId) ?? null;
  if (!config?.authVaultRef && !config?.authVaultRefHash && !config?.oauthSessionId) return { headers: {}, evidence: null };
  const headerName = normalizeProviderAuthHeaderName(config.catalogAuthHeaderName ?? "authorization");
  const authScheme = normalizeCatalogAuthScheme(config.catalogAuthScheme ?? "bearer");
  if (authScheme === "oauth2" && config.oauthSessionId) {
    throwCatalogProviderControlRustCoreRequired(
      "model_mount.catalog_provider_auth_header.refresh",
      {
        provider_id: providerId,
        oauth_session_hash: config.oauthSessionHash ?? stableHash(config.oauthSessionId),
        catalog_auth_scheme: authScheme,
        catalog_auth_header_name_hash: stableHash(headerName),
      },
    );
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

export function throwCatalogProviderControlRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_catalog_provider_control_rust_core_required",
    message:
      "Catalog provider configuration, OAuth, and auth-header mutation facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.catalog_provider_control",
      evidence_refs: [
        "public_catalog_provider_control_js_facade_retired",
        "rust_daemon_core_catalog_provider_control_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}
