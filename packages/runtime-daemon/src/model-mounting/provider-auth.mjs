import {
  runtimeError,
  stableHash,
} from "./io.mjs";

const SECRET_REDACTION = "[REDACTED]";

export function sanitizeVaultRefs(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, vaultRef]) => [
      key,
      typeof vaultRef === "string" && vaultRef.startsWith("vault://") ? vaultRef : SECRET_REDACTION,
    ]),
  );
}

export function providerSecretInput(body = {}) {
  for (const key of ["secret_ref", "secretRef", "auth_vault_ref", "authVaultRef", "api_key_vault_ref", "apiKeyVaultRef"]) {
    if (Object.prototype.hasOwnProperty.call(body, key)) return body[key];
  }
  return undefined;
}

export function providerRequiresVaultSecret(providerOrKind) {
  const kind = typeof providerOrKind === "string" ? providerOrKind : providerOrKind?.kind;
  return ["openai", "anthropic", "gemini", "custom_http"].includes(kind);
}

export function assertNoPlaintextProviderSecret(body = {}) {
  for (const key of Object.keys(body)) {
    if (isPlaintextProviderSecretKey(key)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Provider secrets and auth headers must be configured through wallet.network vault refs.",
        details: { field: key, secret: SECRET_REDACTION },
      });
    }
  }
}

export function isPlaintextProviderSecretKey(key) {
  return /^(api_?key|authorization|auth|headers?|bearer_?token|access_?token|provider_?key)$/i.test(String(key));
}

export function assertProviderVaultBoundary(provider) {
  if (!providerRequiresVaultSecret(provider)) return;
  if (providerHasVaultRef(provider)) return;
  throw runtimeError({
    status: 403,
    code: "policy",
    message: "Hosted and custom HTTP providers fail closed until auth is bound to a wallet.network vault ref.",
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      vaultRefConfigured: false,
    },
  });
}

export function providerHasVaultRef(provider) {
  return typeof provider.secretRef === "string" && provider.secretRef.startsWith("vault://");
}

export function providerAuthHeaders(provider, state) {
  const requiresVault = providerRequiresVaultSecret(provider);
  const hasVaultRef = providerHasVaultRef(provider);
  if (!requiresVault && !hasVaultRef) return { headers: {}, evidence: null };
  if (requiresVault) assertProviderVaultBoundary(provider);
  const resolved = state?.vault?.resolveVaultRef(provider.secretRef, `provider.auth:${provider.id}`);
  const headerName = normalizeProviderAuthHeaderName(provider.authHeaderName ?? provider.auth_header_name);
  if (!resolved?.material) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Provider vault ref is configured, but no runtime vault material is available.",
      details: {
        providerId: provider.id,
        providerKind: provider.kind,
        vaultRefHash: stableHash(provider.secretRef),
        resolvedMaterial: false,
      },
    });
  }
  return {
    headers: {
      [headerName]: providerAuthorizationHeaderValue(provider, resolved.material),
    },
    evidence: {
      vaultRefHash: resolved.vaultRefHash,
      resolvedMaterial: true,
      evidenceRefs: resolved.evidenceRefs ?? ["VaultPort.resolveVaultRef"],
      headerNames: [headerName],
      authScheme: normalizeProviderAuthScheme(provider.authScheme ?? provider.auth_scheme),
    },
  };
}

export function providerAuthorizationHeaderValue(provider, material) {
  const scheme = normalizeProviderAuthScheme(provider.authScheme ?? provider.auth_scheme);
  if (scheme === "raw") return material;
  if (scheme === "api_key") return material;
  return `Bearer ${material}`;
}

export function normalizeProviderAuthScheme(value) {
  const scheme = String(value ?? "bearer").toLowerCase().replace(/[-\s]+/g, "_");
  if (["bearer", "raw", "api_key"].includes(scheme)) return scheme;
  throw runtimeError({
    status: 400,
    code: "validation",
    message: "Provider auth scheme must be bearer, raw, or api_key.",
    details: { authScheme: scheme },
  });
}

export function normalizeProviderAuthHeaderName(value) {
  const headerName = String(value ?? "authorization").trim().toLowerCase();
  if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(headerName)) {
    throw runtimeError({
      status: 400,
      code: "validation",
      message: "Provider auth header name must be a valid HTTP header token.",
      details: { authHeaderName: SECRET_REDACTION },
    });
  }
  const forbidden = new Set([
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);
  if (forbidden.has(headerName)) {
    throw runtimeError({
      status: 400,
      code: "validation",
      message: "Provider auth header name is not allowed for vault-backed auth injection.",
      details: { authHeaderName: headerName },
    });
  }
  return headerName;
}
