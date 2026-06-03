const SECRET_REDACTION = "[REDACTED]";

export function hostedProvider(id, label, apiFormat, secret) {
  return {
    id,
    kind: apiFormat,
    label,
    apiFormat,
    driver: "openai_compatible",
    baseUrl: null,
    status: secret ? "configured" : "blocked",
    privacyClass: "hosted",
    capabilities: ["chat", "responses", "embeddings"],
    discovery: {
      checkedAt: new Date().toISOString(),
      evidenceRefs: [`${label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_API_KEY`],
    },
    secretRef: secret ? `vault://${id}/api-key` : null,
    estimatedCostUsd: 0.01,
  };
}

export function publicProvider(provider, vaultMetadata = null, deps = {}) {
  const {
    providerHasVaultRef,
    providerRequiresVaultSecret,
    stableHash,
  } = deps;
  if (typeof providerHasVaultRef !== "function") {
    throw new TypeError("publicProvider requires providerHasVaultRef.");
  }
  if (typeof providerRequiresVaultSecret !== "function") {
    throw new TypeError("publicProvider requires providerRequiresVaultSecret.");
  }
  if (typeof stableHash !== "function") {
    throw new TypeError("publicProvider requires stableHash.");
  }
  const hasVaultRef = providerHasVaultRef(provider);
  const requiresVault = providerRequiresVaultSecret(provider);
  const runtimeBound = Boolean(vaultMetadata?.resolvedMaterial);
  const configured = hasVaultRef || Boolean(vaultMetadata?.configured);
  return {
    ...provider,
    status: requiresVault && !hasVaultRef ? "blocked" : provider.status,
    secretRef: hasVaultRef ? { redacted: true, hash: stableHash(provider.secretRef) } : provider.secretRef ? SECRET_REDACTION : null,
    secretConfigured: configured,
    authScheme: provider.authScheme ?? "bearer",
    authHeaderName: provider.authHeaderName ?? "authorization",
    vaultBoundary: {
      required: requiresVault,
      failClosed: requiresVault && !hasVaultRef,
      configured,
      resolvedMaterial: runtimeBound,
      runtimeBound,
      requiresRuntimeBinding: configured && !runtimeBound,
      vaultRefHash: hasVaultRef ? stableHash(provider.secretRef) : vaultMetadata?.vaultRefHash ?? null,
    },
  };
}

export function requiredString(value, field, deps = {}) {
  const { runtimeError } = deps;
  if (typeof value !== "string" || value.trim() === "") {
    const errorFactory = typeof runtimeError === "function"
      ? runtimeError
      : ({ status, code, message, details }) => Object.assign(new Error(message), { status, code, details });
    throw errorFactory({
      status: 400,
      code: "runtime",
      message: `${field} is required.`,
      details: { field },
    });
  }
  return value;
}

export function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}
