import {
  runtimeError,
} from "./io.mjs";

const SECRET_REDACTION = "[REDACTED]";

const RETIRED_PROVIDER_SECRET_REQUEST_ALIASES = [
  "secretRef",
  "authVaultRef",
  "apiKeyVaultRef",
];

const CANONICAL_PROVIDER_SECRET_REQUEST_FIELDS = [
  "secret_ref",
  "auth_vault_ref",
  "api_key_vault_ref",
];

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
  assertCanonicalProviderSecretRequestBody(body);
  for (const key of CANONICAL_PROVIDER_SECRET_REQUEST_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(body, key)) return body[key];
  }
  return undefined;
}

function assertCanonicalProviderSecretRequestBody(body = {}) {
  const retiredAliases = RETIRED_PROVIDER_SECRET_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "provider_secret_request_aliases_retired",
    message: "Provider secret request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_PROVIDER_SECRET_REQUEST_FIELDS,
    },
  });
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
