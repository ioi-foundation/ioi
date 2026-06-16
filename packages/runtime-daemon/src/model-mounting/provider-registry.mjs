const HOSTED_PROVIDER_VAULT_EVIDENCE_REFS = [
  "wallet.network.vault_ref_boundary",
  "provider_request_time_secret_resolution",
  "provider_env_secret_material_fallback_retired",
];

export function hostedProvider(id, label, apiFormat, options = {}) {
  assertNoPlaintextHostedProviderSecretOptions(options);
  const secretRef = typeof options.secret_ref === "string" && options.secret_ref.trim()
    ? options.secret_ref.trim()
    : `vault://${id}/api-key`;
  return {
    id,
    kind: apiFormat,
    label,
    apiFormat,
    driver: "openai_compatible",
    baseUrl: null,
    status: options.configured === true ? "configured" : "blocked",
    privacyClass: "hosted",
    capabilities: ["chat", "responses", "embeddings"],
    discovery: {
      checkedAt: new Date().toISOString(),
      evidenceRefs: HOSTED_PROVIDER_VAULT_EVIDENCE_REFS,
    },
    secretRef,
    estimatedCostUsd: 0.01,
  };
}

function assertNoPlaintextHostedProviderSecretOptions(options) {
  if (typeof options === "string") {
    throw Object.assign(
      new Error("Hosted provider plaintext secret arguments are retired; bind wallet.network vault refs instead."),
      {
        code: "hosted_provider_plaintext_secret_argument_retired",
      },
    );
  }
  if (!options || typeof options !== "object" || Array.isArray(options)) return;
  const retiredFields = ["secret", "secretRef", "apiKey", "api_key", "authorization", "bearerToken", "accessToken"]
    .filter((field) => Object.hasOwn(options, field));
  if (retiredFields.length === 0) return;
  throw Object.assign(
    new Error("Hosted provider plaintext secret options are retired; use canonical secret_ref vault refs."),
    {
      code: "hosted_provider_plaintext_secret_options_retired",
      retiredFields,
    },
  );
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
