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
