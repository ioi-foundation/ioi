export function isFixtureEndpointCandidate(endpoint = {}, provider = {}) {
  const haystack = [
    endpoint.id,
    endpoint.modelId,
    endpoint.apiFormat,
    endpoint.driver,
    endpoint.baseUrl,
    endpoint.backendId,
    provider.id,
    provider.kind,
    provider.driver,
  ]
    .map((value) => String(value ?? "").toLowerCase())
    .join(" ");
  return (
    haystack.includes("fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k") ||
    haystack.includes("backend.fixture")
  );
}

export function isFixtureModelRecord(record = {}) {
  const haystack = [
    record.id,
    record.modelId,
    record.model_id,
    record.displayName,
    record.name,
    record.family,
    record.quantization,
    record.source,
    record.driver,
    record.providerId,
    record.provider_id,
    record.artifactPath,
    record.artifact_path,
  ]
    .map((value) => String(value ?? "").toLowerCase())
    .join(" ");
  return (
    haystack.includes("fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k")
  );
}
