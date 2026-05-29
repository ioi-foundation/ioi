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
