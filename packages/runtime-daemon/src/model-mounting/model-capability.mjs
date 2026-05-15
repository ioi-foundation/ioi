export const MODEL_CAPABILITY_SCHEMA_VERSION = "ioi.model-capability.v1";

const ACTIVE_PROVIDER_STATUSES = new Set(["available", "configured", "running"]);
const HOSTED_PROVIDER_KINDS = new Set(["openai", "anthropic", "gemini", "custom_http"]);

export function modelCapabilities({
  routes = [],
  endpoints = [],
  providers = [],
  artifacts = [],
  instances = [],
} = {}) {
  const endpointById = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const providerById = new Map(providers.map((provider) => [provider.id, provider]));
  const artifactByModelId = new Map(artifacts.map((artifact) => [artifact.modelId, artifact]));
  const loadedEndpointIds = new Set(
    instances.filter((instance) => instance.status === "loaded").map((instance) => instance.endpointId),
  );

  return routes.map((route) =>
    modelCapabilityForRoute(route, {
      artifactByModelId,
      endpointById,
      loadedEndpointIds,
      providerById,
    }),
  );
}

function modelCapabilityForRoute(route, context) {
  const candidates = route.fallback.map((endpointId, index) =>
    candidateReadiness(route, endpointId, index, context),
  );
  const readyCandidates = candidates.filter((candidate) => candidate.ready);
  const missingVaultCount = candidates.filter((candidate) => candidate.vaultRequired && !candidate.vaultReady).length;
  const selectedCandidate = readyCandidates[0] ?? candidates[0] ?? null;
  const credentialStatus = readinessStatus(route, candidates, readyCandidates);
  const available = route.status === "active" && readyCandidates.length > 0;
  const capability = selectedCandidate?.capability ?? "chat";

  return {
    schemaVersion: MODEL_CAPABILITY_SCHEMA_VERSION,
    object: "ioi.model_capability",
    id: `model-capability:${route.id}`,
    routeId: route.id,
    role: route.role,
    modelRole: route.role,
    capability,
    primitiveCapability: `prim:model.${capability}`,
    authorityScopeRequirements: [`route.use:${route.id}`, `model.${capability}:*`],
    policyTarget: modelPolicyTarget(route.id),
    privacyTier: route.privacy,
    providerPriority: route.providerEligibility,
    fallbackPolicy: {
      allowed: route.fallback.length > 1,
      endpointIds: route.fallback,
      deniedProviders: route.deniedProviders,
      selectedEndpointId: selectedCandidate?.endpointId ?? null,
      deterministicOrder: true,
    },
    fallbackEvidence: candidates.map((candidate) => candidate.evidence),
    costEstimateVisibility: {
      visible: true,
      maxCostUsd: route.maxCostUsd,
      maxLatencyMs: route.maxLatencyMs,
      source: "model_route_policy",
    },
    credentialReadiness: {
      status: credentialStatus,
      reason: readinessReason(route, candidates, readyCandidates),
      evidenceRefs: compactEvidence(candidates.flatMap((candidate) => candidate.evidenceRefs)),
    },
    vaultReadiness: {
      status: missingVaultCount === 0 ? "ready" : "missing",
      requiredCount: candidates.filter((candidate) => candidate.vaultRequired).length,
      configuredCount: candidates.filter((candidate) => candidate.vaultRequired && candidate.vaultReady).length,
      missingCount: missingVaultCount,
    },
    byokRequired: candidates.some((candidate) => candidate.vaultRequired),
    receiptBehavior: {
      receiptRequired: true,
      requiredReceiptTypes: ["model_route_selection", "model_invocation"],
    },
    workflowAvailability: {
      available,
      reason: available ? "At least one route candidate is executable." : "No executable model route candidate is ready.",
      configFields: ["modelRef", "routeId", "modelBinding"],
      evidenceRefs: compactEvidence(candidates.flatMap((candidate) => candidate.evidenceRefs)),
    },
    agentAvailability: {
      available,
      reason: available ? "Agent runtime can request this route capability." : "Agent runtime must resolve model readiness first.",
      evidenceRefs: compactEvidence(candidates.flatMap((candidate) => candidate.evidenceRefs)),
    },
    candidates,
  };
}

function candidateReadiness(route, endpointId, priority, { artifactByModelId, endpointById, providerById, loadedEndpointIds }) {
  const endpoint = endpointById.get(endpointId) ?? null;
  const provider = endpoint ? providerById.get(endpoint.providerId) ?? null : null;
  const artifact = endpoint ? artifactByModelId.get(endpoint.modelId) ?? null : null;
  const vaultRequired = providerRequiresVault(provider);
  const vaultReady = !vaultRequired || Boolean(provider?.secretConfigured || provider?.vaultBoundary?.configured);
  const providerReady = provider ? ACTIVE_PROVIDER_STATUSES.has(String(provider.status)) : false;
  const endpointReady = endpoint ? endpoint.status === "mounted" || loadedEndpointIds.has(endpoint.id) : false;
  const ready = route.status === "active" && endpointReady && providerReady && vaultReady;
  const reason = readinessCandidateReason({ endpoint, endpointReady, provider, providerReady, vaultRequired, vaultReady });
  const evidenceRefs = compactEvidence([
    endpoint?.lastReceiptId,
    provider?.lastReceiptId,
    artifact?.lastReceiptId,
    ...(endpoint?.evidenceRefs ?? []),
    ...(provider?.evidenceRefs ?? []),
  ]);

  return {
    endpointId,
    priority,
    modelId: endpoint?.modelId ?? null,
    providerId: provider?.id ?? null,
    providerKind: provider?.kind ?? null,
    capability: firstCapability(endpoint?.capabilities ?? artifact?.capabilities),
    privacyTier: endpoint?.privacyClass ?? provider?.privacyClass ?? route.privacy,
    status: ready ? "ready" : "blocked",
    ready,
    vaultRequired,
    vaultReady,
    reason,
    evidenceRefs,
    evidence: {
      endpointId,
      providerId: provider?.id ?? null,
      status: ready ? "ready" : "blocked",
      reason,
      vaultRequired,
      vaultReady,
    },
  };
}

function providerRequiresVault(provider) {
  if (!provider) return false;
  return Boolean(provider.vaultBoundary?.required) || HOSTED_PROVIDER_KINDS.has(String(provider.kind));
}

function modelPolicyTarget(routeId) {
  return routeId.startsWith("route.") ? `model.${routeId}` : `model.route.${routeId}`;
}

function readinessStatus(route, candidates, readyCandidates) {
  if (route.status !== "active") return "disabled";
  if (readyCandidates.length > 0) return "ready";
  if (candidates.some((candidate) => candidate.vaultRequired && !candidate.vaultReady)) return "missing";
  return "degraded";
}

function readinessReason(route, candidates, readyCandidates) {
  if (route.status !== "active") return "Model route is disabled.";
  if (readyCandidates.length > 0) return "Route has an executable candidate.";
  return candidates[0]?.reason ?? "Route has no configured fallback candidates.";
}

function readinessCandidateReason({ endpoint, endpointReady, provider, providerReady, vaultRequired, vaultReady }) {
  if (!endpoint) return "Route fallback endpoint is not registered.";
  if (!provider) return "Endpoint provider is not registered.";
  if (!providerReady) return `Provider status is ${provider.status}.`;
  if (vaultRequired && !vaultReady) return "Provider requires wallet vault credentials.";
  if (!endpointReady) return `Endpoint status is ${endpoint.status}.`;
  return "Endpoint, provider, and credential posture are ready.";
}

function firstCapability(capabilities) {
  return Array.isArray(capabilities) && capabilities.length > 0 ? String(capabilities[0]) : "chat";
}

function compactEvidence(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.trim()))];
}
