import type {
  GraphModelBinding,
  NodeLogic,
  WorkflowCapabilityAvailability,
  WorkflowCapabilityCredentialReadiness,
  WorkflowModelBinding,
} from "../types/graph";

export const MODEL_CAPABILITY_BINDING_ENDPOINT = "/v1/model-capabilities";
export const MODEL_AUTHORITY_BINDING_ENDPOINT = "/api/v1/authority";

export const WORKFLOW_MODEL_BINDING_KEYS = [
  "reasoning",
  "vision",
  "embedding",
  "image",
] as const;

export type WorkflowModelBindingKey = (typeof WORKFLOW_MODEL_BINDING_KEYS)[number];

const DEFAULT_ROUTE_ID_BY_MODEL_REF: Record<string, string> = {
  reasoning: "route.local-first",
  vision: "route.local-first",
  embedding: "route.local-first",
  image: "route.local-first",
};

const DEFAULT_CAPABILITY_BY_MODEL_REF: Record<string, string> = {
  reasoning: "chat",
  vision: "vision",
  embedding: "embeddings",
  image: "vision",
};

const DEFAULT_PROVIDER_PRIORITY = ["local_private", "workspace", "hosted"];

function cleanText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function capabilityForModelRef(modelRef: string, explicitCapability?: string): string {
  return cleanText(explicitCapability) || DEFAULT_CAPABILITY_BY_MODEL_REF[modelRef] || "chat";
}

function routeIdForModelRef(modelRef: string, routeId?: string): string {
  return cleanText(routeId) || DEFAULT_ROUTE_ID_BY_MODEL_REF[modelRef] || "route.local-first";
}

export function modelCapabilityRefForRoute(routeId: string): string {
  return `model-capability:${routeIdForModelRef("reasoning", routeId)}`;
}

export function defaultModelAuthorityScopes(routeId: string, capability = "chat"): string[] {
  return [`route.use:${routeId}`, `model.${capability}:*`];
}

export function defaultModelReceiptBehavior(): Record<string, unknown> {
  return {
    receiptRequired: true,
    requiredReceiptTypes: ["model_route_selection", "model_invocation"],
  };
}

function defaultAvailability(
  available: boolean,
  reason: string,
): WorkflowCapabilityAvailability {
  return {
    available,
    reason,
    configFields: ["modelCapabilityRef", "routeId", "modelBinding"],
  };
}

function defaultReadiness(
  ready: boolean,
  evidenceRef: string,
  reason: string,
): WorkflowCapabilityCredentialReadiness {
  return {
    status: ready ? "ready" : "unknown",
    reason,
    evidenceRefs: ready ? [evidenceRef] : [],
  };
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => cleanText(item))
    .filter(Boolean);
}

function hasReadyCredentialProjection(binding: {
  credentialReady?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
}): boolean {
  const status = cleanText(binding.credentialReadiness?.status).toLowerCase();
  return Boolean(binding.credentialReady) || status === "ready";
}

export function normalizeGraphModelBinding(
  modelRef: string,
  binding: Partial<GraphModelBinding> | null | undefined,
): GraphModelBinding {
  const modelId = cleanText(binding?.modelId) || "";
  const routeId = routeIdForModelRef(modelRef, binding?.routeId);
  const capability = capabilityForModelRef(modelRef);
  const modelCapabilityRef =
    cleanText(binding?.modelCapabilityRef) || modelCapabilityRefForRoute(routeId);
  const authorityScopes = stringArray(binding?.authorityScopes).length
    ? stringArray(binding?.authorityScopes)
    : stringArray(binding?.authorityScopeRequirements).length
      ? stringArray(binding?.authorityScopeRequirements)
      : defaultModelAuthorityScopes(routeId, capability);
  const ready = hasReadyCredentialProjection({
    credentialReadiness: binding?.credentialReadiness,
  });
  const evidenceRef = modelCapabilityRef;

  return {
    modelId,
    modelRef,
    routeId,
    modelCapabilityRef,
    authorityScopes,
    authorityScopeRequirements: stringArray(binding?.authorityScopeRequirements).length
      ? stringArray(binding?.authorityScopeRequirements)
      : authorityScopes,
    receiptBehavior: binding?.receiptBehavior ?? defaultModelReceiptBehavior(),
    credentialReadiness:
      binding?.credentialReadiness ??
      defaultReadiness(
        ready,
        evidenceRef,
        ready
          ? "Model binding readiness was projected from canonical credential metadata."
          : "No executable model capability readiness has been confirmed.",
      ),
    workflowAvailability:
      binding?.workflowAvailability ??
      defaultAvailability(
        ready,
        ready
          ? "Workflow can bind this projected model capability."
          : "Workflow needs a ready model capability before activation.",
      ),
    agentAvailability:
      binding?.agentAvailability ??
      defaultAvailability(
        ready,
        ready
          ? "Agent runtime can request this projected model capability."
          : "Agent runtime needs model capability readiness before execution.",
      ),
    privacyTier: binding?.privacyTier ?? "local_or_enterprise",
    providerPriority: binding?.providerPriority ?? DEFAULT_PROVIDER_PRIORITY,
    fallbackPolicy:
      binding?.fallbackPolicy ??
      {
        allowed: false,
        endpointIds: [],
        selectedEndpointId: null,
        deterministicOrder: true,
      },
    fallbackEvidence: binding?.fallbackEvidence ?? [],
    costEstimateVisibility:
      binding?.costEstimateVisibility ??
      {
        visible: true,
        maxCostUsd: null,
        source: "workflow_model_capability_projection",
      },
    grantReadiness:
      binding?.grantReadiness ??
      defaultReadiness(
        ready,
        evidenceRef,
        ready
          ? "Model capability grant posture was projected from canonical credential metadata."
          : "No model capability grant has been confirmed.",
      ),
    policyPosture:
      binding?.policyPosture ??
      {
        status: ready ? "allowed" : "unknown",
        policyTarget: `model.${routeId}`,
        source: "workflow_model_capability_projection",
      },
    vaultReadiness: binding?.vaultReadiness,
    byokRequired: binding?.byokRequired,
    required: binding?.required,
    modelHash: binding?.modelHash,
    mockBinding: binding?.mockBinding,
  };
}

export function normalizeWorkflowModelBinding(
  binding: Partial<WorkflowModelBinding> | null | undefined,
  logic: Partial<NodeLogic> = {},
): WorkflowModelBinding {
  const modelRef = cleanText(binding?.modelRef) || cleanText(logic.modelRef) || "reasoning";
  const modelId = binding?.modelId ?? logic.modelId ?? null;
  const routeId = routeIdForModelRef(modelRef, binding?.routeId ?? logic.routeId);
  const capability = capabilityForModelRef(modelRef, binding?.capability ?? logic.capability);
  const modelCapabilityRef =
    cleanText(binding?.modelCapabilityRef) ||
    cleanText(logic.modelCapabilityRef) ||
    modelCapabilityRefForRoute(routeId);
  const authorityScopes = stringArray(binding?.authorityScopes).length
    ? stringArray(binding?.authorityScopes)
    : stringArray(binding?.authorityScopeRequirements).length
      ? stringArray(binding?.authorityScopeRequirements)
      : defaultModelAuthorityScopes(routeId, capability);
  const mockBinding = binding?.mockBinding ?? true;
  const ready = hasReadyCredentialProjection({
    credentialReady: binding?.credentialReady,
    credentialReadiness: binding?.credentialReadiness,
  });

  return {
    modelRef,
    modelId,
    routeId,
    modelCapabilityRef,
    reasoningEffort: binding?.reasoningEffort ?? logic.reasoningEffort ?? "medium",
    modelPolicy: binding?.modelPolicy ?? logic.modelPolicy,
    capability: capability as WorkflowModelBinding["capability"],
    receiptRequired: binding?.receiptRequired ?? logic.receiptRequired ?? true,
    daemonApi: binding?.daemonApi,
    selectedEndpointId: binding?.selectedEndpointId ?? null,
    lastReceiptId: binding?.lastReceiptId ?? null,
    mockBinding,
    capabilityScope: binding?.capabilityScope ?? [capability],
    argumentSchema: binding?.argumentSchema ?? logic.inputSchema ?? { type: "object" },
    resultSchema: binding?.resultSchema ?? logic.outputSchema ?? { type: "object" },
    sideEffectClass: binding?.sideEffectClass ?? "none",
    requiresApproval: binding?.requiresApproval ?? false,
    credentialReady: binding?.credentialReady ?? ready,
    credentialReadiness:
      binding?.credentialReadiness ??
      defaultReadiness(
        ready,
        modelCapabilityRef,
        ready
          ? "Model binding readiness projected into the canonical capability contract."
          : "No executable model capability readiness has been confirmed.",
      ),
    receiptBehavior: binding?.receiptBehavior ?? defaultModelReceiptBehavior(),
    workflowAvailability:
      binding?.workflowAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock model binding is available only for mock-authorized runs."
          : ready
            ? "Workflow can bind this model capability."
            : "Workflow needs a ready model capability before activation.",
      ),
    agentAvailability:
      binding?.agentAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock model binding is available only for mock-authorized runs."
          : ready
            ? "Agent runtime can request this model capability."
            : "Agent runtime needs model capability readiness before execution.",
      ),
    privacyTier: binding?.privacyTier ?? "local_or_enterprise",
    providerPriority: binding?.providerPriority ?? DEFAULT_PROVIDER_PRIORITY,
    fallbackPolicy:
      binding?.fallbackPolicy ??
      {
        allowed: false,
        endpointIds: [],
        selectedEndpointId: binding?.selectedEndpointId ?? null,
        deterministicOrder: true,
      },
    fallbackEvidence: binding?.fallbackEvidence ?? [],
    costEstimateVisibility:
      binding?.costEstimateVisibility ??
      {
        visible: true,
        maxCostUsd: null,
        source: "workflow_model_capability_projection",
      },
    authorityScopes,
    authorityScopeRequirements: stringArray(binding?.authorityScopeRequirements).length
      ? stringArray(binding?.authorityScopeRequirements)
      : authorityScopes,
    grantReadiness:
      binding?.grantReadiness ??
      defaultReadiness(
        ready,
        modelCapabilityRef,
        ready
          ? "Model capability grant posture is projected from readiness metadata."
          : "No model capability grant has been confirmed.",
      ),
    policyPosture:
      binding?.policyPosture ??
      {
        status: ready || mockBinding ? "allowed" : "unknown",
        policyTarget: `model.${routeId}`,
        source: "workflow_model_capability_projection",
      },
    vaultReadiness: binding?.vaultReadiness,
    byokRequired: binding?.byokRequired,
    toolUseMode: binding?.toolUseMode ?? logic.toolUseMode ?? "none",
  };
}

export function workflowModelBindingIsReady(
  binding: Partial<WorkflowModelBinding> | Partial<GraphModelBinding> | null | undefined,
): boolean {
  if (!binding) return false;
  if ((binding as WorkflowModelBinding).mockBinding === true) return true;
  const normalized =
    "modelRef" in binding || "capabilityScope" in binding
      ? normalizeWorkflowModelBinding(binding as Partial<WorkflowModelBinding>)
      : normalizeGraphModelBinding("reasoning", binding as Partial<GraphModelBinding>);
  const credentialStatus = cleanText(normalized.credentialReadiness?.status).toLowerCase();
  const grantStatus = cleanText(normalized.grantReadiness?.status).toLowerCase();
  const policyStatus = cleanText((normalized.policyPosture as { status?: unknown })?.status).toLowerCase();
  const receiptTypes = Array.isArray(normalized.receiptBehavior?.requiredReceiptTypes)
    ? normalized.receiptBehavior.requiredReceiptTypes.length
    : 0;
  return (
    Boolean(cleanText(normalized.modelCapabilityRef)) &&
    Boolean(cleanText(normalized.routeId)) &&
    (credentialStatus === "ready" || (normalized as WorkflowModelBinding).credentialReady === true) &&
    grantStatus === "ready" &&
    ["allowed", "ready", "approved"].includes(policyStatus) &&
    Boolean(normalized.receiptBehavior?.receiptRequired) &&
    receiptTypes > 0 &&
    normalized.workflowAvailability?.available === true &&
    normalized.agentAvailability?.available === true
  );
}
