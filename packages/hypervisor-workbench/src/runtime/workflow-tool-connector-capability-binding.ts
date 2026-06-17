import type {
  Node,
  NodeLogic,
  WorkflowCapabilityAvailability,
  WorkflowCapabilityCredentialReadiness,
  WorkflowConnectorBinding,
  WorkflowProject,
  WorkflowSideEffectClass,
  WorkflowToolBinding,
} from "../types/graph";

export type WorkflowCatalogBindingSelection =
  | { kind: "tool"; value: WorkflowToolBinding }
  | { kind: "connector"; value: WorkflowConnectorBinding };

export const TOOL_CAPABILITY_BINDING_ENDPOINT = "/v1/tools";
export const TOOL_AUTHORITY_BINDING_ENDPOINT = "/v1/model-mount/authority";
export const CONNECTOR_AUTHORITY_BINDING_ENDPOINT = "/v1/model-mount/authority";

export type WorkflowRuntimeToolContractLike = Record<string, unknown> & {
  stableToolId?: string;
  stable_tool_id?: string;
  toolId?: string;
  tool_id?: string;
  displayName?: string;
  display_name?: string;
  inputSchema?: Record<string, unknown>;
  input_schema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  riskClass?: string;
  risk_class?: string;
  riskDomain?: string;
  risk_domain?: string;
  effectClass?: string;
  effect_class?: string;
  primitiveCapabilities?: string[];
  primitive_capabilities_required?: string[];
  authorityScopeRequirements?: string[];
  authority_scopes_required?: string[];
  approvalRequired?: boolean;
  approval_required?: boolean;
  evidenceRequirements?: string[];
  evidence_required?: string[];
};

function cleanText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function recordValue(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function stringField(record: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = cleanText(record[key]);
    if (value) return value;
  }
  return "";
}

function booleanField(record: Record<string, unknown>, ...keys: string[]): boolean | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") return value;
  }
  return undefined;
}

function recordField(
  record: Record<string, unknown>,
  ...keys: string[]
): Record<string, unknown> | undefined {
  for (const key of keys) {
    const value = recordValue(record[key]);
    if (value) return value;
  }
  return undefined;
}

function arrayField(record: Record<string, unknown>, ...keys: string[]): string[] {
  for (const key of keys) {
    const values = stringArray(record[key]);
    if (values.length) return values;
  }
  return [];
}

function slug(value: string, fallback: string): string {
  const result = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return result || fallback;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => cleanText(item)).filter(Boolean);
}

function sideEffectClassFor(
  value: unknown,
  fallback: WorkflowSideEffectClass,
): WorkflowSideEffectClass {
  const text = cleanText(value);
  if (
    text === "none" ||
    text === "read" ||
    text === "write" ||
    text === "external_write" ||
    text === "financial_write" ||
    text === "admin"
  ) {
    return text;
  }
  return fallback;
}

function isReadOnly(sideEffectClass: string): boolean {
  return sideEffectClass === "none" || sideEffectClass === "read" || sideEffectClass.endsWith("_read");
}

function isEffectful(sideEffectClass: string): boolean {
  return !isReadOnly(sideEffectClass);
}

function readinessStatus(value: unknown): string {
  return cleanText((value as { status?: unknown } | undefined)?.status).toLowerCase();
}

function hasReadyProjection(binding: {
  credentialReady?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
}): boolean {
  const status = readinessStatus(binding.credentialReadiness);
  return Boolean(binding.credentialReady) || status === "ready" || status === "not_required";
}

function defaultReadiness(
  ready: boolean,
  evidenceRef: string,
  readyReason: string,
  missingReason: string,
): WorkflowCapabilityCredentialReadiness {
  return {
    status: ready ? "ready" : "unknown",
    reason: ready ? readyReason : missingReason,
    evidenceRefs: ready ? [evidenceRef] : [],
  };
}

function defaultAvailability(
  available: boolean,
  reason: string,
  nodeType: string,
  configFields: string[],
): WorkflowCapabilityAvailability {
  return {
    available,
    reason,
    nodeType,
    configFields,
  };
}

export function toolCapabilityRefForToolRef(toolRef: string): string {
  return `tool-capability:${slug(toolRef, "tool")}`;
}

export function connectorCapabilityRefForConnectorRef(connectorRef: string): string {
  return `connector-capability:${slug(connectorRef, "connector")}`;
}

export function defaultToolAuthorityScopes(
  toolRef: string,
  sideEffectClass: string,
  capabilityScope: string[] = [],
): string[] {
  const explicitComputerUseScopes = capabilityScope.filter((scope) =>
    scope.startsWith("computer_use."),
  );
  if (explicitComputerUseScopes.length) return explicitComputerUseScopes;
  if (toolRef === "file.apply_patch") return ["scope:workspace.write"];
  if (toolRef === "test.run") return ["scope:workspace.test"];
  if (toolRef.startsWith("mcp.")) return ["scope:mcp.invoke"];
  if (!isEffectful(sideEffectClass)) return [];
  return [`tool.invoke:${slug(toolRef, "tool")}`];
}

export function defaultConnectorAuthorityScopes(
  connectorRef: string,
  sideEffectClass: string,
): string[] {
  if (!isEffectful(sideEffectClass)) return [];
  return [`connector.invoke:${slug(connectorRef, "connector")}`];
}

function riskClassFor(sideEffectClass: string): string {
  switch (sideEffectClass) {
    case "none":
    case "read":
      return "low";
    case "write":
      return "local_write";
    case "external_write":
      return "external_write";
    case "financial_write":
      return "financial_high";
    case "admin":
      return "admin_high";
    default:
      return isEffectful(sideEffectClass) ? "elevated" : "low";
  }
}

function sideEffectClassFromRuntimeEffect(value: string): WorkflowSideEffectClass {
  switch (value) {
    case "read":
      return "read";
    case "local_write":
    case "draft":
    case "write_reversible":
      return "write";
    case "external_message":
    case "commerce":
      return "external_write";
    case "funds":
      return "financial_write";
    case "credential_touching":
    case "secret_export":
    case "policy_widening":
    case "system_destructive":
      return "admin";
    default:
      return value.includes("write") ? "external_write" : "read";
  }
}

function runtimeToolContractLike(
  value: unknown,
): value is WorkflowRuntimeToolContractLike {
  const record = recordValue(value);
  if (!record) return false;
  return Boolean(
    stringField(record, "stableToolId", "stable_tool_id", "toolId", "tool_id") ||
      stringField(record, "effectClass", "effect_class") ||
      arrayField(record, "authorityScopeRequirements", "authority_scopes_required")
        .length ||
      arrayField(
        record,
        "primitiveCapabilities",
        "primitive_capabilities_required",
      ).length,
  );
}

function runtimeToolContractProjection(
  value: unknown,
): Partial<WorkflowToolBinding> | null {
  if (!runtimeToolContractLike(value)) return null;
  const record = value as Record<string, unknown>;
  const stableToolId = stringField(
    record,
    "stableToolId",
    "stable_tool_id",
    "toolId",
    "tool_id",
  );
  const toolRef =
    cleanText((record as Partial<WorkflowToolBinding>).toolRef) ||
    stableToolId.replace(/^tool:\/\//, "");
  if (!toolRef) return null;
  const effectClass = stringField(record, "effectClass", "effect_class") || "read";
  const sideEffectClass = sideEffectClassFromRuntimeEffect(effectClass);
  const authorityScopes = arrayField(
    record,
    "authorityScopeRequirements",
    "authority_scopes_required",
    "authorityScopes",
    "authority_scopes",
  );
  const primitiveCapabilities = arrayField(
    record,
    "primitiveCapabilities",
    "primitive_capabilities_required",
  );
  const evidenceRequirements = arrayField(
    record,
    "evidenceRequirements",
    "evidence_required",
    "evidenceRequirementsRequired",
  );
  const credentialReadiness =
    recordField(record, "credentialReadiness", "credential_readiness") ??
    undefined;
  const credentialReady =
    booleanField(record, "credentialReady", "credential_ready") ??
    ["ready", "not_required"].includes(
      cleanText(credentialReadiness?.status).toLowerCase(),
    );
  const approvalRequired =
    booleanField(record, "approvalRequired", "approval_required") ??
    isEffectful(sideEffectClass);
  const capabilityRef =
    stringField(record, "toolCapabilityRef", "tool_capability_ref") ||
    toolCapabilityRefForToolRef(toolRef);
  const inputSchema =
    recordField(record, "inputSchema", "input_schema") ?? { type: "object" };
  const outputSchema =
    recordField(record, "outputSchema", "output_schema") ?? { type: "object" };
  const defaultToolReceiptBehavior = defaultReceiptBehavior("tool");
  const bindingKind = (
    stringField(record, "bindingKind", "binding_kind") ||
    (toolRef.startsWith("mcp.") ? "mcp_tool" : "plugin_tool")
  ) as WorkflowToolBinding["bindingKind"];

  return {
    toolRef,
    toolCapabilityRef: capabilityRef,
    bindingKind,
    mockBinding: booleanField(record, "mockBinding", "mock_binding") ?? false,
    credentialReady,
    credentialReadiness: credentialReadiness as WorkflowCapabilityCredentialReadiness | undefined,
    riskClass:
      stringField(record, "riskClass", "risk_class", "riskDomain", "risk_domain") ||
      riskClassFor(sideEffectClass),
    primitiveCapabilities,
    authorityScopes,
    authorityScopeRequirements: authorityScopes,
    inputSchema,
    outputSchema,
    evidenceRequirements,
    approvalRequirement:
      recordField(record, "approvalRequirement", "approval_requirement") ??
      defaultApprovalRequirement(approvalRequired, sideEffectClass),
    grantReadiness:
      recordField(record, "grantReadiness", "grant_readiness") ??
      defaultReadiness(
        credentialReady,
        capabilityRef,
        "Tool contract grant posture is projected from runtime authority metadata.",
        "No runtime tool authority grant has been confirmed.",
      ),
    policyPosture:
      recordField(record, "policyPosture", "policy_posture") ??
      defaultPolicyPosture(credentialReady, capabilityRef),
    rateLimitProfile: recordField(record, "rateLimitProfile", "rate_limit_profile"),
    idempotencyBehavior: recordField(
      record,
      "idempotencyBehavior",
      "idempotency_behavior",
    ),
    receiptBehavior:
      recordField(record, "receiptBehavior", "receipt_behavior") ??
      {
        ...defaultToolReceiptBehavior,
        requiredReceiptTypes: evidenceRequirements.length
          ? evidenceRequirements
          : defaultToolReceiptBehavior.requiredReceiptTypes,
      },
    workflowAvailability: recordField(
      record,
      "workflowAvailability",
      "workflow_availability",
    ) as WorkflowCapabilityAvailability | undefined,
    agentAvailability: recordField(
      record,
      "agentAvailability",
      "agent_availability",
    ) as WorkflowCapabilityAvailability | undefined,
    marketplaceExposure:
      recordField(record, "marketplaceExposure", "marketplace_exposure") ??
      defaultMarketplaceExposure(approvalRequired, sideEffectClass),
    capabilityScope: primitiveCapabilities.length
      ? primitiveCapabilities
      : [isReadOnly(sideEffectClass) ? "read" : "write"],
    sideEffectClass,
    requiresApproval: approvalRequired,
    arguments: {},
    runtimeToolContract: {
      stableToolId,
      displayName: stringField(record, "displayName", "display_name"),
      effectClass,
      primitiveCapabilities,
      authorityScopeRequirements: authorityScopes,
      inputSchema,
      outputSchema,
      evidenceRequirements,
      owner: stringField(record, "owner", "ownerModule", "owner_module"),
      version: stringField(record, "version"),
    },
  };
}

function defaultRateLimitProfile(
  capabilityRef: string,
  sideEffectClass: string,
): Record<string, unknown> {
  return {
    policy: isReadOnly(sideEffectClass) ? "unlimited_local_read" : "runtime_governed",
    scope: capabilityRef,
    maxCalls: null,
    windowMs: null,
  };
}

function defaultIdempotencyBehavior(
  capabilityRef: string,
  sideEffectClass: string,
): Record<string, unknown> {
  return {
    required: isEffectful(sideEffectClass),
    strategy: isReadOnly(sideEffectClass) ? "read_only" : "runtime_key",
    keyScope: isReadOnly(sideEffectClass) ? null : capabilityRef,
  };
}

function defaultReceiptBehavior(
  bindingKind: "tool" | "connector",
): Record<string, unknown> {
  return {
    emitsReceipt: true,
    receiptRequired: true,
    requiredReceiptTypes: [
      `${bindingKind}_invocation`,
      `${bindingKind}_verification`,
    ],
  };
}

function defaultApprovalRequirement(
  requiresApproval: boolean,
  sideEffectClass: string,
): Record<string, unknown> {
  return {
    required: requiresApproval,
    source: "workflow_capability_projection",
    reason: requiresApproval
      ? `${sideEffectClass} actions require approval before execution.`
      : "Read-only or locally governed action does not require a separate approval gate.",
  };
}

function defaultMarketplaceExposure(
  requiresApproval: boolean,
  sideEffectClass: string,
): Record<string, unknown> {
  const eligible = !requiresApproval && isReadOnly(sideEffectClass);
  return {
    eligible,
    reason: eligible
      ? "Read-only capability is eligible for marketplace exposure after version pinning."
      : "Capability requires authority review before marketplace exposure.",
    trustRequired: requiresApproval,
    versionPinned: true,
  };
}

function defaultPolicyPosture(
  ready: boolean,
  capabilityRef: string,
): Record<string, unknown> {
  return {
    status: ready ? "allowed" : "unknown",
    policyTarget: capabilityRef,
    source: "workflow_capability_projection",
  };
}

function scopesForBinding(
  explicitScopes: unknown,
  explicitRequirements: unknown,
  fallback: string[],
): { authorityScopes: string[]; authorityScopeRequirements: string[] } {
  const authorityScopes = stringArray(explicitScopes);
  const authorityScopeRequirements = stringArray(explicitRequirements);
  if (authorityScopes.length) {
    return {
      authorityScopes,
      authorityScopeRequirements: authorityScopeRequirements.length
        ? authorityScopeRequirements
        : authorityScopes,
    };
  }
  if (authorityScopeRequirements.length) {
    return {
      authorityScopes: authorityScopeRequirements,
      authorityScopeRequirements,
    };
  }
  return {
    authorityScopes: fallback,
    authorityScopeRequirements: fallback,
  };
}

export function normalizeWorkflowToolBinding(
  binding: Partial<WorkflowToolBinding> | WorkflowRuntimeToolContractLike | null | undefined,
  _logic: Partial<NodeLogic> = {},
): WorkflowToolBinding {
  const projected = runtimeToolContractProjection(binding);
  const source = {
    ...(projected ?? {}),
    ...(binding ?? {}),
  } as Partial<WorkflowToolBinding>;
  const bindingKind = source.bindingKind ?? "plugin_tool";
  const toolRef = cleanText(source.toolRef) || (bindingKind === "workflow_tool" ? "workflow_tool" : "");
  const sideEffectClass = sideEffectClassFor(source.sideEffectClass, bindingKind === "coding_tool_pack" ? "write" : "read");
  const mockBinding = source.mockBinding ?? true;
  const requiresApproval = source.requiresApproval ?? isEffectful(sideEffectClass);
  const capabilityScope = source.capabilityScope?.length ? source.capabilityScope : [isReadOnly(sideEffectClass) ? "read" : "write"];
  const toolCapabilityRef =
    cleanText(source.toolCapabilityRef) ||
    (toolRef ? toolCapabilityRefForToolRef(toolRef) : "tool-capability:unbound");
  const ready = bindingKind === "workflow_tool"
    ? Boolean(cleanText(source.workflowTool?.workflowPath))
    : hasReadyProjection(source ?? {});
  const { authorityScopes, authorityScopeRequirements } = scopesForBinding(
    source.authorityScopes,
    source.authorityScopeRequirements,
    defaultToolAuthorityScopes(toolRef, sideEffectClass, capabilityScope),
  );

  return {
    toolRef,
    toolCapabilityRef,
    bindingKind,
    mockBinding,
    credentialReady: source.credentialReady ?? ready,
    credentialReadiness:
      source.credentialReadiness ??
      defaultReadiness(
        ready,
        toolCapabilityRef,
        "Tool capability readiness was projected from the workflow binding.",
        "No executable tool capability readiness has been confirmed.",
      ),
    riskClass: source.riskClass ?? riskClassFor(sideEffectClass),
    primitiveCapabilities: source.primitiveCapabilities ?? [],
    authorityScopes,
    authorityScopeRequirements,
    inputSchema: source.inputSchema,
    outputSchema: source.outputSchema,
    evidenceRequirements: source.evidenceRequirements ?? [],
    approvalRequirement:
      source.approvalRequirement ??
      defaultApprovalRequirement(requiresApproval, sideEffectClass),
    grantReadiness:
      source.grantReadiness ??
      defaultReadiness(
        ready,
        toolCapabilityRef,
        "Tool capability grant posture is projected from readiness metadata.",
        "No tool capability grant has been confirmed.",
      ),
    policyPosture: source.policyPosture ?? defaultPolicyPosture(ready || mockBinding, toolCapabilityRef),
    rateLimitProfile:
      source.rateLimitProfile ?? defaultRateLimitProfile(toolCapabilityRef, sideEffectClass),
    idempotencyBehavior:
      source.idempotencyBehavior ?? defaultIdempotencyBehavior(toolCapabilityRef, sideEffectClass),
    receiptBehavior: source.receiptBehavior ?? defaultReceiptBehavior("tool"),
    workflowAvailability:
      source.workflowAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock tool binding is available only for mock-authorized runs."
          : ready
            ? "Workflow can bind this tool capability."
            : "Workflow needs a ready tool capability before activation.",
        "plugin_tool",
        ["toolCapabilityRef", "toolBinding"],
      ),
    agentAvailability:
      source.agentAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock tool binding is available only for mock-authorized runs."
          : ready
            ? "Agent runtime can request this tool capability."
            : "Agent runtime needs tool capability readiness before execution.",
        "plugin_tool",
        ["toolCapabilityRef", "toolBinding"],
      ),
    marketplaceExposure:
      source.marketplaceExposure ??
      defaultMarketplaceExposure(requiresApproval, sideEffectClass),
    runtimeToolContract: source.runtimeToolContract,
    capabilityScope,
    sideEffectClass,
    requiresApproval,
    arguments: source.arguments ?? {},
    mcp: source.mcp,
    toolPack: source.toolPack,
    workflowTool: source.workflowTool,
  };
}

export function normalizeWorkflowConnectorBinding(
  binding: Partial<WorkflowConnectorBinding> | null | undefined,
): WorkflowConnectorBinding {
  const connectorRef = cleanText(binding?.connectorRef);
  const operation = cleanText(binding?.operation) || "read";
  const sideEffectClass = sideEffectClassFor(binding?.sideEffectClass, "read");
  const mockBinding = binding?.mockBinding ?? true;
  const requiresApproval = binding?.requiresApproval ?? isEffectful(sideEffectClass);
  const capabilityScope = binding?.capabilityScope?.length ? binding.capabilityScope : [operation || "read"];
  const connectorCapabilityRef =
    cleanText(binding?.connectorCapabilityRef) ||
    (connectorRef ? connectorCapabilityRefForConnectorRef(connectorRef) : "connector-capability:unbound");
  const ready = hasReadyProjection(binding ?? {});
  const { authorityScopes, authorityScopeRequirements } = scopesForBinding(
    binding?.authorityScopes,
    binding?.authorityScopeRequirements,
    defaultConnectorAuthorityScopes(connectorRef, sideEffectClass),
  );

  return {
    connectorRef,
    connectorCapabilityRef,
    mockBinding,
    credentialReady: binding?.credentialReady ?? ready,
    credentialReadiness:
      binding?.credentialReadiness ??
      defaultReadiness(
        ready,
        connectorCapabilityRef,
        "Connector capability readiness was projected from the workflow binding.",
        "No executable connector capability readiness has been confirmed.",
      ),
    riskClass: binding?.riskClass ?? riskClassFor(sideEffectClass),
    authorityScopes,
    authorityScopeRequirements,
    approvalRequirement:
      binding?.approvalRequirement ??
      defaultApprovalRequirement(requiresApproval, sideEffectClass),
    grantReadiness:
      binding?.grantReadiness ??
      defaultReadiness(
        ready,
        connectorCapabilityRef,
        "Connector capability grant posture is projected from readiness metadata.",
        "No connector capability grant has been confirmed.",
      ),
    policyPosture:
      binding?.policyPosture ??
      defaultPolicyPosture(ready || mockBinding, connectorCapabilityRef),
    rateLimitProfile:
      binding?.rateLimitProfile ?? defaultRateLimitProfile(connectorCapabilityRef, sideEffectClass),
    idempotencyBehavior:
      binding?.idempotencyBehavior ?? defaultIdempotencyBehavior(connectorCapabilityRef, sideEffectClass),
    receiptBehavior: binding?.receiptBehavior ?? defaultReceiptBehavior("connector"),
    workflowAvailability:
      binding?.workflowAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock connector binding is available only for mock-authorized runs."
          : ready
            ? "Workflow can bind this connector capability."
            : "Workflow needs a ready connector capability before activation.",
        "adapter",
        ["connectorCapabilityRef", "connectorBinding"],
      ),
    agentAvailability:
      binding?.agentAvailability ??
      defaultAvailability(
        mockBinding || ready,
        mockBinding
          ? "Mock connector binding is available only for mock-authorized runs."
          : ready
            ? "Agent runtime can request this connector capability."
            : "Agent runtime needs connector capability readiness before execution.",
        "adapter",
        ["connectorCapabilityRef", "connectorBinding"],
      ),
    marketplaceExposure:
      binding?.marketplaceExposure ??
      defaultMarketplaceExposure(requiresApproval, sideEffectClass),
    capabilityScope,
    sideEffectClass,
    requiresApproval,
    operation,
  };
}

function bindingIsReady(
  binding: {
    mockBinding?: boolean;
    credentialReady?: boolean;
    credentialReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
    grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
    policyPosture?: Record<string, unknown>;
    receiptBehavior?: Record<string, unknown>;
    workflowAvailability?: WorkflowCapabilityAvailability;
    agentAvailability?: WorkflowCapabilityAvailability;
  },
): boolean {
  if (binding.mockBinding === true) return true;
  const credentialStatus = readinessStatus(binding.credentialReadiness);
  const grantStatus = readinessStatus(binding.grantReadiness);
  const policyStatus = cleanText((binding.policyPosture as { status?: unknown } | undefined)?.status).toLowerCase();
  const receiptTypes = Array.isArray(binding.receiptBehavior?.requiredReceiptTypes)
    ? binding.receiptBehavior.requiredReceiptTypes.length
    : 0;
  return (
    (binding.credentialReady === true || credentialStatus === "ready" || credentialStatus === "not_required") &&
    (grantStatus === "ready" || grantStatus === "not_required") &&
    ["allowed", "ready", "approved"].includes(policyStatus) &&
    Boolean(binding.receiptBehavior?.receiptRequired) &&
    receiptTypes > 0 &&
    binding.workflowAvailability?.available === true &&
    binding.agentAvailability?.available === true
  );
}

export function workflowToolBindingIsReady(
  binding: Partial<WorkflowToolBinding> | null | undefined,
): boolean {
  if (!binding) return false;
  const normalized = normalizeWorkflowToolBinding(binding);
  if (normalized.bindingKind === "workflow_tool") {
    return Boolean(cleanText(normalized.workflowTool?.workflowPath));
  }
  return Boolean(cleanText(normalized.toolCapabilityRef)) && bindingIsReady(normalized);
}

export function workflowConnectorBindingIsReady(
  binding: Partial<WorkflowConnectorBinding> | null | undefined,
): boolean {
  if (!binding) return false;
  const normalized = normalizeWorkflowConnectorBinding(binding);
  return Boolean(cleanText(normalized.connectorCapabilityRef)) && bindingIsReady(normalized);
}

export function workflowToolBindingCatalogFallback(): WorkflowToolBinding[] {
  return [
    normalizeWorkflowToolBinding({
      toolRef: "mcp.tool.catalog.read",
      bindingKind: "mcp_tool",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: ["mcp.tool.catalog.read", "mcp.provider.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        mode: "catalog_preview",
        mutation: false,
        providerCatalogRef: "previousAuthorityOutput.providerCatalog",
      },
    }),
    normalizeWorkflowToolBinding({
      toolRef: "agent.runtime.native-tool.catalog.read",
      bindingKind: "native_tool",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: ["native.tool.catalog.read", "mcp.tool.catalog.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {
        mode: "native_catalog_preview",
        mutation: false,
        mcpToolCatalogRef: "input.mcpToolCatalog",
      },
    }),
    normalizeWorkflowToolBinding({
      toolRef: "web_search_mcp",
      bindingKind: "mcp_tool",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: { query: "{{input}}" },
    }),
    normalizeWorkflowToolBinding({
      toolRef: "codex_plugin",
      bindingKind: "plugin_tool",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read", "analyze"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {},
    }),
    normalizeWorkflowToolBinding({
      toolRef: "workflow_tool",
      bindingKind: "workflow_tool",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: ["invoke"],
      sideEffectClass: "read",
      requiresApproval: false,
      arguments: {},
      workflowTool: {
        workflowPath: ".agents/workflows/scratch-gui-node-composition.workflow.json",
        argumentSchema: { type: "object" },
        resultSchema: { type: "object" },
        timeoutMs: 30000,
        maxAttempts: 1,
      },
    }),
  ];
}

export function workflowConnectorBindingCatalogFallback(): WorkflowConnectorBinding[] {
  return [
    normalizeWorkflowConnectorBinding({
      connectorRef: "mcp.capability-provider",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: ["mcp.provider.read", "mcp.catalog.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "catalog",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "agent.connector.catalog",
      mockBinding: false,
      credentialReady: true,
      capabilityScope: ["connector.catalog.read", "mcp.tool.catalog.read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "describe",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "slack",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "read",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "support",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "read",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "it_ticketing",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read", "write"],
      sideEffectClass: "external_write",
      requiresApproval: true,
      operation: "draft_or_create",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "analytics",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "read",
    }),
    normalizeWorkflowConnectorBinding({
      connectorRef: "accounting_system",
      mockBinding: true,
      credentialReady: false,
      capabilityScope: ["read"],
      sideEffectClass: "read",
      requiresApproval: false,
      operation: "read",
    }),
  ];
}

function uniqueByCapabilityRef<T>(
  bindings: T[],
  capabilityRef: (binding: T) => string | undefined,
): T[] {
  const seen = new Set<string>();
  return bindings.filter((binding) => {
    const key = capabilityRef(binding) ?? "";
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function normalizeWorkflowToolCatalog(
  bindings:
    | Array<Partial<WorkflowToolBinding> | WorkflowRuntimeToolContractLike>
    | null
    | undefined,
): WorkflowToolBinding[] {
  const source =
    Array.isArray(bindings) && bindings.length > 0
      ? bindings
      : workflowToolBindingCatalogFallback();
  return uniqueByCapabilityRef(
    source.map((binding) => normalizeWorkflowToolBinding(binding)),
    (binding) => binding.toolCapabilityRef,
  );
}

export function normalizeWorkflowConnectorCatalog(
  bindings: Array<Partial<WorkflowConnectorBinding>> | null | undefined,
): WorkflowConnectorBinding[] {
  const source =
    Array.isArray(bindings) && bindings.length > 0
      ? bindings
      : workflowConnectorBindingCatalogFallback();
  return uniqueByCapabilityRef(
    source.map((binding) => normalizeWorkflowConnectorBinding(binding)),
    (binding) => binding.connectorCapabilityRef,
  );
}

function defaultNodeConfig(nodeItem: Node): NonNullable<Node["config"]> {
  return {
    kind: nodeItem.type as NonNullable<Node["config"]>["kind"],
    logic: {},
    law: {},
  } as NonNullable<Node["config"]>;
}

export function workflowNodeWithCatalogBinding(
  nodeItem: Node,
  selection: WorkflowCatalogBindingSelection,
): Node {
  const currentConfig = nodeItem.config ?? defaultNodeConfig(nodeItem);
  const nextLogic = {
    ...(currentConfig.logic ?? {}),
  };
  if (selection.kind === "tool") {
    nextLogic.toolBinding = normalizeWorkflowToolBinding(selection.value);
    delete nextLogic.connectorBinding;
  } else {
    nextLogic.connectorBinding = normalizeWorkflowConnectorBinding(
      selection.value,
    );
    delete nextLogic.toolBinding;
  }
  return {
    ...nodeItem,
    config: {
      ...currentConfig,
      logic: nextLogic,
      law: currentConfig.law ?? {},
    } as NonNullable<Node["config"]>,
  };
}

export function workflowWithCatalogBinding(
  workflow: WorkflowProject,
  nodeId: string,
  selection: WorkflowCatalogBindingSelection,
): { workflow: WorkflowProject; applied: boolean; node: Node | null } {
  let appliedNode: Node | null = null;
  const nodes = workflow.nodes.map((nodeItem) => {
    if (nodeItem.id !== nodeId) return nodeItem;
    appliedNode = workflowNodeWithCatalogBinding(nodeItem, selection);
    return appliedNode;
  });
  return {
    workflow: {
      ...workflow,
      nodes,
    },
    applied: Boolean(appliedNode),
    node: appliedNode,
  };
}
