function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function uniqueStrings(values = []) {
  return [...new Set((Array.isArray(values) ? values : [values]).map((value) => optionalString(value)).filter(Boolean))];
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

export function runtimeToolRegistryGovernanceMetadata(tool = {}) {
  const stableToolId = optionalString(tool.stableToolId ?? tool.stable_tool_id) ?? "runtime.tool";
  const effectClass = optionalString(tool.effectClass ?? tool.effect_class) ?? "local_read";
  const riskDomain = optionalString(tool.riskDomain ?? tool.risk_domain) ?? "runtime";
  const authorityScopeRequirements = uniqueStrings(tool.authorityScopeRequirements ?? tool.authority_scope_requirements);
  const evidenceRequirements = uniqueStrings(tool.evidenceRequirements ?? tool.evidence_requirements);
  const workflowNodeType = optionalString(tool.workflowNodeType ?? tool.workflow_node_type) ?? null;
  const workflowConfigFields = uniqueStrings(tool.workflowConfigFields ?? tool.workflow_config_fields);
  const approvalRequired =
    typeof tool.approvalRequired === "boolean"
      ? tool.approvalRequired
      : typeof tool.approval_required === "boolean"
        ? tool.approval_required
        : authorityScopeRequirements.length > 0 || !runtimeToolEffectIsReadOnly(effectClass);
  const credentialReadiness =
    tool.credentialReadiness && typeof tool.credentialReadiness === "object"
      ? tool.credentialReadiness
      : {
          status: runtimeToolLikelyRequiresCredential(stableToolId, riskDomain, effectClass) ? "unknown" : "not_required",
          checkedAt: null,
          evidenceRefs: [],
          reason: null,
        };
  const credentialReady = credentialReadiness.status === "ready" || credentialReadiness.status === "not_required";
  return {
    ...tool,
    stableToolId,
    displayName: tool.displayName ?? tool.display_name ?? stableToolId,
    primitiveCapabilities: uniqueStrings(tool.primitiveCapabilities ?? tool.primitive_capabilities),
    authorityScopeRequirements,
    effectClass,
    riskDomain,
    evidenceRequirements,
    credentialReady,
    credentialReadiness,
    approvalRequired,
    approval_required: approvalRequired,
    rateLimitProfile: tool.rateLimitProfile ?? {
      policy: runtimeToolEffectIsReadOnly(effectClass) ? "unlimited_local_read" : "runtime_governed",
      scope: stableToolId,
      maxCalls: null,
      windowMs: null,
      burst: null,
      evidenceRefs: [],
    },
    idempotencyBehavior: tool.idempotencyBehavior ?? {
      required: !runtimeToolEffectIsReadOnly(effectClass),
      strategy: runtimeToolEffectIsReadOnly(effectClass)
        ? "read_only"
        : runtimeToolEffectIsExternal(effectClass)
          ? "caller_or_runtime_key"
          : "runtime_key",
      keyScope: runtimeToolEffectIsReadOnly(effectClass) ? null : stableToolId,
      evidenceRefs: [],
    },
    receiptBehavior: tool.receiptBehavior ?? {
      emitsReceipt: evidenceRequirements.length > 0,
      receiptRequired: evidenceRequirements.length > 0,
      requiredReceiptTypes: evidenceRequirements,
      evidenceRequirements,
    },
    workflowAvailability: tool.workflowAvailability ?? {
      available: Boolean(workflowNodeType),
      reason: workflowNodeType ? null : "No workflow node projection registered.",
      nodeType: workflowNodeType,
      configFields: workflowConfigFields,
      evidenceRefs: [],
    },
    agentAvailability: tool.agentAvailability ?? {
      available: true,
      reason: null,
      nodeType: null,
      configFields: [],
      evidenceRefs: [],
    },
    marketplaceExposure: tool.marketplaceExposure ?? {
      eligible: !approvalRequired && credentialReady && runtimeToolEffectIsReadOnly(effectClass),
      reason:
        !approvalRequired && credentialReady && runtimeToolEffectIsReadOnly(effectClass)
          ? "Read-only tool is eligible for governed exposure."
          : "Requires authority review before exposure.",
      trustRequired: approvalRequired,
      versionPinned: true,
      evidenceRefs: [],
    },
    workflowNodeType,
    workflowConfigFields,
  };
}

export function runtimeToolEffectIsReadOnly(effectClass) {
  const normalized = String(effectClass ?? "").trim().toLowerCase();
  return normalized === "read" || normalized === "local_read" || normalized.endsWith("_read");
}

export function runtimeToolEffectIsExternal(effectClass) {
  const normalized = String(effectClass ?? "").trim().toLowerCase();
  return (
    normalized.includes("external") ||
    normalized.includes("connector") ||
    normalized.includes("destructive") ||
    normalized.includes("commerce")
  );
}

export function runtimeToolLikelyRequiresCredential(stableToolId, riskDomain, effectClass) {
  const haystack = `${stableToolId} ${riskDomain} ${effectClass}`.toLowerCase();
  return haystack.includes("connector") || haystack.includes("mcp") || haystack.includes("model") || haystack.includes("oauth");
}

export function runtimeAccount(env = process.env) {
  return {
    id: "local-operator",
    email: env.IOI_OPERATOR_EMAIL ?? null,
    authorityLevel: "local",
    privacyClass: "local_private",
    source: "ioi-daemon-agentgres",
  };
}

export function runtimeNodes(env = process.env) {
  return [
    {
      id: "local-daemon-agentgres",
      kind: "local",
      status: "available",
      endpoint: "local",
      privacyClass: "local_private",
      evidenceRefs: ["agentgres_canonical_state_projection", "ioi_daemon_public_runtime_api"],
    },
    {
      id: "hosted-provider",
      kind: "hosted",
      status: env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
      endpoint: env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
      privacyClass: "hosted",
      evidenceRefs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
    },
    {
      id: "self-hosted-provider",
      kind: "self_hosted",
      status: env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
      endpoint: env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
      privacyClass: "workspace",
      evidenceRefs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
    },
  ];
}

export function runtimeTools(options = {}, deps = {}) {
  const { codingToolContracts = () => [] } = deps;
  const pack = optionalString(options.pack)?.toLowerCase();
  const tools = [
    {
      stableToolId: "fs.read",
      displayName: "Read file",
      pack: "runtime",
      primitiveCapabilities: ["prim:fs.read"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "filesystem",
      inputSchema: { type: "object", required: ["path"] },
      outputSchema: { type: "object", required: ["content"] },
      evidenceRequirements: ["file_read_receipt"],
    },
    {
      stableToolId: "sys.exec",
      displayName: "Shell command",
      pack: "runtime",
      primitiveCapabilities: ["prim:sys.exec"],
      authorityScopeRequirements: ["scope:host.controlled_execution"],
      effectClass: "local_command",
      riskDomain: "host",
      inputSchema: { type: "object", required: ["command"] },
      outputSchema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
      evidenceRequirements: ["shell_receipt", "sandbox_profile"],
    },
    {
      stableToolId: "mcp.invoke",
      displayName: "MCP tool invocation",
      pack: "runtime",
      primitiveCapabilities: ["prim:connector.invoke"],
      authorityScopeRequirements: ["scope:mcp.invoke"],
      effectClass: "connector_call",
      riskDomain: "connector",
      inputSchema: { type: "object", required: ["server", "tool"] },
      outputSchema: { type: "object" },
      evidenceRequirements: ["mcp_containment_receipt"],
    },
    ...codingToolContracts(),
  ].map((tool) => runtimeToolRegistryGovernanceMetadata(tool));
  return pack
    ? tools.filter((tool) => optionalString(tool.pack)?.toLowerCase() === pack)
    : tools;
}

export function redactRuntimeNodeForDoctor(node = {}, deps = {}) {
  const { doctorHash = (value) => String(value) } = deps;
  return {
    id: node.id,
    kind: node.kind,
    status: node.status,
    privacyClass: node.privacyClass,
    endpointConfigured: Boolean(node.endpoint),
    endpointHash: node.endpoint ? doctorHash(node.endpoint) : null,
    evidenceRefs: normalizeArray(node.evidenceRefs),
  };
}
