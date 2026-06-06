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
  const stableToolId = optionalString(tool.stable_tool_id) ?? "runtime.tool";
  const effectClass = optionalString(tool.effect_class) ?? "local_read";
  const riskDomain = optionalString(tool.risk_domain) ?? "runtime";
  const authorityScopeRequirements = uniqueStrings(tool.authority_scope_requirements);
  const evidenceRequirements = uniqueStrings(tool.evidence_requirements);
  const workflowNodeType = optionalString(tool.workflow_node_type) ?? null;
  const workflowConfigFields = uniqueStrings(tool.workflow_config_fields);
  const approvalRequired =
    typeof tool.approval_required === "boolean"
      ? tool.approval_required
      : authorityScopeRequirements.length > 0 || !runtimeToolEffectIsReadOnly(effectClass);
  const credentialReadiness =
    tool.credential_readiness && typeof tool.credential_readiness === "object"
      ? tool.credential_readiness
      : {
          status: runtimeToolLikelyRequiresCredential(stableToolId, riskDomain, effectClass) ? "unknown" : "not_required",
          checked_at: null,
          evidence_refs: [],
          reason: null,
        };
  const credentialReady = credentialReadiness.status === "ready" || credentialReadiness.status === "not_required";
  return {
    schema_version: optionalString(tool.schema_version) ?? null,
    stable_tool_id: stableToolId,
    display_name: tool.display_name ?? stableToolId,
    pack: tool.pack ?? "runtime",
    primitive_capabilities: uniqueStrings(tool.primitive_capabilities),
    authority_scope_requirements: authorityScopeRequirements,
    effect_class: effectClass,
    risk_domain: riskDomain,
    input_schema: tool.input_schema ?? { type: "object" },
    output_schema: tool.output_schema ?? { type: "object" },
    evidence_requirements: evidenceRequirements,
    credential_ready: credentialReady,
    credential_readiness: credentialReadiness,
    approval_required: approvalRequired,
    rate_limit_profile: tool.rate_limit_profile ?? {
      policy: runtimeToolEffectIsReadOnly(effectClass) ? "unlimited_local_read" : "runtime_governed",
      scope: stableToolId,
      max_calls: null,
      window_ms: null,
      burst: null,
      evidence_refs: [],
    },
    idempotency_behavior: tool.idempotency_behavior ?? {
      required: !runtimeToolEffectIsReadOnly(effectClass),
      strategy: runtimeToolEffectIsReadOnly(effectClass)
        ? "read_only"
        : runtimeToolEffectIsExternal(effectClass)
          ? "caller_or_runtime_key"
          : "runtime_key",
      key_scope: runtimeToolEffectIsReadOnly(effectClass) ? null : stableToolId,
      evidence_refs: [],
    },
    receipt_behavior: tool.receipt_behavior ?? {
      emits_receipt: evidenceRequirements.length > 0,
      receipt_required: evidenceRequirements.length > 0,
      required_receipt_types: evidenceRequirements,
      evidence_requirements: evidenceRequirements,
    },
    workflow_availability: tool.workflow_availability ?? {
      available: Boolean(workflowNodeType),
      reason: workflowNodeType ? null : "No workflow node projection registered.",
      node_type: workflowNodeType,
      config_fields: workflowConfigFields,
      evidence_refs: [],
    },
    agent_availability: tool.agent_availability ?? {
      available: true,
      reason: null,
      node_type: null,
      config_fields: [],
      evidence_refs: [],
    },
    marketplace_exposure: tool.marketplace_exposure ?? {
      eligible: !approvalRequired && credentialReady && runtimeToolEffectIsReadOnly(effectClass),
      reason:
        !approvalRequired && credentialReady && runtimeToolEffectIsReadOnly(effectClass)
          ? "Read-only tool is eligible for governed exposure."
          : "Requires authority review before exposure.",
      trust_required: approvalRequired,
      version_pinned: true,
      evidence_refs: [],
    },
    workflow_node_type: workflowNodeType,
    workflow_config_fields: workflowConfigFields,
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
      evidence_refs: ["agentgres_canonical_state_projection", "ioi_daemon_public_runtime_api"],
    },
    {
      id: "hosted-provider",
      kind: "hosted",
      status: env.IOI_AGENT_SDK_HOSTED_ENDPOINT ? "available" : "blocked",
      endpoint: env.IOI_AGENT_SDK_HOSTED_ENDPOINT,
      privacyClass: "hosted",
      evidence_refs: ["IOI_AGENT_SDK_HOSTED_ENDPOINT"],
    },
    {
      id: "self-hosted-provider",
      kind: "self_hosted",
      status: env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT ? "available" : "blocked",
      endpoint: env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT,
      privacyClass: "workspace",
      evidence_refs: ["IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT"],
    },
  ];
}

export function runtimeTools(options = {}, deps = {}) {
  const { codingToolContracts = () => [] } = deps;
  const pack = optionalString(options.pack)?.toLowerCase();
  const tools = [
    {
      stable_tool_id: "fs.read",
      display_name: "Read file",
      pack: "runtime",
      primitive_capabilities: ["prim:fs.read"],
      authority_scope_requirements: [],
      effect_class: "local_read",
      risk_domain: "filesystem",
      input_schema: { type: "object", required: ["path"] },
      output_schema: { type: "object", required: ["content"] },
      evidence_requirements: ["file_read_receipt"],
    },
    {
      stable_tool_id: "sys.exec",
      display_name: "Shell command",
      pack: "runtime",
      primitive_capabilities: ["prim:sys.exec"],
      authority_scope_requirements: ["scope:host.controlled_execution"],
      effect_class: "local_command",
      risk_domain: "host",
      input_schema: { type: "object", required: ["command"] },
      output_schema: { type: "object", required: ["exitCode", "stdout", "stderr"] },
      evidence_requirements: ["shell_receipt", "sandbox_profile"],
    },
    {
      stable_tool_id: "mcp.invoke",
      display_name: "MCP tool invocation",
      pack: "runtime",
      primitive_capabilities: ["prim:connector.invoke"],
      authority_scope_requirements: ["scope:mcp.invoke"],
      effect_class: "connector_call",
      risk_domain: "connector",
      input_schema: { type: "object", required: ["server", "tool"] },
      output_schema: { type: "object" },
      evidence_requirements: ["mcp_containment_receipt"],
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
    evidence_refs: normalizeArray(node.evidence_refs),
  };
}
