export const WORKFLOW_MODEL_CAPABILITY_SELECTOR_SCHEMA_VERSION =
  "ioi.workflow.model-capability-selector.v1" as const;

export interface WorkflowModelCapabilitySelectorInput {
  capabilities: unknown[];
  chatRouteId?: string | null;
  agentRouteId?: string | null;
  currentReasoningEffort?: string | null;
}

export interface WorkflowModelCapabilitySelectorRow {
  id: string;
  rowKind: "chat_direct" | "agent_harness";
  responsibility: "direct_model_answer" | "default_agent_harness";
  routeId: string;
  capabilityRef: string;
  modelId: string | null;
  providerKind: string | null;
  privacyTier: string | null;
  available: boolean;
  reasoningSelectorVisible: boolean;
  reasoningSelectorOwner: "chat" | "agent";
  reasoningOptions: string[];
  selectedReasoningEffort: string | null;
  authorityScopes: string[];
  receiptRequired: boolean;
  evidenceRefs: string[];
}

export interface WorkflowModelCapabilitySelector {
  schemaVersion: typeof WORKFLOW_MODEL_CAPABILITY_SELECTOR_SCHEMA_VERSION;
  status: "ready" | "needs_routes";
  chatDirectCount: number;
  agentHarnessCount: number;
  reasoningSelectableCount: number;
  rows: WorkflowModelCapabilitySelectorRow[];
}

const REASONING_OPTIONS = ["none", "provider_default", "low", "medium", "high"];

export function buildWorkflowModelCapabilitySelector(
  input: WorkflowModelCapabilitySelectorInput,
): WorkflowModelCapabilitySelector {
  const capabilities = normalizeArray(input.capabilities)
    .map(objectValue)
    .filter((capability): capability is Record<string, unknown> => Boolean(capability));
  const rows = [
    selectorRow({
      rowKind: "chat_direct",
      responsibility: "direct_model_answer",
      owner: "chat",
      routeId: input.chatRouteId ?? "route.local-first",
      selectedReasoningEffort: input.currentReasoningEffort ?? null,
      capabilities,
    }),
    selectorRow({
      rowKind: "agent_harness",
      responsibility: "default_agent_harness",
      owner: "agent",
      routeId: input.agentRouteId ?? "route.native-local",
      selectedReasoningEffort: input.currentReasoningEffort ?? null,
      capabilities,
    }),
  ].filter((row): row is WorkflowModelCapabilitySelectorRow => Boolean(row));
  return {
    schemaVersion: WORKFLOW_MODEL_CAPABILITY_SELECTOR_SCHEMA_VERSION,
    status:
      rows.some((row) => row.rowKind === "chat_direct") &&
      rows.some((row) => row.rowKind === "agent_harness")
        ? "ready"
        : "needs_routes",
    chatDirectCount: rows.filter((row) => row.rowKind === "chat_direct").length,
    agentHarnessCount: rows.filter((row) => row.rowKind === "agent_harness").length,
    reasoningSelectableCount: rows.filter((row) => row.reasoningSelectorVisible).length,
    rows,
  };
}

function selectorRow({
  rowKind,
  responsibility,
  owner,
  routeId,
  selectedReasoningEffort,
  capabilities,
}: {
  rowKind: "chat_direct" | "agent_harness";
  responsibility: "direct_model_answer" | "default_agent_harness";
  owner: "chat" | "agent";
  routeId: string;
  selectedReasoningEffort: string | null;
  capabilities: Record<string, unknown>[];
}): WorkflowModelCapabilitySelectorRow | null {
  const capability = capabilities.find((candidate) => stringField(candidate, "routeId") === routeId);
  if (!capability) return null;
  const candidate = normalizeArray(capability.candidates)
    .map(objectValue)
    .filter((value): value is Record<string, unknown> => Boolean(value))
    .find((value) => value.ready === true) ??
    objectValue(normalizeArray(capability.candidates)[0]);
  const capabilityKind = stringField(capability, "capability") ?? "chat";
  const reasoningSelectorVisible = capabilityKind === "chat" || capabilityKind === "responses";
  return {
    id: `model-selector-${rowKind}-${safeId(routeId)}`,
    rowKind,
    responsibility,
    routeId,
    capabilityRef: stringField(capability, "id") ?? `model-capability:${routeId}`,
    modelId: stringField(candidate, "modelId"),
    providerKind: stringField(candidate, "providerKind"),
    privacyTier: stringField(capability, "privacyTier") ?? stringField(candidate, "privacyTier"),
    available: objectField(capability, "workflowAvailability").available === true ||
      objectField(capability, "agentAvailability").available === true,
    reasoningSelectorVisible,
    reasoningSelectorOwner: owner,
    reasoningOptions: reasoningSelectorVisible ? REASONING_OPTIONS : [],
    selectedReasoningEffort: reasoningSelectorVisible ? selectedReasoningEffort : null,
    authorityScopes: arrayField(capability, "authorityScopeRequirements"),
    receiptRequired: objectField(capability, "receiptBehavior").receiptRequired === true,
    evidenceRefs: uniqueStrings([
      ...arrayField(objectField(capability, "credentialReadiness"), "evidenceRefs"),
      ...arrayField(objectField(capability, "workflowAvailability"), "evidenceRefs"),
      ...arrayField(objectField(capability, "agentAvailability"), "evidenceRefs"),
      stringField(capability, "id"),
    ]),
  };
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, key: string): Record<string, unknown> {
  const object = objectValue(record);
  return objectValue(object?.[key]) ?? {};
}

function stringField(record: unknown, key: string): string | null {
  const object = objectValue(record);
  const value = object?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function arrayField(record: unknown, key: string): string[] {
  const object = objectValue(record);
  const value = object?.[key];
  return Array.isArray(value)
    ? uniqueStrings(value)
    : [];
}

function normalizeArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value === undefined || value === null ? null : String(value).trim()))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}

function safeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
}
