import type { ConnectorSummary } from "@ioi/agent-ide";
import type { ShieldPolicyState } from "./policyCenter";

export type AuthorityCenterTone = "ready" | "warning" | "blocked" | "idle";

export interface AuthorityCenterCapabilityRow {
  id: string;
  label: string;
  kind: "model" | "tool" | "connector";
  status: string;
  tone: AuthorityCenterTone;
  detail: string;
  policyTarget?: string | null;
  requiredScopes: string[];
  receiptTypes: string[];
}

export interface AuthorityCenterGrantRow {
  id: string;
  grantId: string;
  state: string;
  tone: AuthorityCenterTone;
  allowedCount: number;
  deniedCount: number;
  vaultRefCount: number;
  receiptRef: string;
  receiptRefs: string[];
  lastScope: string;
  expiresAt: string;
  canRevoke: boolean;
}

export interface AuthorityCenterVaultRow {
  id: string;
  label: string;
  purpose: string;
  state: string;
  tone: AuthorityCenterTone;
  lastResolved: string;
}

export interface AuthorityCenterProjection {
  generatedAtMs: number;
  status: "ready" | "degraded" | "blocked" | "idle";
  headline: string;
  detail: string;
  summary: {
    readyCapabilities: number;
    blockedCapabilities: number;
    activeGrants: number;
    revokedGrants: number;
    vaultRefs: number;
    rawSecretLeakSuspected: boolean;
    policyOverrides: number;
  };
  capabilities: AuthorityCenterCapabilityRow[];
  grants: AuthorityCenterGrantRow[];
  vaultRefs: AuthorityCenterVaultRow[];
  blockers: string[];
}

export interface BuildAuthorityCenterProjectionInput {
  authoritySnapshot?: unknown;
  modelSnapshot?: unknown;
  toolCatalog?: unknown;
  connectors?: ConnectorSummary[];
  policyState: ShieldPolicyState;
  generatedAtMs?: number;
  error?: string | null;
}

export interface AuthorityCenterGrantRequestPayload {
  audience: string;
  allowed: string[];
  denied: string[];
  expiresAt: string;
  grantId: string;
}

export function buildAuthorityGrantRequestPayload(
  capability: AuthorityCenterCapabilityRow,
  {
    generatedAtMs = Date.now(),
    expiresInMs = 60 * 60 * 1000,
  }: { generatedAtMs?: number; expiresInMs?: number } = {},
): AuthorityCenterGrantRequestPayload {
  const allowed =
    capability.requiredScopes.length > 0
      ? capability.requiredScopes
      : fallbackScopesForCapability(capability);
  return {
    audience: "autopilot-authority-center",
    allowed,
    denied: ["connector.gmail.send", "filesystem.write", "shell.exec"],
    expiresAt: new Date(generatedAtMs + expiresInMs).toISOString(),
    grantId: `wallet.grant.authority-center.${safeGrantSegment(
      capability.kind,
    )}.${safeGrantSegment(capability.id)}`,
  };
}

export function buildAuthorityCenterProjection({
  authoritySnapshot,
  modelSnapshot,
  toolCatalog,
  connectors = [],
  policyState,
  generatedAtMs = Date.now(),
  error = null,
}: BuildAuthorityCenterProjectionInput): AuthorityCenterProjection {
  const modelCapabilities = arrayOf(
    recordValue(modelSnapshot)?.modelCapabilities,
  ).map(modelCapabilityRow);
  const toolCapabilities = arrayOf(toolCatalog).map(toolCapabilityRow);
  const connectorCapabilities = connectors.map(connectorCapabilityRow);
  const capabilities = [
    ...modelCapabilities,
    ...toolCapabilities,
    ...connectorCapabilities,
  ];
  const authorityRecord = recordValue(authoritySnapshot);
  const modelRecord = recordValue(modelSnapshot);
  const grants = arrayOf(authorityRecord?.grants ?? modelRecord?.tokens).map(
    grantRow,
  );
  const vaultRefs = arrayOf(
    authorityRecord?.vaultRefs ?? modelRecord?.vaultRefs,
  ).map(vaultRow);
  const blockedCapabilities = capabilities.filter(
    (capability) => capability.tone === "blocked",
  ).length;
  const rawSecretLeakSuspected = containsRawSecretMaterial({
    capabilities,
    grants,
    vaultRefs,
  });
  const blockers = [
    ...(error ? [error] : []),
    ...(blockedCapabilities > 0
      ? [`${blockedCapabilities} live capabilities are blocked.`]
      : []),
    ...(rawSecretLeakSuspected
      ? ["Authority projection includes material that resembles a raw secret."]
      : []),
  ];
  const readyCapabilities = capabilities.filter(
    (capability) => capability.tone === "ready",
  ).length;
  const activeGrants = grants.filter(
    (grant) => grant.state === "active",
  ).length;
  const revokedGrants = grants.filter(
    (grant) => grant.state === "revoked",
  ).length;
  const status =
    rawSecretLeakSuspected ||
    blockers.some((blocker) => blocker.includes("raw secret"))
      ? "blocked"
      : error || blockedCapabilities > 0
        ? "degraded"
        : capabilities.length === 0 &&
            grants.length === 0 &&
            vaultRefs.length === 0
          ? "idle"
          : "ready";

  return {
    generatedAtMs,
    status,
    headline:
      status === "ready"
        ? "Authority posture ready"
        : status === "degraded"
          ? "Authority posture degraded"
          : status === "blocked"
            ? "Authority posture blocked"
            : "Authority posture unavailable",
    detail:
      status === "ready"
        ? "Model, tool, connector, grant, and vault posture are projected from runtime contracts."
        : (blockers[0] ?? "No runtime authority projection is available yet."),
    summary: {
      readyCapabilities,
      blockedCapabilities,
      activeGrants,
      revokedGrants,
      vaultRefs: vaultRefs.length,
      rawSecretLeakSuspected,
      policyOverrides: Object.values(policyState.overrides).filter(
        (override) => override.inheritGlobal === false,
      ).length,
    },
    capabilities,
    grants,
    vaultRefs,
    blockers,
  };
}

function modelCapabilityRow(item: unknown): AuthorityCenterCapabilityRow {
  const record = recordValue(item);
  const routeId = stringValue(record?.routeId, "route.unknown");
  const credentialStatus = stringValue(
    record?.credentialReadiness?.status,
    "unknown",
  );
  const available =
    record?.workflowAvailability?.available === true &&
    record?.agentAvailability?.available === true;
  const status =
    available && credentialStatus === "ready" ? "ready" : credentialStatus;
  const privacyTier = stringValue(record?.privacyTier, "unknown privacy");
  const fallback = recordValue(record?.fallbackPolicy);
  const selectedEndpoint = stringValue(
    fallback?.selectedEndpointId,
    "no selected endpoint",
  );
  return {
    id: stringValue(record?.id, `model-capability:${routeId}`),
    label: `${routeId} / ${stringValue(record?.capability, "model")}`,
    kind: "model",
    status,
    tone: toneForStatus(status),
    detail: `${privacyTier} / ${selectedEndpoint}`,
    policyTarget: stringValue(record?.policyTarget, null),
    requiredScopes: stringArray(record?.authorityScopeRequirements),
    receiptTypes: stringArray(record?.receiptBehavior?.requiredReceiptTypes),
  };
}

function toolCapabilityRow(item: unknown): AuthorityCenterCapabilityRow {
  const record = recordValue(item);
  const status = stringValue(
    record?.credentialReadiness?.status,
    record?.credentialReady === true ? "ready" : "unknown",
  );
  return {
    id: stringValue(record?.stableToolId ?? record?.id, "tool.unknown"),
    label: stringValue(
      record?.displayName ?? record?.stableToolId,
      "Runtime tool",
    ),
    kind: "tool",
    status,
    tone: toneForStatus(status),
    detail: `${stringValue(record?.effectClass, "effect unknown")} / ${stringValue(record?.riskDomain, "risk unknown")}`,
    policyTarget: stringValue(record?.policyTarget, null),
    requiredScopes: stringArray(record?.authorityScopeRequirements),
    receiptTypes: stringArray(record?.receiptBehavior?.requiredReceiptTypes),
  };
}

function connectorCapabilityRow(
  connector: ConnectorSummary,
): AuthorityCenterCapabilityRow {
  const status = connector.status === "connected" ? "ready" : connector.status;
  return {
    id: connector.id,
    label: connector.name,
    kind: "connector",
    status,
    tone: toneForStatus(status),
    detail: `${connector.provider} / ${connector.authMode}`,
    policyTarget: `connector.${connector.id}`,
    requiredScopes: connector.scopes,
    receiptTypes: ["connector_policy_decision"],
  };
}

function grantRow(item: unknown): AuthorityCenterGrantRow {
  const record = recordValue(item);
  const revoked = Boolean(record?.revokedAt);
  const state = revoked ? "revoked" : "active";
  const receiptRef = stringValue(record?.receiptId, "none");
  const receiptRefs = [
    receiptRef,
    ...stringArray(record?.auditReceiptIds),
  ].filter((receiptId) => receiptId !== "none");
  return {
    id: stringValue(record?.id, "grant.unknown"),
    grantId: stringValue(record?.grantId, "wallet.grant.unknown"),
    state,
    tone: revoked ? "blocked" : "ready",
    allowedCount: stringArray(record?.allowed).length,
    deniedCount: stringArray(record?.denied).length,
    vaultRefCount: Object.keys(recordValue(record?.vaultRefs) ?? {}).length,
    receiptRef,
    receiptRefs,
    lastScope: stringValue(record?.lastUsedScope, "none"),
    expiresAt: stringValue(record?.expiresAt, "unknown"),
    canRevoke: !revoked,
  };
}

function vaultRow(item: unknown): AuthorityCenterVaultRow {
  const record = recordValue(item);
  const state = stringValue(record?.state ?? record?.status, "metadata");
  return {
    id: stringValue(
      record?.vaultRefHash ?? record?.id ?? record?.label,
      "vault.unknown",
    ),
    label: stringValue(record?.label, "Vault ref"),
    purpose: stringValue(record?.purpose, "provider.auth"),
    state,
    tone:
      state.includes("removed") || state.includes("missing")
        ? "blocked"
        : "ready",
    lastResolved: stringValue(record?.lastResolvedAt, "not resolved"),
  };
}

function toneForStatus(status: string): AuthorityCenterTone {
  const normalized = status.toLowerCase();
  if (["ready", "not_required", "connected", "active"].includes(normalized))
    return "ready";
  if (
    ["missing", "blocked", "revoked", "disabled", "needs_auth"].includes(
      normalized,
    )
  )
    return "blocked";
  if (["degraded", "unknown"].includes(normalized)) return "warning";
  return "idle";
}

function stringValue(value: unknown, fallback: string): string;
function stringValue(value: unknown, fallback: null): string | null;
function stringValue(value: unknown, fallback: string | null): string | null {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is string =>
          typeof item === "string" && item.trim().length > 0,
      )
    : [];
}

function arrayOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function recordValue(value: unknown): Record<string, any> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, any>)
    : null;
}

function containsRawSecretMaterial(value: unknown): boolean {
  const serialized = JSON.stringify(value);
  return /\b(sk-[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,})\b/.test(
    serialized,
  );
}

function fallbackScopesForCapability(
  capability: AuthorityCenterCapabilityRow,
): string[] {
  if (capability.kind === "model") return ["model.chat:*", "route.use:*"];
  if (capability.kind === "tool") return [`tool.call:${capability.id}`];
  return [`connector.use:${capability.id}`];
}

function safeGrantSegment(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
