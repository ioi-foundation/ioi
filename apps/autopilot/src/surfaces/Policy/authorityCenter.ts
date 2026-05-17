import type { ConnectorSummary } from "@ioi/agent-ide";
import type { ShieldPolicyState } from "./policyCenter";

export type AuthorityCenterTone = "ready" | "warning" | "blocked" | "idle";
export type AuthorityCenterGrantStatus =
  | "active"
  | "partial"
  | "missing"
  | "not_required";
export type AuthorityCenterPolicyStatus =
  | "governed"
  | "custom"
  | "inherited"
  | "unbound";
export type AuthorityCenterReceiptStatus = "required" | "missing";
export type AuthorityCenterRepairActionKind =
  | "requestGrant"
  | "openConnectorCredential"
  | "openModelRoute"
  | "openWorkflowPreflight";

export function authorityCenterPostureTone(value: string): AuthorityCenterTone {
  if (
    value === "active" ||
    value === "required" ||
    value === "governed" ||
    value === "custom" ||
    value === "inherited" ||
    value === "not_required"
  ) {
    return "ready";
  }
  if (value === "missing" || value === "unbound") return "blocked";
  if (value === "partial") return "warning";
  return "idle";
}

export interface AuthorityCenterRepairAction {
  id: string;
  kind: AuthorityCenterRepairActionKind;
  label: string;
  detail: string;
  targetRef: string;
  authorityScopes: string[];
  receiptTypes: string[];
}

export interface AuthorityCenterCapabilityRow {
  id: string;
  capabilityRef: string;
  label: string;
  kind: "model" | "tool" | "connector";
  status: string;
  readinessStatus: string;
  tone: AuthorityCenterTone;
  detail: string;
  policyTarget?: string | null;
  requiredScopes: string[];
  receiptTypes: string[];
  grantStatus: AuthorityCenterGrantStatus;
  policyStatus: AuthorityCenterPolicyStatus;
  receiptStatus: AuthorityCenterReceiptStatus;
  readinessSummary: string;
  lastRepairReceiptRefs: string[];
  lastRepairSummary: string;
  repairActions: AuthorityCenterRepairAction[];
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
  allowedScopes: string[];
  deniedScopes: string[];
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
  workflowPreflightSnapshot?: unknown;
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
  workflowPreflightSnapshot,
  connectors = [],
  policyState,
  generatedAtMs = Date.now(),
  error = null,
}: BuildAuthorityCenterProjectionInput): AuthorityCenterProjection {
  const modelCapabilities = arrayPayload(modelSnapshot, [
    "modelCapabilities",
    "capabilities",
    "items",
  ]).map(modelCapabilityRow);
  const toolCapabilities = arrayPayload(toolCatalog, [
    "tools",
    "toolCatalog",
    "toolContracts",
    "capabilities",
    "items",
  ]).map(toolCapabilityRow);
  const connectorCapabilities = connectors.map(connectorCapabilityRow);
  const baseCapabilities = [
    ...modelCapabilities,
    ...toolCapabilities,
    ...connectorCapabilities,
  ];
  const authorityRecord = recordValue(authoritySnapshot);
  const modelRecord = recordValue(modelSnapshot);
  const grants = arrayOf(authorityRecord?.grants ?? modelRecord?.tokens).map(
    grantRow,
  );
  const workflowRepairReceipts = workflowPreflightRepairReceiptRows(
    workflowPreflightSnapshot ??
      field(
        authorityRecord,
        "workflowCapabilityPreflights",
        "workflow_capability_preflights",
        "workflowPreflightReceipts",
        "workflow_preflight_receipts",
      ) ??
      field(
        modelRecord,
        "workflowCapabilityPreflights",
        "workflow_capability_preflights",
      ),
  );
  const capabilities = baseCapabilities.map((capability) =>
    withAuthorityPosture(
      capability,
      grants,
      policyState,
      workflowRepairReceipts,
    ),
  );
  const vaultRefs = arrayOf(
    authorityRecord?.vaultRefs ?? modelRecord?.vaultRefs,
  ).map(vaultRow);
  const blockedCapabilities = capabilities.filter(
    (capability) => !capabilityRuntimeReady(capability),
  ).length;
  const rawSecretLeakSuspected = containsRawSecretMaterial({
    capabilities,
    grants,
    vaultRefs,
  });
  const blockers = [
    ...(error ? [error] : []),
    ...(blockedCapabilities > 0
      ? [`${blockedCapabilities} live capabilities are not run-ready.`]
      : []),
    ...(rawSecretLeakSuspected
      ? ["Authority projection includes material that resembles a raw secret."]
      : []),
  ];
  const readyCapabilities = capabilities.filter(capabilityRuntimeReady).length;
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
  const credentialReadiness = recordValue(
    field(record, "credentialReadiness", "credential_readiness"),
  );
  const workflowAvailability = recordValue(
    field(record, "workflowAvailability", "workflow_availability"),
  );
  const agentAvailability = recordValue(
    field(record, "agentAvailability", "agent_availability"),
  );
  const fallback = recordValue(
    field(record, "fallbackPolicy", "fallback_policy"),
  );
  const receiptBehavior = recordValue(
    field(record, "receiptBehavior", "receipt_behavior"),
  );
  const routeId = stringValue(
    field(record, "routeId", "route_id"),
    "route.unknown",
  );
  const credentialStatus = stringValue(
    field(credentialReadiness, "status", "state"),
    "unknown",
  );
  const available =
    workflowAvailability?.available === true &&
    agentAvailability?.available === true;
  const status =
    available && credentialStatus === "ready" ? "ready" : credentialStatus;
  const privacyTier = stringValue(
    field(record, "privacyTier", "privacy_tier"),
    "unknown privacy",
  );
  const selectedEndpoint = stringValue(
    field(fallback, "selectedEndpointId", "selected_endpoint_id"),
    "no selected endpoint",
  );
  const id = stringValue(
    field(record, "id", "modelCapabilityRef", "model_capability_ref"),
    `model-capability:${routeId}`,
  );
  return withRepairActions({
    id,
    capabilityRef: id,
    label: `${routeId} / ${stringValue(field(record, "capability"), "model")}`,
    kind: "model",
    status,
    readinessStatus: status,
    tone: toneForStatus(status),
    detail: `${privacyTier} / ${selectedEndpoint}`,
    policyTarget: stringValue(
      field(record, "policyTarget", "policy_target"),
      `model.${routeId}`,
    ),
    requiredScopes: stringArray(
      field(
        record,
        "authorityScopeRequirements",
        "authority_scope_requirements",
      ),
    ),
    receiptTypes: stringArray(
      field(receiptBehavior, "requiredReceiptTypes", "required_receipt_types"),
    ),
    lastRepairReceiptRefs: receiptRefsFromCapabilityRecord(record),
  });
}

function toolCapabilityRow(item: unknown): AuthorityCenterCapabilityRow {
  const record = recordValue(item);
  const credentialReadiness = recordValue(
    field(record, "credentialReadiness", "credential_readiness"),
  );
  const receiptBehavior = recordValue(
    field(record, "receiptBehavior", "receipt_behavior"),
  );
  const stableToolId = stringValue(
    field(record, "stableToolId", "stable_tool_id", "toolId", "tool_id", "id"),
    "tool.unknown",
  );
  const status = stringValue(
    field(credentialReadiness, "status", "state"),
    field(record, "credentialReady", "credential_ready") === true
      ? "ready"
      : "unknown",
  );
  return withRepairActions({
    id: stableToolId,
    capabilityRef: `tool-capability:${stableToolId}`,
    label: stringValue(
      field(record, "displayName", "display_name") ?? stableToolId,
      "Runtime tool",
    ),
    kind: "tool",
    status,
    readinessStatus: status,
    tone: toneForStatus(status),
    detail: `${stringValue(field(record, "effectClass", "effect_class"), "effect unknown")} / ${stringValue(field(record, "riskDomain", "risk_domain", "riskClass", "risk_class"), "risk unknown")}`,
    policyTarget: stringValue(
      field(record, "policyTarget", "policy_target"),
      `tool.${stableToolId}`,
    ),
    requiredScopes: stringArray(
      field(
        record,
        "authorityScopeRequirements",
        "authority_scope_requirements",
        "authorityScopes",
        "authority_scopes",
      ),
    ),
    receiptTypes: stringArray(
      field(receiptBehavior, "requiredReceiptTypes", "required_receipt_types"),
    ),
    lastRepairReceiptRefs: receiptRefsFromCapabilityRecord(record),
  });
}

function connectorCapabilityRow(
  connector: ConnectorSummary,
): AuthorityCenterCapabilityRow {
  const status = connector.status === "connected" ? "ready" : connector.status;
  return withRepairActions({
    id: connector.id,
    capabilityRef: `connector-capability:${connector.id}`,
    label: connector.name,
    kind: "connector",
    status,
    readinessStatus: status,
    tone: toneForStatus(status),
    detail: `${connector.provider} / ${connector.authMode}`,
    policyTarget: `connector.${connector.id}`,
    requiredScopes: connector.scopes,
    receiptTypes: ["connector_policy_decision"],
    lastRepairReceiptRefs: [],
  });
}

function withRepairActions(
  capability: Omit<
    AuthorityCenterCapabilityRow,
    | "repairActions"
    | "grantStatus"
    | "policyStatus"
    | "receiptStatus"
    | "readinessSummary"
    | "lastRepairSummary"
  >,
): AuthorityCenterCapabilityRow {
  const lastRepairReceiptRefs = safeReceiptRefs(
    capability.lastRepairReceiptRefs,
  );
  const base = {
    ...capability,
    lastRepairReceiptRefs,
    grantStatus: "missing" as const,
    policyStatus: capability.policyTarget
      ? ("governed" as const)
      : ("unbound" as const),
    receiptStatus:
      capability.receiptTypes.length > 0
        ? ("required" as const)
        : ("missing" as const),
    readinessSummary: "Awaiting authority posture projection.",
    lastRepairSummary: repairReceiptSummary(lastRepairReceiptRefs),
  };
  return {
    ...base,
    repairActions: repairActionsForCapability(base),
  };
}

export function repairActionsForCapability(
  capability: Omit<AuthorityCenterCapabilityRow, "repairActions">,
): AuthorityCenterRepairAction[] {
  const normalizedStatus = capability.status.toLowerCase();
  const needsRepair =
    capability.tone !== "ready" ||
    capability.grantStatus === "missing" ||
    capability.grantStatus === "partial" ||
    capability.receiptStatus === "missing" ||
    capability.policyStatus === "unbound" ||
    [
      "missing",
      "needs_auth",
      "blocked",
      "disabled",
      "unknown",
      "degraded",
    ].includes(normalizedStatus);
  if (!needsRepair) return [];

  const targetRef = capability.policyTarget ?? capability.id;
  const base = {
    targetRef,
    authorityScopes: capability.requiredScopes,
    receiptTypes: capability.receiptTypes,
  };
  const actions: AuthorityCenterRepairAction[] = [];

  if (
    capability.grantStatus === "missing" ||
    capability.grantStatus === "partial" ||
    capability.tone !== "ready"
  ) {
    actions.push({
      ...base,
      id: `${capability.id}:request-grant`,
      kind: "requestGrant",
      label: "Request scoped grant",
      detail:
        capability.requiredScopes.length > 0
          ? `Issue a short-lived grant for ${capability.requiredScopes
              .slice(0, 2)
              .join(", ")}.`
          : "Issue a short-lived grant using the runtime capability fallback scope.",
    });
  }

  if (capability.kind === "model" && capability.tone !== "ready") {
    actions.push({
      ...base,
      id: `${capability.id}:open-model-route`,
      kind: "openModelRoute",
      label: "Open model route",
      detail:
        "Review capability routing, model mounting, credential readiness, and fallback posture.",
    });
  } else if (capability.kind !== "model" && capability.tone !== "ready") {
    actions.push({
      ...base,
      id: `${capability.id}:open-connector-credential`,
      kind: "openConnectorCredential",
      label:
        capability.kind === "connector"
          ? "Open connector credential"
          : "Open tool credential",
      detail:
        capability.kind === "connector"
          ? "Resolve connector auth, scopes, and vault-backed credential readiness."
          : "Resolve the connector or local credential backing this tool capability.",
    });
  }

  if (
    capability.receiptStatus === "missing" ||
    capability.policyStatus === "unbound" ||
    capability.grantStatus === "missing" ||
    capability.grantStatus === "partial"
  ) {
    actions.push({
      ...base,
      id: `${capability.id}:open-workflow-preflight`,
      kind: "openWorkflowPreflight",
      label: "Open workflow preflight",
      detail:
        "Inspect workflow readiness before a live run can consume this capability.",
    });
  }

  return actions;
}

function withAuthorityPosture(
  capability: AuthorityCenterCapabilityRow,
  grants: AuthorityCenterGrantRow[],
  policyState: ShieldPolicyState,
  workflowRepairReceipts: AuthorityWorkflowPreflightRepairReceiptRow[] = [],
): AuthorityCenterCapabilityRow {
  const grantStatus = grantStatusForCapability(capability, grants);
  const policyStatus = policyStatusForCapability(capability, policyState);
  const receiptStatus: AuthorityCenterReceiptStatus =
    capability.receiptTypes.length > 0 ? "required" : "missing";
  const readinessSummary = [
    `capability ${capability.readinessStatus}`,
    `grant ${grantStatus}`,
    `policy ${policyStatus}`,
    `receipts ${receiptStatus}`,
  ].join(" · ");
  const lastRepairReceiptRefs = safeReceiptRefs([
    ...capability.lastRepairReceiptRefs,
    ...grantRepairReceiptRefsForCapability(capability, grants),
    ...workflowRepairReceiptRefsForCapability(
      capability,
      workflowRepairReceipts,
    ),
  ]);
  const next = {
    ...capability,
    grantStatus,
    policyStatus,
    receiptStatus,
    readinessSummary,
    lastRepairReceiptRefs,
    lastRepairSummary: repairReceiptSummary(lastRepairReceiptRefs),
  };
  return {
    ...next,
    repairActions: repairActionsForCapability(next),
  };
}

function grantStatusForCapability(
  capability: AuthorityCenterCapabilityRow,
  grants: AuthorityCenterGrantRow[],
): AuthorityCenterGrantStatus {
  if (capability.requiredScopes.length === 0) return "not_required";
  const activeAllowedScopes = grants
    .filter((grant) => grant.state === "active")
    .flatMap((grant) => grant.allowedScopes);
  if (activeAllowedScopes.length === 0) return "missing";
  const matchedCount = capability.requiredScopes.filter((scope) =>
    activeAllowedScopes.some((allowedScope) =>
      authorityScopeMatches(scope, allowedScope),
    ),
  ).length;
  if (matchedCount === capability.requiredScopes.length) return "active";
  if (matchedCount > 0) return "partial";
  return "missing";
}

function authorityScopeMatches(
  requiredScope: string,
  allowedScope: string,
): boolean {
  if (requiredScope === allowedScope) return true;
  if (allowedScope.endsWith(":*")) {
    return requiredScope.startsWith(allowedScope.slice(0, -1));
  }
  if (allowedScope.endsWith(".*")) {
    return requiredScope.startsWith(allowedScope.slice(0, -1));
  }
  return false;
}

function policyStatusForCapability(
  capability: AuthorityCenterCapabilityRow,
  policyState: ShieldPolicyState,
): AuthorityCenterPolicyStatus {
  if (capability.kind === "connector") {
    const override = policyState.overrides[capability.id];
    return override && !override.inheritGlobal ? "custom" : "inherited";
  }
  return capability.policyTarget ? "governed" : "unbound";
}

function capabilityRuntimeReady(
  capability: AuthorityCenterCapabilityRow,
): boolean {
  return (
    capability.tone === "ready" &&
    (capability.grantStatus === "active" ||
      capability.grantStatus === "not_required") &&
    capability.policyStatus !== "unbound" &&
    capability.receiptStatus === "required"
  );
}

function grantRow(item: unknown): AuthorityCenterGrantRow {
  const record = recordValue(item);
  const revoked = Boolean(record?.revokedAt);
  const state = revoked ? "revoked" : "active";
  const receiptRef =
    safeReceiptRefs([field(record, "receiptId", "receipt_id")])[0] ?? "none";
  const allowedScopes = stringArray(
    field(record, "allowed", "allowedScopes", "allowed_scopes"),
  );
  const deniedScopes = stringArray(
    field(record, "denied", "deniedScopes", "denied_scopes"),
  );
  const receiptRefs = safeReceiptRefs([
    receiptRef,
    ...stringArray(field(record, "auditReceiptIds", "audit_receipt_ids")),
    ...stringArray(field(record, "repairReceiptRefs", "repair_receipt_refs")),
    ...stringArray(
      field(record, "lastRepairReceiptRefs", "last_repair_receipt_refs"),
    ),
  ]);
  return {
    id: stringValue(record?.id, "grant.unknown"),
    grantId: stringValue(
      field(record, "grantId", "grant_id"),
      "wallet.grant.unknown",
    ),
    state,
    tone: revoked ? "blocked" : "ready",
    allowedCount: allowedScopes.length,
    deniedCount: deniedScopes.length,
    vaultRefCount: Object.keys(recordValue(record?.vaultRefs) ?? {}).length,
    receiptRef,
    receiptRefs,
    allowedScopes,
    deniedScopes,
    lastScope: stringValue(
      field(record, "lastUsedScope", "last_used_scope"),
      "none",
    ),
    expiresAt: stringValue(field(record, "expiresAt", "expires_at"), "unknown"),
    canRevoke: !revoked,
  };
}

function grantRepairReceiptRefsForCapability(
  capability: AuthorityCenterCapabilityRow,
  grants: AuthorityCenterGrantRow[],
): string[] {
  if (capability.requiredScopes.length === 0) return [];
  return grants
    .filter((grant) => grant.state === "active")
    .filter((grant) =>
      capability.requiredScopes.some((scope) =>
        grant.allowedScopes.some((allowedScope) =>
          authorityScopeMatches(scope, allowedScope),
        ),
      ),
    )
    .flatMap((grant) => grant.receiptRefs);
}

function repairReceiptSummary(receiptRefs: string[]): string {
  if (receiptRefs.length === 0) return "No repair receipt yet";
  return `${receiptRefs.length} repair receipt${
    receiptRefs.length === 1 ? "" : "s"
  } projected`;
}

function receiptRefsFromCapabilityRecord(
  record: Record<string, any> | null,
): string[] {
  const repairMetadata = recordValue(
    field(
      record,
      "repairMetadata",
      "repair_metadata",
      "repair",
      "workflowPreflight",
      "workflow_preflight",
      "preflight",
      "preflightReceipt",
      "preflight_receipt",
    ),
  );
  return safeReceiptRefs([
    ...stringArray(field(record, "receiptRefs", "receipt_refs")),
    ...stringArray(field(record, "auditReceiptIds", "audit_receipt_ids")),
    ...stringArray(field(record, "repairReceiptRefs", "repair_receipt_refs")),
    ...stringArray(
      field(record, "lastRepairReceiptRefs", "last_repair_receipt_refs"),
    ),
    ...stringArray(
      field(record, "preflightReceiptRefs", "preflight_receipt_refs"),
    ),
    ...stringArray(field(repairMetadata, "receiptRefs", "receipt_refs")),
    ...stringArray(
      field(repairMetadata, "auditReceiptIds", "audit_receipt_ids"),
    ),
    ...stringArray(
      field(repairMetadata, "repairReceiptRefs", "repair_receipt_refs"),
    ),
  ]);
}

interface AuthorityWorkflowPreflightRepairReceiptRow {
  capabilityRef: string;
  routeId: string | null;
  receiptRefs: string[];
  authorityScopes: string[];
  authorityScopeRequirements: string[];
}

function workflowRepairReceiptRefsForCapability(
  capability: AuthorityCenterCapabilityRow,
  rows: AuthorityWorkflowPreflightRepairReceiptRow[],
): string[] {
  return rows
    .filter((row) => workflowRepairReceiptMatchesCapability(capability, row))
    .flatMap((row) => row.receiptRefs);
}

function workflowRepairReceiptMatchesCapability(
  capability: AuthorityCenterCapabilityRow,
  row: AuthorityWorkflowPreflightRepairReceiptRow,
): boolean {
  const candidateRefs = [
    capability.capabilityRef,
    capability.id,
    capability.policyTarget,
  ].filter((value): value is string => Boolean(value));
  if (
    row.capabilityRef &&
    candidateRefs.some((candidate) => candidate === row.capabilityRef)
  ) {
    return true;
  }
  if (capability.kind === "model" && row.routeId) {
    const routeId = row.routeId;
    if (candidateRefs.some((candidate) => candidate.includes(routeId))) {
      return true;
    }
  }
  const rowScopes = [
    ...row.authorityScopes,
    ...row.authorityScopeRequirements,
  ];
  return capability.requiredScopes.some((scope) =>
    rowScopes.some(
      (rowScope) =>
        authorityScopeMatches(scope, rowScope) ||
        authorityScopeMatches(rowScope, scope),
    ),
  );
}

function workflowPreflightRepairReceiptRows(
  snapshot: unknown,
): AuthorityWorkflowPreflightRepairReceiptRow[] {
  const rows: AuthorityWorkflowPreflightRepairReceiptRow[] = [];
  for (const envelope of workflowPreflightEnvelopeCandidates(snapshot)) {
    const envelopeRecord = recordValue(envelope);
    if (!envelopeRecord) continue;
    const payload =
      recordValue(field(envelopeRecord, "payload", "output")) ??
      envelopeRecord;
    const preflight = recordValue(field(payload, "preflight")) ?? payload;
    const receiptRefs = safeReceiptRefs([
      ...stringArray(field(envelopeRecord, "receiptRefs", "receipt_refs")),
      ...stringArray(field(payload, "receiptRefs", "receipt_refs")),
      ...stringArray(field(preflight, "receiptRefs", "receipt_refs")),
    ]);
    const rowRecords = workflowPreflightRowCandidates(preflight, payload);
    if (rowRecords.length === 0) {
      for (const capabilityRef of stringArray(
        field(preflight, "capabilityRefs", "capability_refs"),
      )) {
        rows.push({
          capabilityRef,
          routeId: null,
          receiptRefs,
          authorityScopes: [],
          authorityScopeRequirements: [],
        });
      }
      continue;
    }
    for (const row of rowRecords) {
      rows.push({
        capabilityRef: stringValue(
          field(row, "capabilityRef", "capability_ref"),
          "",
        ),
        routeId: stringValue(field(row, "routeId", "route_id"), null),
        receiptRefs: safeReceiptRefs([
          ...receiptRefs,
          ...stringArray(field(row, "receiptRefs", "receipt_refs")),
        ]),
        authorityScopes: stringArray(
          field(row, "authorityScopes", "authority_scopes"),
        ),
        authorityScopeRequirements: stringArray(
          field(
            row,
            "authorityScopeRequirements",
            "authority_scope_requirements",
          ),
        ),
      });
    }
  }
  return rows.filter((row) => row.receiptRefs.length > 0);
}

function workflowPreflightEnvelopeCandidates(snapshot: unknown): unknown[] {
  if (!snapshot) return [];
  if (Array.isArray(snapshot)) return snapshot;
  const record = recordValue(snapshot);
  if (!record) return [];
  return [
    snapshot,
    ...arrayPayload(record, [
      "workflowCapabilityPreflights",
      "workflow_capability_preflights",
      "workflowPreflightReceipts",
      "workflow_preflight_receipts",
      "capabilityPreflights",
      "capability_preflights",
      "items",
    ]),
    ...arrayPayload(field(record, "runtimeThreadEvents", "runtime_thread_events"), [
      "items",
      "events",
    ]),
    ...arrayPayload(field(record, "nodeRuns", "node_runs"), ["items", "runs"]),
    ...workflowPreflightNestedCandidate(record, ["tuiControlState", "tui_control_state"]),
    ...workflowPreflightNestedCandidate(record, ["finalState", "final_state"]),
  ];
}

function workflowPreflightNestedCandidate(
  record: Record<string, any>,
  keys: string[],
): unknown[] {
  const nested = recordValue(field(record, ...keys));
  if (!nested) return [];
  const values = recordValue(field(nested, "values"));
  return [
    nested,
    field(values, "capabilityPreflight", "capability_preflight"),
  ].filter(Boolean);
}

function workflowPreflightRowCandidates(
  preflight: Record<string, any>,
  payload: Record<string, any>,
): Record<string, any>[] {
  return [
    ...arrayPayload(preflight, ["rows", "capabilityRows", "capability_rows"]),
    ...arrayPayload(payload, ["rows", "capabilityRows", "capability_rows"]),
  ]
    .map(recordValue)
    .filter((row): row is Record<string, any> => Boolean(row));
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

function safeReceiptRefs(value: unknown[]): string[] {
  return Array.from(
    new Set(
      value
        .filter(
          (item): item is string =>
            typeof item === "string" && item.trim().length > 0,
        )
        .map((item) => item.trim())
        .filter(
          (item) =>
            item !== "none" &&
            item !== "null" &&
            !rawSecretMaterialPattern.test(item),
        ),
    ),
  );
}

function arrayOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function recordValue(value: unknown): Record<string, any> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, any>)
    : null;
}

function field(record: Record<string, any> | null, ...keys: string[]): unknown {
  if (!record) return undefined;
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null) return record[key];
  }
  return undefined;
}

function arrayPayload(value: unknown, keys: readonly string[]): unknown[] {
  if (Array.isArray(value)) return value;
  const record = recordValue(value);
  if (!record) return [];
  for (const key of keys) {
    const candidate = record[key];
    if (Array.isArray(candidate)) return candidate;
  }
  return [];
}

function containsRawSecretMaterial(value: unknown): boolean {
  const serialized = JSON.stringify(value);
  return rawSecretMaterialPattern.test(serialized);
}

const rawSecretMaterialPattern =
  /\b(sk-[A-Za-z0-9_-]{8,}|xox[baprs]-[A-Za-z0-9-]{8,}|gh[pousr]_[A-Za-z0-9_]{12,})\b/;

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
