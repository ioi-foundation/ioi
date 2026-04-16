import type { ConnectorApprovalMemoryRequest } from "./connector-runtime-types";

const SHIELD_APPROVAL_PREFIX = "SHIELD_APPROVAL_REQUIRED:";

export interface ShieldApprovalRequest {
  connectorId: string;
  actionId: string;
  actionLabel: string;
  message: string;
  policyFamily?: string | null;
  scopeKey?: string | null;
  scopeLabel?: string | null;
  rememberable?: boolean;
}

export function parseShieldApprovalRequest(
  error: unknown,
): ShieldApprovalRequest | null {
  const message = String(error ?? "");
  const markerIndex = message.indexOf(SHIELD_APPROVAL_PREFIX);
  if (markerIndex < 0) {
    return null;
  }

  const payload = message
    .slice(markerIndex + SHIELD_APPROVAL_PREFIX.length)
    .trim();
  try {
    const parsed = JSON.parse(payload) as Partial<ShieldApprovalRequest>;
    if (
      typeof parsed.connectorId === "string" &&
      typeof parsed.actionId === "string" &&
      typeof parsed.actionLabel === "string" &&
      typeof parsed.message === "string"
    ) {
      return {
        connectorId: parsed.connectorId,
        actionId: parsed.actionId,
        actionLabel: parsed.actionLabel,
        message: parsed.message,
        policyFamily:
          typeof parsed.policyFamily === "string" ? parsed.policyFamily : null,
        scopeKey: typeof parsed.scopeKey === "string" ? parsed.scopeKey : null,
        scopeLabel:
          typeof parsed.scopeLabel === "string" ? parsed.scopeLabel : null,
        rememberable:
          typeof parsed.rememberable === "boolean"
            ? parsed.rememberable
            : false,
      };
    }
  } catch (_error) {
    // Fall through so the caller can surface the original runtime error.
  }

  return null;
}

export function buildConnectorApprovalMemoryRequest(
  request: ShieldApprovalRequest,
  sourceLabel?: string | null,
): ConnectorApprovalMemoryRequest | null {
  if (!request.rememberable) {
    return null;
  }

  const policyFamily = request.policyFamily?.trim();
  if (!policyFamily) {
    return null;
  }

  return {
    connectorId: request.connectorId,
    actionId: request.actionId,
    actionLabel: request.actionLabel,
    policyFamily,
    scopeKey: request.scopeKey?.trim() || null,
    scopeLabel: request.scopeLabel?.trim() || null,
    sourceLabel: sourceLabel?.trim() || null,
  };
}
