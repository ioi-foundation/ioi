import { useMemo } from "react";
import {
  buildPolicySimulationDeck,
  dataHandlingLabel,
  resolveConnectorPolicy,
  type ShieldApprovalHookReceipt,
  type ShieldRememberedApprovalSnapshot,
  type CapabilityGovernanceRequest,
  type DataHandlingMode,
  type ShieldPolicyState,
} from "../../ChatWindow/chatPolicyCenter";
import type { ChatPermissionConnectorOverrideSummary } from "./useChatPermissions";
import { buildPrivacyGovernanceHistoryOverview } from "../utils/privacyGovernanceHistoryModel";

export interface ChatPrivacyConnectorSummary {
  connectorId: string;
  label: string;
  mode: DataHandlingMode;
  modeLabel: string;
  headline: string;
  detail: string;
}

export interface ChatPrivacySnapshot {
  generatedAtMs: number;
  focusedScopeLabel: string;
  focusedDataHandlingLabel: string;
  focusedDataHandlingDetail: string;
  sessionReviewLabel: string;
  sessionReviewDetail: string;
  exportSurfaceLabel: string;
  exportSurfaceDetail: string;
  governingSourceLabel: string;
  activeOverrideCount: number;
  redactedOverrideCount: number;
  localOnlyOverrideCount: number;
  pendingGovernanceSummary: string | null;
  governanceHistoryLabel: string;
  governanceHistoryDetail: string;
  recentGovernanceReceipts: ShieldApprovalHookReceipt[];
  connectors: ChatPrivacyConnectorSummary[];
}

interface UseChatPrivacySettingsOptions {
  policyState: ShieldPolicyState;
  governanceRequest: CapabilityGovernanceRequest | null;
  connectorOverrides: ChatPermissionConnectorOverrideSummary[];
  activeOverrideCount: number;
  rememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  isPiiGate?: boolean;
}

function focusConnectorId(
  governanceRequest: CapabilityGovernanceRequest | null,
  connectorOverrides: ChatPermissionConnectorOverrideSummary[],
): string | null {
  return governanceRequest?.connectorId || connectorOverrides[0]?.connectorId || null;
}

export function useChatPrivacySettings({
  policyState,
  governanceRequest,
  connectorOverrides,
  activeOverrideCount,
  rememberedApprovals,
  isPiiGate = false,
}: UseChatPrivacySettingsOptions): ChatPrivacySnapshot {
  return useMemo(() => {
    const connectors = connectorOverrides.map((override) => {
      const effective = resolveConnectorPolicy(policyState, override.connectorId).effective;
      return {
        connectorId: override.connectorId,
        label: override.label,
        mode: effective.dataHandling,
        modeLabel: dataHandlingLabel(effective.dataHandling),
        headline: override.headline,
        detail: override.detail,
      };
    });

    const focusedConnectorId = focusConnectorId(governanceRequest, connectorOverrides);
    const focusedScopeLabel =
      governanceRequest?.connectorLabel ||
      connectors[0]?.label ||
      "Global runtime posture";
    const focusedPolicy = focusedConnectorId
      ? resolveConnectorPolicy(policyState, focusedConnectorId).effective
      : policyState.global;
    const focusedDataHandling = buildPolicySimulationDeck(
      policyState,
      focusedConnectorId,
    ).artifactHandling;

    const redactedOverrideCount = connectors.filter(
      (connector) => connector.mode === "local_redacted",
    ).length;
    const localOnlyOverrideCount = connectors.filter(
      (connector) => connector.mode === "local_only",
    ).length;

    const requestedArtifactHandling = governanceRequest
      ? buildPolicySimulationDeck(
          governanceRequest.requestedState,
          governanceRequest.connectorId || null,
        ).artifactHandling
      : null;

    let sessionReviewLabel = "Local-only evidence";
    let sessionReviewDetail =
      focusedPolicy.dataHandling === "local_redacted"
        ? "The focused runtime posture allows artifacts to leave the local shell only after runtime redaction."
        : "Artifacts stay local to the shell/runtime path unless the governing policy is widened.";

    if (isPiiGate) {
      sessionReviewLabel = "Privacy review pending";
      sessionReviewDetail =
        "The runtime is holding the active session at a privacy-aware review gate before continuing.";
    } else if (requestedArtifactHandling) {
      sessionReviewLabel = "Privacy posture change pending";
      sessionReviewDetail = `${governanceRequest?.headline ?? "A governance request"} would move artifact handling to ${requestedArtifactHandling.label}.`;
    } else if (focusedPolicy.dataHandling === "local_redacted") {
      sessionReviewLabel = "Redacted export allowed";
    }

    const governanceHistory = buildPrivacyGovernanceHistoryOverview({
      governanceRequest,
      rememberedApprovals,
    });

    return {
      generatedAtMs: Date.now(),
      focusedScopeLabel,
      focusedDataHandlingLabel: focusedDataHandling.label,
      focusedDataHandlingDetail: focusedDataHandling.detail,
      sessionReviewLabel,
      sessionReviewDetail,
      exportSurfaceLabel: "Canonical local export",
      exportSurfaceDetail:
        "Trace bundle export stays operator-initiated through the local save dialog. Artifact sharing is still governed by the current data-handling posture.",
      governingSourceLabel:
        governanceRequest?.governingLabel ||
        (focusedConnectorId ? "Connector policy override" : "Global Shield policy"),
      activeOverrideCount,
      redactedOverrideCount,
      localOnlyOverrideCount,
      pendingGovernanceSummary: requestedArtifactHandling
        ? `${requestedArtifactHandling.label} requested for ${governanceRequest?.connectorLabel ?? "the focused scope"}.`
        : null,
      governanceHistoryLabel: governanceHistory.label,
      governanceHistoryDetail: governanceHistory.detail,
      recentGovernanceReceipts: governanceHistory.recentReceipts,
      connectors,
    };
  }, [
    activeOverrideCount,
    connectorOverrides,
    governanceRequest,
    isPiiGate,
    policyState,
    rememberedApprovals,
  ]);
}
