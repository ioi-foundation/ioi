import type {
  CapabilityGovernanceRequest,
  GlobalPolicyDefaults,
  PolicyDeltaDeck,
  PolicySimulationDeck,
  ShieldPolicyState,
} from "../../ChatWindow/chatPolicyCenter";
import {
  buildConnectorPolicySummary,
  buildPolicyDeltaDeck,
  buildPolicyIntentDeltaDeck,
  buildPolicySimulationDeck,
  resolveConnectorPolicy,
} from "../../ChatWindow/chatPolicyCenter";
import type { ChatPermissionConnectorOverrideSummary } from "../hooks/useChatPermissions";

export interface AuthorityOverrideReviewCard {
  connectorId: string;
  label: string;
  source: "governance_request" | "override";
  headline: string;
  detail: string;
  effectivePolicy: GlobalPolicyDefaults;
  deltaDeck: PolicyDeltaDeck;
  simulationDeck: PolicySimulationDeck;
  canApplyGovernanceRequest: boolean;
  canEdit: boolean;
}

export interface BuildAuthorityOverrideReviewCardsInput {
  policyState: ShieldPolicyState;
  connectorOverrides: ChatPermissionConnectorOverrideSummary[];
  governanceRequest?: CapabilityGovernanceRequest | null;
}

function connectorDetail(
  policyState: ShieldPolicyState,
  connectorId: string,
): { detail: string; effectivePolicy: GlobalPolicyDefaults } {
  const summary = buildConnectorPolicySummary(policyState, connectorId);
  const resolved = resolveConnectorPolicy(policyState, connectorId);
  return {
    detail: summary.detail,
    effectivePolicy: resolved.effective,
  };
}

export function buildAuthorityOverrideReviewCards(
  input: BuildAuthorityOverrideReviewCardsInput,
): AuthorityOverrideReviewCard[] {
  const cards: AuthorityOverrideReviewCard[] = [];
  const seenConnectorIds = new Set<string>();

  const governanceConnectorId = input.governanceRequest?.connectorId?.trim() || null;
  if (input.governanceRequest && governanceConnectorId) {
    const governanceSummary = connectorDetail(
      input.governanceRequest.requestedState,
      governanceConnectorId,
    );
    cards.push({
      connectorId: governanceConnectorId,
      label:
        input.governanceRequest.connectorLabel?.trim() || governanceConnectorId,
      source: "governance_request",
      headline: input.governanceRequest.headline,
      detail: governanceSummary.detail,
      effectivePolicy: governanceSummary.effectivePolicy,
      deltaDeck: buildPolicyIntentDeltaDeck(
        input.policyState,
        input.governanceRequest.requestedState,
        governanceConnectorId,
        {
          baselineLabel: "Current effective posture",
          nextLabel:
            input.governanceRequest.action === "widen"
              ? "Requested wider posture"
              : "Requested baseline posture",
        },
      ),
      simulationDeck: buildPolicySimulationDeck(
        input.governanceRequest.requestedState,
        governanceConnectorId,
      ),
      canApplyGovernanceRequest:
        JSON.stringify(input.governanceRequest.requestedState) !==
        JSON.stringify(input.policyState),
      canEdit: false,
    });
    seenConnectorIds.add(governanceConnectorId);
  }

  input.connectorOverrides.forEach((override) => {
    if (seenConnectorIds.has(override.connectorId)) {
      return;
    }
    const currentSummary = connectorDetail(input.policyState, override.connectorId);
    cards.push({
      connectorId: override.connectorId,
      label: override.label,
      source: "override",
      headline: override.headline,
      detail: currentSummary.detail,
      effectivePolicy: currentSummary.effectivePolicy,
      deltaDeck: buildPolicyDeltaDeck(input.policyState, override.connectorId),
      simulationDeck: buildPolicySimulationDeck(
        input.policyState,
        override.connectorId,
      ),
      canApplyGovernanceRequest: false,
      canEdit: true,
    });
  });

  return cards;
}
