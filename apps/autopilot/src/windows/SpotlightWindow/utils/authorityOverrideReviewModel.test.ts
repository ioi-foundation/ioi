import assert from "node:assert/strict";
import type {
  CapabilityGovernanceRequest,
  ShieldPolicyState,
} from "../../ChatWindow/chatPolicyCenter";
import type { SpotlightPermissionConnectorOverrideSummary } from "../hooks/useSpotlightPermissions";
import { buildAuthorityOverrideReviewCards } from "./authorityOverrideReviewModel.ts";

function createPolicyState(): ShieldPolicyState {
  return {
    version: 1,
    global: {
      reads: "auto",
      writes: "confirm",
      admin: "confirm",
      expert: "block",
      automations: "confirm_on_create",
      dataHandling: "local_only",
    },
    overrides: {
      gmail: {
        inheritGlobal: false,
        reads: "auto",
        writes: "auto",
        admin: "confirm",
        expert: "confirm",
        automations: "confirm_on_run",
        dataHandling: "local_redacted",
      },
      slack: {
        inheritGlobal: false,
        reads: "confirm",
        writes: "confirm",
        admin: "block",
        expert: "block",
        automations: "manual_only",
        dataHandling: "local_only",
      },
    },
  };
}

function createOverrides(): SpotlightPermissionConnectorOverrideSummary[] {
  return [
    {
      connectorId: "gmail",
      entryId: "connector:gmail",
      label: "Gmail",
      headline: "Policy override active",
      detail: "Reads Auto · Writes Auto · Automations Confirm on run",
    },
    {
      connectorId: "slack",
      entryId: "connector:slack",
      label: "Slack",
      headline: "Policy override active",
      detail: "Reads Confirm · Writes Confirm · Automations Manual only",
    },
  ];
}

function createGovernanceRequest(
  requestedState: ShieldPolicyState,
): CapabilityGovernanceRequest {
  return {
    requestId: "req-1",
    createdAtMs: 1,
    status: "pending",
    action: "widen",
    capabilityEntryId: "connector:gmail",
    capabilityLabel: "Gmail",
    capabilityKind: "connector",
    governingEntryId: "connector:gmail",
    governingLabel: "Gmail",
    governingKind: "connector",
    connectorId: "gmail",
    connectorLabel: "Gmail",
    sourceLabel: "Runtime connector",
    authorityTierLabel: "Connector",
    governedProfileLabel: "Guided default",
    leaseModeLabel: "Session",
    whySelectable: "Gmail can widen under connector authority.",
    headline: "Request wider lease for Gmail",
    detail: "Preview the requested wider connector posture before applying it.",
    requestedState,
  };
}

{
  const requestedState = createPolicyState();
  requestedState.overrides.gmail = {
    ...requestedState.overrides.gmail,
    admin: "auto",
  };

  const cards = buildAuthorityOverrideReviewCards({
    policyState: createPolicyState(),
    connectorOverrides: createOverrides(),
    governanceRequest: createGovernanceRequest(requestedState),
  });

  assert.equal(cards[0]?.connectorId, "gmail");
  assert.equal(cards[0]?.source, "governance_request");
  assert.equal(cards[0]?.canApplyGovernanceRequest, true);
  assert.equal(cards[0]?.canEdit, false);
  assert.equal(cards[0]?.deltaDeck.items.some((item) => item.id === "admin"), true);
  assert.equal(cards[1]?.connectorId, "slack");
}

{
  const cards = buildAuthorityOverrideReviewCards({
    policyState: createPolicyState(),
    connectorOverrides: createOverrides(),
    governanceRequest: null,
  });

  assert.equal(cards.length, 2);
  assert.equal(cards[0]?.source, "override");
  assert.equal(cards[0]?.canEdit, true);
  assert.equal(cards[0]?.simulationDeck.summary.auto > 0, true);
  assert.equal(cards[1]?.connectorId, "slack");
}
