import type { ConnectorSummary } from "@ioi/agent-ide";
import type { CapabilityTrustProfile } from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";

export interface CapabilitiesDetailPaneProps {
  controller: CapabilitiesController;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  getConnectorTrustProfile?: (
    connector: ConnectorSummary,
    options?: { template?: boolean },
  ) => CapabilityTrustProfile | null;
  onOpenPolicyCenter?: (connector?: ConnectorSummary | null) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
}
