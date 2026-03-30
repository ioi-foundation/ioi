import type { ConnectorSummary } from "@ioi/agent-ide";
import { type CapabilitiesController } from "./useCapabilitiesController";

export interface CapabilitiesDetailPaneProps {
  controller: CapabilitiesController;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
}
