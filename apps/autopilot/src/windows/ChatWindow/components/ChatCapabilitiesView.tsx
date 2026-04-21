import type {
  ConnectorSummary,
  StudioCapabilityDetailSection,
} from "@ioi/agent-ide";
import { useEffect } from "react";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import type {
  CapabilitySurface,
  CapabilityTrustProfile,
} from "./capabilities/model";
import { CapabilitiesDetailPane } from "./capabilities/CapabilitiesDetailPane";
import { CapabilitiesModals } from "./capabilities/CapabilitiesModals";
import { CapabilitiesNavigationPane } from "./capabilities/CapabilitiesNavigationPane";
import { useCapabilitiesController } from "./capabilities/useCapabilitiesController";
import "./ChatCapabilitiesView.css";

interface ChatCapabilitiesViewProps {
  runtime: TauriRuntime;
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
  onOpenSkillSources?: () => void;
  seedSurface?: CapabilitySurface | null;
  seedConnectorId?: string | null;
  seedConnectionDetailSection?: StudioCapabilityDetailSection | null;
  onConsumeSeedSurface?: () => void;
  onConsumeSeedConnector?: () => void;
}

export function ChatCapabilitiesView({
  runtime,
  getConnectorPolicySummary,
  getConnectorTrustProfile,
  onOpenPolicyCenter,
  onOpenInbox,
  onOpenSettings,
  onOpenSkillSources,
  seedSurface,
  seedConnectorId,
  seedConnectionDetailSection,
  onConsumeSeedSurface,
  onConsumeSeedConnector,
}: ChatCapabilitiesViewProps) {
  const controller = useCapabilitiesController({
    runtime,
    onOpenPolicyCenter,
  });

  useEffect(() => {
    if (!seedSurface) return;
    if (controller.surface !== seedSurface) {
      controller.openSurface(seedSurface);
    }
    onConsumeSeedSurface?.();
  }, [controller, onConsumeSeedSurface, seedSurface]);

  useEffect(() => {
    if (!seedConnectorId) return;
    if (controller.surface !== "connections") {
      controller.openSurface("connections");
      return;
    }

    const hasTarget = controller.connections.items.some(
      ({ connector }) => connector.id === seedConnectorId,
    );
    if (!hasTarget) {
      return;
    }

    if (controller.connections.selectedConnectionId !== seedConnectorId) {
      controller.connections.setSelectedConnectionId(seedConnectorId);
      return;
    }

    if (
      seedConnectionDetailSection &&
      controller.connections.detailSection !== seedConnectionDetailSection
    ) {
      controller.connections.setDetailSection(seedConnectionDetailSection);
      return;
    }

    onConsumeSeedConnector?.();
  }, [
    controller,
    onConsumeSeedConnector,
    seedConnectionDetailSection,
    seedConnectorId,
  ]);

  return (
    <div
      className={`capabilities-workbench ${controller.surface === null ? "is-home" : ""}`}
    >
      <CapabilitiesNavigationPane
        controller={controller}
        getConnectorTrustProfile={getConnectorTrustProfile}
        onOpenSkillSources={onOpenSkillSources}
      />

      {controller.surface !== null ? (
        <CapabilitiesDetailPane
          controller={controller}
          getConnectorPolicySummary={getConnectorPolicySummary}
          getConnectorTrustProfile={getConnectorTrustProfile}
          onOpenPolicyCenter={onOpenPolicyCenter}
          onOpenInbox={onOpenInbox}
          onOpenSettings={onOpenSettings}
        />
      ) : null}

      <CapabilitiesModals controller={controller} />
    </div>
  );
}

export const CapabilitiesView = ChatCapabilitiesView;
