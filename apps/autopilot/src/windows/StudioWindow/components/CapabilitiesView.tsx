import type { ConnectorSummary } from "@ioi/agent-ide";
import { useEffect } from "react";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import type { CapabilitySurface } from "./capabilities/model";
import { CapabilitiesDetailPane } from "./capabilities/CapabilitiesDetailPane";
import { CapabilitiesModals } from "./capabilities/CapabilitiesModals";
import { CapabilitiesNavigationPane } from "./capabilities/CapabilitiesNavigationPane";
import { useCapabilitiesController } from "./capabilities/useCapabilitiesController";
import "./CapabilitiesView.css";

interface CapabilitiesViewProps {
  runtime: TauriRuntime;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
  seedSurface?: CapabilitySurface | null;
  onConsumeSeedSurface?: () => void;
}

export function CapabilitiesView({
  runtime,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
  onOpenInbox,
  onOpenSettings,
  seedSurface,
  onConsumeSeedSurface,
}: CapabilitiesViewProps) {
  const controller = useCapabilitiesController({ runtime });

  useEffect(() => {
    if (!seedSurface) return;
    if (controller.surface !== seedSurface) {
      controller.openSurface(seedSurface);
    }
    onConsumeSeedSurface?.();
  }, [controller, onConsumeSeedSurface, seedSurface]);

  return (
    <div
      className={`capabilities-workbench ${controller.surface === null ? "is-home" : ""}`}
    >
      <CapabilitiesNavigationPane controller={controller} />

      {controller.surface !== null ? (
        <CapabilitiesDetailPane
          controller={controller}
          getConnectorPolicySummary={getConnectorPolicySummary}
          onOpenPolicyCenter={onOpenPolicyCenter}
          onOpenInbox={onOpenInbox}
          onOpenSettings={onOpenSettings}
        />
      ) : null}

      <CapabilitiesModals controller={controller} />
    </div>
  );
}
