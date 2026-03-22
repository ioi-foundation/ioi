import type { ConnectorSummary } from "@ioi/agent-ide";
import { type TauriRuntime } from "../../../services/TauriRuntime";
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
}

export function CapabilitiesView({
  runtime,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
}: CapabilitiesViewProps) {
  const controller = useCapabilitiesController({ runtime });

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
        />
      ) : null}

      <CapabilitiesModals controller={controller} />
    </div>
  );
}
