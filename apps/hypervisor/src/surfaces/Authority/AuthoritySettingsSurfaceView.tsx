import { SettingsView } from "../Settings";
import { PolicyView } from "../Policy";
import { HypervisorClientRuntime } from "../../services/HypervisorClientRuntime";
import type { WorkflowComposerPreflightSeed } from "@ioi/hypervisor-workbench";
import type {
  CapabilityGovernanceRequest,
  ShieldPolicyState,
} from "../Policy/policyCenter";
import type { SettingsSection } from "../Settings/settingsViewShared";

interface AuthoritySettingsSurfaceViewProps {
  runtime: HypervisorClientRuntime;
  surface: "policy" | "system";
  policyState: ShieldPolicyState;
  governanceRequest?: CapabilityGovernanceRequest | null;
  focusedConnectorId?: string | null;
  settingsSeedSection?: SettingsSection | null;
  onSurfaceChange: (surface: "policy" | "system") => void;
  onConsumeSettingsSeedSection?: () => void;
  onPolicyChange: (next: ShieldPolicyState) => void;
  onFocusConnector: (connectorId: string | null) => void;
  onApplyGovernanceRequest?: (next: ShieldPolicyState) => void;
  onDismissGovernanceRequest?: () => void;
  onOpenConnections: () => void;
  onOpenModelRoutes?: () => void;
  onOpenWorkflowPreflight?: (seed?: WorkflowComposerPreflightSeed) => void;
}

export function AuthoritySettingsSurfaceView({
  runtime,
  surface,
  policyState,
  governanceRequest,
  focusedConnectorId,
  settingsSeedSection,
  onSurfaceChange,
  onConsumeSettingsSeedSection,
  onPolicyChange,
  onFocusConnector,
  onApplyGovernanceRequest,
  onDismissGovernanceRequest,
  onOpenConnections,
  onOpenModelRoutes,
  onOpenWorkflowPreflight,
}: AuthoritySettingsSurfaceViewProps) {
  const title = surface === "policy" ? "Authority Center" : "System Settings";
  const kicker = surface === "policy" ? "Govern" : "Configure";
  const surfaceLabel =
    surface === "policy" ? "Policy and grants" : "Control plane";

  return (
    <div className="hypervisor-surface-view hypervisor-surface-view--control">
      <header className="hypervisor-surface-header hypervisor-surface-header--control">
        <div className="hypervisor-surface-header-copy hypervisor-surface-header-copy--control">
          <span className="hypervisor-surface-kicker">{kicker}</span>
          <div className="hypervisor-governance-title-row">
            <h2>{title}</h2>
            <span className="hypervisor-governance-surface">
              {surfaceLabel}
            </span>
          </div>
        </div>

        <div className="hypervisor-surface-header-actions">
          <div
            className="hypervisor-surface-tabs"
            role="tablist"
            aria-label="Governance surfaces"
          >
            <button
              type="button"
              className={surface === "policy" ? "is-active" : ""}
              onClick={() => onSurfaceChange("policy")}
            >
              Authority
            </button>
            <button
              type="button"
              className={surface === "system" ? "is-active" : ""}
              onClick={() => onSurfaceChange("system")}
            >
              Settings
            </button>
          </div>
        </div>
      </header>

      <div className="hypervisor-surface-stage hypervisor-surface-stage--control">
        <div className="hypervisor-surface-stage-frame hypervisor-surface-stage-frame--control">
          {surface === "policy" ? (
            <PolicyView
              runtime={runtime}
              policyState={policyState}
              onChange={onPolicyChange}
              governanceRequest={governanceRequest}
              focusedConnectorId={focusedConnectorId}
              onFocusConnector={onFocusConnector}
              onApplyGovernanceRequest={onApplyGovernanceRequest}
              onDismissGovernanceRequest={onDismissGovernanceRequest}
              onOpenIntegrations={onOpenConnections}
              onOpenModelRoutes={onOpenModelRoutes}
              onOpenWorkflowPreflight={onOpenWorkflowPreflight}
            />
          ) : (
            <SettingsView
              seedSection={settingsSeedSection}
              onConsumeSeedSection={onConsumeSettingsSeedSection}
            />
          )}
        </div>
      </div>
    </div>
  );
}
