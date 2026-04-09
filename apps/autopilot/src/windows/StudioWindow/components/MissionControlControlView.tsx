import { SettingsView } from "./SettingsView";
import { ShieldPolicyView } from "./ShieldPolicyView";
import { TauriRuntime } from "../../../services/TauriRuntime";
import type { AssistantUserProfile } from "../../../types";
import type {
  CapabilityGovernanceRequest,
  ShieldPolicyState,
} from "../policyCenter";
import type { SettingsSection } from "./SettingsView.shared";

interface MissionControlControlViewProps {
  runtime: TauriRuntime;
  surface: "policy" | "system";
  policyState: ShieldPolicyState;
  profile: AssistantUserProfile;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  governanceRequest?: CapabilityGovernanceRequest | null;
  focusedConnectorId?: string | null;
  settingsSeedSection?: SettingsSection | null;
  onSurfaceChange: (surface: "policy" | "system") => void;
  onConsumeSettingsSeedSection?: () => void;
  onPolicyChange: (next: ShieldPolicyState) => void;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
  onFocusConnector: (connectorId: string | null) => void;
  onApplyGovernanceRequest?: (next: ShieldPolicyState) => void;
  onDismissGovernanceRequest?: () => void;
  onOpenConnections: () => void;
}

export function MissionControlControlView({
  runtime,
  surface,
  policyState,
  profile,
  profileDraft,
  profileSaving,
  profileError,
  governanceRequest,
  focusedConnectorId,
  settingsSeedSection,
  onSurfaceChange,
  onConsumeSettingsSeedSection,
  onPolicyChange,
  onProfileDraftChange,
  onResetProfileDraft,
  onSaveProfile,
  onFocusConnector,
  onApplyGovernanceRequest,
  onDismissGovernanceRequest,
  onOpenConnections,
}: MissionControlControlViewProps) {
  const title = surface === "policy" ? "Policy" : "System Settings";
  const kicker = surface === "policy" ? "Govern" : "Configure";
  const surfaceLabel = surface === "policy" ? "Policy" : "Control plane";

  return (
    <div className="mission-control-view mission-control-view--control">
      <header className="mission-control-header mission-control-header--control">
        <div className="mission-control-header-copy mission-control-header-copy--control">
          <span className="mission-control-kicker">{kicker}</span>
          <div className="mission-control-control-title-row">
            <h2>{title}</h2>
            <span className="mission-control-control-surface">
              {surfaceLabel}
            </span>
          </div>
        </div>

        <div className="mission-control-header-actions">
          <div
            className="mission-control-tabs"
            role="tablist"
            aria-label="Governance surfaces"
          >
            <button
              type="button"
              className={surface === "policy" ? "is-active" : ""}
              onClick={() => onSurfaceChange("policy")}
            >
              Policy
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

      <div className="mission-control-stage mission-control-stage--control">
        <div className="mission-control-stage-frame mission-control-stage-frame--control">
          {surface === "policy" ? (
            <ShieldPolicyView
              runtime={runtime}
              policyState={policyState}
              onChange={onPolicyChange}
              governanceRequest={governanceRequest}
              focusedConnectorId={focusedConnectorId}
              onFocusConnector={onFocusConnector}
              onApplyGovernanceRequest={onApplyGovernanceRequest}
              onDismissGovernanceRequest={onDismissGovernanceRequest}
              onOpenIntegrations={onOpenConnections}
            />
          ) : (
            <SettingsView
              runtime={runtime}
              profile={profile}
              profileDraft={profileDraft}
              profileSaving={profileSaving}
              profileError={profileError}
              policyState={policyState}
              governanceRequest={governanceRequest}
              seedSection={settingsSeedSection}
              onConsumeSeedSection={onConsumeSettingsSeedSection}
              onProfileDraftChange={onProfileDraftChange}
              onResetProfileDraft={onResetProfileDraft}
              onSaveProfile={onSaveProfile}
              onPolicyChange={onPolicyChange}
              onOpenPolicySurface={() => onSurfaceChange("policy")}
              onOpenConnections={onOpenConnections}
            />
          )}
        </div>
      </div>
    </div>
  );
}
