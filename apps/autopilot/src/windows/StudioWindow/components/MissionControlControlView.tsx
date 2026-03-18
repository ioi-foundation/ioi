import { SettingsView } from "./SettingsView";
import { ShieldPolicyView } from "./ShieldPolicyView";
import { TauriRuntime } from "../../../services/TauriRuntime";
import type { AssistantUserProfile } from "../../../types";
import type { ShieldPolicyState } from "../policyCenter";

interface MissionControlControlViewProps {
  runtime: TauriRuntime;
  surface: "policy" | "system";
  policyState: ShieldPolicyState;
  profile: AssistantUserProfile;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  focusedConnectorId?: string | null;
  onSurfaceChange: (surface: "policy" | "system") => void;
  onPolicyChange: (next: ShieldPolicyState) => void;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
  onFocusConnector: (connectorId: string | null) => void;
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
  focusedConnectorId,
  onSurfaceChange,
  onPolicyChange,
  onProfileDraftChange,
  onResetProfileDraft,
  onSaveProfile,
  onFocusConnector,
  onOpenConnections,
}: MissionControlControlViewProps) {
  return (
    <div className="mission-control-view mission-control-view--control">
      <header className="mission-control-header mission-control-header--control">
        <div className="mission-control-header-copy mission-control-header-copy--control">
          <span className="mission-control-kicker">Govern</span>
          <div className="mission-control-control-title-row">
            <h2>Control</h2>
            <span className="mission-control-control-surface">
              {surface === "policy" ? "Policy" : "System"}
            </span>
          </div>
        </div>

        <div className="mission-control-header-actions">
          <div className="mission-control-tabs" role="tablist" aria-label="Control surfaces">
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
              System
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
              focusedConnectorId={focusedConnectorId}
              onFocusConnector={onFocusConnector}
              onOpenIntegrations={onOpenConnections}
            />
          ) : (
            <SettingsView
              runtime={runtime}
              profile={profile}
              profileDraft={profileDraft}
              profileSaving={profileSaving}
              profileError={profileError}
              onProfileDraftChange={onProfileDraftChange}
              onResetProfileDraft={onResetProfileDraft}
              onSaveProfile={onSaveProfile}
            />
          )}
        </div>
      </div>
    </div>
  );
}
