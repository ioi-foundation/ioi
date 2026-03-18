import { useMemo, useState } from "react";
import type { AssistantUserProfile, ResetAutopilotDataResult } from "../../../types";

interface SettingsViewProps {
  runtime: {
    resetAutopilotData: () => Promise<ResetAutopilotDataResult>;
  };
  profile: AssistantUserProfile;
  profileDraft: AssistantUserProfile;
  profileSaving: boolean;
  profileError: string | null;
  onProfileDraftChange: <K extends keyof AssistantUserProfile>(
    key: K,
    value: AssistantUserProfile[K],
  ) => void;
  onResetProfileDraft: () => void;
  onSaveProfile: () => Promise<void>;
}

const RESET_COPY = [
  "Local conversation history, events, and artifacts in `studio.scs`.",
  "Connector subscription registry and control policy state.",
  "Spotlight validation artifacts and browser-side local storage for the app origin.",
];

export function SettingsView({
  runtime,
  profile,
  profileDraft,
  profileSaving,
  profileError,
  onProfileDraftChange,
  onResetProfileDraft,
  onSaveProfile,
}: SettingsViewProps) {
  const [selectedSection, setSelectedSection] = useState<
    "identity" | "local_data" | "repair_reset" | "diagnostics"
  >("identity");
  const [isResetting, setIsResetting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ResetAutopilotDataResult | null>(null);
  const profileDirty = JSON.stringify(profileDraft) !== JSON.stringify(profile);

  const summary = useMemo(() => {
    if (!lastResult) return null;
    return `${lastResult.removedPaths.length} local targets reset at ${lastResult.dataDir}.`;
  }, [lastResult]);

  const handleReset = async () => {
    const confirmed = window.confirm(
      "Reset Autopilot local data?\n\nThis clears local history, cached context state, connector policy, and browser-side app storage. Identity is preserved, so remote session history may still rehydrate.",
    );
    if (!confirmed) return;

    setIsResetting(true);
    setError(null);

    try {
      const result = await runtime.resetAutopilotData();
      setLastResult(result);
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setIsResetting(false);
    }
  };

  const diagnostics = [
    {
      label: "Profile draft",
      value: profileDirty ? "Unsaved changes" : "Synced",
      tone: profileDirty ? "warning" : "normal",
    },
    {
      label: "Timezone",
      value: profileDraft.timezone || "Unset",
      tone: "normal",
    },
    {
      label: "Locale",
      value: profileDraft.locale || "Unset",
      tone: "normal",
    },
    {
      label: "Last local reset",
      value: lastResult ? `${lastResult.removedPaths.length} targets removed` : "Not run yet",
      tone: lastResult ? "normal" : "muted",
    },
  ] as const;

  return (
    <div className="studio-settings-view">
      <div className="studio-settings-layout">
        <aside className="studio-settings-sidebar">
          <div className="studio-settings-sidebar-head">
            <strong>System objects</strong>
            <span>Local shell</span>
          </div>

          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "identity" ? "active" : ""}`}
            onClick={() => setSelectedSection("identity")}
          >
            <strong>Identity</strong>
            <span>Display name, locale, and operator metadata.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "local_data" ? "active" : ""}`}
            onClick={() => setSelectedSection("local_data")}
          >
            <strong>Local data</strong>
            <span>What is stored in the shell and what survives resets.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "repair_reset" ? "active" : ""}`}
            onClick={() => setSelectedSection("repair_reset")}
          >
            <strong>Repair / reset</strong>
            <span>Clear local state when builds or policies are carrying context.</span>
          </button>
          <button
            type="button"
            className={`studio-settings-target ${selectedSection === "diagnostics" ? "active" : ""}`}
            onClick={() => setSelectedSection("diagnostics")}
          >
            <strong>Diagnostics</strong>
            <span>Current shell state, profile status, and reset history.</span>
          </button>
        </aside>

        <section className="studio-settings-panel">
          {selectedSection === "identity" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">Identity</span>
                  <h2>Shell Identity</h2>
                </div>
                <span className="studio-settings-pill">Local only</span>
              </div>

              <p className="studio-settings-body">
                This local operator profile shapes how the shell names you across Autopilot
                surfaces. It is not used for grounding or inference.
              </p>

              <div className="studio-settings-profile-grid">
                <label className="studio-settings-field">
                  <span>Display name</span>
                  <input
                    value={profileDraft.displayName}
                    onChange={(event) => onProfileDraftChange("displayName", event.target.value)}
                    placeholder="Operator"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Preferred name</span>
                  <input
                    value={profileDraft.preferredName ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange("preferredName", event.target.value || null)
                    }
                    placeholder="Optional"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Role label</span>
                  <input
                    value={profileDraft.roleLabel ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange("roleLabel", event.target.value || null)
                    }
                    placeholder="Private Operator"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Primary email</span>
                  <input
                    value={profileDraft.primaryEmail ?? ""}
                    onChange={(event) =>
                      onProfileDraftChange("primaryEmail", event.target.value || null)
                    }
                    placeholder="Optional"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Timezone</span>
                  <input
                    value={profileDraft.timezone}
                    onChange={(event) => onProfileDraftChange("timezone", event.target.value)}
                    placeholder="America/New_York"
                  />
                </label>
                <label className="studio-settings-field">
                  <span>Locale</span>
                  <input
                    value={profileDraft.locale}
                    onChange={(event) => onProfileDraftChange("locale", event.target.value)}
                    placeholder="en-US"
                  />
                </label>
              </div>

              {profileError ? <p className="studio-settings-error">{profileError}</p> : null}

              <div className="studio-settings-actions">
                <button
                  type="button"
                  className="studio-settings-secondary"
                  onClick={onResetProfileDraft}
                  disabled={profileSaving || !profileDirty}
                >
                  Reset changes
                </button>
                <button
                  type="button"
                  className="studio-settings-primary"
                  onClick={() => {
                    void onSaveProfile();
                  }}
                  disabled={profileSaving || !profileDirty}
                >
                  {profileSaving ? "Saving..." : "Save profile"}
                </button>
              </div>
            </article>
          ) : null}

          {selectedSection === "local_data" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">State</span>
                  <h2>Local data footprint</h2>
                </div>
                <span className="studio-settings-pill">Local only</span>
              </div>

              <p className="studio-settings-body">
                This shell keeps conversation history, policy state, and browser-side app storage
                locally so experiments remain isolated to this workspace.
              </p>

              <ul className="studio-settings-list">
                {RESET_COPY.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>

              <div className="studio-settings-callout">
                <strong>Identity survives reset</strong>
                <p>
                  The local identity file is preserved so authenticated flows can rehydrate after
                  reload even when app state is cleared.
                </p>
              </div>
            </article>
          ) : null}

          {selectedSection === "repair_reset" ? (
            <article className="studio-settings-card">
              <div className="studio-settings-card-head">
                <div>
                  <span className="studio-settings-card-eyebrow">Repair</span>
                  <h2>Reset Autopilot Data</h2>
                </div>
                <span className="studio-settings-pill studio-settings-pill-warning">Local only</span>
              </div>

              <p className="studio-settings-body">
                Use this when conversation history, cached context, or connector state is leaking
                between builds. The reset preserves identity so remote session history can still
                rehydrate.
              </p>

              <div className="studio-settings-callout">
                <strong>Remote history caveat</strong>
                <p>
                  Session history merged from the kernel can still reappear after reload because this
                  action only wipes local app data.
                </p>
              </div>

              {summary ? <p className="studio-settings-success">{summary}</p> : null}
              {error ? <p className="studio-settings-error">{error}</p> : null}

              <div className="studio-settings-actions">
                <button
                  type="button"
                  className="studio-settings-danger"
                  disabled={isResetting}
                  onClick={() => {
                    void handleReset();
                  }}
                >
                  {isResetting ? "Resetting..." : "Reset Autopilot Data"}
                </button>
              </div>
            </article>
          ) : null}

          {selectedSection === "diagnostics" ? (
            <div className="studio-settings-diagnostics">
              {diagnostics.map((item) => (
                <article key={item.label} className={`studio-settings-status-card tone-${item.tone}`}>
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}
