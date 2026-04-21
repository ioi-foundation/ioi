import type { SettingsViewBodyView } from "./ChatSettingsView.types";

export function SettingsIdentitySection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    profileDraft,
    profileSaving,
    profileError,
    onProfileDraftChange,
    onResetProfileDraft,
    onSaveProfile,
    profileDirty,
  } = view;

  return (
    <article className="chat-settings-card">
      <div className="chat-settings-card-head">
        <div>
          <span className="chat-settings-card-eyebrow">Identity</span>
          <h2>Shell identity</h2>
        </div>
        <span className="chat-settings-pill">Local only</span>
      </div>

      <p className="chat-settings-body">
        This local operator profile shapes how the shell names you across
        Autopilot surfaces. It does not replace runtime, policy, or tool
        configuration.
      </p>

      <div className="chat-settings-profile-grid">
        <label className="chat-settings-field">
          <span>Display name</span>
          <input
            value={profileDraft.displayName}
            onChange={(event) =>
              onProfileDraftChange("displayName", event.target.value)
            }
            placeholder="Operator"
          />
        </label>
        <label className="chat-settings-field">
          <span>Preferred name</span>
          <input
            value={profileDraft.preferredName ?? ""}
            onChange={(event) =>
              onProfileDraftChange("preferredName", event.target.value || null)
            }
            placeholder="Optional"
          />
        </label>
        <label className="chat-settings-field">
          <span>Role label</span>
          <input
            value={profileDraft.roleLabel ?? ""}
            onChange={(event) =>
              onProfileDraftChange("roleLabel", event.target.value || null)
            }
            placeholder="Private Operator"
          />
        </label>
        <label className="chat-settings-field">
          <span>Primary email</span>
          <input
            value={profileDraft.primaryEmail ?? ""}
            onChange={(event) =>
              onProfileDraftChange("primaryEmail", event.target.value || null)
            }
            placeholder="Optional"
          />
        </label>
        <label className="chat-settings-field">
          <span>Timezone</span>
          <input
            value={profileDraft.timezone}
            onChange={(event) =>
              onProfileDraftChange("timezone", event.target.value)
            }
            placeholder="America/New_York"
          />
        </label>
        <label className="chat-settings-field">
          <span>Locale</span>
          <input
            value={profileDraft.locale}
            onChange={(event) =>
              onProfileDraftChange("locale", event.target.value)
            }
            placeholder="en-US"
          />
        </label>
      </div>

      {profileError ? (
        <p className="chat-settings-error">{profileError}</p>
      ) : null}

      <div className="chat-settings-actions">
        <button
          type="button"
          className="chat-settings-secondary"
          onClick={onResetProfileDraft}
          disabled={profileSaving || !profileDirty}
        >
          Reset changes
        </button>
        <button
          type="button"
          className="chat-settings-primary"
          onClick={() => {
            void onSaveProfile();
          }}
          disabled={profileSaving || !profileDirty}
        >
          {profileSaving ? "Saving..." : "Save profile"}
        </button>
      </div>
    </article>
  );
}
