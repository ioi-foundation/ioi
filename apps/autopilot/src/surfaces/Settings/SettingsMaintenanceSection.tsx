import { RESET_COPY, formatSettingsTime } from "./settingsViewShared";
import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsMaintenanceSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    selectedSection,
    summary,
    error,
    isResetting,
    resetConfirmOpen,
    setResetConfirmOpen,
    handleReset,
    diagnostics,
    engineSnapshot,
  } = view;

  if (selectedSection === "local_data") {
    return (
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">State</span>
            <h2>Local data footprint</h2>
          </div>
          <span className="chat-settings-pill">Local only</span>
        </div>

        <p className="chat-settings-body">
          This shell keeps conversation history, policy state, runtime
          settings, and browser-side app storage locally so experiments remain
          isolated to this workspace.
        </p>

        <ul className="chat-settings-list">
          {RESET_COPY.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>

        <div className="chat-settings-callout">
          <strong>Identity survives reset</strong>
          <p>
            The local identity file is preserved so authenticated flows can
            rehydrate after reload even when app state is cleared.
          </p>
        </div>
      </article>
    );
  }

  if (selectedSection === "repair_reset") {
    return (
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Repair</span>
            <h2>Reset Autopilot data</h2>
          </div>
          <span className="chat-settings-pill chat-settings-pill-warning">
            Local only
          </span>
        </div>

        <p className="chat-settings-body">
          Use this when conversation history, cached context, or connector
          state is leaking between builds. The reset preserves identity so
          remote session history can still rehydrate.
        </p>

        <div className="chat-settings-callout">
          <strong>Remote history caveat</strong>
          <p>
            Session history merged from the kernel can still reappear after
            reload because this action only wipes local app data.
          </p>
        </div>

        {summary ? <p className="chat-settings-success">{summary}</p> : null}
        {error ? <p className="chat-settings-error">{error}</p> : null}

        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-danger"
            disabled={isResetting}
            onClick={() => {
              setResetConfirmOpen(true);
            }}
          >
            {isResetting ? "Resetting..." : "Reset Autopilot data"}
          </button>
        </div>

        {resetConfirmOpen ? (
          <div className="chat-settings-callout">
            <strong>Confirm local reset</strong>
            <p>
              This clears local history, cached context state, connector
              policy, and browser-side app storage. Identity is preserved, so
              remote session history may still rehydrate after reload.
            </p>
            <div className="chat-settings-actions">
              <button
                type="button"
                className="chat-settings-danger"
                disabled={isResetting}
                onClick={() => {
                  void handleReset();
                }}
              >
                {isResetting ? "Resetting..." : "Confirm reset"}
              </button>
              <button
                type="button"
                className="chat-settings-secondary"
                disabled={isResetting}
                onClick={() => {
                  setResetConfirmOpen(false);
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        ) : null}
      </article>
    );
  }

  if (selectedSection !== "diagnostics") {
    return null;
  }

  const latestConfigMigration =
    engineSnapshot?.controlPlaneMigrations
      .slice()
      .sort((left, right) => right.appliedAtMs - left.appliedAtMs)[0] ?? null;

  return (
    <div className="chat-settings-stack">
      <div className="chat-settings-diagnostics">
        {diagnostics.map((item) => (
          <article
            key={item.label}
            className={`chat-settings-status-card tone-${item.tone}`}
          >
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </article>
        ))}
      </div>

      {engineSnapshot ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Runtime summary</span>
              <h2>Control-plane snapshot</h2>
            </div>
            <span className="chat-settings-pill">
              {formatSettingsTime(engineSnapshot.generatedAtMs)}
            </span>
          </div>
          <div className="chat-settings-summary-grid">
            <article className="chat-settings-subcard">
              <strong>Capability families</strong>
              <span>{engineSnapshot.capabilities.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Live jobs</strong>
              <span>{engineSnapshot.jobs.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Recent receipts</strong>
              <span>{engineSnapshot.recentActivity.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Config profile</strong>
              <span>{engineSnapshot.controlPlaneProfileId}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Config schema</strong>
              <span>v{engineSnapshot.controlPlaneSchemaVersion}</span>
            </article>
          </div>

          <div className="chat-settings-callout">
            <strong>
              {engineSnapshot.controlPlaneMigrations.length > 0
                ? "Migration history retained"
                : "Native config profile"}
            </strong>
            <p>
              Profile <strong>{engineSnapshot.controlPlaneProfileId}</strong>{" "}
              is currently persisted as schema v
              {engineSnapshot.controlPlaneSchemaVersion}.
              {latestConfigMigration
                ? ` Latest upgrade: ${latestConfigMigration.summary} (${formatSettingsTime(
                    latestConfigMigration.appliedAtMs,
                  )}).`
                : " No legacy upgrades were needed for the current document."}
            </p>
            {latestConfigMigration?.details.length ? (
              <ul className="chat-settings-list">
                {latestConfigMigration.details.map((detail) => (
                  <li key={detail}>{detail}</li>
                ))}
              </ul>
            ) : null}
          </div>
        </article>
      ) : null}
    </div>
  );
}
