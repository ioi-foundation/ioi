import { RESET_COPY, formatSettingsTime } from "./SettingsView.shared";
import type { SettingsViewBodyView } from "./SettingsView.types";

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
    handleReset,
    diagnostics,
    engineSnapshot,
  } = view;

  if (selectedSection === "local_data") {
    return (
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">State</span>
            <h2>Local data footprint</h2>
          </div>
          <span className="studio-settings-pill">Local only</span>
        </div>

        <p className="studio-settings-body">
          This shell keeps conversation history, policy state, runtime
          settings, and browser-side app storage locally so experiments remain
          isolated to this workspace.
        </p>

        <ul className="studio-settings-list">
          {RESET_COPY.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>

        <div className="studio-settings-callout">
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
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Repair</span>
            <h2>Reset Autopilot data</h2>
          </div>
          <span className="studio-settings-pill studio-settings-pill-warning">
            Local only
          </span>
        </div>

        <p className="studio-settings-body">
          Use this when conversation history, cached context, or connector
          state is leaking between builds. The reset preserves identity so
          remote session history can still rehydrate.
        </p>

        <div className="studio-settings-callout">
          <strong>Remote history caveat</strong>
          <p>
            Session history merged from the kernel can still reappear after
            reload because this action only wipes local app data.
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
            {isResetting ? "Resetting..." : "Reset Autopilot data"}
          </button>
        </div>
      </article>
    );
  }

  if (selectedSection !== "diagnostics") {
    return null;
  }

  return (
    <div className="studio-settings-stack">
      <div className="studio-settings-diagnostics">
        {diagnostics.map((item) => (
          <article
            key={item.label}
            className={`studio-settings-status-card tone-${item.tone}`}
          >
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </article>
        ))}
      </div>

      {engineSnapshot ? (
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Runtime summary</span>
              <h2>Control-plane snapshot</h2>
            </div>
            <span className="studio-settings-pill">
              {formatSettingsTime(engineSnapshot.generatedAtMs)}
            </span>
          </div>
          <div className="studio-settings-summary-grid">
            <article className="studio-settings-subcard">
              <strong>Capability families</strong>
              <span>{engineSnapshot.capabilities.length}</span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Compatibility routes</strong>
              <span>{engineSnapshot.compatibilityRoutes.length}</span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Live jobs</strong>
              <span>{engineSnapshot.jobs.length}</span>
            </article>
            <article className="studio-settings-subcard">
              <strong>Recent receipts</strong>
              <span>{engineSnapshot.recentActivity.length}</span>
            </article>
          </div>
        </article>
      ) : null}
    </div>
  );
}
