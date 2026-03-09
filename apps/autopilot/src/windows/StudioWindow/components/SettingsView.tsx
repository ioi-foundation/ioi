import { useMemo, useState } from "react";
import type { ResetAutopilotDataResult } from "../../../types";

interface SettingsViewProps {
  runtime: {
    resetAutopilotData: () => Promise<ResetAutopilotDataResult>;
  };
}

const RESET_COPY = [
  "Local conversation history, events, and artifacts in `studio.scs`.",
  "Connector subscription registry and Shield policy state.",
  "Spotlight validation artifacts and browser-side local storage for the app origin.",
];

export function SettingsView({ runtime }: SettingsViewProps) {
  const [isResetting, setIsResetting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<ResetAutopilotDataResult | null>(null);

  const summary = useMemo(() => {
    if (!lastResult) return null;
    return `${lastResult.removedPaths.length} local targets reset at ${lastResult.dataDir}.`;
  }, [lastResult]);

  const handleReset = async () => {
    const confirmed = window.confirm(
      "Reset Autopilot local data?\n\nThis clears local history, Atlas state, connector policy, and browser-side app storage. Identity is preserved, so remote session history may still rehydrate.",
    );
    if (!confirmed) return;

    setIsResetting(true);
    setError(null);

    try {
      const result = await runtime.resetAutopilotData();
      setLastResult(result);
    } catch (nextError) {
      setError(String(nextError));
      setIsResetting(false);
    }
  };

  return (
    <div className="studio-settings-view">
      <header className="studio-settings-header">
        <div>
          <span className="studio-settings-kicker">Developer</span>
          <h1>Settings</h1>
          <p>
            Reset local Autopilot state when builds or UI experiments are carrying context across
            runs.
          </p>
        </div>
      </header>

      <section className="studio-settings-grid">
        <article className="studio-settings-card">
          <div className="studio-settings-card-head">
            <div>
              <span className="studio-settings-card-eyebrow">Reset</span>
              <h2>Reset Autopilot Data</h2>
            </div>
            <span className="studio-settings-pill studio-settings-pill-warning">Local only</span>
          </div>

          <p className="studio-settings-body">
            Use this when conversation history, Atlas context, or connector state is leaking
            between builds. The reset preserves the local identity file so authenticated flows still
            work after reload.
          </p>

          <ul className="studio-settings-list">
            {RESET_COPY.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>

          <div className="studio-settings-callout">
            <strong>Remote history caveat</strong>
            <p>
              Session history merged from the kernel can still reappear after reload because this
              action preserves identity and only wipes local app data.
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
      </section>
    </div>
  );
}
