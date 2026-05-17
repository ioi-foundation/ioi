import type { SettingsViewBodyView } from "./settingsViewTypes";
import { summarizeSettingsAuthorityPosture } from "./settingsAuthorityPosture";

export function SettingsEnvironmentSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    controlPlane,
    updateEngineDraft,
    onOpenPolicySurface,
    onOpenConnections,
  } = view;
  if (!controlPlane) return null;
  const authorityPosture = summarizeSettingsAuthorityPosture(
    controlPlane.environment,
  );
  const posturePillClass =
    authorityPosture.tone === "warning"
      ? "chat-settings-pill chat-settings-pill-warning"
      : "chat-settings-pill";

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">
              Compatibility bindings
            </span>
            <h2>Legacy environment credentials</h2>
          </div>
          <span className={posturePillClass}>{authorityPosture.label}</span>
        </div>
        <p className="chat-settings-body">{authorityPosture.detail}</p>
        <div className="chat-settings-callout">
          <strong>Source of truth</strong>
          <p>
            Runtime grants, policy posture, receipts, and workflow readiness are
            governed by Authority Center. This editor only preserves local
            environment compatibility bindings.
          </p>
        </div>
        <div className="chat-settings-summary-grid">
          {authorityPosture.checklist.map((item) => (
            <article key={item} className="chat-settings-subcard">
              <strong>{item.split(" ").slice(1).join(" ")}</strong>
              <span>{item.split(" ")[0]}</span>
            </article>
          ))}
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={onOpenPolicySurface}
          >
            Open Authority Center
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={onOpenConnections}
          >
            Open connections
          </button>
        </div>
      </article>
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Environment</span>
            <h2>Advanced compatibility bindings</h2>
          </div>
          <span className="chat-settings-pill">
            {controlPlane.environment.length} bindings
          </span>
        </div>
        <p className="chat-settings-body">
          Long-lived provider keys and connector credentials should resolve to
          vault or wallet refs. Raw values remain available only as a local
          compatibility path while the Authority Center is the primary posture.
        </p>
        <div className="chat-settings-stack chat-settings-stack--compact">
          {controlPlane.environment.map((binding, index) => (
            <div
              key={`${binding.key}-${index}`}
              className="chat-settings-binding-row"
            >
              <input
                value={binding.key}
                onChange={(event) =>
                  updateEngineDraft((current) => ({
                    ...current,
                    environment: current.environment.map((entry, entryIndex) =>
                      entryIndex === index
                        ? { ...entry, key: event.target.value }
                        : entry,
                    ),
                  }))
                }
                placeholder="ENV_KEY"
              />
              <input
                value={binding.value}
                onChange={(event) =>
                  updateEngineDraft((current) => ({
                    ...current,
                    environment: current.environment.map((entry, entryIndex) =>
                      entryIndex === index
                        ? { ...entry, value: event.target.value }
                        : entry,
                    ),
                  }))
                }
                placeholder="value"
              />
              <label className="chat-settings-binding-secret">
                <input
                  type="checkbox"
                  checked={binding.secret}
                  onChange={(event) =>
                    updateEngineDraft((current) => ({
                      ...current,
                      environment: current.environment.map(
                        (entry, entryIndex) =>
                          entryIndex === index
                            ? { ...entry, secret: event.target.checked }
                            : entry,
                      ),
                    }))
                  }
                />
                <span>Secret</span>
              </label>
              <button
                type="button"
                className="chat-settings-secondary"
                onClick={() =>
                  updateEngineDraft((current) => ({
                    ...current,
                    environment: current.environment.filter(
                      (_entry, entryIndex) => entryIndex !== index,
                    ),
                  }))
                }
              >
                Remove
              </button>
            </div>
          ))}
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={() =>
              updateEngineDraft((current) => ({
                ...current,
                environment: [
                  ...current.environment,
                  { key: "", value: "", secret: false },
                ],
              }))
            }
          >
            Add binding
          </button>
        </div>
      </article>
    </div>
  );
}
