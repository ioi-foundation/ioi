import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsEnvironmentSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const { controlPlane, updateEngineDraft } = view;
  if (!controlPlane) return null;

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Environment</span>
            <h2>Runtime bindings</h2>
          </div>
          <span className="chat-settings-pill">
            {controlPlane.environment.length} bindings
          </span>
        </div>
        <p className="chat-settings-body">
          Bindings are now kernel-backed settings documents so the same runtime
          posture can later be applied from the CLI or another shell.
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
                      environment: current.environment.map((entry, entryIndex) =>
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
