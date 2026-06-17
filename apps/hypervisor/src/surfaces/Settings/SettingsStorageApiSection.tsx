import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsStorageApiSection({
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
            <span className="chat-settings-card-eyebrow">Storage</span>
            <h2>Filesystem and runtime paths</h2>
          </div>
          <span className="chat-settings-pill">Local only</span>
        </div>
        <div className="chat-settings-profile-grid">
          <label className="chat-settings-field">
            <span>Models path</span>
            <input
              value={controlPlane.storage.modelsPath}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  storage: {
                    ...current.storage,
                    modelsPath: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-field">
            <span>Backends path</span>
            <input
              value={controlPlane.storage.backendsPath}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  storage: {
                    ...current.storage,
                    backendsPath: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-field">
            <span>Artifacts path</span>
            <input
              value={controlPlane.storage.artifactsPath}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  storage: {
                    ...current.storage,
                    artifactsPath: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-field">
            <span>Cache path</span>
            <input
              value={controlPlane.storage.cachePath}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  storage: {
                    ...current.storage,
                    cachePath: event.target.value,
                  },
                }))
              }
            />
          </label>
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">API</span>
            <h2>API exposure and compatibility</h2>
          </div>
          <span className="chat-settings-pill">Kernel-backed</span>
        </div>
        <div className="chat-settings-form-grid">
          <label className="chat-settings-field">
            <span>Bind address</span>
            <input
              value={controlPlane.api.bindAddress}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  api: {
                    ...current.api,
                    bindAddress: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-field">
            <span>CORS mode</span>
            <input
              value={controlPlane.api.corsMode}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  api: {
                    ...current.api,
                    corsMode: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-field">
            <span>Auth mode</span>
            <input
              value={controlPlane.api.authMode}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  api: {
                    ...current.api,
                    authMode: event.target.value,
                  },
                }))
              }
            />
          </label>
          <label className="chat-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.api.remoteAccessEnabled}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  api: {
                    ...current.api,
                    remoteAccessEnabled: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Allow remote access</strong>
              <span>Expose runtime services beyond localhost when appropriate.</span>
            </div>
          </label>
        </div>
      </article>
    </div>
  );
}
