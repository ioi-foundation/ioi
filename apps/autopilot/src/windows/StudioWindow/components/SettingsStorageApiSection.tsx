import type { SettingsViewBodyView } from "./SettingsView.types";

export function SettingsStorageApiSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const { controlPlane, engineSnapshot, updateEngineDraft } = view;
  if (!controlPlane) return null;

  return (
    <div className="studio-settings-stack">
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Storage</span>
            <h2>Filesystem and runtime paths</h2>
          </div>
          <span className="studio-settings-pill">Local only</span>
        </div>
        <div className="studio-settings-profile-grid">
          <label className="studio-settings-field">
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
          <label className="studio-settings-field">
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
          <label className="studio-settings-field">
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
          <label className="studio-settings-field">
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

      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">API</span>
            <h2>API exposure and compatibility</h2>
          </div>
          <span className="studio-settings-pill">Kernel-backed</span>
        </div>
        <div className="studio-settings-form-grid">
          <label className="studio-settings-field">
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
          <label className="studio-settings-field">
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
          <label className="studio-settings-field">
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
          <label className="studio-settings-toggle">
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
          <label className="studio-settings-toggle">
            <input
              type="checkbox"
              checked={controlPlane.api.exposeCompatRoutes}
              onChange={(event) =>
                updateEngineDraft((current) => ({
                  ...current,
                  api: {
                    ...current.api,
                    exposeCompatRoutes: event.target.checked,
                  },
                }))
              }
            />
            <div>
              <strong>Expose compatibility routes</strong>
              <span>Keep OpenAI, Anthropic, and speech facades operator-controlled.</span>
            </div>
          </label>
        </div>
      </article>

      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Facades</span>
            <h2>Compatibility routes</h2>
          </div>
          <span className="studio-settings-pill">
            {engineSnapshot?.compatibilityRoutes.filter((route) => route.enabled)
              .length ?? 0}{" "}
            live
          </span>
        </div>
        <div className="studio-settings-stack studio-settings-stack--compact">
          {(engineSnapshot?.compatibilityRoutes ?? []).map((route) => (
            <article
              key={route.id}
              className={`studio-settings-subcard ${
                route.enabled ? "is-live" : "is-muted"
              }`}
            >
              <div className="studio-settings-subcard-head">
                <strong>{route.label}</strong>
                <span>{route.enabled ? "Live" : "Hidden"}</span>
              </div>
              <p>{route.path}</p>
              <small>{route.url}</small>
            </article>
          ))}
        </div>
      </article>
    </div>
  );
}
