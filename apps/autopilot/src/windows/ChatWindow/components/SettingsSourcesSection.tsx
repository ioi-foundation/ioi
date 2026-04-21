import { humanize } from "./capabilities/model";
import type { SettingsViewBodyView } from "./ChatSettingsView.types";

export function SettingsSourcesSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const { controlPlane, updateEngineDraft } = view;
  if (!controlPlane) return null;

  return (
    <div className="studio-settings-stack">
      <article className="studio-settings-card">
        <div className="studio-settings-card-head">
          <div>
            <span className="studio-settings-card-eyebrow">Sources</span>
            <h2>Model and backend galleries</h2>
          </div>
          <span className="studio-settings-pill">
            {controlPlane.galleries.filter((source) => source.enabled).length}{" "}
            enabled
          </span>
        </div>
        <p className="studio-settings-body">
          The gallery catalog and migration sources now live in the Settings
          plane instead of hiding inside a capabilities-only workflow.
        </p>
        <div className="studio-settings-stack studio-settings-stack--compact">
          {controlPlane.galleries.map((source, index) => (
            <article key={source.id} className="studio-settings-subcard">
              <div className="studio-settings-subcard-head">
                <strong>{source.label}</strong>
                <span>{humanize(source.compatibilityTier)}</span>
              </div>
              <div className="studio-settings-chip-row">
                <span className="studio-settings-chip">
                  {humanize(source.kind)}
                </span>
                <span className="studio-settings-chip">
                  {humanize(source.syncStatus)}
                </span>
              </div>
              <div className="studio-settings-profile-grid">
                <label className="studio-settings-field">
                  <span>Source URI</span>
                  <input
                    value={source.uri}
                    onChange={(event) =>
                      updateEngineDraft((current) => ({
                        ...current,
                        galleries: current.galleries.map((entry, entryIndex) =>
                          entryIndex === index
                            ? { ...entry, uri: event.target.value }
                            : entry,
                        ),
                      }))
                    }
                  />
                </label>
                <label className="studio-settings-toggle">
                  <input
                    type="checkbox"
                    checked={source.enabled}
                    onChange={(event) =>
                      updateEngineDraft((current) => ({
                        ...current,
                        galleries: current.galleries.map((entry, entryIndex) =>
                          entryIndex === index
                            ? { ...entry, enabled: event.target.checked }
                            : entry,
                        ),
                      }))
                    }
                  />
                  <div>
                    <strong>Enabled</strong>
                    <span>Include this source in the first-party control plane.</span>
                  </div>
                </label>
                <div className="studio-settings-inline-actions">
                  <button
                    type="button"
                    className="studio-settings-secondary"
                    onClick={() =>
                      updateEngineDraft((current) => ({
                        ...current,
                        galleries: current.galleries.filter(
                          (_entry, entryIndex) => entryIndex !== index,
                        ),
                      }))
                    }
                  >
                    Remove source
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
        <div className="studio-settings-actions">
          <button
            type="button"
            className="studio-settings-secondary"
            onClick={() =>
              updateEngineDraft((current) => ({
                ...current,
                galleries: [
                  ...current.galleries,
                  {
                    id: `custom.gallery.${current.galleries.length + 1}`,
                    kind: "model",
                    label: "Custom gallery",
                    uri: "",
                    enabled: true,
                    syncStatus: "planned",
                    compatibilityTier: "native",
                  },
                ],
              }))
            }
          >
            Add gallery source
          </button>
        </div>
      </article>
    </div>
  );
}
