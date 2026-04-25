import { humanize } from "../Capabilities/components/model";
import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsSourcesSection({
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
            <span className="chat-settings-card-eyebrow">Sources</span>
            <h2>Model and backend galleries</h2>
          </div>
          <span className="chat-settings-pill">
            {controlPlane.galleries.filter((source) => source.enabled).length}{" "}
            enabled
          </span>
        </div>
        <p className="chat-settings-body">
          The gallery catalog and migration sources now live in the Settings
          plane instead of hiding inside a capabilities-only workflow.
        </p>
        <div className="chat-settings-stack chat-settings-stack--compact">
          {controlPlane.galleries.map((source, index) => (
            <article key={source.id} className="chat-settings-subcard">
              <div className="chat-settings-subcard-head">
                <strong>{source.label}</strong>
                <span>{humanize(source.compatibilityTier)}</span>
              </div>
              <div className="chat-settings-chip-row">
                <span className="chat-settings-chip">
                  {humanize(source.kind)}
                </span>
                <span className="chat-settings-chip">
                  {humanize(source.syncStatus)}
                </span>
              </div>
              <div className="chat-settings-profile-grid">
                <label className="chat-settings-field">
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
                <label className="chat-settings-toggle">
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
                <div className="chat-settings-inline-actions">
                  <button
                    type="button"
                    className="chat-settings-secondary"
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
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
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
