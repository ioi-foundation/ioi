import { humanize } from "../Capabilities/components/model";
import { formatSettingsTime } from "./settingsViewShared";
import type { SettingsViewBodyView } from "./settingsViewTypes";

export function SettingsSkillSourcesSection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    runtime,
    skillSources,
    skillSourcesLoading,
    skillSourcesBusy,
    skillSourcesError,
    skillSourcesMessage,
    skillSourceLabel,
    setSkillSourceLabel,
    skillSourceUri,
    setSkillSourceUri,
    setSelectedSkillSourceId,
    selectedSkillSource,
    runSkillSourceAction,
  } = view;

  return (
    <div className="chat-settings-stack">
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Skill sources</span>
            <h2>Source registry and sync</h2>
          </div>
          <span className="chat-settings-pill">{skillSources.length} sources</span>
        </div>
        <p className="chat-settings-body">
          Point the shell at local skill roots or checked-out repositories.
          Autopilot syncs `SKILL.md` manifests into a first-party source
          registry so runtime skills can carry provenance instead of just
          unlabeled local-versus-synced origin hints.
        </p>
        {skillSourcesMessage ? (
          <p className="chat-settings-success">{skillSourcesMessage}</p>
        ) : null}
        {skillSourcesError ? (
          <p className="chat-settings-error">{skillSourcesError}</p>
        ) : null}
        <div className="chat-settings-profile-grid">
          <label className="chat-settings-field">
            <span>Source label</span>
            <input
              value={skillSourceLabel}
              onChange={(event) => setSkillSourceLabel(event.target.value)}
              placeholder="Workspace skills"
            />
          </label>
          <label className="chat-settings-field chat-settings-field--wide">
            <span>Directory or checked-out repo path</span>
            <input
              value={skillSourceUri}
              onChange={(event) => setSkillSourceUri(event.target.value)}
              placeholder="/abs/path/to/skills-or-repo"
            />
          </label>
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            disabled={skillSourcesBusy || skillSourceUri.trim().length === 0}
            onClick={() =>
              void runSkillSourceAction(async () => {
                const created = await runtime.addSkillSource(
                  skillSourceUri,
                  skillSourceLabel || null,
                );
                setSelectedSkillSourceId(created.sourceId);
                setSkillSourceLabel("");
                setSkillSourceUri("");
              }, "Skill source added and synced.")
            }
          >
            {skillSourcesBusy ? "Working..." : "Add skill source"}
          </button>
        </div>
      </article>

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Registered sources</span>
            <h2>Provenance roots</h2>
          </div>
          <span className="chat-settings-pill">
            {skillSourcesLoading ? "Loading" : `${skillSources.length} tracked`}
          </span>
        </div>
        {skillSourcesLoading ? (
          <p className="chat-settings-body">Loading skill sources...</p>
        ) : skillSources.length === 0 ? (
          <p className="chat-settings-body">
            No skill sources are registered yet.
          </p>
        ) : (
          <div className="chat-settings-summary-grid">
            {skillSources.map((source) => (
              <button
                key={source.sourceId}
                type="button"
                className={`chat-settings-subcard ${
                  selectedSkillSource?.sourceId === source.sourceId
                    ? "is-live"
                    : ""
                }`}
                onClick={() => setSelectedSkillSourceId(source.sourceId)}
              >
                <strong>{source.label}</strong>
                <span>{humanize(source.syncStatus)}</span>
                <small>{source.discoveredSkills.length} skills</small>
                <p>{source.uri}</p>
              </button>
            ))}
          </div>
        )}
      </article>

      {selectedSkillSource ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Selected source</span>
              <h2>{selectedSkillSource.label}</h2>
            </div>
            <span className="chat-settings-pill">
              {humanize(selectedSkillSource.kind)}
            </span>
          </div>
          <div className="chat-settings-summary-grid">
            <article className="chat-settings-subcard">
              <strong>Status</strong>
              <span>{humanize(selectedSkillSource.syncStatus)}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Discovered skills</strong>
              <span>{selectedSkillSource.discoveredSkills.length}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Enabled</strong>
              <span>{selectedSkillSource.enabled ? "Yes" : "No"}</span>
            </article>
            <article className="chat-settings-subcard">
              <strong>Last sync</strong>
              <span>
                {selectedSkillSource.lastSyncedAtMs
                  ? formatSettingsTime(selectedSkillSource.lastSyncedAtMs)
                  : "Never"}
              </span>
            </article>
          </div>
          <p className="chat-settings-body">
            Path: <code>{selectedSkillSource.uri}</code>
          </p>
          {selectedSkillSource.lastError ? (
            <div className="chat-settings-callout">
              <strong>Last sync error</strong>
              <p>{selectedSkillSource.lastError}</p>
            </div>
          ) : null}
          <div className="chat-settings-actions">
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={skillSourcesBusy}
              onClick={() =>
                void runSkillSourceAction(
                  async () => {
                    await runtime.syncSkillSource(selectedSkillSource.sourceId);
                  },
                  "Skill source synced.",
                )
              }
            >
              Sync source
            </button>
            <button
              type="button"
              className="chat-settings-secondary"
              disabled={skillSourcesBusy}
              onClick={() =>
                void runSkillSourceAction(
                  async () => {
                    await runtime.setSkillSourceEnabled(
                      selectedSkillSource.sourceId,
                      !selectedSkillSource.enabled,
                    );
                  },
                  selectedSkillSource.enabled
                    ? "Skill source disabled."
                    : "Skill source enabled.",
                )
              }
            >
              {selectedSkillSource.enabled ? "Disable source" : "Enable source"}
            </button>
            <button
              type="button"
              className="chat-settings-danger"
              disabled={skillSourcesBusy}
              onClick={() =>
                void runSkillSourceAction(async () => {
                  await runtime.removeSkillSource(selectedSkillSource.sourceId);
                  setSelectedSkillSourceId(null);
                }, "Skill source removed.")
              }
            >
              Remove source
            </button>
          </div>
        </article>
      ) : null}

      {selectedSkillSource ? (
        <article className="chat-settings-card">
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Discovered skills</span>
              <h2>Indexed manifests</h2>
            </div>
            <span className="chat-settings-pill">
              {selectedSkillSource.discoveredSkills.length} found
            </span>
          </div>
          <div className="chat-settings-stack chat-settings-stack--compact">
            {selectedSkillSource.discoveredSkills.length === 0 ? (
              <p className="chat-settings-body">
                No `SKILL.md` files were discovered under this root yet.
              </p>
            ) : (
              selectedSkillSource.discoveredSkills.map((skill) => (
                <article
                  key={`${selectedSkillSource.sourceId}:${skill.relativePath}`}
                  className="chat-settings-subcard"
                >
                  <div className="chat-settings-subcard-head">
                    <strong>{skill.name}</strong>
                    <span>{skill.relativePath}</span>
                  </div>
                  {skill.description ? <p>{skill.description}</p> : null}
                </article>
              ))
            )}
          </div>
        </article>
      ) : null}
    </div>
  );
}
