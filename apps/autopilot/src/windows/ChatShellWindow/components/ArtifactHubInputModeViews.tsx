import {
  openReviewCapabilities,
  openReviewSettings,
} from "../../../services/reviewNavigation";
import type { ArtifactHubViewKey } from "../../../types";
import type { ChatKeybindingSnapshot } from "../hooks/useChatKeybindings";
import type { ChatVimModeSnapshot } from "../hooks/useChatVimMode";

export function KeybindingsView({
  snapshot,
}: {
  snapshot: ChatKeybindingSnapshot;
}) {
  const groupedRecords = snapshot.records.reduce<
    Record<string, typeof snapshot.records>
  >((acc, record) => {
    if (!acc[record.scope]) {
      acc[record.scope] = [];
    }
    acc[record.scope].push(record);
    return acc;
  }, {});

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Keybindings</span>
        <strong>Current shell shortcuts</strong>
        <p>
          Review the active keyboard shortcuts across Chat and the global
          launcher surface.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Platform: {snapshot.platformLabel}</span>
          <span>{snapshot.records.length} shortcuts</span>
          <span>Source: live shell defaults</span>
        </div>
      </section>

      {Object.entries(groupedRecords).map(([scope, records]) => (
        <section className="artifact-hub-task-section" key={scope}>
          <div className="artifact-hub-task-section-head">
            <span>{scope}</span>
            <span>{records.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {records.map((record) => (
              <article className="artifact-hub-generic-row" key={record.id}>
                <div className="artifact-hub-generic-meta">
                  <span>{record.source}</span>
                  <span>Current: {record.binding}</span>
                  <span>Default: {record.defaultBinding}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {record.command}
                </div>
                <p className="artifact-hub-generic-summary">{record.summary}</p>
              </article>
            ))}
          </div>
        </section>
      ))}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Shortcut management</strong>
          <span className="artifact-hub-policy-pill">Current defaults</span>
        </div>
        <p>
          This slice now reflects one shared shortcut registry across Chat,
          Chat, and the launcher surface. User-editable keymap overrides have
          not been productized yet.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openReviewSettings()}
          >
            Open Chat Settings
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewCapabilities()}
          >
            Open Chat
          </button>
        </div>
      </section>
    </div>
  );
}

export function VimModeView({
  snapshot,
  onOpenView,
  onToggleVimMode,
}: {
  snapshot: ChatVimModeSnapshot;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  onToggleVimMode?: () => void;
}) {
  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Vim Mode</span>
        <strong>Editor input posture</strong>
        <p>
          Review whether Chat is following its standard shell input stack or a
          vim-style shell posture with the current supported normal-mode command
          set: `h`, `j`, `k`, `l`, `0`, `^`, `$`, `gg`, `G`, absolute-line jumps
          like `2gg` and `2G`, `w`, `b`, `e`, count prefixes like `2w`, `3x`,
          `2dw`, and `2dd`, `x`, `dw`, `de`, `db`, `d0`, `d^`, `dgg`, `dG`,
          `cw`, `ce`, `cb`, `c0`, `c^`, `cgg`, `cG`, `diw`, `daw`, `ciw`, `caw`,
          `di"`, `da"`, `ci"`, `ca"`, `di'`, `da'`, `ci'`, `ca'`, `di(`, `da(`,
          `ci(`, `ca(`, `di[`, `da[`, `ci[`, `ca[`, `di&#123;`, `da&#123;`,
          `ci&#123;`, `ca&#123;`, `D`, `C`, `dd`, `cc`, `o`, `O`, `.`, `i`, `a`,
          `I`, `A`, and `Esc`.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Status: {snapshot.statusLabel}</span>
          <span>Scope: {snapshot.scopeLabel}</span>
          <span>Source: {snapshot.sourceLabel}</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{snapshot.modeLabel}</strong>
          <span className="artifact-hub-policy-pill">{snapshot.syncLabel}</span>
        </div>
        <p>{snapshot.statusDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          {onToggleVimMode && (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onToggleVimMode()}
              aria-label={
                snapshot.enabled ? "Disable Vim Mode" : "Enable Vim Mode"
              }
            >
              {snapshot.enabled ? "Disable Vim Mode" : "Enable Vim Mode"}
            </button>
          )}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewSettings()}
          >
            Open Chat Settings
          </button>
        </div>
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Mode hints</span>
          <span>{snapshot.keyHints.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {snapshot.keyHints.map((hint) => (
            <article className="artifact-hub-generic-row" key={hint.id}>
              <div className="artifact-hub-generic-meta">
                <span>{hint.availability}</span>
                <span>{hint.keys}</span>
              </div>
              <div className="artifact-hub-generic-title">{hint.label}</div>
              <p className="artifact-hub-generic-summary">{hint.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{snapshot.parityLabel}</strong>
          <span className="artifact-hub-policy-pill">Honest parity status</span>
        </div>
        <p>{snapshot.parityDetail}</p>
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView?.("keybindings")}
          >
            Open Keybindings
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewSettings()}
          >
            Open Chat Settings
          </button>
        </div>
      </section>
    </div>
  );
}
