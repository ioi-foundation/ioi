import { icons } from "./Icons";
import { spotlightCommandPaletteShortcutLabel } from "../../shared/shellShortcuts";

export function SpotlightInputControls({
  blocked,
  showPasswordPrompt,
  isRunning,
  planMode,
  intent,
  isGated,
  inputLockedByCredential,
  onStop,
  onTogglePlanMode,
  onTriggerCommands,
  onTriggerCommandPalette,
  onSubmit,
}: {
  blocked: boolean;
  showPasswordPrompt: boolean;
  isRunning: boolean;
  planMode: boolean;
  intent: string;
  isGated: boolean;
  inputLockedByCredential: boolean;
  onStop: () => void;
  onTogglePlanMode: () => void;
  onTriggerCommands: () => void;
  onTriggerCommandPalette: () => void;
  onSubmit: () => void;
}) {
  if (blocked) {
    return (
      <div className="spot-blocker-footer">
        <div className="spot-blocker-footer__copy">
          <strong>
            {showPasswordPrompt
              ? "Awaiting credential"
              : "Awaiting clarification"}
          </strong>
          <span>
            {showPasswordPrompt
              ? "Provide the requested credential above to continue the run."
              : "Answer the blocker above. Press Enter to confirm the selected option or Esc to cancel."}
          </span>
        </div>
        <div className="spot-controls-right">
          {isRunning ? (
            <button
              className="spot-stop-btn"
              onClick={onStop}
              title="Stop (Esc)"
              type="button"
            >
              {icons.stop}
              <span>Stop</span>
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="spot-controls">
      <div className="spot-controls-left">
        <button className="spot-action-btn" title="Attach file (⌘U)" type="button">
          {icons.paperclip}
        </button>
        <button
          className={`spot-action-btn ${planMode ? "spot-action-btn--active" : ""}`}
          onClick={onTogglePlanMode}
          title={planMode ? "Exit plan mode" : "Enter plan mode"}
          type="button"
        >
          {icons.sidebar}
        </button>
        <button
          className="spot-action-btn spot-action-btn--slash"
          onClick={onTriggerCommands}
          title="Commands (/)"
          type="button"
        >
          <span className="spot-slash-trigger-text">/</span>
        </button>
        <button
          className="spot-action-btn"
          onClick={onTriggerCommandPalette}
          title={`Command palette (${spotlightCommandPaletteShortcutLabel()})`}
          type="button"
        >
          {icons.search}
        </button>
      </div>

      <div className="spot-controls-right">
        {isRunning ? (
          <button
            className="spot-stop-btn"
            onClick={onStop}
            title="Stop (Esc)"
            type="button"
          >
            {icons.stop}
            <span>Stop</span>
          </button>
        ) : (
          <button
            className="spot-send-btn"
            onClick={onSubmit}
            disabled={!intent.trim() || isGated || inputLockedByCredential}
            title="Send (⏎)"
            type="button"
          >
            {icons.send}
          </button>
        )}
      </div>
    </div>
  );
}
