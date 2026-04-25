import { icons } from "../../../components/ui/icons";
import { chatCommandPaletteShortcutLabel } from "../../shared/shellShortcuts";

export function ChatInputControls({
  blocked,
  showPasswordPrompt,
  isRunning,
  planMode,
  autoContext,
  workspaceModeLabel,
  modelLabel,
  intent,
  isGated,
  inputLockedByCredential,
  onStop,
  onTogglePlanMode,
  onToggleAutoContext,
  onTriggerContext,
  onTriggerCommands,
  onTriggerCommandPalette,
  onOpenSettings,
  onSubmit,
}: {
  blocked: boolean;
  showPasswordPrompt: boolean;
  isRunning: boolean;
  planMode: boolean;
  autoContext: boolean;
  workspaceModeLabel: string;
  modelLabel: string;
  intent: string;
  isGated: boolean;
  inputLockedByCredential: boolean;
  onStop: () => void;
  onTogglePlanMode: () => void;
  onToggleAutoContext: () => void;
  onTriggerContext: () => void;
  onTriggerCommands: () => void;
  onTriggerCommandPalette: () => void;
  onOpenSettings: () => void;
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
        <button
          className="spot-context-btn"
          onClick={onTriggerContext}
          title="Add context from files, sessions, tools, or commands"
          type="button"
        >
          <span className="spot-context-btn__icon" aria-hidden="true">
            {icons.paperclip}
          </span>
          <span>Add Context...</span>
        </button>

        <button
          className="spot-input-selector"
          onClick={onTriggerCommands}
          title="Choose workspace context"
          type="button"
        >
          <span>{workspaceModeLabel}</span>
          <span className="spot-input-selector__chevron" aria-hidden="true">
            {icons.chevron}
          </span>
        </button>

        <button
          className="spot-input-selector"
          onClick={onTriggerCommandPalette}
          title={`Choose model or command (${chatCommandPaletteShortcutLabel()})`}
          type="button"
        >
          <span>{modelLabel}</span>
          <span className="spot-input-selector__chevron" aria-hidden="true">
            {icons.chevron}
          </span>
        </button>

        <button
          className={`spot-input-selector spot-input-selector--mode ${
            planMode ? "is-active" : ""
          }`}
          onClick={onTogglePlanMode}
          title={planMode ? "Exit plan mode" : "Enter plan mode"}
          type="button"
        >
          <span>{planMode ? "Plan" : "Auto"}</span>
          <span className="spot-input-selector__chevron" aria-hidden="true">
            {icons.chevron}
          </span>
        </button>

        <button
          className={`spot-tool-toggle ${autoContext ? "is-active" : ""}`}
          onClick={onToggleAutoContext}
          title={autoContext ? "Auto context enabled" : "Auto context disabled"}
          type="button"
        >
          {icons.sparkles}
        </button>

        <button
          className="spot-tool-toggle"
          onClick={onTriggerCommands}
          title="Commands (/)"
          type="button"
        >
          <span className="spot-slash-trigger-text">/</span>
        </button>

        <button
          className="spot-tool-toggle"
          onClick={onOpenSettings}
          title="Chat settings"
          type="button"
        >
          {icons.wrench}
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
