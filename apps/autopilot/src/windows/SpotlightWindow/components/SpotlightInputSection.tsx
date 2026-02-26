import type { ChangeEvent, KeyboardEvent, RefObject } from "react";
import type { DropdownOption } from "./SpotlightDropdown";
import { Dropdown } from "./SpotlightDropdown";
import { icons } from "./Icons";

type SpotlightInputSectionProps = {
  inputRef: RefObject<HTMLTextAreaElement>;
  inputFocused: boolean;
  setInputFocused: (focused: boolean) => void;
  isDraggingFile: boolean;
  inputLockedByCredential: boolean;
  showPasswordPrompt: boolean;
  intent: string;
  onInputChange: (event: ChangeEvent<HTMLTextAreaElement>) => void;
  onInputKeyDown: (event: KeyboardEvent<HTMLTextAreaElement>) => void;
  autoContext: boolean;
  onToggleAutoContext: () => void;
  isRunning: boolean;
  isGated: boolean;
  onStop: () => void;
  onSubmit: () => void;
  workspaceOptions: DropdownOption[];
  workspaceMode: string;
  onSelectWorkspaceMode: (value: string) => void;
  modelOptions: DropdownOption[];
  selectedModel: string;
  onSelectModel: (value: string) => void;
  activeDropdown: string | null;
  setActiveDropdown: (value: string | null) => void;
  onOpenSettings: () => void;
};

export function SpotlightInputSection({
  inputRef,
  inputFocused,
  setInputFocused,
  isDraggingFile,
  inputLockedByCredential,
  showPasswordPrompt,
  intent,
  onInputChange,
  onInputKeyDown,
  autoContext,
  onToggleAutoContext,
  isRunning,
  isGated,
  onStop,
  onSubmit,
  workspaceOptions,
  workspaceMode,
  onSelectWorkspaceMode,
  modelOptions,
  selectedModel,
  onSelectModel,
  activeDropdown,
  setActiveDropdown,
  onOpenSettings,
}: SpotlightInputSectionProps) {
  return (
    <div
      className={`spot-input-section ${inputFocused ? "focused" : ""} ${
        isDraggingFile ? "drag-active" : ""
      }`}
    >
      <div className="spot-input-wrapper">
        <textarea
          ref={inputRef}
          className="spot-input"
          placeholder={
            inputLockedByCredential
              ? showPasswordPrompt
                ? "Sudo password required below to continue install..."
                : "Clarification required below to continue..."
              : "How can I help you today?"
          }
          value={intent}
          onChange={onInputChange}
          onKeyDown={onInputKeyDown}
          onFocus={() => setInputFocused(true)}
          onBlur={() => setInputFocused(false)}
          rows={1}
          disabled={inputLockedByCredential}
        />

        <div className="spot-controls">
          <div className="spot-controls-left">
            <button className="spot-action-btn" title="Attach file (⌘U)">
              {icons.paperclip}
            </button>
            <button className="spot-action-btn" title="Commands (/)">
              {icons.slash}
            </button>
            <button
              className={`spot-context-btn ${autoContext ? "active" : ""}`}
              onClick={onToggleAutoContext}
              title="Auto context (⌘.)"
            >
              {icons.sparkles}
              <span>Context</span>
            </button>
          </div>

          {isRunning ? (
            <button className="spot-stop-btn" onClick={onStop} title="Stop (Esc)">
              {icons.stop}
              <span>Stop</span>
            </button>
          ) : (
            <button
              className="spot-send-btn"
              onClick={onSubmit}
              disabled={!intent.trim() || isGated || inputLockedByCredential}
              title="Send (⏎)"
            >
              {icons.send}
            </button>
          )}
        </div>
      </div>

      <div className="spot-toggles">
        <Dropdown
          icon={icons.laptop}
          options={workspaceOptions}
          selected={workspaceMode}
          onSelect={onSelectWorkspaceMode}
          isOpen={activeDropdown === "workspace"}
          onToggle={() =>
            setActiveDropdown(activeDropdown === "workspace" ? null : "workspace")
          }
          footer={{
            label: "Manage Workspaces...",
            onClick: onOpenSettings,
          }}
        />
        <Dropdown
          icon={icons.cube}
          options={modelOptions}
          selected={selectedModel}
          onSelect={onSelectModel}
          isOpen={activeDropdown === "model"}
          onToggle={() => setActiveDropdown(activeDropdown === "model" ? null : "model")}
          footer={{
            label: "Manage Models...",
            onClick: onOpenSettings,
          }}
        />
      </div>
    </div>
  );
}
