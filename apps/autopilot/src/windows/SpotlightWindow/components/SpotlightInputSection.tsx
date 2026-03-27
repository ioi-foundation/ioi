import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent, KeyboardEvent, RefObject, SyntheticEvent } from "react";
import type { SkillCatalogEntry } from "../../../types";
import type { DropdownOption } from "./SpotlightDropdown";
import { icons } from "./Icons";
import {
  SpotlightSlashMenu,
  type SlashMenuItem,
  type SlashMenuSection,
} from "./SpotlightSlashMenu";

type SpotlightInputSectionProps = {
  inputRef: RefObject<HTMLTextAreaElement>;
  inputFocused: boolean;
  setInputFocused: (focused: boolean) => void;
  isDraggingFile: boolean;
  inputLockedByCredential: boolean;
  showPasswordPrompt: boolean;
  intent: string;
  setIntent: (value: string) => void;
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

type SlashTokenContext = {
  query: string;
  start: number;
  end: number;
};

function adjustTextareaHeight(textarea: HTMLTextAreaElement | null) {
  if (!textarea) {
    return;
  }
  textarea.style.height = "auto";
  textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
}

function getSlashTokenContext(value: string, caret: number): SlashTokenContext | null {
  const safeCaret = Math.max(0, Math.min(caret, value.length));
  const beforeCaret = value.slice(0, safeCaret);
  const leadingMatch = beforeCaret.match(/(?:^|\s)\/([^\s/]*)$/);

  if (!leadingMatch) {
    return null;
  }

  const queryBeforeCaret = leadingMatch[1] ?? "";
  const tokenStart = safeCaret - queryBeforeCaret.length - 1;
  const trailingMatch = value.slice(safeCaret).match(/^[^\s/]*/);
  const trailingQuery = trailingMatch?.[0] ?? "";

  return {
    query: `${queryBeforeCaret}${trailingQuery}`,
    start: tokenStart,
    end: safeCaret + trailingQuery.length,
  };
}

function humanizeLabel(value: string | null | undefined) {
  if (!value) {
    return "";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function matchesSlashQuery(query: string, ...parts: Array<string | null | undefined>) {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return true;
  }

  return parts
    .filter(Boolean)
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
}

function sourceLabelForSkill(skill: SkillCatalogEntry) {
  if (skill.source_type === "starter") {
    return "System";
  }
  if (skill.source_type === "workspace") {
    return "Personal";
  }

  return humanizeLabel(skill.source_type) || "Skill";
}

export function SpotlightInputSection({
  inputRef,
  inputFocused,
  setInputFocused,
  isDraggingFile,
  inputLockedByCredential,
  showPasswordPrompt,
  intent,
  setIntent,
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
  const commandsMenuOpen = activeDropdown === "commands";
  const [slashContext, setSlashContext] = useState<SlashTokenContext | null>(null);
  const [skillCatalog, setSkillCatalog] = useState<SkillCatalogEntry[]>([]);
  const [skillsStatus, setSkillsStatus] = useState<"idle" | "loading" | "ready" | "error">(
    "idle",
  );

  const syncSlashMenu = useCallback(
    (value: string, caret: number | null | undefined) => {
      if (inputLockedByCredential) {
        setSlashContext(null);
        if (commandsMenuOpen) {
          setActiveDropdown(null);
        }
        return;
      }

      const nextContext = getSlashTokenContext(value, caret ?? value.length);
      setSlashContext(nextContext);

      if (nextContext) {
        if (!commandsMenuOpen) {
          setActiveDropdown("commands");
        }
        return;
      }

      if (commandsMenuOpen) {
        setActiveDropdown(null);
      }
    },
    [commandsMenuOpen, inputLockedByCredential, setActiveDropdown],
  );

  useEffect(() => {
    if (!commandsMenuOpen || skillsStatus !== "idle") {
      return;
    }

    let cancelled = false;
    setSkillsStatus("loading");

    invoke<SkillCatalogEntry[]>("get_skill_catalog")
      .then((entries) => {
        if (cancelled) {
          return;
        }
        setSkillCatalog(entries);
        setSkillsStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load slash-menu skills:", error);
        if (!cancelled) {
          setSkillsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commandsMenuOpen, skillsStatus]);

  useEffect(() => {
    if (!commandsMenuOpen) {
      return;
    }

    syncSlashMenu(intent, inputRef.current?.selectionStart ?? intent.length);
  }, [commandsMenuOpen, inputRef, intent, syncSlashMenu]);

  const replaceSlashToken = useCallback(
    (replacement: string) => {
      const currentContext =
        slashContext ??
        getSlashTokenContext(intent, inputRef.current?.selectionStart ?? intent.length);

      const nextIntent = currentContext
        ? `${intent.slice(0, currentContext.start)}${replacement}${intent.slice(currentContext.end)}`
        : `${intent}${replacement}`;
      const nextCursor = currentContext ? currentContext.start + replacement.length : nextIntent.length;

      setIntent(nextIntent);
      setSlashContext(null);
      setActiveDropdown(null);

      window.requestAnimationFrame(() => {
        const textarea = inputRef.current;
        adjustTextareaHeight(textarea);
        textarea?.focus();
        textarea?.setSelectionRange(nextCursor, nextCursor);
      });
    },
    [inputRef, intent, setActiveDropdown, setIntent, slashContext],
  );

  const handleCommandTrigger = useCallback(() => {
    if (inputLockedByCredential) {
      return;
    }

    const textarea = inputRef.current;
    const selectionStart = textarea?.selectionStart ?? intent.length;
    const selectionEnd = textarea?.selectionEnd ?? selectionStart;
    const currentContext = getSlashTokenContext(intent, selectionStart);

    if (currentContext) {
      setSlashContext(currentContext);
      setActiveDropdown("commands");
      window.requestAnimationFrame(() => textarea?.focus());
      return;
    }

    const before = intent.slice(0, selectionStart);
    const after = intent.slice(selectionEnd);
    const needsLeadingSpace = before.length > 0 && !/\s$/.test(before);
    const insertText = `${needsLeadingSpace ? " " : ""}/`;
    const nextIntent = `${before}${insertText}${after}`;
    const nextCaret = before.length + insertText.length;

    setIntent(nextIntent);

    window.requestAnimationFrame(() => {
      const nextTextarea = inputRef.current;
      adjustTextareaHeight(nextTextarea);
      nextTextarea?.focus();
      nextTextarea?.setSelectionRange(nextCaret, nextCaret);
      syncSlashMenu(nextIntent, nextCaret);
    });
  }, [inputLockedByCredential, inputRef, intent, setActiveDropdown, setIntent, syncSlashMenu]);

  const slashQuery = slashContext?.query.trim().toLowerCase() ?? "";

  const actionSections = useMemo<SlashMenuSection[]>(() => {
    const actionItems: SlashMenuItem[] = [];

    const autoContextLabel = autoContext ? "Disable Auto Context" : "Enable Auto Context";
    const autoContextDescription = autoContext
      ? "Stop pulling nearby thread context into the prompt."
      : "Include nearby thread context automatically.";
    if (matchesSlashQuery(slashQuery, autoContextLabel, autoContextDescription, "context")) {
      actionItems.push({
        id: "toggle-auto-context",
        title: autoContextLabel,
        description: autoContextDescription,
        meta: autoContext ? "On" : "Off",
        icon: icons.sparkles,
        active: autoContext,
        onSelect: () => {
          onToggleAutoContext();
          replaceSlashToken("");
        },
      });
    }

    if (
      matchesSlashQuery(
        slashQuery,
        "Open Settings",
        "Manage models workspaces skills settings",
      )
    ) {
      actionItems.push({
        id: "open-settings",
        title: "Open Settings",
        description: "Manage models, workspaces, and skill sources.",
        icon: icons.settings,
        onSelect: () => {
          replaceSlashToken("");
          onOpenSettings();
        },
      });
    }

    const modelItems = modelOptions
      .filter((option) =>
        matchesSlashQuery(
          slashQuery,
          option.label,
          option.desc,
          "model llm openai anthropic meta",
        ),
      )
      .map<SlashMenuItem>((option) => ({
        id: `model-${option.value}`,
        title: option.label,
        description: option.desc || "Switch active model",
        icon: option.icon ?? icons.cube,
        active: option.value === selectedModel,
        meta: option.value === selectedModel ? "Current" : "Model",
        onSelect: () => {
          onSelectModel(option.value);
          replaceSlashToken("");
        },
      }));

    const workspaceItems = workspaceOptions
      .filter((option) =>
        matchesSlashQuery(slashQuery, option.label, option.desc, "workspace local cloud"),
      )
      .map<SlashMenuItem>((option) => ({
        id: `workspace-${option.value}`,
        title: option.label,
        description: option.desc || "Switch workspace",
        icon: option.icon ?? icons.laptop,
        active: option.value === workspaceMode,
        meta: option.value === workspaceMode ? "Current" : "Workspace",
        onSelect: () => {
          onSelectWorkspaceMode(option.value);
          replaceSlashToken("");
        },
      }));

    const sortedSkills = [...skillCatalog].sort((left, right) => {
      if (left.stale !== right.stale) {
        return Number(left.stale) - Number(right.stale);
      }
      if (left.success_rate_bps !== right.success_rate_bps) {
        return right.success_rate_bps - left.success_rate_bps;
      }
      if (left.sample_size !== right.sample_size) {
        return right.sample_size - left.sample_size;
      }
      return left.name.localeCompare(right.name);
    });

    const skillItems: SlashMenuItem[] =
      skillsStatus === "loading"
        ? [
            {
              id: "skills-loading",
              title: "Loading Skills",
              description: "Fetching runtime skill catalog...",
              icon: icons.code,
              disabled: true,
            },
          ]
        : skillsStatus === "error"
          ? [
              {
                id: "skills-error",
                title: "Skills Unavailable",
                description: "Open settings to check skill sources.",
                icon: icons.code,
                onSelect: () => {
                  replaceSlashToken("");
                  onOpenSettings();
                },
              },
            ]
          : sortedSkills
              .filter((skill) =>
                matchesSlashQuery(
                  slashQuery,
                  skill.name,
                  skill.description,
                  skill.definition?.description,
                  skill.source_type,
                  skill.lifecycle_state,
                ),
              )
              .slice(0, 8)
              .map<SlashMenuItem>((skill) => ({
                id: `skill-${skill.skill_hash}`,
                title: skill.name,
                description:
                  skill.description ||
                  skill.definition?.description ||
                  "Add this skill to the prompt as guidance.",
                icon: icons.code,
                meta: sourceLabelForSkill(skill),
                onSelect: () => {
                  replaceSlashToken(`Use the ${skill.name} skill for this request. `);
                },
              }));

    return [
      { id: "actions", title: "Actions", items: actionItems },
      { id: "models", title: "Model", items: modelItems },
      { id: "workspaces", title: "Workspace", items: workspaceItems },
      { id: "skills", title: "Skills", items: skillItems },
    ];
  }, [
    autoContext,
    modelOptions,
    onOpenSettings,
    onSelectModel,
    onSelectWorkspaceMode,
    onToggleAutoContext,
    replaceSlashToken,
    selectedModel,
    skillCatalog,
    skillsStatus,
    slashQuery,
    workspaceMode,
    workspaceOptions,
  ]);

  const slashActionItems = useMemo(
    () =>
      actionSections.flatMap((section) =>
        section.items.filter((item) => item.onSelect && !item.disabled),
      ),
    [actionSections],
  );

  const handleTextareaChange = useCallback(
    (event: ChangeEvent<HTMLTextAreaElement>) => {
      onInputChange(event);
      syncSlashMenu(event.target.value, event.target.selectionStart ?? event.target.value.length);
    },
    [onInputChange, syncSlashMenu],
  );

  const handleTextareaKeyDown = useCallback(
    (event: KeyboardEvent<HTMLTextAreaElement>) => {
      if (commandsMenuOpen && event.key === "Escape") {
        event.preventDefault();
        setSlashContext(null);
        setActiveDropdown(null);
        return;
      }

      if (commandsMenuOpen && event.key === "Enter" && !event.shiftKey) {
        const [firstItem] = slashActionItems;
        if (firstItem?.onSelect) {
          event.preventDefault();
          firstItem.onSelect();
          return;
        }
      }

      onInputKeyDown(event);
    },
    [commandsMenuOpen, onInputKeyDown, setActiveDropdown, slashActionItems],
  );

  const handleTextareaSelection = useCallback(
    (event: ChangeEvent<HTMLTextAreaElement> | SyntheticEvent<HTMLTextAreaElement>) => {
      const textarea = event.currentTarget;
      syncSlashMenu(textarea.value, textarea.selectionStart ?? textarea.value.length);
    },
    [syncSlashMenu],
  );

  return (
    <div
      className={`spot-input-section ${inputFocused ? "focused" : ""} ${
        isDraggingFile ? "drag-active" : ""
      }`}
    >
      <div className="spot-input-wrapper">
        {commandsMenuOpen ? (
          <SpotlightSlashMenu
            sections={actionSections}
            emptyState={
              slashQuery
                ? `No commands or skills match "${slashContext?.query ?? ""}".`
                : "No commands available right now."
            }
          />
        ) : null}

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
          onChange={handleTextareaChange}
          onKeyDown={handleTextareaKeyDown}
          onClick={handleTextareaSelection}
          onKeyUp={handleTextareaSelection}
          onSelect={handleTextareaSelection}
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
            <button
              className="spot-action-btn spot-action-btn--slash"
              onClick={handleCommandTrigger}
              title="Commands (/)"
              type="button"
            >
              <span className="spot-slash-trigger-text">/</span>
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
    </div>
  );
}
