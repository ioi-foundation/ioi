import {
  type ConnectorActionDefinition,
  type ConnectorSummary,
  type RuntimeCatalogEntry,
} from "@ioi/hypervisor-workbench";
import { listenIfHostBridge as listen } from "../../../services/hostListeners";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useState,
} from "react";
import { createPortal } from "react-dom";
import type {
  ChangeEvent,
  CSSProperties,
  KeyboardEvent,
  MouseEvent,
  RefObject,
  SyntheticEvent,
} from "react";
import {
  openCompanionCapabilityActions,
  openCompanionCatalog,
} from "../../../services/companionShellNavigation";
import {
  openReviewCapabilities,
  openReviewPolicyCenter,
} from "../../../services/reviewNavigation";
import { getSessionWorkbenchRuntime } from "../../../services/sessionRuntime";
import { safelyDisposeHostListener } from "../../../services/hostListeners";
import type {
  AgentTask,
  ArtifactHubViewKey,
  SessionSummary,
} from "../../../types";
import { useChatCapabilityRegistry, resolveCapabilityRegistryEntryForCatalogSkill } from "../../ChatShellWindow/hooks/useChatCapabilityRegistry";
import { useChatPermissions } from "../../ChatShellWindow/hooks/useChatPermissions";
import { useChatVimMode } from "../../ChatShellWindow/hooks/useChatVimMode";
import {
  planModePlaceholder,
  planModeStatusCopy,
} from "../../ChatShellWindow/utils/planModePrompt";
import {
  applyChatVimNormalKey,
  type PendingVimMotionPrefix,
  type PendingVimOperator,
  type ChatVimRepeatableCommand,
} from "../../ChatShellWindow/utils/chatVimComposer";
import type { DropdownOption } from "../../../components/ui/Dropdown";
import { icons } from "../../../components/ui/icons";
import {
  CommandMenu,
  type CommandMenuItem,
  type CommandMenuSection,
} from "../../../components/ui/CommandMenu";
import { ChatInputControls } from "./ChatInputControls";
import {
  buildModelSlashItems,
  buildRecentSessionItems,
  buildSharedSessionCommandItems,
  buildWorkspaceWorkflowItems,
  buildWorkspaceSlashItems,
} from "./chatInputCommandDefinitions";
import {
  adjustTextareaHeight,
  capabilityDescriptionForSkill,
  capabilityMetaLabel,
  connectorStatusRank,
  getSlashTokenContext,
  humanizeLabel,
  matchesSlashQuery,
  sessionResumeContext,
  sourceLabelForSkill,
  stableSessionCandidate,
  workspaceRootFromTask,
  type SlashTokenContext,
} from "./chatInputHelpers";
import type { WorkspaceWorkflowSummary } from "../../../services/HypervisorClientRuntime";

type ChatInputSectionProps = {
  inputRef: RefObject<HTMLTextAreaElement>;
  inputFocused: boolean;
  setInputFocused: (focused: boolean) => void;
  isDraggingFile: boolean;
  inputLockedByCredential: boolean;
  showPasswordPrompt: boolean;
  task: AgentTask | null;
  sessions: SessionSummary[];
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
  onNewSession: () => void;
  onLoadSession: (sessionId: string) => void;
  onOpenGate: () => void;
  onOpenView: (view: ArtifactHubViewKey) => void;
  onSubmitClarification?: (optionId: string, otherText: string) => Promise<void>;
  onOpenValidationEvidence: () => void;
  workspaceOptions: DropdownOption[];
  workspaceMode: string;
  onSelectWorkspaceMode: (value: string) => void;
  modelOptions: DropdownOption[];
  selectedModel: string;
  onSelectModel: (value: string) => void;
  planMode: boolean;
  onTogglePlanMode: (nextValue?: boolean) => void;
  artifactCount: number;
  workerCount: number;
  activeDropdown: string | null;
  setActiveDropdown: (value: string | null) => void;
  onOpenSettings: () => void;
  placeholder?: string;
};

type LoadStatus = "idle" | "loading" | "ready" | "error";

const CHAT_COMPOSER_FOCUS_REQUESTED_EVENT = "chat-composer-focus-requested";
const COMMAND_CENTER_SELECTOR = "[data-operator-command-center]";
const COMMAND_CENTER_MENU_EDGE_GUTTER = 8;
const COMMAND_CENTER_MENU_WIDTH = 596;

type LiveToolRecord = {
  connector: ConnectorSummary;
  action: ConnectorActionDefinition;
};

type CommandSurfaceKeyEvent = {
  key: string;
  shiftKey: boolean;
  preventDefault: () => void;
};

function clampNumber(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function slashContextsEqual(
  left: SlashTokenContext | null,
  right: SlashTokenContext | null,
): boolean {
  return (
    left?.query === right?.query &&
    left?.start === right?.start &&
    left?.end === right?.end
  );
}

export function ChatInputSection({
  inputRef,
  inputFocused,
  setInputFocused,
  isDraggingFile,
  inputLockedByCredential,
  showPasswordPrompt,
  task,
  sessions,
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
  onNewSession,
  onLoadSession,
  onOpenGate,
  onOpenView,
  onSubmitClarification,
  onOpenValidationEvidence,
  workspaceOptions,
  workspaceMode,
  onSelectWorkspaceMode,
  modelOptions,
  selectedModel,
  onSelectModel,
  planMode,
  onTogglePlanMode,
  artifactCount,
  workerCount,
  activeDropdown,
  setActiveDropdown,
  onOpenSettings,
  placeholder,
}: ChatInputSectionProps) {
  const commandSurfaceMode =
    activeDropdown === "command_palette"
      ? "palette"
      : activeDropdown === "commands"
        ? "slash"
        : activeDropdown === "tools"
          ? "tools"
        : null;
  const commandsMenuOpen = commandSurfaceMode !== null;
  const commandPaletteMode = commandSurfaceMode === "palette";
  const toolPaletteMode = commandSurfaceMode === "tools";
  const searchablePaletteMode = commandPaletteMode || toolPaletteMode;
  const [slashContext, setSlashContext] = useState<SlashTokenContext | null>(null);
  const [commandPaletteQuery, setCommandPaletteQuery] = useState("");
  const [runtimeCatalogEntries, setRuntimeCatalogEntries] = useState<RuntimeCatalogEntry[]>([]);
  const [runtimeCatalogStatus, setRuntimeCatalogStatus] = useState<LoadStatus>("idle");
  const [workspaceWorkflows, setWorkspaceWorkflows] = useState<WorkspaceWorkflowSummary[]>([]);
  const [workspaceWorkflowsStatus, setWorkspaceWorkflowsStatus] =
    useState<LoadStatus>("idle");
  const [liveTools, setLiveTools] = useState<LiveToolRecord[]>([]);
  const [liveToolsStatus, setLiveToolsStatus] = useState<LoadStatus>("idle");
  const [commandCenterMenuStyle, setCommandCenterMenuStyle] =
    useState<CSSProperties>(() => ({
      left: COMMAND_CENTER_MENU_EDGE_GUTTER,
      top: 40,
      width: `min(${COMMAND_CENTER_MENU_WIDTH}px, calc(100vw - ${
        COMMAND_CENTER_MENU_EDGE_GUTTER * 2
      }px))`,
      maxHeight: "min(74vh, 640px)",
    }));
  const [highlightedItemId, setHighlightedItemId] = useState<string | null>(null);
  const [pendingVimOperator, setPendingVimOperator] =
    useState<PendingVimOperator>(null);
  const [pendingVimMotionPrefix, setPendingVimMotionPrefix] =
    useState<PendingVimMotionPrefix>(null);
  const [pendingVimCount, setPendingVimCount] = useState<number | null>(null);
  const [lastVimCommand, setLastVimCommand] =
    useState<ChatVimRepeatableCommand | null>(null);
  const {
    snapshot: capabilityRegistrySnapshot,
    status: capabilityRegistryStatus,
    error: capabilityRegistryError,
    entryLookup: capabilityRegistryEntryLookup,
  } = useChatCapabilityRegistry(commandsMenuOpen);
  const {
    availableProfiles: permissionProfiles,
    currentProfileId: currentPermissionProfileId,
    applyingProfileId: applyingPermissionProfileId,
    applyProfile: applyPermissionProfile,
  } = useChatPermissions(commandsMenuOpen);
  const {
    snapshot: vimModeSnapshot,
    toggle: toggleVimMode,
    enterInsertMode,
    enterNormalMode,
  } = useChatVimMode(true);

  const currentSessionId = task?.session_id || task?.id || null;
  const hasSessionContext = Boolean(currentSessionId);
  const hasReplSurface = Boolean(
    hasSessionContext ||
      workspaceRootFromTask(task) ||
      sessions.length > 0,
  );
  const hasRewindSurface = sessions.length > 0 || Boolean(task?.session_id || task?.id);
  const hasWorkerContext = workerCount > 0;
  const hasArtifacts = artifactCount > 0;
  const hasFileSurface = hasSessionContext || hasArtifacts;
  const hasBranchSurface = Boolean(
    workspaceRootFromTask(task) ||
      sessions.some((session) => Boolean(session.workspace_root?.trim())),
  );
  const hookContributionCount = useMemo(
    () =>
      capabilityRegistrySnapshot?.extensionManifests.reduce((count, manifest) => {
        return (
          count +
          manifest.contributions.filter((contribution) => contribution.kind === "hooks")
            .length
        );
      }, 0) ?? 0,
    [capabilityRegistrySnapshot],
  );
  const mcpContributionCount = useMemo(
    () =>
      capabilityRegistrySnapshot?.extensionManifests.reduce((count, manifest) => {
        return (
          count +
          manifest.contributions
            .filter((contribution) => contribution.kind === "mcp_servers")
            .reduce(
              (manifestCount, contribution) =>
                manifestCount + Math.max(1, contribution.itemCount ?? 1),
              0,
            )
        );
      }, 0) ?? 0,
    [capabilityRegistrySnapshot],
  );
  const hasPermissionRequest = Boolean(
    isGated ||
      task?.pending_request_hash ||
      task?.credential_request ||
      task?.clarification_request ||
      task?.gate_info,
  );
  const skillCatalog = capabilityRegistrySnapshot?.skillCatalog ?? [];

  const syncSlashMenu = useCallback(
    (value: string, caret: number | null | undefined) => {
      if (inputLockedByCredential) {
        setSlashContext((current) => (current === null ? current : null));
        if (commandsMenuOpen) {
          setActiveDropdown(null);
        }
        return;
      }

      const nextContext = getSlashTokenContext(value, caret ?? value.length);
      setSlashContext((current) =>
        slashContextsEqual(current, nextContext) ? current : nextContext,
      );

      if (nextContext) {
        if (!commandsMenuOpen) {
          setActiveDropdown("commands");
        }
        return;
      }
    },
    [commandsMenuOpen, inputLockedByCredential, setActiveDropdown],
  );

  const focusComposer = useCallback(
    (cursor?: number) => {
      enterInsertMode();
      window.requestAnimationFrame(() => {
        const textarea = inputRef.current;
        adjustTextareaHeight(textarea);
        textarea?.focus();
        if (typeof cursor === "number") {
          textarea?.setSelectionRange(cursor, cursor);
        }
      });
    },
    [enterInsertMode, inputRef],
  );

  const commandCenterMenuOpen =
    commandsMenuOpen && searchablePaletteMode && !inputLockedByCredential;

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const event = new CustomEvent("spot-command-menu-toggled", {
      detail: { open: commandCenterMenuOpen },
    });
    window.dispatchEvent(event);
  }, [commandCenterMenuOpen]);

  useLayoutEffect(() => {
    if (!commandCenterMenuOpen || typeof window === "undefined") {
      return;
    }

    const computePosition = () => {
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;
      const availableWidth = Math.max(
        1,
        viewportWidth - COMMAND_CENTER_MENU_EDGE_GUTTER * 2,
      );
      const width = Math.min(COMMAND_CENTER_MENU_WIDTH, availableWidth);
      const anchor = document.querySelector(COMMAND_CENTER_SELECTOR);
      const anchorRect = anchor?.getBoundingClientRect();
      const anchorCenter = anchorRect
        ? anchorRect.left + anchorRect.width / 2
        : viewportWidth / 2;
      const left = clampNumber(
        anchorCenter - width / 2,
        COMMAND_CENTER_MENU_EDGE_GUTTER,
        Math.max(
          COMMAND_CENTER_MENU_EDGE_GUTTER,
          viewportWidth - width - COMMAND_CENTER_MENU_EDGE_GUTTER,
        ),
      );
      const preferredTop = anchorRect ? anchorRect.bottom + 6 : 40;
      const maxHeight = Math.min(
        640,
        Math.max(
          240,
          viewportHeight - preferredTop - COMMAND_CENTER_MENU_EDGE_GUTTER,
        ),
      );
      const top = clampNumber(
        preferredTop,
        COMMAND_CENTER_MENU_EDGE_GUTTER,
        Math.max(
          COMMAND_CENTER_MENU_EDGE_GUTTER,
          viewportHeight - maxHeight - COMMAND_CENTER_MENU_EDGE_GUTTER,
        ),
      );

      setCommandCenterMenuStyle({
        left,
        top,
        width,
        maxHeight,
      });
    };

    computePosition();
    window.addEventListener("resize", computePosition);
    window.addEventListener("scroll", computePosition, true);
    return () => {
      window.removeEventListener("resize", computePosition);
      window.removeEventListener("scroll", computePosition, true);
    };
  }, [commandCenterMenuOpen]);

  const handleComposerWrapperMouseDown = useCallback(
    (event: MouseEvent<HTMLDivElement>) => {
      const target = event.target as HTMLElement | null;
      if (
        target?.closest(
          "button,a,input,select,[role='button'],[data-composer-control='true']",
        )
      ) {
        return;
      }
      enterInsertMode();
      focusComposer();
    },
    [enterInsertMode, focusComposer],
  );

  const handleTextareaFocus = useCallback(() => {
    setInputFocused(true);
    enterInsertMode();
  }, [enterInsertMode, setInputFocused]);

  useEffect(() => {
    const unlistenPromise = listen(CHAT_COMPOSER_FOCUS_REQUESTED_EVENT, () => {
      focusComposer();
    });
    return () => {
      safelyDisposeHostListener(unlistenPromise);
    };
  }, [focusComposer]);

  useEffect(() => {
    if (!commandsMenuOpen || runtimeCatalogStatus !== "idle") {
      return;
    }

    let cancelled = false;
    const runtime = getSessionWorkbenchRuntime();
    setRuntimeCatalogStatus("loading");

    runtime
      .getRuntimeCatalogEntries()
      .then((entries) => {
        if (cancelled) {
          return;
        }
        setRuntimeCatalogEntries(entries);
        setRuntimeCatalogStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load runtime catalog entries for slash menu:", error);
        if (!cancelled) {
          setRuntimeCatalogStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commandsMenuOpen, runtimeCatalogStatus]);

  useEffect(() => {
    if (!commandsMenuOpen || liveToolsStatus !== "idle") {
      return;
    }

    const runtime = getSessionWorkbenchRuntime();
    if (!runtime.getConnectors || !runtime.getConnectorActions) {
      setLiveToolsStatus("ready");
      return;
    }

    let cancelled = false;
    setLiveToolsStatus("loading");

    runtime
      .getConnectors()
      .then(async (connectors) => {
        const sortedConnectors = [...connectors].sort((left, right) => {
          const statusDelta =
            connectorStatusRank(left.status) - connectorStatusRank(right.status);
          if (statusDelta !== 0) {
            return statusDelta;
          }
          return left.name.localeCompare(right.name);
        });

        const actionGroups = await Promise.all(
          sortedConnectors.map(async (connector) => {
            try {
              const actions = await runtime.getConnectorActions?.(connector.id);
              return (actions ?? []).map<LiveToolRecord>((action) => ({
                connector,
                action,
              }));
            } catch (error) {
              console.error(
                `Failed to load connector actions for slash menu: ${connector.id}`,
                error,
              );
              return [];
            }
          }),
        );

        if (cancelled) {
          return;
        }

        setLiveTools(
          actionGroups.flat().sort((left, right) => {
            const connectorDelta =
              connectorStatusRank(left.connector.status) -
              connectorStatusRank(right.connector.status);
            if (connectorDelta !== 0) {
              return connectorDelta;
            }
            return left.action.label.localeCompare(right.action.label);
          }),
        );
        setLiveToolsStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load live tool catalog for slash menu:", error);
        if (!cancelled) {
          setLiveToolsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commandsMenuOpen, liveToolsStatus]);

  useEffect(() => {
    if (!commandsMenuOpen || workspaceWorkflowsStatus !== "idle") {
      return;
    }

    const runtime = getSessionWorkbenchRuntime();
    if (typeof runtime.listWorkspaceWorkflows !== "function") {
      setWorkspaceWorkflowsStatus("ready");
      return;
    }

    let cancelled = false;
    setWorkspaceWorkflowsStatus("loading");

    runtime
      .listWorkspaceWorkflows()
      .then((workflows) => {
        if (cancelled) {
          return;
        }
        setWorkspaceWorkflows(workflows);
        setWorkspaceWorkflowsStatus("ready");
      })
      .catch((error) => {
        console.error("Failed to load workspace workflows for slash menu:", error);
        if (!cancelled) {
          setWorkspaceWorkflowsStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [commandsMenuOpen, workspaceWorkflowsStatus]);

  useEffect(() => {
    if (!commandsMenuOpen && workspaceWorkflowsStatus !== "idle") {
      setWorkspaceWorkflowsStatus("idle");
    }
  }, [commandsMenuOpen, workspaceWorkflowsStatus]);

  useEffect(() => {
    if (!commandsMenuOpen || searchablePaletteMode) {
      return;
    }

    syncSlashMenu(intent, inputRef.current?.selectionStart ?? intent.length);
  }, [commandsMenuOpen, inputRef, intent, searchablePaletteMode, syncSlashMenu]);

  useEffect(() => {
    if (!vimModeSnapshot.enabled || vimModeSnapshot.modeId !== "vim_normal") {
      setPendingVimOperator((current) => (current === null ? current : null));
      setPendingVimMotionPrefix((current) =>
        current === null ? current : null,
      );
      setPendingVimCount((current) => (current === null ? current : null));
    }
  }, [vimModeSnapshot.enabled, vimModeSnapshot.modeId]);

  useEffect(() => {
    if (searchablePaletteMode) {
      setSlashContext((current) => (current === null ? current : null));
      return;
    }

    if (commandPaletteQuery) {
      setCommandPaletteQuery("");
    }
  }, [commandPaletteQuery, searchablePaletteMode]);

  const replaceSlashToken = useCallback(
    (replacement: string, refocus = true) => {
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

      if (refocus) {
        window.requestAnimationFrame(() => {
          const textarea = inputRef.current;
          adjustTextareaHeight(textarea);
          textarea?.focus();
          textarea?.setSelectionRange(nextCursor, nextCursor);
        });
      }
    },
    [inputRef, intent, setActiveDropdown, setIntent, slashContext],
  );

  const dismissCommandSurface = useCallback(
    (refocusComposer = true) => {
      if (searchablePaletteMode) {
        setSlashContext(null);
        setCommandPaletteQuery("");
        setActiveDropdown(null);
        if (refocusComposer) {
          focusComposer();
        }
        return;
      }

      replaceSlashToken("", refocusComposer);
    },
    [
      focusComposer,
      replaceSlashToken,
      searchablePaletteMode,
      setActiveDropdown,
    ],
  );

  useEffect(() => {
    if (!commandsMenuOpen) {
      return;
    }
    const handleBlur = () => {
      requestAnimationFrame(() => {
        if (document.activeElement && document.activeElement.tagName === "IFRAME") {
          dismissCommandSurface(false);
        }
      });
    };
    window.addEventListener("blur", handleBlur);
    return () => {
      window.removeEventListener("blur", handleBlur);
    };
  }, [commandsMenuOpen, dismissCommandSurface]);

  const insertSkillGuidance = useCallback(
    (skillName: string) => {
      const guidance = `Use the ${skillName} skill for this request. `;
      if (!searchablePaletteMode) {
        replaceSlashToken(guidance);
        return;
      }

      const nextIntent =
        intent.trim().length > 0 ? `${intent.trimEnd()} ${guidance}` : guidance;
      setIntent(nextIntent);
      setSlashContext(null);
      setCommandPaletteQuery("");
      setActiveDropdown(null);
      focusComposer(nextIntent.length);
    },
    [
      focusComposer,
      intent,
      replaceSlashToken,
      searchablePaletteMode,
      setActiveDropdown,
      setIntent,
    ],
  );

  const insertWorkflowSlashCommand = useCallback(
    (slashCommand: string) => {
      const replacement = `${slashCommand} `;
      if (!searchablePaletteMode) {
        replaceSlashToken(replacement);
        return;
      }

      setIntent(replacement);
      setSlashContext(null);
      setCommandPaletteQuery("");
      setActiveDropdown(null);
      focusComposer(replacement.length);
    },
    [
      focusComposer,
      replaceSlashToken,
      searchablePaletteMode,
      setActiveDropdown,
      setIntent,
    ],
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

  const handleCommandPaletteTrigger = useCallback(() => {
    if (inputLockedByCredential) {
      return;
    }

    if (commandPaletteMode) {
      setCommandPaletteQuery("");
      setActiveDropdown(null);
      focusComposer();
      return;
    }

    setSlashContext(null);
    setCommandPaletteQuery("");
    setActiveDropdown("command_palette");
  }, [
    commandPaletteMode,
    focusComposer,
    inputLockedByCredential,
    setActiveDropdown,
  ]);

  const handleToolPaletteTrigger = useCallback(() => {
    if (inputLockedByCredential) {
      return;
    }

    if (toolPaletteMode) {
      setCommandPaletteQuery("");
      setActiveDropdown(null);
      focusComposer();
      return;
    }

    setSlashContext(null);
    setCommandPaletteQuery("");
    setActiveDropdown("tools");
  }, [
    focusComposer,
    inputLockedByCredential,
    setActiveDropdown,
    toolPaletteMode,
  ]);

  const handleContextTrigger = useCallback(() => {
    if (inputLockedByCredential) {
      return;
    }

    setSlashContext(null);
    setCommandPaletteQuery("context");
    setActiveDropdown("command_palette");
  }, [inputLockedByCredential, setActiveDropdown]);

  const openCommandSearch = useCallback(
    (query: string) => {
      if (inputLockedByCredential) {
        return;
      }

      setSlashContext(null);
      setCommandPaletteQuery(query);
      setActiveDropdown("command_palette");
    },
    [inputLockedByCredential, setActiveDropdown],
  );

  const commandQuery = searchablePaletteMode
    ? commandPaletteQuery.trim().toLowerCase()
    : slashContext?.query.trim().toLowerCase() ?? "";
  const slashQuickMode = !searchablePaletteMode && commandQuery.length === 0;
  const shouldShowSearchBackedItems = searchablePaletteMode || commandQuery.length > 0;
  const hasTaskReview = !!task;
  const hasTaskBlocker = Boolean(
    task?.clarification_request ||
      task?.credential_request ||
      task?.pending_request_hash ||
      task?.gate_info ||
      task?.phase === "Gate",
  );
  const canStopTask = Boolean(
    isRunning || task?.background_tasks.some((entry) => entry.can_stop),
  );
  const recommendedClarificationOptionId =
    task?.clarification_request?.options.find((option) => option.recommended)
      ?.id ||
    task?.clarification_request?.options[0]?.id ||
    null;
  const lastStableSession = stableSessionCandidate(sessions, currentSessionId);
  const currentPermissionProfile =
    permissionProfiles.find((profile) => profile.id === currentPermissionProfileId) ??
    null;

  const actionSections = useMemo<CommandMenuSection[]>(() => {
    const commandItems: CommandMenuItem[] = [];

    if (slashQuickMode) {
      commandItems.push(
        {
          id: "add-context",
          title: "Add context",
          description: "Attach files, repo state, evidence, or runtime context.",
          meta: "Context",
          icon: icons.paperclip,
          onSelect: handleContextTrigger,
        },
        {
          id: "new-session",
          title: "New chat",
          description: "Start a fresh operator thread.",
          meta: "Session",
          icon: icons.plus,
          onSelect: () => {
            dismissCommandSurface(false);
            onNewSession();
          },
        },
        {
          id: "open-models",
          title: "Model",
          description: "Switch or inspect mounted model capabilities.",
          meta: selectedModel || "Model",
          icon: icons.cube,
          onSelect: () => openCommandSearch("model"),
        },
        {
          id: "toggle-plan-mode",
          title: planMode ? "Exit plan mode" : "Plan mode",
          description: planMode
            ? "Return to normal execution mode."
            : "Turn the next request into a plan-first request.",
          meta: planMode ? "On" : "Off",
          icon: icons.sidebar,
          active: planMode,
          onSelect: () => {
            dismissCommandSurface(false);
            onTogglePlanMode(!planMode);
          },
        },
        {
          id: "open-skills-search",
          title: "Skills",
          description: "Find available skills and capability packs.",
          meta: "Search",
          icon: icons.sparkles,
          onSelect: () => openCommandSearch("skill"),
        },
        {
          id: "open-capabilities",
          title: "Capabilities",
          description: "Review connectors, tools, skills, and authority posture.",
          meta: "Connectors",
          icon: icons.code,
          onSelect: () => {
            dismissCommandSurface(false);
            void openReviewCapabilities();
          },
        },
        {
          id: "open-workflows-search",
          title: "Workflows",
          description: "Find runnable workspace workflows.",
          meta: "Search",
          icon: icons.globe,
          onSelect: () => openCommandSearch("workflow"),
        },
        {
          id: "open-settings",
          title: "Settings",
          description: "Manage models, workspaces, and skill sources.",
          icon: icons.settings,
          onSelect: () => {
            dismissCommandSurface(false);
            onOpenSettings();
          },
        },
      );
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        "New Session",
        "Start a fresh Chat run",
        "new session chat thread",
      )
    ) {
      commandItems.push({
        id: "new-session",
        title: "New Session",
        description: "Reset the composer and start a fresh operator thread.",
        meta: "Session",
        icon: icons.plus,
        onSelect: () => {
          dismissCommandSurface(false);
          onNewSession();
        },
      });
    }

    const gateLabel = isGated ? "Open Gate" : "Open Queue";
    const gateDescription = isGated
      ? "Jump to the governed approval surface for this run."
      : "Open the compact queue and approval shell.";
    if (
      !slashQuickMode &&
      (isGated || hasTaskBlocker || commandQuery.length > 0) &&
      matchesSlashQuery(commandQuery, gateLabel, gateDescription, "gate queue approval")
    ) {
      commandItems.push({
        id: "open-gate",
        title: gateLabel,
        description: gateDescription,
        meta: isGated ? "Approval" : "Queue",
        icon: icons.lock,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenGate();
        },
      });
    }

    if (
      !slashQuickMode &&
      hasTaskReview &&
      matchesSlashQuery(
        commandQuery,
        "Review Tasks",
        "Inspect runtime checklist, blockers, and task output",
        "tasks task checklist runtime output blocker review",
      )
    ) {
      commandItems.push({
        id: "open-tasks",
        title: "Review Tasks",
        description:
          "Review the current run, checklist state, blockers, and task output.",
        meta: "Runtime",
        icon: icons.sidebar,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenView("tasks");
        },
      });
    }

    if (
      !slashQuickMode &&
      hasTaskBlocker &&
      matchesSlashQuery(
        commandQuery,
        "Review Blocker",
        "Jump to the blocker or approval surface for this task",
        "blocker approval clarification credential gate review",
      )
    ) {
      commandItems.push({
        id: "review-blocker",
        title: "Review Blocker",
        description:
          "Open the task review surface for approvals, clarification, or credentials.",
        meta: "Runtime",
        icon: icons.alert,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenView("tasks");
        },
      });
    }

    if (
      !slashQuickMode &&
      recommendedClarificationOptionId &&
      matchesSlashQuery(
        commandQuery,
        "Choose Recommended Clarification",
        "Submit the recommended clarification option for the active task",
        "clarification recommended answer blocker task",
      )
    ) {
      commandItems.push({
        id: "choose-recommended-clarification",
        title: "Choose Recommended Clarification",
        description:
          "Submit the recommended clarification option from the active task blocker.",
        meta: "Runtime",
        icon: icons.sparkles,
        onSelect: () => {
          if (!onSubmitClarification) {
            return;
          }
          void onSubmitClarification(recommendedClarificationOptionId, "").catch(
            console.error,
          );
          dismissCommandSurface();
        },
      });
    }

    if (
      !slashQuickMode &&
      task?.credential_request &&
      matchesSlashQuery(
        commandQuery,
        "Provide Credential",
        "Open the task drawer and provide the required credential",
        "credential password blocker task sudo",
      )
    ) {
      commandItems.push({
        id: "provide-credential",
        title: "Provide Credential",
        description:
          "Open the task review drawer and provide the credential this run needs.",
        meta: "Runtime",
        icon: icons.lock,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenView("tasks");
        },
      });
    }

    if (
      !slashQuickMode &&
      canStopTask &&
      matchesSlashQuery(
        commandQuery,
        "Stop Current Task",
        "Stop the active background task or run",
        "stop task run background cancel",
      )
    ) {
      commandItems.push({
        id: "stop-current-task",
        title: "Stop Current Task",
        description: "Stop the active runtime task from the primary shell.",
        meta: "Runtime",
        icon: icons.stop,
        onSelect: () => {
          onStop();
          dismissCommandSurface();
        },
      });
    }

    if (!slashQuickMode) {
      commandItems.push(
        ...buildSharedSessionCommandItems({
          commandQuery,
          hasBranchSurface,
          sessions,
          hasSessionContext,
          hasPermissionRequest,
          hasReplSurface,
          task,
          mcpContributionCount,
          capabilityRegistryStatus,
          capabilityRegistryExtensionCount:
            capabilityRegistrySnapshot?.extensionManifests.length ?? 0,
          hookContributionCount,
          hasRewindSurface,
          planMode,
          vimModeLabel: vimModeSnapshot.modeLabel,
          hasWorkerContext,
          workerCount,
          hasFileSurface,
          hasArtifacts,
          artifactCount,
          dismissCommandSurface,
          onOpenView,
          onOpenValidationEvidence,
          onOpenSettings,
          onTogglePlanMode,
        }),
      );
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        vimModeSnapshot.enabled ? "Disable Vim Mode" : "Enable Vim Mode",
        "Toggle between vim-style preview posture and standard shell input.",
        "vim vi modal normal insert editor mode",
      )
    ) {
      commandItems.push({
        id: vimModeSnapshot.enabled ? "disable-vim-mode" : "enable-vim-mode",
        title: vimModeSnapshot.enabled ? "Disable Vim Mode" : "Enable Vim Mode",
        description: vimModeSnapshot.enabled
          ? "Return Chat to the standard shell input posture."
          : "Enable the vim-style preview posture for this shell session.",
        meta: vimModeSnapshot.enabled ? vimModeSnapshot.modeLabel : "Currently disabled",
        icon: icons.code,
        onSelect: () => {
          toggleVimMode();
          dismissCommandSurface();
        },
      });
    }

    if (
      !slashQuickMode &&
      lastStableSession &&
      matchesSlashQuery(
        commandQuery,
        "Rewind to Last Stable Session",
        "Reattach the last retained session that is no longer actively running",
        "rewind history stable session",
      )
    ) {
      commandItems.push({
        id: "rewind-last-stable-session",
        title: "Rewind to Last Stable Session",
        description:
          "Reattach the last retained stable session without deleting stored evidence.",
        meta: sessionResumeContext(lastStableSession) || "History",
        icon: icons.history,
        onSelect: () => {
          dismissCommandSurface(false);
          onLoadSession(lastStableSession.session_id);
        },
      });
    }

    if (
      !slashQuickMode &&
      hasPermissionRequest &&
      matchesSlashQuery(
        commandQuery,
        "Review Pending Request",
        "Open live permission blockers and approval posture",
        "permissions approvals gate blocker",
      )
    ) {
      commandItems.push({
        id: "review-pending-permission-request",
        title: "Review Pending Request",
        description:
          "Open the live permissions drawer on the current approval or clarification blocker.",
        meta: "Permissions",
        icon: icons.lock,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenView("permissions");
        },
      });
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        "Open Permission Profiles",
        "Open the permissions drawer on session authority profiles",
        "permissions profiles policy posture safer autonomous expert",
      )
    ) {
      commandItems.push({
        id: "open-permission-profiles",
        title: "Open Permission Profiles",
        description:
          "Open the live permissions drawer and review curated session authority profiles.",
        meta: currentPermissionProfile?.label ?? "Permissions",
        icon: icons.lock,
        onSelect: () => {
          dismissCommandSurface(false);
          onOpenView("permissions");
        },
      });
    }

    permissionProfiles.forEach((profile) => {
      if (slashQuickMode) {
        return;
      }

      if (
        !matchesSlashQuery(
          commandQuery,
          `Use ${profile.label} Profile`,
          profile.summary,
          profile.detail,
          profile.id,
          "permissions profile policy posture safer autonomous expert guided",
        )
      ) {
        return;
      }

      const isCurrent = currentPermissionProfileId === profile.id;
      const isApplying = applyingPermissionProfileId === profile.id;
      commandItems.push({
        id: `use-permission-profile-${profile.id}`,
        title: `Use ${profile.label} Profile`,
        description: isCurrent
          ? `${profile.label} is already the active session posture.`
          : profile.summary,
        meta: isApplying
          ? "Applying"
          : isCurrent
            ? "Current"
            : "Permissions",
        icon: icons.lock,
        disabled: isCurrent || isApplying,
        onSelect:
          isCurrent || isApplying
            ? undefined
            : () => {
                void applyPermissionProfile(profile.id)
                  .then(() => {
                    dismissCommandSurface();
                  })
                  .catch(console.error);
              },
      });
    });

    const autoContextLabel = autoContext ? "Disable Auto Context" : "Enable Auto Context";
    const autoContextDescription = autoContext
      ? "Stop pulling nearby thread context into the prompt."
      : "Include nearby thread context automatically.";
    if (
      !slashQuickMode &&
      matchesSlashQuery(commandQuery, autoContextLabel, autoContextDescription, "context")
    ) {
      commandItems.push({
        id: "toggle-auto-context",
        title: autoContextLabel,
        description: autoContextDescription,
        meta: autoContext ? "On" : "Off",
        icon: icons.sparkles,
        active: autoContext,
        onSelect: () => {
          onToggleAutoContext();
          dismissCommandSurface();
        },
      });
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        "Open Catalog",
        "Inspect runtime catalog entries in Chat",
        "catalog chat runtime gallery",
      )
    ) {
      commandItems.push({
        id: "open-catalog",
        title: "Open Catalog",
        description: "Inspect the live runtime catalog in Chat.",
        icon: icons.globe,
        meta: "Chat",
        onSelect: () => {
          dismissCommandSurface(false);
          void openCompanionCatalog();
        },
      });
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        "Open Capabilities",
        "Inspect live connectors, skills, extensions, and runtime trust posture",
        "capabilities connectors skills extensions trust chat",
      )
    ) {
      commandItems.push({
        id: "open-capabilities",
        title: "Open Capabilities",
        description:
          "Inspect live connectors, skills, extensions, and trust posture in Chat.",
        icon: icons.code,
        meta: "Chat",
        onSelect: () => {
          dismissCommandSurface(false);
          void openReviewCapabilities();
        },
      });
    }

    if (
      !slashQuickMode &&
      matchesSlashQuery(
        commandQuery,
        "Open Policy",
        "Inspect Shield policy and connector authority tiers",
        "policy shield trust connectors chat",
      )
    ) {
      commandItems.push({
        id: "open-policy",
        title: "Open Policy",
        description:
          "Inspect Shield policy, connector authority tiers, and governed posture.",
        icon: icons.lock,
        meta: "Chat",
        onSelect: () => {
          dismissCommandSurface(false);
          void openReviewPolicyCenter();
        },
      });
    }

    const recentSessionItems = shouldShowSearchBackedItems
      ? buildRecentSessionItems({
          sessions,
          currentSessionId,
          commandQuery,
          dismissCommandSurface,
          onLoadSession,
        })
      : [];

    const runtimeCatalogItems: CommandMenuItem[] =
      !shouldShowSearchBackedItems
        ? []
        : runtimeCatalogStatus === "loading"
        ? [
            {
              id: "catalog-loading",
              title: "Loading Runtime Catalog",
              description: "Fetching live runtime catalog entries...",
              icon: icons.globe,
              disabled: true,
            },
          ]
        : runtimeCatalogStatus === "error"
          ? [
              {
                id: "catalog-error",
                title: "Catalog Unavailable",
                description: "Open Chat to inspect runtime catalog status.",
                icon: icons.globe,
                meta: "Chat",
                onSelect: () => {
                  dismissCommandSurface(false);
                  void openCompanionCatalog();
                },
              },
            ]
          : runtimeCatalogEntries
              .filter((entry) =>
                matchesSlashQuery(
                  commandQuery,
                  entry.name,
                  entry.description,
                  entry.ownerLabel,
                  entry.entryKind,
                  entry.runtimeNotes,
                  entry.statusLabel,
                  "runtime catalog",
                ),
              )
              .slice(0, 6)
              .map<CommandMenuItem>((entry) => ({
                id: `catalog-${entry.id}`,
                title: entry.name,
                description: entry.description || entry.runtimeNotes,
                meta:
                  entry.statusLabel ||
                  humanizeLabel(entry.entryKind) ||
                  "Catalog entry",
                icon: icons.cube,
                onSelect: () => {
                  dismissCommandSurface(false);
                  void openCompanionCatalog();
                },
              }));

    const liveToolItems: CommandMenuItem[] =
      !shouldShowSearchBackedItems
        ? []
        : liveToolsStatus === "loading"
        ? [
            {
              id: "live-tools-loading",
              title: "Loading Live Tools",
              description: "Querying connector-backed tool affordances...",
              icon: icons.code,
              disabled: true,
            },
          ]
        : liveToolsStatus === "error"
          ? [
              {
                id: "live-tools-error",
                title: "Live Tools Unavailable",
                description: "Open Chat capabilities to inspect connector posture.",
                icon: icons.code,
                onSelect: () => {
                  dismissCommandSurface(false);
                  void openReviewCapabilities();
                },
              },
            ]
          : liveTools
              .filter(({ connector, action }) =>
                matchesSlashQuery(
                  commandQuery,
                  action.label,
                  action.description,
                  action.toolName,
                  action.service,
                  action.serviceLabel,
                  action.kind,
                  connector.name,
                  connector.provider,
                  connector.status,
                  "tool connector capability action",
                ),
              )
              .slice(0, 8)
              .map<CommandMenuItem>(({ connector, action }) => ({
                id: `tool-${connector.id}-${action.id}`,
                title: action.label,
                description:
                  action.description ||
                  `${connector.name} exposes this ${humanizeLabel(action.kind).toLowerCase()} action.`,
                meta: connector.name,
                icon: icons.code,
                onSelect: () => {
                  dismissCommandSurface(false);
                  void openCompanionCapabilityActions(connector.id);
                },
              }));

    const modelItems = shouldShowSearchBackedItems
      ? buildModelSlashItems({
          modelOptions,
          selectedModel,
          commandQuery,
          onSelectModel,
          dismissCommandSurface,
        })
      : [];

    const workspaceItems = shouldShowSearchBackedItems
      ? buildWorkspaceSlashItems({
          workspaceOptions,
          workspaceMode,
          commandQuery,
          onSelectWorkspaceMode,
          dismissCommandSurface,
        })
      : [];
    const workflowItems: CommandMenuItem[] =
      !shouldShowSearchBackedItems
        ? []
        : workspaceWorkflowsStatus === "loading"
        ? [
            {
              id: "workflow-loading",
              title: "Loading Workspace Workflows",
              description: "Scanning .agents/.agent workflow roots in the active workspace...",
              icon: icons.sparkles,
              disabled: true,
            },
          ]
        : workspaceWorkflowsStatus === "error"
          ? [
              {
                id: "workflow-error",
                title: "Workspace Workflows Unavailable",
                description:
                  "Workflow discovery failed. You can still type a slash workflow command manually.",
                icon: icons.alert,
                disabled: true,
              },
            ]
          : buildWorkspaceWorkflowItems({
              workflows: workspaceWorkflows,
              commandQuery,
              onSelectWorkflow: insertWorkflowSlashCommand,
            });

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
    const registryBackedSkills = sortedSkills.map((skill) => ({
      skill,
      registryEntry: resolveCapabilityRegistryEntryForCatalogSkill(
        capabilityRegistryEntryLookup,
        skill,
      ),
    }));

    const skillItems: CommandMenuItem[] =
      !shouldShowSearchBackedItems
        ? []
        : capabilityRegistryStatus === "loading" && skillCatalog.length === 0
        ? [
            {
              id: "skills-loading",
              title: "Loading Capability Fabric",
              description: "Fetching the runtime-owned skill registry...",
              icon: icons.code,
              disabled: true,
            },
          ]
        : capabilityRegistryStatus === "error" && skillCatalog.length === 0
          ? [
              {
                id: "skills-error",
                title: "Skills Unavailable",
                description:
                  capabilityRegistryError ||
                  "Open Capabilities to inspect skill sources and runtime posture.",
                icon: icons.code,
                onSelect: () => {
                  dismissCommandSurface(false);
                  void openReviewCapabilities();
                },
              },
            ]
          : registryBackedSkills
              .filter(({ skill, registryEntry }) =>
                matchesSlashQuery(
                  commandQuery,
                  skill.name,
                  skill.description,
                  skill.definition?.description,
                  skill.source_type,
                  skill.lifecycle_state,
                  registryEntry?.authority.tierLabel,
                  registryEntry?.authority.governedProfileLabel,
                  registryEntry?.lease.modeLabel,
                  registryEntry?.lease.availabilityLabel,
                  registryEntry?.whySelectable,
                  registryEntry?.sourceLabel,
                ),
              )
              .slice(0, 8)
              .map<CommandMenuItem>(({ skill, registryEntry }) => ({
                id: `skill-${skill.skill_hash}`,
                title: skill.name,
                description: capabilityDescriptionForSkill(skill, registryEntry),
                icon: icons.code,
                meta: capabilityMetaLabel(
                  registryEntry,
                  sourceLabelForSkill(skill),
                ),
                onSelect: () => {
                  insertSkillGuidance(skill.name);
                },
              }));

    if (toolPaletteMode) {
      const builtInToolItems: CommandMenuItem[] = [
        {
          id: "tool-auto-context",
          title: autoContext ? "Auto context enabled" : "Auto context",
          description: autoContext
            ? "Nearby runtime and workspace context is attached automatically."
            : "Attach nearby runtime and workspace context automatically.",
          meta: autoContext ? "Enabled" : "Built-In",
          icon: icons.sparkles,
          active: autoContext,
          onSelect: () => {
            onToggleAutoContext();
            dismissCommandSurface();
          },
        },
        {
          id: "tool-workspace-context",
          title: "Workspace context",
          description: "Choose files, editor state, artifacts, or retained evidence.",
          meta: "Context",
          icon: icons.paperclip,
          onSelect: () => openCommandSearch("context"),
        },
        {
          id: "tool-manage-capabilities",
          title: "Manage tools",
          description: "Review callable connectors, skills, and authority posture.",
          meta: "Capabilities",
          icon: icons.code,
          onSelect: () => {
            dismissCommandSurface(false);
            void openReviewCapabilities();
          },
        },
      ];

      return [
        { id: "built-in-tools", title: "Built-In", items: builtInToolItems },
        { id: "live-tools", title: "Live Tools", items: liveToolItems },
        { id: "runtime-catalog", title: "Runtime Catalog", items: runtimeCatalogItems },
        { id: "skills", title: "Skills", items: skillItems },
      ];
    }

    return [
      {
        id: "commands",
        title: slashQuickMode ? undefined : "Commands",
        items: commandItems,
      },
      { id: "sessions", title: "Recent Sessions", items: recentSessionItems },
      { id: "live-tools", title: "Live Tools", items: liveToolItems },
      { id: "runtime-catalog", title: "Runtime Catalog", items: runtimeCatalogItems },
      { id: "workspace-workflows", title: "Workflows", items: workflowItems },
      { id: "models", title: "Model", items: modelItems },
      { id: "workspaces", title: "Workspace", items: workspaceItems },
      { id: "skills", title: "Skills", items: skillItems },
    ];
  }, [
    autoContext,
    artifactCount,
    currentSessionId,
    hasArtifacts,
    hasFileSurface,
    handleContextTrigger,
    hasPermissionRequest,
    hasReplSurface,
    hasRewindSurface,
    hasSessionContext,
    hasTaskBlocker,
    hasTaskReview,
    hasWorkerContext,
    isGated,
    canStopTask,
    lastStableSession,
    recommendedClarificationOptionId,
    liveTools,
    liveToolsStatus,
    modelOptions,
    capabilityRegistryEntryLookup,
    capabilityRegistryError,
    capabilityRegistryStatus,
    onOpenSettings,
    onLoadSession,
    onNewSession,
    onOpenGate,
    onOpenValidationEvidence,
    onOpenView,
    openCommandSearch,
    onSubmitClarification,
    onStop,
    onSelectModel,
    onSelectWorkspaceMode,
    onToggleAutoContext,
    dismissCommandSurface,
    insertSkillGuidance,
    insertWorkflowSlashCommand,
    permissionProfiles,
    currentPermissionProfile,
    currentPermissionProfileId,
    applyingPermissionProfileId,
    applyPermissionProfile,
    runtimeCatalogEntries,
    runtimeCatalogStatus,
    selectedModel,
    shouldShowSearchBackedItems,
    sessions,
    skillCatalog,
    slashQuickMode,
    task,
    toolPaletteMode,
    commandQuery,
    toggleVimMode,
    vimModeSnapshot.enabled,
    workerCount,
    workspaceWorkflows,
    workspaceWorkflowsStatus,
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

  const activeHighlightedItemId =
    commandsMenuOpen && slashActionItems.length > 0
      ? highlightedItemId &&
        slashActionItems.some((item) => item.id === highlightedItemId)
        ? highlightedItemId
        : slashActionItems[0]?.id ?? null
      : null;

  const handleCommandSurfaceKeyDown = useCallback(
    (event: CommandSurfaceKeyEvent) => {
      if (!commandsMenuOpen) {
        return false;
      }

      if (event.key === "Escape") {
        event.preventDefault();
        setCommandPaletteQuery("");
        setSlashContext(null);
        setActiveDropdown(null);
        if (searchablePaletteMode) {
          focusComposer();
        }
        return true;
      }

      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (slashActionItems.length === 0) {
          return true;
        }

        const currentIndex = Math.max(
          0,
          slashActionItems.findIndex(
            (item) => item.id === activeHighlightedItemId,
          ),
        );
        const delta = event.key === "ArrowDown" ? 1 : -1;
        const nextIndex =
          (currentIndex + delta + slashActionItems.length) %
          slashActionItems.length;
        setHighlightedItemId(slashActionItems[nextIndex]?.id ?? null);
        return true;
      }

      if (event.key === "Enter" && !event.shiftKey) {
        const selectedItem =
          slashActionItems.find((item) => item.id === activeHighlightedItemId) ??
          slashActionItems[0];
        if (!selectedItem?.onSelect) {
          return false;
        }

        event.preventDefault();
        selectedItem.onSelect();
        return true;
      }

      return false;
    },
    [
      activeHighlightedItemId,
      commandsMenuOpen,
      focusComposer,
      searchablePaletteMode,
      setActiveDropdown,
      slashActionItems,
    ],
  );

  const handleTextareaChange = useCallback(
    (event: ChangeEvent<HTMLTextAreaElement>) => {
      setPendingVimOperator(null);
      setPendingVimMotionPrefix(null);
      setPendingVimCount(null);
      onInputChange(event);
      syncSlashMenu(event.target.value, event.target.selectionStart ?? event.target.value.length);
    },
    [onInputChange, syncSlashMenu],
  );

  const handleTextareaKeyDown = useCallback(
    (event: KeyboardEvent<HTMLTextAreaElement>) => {
      if (handleCommandSurfaceKeyDown(event)) {
        return;
      }

      if (vimModeSnapshot.enabled) {
        const textarea = event.currentTarget;
        const selectionStart = textarea.selectionStart ?? textarea.value.length;
        const selectionEnd = textarea.selectionEnd ?? selectionStart;
        const composerValue = textarea.value;

        if (event.key === "Escape") {
          event.preventDefault();
          setPendingVimOperator(null);
          setPendingVimMotionPrefix(null);
          setPendingVimCount(null);
          enterNormalMode();
          return;
        }

        if (vimModeSnapshot.modeId === "vim_normal") {
          const outcome = applyChatVimNormalKey(
            {
              value: composerValue,
              selectionStart,
              selectionEnd,
              pendingOperator: pendingVimOperator,
              pendingMotionPrefix: pendingVimMotionPrefix,
              pendingCount: pendingVimCount,
              lastCommand: lastVimCommand,
            },
            {
              key: event.key,
              code: event.code,
              shiftKey: event.shiftKey,
              altKey: event.altKey,
              ctrlKey: event.ctrlKey,
              metaKey: event.metaKey,
            },
          );

          if (outcome.handled) {
            event.preventDefault();
            setPendingVimOperator(outcome.pendingOperator);
            setPendingVimMotionPrefix(outcome.pendingMotionPrefix);
            setPendingVimCount(outcome.pendingCount);
            setLastVimCommand(outcome.lastCommand);
            if (outcome.value !== composerValue) {
              setIntent(outcome.value);
            }
            window.requestAnimationFrame(() => {
              const nextTextarea = inputRef.current;
              adjustTextareaHeight(nextTextarea);
              nextTextarea?.focus();
              nextTextarea?.setSelectionRange(
                outcome.selectionStart,
                outcome.selectionEnd,
              );
              syncSlashMenu(outcome.value, outcome.selectionEnd);
            });
            if (outcome.enterInsertMode) {
              enterInsertMode();
            }
            return;
          }
        }
      }

      onInputKeyDown(event);
    },
    [
      enterInsertMode,
      enterNormalMode,
      handleCommandSurfaceKeyDown,
      inputRef,
      lastVimCommand,
      onInputKeyDown,
      pendingVimCount,
      pendingVimMotionPrefix,
      pendingVimOperator,
      setIntent,
      setLastVimCommand,
      setPendingVimCount,
      setPendingVimMotionPrefix,
      setPendingVimOperator,
      syncSlashMenu,
      vimModeSnapshot.enabled,
      vimModeSnapshot.modeId,
    ],
  );

  const handleTextareaSelection = useCallback(
    (event: ChangeEvent<HTMLTextAreaElement> | SyntheticEvent<HTMLTextAreaElement>) => {
      const textarea = event.currentTarget;
      syncSlashMenu(textarea.value, textarea.selectionStart ?? textarea.value.length);
    },
    [syncSlashMenu],
  );

  const workspaceModeLabel =
    workspaceOptions.find((option) => option.value === workspaceMode)?.label ??
    (workspaceMode || "Local");
  const modelLabel =
    modelOptions.find((option) => option.value === selectedModel)?.label ??
    (selectedModel || "Agent");
  const commandMenu =
    commandsMenuOpen && !inputLockedByCredential ? (
      <CommandMenu
        sections={actionSections}
        mode={searchablePaletteMode ? "palette" : "slash"}
        placement={searchablePaletteMode ? "command-center" : "composer"}
        style={searchablePaletteMode ? commandCenterMenuStyle : undefined}
        ariaLabel={toolPaletteMode ? "Tool picker" : undefined}
        selectedItemId={activeHighlightedItemId}
        onHighlightItem={setHighlightedItemId}
        searchQuery={searchablePaletteMode ? commandPaletteQuery : undefined}
        searchPlaceholder={
          toolPaletteMode
            ? "Select a tool"
            : "Search commands, sessions, live tools, and skills"
        }
        onSearchKeyDown={
          searchablePaletteMode
            ? (event) => {
                void handleCommandSurfaceKeyDown(event);
              }
            : undefined
        }
        onSearchQueryChange={
          searchablePaletteMode ? setCommandPaletteQuery : undefined
        }
        emptyState={
          commandQuery
            ? `No ${toolPaletteMode ? "tools" : "commands or skills"} match "${
                searchablePaletteMode
                  ? commandPaletteQuery
                  : slashContext?.query ?? ""
              }".`
            : toolPaletteMode
              ? "No tools are available right now."
              : "No commands available right now."
        }
      />
    ) : null;
  const commandCenterMenuPortal =
    commandCenterMenuOpen && commandMenu && typeof document !== "undefined"
      ? createPortal(
          <div
            className="spot-command-center-menu-overlay"
            data-inspection-target="operator-command-center-menu"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) {
                dismissCommandSurface(false);
              }
            }}
          >
            {commandMenu}
          </div>,
          document.body,
        )
      : null;

  return (
    <div
      className={`spot-input-section ${inputFocused ? "focused" : ""} ${
        isDraggingFile ? "drag-active" : ""
      }`}
      data-inspection-target="operator-chat-composer"
    >
      {commandCenterMenuPortal}
      <div className="spot-input-wrapper" onMouseDown={handleComposerWrapperMouseDown}>
        {planMode ? (
          <div className="spot-plan-mode-banner">
            <div className="spot-plan-mode-banner__copy">
              <strong>Plan mode active</strong>
              <span>{planModeStatusCopy()}</span>
            </div>
            <button
              type="button"
              className="spot-action-btn spot-action-btn--active"
              onClick={() => onTogglePlanMode(false)}
              title="Exit plan mode"
            >
              {icons.x}
            </button>
          </div>
        ) : null}

        {!commandCenterMenuOpen ? commandMenu : null}

        {inputLockedByCredential ? (
          <ChatInputControls
            blocked={true}
            showPasswordPrompt={showPasswordPrompt}
            isRunning={isRunning}
            planMode={planMode}
            autoContext={autoContext}
            workspaceModeLabel={workspaceModeLabel}
            modelLabel={modelLabel}
            intent={intent}
            isGated={isGated}
            inputLockedByCredential={inputLockedByCredential}
            onStop={onStop}
            onTogglePlanMode={() => onTogglePlanMode()}
            onTriggerContext={handleContextTrigger}
            onTriggerCommands={handleCommandTrigger}
            onTriggerCommandPalette={handleCommandPaletteTrigger}
            onTriggerTools={handleToolPaletteTrigger}
            onSubmit={onSubmit}
          />
        ) : (
          <>
            <textarea
              ref={inputRef}
              className="spot-input"
              aria-label="Operator chat composer"
              data-inspection-target="operator-chat-composer-input"
              data-testid="operator-chat-composer-input"
              placeholder={
                planMode
                  ? planModePlaceholder(placeholder)
                  : placeholder || "How can I help you today?"
              }
              value={intent}
              onChange={handleTextareaChange}
              onKeyDown={handleTextareaKeyDown}
              onClick={handleTextareaSelection}
              onKeyUp={handleTextareaSelection}
              onSelect={handleTextareaSelection}
              onFocus={handleTextareaFocus}
              onBlur={() => setInputFocused(false)}
              rows={1}
            />

            <ChatInputControls
              blocked={false}
              showPasswordPrompt={showPasswordPrompt}
              isRunning={isRunning}
              planMode={planMode}
              autoContext={autoContext}
              workspaceModeLabel={workspaceModeLabel}
              modelLabel={modelLabel}
              intent={intent}
              isGated={isGated}
              inputLockedByCredential={inputLockedByCredential}
              onStop={onStop}
              onTogglePlanMode={() => onTogglePlanMode()}
              onTriggerContext={handleContextTrigger}
              onTriggerCommands={handleCommandTrigger}
              onTriggerCommandPalette={handleCommandPaletteTrigger}
              onTriggerTools={handleToolPaletteTrigger}
              onSubmit={onSubmit}
            />
          </>
        )}
      </div>
    </div>
  );
}
