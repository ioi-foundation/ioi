import { useCallback, useEffect, useReducer } from "react";
import type {
  ChangeEvent,
  Dispatch,
  KeyboardEvent,
  RefObject,
  SetStateAction,
} from "react";
import { emit } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { initEventListeners } from "../../../store/agentStore";
import type {
  ArtifactHubViewKey,
  ChatMessage,
  SessionSummary,
} from "../../../types";
import type { AgentTask } from "../../../store/agentStore";
import type { ChatEvent } from "./useGateState";

type UseSpotlightSessionOptions = {
  isStudioVariant: boolean;
  task: AgentTask | null;
  inputRef: RefObject<HTMLTextAreaElement>;
  startTask: (intent: string) => Promise<AgentTask | null>;
  continueTask: (sessionId: string, input: string) => Promise<void>;
  resetSession: () => void;
  setSelectedArtifactId: (artifactId: string | null) => void;
  toggleArtifactPanel: (visible?: boolean) => Promise<void>;
  loadThreadEvents: (threadId: string, limit?: number, cursor?: number) => Promise<unknown>;
  loadThreadArtifacts: (threadId: string) => Promise<unknown>;
};

type SessionUiState = {
  intent: string;
  localHistory: ChatMessage[];
  autoContext: boolean;
  activeDropdown: string | null;
  sessions: SessionSummary[];
  workspaceMode: string;
  selectedModel: string;
  chatEvents: ChatEvent[];
  artifactHubView: ArtifactHubViewKey | null;
  artifactHubTurnId: string | null;
  runtimePasswordPending: boolean;
  runtimePasswordSessionId: string | null;
  inputFocused: boolean;
  searchQuery: string;
  isDraggingFile: boolean;
};

type SessionUiValue = SessionUiState[keyof SessionUiState];

type SessionUiAction = {
  type: "set";
  key: keyof SessionUiState;
  value: SetStateAction<SessionUiValue>;
};

const INITIAL_STATE: SessionUiState = {
  intent: "",
  localHistory: [],
  autoContext: true,
  activeDropdown: null,
  sessions: [],
  workspaceMode: "local",
  selectedModel: "GPT-4o",
  chatEvents: [],
  artifactHubView: null,
  artifactHubTurnId: null,
  runtimePasswordPending: false,
  runtimePasswordSessionId: null,
  inputFocused: false,
  searchQuery: "",
  isDraggingFile: false,
};

function sessionUiReducer(
  state: SessionUiState,
  action: SessionUiAction,
): SessionUiState {
  if (action.type !== "set") {
    return state;
  }

  const current = state[action.key] as SessionUiValue;
  const next =
    typeof action.value === "function"
      ? (action.value as (prev: SessionUiValue) => SessionUiValue)(current)
      : action.value;

  if (Object.is(current, next)) {
    return state;
  }

  return {
    ...state,
    [action.key]: next,
  } as SessionUiState;
}

export function useSpotlightSession({
  isStudioVariant,
  task,
  inputRef,
  startTask,
  continueTask,
  resetSession,
  setSelectedArtifactId,
  toggleArtifactPanel,
  loadThreadEvents,
  loadThreadArtifacts,
}: UseSpotlightSessionOptions) {
  const [state, dispatch] = useReducer(sessionUiReducer, INITIAL_STATE);

  const setField = useCallback(
    <K extends keyof SessionUiState>(
      key: K,
      value: SetStateAction<SessionUiState[K]>,
    ) => {
      dispatch({ type: "set", key, value: value as SetStateAction<SessionUiValue> });
    },
    [],
  );

  const setIntent = useCallback((value: SetStateAction<string>) => {
    setField("intent", value);
  }, [setField]);
  const setAutoContext = useCallback((value: SetStateAction<boolean>) => {
    setField("autoContext", value);
  }, [setField]);
  const setActiveDropdown = useCallback((value: SetStateAction<string | null>) => {
    setField("activeDropdown", value);
  }, [setField]);
  const setSessions = useCallback((value: SetStateAction<SessionSummary[]>) => {
    setField("sessions", value);
  }, [setField]);
  const setWorkspaceMode = useCallback((value: SetStateAction<string>) => {
    setField("workspaceMode", value);
  }, [setField]);
  const setSelectedModel = useCallback((value: SetStateAction<string>) => {
    setField("selectedModel", value);
  }, [setField]);
  const setChatEvents: Dispatch<SetStateAction<ChatEvent[]>> = useCallback((value) => {
    setField("chatEvents", value);
  }, [setField]);
  const setArtifactHubView = useCallback((value: SetStateAction<ArtifactHubViewKey | null>) => {
    setField("artifactHubView", value);
  }, [setField]);
  const setArtifactHubTurnId = useCallback((value: SetStateAction<string | null>) => {
    setField("artifactHubTurnId", value);
  }, [setField]);
  const setRuntimePasswordPending: Dispatch<SetStateAction<boolean>> = useCallback((value) => {
    setField("runtimePasswordPending", value);
  }, [setField]);
  const setRuntimePasswordSessionId: Dispatch<SetStateAction<string | null>> = useCallback((value) => {
    setField("runtimePasswordSessionId", value);
  }, [setField]);
  const setInputFocused = useCallback((value: SetStateAction<boolean>) => {
    setField("inputFocused", value);
  }, [setField]);
  const setSearchQuery = useCallback((value: SetStateAction<string>) => {
    setField("searchQuery", value);
  }, [setField]);
  const setLocalHistory = useCallback((value: SetStateAction<ChatMessage[]>) => {
    setField("localHistory", value);
  }, [setField]);

  useEffect(() => {
    initEventListeners();
    window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
  }, [inputRef]);

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const history = await invoke<SessionSummary[]>("get_session_history");
        setSessions(history);
      } catch (e) {
        console.error("Failed to load history:", e);
      }
    };

    loadHistory();
    const interval = setInterval(loadHistory, 5000);
    return () => clearInterval(interval);
  }, [setSessions]);

  useEffect(() => {
    const threadId = task?.session_id || task?.id;
    if (!threadId) return;
    void loadThreadEvents(threadId).catch(console.error);
    void loadThreadArtifacts(threadId).catch(console.error);
  }, [loadThreadArtifacts, loadThreadEvents, task?.id, task?.session_id]);

  const openStudio = useCallback(
    async (targetView: string = "compose") => {
      const resolvedView = targetView === "settings" ? "marketplace" : targetView;
      await emit("request-studio-view", resolvedView);
      if (isStudioVariant) {
        return;
      }
      await invoke("hide_spotlight");
      await invoke("show_studio");
    },
    [isStudioVariant],
  );

  const handleLoadSession = useCallback(
    async (id: string) => {
      try {
        setArtifactHubView(null);
        setSelectedArtifactId(null);
        await toggleArtifactPanel(false);
        await invoke("load_session", { sessionId: id });
      } catch (e) {
        console.error("Failed to load session:", e);
      }
    },
    [setArtifactHubView, setSelectedArtifactId, toggleArtifactPanel],
  );

  const handleSubmit = useCallback(async () => {
    const text = state.intent.trim();
    if (!text) return;
    if (task?.phase === "Gate" || task?.pending_request_hash) return;
    if (task?.credential_request?.kind === "sudo_password") return;
    if (
      task?.clarification_request &&
      (() => {
        const step = (task?.current_step || "").toLowerCase();
        return (
          step.includes("waiting for clarification") ||
          step.includes("waiting for intent clarification") ||
          step.includes("wait_for_clarification")
        );
      })()
    ) {
      return;
    }
    if ((task?.current_step || "").toLowerCase().includes("waiting for sudo password")) {
      return;
    }

    if (task && task.phase === "Running") return;

    if (inputRef.current) {
      inputRef.current.style.height = "auto";
    }
    setIntent("");

    try {
      if (task && task.id && task.phase !== "Failed") {
        await continueTask(task.id || task.session_id || "", text);
      } else {
        if (
          !isStudioVariant &&
          (text.toLowerCase().includes("swarm") || text.toLowerCase().includes("team"))
        ) {
          await openStudio("autopilot");
        }
        await startTask(text);
      }
    } catch (e) {
      console.error(e);
    }
  }, [
    continueTask,
    inputRef,
    isStudioVariant,
    openStudio,
    setIntent,
    startTask,
    state.intent,
    task,
  ]);

  const handleSubmitRuntimePassword = useCallback(
    async (password: string) => {
      const sessionId = task?.id || task?.session_id;
      if (!sessionId) {
        throw new Error("No active session found");
      }
      setRuntimePasswordPending(true);
      setRuntimePasswordSessionId(sessionId);
      try {
        await invoke("submit_runtime_password", { sessionId, password });
      } catch (err) {
        setRuntimePasswordPending(false);
        setRuntimePasswordSessionId(null);
        throw err;
      }
    },
    [setRuntimePasswordPending, setRuntimePasswordSessionId, task?.id, task?.session_id],
  );

  const handleCancelRuntimePassword = useCallback(() => {
    // Keep task paused until user provides password or starts a new chat.
  }, []);

  const handleSubmitClarification = useCallback(
    async (optionId: string, otherText: string) => {
      const sessionId = task?.id || task?.session_id;
      if (!sessionId) {
        throw new Error("No active session found");
      }
      const request = task?.clarification_request;
      const selected = request?.options?.find((option) => option.id === optionId);
      const exactIdentifier = otherText.trim();
      const requestKind = request?.kind?.toLowerCase() ?? "";
      const isIntentResolution = requestKind === "intent_resolution";
      const intentStrategyFallback: Record<string, string> = {
        clarify_outcome: "Please continue with the current request outcome.",
        add_constraints: "Please continue with added constraints.",
        cancel_request: "Cancel this request.",
      };
      const structuredPrompt = isIntentResolution
        ? exactIdentifier ||
          selected?.description ||
          intentStrategyFallback[optionId] ||
          "Continue."
        : [
            "Clarification response:",
            request?.question ? `question=${request.question}` : undefined,
            request?.tool_name ? `tool_name=${request.tool_name}` : undefined,
            request?.failure_class ? `failure_class=${request.failure_class}` : undefined,
            request?.context_hint ? `context_hint=${request.context_hint}` : undefined,
            `strategy=${optionId}`,
            selected ? `strategy_label=${selected.label}` : undefined,
            exactIdentifier ? `exact_identifier=${exactIdentifier}` : undefined,
            "Execution constraints:",
            exactIdentifier
              ? `- Treat '${exactIdentifier}' as the authoritative target identifier for the next retry.`
              : "- Use the selected strategy to resolve target identity.",
            "- Retry once on the same session.",
            "- If still unresolved, provide concrete discovered candidates and why each failed.",
            "- Do not ask the same clarification again without new evidence.",
          ]
            .filter(Boolean)
            .join("\n");
      console.info("[Autopilot][Clarification] submit", {
        sessionId,
        optionId,
        exactIdentifier,
      });
      await continueTask(sessionId, structuredPrompt);
    },
    [continueTask, task],
  );

  const handleCancelClarification = useCallback(() => {
    const sessionId = task?.id || task?.session_id;
    if (!sessionId) return;
    console.info("[Autopilot][Clarification] cancel", { sessionId });
    void continueTask(
      sessionId,
      "User canceled clarification. Stop retries for this task, summarize the blocker, and remain idle until a new user request.",
    ).catch(console.error);
  }, [continueTask, task?.id, task?.session_id]);

  const handleNewChat = useCallback(() => {
    resetSession();
    setLocalHistory([]);
    setChatEvents([]);
    setArtifactHubView(null);
    setSelectedArtifactId(null);
    void toggleArtifactPanel(false);
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [
    inputRef,
    resetSession,
    setArtifactHubView,
    setChatEvents,
    setLocalHistory,
    setSelectedArtifactId,
    toggleArtifactPanel,
  ]);

  const handleGlobalClick = useCallback(() => {
    if (state.activeDropdown) setActiveDropdown(null);
  }, [setActiveDropdown, state.activeDropdown]);

  const handleInputChange = useCallback(
    (e: ChangeEvent<HTMLTextAreaElement>) => {
      setIntent(e.target.value);
      e.target.style.height = "auto";
      e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
    },
    [setIntent],
  );

  const handleInputKeyDown = useCallback(
    (e: KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Escape") {
        if (!isStudioVariant) {
          e.preventDefault();
          invoke("hide_spotlight").catch(console.error);
        }
        return;
      }

      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        void handleSubmit();
      }
    },
    [handleSubmit, isStudioVariant],
  );

  return {
    intent: state.intent,
    setIntent,
    localHistory: state.localHistory,
    autoContext: state.autoContext,
    setAutoContext,
    activeDropdown: state.activeDropdown,
    setActiveDropdown,
    sessions: state.sessions,
    workspaceMode: state.workspaceMode,
    setWorkspaceMode,
    selectedModel: state.selectedModel,
    setSelectedModel,
    chatEvents: state.chatEvents,
    setChatEvents,
    artifactHubView: state.artifactHubView,
    setArtifactHubView,
    artifactHubTurnId: state.artifactHubTurnId,
    setArtifactHubTurnId,
    runtimePasswordPending: state.runtimePasswordPending,
    setRuntimePasswordPending,
    runtimePasswordSessionId: state.runtimePasswordSessionId,
    setRuntimePasswordSessionId,
    inputFocused: state.inputFocused,
    setInputFocused,
    searchQuery: state.searchQuery,
    setSearchQuery,
    isDraggingFile: state.isDraggingFile,
    openStudio,
    handleLoadSession,
    handleSubmit,
    handleSubmitRuntimePassword,
    handleCancelRuntimePassword,
    handleSubmitClarification,
    handleCancelClarification,
    handleNewChat,
    handleGlobalClick,
    handleInputChange,
    handleInputKeyDown,
  };
}
