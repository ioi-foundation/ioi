import { useCallback, useEffect, useState } from "react";
import type {
  ChangeEvent,
  KeyboardEvent,
  RefObject,
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
  const [intent, setIntent] = useState("");
  const [localHistory, setLocalHistory] = useState<ChatMessage[]>([]);
  const [autoContext, setAutoContext] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [workspaceMode, setWorkspaceMode] = useState("local");
  const [selectedModel, setSelectedModel] = useState("GPT-4o");
  const [chatEvents, setChatEvents] = useState<ChatEvent[]>([]);
  const [artifactHubView, setArtifactHubView] = useState<ArtifactHubViewKey | null>(null);
  const [artifactHubTurnId, setArtifactHubTurnId] = useState<string | null>(null);
  const [runtimePasswordPending, setRuntimePasswordPending] = useState(false);
  const [runtimePasswordSessionId, setRuntimePasswordSessionId] = useState<string | null>(null);
  const [inputFocused, setInputFocused] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [isDraggingFile] = useState(false);

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
  }, []);

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
    [setSelectedArtifactId, toggleArtifactPanel],
  );

  const handleSubmit = useCallback(async () => {
    const text = intent.trim();
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
    setIntent("");

    if (inputRef.current) {
      inputRef.current.style.height = "auto";
    }

    if (task && task.phase === "Running") return;

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
  }, [continueTask, inputRef, intent, isStudioVariant, openStudio, startTask, task]);

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
    [task?.id, task?.session_id],
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
  }, [inputRef, resetSession, setSelectedArtifactId, toggleArtifactPanel]);

  const handleGlobalClick = useCallback(() => {
    if (activeDropdown) setActiveDropdown(null);
  }, [activeDropdown]);

  const handleInputChange = useCallback((e: ChangeEvent<HTMLTextAreaElement>) => {
    setIntent(e.target.value);
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
  }, []);

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
    intent,
    setIntent,
    localHistory,
    autoContext,
    setAutoContext,
    activeDropdown,
    setActiveDropdown,
    sessions,
    workspaceMode,
    setWorkspaceMode,
    selectedModel,
    setSelectedModel,
    chatEvents,
    setChatEvents,
    artifactHubView,
    setArtifactHubView,
    artifactHubTurnId,
    setArtifactHubTurnId,
    runtimePasswordPending,
    setRuntimePasswordPending,
    runtimePasswordSessionId,
    setRuntimePasswordSessionId,
    inputFocused,
    setInputFocused,
    searchQuery,
    setSearchQuery,
    isDraggingFile,
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
