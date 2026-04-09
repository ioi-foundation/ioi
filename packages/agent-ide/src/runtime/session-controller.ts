import { create } from "zustand";
import type { StoreApi, UseBoundStore } from "zustand";
import type { AgentSessionEventName, AgentSessionProjection } from "./agent-runtime";
import {
  continueSessionTask,
  dismissSessionTask,
  getCurrentSessionTask,
  getSessionProjection,
  hideSpotlightShell,
  listenSessionProjection,
  listenSessionEvent,
  listSessionHistory,
  loadSessionTask,
  loadSessionThreadArtifacts,
  loadSessionThreadEvents,
  showSpotlightShell,
  showStudioShell,
  startSessionTask,
} from "./session-runtime";

export interface SessionControllerHistoryPollingOptions {
  intervalMs?: number;
  timeoutMs?: number;
  onError?: (error: unknown) => void;
}

export interface SessionControllerReplSessionLike {
  session_id: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  current_step?: string | null;
  resume_hint?: string | null;
  workspace_root?: string | null;
}

export interface SessionControllerReplTarget {
  sessionId: string;
  title: string;
  timestamp: number;
  phase: string | null;
  currentStep: string | null;
  resumeHint: string | null;
  workspaceRoot: string | null;
  isCurrent: boolean;
  attachable: boolean;
  priorityLabel: string;
}

export interface SessionControllerBootstrapOptions {
  refreshCurrentTask?: boolean;
  onError?: (error: unknown) => void;
}

export interface SessionControllerTaskPollingOptions<TTask> {
  initialDelayMs?: number;
  idleDelayMs?: number;
  shouldPollTask?: (task: TTask | null) => boolean;
  getDelayMs?: (task: TTask) => number;
  onError?: (error: unknown) => void;
}

export interface SessionControllerRuntime<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> {
  startTask(intent: string): Promise<TTask>;
  continueTask(sessionId: string, userInput: string): Promise<void>;
  dismissTask(): Promise<void>;
  getCurrentTask(): Promise<TTask | null>;
  listSessionHistory(): Promise<TSessionSummary[]>;
  getSessionProjection(): Promise<AgentSessionProjection<TTask, TSessionSummary>>;
  loadSession(sessionId: string): Promise<TTask>;
  loadThreadEvents(
    threadId: string,
    limit?: number,
    cursor?: number,
  ): Promise<TEvent[]>;
  loadThreadArtifacts(threadId: string): Promise<TArtifact[]>;
  listenEvent<TPayload>(
    eventName: AgentSessionEventName,
    handler: (payload: TPayload) => void,
  ): Promise<() => void>;
  listenSessionProjection(
    handler: (projection: AgentSessionProjection<TTask, TSessionSummary>) => void,
  ): Promise<() => void>;
  showSpotlight(): Promise<void>;
  hideSpotlight(): Promise<void>;
  showStudio(): Promise<void>;
}

export interface SessionControllerConfig<TTask, TEvent, TArtifact> {
  normalizeTask(task: TTask): TTask;
  getTaskEvents(task: TTask): TEvent[];
  setTaskEvents(task: TTask, events: TEvent[]): TTask;
  getTaskArtifacts(task: TTask): TArtifact[];
  setTaskArtifacts(task: TTask, artifacts: TArtifact[]): TTask;
  getArtifactId(artifact: TArtifact): string | null | undefined;
  appendUniqueEvent(events: TEvent[], next: TEvent): TEvent[];
  appendUniqueArtifact(artifacts: TArtifact[], next: TArtifact): TArtifact[];
  buildOptimisticContinueTask(task: TTask, input: string): TTask;
  buildContinueFailureTask(task: TTask, error: unknown): TTask;
}

export interface SessionControllerEventLike {
  event_id: string;
}

export interface SessionControllerArtifactLike {
  artifact_id: string;
}

export interface SessionControllerChatMessageLike {
  role: string;
  text: string;
  timestamp: number;
}

export interface SessionControllerChatTaskLike<
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
> {
  history: TMessage[];
  events: TEvent[];
  artifacts: TArtifact[];
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  current_step: string;
  credential_request?: unknown;
  clarification_request?: unknown;
}

export interface SessionControllerLineageTaskLike {
  generation?: number;
  fitness_score?: number;
  lineage_id?: string;
}

export interface SessionControllerStudioTaskLike {
  studio_session?: unknown | null;
  studio_outcome?: unknown | null;
  renderer_session?: unknown | null;
  build_session?: unknown | null;
}

type RetainableProjectionTaskLike = Partial<
  SessionControllerChatTaskLike<
    SessionControllerEventLike,
    SessionControllerArtifactLike,
    SessionControllerChatMessageLike
  >
> & {
  pending_request_hash?: unknown;
  gate_info?: unknown;
  background_tasks?: Array<{ can_stop?: boolean | null }> | null;
};

function looksLikeLiveRetainableTask(task: unknown): task is RetainableProjectionTaskLike {
  return !!task && typeof task === "object";
}

function shouldRetainTaskOnNullProjection(task: unknown): boolean {
  if (!looksLikeLiveRetainableTask(task)) {
    return false;
  }

  const phase = typeof task.phase === "string" ? task.phase : null;
  const currentStep =
    typeof task.current_step === "string"
      ? task.current_step.trim().toLowerCase()
      : "";
  const hasBackgroundStop =
    Array.isArray(task.background_tasks) &&
    task.background_tasks.some((entry) => Boolean(entry?.can_stop));
  const hasLiveBlocker =
    Boolean(task.credential_request) ||
    Boolean(task.clarification_request) ||
    Boolean(task.pending_request_hash) ||
    Boolean(task.gate_info) ||
    phase === "Gate";

  return (
    hasLiveBlocker ||
    phase === "Running" ||
    hasBackgroundStop ||
    currentStep.includes("waiting for") ||
    currentStep.includes("initializing") ||
    currentStep.includes("routing the request")
  );
}

export interface SessionControllerStoreState<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> {
  task: TTask | null;
  events: TEvent[];
  artifacts: TArtifact[];
  selectedArtifactId: string | null;
  sessions: TSessionSummary[];
  startTask: (intent: string) => Promise<TTask | null>;
  updateTask: (task: TTask) => void;
  dismissTask: () => Promise<void>;
  showSpotlight: () => Promise<void>;
  hideSpotlight: () => Promise<void>;
  showStudio: () => Promise<void>;
  continueTask: (sessionId: string, input: string) => Promise<void>;
  resetSession: () => void;
  startNewSession: () => void;
  refreshCurrentTask: () => Promise<TTask | null>;
  refreshSessionHistory: () => Promise<TSessionSummary[]>;
  loadSession: (sessionId: string) => Promise<TTask | null>;
  setSelectedArtifactId: (artifactId: string | null) => void;
  loadThreadEvents: (
    threadId: string,
    limit?: number,
    cursor?: number,
  ) => Promise<TEvent[]>;
  loadThreadArtifacts: (threadId: string) => Promise<TArtifact[]>;
}

interface CreateSessionControllerStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> {
  useSessionControllerStore: UseBoundStore<
    StoreApi<
      SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
    >
  >;
  bootstrapSessionController: (
    options?: SessionControllerBootstrapOptions,
  ) => Promise<void>;
}

function selectedArtifactStillPresent<TArtifact>(
  artifacts: TArtifact[],
  selectedArtifactId: string | null,
  getArtifactId: (artifact: TArtifact) => string | null | undefined,
): boolean {
  if (!selectedArtifactId) {
    return false;
  }

  return artifacts.some((artifact) => getArtifactId(artifact) === selectedArtifactId);
}

function sessionLooksLiveForRepl(session: SessionControllerReplSessionLike): boolean {
  const phase = (session.phase ?? "").trim().toLowerCase();
  const currentStep = (session.current_step ?? "").trim().toLowerCase();
  return (
    phase === "running" ||
    phase === "gate" ||
    currentStep.includes("waiting for") ||
    currentStep.includes("initializing") ||
    currentStep.includes("routing the request") ||
    currentStep.includes("sending message")
  );
}

function replPriorityLabel(
  session: SessionControllerReplSessionLike,
  activeSessionId?: string | null,
): string {
  if (activeSessionId && session.session_id === activeSessionId) {
    return "Current session";
  }
  if (sessionLooksLiveForRepl(session)) {
    return "Live session";
  }
  if (session.workspace_root) {
    return "Recent workspace";
  }
  return "Session history";
}

function replPriorityScore(
  session: SessionControllerReplSessionLike,
  activeSessionId?: string | null,
): number {
  if (activeSessionId && session.session_id === activeSessionId) {
    return 4;
  }
  if (sessionLooksLiveForRepl(session)) {
    return 3;
  }
  if (session.workspace_root) {
    return 2;
  }
  return 1;
}

export function buildSessionReplTargets<
  TSession extends SessionControllerReplSessionLike,
>(
  sessions: TSession[],
  activeSessionId?: string | null,
): SessionControllerReplTarget[] {
  return [...sessions]
    .sort((left, right) => {
      const priorityDelta =
        replPriorityScore(right, activeSessionId) -
        replPriorityScore(left, activeSessionId);
      if (priorityDelta !== 0) {
        return priorityDelta;
      }
      return right.timestamp - left.timestamp;
    })
    .map((session) => ({
      sessionId: session.session_id,
      title: session.title,
      timestamp: session.timestamp,
      phase: session.phase ?? null,
      currentStep: session.current_step ?? null,
      resumeHint: session.resume_hint ?? null,
      workspaceRoot: session.workspace_root ?? null,
      isCurrent: Boolean(activeSessionId && session.session_id === activeSessionId),
      attachable: Boolean(session.workspace_root),
      priorityLabel: replPriorityLabel(session, activeSessionId),
    }));
}

export function selectPrimarySessionReplTarget<
  TSession extends SessionControllerReplSessionLike,
>(
  sessions: TSession[],
  activeSessionId?: string | null,
): SessionControllerReplTarget | null {
  return buildSessionReplTargets(sessions, activeSessionId)[0] ?? null;
}

export function appendUniqueSessionEvent<TEvent extends SessionControllerEventLike>(
  events: TEvent[],
  next: TEvent,
): TEvent[] {
  return events.some((event) => event.event_id === next.event_id)
    ? events
    : [...events, next];
}

export function appendUniqueSessionArtifact<
  TArtifact extends SessionControllerArtifactLike,
>(artifacts: TArtifact[], next: TArtifact): TArtifact[] {
  return artifacts.some((artifact) => artifact.artifact_id === next.artifact_id)
    ? artifacts
    : [...artifacts, next];
}

export function buildOptimisticChatContinueTask<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(task: TTask, input: string): TTask {
  return {
    ...task,
    history: [
      ...task.history,
      { role: "user", text: input, timestamp: Date.now() } as TMessage,
    ],
    phase: "Running",
    current_step: "Sending message...",
    credential_request: undefined,
    clarification_request: undefined,
  };
}

export function buildChatContinueFailureTask<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(task: TTask, error: unknown): TTask {
  return {
    ...task,
    phase: "Failed",
    current_step: `Failed to send: ${error}`,
  };
}

export function normalizeRuntimeChatTaskDefaults<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage> &
    Partial<SessionControllerLineageTaskLike & SessionControllerStudioTaskLike>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(task: TTask): TTask {
  return {
    ...task,
    generation: task.generation ?? 0,
    fitness_score: task.fitness_score ?? 0.0,
    lineage_id: task.lineage_id || "genesis",
    events: Array.isArray(task.events) ? task.events : [],
    artifacts: Array.isArray(task.artifacts) ? task.artifacts : [],
    studio_session: task.studio_session ?? null,
    studio_outcome: task.studio_outcome ?? null,
    renderer_session: task.renderer_session ?? null,
    build_session: task.build_session ?? null,
  };
}

function composeSessionControllerErrorHandlers(
  primary?: (error: unknown) => void,
  secondary?: (error: unknown) => void,
): ((error: unknown) => void) | undefined {
  if (!primary) {
    return secondary;
  }
  if (!secondary) {
    return primary;
  }

  return (error: unknown) => {
    primary(error);
    secondary(error);
  };
}

export function composeRuntimeChatTaskNormalizer<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage> &
    Partial<SessionControllerLineageTaskLike & SessionControllerStudioTaskLike>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  normalizeTask: (task: TTask) => TTask,
): (task: TTask) => TTask {
  return (task: TTask) =>
    normalizeTask(normalizeRuntimeChatTaskDefaults(task));
}

export function createSessionControllerStore<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
>(
  runtime: SessionControllerRuntime<TTask, TEvent, TArtifact, TSessionSummary>,
  config: SessionControllerConfig<TTask, TEvent, TArtifact>,
): CreateSessionControllerStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary
> {
  const TASK_POLL_INITIAL_DELAY_MS = 180;
  const TASK_POLL_IDLE_DELAY_MS = 1_000;
  const applyTaskSnapshot = (
    set: (
      partial:
        | Partial<SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>>
        | ((
            state: SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>,
          ) => Partial<
            SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
          >),
    ) => void,
    task: TTask | null,
  ): TTask | null => {
    if (!task) {
      set({ task: null, events: [], artifacts: [], selectedArtifactId: null });
      return null;
    }

    const normalized = config.normalizeTask(task);
    const normalizedArtifacts = config.getTaskArtifacts(normalized);
    set((state) => ({
      task: normalized,
      events: config.getTaskEvents(normalized),
      artifacts: normalizedArtifacts,
      selectedArtifactId: selectedArtifactStillPresent(
        normalizedArtifacts,
        state.selectedArtifactId,
        config.getArtifactId,
      )
        ? state.selectedArtifactId
        : null,
    }));
    return normalized;
  };

  const shouldPollTaskSnapshot = (task: TTask | null): boolean =>
    shouldRetainTaskOnNullProjection(task);

  let taskPollTimer: ReturnType<typeof setTimeout> | null = null;
  let taskPollInFlight = false;
  let storeSet:
    | ((
        partial:
          | Partial<
              SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
            >
          | ((
              state: SessionControllerStoreState<
                TTask,
                TEvent,
                TArtifact,
                TSessionSummary
              >,
            ) => Partial<
              SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
            >),
      ) => void)
    | null = null;
  let storeGet:
    | (() => SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>)
    | null = null;

  const clearTaskPollTimer = () => {
    if (taskPollTimer !== null) {
      clearTimeout(taskPollTimer);
      taskPollTimer = null;
    }
  };

  let scheduleTaskPoll = (
    _set: (
      partial:
        | Partial<SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>>
        | ((
            state: SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>,
          ) => Partial<
            SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
          >),
    ) => void,
    _get: () => SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>,
    _delayMs?: number,
  ): void => {};

  const applySessionProjection = (
    set: (
      partial:
        | Partial<SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>>
        | ((
            state: SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>,
          ) => Partial<
            SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
          >),
    ) => void,
    get: () => SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>,
    projection: AgentSessionProjection<TTask, TSessionSummary>,
  ) => {
    useSessionControllerStore.setState((state) => {
      if (!projection.task) {
        if (shouldRetainTaskOnNullProjection(state.task)) {
          return {
            sessions: projection.sessions,
          };
        }
        return {
          task: null,
          events: [],
          artifacts: [],
          selectedArtifactId: null,
          sessions: projection.sessions,
        };
      }

      const normalized = config.normalizeTask(projection.task);
      const normalizedArtifacts = config.getTaskArtifacts(normalized);
      return {
        task: normalized,
        events: config.getTaskEvents(normalized),
        artifacts: normalizedArtifacts,
        selectedArtifactId: selectedArtifactStillPresent(
          normalizedArtifacts,
          state.selectedArtifactId,
          config.getArtifactId,
        )
          ? state.selectedArtifactId
          : null,
        sessions: projection.sessions,
      };
    });

    if (shouldPollTaskSnapshot(get().task)) {
      scheduleTaskPoll(set, get);
      return;
    }

    clearTaskPollTimer();
  };

  const useSessionControllerStore = create<
    SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
  >((set, get) => ({
    task: null,
    events: [],
    artifacts: [],
    selectedArtifactId: null,
    sessions: [],

    startTask: async (intent: string): Promise<TTask | null> => {
      const task = applyTaskSnapshot(set, await runtime.startTask(intent));
      if (shouldPollTaskSnapshot(task)) {
        scheduleTaskPoll(set, get);
      } else {
        clearTaskPollTimer();
      }
      return task;
    },

    updateTask: (task: TTask) => {
      void applyTaskSnapshot(set, task);
    },

    dismissTask: async () => {
      await runtime.dismissTask();
      set({ task: null, events: [], artifacts: [], selectedArtifactId: null });
    },

    showSpotlight: async () => runtime.showSpotlight(),
    hideSpotlight: async () => runtime.hideSpotlight(),
    showStudio: async () => runtime.showStudio(),

    continueTask: async (sessionId: string, input: string) => {
      const currentTask = get().task;
      if (currentTask) {
        set({ task: config.buildOptimisticContinueTask(currentTask, input) });
      }

      try {
        await runtime.continueTask(sessionId, input);
      } catch (error) {
        const task = get().task;
        if (task) {
          set({ task: config.buildContinueFailureTask(task, error) });
        }
      }
    },

    resetSession: () => {
      set({
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
    },

    startNewSession: () => {
      get().resetSession();
    },

    refreshCurrentTask: async () => {
      try {
        return applyTaskSnapshot(set, await runtime.getCurrentTask());
      } catch (error) {
        console.error("Failed to refresh current task:", error);
        return get().task;
      }
    },

    refreshSessionHistory: async () => {
      const sessions = await runtime.listSessionHistory();
      set({ sessions });
      return sessions;
    },

    loadSession: async (sessionId: string) => {
      const task = applyTaskSnapshot(set, await runtime.loadSession(sessionId));
      if (shouldPollTaskSnapshot(task)) {
        scheduleTaskPoll(set, get);
      } else {
        clearTaskPollTimer();
      }
      return task;
    },

    setSelectedArtifactId: (artifactId: string | null) => {
      set({ selectedArtifactId: artifactId });
    },

    loadThreadEvents: async (threadId: string, limit?: number, cursor?: number) => {
      const events = await runtime.loadThreadEvents(threadId, limit, cursor);
      set({ events });
      return events;
    },

    loadThreadArtifacts: async (threadId: string) => {
      const artifacts = await runtime.loadThreadArtifacts(threadId);
      set((state) => ({
        artifacts,
        selectedArtifactId: selectedArtifactStillPresent(
          artifacts,
          state.selectedArtifactId,
          config.getArtifactId,
        )
          ? state.selectedArtifactId
          : null,
      }));
      return artifacts;
    },
  }));

  storeSet = useSessionControllerStore.setState;
  storeGet = useSessionControllerStore.getState;

  scheduleTaskPoll = (set, get, delayMs = TASK_POLL_INITIAL_DELAY_MS) => {
    clearTaskPollTimer();
    taskPollTimer = setTimeout(() => {
      taskPollTimer = null;
      if (taskPollInFlight) {
        scheduleTaskPoll(set, get, TASK_POLL_IDLE_DELAY_MS);
        return;
      }

      taskPollInFlight = true;
      void runtime
        .getCurrentTask()
        .then((task) => {
          const currentTask = get().task;
          if (!task) {
            if (shouldPollTaskSnapshot(currentTask)) {
              scheduleTaskPoll(set, get, TASK_POLL_IDLE_DELAY_MS);
            } else {
              clearTaskPollTimer();
            }
            return;
          }

          const refreshedTask = applyTaskSnapshot(set, task);
          if (shouldPollTaskSnapshot(refreshedTask)) {
            scheduleTaskPoll(set, get, TASK_POLL_IDLE_DELAY_MS);
          } else {
            clearTaskPollTimer();
          }
        })
        .catch(() => {
          if (shouldPollTaskSnapshot(get().task)) {
            scheduleTaskPoll(set, get, TASK_POLL_IDLE_DELAY_MS);
          } else {
            clearTaskPollTimer();
          }
        })
        .finally(() => {
          taskPollInFlight = false;
        });
    }, Math.max(0, delayMs));
  };

  let listenersInitPromise: Promise<void> | null = null;

  async function initSessionControllerListeners(): Promise<void> {
    if (listenersInitPromise) {
      return listenersInitPromise;
    }

    listenersInitPromise = (async () => {
      if (!storeSet || !storeGet) {
        throw new Error("Session controller store was not initialized");
      }

      await runtime.listenSessionProjection((projection) => {
        applySessionProjection(storeSet!, storeGet!, projection);
      });

      await runtime.listenEvent<TTask>("task-started", (payload) => {
        useSessionControllerStore.getState().updateTask(payload);
        if (shouldPollTaskSnapshot(useSessionControllerStore.getState().task)) {
          scheduleTaskPoll(storeSet!, storeGet!);
        }
      });

      await runtime.listenEvent<TTask>("task-updated", (payload) => {
        useSessionControllerStore.getState().updateTask(payload);
        if (shouldPollTaskSnapshot(useSessionControllerStore.getState().task)) {
          scheduleTaskPoll(storeSet!, storeGet!);
        } else {
          clearTaskPollTimer();
        }
      });

      await runtime.listenEvent<TTask>("task-completed", (payload) => {
        useSessionControllerStore.getState().updateTask(payload);
        scheduleTaskPoll(storeSet!, storeGet!, 0);
      });

      await runtime.listenEvent("task-dismissed", () => {
        clearTaskPollTimer();
        useSessionControllerStore.setState({
          task: null,
          events: [],
          artifacts: [],
          selectedArtifactId: null,
        });
      });

      await runtime.listenEvent<TEvent>("agent-event", (payload) => {
        useSessionControllerStore.setState((state) => {
          const events = config.appendUniqueEvent(state.events, payload);
          const task = state.task
            ? config.setTaskEvents(
                state.task,
                config.appendUniqueEvent(config.getTaskEvents(state.task), payload),
              )
            : state.task;
          return { events, task };
        });
      });

      await runtime.listenEvent<TArtifact>("artifact-created", (payload) => {
        useSessionControllerStore.setState((state) => {
          const artifacts = config.appendUniqueArtifact(state.artifacts, payload);
          const task = state.task
            ? config.setTaskArtifacts(
                state.task,
                config.appendUniqueArtifact(config.getTaskArtifacts(state.task), payload),
              )
            : state.task;
          return { artifacts, task };
        });
      });
    })().catch((error) => {
      listenersInitPromise = null;
      throw error;
    });

    return listenersInitPromise;
  }

  async function bootstrapSessionController(
    options: SessionControllerBootstrapOptions = {},
  ): Promise<void> {
    await initSessionControllerListeners();

    if (options.refreshCurrentTask === false) {
      return;
    }

    try {
      if (!storeSet || !storeGet) {
        throw new Error("Session controller store was not initialized");
      }
      applySessionProjection(
        storeSet,
        storeGet,
        await runtime.getSessionProjection(),
      );
    } catch (error) {
      options.onError?.(error);
    }
  }

  return {
    bootstrapSessionController,
    useSessionControllerStore,
  };
}

export function createRuntimeSessionControllerStore<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
>(
  config: SessionControllerConfig<TTask, TEvent, TArtifact>,
): CreateSessionControllerStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary
> {
  return createSessionControllerStore<
    TTask,
    TEvent,
    TArtifact,
    TSessionSummary
  >(
    {
      startTask: (intent: string) => startSessionTask<TTask>(intent),
      continueTask: (sessionId: string, userInput: string) =>
        continueSessionTask(sessionId, userInput),
      dismissTask: () => dismissSessionTask(),
      getCurrentTask: () => getCurrentSessionTask<TTask>(),
      listSessionHistory: () => listSessionHistory<TSessionSummary>(),
      getSessionProjection: () => getSessionProjection<TTask, TSessionSummary>(),
      loadSession: (sessionId: string) => loadSessionTask<TTask>(sessionId),
      loadThreadEvents: (threadId: string, limit?: number, cursor?: number) =>
        loadSessionThreadEvents<TEvent>(threadId, limit, cursor),
      loadThreadArtifacts: (threadId: string) =>
        loadSessionThreadArtifacts<TArtifact>(threadId),
      listenEvent: <TPayload,>(
        eventName: AgentSessionEventName,
        handler: (payload: TPayload) => void,
      ) => listenSessionEvent<TPayload>(eventName, handler),
      listenSessionProjection: (
        handler: (
          projection: AgentSessionProjection<TTask, TSessionSummary>,
        ) => void,
      ) => listenSessionProjection<TTask, TSessionSummary>(handler),
      showSpotlight: () => showSpotlightShell(),
      hideSpotlight: () => hideSpotlightShell(),
      showStudio: () => showStudioShell(),
    },
    config,
  );
}

export function createRuntimeChatSessionControllerStore<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TSessionSummary,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  options: {
    normalizeTask(task: TTask): TTask;
  },
): CreateSessionControllerStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary
> {
  return createRuntimeSessionControllerStore<
    TTask,
    TEvent,
    TArtifact,
    TSessionSummary
  >({
    normalizeTask: options.normalizeTask,
    getTaskEvents: (task) => task.events,
    setTaskEvents: (task, events) => ({
      ...task,
      events,
    }),
    getTaskArtifacts: (task) => task.artifacts,
    setTaskArtifacts: (task, artifacts) => ({
      ...task,
      artifacts,
    }),
    getArtifactId: (artifact) => artifact.artifact_id,
    appendUniqueEvent: appendUniqueSessionEvent,
    appendUniqueArtifact: appendUniqueSessionArtifact,
    buildOptimisticContinueTask: buildOptimisticChatContinueTask,
    buildContinueFailureTask: buildChatContinueFailureTask,
  });
}

export function createNormalizedRuntimeChatSessionControllerStore<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage> &
    Partial<SessionControllerLineageTaskLike & SessionControllerStudioTaskLike>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TSessionSummary,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  options: {
    normalizeTask(task: TTask): TTask;
    onBootstrapError?: (error: unknown) => void;
  },
): CreateSessionControllerStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary
> {
  const controllerStore = createRuntimeChatSessionControllerStore<
    TTask,
    TEvent,
    TArtifact,
    TSessionSummary,
    TMessage
  >({
    normalizeTask: composeRuntimeChatTaskNormalizer(options.normalizeTask),
  });

  return {
    useSessionControllerStore: controllerStore.useSessionControllerStore,
    bootstrapSessionController: (
      bootstrapOptions: SessionControllerBootstrapOptions = {},
    ) =>
      controllerStore.bootstrapSessionController({
        ...bootstrapOptions,
        onError: composeSessionControllerErrorHandlers(
          bootstrapOptions.onError,
          options.onBootstrapError,
        ),
      }),
  };
}
