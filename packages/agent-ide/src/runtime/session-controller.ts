import { create } from "zustand";
import type { StoreApi, UseBoundStore } from "zustand";
import type {
  AssistantSessionEventName,
  AssistantSessionProjection,
} from "./assistant-session-runtime-types";
import {
  dismissAssistantSession,
  getActiveAssistantSession,
  getAssistantSessionProjection,
  hideChatSessionShell,
  listAssistantSessions,
  listenAssistantSessionEvent,
  listenAssistantSessionProjection,
  loadAssistantSession,
  loadAssistantSessionArtifacts,
  loadAssistantSessionEvents,
  showChatSessionShell,
  showChatShell,
  startAssistantSession,
  submitAssistantSessionInput,
} from "./session-runtime";
import {
  buildSessionAttachTargets,
  mergeSessionSnapshotCollection,
  resolveSessionRecoveryId,
  selectPrimarySessionAttachTarget,
  shouldRetainHydratedThreadCollections,
  type SessionAttachTarget,
} from "./session-repl-targets";
import {
  shouldRetainSessionOnMissingProjection,
} from "./session-status";

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

export type SessionControllerReplTarget = SessionAttachTarget;

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
  getSessionProjection(): Promise<
    AssistantSessionProjection<TTask, TSessionSummary>
  >;
  loadSession(sessionId: string): Promise<TTask>;
  loadThreadEvents(
    threadId: string,
    limit?: number,
    cursor?: number,
  ): Promise<TEvent[]>;
  loadThreadArtifacts(threadId: string): Promise<TArtifact[]>;
  listenEvent<TPayload>(
    eventName: AssistantSessionEventName,
    handler: (payload: TPayload) => void,
  ): Promise<() => void>;
  listenSessionProjection(
    handler: (
      projection: AssistantSessionProjection<TTask, TSessionSummary>,
    ) => void,
  ): Promise<() => void>;
  showChatSession(): Promise<void>;
  hideChatSession(): Promise<void>;
  showChat(): Promise<void>;
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

export interface SessionControllerChatSurfaceTaskLike {
  chat_session?: unknown | null;
  chat_outcome?: unknown | null;
  renderer_session?: unknown | null;
  build_session?: unknown | null;
}

export interface SessionControllerStoreState<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> {
  session: TTask | null;
  task: TTask | null;
  events: TEvent[];
  artifacts: TArtifact[];
  selectedArtifactId: string | null;
  sessions: TSessionSummary[];
  startSession: (intent: string) => Promise<TTask | null>;
  startTask: (intent: string) => Promise<TTask | null>;
  setSession: (task: TTask) => void;
  updateTask: (task: TTask) => void;
  dismissSession: () => Promise<void>;
  dismissTask: () => Promise<void>;
  showChatSession: () => Promise<void>;
  hideChatSession: () => Promise<void>;
  showChat: () => Promise<void>;
  submitSessionInput: (sessionId: string, input: string) => Promise<void>;
  continueTask: (sessionId: string, input: string) => Promise<void>;
  clearSession: () => void;
  resetSession: () => void;
  startNewSession: () => void;
  refreshActiveSession: () => Promise<TTask | null>;
  refreshCurrentTask: () => Promise<TTask | null>;
  refreshSessionList: () => Promise<TSessionSummary[]>;
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

interface CreateSessionStoreResult<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> {
  useSessionStore: UseBoundStore<
    StoreApi<SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>>
  >;
  useSessionControllerStore: UseBoundStore<
    StoreApi<
      SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>
    >
  >;
  connectSessionStore: (
    options?: SessionControllerBootstrapOptions,
  ) => Promise<void>;
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
    Partial<SessionControllerLineageTaskLike & SessionControllerChatSurfaceTaskLike>,
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
    chat_session: task.chat_session ?? null,
    chat_outcome: task.chat_outcome ?? null,
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
    Partial<SessionControllerLineageTaskLike & SessionControllerChatSurfaceTaskLike>,
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
): CreateSessionStoreResult<
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
      set({
        session: null,
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
      return null;
    }

    const normalized = config.normalizeTask(task);
    let appliedTask = normalized;
    set((state) => {
      const retainHydratedCollections = shouldRetainHydratedThreadCollections(
        state.task,
        normalized,
      );
      const snapshotEvents = config.getTaskEvents(normalized);
      const snapshotArtifacts = config.getTaskArtifacts(normalized);
      const mergedEvents = retainHydratedCollections
        ? mergeSessionSnapshotCollection(
            state.events,
            snapshotEvents,
            config.appendUniqueEvent,
          )
        : snapshotEvents;
      const mergedArtifacts = retainHydratedCollections
        ? mergeSessionSnapshotCollection(
            state.artifacts,
            snapshotArtifacts,
            config.appendUniqueArtifact,
          )
        : snapshotArtifacts;
      const normalizedWithCollections = config.setTaskArtifacts(
        config.setTaskEvents(normalized, mergedEvents),
        mergedArtifacts,
      );
      appliedTask = normalizedWithCollections;

      return {
        session: normalizedWithCollections,
        task: normalizedWithCollections,
        events: mergedEvents,
        artifacts: mergedArtifacts,
        selectedArtifactId: selectedArtifactStillPresent(
          mergedArtifacts,
          state.selectedArtifactId,
          config.getArtifactId,
        )
          ? state.selectedArtifactId
          : null,
      };
    });
    return appliedTask;
  };

  const shouldPollTaskSnapshot = (task: TTask | null): boolean =>
    shouldRetainSessionOnMissingProjection(task);

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
    projection: AssistantSessionProjection<TTask, TSessionSummary>,
  ) => {
    useSessionControllerStore.setState((state) => {
      if (!projection.task) {
        if (shouldRetainSessionOnMissingProjection(state.task)) {
          return {
            sessions: projection.sessions,
          };
        }
        return {
          session: null,
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
        session: normalized,
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
    session: null,
    task: null,
    events: [],
    artifacts: [],
    selectedArtifactId: null,
    sessions: [],

    startSession: async (intent: string): Promise<TTask | null> => {
      const task = applyTaskSnapshot(set, await runtime.startTask(intent));
      if (shouldPollTaskSnapshot(task)) {
        scheduleTaskPoll(set, get);
      } else {
        clearTaskPollTimer();
      }
      return task;
    },

    startTask: async (intent: string): Promise<TTask | null> => {
      const task = applyTaskSnapshot(set, await runtime.startTask(intent));
      if (shouldPollTaskSnapshot(task)) {
        scheduleTaskPoll(set, get);
      } else {
        clearTaskPollTimer();
      }
      return task;
    },

    setSession: (task: TTask) => {
      void applyTaskSnapshot(set, task);
    },

    updateTask: (task: TTask) => {
      void applyTaskSnapshot(set, task);
    },

    dismissSession: async () => {
      await runtime.dismissTask();
      set({
        session: null,
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
    },

    dismissTask: async () => {
      await runtime.dismissTask();
      set({
        session: null,
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
    },

    showChatSession: async () => runtime.showChatSession(),
    hideChatSession: async () => runtime.hideChatSession(),
    showChat: async () => runtime.showChat(),

    submitSessionInput: async (sessionId: string, input: string) => {
      const currentTask = get().task;
      if (currentTask) {
        const nextTask = config.buildOptimisticContinueTask(currentTask, input);
        set({ session: nextTask, task: nextTask });
      }

      try {
        await runtime.continueTask(sessionId, input);
      } catch (error) {
        const task = get().task;
        if (task) {
          const nextTask = config.buildContinueFailureTask(task, error);
          set({ session: nextTask, task: nextTask });
        }
      }
    },

    continueTask: async (sessionId: string, input: string) => {
      const currentTask = get().task;
      if (currentTask) {
        const nextTask = config.buildOptimisticContinueTask(currentTask, input);
        set({ session: nextTask, task: nextTask });
      }

      try {
        await runtime.continueTask(sessionId, input);
      } catch (error) {
        const task = get().task;
        if (task) {
          const nextTask = config.buildContinueFailureTask(task, error);
          set({ session: nextTask, task: nextTask });
        }
      }
    },

    clearSession: () => {
      set({
        session: null,
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
    },

    resetSession: () => {
      set({
        session: null,
        task: null,
        events: [],
        artifacts: [],
        selectedArtifactId: null,
      });
    },

    startNewSession: () => {
      get().resetSession();
    },

    refreshActiveSession: async () => {
      try {
        return applyTaskSnapshot(set, await runtime.getCurrentTask());
      } catch (error) {
        console.error("Failed to refresh current task:", error);
        return get().task;
      }
    },

    refreshCurrentTask: async () => {
      try {
        return applyTaskSnapshot(set, await runtime.getCurrentTask());
      } catch (error) {
        console.error("Failed to refresh current task:", error);
        return get().task;
      }
    },

    refreshSessionList: async () => {
      const sessions = await runtime.listSessionHistory();
      set({ sessions });
      return sessions;
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

  const recoverTaskFromSessionSummary = (
    sessionId: string | null,
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
  ) => {
    if (!sessionId) {
      return;
    }

    void runtime
      .loadSession(sessionId)
      .then((task) => {
        const recoveredTask = applyTaskSnapshot(set, task);
        if (shouldPollTaskSnapshot(recoveredTask)) {
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
      });
  };

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
            const recoverySessionId = resolveSessionRecoveryId(
              currentTask,
              get().sessions,
            );
            if (recoverySessionId) {
              recoverTaskFromSessionSummary(recoverySessionId, set, get);
              return;
            }
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
        const recoverySessionId = !projection.task
          ? resolveSessionRecoveryId(
              storeGet!().task,
              projection.sessions,
            )
          : null;
        applySessionProjection(storeSet!, storeGet!, projection);
        recoverTaskFromSessionSummary(recoverySessionId, storeSet!, storeGet!);
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
          session: null,
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
          return { events, session: task, task };
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
          return { artifacts, session: task, task };
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
    connectSessionStore: bootstrapSessionController,
    bootstrapSessionController,
    useSessionStore: useSessionControllerStore,
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
): CreateSessionStoreResult<
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
      startTask: (intent: string) => startAssistantSession<TTask>(intent),
      continueTask: (sessionId: string, userInput: string) =>
        submitAssistantSessionInput(sessionId, userInput),
      dismissTask: () => dismissAssistantSession(),
      getCurrentTask: () => getActiveAssistantSession<TTask>(),
      listSessionHistory: () => listAssistantSessions<TSessionSummary>(),
      getSessionProjection: () =>
        getAssistantSessionProjection<TTask, TSessionSummary>(),
      loadSession: (sessionId: string) => loadAssistantSession<TTask>(sessionId),
      loadThreadEvents: (threadId: string, limit?: number, cursor?: number) =>
        loadAssistantSessionEvents<TEvent>(threadId, limit, cursor),
      loadThreadArtifacts: (threadId: string) =>
        loadAssistantSessionArtifacts<TArtifact>(threadId),
      listenEvent: <TPayload,>(
        eventName: AssistantSessionEventName,
        handler: (payload: TPayload) => void,
      ) => listenAssistantSessionEvent<TPayload>(eventName, handler),
      listenSessionProjection: (
        handler: (
          projection: AssistantSessionProjection<TTask, TSessionSummary>,
        ) => void,
      ) => listenAssistantSessionProjection<TTask, TSessionSummary>(handler),
      showChatSession: () => showChatSessionShell(),
      hideChatSession: () => hideChatSessionShell(),
      showChat: () => showChatShell(),
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
): CreateSessionStoreResult<
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
    Partial<SessionControllerLineageTaskLike & SessionControllerChatSurfaceTaskLike>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TSessionSummary,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  options: {
    normalizeTask(task: TTask): TTask;
    onBootstrapError?: (error: unknown) => void;
  },
): CreateSessionStoreResult<
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
    useSessionStore: controllerStore.useSessionStore,
    useSessionControllerStore: controllerStore.useSessionControllerStore,
    connectSessionStore: (
      bootstrapOptions: SessionControllerBootstrapOptions = {},
    ) =>
      controllerStore.connectSessionStore({
        ...bootstrapOptions,
        onError: composeSessionControllerErrorHandlers(
          bootstrapOptions.onError,
          options.onBootstrapError,
        ),
      }),
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

export function createSessionStore<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
>(
  runtime: SessionControllerRuntime<TTask, TEvent, TArtifact, TSessionSummary>,
  config: SessionControllerConfig<TTask, TEvent, TArtifact>,
): CreateSessionStoreResult<TTask, TEvent, TArtifact, TSessionSummary> {
  return createSessionControllerStore(runtime, config);
}

export function createConnectedSessionStore<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
>(
  config: SessionControllerConfig<TTask, TEvent, TArtifact>,
): CreateSessionStoreResult<TTask, TEvent, TArtifact, TSessionSummary> {
  return createRuntimeSessionControllerStore(config);
}

export function createChatSessionStore<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TSessionSummary,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  options: {
    normalizeTask(task: TTask): TTask;
  },
): CreateSessionStoreResult<TTask, TEvent, TArtifact, TSessionSummary> {
  return createRuntimeChatSessionControllerStore(options);
}

export function createNormalizedChatSessionStore<
  TTask extends SessionControllerChatTaskLike<TEvent, TArtifact, TMessage> &
    Partial<SessionControllerLineageTaskLike & SessionControllerChatSurfaceTaskLike>,
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TSessionSummary,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
>(
  options: {
    normalizeTask(task: TTask): TTask;
    onBootstrapError?: (error: unknown) => void;
  },
): CreateSessionStoreResult<TTask, TEvent, TArtifact, TSessionSummary> {
  return createNormalizedRuntimeChatSessionControllerStore(options);
}

export type SessionHistoryPollingOptions = SessionControllerHistoryPollingOptions;
export type SessionListEntryLike = SessionControllerReplSessionLike;
export type SessionAttachTargetLike = SessionControllerReplTarget;
export type SessionStoreConnectOptions = SessionControllerBootstrapOptions;
export type SessionPollingOptions<TTask> = SessionControllerTaskPollingOptions<TTask>;
export type SessionStoreAdapter<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> = SessionControllerRuntime<TTask, TEvent, TArtifact, TSessionSummary>;
export type SessionStoreConfig<TTask, TEvent, TArtifact> =
  SessionControllerConfig<TTask, TEvent, TArtifact>;
export type SessionEventLike = SessionControllerEventLike;
export type SessionArtifactLike = SessionControllerArtifactLike;
export type ChatSessionMessageLike = SessionControllerChatMessageLike;
export type ChatSessionLike<
  TEvent extends SessionControllerEventLike,
  TArtifact extends SessionControllerArtifactLike,
  TMessage extends SessionControllerChatMessageLike = SessionControllerChatMessageLike,
> = SessionControllerChatTaskLike<TEvent, TArtifact, TMessage>;
export type LineageSessionLike = SessionControllerLineageTaskLike;
export type SessionStoreState<
  TTask,
  TEvent,
  TArtifact,
  TSessionSummary,
> = SessionControllerStoreState<TTask, TEvent, TArtifact, TSessionSummary>;

export const buildSessionReplTargets = buildSessionAttachTargets;
export const selectPrimarySessionReplTarget = selectPrimarySessionAttachTarget;
export const resolveNullProjectionRecoverySessionId = resolveSessionRecoveryId;
export { mergeSessionSnapshotCollection, shouldRetainHydratedThreadCollections };
