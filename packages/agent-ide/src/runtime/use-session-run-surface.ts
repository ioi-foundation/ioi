import { useMemo } from "react";

export interface SessionRunSurfaceTaskLike<
  TMessage,
  TEvent,
  TArtifact,
> {
  history?: TMessage[] | null;
  events?: TEvent[] | null;
  artifacts?: TArtifact[] | null;
  phase?: string | null;
}

export interface UseSessionRunSurfaceOptions<
  TTask extends SessionRunSurfaceTaskLike<TMessage, TEvent, TArtifact>,
  TMessage,
  TEvent,
  TArtifact,
> {
  task: TTask | null;
  localHistory: TMessage[];
  events: TEvent[];
  artifacts: TArtifact[];
  preferLocalHistory?: boolean;
  selectedArtifactId: string | null;
  getArtifactId: (artifact: TArtifact) => string | null | undefined;
}

export type UseSessionDisplayStateOptions<
  TTask extends SessionRunSurfaceTaskLike<TMessage, TEvent, TArtifact>,
  TMessage,
  TEvent,
  TArtifact,
> = UseSessionRunSurfaceOptions<TTask, TMessage, TEvent, TArtifact>;

export function useSessionRunSurface<
  TTask extends SessionRunSurfaceTaskLike<TMessage, TEvent, TArtifact>,
  TMessage,
  TEvent,
  TArtifact,
>({
  task,
  localHistory,
  events,
  artifacts,
  preferLocalHistory = false,
  selectedArtifactId,
  getArtifactId,
}: UseSessionRunSurfaceOptions<TTask, TMessage, TEvent, TArtifact>) {
  const shouldPreferLocalHistory =
    localHistory.length > 0 && (!task?.history?.length || preferLocalHistory);

  const activeHistory = useMemo(
    () => (shouldPreferLocalHistory ? localHistory : (task?.history ?? [])),
    [localHistory, shouldPreferLocalHistory, task?.history],
  );

  const activeEvents = useMemo(
    () => (task?.events?.length ? task.events : events),
    [events, task?.events],
  );

  const activeArtifacts = useMemo(
    () => (task?.artifacts?.length ? task.artifacts : artifacts),
    [artifacts, task?.artifacts],
  );

  const selectedArtifact = useMemo(
    () =>
      activeArtifacts.find((artifact) => getArtifactId(artifact) === selectedArtifactId) ??
      null,
    [activeArtifacts, getArtifactId, selectedArtifactId],
  );

  const hasContent =
    !!task ||
    localHistory.length > 0 ||
    activeEvents.length > 0 ||
    activeHistory.length > 0;

  const isRunning = task?.phase === "Running";

  return {
    shouldPreferLocalHistory,
    activeHistory,
    activeEvents,
    activeArtifacts,
    selectedArtifact,
    hasContent,
    isRunning,
  };
}

export const useSessionDisplayState = useSessionRunSurface;
