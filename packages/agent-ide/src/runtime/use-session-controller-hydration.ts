import { useEffect } from "react";
import type { SessionControllerBootstrapOptions } from "./session-controller";

export interface UseHydrateSessionStoreOptions<TTask> {
  connectSessionStore: (
    options?: SessionControllerBootstrapOptions,
  ) => Promise<void>;
  connectOptions?: SessionControllerBootstrapOptions;
  session: TTask | null;
  getSessionThreadId?: (session: TTask) => string | null;
  loadSessionEvents?: (threadId: string) => Promise<unknown>;
  loadSessionArtifacts?: (threadId: string) => Promise<unknown>;
  onLoadError?: (error: unknown) => void;
}

export function useHydrateSessionStore<TTask>({
  connectSessionStore,
  connectOptions,
  session,
  getSessionThreadId,
  loadSessionEvents,
  loadSessionArtifacts,
  onLoadError,
}: UseHydrateSessionStoreOptions<TTask>) {
  useEffect(() => {
    void connectSessionStore(connectOptions);
  }, [connectOptions, connectSessionStore]);

  useEffect(() => {
    const threadId =
      session && getSessionThreadId ? getSessionThreadId(session) : null;
    if (!threadId) {
      return;
    }

    const handleError = onLoadError ?? console.error;
    void loadSessionEvents?.(threadId).catch(handleError);
    void loadSessionArtifacts?.(threadId).catch(handleError);
  }, [
    getSessionThreadId,
    loadSessionArtifacts,
    loadSessionEvents,
    onLoadError,
    session,
  ]);
}

export interface UseSessionControllerHydrationOptions<TTask> {
  bootstrapSessionController: (
    options?: SessionControllerBootstrapOptions,
  ) => Promise<void>;
  bootstrapOptions?: SessionControllerBootstrapOptions;
  task: TTask | null;
  getTaskThreadId?: (task: TTask) => string | null;
  loadThreadEvents?: (threadId: string) => Promise<unknown>;
  loadThreadArtifacts?: (threadId: string) => Promise<unknown>;
  onLoadError?: (error: unknown) => void;
}

export function useSessionControllerHydration<TTask>({
  bootstrapSessionController,
  bootstrapOptions,
  task,
  getTaskThreadId,
  loadThreadEvents,
  loadThreadArtifacts,
  onLoadError,
}: UseSessionControllerHydrationOptions<TTask>) {
  return useHydrateSessionStore({
    connectSessionStore: bootstrapSessionController,
    connectOptions: bootstrapOptions,
    session: task,
    getSessionThreadId: getTaskThreadId,
    loadSessionEvents: loadThreadEvents,
    loadSessionArtifacts: loadThreadArtifacts,
    onLoadError,
  });
}
