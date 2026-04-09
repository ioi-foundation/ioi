import { useEffect } from "react";
import type {
  SessionControllerBootstrapOptions,
} from "./session-controller";

export interface UseSessionControllerHydrationOptions<TTask> {
  bootstrapSessionController: (
    options?: SessionControllerBootstrapOptions,
  ) => Promise<void>;
  bootstrapOptions?: SessionControllerBootstrapOptions;
  task: TTask | null;
  getTaskThreadId?: (task: TTask) => string | null;
  loadThreadEvents?: (threadId: string) => Promise<unknown>;
  loadThreadArtifacts?: (threadId: string) => Promise<unknown>;
}

export function useSessionControllerHydration<TTask>({
  bootstrapSessionController,
  bootstrapOptions,
  task,
  getTaskThreadId,
  loadThreadEvents,
  loadThreadArtifacts,
}: UseSessionControllerHydrationOptions<TTask>) {
  useEffect(() => {
    void bootstrapSessionController(bootstrapOptions);
  }, [bootstrapOptions, bootstrapSessionController]);

  useEffect(() => {
    const threadId = task && getTaskThreadId ? getTaskThreadId(task) : null;
    if (!threadId) {
      return;
    }

    void loadThreadEvents?.(threadId).catch(console.error);
    void loadThreadArtifacts?.(threadId).catch(console.error);
  }, [getTaskThreadId, loadThreadArtifacts, loadThreadEvents, task]);
}
