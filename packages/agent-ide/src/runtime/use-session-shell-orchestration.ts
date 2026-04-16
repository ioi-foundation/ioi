import { useCallback } from "react";
import { openStudioShellView } from "./session-runtime";

export interface UseSessionShellActionsOptions<TTask> {
  isStudioShell?: boolean;
  hideCurrentShell?: () => Promise<void>;
  resolveStudioView?: (targetView: string) => string;
  loadSession: (sessionId: string) => Promise<TTask | null>;
  beforeAttachSession?: () => Promise<void> | void;
  onAttachSessionError?: (error: unknown) => void;
}

export function useSessionShellActions<TTask>({
  isStudioShell = false,
  hideCurrentShell,
  resolveStudioView,
  loadSession,
  beforeAttachSession,
  onAttachSessionError,
}: UseSessionShellActionsOptions<TTask>) {
  const openStudio = useCallback(
    async (targetView: string = "compose") => {
      const resolvedView = resolveStudioView
        ? resolveStudioView(targetView)
        : targetView;
      if (!isStudioShell) {
        await hideCurrentShell?.();
      }
      await openStudioShellView(resolvedView);
    },
    [hideCurrentShell, isStudioShell, resolveStudioView],
  );

  const attachSession = useCallback(
    async (sessionId: string) => {
      try {
        await beforeAttachSession?.();
        await loadSession(sessionId);
      } catch (error) {
        if (onAttachSessionError) {
          onAttachSessionError(error);
          return;
        }
        console.error("Failed to attach session:", error);
      }
    },
    [beforeAttachSession, loadSession, onAttachSessionError],
  );

  return {
    openStudio,
    attachSession,
  };
}

export type UseSessionShellOrchestrationOptions<TTask> =
  UseSessionShellActionsOptions<TTask>;

export const useSessionShellOrchestration = useSessionShellActions;
