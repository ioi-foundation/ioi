import { useCallback } from "react";
import { openChatShellView } from "./session-runtime";

export interface UseSessionShellActionsOptions<TTask> {
  isChatShell?: boolean;
  hideCurrentShell?: () => Promise<void>;
  resolveChatView?: (targetView: string) => string;
  loadSession: (sessionId: string) => Promise<TTask | null>;
  beforeAttachSession?: () => Promise<void> | void;
  onAttachSessionError?: (error: unknown) => void;
}

export function useSessionShellActions<TTask>({
  isChatShell = false,
  hideCurrentShell,
  resolveChatView,
  loadSession,
  beforeAttachSession,
  onAttachSessionError,
}: UseSessionShellActionsOptions<TTask>) {
  const openChat = useCallback(
    async (targetView: string = "compose") => {
      const resolvedView = resolveChatView
        ? resolveChatView(targetView)
        : targetView;
      if (!isChatShell) {
        await hideCurrentShell?.();
      }
      await openChatShellView(resolvedView);
    },
    [hideCurrentShell, isChatShell, resolveChatView],
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
    openChat,
    attachSession,
  };
}

export type UseSessionShellOrchestrationOptions<TTask> =
  UseSessionShellActionsOptions<TTask>;

export const useSessionShellOrchestration = useSessionShellActions;
