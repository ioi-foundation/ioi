import { useCallback, useEffect } from "react";
import type {
  ChangeEvent,
  Dispatch,
  KeyboardEvent,
  RefObject,
  SetStateAction,
} from "react";
import { flushSync } from "react-dom";
import {
  getSessionId,
  isWaitingForClarificationStep,
  isWaitingForSudoStep,
} from "./session-status";

const UI_PAINT_FALLBACK_MS = 48;

export interface SessionComposerMessageLike {
  role: string;
  text: string;
  timestamp: number;
}

interface SessionComposerCredentialRequestLike {
  kind?: string | null;
}

interface SessionComposerClarificationRequestLike {
  kind?: string | null;
}

export interface SessionComposerTaskLike {
  id?: string | null;
  session_id?: string | null;
  sessionId?: string | null;
  phase?: string | null;
  current_step?: string | null;
  currentStep?: string | null;
  pending_request_hash?: string | null;
  pendingRequestHash?: string | null;
  credential_request?: SessionComposerCredentialRequestLike | null;
  credentialRequest?: SessionComposerCredentialRequestLike | null;
  clarification_request?: SessionComposerClarificationRequestLike | null;
  clarificationRequest?: SessionComposerClarificationRequestLike | null;
}

export function isSessionComposerSubmissionBlocked<
  TTask extends SessionComposerTaskLike,
>(task: TTask | null): boolean {
  if (!task) {
    return false;
  }
  if (task.phase === "Gate" || !!(task.pendingRequestHash ?? task.pending_request_hash)) {
    return true;
  }
  if ((task.credentialRequest ?? task.credential_request)?.kind === "sudo_password") {
    return true;
  }
  if (
    (task.clarificationRequest ?? task.clarification_request) &&
    isWaitingForClarificationStep(task.currentStep ?? task.current_step)
  ) {
    return true;
  }
  if (isWaitingForSudoStep(task.currentStep ?? task.current_step)) {
    return true;
  }
  return task.phase === "Running";
}

export interface UseSessionComposerOptions<
  TTask extends SessionComposerTaskLike,
  TLocalHistoryMessage extends SessionComposerMessageLike,
  TChatEvent,
> {
  task: TTask | null;
  intent: string;
  inputRef: RefObject<HTMLTextAreaElement | null>;
  startTask: (intent: string) => Promise<TTask | null>;
  continueTask: (sessionId: string, input: string) => Promise<void>;
  dismissTask?: () => Promise<void>;
  resetSession: () => void;
  setIntent: Dispatch<SetStateAction<string>>;
  setLocalHistory: Dispatch<SetStateAction<TLocalHistoryMessage[]>>;
  setSubmissionInFlight: Dispatch<SetStateAction<boolean>>;
  setSubmissionError: Dispatch<SetStateAction<string | null>>;
  setChatEvents: Dispatch<SetStateAction<TChatEvent[]>>;
  resetInspectionSurface: () => Promise<void> | void;
  beforeStartTask?: (intent: string) => Promise<void>;
  onSubmitError?: (error: unknown) => void;
  onEscapeKeyDown?: () => Promise<void> | void;
  shouldContinueExistingSession?: (task: TTask | null) => boolean;
  inputMaxHeightPx?: number;
  newSessionFocusDelayMs?: number;
  createLocalHistoryMessage?: (input: {
    text: string;
    timestamp: number;
  }) => TLocalHistoryMessage;
  resolveTaskFailureMessage?: (task: TTask) => string | null;
  startTaskUnavailableMessage?: string;
}

function defaultLocalHistoryMessage({
  text,
  timestamp,
}: {
  text: string;
  timestamp: number;
}): SessionComposerMessageLike {
  return {
    role: "user",
    text,
    timestamp,
  };
}

export function defaultShouldContinueExistingSession(
  task: SessionComposerTaskLike | null,
): boolean {
  return !!task && !!task.id && task.phase !== "Failed";
}

export function waitForNextUiPaint(timeoutMs = UI_PAINT_FALLBACK_MS): Promise<void> {
  return new Promise<void>((resolve) => {
    let settled = false;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
      }
      resolve();
    };

    timeoutId = setTimeout(finish, timeoutMs);

    if (
      typeof window !== "undefined" &&
      typeof window.requestAnimationFrame === "function"
    ) {
      window.requestAnimationFrame(() => finish());
      return;
    }

    finish();
  });
}

export function useSessionComposer<
  TTask extends SessionComposerTaskLike,
  TLocalHistoryMessage extends SessionComposerMessageLike,
  TChatEvent,
>({
  task,
  intent,
  inputRef,
  startTask,
  continueTask,
  dismissTask,
  resetSession,
  setIntent,
  setLocalHistory,
  setSubmissionInFlight,
  setSubmissionError,
  setChatEvents,
  resetInspectionSurface,
  beforeStartTask,
  onSubmitError,
  onEscapeKeyDown,
  shouldContinueExistingSession = defaultShouldContinueExistingSession,
  inputMaxHeightPx = 120,
  newSessionFocusDelayMs = 50,
  createLocalHistoryMessage,
  resolveTaskFailureMessage,
  startTaskUnavailableMessage = "Chat could not start this run. Check receipts for backend errors, then try again.",
}: UseSessionComposerOptions<TTask, TLocalHistoryMessage, TChatEvent>) {
  useEffect(() => {
    if (!task) {
      return;
    }

    if (task.phase === "Failed") {
      const resolvedFailureMessage = resolveTaskFailureMessage?.(task);
      setSubmissionInFlight(false);
      setSubmissionError(
        resolvedFailureMessage === undefined
          ? task.current_step ?? "Run could not complete."
          : resolvedFailureMessage,
      );
      return;
    }

    setSubmissionInFlight(false);
    setSubmissionError(null);
  }, [resolveTaskFailureMessage, setSubmissionError, setSubmissionInFlight, task]);

  const waitForUiPaint = useCallback(
    () => waitForNextUiPaint(),
    [],
  );

  const submitText = useCallback(async (rawText: string) => {
    const text = rawText.trim();
    if (!text || isSessionComposerSubmissionBlocked(task)) {
      return;
    }

    try {
      const shouldContinueCurrentSession = shouldContinueExistingSession(task);

      if (shouldContinueCurrentSession) {
        const currentTask = task;
        const sessionId = currentTask ? getSessionId(currentTask) : null;
        if (!sessionId) {
          throw new Error("Composer continuation requires an active session id.");
        }
        flushSync(() => {
          if (inputRef.current) {
            inputRef.current.style.height = "auto";
          }
          setIntent("");
          setSubmissionError(null);
          setSubmissionInFlight(true);
        });
        await waitForUiPaint();
        await continueTask(sessionId, text);
        return;
      }

      if (beforeStartTask) {
        await beforeStartTask(text);
      }

      flushSync(() => {
        if (inputRef.current) {
          inputRef.current.style.height = "auto";
        }
        setIntent("");
        setLocalHistory((current) => [
          ...current,
          (createLocalHistoryMessage ??
            defaultLocalHistoryMessage)({
            text,
            timestamp: Date.now(),
          }) as TLocalHistoryMessage,
        ]);
        setSubmissionError(null);
        setSubmissionInFlight(true);
      });
      await waitForUiPaint();
      const startedTask = await startTask(text);
      if (!startedTask) {
        setSubmissionInFlight(false);
        setSubmissionError(startTaskUnavailableMessage);
      }
    } catch (error) {
      setSubmissionInFlight(false);
      setSubmissionError(String(error));
      onSubmitError?.(error);
    }
  }, [
    beforeStartTask,
    continueTask,
    createLocalHistoryMessage,
    inputRef,
    intent,
    onSubmitError,
    setIntent,
    setLocalHistory,
    setSubmissionError,
    setSubmissionInFlight,
    startTask,
    startTaskUnavailableMessage,
    shouldContinueExistingSession,
    task,
    waitForUiPaint,
  ]);

  const handleSubmit = useCallback(async () => {
    await submitText(intent);
  }, [intent, submitText]);

  const handleNewSession = useCallback(() => {
    const activeSessionId = task ? getSessionId(task) : null;
    resetSession();
    setLocalHistory([]);
    setSubmissionInFlight(false);
    setSubmissionError(null);
    setChatEvents([]);
    void resetInspectionSurface();
    if (activeSessionId && dismissTask) {
      void dismissTask().catch((error) => {
        console.error("Failed to dismiss task while starting a new session:", error);
      });
    }
    window.setTimeout(() => inputRef.current?.focus(), newSessionFocusDelayMs);
  }, [
    dismissTask,
    inputRef,
    newSessionFocusDelayMs,
    resetInspectionSurface,
    resetSession,
    setChatEvents,
    setLocalHistory,
    setSubmissionError,
    setSubmissionInFlight,
    task,
  ]);

  const handleInputChange = useCallback(
    (event: ChangeEvent<HTMLTextAreaElement>) => {
      setIntent(event.target.value);
      event.target.style.height = "auto";
      event.target.style.height = `${Math.min(event.target.scrollHeight, inputMaxHeightPx)}px`;
    },
    [inputMaxHeightPx, setIntent],
  );

  const handleInputKeyDown = useCallback(
    (event: KeyboardEvent<HTMLTextAreaElement>) => {
      if (event.key === "Escape") {
        if (onEscapeKeyDown) {
          event.preventDefault();
          void onEscapeKeyDown();
        }
        return;
      }

      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        void handleSubmit();
      }
    },
    [handleSubmit, onEscapeKeyDown],
  );

  return {
    handleSubmit,
    submitText,
    handleNewSession,
    handleInputChange,
    handleInputKeyDown,
  };
}

export const useSessionInputComposer = useSessionComposer;
export { isWaitingForClarificationStep, isWaitingForSudoStep };
