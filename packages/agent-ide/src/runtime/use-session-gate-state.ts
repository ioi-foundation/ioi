import { useCallback, useEffect, useMemo, useState } from "react";
import { respondToSessionGate } from "./session-runtime";

export interface SessionGateChatEvent {
  role: string;
  text: string;
  timestamp: number;
  isGate?: boolean;
  gateData?: unknown;
}

export interface SessionGatePiiInfo {
  decision_hash: string;
  target_label: string;
  span_summary: string;
  class_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
  stage2_prompt: string;
  deadline_ms: number;
  target_id?: Record<string, unknown> | null;
}

export interface SessionGateInfo {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
  approve_label?: string;
  deny_label?: string;
  deadline_ms?: number;
  surface_label?: string;
  scope_label?: string;
  operation_label?: string;
  target_label?: string;
  operator_note?: string;
  pii?: SessionGatePiiInfo;
}

export interface SessionCredentialRequest {
  kind: string;
  prompt: string;
  one_time?: boolean;
}

export interface SessionClarificationOption {
  id: string;
  label: string;
  description: string;
  recommended?: boolean;
}

export interface SessionClarificationRequest {
  kind: string;
  question: string;
  tool_name?: string;
  failure_class?: string;
  evidence_snippet?: string;
  context_hint?: string;
  options: SessionClarificationOption[];
  allow_other?: boolean;
}

export interface SessionGateTaskLike {
  id?: string | null;
  session_id?: string | null;
  phase?: string | null;
  current_step?: string | null;
  pending_request_hash?: string | null;
  gate_info?: SessionGateInfo | null;
  credential_request?: SessionCredentialRequest | null;
  clarification_request?: SessionClarificationRequest | null;
}

export interface UseSessionGateStateOptions<TTask extends SessionGateTaskLike> {
  task: TTask | null;
}

export function useSessionGateState<TTask extends SessionGateTaskLike>({
  task,
}: UseSessionGateStateOptions<TTask>) {
  const [gateActionError, setGateActionError] = useState<string | null>(null);
  const [chatEvents, setChatEvents] = useState<SessionGateChatEvent[]>([]);
  const [runtimePasswordPending, setRuntimePasswordPending] = useState(false);
  const [runtimePasswordSessionId, setRuntimePasswordSessionId] = useState<string | null>(
    null,
  );

  const hasPendingApproval = !!task?.pending_request_hash;
  const credentialRequest = task?.credential_request ?? undefined;
  const clarificationRequest = task?.clarification_request ?? undefined;
  const activeSessionId = task?.session_id || task?.id || null;

  const waitingForSudoByStep = (task?.current_step || "")
    .toLowerCase()
    .includes("waiting for sudo password");
  const waitingForClarificationByStep = (() => {
    const step = (task?.current_step || "").toLowerCase();
    return (
      step.includes("waiting for clarification") ||
      step.includes("waiting for intent clarification") ||
      step.includes("wait_for_clarification")
    );
  })();

  const waitingForSudoPrompt =
    credentialRequest?.kind === "sudo_password" || waitingForSudoByStep;
  const suppressPasswordPrompt =
    runtimePasswordPending &&
    !!runtimePasswordSessionId &&
    runtimePasswordSessionId === activeSessionId;
  const showPasswordPrompt =
    waitingForSudoPrompt &&
    !suppressPasswordPrompt &&
    !!(task?.session_id || task?.id);
  const showClarificationPrompt =
    !!clarificationRequest &&
    !!(task?.session_id || task?.id) &&
    (waitingForClarificationByStep ||
      task?.phase === "Complete" ||
      task?.phase === "Running");
  const inputLockedByCredential = showPasswordPrompt || showClarificationPrompt;

  const gateInfo: SessionGateInfo | undefined = useMemo(() => {
    if (task?.gate_info) {
      return task.gate_info;
    }
    if (!hasPendingApproval) {
      return undefined;
    }
    return {
      title: "Approval Required",
      description: task?.pending_request_hash
        ? `Authorization required for request ${task.pending_request_hash}.`
        : "Authorization required before execution can continue.",
      risk: "high",
    };
  }, [hasPendingApproval, task?.gate_info, task?.pending_request_hash]);

  const isPiiGate = !!gateInfo?.pii;
  const activeRequestHash = task?.pending_request_hash || undefined;
  const isGated =
    !showPasswordPrompt &&
    !showClarificationPrompt &&
    (task?.phase === "Gate" || hasPendingApproval) &&
    !!gateInfo;
  const gateDeadlineMs = gateInfo?.deadline_ms ?? gateInfo?.pii?.deadline_ms ?? undefined;

  const handleApprove = useCallback(async () => {
    setGateActionError(null);
    try {
      await respondToSessionGate({ approved: true, requestHash: activeRequestHash });
      setChatEvents((prev) =>
        prev.map((event) =>
          event.isGate ? { ...event, isGate: false, text: "✓ Approved" } : event,
        ),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : String(error || "Gate action failed");
      setGateActionError(`Submit failed: ${reason}`);
    }
  }, [activeRequestHash, setChatEvents]);

  const handleDeny = useCallback(async () => {
    setGateActionError(null);
    try {
      await respondToSessionGate({
        approved: false,
        action: "deny",
        requestHash: activeRequestHash,
      });
      setChatEvents((prev) =>
        prev.map((event) =>
          event.isGate ? { ...event, isGate: false, text: "✗ Denied" } : event,
        ),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : String(error || "Gate action failed");
      setGateActionError(`Submit failed: ${reason}`);
    }
  }, [activeRequestHash, setChatEvents]);

  const handleGrantScopedException = useCallback(async () => {
    setGateActionError(null);
    try {
      await respondToSessionGate({
        approved: true,
        action: "grant_scoped_exception",
        requestHash: activeRequestHash,
      });
      setChatEvents((prev) =>
        prev.map((event) =>
          event.isGate
            ? { ...event, isGate: false, text: "✓ Scoped exception granted" }
            : event,
        ),
      );
    } catch (error) {
      const reason =
        error instanceof Error ? error.message : String(error || "Gate action failed");
      setGateActionError(`Submit failed: ${reason}`);
    }
  }, [activeRequestHash, setChatEvents]);

  useEffect(() => {
    if (task && task.phase === "Gate" && task.gate_info) {
      const last = chatEvents[chatEvents.length - 1];
      if (!last || !last.isGate) {
        setChatEvents((prev) => [
          ...prev,
          {
            role: "system",
            text: "",
            timestamp: Date.now(),
            isGate: true,
            gateData: task.gate_info,
          },
        ]);
      }
    }
  }, [chatEvents, setChatEvents, task]);

  useEffect(() => {
    if (!runtimePasswordPending) {
      return;
    }
    if (!activeSessionId || runtimePasswordSessionId !== activeSessionId) {
      setRuntimePasswordPending(false);
      setRuntimePasswordSessionId(null);
      return;
    }
    if (!waitingForSudoPrompt) {
      setRuntimePasswordPending(false);
      setRuntimePasswordSessionId(null);
    }
  }, [
    activeSessionId,
    runtimePasswordPending,
    runtimePasswordSessionId,
    setRuntimePasswordPending,
    setRuntimePasswordSessionId,
    waitingForSudoPrompt,
  ]);

  useEffect(() => {
    if (!isGated) {
      setGateActionError(null);
    }
  }, [isGated]);

  useEffect(() => {
    if (!isGated || typeof gateDeadlineMs !== "number") {
      return;
    }
    const emitTimeoutNote = () => {
      setChatEvents((prev) => [
        ...prev,
        {
          role: "system",
          text: "⏱ Approval timed out. Submitting deny action.",
          timestamp: Date.now(),
        },
      ]);
    };
    const remaining = gateDeadlineMs - Date.now();
    if (remaining <= 0) {
      emitTimeoutNote();
      void handleDeny();
      return;
    }
    const timer = window.setTimeout(() => {
      emitTimeoutNote();
      void handleDeny();
    }, remaining);
    return () => window.clearTimeout(timer);
  }, [gateDeadlineMs, handleDeny, isGated, setChatEvents]);

  return {
    chatEvents,
    setChatEvents,
    runtimePasswordPending,
    setRuntimePasswordPending,
    runtimePasswordSessionId,
    setRuntimePasswordSessionId,
    gateActionError,
    credentialRequest,
    clarificationRequest,
    activeSessionId,
    hasPendingApproval,
    waitingForSudoPrompt,
    showPasswordPrompt,
    showClarificationPrompt,
    inputLockedByCredential,
    gateInfo,
    isPiiGate,
    isGated,
    gateDeadlineMs,
    handleApprove,
    handleDeny,
    handleGrantScopedException,
  };
}
