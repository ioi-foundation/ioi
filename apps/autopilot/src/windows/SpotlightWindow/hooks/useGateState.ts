import { useCallback, useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { invoke } from "@tauri-apps/api/core";
import type {
  ChatMessage,
} from "../../../types";
import type {
  AgentTask,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
} from "../../../store/agentStore";

export type ChatEvent = ChatMessage & {
  isGate?: boolean;
  gateData?: unknown;
};

type UseGateStateOptions = {
  task: AgentTask | null;
  chatEvents: ChatEvent[];
  setChatEvents: Dispatch<SetStateAction<ChatEvent[]>>;
  runtimePasswordPending: boolean;
  runtimePasswordSessionId: string | null;
  setRuntimePasswordPending: Dispatch<SetStateAction<boolean>>;
  setRuntimePasswordSessionId: Dispatch<SetStateAction<string | null>>;
};

export function useGateState({
  task,
  chatEvents,
  setChatEvents,
  runtimePasswordPending,
  runtimePasswordSessionId,
  setRuntimePasswordPending,
  setRuntimePasswordSessionId,
}: UseGateStateOptions) {
  const [gateActionError, setGateActionError] = useState<string | null>(null);

  const hasPendingApproval = !!task?.pending_request_hash;
  const credentialRequest: CredentialRequest | undefined = task?.credential_request;
  const clarificationRequest: ClarificationRequest | undefined = task?.clarification_request;
  const activeSessionId = task?.id || task?.session_id || null;

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

  const waitingForSudoPrompt = credentialRequest?.kind === "sudo_password" || waitingForSudoByStep;
  const suppressPasswordPrompt =
    runtimePasswordPending &&
    !!runtimePasswordSessionId &&
    runtimePasswordSessionId === activeSessionId;
  const showPasswordPrompt =
    waitingForSudoPrompt &&
    task?.phase === "Complete" &&
    !suppressPasswordPrompt &&
    !!(task?.session_id || task?.id);
  const showClarificationPrompt =
    !!clarificationRequest &&
    !!(task?.session_id || task?.id) &&
    waitingForClarificationByStep &&
    task?.phase === "Complete";
  const inputLockedByCredential = showPasswordPrompt || showClarificationPrompt;

  const gateInfo: GateInfo | undefined = useMemo(() => {
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
      await invoke("gate_respond", { approved: true, requestHash: activeRequestHash });
      setChatEvents((prev) =>
        prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✓ Approved" } : m)),
      );
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err || "Gate action failed");
      setGateActionError(`Submit failed: ${reason}`);
    }
  }, [activeRequestHash, setChatEvents]);

  const handleDeny = useCallback(async () => {
    setGateActionError(null);
    try {
      await invoke("gate_respond", {
        approved: false,
        action: "deny",
        requestHash: activeRequestHash,
      });
      setChatEvents((prev) =>
        prev.map((m) => (m.isGate ? { ...m, isGate: false, text: "✗ Denied" } : m)),
      );
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err || "Gate action failed");
      setGateActionError(`Submit failed: ${reason}`);
    }
  }, [activeRequestHash, setChatEvents]);

  const handleGrantScopedException = useCallback(async () => {
    setGateActionError(null);
    try {
      await invoke("gate_respond", {
        approved: true,
        action: "grant_scoped_exception",
        requestHash: activeRequestHash,
      });
      setChatEvents((prev) =>
        prev.map((m) =>
          m.isGate ? { ...m, isGate: false, text: "✓ Scoped exception granted" } : m,
        ),
      );
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err || "Gate action failed");
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
    if (!runtimePasswordPending) return;
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
    if (!isGated || typeof gateDeadlineMs !== "number") return;
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
