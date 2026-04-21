import type { SessionControllerReplTarget } from "@ioi/agent-ide";
import type { AgentTask } from "../types";

export interface SessionContinuityOverview {
  targetCount: number;
  attachableCount: number;
  liveCount: number;
  currentSessionId: string | null;
  statusLabel: string;
  detail: string;
}

export function currentSessionIdFromTask(
  task: AgentTask | null,
  activeSessionId?: string | null,
): string | null {
  return task?.session_id || task?.id || activeSessionId || null;
}

export function workspaceRootFromTask(task: AgentTask | null): string | null {
  return (
    task?.build_session?.workspaceRoot ||
    task?.renderer_session?.workspaceRoot ||
    task?.chat_session?.workspaceRoot ||
    null
  );
}

export function sessionTitleFromTask(task: AgentTask | null): string | null {
  const explicit =
    task?.intent?.trim() ||
    task?.current_step?.trim() ||
    task?.history?.find((entry) => entry.role === "user")?.text?.trim() ||
    "";
  return explicit || null;
}

export function mergeCurrentTaskRootIntoTargets(
  targets: SessionControllerReplTarget[],
  task: AgentTask | null,
  activeSessionId?: string | null,
): SessionControllerReplTarget[] {
  const currentSessionId = currentSessionIdFromTask(task, activeSessionId);
  const taskRoot = workspaceRootFromTask(task);
  if (!currentSessionId || !taskRoot) {
    return targets;
  }

  let patched = false;
  const merged = targets.map((target) => {
    if (target.sessionId !== currentSessionId) {
      return target;
    }
    patched = true;
    return {
      ...target,
      workspaceRoot: target.workspaceRoot || taskRoot,
      attachable: true,
      priorityLabel: target.isCurrent ? "Current session" : target.priorityLabel,
    };
  });

  if (patched) {
    return merged;
  }

  return [
    {
      sessionId: currentSessionId,
      title: sessionTitleFromTask(task) || `Session ${currentSessionId.slice(0, 8)}`,
      timestamp: Date.now(),
      phase: task?.phase ?? null,
      currentStep: task?.current_step ?? null,
      resumeHint: "Active session",
      workspaceRoot: taskRoot,
      attachable: true,
      isCurrent: true,
      priorityLabel: "Current session",
    },
    ...merged,
  ];
}

export function selectSessionContinuityTarget(
  targets: SessionControllerReplTarget[],
  selectedSessionId: string | null,
): SessionControllerReplTarget | null {
  if (selectedSessionId) {
    const matched = targets.find((target) => target.sessionId === selectedSessionId);
    if (matched) {
      return matched;
    }
  }

  return targets[0] ?? null;
}

export function buildSessionContinuityOverview(
  targets: SessionControllerReplTarget[],
  currentSessionId?: string | null,
): SessionContinuityOverview {
  const attachableCount = targets.filter((target) => target.attachable).length;
  const liveCount = targets.filter(
    (target) =>
      target.priorityLabel === "Current session" ||
      target.priorityLabel === "Live session",
  ).length;
  const activeTarget =
    (currentSessionId
      ? targets.find((target) => target.sessionId === currentSessionId)
      : null) ?? targets[0] ?? null;

  if (targets.length === 0) {
    return {
      targetCount: 0,
      attachableCount: 0,
      liveCount: 0,
      currentSessionId: currentSessionId ?? null,
      statusLabel: "No retained session targets",
      detail:
        "Run or resume a canonical session to retain cross-shell continuity and a workspace-backed REPL target.",
    };
  }

  if (activeTarget?.isCurrent && activeTarget.attachable) {
    return {
      targetCount: targets.length,
      attachableCount,
      liveCount,
      currentSessionId: activeTarget.sessionId,
      statusLabel: "Current session ready",
      detail:
        "The active canonical session already has a retained workspace root, so Chat and Spotlight can resume and attach without rebuilding local shell state.",
    };
  }

  if (attachableCount > 0) {
    const label =
      attachableCount === 1
        ? "1 attachable session retained"
        : `${attachableCount} attachable sessions retained`;
    return {
      targetCount: targets.length,
      attachableCount,
      liveCount,
      currentSessionId: activeTarget?.sessionId ?? currentSessionId ?? null,
      statusLabel: label,
      detail:
        "Recent canonical sessions still carry workspace roots, so the shared bridge can resume them in Chat or attach a REPL lens on demand.",
    };
  }

  return {
    targetCount: targets.length,
    attachableCount,
    liveCount,
    currentSessionId: activeTarget?.sessionId ?? currentSessionId ?? null,
    statusLabel: "History retained without workspace roots",
    detail:
      "Session summaries are available across shells, but the workspace root needs to be retained before a PTY-backed attach can continue from the same runtime context.",
  };
}
