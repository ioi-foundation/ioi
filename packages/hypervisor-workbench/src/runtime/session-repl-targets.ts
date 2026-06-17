import {
  getSessionId,
  getSessionStepText,
  normalizeSessionSummary,
  sessionSummaryLooksLive,
  shouldRetainSessionOnMissingProjection,
  type SessionProgressLike,
  type SessionSummaryLike,
} from "./session-status";

export interface SessionAttachTarget {
  sessionId: string;
  title: string;
  timestamp: number;
  phase: string | null;
  currentStep: string | null;
  resumeHint: string | null;
  workspaceRoot: string | null;
  isCurrent: boolean;
  attachable: boolean;
  priorityLabel: string;
}

function priorityLabel(
  session: SessionSummaryLike,
  activeSessionId?: string | null,
): string {
  const sessionId = getSessionId(session);
  if (activeSessionId && sessionId === activeSessionId) {
    return "Current session";
  }
  if (sessionSummaryLooksLive(session)) {
    return "Live session";
  }
  if (session.workspaceRoot || session.workspace_root) {
    return "Recent workspace";
  }
  return "Session history";
}

function priorityScore(
  session: SessionSummaryLike,
  activeSessionId?: string | null,
): number {
  const sessionId = getSessionId(session);
  if (activeSessionId && sessionId === activeSessionId) {
    return 4;
  }
  if (sessionSummaryLooksLive(session)) {
    return 3;
  }
  if (session.workspaceRoot || session.workspace_root) {
    return 2;
  }
  return 1;
}

export function resolveSessionRecoveryId<TSessionSummary>(
  retainedSession: unknown,
  sessions: TSessionSummary[],
): string | null {
  if (!shouldRetainSessionOnMissingProjection(retainedSession)) {
    return null;
  }

  const retainedSessionId = getSessionId(retainedSession);
  if (!retainedSessionId) {
    return null;
  }

  const matchingSession = sessions
    .map((session) => normalizeSessionSummary(session))
    .find((session) => getSessionId(session) === retainedSessionId);

  if (!matchingSession) {
    return null;
  }

  return sessionSummaryLooksLive(matchingSession) ? null : retainedSessionId;
}

export function buildSessionAttachTargets<
  TSession extends SessionSummaryLike,
>(
  sessions: TSession[],
  activeSessionId?: string | null,
): SessionAttachTarget[] {
  return [...sessions]
    .sort((left, right) => {
      const priorityDelta =
        priorityScore(right, activeSessionId) -
        priorityScore(left, activeSessionId);
      if (priorityDelta !== 0) {
        return priorityDelta;
      }
      return right.timestamp - left.timestamp;
    })
    .map((session) => {
      const sessionId = getSessionId(session) ?? "";
      return {
        sessionId,
        title: session.title,
        timestamp: session.timestamp,
        phase: session.phase ?? null,
        currentStep: getSessionStepText(session) || null,
        resumeHint: session.resumeHint ?? session.resume_hint ?? null,
        workspaceRoot: session.workspaceRoot ?? session.workspace_root ?? null,
        isCurrent: Boolean(activeSessionId && sessionId === activeSessionId),
        attachable: Boolean(session.workspaceRoot ?? session.workspace_root),
        priorityLabel: priorityLabel(session, activeSessionId),
      };
    });
}

export function selectPrimarySessionAttachTarget<
  TSession extends SessionSummaryLike,
>(
  sessions: TSession[],
  activeSessionId?: string | null,
): SessionAttachTarget | null {
  return buildSessionAttachTargets(sessions, activeSessionId)[0] ?? null;
}

export function shouldRetainHydratedThreadCollections(
  currentSession: unknown,
  nextSession: unknown,
): boolean {
  const currentSessionId = getSessionId(currentSession);
  const nextSessionId = getSessionId(nextSession);
  return Boolean(
    currentSessionId &&
      nextSessionId &&
      currentSessionId === nextSessionId,
  );
}

export function mergeSessionSnapshotCollection<TItem>(
  retained: TItem[],
  incoming: TItem[],
  appendUnique: (items: TItem[], next: TItem) => TItem[],
): TItem[] {
  return incoming.reduce(
    (items, next) => appendUnique(items, next),
    retained,
  );
}

export type RetainableSessionProgressLike = SessionProgressLike;
