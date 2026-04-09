import type { SessionServerSessionRecord, SessionServerSnapshot } from "../../../types";
import type {
  SpotlightRemoteContinuityLaunchMode,
  SpotlightRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";

export type RemoteContinuityGovernanceTone =
  | "ready"
  | "review"
  | "setup"
  | "attention";

export interface RemoteContinuityGovernanceAction {
  label: string;
  detail: string;
  sessionCount: number;
  launchRequest: SpotlightRemoteContinuityLaunchRequest;
}

export interface RemoteContinuityGovernanceOverview {
  tone: RemoteContinuityGovernanceTone;
  statusLabel: string;
  detail: string;
  checklist: string[];
  primaryAction: RemoteContinuityGovernanceAction | null;
  secondaryAction: RemoteContinuityGovernanceAction | null;
}

function sortedSessionQueue(
  sessions: SessionServerSessionRecord[],
): SessionServerSessionRecord[] {
  return [...sessions].sort((left, right) => right.timestamp - left.timestamp);
}

function buildQueueLaunchRequest(input: {
  sessions: SessionServerSessionRecord[];
  mode: SpotlightRemoteContinuityLaunchMode;
  queueLabel: string;
  notice: string;
}): SpotlightRemoteContinuityLaunchRequest | null {
  const queue = sortedSessionQueue(input.sessions)
    .map((session) => session.sessionId.trim())
    .filter((sessionId, index, sessionIds) => {
      return sessionId.length > 0 && sessionIds.indexOf(sessionId) === index;
    });

  const [firstSessionId] = queue;
  if (!firstSessionId) {
    return null;
  }

  return {
    sessionId: firstSessionId,
    source: "server",
    mode: input.mode,
    notice: input.notice,
    queueSessionIds: queue,
    queueLabel: input.queueLabel,
  };
}

function buildQueueAction(input: {
  sessions: SessionServerSessionRecord[];
  mode: SpotlightRemoteContinuityLaunchMode;
}): RemoteContinuityGovernanceAction | null {
  const sessionCount = input.sessions.length;
  if (sessionCount === 0) {
    return null;
  }

  const label =
    input.mode === "attach"
      ? sessionCount > 1
        ? `Attach ${sessionCount} remote sessions`
        : "Attach remote session"
      : sessionCount > 1
        ? `Review ${sessionCount} remote sessions`
        : "Review remote session";
  const detail =
    input.mode === "attach"
      ? sessionCount > 1
        ? "Queue the attachable retained remote sessions into the shared Spotlight REPL so the operator can step through workspace-backed continuity targets without losing server merge posture."
        : "Queue the newest attachable retained remote session into the shared Spotlight REPL."
      : sessionCount > 1
        ? "Queue the history-only retained remote sessions into the shared Spotlight REPL so review can move through them without attempting PTY attach."
        : "Queue the newest history-only retained remote session into the shared Spotlight REPL for retained-session review.";
  const launchRequest = buildQueueLaunchRequest({
    sessions: input.sessions,
    mode: input.mode,
    queueLabel:
      input.mode === "attach"
        ? "Attachable remote continuity queue"
        : "History-only remote continuity queue",
    notice:
      input.mode === "attach"
        ? `Server continuity queued ${sessionCount} attachable retained remote session${sessionCount === 1 ? "" : "s"} for shared REPL attach control.`
        : `Server continuity queued ${sessionCount} history-only retained remote session${sessionCount === 1 ? "" : "s"} for shared REPL review control.`,
  });
  if (!launchRequest) {
    return null;
  }

  return {
    label,
    detail,
    sessionCount,
    launchRequest,
  };
}

export function buildRemoteContinuityGovernanceOverview(
  snapshot: SessionServerSnapshot | null,
): RemoteContinuityGovernanceOverview {
  if (!snapshot) {
    return {
      tone: "setup",
      statusLabel: "Remote continuity governance waiting on server posture",
      detail:
        "Load a server continuity snapshot before the shell can recommend attach or review batches over retained remote history.",
      checklist: ["Awaiting server snapshot"],
      primaryAction: null,
      secondaryAction: null,
    };
  }

  const attachableSessions = sortedSessionQueue(
    snapshot.recentRemoteSessions.filter((session) =>
      Boolean(session.workspaceRoot?.trim()),
    ),
  );
  const historyOnlySessions = sortedSessionQueue(
    snapshot.recentRemoteSessions.filter(
      (session) => !session.workspaceRoot?.trim(),
    ),
  );

  const primaryAction =
    buildQueueAction({ sessions: attachableSessions, mode: "attach" }) ??
    buildQueueAction({ sessions: historyOnlySessions, mode: "review" });
  const secondaryAction =
    attachableSessions.length > 0 && historyOnlySessions.length > 0
      ? buildQueueAction({ sessions: historyOnlySessions, mode: "review" })
      : null;

  const tone: RemoteContinuityGovernanceTone = !snapshot.kernelReachable
    ? "attention"
    : attachableSessions.length > 0
      ? "ready"
      : historyOnlySessions.length > 0
        ? "review"
        : "setup";
  const statusLabel =
    attachableSessions.length > 0
      ? "Remote continuity queue ready"
      : historyOnlySessions.length > 0
        ? "Remote review queue ready"
        : !snapshot.kernelReachable
          ? "Remote continuity attention required"
          : "No retained remote queue yet";
  const detail =
    attachableSessions.length > 0 && historyOnlySessions.length > 0
      ? "Attachable remote sessions can move through the shared REPL as a batch while history-only sessions stay available in a separate review queue."
      : attachableSessions.length > 0
        ? "The server continuity surface has attachable retained remote sessions ready for shared REPL control."
        : historyOnlySessions.length > 0
          ? "Only history-only retained remote sessions are available right now, so review mode is the governed continuity path."
          : !snapshot.kernelReachable
            ? "The configured remote kernel is unreachable, so continuity governance is waiting on a fresh server snapshot."
            : "Retained remote history has not produced a governable continuity queue yet.";

  return {
    tone,
    statusLabel,
    detail,
    checklist: [
      `${attachableSessions.length} attachable queued`,
      `${historyOnlySessions.length} review queued`,
      `${snapshot.remoteOnlySessionCount} remote-only`,
      `${snapshot.mergedSessionCount} merged`,
    ],
    primaryAction,
    secondaryAction,
  };
}
