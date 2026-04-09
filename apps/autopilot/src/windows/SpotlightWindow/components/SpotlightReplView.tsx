import {
  buildSessionReplTargets,
  formatSessionTimeAgo,
  selectPrimarySessionReplTarget,
} from "@ioi/agent-ide";
import {
  useWorkspaceTerminalSession,
  WorkspaceTerminalView,
} from "@ioi/workspace-substrate";
import { useEffect, useMemo, useState } from "react";
import type { AgentTask, ArtifactHubViewKey, SessionSummary } from "../../../types";
import { tauriWorkspaceAdapter } from "../../../services/workspaceAdapter";
import {
  currentSessionIdFromTask,
  mergeCurrentTaskRootIntoTargets,
  selectSessionContinuityTarget,
} from "../../../session/sessionContinuity";
import type {
  SpotlightRemoteContinuityLaunchMode,
  SpotlightRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";

interface SpotlightReplViewProps {
  activeSessionId?: string | null;
  currentTask: AgentTask | null;
  sessions: SessionSummary[];
  launchRequest?: SpotlightRemoteContinuityLaunchRequest | null;
  onLoadSession?: (sessionId: string) => void;
  onLaunchRequestHandled?: () => void;
  onOpenStudioSession?: (sessionId: string) => void;
  onStopSession?: () => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}

function continuityLaunchSourceLabel(source: "mobile" | "server"): string {
  return source === "mobile" ? "Mobile continuity" : "Server continuity";
}

function continuityQueueSessionIdsForRequest(
  request: SpotlightRemoteContinuityLaunchRequest | null,
): string[] {
  if (!request) {
    return [];
  }
  const queue = [request.sessionId, ...(request.queueSessionIds ?? [])]
    .map((sessionId) => sessionId.trim())
    .filter((sessionId, index, sessionIds) => {
      return sessionId.length > 0 && sessionIds.indexOf(sessionId) === index;
    });
  return queue;
}

export function SpotlightReplView({
  activeSessionId,
  currentTask,
  sessions,
  launchRequest,
  onLoadSession,
  onLaunchRequestHandled,
  onOpenStudioSession,
  onStopSession,
  onOpenView,
}: SpotlightReplViewProps) {
  const derivedActiveSessionId = currentSessionIdFromTask(
    currentTask,
    activeSessionId,
  );
  const baseTargets = useMemo(
    () => buildSessionReplTargets(sessions, derivedActiveSessionId),
    [derivedActiveSessionId, sessions],
  );
  const targets = useMemo(
    () => mergeCurrentTaskRootIntoTargets(baseTargets, currentTask, derivedActiveSessionId),
    [baseTargets, currentTask, derivedActiveSessionId],
  );
  const primaryTarget = useMemo(() => {
    const selected = selectPrimarySessionReplTarget(sessions, derivedActiveSessionId);
    if (!selected) {
      return targets[0] ?? null;
    }
    return (
      targets.find((target) => target.sessionId === selected.sessionId) ??
      targets[0] ??
      null
    );
  }, [derivedActiveSessionId, sessions, targets]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    primaryTarget?.sessionId ?? null,
  );
  const [terminalEnabled, setTerminalEnabled] = useState(
    Boolean(primaryTarget?.workspaceRoot),
  );
  const [pendingLaunchRequest, setPendingLaunchRequest] =
    useState<SpotlightRemoteContinuityLaunchRequest | null>(null);
  const [lastLaunchRequest, setLastLaunchRequest] =
    useState<SpotlightRemoteContinuityLaunchRequest | null>(null);

  useEffect(() => {
    setSelectedSessionId((current) => {
      if (current && targets.some((target) => target.sessionId === current)) {
        return current;
      }
      return primaryTarget?.sessionId ?? null;
    });
  }, [primaryTarget?.sessionId, targets]);

  const selectedTarget = useMemo(
    () => selectSessionContinuityTarget(targets, selectedSessionId),
    [selectedSessionId, targets],
  );
  const continuityQueueSessionIds = useMemo(
    () => continuityQueueSessionIdsForRequest(lastLaunchRequest),
    [lastLaunchRequest],
  );
  const continuityQueueIndex =
    selectedSessionId && continuityQueueSessionIds.length > 0
      ? continuityQueueSessionIds.indexOf(selectedSessionId)
      : -1;
  const continuityQueueLoadedCount = continuityQueueSessionIds.filter((sessionId) =>
    targets.some((target) => target.sessionId === sessionId),
  ).length;

  const handleSessionSelection = (
    sessionId: string,
    mode: SpotlightRemoteContinuityLaunchMode | null = null,
  ) => {
    setSelectedSessionId(sessionId);
    const target = selectSessionContinuityTarget(targets, sessionId);
    if (!target) {
      setTerminalEnabled(false);
      if (lastLaunchRequest && mode) {
        setPendingLaunchRequest({
          ...lastLaunchRequest,
          sessionId,
          mode,
        });
      }
      onLoadSession?.(sessionId);
      return;
    }
    if (mode === "review") {
      setTerminalEnabled(false);
      return;
    }
    setTerminalEnabled(Boolean(target.workspaceRoot));
  };

  useEffect(() => {
    if (!launchRequest) {
      return;
    }
    setPendingLaunchRequest(launchRequest);
    setLastLaunchRequest(launchRequest);
    setSelectedSessionId(launchRequest.sessionId);
    onLaunchRequestHandled?.();
  }, [launchRequest, onLaunchRequestHandled]);

  useEffect(() => {
    if (pendingLaunchRequest) {
      if (selectedTarget?.sessionId !== pendingLaunchRequest.sessionId) {
        return;
      }
      setTerminalEnabled(
        pendingLaunchRequest.mode === "attach" &&
          Boolean(selectedTarget?.workspaceRoot),
      );
      setPendingLaunchRequest(null);
      return;
    }
    if (!selectedTarget?.workspaceRoot) {
      setTerminalEnabled(false);
      return;
    }
    setTerminalEnabled(true);
  }, [
    pendingLaunchRequest,
    selectedTarget?.sessionId,
    selectedTarget?.workspaceRoot,
  ]);

  const terminal = useWorkspaceTerminalSession({
    adapter: tauriWorkspaceAdapter,
    root: selectedTarget?.workspaceRoot ?? ".",
    enabled: terminalEnabled && Boolean(selectedTarget?.workspaceRoot),
  });

  const attachableCount = targets.filter((target) => target.attachable).length;
  const runningSession = currentTask?.phase === "Running" || currentTask?.phase === "Gate";

  if (!selectedTarget && !currentTask && sessions.length === 0) {
    return (
      <div className="artifact-hub-permissions">
        <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
          <strong>Session Terminal</strong>
          <p>
            Start or resume a session to attach a workspace runtime console and
            inspect the canonical session from an operator terminal.
          </p>
        </section>
      </div>
    );
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <strong>Session Terminal</strong>
        <p>
          Attach a shared PTY-backed runtime console to the current or a recent
          canonical session workspace without leaving Spotlight.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Targets: {targets.length}</span>
          <span>Attachable: {attachableCount}</span>
          <span>
            Active selection: {selectedTarget?.priorityLabel || "No session selected"}
          </span>
          <span>
            Runtime:{" "}
            {selectedTarget?.workspaceRoot
              ? terminal.enabled
                ? terminal.running
                  ? "Attached"
                  : "Idle"
                : "Detached"
              : "Unavailable"}
          </span>
        </div>
      </section>

      {lastLaunchRequest ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{continuityLaunchSourceLabel(lastLaunchRequest.source)}</strong>
            <span className="artifact-hub-policy-pill">
              {lastLaunchRequest.mode === "attach"
                ? "Attach requested"
                : "Review requested"}
            </span>
          </div>
          <p>{lastLaunchRequest.notice}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Target: {lastLaunchRequest.sessionId.slice(0, 12)}</span>
            <span>
              {lastLaunchRequest.mode === "attach"
                ? "Prefer workspace-backed shell attach"
                : "Prefer retained-session review"}
            </span>
            {continuityQueueSessionIds.length > 1 ? (
              <span>{continuityQueueSessionIds.length} queued continuity targets</span>
            ) : null}
          </div>
        </section>
      ) : null}

      {continuityQueueSessionIds.length > 1 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{lastLaunchRequest?.queueLabel || "Continuity queue"}</strong>
            <span className="artifact-hub-policy-pill">
              {continuityQueueIndex >= 0
                ? `Target ${continuityQueueIndex + 1} of ${continuityQueueSessionIds.length}`
                : `${continuityQueueSessionIds.length} queued`}
            </span>
          </div>
          <p>
            {lastLaunchRequest?.mode === "attach"
              ? "Step through the queued attachable remote sessions without leaving the shared REPL lens."
              : "Step through the queued history-only remote sessions in review mode without attempting PTY attach."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{continuityQueueSessionIds.length} queued</span>
            <span>{continuityQueueLoadedCount} loaded locally</span>
            <span>
              {lastLaunchRequest?.mode === "attach"
                ? "Attach-preferred batch"
                : "Review-preferred batch"}
            </span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--secondary"
              disabled={continuityQueueIndex <= 0}
              onClick={() => {
                if (continuityQueueIndex <= 0) {
                  return;
                }
                handleSessionSelection(
                  continuityQueueSessionIds[continuityQueueIndex - 1],
                  lastLaunchRequest?.mode ?? null,
                );
              }}
            >
              Previous target
            </button>
            <button
              type="button"
              className="artifact-hub-action"
              disabled={
                continuityQueueIndex < 0 ||
                continuityQueueIndex >= continuityQueueSessionIds.length - 1
              }
              onClick={() => {
                if (
                  continuityQueueIndex < 0 ||
                  continuityQueueIndex >= continuityQueueSessionIds.length - 1
                ) {
                  return;
                }
                handleSessionSelection(
                  continuityQueueSessionIds[continuityQueueIndex + 1],
                  lastLaunchRequest?.mode ?? null,
                );
              }}
            >
              Next target
            </button>
          </div>
          <div className="artifact-hub-permissions-list">
            {continuityQueueSessionIds.slice(0, 6).map((sessionId) => {
              const target = selectSessionContinuityTarget(targets, sessionId);
              const selected = sessionId === selectedSessionId;
              return (
                <div
                  key={sessionId}
                  className="artifact-hub-permissions-list__row"
                >
                  <div>
                    <strong>
                      {target?.title || sessionId.slice(0, 12)}
                      {selected ? " · selected" : ""}
                    </strong>
                    <p>
                      {target?.workspaceRoot
                        ? target.workspaceRoot
                        : "Pending local session load"}
                    </p>
                  </div>
                  <div className="artifact-hub-permissions-card__actions">
                    <button
                      type="button"
                      className="artifact-hub-action artifact-hub-action--secondary"
                      onClick={() =>
                        handleSessionSelection(
                          sessionId,
                          lastLaunchRequest?.mode ?? null,
                        )
                      }
                    >
                      {selected ? "Selected" : target ? "Select" : "Load"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{selectedTarget?.title || "No session selected"}</strong>
          <span className="artifact-hub-policy-pill">
            {selectedTarget?.phase || currentTask?.phase || "Idle"}
          </span>
        </div>
        <p>
          {selectedTarget?.resumeHint ||
            selectedTarget?.currentStep ||
            "No retained resume hint is available for this session yet."}
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>
            Session: {selectedTarget?.sessionId.slice(0, 12) || "Unavailable"}
          </span>
          <span>
            Updated:{" "}
            {selectedTarget ? formatSessionTimeAgo(selectedTarget.timestamp) : "Unknown"}
          </span>
          <span>
            Root: {selectedTarget?.workspaceRoot || "No workspace root retained"}
          </span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onLoadSession && selectedTarget ? (
            <button
              type="button"
              className="artifact-hub-action"
              onClick={() => onLoadSession(selectedTarget.sessionId)}
            >
              Resume session
            </button>
          ) : null}
          {onOpenStudioSession && selectedTarget ? (
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--secondary"
              onClick={() => onOpenStudioSession(selectedTarget.sessionId)}
            >
              Continue in Studio
            </button>
          ) : null}
          {selectedTarget?.workspaceRoot ? (
            terminal.enabled ? (
              <button
                type="button"
                className="artifact-hub-action"
                onClick={() => {
                  terminal.stop();
                  setTerminalEnabled(false);
                }}
              >
                Detach REPL
              </button>
            ) : (
              <button
                type="button"
                className="artifact-hub-action"
                onClick={() => {
                  setTerminalEnabled(true);
                  terminal.start();
                }}
              >
                Attach REPL
              </button>
            )
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--secondary"
              onClick={() => onOpenView("tasks")}
            >
              Open tasks
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--secondary"
              onClick={() => onOpenView("files")}
            >
              Open files
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--secondary"
              onClick={() => onOpenView("compact")}
            >
              Open compact
            </button>
          ) : null}
          {onStopSession && runningSession ? (
            <button
              type="button"
              className="artifact-hub-action artifact-hub-action--danger"
              onClick={onStopSession}
            >
              Stop run
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Runtime console</strong>
          <span className="artifact-hub-policy-pill">
            {selectedTarget?.workspaceRoot ? "PTY-backed" : "No workspace"}
          </span>
        </div>
        <p>
          This shell reuses the existing workspace PTY substrate and follows the
          currently selected canonical session root.
        </p>
        {selectedTarget?.workspaceRoot ? (
          <WorkspaceTerminalView
            controller={terminal}
            className="artifact-hub-repl-terminal"
          />
        ) : (
          <div className="workspace-terminal-loading">
            <span className="workspace-pane-eyebrow">Terminal</span>
            <strong>No workspace root available</strong>
            <p>
              Choose a session with a retained workspace root to attach the REPL
              lens and begin reading or writing terminal output.
            </p>
          </div>
        )}
      </section>

      {targets.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent session targets</strong>
            <span className="artifact-hub-policy-pill">{targets.length} available</span>
          </div>
          <div className="artifact-hub-permissions-list">
            {targets.slice(0, 8).map((target) => (
              <div
                key={target.sessionId}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{target.title}</strong>
                  <p>
                    {target.priorityLabel}
                    {target.resumeHint ? ` · ${target.resumeHint}` : ""}
                    {target.workspaceRoot ? ` · ${target.workspaceRoot}` : ""}
                  </p>
                </div>
                <div className="artifact-hub-permissions-card__actions">
                  <button
                    type="button"
                    className="artifact-hub-action artifact-hub-action--secondary"
                    onClick={() => {
                      handleSessionSelection(
                        target.sessionId,
                        target.workspaceRoot ? "attach" : "review",
                      );
                    }}
                  >
                    {target.sessionId === selectedTarget?.sessionId ? "Selected" : "Attach"}
                  </button>
                  {onLoadSession ? (
                    <button
                      type="button"
                      className="artifact-hub-action artifact-hub-action--secondary"
                      onClick={() => onLoadSession(target.sessionId)}
                    >
                      Resume
                    </button>
                  ) : null}
                  {onOpenStudioSession ? (
                    <button
                      type="button"
                      className="artifact-hub-action artifact-hub-action--secondary"
                      onClick={() => onOpenStudioSession(target.sessionId)}
                    >
                      Studio
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
