import { useEffect, useMemo, useState } from "react";
import {
  formatSessionTimeAgo,
  type AssistantWorkbenchActivity,
} from "@ioi/agent-ide";
import type { RuntimeValidationStatus } from "../services/runtimeInspection";
import type { AgentEvent, AgentTask, Artifact, SessionSummary } from "../types";

export interface LiveValidationItem {
  id: string;
  label: string;
  status: RuntimeValidationStatus;
  detail: string;
}

export interface LiveValidationSummary {
  title: string;
  subtitle: string;
  lastUpdatedLabel: string | null;
  items: LiveValidationItem[];
}

interface RetainedWorkbenchTraceLike {
  threadId: string | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  loading: boolean;
  error: string | null;
}

interface LatestSessionEvidenceState {
  threadId: string | null;
  title: string | null;
  timestamp: number | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  loading: boolean;
  error: string | null;
}

interface UseLiveValidationSummaryOptions {
  task: AgentTask | null;
  sessions: SessionSummary[];
  retainedWorkbenchActivities: AssistantWorkbenchActivity[];
  retainedWorkbenchTrace: RetainedWorkbenchTraceLike;
  latestRetainedWorkbenchEvent: AgentEvent | null;
  latestRetainedWorkbenchArtifact: Artifact | null;
  loadThreadEvents: (threadId: string) => Promise<AgentEvent[]>;
  loadThreadArtifacts: (threadId: string) => Promise<Artifact[]>;
}

function latestHistoryTimestamp(task: AgentTask | null): number | null {
  if (!task || task.history.length === 0) {
    return null;
  }

  return task.history.reduce<number | null>((latest, message) => {
    const currentMs = parseTimestamp(message.timestamp);
    if (currentMs === null) {
      return latest;
    }
    if (latest === null) {
      return currentMs;
    }
    return currentMs > latest ? currentMs : latest;
  }, null);
}

function latestTaskActivityTimestamp(task: AgentTask | null): number | null {
  if (!task) {
    return null;
  }

  return [
    latestHistoryTimestamp(task),
    parseTimestamp(latestEvent(task.events)?.timestamp),
    parseTimestamp(latestArtifact(task.artifacts)?.created_at),
  ]
    .filter((value): value is number => typeof value === "number" && Number.isFinite(value))
    .sort((left, right) => right - left)[0] ?? null;
}

function parseTimestamp(value: string | number | null | undefined): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function eventText(event: AgentEvent): string {
  return [
    event.title,
    event.event_type,
    JSON.stringify(event.digest),
    JSON.stringify(event.details),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function eventToolName(event: AgentEvent): string | null {
  const digestTool =
    typeof event.digest?.tool_name === "string" ? event.digest.tool_name : null;
  if (digestTool) {
    return digestTool.toLowerCase();
  }

  const detailTool =
    typeof event.details?.tool_name === "string" ? event.details.tool_name : null;
  if (detailTool) {
    return detailTool.toLowerCase();
  }

  const titleMatch = event.title.match(/\b(?:ran|tool)\s+([a-z0-9:_-]+)/i);
  return titleMatch?.[1]?.toLowerCase() ?? null;
}

function hasTool(events: AgentEvent[], toolName: string): boolean {
  const normalized = toolName.toLowerCase();
  return events.some((event) => eventToolName(event) === normalized);
}

function latestEvent(events: AgentEvent[]): AgentEvent | null {
  if (events.length === 0) return null;
  return events.reduce<AgentEvent | null>((latest, event) => {
    const currentMs = parseTimestamp(event.timestamp);
    const latestMs = latest ? parseTimestamp(latest.timestamp) : null;
    if (latestMs === null) return event;
    if (currentMs === null) return latest;
    return currentMs > latestMs ? event : latest;
  }, null);
}

function latestArtifact(artifacts: Artifact[]): Artifact | null {
  if (artifacts.length === 0) return null;
  return artifacts.reduce<Artifact | null>((latest, artifact) => {
    const currentMs = parseTimestamp(artifact.created_at);
    const latestMs = latest ? parseTimestamp(latest.created_at) : null;
    if (latestMs === null) return artifact;
    if (currentMs === null) return latest;
    return currentMs > latestMs ? artifact : latest;
  }, null);
}

function latestWorkbenchActivity(
  activities: AssistantWorkbenchActivity[],
): AssistantWorkbenchActivity | null {
  if (activities.length === 0) return null;
  return [...activities].sort((left, right) => right.timestampMs - left.timestampMs)[0] ?? null;
}

export function useLiveValidationSummary({
  task,
  sessions,
  retainedWorkbenchActivities,
  retainedWorkbenchTrace,
  latestRetainedWorkbenchEvent,
  latestRetainedWorkbenchArtifact,
  loadThreadEvents,
  loadThreadArtifacts,
}: UseLiveValidationSummaryOptions) {
  const latestSession = useMemo(
    () => [...sessions].sort((left, right) => right.timestamp - left.timestamp)[0] ?? null,
    [sessions],
  );
  const currentTaskThreadId = task ? task.session_id || task.id : null;
  const currentTaskActivityMs = latestTaskActivityTimestamp(task);
  const latestSessionThreadId =
    latestSession?.session_id ?? currentTaskThreadId ?? null;
  const [latestSessionEvidence, setLatestSessionEvidence] =
    useState<LatestSessionEvidenceState>({
      threadId: null,
      title: null,
      timestamp: null,
      events: [],
      artifacts: [],
      loading: false,
      error: null,
    });

  useEffect(() => {
    if (!latestSessionThreadId) {
      setLatestSessionEvidence({
        threadId: null,
        title: null,
        timestamp: null,
        events: [],
        artifacts: [],
        loading: false,
        error: null,
      });
      return;
    }

    if (
      task &&
      currentTaskThreadId === latestSessionThreadId &&
      (task.events.length > 0 || task.artifacts.length > 0 || task.history.length > 0)
    ) {
      const latestEvidenceTimestamp =
        [
          latestSession?.timestamp ?? null,
          currentTaskActivityMs,
        ]
          .filter(
            (value): value is number =>
              typeof value === "number" && Number.isFinite(value),
          )
          .sort((left, right) => right - left)[0] ?? null;
      setLatestSessionEvidence({
        threadId: latestSessionThreadId,
        title: latestSession?.title ?? task.intent,
        timestamp: latestEvidenceTimestamp,
        events: task.events,
        artifacts: task.artifacts,
        loading: false,
        error: null,
      });
      return;
    }

    let active = true;
    setLatestSessionEvidence((current) => ({
      threadId: latestSessionThreadId,
      title: latestSession?.title ?? current.title,
      timestamp: latestSession?.timestamp ?? current.timestamp,
      events: current.threadId === latestSessionThreadId ? current.events : [],
      artifacts:
        current.threadId === latestSessionThreadId ? current.artifacts : [],
      loading: true,
      error: null,
    }));

    void Promise.all([
      loadThreadEvents(latestSessionThreadId),
      loadThreadArtifacts(latestSessionThreadId),
    ])
      .then(([events, artifacts]) => {
        if (!active) return;
        setLatestSessionEvidence({
          threadId: latestSessionThreadId,
          title: latestSession?.title ?? task?.intent ?? null,
          timestamp: latestSession?.timestamp ?? null,
          events,
          artifacts,
          loading: false,
          error: null,
        });
      })
      .catch((error) => {
        if (!active) return;
        setLatestSessionEvidence({
          threadId: latestSessionThreadId,
          title: latestSession?.title ?? task?.intent ?? null,
          timestamp: latestSession?.timestamp ?? null,
          events: [],
          artifacts: [],
          loading: false,
          error: String(error),
        });
      });

    return () => {
      active = false;
    };
  }, [
    currentTaskThreadId,
    latestSession?.timestamp,
    latestSession?.title,
    latestSessionThreadId,
    loadThreadArtifacts,
    loadThreadEvents,
    currentTaskActivityMs,
    task,
  ]);

  const latestSessionEvent = useMemo(
    () => latestEvent(latestSessionEvidence.events),
    [latestSessionEvidence.events],
  );
  const latestSessionArtifact = useMemo(
    () => latestArtifact(latestSessionEvidence.artifacts),
    [latestSessionEvidence.artifacts],
  );
  const latestActivity = useMemo(
    () => latestWorkbenchActivity(retainedWorkbenchActivities),
    [retainedWorkbenchActivities],
  );

  const validationSummary = useMemo<LiveValidationSummary>(() => {
    const latestSessionThreadMatchesCurrent =
      latestSessionEvidence.threadId !== null &&
      latestSessionEvidence.threadId === currentTaskThreadId;
    const latestSessionTexts = latestSessionEvidence.events.map(eventText);
    const hasSessionReply =
      hasTool(latestSessionEvidence.events, "chat__reply") ||
      hasTool(latestSessionEvidence.events, "agent__complete");
    const hasInstallTool = hasTool(latestSessionEvidence.events, "package__install");
    const waitingForSudo =
      (latestSessionThreadMatchesCurrent &&
        task?.credential_request?.kind === "sudo_password") ||
      latestSessionTexts.some((text) => text.includes("sudo password"));
    const waitingForClarification =
      (latestSessionThreadMatchesCurrent && Boolean(task?.clarification_request)) ||
      latestSessionTexts.some((text) => text.includes("clarification"));

    const sessionContinuity: LiveValidationItem = !latestSessionThreadId
      ? {
          id: "session",
          label: "Session continuity",
          status: "missing",
          detail: "Run a real Chat query to retain live session proof.",
        }
      : latestSessionEvidence.loading
        ? {
            id: "session",
            label: "Session continuity",
            status: "running",
            detail: "Loading retained evidence for the latest live session.",
          }
        : latestSessionEvidence.error
          ? {
              id: "session",
              label: "Session continuity",
              status: "error",
              detail: `Retained session evidence unavailable: ${latestSessionEvidence.error}`,
            }
          : hasSessionReply
            ? {
                id: "session",
                label: "Session continuity",
                status: "verified",
                detail: latestSessionEvidence.title
                  ? `Latest live session "${latestSessionEvidence.title}" retained reply/completion evidence.`
                  : "Latest live session retained reply/completion evidence.",
              }
            : latestSessionThreadMatchesCurrent && task?.phase === "Gate"
              ? {
                  id: "session",
                  label: "Session continuity",
                  status: "waiting",
                  detail: "Latest live session is paused at an approval gate.",
                }
              : latestSessionThreadMatchesCurrent && task?.phase === "Running"
                ? {
                    id: "session",
                    label: "Session continuity",
                    status: "running",
                    detail: task.current_step
                      ? `Latest live session is still running: ${task.current_step}`
                      : "Latest live session is still running and retaining events.",
                  }
                : latestSessionEvidence.events.length > 0 ||
                    latestSessionEvidence.artifacts.length > 0
                  ? {
                      id: "session",
                      label: "Session continuity",
                      status: "verified",
                      detail: "Latest live session retained activity evidence.",
                    }
                  : {
                      id: "session",
                      label: "Session continuity",
                      status: "missing",
                      detail: "Latest session exists but has not retained evidence yet.",
                    };

    const governedResume: LiveValidationItem = !latestSessionThreadId
      ? {
          id: "governed",
          label: "Governed install/resume",
          status: "missing",
          detail: "No recent governed session has been retained yet.",
        }
      : latestSessionEvidence.loading
        ? {
            id: "governed",
            label: "Governed install/resume",
            status: "running",
            detail: "Loading retained governed-session evidence.",
          }
        : latestSessionEvidence.error
          ? {
              id: "governed",
              label: "Governed install/resume",
              status: "error",
              detail: "Retained governed-session evidence is unavailable.",
            }
          : hasInstallTool && hasSessionReply
            ? {
                id: "governed",
                label: "Governed install/resume",
                status: "verified",
                detail: "Latest governed install retained both tool and terminal completion evidence.",
              }
            : hasInstallTool && waitingForSudo
              ? {
                  id: "governed",
                  label: "Governed install/resume",
                  status: "waiting",
                  detail: "Latest governed install is waiting for a runtime secret.",
                }
              : hasInstallTool && waitingForClarification
                ? {
                    id: "governed",
                    label: "Governed install/resume",
                    status: "waiting",
                    detail: "Latest governed session is paused for clarification.",
                  }
                : hasInstallTool
                  ? {
                      id: "governed",
                      label: "Governed install/resume",
                      status: "running",
                      detail: "Governed install activity was observed without terminal proof yet.",
                    }
                  : {
                      id: "governed",
                      label: "Governed install/resume",
                      status: "missing",
                      detail: "No recent governed install/resume proof is visible on the latest retained session.",
                    };

    const workbenchExecution: LiveValidationItem =
      !latestActivity && !retainedWorkbenchTrace.threadId
        ? {
            id: "workbench",
            label: "Workbench execution",
            status: "missing",
            detail: "Run a Gate or Pill reply/prep flow to retain workbench proof.",
          }
        : retainedWorkbenchTrace.loading
          ? {
              id: "workbench",
              label: "Workbench execution",
              status: "running",
              detail: "Loading retained workbench evidence.",
            }
          : retainedWorkbenchTrace.error
            ? {
                id: "workbench",
                label: "Workbench execution",
                status: "error",
                detail: `Retained workbench evidence unavailable: ${retainedWorkbenchTrace.error}`,
              }
            : latestActivity?.status === "succeeded"
              ? {
                  id: "workbench",
                  label: "Workbench execution",
                  status: "verified",
                  detail: latestActivity.message,
                }
              : latestActivity?.status === "failed"
                ? {
                    id: "workbench",
                    label: "Workbench execution",
                    status: "error",
                    detail: latestActivity.message,
                  }
                : latestActivity?.status === "requested"
                  ? {
                      id: "workbench",
                      label: "Workbench execution",
                      status: "waiting",
                      detail: latestActivity.message,
                    }
                  : latestActivity?.status === "started"
                    ? {
                        id: "workbench",
                        label: "Workbench execution",
                        status: "running",
                        detail: latestActivity.message,
                      }
                    : retainedWorkbenchTrace.events.length > 0 ||
                        retainedWorkbenchTrace.artifacts.length > 0
                      ? {
                          id: "workbench",
                          label: "Workbench execution",
                          status: "verified",
                          detail: "Retained workbench evidence is available from the latest operator run.",
                        }
                      : {
                          id: "workbench",
                          label: "Workbench execution",
                          status: "missing",
                          detail: "No retained workbench evidence is visible yet.",
                        };

    const lastUpdatedMs = [
      latestSessionEvidence.timestamp,
      latestSessionThreadMatchesCurrent ? currentTaskActivityMs : null,
      parseTimestamp(latestSessionEvent?.timestamp),
      parseTimestamp(latestSessionArtifact?.created_at),
      latestActivity?.timestampMs ?? null,
      parseTimestamp(latestRetainedWorkbenchEvent?.timestamp),
      parseTimestamp(latestRetainedWorkbenchArtifact?.created_at),
    ]
      .filter((value): value is number => typeof value === "number" && Number.isFinite(value))
      .sort((left, right) => right - left)[0] ?? null;

    return {
      title: "Last live validation",
      subtitle:
        "Real runtime/session proof retained from the latest session and workbench evidence threads.",
      lastUpdatedLabel:
        lastUpdatedMs !== null ? `Updated ${formatSessionTimeAgo(lastUpdatedMs)}` : null,
      items: [sessionContinuity, governedResume, workbenchExecution],
    };
  }, [
    currentTaskThreadId,
    latestActivity,
    latestRetainedWorkbenchArtifact,
    latestRetainedWorkbenchEvent,
    latestSessionArtifact,
    latestSessionEvidence,
    latestSessionEvent,
    latestSessionThreadId,
    currentTaskActivityMs,
    retainedWorkbenchTrace,
    task,
  ]);

  const preferredEvidenceArtifactId =
    latestRetainedWorkbenchArtifact?.artifact_id ??
    latestSessionArtifact?.artifact_id ??
    null;

  return {
    validationSummary,
    preferredEvidenceArtifactId,
  };
}
