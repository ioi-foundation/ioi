import { useEffect, useMemo, useState } from "react";
import {
  loadSessionThreadArtifacts,
  loadSessionThreadEvents,
  type AssistantWorkbenchActivity,
} from "@ioi/agent-ide";
import type { AgentEvent, Artifact } from "../types";

interface RetainedWorkbenchTraceState {
  threadId: string | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  loading: boolean;
  error: string | null;
}

export function useRetainedWorkbenchTrace(
  activities: AssistantWorkbenchActivity[],
) {
  const evidenceThreadId = useMemo(
    () => activities.find((activity) => activity.evidenceThreadId)?.evidenceThreadId ?? null,
    [activities],
  );
  const [trace, setTrace] = useState<RetainedWorkbenchTraceState>({
    threadId: null,
    events: [],
    artifacts: [],
    loading: false,
    error: null,
  });

  useEffect(() => {
    if (!evidenceThreadId) {
      setTrace({
        threadId: null,
        events: [],
        artifacts: [],
        loading: false,
        error: null,
      });
      return;
    }

    let active = true;
    setTrace((current) => ({
      threadId: evidenceThreadId,
      events: current.threadId === evidenceThreadId ? current.events : [],
      artifacts: current.threadId === evidenceThreadId ? current.artifacts : [],
      loading: true,
      error: null,
    }));

    void Promise.all([
      loadSessionThreadEvents<AgentEvent>(evidenceThreadId),
      loadSessionThreadArtifacts<Artifact>(evidenceThreadId),
    ])
      .then(([events, artifacts]) => {
        if (!active) return;
        setTrace({
          threadId: evidenceThreadId,
          events,
          artifacts,
          loading: false,
          error: null,
        });
      })
      .catch((error) => {
        if (!active) return;
        setTrace({
          threadId: evidenceThreadId,
          events: [],
          artifacts: [],
          loading: false,
          error: String(error),
        });
      });

    return () => {
      active = false;
    };
  }, [evidenceThreadId]);

  const latestEvent = useMemo(() => {
    if (trace.events.length === 0) return null;
    return trace.events.reduce<AgentEvent | null>((latest, event) => {
      if (!latest) return event;
      return Date.parse(event.timestamp) > Date.parse(latest.timestamp)
        ? event
        : latest;
    }, null);
  }, [trace.events]);

  const latestArtifact = useMemo(() => {
    if (trace.artifacts.length === 0) return null;
    return trace.artifacts.reduce<Artifact | null>((latest, artifact) => {
      if (!latest) return artifact;
      return Date.parse(artifact.created_at) > Date.parse(latest.created_at)
        ? artifact
        : latest;
    }, null);
  }, [trace.artifacts]);

  return {
    evidenceThreadId,
    trace,
    latestEvent,
    latestArtifact,
  };
}
