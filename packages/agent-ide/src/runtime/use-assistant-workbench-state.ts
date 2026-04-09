import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
} from "./agent-runtime";
import {
  assistantWorkbenchActivityTargetKey,
  assistantWorkbenchSessionTargetKey,
  assistantWorkbenchSurfaceForSession,
  type AssistantWorkbenchSurface,
} from "./assistant-workbench-activity";
import {
  activateAssistantWorkbenchSession,
  getActiveAssistantWorkbenchSession,
  getRecentAssistantWorkbenchActivities,
  listenAssistantWorkbenchActivity,
  listenAssistantWorkbenchSession,
  reportAssistantWorkbenchActivity,
} from "./session-runtime";

export interface UseAssistantWorkbenchStateOptions {
  onActivateSession?: (
    session: AssistantWorkbenchSession,
    surface: AssistantWorkbenchSurface,
  ) => void;
}

export function useAssistantWorkbenchState(
  options: UseAssistantWorkbenchStateOptions = {},
) {
  const [assistantWorkbench, setAssistantWorkbench] =
    useState<AssistantWorkbenchSession | null>(null);
  const [assistantWorkbenchActivities, setAssistantWorkbenchActivities] =
    useState<AssistantWorkbenchActivity[]>([]);
  const assistantWorkbenchRef = useRef<AssistantWorkbenchSession | null>(null);
  const onActivateSession = options.onActivateSession;

  const appendWorkbenchActivity = useCallback(
    (activity: AssistantWorkbenchActivity) => {
      setAssistantWorkbenchActivities((current) => {
        const next = [activity, ...current.filter((entry) => entry.activityId !== activity.activityId)];
        return next.slice(0, 12);
      });
    },
    [],
  );

  const seedWorkbenchActivities = useCallback(
    (activities: AssistantWorkbenchActivity[]) => {
      setAssistantWorkbenchActivities((current) => {
        const next = [...activities, ...current].reduce<AssistantWorkbenchActivity[]>(
          (acc, activity) => {
            if (acc.some((entry) => entry.activityId === activity.activityId)) {
              return acc;
            }
            acc.push(activity);
            return acc;
          },
          [],
        );
        next.sort((a, b) => b.timestampMs - a.timestampMs);
        return next.slice(0, 12);
      });
    },
    [],
  );

  const activateAssistantWorkbench = useCallback(
    (session: AssistantWorkbenchSession) => {
      const currentKey = assistantWorkbenchRef.current
        ? assistantWorkbenchSessionTargetKey(assistantWorkbenchRef.current)
        : null;
      const nextKey = assistantWorkbenchSessionTargetKey(session);
      assistantWorkbenchRef.current = session;
      setAssistantWorkbench(session);
      if (currentKey !== nextKey) {
        onActivateSession?.(session, assistantWorkbenchSurfaceForSession(session));
      }
    },
    [onActivateSession],
  );

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;

    const bootstrap = async () => {
      try {
        const dispose = await listenAssistantWorkbenchSession((session) => {
          if (!active) return;
          activateAssistantWorkbench(session);
        });
        if (!active) {
          dispose();
          return;
        }
        unlisten = dispose;
      } catch (error) {
        console.error(
          "Failed to attach assistant workbench listener:",
          error,
        );
      }

      try {
        const session = await getActiveAssistantWorkbenchSession();
        if (!active || !session) {
          return;
        }
        activateAssistantWorkbench(session);
      } catch (error) {
        console.error(
          "Failed to load active assistant workbench session:",
          error,
        );
      }
    };

    void bootstrap();

    return () => {
      active = false;
      unlisten?.();
    };
  }, [activateAssistantWorkbench]);

  useEffect(() => {
    let active = true;
    let unlisten: (() => void) | null = null;

    const bootstrap = async () => {
      try {
        const dispose = await listenAssistantWorkbenchActivity((activity) => {
          if (!active) return;
          appendWorkbenchActivity(activity);
        });
        if (!active) {
          dispose();
          return;
        }
        unlisten = dispose;
      } catch (error) {
        console.error(
          "Failed to attach assistant workbench activity listener:",
          error,
        );
      }

      try {
        const activities = await getRecentAssistantWorkbenchActivities(12);
        if (!active || activities.length === 0) {
          return;
        }
        seedWorkbenchActivities(activities);
      } catch (error) {
        console.error(
          "Failed to load recent assistant workbench activities:",
          error,
        );
      }
    };

    void bootstrap();

    return () => {
      active = false;
      unlisten?.();
    };
  }, [appendWorkbenchActivity, seedWorkbenchActivities]);

  const activeWorkbenchSurface = useMemo(
    () =>
      assistantWorkbench
        ? assistantWorkbenchSurfaceForSession(assistantWorkbench)
        : null,
    [assistantWorkbench],
  );

  const activeAssistantWorkbenchActivities = useMemo(() => {
    if (!assistantWorkbench) return [];
    const activeKey = assistantWorkbenchSessionTargetKey(assistantWorkbench);
    return assistantWorkbenchActivities.filter(
      (activity) => assistantWorkbenchActivityTargetKey(activity) === activeKey,
    );
  }, [assistantWorkbench, assistantWorkbenchActivities]);

  const recordAssistantWorkbenchActivity = useCallback(
    async (activity: AssistantWorkbenchActivity) => {
      appendWorkbenchActivity(activity);
      try {
        await reportAssistantWorkbenchActivity(activity);
      } catch (error) {
        console.error(
          "Failed to broadcast assistant workbench activity:",
          error,
        );
      }
    },
    [appendWorkbenchActivity],
  );

  const clearAssistantWorkbench = useCallback(() => {
    assistantWorkbenchRef.current = null;
    setAssistantWorkbench(null);
  }, []);

  const openReplyComposer = useCallback(
    (
      session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
    ) => {
      activateAssistantWorkbench(session);
      void activateAssistantWorkbenchSession(session).catch((error) => {
        console.error(
          "Failed to persist assistant reply composer activation:",
          error,
        );
      });
    },
    [activateAssistantWorkbench],
  );

  const openMeetingPrep = useCallback(
    (
      session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
    ) => {
      activateAssistantWorkbench(session);
      void activateAssistantWorkbenchSession(session).catch((error) => {
        console.error(
          "Failed to persist assistant meeting prep activation:",
          error,
        );
      });
    },
    [activateAssistantWorkbench],
  );

  return {
    assistantWorkbench,
    assistantWorkbenchActivities,
    activeAssistantWorkbenchActivities,
    activeWorkbenchSurface,
    activateAssistantWorkbench,
    openReplyComposer,
    openMeetingPrep,
    clearAssistantWorkbench,
    recordAssistantWorkbenchActivity,
  };
}
