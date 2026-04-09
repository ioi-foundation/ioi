import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  AssistantNotificationRecord,
  AssistantNotificationStatus,
  InterventionRecord,
  InterventionStatus,
} from "../types";
import { buildInboxQueueItems } from "../lib/operatorInboxQueue";
import {
  isResolvedAssistant,
  isResolvedIntervention,
} from "../lib/operatorNotifications";

type OperatorNotificationsState = {
  badgeCount: number;
  interventions: InterventionRecord[];
  assistantNotifications: AssistantNotificationRecord[];
  loading: boolean;
  error: string | null;
};

const INITIAL_STATE: OperatorNotificationsState = {
  badgeCount: 0,
  interventions: [],
  assistantNotifications: [],
  loading: true,
  error: null,
};

function upsertById<T extends { itemId: string; updatedAtMs: number }>(
  items: T[],
  next: T,
): T[] {
  const existingIndex = items.findIndex((item) => item.itemId === next.itemId);
  if (existingIndex === -1) {
    return [next, ...items];
  }

  const updated = [...items];
  updated[existingIndex] = next;
  return updated;
}

function sortByUpdatedAt<T extends { updatedAtMs: number }>(items: T[]): T[] {
  return [...items].sort((left, right) => right.updatedAtMs - left.updatedAtMs);
}

export function useOperatorNotifications() {
  const [state, setState] = useState<OperatorNotificationsState>(INITIAL_STATE);

  const refreshNotifications = useCallback(async () => {
    try {
      const [badgeCount, interventions, assistantNotifications] = await Promise.all([
        invoke<number>("notification_badge_count_get"),
        invoke<InterventionRecord[]>("notification_list_interventions"),
        invoke<AssistantNotificationRecord[]>("notification_list_assistant"),
      ]);
      setState({
        badgeCount,
        interventions: sortByUpdatedAt(interventions),
        assistantNotifications: sortByUpdatedAt(assistantNotifications),
        loading: false,
        error: null,
      });
    } catch (error) {
      setState((current) => ({
        ...current,
        loading: false,
        error: String(error),
      }));
    }
  }, []);

  useEffect(() => {
    let active = true;

    void refreshNotifications();

    const listeners = Promise.all([
      listen<number>("notifications-badge-updated", (event) => {
        if (!active) return;
        setState((current) => ({
          ...current,
          badgeCount: event.payload,
        }));
        void refreshNotifications();
      }),
      listen<InterventionRecord>("intervention-updated", (event) => {
        if (!active) return;
        setState((current) => ({
          ...current,
          interventions: sortByUpdatedAt(
            upsertById(current.interventions, event.payload),
          ),
        }));
      }),
      listen<AssistantNotificationRecord>(
        "assistant-notification-updated",
        (event) => {
          if (!active) return;
          setState((current) => ({
            ...current,
            assistantNotifications: sortByUpdatedAt(
              upsertById(current.assistantNotifications, event.payload),
            ),
          }));
        },
      ),
    ]);

    return () => {
      active = false;
      void listeners.then((unlisteners) =>
        unlisteners.forEach((unlisten) => unlisten()),
      );
    };
  }, [refreshNotifications]);

  const updateInterventionStatus = useCallback(
    async (
      itemId: string,
      status: InterventionStatus,
      snoozedUntilMs?: number | null,
    ) => {
      await invoke("notification_update_intervention_status", {
        itemId,
        item_id: itemId,
        status,
        snoozedUntilMs,
        snoozed_until_ms: snoozedUntilMs,
      });
    },
    [],
  );

  const updateAssistantStatus = useCallback(
    async (
      itemId: string,
      status: AssistantNotificationStatus,
      snoozedUntilMs?: number | null,
    ) => {
      await invoke("notification_update_assistant_status", {
        itemId,
        item_id: itemId,
        status,
        snoozedUntilMs,
        snoozed_until_ms: snoozedUntilMs,
      });
    },
    [],
  );

  const pendingInterventions = useMemo(
    () =>
      state.interventions.filter((item) => !isResolvedIntervention(item.status)),
    [state.interventions],
  );

  const pendingAssistantNotifications = useMemo(
    () =>
      state.assistantNotifications.filter(
        (item) => !isResolvedAssistant(item.status),
      ),
    [state.assistantNotifications],
  );

  const queueItems = useMemo(
    () => buildInboxQueueItems(state.interventions, state.assistantNotifications),
    [state.assistantNotifications, state.interventions],
  );

  const activeQueueItems = useMemo(
    () => queueItems.filter((item) => item.lane !== "resolved"),
    [queueItems],
  );

  const topQueueItem = activeQueueItems[0] ?? null;
  const topIntervention = pendingInterventions[0] ?? null;
  const topAssistantNotification = pendingAssistantNotifications[0] ?? null;

  return {
    ...state,
    pendingInterventions,
    pendingAssistantNotifications,
    queueItems,
    activeQueueItems,
    topQueueItem,
    topIntervention,
    topAssistantNotification,
    refreshNotifications,
    updateInterventionStatus,
    updateAssistantStatus,
  };
}
