import { invoke } from "@tauri-apps/api/core";
import type {
  ConnectorActionResult,
  ConnectorSubscriptionSummary,
} from "@ioi/agent-ide";
import { useEffect, useState } from "react";
import {
  notificationTargetCalendarId,
  notificationTargetConnectorId,
  notificationTargetEventId,
  notificationTargetSubscriptionId,
  notificationTargetThreadId,
} from "../lib/notificationTargets";
import type {
  AssistantNotificationRecord,
  CalendarEventDetail,
  GmailThreadDetail,
  InterventionRecord,
  NotificationTarget,
  WalletConnectorAuthGetResult,
} from "../types";

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function headerMap(message: Record<string, unknown>): Record<string, string> {
  const payload = objectValue(message.payload);
  const headers = arrayValue(payload?.headers);
  const entries = headers
    .map((header) => objectValue(header))
    .filter(Boolean)
    .map(
      (header) =>
        [
          String(header?.name ?? "").toLowerCase(),
          String(header?.value ?? ""),
        ] as const,
    )
    .filter(([name]) => Boolean(name));
  return Object.fromEntries(entries);
}

function parseGmailThread(result: ConnectorActionResult): GmailThreadDetail {
  const payload = objectValue(result.data) ?? {};
  const messages = arrayValue(payload.messages)
    .map((message) => objectValue(message))
    .filter(Boolean)
    .map((message) => {
      const headers = headerMap(message ?? {});
      return {
        id: stringValue(message?.id) ?? "unknown",
        from: headers.from,
        to: headers.to,
        subject: headers.subject,
        date: headers.date,
        snippet: stringValue(message?.snippet),
        rfcMessageId: headers["message-id"],
        references: headers.references,
        labelIds: arrayValue(message?.labelIds)
          .map((value) => stringValue(value))
          .filter(Boolean) as string[],
      };
    });

  return {
    threadId: stringValue(payload.id) ?? "unknown",
    historyId: stringValue(payload.historyId),
    snippet: stringValue(payload.snippet),
    messages,
  };
}

function parseCalendarEvent(
  result: ConnectorActionResult,
): CalendarEventDetail {
  const payload = objectValue(result.data) ?? {};
  return {
    calendarId: stringValue(payload.calendarId) ?? "primary",
    eventId: stringValue(payload.id) ?? "unknown",
    summary: stringValue(payload.summary),
    description: stringValue(payload.description),
    location: stringValue(payload.location),
    status: stringValue(payload.status),
    start:
      stringValue(objectValue(payload.start)?.dateTime) ??
      stringValue(objectValue(payload.start)?.date),
    end:
      stringValue(objectValue(payload.end)?.dateTime) ??
      stringValue(objectValue(payload.end)?.date),
    htmlLink: stringValue(payload.htmlLink),
    attendees: arrayValue(payload.attendees)
      .map((attendee) => objectValue(attendee))
      .filter(Boolean)
      .map((attendee) => ({
        email: stringValue(attendee?.email),
        displayName: stringValue(attendee?.displayName),
        responseStatus: stringValue(attendee?.responseStatus),
        organizer: booleanValue(attendee?.organizer),
      })),
  };
}

type NotificationDetailItem =
  | AssistantNotificationRecord
  | InterventionRecord
  | null;

export function useNotificationTargetDetail(item: NotificationDetailItem) {
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [gmailThread, setGmailThread] = useState<GmailThreadDetail | null>(null);
  const [calendarEvent, setCalendarEvent] =
    useState<CalendarEventDetail | null>(null);
  const [authRecord, setAuthRecord] =
    useState<WalletConnectorAuthGetResult | null>(null);
  const [subscription, setSubscription] =
    useState<ConnectorSubscriptionSummary | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    setGmailThread(null);
    setCalendarEvent(null);
    setAuthRecord(null);
    setSubscription(null);
    setError(null);

    if (!item?.target) {
      return;
    }

    let cancelled = false;

    const load = async (target: NotificationTarget) => {
      setLoading(true);
      try {
        if (target.kind === "gmail_thread") {
          const connectorId = notificationTargetConnectorId(target);
          const threadId = notificationTargetThreadId(target);
          if (!connectorId || !threadId) {
            throw new Error("Missing Gmail thread target detail.");
          }
          const result = await invoke<ConnectorActionResult>(
            "connector_fetch_gmail_thread",
            {
              connectorId,
              connector_id: connectorId,
              threadId,
              thread_id: threadId,
            },
          );
          if (cancelled) return;
          setGmailThread(parseGmailThread(result));
        } else if (target.kind === "calendar_event") {
          const connectorId = notificationTargetConnectorId(target);
          const calendarId = notificationTargetCalendarId(target);
          const eventId = notificationTargetEventId(target);
          if (!connectorId || !calendarId || !eventId) {
            throw new Error("Missing calendar event target detail.");
          }
          const result = await invoke<ConnectorActionResult>(
            "connector_fetch_calendar_event",
            {
              connectorId,
              connector_id: connectorId,
              calendarId,
              calendar_id: calendarId,
              eventId,
              event_id: eventId,
            },
          );
          if (cancelled) return;
          setCalendarEvent(parseCalendarEvent(result));
        } else if (target.kind === "connector_auth") {
          const connectorId = notificationTargetConnectorId(target);
          if (!connectorId) {
            throw new Error("Missing connector auth target detail.");
          }
          const result = await invoke<WalletConnectorAuthGetResult>(
            "wallet_connector_auth_get",
            {
              connectorId,
              connector_id: connectorId,
            },
          );
          if (cancelled) return;
          setAuthRecord(result);
        } else if (target.kind === "connector_subscription") {
          const connectorId = notificationTargetConnectorId(target);
          const subscriptionId = notificationTargetSubscriptionId(target);
          if (!connectorId || !subscriptionId) {
            throw new Error("Missing connector subscription target detail.");
          }
          const result = await invoke<ConnectorSubscriptionSummary>(
            "connector_get_subscription",
            {
              connectorId,
              connector_id: connectorId,
              subscriptionId,
              subscription_id: subscriptionId,
            },
          );
          if (cancelled) return;
          setSubscription(result);
        }
      } catch (nextError) {
        if (!cancelled) {
          setError(String(nextError));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void load(item.target);

    return () => {
      cancelled = true;
    };
  }, [item, refreshKey]);

  const runSubscriptionAction = async (action: "renew" | "resume" | "stop") => {
    if (!item?.target || item.target.kind !== "connector_subscription") return;
    const connectorId = notificationTargetConnectorId(item.target);
    const subscriptionId = notificationTargetSubscriptionId(item.target);
    if (!connectorId || !subscriptionId) {
      setError("Missing connector subscription target detail.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const payload = {
        connectorId,
        connector_id: connectorId,
        subscriptionId,
        subscription_id: subscriptionId,
      };
      if (action === "renew") {
        await invoke("connector_renew_subscription", payload);
      } else if (action === "resume") {
        await invoke("connector_resume_subscription", payload);
      } else {
        await invoke("connector_stop_subscription", payload);
      }
      setRefreshKey((current) => current + 1);
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setBusy(false);
    }
  };

  return {
    loading,
    busy,
    error,
    gmailThread,
    calendarEvent,
    authRecord,
    subscription,
    refresh: () => {
      setRefreshKey((current) => current + 1);
    },
    runSubscriptionAction,
  };
}
