import type { NotificationTarget } from "../types";

function preferredString(
  primary: string | null | undefined,
  fallback: string | null | undefined,
): string | null {
  return primary?.trim() || fallback?.trim() || null;
}

export function notificationTargetConnectorId(
  target: NotificationTarget | null | undefined,
): string | null {
  if (!target) return null;
  return preferredString(target.connectorId, target.connector_id);
}

export function notificationTargetThreadId(
  target: Extract<NotificationTarget, { kind: "gmail_thread" }> | null | undefined,
): string | null {
  if (!target) return null;
  return preferredString(target.threadId, target.thread_id);
}

export function notificationTargetCalendarId(
  target: Extract<NotificationTarget, { kind: "calendar_event" }> | null | undefined,
): string | null {
  if (!target) return null;
  return preferredString(target.calendarId, target.calendar_id);
}

export function notificationTargetEventId(
  target: Extract<NotificationTarget, { kind: "calendar_event" }> | null | undefined,
): string | null {
  if (!target) return null;
  return preferredString(target.eventId, target.event_id);
}

export function notificationTargetSubscriptionId(
  target: Extract<NotificationTarget, { kind: "connector_subscription" }> | null | undefined,
): string | null {
  if (!target) return null;
  return preferredString(target.subscriptionId, target.subscription_id);
}
