import type {
  AssistantNotificationRecord,
  AssistantWorkbenchSession,
  CalendarEventDetail,
  GmailThreadDetail,
  InterventionRecord,
} from "../types";
import { notificationTargetConnectorId } from "./notificationTargets";

type NotificationDetailItem = AssistantNotificationRecord | InterventionRecord;

export type OperatorWorkbenchSummary =
  | {
      kind: "gmail_reply";
      title: string;
      summary: string;
      meta: string[];
      ctaLabel: string;
      session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>;
    }
  | {
      kind: "meeting_prep";
      title: string;
      summary: string;
      meta: string[];
      ctaLabel: string;
      session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>;
    };

function formatRawTime(raw?: string): string | null {
  if (!raw) return null;
  const value = new Date(raw);
  if (Number.isNaN(value.getTime())) {
    return raw;
  }
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(value);
}

function extractDisplayName(raw?: string): string {
  if (!raw) return "the sender";
  const bracketIndex = raw.indexOf("<");
  const base = (bracketIndex >= 0 ? raw.slice(0, bracketIndex) : raw).trim();
  if (base) {
    return base.replace(/^"|"$/g, "");
  }
  return raw.trim() || "the sender";
}

export function buildOperatorWorkbenchSummary(
  item: NotificationDetailItem | null,
  gmailThread: GmailThreadDetail | null,
  calendarEvent: CalendarEventDetail | null,
): OperatorWorkbenchSummary | null {
  if (!item?.target) return null;

  const connectorId =
    notificationTargetConnectorId(item.target) ?? "google.workspace";

  if (item.target.kind === "gmail_thread" && gmailThread) {
    const latest =
      gmailThread.messages[gmailThread.messages.length - 1] ?? null;
    const sender = extractDisplayName(latest?.from);
    const subject = latest?.subject || gmailThread.snippet || "this thread";
    const latestTime = formatRawTime(latest?.date);

    return {
      kind: "gmail_reply",
      title: "Recommended next workbench",
      summary: `Reply to ${sender} about ${subject}. The workbench opens with the current thread context and reply headers prefilled.`,
      meta: [
        `${gmailThread.messages.length} messages`,
        latestTime ? `Latest ${latestTime}` : "",
      ].filter(Boolean),
      ctaLabel: "Open reply composer",
      session: {
        kind: "gmail_reply",
        connectorId,
        thread: gmailThread,
        sourceNotificationId: item.itemId,
      },
    };
  }

  if (item.target.kind === "calendar_event" && calendarEvent) {
    const startTime = formatRawTime(calendarEvent.start);
    return {
      kind: "meeting_prep",
      title: "Recommended next workbench",
      summary: `Prepare for ${calendarEvent.summary || "this meeting"} with attendee context, open questions, and follow-up risks in one brief.`,
      meta: [
        startTime ? `Starts ${startTime}` : "",
        calendarEvent.attendees.length > 0
          ? `${calendarEvent.attendees.length} attendees`
          : "",
        calendarEvent.location || "",
      ].filter(Boolean),
      ctaLabel: "Open prep workbench",
      session: {
        kind: "meeting_prep",
        connectorId,
        event: calendarEvent,
        sourceNotificationId: item.itemId,
      },
    };
  }

  return null;
}
