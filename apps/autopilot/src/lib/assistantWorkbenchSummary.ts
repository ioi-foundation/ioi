import type { AssistantWorkbenchSession } from "../types";

export interface AssistantWorkbenchSummary {
  title: string;
  summary: string;
  resumeLabel: string;
}

function formatWorkbenchTime(raw?: string): string | null {
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

export function buildAssistantWorkbenchSummary(
  session: AssistantWorkbenchSession | null,
): AssistantWorkbenchSummary | null {
  if (!session) return null;

  if (session.kind === "gmail_reply") {
    const latest =
      session.thread.messages[session.thread.messages.length - 1] ?? null;
    const sender = extractDisplayName(latest?.from);
    const subject =
      latest?.subject || session.thread.snippet || "this thread";
    const latestTime = formatWorkbenchTime(latest?.date);

    return {
      title: "Active reply composer",
      summary: `Reply to ${sender} about ${subject}${latestTime ? ` · latest ${latestTime}` : ""}.`,
      resumeLabel: "Resume reply",
    };
  }

  const event = session.event;
  const startTime = formatWorkbenchTime(event.start);
  return {
    title: "Active meeting prep",
    summary: `Continue ${event.summary || "the current meeting brief"}${startTime ? ` · starts ${startTime}` : ""}.`,
    resumeLabel: "Resume prep",
  };
}
