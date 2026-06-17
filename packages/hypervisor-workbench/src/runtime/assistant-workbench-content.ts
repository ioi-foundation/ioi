import type {
  CalendarEventDetail,
  GmailThreadDetail,
} from "./assistant-session-runtime-types";

export function formatWorkbenchEventTime(raw?: string): string {
  if (!raw) {
    return "Unknown";
  }

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

export function extractEmailAddress(raw?: string): string {
  if (!raw) {
    return "";
  }

  const match = raw.match(/<([^>]+)>/);
  if (match?.[1]) {
    return match[1].trim();
  }

  const fallback = raw.trim();
  return /\S+@\S+\.\S+/.test(fallback) ? fallback : "";
}

export function extractDisplayName(raw?: string): string {
  if (!raw) {
    return "there";
  }

  const bracketIndex = raw.indexOf("<");
  const base = (bracketIndex >= 0 ? raw.slice(0, bracketIndex) : raw).trim();
  if (base) {
    return base.replace(/^"|"$/g, "");
  }

  const email = extractEmailAddress(raw);
  if (!email) {
    return "there";
  }

  return email.split("@")[0]?.replace(/[._-]+/g, " ") || "there";
}

export function ensureReplySubject(subject?: string): string {
  if (!subject?.trim()) {
    return "Re:";
  }
  return /^re:/i.test(subject) ? subject : `Re: ${subject}`;
}

export function buildReplyReferences(
  references?: string,
  rfcMessageId?: string,
): string | undefined {
  const parts = [
    ...(references
      ? references
          .split(/\s+/)
          .map((value) => value.trim())
          .filter(Boolean)
      : []),
    ...(rfcMessageId?.trim() ? [rfcMessageId.trim()] : []),
  ];

  const deduped = Array.from(new Set(parts));
  return deduped.length > 0 ? deduped.join(" ") : undefined;
}

export function buildReplyBody(thread: GmailThreadDetail): string {
  const latest = thread.messages[thread.messages.length - 1];
  const salutation = `Hi ${extractDisplayName(latest?.from)},`;
  return `${salutation}\n\n\n\nBest,\n`;
}

export function buildReplyAutopilotIntent(
  thread: GmailThreadDetail,
  to: string,
  subject: string,
  currentBody: string,
): string {
  const latest = thread.messages[thread.messages.length - 1];
  const transcript = thread.messages
    .slice(-3)
    .map((message, index) => {
      const lines = [
        `Message ${index + 1}`,
        message.from ? `From: ${message.from}` : null,
        message.to ? `To: ${message.to}` : null,
        message.subject ? `Subject: ${message.subject}` : null,
        message.date ? `Date: ${message.date}` : null,
        message.snippet ? `Snippet: ${message.snippet}` : null,
      ].filter(Boolean);
      return lines.join("\n");
    })
    .join("\n\n");

  const draftNote = currentBody.trim()
    ? `Current draft body:\n${currentBody.trim()}\n\n`
    : "";

  return [
    "Draft a concise reply for this Gmail thread.",
    `Recipient: ${to}`,
    `Subject: ${subject}`,
    latest?.from ? `Latest sender: ${latest.from}` : null,
    draftNote.trim() ? draftNote.trim() : null,
    "Thread context:",
    transcript,
    "Return plain text email body only. Preserve the thread context and stay concrete.",
  ]
    .filter(Boolean)
    .join("\n\n");
}

export function collectCalendarLinks(event: CalendarEventDetail): string[] {
  const seen = new Set<string>();
  const links: string[] = [];
  const record = (value?: string) => {
    if (!value || seen.has(value)) {
      return;
    }
    seen.add(value);
    links.push(value);
  };

  if (event.htmlLink) {
    record(event.htmlLink);
  }

  const matches = event.description?.match(/https?:\/\/[^\s)]+/g) ?? [];
  matches.forEach((match) => record(match));
  return links;
}

export function buildMeetingBriefDraft(event: CalendarEventDetail): string {
  const attendees = event.attendees
    .map((attendee) => attendee.displayName || attendee.email)
    .filter(Boolean)
    .join(", ");
  const links = collectCalendarLinks(event);
  const linkSection =
    links.length > 0 ? links.map((link) => `- ${link}`).join("\n") : "- None";

  return [
    `Meeting: ${event.summary || "Untitled event"}`,
    `When: ${formatWorkbenchEventTime(event.start)} to ${formatWorkbenchEventTime(event.end)}`,
    event.location ? `Where: ${event.location}` : "Where: TBD",
    attendees ? `Attendees: ${attendees}` : "Attendees: TBD",
    "",
    "Prep goals",
    "- Clarify the desired outcome",
    "- Review open questions before joining",
    "- Capture a short post-meeting follow-up plan",
    "",
    "Source notes",
    event.description?.trim() || "No additional event description.",
    "",
    "Linked context",
    linkSection,
  ].join("\n");
}

export function buildMeetingPrepAutopilotIntent(
  event: CalendarEventDetail,
  briefDraft: string,
): string {
  const attendees = event.attendees
    .map((attendee) => attendee.displayName || attendee.email)
    .filter(Boolean)
    .join(", ");

  return [
    "Prepare a focused meeting brief from this calendar event.",
    `Title: ${event.summary || "Untitled event"}`,
    `Start: ${formatWorkbenchEventTime(event.start)}`,
    `End: ${formatWorkbenchEventTime(event.end)}`,
    event.location ? `Location: ${event.location}` : null,
    attendees ? `Attendees: ${attendees}` : null,
    event.description?.trim() ? `Description:\n${event.description.trim()}` : null,
    briefDraft.trim() ? `Current brief draft:\n${briefDraft.trim()}` : null,
    "Return a polished prep brief with objectives, attendee context, questions to resolve, and follow-up risks.",
  ]
    .filter(Boolean)
    .join("\n\n");
}
