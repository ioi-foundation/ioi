import { useEffect, useMemo, useState } from "react";
import type {
  AgentRuntime,
  AssistantWorkbenchSession,
  CalendarEventDetail,
  GmailThreadDetail,
} from "./agent-runtime";
import { createAssistantWorkbenchActivity } from "./assistant-workbench-activity";
import { reportAssistantWorkbenchActivity } from "./session-runtime";
import {
  buildConnectorApprovalMemoryRequest,
  parseShieldApprovalRequest,
  type ShieldApprovalRequest,
} from "./shield-approval";

export type AssistantWorkbenchBusyAction =
  | "draft"
  | "send"
  | "copy"
  | null;

export interface UseAssistantWorkbenchControllerOptions {
  session: AssistantWorkbenchSession | null;
  runtime: AgentRuntime;
}

async function emitWorkbenchActivity(
  session: AssistantWorkbenchSession | null,
  params: Parameters<typeof createAssistantWorkbenchActivity>[1],
) {
  if (!session) return;
  try {
    await reportAssistantWorkbenchActivity(
      createAssistantWorkbenchActivity(session, params),
    );
  } catch (error) {
    console.error("Failed to report assistant workbench activity:", error);
  }
}

function formatEventTime(raw?: string): string {
  if (!raw) return "Unknown";
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

function extractEmailAddress(raw?: string): string {
  if (!raw) return "";
  const match = raw.match(/<([^>]+)>/);
  if (match?.[1]) {
    return match[1].trim();
  }
  const fallback = raw.trim();
  return /\S+@\S+\.\S+/.test(fallback) ? fallback : "";
}

function extractDisplayName(raw?: string): string {
  if (!raw) return "there";
  const bracketIndex = raw.indexOf("<");
  const base = (bracketIndex >= 0 ? raw.slice(0, bracketIndex) : raw).trim();
  if (base) {
    return base.replace(/^"|"$/g, "");
  }
  const email = extractEmailAddress(raw);
  if (!email) return "there";
  return email.split("@")[0]?.replace(/[._-]+/g, " ") || "there";
}

function ensureReplySubject(subject?: string): string {
  if (!subject?.trim()) return "Re:";
  return /^re:/i.test(subject) ? subject : `Re: ${subject}`;
}

function buildReplyReferences(
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

function buildReplyBody(thread: GmailThreadDetail): string {
  const latest = thread.messages[thread.messages.length - 1];
  const salutation = `Hi ${extractDisplayName(latest?.from)},`;
  return `${salutation}\n\n\n\nBest,\n`;
}

function buildReplyPrompt(
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

function collectLinks(event: CalendarEventDetail): string[] {
  const seen = new Set<string>();
  const links: string[] = [];
  const record = (value?: string) => {
    if (!value || seen.has(value)) return;
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

function buildMeetingBrief(event: CalendarEventDetail): string {
  const attendees = event.attendees
    .map((attendee) => attendee.displayName || attendee.email)
    .filter(Boolean)
    .join(", ");
  const links = collectLinks(event);
  const linkSection =
    links.length > 0 ? links.map((link) => `- ${link}`).join("\n") : "- None";

  return [
    `Meeting: ${event.summary || "Untitled event"}`,
    `When: ${formatEventTime(event.start)} to ${formatEventTime(event.end)}`,
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

function buildMeetingPrepPrompt(
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
    `Start: ${formatEventTime(event.start)}`,
    `End: ${formatEventTime(event.end)}`,
    event.location ? `Location: ${event.location}` : null,
    attendees ? `Attendees: ${attendees}` : null,
    event.description?.trim() ? `Description:\n${event.description.trim()}` : null,
    briefDraft.trim() ? `Current brief draft:\n${briefDraft.trim()}` : null,
    "Return a polished prep brief with objectives, attendee context, questions to resolve, and follow-up risks.",
  ]
    .filter(Boolean)
    .join("\n\n");
}

export function useAssistantWorkbenchController({
  session,
  runtime,
}: UseAssistantWorkbenchControllerOptions) {
  const [replyTo, setReplyTo] = useState("");
  const [replySubject, setReplySubject] = useState("");
  const [replyBody, setReplyBody] = useState("");
  const [meetingBrief, setMeetingBrief] = useState("");
  const [busyAction, setBusyAction] =
    useState<AssistantWorkbenchBusyAction>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pendingShieldApproval, setPendingShieldApproval] =
    useState<{
      actionId: "gmail.draft_email" | "gmail.send_email";
      request: ShieldApprovalRequest;
    } | null>(null);

  const latestMessage = useMemo(() => {
    if (!session || session.kind !== "gmail_reply") return null;
    return session.thread.messages[session.thread.messages.length - 1] ?? null;
  }, [session]);

  const meetingLinks = useMemo(() => {
    if (!session || session.kind !== "meeting_prep") return [];
    return collectLinks(session.event);
  }, [session]);

  useEffect(() => {
    setActionResult(null);
    setActionError(null);
    setPendingShieldApproval(null);
    setBusyAction(null);

    if (!session) {
      setReplyTo("");
      setReplySubject("");
      setReplyBody("");
      setMeetingBrief("");
      return;
    }

    if (session.kind === "gmail_reply") {
      const latest = session.thread.messages[session.thread.messages.length - 1];
      setReplyTo(extractEmailAddress(latest?.from));
      setReplySubject(ensureReplySubject(latest?.subject));
      setReplyBody(buildReplyBody(session.thread));
      setMeetingBrief("");
      return;
    }

    setReplyTo("");
    setReplySubject("");
    setReplyBody("");
    setMeetingBrief(buildMeetingBrief(session.event));
  }, [session]);

  const runReplyAction = async (
    actionId: "gmail.draft_email" | "gmail.send_email",
    options?: { shieldApproved?: boolean },
  ) => {
    if (!session || session.kind !== "gmail_reply") return;
    if (!runtime.runConnectorAction) {
      setActionError("Connector action runtime is unavailable in this shell.");
      return;
    }
    if (!replyTo.trim() || !replySubject.trim() || !replyBody.trim()) {
      setActionError("Recipient, subject, and body are required.");
      return;
    }
    setBusyAction(actionId === "gmail.draft_email" ? "draft" : "send");
    setActionError(null);
    setPendingShieldApproval(null);
    await emitWorkbenchActivity(session, {
      action: actionId === "gmail.draft_email" ? "draft" : "send",
      status: "started",
      message:
        actionId === "gmail.draft_email"
          ? "Saving Gmail draft from Gate/Studio workbench."
          : "Sending Gmail reply from Gate/Studio workbench.",
    });
    try {
      const latest = session.thread.messages[session.thread.messages.length - 1];
      const result = await runtime.runConnectorAction({
        connectorId: session.connectorId,
        actionId,
        input: {
          to: replyTo.trim(),
          subject: replySubject.trim(),
          body: replyBody,
          threadId: session.thread.threadId,
          inReplyTo: latest?.rfcMessageId ?? null,
          references:
            buildReplyReferences(latest?.references, latest?.rfcMessageId) ??
            null,
          ...(options?.shieldApproved ? { _shieldApproved: true } : {}),
        },
      });
      setActionResult(result.summary);
      await emitWorkbenchActivity(session, {
        action: actionId === "gmail.draft_email" ? "draft" : "send",
        status: "succeeded",
        message: result.summary,
      });
    } catch (nextError) {
      const approvalRequest = parseShieldApprovalRequest(nextError);
      if (approvalRequest && !options?.shieldApproved) {
        setActionResult(null);
        setActionError(null);
        setPendingShieldApproval({ actionId, request: approvalRequest });
        await emitWorkbenchActivity(session, {
          action: "shield_approval",
          status: "requested",
          message: approvalRequest.message,
        });
        return;
      }
      setActionError(String(nextError));
      await emitWorkbenchActivity(session, {
        action: actionId === "gmail.draft_email" ? "draft" : "send",
        status: "failed",
        message:
          actionId === "gmail.draft_email"
            ? "Gmail draft action failed."
            : "Gmail send action failed.",
        detail: String(nextError),
      });
    } finally {
      setBusyAction(null);
    }
  };

  const approvePendingShieldAction = async () => {
    if (!pendingShieldApproval) return;
    if (runtime.rememberConnectorApproval) {
      const input = buildConnectorApprovalMemoryRequest(
        pendingShieldApproval.request,
        "Assistant workbench",
      );
      if (input) {
        try {
          await runtime.rememberConnectorApproval(input);
        } catch (error) {
          console.warn("Failed to remember Shield approval:", error);
        }
      }
    }
    await runReplyAction(pendingShieldApproval.actionId, {
      shieldApproved: true,
    });
  };

  const copyMeetingBrief = async () => {
    if (!meetingBrief.trim()) {
      setActionError("Nothing to copy yet.");
      return;
    }
    setBusyAction("copy");
    setActionError(null);
    await emitWorkbenchActivity(session, {
      action: "copy",
      status: "started",
      message: "Copying meeting brief to clipboard.",
    });
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(meetingBrief);
        setActionResult("Copied meeting brief to clipboard.");
        await emitWorkbenchActivity(session, {
          action: "copy",
          status: "succeeded",
          message: "Copied meeting brief to clipboard.",
        });
      } else {
        throw new Error("Clipboard access is unavailable in this environment.");
      }
    } catch (nextError) {
      setActionError(String(nextError));
      await emitWorkbenchActivity(session, {
        action: "copy",
        status: "failed",
        message: "Meeting brief copy failed.",
        detail: String(nextError),
      });
    } finally {
      setBusyAction(null);
    }
  };

  return {
    replyTo,
    setReplyTo,
    replySubject,
    setReplySubject,
    replyBody,
    setReplyBody,
    meetingBrief,
    setMeetingBrief,
    busyAction,
    actionResult,
    actionError,
    pendingShieldApproval,
    latestMessage,
    meetingLinks,
    replyAutopilotIntent:
      session && session.kind === "gmail_reply"
        ? buildReplyPrompt(session.thread, replyTo, replySubject, replyBody)
        : null,
    meetingPrepAutopilotIntent:
      session && session.kind === "meeting_prep"
        ? buildMeetingPrepPrompt(session.event, meetingBrief)
        : null,
    runReplyAction,
    approvePendingShieldAction,
    dismissPendingShieldApproval: () => setPendingShieldApproval(null),
    copyMeetingBrief,
  };
}
