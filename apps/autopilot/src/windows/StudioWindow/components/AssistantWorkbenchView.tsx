import type { AgentRuntime } from "@ioi/agent-ide";
import { useEffect, useMemo, useState } from "react";
import type { AssistantWorkbenchSession, CalendarEventDetail, GmailThreadDetail } from "../../../types";

interface AssistantWorkbenchViewProps {
  session: AssistantWorkbenchSession | null;
  runtime: AgentRuntime;
  onBack: () => void;
  onOpenNotifications: () => void;
  onOpenAutopilot: (intent: string) => void;
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
  const linkSection = links.length > 0 ? links.map((link) => `- ${link}`).join("\n") : "- None";

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

function buildMeetingPrepPrompt(event: CalendarEventDetail, briefDraft: string): string {
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

export function AssistantWorkbenchView({
  session,
  runtime,
  onBack,
  onOpenNotifications,
  onOpenAutopilot,
}: AssistantWorkbenchViewProps) {
  const [replyTo, setReplyTo] = useState("");
  const [replySubject, setReplySubject] = useState("");
  const [replyBody, setReplyBody] = useState("");
  const [meetingBrief, setMeetingBrief] = useState("");
  const [busyAction, setBusyAction] = useState<"draft" | "send" | "copy" | null>(null);
  const [actionResult, setActionResult] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const latestMessage = useMemo(() => {
    if (!session || session.kind !== "gmail_reply") return null;
    return session.thread.messages[session.thread.messages.length - 1] ?? null;
  }, [session]);

  useEffect(() => {
    setActionResult(null);
    setActionError(null);
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

  const runReplyAction = async (actionId: "gmail.draft_email" | "gmail.send_email") => {
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
          references: buildReplyReferences(latest?.references, latest?.rfcMessageId) ?? null,
        },
      });
      setActionResult(result.summary);
    } catch (nextError) {
      setActionError(String(nextError));
    } finally {
      setBusyAction(null);
    }
  };

  const copyMeetingBrief = async () => {
    if (!meetingBrief.trim()) {
      setActionError("Nothing to copy yet.");
      return;
    }
    setBusyAction("copy");
    setActionError(null);
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(meetingBrief);
        setActionResult("Copied meeting brief to clipboard.");
      } else {
        throw new Error("Clipboard access is unavailable in this environment.");
      }
    } catch (nextError) {
      setActionError(String(nextError));
    } finally {
      setBusyAction(null);
    }
  };

  if (!session) {
    return (
      <div className="assistant-workbench assistant-workbench-empty">
        <div className="assistant-workbench-card">
          <span className="notifications-card-eyebrow">Assistant Workbench</span>
          <h2>No active handoff</h2>
          <p>Open a Gmail or Calendar notification target to continue from a dedicated assistant surface.</p>
          <div className="assistant-workbench-actions">
            <button type="button" className="notifications-primary-button" onClick={onOpenNotifications}>
              Open notifications
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="assistant-workbench">
      <header className="assistant-workbench-header">
        <div>
          <span className="notifications-card-eyebrow">Assistant Workbench</span>
          <h2>
            {session.kind === "gmail_reply" ? "Native reply composer" : "Meeting prep workbench"}
          </h2>
          <p>
            {session.kind === "gmail_reply"
              ? "Carry thread context forward into a native composer without dropping back to the generic assistant."
              : "Review meeting context, links, and a working prep brief before handing off to Autopilot if needed."}
          </p>
        </div>
        <div className="assistant-workbench-actions">
          <button type="button" className="notifications-secondary-button" onClick={onBack}>
            Back
          </button>
          <button
            type="button"
            className="notifications-quiet-button"
            onClick={onOpenNotifications}
          >
            Notifications
          </button>
        </div>
      </header>

      {actionError ? <div className="notifications-error">{actionError}</div> : null}
      {actionResult ? <div className="assistant-workbench-result">{actionResult}</div> : null}

      {session.kind === "gmail_reply" ? (
        <div className="assistant-workbench-shell">
          <section className="assistant-workbench-panel">
            <div className="assistant-workbench-panel-head">
              <h3>Thread context</h3>
              <span>Thread {session.thread.threadId.slice(0, 12)}</span>
            </div>
            {session.thread.snippet ? (
              <p className="assistant-workbench-summary">{session.thread.snippet}</p>
            ) : null}
            <div className="assistant-workbench-stack">
              {session.thread.messages.map((message) => (
                <article key={message.id} className="assistant-workbench-card">
                  <div className="assistant-workbench-card-head">
                    <strong>{message.subject || "Untitled message"}</strong>
                    <span>{message.date || "No date"}</span>
                  </div>
                  <div className="assistant-workbench-meta">
                    {message.from ? <span>From {message.from}</span> : null}
                    {message.to ? <span>To {message.to}</span> : null}
                  </div>
                  {message.snippet ? <p>{message.snippet}</p> : null}
                </article>
              ))}
            </div>
          </section>

          <section className="assistant-workbench-panel">
            <div className="assistant-workbench-panel-head">
              <h3>Compose reply</h3>
              <span>Subject lineage preserved</span>
            </div>
            <label className="assistant-workbench-field">
              <span>To</span>
              <input
                type="email"
                value={replyTo}
                onChange={(event) => setReplyTo(event.target.value)}
                placeholder="recipient@example.com"
              />
            </label>
            <label className="assistant-workbench-field">
              <span>Subject</span>
              <input
                type="text"
                value={replySubject}
                onChange={(event) => setReplySubject(event.target.value)}
                placeholder="Re: Subject"
              />
            </label>
            <label className="assistant-workbench-field assistant-workbench-field-grow">
              <span>Body</span>
              <textarea
                value={replyBody}
                onChange={(event) => setReplyBody(event.target.value)}
                placeholder="Write a reply…"
              />
            </label>
            <div className="assistant-workbench-actions">
              <button
                type="button"
                className="notifications-primary-button"
                disabled={busyAction !== null || !runtime.runConnectorAction}
                onClick={() => {
                  void runReplyAction("gmail.draft_email");
                }}
              >
                {busyAction === "draft" ? "Drafting…" : "Save draft to Gmail"}
              </button>
              <button
                type="button"
                className="notifications-secondary-button"
                disabled={busyAction !== null || !runtime.runConnectorAction}
                onClick={() => {
                  void runReplyAction("gmail.send_email");
                }}
              >
                {busyAction === "send" ? "Sending…" : "Send via Gmail"}
              </button>
              <button
                type="button"
                className="notifications-quiet-button"
                onClick={() =>
                  onOpenAutopilot(buildReplyPrompt(session.thread, replyTo, replySubject, replyBody))
                }
              >
                Draft with Autopilot
              </button>
            </div>
            {latestMessage ? (
              <p className="assistant-workbench-summary">
                Latest inbound context from {latestMessage.from || "unknown sender"} remains visible
                while you draft.
              </p>
            ) : null}
          </section>
        </div>
      ) : (
        <div className="assistant-workbench-shell">
          <section className="assistant-workbench-panel">
            <div className="assistant-workbench-panel-head">
              <h3>Meeting context</h3>
              <span>{session.event.status || "scheduled"}</span>
            </div>
            <div className="assistant-workbench-meta">
              <span>{session.event.summary || "Untitled event"}</span>
              <span>{formatEventTime(session.event.start)}</span>
              <span>{formatEventTime(session.event.end)}</span>
              {session.event.location ? <span>{session.event.location}</span> : null}
            </div>
            {session.event.description ? (
              <p className="assistant-workbench-summary">{session.event.description}</p>
            ) : null}
            {session.event.attendees.length > 0 ? (
              <div className="assistant-workbench-tags">
                {session.event.attendees.map((attendee, index) => (
                  <span key={`${attendee.email ?? "attendee"}-${index}`}>
                    {attendee.displayName || attendee.email || "Attendee"}
                  </span>
                ))}
              </div>
            ) : null}
            {collectLinks(session.event).length > 0 ? (
              <div className="assistant-workbench-stack">
                <h4>Linked context</h4>
                {collectLinks(session.event).map((link) => (
                  <a
                    key={link}
                    className="notifications-secondary-link"
                    href={link}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {link}
                  </a>
                ))}
              </div>
            ) : null}
          </section>

          <section className="assistant-workbench-panel">
            <div className="assistant-workbench-panel-head">
              <h3>Prep brief</h3>
              <span>Editable draft</span>
            </div>
            <label className="assistant-workbench-field assistant-workbench-field-grow">
              <span>Brief</span>
              <textarea
                value={meetingBrief}
                onChange={(event) => setMeetingBrief(event.target.value)}
                placeholder="Summarize the meeting, attendees, and key questions."
              />
            </label>
            <div className="assistant-workbench-actions">
              <button
                type="button"
                className="notifications-primary-button"
                onClick={() => onOpenAutopilot(buildMeetingPrepPrompt(session.event, meetingBrief))}
              >
                Prepare brief in Autopilot
              </button>
              <button
                type="button"
                className="notifications-secondary-button"
                disabled={busyAction !== null}
                onClick={() => {
                  void copyMeetingBrief();
                }}
              >
                {busyAction === "copy" ? "Copying…" : "Copy brief"}
              </button>
              {session.event.htmlLink ? (
                <a className="notifications-secondary-link" href={session.event.htmlLink} target="_blank" rel="noreferrer">
                  Open in Calendar
                </a>
              ) : null}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
