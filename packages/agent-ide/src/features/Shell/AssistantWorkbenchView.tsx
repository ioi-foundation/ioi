import type {
  AgentWorkbenchRuntime,
  AssistantWorkbenchSession,
} from "../../runtime/agent-runtime";
import { formatWorkbenchEventTime } from "../../runtime/assistant-workbench-content";
import { useAssistantWorkbenchActions } from "../../runtime/use-assistant-workbench-controller";

interface AssistantWorkbenchViewProps {
  session: AssistantWorkbenchSession | null;
  runtime: AgentWorkbenchRuntime;
  onBack: () => void;
  onOpenNotifications: () => void;
  onOpenAutopilot: (intent: string) => void;
}

export function AssistantWorkbenchView({
  session,
  runtime,
  onBack,
  onOpenNotifications,
  onOpenAutopilot,
}: AssistantWorkbenchViewProps) {
  const {
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
    replyAutopilotIntent,
    meetingPrepAutopilotIntent,
    runReplyAction,
    approvePendingShieldAction,
    dismissPendingShieldApproval,
    copyMeetingBrief,
    reportAutopilotHandoff,
  } = useAssistantWorkbenchActions({
    session,
    runtime,
  });

  if (!session) {
    return (
      <div className="assistant-workbench assistant-workbench-empty">
        <div className="assistant-workbench-card">
          <span className="notifications-card-eyebrow">Assistant Workbench</span>
          <h2>No active handoff</h2>
          <p>Open a Gmail or Calendar inbox target to continue from a dedicated assistant surface.</p>
          <div className="assistant-workbench-actions">
            <button type="button" className="notifications-primary-button" onClick={onOpenNotifications}>
              Open inbox
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
            Inbox
          </button>
        </div>
      </header>

      {actionError ? <div className="notifications-error">{actionError}</div> : null}
      {actionResult ? <div className="assistant-workbench-result">{actionResult}</div> : null}
      {pendingShieldApproval ? (
        <div className="assistant-workbench-result">
          <strong>Shield approval required.</strong> {pendingShieldApproval.request.message}
          <div className="assistant-workbench-actions">
            <button
              type="button"
              className="notifications-primary-button"
              disabled={busyAction !== null}
              onClick={() => {
                void approvePendingShieldAction();
              }}
            >
              Approve and continue
            </button>
            <button
              type="button"
              className="notifications-secondary-button"
              disabled={busyAction !== null}
              onClick={() => {
                dismissPendingShieldApproval();
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : null}

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
                onClick={() => {
                  void reportAutopilotHandoff(replyAutopilotIntent ?? "");
                  onOpenAutopilot(replyAutopilotIntent ?? "");
                }}
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
              <span>{formatWorkbenchEventTime(session.event.start)}</span>
              <span>{formatWorkbenchEventTime(session.event.end)}</span>
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
            {meetingLinks.length > 0 ? (
              <div className="assistant-workbench-stack">
                <h4>Linked context</h4>
                {meetingLinks.map((link) => (
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
                onClick={() => {
                  void reportAutopilotHandoff(meetingPrepAutopilotIntent ?? "");
                  onOpenAutopilot(meetingPrepAutopilotIntent ?? "");
                }}
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
