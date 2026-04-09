import type { ConnectorSubscriptionSummary } from "@ioi/agent-ide";
import { buildOperatorWorkbenchSummary } from "../lib/operatorWorkbenchSummary";
import { notificationTargetConnectorId } from "../lib/notificationTargets";
import type {
  AssistantNotificationRecord,
  AssistantWorkbenchSession,
  CalendarEventDetail,
  GmailThreadDetail,
  InterventionRecord,
  WalletConnectorAuthGetResult,
} from "../types";

type NotificationDetailItem = AssistantNotificationRecord | InterventionRecord;

export interface NotificationTargetDetailClassNames {
  section: string;
  meta: string;
  snippet: string;
  stack: string;
  card: string;
  cardHead: string;
  tags: string;
  actions: string;
  primaryButton: string;
  secondaryButton: string;
  quietButton: string;
  secondaryLink?: string;
}

interface NotificationTargetDetailSectionsProps {
  item: NotificationDetailItem;
  gmailThread: GmailThreadDetail | null;
  calendarEvent: CalendarEventDetail | null;
  authRecord: WalletConnectorAuthGetResult | null;
  subscription: ConnectorSubscriptionSummary | null;
  busy: boolean;
  runSubscriptionAction: (
    action: "renew" | "resume" | "stop",
  ) => Promise<void>;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
  onOpenCapabilities: (connectorId?: string | null) => void;
  onOpenPolicy: (connectorId?: string | null) => void;
  onOpenInbox?: () => void;
  classNames: NotificationTargetDetailClassNames;
  maxMessages?: number;
  maxAttendees?: number;
  maxMetadataEntries?: number;
  showCalendarExternalLink?: boolean;
  showCalendarCapabilitiesAction?: boolean;
}

function formatRawTime(raw?: string): string {
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

export function NotificationTargetDetailSections({
  item,
  gmailThread,
  calendarEvent,
  authRecord,
  subscription,
  busy,
  runSubscriptionAction,
  onOpenReplyComposer,
  onOpenMeetingPrep,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenInbox,
  classNames,
  maxMessages,
  maxAttendees,
  maxMetadataEntries,
  showCalendarExternalLink = false,
  showCalendarCapabilitiesAction = false,
}: NotificationTargetDetailSectionsProps) {
  const connectorId = notificationTargetConnectorId(item.target);
  const workbenchSummary = buildOperatorWorkbenchSummary(
    item,
    gmailThread,
    calendarEvent,
  );

  return (
    <>
      {item.target?.kind === "gmail_thread" && gmailThread ? (
        <section className={classNames.section}>
          <div className={classNames.meta}>
            <span>Thread {gmailThread.threadId.slice(0, 12)}</span>
            {gmailThread.historyId ? (
              <span>History {gmailThread.historyId}</span>
            ) : null}
            <span>Source {item.itemId.slice(0, 8)}</span>
          </div>
          {gmailThread.snippet ? (
            <p className={classNames.snippet}>{gmailThread.snippet}</p>
          ) : null}
          {workbenchSummary?.kind === "gmail_reply" ? (
            <article className={classNames.card}>
              <div className={classNames.cardHead}>
                <strong>{workbenchSummary.title}</strong>
                <span>{workbenchSummary.ctaLabel}</span>
              </div>
              <p>{workbenchSummary.summary}</p>
              {workbenchSummary.meta.length > 0 ? (
                <div className={classNames.tags}>
                  {workbenchSummary.meta.map((value) => (
                    <span key={value}>{value}</span>
                  ))}
                </div>
              ) : null}
              <div className={classNames.actions}>
                <button
                  type="button"
                  className={classNames.primaryButton}
                  onClick={() => onOpenReplyComposer(workbenchSummary.session)}
                >
                  {workbenchSummary.ctaLabel}
                </button>
              </div>
            </article>
          ) : null}
          <div className={classNames.stack}>
            {gmailThread.messages
              .slice(0, maxMessages)
              .map((message) => (
                <article key={message.id} className={classNames.card}>
                  <div className={classNames.cardHead}>
                    <strong>{message.subject || "Untitled message"}</strong>
                    <span>{message.date || "No date"}</span>
                  </div>
                  <div className={classNames.meta}>
                    {message.from ? <span>From {message.from}</span> : null}
                    {message.to ? <span>To {message.to}</span> : null}
                  </div>
                  {message.snippet ? <p>{message.snippet}</p> : null}
                  {message.labelIds.length > 0 ? (
                    <div className={classNames.tags}>
                      {message.labelIds.map((label) => (
                        <span key={label}>{label}</span>
                      ))}
                    </div>
                  ) : null}
                </article>
              ))}
          </div>
          <div className={classNames.actions}>
            <button
              type="button"
              className={classNames.primaryButton}
              onClick={() =>
                onOpenReplyComposer({
                  kind: "gmail_reply",
                  connectorId: connectorId ?? "google.workspace",
                  thread: gmailThread,
                  sourceNotificationId: item.itemId,
                })
              }
            >
              Open reply composer
            </button>
            {onOpenInbox ? (
              <button
                type="button"
                className={classNames.secondaryButton}
                onClick={onOpenInbox}
              >
                Open inbox
              </button>
            ) : null}
            {connectorId ? (
              <button
                type="button"
                className={onOpenInbox ? classNames.quietButton : classNames.secondaryButton}
                onClick={() => onOpenCapabilities(connectorId)}
              >
                Open capabilities
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      {item.target?.kind === "calendar_event" && calendarEvent ? (
        <section className={classNames.section}>
          <div className={classNames.meta}>
            <span>{calendarEvent.summary || "Untitled event"}</span>
            {calendarEvent.status ? (
              <span>Status {calendarEvent.status}</span>
            ) : null}
            {calendarEvent.location ? <span>{calendarEvent.location}</span> : null}
          </div>
          <div className={classNames.meta}>
            {calendarEvent.start ? (
              <span>Starts {formatRawTime(calendarEvent.start)}</span>
            ) : null}
            {calendarEvent.end ? (
              <span>Ends {formatRawTime(calendarEvent.end)}</span>
            ) : null}
          </div>
          {calendarEvent.description ? (
            <p className={classNames.snippet}>{calendarEvent.description}</p>
          ) : null}
          {workbenchSummary?.kind === "meeting_prep" ? (
            <article className={classNames.card}>
              <div className={classNames.cardHead}>
                <strong>{workbenchSummary.title}</strong>
                <span>{workbenchSummary.ctaLabel}</span>
              </div>
              <p>{workbenchSummary.summary}</p>
              {workbenchSummary.meta.length > 0 ? (
                <div className={classNames.tags}>
                  {workbenchSummary.meta.map((value) => (
                    <span key={value}>{value}</span>
                  ))}
                </div>
              ) : null}
              <div className={classNames.actions}>
                <button
                  type="button"
                  className={classNames.primaryButton}
                  onClick={() => onOpenMeetingPrep(workbenchSummary.session)}
                >
                  {workbenchSummary.ctaLabel}
                </button>
              </div>
            </article>
          ) : null}
          {calendarEvent.attendees.length > 0 ? (
            <div className={classNames.stack}>
              {calendarEvent.attendees
                .slice(0, maxAttendees)
                .map((attendee, index) => (
                  <article
                    key={`${attendee.email ?? "attendee"}-${index}`}
                    className={classNames.card}
                  >
                    <div className={classNames.cardHead}>
                      <strong>
                        {attendee.displayName || attendee.email || "Attendee"}
                      </strong>
                      <span>
                        {attendee.responseStatus || "response unknown"}
                      </span>
                    </div>
                    {attendee.organizer ? <p>Organizer</p> : null}
                  </article>
                ))}
            </div>
          ) : null}
          <div className={classNames.actions}>
            <button
              type="button"
              className={classNames.primaryButton}
              onClick={() =>
                onOpenMeetingPrep({
                  kind: "meeting_prep",
                  connectorId: connectorId ?? "google.workspace",
                  event: calendarEvent,
                  sourceNotificationId: item.itemId,
                })
              }
            >
              Open prep workbench
            </button>
            {showCalendarExternalLink &&
            calendarEvent.htmlLink &&
            classNames.secondaryLink ? (
              <a
                className={classNames.secondaryLink}
                href={calendarEvent.htmlLink}
                target="_blank"
                rel="noreferrer"
              >
                Open in Calendar
              </a>
            ) : null}
            {onOpenInbox ? (
              <button
                type="button"
                className={classNames.secondaryButton}
                onClick={onOpenInbox}
              >
                Open inbox
              </button>
            ) : null}
            {showCalendarCapabilitiesAction && connectorId ? (
              <button
                type="button"
                className={classNames.quietButton}
                onClick={() => onOpenCapabilities(connectorId)}
              >
                Open capabilities
              </button>
            ) : null}
          </div>
        </section>
      ) : null}

      {item.target?.kind === "connector_auth" && authRecord ? (
        <section className={classNames.section}>
          <div className={classNames.meta}>
            <span>State {authRecord.record.state}</span>
            <span>Protocol {authRecord.record.authProtocol}</span>
            {authRecord.record.expiresAtMs ? (
              <span>Expires {formatRawTime(new Date(authRecord.record.expiresAtMs).toISOString())}</span>
            ) : null}
          </div>
          {authRecord.record.accountLabel ? (
            <p className={classNames.snippet}>{authRecord.record.accountLabel}</p>
          ) : null}
          {authRecord.record.grantedScopes.length > 0 ? (
            <div className={classNames.tags}>
              {authRecord.record.grantedScopes.map((scope) => (
                <span key={scope}>{scope}</span>
              ))}
            </div>
          ) : null}
          <div className={classNames.stack}>
            {Object.entries(authRecord.record.metadata)
              .slice(0, maxMetadataEntries)
              .map(([key, value]) => (
                <article key={key} className={classNames.card}>
                  <div className={classNames.cardHead}>
                    <strong>{key}</strong>
                  </div>
                  <p>{value}</p>
                </article>
              ))}
          </div>
          <div className={classNames.actions}>
            <button
              type="button"
              className={classNames.primaryButton}
              onClick={() => onOpenCapabilities(connectorId)}
            >
              Open capabilities
            </button>
            <button
              type="button"
              className={classNames.secondaryButton}
              onClick={() => onOpenPolicy(connectorId)}
            >
              Open policy
            </button>
          </div>
        </section>
      ) : null}

      {item.target?.kind === "connector_subscription" && subscription ? (
        <section className={classNames.section}>
          <div className={classNames.meta}>
            <span>{subscription.kind}</span>
            <span>Status {subscription.status}</span>
            {subscription.accountEmail ? <span>{subscription.accountEmail}</span> : null}
          </div>
          <div className={classNames.stack}>
            <article className={classNames.card}>
              <div className={classNames.cardHead}>
                <strong>Pub/Sub</strong>
              </div>
              <p>{subscription.pubsubSubscription}</p>
              <p>{subscription.pubsubTopic}</p>
            </article>
            {subscription.lastError ? (
              <article className={classNames.card}>
                <div className={classNames.cardHead}>
                  <strong>Last error</strong>
                </div>
                <p>{subscription.lastError}</p>
              </article>
            ) : null}
            <article className={classNames.card}>
              <div className={classNames.cardHead}>
                <strong>Lifecycle</strong>
              </div>
              {subscription.renewAtUtc ? (
                <p>Renew at {formatRawTime(subscription.renewAtUtc)}</p>
              ) : null}
              {subscription.expiresAtUtc ? (
                <p>Expires at {formatRawTime(subscription.expiresAtUtc)}</p>
              ) : null}
              {subscription.lastDeliveryAtUtc ? (
                <p>Last delivery {formatRawTime(subscription.lastDeliveryAtUtc)}</p>
              ) : null}
              {subscription.lastAckAtUtc ? (
                <p>Last ack {formatRawTime(subscription.lastAckAtUtc)}</p>
              ) : null}
            </article>
          </div>
          <div className={classNames.actions}>
            <button
              type="button"
              className={classNames.primaryButton}
              onClick={() => {
                void runSubscriptionAction("renew");
              }}
              disabled={busy}
            >
              {busy ? "Working…" : "Renew now"}
            </button>
            <button
              type="button"
              className={classNames.secondaryButton}
              onClick={() => {
                void runSubscriptionAction(
                  subscription.status === "paused" ? "resume" : "stop",
                );
              }}
              disabled={busy}
            >
              {subscription.status === "paused" ? "Resume" : "Pause"}
            </button>
            <button
              type="button"
              className={classNames.quietButton}
              onClick={() => onOpenCapabilities(connectorId)}
            >
              Open capabilities
            </button>
          </div>
        </section>
      ) : null}
    </>
  );
}
