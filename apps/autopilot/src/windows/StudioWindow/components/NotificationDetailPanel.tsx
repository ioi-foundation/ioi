import { invoke } from "@tauri-apps/api/core";
import type {
  ConnectorActionResult,
  ConnectorSubscriptionSummary,
} from "@ioi/agent-ide";
import { useEffect, useState } from "react";
import type {
  AssistantWorkbenchSession,
  AssistantNotificationRecord,
  CalendarEventDetail,
  GmailThreadDetail,
  InterventionRecord,
  NotificationTarget,
  WalletConnectorAuthGetResult,
} from "../../../types";

interface NotificationDetailPanelProps {
  item: AssistantNotificationRecord | InterventionRecord | null;
  onClose: () => void;
  onOpenAutopilot: () => void;
  onOpenLocalEngine: () => void;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
  onOpenIntegrations: (connectorId?: string | null) => void;
  onOpenShield: (connectorId?: string | null) => void;
}

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

function humanize(value: string): string {
  return value.replace(/::/g, " ").replace(/_/g, " ");
}

function timestampCopy(raw?: string): string {
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

function isInterventionRecord(
  item: AssistantNotificationRecord | InterventionRecord,
): item is InterventionRecord {
  return "interventionType" in item;
}

function isLocalEngineIntervention(item: InterventionRecord): boolean {
  if (item.approvalScope === "model::control") return true;
  const text = [
    item.title,
    item.summary,
    item.reason ?? "",
    item.sensitiveActionType ?? "",
    item.approvalScope ?? "",
    item.recoveryHint ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return (
    text.includes("local engine") ||
    text.includes("model::control") ||
    text.includes("model_registry") ||
    text.includes("model control") ||
    text.includes("backend control") ||
    text.includes("gallery control")
  );
}

export function NotificationDetailPanel({
  item,
  onClose,
  onOpenAutopilot,
  onOpenLocalEngine,
  onOpenReplyComposer,
  onOpenMeetingPrep,
  onOpenIntegrations,
  onOpenShield,
}: NotificationDetailPanelProps) {
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [gmailThread, setGmailThread] = useState<GmailThreadDetail | null>(
    null,
  );
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
          const result = await invoke<ConnectorActionResult>(
            "connector_fetch_gmail_thread",
            {
              connectorId: target.connectorId,
              connector_id: target.connectorId,
              threadId: target.threadId,
              thread_id: target.threadId,
            },
          );
          if (cancelled) return;
          setGmailThread(parseGmailThread(result));
        } else if (target.kind === "calendar_event") {
          const result = await invoke<ConnectorActionResult>(
            "connector_fetch_calendar_event",
            {
              connectorId: target.connectorId,
              connector_id: target.connectorId,
              calendarId: target.calendarId,
              calendar_id: target.calendarId,
              eventId: target.eventId,
              event_id: target.eventId,
            },
          );
          if (cancelled) return;
          setCalendarEvent(parseCalendarEvent(result));
        } else if (target.kind === "connector_auth") {
          const result = await invoke<WalletConnectorAuthGetResult>(
            "wallet_connector_auth_get",
            {
              connectorId: target.connectorId,
              connector_id: target.connectorId,
            },
          );
          if (cancelled) return;
          setAuthRecord(result);
        } else if (target.kind === "connector_subscription") {
          const result = await invoke<ConnectorSubscriptionSummary>(
            "connector_get_subscription",
            {
              connectorId: target.connectorId,
              connector_id: target.connectorId,
              subscriptionId: target.subscriptionId,
              subscription_id: target.subscriptionId,
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
    setBusy(true);
    setError(null);
    try {
      const payload = {
        connectorId: item.target.connectorId,
        connector_id: item.target.connectorId,
        subscriptionId: item.target.subscriptionId,
        subscription_id: item.target.subscriptionId,
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

  if (!item) {
    return (
      <aside className="notifications-detail-pane notifications-detail-pane-empty">
        <div>
          <span className="notifications-card-eyebrow">Detail</span>
          <h2>Select an inbox item</h2>
          <p>
            Select an inbox item to inspect context, risk, and the underlying
            record without leaving the queue.
          </p>
        </div>
      </aside>
    );
  }

  const detailType = isInterventionRecord(item)
    ? humanize(item.interventionType)
    : humanize(item.notificationClass);

  return (
    <aside className="notifications-detail-pane">
      <div className="notifications-detail-head">
        <div>
          <span className="notifications-card-eyebrow">{detailType}</span>
          <h2>{item.title}</h2>
          <p>{item.summary}</p>
        </div>
        <button
          type="button"
          className="notifications-quiet-button"
          onClick={onClose}
        >
          Close
        </button>
      </div>

      <div className="notifications-detail-meta">
        <span>{humanize(item.status)}</span>
        <span>{humanize(item.severity)}</span>
        <span>{item.source.serviceName}</span>
        {item.dueAtMs ? (
          <span>Due {timestampCopy(new Date(item.dueAtMs).toISOString())}</span>
        ) : null}
        <span>
          Updated {timestampCopy(new Date(item.updatedAtMs).toISOString())}
        </span>
      </div>

      <div className="notifications-detail-section">
        {isInterventionRecord(item) && isLocalEngineIntervention(item) ? (
          <article className="notifications-detail-card notifications-detail-card-engine">
            <div className="notifications-detail-card-head">
              <strong>Local engine control plane</strong>
              <span>Kernel-managed</span>
            </div>
            <p>
              This intervention belongs to the absorbed local engine surface, so
              approvals and lifecycle receipts route through the kernel rather
              than a connector adapter.
            </p>
            <div className="notifications-detail-tags">
              <span>{item.approvalScope || "model::control"}</span>
              {item.sensitiveActionType ? (
                <span>{humanize(item.sensitiveActionType)}</span>
              ) : null}
              {item.requestHash ? (
                <span>Request {item.requestHash.slice(0, 12)}</span>
              ) : null}
            </div>
            {item.recoveryHint ? <p>{item.recoveryHint}</p> : null}
          </article>
        ) : null}

        <article className="notifications-detail-card">
          <div className="notifications-detail-card-head">
            <strong>Why this surfaced</strong>
          </div>
          {item.reason ? <p>{item.reason}</p> : <p>{item.summary}</p>}
          {item.recommendedAction ? (
            <p>Next: {item.recommendedAction}</p>
          ) : null}
          {item.consequenceIfIgnored ? (
            <p>If ignored: {item.consequenceIfIgnored}</p>
          ) : null}
        </article>

        <article className="notifications-detail-card">
          <div className="notifications-detail-card-head">
            <strong>Context</strong>
          </div>
          <div className="notifications-detail-tags">
            {item.workflowId ? <span>Workflow {item.workflowId}</span> : null}
            {item.runId ? <span>Run {item.runId}</span> : null}
            {item.sessionId ? (
              <span>Session {item.sessionId.slice(0, 8)}</span>
            ) : null}
            {item.threadId ? (
              <span>Thread {item.threadId.slice(0, 8)}</span>
            ) : null}
            {item.artifactRefs.length > 0 ? (
              <span>{item.artifactRefs.length} artifacts</span>
            ) : null}
          </div>
          {isInterventionRecord(item) ? (
            <>
              <div className="notifications-detail-tags">
                {item.blocking ? <span>Blocking</span> : null}
                {item.approvalScope ? (
                  <span>{humanize(item.approvalScope)}</span>
                ) : null}
                {item.sensitiveActionType ? (
                  <span>{humanize(item.sensitiveActionType)}</span>
                ) : null}
                {item.blockedStage ? (
                  <span>{humanize(item.blockedStage)}</span>
                ) : null}
                {item.retryAvailable ? <span>Retry available</span> : null}
              </div>
              {item.recoveryHint ? <p>{item.recoveryHint}</p> : null}
            </>
          ) : (
            <>
              <div className="notifications-detail-tags">
                <span>Priority {(item.priorityScore * 100).toFixed(0)}%</span>
                <span>
                  Confidence {(item.confidenceScore * 100).toFixed(0)}%
                </span>
                {item.rankingReason.slice(0, 3).map((reason) => (
                  <span key={reason}>{humanize(reason)}</span>
                ))}
              </div>
              <p>Observation tier: {humanize(item.privacy.observationTier)}</p>
            </>
          )}
        </article>

        <div className="notifications-detail-actions">
          {isInterventionRecord(item) && isLocalEngineIntervention(item) ? (
            <button
              type="button"
              className="notifications-primary-button"
              onClick={onOpenLocalEngine}
            >
              Open local engine
            </button>
          ) : null}
          <button
            type="button"
            className={
              isInterventionRecord(item) && isLocalEngineIntervention(item)
                ? "notifications-secondary-button"
                : "notifications-primary-button"
            }
            onClick={onOpenAutopilot}
          >
            Open chat
          </button>
          {item.target?.connectorId ? (
            <button
              type="button"
              className="notifications-secondary-button"
              onClick={() => onOpenIntegrations(item.target?.connectorId)}
            >
              Open Capabilities
            </button>
          ) : null}
          {item.target?.connectorId ? (
            <button
              type="button"
              className="notifications-quiet-button"
              onClick={() => onOpenShield(item.target?.connectorId)}
            >
              Open Policy
            </button>
          ) : null}
        </div>
      </div>

      {loading ? (
        <div className="notifications-empty-card">Loading target detail…</div>
      ) : null}
      {error ? (
        <div className="notifications-empty-card notifications-empty-state-error">
          {error}
        </div>
      ) : null}

      {!loading &&
      !error &&
      item.target?.kind === "gmail_thread" &&
      gmailThread ? (
        <div className="notifications-detail-section">
          <div className="notifications-detail-meta">
            <span>Thread {gmailThread.threadId.slice(0, 12)}</span>
            {gmailThread.historyId ? (
              <span>History {gmailThread.historyId}</span>
            ) : null}
          </div>
          {gmailThread.snippet ? (
            <p className="notifications-detail-snippet">
              {gmailThread.snippet}
            </p>
          ) : null}
          <div className="notifications-detail-stack">
            {gmailThread.messages.map((message) => (
              <article key={message.id} className="notifications-detail-card">
                <div className="notifications-detail-card-head">
                  <strong>{message.subject || "Untitled message"}</strong>
                  <span>{message.date || "No date"}</span>
                </div>
                <div className="notifications-detail-meta">
                  {message.from ? <span>From {message.from}</span> : null}
                  {message.to ? <span>To {message.to}</span> : null}
                </div>
                {message.snippet ? <p>{message.snippet}</p> : null}
                {message.labelIds.length > 0 ? (
                  <div className="notifications-detail-tags">
                    {message.labelIds.map((label) => (
                      <span key={label}>{label}</span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
          </div>
          <div className="notifications-detail-actions">
            <button
              type="button"
              className="notifications-primary-button"
              onClick={() =>
                onOpenReplyComposer({
                  kind: "gmail_reply",
                  connectorId: item.target?.connectorId ?? "google.workspace",
                  thread: gmailThread,
                  sourceNotificationId: item.itemId,
                })
              }
            >
              Open reply composer
            </button>
            <button
              type="button"
              className="notifications-secondary-button"
              onClick={() => onOpenIntegrations(item.target?.connectorId)}
            >
              Open Capabilities
            </button>
          </div>
        </div>
      ) : null}

      {!loading &&
      !error &&
      item.target?.kind === "calendar_event" &&
      calendarEvent ? (
        <div className="notifications-detail-section">
          <div className="notifications-detail-meta">
            <span>{calendarEvent.summary || "Untitled event"}</span>
            {calendarEvent.status ? (
              <span>Status {calendarEvent.status}</span>
            ) : null}
          </div>
          <div className="notifications-detail-meta">
            {calendarEvent.start ? (
              <span>Starts {timestampCopy(calendarEvent.start)}</span>
            ) : null}
            {calendarEvent.end ? (
              <span>Ends {timestampCopy(calendarEvent.end)}</span>
            ) : null}
            {calendarEvent.location ? (
              <span>{calendarEvent.location}</span>
            ) : null}
          </div>
          {calendarEvent.description ? (
            <p className="notifications-detail-snippet">
              {calendarEvent.description}
            </p>
          ) : null}
          {calendarEvent.attendees.length > 0 ? (
            <div className="notifications-detail-stack">
              {calendarEvent.attendees.map((attendee, index) => (
                <article
                  key={`${attendee.email ?? "attendee"}-${index}`}
                  className="notifications-detail-card"
                >
                  <div className="notifications-detail-card-head">
                    <strong>
                      {attendee.displayName || attendee.email || "Attendee"}
                    </strong>
                    <span>{attendee.responseStatus || "response unknown"}</span>
                  </div>
                  {attendee.organizer ? <p>Organizer</p> : null}
                </article>
              ))}
            </div>
          ) : null}
          <div className="notifications-detail-actions">
            <button
              type="button"
              className="notifications-primary-button"
              onClick={() =>
                onOpenMeetingPrep({
                  kind: "meeting_prep",
                  connectorId: item.target?.connectorId ?? "google.workspace",
                  event: calendarEvent,
                  sourceNotificationId: item.itemId,
                })
              }
            >
              Open prep workbench
            </button>
            {calendarEvent.htmlLink ? (
              <a
                className="notifications-secondary-link"
                href={calendarEvent.htmlLink}
                target="_blank"
                rel="noreferrer"
              >
                Open in Calendar
              </a>
            ) : null}
          </div>
        </div>
      ) : null}

      {!loading &&
      !error &&
      item.target?.kind === "connector_auth" &&
      authRecord ? (
        <div className="notifications-detail-section">
          <div className="notifications-detail-meta">
            <span>State {authRecord.record.state}</span>
            <span>Protocol {authRecord.record.authProtocol}</span>
            {authRecord.record.expiresAtMs ? (
              <span>
                Expires{" "}
                {timestampCopy(
                  new Date(authRecord.record.expiresAtMs).toISOString(),
                )}
              </span>
            ) : null}
          </div>
          {authRecord.record.accountLabel ? (
            <p className="notifications-detail-snippet">
              {authRecord.record.accountLabel}
            </p>
          ) : null}
          {authRecord.record.grantedScopes.length > 0 ? (
            <div className="notifications-detail-tags">
              {authRecord.record.grantedScopes.map((scope) => (
                <span key={scope}>{scope}</span>
              ))}
            </div>
          ) : null}
          <div className="notifications-detail-stack">
            {Object.entries(authRecord.record.metadata).map(([key, value]) => (
              <article key={key} className="notifications-detail-card">
                <div className="notifications-detail-card-head">
                  <strong>{key}</strong>
                </div>
                <p>{value}</p>
              </article>
            ))}
          </div>
          <div className="notifications-detail-actions">
            <button
              type="button"
              className="notifications-primary-button"
              onClick={() => onOpenIntegrations(item.target?.connectorId)}
            >
              Open Capabilities
            </button>
            <button
              type="button"
              className="notifications-secondary-button"
              onClick={() => onOpenShield(item.target?.connectorId)}
            >
              Open Policy
            </button>
          </div>
        </div>
      ) : null}

      {!loading &&
      !error &&
      item.target?.kind === "connector_subscription" &&
      subscription ? (
        <div className="notifications-detail-section">
          <div className="notifications-detail-meta">
            <span>{subscription.kind}</span>
            <span>Status {subscription.status}</span>
            {subscription.accountEmail ? (
              <span>{subscription.accountEmail}</span>
            ) : null}
          </div>
          <div className="notifications-detail-stack">
            <article className="notifications-detail-card">
              <div className="notifications-detail-card-head">
                <strong>Pub/Sub</strong>
              </div>
              <p>{subscription.pubsubSubscription}</p>
              <p>{subscription.pubsubTopic}</p>
            </article>
            {subscription.lastError ? (
              <article className="notifications-detail-card">
                <div className="notifications-detail-card-head">
                  <strong>Last error</strong>
                </div>
                <p>{subscription.lastError}</p>
              </article>
            ) : null}
            <article className="notifications-detail-card">
              <div className="notifications-detail-card-head">
                <strong>Lifecycle</strong>
              </div>
              {subscription.renewAtUtc ? (
                <p>Renew at {timestampCopy(subscription.renewAtUtc)}</p>
              ) : null}
              {subscription.expiresAtUtc ? (
                <p>Expires at {timestampCopy(subscription.expiresAtUtc)}</p>
              ) : null}
              {subscription.lastDeliveryAtUtc ? (
                <p>
                  Last delivery {timestampCopy(subscription.lastDeliveryAtUtc)}
                </p>
              ) : null}
              {subscription.lastAckAtUtc ? (
                <p>Last ack {timestampCopy(subscription.lastAckAtUtc)}</p>
              ) : null}
            </article>
          </div>
          <div className="notifications-detail-actions">
            <button
              type="button"
              className="notifications-primary-button"
              onClick={() => {
                void runSubscriptionAction("renew");
              }}
              disabled={busy}
            >
              {busy ? "Working…" : "Renew now"}
            </button>
            {subscription.status === "paused" ? (
              <button
                type="button"
                className="notifications-secondary-button"
                onClick={() => {
                  void runSubscriptionAction("resume");
                }}
                disabled={busy}
              >
                Resume
              </button>
            ) : (
              <button
                type="button"
                className="notifications-secondary-button"
                onClick={() => {
                  void runSubscriptionAction("stop");
                }}
                disabled={busy}
              >
                Pause
              </button>
            )}
            <button
              type="button"
              className="notifications-quiet-button"
              onClick={() => onOpenIntegrations(item.target?.connectorId)}
            >
              Open Capabilities
            </button>
          </div>
        </div>
      ) : null}

      {!loading && !error && !item.target ? (
        <div className="notifications-empty-card">
          This notification does not expose a focused target yet.
        </div>
      ) : null}
    </aside>
  );
}
